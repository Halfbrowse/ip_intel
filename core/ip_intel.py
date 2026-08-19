#!/usr/bin/env python3
"""
ip_intel.py — shared collection helpers for the scan pipeline.

This module is a *library*, not an entry point. It used to hold a second,
async scan engine (`analyze_domain` / `_analyze_domain_async`) plus a `main()`
CLI, which duplicated ~12 collectors that `core/basic.py` already implements
for the live pipeline — the same CIRCL passive-DNS query under two names
(`circl_pdns` vs `historical_dns`), two `extract_spf_origins`, two page-metadata
fetchers, and so on. Only the CLI and the retired OpenCTI worker ever called it,
so the engine, the CLI and the duplicate collectors were removed; the scan path
is `cases/case_runtime.py` → `core/analysis_service.py` → `core.basic.analyze`.

What remains here is what the live pipeline actually imports:

    - censys_cert_search  : Censys Platform host search for certs naming a domain,
                            plus the opt-in historical cert→host pivot
                            (CENSYS_API_KEY + CENSYS_ORG_ID; Starter+ tier, and
                            Enterprise Adversary Investigation for cert history)
    - detect_proxy_details: CDN / reverse-proxy classification for an IP
    - _classify_nameservers, attempt_zone_transfer
    - probe_subdomain_origins / probe_mx_origins / probe_wordlist_subdomains
      and _select_wordlist_followup_targets  (origin-leak hunting)
    - _acrt_sh_data + the Cert Spotter fallback helpers, used by
      cases/case_runtime.py's crt.sh retry path
    - targeted_origin_scan / targeted_asn_scan / targeted_country_scan: two-phase
      TCP+TLS sweeps of an IP range. Retained deliberately, but note nothing
      currently calls them — analysis_service stubs them out for case mode
      ("Targeted origin scan is not enabled for case mode") and the CLI that did
      call them is gone.
"""

import asyncio
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed

from dotenv import load_dotenv
load_dotenv()
import ipaddress
import re
from pathlib import Path

import dns.resolver
import dns.zone
import dns.query
import httpx
import requests
from tqdm import tqdm

from sources.signal_transport import parse_certificate_der
from utils.outbound import requests_kwargs


RESULTS_DIR = Path(__file__).parent.parent / "results"
CONFIG_DIR = Path(__file__).parent.parent / "config"
_LOG_CONTEXT = threading.local()
_URLSCAN_GATE = threading.Semaphore(max(1, int(os.getenv("URLSCAN_MAX_PARALLEL", "1"))))
_DNS_RECORD_TYPES = ("A", "AAAA", "CAA", "CNAME", "MX", "NS", "TXT", "SOA")
_DNS_FALLBACK_NAMESERVERS = tuple(
    item.strip()
    for item in os.getenv("IP_INTEL_DNS_RESOLVERS", "1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4").split(",")
    if item.strip()
)
_DNS_FALLBACK_LOCK = threading.Lock()
_DNS_FALLBACK_WARNED = False

# ── Process-wide DNS admission control ───────────────────────────────────────
# Every DNS query this process makes passes through here, whoever issues it.
#
# The alternative — which is what was here — is each call site sizing its own
# thread pool: 322 for the wordlist sweep, 20 for the crt.sh subdomain probe, 10
# for MX, 8 for the record fan-out, plus one PTR per IP-enrichment worker. Each
# looked reasonable alone. Multiplied by ANALYSIS_WORKERS concurrent targets
# they put thousands of queries in flight against four public resolvers, which
# throttle — and a throttled query does not fail fast, it costs a full timeout.
#
# The result was that tuning any one pool moved nothing measurable, because the
# resolver was saturated by the others: halving the IP-enrichment workers left
# per-IP time unchanged (3.31s -> 3.47s) while bounding the wordlist sweep alone
# improved it to 2.48s. A shared resource needs a shared bound, not N local ones.
#
# So: call sites are free to be as concurrent as their own logic wants, and
# total DNS pressure is this one number. Raise it if the resolvers can take more
# (a local caching resolver can take far more than 1.1.1.1 will); lower it if
# lookups start timing out under load.
_DNS_MAX_INFLIGHT = max(1, int(os.getenv("DNS_MAX_INFLIGHT", "64")))
_DNS_GATE = threading.Semaphore(_DNS_MAX_INFLIGHT)


# ── Helpers ───────────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    message = str(msg)
    handler = getattr(_LOG_CONTEXT, "handler", None)
    if handler is not None:
        try:
            handler(message)
        except Exception:
            pass
    print(f"  [*] {message}", flush=True)






def clean_target(target: str) -> str:
    """Strip protocol prefix and trailing slashes so bare hostnames/IPs remain."""
    target = re.sub(r'^https?://', '', target)
    return target.rstrip('/').strip()


def _warn_dns_fallback(exc: Exception) -> None:
    global _DNS_FALLBACK_WARNED
    with _DNS_FALLBACK_LOCK:
        if _DNS_FALLBACK_WARNED:
            return
        _DNS_FALLBACK_WARNED = True
    log(
        "DNS resolver configuration is unavailable "
        f"({exc}); falling back to IP_INTEL_DNS_RESOLVERS."
    )


def _iter_mapping_items(values):
    for item in values or []:
        if isinstance(item, Mapping):
            yield item




def _build_sync_resolver(*, timeout: float, lifetime: float):
    try:
        resolver = dns.resolver.Resolver()
    except Exception as exc:
        if not _DNS_FALLBACK_NAMESERVERS:
            raise
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(_DNS_FALLBACK_NAMESERVERS)
        _warn_dns_fallback(exc)
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    return resolver




def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


# Cloudflare's published IP ranges (https://www.cloudflare.com/ips/)
_CF_CIDRS = [ipaddress.ip_network(n) for n in [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]]


def is_cloudflare_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _CF_CIDRS)
    except ValueError:
        return False


def _normalize_asn(value: str | None) -> str:
    text = str(value or "").strip().upper()
    if not text:
        return ""
    return text[2:] if text.startswith("AS") else text


def _load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _load_lines(path: Path) -> list[str]:
    try:
        return [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    except Exception:
        return []


def _load_proxy_rules() -> list[dict[str, object]]:
    raw = _load_json(CONFIG_DIR / "proxy_rules.json", {})
    rule_list = raw.get("rules") if isinstance(raw, dict) else raw
    rules: list[dict[str, object]] = []
    for entry in rule_list if isinstance(rule_list, list) else []:
        rules.append(
            {
                "family": str(entry.get("family") or ""),
                "patterns": tuple(str(item).lower() for item in entry.get("patterns") or []),
                "asns": {_normalize_asn(item) for item in entry.get("asns") or [] if _normalize_asn(item)},
            }
        )
    return rules


def _load_provider_asns() -> dict[str, str]:
    raw = _load_json(CONFIG_DIR / "provider_asns.json", {})
    providers = raw.get("providers") if isinstance(raw, dict) else {}
    return {f"AS{_normalize_asn(key)}": str(value) for key, value in (providers or {}).items() if _normalize_asn(key)}


def _apex_domain(hostname: str | None) -> str | None:
    labels = [label for label in str(hostname or "").strip(".").lower().split(".") if label]
    if len(labels) < 2:
        return None
    return ".".join(labels[-2:])


def _classify_nameservers(nameservers: list[str]) -> dict[str, list[dict[str, str]]]:
    boring_tokens = {item.lower() for item in _BORING_NS_PROVIDERS}
    boring: list[dict[str, str]] = []
    vanity: list[dict[str, str]] = []
    for nameserver in nameservers or []:
        apex = _apex_domain(nameserver)
        item = {"nameserver": nameserver, "apex": apex or ""}
        if apex and any(token in apex for token in boring_tokens):
            boring.append(item)
        else:
            vanity.append(item)
    return {"boring": boring, "vanity_candidates": vanity}


_PROXY_FAMILY_RULES = _load_proxy_rules()
_SUBDOMAIN_WORDLIST = _load_lines(CONFIG_DIR / "subdomain_wordlist.txt")
_WORDLIST_FOLLOWUP_LIMIT = 8
# Concurrent DNS queries the wordlist sweep may have in flight. See
# probe_wordlist_subdomains for why this is bounded rather than one per word.
_WORDLIST_PROBE_WORKERS = max(1, int(os.environ.get("WORDLIST_PROBE_WORKERS", "24")))
_BORING_NS_PROVIDERS = set(_load_lines(CONFIG_DIR / "boring_ns_providers.txt"))


def detect_proxy_details(
    ip: str,
    ptr: str | None,
    asn_info: dict | None,
    cert: dict | None = None,
) -> dict[str, object]:
    if is_cloudflare_ip(ip):
        return {"proxy_family": "cloudflare", "proxy_confidence": 0.99}

    asn_info = asn_info or {}
    cert = cert or {}
    norm_asn = _normalize_asn(asn_info.get("asn"))
    ipinfo_norm_asn = _normalize_asn(asn_info.get("ipinfo_asn"))
    text_fields = [
        ptr,
        asn_info.get("asn_description"),
        asn_info.get("network_name"),
        asn_info.get("ipinfo_as_name"),
        asn_info.get("ipinfo_as_domain"),
        cert.get("cn"),
        cert.get("issuer_cn"),
        cert.get("issuer_org"),
    ]
    text_fields.extend((cert.get("sans") or [])[:12])
    haystacks = [str(value).lower() for value in text_fields if value]
    joined = " ".join(haystacks)
    ptr_text = str(ptr or "").lower()
    network_text = " ".join(
        str(value).lower()
        for value in (
            asn_info.get("asn_description"),
            asn_info.get("network_name"),
            asn_info.get("ipinfo_as_name"),
            asn_info.get("ipinfo_as_domain"),
        )
        if value
    )
    cert_text = " ".join(
        str(value).lower()
        for value in [cert.get("cn"), cert.get("issuer_cn"), cert.get("issuer_org"), *(cert.get("sans") or [])[:12]]
        if value
    )

    best_family = ""
    best_score = 0.0
    for rule in _PROXY_FAMILY_RULES:
        score = 0.0
        asn_hit = bool(
            (norm_asn and norm_asn in rule["asns"])
            or (ipinfo_norm_asn and ipinfo_norm_asn in rule["asns"])
        )
        ptr_hit = any(pattern in ptr_text for pattern in rule["patterns"])
        cert_hit = any(pattern in cert_text for pattern in rule["patterns"])
        network_hit = any(pattern in network_text for pattern in rule["patterns"])
        generic_text_hit = any(pattern in joined for pattern in rule["patterns"])

        if asn_hit:
            score += 0.58
        if ptr_hit:
            score += 0.52
        if cert_hit:
            score += 0.22
        if network_hit:
            score += 0.16
        if generic_text_hit and not (ptr_hit or cert_hit or network_hit):
            score += 0.12
        if score > best_score:
            best_score = score
            best_family = rule["family"]

    if best_score >= 0.5:
        return {
            "proxy_family": best_family,
            "proxy_confidence": round(min(best_score, 0.98), 2),
        }

    generic_edge_terms = (
        " reverse proxy",
        " load balancer",
        " application gateway",
        " front door",
        " edge network",
        " edge service",
        " cdn",
        " proxy edge",
    )
    if any(term in joined for term in generic_edge_terms):
        return {"proxy_family": "managed_edge", "proxy_confidence": 0.51}

    return {"proxy_family": None, "proxy_confidence": None}


def resolve_ips(hostname: str) -> list[str]:
    """Return A + AAAA records for hostname, empty list on failure."""
    try:
        resolver = _build_sync_resolver(timeout=5, lifetime=8)
    except Exception:
        return []
    ips: list[str] = []
    for rtype in ("A", "AAAA"):
        try:
            with _DNS_GATE:
                ips.extend(str(r) for r in resolver.resolve(hostname, rtype))
        except Exception:
            pass
    return ips


# ── DNS ───────────────────────────────────────────────────────────────────────





def attempt_zone_transfer(domain: str, nameservers: list[str]) -> list[str]:
    found: list[str] = []
    for ns in nameservers:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            for name in zone.nodes:
                label = str(name)
                if label == "@":
                    continue
                full = f"{label}.{domain}"
                if full not in found:
                    found.append(full)
        except Exception:
            pass
    return sorted(found)


# ── Certificate Transparency via crt.sh ───────────────────────────────────────


def _parse_crt_sh_entries(entries: list, domain: str) -> dict:
    """Pure processing of a crt.sh JSON response list (no I/O)."""
    result = {"subdomains": [], "total_certs": 0, "issuers": [], "cross_domain_sans": [], "certs": []}
    result["total_certs"] = len(entries)
    subdomains: set[str] = set()
    issuers: set[str] = set()
    cross_sans: set[str] = set()
    seen_ids: set[int] = set()
    certs: list[dict] = []

    for entry in _iter_mapping_items(entries):
        cert_id = entry.get("id")
        if cert_id in seen_ids:
            continue
        seen_ids.add(cert_id)

        issuer = entry.get("issuer_name", "")
        cn_match = re.search(r"CN=([^,]+)", issuer)
        issuer_cn = cn_match.group(1).strip() if cn_match else issuer
        if issuer_cn:
            issuers.add(issuer_cn)

        sans_in_cert: list[str] = []
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lstrip("*.").lower()
            if not name:
                continue
            sans_in_cert.append(name)
            if name.endswith(f".{domain}") or name == domain:
                subdomains.add(name) if name != domain else None
            else:
                cross_sans.add(name)

        certs.append({
            "id":         cert_id,
            "issuer":     issuer_cn,
            "not_before": entry.get("not_before"),
            "not_after":  entry.get("not_after"),
            "logged_at":  entry.get("entry_timestamp"),
            "sans":       sorted(set(sans_in_cert)),
        })

    result["subdomains"]        = sorted(subdomains)
    result["issuers"]           = sorted(issuers)
    result["cross_domain_sans"] = sorted(cross_sans)
    result["certs"]             = sorted(certs, key=lambda c: c.get("not_before") or "", reverse=True)
    return result


_CRT_SH_EMPTY = {"subdomains": [], "total_certs": 0, "issuers": [], "cross_domain_sans": [], "certs": []}


# ── Certificate Transparency fallback via Cert Spotter ───────────────────────
# crt.sh rate-limits aggressively and falls over often. When it fails we fall
# back to Cert Spotter's free issuances API (no key required; an optional
# CERTSPOTTER_API_KEY Bearer token raises the rate limit). Issuances are
# converted into crt.sh-shaped entries and fed through _parse_crt_sh_entries
# so everything downstream (ct_certs storage, clustering, sibling picks)
# behaves exactly as with crt.sh data.

CERTSPOTTER_API_URL = "https://api.certspotter.com/v1/issuances"
CERTSPOTTER_MAX_PAGES = 20  # pagination safety cap (free tier ≈ 100 queries/hour)


def _certspotter_headers() -> dict:
    headers = {"Accept": "application/json"}
    api_key = os.environ.get("CERTSPOTTER_API_KEY", "").strip()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _certspotter_params(domain: str, after: str | None = None) -> dict:
    params: dict = {
        "domain": domain,
        "include_subdomains": "true",
        "expand": ["dns_names", "issuer", "cert"],
    }
    if after is not None:
        params["after"] = after
    return params


def _certspotter_to_crt_sh_entries(issuances: list) -> list[dict]:
    """Convert Cert Spotter issuance objects into crt.sh-shaped entries so they
    can be normalized by _parse_crt_sh_entries (no I/O)."""
    entries: list[dict] = []
    for issuance in _iter_mapping_items(issuances):
        cert_id = issuance.get("id")
        try:
            cert_id = int(cert_id)
        except (TypeError, ValueError):
            pass
        issuer = issuance.get("issuer")
        if isinstance(issuer, Mapping):
            issuer_name = issuer.get("name") or issuer.get("friendly_name") or ""
        else:
            issuer_name = str(issuer or "")
        dns_names = [n for n in (issuance.get("dns_names") or []) if isinstance(n, str)]
        entries.append({
            "id":              cert_id,
            "issuer_name":     issuer_name,
            "name_value":      "\n".join(dns_names),
            "not_before":      issuance.get("not_before"),
            "not_after":       issuance.get("not_after"),
            "entry_timestamp": None,  # Cert Spotter does not expose CT log timestamps
        })
    return entries






# ── Historical / Passive DNS via CIRCL ────────────────────────────────────────



# ── Subdomain origin probe ────────────────────────────────────────────────────

def probe_subdomain_origins(subdomains: list[str]) -> list[dict]:
    """
    Resolve each subdomain discovered via crt.sh and flag any that resolve to
    a non-Cloudflare IP. These are origin server leaks — the operator forgot to
    proxy that subdomain through Cloudflare, exposing the real hosting IP.
    """
    leaks: list[dict] = []

    def _check(sub: str) -> list[dict]:
        return [{"subdomain": sub, "ip": ip} for ip in resolve_ips(sub) if not is_cloudflare_ip(ip)]

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_check, sub): sub for sub in subdomains}
        with tqdm(total=len(subdomains), desc="  Subdomain probe", unit="sub",
                  dynamic_ncols=True) as bar:
            for fut in as_completed(futures):
                leaks.extend(fut.result())
                bar.update(1)

    return leaks


# ── MX origin probe ──────────────────────────────────────────────────────────

def probe_mx_origins(mx_records: list[dict]) -> list[dict]:
    """
    Resolve MX hostnames and flag any that resolve to a non-Cloudflare IP.
    Mail servers are often co-hosted with the web server and not proxied,
    leaking the real origin.
    """
    leaks: list[dict] = []

    def _check(mx: dict) -> list[dict]:
        host = mx.get("exchange", "")
        if not host:
            return []
        return [
            {"subdomain": host, "ip": ip, "source": "MX record"}
            for ip in resolve_ips(host)
            if not is_cloudflare_ip(ip)
        ]

    with ThreadPoolExecutor(max_workers=10) as ex:
        for hits in ex.map(_check, mx_records):
            leaks.extend(hits)

    return leaks


def probe_wordlist_subdomains(domain: str) -> list[dict]:
    """
    Probe a fixed wordlist of common subdomains for non-Cloudflare IPs.
    Catches origin leaks that crt.sh never logged a cert for.
    """
    candidates = [f"{prefix}.{domain}" for prefix in _SUBDOMAIN_WORDLIST]

    def _check(fqdn: str) -> list[dict]:
        return [
            {"subdomain": fqdn, "ip": ip, "source": "wordlist probe"}
            for ip in resolve_ips(fqdn)
            if not is_cloudflare_ip(ip)
        ]

    leaks: list[dict] = []
    # Bounded, not one thread per word. This was `max_workers=len(candidates)`,
    # which for the 322-entry wordlist meant 322 concurrent DNS queries per
    # domain — and with ANALYSIS_WORKERS concurrent targets, ~3,900 in flight at
    # once against the public resolvers in IP_INTEL_DNS_RESOLVERS.
    #
    # That is well past where 1.1.1.1/8.8.8.8 start dropping traffic, and a
    # dropped query does not fail fast: it costs a full resolver timeout. So the
    # unbounded pool was not buying speed, it was converting a rate-limit into
    # seconds of dead wall-clock, and dragging every other DNS-using step in the
    # concurrent parity block down with it (origin candidates measured 5.1s
    # alone, 19.7s alongside).
    #
    # 24 keeps this step's own latency flat (322 lookups in ~14 rounds) while
    # leaving resolver headroom for the rest of the scan.
    workers = min(len(candidates), _WORDLIST_PROBE_WORKERS) or 1
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for hits in ex.map(_check, candidates):
            leaks.extend(hits)

    return leaks


def _select_wordlist_followup_targets(wordlist_hits: list[dict], *, limit: int = _WORDLIST_FOLLOWUP_LIMIT) -> list[dict]:
    """
    Pick a stable, de-duplicated set of wordlist hits for full subdomain follow-up scans.

    We preserve first-seen order, merge duplicate IPs for the same subdomain, and cap
    the total follow-up count so a noisy domain does not recursively explode the job.
    """
    grouped: dict[str, dict] = {}
    ordered: list[dict] = []

    for entry in wordlist_hits or []:
        if not isinstance(entry, dict):
            continue

        subdomain = clean_target(str(entry.get("subdomain") or "")).lower()
        if not subdomain or is_ip(subdomain):
            continue

        payload = grouped.get(subdomain)
        if payload is None:
            payload = {
                "subdomain": subdomain,
                "ips": [],
                "hits": [],
            }
            grouped[subdomain] = payload
            ordered.append(payload)

        ip_address = str(entry.get("ip") or "").strip()
        if ip_address and ip_address not in payload["ips"]:
            payload["ips"].append(ip_address)

        payload["hits"].append(dict(entry))

    return [
        {
            "subdomain": item["subdomain"],
            "ips": list(item["ips"]),
            "hits": list(item["hits"]),
        }
        for item in ordered[:limit]
    ]


# ── SPF ip4 extraction ────────────────────────────────────────────────────────



# ── HackerTarget host search ──────────────────────────────────────────────────



# ── urlscan.io historical IPs ─────────────────────────────────────────────────



# ── Censys cert search ────────────────────────────────────────────────────────

# Cost caps. Censys bills 1 credit for a search and 1 more for *every additional
# page of 100 results*, so page count is the credit count: one page, one credit,
# up to 100 hosts. This was 10 (up to 1000 hosts, up to 10 credits) — the extra
# nine pages are hosts serving a cert naming the domain, which past the first
# hundred are overwhelmingly shared-CDN edges rather than origins. The response
# still reports `total_hits`, so a domain whose cert is on more than 100 hosts is
# visible as such without paying to enumerate them.
_CENSYS_SEARCH_MAX_PAGES   = 1    # 1 * 100 = up to 100 current hosts, 1 credit
_CENSYS_HISTORY_MAX_CERTS  = 5    # distinct leaf certs to pull history for
_CENSYS_HISTORY_MAX_PAGES  = 5    # history pages per cert (100 ranges each)


def _as_dict(obj) -> dict:
    """Normalize a Censys SDK model (or dict) into a plain dict for defensive
    navigation. The generated SDK models are deeply nested and have drifted
    between versions, so we never rely on typed attribute paths."""
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        try:
            return obj.model_dump()
        except Exception:
            pass
    return {}


def _service_key(svc: dict) -> tuple[int | None, str]:
    """The (port, transport) identity shared by a host service and a
    `matched_services` entry, so the two can be lined up.

    transport_protocol may arrive as a ServiceTransportProtocol enum whose
    str() is the member name ("ServiceTransportProtocol.TCP"); use its .value
    ("tcp") when present."""
    proto = svc.get("transport_protocol") or ""
    proto = getattr(proto, "value", proto)
    port  = svc.get("port")
    return (port if isinstance(port, int) else None), str(proto).lower()


def _censys_parse_host_hit(hit) -> tuple[dict | None, str | None]:
    """Turn one search hit into our normalized host entry and pull the leaf
    cert fingerprint of the service that actually matched the query.

    `host_v1.matched_services` (SDK model HostAssetWithMatchedServices) is the
    API telling us which of the host's services matched — i.e. which one serves
    a cert naming the domain we asked about. It carries only
    {port, protocol, transport_protocol} and no cert, so it is used as a
    selector into `host_v1.resource.services` rather than as the fingerprint
    source itself.

    This matters on shared hosting: a host can run dozens of services for
    dozens of tenants, and taking the first cert-bearing one frequently picks
    a *different* tenant's certificate — which the cert-history pivot then
    spends 25 credits chasing for infrastructure that was never ours.
    """
    host_v1 = _as_dict(hit).get("host_v1") or {}
    host    = host_v1.get("resource") or {}
    ip      = host.get("ip")
    if not ip:
        return None, None

    asn_block = host.get("autonomous_system") or {}
    loc_block = host.get("location") or {}

    matched_keys = [_service_key(svc) for svc in (host_v1.get("matched_services") or [])]

    def _matches_query(key: tuple[int | None, str]) -> bool:
        port, proto = key
        # Transport is only compared when both sides report one: a service and
        # its matched_services entry always agree on port, but either side can
        # come back with an empty transport_protocol.
        return any(
            port is not None and port == m_port and (not proto or not m_proto or proto == m_proto)
            for m_port, m_proto in matched_keys
        )

    services: list[str] = []
    matched_fingerprint: str | None = None
    first_fingerprint: str | None = None
    for svc in (host.get("services") or []):
        key = _service_key(svc)
        port, proto = key
        if port:
            services.append(f"{port}/{proto}")
        # The served leaf cert lives under svc["cert"]; presented_chain[0]
        # is frequently the issuing intermediate, so pivot cert history on
        # the leaf fingerprint instead.
        fp = (svc.get("cert") or {}).get("fingerprint_sha256")
        if not fp:
            continue
        if first_fingerprint is None:
            first_fingerprint = fp
        if matched_fingerprint is None and _matches_query(key):
            matched_fingerprint = fp

    # Fall back to the first cert-bearing service only when the response
    # carried no matched_services at all — older API versions omit it, and the
    # SDK documents that a `fields` selection dropping
    # host.services.port/transport_protocol/protocol suppresses it too. When
    # the field *is* present but none of the matched services carried a cert,
    # we deliberately return no fingerprint rather than guess: a wrong
    # fingerprint costs 25 credits of history pivot on someone else's host.
    fingerprint = matched_fingerprint if matched_keys else first_fingerprint

    entry = {
        "ip":         ip,
        "cloudflare": is_cloudflare_ip(ip),
        "asn":        asn_block.get("asn"),
        "asn_name":   asn_block.get("description") or asn_block.get("name"),
        "country":    loc_block.get("country_code"),
        "services":   services,
        # The leaf fingerprint is kept on the hit, not just returned for the
        # history pivot. It used to be discarded whenever CENSYS_CERT_HISTORY
        # was off — which is the default and the only sane setting for a Core
        # account — throwing away the most valuable thing in the response.
        #
        # A shared TLS fingerprint is the strongest correlation signal the
        # system has (utils/pairwise.py scores it 100, "near-identity"), and
        # until now the only source of one was `tls_certs.probes`: our own
        # socket probes, capped at IP_PROBE_LIMIT and limited to hosts that
        # actually answer on the ports we try. This response carries leaf
        # fingerprints for up to 100 hosts, already paid for, including hosts
        # we cannot reach. Censys host *enrichment* returns no cert data at all
        # (see utils/censys_enrichment.normalize_host_enrichment), so there is
        # no free path to this and nothing here overlaps it.
        "cert_fingerprint_sha256": fingerprint,
    }
    return entry, fingerprint


def _iso(value) -> str | None:
    """Render a datetime (or already-string) timestamp as ISO-8601 text."""
    if value is None:
        return None
    iso = getattr(value, "isoformat", None)
    return iso() if callable(iso) else str(value)


def _censys_cert_history(sdk, fingerprints: list[str]) -> list[dict]:
    """Historical host observations for each leaf-cert fingerprint via the
    Censys threat-hunting endpoint. This is the Enterprise-only pivot that
    surfaces IPs that served the cert in the past — including rotated origins
    that no longer appear in the current-state host search.

    Requires the Adversary Investigation entitlement; if the account lacks it
    the per-cert call is recorded as an error rather than aborting the run."""
    history: list[dict] = []
    for fp in fingerprints:
        try:
            page_token: str | None = None
            for _ in range(_CENSYS_HISTORY_MAX_PAGES):
                req: dict = {"certificate_id": fp, "page_size": 100}
                if page_token:
                    req["page_token"] = page_token
                resp    = sdk.threat_hunting.get_host_observations_with_certificate(request=req)
                payload = _as_dict(_as_dict(getattr(resp, "result", None)).get("result"))
                ranges  = payload.get("ranges") or []
                for rng in ranges:
                    ip = rng.get("ip")
                    if not ip:
                        continue
                    history.append({
                        "certificate": fp,
                        "ip":          ip,
                        "cloudflare":  is_cloudflare_ip(ip),
                        "port":        rng.get("port"),
                        "transport":   rng.get("transport_protocol"),
                        "first_seen":  _iso(rng.get("start_time")),
                        "last_seen":   _iso(rng.get("end_time")),
                    })
                page_token = payload.get("next_page_token")
                if not page_token or not ranges:
                    break
        except Exception as exc:
            history.append({"certificate": fp, "_error": str(exc)})
    return history


def _censys_history_enabled() -> bool:
    """Whether the cert-history pivot is switched on for this run.

    Off unless CENSYS_CERT_HISTORY is set, because the pivot dominates the
    Censys bill: _CENSYS_HISTORY_MAX_CERTS × _CENSYS_HISTORY_MAX_PAGES × 5
    credits = up to 125 of the ~135 credits a single seed domain spends, and it
    needs the Enterprise Adversary Investigation entitlement that most accounts
    (including every Starter/Core one) lack — so on a typical account it burns
    the run's whole budget only to record per-cert entitlement errors. The free
    CIRCL passive-DNS source already covers much of the same "IPs that used to
    serve this domain" ground at zero cost.
    """
    return os.environ.get("CENSYS_CERT_HISTORY", "").strip().lower() in ("1", "true", "yes", "on")


def censys_cert_search(domain: str, *, include_history: bool | None = None) -> dict:
    """
    Search Censys Platform for hosts currently serving a TLS cert whose CN
    matches the target domain. Any result that isn't a Cloudflare IP is a
    candidate origin server.

    Paginates the current-state host search (up to _CENSYS_SEARCH_MAX_PAGES)
    and, when cert history is enabled, pivots each distinct leaf cert through
    the threat-hunting host-observation endpoint to recover historical origins.
    Historical IPs that aren't Cloudflare and aren't already in the current
    hits are folded into ``origin_candidates``.

    ``include_history`` defaults to ``None``, meaning "ask the environment"
    (CENSYS_CERT_HISTORY — see _censys_history_enabled); pass ``True``/``False``
    to force it for one call. It is **off** by default: the pivot is up to 125
    of the ~135 credits per seed domain and needs an entitlement most accounts
    don't have.

    Requires a Censys Starter tier or higher for the search API; cert history
    additionally needs the Enterprise Adversary Investigation entitlement.
    The Censys Platform API requires the request to be associated with an
    organization — calls without it are rejected — so we pass CENSYS_ORG_ID.
    Add to .env:
        CENSYS_API_KEY=<personal-access-token>
        CENSYS_ORG_ID=<organization-id>
        CENSYS_CERT_HISTORY=1        # opt in to the cert-history pivot
    """
    if include_history is None:
        include_history = _censys_history_enabled()

    api_key = os.environ.get("CENSYS_API_KEY")
    org_id  = os.environ.get("CENSYS_ORG_ID")

    if not api_key:
        return {"skipped": True, "reason": "CENSYS_API_KEY not set in .env"}
    if not org_id:
        return {"skipped": True, "reason": "CENSYS_ORG_ID not set in .env"}

    from censys_platform import SDK

    result: dict = {"hits": [], "origin_candidates": [], "history": []}
    fingerprints: list[str] = []
    seen_ips: set[str] = set()
    try:
        with SDK(personal_access_token=api_key, organization_id=org_id) as sdk:
            query = f'host.services.cert.names = "{domain}"'
            page_token: str | None = None
            for _ in range(_CENSYS_SEARCH_MAX_PAGES):
                # No `fields` selection: this SDK/API version only populates
                # top-level selected fields, returning empty nested objects
                # (autonomous_system, location, services) under `fields`, so we
                # request the full host resource.
                body: dict = {
                    "query":     query,
                    "page_size": 100,
                }
                if page_token:
                    body["page_token"] = page_token
                resp    = sdk.global_data.search(search_query_input_body=body)
                # resp.result wraps the real payload under a further "result"
                # key (same shape _censys_cert_history unwraps).
                payload = _as_dict(_as_dict(getattr(resp, "result", None)).get("result"))
                hits    = payload.get("hits") or []
                for hit in hits:
                    entry, fp = _censys_parse_host_hit(hit)
                    if entry is None:
                        continue
                    result["hits"].append(entry)
                    seen_ips.add(entry["ip"])
                    if not entry["cloudflare"]:
                        result["origin_candidates"].append(entry)
                    if fp and fp not in fingerprints:
                        fingerprints.append(fp)
                page_token = payload.get("next_page_token")
                if not page_token or not hits:
                    break

            result["total"] = int(payload.get("total_hits") or len(result["hits"]))

            if include_history and fingerprints:
                result["history"] = _censys_cert_history(
                    sdk, fingerprints[:_CENSYS_HISTORY_MAX_CERTS]
                )

        # Fold historical origins (non-Cloudflare, not already seen) into the
        # candidate list so downstream scoring picks up rotated infrastructure.
        for obs in result["history"]:
            ip = obs.get("ip")
            if not ip or obs.get("cloudflare") or ip in seen_ips or "_error" in obs:
                continue
            seen_ips.add(ip)
            result["origin_candidates"].append({
                "ip":         ip,
                "cloudflare": False,
                "source":     "censys_history",
                "first_seen": obs.get("first_seen"),
                "last_seen":  obs.get("last_seen"),
            })

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ── Shodan cert search ───────────────────────────────────────────────────────



# ── Netlas cert search ───────────────────────────────────────────────────────



# ── Targeted origin scan ─────────────────────────────────────────────────────

GCP_IP_RANGES_URL = "https://www.gstatic.com/ipranges/cloud.json"

# Focused Eastern-European set — fast default for FIMI investigations.
# GCP has no datacenters in Russia, Ukraine, Belarus, Romania, or Bulgaria;
# these are the nearest regions for those markets.
GCP_DEFAULT_REGIONS = [
    "europe-north1",    # Finland      — closest GCP region to Russia
    "europe-north2",    # Stockholm    — near Russia/Baltic states
    "europe-central2",  # Warsaw       — nearest to Ukraine/Belarus
    "europe-west3",     # Frankfurt    — most popular for Russian-language hosting
    "europe-west10",    # Berlin       — additional Germany coverage
    "europe-west4",     # Netherlands
    "europe-west8",     # Milan        — nearest GCP region to Romania/Bulgaria
]

# Every GCP region on the European continent plus the nearest Middle-East
# region for Turkey (me-west1 / Tel Aviv is the closest GCP PoP to Istanbul).
# Pass None to fetch_gcp_ip_ranges() to scan every GCP region globally.
GCP_EUROPE_ALL_REGIONS = [
    "europe-north1",      # Helsinki, Finland   — closest to Russia
    "europe-north2",      # Stockholm, Sweden   — near Russia / Baltic states
    "europe-west1",       # St. Ghislain, Belgium
    "europe-west2",       # London, UK
    "europe-west3",       # Frankfurt, Germany
    "europe-west4",       # Eemshaven, Netherlands
    "europe-west6",       # Zurich, Switzerland
    "europe-west8",       # Milan, Italy
    "europe-west9",       # Paris, France
    "europe-west10",      # Berlin, Germany
    "europe-west12",      # Turin, Italy
    "europe-central2",    # Warsaw, Poland       — nearest to Ukraine / Belarus
    "europe-southwest1",  # Madrid, Spain
    "me-west1",           # Tel Aviv, Israel     — nearest GCP PoP to Turkey
]


PROVIDER_ASNS: dict[str, str] = _load_provider_asns()

RIPE_STAT_URL          = "https://stat.ripe.net/data/announced-prefixes/data.json"
RIPE_COUNTRY_URL       = "https://stat.ripe.net/data/country-resource-list/data.json"

# All 27 EU member states (post-Brexit)
EU_MEMBER_STATES = [
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
    "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
    "PL", "PT", "RO", "SK", "SI", "ES", "SE",
]


def fetch_country_ip_ranges(country_code: str) -> list[str]:
    """
    Fetch all IPv4 prefixes allocated to a country via RIPE Stat (free, no key).
    country_code is a 2-letter ISO code, e.g. "RU", "UA", "DE".
    """
    try:
        resp = requests.get(
            RIPE_COUNTRY_URL,
            params={"resource": country_code.upper(), "v4_format": "prefix"},
            timeout=30,
            headers={"Accept": "application/json"},
            **requests_kwargs(),
        )
        resp.raise_for_status()
        resources = resp.json().get("data", {}).get("resources", {})
        # Returns {"ipv4": ["1.2.3.0/24", ...], "ipv6": [...], "asn": [...]}
        cidrs = [p for p in resources.get("ipv4", []) if "/" in p]
        return cidrs
    except Exception as exc:
        log(f"RIPE Stat country lookup failed for {country_code}: {exc}")
        return []


def fetch_asn_ip_ranges(asns: list[str]) -> dict[str, list[str]]:
    """
    Fetch announced IPv4 prefixes for each ASN from RIPE Stat (free, no key).
    Returns {asn: [cidr, ...]} for ASNs that returned results.
    All ASNs are fetched in parallel via ThreadPoolExecutor.
    """
    asn_to_cidrs: dict[str, list[str]] = {}

    def _fetch_single_asn(asn: str) -> tuple[str, list[str]]:
        try:
            response = requests.get(
                RIPE_STAT_URL,
                params={"resource": asn},
                timeout=15,
                headers={"Accept": "application/json"},
                **requests_kwargs(),
            )
            response.raise_for_status()
            announced_prefixes = response.json().get("data", {}).get("prefixes", [])
            ipv4_cidrs = [
                prefix_entry["prefix"]
                for prefix_entry in announced_prefixes
                if ":" not in prefix_entry.get("prefix", "")  # IPv4 only
            ]
            return asn, ipv4_cidrs
        except Exception as exc:
            log(f"RIPE Stat failed for {asn}: {exc}")
            return asn, []

    with ThreadPoolExecutor(max_workers=10) as executor:
        for asn, ipv4_cidrs in executor.map(_fetch_single_asn, asns):
            if ipv4_cidrs:
                asn_to_cidrs[asn] = ipv4_cidrs

    return asn_to_cidrs


def fetch_gcp_ip_ranges(region_prefixes: list[str] | None = None) -> list[str]:
    """Download GCP's published IPv4 ranges, filtered to the given region prefixes."""
    try:
        resp = requests.get(GCP_IP_RANGES_URL, timeout=15, **requests_kwargs())
        resp.raise_for_status()
        cidrs = []
        for entry in resp.json().get("prefixes", []):
            cidr = entry.get("ipv4Prefix")
            if not cidr:
                continue
            scope = entry.get("scope", "")
            if region_prefixes is None or any(scope.startswith(r) for r in region_prefixes):
                cidrs.append(cidr)
        return cidrs
    except Exception as exc:
        log(f"Failed to fetch GCP IP ranges: {exc}")
        return []


def _parse_tls_cert(der: bytes, ip: str, port: int, domain: str) -> dict | None:
    """Parse a DER cert and return a hit dict if CN or SAN matches domain."""
    parsed = parse_certificate_der(der, ip=ip, port=port, sni_used=domain)
    if not parsed:
        return None
    cn = parsed.get("cn") or ""
    sans = parsed.get("sans") or []
    wildcard = "*." + ".".join(domain.split(".")[1:])
    if domain not in ([cn] + sans) and wildcard not in ([cn] + sans):
        return None
    return {
        **parsed,
        "cloudflare": is_cloudflare_ip(ip),
        "issuer": parsed.get("issuer_cn") or "",
    }




async def _tcp_open_async(ip: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _check_tls_async(ip: str, domain: str, port: int, timeout: float) -> dict | None:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=domain),
            timeout=timeout,
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        der = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if not der:
            return None
        return _parse_tls_cert(der, ip, port, domain)
    except Exception:
        return None


async def _phase1_async(
    ips: list[str], port: int, timeout: float, concurrency: int
) -> list[str]:
    """Async TCP connect scan. Returns IPs with port open."""
    sem      = asyncio.Semaphore(concurrency)
    open_ips: list[str] = []

    async def check(ip: str) -> None:
        async with sem:
            if await _tcp_open_async(ip, port, timeout):
                open_ips.append(ip)

    # Process in chunks to avoid creating millions of task objects at once.
    # The semaphore already caps concurrency; chunking caps peak memory.
    chunk = 100_000
    with tqdm(total=len(ips), desc="  Phase 1 TCP", unit="ip",
              dynamic_ncols=True, miniters=1000) as bar:
        for i in range(0, len(ips), chunk):
            tasks = [asyncio.create_task(check(ip)) for ip in ips[i:i + chunk]]
            for t in asyncio.as_completed(tasks):
                await t
                bar.update(1)
                bar.set_postfix(open=len(open_ips), refresh=False)

    return open_ips


async def _phase2_async(
    ips: list[str], domain: str, port: int, timeout: float, concurrency: int
) -> list[dict]:
    """Async TLS cert scan. Returns cert match dicts."""
    sem  = asyncio.Semaphore(concurrency)
    hits: list[dict] = []

    async def check(ip: str) -> None:
        async with sem:
            result = await _check_tls_async(ip, domain, port, timeout)
            if result:
                hits.append(result)
                tqdm.write(
                    f"  [!] CERT MATCH: {result['ip']} — "
                    f"CN={result['cn']} issuer={result['issuer']}"
                )

    with tqdm(total=len(ips), desc="  Phase 2 TLS", unit="ip",
              dynamic_ncols=True, miniters=100) as bar:
        tasks = [asyncio.create_task(check(ip)) for ip in ips]
        for t in asyncio.as_completed(tasks):
            await t
            bar.update(1)
            bar.set_postfix(hits=len(hits), refresh=False)

    return hits


def _cidrs_to_ips(cidrs: list[str]) -> list[str]:
    """Expand a list of IPv4 CIDRs to individual host IP strings."""
    ips: list[str] = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.version == 4:
                ips.extend(str(h) for h in net.hosts())
        except ValueError:
            continue
    return ips


def _count_ips(cidrs: list[str]) -> int:
    """Count total hosts across CIDRs without allocating strings."""
    total = 0
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.version == 4:
                total += net.num_addresses - 2  # exclude network/broadcast
        except ValueError:
            pass
    return max(total, 0)


def _run_two_phase_scan(
    domain: str,
    cidrs: list[str],
    port: int,
    concurrency: int,
    tcp_timeout: float,
    tls_timeout: float,
    rate: int,
) -> tuple[str, int, list[dict]]:
    """
    Run phase 1 (TCP open check) + phase 2 (TLS cert match) against cidrs.
    Returns (phase1_method, open_port_count, hits).

    Defers CIDR→IP expansion until after masscan is attempted — masscan takes
    the CIDR file directly so expansion is only needed for the asyncio fallback.
    """
    masscan_result = _masscan_phase1(cidrs, port, rate=rate)
    if masscan_result is not None:
        open_ips = masscan_result
        log(f"masscan complete: {len(open_ips):,} hosts have port {port} open")
        phase1_method = "masscan"
    else:
        all_ips = _cidrs_to_ips(cidrs)
        log(f"Phase 1: async TCP on {len(all_ips):,} IPs — {concurrency} concurrent, {tcp_timeout}s timeout")
        open_ips = asyncio.run(_phase1_async(all_ips, port, tcp_timeout, concurrency))
        log(f"Phase 1 complete: {len(open_ips):,} hosts have port {port} open")
        phase1_method = "asyncio"

    if not open_ips:
        return phase1_method, 0, []

    log(f"Phase 2: TLS cert check on {len(open_ips):,} responsive hosts")
    hits = asyncio.run(_phase2_async(open_ips, domain, port, tls_timeout, concurrency))
    return phase1_method, len(open_ips), hits


def _masscan_phase1(cidrs: list[str], port: int, rate: int) -> list[str] | None:
    """
    Use masscan for phase 1 if available — orders of magnitude faster than
    async TCP. Returns list of open IPs, or None if masscan is not installed.

    Install:  sudo apt install masscan
    Fix perms: sudo setcap cap_net_raw+ep $(which masscan)
    """
    if not shutil.which("masscan"):
        return None

    # Write CIDRs to a file to avoid shell arg-length limits with large region sets
    with tempfile.NamedTemporaryFile(suffix=".ranges", delete=False, mode="w") as rf:
        rf.write("\n".join(cidrs))
        ranges_file = rf.name

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as of:
        outfile = of.name

    base_cmd = [
        "-p", str(port),
        "--includefile", ranges_file,
        "--rate", str(rate),
        "-oL", outfile,
        "--wait", "3",
    ]

    # masscan needs raw socket access (raw packets).
    # The cleanest fix is a one-time capability grant — no sudo required after that:
    #   sudo setcap cap_net_raw+ep $(which masscan)
    #
    # Both stdout and stderr inherit the terminal so masscan's live status
    # (rate, progress, ETA) prints directly with no buffering issues.
    cmd = ["masscan"] + base_cmd
    log(f"masscan -p{port} --includefile {ranges_file} --rate {rate} ...")
    proc = subprocess.run(cmd)
    if proc.returncode != 0:
        log("masscan exited with an error (see output above) — falling back to async TCP scan")
        log("  If you saw a permission error, run once: sudo setcap cap_net_raw+ep $(which masscan)")
        return None

    open_ips: list[str] = []
    try:
        with open(outfile) as f:
            for line in f:
                if line.startswith("open"):
                    parts = line.split()
                    # format: open tcp 443 1.2.3.4 <timestamp>
                    if len(parts) >= 4:
                        open_ips.append(parts[3])
    except Exception:
        pass

    return open_ips


def targeted_origin_scan(
    domain: str,
    cert_issuers: list[str],
    regions: list[str] | None = None,
    force: bool = False,
    port: int = 443,
    concurrency: int = 5_000,
    tcp_timeout: float = 0.2,
    tls_timeout: float = 4.0,
    *,
    rate: int,
) -> dict:
    """
    Two-phase scan to find the origin server behind Cloudflare.

    Phase 1 — fast port check across target IP ranges.
               Uses masscan if installed (sudo apt install masscan), otherwise
               falls back to async TCP connects (5000 concurrent, 0.2s timeout).
    Phase 2 — async TLS handshake on responsive hosts only, checking cert
               CN and SANs for a match against domain.

    regions=None  → scan every GCP region globally (--scan-all).
    force=True    → skip the GTS-cert heuristic and scan regardless (--scan-europe).
    """
    result: dict = {
        "strategy":        None,
        "phase1_method":   None,
        "regions":         [],
        "cidrs_scanned":   0,
        "hosts_attempted": 0,
        "open_port_count": 0,
        "hits":            [],
    }

    gts_family = {"GTS CA 1P5", "GTS CA 1C3", "GTS CA 1D4", "GTS Root R1"}
    if regions is None:
        # --scan-all: scan every GCP region, bypass heuristic
        scan_regions = None
    elif force:
        # --scan-europe (or explicit region list): bypass heuristic
        scan_regions = regions
    elif not (set(cert_issuers) & gts_family):
        result["strategy"] = "skipped"
        result["reason"]   = "No GTS cert in history — no targeted range to scan. Re-run with --scan-europe or --scan-all to force a scan."
        return result
    else:
        scan_regions = regions if regions else GCP_DEFAULT_REGIONS

    result["strategy"] = "gcp"
    result["regions"]  = scan_regions or ["(all GCP)"]

    label = "ALL GCP regions" if scan_regions is None else f"{len(scan_regions)} regions"
    log(f"Fetching GCP IP ranges for: {label}")
    cidrs = fetch_gcp_ip_ranges(scan_regions)
    if not cidrs:
        result["strategy"] = "error"
        result["reason"]   = "Failed to fetch GCP IP ranges"
        return result

    result["cidrs_scanned"]   = len(cidrs)
    result["hosts_attempted"] = _count_ips(cidrs)

    method, open_count, hits = _run_two_phase_scan(domain, cidrs, port, concurrency, tcp_timeout, tls_timeout, rate=rate)
    result["phase1_method"]   = method
    result["open_port_count"] = open_count
    result["hits"]            = hits
    return result


# ── ASN provider scan ────────────────────────────────────────────────────────

def targeted_asn_scan(
    domain: str,
    asns: list[str] | None = None,
    port: int = 443,
    concurrency: int = 5_000,
    tcp_timeout: float = 0.2,
    tls_timeout: float = 4.0,
    *,
    rate: int,
) -> dict:
    """
    Two-phase scan across hosting provider IP ranges fetched live from RIPE Stat.

    asns=None uses the built-in PROVIDER_ASNS list. Pass a custom list of ASN
    strings (e.g. ["AS24940", "AS9009"]) to target specific providers.
    """
    scan_asns = asns if asns is not None else list(PROVIDER_ASNS.keys())

    result: dict = {
        "strategy":        "asn",
        "phase1_method":   None,
        "asns_scanned":    scan_asns,
        "cidrs_scanned":   0,
        "hosts_attempted": 0,
        "open_port_count": 0,
        "hits":            [],
    }

    log(f"Fetching IP ranges for {len(scan_asns)} ASNs via RIPE Stat...")
    asn_ranges = fetch_asn_ip_ranges(scan_asns)
    if not asn_ranges:
        result["strategy"] = "error"
        result["reason"]   = "No IP ranges returned from RIPE Stat"
        return result

    cidrs: list[str] = [cidr for ranges in asn_ranges.values() for cidr in ranges]
    result["cidrs_scanned"]   = len(cidrs)
    result["hosts_attempted"] = _count_ips(cidrs)

    for asn, name in PROVIDER_ASNS.items():
        if asn in asn_ranges:
            log(f"  {asn:12s} {name}  ({len(asn_ranges[asn])} prefixes)")
    log(f"Total IPs to scan: {result['hosts_attempted']:,}")

    method, open_count, hits = _run_two_phase_scan(domain, cidrs, port, concurrency, tcp_timeout, tls_timeout, rate=rate)
    result["phase1_method"]   = method
    result["open_port_count"] = open_count
    result["hits"]            = hits
    return result


# ── Country IP scan ───────────────────────────────────────────────────────────

def targeted_country_scan(
    domain: str,
    country_codes: list[str],
    port: int = 443,
    concurrency: int = 5_000,
    tcp_timeout: float = 0.2,
    tls_timeout: float = 4.0,
    *,
    rate: int,
) -> dict:
    """
    Two-phase scan across all IPv4 space allocated to one or more countries.
    IP ranges are fetched live from RIPE Stat (free, no key required).

    At 100k pps with masscan:
      Russia (~40M IPs)  ≈ 7 min
      Ukraine (~8M IPs)  ≈ 2 min
    """
    result: dict = {
        "strategy":        "country",
        "phase1_method":   None,
        "countries":       country_codes,
        "cidrs_scanned":   0,
        "hosts_attempted": 0,
        "open_port_count": 0,
        "hits":            [],
    }

    all_cidrs: list[str] = []
    for cc in country_codes:
        log(f"Fetching IPv4 ranges for {cc.upper()} via RIPE Stat...")
        cidrs = fetch_country_ip_ranges(cc)
        log(f"  {cc.upper()}: {len(cidrs):,} prefixes  (~{_count_ips(cidrs):,} IPs)")
        all_cidrs.extend(cidrs)

    if not all_cidrs:
        result["strategy"] = "error"
        result["reason"]   = f"No IP ranges returned for: {country_codes}"
        return result

    result["cidrs_scanned"]   = len(all_cidrs)
    result["hosts_attempted"] = _count_ips(all_cidrs)
    log(f"Total: {result['cidrs_scanned']:,} prefixes, {result['hosts_attempted']:,} IPs")

    method, open_count, hits = _run_two_phase_scan(domain, all_cidrs, port, concurrency, tcp_timeout, tls_timeout, rate=rate)
    result["phase1_method"]   = method
    result["open_port_count"] = open_count
    result["hits"]            = hits
    return result


# ── Reverse IP via hackertarget ───────────────────────────────────────────────



# ── WHOIS ─────────────────────────────────────────────────────────────────────





# ── Per-IP enrichment (used for IPs resolved from a domain) ───────────────────



# ── Page metadata / FIMI signals ─────────────────────────────────────────────

_PAGE_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


_SOCIAL_DEFS = [
    ("telegram",       r'https?://t\.me/([A-Za-z0-9_]{3,60})'),
    ("vkontakte",      r'https?://(?:www\.)?vk\.com/([^\s"\'<>/?]{2,80})'),
    ("odnoklassniki",  r'https?://(?:www\.)?ok\.ru/(?:profile/|group/)?([^\s"\'<>/?]{2,80})'),
    ("odnoklassniki",  r'https?://(?:www\.)?odnoklassniki\.ru/([^\s"\'<>/?]{2,80})'),
    ("twitter_x",      r'https?://(?:www\.)?(?:twitter|x)\.com/(?!search|share|intent|home)([^\s"\'<>/?]{2,60})'),
    ("tiktok",         r'https?://(?:www\.)?tiktok\.com/@([A-Za-z0-9_.]{2,60})'),
    ("instagram",      r'https?://(?:www\.)?instagram\.com/([^\s"\'<>/?]{2,60})'),
    ("facebook",       r'https?://(?:www\.)?facebook\.com/(?!sharer|share|dialog|tr\b)([^\s"\'<>/?]{2,80})'),
    ("youtube",        r'https?://(?:www\.)?youtube\.com/(?:channel/|@)([^\s"\'<>/?]{2,80})'),
    ("linkedin",       r'https?://(?:www\.)?linkedin\.com/(?:company|in)/([^\s"\'<>/?]{2,80})'),
    ("pinterest",      r'https?://(?:www\.)?pinterest\.(?:com|[a-z]{2})/([^\s"\'<>/?]{2,80})'),
]
_SOCIAL_NOISE = {"", "home", "login", "signup", "help", "support", "about", "contact"}








# ── Main analysis functions ───────────────────────────────────────────────────

# ── Async helpers ─────────────────────────────────────────────────────────────

_HTTPX_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0)






_CRT_SH_FAILED = {**_CRT_SH_EMPTY, "_failed": True}


async def _acertspotter_data(domain: str, client: httpx.AsyncClient) -> dict:
    """Async Cert Spotter fallback — same normalization as certspotter_data().
    Returns _CRT_SH_FAILED (so the crt.sh retry sweep still kicks in) only when
    Cert Spotter yields nothing either."""
    issuances: list = []
    after: str | None = None
    try:
        for _ in range(CERTSPOTTER_MAX_PAGES):
            resp = await client.get(
                CERTSPOTTER_API_URL,
                params=_certspotter_params(domain, after),
                headers=_certspotter_headers(),
                timeout=30.0,
            )
            if resp.status_code != 200:
                if issuances:
                    break  # keep the pages we already collected
                log(f"Cert Spotter HTTP {resp.status_code}")
                return dict(_CRT_SH_FAILED)
            page = resp.json()
            if not isinstance(page, list) or not page:
                break
            issuances.extend(page)
            last_id = page[-1].get("id") if isinstance(page[-1], Mapping) else None
            if not last_id:
                break
            after = str(last_id)
    except Exception as exc:
        if not issuances:
            log(f"Cert Spotter failed: {exc}")
            return dict(_CRT_SH_FAILED)
    result = _parse_crt_sh_entries(_certspotter_to_crt_sh_entries(issuances), domain)
    result["ct_source"] = "certspotter"
    return result


async def _acrt_sh_data(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get("https://crt.sh/", params={"q": domain, "output": "json"}, headers={"Accept": "application/json"}, timeout=30.0)
        if resp.status_code != 200:
            log(f"crt.sh HTTP {resp.status_code} — falling back to Cert Spotter")
            return await _acertspotter_data(domain, client)
        result = _parse_crt_sh_entries(resp.json(), domain)
        result["ct_source"] = "crt.sh"
        return result
    except Exception as exc:
        log(f"crt.sh failed ({exc}) — falling back to Cert Spotter")
        return await _acertspotter_data(domain, client)






_RATE_LIMITED = "__rate_limited__"





# Anchored to specific Google/Meta/Yandex endpoints, so unlike GA_PROPERTY_RE
# these do not need a strict boundary or an exact ID length to be safe — an
# `id=` inside `googletagmanager.com/gtag/js` is a measurement ID by
# construction. The length bounds stay deliberately loose here so a real ID
# that does not happen to be 10 characters is still captured from a URL where
# it cannot be anything else.
_URLSCAN_ANALYTICS_PATTERNS: list[tuple[str, re.Pattern]] = [
    # GA4 gtag loader URL:  /gtag/js?id=G-XXXXXX
    ("ga",             re.compile(r'googletagmanager\.com/gtag/js\?id=(G-[A-Z0-9]{6,12})')),
    # GA4 collect calls:    /g/collect?...&tid=G-XXXXXX
    ("ga",             re.compile(r'google-analytics\.com/[^?]*collect\?[^"\']*?tid=(G-[A-Z0-9]{6,12})')),
    # Universal Analytics:  /collect?...&tid=UA-XXXXX-X
    ("ga",             re.compile(r'google-analytics\.com/[^?]*collect\?[^"\']*?tid=(UA-\d{4,12}-\d{1,3})')),
    # GTM loader:           /gtm.js?id=GTM-XXXXX
    ("gtm",            re.compile(r'googletagmanager\.com/gtm\.js\?id=(GTM-[A-Z0-9]{4,8})')),
    # Facebook Pixel:       /tr/?id=XXXXXXXXXX  (id= may be the first param)
    ("fb_pixel",       re.compile(r'facebook\.com/tr/?\?(?:[^"\']*?[?&])?id=(\d{10,20})')),
    # Yandex Metrika:       mc.yandex.*/watch/XXXXXXXX
    ("yandex_metrika", re.compile(r'mc\.yandex\.(?:ru|com)/watch/(\d{5,12})')),
    # TikTok pixel events:  analytics.tiktok.com/...?sdkid=XXXXX
    ("tiktok_pixel",   re.compile(r'analytics\.tiktok\.com[^"\']*?[?&](?:sdkid|pixel_id)=([A-Z0-9]{15,25})')),
]

# Keys that map urlscan analytics output -> page_metadata field names
_URLSCAN_ANALYTICS_KEY_MAP = {
    "ga":             "google_analytics",
    "gtm":            "gtm_ids",
    "fb_pixel":       "facebook_pixel",
    "yandex_metrika": "yandex_metrika",
    "tiktok_pixel":   "tiktok_pixel",
}












# ── Entry point ───────────────────────────────────────────────────────────────



