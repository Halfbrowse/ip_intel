#!/usr/bin/env python3
"""
ip_intel.py — Domain / IP intelligence tool

Usage:
    uv run ip_intel.py <domain or IP>

Sources (all free, no API keys required by default):
    - dnspython   : DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME, PTR)
    - python-whois: Domain and IP WHOIS
    - ipwhois     : IP ASN / network info via RDAP
    - crt.sh      : Subdomain discovery + full cert transparency data (SANs, issuers)
    - hackertarget: Reverse IP lookup — skipped automatically for Cloudflare IPs
    - CIRCL pDNS  : Passive / historical DNS records (pdns.circl.lu)
    - Origin probe: Resolves crt.sh subdomains and flags any that bypass Cloudflare
    - Censys      : Searches indexed TLS certs for IPs serving the domain's cert
                    (optional — set CENSYS_API_KEY in .env)
    - Shodan      : Searches indexed banners for ssl:"domain" hits
                    (optional — set SHODAN_API_KEY in .env)
    - Netlas      : Searches indexed TLS banners by cert CN — free tier available
                    (optional — set NETLAS_API_KEY in .env)
    - Origin scan : Two-phase TCP+TLS scan of targeted IP ranges (e.g. GCP) to
                    find the cert CN directly. Opt-in via --scan flag.
"""

import asyncio
import hashlib
import json
import os
import shutil
import ssl
import socket
import subprocess
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from dotenv import load_dotenv
load_dotenv()
import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path

import dns.asyncresolver
import dns.resolver
import dns.reversename
import dns.zone
import dns.query
import dns.exception
import httpx
import requests
import whois
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError
from cryptography import x509
from cryptography.x509.oid import NameOID
from tqdm import tqdm

from signal_dns import (
    acollect_spf_details,
    aget_email_security_records,
    aprobe_microsoft_tenant,
    collect_spf_details,
    extract_txt_tenancy_tokens,
    get_email_security_records,
    parse_caa_records,
    probe_microsoft_tenant_sync,
)
from signal_transport import fetch_ssh_host_key, fetch_tls_certificate, parse_certificate_der
from signal_web import (
    extract_page_enrichment,
    afetch_homepage_profile,
    afetch_mail_client_config,
    afetch_well_known_artifacts,
    ascrape_legal_pages,
)


RESULTS_DIR = Path(__file__).parent / "results"
CONFIG_DIR = Path(__file__).parent / "config"
_LOG_CONTEXT = threading.local()
_URLSCAN_GATE = threading.Semaphore(max(1, int(os.getenv("URLSCAN_MAX_PARALLEL", "1"))))


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


def set_log_handler(handler) -> object:
    """
    Attach a log callback for the current worker thread.

    Returns a token that can be passed back to reset_log_handler() to restore
    the previous handler once the caller is done.
    """
    previous = getattr(_LOG_CONTEXT, "handler", None)
    _LOG_CONTEXT.handler = handler
    return previous


def reset_log_handler(token: object) -> None:
    """Restore the previous per-thread log callback returned by set_log_handler()."""
    if token is None:
        if hasattr(_LOG_CONTEXT, "handler"):
            delattr(_LOG_CONTEXT, "handler")
        return
    _LOG_CONTEXT.handler = token


def clean_target(target: str) -> str:
    """Strip protocol prefix and trailing slashes so bare hostnames/IPs remain."""
    target = re.sub(r'^https?://', '', target)
    return target.rstrip('/').strip()


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
    raw = _load_json(CONFIG_DIR / "proxy_rules.json", [])
    rules: list[dict[str, object]] = []
    for entry in raw if isinstance(raw, list) else []:
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
    text_fields = [
        ptr,
        asn_info.get("asn_description"),
        asn_info.get("network_name"),
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
        for value in (asn_info.get("asn_description"), asn_info.get("network_name"))
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
        asn_hit = bool(norm_asn and norm_asn in rule["asns"])
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
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 8
    ips: list[str] = []
    for rtype in ("A", "AAAA"):
        try:
            ips.extend(str(r) for r in resolver.resolve(hostname, rtype))
        except Exception:
            pass
    return ips


# ── DNS ───────────────────────────────────────────────────────────────────────

def get_dns_records(domain: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    def _resolve(rtype: str) -> tuple[str, object]:
        try:
            answers = resolver.resolve(domain, rtype)
            if rtype == "MX":
                return rtype, [
                    {"preference": r.preference, "exchange": str(r.exchange).rstrip(".")}
                    for r in answers
                ]
            if rtype == "SOA":
                r = answers[0]
                return rtype, {
                    "mname":   str(r.mname).rstrip("."),
                    "rname":   str(r.rname).rstrip("."),
                    "serial":  int(r.serial),
                    "refresh": int(r.refresh),
                    "retry":   int(r.retry),
                    "expire":  int(r.expire),
                    "minimum": int(r.minimum),
                }
            if rtype == "NS":
                return rtype, sorted(str(r).rstrip(".") for r in answers)
            if rtype == "TXT":
                return rtype, [
                    b"".join(r.strings).decode("utf-8", errors="replace")
                    for r in answers
                ]
            return rtype, [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return rtype, []
        except dns.exception.DNSException as exc:
            return rtype, {"error": str(exc)}

    rtypes = ("A", "AAAA", "CAA", "CNAME", "MX", "NS", "TXT", "SOA")
    with ThreadPoolExecutor(max_workers=len(rtypes)) as ex:
        return dict(ex.map(_resolve, rtypes))


def get_ptr(ip: str) -> str | None:
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, "PTR", lifetime=5)
        return str(answers[0]).rstrip(".")
    except Exception:
        return None


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

    for entry in entries:
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


def crt_sh_data(domain: str) -> dict:
    """
    Query crt.sh for full certificate transparency data.

    Returns subdomains, cert metadata, and cross-domain SANs — names that appear
    in the same certificate as the target domain but belong to a different domain.
    Cross-domain SANs are a strong signal for shared hosting / origin server
    infrastructure that may not be visible via reverse-IP lookups.
    """
    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": domain, "output": "json"},
            timeout=20,
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            return dict(_CRT_SH_EMPTY)
        return _parse_crt_sh_entries(resp.json(), domain)
    except Exception:
        return dict(_CRT_SH_EMPTY)


# ── Historical / Passive DNS via CIRCL ────────────────────────────────────────

def circl_passive_dns(domain: str) -> dict:
    """
    Query CIRCL Passive DNS (pdns.circl.lu) for historical DNS records.

    Returns historical A/AAAA records with first-seen / last-seen timestamps.
    IPs that pre-date the current Cloudflare records may be the true origin servers.
    No API key required.
    """
    result: dict = {"records": [], "unique_historical_ips": []}
    try:
        resp = requests.get(
            f"https://www.circl.lu/pdns/query/{domain}",
            timeout=15,
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            return result

        records: list[dict] = []
        seen_ips: set[str] = set()

        # Response is newline-delimited JSON
        for line in resp.text.strip().splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            rrtype = entry.get("rrtype", "")
            rdata  = entry.get("rdata", "")

            records.append({
                "rrtype":     rrtype,
                "rdata":      rdata,
                "first_seen": entry.get("time_first_ms") or entry.get("time_first"),
                "last_seen":  entry.get("time_last_ms")  or entry.get("time_last"),
                "count":      entry.get("count"),
            })

            if rrtype in ("A", "AAAA") and rdata:
                seen_ips.add(rdata)

        result["records"]               = records
        result["unique_historical_ips"] = sorted(seen_ips)

    except Exception:
        pass

    return result


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
    with ThreadPoolExecutor(max_workers=len(candidates)) as ex:
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

def extract_spf_origins(txt_records: list) -> list[dict]:
    """
    Parse SPF TXT records and extract ip4:/ip6: directives as origin candidates.
    No extra network call — operates on already-fetched TXT records.
    """
    return collect_spf_details("__seed__", txt_records).get("origins", [])


# ── HackerTarget host search ──────────────────────────────────────────────────

def hackertarget_host_search(domain: str) -> list[dict]:
    """
    Query HackerTarget hostsearch for subdomains and their IPs.
    Different from reverse-IP lookup — this goes domain → subdomains+IPs
    and surfaces non-Cloudflare addresses directly.
    """
    try:
        resp = requests.get(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": domain},
            timeout=15,
        )
        if resp.status_code != 200:
            return []
        text = resp.text.strip()
        if "error" in text.lower() or "API count" in text:
            return []
        results: list[dict] = []
        for line in text.splitlines():
            parts = line.strip().split(",")
            if len(parts) == 2:
                subdomain, ip = parts[0].strip(), parts[1].strip()
                if ip:
                    results.append({
                        "subdomain": subdomain,
                        "ip":        ip,
                        "cf":        is_cloudflare_ip(ip),
                        "source":    "HackerTarget hostsearch",
                    })
        return results
    except Exception:
        return []


# ── urlscan.io historical IPs ─────────────────────────────────────────────────

def urlscan_historical_ips(domain: str) -> list[dict]:
    """
    Query urlscan.io for historical scan results and extract IPs seen serving
    the domain. Pre-Cloudflare snapshots often reveal the real origin IP.
    No API key required for basic search.
    """
    try:
        resp = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": "100"},
            timeout=15,
            headers={"User-Agent": "ip-intel/1.0 (OSINT research)"},
        )
        if resp.status_code != 200:
            return []
        seen: set[str] = set()
        results: list[dict] = []
        for hit in resp.json().get("results", []):
            ip   = hit.get("page", {}).get("ip", "")
            date = hit.get("task", {}).get("time", "")[:10]
            if ip and ip not in seen:
                seen.add(ip)
                results.append({
                    "ip":     ip,
                    "date":   date,
                    "url":    hit.get("page", {}).get("url", ""),
                    "cf":     is_cloudflare_ip(ip),
                    "source": "urlscan.io",
                })
        return results
    except Exception:
        return []


# ── Censys cert search ────────────────────────────────────────────────────────

def censys_cert_search(domain: str) -> dict:
    """
    Search Censys Platform for hosts currently serving a TLS cert whose CN
    matches the target domain. Any result that isn't a Cloudflare IP is a
    candidate origin server.

    Requires a free Censys account — add to .env:
        CENSYS_API_KEY=<personal-access-token>
    """
    api_key = os.environ.get("CENSYS_API_KEY")

    if not api_key:
        return {"skipped": True, "reason": "CENSYS_API_KEY not set in .env"}

    from censys_platform import SDK

    result: dict = {"hits": [], "origin_candidates": []}
    try:
        with SDK(personal_access_token=api_key) as sdk:
            query = f'host.services.tls.leaf_certificate.subject.common_name = "{domain}"'
            resp = sdk.global_data.search(search_query_input_body={
                "query":     query,
                "fields":    ["host.ip", "host.autonomous_system", "host.location", "host.services"],
                "page_size": 100,
            })

        for record in (resp.search_response.results or []):
            ip = getattr(record, "ip", None) or (
                record.get("host", {}).get("ip") if isinstance(record, dict) else None
            )
            if not ip:
                continue

            asn_block  = getattr(record, "autonomous_system", None) or {}
            loc_block  = getattr(record, "location", None) or {}
            svc_block  = getattr(record, "services", None) or []

            if isinstance(asn_block, dict):
                asn      = asn_block.get("asn")
                asn_name = asn_block.get("description")
            else:
                asn      = getattr(asn_block, "asn", None)
                asn_name = getattr(asn_block, "description", None)

            if isinstance(loc_block, dict):
                country = loc_block.get("country_code")
            else:
                country = getattr(loc_block, "country_code", None)

            services = []
            for s in svc_block:
                port  = s.get("port")  if isinstance(s, dict) else getattr(s, "port", None)
                proto = s.get("transport_protocol", "") if isinstance(s, dict) else getattr(s, "transport_protocol", "")
                if port:
                    services.append(f"{port}/{str(proto).lower()}")

            entry = {
                "ip":         ip,
                "cloudflare": is_cloudflare_ip(ip),
                "asn":        asn,
                "asn_name":   asn_name,
                "country":    country,
                "services":   services,
            }
            result["hits"].append(entry)
            if not entry["cloudflare"]:
                result["origin_candidates"].append(entry)

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ── Shodan cert search ───────────────────────────────────────────────────────

def shodan_cert_search(domain: str) -> dict:
    """
    Search Shodan for hosts whose TLS banner matches the target domain using
    the ssl:"domain" filter. Returns all hits with ASN, org, country, and open
    ports. Any non-Cloudflare result is a candidate origin server.

    Requires a free Shodan account — add to .env:
        SHODAN_API_KEY=<your-api-key>
    """
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return {"skipped": True, "reason": "SHODAN_API_KEY not set in .env"}

    import shodan

    result: dict = {"hits": [], "origin_candidates": []}
    try:
        api = shodan.Shodan(api_key)
        resp = api.search(f'ssl:"{domain}"', minify=False)

        for match in resp.get("matches", []):
            ip = match.get("ip_str")
            if not ip:
                continue

            loc = match.get("location", {})
            entry = {
                "ip":         ip,
                "cloudflare": is_cloudflare_ip(ip),
                "asn":        match.get("asn"),
                "org":        match.get("org"),
                "country":    loc.get("country_code"),
                "ports":      match.get("ports", []),
                "hostnames":  match.get("hostnames", []),
            }
            result["hits"].append(entry)
            if not entry["cloudflare"]:
                result["origin_candidates"].append(entry)

        result["total"] = resp.get("total", len(result["hits"]))

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ── Netlas cert search ───────────────────────────────────────────────────────

def netlas_cert_search(domain: str) -> dict:
    """
    Search Netlas for hosts whose TLS response includes a cert with the target
    domain as the CN. Netlas has a free tier (~50 queries/day, no credit card).

    Requires a free Netlas account — add to .env:
        NETLAS_API_KEY=<your-api-key>
    """
    api_key = os.environ.get("NETLAS_API_KEY")
    if not api_key:
        return {"skipped": True, "reason": "NETLAS_API_KEY not set in .env"}

    import netlas

    result: dict = {"hits": [], "origin_candidates": []}
    try:
        conn  = netlas.Netlas(api_key=api_key)
        query = f'certificate.subject.common_name:"{domain}"'
        resp  = conn.query(query=query, datatype="response", page=0)

        for item in (resp or {}).get("items", []):
            data = item.get("data", {})
            ip   = data.get("ip")
            if not ip:
                continue

            entry = {
                "ip":         ip,
                "cloudflare": is_cloudflare_ip(ip),
                "port":       data.get("port"),
                "protocol":   data.get("protocol"),
                "asn":        data.get("asn", {}).get("asn") if isinstance(data.get("asn"), dict) else data.get("asn"),
                "org":        data.get("asn", {}).get("org")  if isinstance(data.get("asn"), dict) else None,
                "country":    data.get("geo", {}).get("country") if isinstance(data.get("geo"), dict) else None,
            }
            result["hits"].append(entry)
            if not entry["cloudflare"]:
                result["origin_candidates"].append(entry)
    except Exception as exc:
        result["error"] = str(exc)

    return result


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
        resp = requests.get(GCP_IP_RANGES_URL, timeout=15)
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


def grab_tls_cert(
    ip: str,
    sni: str | None = None,
    port: int = 443,
    timeout: float = 5.0,
) -> dict | None:
    """
    Grab a TLS certificate directly from ip:port without hostname verification.

    sni is used as the TLS SNI / server_hostname hint.  When None the IP itself
    is used as the hostname so at least SNI is attempted even without a domain.

    Returns a dict with full cert metadata, or None if the connection fails
    or the peer presents no certificate.
    """
    return fetch_tls_certificate(ip, sni=sni, port=port, timeout=timeout)


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

def hackertarget_reverse_ip(ip: str) -> list[str]:
    try:
        resp = requests.get(
            "https://api.hackertarget.com/reverseiplookup/",
            params={"q": ip},
            timeout=15,
        )
        if resp.status_code != 200:
            return []
        text = resp.text.strip()
        if "error" in text.lower() or "API count" in text:
            return []
        return [line.strip() for line in text.splitlines() if line.strip()]
    except Exception:
        return []


# ── WHOIS ─────────────────────────────────────────────────────────────────────

def get_domain_whois(domain: str) -> dict:
    try:
        w = whois.whois(domain)

        def _fmt(v):
            if v is None:
                return None
            if isinstance(v, list):
                seen = []
                for item in v:
                    s = str(item)
                    if s not in seen:
                        seen.append(s)
                return seen
            return str(v)

        return {
            "registrar":     _fmt(w.registrar),
            "creation_date": _fmt(w.creation_date),
            "expiry_date":   _fmt(w.expiration_date),
            "updated_date":  _fmt(w.updated_date),
            "nameservers":   _fmt(w.name_servers),
            "status":        _fmt(w.status),
            "emails":        _fmt(w.emails),
            "org":           _fmt(w.org),
            "country":       _fmt(w.country),
        }
    except Exception as exc:
        return {"error": str(exc)}


def get_ip_whois(ip: str) -> dict:
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        net = result.get("network", {})
        return {
            "asn":             result.get("asn"),
            "asn_description": result.get("asn_description"),
            "asn_country":     result.get("asn_country_code"),
            "asn_cidr":        result.get("asn_cidr"),
            "asn_registry":    result.get("asn_registry"),
            "network_name":    net.get("name"),
            "network_cidr":    net.get("cidr"),
            "network_country": net.get("country"),
        }
    except IPDefinedError:
        return {"error": "Private/reserved IP address — no public WHOIS"}
    except Exception as exc:
        return {"error": str(exc)}


# ── Per-IP enrichment (used for IPs resolved from a domain) ───────────────────

def enrich_ip(ip: str) -> dict:
    cf = is_cloudflare_ip(ip)

    ptr = get_ptr(ip)

    if cf:
        asn_info = {"asn_description": "Cloudflare, Inc.", "asn_country": "US", "note": "Cloudflare anycast — RDAP skipped"}
        other_domains = []
    else:
        asn_info = get_ip_whois(ip)
        other_domains = hackertarget_reverse_ip(ip)

    proxy_details = detect_proxy_details(ip, ptr, asn_info)

    return {
        "ptr":                 ptr,
        "cloudflare":          cf,
        "asn_info":            asn_info,
        "other_domains_on_ip": other_domains,
        "proxy_family":        proxy_details.get("proxy_family"),
        "proxy_confidence":    proxy_details.get("proxy_confidence"),
    }


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


def _process_page_html(html: str) -> dict:
    """Pure extraction of FIMI signals from raw HTML — no I/O."""
    out: dict = {
        "google_analytics": [],
        "gtm_ids":          [],
        "facebook_pixel":   [],
        "tiktok_pixel":     [],
        "yandex_metrika":   [],
        "html_lang":        None,
        "cms_generator":    None,
        "social_links":     {},
        "social_handles":   {},
        "adsense_publisher_ids": [],
        "fb_app_id":        [],
        "twitter_site":     [],
        "twitter_creator":  [],
        "authors":          [],
        "rel_me":           [],
        "homepage_html_hash": None,
        "meta_tags":        {},
        "script_assets":    [],
        "bundler_hints":    [],
    }
    if not html:
        return out

    m = re.search(r'<html[^>]+\blang=["\']([^"\']{2,10})["\']', html, re.I)
    if m:
        out["html_lang"] = m.group(1).lower()

    ga = re.findall(r'\b(UA-\d{4,12}-\d{1,3}|G-[A-Z0-9]{6,12}|AW-[0-9]{8,12})\b', html)
    out["google_analytics"] = sorted(set(ga))

    gtm = re.findall(r'\b(GTM-[A-Z0-9]{4,8})\b', html)
    out["gtm_ids"] = sorted(set(gtm))

    fb = re.findall(r'fbq\(["\']init["\'],\s*["\'](\d{10,20})["\']', html)
    out["facebook_pixel"] = sorted(set(fb))

    tt = re.findall(r'ttq\.load\(["\']([A-Z0-9]{15,25})["\']', html)
    out["tiktok_pixel"] = sorted(set(tt))

    ym  = re.findall(r'\bym\((\d{5,12})\s*,', html)
    ym2 = re.findall(r'metrika\.yandex\.(?:com|ru)/watch/(\d{5,12})', html)
    out["yandex_metrika"] = sorted(set(ym + ym2))

    cm = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']'
        r'|<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
        html, re.I,
    )
    if cm:
        out["cms_generator"] = (cm.group(1) or cm.group(2) or "").strip()

    social_links: dict[str, list[str]] = {}
    social_handles: dict[str, list[str]] = {}
    for key, pattern in _SOCIAL_DEFS:
        for m2 in re.finditer(pattern, html, re.I):
            full_url = m2.group(0).rstrip("/?")
            handle   = m2.group(1).rstrip("/?")
            if handle.lower() in _SOCIAL_NOISE:
                continue
            social_links.setdefault(key, [])
            if full_url not in social_links[key]:
                social_links[key].append(full_url)
            social_handles.setdefault(key, [])
            if handle not in social_handles[key]:
                social_handles[key].append(handle)

    out["social_links"]   = {k: sorted(set(v)) for k, v in social_links.items()}
    out["social_handles"] = {k: sorted(set(v)) for k, v in social_handles.items()}
    out.update(extract_page_enrichment(html))
    return out


def fetch_page_metadata(domain: str, save_favicon_as: Path | None = None) -> dict:
    """
    Fetch the domain homepage and extract FIMI-relevant signals:
    Google Analytics / GTM / Facebook Pixel / TikTok Pixel / Yandex.Metrika IDs,
    HTML lang attribute, CMS generator, social links + handles, and favicon MD5.
    """
    async def _run() -> dict:
        async with httpx.AsyncClient(timeout=_HTTPX_TIMEOUT, follow_redirects=True) as client:
            return await _afetch_page_metadata(domain, client, save_favicon_as)

    return asyncio.run(_run())


def get_dmarc_dkim(domain: str) -> dict:
    """
    Look up DMARC policy and DKIM public keys for common selectors.
    Useful for attributing operators via mail infrastructure.
    """
    return get_email_security_records(domain)


# ── Main analysis functions ───────────────────────────────────────────────────

# ── Async helpers ─────────────────────────────────────────────────────────────

_HTTPX_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0)


async def _aget_dns_records(domain: str) -> dict:
    """True-async DNS resolution using dns.asyncresolver (no threads)."""
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    async def _resolve(rtype: str):
        try:
            answers = await resolver.resolve(domain, rtype)
            if rtype == "MX":
                return rtype, [{"preference": r.preference, "exchange": str(r.exchange).rstrip(".")} for r in answers]
            if rtype == "SOA":
                r = answers[0]
                return rtype, {"mname": str(r.mname).rstrip("."), "rname": str(r.rname).rstrip("."), "serial": int(r.serial), "refresh": int(r.refresh), "retry": int(r.retry), "expire": int(r.expire), "minimum": int(r.minimum)}
            if rtype == "NS":
                return rtype, sorted(str(r).rstrip(".") for r in answers)
            if rtype == "TXT":
                return rtype, [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
            return rtype, [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return rtype, []
        except dns.exception.DNSException as exc:
            return rtype, {"error": str(exc)}

    pairs = await asyncio.gather(*[_resolve(rt) for rt in ("A", "AAAA", "CAA", "CNAME", "MX", "NS", "TXT", "SOA")])
    return dict(pairs)


async def _aget_dmarc_dkim(domain: str) -> dict:
    return await aget_email_security_records(domain)


async def _acrt_sh_data(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get("https://crt.sh/", params={"q": domain, "output": "json"}, headers={"Accept": "application/json"}, timeout=30.0)
        if resp.status_code != 200:
            return dict(_CRT_SH_EMPTY)
        return _parse_crt_sh_entries(resp.json(), domain)
    except Exception:
        return dict(_CRT_SH_EMPTY)


async def _acircl_passive_dns(domain: str, client: httpx.AsyncClient) -> dict:
    result: dict = {"records": [], "unique_historical_ips": []}
    try:
        resp = await client.get(f"https://www.circl.lu/pdns/query/{domain}", headers={"Accept": "application/json"}, timeout=15.0)
        if resp.status_code != 200:
            return result
        records: list[dict] = []
        seen_ips: set[str] = set()
        for line in resp.text.strip().splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            rrtype = entry.get("rrtype", "")
            rdata  = entry.get("rdata", "")
            records.append({"rrtype": rrtype, "rdata": rdata, "first_seen": entry.get("time_first_ms") or entry.get("time_first"), "last_seen": entry.get("time_last_ms") or entry.get("time_last"), "count": entry.get("count")})
            if rrtype in ("A", "AAAA") and rdata:
                seen_ips.add(rdata)
        result["records"]               = records
        result["unique_historical_ips"] = sorted(seen_ips)
    except Exception:
        pass
    return result


async def _ahackertarget_host_search(domain: str, client: httpx.AsyncClient) -> list:
    try:
        resp = await client.get("https://api.hackertarget.com/hostsearch/", params={"q": domain}, timeout=15.0)
        if resp.status_code != 200:
            return []
        text = resp.text.strip()
        if "error" in text.lower() or "API count" in text:
            return []
        results: list[dict] = []
        for line in text.splitlines():
            parts = line.strip().split(",")
            if len(parts) == 2:
                subdomain, ip = parts[0].strip(), parts[1].strip()
                if ip:
                    results.append({"subdomain": subdomain, "ip": ip, "cf": is_cloudflare_ip(ip), "source": "HackerTarget hostsearch"})
        return results
    except Exception:
        return []


_RATE_LIMITED = "__rate_limited__"

async def _run_serial_urlscan(coro):
    await asyncio.to_thread(_URLSCAN_GATE.acquire)
    try:
        return await coro
    finally:
        _URLSCAN_GATE.release()


async def _aurlscan_historical_ips(domain: str, client: httpx.AsyncClient) -> list:
    try:
        resp = await client.get("https://urlscan.io/api/v1/search/", params={"q": f"domain:{domain}", "size": "100"}, timeout=15.0)
        if resp.status_code == 429:
            return [{"_error": _RATE_LIMITED, "source": "urlscan"}]
        if resp.status_code != 200:
            return []
        seen: set[str] = set()
        results: list[dict] = []
        for hit in resp.json().get("results", []):
            ip   = hit.get("page", {}).get("ip", "")
            date = hit.get("task", {}).get("time", "")[:10]
            if ip and ip not in seen:
                seen.add(ip)
                results.append({"ip": ip, "date": date, "url": hit.get("page", {}).get("url", ""), "cf": is_cloudflare_ip(ip), "source": "urlscan.io"})
        return results
    except Exception:
        return []


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


async def _aurlscan_fetch_analytics(domain: str, client: httpx.AsyncClient) -> dict:
    """
    Pull analytics / tracking IDs from the most recent urlscan.io result for
    this domain by:
      1. Searching for the latest scan UUID
      2. Fetching the full result JSON and parsing every request URL
      3. Fetching the rendered DOM HTML and running the same regex extraction

    Returns a dict with the same keys as page_metadata tracking fields.
    An empty dict is returned on any failure or rate-limit.
    """
    out: dict[str, list[str]] = {v: [] for v in _URLSCAN_ANALYTICS_KEY_MAP.values()}

    try:
        # Step 1 — find the most recent scan for this domain
        search_resp = await client.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": "5"},
            timeout=15.0,
        )
        if search_resp.status_code == 429:
            return out
        if search_resp.status_code != 200:
            return out

        results = search_resp.json().get("results", [])
        if not results:
            return out

        # Take the most recent scan that has a result URL
        uuid = None
        for hit in results:
            uid = hit.get("task", {}).get("uuid") or hit.get("_id")
            if uid:
                uuid = uid
                break
        if not uuid:
            return out

        found: dict[str, set[str]] = {v: set() for v in _URLSCAN_ANALYTICS_KEY_MAP.values()}

        # Step 2 — fetch the full result JSON, parse request URLs
        result_resp = await client.get(
            f"https://urlscan.io/api/v1/result/{uuid}/",
            timeout=20.0,
        )
        if result_resp.status_code == 200:
            result_json = result_resp.json()
            requests_list = result_json.get("data", {}).get("requests", [])
            for req_entry in requests_list:
                url = (
                    req_entry.get("request", {}).get("url")
                    or req_entry.get("requests", [{}])[0].get("request", {}).get("url", "")
                    if isinstance(req_entry.get("requests"), list)
                    else req_entry.get("request", {}).get("url", "")
                )
                if not url:
                    continue
                for id_type, pattern in _URLSCAN_ANALYTICS_PATTERNS:
                    for m in pattern.finditer(url):
                        field = _URLSCAN_ANALYTICS_KEY_MAP[id_type]
                        found[field].add(m.group(1))

        # Step 3 — fetch the rendered DOM, run the same HTML extraction
        dom_resp = await client.get(
            f"https://urlscan.io/dom/{uuid}/",
            timeout=20.0,
        )
        if dom_resp.status_code == 200:
            dom_result = _process_page_html(dom_resp.text)
            for id_type, field in _URLSCAN_ANALYTICS_KEY_MAP.items():
                html_key = field  # field names match page_metadata keys
                for val in (dom_result.get(html_key) or []):
                    found[field].add(val)

        for field, values in found.items():
            out[field] = sorted(values)

    except Exception:
        pass

    return out


async def _afetch_page_metadata(domain: str, client: httpx.AsyncClient, save_favicon_as: Path | None = None) -> dict:
    result: dict = {
        "google_analytics": [], "gtm_ids": [], "facebook_pixel": [], "tiktok_pixel": [],
        "yandex_metrika": [], "html_lang": None, "cms_generator": None,
        "social_links": {}, "social_handles": {}, "favicon_md5": None,
        "favicon_mmh3": None, "favicon_saved": None, "error": None,
        "adsense_publisher_ids": [], "fb_app_id": [], "twitter_site": [],
        "twitter_creator": [], "authors": [], "rel_me": [],
        "homepage_html_hash": None, "meta_tags": {}, "script_assets": [],
        "bundler_hints": [], "http_fingerprint": {}, "source_map_leaks": [],
        "final_url": None,
    }
    profile = await afetch_homepage_profile(
        domain,
        client,
        save_favicon_as=save_favicon_as,
        user_agent=_PAGE_UA,
    )
    html = profile.pop("html", "")
    if html:
        result.update(_process_page_html(html))
    result.update(profile)
    return result


async def _analyze_domain_async(
    domain: str,
    scan: bool = False,
    scan_europe: bool = False,
    scan_all: bool = False,
    scan_providers: bool = False,
    scan_countries: list[str] | None = None,
    scan_eu_countries: bool = False,
    scan_full: bool = False,
    concurrency: int = 5_000,
    *,
    rate: int,
    on_partial=None,
    persist: bool = True,
    enable_wordlist_probe: bool = True,
    enable_wordlist_followups: bool = True,
    enable_urlscan: bool = True,
) -> dict:
    result: dict = {
        "input":             domain,
        "type":              "domain",
        "timestamp":         datetime.now(timezone.utc).isoformat(),
        "whois":             {},
        "dns":               {},
        "dns_txt_tokens":    [],
        "zone_transfer":     [],
        "subdomains":        [],
        "cert_transparency": {},
        "historical_dns":    {},
        "page_metadata":     {},
        "email_security":    {},
        "spf_origins":       [],
        "nameserver_analysis": {},
        "well_known":        {},
        "legal_pages":       [],
        "mail_client_config": {},
        "microsoft_tenant":  {},
        "origin_candidates": {},
        "ip_details":        {},
        "ssh_host_keys":     [],
        "subdomain_followups": [],
        "subdomain_followup_summary": {
            "enabled": enable_wordlist_followups,
            "limit": _WORDLIST_FOLLOWUP_LIMIT,
            "candidate_count": 0,
            "selected_count": 0,
            "truncated": 0,
            "completed": 0,
            "failed": 0,
            "status": "pending" if enable_wordlist_followups else "disabled",
        },
    }

    RESULTS_DIR.mkdir(exist_ok=True)
    _safe     = re.sub(r"[^a-zA-Z0-9._-]", "_", domain)
    _ts       = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    _fav_path = RESULTS_DIR / f"{_safe}_{_ts}_favicon.ico"

    def _cb(key: str, value) -> None:
        """Store value into result and fire the on_partial callback."""
        if "." in key:
            top, sub = key.split(".", 1)
            result.setdefault(top, {})[sub] = value
        else:
            result[key] = value
        if on_partial:
            on_partial(key, value)

    async def _task(key: str, coro):
        v = await coro
        _cb(key, v)
        return v

    async def _oc_task(key: str, coro):
        v = await coro
        _cb(f"origin_candidates.{key}", v)
        return v

    async def _empty_list():
        return []

    async def _empty_dict():
        return {}

    # ── Group 1: all concurrent via shared httpx client ───────────────────────
    log("WHOIS / DNS / crt.sh / CIRCL pDNS / page metadata / well-known / legal / tenant probe (async)...")
    async with httpx.AsyncClient(timeout=_HTTPX_TIMEOUT, follow_redirects=True) as client:
        (_, dns_records, cert_transparency_raw, _, _, _, _, _, _) = await asyncio.gather(
            _task("whois",          asyncio.to_thread(get_domain_whois, domain)),
            _task("dns",            _aget_dns_records(domain)),
            _task("_ct_tmp",        _acrt_sh_data(domain, client)),
            _task("historical_dns", _acircl_passive_dns(domain, client)),
            _task("page_metadata",  _afetch_page_metadata(domain, client, _fav_path)),
            _task("email_security", _aget_dmarc_dkim(domain)),
            _task("well_known",     afetch_well_known_artifacts(domain, client)),
            _task("legal_pages",    ascrape_legal_pages(domain, client)),
            _task("mail_client_config", afetch_mail_client_config(domain, client)),
        )
        _cb("microsoft_tenant", await aprobe_microsoft_tenant(domain, client))

        # Post-process CT — split subdomains out and notify each separately
        del result["_ct_tmp"]
        discovered_subdomains = cert_transparency_raw.pop("subdomains", [])
        result["subdomains"]        = discovered_subdomains
        result["cert_transparency"] = cert_transparency_raw
        _cb("cert_transparency", cert_transparency_raw)
        _cb("subdomains", discovered_subdomains)

        dns_records["CAA_parsed"] = parse_caa_records(dns_records.get("CAA", []))
        _cb("dns", dns_records)
        _cb("dns_txt_tokens", extract_txt_tenancy_tokens(dns_records.get("TXT", [])))

        spf_details = await acollect_spf_details(domain, dns_records.get("TXT", []))
        _cb("spf_origins", spf_details.get("origins", []))

        nameservers  = dns_records.get("NS", [])
        mx_records   = dns_records.get("MX") or []
        _cb("nameserver_analysis", _classify_nameservers(nameservers))
        email_security = result.get("email_security") or {}
        email_security["spf_includes"] = spf_details.get("includes", [])
        email_security["spf_records"] = spf_details.get("records", [])
        _cb("email_security", email_security)

        # ── Group 2: origin discovery + zone transfer — all concurrent ────────
        # Zone transfer is included here (not before) so its per-nameserver
        # 5 s timeout does not delay the rest of origin discovery.
        if nameservers:
            log(f"Zone transfer attempt on {len(nameservers)} nameserver(s) (concurrent with origin discovery)")
        group_two_sources = "Zone transfer / subdomain probe / MX / wordlist / HackerTarget"
        if enable_urlscan:
            group_two_sources += " / urlscan"
        group_two_sources += " / Censys / Shodan / Netlas (async)..."
        log(group_two_sources)
        await asyncio.gather(
            _task("zone_transfer",      asyncio.to_thread(attempt_zone_transfer, domain, nameservers) if nameservers else _empty_list()),
            _oc_task("subdomain_leaks", asyncio.to_thread(probe_subdomain_origins, discovered_subdomains) if discovered_subdomains else _empty_list()),
            _oc_task("mx_leaks",        asyncio.to_thread(probe_mx_origins, mx_records)),
            _oc_task("wordlist_leaks",  asyncio.to_thread(probe_wordlist_subdomains, domain) if enable_wordlist_probe else _empty_list()),
            _oc_task("hackertarget",    _ahackertarget_host_search(domain, client)),
            _oc_task("urlscan",         _run_serial_urlscan(_aurlscan_historical_ips(domain, client)) if enable_urlscan else _empty_list()),
            _task("urlscan_analytics",  _run_serial_urlscan(_aurlscan_fetch_analytics(domain, client)) if enable_urlscan else _empty_dict()),
            _oc_task("censys",          asyncio.to_thread(censys_cert_search, domain)),
            _oc_task("shodan",          asyncio.to_thread(shodan_cert_search, domain)),
            _oc_task("netlas",          asyncio.to_thread(netlas_cert_search, domain)),
        )

    wordlist_hits = (result.get("origin_candidates", {}) or {}).get("wordlist_leaks", [])
    all_wordlist_followup_targets = _select_wordlist_followup_targets(
        wordlist_hits,
        limit=max(len(wordlist_hits), _WORDLIST_FOLLOWUP_LIMIT),
    )
    wordlist_followup_targets = all_wordlist_followup_targets[:_WORDLIST_FOLLOWUP_LIMIT]
    followup_summary = {
        "enabled": enable_wordlist_followups,
        "limit": _WORDLIST_FOLLOWUP_LIMIT,
        "candidate_count": len(all_wordlist_followup_targets),
        "selected_count": len(wordlist_followup_targets),
        "truncated": 0,
        "completed": 0,
        "failed": 0,
        "status": "pending" if wordlist_followup_targets and enable_wordlist_followups else ("disabled" if not enable_wordlist_followups else "none"),
    }
    followup_summary["truncated"] = max(0, followup_summary["candidate_count"] - followup_summary["selected_count"])
    _cb("subdomain_followup_summary", followup_summary)

    # ── Merge urlscan analytics IDs into page_metadata ───────────────────────
    # urlscan renders pages in a real browser — it catches IDs that a plain
    # HTTP fetch misses (lazy-loaded scripts, GTM-injected tags, etc.).
    # We merge rather than replace so both sources contribute.
    _us_analytics = result.get("urlscan_analytics") or {}
    if _us_analytics:
        _pm = result.setdefault("page_metadata", {})
        for _field, _vals in _us_analytics.items():
            existing = _pm.get(_field) or []
            merged   = sorted(set(existing) | set(_vals))
            if merged:
                _pm[_field] = merged
        _cb("page_metadata", _pm)
    # Remove the staging key — not needed in the final result
    result.pop("urlscan_analytics", None)

    # ── Extract source errors (e.g. rate limits) from origin_candidates ───────
    source_errors: list[str] = []
    oc = result.get("origin_candidates", {})
    for src, entries in list(oc.items()):
        if isinstance(entries, list):
            errors   = [e for e in entries if isinstance(e, dict) and "_error" in e]
            clean    = [e for e in entries if not (isinstance(e, dict) and "_error" in e)]
            if errors:
                source_errors.extend(e["source"] for e in errors)
                oc[src] = clean
    if source_errors:
        result["source_errors"] = source_errors

    # ── Scan phases — sequential, long-running, each uses its own event loop ──
    do_gcp_europe_scan   = scan_europe   or scan_full
    do_provider_scan     = scan_providers or scan_full
    do_eu_country_scan   = scan_eu_countries or scan_full
    country_code_list    = list({country_code.upper() for country_code in (scan_countries or [])})
    if do_eu_country_scan:
        country_code_list = sorted(set(country_code_list) | set(EU_MEMBER_STATES))

    cert_issuers     = result["cert_transparency"].get("issuers", [])
    gts_issuer_names = {"GTS CA 1P5", "GTS CA 1C3", "GTS CA 1D4", "GTS Root R1"}
    has_gts_cert     = bool(set(cert_issuers) & gts_issuer_names)

    if scan_all or do_gcp_europe_scan or scan or (scan_full and has_gts_cert):
        if scan_all:
            gcp_regions, force_scan, scan_label = None, True, "all GCP regions globally"
        elif do_gcp_europe_scan or scan_full:
            gcp_regions, force_scan, scan_label = GCP_EUROPE_ALL_REGIONS, True, "all European GCP regions + Turkey"
        else:
            gcp_regions, force_scan, scan_label = GCP_DEFAULT_REGIONS, False, "Eastern European GCP regions"
        log(f"Origin scan (GCP): {scan_label}")
        gcp_scan_result = await asyncio.to_thread(
            targeted_origin_scan, domain, cert_issuers, regions=gcp_regions, force=force_scan, concurrency=concurrency, rate=rate,
        )
        _cb("origin_candidates.scan", gcp_scan_result)
    else:
        _cb("origin_candidates.scan", {"skipped": True, "reason": "Pass --scan, --scan-europe, --scan-full, or --scan-all to enable GCP scanning"})

    if do_provider_scan:
        log(f"Origin scan (providers): {len(PROVIDER_ASNS)} ASNs via RIPE Stat")
        provider_scan_result = await asyncio.to_thread(targeted_asn_scan, domain, concurrency=concurrency, rate=rate)
        _cb("origin_candidates.provider_scan", provider_scan_result)
    else:
        _cb("origin_candidates.provider_scan", {"skipped": True, "reason": "Pass --scan-providers or --scan-full to scan known RU/EU hosters"})

    if country_code_list:
        log(f"Origin scan (country): {', '.join(country_code_list)}")
        country_scan_result = await asyncio.to_thread(targeted_country_scan, domain, country_code_list, concurrency=concurrency, rate=rate)
        _cb("origin_candidates.country_scan", country_scan_result)
    else:
        _cb("origin_candidates.country_scan", {"skipped": True, "reason": "Pass --scan-country CC or --scan-full (EU) to scan country IP space"})

    # ── IP enrichment ──────────────────────────────────────────────────────────
    # Collect every IP seen from any source: direct DNS + all origin discovery.
    # ip_sources tracks which source(s) surfaced each IP so the report can show
    # where it came from.
    ip_sources: dict[str, list[str]] = {}

    for record_type in ("A", "AAAA"):
        for ip_address in (dns_records.get(record_type) or []):
            if isinstance(ip_address, str):
                ip_sources.setdefault(ip_address, []).append("dns")

    origin_candidates_result = result.get("origin_candidates", {})

    for candidate_entry in origin_candidates_result.get("hackertarget", []):
        ip_address = candidate_entry.get("ip", "")
        if ip_address and not candidate_entry.get("cf", False):
            ip_sources.setdefault(ip_address, []).append("hackertarget")

    for candidate_entry in origin_candidates_result.get("wordlist_leaks", []):
        ip_address = candidate_entry.get("ip", "")
        if ip_address:
            ip_sources.setdefault(ip_address, []).append("wordlist_probe")

    for candidate_entry in origin_candidates_result.get("mx_leaks", []):
        ip_address = candidate_entry.get("ip", "")
        if ip_address:
            ip_sources.setdefault(ip_address, []).append("mx_record")

    for candidate_entry in origin_candidates_result.get("subdomain_leaks", []):
        ip_address = candidate_entry.get("ip", "")
        if ip_address:
            ip_sources.setdefault(ip_address, []).append("subdomain_probe")

    for candidate_entry in origin_candidates_result.get("urlscan", []):
        ip_address = candidate_entry.get("ip", "")
        if ip_address and not candidate_entry.get("cf", False):
            ip_sources.setdefault(ip_address, []).append("urlscan")

    for historical_record in result.get("historical_dns", {}).get("records", []):
        if historical_record.get("rrtype") in ("A", "AAAA"):
            ip_address = historical_record.get("rdata", "")
            if ip_address and not is_cloudflare_ip(ip_address):
                ip_sources.setdefault(ip_address, []).append("historical_dns")

    for spf_entry in result.get("spf_origins", []):
        ip_address = spf_entry.get("ip", "")
        if ip_address and not is_cloudflare_ip(ip_address):
            ip_sources.setdefault(ip_address, []).append("spf")

    provider_source_map = {
        "censys": "censys",
        "shodan": "shodan",
        "netlas": "netlas",
    }
    for provider_key, source_name in provider_source_map.items():
        provider_result = origin_candidates_result.get(provider_key, {})
        for hit in provider_result.get("hits", []):
            ip_address = hit.get("ip", "")
            if ip_address:
                ip_sources.setdefault(ip_address, []).append(source_name)

    scan_source_map = {
        "scan": "scan_gcp",
        "provider_scan": "scan_provider",
        "country_scan": "scan_country",
    }
    for scan_key, source_name in scan_source_map.items():
        scan_result = origin_candidates_result.get(scan_key, {})
        for hit in scan_result.get("hits", []):
            ip_address = hit.get("ip", "")
            if ip_address:
                ip_sources.setdefault(ip_address, []).append(source_name)

    if ip_sources:
        log(f"IP enrichment ({len(ip_sources)} unique IPs from DNS + all discovery sources)...")
        all_discovered_ips = list(ip_sources.keys())
        enrichment_results = await asyncio.gather(*[asyncio.to_thread(enrich_ip, ip_address) for ip_address in all_discovered_ips])
        ip_details: dict = {}
        for ip_address, enrichment_data in zip(all_discovered_ips, enrichment_results):
            enriched_entry = dict(enrichment_data)
            enriched_entry["sources"] = ip_sources[ip_address]
            ip_details[ip_address] = enriched_entry
        _cb("ip_details", ip_details)

    # ── TLS probe — grab live certs from every non-CF IP found ────────────────
    # ip_sources already contains every IP from every discovery source.
    # Filter to non-Cloudflare IPs only; each is probed with the target domain
    # as SNI so the server presents the cert it is actually serving.
    tls_probe_targets: dict[str, str] = {
        ip_address: domain
        for ip_address in ip_sources
        if not is_cloudflare_ip(ip_address)
    }

    result["non_cf_ips"] = list(tls_probe_targets.keys())

    if tls_probe_targets:
        log(f"TLS probe: grabbing certs from {len(tls_probe_targets)} non-Cloudflare IP(s)...")
        raw_tls_certs = await asyncio.gather(*[
            asyncio.to_thread(grab_tls_cert, ip_address, sni_domain)
            for ip_address, sni_domain in tls_probe_targets.items()
        ])
        non_cloudflare_tls_certs = [cert for cert in raw_tls_certs if cert is not None]
        log(f"TLS probe: {len(non_cloudflare_tls_certs)} cert(s) retrieved")
    else:
        non_cloudflare_tls_certs = []

    if tls_probe_targets:
        log(f"SSH probe: grabbing host keys from {len(tls_probe_targets)} non-Cloudflare IP(s)...")
        ssh_results = await asyncio.gather(*[
            asyncio.to_thread(fetch_ssh_host_key, ip_address)
            for ip_address in tls_probe_targets
        ])
        _cb("ssh_host_keys", [entry for entry in ssh_results if entry])

    result["non_cf_tls_certs"] = non_cloudflare_tls_certs
    if result.get("ip_details"):
        certs_by_ip = {cert.get("ip"): cert for cert in non_cloudflare_tls_certs if cert and cert.get("ip")}
        for ip_address, details in result["ip_details"].items():
            proxy_details = detect_proxy_details(
                ip_address,
                details.get("ptr"),
                details.get("asn_info"),
                certs_by_ip.get(ip_address),
            )
            details["proxy_family"] = proxy_details.get("proxy_family")
            details["proxy_confidence"] = proxy_details.get("proxy_confidence")
        _cb("ip_details", result["ip_details"])
    _cb("non_cf_tls_certs", non_cloudflare_tls_certs)

    if enable_wordlist_followups and wordlist_followup_targets:
        log(
            f"Subdomain follow-up scans: {len(wordlist_followup_targets)} "
            f"wordlist hit(s) selected (cap {followup_summary['limit']}, "
            f"{followup_summary['truncated']} skipped)"
        )
        followups: list[dict] = []
        for target in wordlist_followup_targets:
            subdomain = target["subdomain"]
            log(f"Subdomain follow-up: scanning {subdomain}")
            try:
                nested_result = await _analyze_domain_async(
                    subdomain,
                    scan=scan,
                    scan_europe=scan_europe,
                    scan_all=scan_all,
                    scan_providers=scan_providers,
                    scan_countries=scan_countries,
                    scan_eu_countries=scan_eu_countries,
                    scan_full=scan_full,
                    concurrency=concurrency,
                    rate=rate,
                    on_partial=None,
                    persist=False,
                    enable_wordlist_probe=False,
                    enable_wordlist_followups=False,
                    enable_urlscan=False,
                )
                followups.append(
                    {
                        "subdomain": subdomain,
                        "source": "wordlist_probe",
                        "ips": list(target.get("ips") or []),
                        "hits": list(target.get("hits") or []),
                        "status": "completed",
                        "result": nested_result,
                    }
                )
                followup_summary["completed"] += 1
            except Exception as exc:
                log(f"Subdomain follow-up failed for {subdomain}: {exc}")
                followups.append(
                    {
                        "subdomain": subdomain,
                        "source": "wordlist_probe",
                        "ips": list(target.get("ips") or []),
                        "hits": list(target.get("hits") or []),
                        "status": "failed",
                        "error": str(exc),
                        "result": {
                            "input": subdomain,
                            "type": "domain",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "error": str(exc),
                            "subdomain_followups": [],
                        },
                    }
                )
                followup_summary["failed"] += 1

            _cb("subdomain_followups", followups)
            _cb("subdomain_followup_summary", followup_summary)

        followup_summary["status"] = "completed"
        _cb("subdomain_followup_summary", followup_summary)

    # Cloudflare-fronted flag
    current_a_records = dns_records.get("A") or []
    result["cloudflare_fronted"] = bool(current_a_records) and all(
        is_cloudflare_ip(ip_address) for ip_address in current_a_records if isinstance(ip_address, str)
    )

    # ── Persist everything to SQLite ──────────────────────────────────────────
    if persist:
        try:
            from intel_db import DB_PATH, save_search
            save_search(result)
            log(f"Search saved to {DB_PATH}")
        except Exception as _exc:
            log(f"DB save failed: {_exc}")

    return result


def analyze_domain(
    domain: str,
    scan: bool = False,
    scan_europe: bool = False,
    scan_all: bool = False,
    scan_providers: bool = False,
    scan_countries: list[str] | None = None,
    scan_eu_countries: bool = False,
    scan_full: bool = False,
    concurrency: int = 5_000,
    enable_urlscan: bool = True,
    *,
    rate: int,
    on_partial=None,
) -> dict:
    """Sync entry point — runs the async core in a new event loop."""
    return asyncio.run(_analyze_domain_async(
        domain,
        scan=scan,
        scan_europe=scan_europe,
        scan_all=scan_all,
        scan_providers=scan_providers,
        scan_countries=scan_countries,
        scan_eu_countries=scan_eu_countries,
        scan_full=scan_full,
        concurrency=concurrency,
        enable_urlscan=enable_urlscan,
        rate=rate,
        on_partial=on_partial,
    ))


def analyze_ip(ip: str) -> dict:
    result: dict = {
        "input":               ip,
        "type":                "ip",
        "timestamp":           datetime.now(timezone.utc).isoformat(),
        "ptr":                 None,
        "cloudflare":          False,
        "asn_info":            {},
        "other_domains_on_ip": [],
        "ssh_host_keys":       [],
    }

    log(f"PTR record for {ip}")
    result["ptr"] = get_ptr(ip)

    log(f"ASN / network info for {ip}")
    result["asn_info"] = get_ip_whois(ip)

    result["cloudflare"] = is_cloudflare_ip(ip)
    if result["cloudflare"]:
        log(f"Skipping reverse IP lookup — Cloudflare anycast (results would be meaningless)")
    else:
        log(f"Reverse IP lookup (hackertarget)")
        result["other_domains_on_ip"] = hackertarget_reverse_ip(ip)

    # ── TLS probe — grab cert directly from this IP ───────────────────────────
    result["tls_cert"] = None
    result["non_cf_ips"] = []
    result["non_cf_tls_certs"] = []
    result["cloudflare_fronted"] = result["cloudflare"]

    if not result["cloudflare"]:
        log(f"Grabbing TLS cert from {ip}:443")
        # Use PTR hostname as SNI if we have one, otherwise fall back to bare IP
        sni = result.get("ptr") or ip
        cert = grab_tls_cert(ip, sni=sni)
        result["tls_cert"] = cert
        result["non_cf_ips"] = [ip]
        result["non_cf_tls_certs"] = [cert] if cert else []
        if cert:
            log(f"TLS cert: CN={cert.get('cn')}  issuer={cert.get('issuer_cn')}")
        ssh_host_key = fetch_ssh_host_key(ip)
        if ssh_host_key:
            result["ssh_host_keys"] = [ssh_host_key]

    # ── Persist to SQLite ─────────────────────────────────────────────────────
    proxy_details = detect_proxy_details(ip, result.get("ptr"), result.get("asn_info"), result.get("tls_cert"))
    result["proxy_family"] = proxy_details.get("proxy_family")
    result["proxy_confidence"] = proxy_details.get("proxy_confidence")

    try:
        from intel_db import DB_PATH, save_search
        save_search(result)
        log(f"Search saved to {DB_PATH}")
    except Exception as _exc:
        log(f"DB save failed: {_exc}")

    return result


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        prog="ip_intel",
        description="Domain / IP intelligence tool",
    )
    parser.add_argument("target", help="Domain name or IP address to analyse")
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan Eastern-European GCP regions for the origin cert (requires GTS cert in history)",
    )
    parser.add_argument(
        "--scan-europe",
        action="store_true",
        help="Scan ALL European GCP regions + Turkey coverage (forces scan regardless of cert history)",
    )
    parser.add_argument(
        "--scan-all",
        action="store_true",
        help="Scan every GCP region globally (very slow — several hours without masscan)",
    )
    parser.add_argument(
        "--scan-providers",
        action="store_true",
        help="Scan Hetzner, OVH, M247, Aeza, Selectel, TimeWeb and other RU/EU hosters via RIPE Stat",
    )
    parser.add_argument(
        "--scan-country",
        metavar="CC",
        nargs="+",
        help="Scan all IPv4 space allocated to one or more countries (ISO codes, e.g. RU UA BY)",
    )
    parser.add_argument(
        "--scan-eu-countries",
        action="store_true",
        help="Scan all IPv4 space for all 27 EU member states via RIPE Stat",
    )
    parser.add_argument(
        "--scan-full",
        action="store_true",
        help="Run everything: EU countries + known providers + GCP Europe (+ GCP if GTS cert found)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5_000,
        metavar="N",
        help="Max concurrent connections for async TCP/TLS phase (default: 5000, reduce if network struggles)",
    )
    parser.add_argument(
        "--rate",
        type=int,
        default=100_000,
        metavar="PPS",
        help="masscan packets-per-second rate (default: 100000, e.g. --rate 1000 to be gentle)",
    )
    args = parser.parse_args()

    target = clean_target(args.target)

    out_dir = Path(__file__).parent / "results"
    out_dir.mkdir(exist_ok=True)

    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
    timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file   = out_dir / f"{safe_name}_{timestamp}.json"

    print(f"\n  ip-intel  |  target: {target}\n")

    if is_ip(target):
        data = analyze_ip(target)
    else:
        data = analyze_domain(
            target,
            scan=args.scan,
            scan_europe=args.scan_europe,
            scan_all=args.scan_all,
            scan_providers=args.scan_providers,
            scan_countries=args.scan_country,
            scan_eu_countries=args.scan_eu_countries,
            scan_full=args.scan_full,
            concurrency=args.concurrency,
            rate=args.rate,
        )

    with open(out_file, "w") as fh:
        json.dump(data, fh, indent=2, default=str)

    print(f"\n  [+] Saved → {out_file}\n")


if __name__ == "__main__":
    main()
