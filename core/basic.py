#!/usr/bin/env python3
"""
ip_intel.py — Simple domain intelligence tool.

One function per service. Each takes a domain (or the inputs it needs) and
returns a dict. Results are saved to results.json after every step so you
can tail it while the run progresses.

Usage:
    python ip_intel.py <domain>
"""

import contextvars
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import dns.resolver
import requests
import whois
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from dotenv import load_dotenv
from tqdm import tqdm

from core.ip_intel import _DNS_GATE, censys_cert_search, detect_proxy_details
from sources import signal_web
from utils.ipinfo_lite import merge_ipinfo_lite
from utils.censys_enrichment import merge_censys_enrichment
from utils.outbound import requests_kwargs

load_dotenv()

# Paramiko's background threads love to dump full tracebacks to stderr when
# SSH handshakes fail (tarpits, resets, hardened hosts). We already capture
# failures as {"error": ...} in our probe return values, so silence the noise.
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
logging.getLogger("paramiko").addHandler(logging.NullHandler())
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)
logging.getLogger("paramiko.transport").addHandler(logging.NullHandler())

OUTPUT_FILE     = Path(__file__).parent / "results.json"
# Follow-up scans never touch Censys (the only active paid-style provider),
# so this can be generous:
# it only costs DNS/WHOIS/crt.sh/page-fetch time, not API credits.
FOLLOWUP_LIMIT  = 20    # max subdomains to recurse into

# Two separate caps, because the two stages are limited by different things and
# used to share one number.
#
# `IP_PROBE_LIMIT` bounds the TLS and SSH probes: raw socket connections to
# ports that are frequently filtered, so each miss costs a full connect timeout.
# That is a latency budget and 20 is about where it stops being worth waiting.
#
# `IP_ENRICH_LIMIT` bounds the per-IP ASN/PTR/host-enrichment pass, which is
# plain HTTP against ipinfo Lite (free and uncapped) and Censys host enrichment
# (no credits; 20,000/day, claimed per call in db.intel_db so it self-limits at
# the cap). Nothing here is billed per IP, so the old shared cap of 20 was
# spending a latency budget it did not need to: a Censys cert search returns up
# to 100 hosts and the 80 past the cap were being dropped with no ASN, no geo
# and no reputation — the exact attribution the paid credit was spent to find.
# 100 matches the search's page size so a full page is always covered.
IP_PROBE_LIMIT  = 20    # max IPs to TLS/SSH probe per run
IP_ENRICH_LIMIT = 100   # max IPs to run ASN/PTR/Censys-enrichment over

# Concurrency for the per-IP enrichment fan-out, and a separate bound on the one
# source inside it that rate-limits.
#
# These were a single number (6 workers) sized entirely by HackerTarget's
# reverse-IP limit — it 429s readily, and tripping it forces a VPN rotation. So
# every IP was throttled to protect one call that most of them no longer make:
# HackerTarget now runs only for the probe-tier IPs (see _enrich_one_ip), while
# the rest do ipinfo Lite (free and uncapped) plus Censys host enrichment (no
# per-second limit, only a daily budget claimed up front).
#
# Splitting them lets the fan-out run wide while HackerTarget stays as polite as
# it was: at IP_ENRICH_LIMIT the enrichment phase was ~15s of a scan (51 IPs at
# ~1.8s each through 6 workers) and is bounded by the semaphore, not the pool.
# 8, not 16. Measured on a 32-target run: at 16 workers per-IP enrichment went
# from 1.80s to 3.31s, so throughput rose only 1.45x for a 2.67x worker
# increase — already past the knee. Worse, each worker does a get_ptr() DNS
# lookup, and 16 of those per domain across 12 concurrent targets saturated the
# resolver: the DNS-heavy parity steps inflated in lockstep (origin candidates
# 5.13s -> 19.66s, zone transfer 0.25s -> 1.31s). Because origin candidates is
# the parity block's long pole, the extra workers made the critical path slower
# to speed up a phase that had barely gained. Tune via IP_ENRICH_WORKERS, but
# measure get_ptr latency and the parity step times together — they share a
# resolver, so this number cannot be judged on its own.
_IP_ENRICH_WORKERS = max(1, int(os.environ.get("IP_ENRICH_WORKERS", "8")))
_HACKERTARGET_CONCURRENCY = max(1, int(os.environ.get("HACKERTARGET_CONCURRENCY", "4")))
_HACKERTARGET_GATE = threading.Semaphore(_HACKERTARGET_CONCURRENCY)


# ── Logging helpers ───────────────────────────────────────────────────────────

_LogHook = Callable[[str, str], None]
_SaveHook = Callable[[dict[str, Any]], None]

_LOG_HOOK: ContextVar[_LogHook | None] = ContextVar("ip_intel_basic_log_hook", default=None)
_SAVE_HOOK: ContextVar[_SaveHook | None] = ContextVar("ip_intel_basic_save_hook", default=None)


@contextmanager
def runtime_hooks(
    *,
    log_hook: _LogHook | None = None,
    save_hook: _SaveHook | None = None,
):
    """Route runtime side effects for this analysis context only."""
    log_token = _LOG_HOOK.set(log_hook)
    save_token = _SAVE_HOOK.set(save_hook)
    try:
        yield
    finally:
        _SAVE_HOOK.reset(save_token)
        _LOG_HOOK.reset(log_token)


def log(msg: str, level: str = "*") -> None:
    """Print a timestamped log line via tqdm.write so bars aren't clobbered."""
    hook = _LOG_HOOK.get()
    if hook is not None:
        hook(str(msg), str(level))
        return
    stamp = datetime.now().strftime("%H:%M:%S")
    tqdm.write(f"  [{level}] {stamp}  {msg}")


def log_info(msg: str) -> None: log(msg, "*")
def log_ok(msg: str)   -> None: log(msg, "+")
def log_warn(msg: str) -> None: log(msg, "!")


# ── Storage ───────────────────────────────────────────────────────────────────

def save_results(results: dict) -> None:
    """Write the running results dict to disk."""
    hook = _SAVE_HOOK.get()
    if hook is not None:
        hook(results)
        return
    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2, default=str)


# ── Cloudflare detection + DNS helpers ────────────────────────────────────────

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


# Fallback resolvers, used only when dns.resolver.Resolver() cannot read the
# system configuration. Same env var and same default list as
# core/ip_intel.py and sources/signal_dns.py, which already honoured it — this
# module did not, so a resolver-config failure here silently produced empty
# record sets that read exactly like "this domain has no records".
_DNS_FALLBACK_NAMESERVERS = tuple(
    item.strip()
    for item in os.getenv("IP_INTEL_DNS_RESOLVERS", "1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4").split(",")
    if item.strip()
)

_dns_fallback_warned = False


def _build_resolver(*, timeout: float, lifetime: float):
    """A configured resolver, falling back to IP_INTEL_DNS_RESOLVERS.

    dns.resolver.Resolver() reads /etc/resolv.conf; in a container that is
    Docker's embedded DNS. When that read fails there is nothing to resolve
    with, and every caller here swallows per-record exceptions, so without this
    fallback the whole scan reports empty DNS rather than a resolver error.
    """
    global _dns_fallback_warned
    try:
        resolver = dns.resolver.Resolver()
    except Exception as exc:
        if not _DNS_FALLBACK_NAMESERVERS:
            raise
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(_DNS_FALLBACK_NAMESERVERS)
        if not _dns_fallback_warned:
            _dns_fallback_warned = True
            log_warn(
                f"DNS resolver configuration unavailable ({exc}); "
                f"falling back to IP_INTEL_DNS_RESOLVERS"
            )
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    return resolver


def resolve_ips(hostname: str) -> list[str]:
    """Return A + AAAA for hostname, empty list on failure."""
    resolver = _build_resolver(timeout=5, lifetime=8)
    ips: list[str] = []
    for rtype in ("A", "AAAA"):
        try:
            # Shared with core.ip_intel's resolvers — see _DNS_GATE there for
            # why the bound is process-wide rather than per call site.
            with _DNS_GATE:
                ips.extend(str(r) for r in resolver.resolve(hostname, rtype))
        except Exception:
            pass
    return ips


# ── Services ──────────────────────────────────────────────────────────────────

def get_dns(domain: str) -> dict:
    """Resolve A, AAAA, MX, NS, TXT, SOA, CNAME, CAA records (parallel lookups)."""

    def _resolve_one(rtype: str) -> tuple[str, object]:
        resolver = _build_resolver(timeout=5, lifetime=10)
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
                    "mname":  str(r.mname).rstrip("."),
                    "rname":  str(r.rname).rstrip("."),
                    "serial": int(r.serial),
                }
            if rtype == "TXT":
                return rtype, [
                    b"".join(r.strings).decode("utf-8", errors="replace")
                    for r in answers
                ]
            return rtype, [str(r).rstrip(".") for r in answers]
        except Exception:
            return rtype, []

    rtypes = ("A", "AAAA", "CAA", "CNAME", "MX", "NS", "TXT", "SOA")
    out: dict = {}
    with ThreadPoolExecutor(max_workers=len(rtypes)) as ex:
        for rtype, value in ex.map(_resolve_one, rtypes):
            out[rtype] = value
    log_ok(f"DNS: A={len(out.get('A', []))} AAAA={len(out.get('AAAA', []))} "
           f"MX={len(out.get('MX', []))} NS={len(out.get('NS', []))}")
    return out


def get_whois(domain: str) -> dict:
    """Domain WHOIS lookup.

    Captures every field the TLD-specific parser extracted -- registrant/
    admin/tech name, org, address, city, state, postal code, phone/email
    when the registry exposes them, not just the handful of summary fields
    kept previously -- plus the full raw response text under "raw".
    db/intel_db.py's whois_data table and identifier extraction read a few
    of these by their historical names (expiry_date, nameservers), so those
    stay aliased for backward compatibility.
    """
    try:
        w = whois.whois(domain)

        def _fmt(v):
            if v is None:
                return None
            if isinstance(v, list):
                return [str(x) for x in v]
            return str(v)

        result = {key: _fmt(value) for key, value in dict(w).items()}
        result["expiry_date"] = _fmt(w.expiration_date)
        result["nameservers"] = _fmt(w.name_servers)
        result["raw"] = getattr(w, "text", None)
        log_ok(f"WHOIS: registrar={result.get('registrar')} created={result.get('creation_date')}")
        return result
    except Exception as exc:
        log_warn(f"WHOIS failed: {exc}")
        return {"error": str(exc)}


def get_crt_sh(domain: str) -> dict:
    """Subdomains + issuers + cert metadata from crt.sh.

    Falls back to Cert Spotter (get_certspotter) when crt.sh errors, times
    out, or rate-limits. A legitimate zero-cert crt.sh response does NOT
    trigger the fallback.
    """
    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": domain, "output": "json"},
            headers={"Accept": "application/json"},
            timeout=20,
            **requests_kwargs(),
        )
        if resp.status_code != 200:
            log_warn(f"crt.sh HTTP {resp.status_code} — falling back to Cert Spotter")
            return get_certspotter(domain)

        entries = resp.json()
        subdomains: set[str] = set()
        issuers:    set[str] = set()
        certs = []
        seen_ids: set[int] = set()

        for entry in entries:
            cid = entry.get("id")
            if cid in seen_ids:
                continue
            seen_ids.add(cid)

            issuer = entry.get("issuer_name", "")
            m = re.search(r"CN=([^,]+)", issuer)
            issuer_cn = m.group(1).strip() if m else issuer
            if issuer_cn:
                issuers.add(issuer_cn)

            sans = []
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.").lower()
                if not name:
                    continue
                sans.append(name)
                if name.endswith(f".{domain}") and name != domain:
                    subdomains.add(name)

            certs.append({
                "id":         cid,
                "issuer":     issuer_cn,
                "not_before": entry.get("not_before"),
                "not_after":  entry.get("not_after"),
                "sans":       sorted(set(sans)),
            })

        log_ok(f"crt.sh: {len(certs)} certs, {len(subdomains)} subdomains, "
               f"{len(issuers)} issuers")
        return {
            "total_certs": len(certs),
            "subdomains":  sorted(subdomains),
            "issuers":     sorted(issuers),
            "certs":       certs,
            "source":      "crt.sh",
        }
    except Exception as exc:
        log_warn(f"crt.sh failed ({exc}) — falling back to Cert Spotter")
        return get_certspotter(domain)


CERTSPOTTER_API_URL   = "https://api.certspotter.com/v1/issuances"
CERTSPOTTER_MAX_PAGES = 20  # pagination safety cap (free tier ≈ 100 queries/hour)


def get_certspotter(domain: str) -> dict:
    """Subdomains + issuers + cert metadata from Cert Spotter — the free CT
    fallback used when crt.sh is down or rate-limiting.

    No API key needed; set CERTSPOTTER_API_KEY (sent as a Bearer token) to
    raise the rate limit. Paginates via the ``after`` parameter and normalizes
    into the exact get_crt_sh() result shape.
    """
    try:
        headers = {"Accept": "application/json"}
        api_key = os.environ.get("CERTSPOTTER_API_KEY", "").strip()
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        issuances: list[dict] = []
        after: str | None = None
        for _ in range(CERTSPOTTER_MAX_PAGES):
            params: dict = {
                "domain":             domain,
                "include_subdomains": "true",
                "expand":             ["dns_names", "issuer", "cert"],
            }
            if after is not None:
                params["after"] = after
            resp = requests.get(
                CERTSPOTTER_API_URL,
                params=params,
                headers=headers,
                timeout=20,
                **requests_kwargs(),
            )
            if resp.status_code != 200:
                if issuances:
                    break  # keep the pages we already collected
                log_warn(f"Cert Spotter HTTP {resp.status_code}")
                return {"error": f"HTTP {resp.status_code}", "source": "certspotter"}
            page = resp.json()
            if not isinstance(page, list) or not page:
                break
            issuances.extend(e for e in page if isinstance(e, dict))
            last_id = page[-1].get("id") if isinstance(page[-1], dict) else None
            if not last_id:
                break
            after = str(last_id)

        subdomains: set[str] = set()
        issuers:    set[str] = set()
        certs = []
        seen_ids: set = set()

        for entry in issuances:
            cid = entry.get("id")
            try:
                cid = int(cid)
            except (TypeError, ValueError):
                pass
            if cid in seen_ids:
                continue
            seen_ids.add(cid)

            issuer = entry.get("issuer")
            if isinstance(issuer, dict):
                issuer_name = issuer.get("name") or issuer.get("friendly_name") or ""
            else:
                issuer_name = str(issuer or "")
            m = re.search(r"CN=([^,]+)", issuer_name)
            issuer_cn = m.group(1).strip() if m else issuer_name
            if issuer_cn:
                issuers.add(issuer_cn)

            sans = []
            for name in entry.get("dns_names") or []:
                if not isinstance(name, str):
                    continue
                name = name.strip().lstrip("*.").lower()
                if not name:
                    continue
                sans.append(name)
                if name.endswith(f".{domain}") and name != domain:
                    subdomains.add(name)

            certs.append({
                "id":         cid,
                "issuer":     issuer_cn,
                "not_before": entry.get("not_before"),
                "not_after":  entry.get("not_after"),
                "sans":       sorted(set(sans)),
            })

        log_ok(f"Cert Spotter: {len(certs)} certs, {len(subdomains)} subdomains, "
               f"{len(issuers)} issuers")
        return {
            "total_certs": len(certs),
            "subdomains":  sorted(subdomains),
            "issuers":     sorted(issuers),
            "certs":       certs,
            "source":      "certspotter",
        }
    except Exception as exc:
        log_warn(f"Cert Spotter failed: {exc}")
        return {"error": str(exc), "source": "certspotter"}


def get_circl_pdns(domain: str) -> dict:
    """Historical DNS records from CIRCL passive DNS."""
    try:
        resp = requests.get(
            f"https://www.circl.lu/pdns/query/{domain}",
            headers={"Accept": "application/json"},
            timeout=15,
            **requests_kwargs(),
        )
        if resp.status_code != 200:
            log_warn(f"CIRCL pDNS HTTP {resp.status_code}")
            return {"records": [], "error": f"HTTP {resp.status_code}"}

        records  = []
        seen_ips: set[str] = set()
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
                "first_seen": entry.get("time_first"),
                "last_seen":  entry.get("time_last"),
                "count":      entry.get("count"),
            })
            if rrtype in ("A", "AAAA") and rdata:
                seen_ips.add(rdata)

        log_ok(f"CIRCL: {len(records)} records, {len(seen_ips)} historical IPs")
        return {"records": records, "unique_historical_ips": sorted(seen_ips)}
    except Exception as exc:
        log_warn(f"CIRCL failed: {exc}")
        return {"error": str(exc)}


def _rotate_vpn_after_rate_limit(provider: str) -> None:
    """Best-effort: rotate the VPN exit IP after a provider rate-limits us, so
    an immediate retry lands from a fresh source IP. No-op when rotation
    isn't configured (VPN_API_BASE_URL unset/VPN_ROTATE_DISABLE=1) or when
    another concurrently-scanning domain already rotated moments ago — the
    retry below still fires either way, just against whatever IP is current."""
    try:
        from utils.vpn import rotate_vpn_ip_sync
        new_ip = rotate_vpn_ip_sync()
        if new_ip:
            log_warn(f"{provider}: rate-limited — rotated VPN exit IP to {new_ip}, retrying")
        else:
            log_warn(f"{provider}: rate-limited — retrying (VPN rotation unavailable or on cooldown)")
    except Exception as exc:
        log_warn(f"{provider}: rate-limited — retrying (VPN rotation failed: {exc})")


def get_hackertarget(domain: str) -> dict:
    """Subdomains + IPs from HackerTarget hostsearch."""
    for attempt in (1, 2):
        try:
            resp = requests.get(
                "https://api.hackertarget.com/hostsearch/",
                params={"q": domain},
                timeout=15,
                **requests_kwargs(),
            )
            if resp.status_code != 200:
                return {"hits": [], "error": f"HTTP {resp.status_code}"}
            text = resp.text.strip()
            if "error" in text.lower() or "API count" in text:
                if attempt == 1:
                    _rotate_vpn_after_rate_limit("HackerTarget")
                    continue
                log_warn(f"HackerTarget: {text[:80]}")
                return {"hits": [], "error": text}

            hits = []
            for line in text.splitlines():
                parts = line.strip().split(",")
                if len(parts) == 2:
                    hits.append({"subdomain": parts[0].strip(), "ip": parts[1].strip()})
            log_ok(f"HackerTarget: {len(hits)} subdomain/IP pairs")
            return {"hits": hits}
        except Exception as exc:
            log_warn(f"HackerTarget failed: {exc}")
            return {"error": str(exc)}


def _urlscan_headers() -> dict:
    """Headers for urlscan.io calls, authenticating when URLSCAN_KEY is set.

    An authenticated key lifts the anonymous per-source-IP rate limit that
    otherwise forces a VPN rotation (and the batch-wide stall that comes with
    it) on nearly every domain. Falls back to an unauthenticated UA-only
    request when no key is configured, so local/dev behaves as before.
    """
    headers = {"User-Agent": "ip-intel/1.0"}
    api_key = os.environ.get("URLSCAN_KEY", "").strip()
    if api_key:
        headers["API-Key"] = api_key
    return headers


def _fetch_urlscan_referrers(uuid: str, domain: str, timeout: float = 15.0) -> dict:
    """
    Fetch the full urlscan result and find every request whose URL contains
    our queried domain. This tells us *how* and *from where* we were referenced
    when the scan's main URL was a third party — the difference between
    "shared hosting" and "content embedding".

    Returns a dict with:
      - scan_url:   the top-level URL that was submitted to urlscan
      - referring:  list of {url, method, type, initiator} for each request
                    whose URL contains `domain` (capped at 10 entries).
    """
    out = {"scan_url": None, "referring": []}
    try:
        resp = requests.get(
            f"https://urlscan.io/api/v1/result/{uuid}/",
            headers=_urlscan_headers(),
            timeout=timeout,
            **requests_kwargs(),
        )
        if resp.status_code != 200:
            out["error"] = f"HTTP {resp.status_code}"
            return out

        data      = resp.json()
        out["scan_url"] = data.get("task", {}).get("url") or data.get("page", {}).get("url")
        requests_ = data.get("data", {}).get("requests", []) or []

        for req_entry in requests_:
            # urlscan nests the actual request info one level deeper in some
            # versions of the API, so try both shapes.
            inner = req_entry.get("request", {})
            if isinstance(inner, dict) and isinstance(inner.get("request"), dict):
                inner = inner["request"]
            url = inner.get("url", "") if isinstance(inner, dict) else ""
            if not url or domain not in url.lower():
                continue
            out["referring"].append({
                "url":       url,
                "method":    inner.get("method"),
                "type":      (req_entry.get("request", {}) or {}).get("type"),
                "initiator": (req_entry.get("initiator", {}) or {}).get("url"),
            })
            if len(out["referring"]) >= 10:
                break
    except Exception as exc:
        out["error"] = str(exc)
    return out


def get_urlscan(domain: str) -> dict:
    """Historical scan results from urlscan.io, with referrer enrichment."""
    try:
        resp = None
        for attempt in (1, 2):
            resp = requests.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{domain}", "size": "100"},
                headers=_urlscan_headers(),
                timeout=15,
                **requests_kwargs(),
            )
            if resp.status_code == 429 and attempt == 1:
                _rotate_vpn_after_rate_limit("urlscan")
                continue
            break
        if resp.status_code != 200:
            return {"hits": [], "error": f"HTTP {resp.status_code}"}

        seen: set[str] = set()
        hits = []
        for hit in resp.json().get("results", []):
            ip   = hit.get("page", {}).get("ip", "")
            url  = hit.get("page", {}).get("url", "")
            uuid = hit.get("task", {}).get("uuid") or hit.get("_id")
            if not ip or ip in seen:
                continue
            seen.add(ip)
            hits.append({
                "ip":   ip,
                "date": hit.get("task", {}).get("time", "")[:10],
                "url":  url,
                "uuid": uuid,
                # Set when the scan URL was a third party, i.e. our domain
                # was pulled in as a resource rather than being the main page.
                "third_party_scan": bool(url) and domain not in url.lower(),
            })

        # Enrich only the third-party scans — for hits where the scan URL is
        # already our own domain, the referrer info is trivially "us".
        to_enrich = [h for h in hits if h["third_party_scan"] and h["uuid"]]
        if to_enrich:
            log_info(f"urlscan: enriching {len(to_enrich)} third-party scan(s)")
            with ThreadPoolExecutor(max_workers=5) as ex:
                futures = {
                    ex.submit(_fetch_urlscan_referrers, h["uuid"], domain): h
                    for h in to_enrich
                }
                with tqdm(total=len(to_enrich), desc="  urlscan referrers",
                          unit="scan", dynamic_ncols=True, leave=False) as bar:
                    for fut in as_completed(futures):
                        h = futures[fut]
                        try:
                            h["referrer_context"] = fut.result()
                        except Exception as exc:
                            h["referrer_context"] = {"error": str(exc)}
                        bar.update(1)

        log_ok(f"urlscan: {len(hits)} unique IPs, "
               f"{sum(1 for h in hits if h['third_party_scan'])} third-party scans")
        return {"hits": hits}
    except Exception as exc:
        log_warn(f"urlscan failed: {exc}")
        return {"error": str(exc)}


def get_censys(domain: str) -> dict:
    """Hosts serving a TLS cert matching the domain (needs CENSYS_API_KEY).

    Delegates to core.ip_intel.censys_cert_search rather than keeping a second
    implementation. Both hit the same endpoint with the same query and so cost
    the same search credits, but this one used to ask for `fields=["host.ip"]`
    and keep only the IP — throwing away the ASN, country, open-service list,
    non-Cloudflare origin-candidate split and pagination that arrive in the
    very same paid response. Since the web pipeline runs *this* function (it's
    the entry in SERVICES) while the CLI ran the richer twin, the web pipeline
    was the one paying full price for a fraction of the data.

    The cert-history pivot stays off unless CENSYS_CERT_HISTORY is set — see
    core.ip_intel._censys_history_enabled for why.
    """
    result = censys_cert_search(domain)
    if result.get("skipped"):
        log_info(f"Censys skipped: {result.get('reason')}")
    elif result.get("error"):
        log_warn(f"Censys failed: {result['error']}")
    else:
        log_ok(f"Censys: {len(result.get('hits') or [])} hits, "
               f"{len(result.get('origin_candidates') or [])} origin candidate(s)")
    return result


def get_page_metadata(domain: str) -> dict:
    """Fetch the homepage and extract tracking IDs, favicon hashes, and identity signals.

    Delegates to sources/signal_web.py rather than scraping here. This used to
    be its own fetch with its own regex set — a strict subset of signal_web's
    (no TikTok pixel, no AdSense, no `AW-` conversion IDs, no favicon hashing,
    no phone/crypto/meta-tag extraction, no ok.ru or Pinterest) — while
    core/analysis_service.py separately called signal_web for the real thing
    and merged the two. Every domain therefore had its homepage fetched twice,
    and the second fetch contributed nothing the first did not already have.
    One collector also means one output vocabulary: see
    signal_web.canonicalize_page_metadata for why that matters.
    """
    result = signal_web.fetch_page_metadata(domain)
    if result.get("error") and not result.get("final_url"):
        log_warn(f"Page fetch failed: {result['error']}")
        return {"error": result["error"]}

    tracker_total = sum(
        len(result.get(key) or [])
        for key in ("google_analytics", "gtm_ids", "facebook_pixel",
                    "yandex_metrika", "tiktok_pixel", "adsense_publisher_ids")
    )
    log_ok(f"page_metadata: lang={result.get('html_lang')} "
           f"cms={result.get('cms_generator')} "
           f"social={len(result.get('social_links') or {})} trackers={tracker_total}")
    return result


# ── TLS / SSH probes ──────────────────────────────────────────────────────────

def _probe_tls(ip: str, sni: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Grab the TLS cert served by ip:port using sni as SNI. No hostname verify."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                der = ssock.getpeercert(binary_form=True)
        if not der:
            return {"ip": ip, "error": "no certificate"}
        cert = x509.load_der_x509_certificate(der)

        def _cn(name) -> str | None:
            try:
                attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
                return attrs[0].value if attrs else None
            except Exception:
                return None

        sans: list[str] = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [n.value for n in ext.value if isinstance(n, x509.DNSName)]
        except x509.ExtensionNotFound:
            pass

        return {
            "ip":                 ip,
            "port":               port,
            "sni_used":            sni,
            "cn":                 _cn(cert.subject),
            "sans":               sans,
            "issuer_cn":          _cn(cert.issuer),
            "not_before":         cert.not_valid_before_utc.isoformat(),
            "not_after":          cert.not_valid_after_utc.isoformat(),
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "serial":             str(cert.serial_number),
        }
    except Exception as exc:
        return {"ip": ip, "error": str(exc)}


def _probe_ssh(ip: str, port: int = 22, timeout: float = 5.0) -> dict:
    """Grab the SSH banner and host-key fingerprint from ip:port."""
    try:
        import paramiko
    except ImportError:
        return {"ip": ip, "error": "paramiko not installed"}

    sock      = None
    transport = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=timeout)
        key       = transport.get_remote_server_key()
        banner    = transport.remote_version
        key_bytes = key.asbytes()
        return {
            "ip":                 ip,
            "port":               port,
            "banner":             banner,
            "key_type":           key.get_name(),
            "fingerprint_sha256": hashlib.sha256(key_bytes).hexdigest(),
            "fingerprint_md5":    hashlib.md5(key_bytes).hexdigest(),
        }
    except Exception as exc:
        # Common, expected failures: peer resets, tarpits, non-SSH services,
        # firewall blocks. Return them as data instead of logging.
        return {"ip": ip, "error": str(exc)}
    finally:
        # Order matters: close the transport first so its background thread
        # exits cleanly, then close the socket.
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def get_tls_certs(domain: str, ips: list[str]) -> dict:
    """Grab TLS certs from a list of IPs, using domain as SNI."""
    results: list[dict] = []
    if not ips:
        return {"probes": []}
    log_info(f"TLS probe: {len(ips)} IP(s) with SNI={domain}")
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(_probe_tls, ip, domain): ip for ip in ips}
        with tqdm(total=len(ips), desc="  TLS probe", unit="ip",
                  dynamic_ncols=True, leave=False) as bar:
            for fut in as_completed(futures):
                r = fut.result()
                results.append(r)
                if "error" not in r:
                    log_ok(f"TLS {r['ip']}: CN={r.get('cn')} issuer={r.get('issuer_cn')}")
                bar.update(1)
    return {"probes": results}


def get_ssh_host_keys(ips: list[str]) -> dict:
    """Grab SSH banner + host key from a list of IPs."""
    results: list[dict] = []
    if not ips:
        return {"probes": []}
    log_info(f"SSH probe: {len(ips)} IP(s) on :22")
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(_probe_ssh, ip): ip for ip in ips}
        with tqdm(total=len(ips), desc="  SSH probe", unit="ip",
                  dynamic_ncols=True, leave=False) as bar:
            for fut in as_completed(futures):
                r = fut.result()
                results.append(r)
                if "error" not in r:
                    log_ok(f"SSH {r['ip']}: {r.get('key_type')} "
                           f"sha256={r.get('fingerprint_sha256', '')[:16]}…")
                bar.update(1)
    return {"probes": results}


# ── Post-service helpers ──────────────────────────────────────────────────────

def collect_non_cf_ips(
    results: dict, limit: int = IP_ENRICH_LIMIT, *, with_sources: bool = False,
) -> list[str] | tuple[list[str], dict[str, list[str]]]:
    """Pull every non-Cloudflare IP surfaced across all services.

    With `with_sources=True`, also returns a {ip: [source, ...]} map of which
    service(s) reported each IP, used to populate ip_details.sources.
    """
    ips: list[str] = []
    seen: set[str] = set()
    sources: dict[str, list[str]] = {}

    def _add(ip: str, source: str) -> None:
        if not ip or is_cloudflare_ip(ip):
            return
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
        source_list = sources.setdefault(ip, [])
        if source not in source_list:
            source_list.append(source)

    dns_results = results.get("dns", {}) or {}
    for rtype in ("A", "AAAA"):
        for ip in dns_results.get(rtype, []) or []:
            _add(ip, "dns")

    for hit in (results.get("hackertarget", {}) or {}).get("hits", []) or []:
        _add(hit.get("ip", ""), "hackertarget")
    for hit in (results.get("urlscan", {}) or {}).get("hits", []) or []:
        _add(hit.get("ip", ""), "urlscan")
    for rec in (results.get("circl_pdns", {}) or {}).get("records", []) or []:
        if rec.get("rrtype") in ("A", "AAAA"):
            _add(rec.get("rdata", ""), "circl_pdns")
    # Censys only: this runs on a freshly-collected `results` dict, so the
    # retired shodan/netlas/viewdns keys can never be present here. Stored
    # payloads that do carry them are handled by the readers in db/intel_db.py.
    for hit in (results.get("censys", {}) or {}).get("hits", []) or []:
        _add(hit.get("ip", ""), "censys")

    limited = ips[:limit]
    if with_sources:
        return limited, {ip: sources[ip] for ip in limited}
    return limited


_FOLLOWUP_PROBE_CAP = 50  # how many subdomains we'll DNS-screen before ranking

# Guaranteed slots for subdomains that *don't* match a leak-hunting priority
# keyword below, even when admin/mail-type hosts are plentiful. Those keywords
# target likely-unproxied backend panels (origin-leak hunting); they say
# nothing about which host actually serves unique page content. Without this
# floor, a domain with several admin-ish subdomains (admin-contacts,
# admin-school, adminst-school, ...) can fill every follow-up slot before a
# `cdn.`/`www.`/`shop.`-style host -- the one actually likely to carry its own
# tracking IDs/favicon -- ever gets probed.
_MIN_CONTENT_FOLLOWUPS = 5


def pick_followup_subdomains(results: dict, limit: int = FOLLOWUP_LIMIT) -> list[str]:
    """
    Pick subdomains from crt.sh and HackerTarget worth a full follow-up scan.

    Previously this required a non-Cloudflare IP (an "origin leak" signal),
    which meant any subdomain that's legitimately CDN-fronted -- exactly the
    kind of host (`cdn.`, `www.`, ...) that actually serves page content and
    carries its own tracking IDs -- was silently never scanned on its own, so
    content-level matches on it (shared analytics/pixel IDs, etc.) could never
    surface. We only require that the subdomain actually resolves (skip
    dead/parked entries); origin-leak detection itself still lives separately
    in ip_intel.probe_subdomain_origins. Follow-up scans skip the paid provider
    (Censys -- see analysis_service.run_providers) regardless of what's picked
    here, so widening this selection doesn't touch paid-provider usage -- only
    DNS/WHOIS/crt.sh/page-fetch time.

    The second source is HackerTarget rather than ViewDNS: ViewDNS was the only
    subdomain source costing a paid key while returning the same
    `{"subdomain", "ip"}` shape HackerTarget already gives for free, so it was
    retired. HackerTarget was previously collected but never consulted here,
    which meant dropping ViewDNS would otherwise have left follow-ups sourced
    from crt.sh alone.
    """
    crt_subs = (results.get("crt_sh", {}) or {}).get("subdomains", []) or []
    hackertarget_subs = [
        hit.get("subdomain", "")
        for hit in (results.get("hackertarget", {}) or {}).get("hits", []) or []
        if hit.get("subdomain")
    ]
    subs = sorted({*crt_subs, *hackertarget_subs})
    priority = ("mail", "api", "dev", "staging", "admin", "portal", "vpn",
                "cpanel", "webmail", "ftp", "smtp", "ns", "autodiscover")

    def is_priority(name: str) -> bool:
        low = name.lower()
        return any(p in low for p in priority)

    def score(name: str) -> int:
        low = name.lower()
        return -sum(1 for p in priority if p in low)  # lower score = higher priority

    ordered = sorted(subs, key=score)
    if not ordered:
        return []
    to_probe = ordered[:_FOLLOWUP_PROBE_CAP]
    log_info(f"screening {len(to_probe)} subdomain(s) for follow-up")
    live: set[str] = set()
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(resolve_ips, sub): sub for sub in to_probe}
        for fut in as_completed(futures):
            sub = futures[fut]
            try:
                ips = fut.result()
            except Exception:
                ips = []
            if ips:
                live.add(sub)
    candidates = [s for s in to_probe if s in live]
    if not candidates:
        return []

    # Reserve content-likely slots first, then fill the rest in priority order.
    reserved = [s for s in candidates if not is_priority(s)][:_MIN_CONTENT_FOLLOWUPS]
    reserved_set = set(reserved)
    fill_budget = max(limit - len(reserved), 0)
    fill = [s for s in candidates if s not in reserved_set][:fill_budget]
    return reserved + fill


def _apex(hostname: str) -> str:
    """
    Crude 'apex' extractor — strip leading subdomain labels down to the
    last two labels. Good enough for `.com`, `.ru`, `.md`, etc. but will
    over-trim for multi-part TLDs like `.co.uk`. Tradeoff accepted: a full
    eTLD+1 lookup would need `tldextract`, another dep.
    """
    hostname = (hostname or "").strip(".").lower()
    # An IP literal has no apex. Splitting on dots and keeping the last two
    # labels turns 78.17.42.166 into the "domain" 42.166 — a string that is not
    # a domain, not the IP, and not anything. Censys web properties are
    # routinely keyed on a bare IP (a site served with no hostname), so this
    # reached discovered_targets and queued 42.166-style garbage for scanning.
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname
    return ".".join(parts[-2:])


def pick_sibling_domains(
    results: dict,
    target: str,
    limit: int = 5,
) -> list[dict]:
    """
    Pick *sibling* domains worth scanning — domains discovered through this
    target's collected data that are strong enough signals to warrant their
    own full scan.

    Two sources are considered high-confidence and auto-scanned:

    1. Cross-domain SANs in certs crt.sh saw for this target. Multi-SAN certs
       are issued by CAs only after all named domains pass validation, so
       they almost always indicate shared operational control.

    2. urlscan third-party scan URLs — pages on other domains that, when
       loaded, referenced our target. The kazak-center.ru pattern from the
       tsargrad investigation is exactly this.

    Returns a list of {domain, reason} dicts, deduped by apex domain.
    """
    target_apex = _apex(target)
    picks:  list[dict] = []
    seen_apex: set[str] = {target_apex}

    def _add(domain: str, reason: str) -> None:
        d = clean_target(domain)
        apex = _apex(d)
        # Don't follow up on ourselves or on anything we've already queued.
        if not apex or apex in seen_apex or apex == target_apex:
            return
        # Only follow up on apex domains, not individual subdomains — the
        # subdomain-followup path already handles those.
        if d != apex:
            return
        seen_apex.add(apex)
        picks.append({"domain": d, "reason": reason})

    # Source 1: cross-domain SANs.
    for cert in ((results.get("crt_sh") or {}).get("certs") or []):
        if not isinstance(cert, dict):
            continue
        for san in cert.get("sans") or []:
            if not isinstance(san, str):
                continue
            san_apex = _apex(san)
            # Skip SANs on our own apex — those are subdomains.
            if san_apex == target_apex:
                continue
            _add(san_apex, f"cross-domain SAN in cert (issuer={cert.get('issuer')})")
            if len(picks) >= limit:
                return picks

    # Source 2: urlscan third-party scan URLs.
    for hit in ((results.get("urlscan") or {}).get("hits") or []):
        if not isinstance(hit, dict) or not hit.get("third_party_scan"):
            continue
        scan_url = hit.get("url") or ""
        # Strip scheme/path to get the host.
        host = re.sub(r"^[a-z]+://", "", scan_url, flags=re.I)
        host = host.split("/", 1)[0]
        if host:
            _add(host, f"urlscan third-party scan on {hit.get('date')} "
                       f"(IP {hit.get('ip')})")
        if len(picks) >= limit:
            return picks

    return picks


# ── Live probe: current-state evidence ────────────────────────────────────────
# The goal here is to capture "what the domain looks like RIGHT NOW" — separate
# from the historical evidence in urlscan / CIRCL. When check.py later
# compares two scans, it needs to know whether a matched IP is the domain's
# current home or a historical ghost, and whether the domain is on a managed
# platform (Hostinger, Vercel, etc.) where SSH/IP matches come from the
# platform's backend pool rather than the site operator.

# Response-header signatures that identify managed hosting platforms. When a
# domain is on one of these, SSH/IP matches against its IP should be weighted
# down because the backend is a shared managed pool, not an operator's box.
_PLATFORM_SIGNATURES: list[tuple[str, dict[str, str]]] = [
    # (label, {header_name_lower: substring_to_match_lower})
    ("hostinger-horizons", {"x-powered-by": "hostinger horizons"}),
    ("hostinger",          {"platform":    "hostinger"}),
    ("vercel",             {"server":      "vercel"}),
    ("netlify",            {"server":      "netlify"}),
    ("github-pages",       {"server":      "github.com"}),
    ("cloudflare-pages",   {"server":      "cloudflare"}),   # also matches CF proxy
    ("squarespace",        {"server":      "squarespace"}),
    ("wix",                {"x-wix-request-id": ""}),
    ("shopify",            {"x-shopify-stage": ""}),
    ("wordpress-com",      {"x-hacker":    "wordpress.com"}),
    ("framer",             {"x-framer-site": ""}),
    ("webflow",            {"server":      "webflow"}),
]


def _detect_platform(headers: dict[str, str]) -> str | None:
    """
    From HTTP response headers, identify a managed hosting platform, if any.
    Returns a short label or None. Order matters — more specific matches
    (e.g. hostinger-horizons) should precede broader ones (hostinger).
    """
    normalized = {k.lower(): str(v or "").lower() for k, v in headers.items()}
    for label, signature in _PLATFORM_SIGNATURES:
        matched = True
        for header_name, needle in signature.items():
            value = normalized.get(header_name.lower())
            if value is None:
                matched = False
                break
            if needle and needle not in value:
                matched = False
                break
        if matched:
            return label
    return None


_GENERATOR_CMS_SIGNATURES = (
    ("wordpress", "wordpress"),
    ("drupal", "drupal"),
    ("joomla", "joomla"),
    ("ghost", "ghost"),
    ("typo3", "typo3"),
    ("wix", "wix"),
    ("squarespace", "squarespace"),
    ("shopify", "shopify"),
    ("hugo", "hugo"),
    ("jekyll", "jekyll"),
    ("bitrix", "bitrix"),
)


def _detect_cms(html: str, headers: dict[str, str], generator: str | None = None) -> str | None:
    """Quick CMS detection from the generator meta tag, then headers + HTML.

    `generator` is page_metadata.cms_generator — the `<meta name="generator">`
    value. It is checked first because it is the platform declaring itself,
    which beats inference from headers or markup. The header/HTML heuristics
    stay for the majority of hardened sites that strip the tag.

    Previously these were two independent fields (`live_probe.cms` from the
    heuristics, `page_metadata.cms_generator` from the tag) scored separately,
    so a site that both declared a generator and fingerprinted as the same CMS
    counted as two matching signals instead of one. This resolves them into a
    single value; the raw tag is still kept as `page_metadata.cms_generator`.
    """
    declared = str(generator or "").strip().lower()
    if declared:
        for needle, label in _GENERATOR_CMS_SIGNATURES:
            if needle in declared:
                return label

    normalized = {k.lower(): str(v or "") for k, v in headers.items()}

    # WordPress tells on itself in multiple ways.
    if "wp-json" in (normalized.get("link") or ""):
        return "wordpress"
    if "/xmlrpc.php" in (normalized.get("x-pingback") or ""):
        return "wordpress"
    if html and ("wp-content/" in html or "wp-includes/" in html):
        return "wordpress"
    # Drupal.
    if "drupal" in (normalized.get("x-generator") or "").lower():
        return "drupal"
    if html and "Drupal.settings" in html:
        return "drupal"
    # Joomla.
    if html and "/media/jui/" in html:
        return "joomla"
    # Ghost.
    if "ghost" in (normalized.get("x-powered-by") or "").lower():
        return "ghost"
    return None


def get_live_probe(
    domain: str,
    *,
    dns_records: dict | None = None,
    page_metadata: dict | None = None,
    html_prefix: str = "",
) -> dict:
    """
    Current-state evidence for the domain, derived rather than re-fetched:
      - what it resolves to right now
      - what HTTP status / headers its homepage returned
      - what managed platform (if any) is serving it
      - what CMS (if any) is running
      - whether it is currently reachable at all

    This used to do its own DNS resolution *and* its own HEAD/GET of the
    homepage. Both were redundant. `resolve_ips` re-queried A/AAAA that
    `get_dns` was resolving concurrently in the same scan — so "current" and
    "historical" were the same instant — and the HTTP leg re-fetched a homepage
    that `page_metadata` was fetching anyway, where
    `signal_web.capture_http_fingerprint` already recorded status, final URL,
    server and X-Powered-By plus more (header order, cookie names, CSP,
    X-Generator). Only the redirect chain and the platform fingerprint were
    unique to this function, and both are now computed from the page-metadata
    response.

    So this is now a projection over two inputs the caller already has. Both are
    optional: with neither, the result is the empty/unreachable shape rather
    than a second round of network calls, which keeps the output keys stable for
    the evidence/pairwise paths that read `live_probe.*`.
    """
    dns_records = dns_records or {}
    page_metadata = page_metadata or {}
    fingerprint = page_metadata.get("http_fingerprint") or {}
    headers_dict = fingerprint.get("headers") or {}

    v4 = [ip for ip in (dns_records.get("A") or []) if str(ip).strip()]
    v6 = [ip for ip in (dns_records.get("AAAA") or []) if str(ip).strip()]

    status = fingerprint.get("status_code") or page_metadata.get("status_code")
    final_url = fingerprint.get("url") or page_metadata.get("final_url")
    fetch_error = page_metadata.get("error")

    out: dict = {
        "probed_at":      datetime.now(timezone.utc).isoformat(),
        "current_ips":    v4,
        "current_ipv6":   v6,
        "http_status":    status,
        "final_url":      final_url,
        "redirect_chain": fingerprint.get("redirect_chain") or [],
        "server_header":  fingerprint.get("server"),
        "x_powered_by":   fingerprint.get("x_powered_by"),
        "platform":       _detect_platform(headers_dict) if headers_dict else None,
        "cms":            _detect_cms(html_prefix, headers_dict,
                                      generator=page_metadata.get("cms_generator")),
        "headers":        headers_dict,
        "reachable":      bool(status) and int(status) < 500,
        "fetch_error":    fetch_error,
    }

    if not v4 and not v6:
        out["fetch_error"] = out["fetch_error"] or "no DNS resolution"
        log_warn(f"live_probe: {domain} does not resolve")
        return out

    log_ok(f"live_probe: {domain} -> {status or '-'} "
           f"ips={len(v4)} platform={out['platform'] or '-'} "
           f"cms={out['cms'] or '-'} server={out['server_header'] or '-'}")
    return out


def annotate_historical_ips(results: dict) -> dict:
    """
    After all services run, cross-reference every IP mentioned in the scan
    against live_probe.current_ips to mark each as 'current' or 'historical'.

    This is what lets check.py weight current shared IPs more heavily
    than historical ones. A match on a current shared IP is still-live shared
    hosting; a match on a historical IP may be a ghost from years ago.
    """
    live     = results.get("live_probe") or {}
    current  = set(live.get("current_ips") or []) | set(live.get("current_ipv6") or [])

    annotation: dict = {
        "current_ips":            sorted(current),
        "all_observed_ips":       [],
        "ip_freshness":           {},   # ip -> "current" | "historical"
        "has_current_resolution": bool(current),
    }

    seen: set[str] = set()

    def _note(ip: str, source: str) -> None:
        if not ip or ip in seen:
            return
        seen.add(ip)
        annotation["all_observed_ips"].append({"ip": ip, "first_source": source})

    dns = results.get("dns") or {}
    for rtype in ("A", "AAAA"):
        for ip in (dns.get(rtype) or []):
            if isinstance(ip, str):
                _note(ip, "dns")

    for hit in ((results.get("urlscan") or {}).get("hits") or []):
        if isinstance(hit, dict):
            _note(hit.get("ip", ""), "urlscan")

    for hit in ((results.get("hackertarget") or {}).get("hits") or []):
        if isinstance(hit, dict):
            _note(hit.get("ip", ""), "hackertarget")

    for rec in ((results.get("circl_pdns") or {}).get("records") or []):
        if isinstance(rec, dict) and rec.get("rrtype") in ("A", "AAAA"):
            _note(rec.get("rdata", ""), "circl_pdns")

    for ip_info in annotation["all_observed_ips"]:
        ip_info["is_current"] = ip_info["ip"] in current

    for ip_info in annotation["all_observed_ips"]:
        annotation["ip_freshness"][ip_info["ip"]] = (
            "current" if ip_info["is_current"] else "historical"
        )

    return annotation


# ── Orchestration ─────────────────────────────────────────────────────────────

# `live_probe` is deliberately absent: it is no longer a network service but a
# projection over the `dns` and `page_metadata` results, so analyze() computes it
# after this fan-out completes rather than concurrently with them.
SERVICES = [
    ("dns",           get_dns),
    ("whois",         get_whois),
    ("crt_sh",        get_crt_sh),
    ("circl_pdns",    get_circl_pdns),
    ("hackertarget",  get_hackertarget),
    ("urlscan",       get_urlscan),
    ("censys",        get_censys),
    ("page_metadata", get_page_metadata),
]

# Cert-search providers that cost one paid/rate-limited API call per target.
# Gated behind analyze(run_providers=...) so subdomain follow-ups don't each
# fire their own Censys query.
#
# Shodan and Netlas used to sit here too. Both answered the same question as
# Censys ("which hosts serve a TLS cert naming this domain") on their own paid
# keys, and Netlas returned strictly less than the other two (ip/port/protocol
# only — no ASN, org or hostnames), so all three were billed for overlapping
# answers. Their *readers* stay: db/intel_db.py, utils/evidence_meta.py and
# utils/pairwise.py still resolve `shodan.hits`/`netlas.hits` out of payloads
# stored before this removal, so a rebuild_clusters keeps projecting the IPs
# those scans already recorded.
_PROVIDER_SERVICES = {"censys"}


# steps per analyze() call: one per service, then live_probe (derived from dns +
# page_metadata, so it bumps outside the SERVICES fan-out), TLS probe, SSH probe,
# IP enrich.
STEPS_PER_DOMAIN = len(SERVICES) + 4

# Global record of every domain we've already scanned in this process. Shared
# across analyze() calls to prevent duplicate work when a batch run turns up
# the same sibling from multiple parents.
_SCANNED_DOMAINS: set[str] = set()


def _bump(overall_bar, step_label: str, domain: str) -> None:
    """Advance the overall progress bar and update its description."""
    if overall_bar is None:
        return
    overall_bar.set_postfix_str(f"{domain[:30]} · {step_label}", refresh=False)
    overall_bar.update(1)


def analyze(domain: str, *, is_followup: bool = False,
            all_results: dict | None = None,
            overall_bar=None,
            follow_siblings: bool = True,
            run_providers: bool = True) -> dict:
    """
    Run every service on `domain`, plus TLS + SSH probes on non-CF IPs.

    If not a follow-up, also pick interesting subdomains and sibling domains
    (cross-domain SANs, urlscan third-party referrers) and recurse one level
    into each. `all_results` is the shared dict written to disk after every
    step. `overall_bar` is a tqdm bar tracking total run progress.
    `follow_siblings=False` disables sibling discovery (useful when called
    from batch mode so we don't explode the scan count).

    `run_providers=False` skips the paid/rate-limited cert-search provider
    (Censys). That is an API call per target, so running it on every discovered
    subdomain is what makes a single case burn 30+ Censys calls. A subdomain's certs/origins are already covered by
    its apex's provider search plus crt.sh / DNS / TLS probing, so callers
    pass run_providers=False for subdomain follow-ups and keep them only for
    apex-level targets.
    """
    started = time.time()
    prefix  = "└─ " if is_followup else ""
    log_info(
        f"{prefix}=== analyze {domain} === "
        f"(follow-up={is_followup}, providers={'on' if run_providers else 'off'}, "
        f"siblings={'on' if follow_siblings else 'off'})"
    )

    # Register this domain so any sibling/subdomain picker elsewhere in the
    # process skips it. Mark before scanning so recursion with the same name
    # can't double-enter.
    _SCANNED_DOMAINS.add(_apex(domain))
    _SCANNED_DOMAINS.add(domain)

    results: dict = {
        "domain":    domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # ── 1. External services ──────────────────────────────────────────────────
    # Each service is an independent network call (15-20s timeouts) with no
    # shared mutable state between them, so we fan them all out concurrently and
    # collect results as they complete. Only the main thread mutates `results`,
    # calls `save_results`, and bumps the progress bar — the worker threads just
    # perform the (thread-safe) network calls.
    def _run_service(name, fn):
        # Evaluate the skip logic inside the worker so it stays a single unit of
        # work per service; no network call is made for a skipped provider.
        if name in _PROVIDER_SERVICES and not run_providers:
            # Skip the per-target paid cert-search APIs on follow-ups; record a
            # marker so the key is present and downstream code treats it like
            # any other skipped service.
            return {"skipped": True,
                    "reason": "provider cert search runs on apex targets only"}
        return fn(domain)

    log_info(f"querying {len(SERVICES)} sources concurrently for {domain}")
    with ThreadPoolExecutor(max_workers=len(SERVICES),
                            thread_name_prefix="svc") as ex:
        future_to_name = {}
        service_started: dict = {}
        for name, fn in SERVICES:
            service_started[name] = time.time()
            # Run each service in a copy of the current context so the worker
            # thread inherits the ContextVar-based log/save hooks that
            # analysis_service._basic_runtime sets on this thread. Without this,
            # the per-provider log lines emitted *inside* each service (e.g.
            # "crt.sh: N certs") would bypass CaseRuntime._log and never reach
            # the job log / UI. A fresh copy per submit is required — a single
            # Context object cannot be entered by two threads at once.
            ctx = contextvars.copy_context()
            future_to_name[ex.submit(ctx.run, _run_service, name, fn)] = name

        for fut in as_completed(future_to_name):
            name = future_to_name[fut]
            elapsed = time.time() - service_started[name]
            try:
                results[name] = fut.result()
            except Exception as exc:
                log_warn(f"{name} crashed: {exc}")
                results[name] = {"error": str(exc)}
            log_info(f"source {name} for {domain} done in {elapsed:.1f}s")
            # Persist and bump from the main thread as each future completes.
            if all_results is not None:
                save_results(all_results)
            _bump(overall_bar, name, domain)

    # ── 1b. live_probe: projection over dns + page_metadata ───────────────────
    # Not a service (see the SERVICES comment): it needs both of those results,
    # so it runs here instead of in the fan-out. `_html_prefix` is the markup
    # page_metadata already downloaded; it feeds the CMS heuristics and is then
    # dropped so it never reaches the stored payload.
    page_meta = results.get("page_metadata")
    if not isinstance(page_meta, dict):
        page_meta = {}
    html_prefix = page_meta.pop("_html_prefix", "") or ""
    results["live_probe"] = get_live_probe(
        domain,
        dns_records=results.get("dns") or {},
        page_metadata=page_meta,
        html_prefix=html_prefix,
    )
    if all_results is not None:
        save_results(all_results)
    _bump(overall_bar, "live_probe", domain)

    # ── 2. TLS + SSH probing on non-CF IPs ────────────────────────────────────
    non_cf_ips, non_cf_ip_sources = collect_non_cf_ips(results, with_sources=True)
    log_info(f"non-CF IPs found: {len(non_cf_ips)}")
    results["non_cf_ips"] = non_cf_ips

    # Sliced explicitly now that collect_non_cf_ips returns up to
    # IP_ENRICH_LIMIT. The list arrives DNS-first (see its _add order), so the
    # IPs the domain currently resolves to are the ones that get probed and the
    # long tail of historical/Censys-discovered hosts is what falls outside —
    # which is the right way round for a socket probe of live services.
    probe_ips = non_cf_ips[:IP_PROBE_LIMIT]
    log_info(f"TLS/SSH probing {len(probe_ips)} IPs (of {len(non_cf_ips)}) for {domain}")

    # SSH runs in the background, overlapping the TLS probe *and* the whole
    # per-IP enrichment pass below, because nothing between here and the join
    # reads `ssh_host_keys`.
    #
    # It is by far the slowest probe and for a structural reason: port 22 is
    # filtered on most public hosts, so nearly all of its time is connect
    # timeouts rather than work. Measured over 20 IPs it takes ~10s against the
    # TLS probe's ~1.2s. Run in sequence, that 10s was pure dead wall-clock in
    # the middle of a scan; overlapped, the phase costs roughly whichever of SSH
    # and IP enrichment is slower instead of their sum.
    #
    # copy_context() for the same reason the SERVICES fan-out uses it: the
    # worker inherits the ContextVar log/save hooks, so probe output still
    # reaches the job log.
    ssh_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ssh-probe")
    ssh_ctx = contextvars.copy_context()
    ssh_future = ssh_pool.submit(ssh_ctx.run, get_ssh_host_keys, probe_ips)

    results["tls_certs"] = get_tls_certs(domain, probe_ips)
    if all_results is not None:
        save_results(all_results)
    _bump(overall_bar, "tls_probe", domain)

    # ── 2b. Per-IP ASN + edge/reverse-proxy classification ────────────────────
    # Runs over *every* non-CF IP (IP_ENRICH_LIMIT), not just the IP_PROBE_LIMIT
    # subset that was TLS/SSH-probed above: none of it is billed per IP, and the
    # IPs beyond the probe cap are exactly the ones a paid Censys cert search
    # surfaced, which would otherwise be stored with no ASN, geo or reputation.
    # `tls_probes_by_ip` is therefore a partial map and detect_proxy_details
    # gets None for the unprobed IPs, which it already handles.
    #
    # Feeds db/intel_db.py's ip_details storage (asn_desc, proxy_family, ...)
    # used for cross-domain clustering and the frontend's provider labels.
    tls_probes_by_ip = {
        probe.get("ip"): probe
        for probe in results["tls_certs"].get("probes", [])
        if probe.get("ip") and "error" not in probe
    }
    ip_details: dict[str, dict] = {}
    ip_total = len(non_cf_ips)
    log_info(f"enriching {ip_total} IPs (ASN/PTR/proxy) for {domain}")

    probe_tier = set(probe_ips)

    def _enrich_one_ip(ip: str) -> tuple[str, dict, float]:
        ip_started = time.time()
        ptr = get_ptr(ip)
        asn_info = get_ip_whois(ip)
        proxy_details = detect_proxy_details(ip, ptr, asn_info, tls_probes_by_ip.get(ip))

        # Domains-on-IP from both available sources, unioned. HackerTarget's
        # reverse-IP API is historical and broad on shared hosting; Censys
        # enrichment's `dns_names` is what it currently binds forward and rides
        # along free in the enrichment call already made above. Neither is a
        # superset of the other, so both contribute.
        #
        # HackerTarget is asked only about the probe-tier IPs. It is the one
        # source here that rate-limits (hard enough to trip a VPN rotation), so
        # widening this loop from IP_PROBE_LIMIT to IP_ENRICH_LIMIT would have
        # quintupled the calls against it while the two free, unmetered sources
        # in this function absorbed the change without noticing. The long tail
        # still gets its domains-on-IP from enrichment's `dns_names` — which is
        # forward-binding and therefore the more accurate half anyway.
        #
        # `other_domains_on_ip` stays a flat list of hostnames because several
        # consumers iterate it as strings (db.intel_db.normalize_ip_details,
        # _ips_table_observations, integrations.mattermost_alerts). Provenance
        # goes in the sibling map instead of changing that shape.
        enrichment = asn_info.get("censys_enrichment") or {}
        domain_sources: dict[str, list[str]] = {}
        if ip in probe_tier:
            # Bounded independently of the pool: this is the only rate-limited
            # source in the function, so it gets the throttle rather than every
            # IP paying for it.
            with _HACKERTARGET_GATE:
                reverse_names = hackertarget_reverse_ip(ip)
            for name in reverse_names:
                cleaned = str(name or "").strip().lower()
                if cleaned:
                    domain_sources.setdefault(cleaned, []).append("hackertarget")
        for name in enrichment.get("dns_names") or []:
            cleaned = str(name or "").strip().lower()
            if cleaned and "censys_enrichment" not in domain_sources.setdefault(cleaned, []):
                domain_sources[cleaned].append("censys_enrichment")

        detail = {
            "sources":                     non_cf_ip_sources.get(ip, []),
            "ptr":                         ptr,
            "cloudflare":                  False,
            "asn_info":                    asn_info,
            "other_domains_on_ip":         sorted(domain_sources),
            "other_domains_on_ip_sources": domain_sources,
            "proxy_family":                proxy_details.get("proxy_family"),
            "proxy_confidence":            proxy_details.get("proxy_confidence"),
        }
        return ip, detail, time.time() - ip_started

    if non_cf_ips:
        with ThreadPoolExecutor(
            max_workers=min(_IP_ENRICH_WORKERS, len(non_cf_ips)),
            thread_name_prefix="ip-enrich",
        ) as ex:
            futures = {ex.submit(_enrich_one_ip, ip): ip for ip in non_cf_ips}
            for idx, fut in enumerate(as_completed(futures), 1):
                try:
                    ip, detail, ip_elapsed = fut.result()
                except Exception as exc:
                    failed_ip = futures[fut]
                    log_warn(f"  IP enrichment failed for {failed_ip}: {exc}")
                    continue
                ip_details[ip] = detail
                log_info(
                    f"  IP {idx}/{ip_total} {ip} enriched in {ip_elapsed:.1f}s"
                    f"{'  <== SLOW' if ip_elapsed >= 5 else ''}"
                )
    results["ip_details"] = ip_details

    # Join the SSH probe started before the TLS probe. By now it has had the TLS
    # probe and the entire enrichment fan-out to finish in, so this is usually
    # already done. Failures are contained: a probe error must not lose the
    # enrichment work this function just did.
    try:
        results["ssh_host_keys"] = ssh_future.result()
    except Exception as exc:
        log_warn(f"SSH probe failed: {exc}")
        results["ssh_host_keys"] = {"probes": [], "error": str(exc)}
    finally:
        ssh_pool.shutdown(wait=False)
    _bump(overall_bar, "ssh_probe", domain)

    if all_results is not None:
        save_results(all_results)
    _bump(overall_bar, "ip_enrich", domain)

    # ── Freshness annotation: mark each observed IP as current vs historical ──
    # Runs after every service + probe completes, so the result has both the
    # live resolution from live_probe and the accumulated historical IPs from
    # urlscan / hackertarget / circl_pdns.
    log_info(f"annotating IP freshness for {domain}")
    results["freshness"] = annotate_historical_ips(results)
    if all_results is not None:
        save_results(all_results)

    # ── 3. Follow-up recursion (top level only) ───────────────────────────────
    # One level of recursion: if we're a follow-up ourselves, don't recurse
    # further, otherwise we could kick off a branching explosion.
    if not is_followup:
        # 3a. Subdomains of our target that leak a non-CF origin IP.
        sub_picks = pick_followup_subdomains(results)
        # Filter out anything already scanned earlier in the run.
        sub_picks = [s for s in sub_picks if s not in _SCANNED_DOMAINS]
        log_info(f"subdomain follow-ups: {len(sub_picks)} selected "
                 f"({', '.join(sub_picks) or 'none'})")

        # 3b. Sibling apex domains discovered through cross-SANs and urlscan.
        sibling_picks: list[dict] = []
        if follow_siblings:
            sibling_picks = [
                p for p in pick_sibling_domains(results, domain)
                if p["domain"] not in _SCANNED_DOMAINS
            ]
            if sibling_picks:
                log_info(f"sibling follow-ups: {len(sibling_picks)} selected")
                for p in sibling_picks:
                    log_info(f"      · {p['domain']}  [{p['reason']}]")

        # Grow the progress bar total to reflect the newly-queued work.
        total_new = len(sub_picks) + len(sibling_picks)
        if overall_bar is not None and total_new:
            overall_bar.total += total_new * STEPS_PER_DOMAIN
            overall_bar.refresh()

        results["subdomain_followups"] = []
        results["sibling_followups"]   = []

        for idx, sub in enumerate(sub_picks, 1):
            log_info(f"[{domain}] subdomain follow-up {idx}/{len(sub_picks)}: {sub}")
            sub_result = analyze(sub, is_followup=True,
                                 all_results=all_results,
                                 overall_bar=overall_bar,
                                 follow_siblings=False)
            results["subdomain_followups"].append(sub_result)
            if all_results is not None:
                all_results["subdomain_followups"] = results["subdomain_followups"]
                save_results(all_results)

        for idx, pick in enumerate(sibling_picks, 1):
            log_info(f"[{domain}] sibling follow-up {idx}/{len(sibling_picks)}: "
                     f"{pick['domain']} [{pick['reason']}]")
            sib_result = analyze(pick["domain"], is_followup=True,
                                 all_results=all_results,
                                 overall_bar=overall_bar,
                                 follow_siblings=False)
            # Annotate with discovery reason so the output shows *why* this
            # sibling was scanned — vital when reviewing later.
            results["sibling_followups"].append({
                "discovered_from": domain,
                "reason":          pick["reason"],
                "result":          sib_result,
            })
            if all_results is not None:
                all_results["sibling_followups"] = results["sibling_followups"]
                save_results(all_results)

    elapsed = time.time() - started
    log_ok(f"{prefix}{domain} done in {elapsed:.1f}s")
    return results


def clean_target(target: str) -> str:
    """
    Normalize a URL/domain string into a bare hostname.

    Handles: scheme prefixes, leading www., trailing paths/queries,
    surrounding whitespace and quotes from CSV input.
    """
    # Strip quoting and whitespace from sloppy CSV rows.
    target = target.strip().strip('"').strip("'").strip()
    # Drop scheme.
    target = re.sub(r'^[a-z]+://', '', target, flags=re.I)
    # Drop everything after the first slash / question mark / hash.
    target = re.split(r'[/?#]', target, maxsplit=1)[0]
    # Drop leading www. (but keep things like www2.).
    target = re.sub(r'^www\.', '', target, flags=re.I)
    return target.strip().lower()


def read_targets_csv(path: Path) -> list[str]:
    """
    Read a CSV of URLs/domains (no header). One per row; only the first
    column is consulted. Blank lines and duplicates are dropped while
    preserving first-seen order.
    """
    import csv
    seen: set[str] = set()
    out: list[str] = []
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row:
                continue
            target = clean_target(row[0])
            if target and target not in seen:
                seen.add(target)
                out.append(target)
    return out


def safe_filename(target: str) -> str:
    """Turn a domain into a filesystem-safe filename stem."""
    return re.sub(r"[^a-zA-Z0-9._-]", "_", target)


def run_batch(csv_path: Path, out_dir: Path, *,
              follow_siblings: bool = True,
              max_depth: int = 2,
              max_domains: int = 200) -> None:
    """
    Run `analyze` on every domain in csv_path. When sibling domains are
    discovered (cross-SANs, urlscan third-party referrers), they are added to
    the queue and scanned the same way as the originals — same service set,
    same probes, same chance to discover their own siblings.

    max_depth caps how far the expansion goes from the original CSV:
      depth 0 = CSV only
      depth 1 = CSV + their siblings
      depth 2 = CSV + siblings + sibling's siblings  (default)

    max_domains is a hard ceiling regardless of depth, to stop runaway crawls
    if a popular IP produces cascading discoveries.
    """
    targets = read_targets_csv(csv_path)
    if not targets:
        print(f"  [!] No valid targets found in {csv_path}")
        sys.exit(1)

    # Pre-register every input target in the global dedup set so siblings
    # don't get double-queued if they were already on the input list.
    for t in targets:
        _SCANNED_DOMAINS.add(t)
        _SCANNED_DOMAINS.add(_apex(t))

    out_dir.mkdir(parents=True, exist_ok=True)
    scans_dir = out_dir / "scans"
    scans_dir.mkdir(exist_ok=True)

    note = ""
    if not follow_siblings:
        note = "  (sibling expansion disabled)"
    else:
        note = f"  (max depth {max_depth}, max domains {max_domains})"
    print(f"\n  ip-intel batch  |  {len(targets)} target(s) → {out_dir}{note}\n")

    # Queue entries are dicts so we can carry per-domain context — which
    # CSV entry this came from, how we discovered it, and at what depth.
    # A list-backed FIFO is fine; we don't need collections.deque speed here.
    queue: list[dict] = [
        {"domain": t, "depth": 0, "discovered_from": None, "reason": "input CSV"}
        for t in targets
    ]

    # Batch progress bar total grows as new siblings enter the queue.
    batch_bar = tqdm(
        total=len(queue),
        desc="  BATCH",
        unit="domain",
        dynamic_ncols=True,
        leave=True,
        bar_format="{desc}: |{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}",
        file=sys.stdout,
        position=0,
    )

    manifest:      list[dict] = []
    batch_started: float       = time.time()
    scanned_count: int         = 0

    while queue:
        entry = queue.pop(0)
        target      = entry["domain"]
        depth       = entry["depth"]
        discovered  = entry["discovered_from"]
        reason      = entry["reason"]

        if scanned_count >= max_domains:
            log_warn(f"max_domains ({max_domains}) reached — stopping expansion. "
                     f"{len(queue)} domain(s) left un-scanned.")
            break

        depth_note = f"depth {depth}"
        if discovered:
            depth_note += f" · from {discovered}"
        batch_bar.set_postfix_str(f"{target[:36]}  [{depth_note}]", refresh=True)

        scan_file = scans_dir / f"{safe_filename(target)}.json"

        # Redirect per-domain output to its own file.
        global OUTPUT_FILE
        old_output_file = OUTPUT_FILE
        OUTPUT_FILE = scan_file

        started     = time.time()
        all_results: dict = {}
        error_msg:   str | None = None

        # Siblings are followed by the OUTER loop (via the queue), not by
        # analyze() itself — so we disable the inner follow_siblings mechanism
        # here. This keeps sibling scans fully first-class (same full service
        # run, full probes, promoted top-level scan file) instead of being
        # nested inside a parent's result.
        try:
            overall_bar = tqdm(
                total=STEPS_PER_DOMAIN,
                desc=f"  └─ {target[:30]}",
                unit="step",
                dynamic_ncols=True,
                leave=False,
                bar_format="{desc}: |{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}",
                file=sys.stdout,
                position=1,
            )
            try:
                result = analyze(target,
                                 all_results=all_results,
                                 overall_bar=overall_bar,
                                 follow_siblings=False)
            finally:
                overall_bar.close()
            all_results.update(result)
            # Stamp the scan with discovery provenance so the trail is
            # visible to downstream readers of the JSON file.
            all_results["discovered_from"] = discovered
            all_results["discovery_reason"] = reason
            all_results["scan_depth"] = depth
            save_results(all_results)
        except Exception as exc:
            error_msg = str(exc)
            log_warn(f"{target} crashed: {exc}")
            if all_results:
                save_results(all_results)
        finally:
            OUTPUT_FILE = old_output_file

        elapsed = time.time() - started
        manifest.append({
            "domain":          target,
            "file":            scan_file.name,
            "elapsed":         round(elapsed, 1),
            "error":           error_msg,
            "depth":           depth,
            "discovered_from": discovered,
            "reason":          reason,
        })
        scanned_count += 1

        # If expansion is enabled and we haven't hit the depth cap, extract
        # siblings from this scan and enqueue them at depth+1.
        if follow_siblings and depth < max_depth and not error_msg:
            siblings = pick_sibling_domains(all_results, target)
            new_siblings = [
                s for s in siblings
                if s["domain"] not in _SCANNED_DOMAINS
                and _apex(s["domain"]) not in _SCANNED_DOMAINS
            ]
            for pick in new_siblings:
                _SCANNED_DOMAINS.add(pick["domain"])
                _SCANNED_DOMAINS.add(_apex(pick["domain"]))
                queue.append({
                    "domain":          pick["domain"],
                    "depth":           depth + 1,
                    "discovered_from": target,
                    "reason":          pick["reason"],
                })
                log_info(f"queued sibling @ depth {depth + 1}: "
                         f"{pick['domain']}  [{pick['reason']}]")
            if new_siblings:
                batch_bar.total += len(new_siblings)
                batch_bar.refresh()

        batch_bar.update(1)

    batch_bar.close()

    # Save manifest so the compare step knows what to load.
    manifest_file = out_dir / "manifest.json"
    manifest_file.write_text(json.dumps({
        "input_targets":  targets,
        "scans":          manifest,
        "scanned_count":  scanned_count,
        "queue_unscanned": [e["domain"] for e in queue],  # hit max_domains
        "max_depth":      max_depth,
        "max_domains":    max_domains,
        "total_elapsed":  round(time.time() - batch_started, 1),
    }, indent=2, default=str))

    successful = [m for m in manifest if m["error"] is None]
    print()
    log_ok(f"batch complete: {len(successful)}/{scanned_count} successful  "
           f"({time.time() - batch_started:.1f}s total)")
    log_ok(f"  input: {len(targets)}  →  scanned: {scanned_count}  "
           f"(expansion added {scanned_count - len(targets)} domain(s))")
    if queue:
        log_warn(f"  {len(queue)} queued domain(s) not scanned (max_domains reached)")

    if len(successful) < 2:
        print(f"  [!] Need at least 2 successful scans to run comparisons")
        return

    # Kick off the pairwise comparison step.
    print()
    log_info("running pairwise comparison across all scans...")
    try:
        from utils.pairwise import compare_directory
        compare_directory(scans_dir, out_dir / "overlaps")
    except ImportError:
        log_warn("utils/pairwise.py not importable — run it manually with:")
        print(f"      python -m utils.pairwise --dir {scans_dir} {out_dir / 'overlaps'}")
        return

    return scans_dir


def _extract_dive_targets(overlap_dir: Path, top_n: int = 5) -> list[dict]:
    """
    From the top N scoring pairs in summary.json, pull out artifacts worth
    scanning directly: shared IPs, cert-named third domains, and urlscan
    cross-referrer apex domains.

    Returns a list of {target, kind, reason, source_pair} dicts.
    Deduplicated against _SCANNED_DOMAINS so we don't re-scan.
    """
    summary_file = overlap_dir / "summary.json"
    if not summary_file.exists():
        return []

    try:
        summary = json.loads(summary_file.read_text())
    except Exception:
        return []

    pairs = (summary.get("pairs") or [])[:top_n]
    if not pairs:
        return []

    found: list[dict] = []
    seen:  set[str]  = set()

    def _add(target: str, kind: str, reason: str, source_pair: str) -> None:
        target = (target or "").strip()
        if not target:
            return
        # Normalize apex for dedup; keep the original for display/scanning.
        key = _apex(target) if not is_ip(target) else target
        if key in _SCANNED_DOMAINS or key in seen:
            return
        seen.add(key)
        found.append({
            "target":       target,
            "kind":         kind,
            "reason":       reason,
            "source_pair":  source_pair,
        })

    for pair_info in pairs:
        pair_name = f"{pair_info.get('a_domain')} ↔ {pair_info.get('b_domain')}"
        pair_file = overlap_dir / pair_info.get("file", "")
        if not pair_file.exists():
            continue
        try:
            pair_data = json.loads(pair_file.read_text())
        except Exception:
            continue

        matches = pair_data.get("matches") or {}

        # Artifact 1: shared IPs (non-CF only — CF is anycast, IP scan pointless).
        for ip_path in ("non_cf_ips", "dns.A", "hackertarget.hits[*].ip",
                        "urlscan.hits[*].ip"):
            for ip in (matches.get(ip_path) or []):
                if isinstance(ip, str) and not is_cloudflare_ip(ip):
                    _add(ip, "ip",
                         f"shared IP ({ip_path}) in top pair",
                         pair_name)

        # Artifact 2: cert-named third domains when quality=="weak".
        # Those are the operator-backend candidates (like 074uuu.top).
        cert_quality = pair_data.get("cert_quality") or {}
        if cert_quality.get("quality") == "weak":
            # The CN that triggered the match is stored under the matches key
            # tls_certs.probes[*].cn — pick it up there.
            for cn in (matches.get("tls_certs.probes[*].cn") or []):
                if isinstance(cn, str):
                    _add(cn, "cert_cn",
                         f"backend cert CN from top pair (quality=weak — "
                         f"may be operator management domain)",
                         pair_name)

        # Artifact 3: urlscan cross-referrer apex domains.
        for finding in (pair_data.get("urlscan_cross_refs") or []):
            if not isinstance(finding, dict):
                continue
            rel = finding.get("relationship")
            if rel not in ("shared_referrer", "both_third_party"):
                continue
            for side in ("a", "b"):
                scan_url = (finding.get(side) or {}).get("scan_url") or ""
                host = re.sub(r"^[a-z]+://", "", scan_url, flags=re.I)
                host = host.split("/", 1)[0]
                if host:
                    _add(_apex(host), "referrer",
                         f"urlscan cross-referrer ({rel}) in top pair",
                         pair_name)

    return found


def run_dive_round(scans_dir: Path, out_dir: Path, *,
                   top_n: int = 5,
                   max_dive_targets: int = 15) -> None:
    """
    After the initial batch + comparison pass, pull artifacts from the top N
    scoring pairs and scan them directly. Then re-run comparison so the new
    scans participate in the ranking.

    One dive round only — not recursive. If you want to dive again, re-invoke.
    """
    overlap_dir = out_dir / "overlaps"

    dive_targets = _extract_dive_targets(overlap_dir, top_n=top_n)
    if not dive_targets:
        log_info("dive: nothing new to scan (either no top pairs, or all "
                 "artifacts already scanned)")
        return

    # Cap total dive size so a single top-pair with many shared artifacts
    # doesn't trigger 30 extra scans.
    truncated = False
    if len(dive_targets) > max_dive_targets:
        truncated = True
        dive_targets = dive_targets[:max_dive_targets]

    print()
    log_info(f"=== DIVE ROUND ===  top {top_n} pair(s) → {len(dive_targets)} new target(s)"
             f"{' (capped)' if truncated else ''}")
    for t in dive_targets:
        log_info(f"  · [{t['kind']:8s}] {t['target']}  ←  {t['source_pair']}")

    dive_bar = tqdm(
        total=len(dive_targets),
        desc="  DIVE",
        unit="target",
        dynamic_ncols=True,
        leave=True,
        bar_format="{desc}: |{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}",
        file=sys.stdout,
        position=0,
    )

    global OUTPUT_FILE
    for t in dive_targets:
        target = t["target"]
        kind   = t["kind"]
        dive_bar.set_postfix_str(f"{target[:36]}  [{kind}]", refresh=True)

        safe_stem = safe_filename(target)
        scan_file = scans_dir / f"{safe_stem}.json"
        if scan_file.exists():
            # Already written — probably from an earlier dive or from the main
            # batch. Skip without scanning.
            dive_bar.update(1)
            continue

        old_output = OUTPUT_FILE
        OUTPUT_FILE = scan_file
        try:
            if is_ip(target):
                result = analyze_ip(target)
                # Annotate provenance so downstream readers know how we got here.
                result["discovered_from"] = t["source_pair"]
                result["discovery_reason"] = t["reason"]
                result["discovery_kind"]   = kind
                save_results(result)
            else:
                all_results: dict = {}
                overall_bar = tqdm(
                    total=STEPS_PER_DOMAIN,
                    desc=f"  └─ {target[:30]}",
                    unit="step",
                    dynamic_ncols=True,
                    leave=False,
                    bar_format="{desc}: |{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}",
                    file=sys.stdout,
                    position=1,
                )
                try:
                    result = analyze(target,
                                     all_results=all_results,
                                     overall_bar=overall_bar,
                                     follow_siblings=False)
                finally:
                    overall_bar.close()
                all_results.update(result)
                all_results["discovered_from"]  = t["source_pair"]
                all_results["discovery_reason"] = t["reason"]
                all_results["discovery_kind"]   = kind
                save_results(all_results)
            _SCANNED_DOMAINS.add(target)
            _SCANNED_DOMAINS.add(_apex(target))
        except Exception as exc:
            log_warn(f"dive scan failed for {target}: {exc}")
        finally:
            OUTPUT_FILE = old_output
        dive_bar.update(1)

    dive_bar.close()

    # Re-run comparison so the new scans participate in the ranking.
    print()
    log_info("dive done — re-running pairwise comparison with dive results included...")
    try:
        from utils.pairwise import compare_directory
        compare_directory(scans_dir, overlap_dir)
    except ImportError:
        log_warn("utils/pairwise.py not importable — run it manually")


def is_ip(target: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def get_ip_whois(ip: str) -> dict:
    """ASN/network lookup for a bare IP: ipinfo Lite, then Censys enrichment.

    ipinfo Lite owns asn/asn_description/asn_country (see merge_ipinfo_lite);
    Censys host enrichment supplies network_name/network_cidr (from its WHOIS
    network block, falling back to bgp_prefix) plus everything only it has —
    reputation, GreyNoise, threat classification, VPN/proxy/hosting flags,
    abuse contacts and city-level geo.

    The RDAP leg (ipwhois.lookup_rdap) was removed. Once enrichment landed,
    RDAP's only unique fields were asn_cidr and asn_registry, and it was the
    slowest, least reliable source in the chain — per-RIR timeouts and hard
    rate limits were the sole reason the per-IP enrichment loop in analyze()
    had to run sequentially. Dropping it lets that loop go concurrent.

    Consequence worth knowing: `asn_info` no longer carries asn_cidr,
    asn_registry or network_country. The `ips.asn_registry` column is left in
    place (nullable) so rows written before this change still read back.
    """
    asn_info: dict = {}
    return merge_censys_enrichment(merge_ipinfo_lite(asn_info, ip), ip)


def get_ptr(ip: str) -> str | None:
    """Reverse-DNS lookup for an IP."""
    try:
        import dns.reversename
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        rev = dns.reversename.from_address(ip)
        # One PTR per IP-enrichment worker, so this is a real contributor to
        # total DNS pressure even though each call is cheap.
        with _DNS_GATE:
            answers = resolver.resolve(rev, "PTR")
        return str(answers[0]).rstrip(".")
    except Exception:
        return None


def hackertarget_reverse_ip(ip: str) -> list[str]:
    """Reverse-IP hostname lookup via HackerTarget's free API."""
    try:
        resp = requests.get(
            "https://api.hackertarget.com/reverseiplookup/",
            params={"q": ip},
            timeout=15,
            **requests_kwargs(),
        )
        if resp.status_code != 200:
            return []
        text = resp.text.strip()
        if "error" in text.lower() or "API count" in text:
            return []
        return [line.strip() for line in text.splitlines() if line.strip()]
    except Exception:
        return []


def analyze_ip(ip: str) -> dict:
    """Streamlined scan for a bare IP. Skips all the domain-only services."""
    log_info(f"analyzing IP {ip}")
    cf = is_cloudflare_ip(ip)

    result: dict = {
        "input":      ip,
        "type":       "ip",
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "cloudflare": cf,
    }

    result["ptr"]      = get_ptr(ip)
    log_ok(f"PTR: {result['ptr']}")
    result["asn_info"] = get_ip_whois(ip)
    asn_info = result["asn_info"]
    if "asn" in asn_info:
        log_ok(f"ASN: AS{asn_info.get('asn')} ({asn_info.get('asn_description')}) "
               f"{asn_info.get('asn_country')}")

    # Reverse-IP lookup only makes sense for non-Cloudflare IPs — CF is
    # anycast across millions of customers.
    if cf:
        log_warn("skipping reverse-IP — Cloudflare anycast")
        result["reverse_dns_hits"] = []
    else:
        result["reverse_dns_hits"] = hackertarget_reverse_ip(ip)
        log_ok(f"reverse-IP hits: {len(result['reverse_dns_hits'])}")

    # TLS + SSH probes. We use the PTR as SNI if we have one, otherwise the
    # IP itself — gives us whatever default-vhost cert the server serves.
    sni = result.get("ptr") or ip
    log_info(f"TLS probe with SNI={sni}")
    tls = _probe_tls(ip, sni)
    result["tls_cert"] = tls
    if tls and "error" not in tls:
        log_ok(f"TLS cert: CN={tls.get('cn')} issuer={tls.get('issuer_cn')} "
               f"expires={tls.get('not_after')}")

    if not cf:
        log_info("SSH probe on port 22")
        ssh = _probe_ssh(ip)
        result["ssh_host_key"] = ssh
        if ssh and "error" not in ssh:
            log_ok(f"SSH: {ssh.get('banner')} "
                   f"key={ssh.get('fingerprint_sha256', '')[:16]}…")
    else:
        result["ssh_host_key"] = None

    proxy_details = detect_proxy_details(
        ip, result.get("ptr"), asn_info, tls if tls and "error" not in tls else None
    )
    result["proxy_family"]     = proxy_details.get("proxy_family")
    result["proxy_confidence"] = proxy_details.get("proxy_confidence")
    if result["proxy_family"]:
        log_ok(f"proxy family: {result['proxy_family']} "
               f"(confidence={result['proxy_confidence']})")

    return result


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(prog="ip_intel",
                                     description="Domain / IP intelligence tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("target", nargs="?", help="Single domain, URL, or IP to scan")
    group.add_argument("--csv", type=Path,
                       help="CSV file of URLs/domains (no header) to batch-scan")
    parser.add_argument("--out", type=Path, default=Path(__file__).parent / "batch_out",
                        help="Output directory for batch mode (default: ./batch_out)")
    parser.add_argument("--no-sibling-followups", action="store_true",
                        help="Disable auto-scanning of sibling domains (cross-SANs, "
                             "urlscan third-party referrers). Subdomain follow-ups "
                             "still run. Useful for fast scans or when you want to "
                             "curate the follow-up list manually.")
    parser.add_argument("--max-depth", type=int, default=2, metavar="N",
                        help="In batch mode, how many hops from the original CSV "
                             "to follow sibling discoveries. 0 = CSV only. "
                             "Default: 2.")
    parser.add_argument("--max-domains", type=int, default=200, metavar="N",
                        help="In batch mode, hard cap on total domains scanned. "
                             "Stops runaway crawls. Default: 200.")
    parser.add_argument("--dive", action="store_true",
                        help="After the batch and comparison finish, pull "
                             "artifacts (shared IPs, backend cert CNs, "
                             "urlscan cross-referrers) from the top-scoring "
                             "pairs and scan them directly, then re-run "
                             "comparison. One round only.")
    parser.add_argument("--dive-top", type=int, default=5, metavar="N",
                        help="How many top-scoring pairs to mine for dive "
                             "targets. Default: 5.")
    parser.add_argument("--dive-max-targets", type=int, default=15, metavar="N",
                        help="Hard cap on dive targets per round. Default: 15.")
    args = parser.parse_args()

    follow_siblings = not args.no_sibling_followups

    if args.csv:
        scans_dir = run_batch(args.csv, args.out,
                              follow_siblings=follow_siblings,
                              max_depth=args.max_depth,
                              max_domains=args.max_domains)
        if args.dive and scans_dir:
            run_dive_round(scans_dir, args.out,
                           top_n=args.dive_top,
                           max_dive_targets=args.dive_max_targets)
        return

    target = clean_target(args.target)

    # IP vs domain split. IPs get a streamlined scan — no crt.sh, no domain
    # WHOIS, no page-metadata scrape for the bare IP.
    if is_ip(target):
        print(f"\n  ip-intel  |  target: {target} (IP mode)\n")
        started = time.time()
        result = analyze_ip(target)
        save_results(result)
        print()
        log_ok(f"total runtime: {time.time() - started:.1f}s")
        print(f"  [+] Saved → {OUTPUT_FILE}\n")
        return

    domain  = target
    started = time.time()

    print(f"\n  ip-intel  |  target: {domain}\n")

    all_results: dict = {}
    overall_bar = tqdm(
        total=STEPS_PER_DOMAIN,
        desc="  OVERALL",
        unit="step",
        dynamic_ncols=True,
        leave=True,
        bar_format="{desc}: |{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}",
        file=sys.stdout,
    )

    try:
        result = analyze(domain,
                         all_results=all_results,
                         overall_bar=overall_bar,
                         follow_siblings=follow_siblings)
    finally:
        overall_bar.close()

    all_results.update(result)
    save_results(all_results)

    print()
    log_ok(f"total runtime: {time.time() - started:.1f}s")
    print(f"  [+] Saved → {OUTPUT_FILE}\n")


if __name__ == "__main__":
    main()
