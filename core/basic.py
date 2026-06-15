#!/usr/bin/env python3
"""
ip_intel.py — Simple domain intelligence tool.

One function per service. Each takes a domain (or the inputs it needs) and
returns a dict. Results are saved to results.json after every step so you
can tail it while the run progresses.

Usage:
    python ip_intel.py <domain>
"""

import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import dns.resolver
import requests
import whois
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from dotenv import load_dotenv
from tqdm import tqdm

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
FOLLOWUP_LIMIT  = 5     # max subdomains to recurse into
IP_PROBE_LIMIT  = 20    # max IPs to TLS/SSH probe per run


# ── Logging helpers ───────────────────────────────────────────────────────────

def log(msg: str, level: str = "*") -> None:
    """Print a timestamped log line via tqdm.write so bars aren't clobbered."""
    stamp = datetime.now().strftime("%H:%M:%S")
    tqdm.write(f"  [{level}] {stamp}  {msg}")


def log_info(msg: str) -> None: log(msg, "*")
def log_ok(msg: str)   -> None: log(msg, "+")
def log_warn(msg: str) -> None: log(msg, "!")


# ── Storage ───────────────────────────────────────────────────────────────────

def save_results(results: dict) -> None:
    """Write the running results dict to disk."""
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


def resolve_ips(hostname: str) -> list[str]:
    """Return A + AAAA for hostname, empty list on failure."""
    resolver = dns.resolver.Resolver()
    resolver.timeout  = 5
    resolver.lifetime = 8
    ips: list[str] = []
    for rtype in ("A", "AAAA"):
        try:
            ips.extend(str(r) for r in resolver.resolve(hostname, rtype))
        except Exception:
            pass
    return ips


# ── Services ──────────────────────────────────────────────────────────────────

def get_dns(domain: str) -> dict:
    """Resolve A, AAAA, MX, NS, TXT, SOA, CNAME, CAA records (parallel lookups)."""

    def _resolve_one(rtype: str) -> tuple[str, object]:
        resolver = dns.resolver.Resolver()
        resolver.timeout  = 5
        resolver.lifetime = 10
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
    """Domain WHOIS lookup."""
    try:
        w = whois.whois(domain)

        def _fmt(v):
            if v is None:
                return None
            if isinstance(v, list):
                return [str(x) for x in v]
            return str(v)

        result = {
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
        log_ok(f"WHOIS: registrar={result['registrar']} created={result['creation_date']}")
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


def get_hackertarget(domain: str) -> dict:
    """Subdomains + IPs from HackerTarget hostsearch."""
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
            headers={"User-Agent": "ip-intel/1.0"},
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
        resp = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": "100"},
            headers={"User-Agent": "ip-intel/1.0"},
            timeout=15,
            **requests_kwargs(),
        )
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
    """Hosts serving a TLS cert matching the domain (needs CENSYS_API_KEY)."""
    api_key = os.environ.get("CENSYS_API_KEY")
    org_id  = os.environ.get("CENSYS_ORG_ID")
    if not api_key:
        return {"skipped": True, "reason": "CENSYS_API_KEY not set"}
    if not org_id:
        return {"skipped": True, "reason": "CENSYS_ORG_ID not set"}
    try:
        from censys_platform import SDK
    except ImportError:
        return {"skipped": True, "reason": "censys_platform not installed"}

    try:
        with SDK(personal_access_token=api_key, organization_id=org_id) as sdk:
            query = f'host.services.cert.names = "{domain}"'
            resp = sdk.global_data.search(search_query_input_body={
                "query":     query,
                "fields":    ["host.ip"],
                "page_size": 100,
            })
        # The generated SDK returns resp.result (a SearchQueryResponse) whose
        # model_dump() nests the real payload under a further "result" key;
        # each hit wraps the host under host_v1.resource. Navigate via
        # model_dump() so we don't depend on drifting typed attribute paths.
        outer   = resp.result.model_dump() if hasattr(getattr(resp, "result", None), "model_dump") else {}
        payload = outer.get("result") or outer
        hits = []
        for hit in (payload.get("hits") or []):
            ip = ((hit.get("host_v1") or {}).get("resource") or {}).get("ip")
            if ip:
                hits.append({"ip": ip})
        log_ok(f"Censys: {len(hits)} hits")
        return {"hits": hits}
    except Exception as exc:
        log_warn(f"Censys failed: {exc}")
        return {"error": str(exc)}


def get_shodan(domain: str) -> dict:
    """Shodan hosts matching ssl:<domain> (needs SHODAN_API_KEY)."""
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return {"skipped": True, "reason": "SHODAN_API_KEY not set"}
    try:
        import shodan
    except ImportError:
        return {"skipped": True, "reason": "shodan not installed"}

    try:
        api  = shodan.Shodan(api_key)
        resp = api.search(f'ssl:"{domain}"', minify=False)
        hits = []
        for match in resp.get("matches", []):
            hits.append({
                "ip":        match.get("ip_str"),
                "asn":       match.get("asn"),
                "org":       match.get("org"),
                "ports":     match.get("ports", []),
                "hostnames": match.get("hostnames", []),
            })
        log_ok(f"Shodan: {len(hits)} hits (total={resp.get('total')})")
        return {"total": resp.get("total", len(hits)), "hits": hits}
    except Exception as exc:
        log_warn(f"Shodan failed: {exc}")
        return {"error": str(exc)}


def get_netlas(domain: str) -> dict:
    """Netlas hosts with TLS cert matching domain (needs NETLAS_API_KEY)."""
    api_key = os.environ.get("NETLAS_API_KEY")
    if not api_key:
        return {"skipped": True, "reason": "NETLAS_API_KEY not set"}
    try:
        import netlas
    except ImportError:
        return {"skipped": True, "reason": "netlas not installed"}

    try:
        conn  = netlas.Netlas(api_key=api_key)
        query = f'certificate.subject.common_name:"{domain}"'
        resp  = conn.query(query=query, datatype="response", page=0)
        hits  = []
        for item in (resp or {}).get("items", []):
            data = item.get("data", {})
            ip   = data.get("ip")
            if ip:
                hits.append({
                    "ip":       ip,
                    "port":     data.get("port"),
                    "protocol": data.get("protocol"),
                })
        log_ok(f"Netlas: {len(hits)} hits")
        return {"hits": hits}
    except Exception as exc:
        log_warn(f"Netlas failed: {exc}")
        return {"error": str(exc)}


def get_page_metadata(domain: str) -> dict:
    """Fetch homepage and extract tracking IDs, CMS generator, social links."""
    out = {
        "google_analytics": [], "gtm_ids": [], "facebook_pixel": [],
        "yandex_metrika": [], "html_lang": None, "cms_generator": None,
        "social_links": {}, "fetched_insecure": False, "fetched_http": False,
    }

    headers = {"User-Agent": "Mozilla/5.0 (compatible; ip-intel/1.0)"}
    html: str | None = None
    last_err: str | None = None

    # Try HTTPS with normal verification first.
    try:
        resp = requests.get(f"https://{domain}", headers=headers,
                            timeout=15, allow_redirects=True,
                            **requests_kwargs())
        html = resp.text
    except Exception as exc:
        last_err = str(exc)

    # If that failed with any TLS/cert error, retry without verification. We're
    # not doing auth here — just scraping the rendered page for signals — so
    # an expired or mismatched cert shouldn't cost us the whole result.
    if html is None and last_err and any(
        needle in last_err.lower()
        for needle in ("certificate", "sslerror", "ssl:", "ssl error")
    ):
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            resp = requests.get(f"https://{domain}", headers=headers,
                                timeout=15, allow_redirects=True, verify=False,
                                **requests_kwargs())
            html = resp.text
            out["fetched_insecure"] = True
            log_warn(f"page_metadata: {domain} has broken TLS — fetched anyway")
        except Exception as exc:
            last_err = str(exc)

    # Last resort: plain HTTP.
    if html is None:
        try:
            resp = requests.get(f"http://{domain}", headers=headers,
                                timeout=15, allow_redirects=True,
                                **requests_kwargs())
            html = resp.text
            out["fetched_http"] = True
            log_warn(f"page_metadata: {domain} fell back to plain HTTP")
        except Exception as exc:
            last_err = str(exc)

    if html is None:
        log_warn(f"Page fetch failed: {last_err}")
        return {"error": last_err or "unknown fetch error"}

    m = re.search(r'<html[^>]+\blang=["\']([^"\']+)["\']', html, re.I)
    if m:
        out["html_lang"] = m.group(1).lower()

    out["google_analytics"] = sorted(set(re.findall(
        r'\b(UA-\d{4,12}-\d{1,3}|G-[A-Z0-9]{6,12})\b', html)))
    out["gtm_ids"]        = sorted(set(re.findall(r'\b(GTM-[A-Z0-9]{4,8})\b', html)))
    out["facebook_pixel"] = sorted(set(re.findall(
        r'fbq\(["\']init["\'],\s*["\'](\d{10,20})["\']', html)))
    out["yandex_metrika"] = sorted(set(re.findall(r'\bym\((\d{5,12})\s*,', html)))

    m = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        html, re.I,
    )
    if m:
        out["cms_generator"] = m.group(1).strip()

    social_patterns = {
        "telegram":  r'https?://t\.me/([A-Za-z0-9_]{3,60})',
        "twitter_x": r'https?://(?:www\.)?(?:twitter|x)\.com/([^\s"\'<>/?]{2,60})',
        "facebook":  r'https?://(?:www\.)?facebook\.com/([^\s"\'<>/?]{2,80})',
        "youtube":   r'https?://(?:www\.)?youtube\.com/(?:channel/|@)([^\s"\'<>/?]{2,80})',
        "instagram": r'https?://(?:www\.)?instagram\.com/([^\s"\'<>/?]{2,60})',
        "linkedin":  r'https?://(?:www\.)?linkedin\.com/(?:company|in)/([^\s"\'<>/?]{2,80})',
        "vk":        r'https?://(?:www\.)?vk\.com/([^\s"\'<>/?]{2,80})',
    }
    for name, pattern in social_patterns.items():
        matches = sorted(set(re.findall(pattern, html, re.I)))
        if matches:
            out["social_links"][name] = matches

    tracker_total = sum(len(out[k]) for k in
                        ("google_analytics", "gtm_ids", "facebook_pixel", "yandex_metrika"))
    log_ok(f"page_metadata: lang={out['html_lang']} cms={out['cms_generator']} "
           f"social={len(out['social_links'])} trackers={tracker_total}")
    return out


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

def collect_non_cf_ips(results: dict, limit: int = IP_PROBE_LIMIT) -> list[str]:
    """Pull every non-Cloudflare IP surfaced across all services."""
    ips: list[str] = []
    seen: set[str] = set()

    def _add(ip: str) -> None:
        if ip and ip not in seen and not is_cloudflare_ip(ip):
            seen.add(ip)
            ips.append(ip)

    dns_results = results.get("dns", {}) or {}
    for rtype in ("A", "AAAA"):
        for ip in dns_results.get(rtype, []) or []:
            _add(ip)

    for hit in (results.get("hackertarget", {}) or {}).get("hits", []) or []:
        _add(hit.get("ip", ""))
    for hit in (results.get("urlscan", {}) or {}).get("hits", []) or []:
        _add(hit.get("ip", ""))
    for rec in (results.get("circl_pdns", {}) or {}).get("records", []) or []:
        if rec.get("rrtype") in ("A", "AAAA"):
            _add(rec.get("rdata", ""))
    for src in ("censys", "shodan", "netlas"):
        for hit in (results.get(src, {}) or {}).get("hits", []) or []:
            _add(hit.get("ip", ""))

    return ips[:limit]


def pick_followup_subdomains(results: dict, limit: int = FOLLOWUP_LIMIT) -> list[str]:
    """Pick subdomains from crt.sh that resolve to at least one non-CF IP."""
    subs = (results.get("crt_sh", {}) or {}).get("subdomains", []) or []
    priority = ("mail", "api", "dev", "staging", "admin", "portal", "vpn",
                "cpanel", "webmail", "ftp", "smtp", "ns", "autodiscover")

    def score(name: str) -> int:
        low = name.lower()
        return -sum(1 for p in priority if p in low)  # lower score = higher priority

    ordered = sorted(subs, key=score)
    if not ordered:
        return []
    to_probe = ordered[:30]
    log_info(f"screening {len(to_probe)} subdomain(s) for origin leaks")
    hits: set[str] = set()
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(resolve_ips, sub): sub for sub in to_probe}
        for fut in as_completed(futures):
            sub = futures[fut]
            try:
                ips = fut.result()
            except Exception:
                ips = []
            if any(not is_cloudflare_ip(ip) for ip in ips):
                hits.add(sub)
    candidates = [s for s in to_probe if s in hits]
    return candidates[:limit]


def _apex(hostname: str) -> str:
    """
    Crude 'apex' extractor — strip leading subdomain labels down to the
    last two labels. Good enough for `.com`, `.ru`, `.md`, etc. but will
    over-trim for multi-part TLDs like `.co.uk`. Tradeoff accepted: a full
    eTLD+1 lookup would need `tldextract`, another dep.
    """
    hostname = (hostname or "").strip(".").lower()
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


def _detect_cms(html: str, headers: dict[str, str]) -> str | None:
    """Quick CMS detection from headers + HTML signatures."""
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


def get_live_probe(domain: str) -> dict:
    """
    Capture current-state evidence for the domain:
      - what it resolves to RIGHT NOW
      - what HTTP headers / status its homepage returns
      - what managed platform (if any) is serving it
      - what CMS (if any) is running
      - whether it's currently reachable at all

    This is deliberately separate from page_metadata so that a scan can fail
    at the HTML level but still capture "is this site alive / where is it /
    what's running it" — which is enough to calibrate historical evidence.
    """
    out: dict = {
        "probed_at":        datetime.now(timezone.utc).isoformat(),
        "current_ips":      [],
        "current_ipv6":     [],
        "http_status":      None,
        "final_url":        None,
        "redirect_chain":   [],
        "server_header":    None,
        "x_powered_by":     None,
        "platform":         None,
        "cms":              None,
        "headers":          {},
        "reachable":        False,
        "fetch_error":      None,
    }

    # Current DNS resolution — not the historical one in the other scan blocks.
    out["current_ips"]  = resolve_ips(domain)  # includes A + AAAA

    # Split v4/v6 for clarity downstream.
    import ipaddress
    v4 = []
    v6 = []
    for ip in out["current_ips"]:
        try:
            addr = ipaddress.ip_address(ip)
            (v4 if addr.version == 4 else v6).append(ip)
        except ValueError:
            continue
    out["current_ips"]  = v4
    out["current_ipv6"] = v6

    if not v4 and not v6:
        out["fetch_error"] = "no DNS resolution"
        log_warn(f"live_probe: {domain} does not resolve")
        return out

    # Live HTTP fetch with redirect chain tracked. We deliberately use a HEAD
    # as the initial probe so we don't pull a large body for closed/redirecting
    # sites; if HEAD is rejected, fall back to GET.
    headers_req = {
        "User-Agent": "Mozilla/5.0 (compatible; ip-intel/live-probe/1.0)",
        "Accept":     "*/*",
    }
    try:
        resp = requests.head(
            f"https://{domain}/",
            headers=headers_req,
            timeout=10,
            allow_redirects=True,
            **requests_kwargs(),
        )
        # Some servers lie about HEAD — accept but treat 405/501 as "retry GET".
        if resp.status_code in (405, 501):
            raise requests.RequestException("HEAD not supported, retry GET")
    except Exception:
        try:
            resp = requests.get(
                f"https://{domain}/",
                headers=headers_req,
                timeout=15,
                allow_redirects=True,
                stream=True,  # don't pull the body — headers are enough
                **requests_kwargs(),
            )
        except Exception as exc:
            # One more try on plain HTTP.
            try:
                resp = requests.get(
                    f"http://{domain}/",
                    headers=headers_req,
                    timeout=15,
                    allow_redirects=True,
                    stream=True,
                    **requests_kwargs(),
                )
            except Exception as exc2:
                out["fetch_error"] = str(exc2)
                log_warn(f"live_probe: {domain} fetch failed: {exc2}")
                return out

    # Capture the redirect chain so we can see e.g. "example.com → cdn.example.com"
    chain = []
    for hop in resp.history:
        chain.append({
            "url":    hop.url,
            "status": hop.status_code,
            "location": hop.headers.get("Location"),
        })
    out["redirect_chain"] = chain
    out["final_url"]      = resp.url
    out["http_status"]    = resp.status_code
    out["reachable"]      = resp.status_code < 500

    headers_dict = {k: v for k, v in resp.headers.items()}
    out["headers"]       = headers_dict
    out["server_header"] = headers_dict.get("Server") or headers_dict.get("server")
    out["x_powered_by"]  = headers_dict.get("X-Powered-By") or headers_dict.get("x-powered-by")
    out["platform"]      = _detect_platform(headers_dict)

    # Only fetch the body if HEAD succeeded and we still need CMS detection.
    # This is cheap — keeps tests lightweight for dead sites.
    html = ""
    if resp.request.method == "GET" and resp.status_code < 400:
        try:
            # Pull first 32KB — enough for <head> + early body for CMS detect.
            html = resp.raw.read(32 * 1024, decode_content=True).decode("utf-8", errors="replace")
        except Exception:
            pass
    out["cms"] = _detect_cms(html, headers_dict)

    log_ok(f"live_probe: {domain} → {resp.status_code} "
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

SERVICES = [
    ("dns",           get_dns),
    ("whois",         get_whois),
    ("live_probe",    get_live_probe),   # NEW — captures current state
    ("crt_sh",        get_crt_sh),
    ("circl_pdns",    get_circl_pdns),
    ("hackertarget",  get_hackertarget),
    ("urlscan",       get_urlscan),
    ("censys",        get_censys),
    ("shodan",        get_shodan),
    ("netlas",        get_netlas),
    ("page_metadata", get_page_metadata),
]

# Cert-search providers that cost one paid/rate-limited API call per target.
# Gated behind analyze(run_providers=...) so subdomain follow-ups don't each
# fire their own Censys/Shodan/Netlas query.
_PROVIDER_SERVICES = {"censys", "shodan", "netlas"}


# steps per analyze() call: one per service + TLS probe + SSH probe
STEPS_PER_DOMAIN = len(SERVICES) + 2

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

    `run_providers=False` skips the paid/rate-limited cert-search providers
    (Censys, Shodan, Netlas). Each of those is an API call per target, so
    running them on every discovered subdomain is what makes a single case
    burn 30+ Censys calls. A subdomain's certs/origins are already covered by
    its apex's provider search plus crt.sh / DNS / TLS probing, so callers
    pass run_providers=False for subdomain follow-ups and keep them only for
    apex-level targets.
    """
    started = time.time()
    prefix  = "└─ " if is_followup else ""
    log_info(f"{prefix}analyzing {domain}")

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
    for name, fn in SERVICES:
        if name in _PROVIDER_SERVICES and not run_providers:
            # Skip the per-target paid cert-search APIs on follow-ups; record a
            # marker so the key is present and downstream code treats it like
            # any other skipped service.
            results[name] = {"skipped": True,
                             "reason": "provider cert search runs on apex targets only"}
            _bump(overall_bar, name, domain)
            continue
        try:
            results[name] = fn(domain)
        except Exception as exc:
            log_warn(f"{name} crashed: {exc}")
            results[name] = {"error": str(exc)}
        if all_results is not None:
            save_results(all_results)
        _bump(overall_bar, name, domain)

    # ── 2. TLS + SSH probing on non-CF IPs ────────────────────────────────────
    non_cf_ips = collect_non_cf_ips(results)
    log_info(f"non-CF IPs found: {len(non_cf_ips)}")
    results["non_cf_ips"] = non_cf_ips

    results["tls_certs"] = get_tls_certs(domain, non_cf_ips)
    if all_results is not None:
        save_results(all_results)
    _bump(overall_bar, "tls_probe", domain)

    results["ssh_host_keys"] = get_ssh_host_keys(non_cf_ips)
    if all_results is not None:
        save_results(all_results)
    _bump(overall_bar, "ssh_probe", domain)

    # ── Freshness annotation: mark each observed IP as current vs historical ──
    # Runs after every service + probe completes, so the result has both the
    # live resolution from live_probe and the accumulated historical IPs from
    # urlscan / hackertarget / circl_pdns.
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

        for sub in sub_picks:
            sub_result = analyze(sub, is_followup=True,
                                 all_results=all_results,
                                 overall_bar=overall_bar,
                                 follow_siblings=False)
            results["subdomain_followups"].append(sub_result)
            if all_results is not None:
                all_results["subdomain_followups"] = results["subdomain_followups"]
                save_results(all_results)

        for pick in sibling_picks:
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
        from utils.check import compare_directory
        compare_directory(scans_dir, out_dir / "overlaps")
    except ImportError:
        log_warn("check.py not importable — run it manually with:")
        print(f"      python check.py --dir {scans_dir} {out_dir / 'overlaps'}")
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
        from utils.check import compare_directory
        compare_directory(scans_dir, overlap_dir)
    except ImportError:
        log_warn("check.py not importable — run it manually")


def is_ip(target: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def get_ip_whois(ip: str) -> dict:
    """RDAP / ASN lookup for a bare IP via ipwhois."""
    try:
        from ipwhois import IPWhois
    except ImportError:
        return {"error": "ipwhois not installed (pip install ipwhois)"}
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        net = result.get("network", {}) or {}
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
    except Exception as exc:
        return {"error": str(exc)}


def get_ptr(ip: str) -> str | None:
    """Reverse-DNS lookup for an IP."""
    try:
        import dns.reversename
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        rev = dns.reversename.from_address(ip)
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