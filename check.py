#!/usr/bin/env python3
"""
Compare JSON scan results for overlap.

Single-pair mode:
    python json_match.py <a.json> <b.json> <out.json>

Batch mode — pairwise compare every JSON in a directory:
    python json_match.py --dir <scans_dir> <out_dir>
"""

import argparse
import itertools
import json
import sys
from pathlib import Path


def _is_trivial(v) -> bool:
    """Skip null/empty values — matching on `null` isn't interesting."""
    return v in (None, "", [], {}, 0, False)


def _is_failed(v) -> bool:
    """
    Treat a dict as 'failed' (and therefore not worth matching on) if it
    looks like a service error or a skipped-service marker. This prevents
    spurious matches like both files sharing {"error": "HTTP 401"} or
    {"skipped": true, "reason": "CENSYS_API_KEY not set"}.
    """
    return isinstance(v, dict) and ("error" in v or v.get("skipped") is True)


# For lists of dicts at these paths, intersect on the named field(s) instead
# of requiring whole-dict equality. This is where the real infrastructure
# signal lives — two runs sharing a TLS fingerprint or SSH host key is a
# near-proof of shared backend even if surrounding metadata differs.
LIST_MATCH_FIELDS: dict[str, list[str]] = {
    "tls_certs.probes":     ["fingerprint_sha256", "cn"],
    "ssh_host_keys.probes": ["fingerprint_sha256"],
    "crt_sh.certs":         ["id"],
    "hackertarget.hits":    ["ip"],
    "urlscan.hits":         ["ip"],
    "circl_pdns.records":   ["rdata"],
    "censys.hits":          ["ip"],
    "shodan.hits":          ["ip"],
    "netlas.hits":          ["ip"],
}


# Paths that describe the scan itself rather than the domain's real-world
# identity. Two domains matching on these paths is trivially true for every
# alive / managed-hosted site — "both are reachable", "both have CF headers",
# "both have keep-alive", etc. Matching on them produces noise that inflates
# scores for unrelated domains that happen to share a hosting platform.
#
# The freshness / live_probe data is still *used* by the scoring and cert
# quality logic (as context), it's just excluded from being its own match.
_EXCLUDED_PATH_PREFIXES = (
    "live_probe",       # headers, server, platform, status, etc. — context only
    "freshness",        # freshness annotations — context only
    "timestamp",        # always differs; never a match anyway
    "scan_depth",       # provenance, not identity
    "discovered_from",  # provenance, not identity
    "discovery_reason", # provenance
    "discovery_kind",   # provenance
)


# Cloudflare's anycast IP ranges. Two domains "sharing" a Cloudflare IP tells
# you only that both use Cloudflare; millions of sites do. Filter these out
# of list intersections so they never appear as shared-infrastructure matches.
_CF_IPV4 = [
    "173.245.48.0/20",  "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18",  "108.162.192.0/18","190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15",  "104.16.0.0/13",
    "104.24.0.0/14",    "172.64.0.0/13",   "131.0.72.0/22",
]
_CF_IPV6 = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]


def _is_cloudflare_ip_local(ip: str) -> bool:
    """Local copy so json_match doesn't depend on ip_intel being importable."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    nets = _CF_IPV4 if addr.version == 4 else _CF_IPV6
    for net in nets:
        if addr in ipaddress.ip_network(net):
            return True
    return False


def _path_is_excluded(path: str) -> bool:
    for prefix in _EXCLUDED_PATH_PREFIXES:
        if path == prefix or path.startswith(prefix + "."):
            return True
    return False


def _extract_field(items, field):
    """Pull non-trivial `field` values from a list of dicts, skipping failures."""
    out = []
    for item in items:
        if not isinstance(item, dict) or _is_failed(item):
            continue
        v = item.get(field)
        if v is not None and not _is_trivial(v):
            out.append(v)
    return out


def find_matches(a, b, path=""):
    """Yield (dot-path, value) pairs where `a` and `b` share a value."""
    if type(a) is not type(b):
        return

    # Don't compare anything inside a failed/skipped service on either side.
    if _is_failed(a) or _is_failed(b):
        return

    # Skip metadata / context paths entirely — they'd produce tautological
    # matches like both-alive or both-CF-headers that inflate scores.
    if path and _path_is_excluded(path):
        return

    if isinstance(a, dict):
        for key in a.keys() & b.keys():
            if key in ("error", "skipped", "reason"):
                continue
            sub_path = f"{path}.{key}" if path else key
            yield from find_matches(a[key], b[key], sub_path)

    elif isinstance(a, list):
        # Field-level intersection for configured list-of-dict paths.
        fields = LIST_MATCH_FIELDS.get(path)
        if fields:
            for field in fields:
                a_vals = _extract_field(a, field)
                b_vals = _extract_field(b, field)
                shared = []
                for v in a_vals:
                    if v in b_vals and v not in shared:
                        # Filter CF IPs from IP-field intersections — two
                        # domains "sharing" a CF anycast IP means nothing.
                        if field == "ip" and isinstance(v, str) and _is_cloudflare_ip_local(v):
                            continue
                        shared.append(v)
                if shared:
                    yield f"{path}[*].{field}", shared
            return

        # Fallback: shared list items via whole-value equality.
        shared = []
        for item in a:
            if _is_failed(item) or _is_trivial(item):
                continue
            if item in b and item not in shared:
                # If this list is an IP path, drop CF anycast IPs.
                if (isinstance(item, str)
                        and path in ("non_cf_ips", "dns.A", "dns.AAAA")
                        and _is_cloudflare_ip_local(item)):
                    continue
                shared.append(item)
        if shared:
            yield path, shared

    else:
        if a == b and not _is_trivial(a):
            yield path, a


def _urlscan_hits(scan: dict) -> list[dict]:
    """Safely pull the urlscan hits list from a run, or []."""
    hits = ((scan or {}).get("urlscan") or {}).get("hits") or []
    return [h for h in hits if isinstance(h, dict)]


def analyze_urlscan_cross_referrers(a: dict, b: dict) -> list[dict]:
    """
    For every IP that appears in both files' urlscan hits, report what was
    going on at the time of each scan. The important case: both scans were
    *not* our queried domain but some third party that was embedding content
    from our targets. That's content-embedding evidence, not shared hosting.

    Returns a list of findings, one per shared IP, with enough context that
    you can eyeball whether it's a real cross-domain reference or noise.
    """
    a_domain = (a or {}).get("domain")
    b_domain = (b or {}).get("domain")

    # Index B's hits by IP for quick lookup.
    b_by_ip: dict[str, dict] = {}
    for h in _urlscan_hits(b):
        ip = h.get("ip")
        if ip:
            b_by_ip.setdefault(ip, h)

    findings: list[dict] = []
    for h_a in _urlscan_hits(a):
        ip = h_a.get("ip")
        if not ip or ip not in b_by_ip:
            continue
        h_b = b_by_ip[ip]

        # Strongest case: both sides have a third-party scan URL (neither is
        # the queried domain), AND that URL is the same. Both targets were
        # being referenced from the same third party.
        both_third_party = h_a.get("third_party_scan") and h_b.get("third_party_scan")
        same_referrer    = h_a.get("url") and h_a.get("url") == h_b.get("url")

        if both_third_party and same_referrer:
            relationship = "shared_referrer"     # strongest
        elif both_third_party:
            relationship = "both_third_party"    # same IP, different referrers
        elif h_a.get("third_party_scan") or h_b.get("third_party_scan"):
            relationship = "mixed"               # one direct, one third party
        else:
            relationship = "shared_host"         # both scans are of our targets directly

        findings.append({
            "ip":           ip,
            "relationship": relationship,
            "a": {
                "domain":           a_domain,
                "scan_url":         h_a.get("url"),
                "scan_date":        h_a.get("date"),
                "third_party_scan": h_a.get("third_party_scan", False),
                "referring":        (h_a.get("referrer_context") or {}).get("referring", []),
            },
            "b": {
                "domain":           b_domain,
                "scan_url":         h_b.get("url"),
                "scan_date":        h_b.get("date"),
                "third_party_scan": h_b.get("third_party_scan", False),
                "referring":        (h_b.get("referrer_context") or {}).get("referring", []),
            },
        })

    # Sort by strength of relationship.
    order = {"shared_referrer": 0, "both_third_party": 1, "mixed": 2, "shared_host": 3}
    findings.sort(key=lambda f: order.get(f["relationship"], 99))
    return findings


# How much each match path weighs when ranking pair damningness. Higher
# means more forensically meaningful. These are calibrated against the
# tsargrad and Huanqiu runs: TLS+SSH fingerprint match = near-identity,
# shared host/IP alone is weak, shared registrar/nameserver is weaker still.
MATCH_WEIGHTS: dict[str, int] = {
    "tls_certs.probes[*].fingerprint_sha256":     100,
    "ssh_host_keys.probes[*].fingerprint_sha256":  90,
    "tls_certs.probes[*].cn":                      40,
    "non_cf_ips":                                  30,
    "dns.A":                                       25,
    "hackertarget.hits[*].ip":                     20,
    "urlscan.hits[*].ip":                          15,
    "circl_pdns.records[*].rdata":                 15,
    "page_metadata.google_analytics":              35,
    "page_metadata.gtm_ids":                       30,
    "page_metadata.facebook_pixel":                35,
    "page_metadata.yandex_metrika":                35,
    "whois.creation_date":                         25,
    "whois.registrar":                              3,
    "whois.emails":                                10,
    "whois.country":                                1,
    "dns.SOA.rname":                                5,
    "dns.SOA.serial":                              10,
    "dns.NS":                                      10,
    "crt_sh.issuers":                               2,
    "page_metadata.adsense_publisher_ids":         35,
    "page_metadata.fb_app_id":                     20,
    "page_metadata.favicon_md5":                   18,
    "page_metadata.favicon_murmurhash3":           18,
    "page_metadata.source_map_urls":               18,
    "page_metadata.social_handle_values":          10,
    "page_metadata.authors":                        8,
    "page_metadata.rel_me":                        10,
    "email_security.dmarc_report_uris":            18,
    "email_security.spf_includes":                 12,
    "email_security.dkim_selectors":               10,
    "txt_verification_tokens":                     25,
    "microsoft_tenant.tenant_guid":                40,
    "mail_client_config.servers":                  20,
    "mail_client_config.domains":                  10,
    "legal_pages.entity_names":                    18,
    "legal_pages.registration_ids":                35,
    "well_known.security_contacts":                12,
    "well_known.assetlinks_packages":              20,
    "well_known.ads_txt_publishers":               18,
    "nameserver_analysis.vanity_apexes":           12,
}


def _cert_is_relevant(cert: dict, domain: str) -> bool:
    """
    Is the cert actually *for* this domain? A cert whose CN and SANs don't
    mention the domain at all is probably the default vhost cert of a stale
    shared host — it says nothing about operator identity.
    """
    if not isinstance(cert, dict):
        return False
    names = [cert.get("cn") or ""]
    names.extend(cert.get("sans") or [])
    domain = (domain or "").lower().lstrip(".")
    apex = ".".join(domain.split(".")[-2:]) if domain.count(".") >= 1 else domain
    for name in names:
        n = (name or "").lower().lstrip("*.").lstrip(".")
        if n == domain or n == apex or n.endswith("." + apex):
            return True
    return False


def _cert_looks_abandoned(cert: dict) -> bool:
    """
    Heuristic for 'this cert is junk default-vhost response, not an operator
    cert' — a self-signed cert, or one expired by years, is almost certainly
    abandoned infra rather than evidence of shared operation.
    """
    if not isinstance(cert, dict):
        return False
    # Self-signed: issuer CN equals subject CN.
    cn = (cert.get("cn") or "").lower()
    issuer_cn = (cert.get("issuer_cn") or "").lower()
    if cn and cn == issuer_cn:
        return True
    # Stale: expired more than a year ago. Legitimate operator certs may be
    # a few weeks expired if renewal broke; years-expired means nobody's home.
    not_after = cert.get("not_after") or ""
    if not_after:
        try:
            from datetime import datetime, timezone
            exp = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
            stale_after_days = (datetime.now(timezone.utc) - exp).days
            if stale_after_days > 365:
                return True
        except Exception:
            pass
    return False


def assess_cert_match_quality(a: dict, b: dict) -> dict:
    """
    Decide whether the TLS fingerprint match between two scans is forensically
    meaningful or is noise from a shared junk vhost.

    Returns a dict like:
      {"quality": "strong" | "weak" | "junk", "reason": "...", "weight_mult": 1.0}

    - "strong"  (1.0×): shared cert that names at least one of the two domains.
      Classic shared-operator signal.
    - "weak"    (0.3×): shared cert doesn't name either domain, but the cert
      looks live (not self-signed, not ancient). Possibly shared hosting with
      a default wildcard.
    - "junk"    (0.0×): shared cert is self-signed, expired-by-years, or
      otherwise smells like an abandoned default vhost. Evidentiary value ≈ 0.
    """
    a_domain = (a or {}).get("domain") or ""
    b_domain = (b or {}).get("domain") or ""

    a_certs = ((a or {}).get("tls_certs") or {}).get("probes") or []
    b_certs = ((b or {}).get("tls_certs") or {}).get("probes") or []

    # Find the first cert pair that actually matches on fingerprint — that's
    # the one that triggered the match we're assessing.
    b_fps = {c.get("fingerprint_sha256"): c for c in b_certs
             if isinstance(c, dict) and c.get("fingerprint_sha256")}
    matched_pair = None
    for c in a_certs:
        if not isinstance(c, dict):
            continue
        fp = c.get("fingerprint_sha256")
        if fp and fp in b_fps:
            matched_pair = (c, b_fps[fp])
            break

    if not matched_pair:
        # No cert match at all; nothing to assess.
        return {"quality": "n/a", "reason": "no matching cert",
                "weight_mult": 1.0}

    cert_a, cert_b = matched_pair
    # Either side's cert object has the same fingerprint, so either should
    # tell us the same story about cert quality. Check both sides just in case.
    relevant = (_cert_is_relevant(cert_a, a_domain)
                or _cert_is_relevant(cert_b, b_domain))
    abandoned = _cert_looks_abandoned(cert_a) or _cert_looks_abandoned(cert_b)

    if abandoned:
        return {
            "quality":     "junk",
            "reason":      f"shared cert is self-signed or expired-by-years "
                           f"(cn={cert_a.get('cn')}, issuer={cert_a.get('issuer_cn')}, "
                           f"expired {cert_a.get('not_after')}) — likely stale "
                           f"default vhost, not operator evidence",
            "weight_mult": 0.0,
        }
    if not relevant:
        return {
            "quality":     "weak",
            "reason":      f"shared cert (cn={cert_a.get('cn')}) doesn't name "
                           f"either {a_domain} or {b_domain} — possibly shared "
                           f"hosting wildcard rather than operator evidence",
            "weight_mult": 0.3,
        }
    return {
        "quality":     "strong",
        "reason":      f"shared cert names at least one of the queried domains "
                       f"(cn={cert_a.get('cn')})",
        "weight_mult": 1.0,
    }


def assess_freshness_context(a: dict, b: dict, matches: dict) -> dict:
    """
    Assess whether the IP-based matches are on IPs that both domains currently
    resolve to, or whether they're historical ghosts from urlscan / pDNS.

    Also flags whether either domain is on a managed platform (Hostinger,
    Vercel, etc.), because SSH/IP matches against a managed platform's IP
    are matches against the PLATFORM's backend pool, not the operator's box.

    Returns a dict like:
      {
        "current_shared_ips":     [...],
        "historical_shared_ips":  [...],
        "a_current_ips":          [...],
        "b_current_ips":          [...],
        "a_platform":             "hostinger-horizons" or None,
        "b_platform":             ...,
        "ip_match_quality":       "current" | "historical" | "mixed" | "n/a",
        "ip_weight_mult":         1.0 | 0.3 | 0.0,
        "platform_demotes_ssh":   bool,
      }
    """
    a_live = (a or {}).get("live_probe") or {}
    b_live = (b or {}).get("live_probe") or {}
    a_fresh = (a or {}).get("freshness") or {}
    b_fresh = (b or {}).get("freshness") or {}

    a_current = set(a_live.get("current_ips") or []) | set(a_live.get("current_ipv6") or [])
    b_current = set(b_live.get("current_ips") or []) | set(b_live.get("current_ipv6") or [])

    # Which IPs appear in the MATCHES block (so we're asking: of the shared
    # IPs json_match flagged, which are currently live for both domains?).
    shared_ips: set[str] = set()
    for ip_path in ("non_cf_ips", "dns.A", "hackertarget.hits[*].ip",
                    "urlscan.hits[*].ip"):
        for ip in (matches.get(ip_path) or []):
            if isinstance(ip, str):
                shared_ips.add(ip)

    current_shared    = sorted(shared_ips & a_current & b_current)
    historical_shared = sorted(shared_ips - (a_current & b_current))

    if not shared_ips:
        quality = "n/a"
        ip_mult = 1.0
    elif current_shared and not historical_shared:
        quality = "current"
        ip_mult = 1.0
    elif historical_shared and not current_shared:
        quality = "historical"
        ip_mult = 0.3   # still worth something — historical hosting is real evidence, just weaker
    else:
        quality = "mixed"
        ip_mult = 0.7

    # Managed-platform detection. If either domain is on a known shared
    # managed platform, an SSH/IP match likely reflects the platform's
    # backend pool rather than an operator's dedicated box.
    a_platform = a_live.get("platform")
    b_platform = b_live.get("platform")
    platform_demotes_ssh = bool(a_platform or b_platform)

    return {
        "current_shared_ips":    current_shared,
        "historical_shared_ips": historical_shared,
        "a_current_ips":         sorted(a_current),
        "b_current_ips":         sorted(b_current),
        "a_platform":            a_platform,
        "b_platform":            b_platform,
        "ip_match_quality":      quality,
        "ip_weight_mult":        ip_mult,
        "platform_demotes_ssh":  platform_demotes_ssh,
    }


def score_matches(matches: dict, cross_refs: list[dict],
                  cert_quality: dict | None = None,
                  freshness: dict | None = None) -> int:
    """Sum weights for every matched path. Used to rank pairs."""
    total = 0
    cert_mult = (cert_quality or {}).get("weight_mult", 1.0)
    ip_mult   = (freshness    or {}).get("ip_weight_mult", 1.0)
    platform_demotes_ssh = (freshness or {}).get("platform_demotes_ssh", False)

    # IP-based signal paths — demoted if shared IPs are historical only.
    ip_paths = {
        "non_cf_ips", "dns.A",
        "hackertarget.hits[*].ip", "urlscan.hits[*].ip",
        "circl_pdns.records[*].rdata",
    }
    # Cert-based paths — demoted if the cert looks abandoned/irrelevant.
    cert_paths = {
        "tls_certs.probes[*].fingerprint_sha256",
        "tls_certs.probes[*].cn",
    }
    # SSH path — the complicated one. Demoted if (a) cert on this IP looks
    # junk, or (b) either domain is on a managed shared platform where the
    # SSH key belongs to the platform, not the operator.
    ssh_paths = {"ssh_host_keys.probes[*].fingerprint_sha256"}

    for path in matches:
        weight = MATCH_WEIGHTS.get(path, 5)
        if path in cert_paths:
            weight = int(weight * cert_mult)
        if path in ssh_paths:
            multiplier = cert_mult
            if platform_demotes_ssh:
                multiplier *= 0.2   # strong demotion on managed platforms
            weight = int(weight * multiplier)
        if path in ip_paths:
            weight = int(weight * ip_mult)
        total += weight
    for finding in cross_refs:
        if finding.get("relationship") == "shared_referrer":
            total += 50
        elif finding.get("relationship") == "both_third_party":
            total += 20
    return total


def compare_pair(a: dict, b: dict) -> dict:
    """Produce the full comparison payload for one pair of scans."""
    matches      = {path: value for path, value in find_matches(a, b)}
    cross_refs   = analyze_urlscan_cross_referrers(a, b)
    cert_quality = assess_cert_match_quality(a, b)
    freshness    = assess_freshness_context(a, b, matches)
    return {
        "a_domain":           a.get("domain") or a.get("input"),
        "b_domain":           b.get("domain") or b.get("input"),
        "score":              score_matches(matches, cross_refs, cert_quality, freshness),
        "match_count":        len(matches),
        "cert_quality":       cert_quality,
        "freshness":          freshness,
        "matches":            matches,
        "urlscan_cross_refs": cross_refs,
    }


def compare_directory(scans_dir: Path, out_dir: Path) -> None:
    """
    Pairwise compare every JSON file in `scans_dir`. Writes one overlap file
    per pair (only if there are matches) plus a summary.json ranked by score.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    scans_dir = Path(scans_dir)

    # Load every scan file into memory once.
    scans: dict[str, dict] = {}
    for path in sorted(scans_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except Exception as exc:
            print(f"  [!] {path.name}: unreadable ({exc})")
            continue
        domain = data.get("domain") or path.stem
        scans[domain] = data

    if len(scans) < 2:
        print(f"  [!] Need at least 2 scan files in {scans_dir}, found {len(scans)}")
        return

    print(f"  [*] comparing {len(scans)} scans "
          f"({len(scans) * (len(scans) - 1) // 2} pairs)")

    # Per-domain aggregation: each domain's strongest overlaps across all peers.
    per_domain: dict[str, list[dict]] = {d: [] for d in scans}
    summary:    list[dict]            = []

    for a_domain, b_domain in itertools.combinations(sorted(scans), 2):
        pair = compare_pair(scans[a_domain], scans[b_domain])
        if pair["match_count"] == 0 and not pair["urlscan_cross_refs"]:
            continue  # no point writing an empty file

        pair_file = out_dir / f"{_safe(a_domain)}__vs__{_safe(b_domain)}.json"
        pair_file.write_text(json.dumps(pair, indent=2, default=str))

        summary.append({
            "a_domain":    a_domain,
            "b_domain":    b_domain,
            "score":       pair["score"],
            "match_count": pair["match_count"],
            "file":        pair_file.name,
            "top_paths":   sorted(
                pair["matches"].keys(),
                key=lambda p: -MATCH_WEIGHTS.get(p, 5),
            )[:5],
        })
        per_domain[a_domain].append({"peer": b_domain, "score": pair["score"]})
        per_domain[b_domain].append({"peer": a_domain, "score": pair["score"]})

    # Rank strongest pairs first — most damning evidence rises to the top.
    summary.sort(key=lambda s: -s["score"])

    # Each domain's peer list sorted by score, for "who is X most linked to".
    for peer_list in per_domain.values():
        peer_list.sort(key=lambda p: -p["score"])

    (out_dir / "summary.json").write_text(json.dumps({
        "pair_count":  len(summary),
        "pairs":       summary,
        "per_domain":  per_domain,
    }, indent=2, default=str))

    print(f"  [+] wrote {len(summary)} pair file(s) + summary.json to {out_dir}")
    print()

    # Print the top pairs so you see the signal immediately.
    if summary:
        print(f"  Top pairs by score:")
        for i, s in enumerate(summary[:10], 1):
            print(f"    {i:2d}. [{s['score']:4d}]  {s['a_domain']}  ↔  {s['b_domain']}")
            for path in s["top_paths"]:
                print(f"            · {path}")
        if len(summary) > 10:
            print(f"    ... and {len(summary) - 10} more pairs")


def _safe(name: str) -> str:
    import re
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name)


def _run_pair_mode(a_path: Path, b_path: Path, out_path: Path) -> None:
    a = json.loads(a_path.read_text())
    b = json.loads(b_path.read_text())

    output = compare_pair(a, b)
    out_path.write_text(json.dumps(output, indent=2, default=str))
    print(f"  [+] {output['match_count']} shared value(s) · score {output['score']} → {out_path}")

    matches = output["matches"]
    for path, value in list(matches.items())[:10]:
        preview = json.dumps(value, default=str)
        if len(preview) > 80:
            preview = preview[:77] + "..."
        print(f"      {path} = {preview}")
    if len(matches) > 10:
        print(f"      ... and {len(matches) - 10} more")

    cross = output["urlscan_cross_refs"]
    if cross:
        print(f"\n  [+] {len(cross)} urlscan cross-reference(s):")
        for f in cross[:10]:
            label = f["relationship"]
            print(f"      [{label}] {f['ip']}")
            print(f"         a ({f['a']['domain']}) → scan of {f['a']['scan_url'] or '(no url)'}")
            print(f"         b ({f['b']['domain']}) → scan of {f['b']['scan_url'] or '(no url)'}")
            if label == "shared_referrer" and f["a"]["referring"]:
                r = f["a"]["referring"][0]
                print(f"         pulled in as: {r.get('type') or '?'} → {r.get('url')}")
        if len(cross) > 10:
            print(f"      ... and {len(cross) - 10} more")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare JSON scan results for overlap.",
    )
    parser.add_argument("--dir", type=Path,
                        help="Directory of scan JSONs to compare pairwise")
    parser.add_argument("positional", nargs="*",
                        help="Pair mode: <a.json> <b.json> <out.json>. "
                             "Dir mode: <out_dir>")
    args = parser.parse_args()

    if args.dir:
        if len(args.positional) != 1:
            parser.error("--dir requires one positional arg: <out_dir>")
        compare_directory(args.dir, Path(args.positional[0]))
        return

    if len(args.positional) != 3:
        parser.error("Pair mode requires three args: <a.json> <b.json> <out.json>")
    a_path, b_path, out_path = map(Path, args.positional)
    _run_pair_mode(a_path, b_path, out_path)


if __name__ == "__main__":
    main()
