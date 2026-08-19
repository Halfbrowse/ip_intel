"""
Censys Platform "host enrichment" API — one flat, latest-state view of an IP.

`GET /v3/global/asset/enrichment/host/{ip}` returns a fixed field set (ASN,
location, WHOIS network/org, reverse DNS, open services, labels, reputation,
GreyNoise, and IPinfo-derived network/privacy classification) for the most
recent scan of a host. It is deliberately *not* the same thing as the
credit-consuming search/view host API this repo already uses in
`core.ip_intel.censys_cert_search`: enrichment spends no API credits, but is
capped at 20,000 calls/day on the Core plan and cannot be queried, filtered, or
asked for history — you pass one IP and take what it gives.

That cap is enforced before the request goes out (see
`db.intel_db.claim_censys_enrichment_calls`) rather than by reacting to a 429,
because on a pool-wide sweep the difference is thousands of wasted round trips.

Needs CENSYS_API_KEY (personal access token) and CENSYS_ORG_ID in .env; when
either is absent callers get a `{"skipped": True, ...}` marker, matching the
convention the other optional-key providers use (ipinfo Lite, Shodan, Netlas).
"""

from __future__ import annotations

import os
from typing import Any

import requests

from utils.outbound import requests_kwargs

CENSYS_ENRICHMENT_URL = "https://api.platform.censys.io/v3/global/asset/enrichment/host/{ip}"

_TIMEOUT = 15


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _label_values(labels: Any) -> list[str]:
    out: list[str] = []
    for label in _as_list(labels):
        value = str(_as_dict(label).get("value") or "").strip()
        if value and value not in out:
            out.append(value)
    return out


def _flatten_bool_sources(entries: Any, keys: tuple[str, ...]) -> dict[str, bool]:
    """Collapse the per-source `network`/`privacy` arrays into one flag set.

    Both fields are lists because Censys reports them per upstream source; a
    host is treated as (say) a VPN if any source says so, which is how the
    field reads in the Censys UI.
    """
    flags = {key: False for key in keys}
    for entry in _as_list(entries):
        row = _as_dict(entry)
        for key in keys:
            if row.get(key) is True:
                flags[key] = True
    return flags


def normalize_host_enrichment(payload: Any) -> dict:
    """Flatten the enrichment envelope into the shape the rest of the app uses.

    The response nests the useful part under result.resource; everything below
    reads from that, so a shape change shows up here rather than in every
    consumer.
    """
    resource = _as_dict(_as_dict(_as_dict(payload).get("result")).get("resource"))
    if not resource:
        return {}

    autonomous_system = _as_dict(resource.get("autonomous_system"))
    location = _as_dict(resource.get("location"))
    whois = _as_dict(resource.get("whois"))
    whois_network = _as_dict(whois.get("network"))
    whois_org = _as_dict(whois.get("organization"))
    dns = _as_dict(resource.get("dns"))
    reputation = _as_dict(resource.get("reputation"))
    greynoise = _as_dict(resource.get("greynoise"))

    services: list[dict] = []
    threats: list[dict] = []
    for entry in _as_list(resource.get("services")):
        row = _as_dict(entry)
        port = row.get("port")
        if port is None:
            continue
        services.append({
            "port": port,
            "protocol": row.get("protocol"),
            "scan_time": row.get("scan_time"),
            "labels": _label_values(row.get("labels")),
        })
        for threat in _as_list(row.get("threats")):
            threat_row = _as_dict(threat)
            if threat_row:
                threats.append({
                    "port": port,
                    "type": threat_row.get("type"),
                    "tactic": threat_row.get("tactic"),
                    "id": threat_row.get("id"),
                    "name": threat_row.get("name"),
                })

    reverse_dns = _as_dict(dns.get("reverse_dns"))
    network_flags = _flatten_bool_sources(resource.get("network"), ("hosting", "mobile", "satellite"))
    privacy_flags = _flatten_bool_sources(
        resource.get("privacy"), ("anonymous", "proxy", "relay", "tor", "vpn")
    )

    return {
        "ip": resource.get("ip"),
        "service_count": resource.get("service_count"),
        "asn": autonomous_system.get("asn"),
        "as_name": autonomous_system.get("name"),
        "as_description": autonomous_system.get("description"),
        "as_organization": autonomous_system.get("organization"),
        "as_country": autonomous_system.get("country_code"),
        "bgp_prefix": autonomous_system.get("bgp_prefix"),
        "country": location.get("country"),
        "country_code": location.get("country_code"),
        "city": location.get("city"),
        "province": location.get("province"),
        "continent": location.get("continent"),
        "network_name": whois_network.get("name"),
        "network_handle": whois_network.get("handle"),
        "network_cidrs": [c for c in _as_list(whois_network.get("cidrs")) if c],
        "whois_organization": whois_org.get("name"),
        "whois_country": whois_org.get("country"),
        "abuse_contacts": [c for c in _as_list(whois_org.get("abuse_contacts")) if c],
        "dns_names": [n for n in _as_list(dns.get("names")) if n],
        "reverse_dns_names": [n for n in _as_list(reverse_dns.get("names")) if n],
        "labels": _label_values(resource.get("labels")),
        "services": services,
        "threats": threats,
        "reputation_score": reputation.get("score"),
        "reputation_level": reputation.get("score_level"),
        "greynoise_classification": greynoise.get("classification"),
        "greynoise_actor": greynoise.get("actor"),
        "greynoise_last_observed": greynoise.get("last_observed_time"),
        "hosting": network_flags["hosting"],
        "mobile": network_flags["mobile"],
        "satellite": network_flags["satellite"],
        "anonymous": privacy_flags["anonymous"],
        "proxy": privacy_flags["proxy"],
        "relay": privacy_flags["relay"],
        "tor": privacy_flags["tor"],
        "vpn": privacy_flags["vpn"],
    }


def _enrichment_allowed() -> bool:
    """Whether the running scan's profile permits spending enrichment budget.

    Imported lazily on purpose: core.analysis_service imports core.ip_intel,
    which imports this module, so a module-level import would be circular. By
    call time both modules are loaded. Callers outside the scan pipeline (the
    CLI, the backfill sweep) get the ContextVar's True default, which is what
    they want — the profile only exists to hold a *discovered* domain back.
    """
    from core.analysis_service import CENSYS_ENRICHMENT_ALLOWED

    return bool(CENSYS_ENRICHMENT_ALLOWED.get())


def get_censys_host_enrichment(ip: str) -> dict:
    """Enrichment for a single IP, or a skipped/error marker.

    Returns `{"skipped": True, ...}` when credentials are missing, the scan
    profile forbids it, or the daily budget is spent, so a sweep can tell "we
    chose not to ask" apart from "the provider failed" — the latter is worth
    retrying, the former is not.
    """
    api_key = os.environ.get("CENSYS_API_KEY")
    org_id = os.environ.get("CENSYS_ORG_ID")
    if not api_key:
        return {"skipped": True, "reason": "CENSYS_API_KEY not set in .env"}
    if not org_id:
        return {"skipped": True, "reason": "CENSYS_ORG_ID not set in .env"}

    # Checked before the budget claim: a free-only scan must not consume a slot
    # of the shared 20k/day allowance it is not allowed to spend.
    if not _enrichment_allowed():
        return {"skipped": True, "reason": "scan profile forbids Censys host enrichment"}

    from db import intel_db

    if not intel_db.claim_censys_enrichment_calls(1):
        return {"skipped": True, "reason": "Censys enrichment daily budget exhausted"}

    try:
        resp = requests.get(
            CENSYS_ENRICHMENT_URL.format(ip=ip),
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            params={"organization_id": org_id},
            timeout=_TIMEOUT,
            **requests_kwargs(),
        )
        if resp.status_code == 404:
            # Censys has simply never scanned this host; not an error worth
            # retrying, and distinct from a credential or quota problem.
            return {"not_found": True}
        if resp.status_code in (401, 403, 409):
            # Wrong token, no permission, or a plan without host enrichment
            # (409) — Censys never counted this against the daily quota, so
            # give the claim back rather than draining the budget on a
            # misconfiguration that will fail identically every time.
            intel_db.release_censys_enrichment_calls(1)
            reason = {
                401: "Censys credentials rejected (401)",
                403: "Censys permission denied (403)",
                409: "host enrichment not enabled on this Censys plan (409) — Core tier only",
            }[resp.status_code]
            return {"skipped": True, "reason": reason}
        if resp.status_code == 429:
            return {"error": "rate limited (429) — daily enrichment cap reached"}
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return {"error": str(exc)}

    enriched = normalize_host_enrichment(data)
    return enriched or {"not_found": True}


def merge_censys_enrichment(asn_info: dict, ip: str) -> dict:
    """Fold enrichment into an `asn_info` dict, in place.

    Precedence, per field:

    * **asn / asn_description** — gap-fill only. ipinfo Lite is published as
      free and uncapped (see utils/ipinfo_lite.py, re-checked 2026-08-12) while
      this call is the scarcer source despite costing no credits: 20,000/day
      account-wide, shared across every IP of every domain in a pool-wide
      sweep. Promoting enrichment here would spend a finite daily budget
      re-deriving what an unlimited source already returned, and would blank
      the fields once the budget ran out mid-sweep.
    * **geo (country / continent / city / province)** — enrichment *wins* where
      it answered, because it is the only source with city/province at all and
      a split where country came from one provider and city from another
      produced incoherent locations. ipinfo Lite's country/continent stay as
      the fallback: enrichment now runs for every target in a case (both scan
      profiles enable it) but stops answering once the 20,000/day budget is
      spent, and for hosts Censys has never scanned. On both paths ipinfo Lite
      has already returned a country that would otherwise be thrown away.
    * **network_name / network_cidr** — enrichment is now the only source. The
      RDAP leg that used to own them was removed from core.basic.get_ip_whois.

    Everything with no other source — reputation, GreyNoise, threat
    classification, VPN/proxy/hosting flags, abuse contacts, open-service
    labels — is attached under `censys_enrichment` untouched.
    """
    enrichment = get_censys_host_enrichment(ip)
    asn_info["censys_enrichment"] = enrichment
    if enrichment.get("skipped") or enrichment.get("error") or enrichment.get("not_found"):
        # ipinfo Lite's country/continent are already on asn_info via
        # merge_ipinfo_lite; promote them to the canonical geo keys so an IP
        # reached after the daily budget is spent — or one Censys has never
        # scanned — still carries a location.
        asn_info.setdefault("asn_country", asn_info.get("ipinfo_country"))
        asn_info.setdefault("geo_country", asn_info.get("ipinfo_country"))
        asn_info.setdefault("geo_continent", asn_info.get("ipinfo_continent"))
        return asn_info

    if not asn_info.get("asn") and enrichment.get("asn") is not None:
        asn_info["asn"] = str(enrichment["asn"])
    if not asn_info.get("asn_description"):
        asn_info["asn_description"] = enrichment.get("as_name") or enrichment.get("as_description")

    # Geo: enrichment wins, ipinfo Lite fills in whatever it did not answer.
    asn_info["asn_country"] = (
        enrichment.get("as_country")
        or enrichment.get("country_code")
        or asn_info.get("ipinfo_country")
    )
    asn_info["geo_country"] = (
        enrichment.get("country_code")
        or enrichment.get("country")
        or asn_info.get("ipinfo_country")
    )
    asn_info["geo_continent"] = enrichment.get("continent") or asn_info.get("ipinfo_continent")
    asn_info["geo_city"] = enrichment.get("city")
    asn_info["geo_province"] = enrichment.get("province")

    if not asn_info.get("network_name"):
        asn_info["network_name"] = enrichment.get("network_name")
    if not asn_info.get("network_cidr"):
        cidrs = enrichment.get("network_cidrs") or []
        asn_info["network_cidr"] = cidrs[0] if cidrs else enrichment.get("bgp_prefix")

    return asn_info
