"""
ipinfo.io "Lite" API — fast ASN + country/continent lookups.

The primary source for ASN/org/country identification, used by get_ip_whois
in core/ip_intel.py and core/basic.py: its values win over RDAP's whenever it
succeeds, since RDAP errors/times out per-RIR fairly often and this single
endpoint rarely does. RDAP is still always queried too (and remains the sole
source when this is unavailable) since ipinfo Lite's response carries no
network_name/network_cidr/asn_cidr — RDAP supplements those, and feeds
detect_proxy_details() alongside ipinfo Lite for edge-server/reverse-proxy
classification. Needs IP_INFO_KEY set in .env; when absent, callers get back
a `{"skipped": True, ...}` marker matching the convention used by the other
optional-key providers (Censys, Shodan, Netlas).
"""

from __future__ import annotations

import os

import requests

from utils.outbound import requests_kwargs

IPINFO_LITE_URL = "https://api.ipinfo.io/lite/{ip}"


def _strip_as_prefix(value: object) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    if text.upper().startswith("AS"):
        text = text[2:]
    return text or None


def get_ipinfo_lite(ip: str) -> dict:
    """Raw ipinfo.io Lite lookup for a single IP."""
    token = os.environ.get("IP_INFO_KEY")
    if not token:
        return {"skipped": True, "reason": "IP_INFO_KEY not set in .env"}
    try:
        resp = requests.get(
            IPINFO_LITE_URL.format(ip=ip),
            params={"token": token},
            timeout=10,
            **requests_kwargs(),
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return {"error": str(exc)}

    return {
        "asn":            _strip_as_prefix(data.get("asn")),
        "as_name":        data.get("as_name"),
        "as_domain":      data.get("as_domain"),
        "country":        data.get("country"),
        "country_code":   data.get("country_code"),
        "continent":      data.get("continent"),
        "continent_code": data.get("continent_code"),
    }


def merge_ipinfo_lite(asn_info: dict, ip: str) -> dict:
    """
    Combine an RDAP-shaped asn_info dict (as returned by get_ip_whois) with
    ipinfo Lite data for one IP, in place. ipinfo Lite is the primary source
    for asn/asn_description/asn_country — its values win over RDAP's whenever
    the lookup succeeds, since RDAP errors/times out per-RIR fairly often and
    this is a single fast endpoint that rarely does. RDAP's network_name/
    network_cidr/asn_cidr/asn_registry are kept as-is (ipinfo Lite's response
    doesn't carry them), and RDAP's asn/asn_description/asn_country remain the
    sole source if ipinfo Lite is unavailable (no IP_INFO_KEY) or errors.
    """
    lite = get_ipinfo_lite(ip)
    if lite.get("skipped") or lite.get("error"):
        asn_info["ipinfo"] = lite
        return asn_info

    asn_info["ipinfo_asn"]       = lite.get("asn")
    asn_info["ipinfo_as_name"]   = lite.get("as_name")
    asn_info["ipinfo_as_domain"] = lite.get("as_domain")
    asn_info["ipinfo_country"]   = lite.get("country_code") or lite.get("country")
    asn_info["ipinfo_continent"] = lite.get("continent_code") or lite.get("continent")

    if lite.get("asn"):
        asn_info["asn"] = lite.get("asn")
    if lite.get("as_name"):
        asn_info["asn_description"] = lite.get("as_name")
    if lite.get("country_code") or lite.get("country"):
        asn_info["asn_country"] = lite.get("country_code") or lite.get("country")

    return asn_info
