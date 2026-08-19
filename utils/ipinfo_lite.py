"""
ipinfo.io "Lite" API — fast ASN + country/continent lookups.

The primary source for ASN/org identification, used by core.basic.get_ip_whois.
It is now the *only* source for asn/asn_description, and the fallback source for
country/continent.

RDAP (ipwhois.lookup_rdap) used to run alongside this and supply the
network_name/network_cidr/asn_cidr that ipinfo Lite's response does not carry.
It was removed: once Censys host enrichment landed, enrichment covered
network_name/network_cidr (WHOIS network block, or bgp_prefix as a last resort)
and RDAP's only remaining unique fields were asn_cidr and asn_registry — not
worth being the slowest, least reliable leg in the chain, and the sole reason
the per-IP loop in core.basic.analyze had to run sequentially.

Geo precedence is the other way round: Censys enrichment wins on
country/continent (it is the only source with city/province, and mixing
providers produced incoherent locations), and the `ipinfo_country` /
`ipinfo_continent` values this module writes are the fallback for the cases
where enrichment does not answer — a sweep that has spent the 20k/day budget,
and hosts Censys has never scanned.

Needs IP_INFO_KEY set in .env; when absent, callers get back a
`{"skipped": True, ...}` marker matching the convention used by the other
optional-key provider (Censys).

**Cost (checked 2026-08-12, and the reason this is primary rather than a
fallback):** the Lite endpoint is free with no request cap at all. ipinfo's
Lite API docs state it "has no daily or monthly limit and provides unlimited
access", and https://ipinfo.io/lite advertises "unlimited API requests ... no
fees, no credit card". That is specific to Lite: the *legacy* free endpoint is
capped at 50k requests/month, which is what makes it tempting to assume Lite
is metered too. Because Lite is uncapped, Censys host enrichment (free of
credits, but hard-capped at 20k calls/day) stays a *gap-filler* for
asn/as_name rather than the winner — spending a finite daily budget to
re-derive what an unlimited source already returned would also blank those
fields the moment the budget ran out mid-sweep. Geo is the deliberate exception
described above. See merge_censys_enrichment in utils/censys_enrichment.py.
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
    Add ipinfo Lite data for one IP to an asn_info dict, in place. This is the
    first leg of core.basic.get_ip_whois and receives an empty dict; Censys host
    enrichment then runs over the result (merge_censys_enrichment).

    Writes asn/asn_description/asn_country as the canonical values, plus the
    `ipinfo_*` copies. The copies matter on their own: enrichment overwrites
    asn_country when it answers, so `ipinfo_country`/`ipinfo_continent` are what
    remain to fall back on when it does not.

    When ipinfo Lite is unavailable (no IP_INFO_KEY) or errors, the marker is
    stored under `asn_info["ipinfo"]` and nothing else is written — enrichment
    then becomes the only source of ASN identity for that IP.
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
