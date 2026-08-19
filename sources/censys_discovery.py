"""Censys Platform reverse lookups — turn one selector into internet-wide discovery.

A shared tracking ID or favicon hash normally only links two domains we already
scanned: the graph in `db/intel_db.py` can only see selectors that appear twice
inside our own corpus. The Censys Platform search endpoint inverts that — one
selector value becomes a query over every web property Censys has ever scanned,
so an operator's second site turns up even though nobody ever submitted it.

Two things come back from every query and both are worth keeping:

* the **hit domains**, which become discovery candidates, and
* `total_hits`, the selector's **global prevalence**. That number is strictly
  better information than `utils/check.py`'s `rarity_weight`, which can only
  measure degree inside our own corpus: a GA property seen on exactly two of our
  domains looks maximally rare locally even when Censys sees it on 40,000 sites.
  The count is stored even when the query surfaces nothing new (see
  `db/discovery_store.py`).

Cost: every selector is one billed Censys search, so this module spends exactly
two credits per ingested domain — one content selector, one tracking selector,
each chosen by `rank_selectors` from everything the page carried. Together with
`core.basic.get_censys`'s cert search that is three per ingested domain, and
nothing else in a case spends a search credit at all: `profile_for` in
`core/analysis_service.py` hands every *discovered* target a profile with both
`run_providers` and `reverse_lookups` off, so a case's Censys bill is three
credits times the number of domains a human actually submitted.

The other half of the Censys surface — `utils/censys_enrichment.py`'s host
enrichment — costs no credits and runs over every IP in the case, discovered or
not. That split is the whole design: enrichment answers everything *forward*
about an IP (ASN, geo, open ports, reputation, GreyNoise, VPN/proxy flags,
bound DNS names), so the paid search is reserved for the questions it
structurally cannot answer — the *inverse* lookups. "Which hosts serve a cert
naming this domain" and "which other web properties carry this selector" have
no free source, and are the only reason to spend a credit.

Requires a Censys Starter tier or higher (the free tier's API is lookup-only and
cannot search). Missing credentials degrade to a `{"skipped": True, ...}` marker
like every other optional provider here.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Any, Iterable

# ── Queryable field paths ────────────────────────────────────────────────────
# Verified against the censys-platform SDK's generated web-property schema
# (models/endpointscanstate.py -> `extracted` / `http`, models/extractedendpointdata.py
# -> `analytics_services`, models/http_favicon.py -> `hash_md5`/`hash_sha256`/
# `hash_shodan`) and https://docs.censys.com/docs/platform-web-property-dataset.
# A wrong field name returns zero hits silently rather than erroring, so these
# are pinned to the schema rather than typed from memory.
TRACKING_ID_FIELD = "web.endpoints.extracted.analytics_services.ids"
FAVICON_MD5_FIELD = "web.endpoints.http.favicons.hash_md5"
FAVICON_SHA256_FIELD = "web.endpoints.http.favicons.hash_sha256"
# Censys' Shodan-compatible favicon hash: mmh3 over the base64 of the icon bytes,
# as a signed decimal integer — the exact construction sources/signal_web.py's
# `hash_favicon_bytes` uses for `favicon_murmurhash3`, so our value is directly
# queryable. (Censys hashes only the first 384 KB of a favicon, so an icon larger
# than that will not match; in practice favicons are a few KB.)
FAVICON_SHODAN_FIELD = "web.endpoints.http.favicons.hash_shodan"
BODY_HASH_FIELD = "web.endpoints.http.body_hash_sha256"

# ── Cost controls ────────────────────────────────────────────────────────────
# One billed Censys search per selector, so the selector count *is* the bill.
# This was 8 — "one favicon plus one to three analytics tags covers every honest
# case" — which made the per-domain cost variable and, on a page that inlines a
# dozen GTM containers, maximal. It is now exactly one query per selector
# *class*: the pipeline picks the single best content selector and the single
# best tracking selector (see `rank_selectors`) and queries those two.
#
# Two queries rather than one combined `or` is deliberate. Credits are charged
# per page of results, not per term, so ORing both classes into one query would
# save a credit — but it would also make the two share a single 100-result page
# and collapse their two `total_hits` counts into one union count that can no
# longer be attributed to either selector. Prevalence is the half of the answer
# `utils/check.py` cannot compute (see the module docstring), so the second
# credit buys back more than it costs.
#
# With core/basic.py's cert search that is a fixed three searches per ingested
# domain, down from up to nine. Nothing else in a case spends a search credit:
# `core.analysis_service.profile_for` gives every discovered target a profile
# with `run_providers=False, reverse_lookups=False`.
SELECTOR_CLASSES = ("content", "tracking")
MAX_SELECTORS_PER_SCAN = len(SELECTOR_CLASSES)

# One page per selector: Censys charges 1 credit for the search and 1 more for
# every additional page of 100 results, so pages are credits. 100 results is the
# API maximum for a single page and already more than MAX_DOMAINS_PER_SELECTOR
# (25) can consume — a selector whose first page does not yield 25 distinct
# registrable domains is not going to become more attributable on page two.
# This was 3, which tripled the reverse-lookup bill for candidates the domain
# cap discarded anyway.
MAX_PAGES_PER_SELECTOR = 1
CENSYS_PAGE_SIZE = 100

# Distinct registrable domains harvested from one selector. Bounds the follow-up
# scan fan-out, which is far more expensive than the search itself: each domain
# here becomes a full (free-only) scan.
MAX_DOMAINS_PER_SELECTOR = 25

# Prevalence ceiling. Above this we record `total_hits` and stop — no pagination,
# no candidates. `utils/check.py`'s rarity_weight is 1/log2(degree), so at 500 a
# shared selector is already worth ~0.11 of its base weight and at the corpus
# scale it is indistinguishable from the 0.04 floor: a selector this common
# cannot attribute anything, so paginating it only burns credits. The count is
# still the useful part of the answer and is kept.
MAX_GLOBAL_HITS_TO_EXPAND = 500

# ── Selector sources ─────────────────────────────────────────────────────────
# Kind names deliberately mirror db/intel_db.py's `identifiers.id_type` spellings
# so stored discovery evidence keys on the same vocabulary as the rest of the
# graph instead of inventing a second one.
_TRACKING_SOURCES: tuple[tuple[str, str], ...] = (
    ("google_analytics", "ga_property"),
    ("gtm_ids", "gtm_container"),
    ("facebook_pixel", "fb_pixel"),
    ("yandex_metrika", "yandex_metrika"),
    ("tiktok_pixel", "tiktok_pixel"),
    ("adsense_publisher_ids", "adsense_publisher"),
)

# (page_metadata key, selector kind, Censys field, numeric?)
_CONTENT_SOURCES: tuple[tuple[str, str, str, bool], ...] = (
    ("favicon_md5", "favicon_md5", FAVICON_MD5_FIELD, False),
    # Two spellings exist in the codebase for the same value: fetch_page_metadata
    # emits `favicon_murmurhash3`, the enrichment path emits `favicon_mmh3`.
    ("favicon_murmurhash3", "favicon_mmh3", FAVICON_SHODAN_FIELD, True),
    ("favicon_mmh3", "favicon_mmh3", FAVICON_SHODAN_FIELD, True),
    ("favicon_sha256", "favicon_sha256", FAVICON_SHA256_FIELD, False),
    # NOT fed by `homepage_html_hash`: that is a sha256 of the *normalized
    # extracted text* (scripts, styles and comments stripped, whitespace
    # collapsed — see signal_web.normalized_text_hash), while Censys hashes the
    # raw HTTP response body. The two can never be equal, so wiring them together
    # would ship a query that silently always returns nothing. This key lights up
    # the moment page_metadata carries a real raw-body digest.
    ("homepage_body_sha256", "body_sha256", BODY_HASH_FIELD, False),
)


# Tie-break order used only when a selector has never been queried before and so
# has no recorded prevalence. Lower is preferred. This is a prior about how
# *specific to one operator* a selector kind tends to be, not about how many
# sites carry it:
#
#   favicon hashes  — an exact byte-identical icon. Distinct per brand, and the
#                     sha256 spelling is preferred over md5/mmh3 only because it
#                     cannot collide; all three match the same properties.
#   fb_pixel        — one pixel per business account; rarely shared beyond it.
#   yandex/tiktok   — same shape, smaller populations.
#   adsense_publisher, ga_property — keyed on an *account*, so they deliberately
#                     span every site the operator runs. That is what makes them
#                     the strongest attribution evidence when they hit, and also
#                     what makes them the most likely to be promiscuous.
#   gtm_container   — tag managers are routinely pasted across unrelated client
#                     sites by agencies, so this is the least trustworthy.
_RARITY_PRIOR: dict[str, int] = {
    "favicon_sha256": 0,
    "favicon_md5": 1,
    "favicon_mmh3": 2,
    "body_sha256": 3,
    "fb_pixel": 10,
    "yandex_metrika": 11,
    "tiktok_pixel": 12,
    "adsense_publisher": 13,
    "ga_property": 14,
    "gtm_container": 15,
}
_UNKNOWN_PRIOR = 50


def _clean_values(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, (str, int)):
        items: Iterable[Any] = [raw]
    elif isinstance(raw, (list, tuple, set)):
        items = raw
    else:
        return []
    out: list[str] = []
    for item in items:
        text = str(item).strip()
        if text and text.lower() not in ("none", "null") and text not in out:
            out.append(text)
    return out


def candidate_selectors(page_metadata: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Every pivotable selector in a scan's page metadata, unranked and uncapped.

    Separated from `collect_selectors` so the ranking step has the full set to
    choose from: capping here (as this function used to, keeping the first 8 in
    tracking-first order) threw away the favicon before anything had looked at
    whether the tracking IDs were worth querying.
    """
    meta = page_metadata if isinstance(page_metadata, dict) else {}
    selectors: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(
        kind: str, value: str, field: str, *, numeric: bool, source_key: str, cls: str
    ) -> None:
        key = (kind, value)
        if key in seen:
            return
        seen.add(key)
        selectors.append(
            {
                "kind": kind,
                "value": value,
                "field": field,
                "selector_class": cls,
                "query": _build_query(field, value, numeric=numeric),
                "source": f"page_metadata.{source_key}",
            }
        )

    for meta_key, kind in _TRACKING_SOURCES:
        for value in _clean_values(meta.get(meta_key)):
            add(kind, value, TRACKING_ID_FIELD, numeric=False,
                source_key=meta_key, cls="tracking")

    for meta_key, kind, field, numeric in _CONTENT_SOURCES:
        for value in _clean_values(meta.get(meta_key)):
            add(kind, value, field, numeric=numeric,
                source_key=meta_key, cls="content")

    return selectors


def _known_prevalence(selectors: list[dict[str, Any]]) -> dict[tuple[str, str], int]:
    """Recorded global `total_hits` for selectors we have queried before.

    Best-effort by design: this runs inside the scan pipeline and a database that
    is unreachable, mid-migration, or simply empty on a first run must degrade to
    "no history" and let the static prior decide, not fail the scan.
    """
    if not selectors:
        return {}
    try:
        from db import discovery_store

        return discovery_store.global_prevalence_map(
            [(sel["kind"], sel["value"]) for sel in selectors]
        )
    except Exception:
        return {}


def rank_selectors(
    selectors: list[dict[str, Any]], prevalence: dict[tuple[str, str], int]
) -> list[dict[str, Any]]:
    """Order selectors by how well a search credit is spent on each.

    Not simply "rarest first". A selector's value as a pivot is not monotonic in
    its prevalence — it peaks in the middle:

    * **prevalence 0 or 1** — nobody but us carries it. The query is guaranteed
      to return no new domain, so it is the *worst* use of a credit even though
      it is the rarest thing we hold. Blind rarity ranking picks these first.
    * **2 .. MAX_GLOBAL_HITS_TO_EXPAND** — carried by a handful of other
      properties. This is the band where a hit is near-proof of shared
      operation, and it is what we want to spend on.
    * **above MAX_GLOBAL_HITS_TO_EXPAND** — too common to attribute anything.
      `_search_selector` already refuses to expand these; querying one again
      only re-reads a count we have.
    * **never queried** — unknown. Ranked between the useful band and the known
      -useless ones: worth a credit to find out, but not ahead of a selector we
      already know sits in the sweet spot. `_RARITY_PRIOR` breaks ties here.

    The counts come from `db.discovery_store`, so every scan sharpens the next
    one's choice rather than re-learning the same promiscuous GTM container.
    """
    def sort_key(sel: dict[str, Any]) -> tuple[int, int, str]:
        hits = prevalence.get((sel["kind"], sel["value"]))
        prior = _RARITY_PRIOR.get(sel["kind"], _UNKNOWN_PRIOR)
        if hits is None:
            return (1, prior, sel["value"])
        if hits <= 1:
            return (3, prior, sel["value"])
        if hits > MAX_GLOBAL_HITS_TO_EXPAND:
            return (2, hits, sel["value"])
        return (0, hits, sel["value"])

    return sorted(selectors, key=sort_key)


def collect_selectors(page_metadata: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The selectors this scan will actually spend credits on: at most one per
    class, best-first within each.

    One content selector and one tracking selector rather than the best two
    overall, because the two classes fail independently. A favicon and a GA
    property are evidence of different things — shared build artefacts vs. a
    shared analytics account — and a site whose favicon is a stock Bootstrap
    icon can still have a highly attributing tracking ID. Ranking the pooled set
    and taking the top two would let one class win both slots and leave the
    other unqueried.
    """
    candidates = candidate_selectors(page_metadata)
    if not candidates:
        return []

    ranked = rank_selectors(candidates, _known_prevalence(candidates))

    chosen: list[dict[str, Any]] = []
    used: set[str] = set()
    for sel in ranked:
        cls = sel.get("selector_class")
        if cls in used or cls not in SELECTOR_CLASSES:
            continue
        used.add(cls)
        chosen.append(sel)
        if len(used) == len(SELECTOR_CLASSES):
            break
    return chosen


def _build_query(field: str, value: str, *, numeric: bool) -> str:
    """CenQL exact-match term. `=` is exact/case-sensitive; `:` would tokenize
    and match substrings of unrelated IDs."""
    if numeric:
        return f"{field} = {int(value)}"
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'{field} = "{escaped}"'


def _as_dict(obj: Any) -> dict:
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        try:
            return obj.model_dump()
        except Exception:
            pass
    return {}


def _hostnames_from_hit(hit: Any) -> list[str]:
    """Pull the web property's hostname out of one search hit.

    Search hits are tagged unions (`webproperty_v1` / `host_v1` /
    `certificate_v1`); the web-property arm nests the record under `resource`,
    the same shape `core.ip_intel._censys_parse_host_hit` unwraps for hosts.
    """
    resource = (_as_dict(hit).get("webproperty_v1") or {}).get("resource") or {}
    names: list[str] = []
    hostname = str(resource.get("hostname") or "").strip().lower()
    if hostname:
        names.append(hostname)
    for endpoint in resource.get("endpoints") or []:
        endpoint_host = str(_as_dict(endpoint).get("hostname") or "").strip().lower()
        if endpoint_host and endpoint_host not in names:
            names.append(endpoint_host)
    return names


def _search_selector(sdk, selector: dict[str, Any]) -> dict[str, Any]:
    """Run one selector's query, capturing total_hits and the hit hostnames."""
    record = {
        **selector,
        "global_hits": None,
        "hostnames": [],
        "truncated": False,
        "pages": 0,
    }
    page_token: str | None = None
    hostnames: list[str] = []
    for page in range(MAX_PAGES_PER_SELECTOR):
        # No `fields` selection: this SDK/API version only populates top-level
        # selected fields and returns empty nested objects underneath, which is
        # why core/ip_intel.py's cert search requests the full resource too.
        body: dict = {"query": selector["query"], "page_size": CENSYS_PAGE_SIZE}
        if page_token:
            body["page_token"] = page_token
        resp = sdk.global_data.search(search_query_input_body=body)
        # resp.result wraps the real payload under a further "result" key.
        payload = _as_dict(_as_dict(getattr(resp, "result", None)).get("result"))
        record["pages"] = page + 1

        if record["global_hits"] is None:
            record["global_hits"] = int(payload.get("total_hits") or 0)
            # The prevalence count is the whole answer for a promiscuous
            # selector; stop before paginating something we would discard.
            if record["global_hits"] > MAX_GLOBAL_HITS_TO_EXPAND:
                record["truncated"] = True
                record["skipped_expansion"] = (
                    f"global prevalence {record['global_hits']} exceeds "
                    f"{MAX_GLOBAL_HITS_TO_EXPAND}; too common to attribute"
                )
                return record

        hits = payload.get("hits") or []
        for hit in hits:
            for name in _hostnames_from_hit(hit):
                if name not in hostnames:
                    hostnames.append(name)
        if len(hostnames) >= MAX_DOMAINS_PER_SELECTOR:
            record["truncated"] = True
            break

        page_token = payload.get("next_page_token")
        if not page_token or not hits:
            break
    else:
        record["truncated"] = True

    record["hostnames"] = hostnames[:MAX_DOMAINS_PER_SELECTOR]
    return record


def reverse_lookup(page_metadata: dict[str, Any] | None) -> dict[str, Any]:
    """Search Censys for every other web property carrying this site's selectors.

    Spends at most `MAX_SELECTORS_PER_SCAN` credits — one per selector class,
    on whichever selector of that class `collect_selectors` judged the best use
    of one. A page with no tracking IDs costs one credit, not two: the cap is a
    ceiling per class, never a quota to spend down.

    Returns `{"selectors": [...], "queries": n}` where each selector record
    carries its Censys field, its global `total_hits`, and the hostnames found.
    Per-selector failures are recorded on that selector rather than aborting the
    rest — one tier/permission error must not cost the whole run.
    """
    selectors = collect_selectors(page_metadata)
    if not selectors:
        return {"skipped": True, "reason": "no pivotable selectors in page metadata", "selectors": []}

    api_key = os.environ.get("CENSYS_API_KEY")
    org_id = os.environ.get("CENSYS_ORG_ID")
    if not api_key:
        return {"skipped": True, "reason": "CENSYS_API_KEY not set in .env", "selectors": []}
    if not org_id:
        return {"skipped": True, "reason": "CENSYS_ORG_ID not set in .env", "selectors": []}

    from censys_platform import SDK

    results: list[dict[str, Any]] = []
    try:
        with SDK(personal_access_token=api_key, organization_id=org_id) as sdk:
            for selector in selectors:
                try:
                    results.append(_search_selector(sdk, selector))
                except Exception as exc:
                    results.append({**selector, "global_hits": None, "hostnames": [], "error": str(exc)})
    except Exception as exc:
        return {"error": str(exc), "selectors": results}

    return {"selectors": results, "queries": len(results)}


def discovered_domains(lookup: dict[str, Any], origin_domain: str, apex: Any) -> list[dict[str, Any]]:
    """Roll a lookup's hostnames up to registrable domains, minus the origin.

    `apex` is the eTLD+1 function (core.basic._apex) — passed in so this module
    stays free of the analysis engine's import graph. The rarest selector wins
    when several surface the same domain, since that is the evidence a reviewer
    should see first.
    """
    origin_apex = apex(str(origin_domain or "").strip().lower())
    best: dict[str, dict[str, Any]] = {}
    for record in lookup.get("selectors") or []:
        hits = record.get("global_hits")
        for hostname in record.get("hostnames") or []:
            domain = apex(hostname)
            if not domain or domain == origin_apex:
                continue
            candidate = {
                "target": domain,
                # Censys web properties can be keyed on a bare IP rather than a
                # hostname, so a reverse lookup legitimately surfaces both. The
                # type rides on the candidate instead of being assumed
                # "domain" downstream: db/discovery_store.py writes it to
                # discovered_targets.target_type, and an IP recorded as a domain
                # is both wrong in the pool and unscannable as one.
                "target_type": "ip" if _is_ip_literal(domain) else "domain",
                "matched_hostname": hostname,
                "selector_kind": record.get("kind"),
                "selector_value": record.get("value"),
                "censys_field": record.get("field"),
                "global_hits": hits,
            }
            current = best.get(domain)
            if current is None or _prevalence_rank(hits) < _prevalence_rank(current.get("global_hits")):
                best[domain] = candidate
    return [best[key] for key in sorted(best)]


def _is_ip_literal(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return True


def _prevalence_rank(hits: Any) -> int:
    # Unknown prevalence sorts last so a selector with a real count always wins.
    return int(hits) if isinstance(hits, int) else 1 << 30
