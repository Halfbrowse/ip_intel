"""
opencti_ingest.py - Read Channel SDOs and their labels out of OpenCTI.

This is now a *reader* only. It used to also drive analysis: `_run` /
`start_background_ingestion` / `restart_ingestion` pulled Domain-Name
observables and Channel SDOs and scanned each derived domain through
`core.ip_intel.analyze_domain`, and `retry_source_errors` re-scanned anything
that had recorded a provider error. All of that went with the async scan engine
those functions called — nothing was wired to it (no API route, no script), and
the live path is `scripts/ingest_opencti_channels.py`, which submits through
`cases.case_runtime.CaseRuntime` like an ordinary case instead.

What is left is the OpenCTI query surface that script imports:
`fetch_all_website_channel_data`, plus the channel/label/tier helpers it needs.

Configuration via env vars:
  OPENCTI_URL   - e.g. https://opencti.example.com
  OPENCTI_TOKEN - API token with read access to observables
"""

from __future__ import annotations

import logging
import os
import re
import sys
from urllib.parse import urlsplit

from pycti import OpenCTIApiClient

log = logging.getLogger("opencti_ingest")
log.setLevel(logging.INFO)

_LOG_FMT = logging.Formatter(
    "%(asctime)s [%(name)s] %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

if not log.handlers:
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(_LOG_FMT)
    log.addHandler(_h)
    log.propagate = False






# Provenance labels for queue entries
SOURCE_DOMAIN_OBSERVABLE = "domain-observable"
SOURCE_CHANNEL = "channel"

# Social-media platform domains - channels hosted on these are not
# "non-social media channels" (per the project end goal), so they are skipped.
_SOCIAL_MEDIA_DOMAINS = frozenset(
    {
        "discord.com",
        "discord.gg",
        "facebook.com",
        "fb.com",
        "instagram.com",
        "linkedin.com",
        "ok.ru",
        "odnoklassniki.ru",
        "reddit.com",
        "rumble.com",
        "t.me",
        "telegram.me",
        "telegram.org",
        "threads.net",
        "tiktok.com",
        "twitch.tv",
        "twitter.com",
        "vk.com",
        "whatsapp.com",
        "x.com",
        "youtu.be",
        "youtube.com",
    }
)

_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")


# Live status dict - read by the UI without a lock (reads are GIL-safe for simple types)
_status: dict = {
    "running": False,
    "started_at": None,
    "completed_at": None,
    "total": 0,
    "done": 0,
    "skipped": 0,
    "current": None,
    "last_error": None,
    "sources": {},
    "logs": [],
}


















def _normalize_domain(text: object) -> str | None:
    """
    Normalize a free-text candidate (bare domain, host/path, or full URL) to a
    bare registrable domain: strip scheme, path, port, and a leading "www.".
    Returns None when the text does not parse as a domain.
    """
    value = str(text or "").strip().lower()
    if not value:
        return None
    try:
        if "://" in value:
            host = urlsplit(value).hostname or ""
        elif "/" in value:
            host = urlsplit(f"//{value}").hostname or ""
        else:
            host = value
    except ValueError:
        return None
    host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host  # bare "host:port"
    host = host.strip(".")
    if host.startswith("www."):
        host = host[4:]
    if not _DOMAIN_RE.match(host):
        return None
    return host


def _is_social_media_domain(domain: str) -> bool:
    return any(domain == skip or domain.endswith(f".{skip}") for skip in _SOCIAL_MEDIA_DOMAINS)


def _channel_candidate_domains(channel: dict) -> list[str]:
    """
    Extract candidate domains from one OpenCTI Channel SDO: from its name
    and aliases (when they parse as a domain/URL) and from external
    reference URLs. Social-media filtering happens in the caller.
    """
    texts: list[object] = [channel.get("name")]
    for alias_key in ("aliases", "x_opencti_aliases"):
        aliases = channel.get(alias_key)
        if isinstance(aliases, (list, tuple)):
            texts.extend(aliases)

    refs = channel.get("externalReferences") or channel.get("external_references") or []
    if isinstance(refs, dict):  # raw GraphQL edges shape
        refs = [edge.get("node", edge) for edge in refs.get("edges") or [] if isinstance(edge, dict)]
    for ref in refs:
        if isinstance(ref, dict):
            texts.append(ref.get("url"))

    candidates: list[str] = []
    seen: set[str] = set()
    for text in texts:
        domain = _normalize_domain(text)
        if domain and domain not in seen:
            seen.add(domain)
            candidates.append(domain)
    return candidates


def _channel_is_website(channel: dict) -> bool:
    """True when a Channel SDO is of type 'website'. The field is normally a
    list (`channel_types`) but tolerate a scalar or the singular key too."""
    types = channel.get("channel_types")
    if types is None:
        types = channel.get("channel_type")
    if isinstance(types, str):
        types = [types]
    if not isinstance(types, (list, tuple)):
        return False
    return any(str(t).strip().lower() == "website" for t in types)


def _label_items(raw: object) -> list[object]:
    if raw is None:
        return []
    if isinstance(raw, dict):
        if isinstance(raw.get("edges"), list):
            return [edge.get("node", edge) for edge in raw.get("edges") or [] if isinstance(edge, dict)]
        if "node" in raw:
            return [raw.get("node")]
        return [raw]
    if isinstance(raw, (list, tuple, set)):
        return list(raw)
    return [raw]


def _label_value(item: object) -> str:
    if isinstance(item, dict):
        node = item.get("node")
        if isinstance(node, dict):
            item = node
        value = item.get("value") or item.get("name") or item.get("label")
    else:
        value = item
    return str(value or "").strip()


def _channel_labels(channel: dict) -> list[str]:
    """Extract label values from a Channel SDO.

    pycti normally returns `objectLabel` as a list of dicts like
    [{"value": "tier-1"}, ...]. Some OpenCTI/client shapes use `labels`, a
    GraphQL `edges[].node` wrapper, or nested `node` dicts, so tolerate all of
    those and keep unique labels in first-seen order.
    """
    labels: list[str] = []
    for raw in (channel.get("objectLabel"), channel.get("labels")):
        for item in _label_items(raw):
            value = _label_value(item)
            if value and value not in labels:
                labels.append(value)
    return labels


# The only labels that matter for classification are the 5 tier labels; a
# channel typically carries other, unrelated labels too (campaign names,
# platform tags, ...) which are not tiers and are ignored here. Matching is
# "tier" + a digit 1-5, case/space/dash/underscore-insensitive, so "Tier 1",
# "tier-2", "TIER_3", "tier   4" all resolve — the rest of a label's text
# (there's more to each one than just the tier marker) doesn't matter.
_TIER_LABEL_RE = re.compile(r"tier[\s_-]*([1-5])\b", re.IGNORECASE)


def _extract_tier(labels: list[str]) -> int | None:
    """Pick the tier (1-5, 1 = highest priority) out of a channel's labels.
    If more than one tier label is somehow present, the lowest number (the
    higher-priority tier) wins."""
    best: int | None = None
    for label in labels:
        match = _TIER_LABEL_RE.search(label)
        if not match:
            continue
        tier = int(match.group(1))
        if best is None or tier < best:
            best = tier
    return best


def fetch_all_website_channel_data() -> dict[str, dict]:
    """
    Fetch every OpenCTI Channel SDO of channel_type 'website' -- no cap (the
    frontend's retired "ingest website channels" button was limited to the
    newest 100) -- and return a
    {domain: {"labels": [...], "tier": int | None}} map, merging labels
    across any channels that resolve to the same domain. Social-media
    platform domains are dropped. `tier` is the domain's tier-1..tier-5
    classification (see _extract_tier), or None if no tier label is present.

    Raises RuntimeError on configuration/connection problems.
    """
    url = os.getenv("OPENCTI_URL", "").strip()
    token = os.getenv("OPENCTI_TOKEN", "").strip()
    if not url or not token:
        raise RuntimeError("OPENCTI_URL or OPENCTI_TOKEN not set")

    api = OpenCTIApiClient(url, token, log_level="error")
    list_channels = getattr(getattr(api, "channel", None), "list", None)
    if not callable(list_channels):
        raise RuntimeError("pycti channel API is not available in this client version")

    # Same server-side channel_types filter as fetch_website_channel_domains,
    # but with getAll=True (pycti auto-paginates through every page) instead
    # of a first=limit cap, since this is meant to sweep the whole corpus.
    website_filter = {
        "mode": "and",
        "filters": [{"key": "channel_types", "values": ["website"], "operator": "eq", "mode": "or"}],
        "filterGroups": [],
    }
    channels = list_channels(filters=website_filter, getAll=True) or []

    domain_labels: dict[str, set[str]] = {}
    skipped_social = 0
    for channel in channels:
        if not isinstance(channel, dict):
            continue
        # Backstop only: drop a channel that *explicitly* declares a non-website
        # type (the server filter above should already guarantee this).
        has_type = channel.get("channel_types") is not None or channel.get("channel_type") is not None
        if has_type and not _channel_is_website(channel):
            continue
        labels = _channel_labels(channel)
        for domain in _channel_candidate_domains(channel):
            if _is_social_media_domain(domain):
                skipped_social += 1
                continue
            domain_labels.setdefault(domain, set()).update(labels)

    tiered = 0
    result: dict[str, dict] = {}
    for domain, labels in domain_labels.items():
        tier = _extract_tier(labels)
        if tier is not None:
            tiered += 1
        result[domain] = {"labels": sorted(labels), "tier": tier}

    log.info(
        "Fetched %d website channel(s) from OpenCTI -> %d domain(s) (%d social-media skipped, %d tiered)",
        len(channels), len(result), skipped_social, tiered,
    )
    return result












