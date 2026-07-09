"""
opencti_ingest.py - Pull Domain-Name observables and Channel SDOs from
OpenCTI and run basic ip-intel analysis on each derived domain.

This worker is triggered manually through the API/UI. Configuration via env vars:
  OPENCTI_URL              - e.g. https://opencti.example.com
  OPENCTI_TOKEN            - API token with read access to observables
  OPENCTI_INGEST_CHANNELS  - set to false/0/no/off to skip Channel SDOs (default: true)
"""

from __future__ import annotations

import logging
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit

from core import ip_intel
from db.intel_db import get_domains_with_source_errors
from integrations.email_alerts import send_opencti_email, send_retry_email
from integrations.mattermost_alerts import send_opencti_notification, send_retry_notification
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


class _StatusLogHandler(logging.Handler):
    """Appends formatted log lines to _status["logs"] for the UI."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            _status["logs"].append(self.format(record))
        except Exception:  # noqa: BLE001
            pass


_status_handler = _StatusLogHandler()
_status_handler.setFormatter(_LOG_FMT)
log.addHandler(_status_handler)

_INGEST_WORKERS = max(1, int(os.getenv("OPENCTI_INGEST_WORKERS", "3")))

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

_started = False
_start_lock = threading.Lock()
_retry_lock = threading.Lock()
_ingest_lock = threading.Lock()
_retry_running = False
_ingest_running = False

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


def get_ingestion_status() -> dict:
    """Return a snapshot of the current ingestion status."""
    return dict(_status)


def _run_kwargs() -> dict:
    return dict(
        scan=False,
        scan_europe=False,
        scan_all=False,
        scan_providers=False,
        scan_eu_countries=False,
        scan_full=False,
        scan_countries=None,
        concurrency=5000,
        rate=5000,
    )


def _format_current_domains(active_domains: set[str]) -> str | None:
    visible = sorted(active_domains)
    if not visible:
        return None
    if len(visible) == 1:
        return visible[0]
    preview = visible[:2]
    if len(visible) == 2:
        return ", ".join(preview)
    return f"{', '.join(preview)} (+{len(visible) - 2} more)"


def _analyze_opencti_domain(domain: str) -> tuple[str, str | None]:
    try:
        ip_intel.analyze_domain(domain, **_run_kwargs())
        return domain, None
    except Exception as exc:  # noqa: BLE001
        log.exception("Unhandled analysis error for %s", domain)
        return domain, str(exc)


def retry_source_errors(source: str | None = None) -> int:
    """
    Re-analyse all domains that previously had source errors (for example urlscan 429s).
    The database is append-only, so each retry adds a fresh run instead of
    overwriting the previous one. Returns the number of domains retried.
    Safe to call from a background thread while ingestion is still running.
    """
    global _retry_running
    with _retry_lock:
        if _retry_running:
            log.info("Retry already in progress - skipping")
            return 0
        _retry_running = True

    last_error = None
    try:
        domains = get_domains_with_source_errors(source)
        if not domains:
            log.info("No domains with source errors to retry")
            send_retry_notification("completed", {"source": source, "retried": 0})
            send_retry_email("completed", {"source": source, "retried": 0})
            return 0

        label = source or "any"
        log.info("Retrying %d domains with source errors (%s)", len(domains), label)
        for i, row in enumerate(domains, 1):
            domain = row["target"]
            log.info("[retry %d/%d] %s (errors: %s)", i, len(domains), domain, row["errors"])
            try:
                ip_intel.analyze_domain(domain, **_run_kwargs())
            except Exception as exc:  # noqa: BLE001
                log.error("Retry error on %s - %s", domain, exc)
                last_error = f"{domain}: {exc}"

        log.info("Retry complete - %d domains reanalysed", len(domains))
        send_retry_notification("completed", {"source": source, "retried": len(domains), "last_error": last_error})
        send_retry_email("completed", {"source": source, "retried": len(domains), "last_error": last_error})
        return len(domains)
    except Exception as exc:
        last_error = str(exc)
        send_retry_notification("failed", {"source": source, "retried": 0, "last_error": last_error})
        send_retry_email("failed", {"source": source, "retried": 0, "last_error": last_error})
        raise
    finally:
        with _retry_lock:
            _retry_running = False


def start_retry_in_background(source: str | None = None) -> bool:
    """Launch retry_source_errors in a daemon thread. Returns False if already running."""
    global _retry_running
    with _retry_lock:
        if _retry_running:
            return False
    t = threading.Thread(target=retry_source_errors, args=(source,), name="opencti-retry", daemon=True)
    t.start()
    return True


def _get_domains() -> list[str]:
    """Fetch all Domain-Name STIX cyber observables from OpenCTI."""
    url = os.getenv("OPENCTI_URL", "").strip()
    token = os.getenv("OPENCTI_TOKEN", "").strip()
    if not url or not token:
        log.info("OPENCTI_URL or OPENCTI_TOKEN not set - skipping ingestion")
        return []

    log.info("Connecting to OpenCTI at %s", url)
    try:
        api = OpenCTIApiClient(url, token, log_level="error")
        log.info("Fetching Domain-Name observables...")
        observables = api.channel.list(
            types=["website"],
            
        )
        domains = []
        for obs in observables:
            value = obs.get("value") or obs.get("observable_value") or ""
            value = value.strip().lower()
            if value:
                domains.append(value)
        log.info("Fetched %d Domain-Name observables from OpenCTI", len(domains))
        return domains
    except Exception as exc:  # noqa: BLE001
        log.error("OpenCTI connection error: %s", exc)
        return []


def _channels_enabled() -> bool:
    """Channel SDO ingestion toggle - OPENCTI_INGEST_CHANNELS, default true."""
    return os.getenv("OPENCTI_INGEST_CHANNELS", "true").strip().lower() not in {"0", "false", "no", "off"}


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


def _channel_labels(channel: dict) -> list[str]:
    """Extract label values (objectLabel[].value) from a Channel SDO.
    pycti's default Channel query already includes objectLabel, so no extra
    request is needed to get these."""
    raw = channel.get("objectLabel") or []
    if isinstance(raw, dict):  # raw GraphQL edges shape, just in case
        raw = [edge.get("node", edge) for edge in raw.get("edges") or [] if isinstance(edge, dict)]
    labels: list[str] = []
    for item in raw:
        value = item.get("value") if isinstance(item, dict) else item
        value = str(value or "").strip()
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
    Fetch every OpenCTI Channel SDO of channel_type 'website' -- no cap,
    unlike fetch_website_channel_domains's newest-100 -- and return a
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


def fetch_website_channel_domains(limit: int = 100) -> list[str]:
    """
    Return the bare domains carried by the most recently created Channel SDOs
    of type 'website' on OpenCTI (newest `limit` channels). Social-media
    platform domains are dropped and the result is de-duplicated in order.

    Used by the case UI's "ingest website channels" button, which seeds a new
    case with these domains. Raises RuntimeError on configuration/connection
    problems so the endpoint can report a clear error.
    """
    url = os.getenv("OPENCTI_URL", "").strip()
    token = os.getenv("OPENCTI_TOKEN", "").strip()
    if not url or not token:
        raise RuntimeError("OPENCTI_URL or OPENCTI_TOKEN not set")

    api = OpenCTIApiClient(url, token, log_level="error")
    list_channels = getattr(getattr(api, "channel", None), "list", None)
    if not callable(list_channels):
        raise RuntimeError("pycti channel API is not available in this client version")

    # Filter to channel_type == "website" SERVER-SIDE via a FilterGroup. NB:
    # pycti's channel.list() ignores a `types=` kwarg (it only reads filters/
    # first/orderBy/...), so the only way `first=limit` returns `limit`
    # *website* channels — rather than `limit` channels of any type that we'd
    # then whittle down — is to push the type filter into the query.
    website_filter = {
        "mode": "and",
        "filters": [{"key": "channel_types", "values": ["website"], "operator": "eq", "mode": "or"}],
        "filterGroups": [],
    }
    try:
        channels = list_channels(
            filters=website_filter,
            first=limit,
            orderBy="created_at",
            orderMode="desc",
        ) or []
    except Exception as exc:  # noqa: BLE001 - guard against schema/arg drift
        log.warning("Ordered website-channel list failed (%s); fetching all and capping locally", exc)
        channels = list_channels(filters=website_filter, getAll=True) or []
        channels = sorted(
            (c for c in channels if isinstance(c, dict)),
            key=lambda c: str(c.get("created_at") or c.get("created") or ""),
            reverse=True,
        )[:limit]

    domains: list[str] = []
    seen: set[str] = set()
    skipped_social = 0
    for channel in channels:
        if not isinstance(channel, dict):
            continue
        # Backstop only: drop a channel that *explicitly* declares a non-website
        # type (the server filter above should already guarantee this).
        has_type = channel.get("channel_types") is not None or channel.get("channel_type") is not None
        if has_type and not _channel_is_website(channel):
            continue
        for domain in _channel_candidate_domains(channel):
            if _is_social_media_domain(domain):
                skipped_social += 1
                continue
            if domain in seen:
                continue
            seen.add(domain)
            domains.append(domain)
    log.info(
        "Fetched %d website channel(s) from OpenCTI -> %d domain(s) (%d social-media skipped)",
        len(channels), len(domains), skipped_social,
    )
    return domains


def _get_channel_domains(exclude: set[str]) -> list[str]:
    """
    Fetch Channel SDOs (STIX 2.1 extension) from OpenCTI and return the
    bare domains they resolve to, skipping social-media platform domains
    and anything already present in `exclude` (the Domain-Name set).
    """
    url = os.getenv("OPENCTI_URL", "").strip()
    token = os.getenv("OPENCTI_TOKEN", "").strip()
    if not url or not token:
        log.info("OPENCTI_URL or OPENCTI_TOKEN not set - skipping channel ingestion")
        return []

    try:
        api = OpenCTIApiClient(url, token, log_level="error")
        channel_api = getattr(api, "channel", None)
        list_channels = getattr(channel_api, "list", None)
        if not callable(list_channels):
            log.warning("pycti channel API not available - continuing with domain observables only")
            return []

        log.info("Fetching Channel objects...")
        channels = list_channels(getAll=True) or []

        domains: list[str] = []
        seen: set[str] = set(exclude)
        skipped_social = 0
        deduped = 0
        for channel in channels:
            if not isinstance(channel, dict):
                continue
            name = channel.get("name")
            for domain in _channel_candidate_domains(channel):
                if _is_social_media_domain(domain):
                    skipped_social += 1
                    log.info("Skipping social-media domain %s (channel %r)", domain, name)
                    continue
                if domain in seen:
                    deduped += 1
                    log.info("Skipping duplicate domain %s (channel %r)", domain, name)
                    continue
                seen.add(domain)
                domains.append(domain)
        log.info(
            "Fetched %d Channel objects from OpenCTI -> %d new domains (%d social-media skipped, %d duplicates)",
            len(channels),
            len(domains),
            skipped_social,
            deduped,
        )
        return domains
    except Exception as exc:  # noqa: BLE001
        log.error("OpenCTI channel fetch error: %s - continuing with domain observables only", exc)
        return []


def _build_queue() -> list[tuple[str, str]]:
    """Build the analysis queue as (domain, source) pairs, deduped across sources."""
    queue: list[tuple[str, str]] = []
    seen: set[str] = set()
    for domain in _get_domains():
        if domain in seen:
            continue
        seen.add(domain)
        queue.append((domain, SOURCE_DOMAIN_OBSERVABLE))

    if _channels_enabled():
        for domain in _get_channel_domains(seen):
            seen.add(domain)
            queue.append((domain, SOURCE_CHANNEL))
    else:
        log.info("Channel ingestion disabled via OPENCTI_INGEST_CHANNELS")
    return queue


def _run(force_reanalyse: bool = False) -> None:
    """Worker: fetch domains from OpenCTI and analyse each one."""
    global _ingest_running
    mode = "full_reanalyse" if force_reanalyse else "full_queue"
    fatal_error = None

    with _ingest_lock:
        if _ingest_running:
            log.info("Ingestion already running - skipping duplicate start")
            return
        _ingest_running = True

    _status.update(
        {
            "running": True,
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "completed_at": None,
            "total": 0,
            "done": 0,
            "skipped": 0,
            "current": None,
            "last_error": None,
            "mode": mode,
            "sources": {},
            "logs": [],
        }
    )

    try:
        log.info("OpenCTI ingestion starting (force_reanalyse=%s)", force_reanalyse)
        queue = _build_queue()
        if not queue:
            log.info("OpenCTI ingestion: nothing to do")
            return

        worker_count = min(_INGEST_WORKERS, len(queue))
        active_domains: set[str] = set()
        future_to_domain: dict = {}
        queue_index = 0

        source_counts = {
            SOURCE_DOMAIN_OBSERVABLE: sum(1 for _, source in queue if source == SOURCE_DOMAIN_OBSERVABLE),
            SOURCE_CHANNEL: sum(1 for _, source in queue if source == SOURCE_CHANNEL),
        }
        log.info(
            "Queueing %d OpenCTI domains (%d from domain observables, %d from channels) "
            "with %d worker(s) (DB skip filter disabled)",
            len(queue),
            source_counts[SOURCE_DOMAIN_OBSERVABLE],
            source_counts[SOURCE_CHANNEL],
            worker_count,
        )
        _status.update({"total": len(queue), "skipped": 0, "sources": dict(source_counts)})

        def submit_next(executor: ThreadPoolExecutor) -> bool:
            nonlocal queue_index
            if queue_index >= len(queue):
                return False
            domain, source = queue[queue_index]
            queue_index += 1
            future = executor.submit(_analyze_opencti_domain, domain)
            future_to_domain[future] = (domain, source)
            active_domains.add(domain)
            _status["current"] = _format_current_domains(active_domains)
            log.info("[queued %d/%d] %s (source=%s)", queue_index, len(queue), domain, source)
            return True

        with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="opencti-domain") as executor:
            for _ in range(worker_count):
                if not submit_next(executor):
                    break

            while future_to_domain:
                completed = next(as_completed(tuple(future_to_domain)))
                domain, source = future_to_domain.pop(completed)
                active_domains.discard(domain)
                _status["done"] += 1

                completed_domain = domain
                try:
                    completed_domain, error = completed.result()
                except Exception as exc:  # noqa: BLE001
                    error = str(exc)

                if error:
                    log.error("Error on %s (source=%s) - %s", completed_domain, source, error)
                    _status["last_error"] = f"{completed_domain}: {error}"

                submit_next(executor)
                _status["current"] = _format_current_domains(active_domains)

        _status["done"] = len(queue)
        _status["current"] = None
        log.info("OpenCTI ingestion complete")
    except Exception as exc:
        fatal_error = str(exc)
        _status["last_error"] = fatal_error
        log.exception("OpenCTI ingestion failed")
    finally:
        _status.update({"running": False, "completed_at": time.strftime("%Y-%m-%d %H:%M:%S")})
        notification_status = "failed" if fatal_error else ("completed_with_errors" if _status.get("last_error") else "completed")
        source_counts = _status.get("sources") or {}
        note_parts = []
        if _status.get("total", 0) == 0 and not fatal_error:
            note_parts.append("No domains to ingest.")
        if any(source_counts.values()):
            note_parts.append(
                f"Sources: {source_counts.get(SOURCE_DOMAIN_OBSERVABLE, 0)} {SOURCE_DOMAIN_OBSERVABLE}, "
                f"{source_counts.get(SOURCE_CHANNEL, 0)} {SOURCE_CHANNEL}."
            )
        notification_details = {
            "mode": _status.get("mode"),
            "done": _status.get("done", 0),
            "total": _status.get("total", 0),
            "skipped": _status.get("skipped", 0),
            "sources": dict(source_counts),
            "started_at": _status.get("started_at"),
            "completed_at": _status.get("completed_at"),
            "last_error": _status.get("last_error"),
            "note": " ".join(note_parts) if note_parts else None,
        }
        send_opencti_notification(notification_status, notification_details)
        send_opencti_email(notification_status, notification_details)
        with _ingest_lock:
            _ingest_running = False


def start_background_ingestion() -> None:
    """
    Launch the ingestion worker as a daemon thread on first call.
    Safe to call multiple times - only starts once per process.
    Use restart_ingestion() for the manual UI/API trigger.
    """
    global _started
    with _start_lock:
        if _started:
            return
        _started = True

    t = threading.Thread(target=_run, name="opencti-ingest", daemon=True)
    t.start()
    log.info("OpenCTI ingestion thread started")


def restart_ingestion(force_reanalyse: bool = False) -> bool:
    """
    Manually re-trigger ingestion in a background thread.

    force_reanalyse=False  - process the full OpenCTI queue
    force_reanalyse=True   - same full queue, explicitly marked as a rerun

    Returns False if ingestion is already running.
    """
    global _started
    with _ingest_lock:
        if _ingest_running:
            log.info("restart_ingestion called but already running")
            return False

    with _start_lock:
        _started = True

    t = threading.Thread(
        target=_run,
        args=(force_reanalyse,),
        name="opencti-ingest",
        daemon=True,
    )
    t.start()
    log.info("OpenCTI ingestion restarted (force_reanalyse=%s)", force_reanalyse)
    return True
