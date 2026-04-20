"""
opencti_ingest.py — Pull Domain-Name observables from OpenCTI and run
basic ip-intel analysis on each.

This worker is triggered manually through the API/UI. Configuration via env vars:
  OPENCTI_URL    — e.g. https://opencti.example.com
  OPENCTI_TOKEN  — API token with read access to observables
"""

import logging
import os
import sys
import threading
import time

import ip_intel
from intel_db import get_recent, get_domains_with_source_errors
from mattermost_alerts import send_opencti_notification, send_retry_notification

logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format="%(asctime)s [%(name)s] %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("opencti_ingest")

from pycti import OpenCTIApiClient

_started = False
_start_lock   = threading.Lock()
_retry_lock   = threading.Lock()
_ingest_lock  = threading.Lock()
_retry_running  = False
_ingest_running = False

# Live status dict — read by the UI without a lock (reads are GIL-safe for simple types)
_status: dict = {
    "running":       False,
    "started_at":    None,
    "completed_at":  None,
    "total":         0,
    "done":          0,
    "skipped":       0,
    "current":       None,
    "last_error":    None,
}


def get_ingestion_status() -> dict:
    """Return a snapshot of the current ingestion status (safe to call from any thread)."""
    return dict(_status)


def _run_kwargs() -> dict:
    return dict(
        scan=False, scan_europe=False, scan_all=False,
        scan_providers=False, scan_eu_countries=False, scan_full=False,
        scan_countries=None, concurrency=5000, rate=5000,
    )


def retry_source_errors(source: str | None = None) -> int:
    """
    Re-analyse all domains that previously had source errors (e.g. urlscan 429).
    The database is append-only, so each retry adds a fresh run instead of
    overwriting the previous one. Returns the number of domains retried.
    Safe to call from a background thread while ingestion is still running.
    """
    global _retry_running
    with _retry_lock:
        if _retry_running:
            log.info("Retry already in progress — skipping")
            return 0
        _retry_running = True

    last_error = None
    try:
        domains = get_domains_with_source_errors(source)
        if not domains:
            log.info("No domains with source errors to retry")
            send_retry_notification("completed", {"source": source, "retried": 0})
            return 0

        label = source or "any"
        log.info("Retrying %d domains with source errors (%s)", len(domains), label)
        for i, row in enumerate(domains, 1):
            domain = row["target"]
            log.info("[retry %d/%d] %s (errors: %s)", i, len(domains), domain, row["errors"])
            try:
                ip_intel.analyze_domain(domain, **_run_kwargs())
            except Exception as exc:
                log.error("Retry error on %s — %s", domain, exc)
                last_error = f"{domain}: {exc}"
            time.sleep(2.0)

        log.info("Retry complete — %d domains reanalysed", len(domains))
        send_retry_notification("completed", {"source": source, "retried": len(domains), "last_error": last_error})
        return len(domains)
    except Exception as exc:
        last_error = str(exc)
        send_retry_notification("failed", {"source": source, "retried": 0, "last_error": last_error})
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
    url   = os.getenv("OPENCTI_URL", "").strip()
    token = os.getenv("OPENCTI_TOKEN", "").strip()
    if not url or not token:
        log.info("OPENCTI_URL or OPENCTI_TOKEN not set — skipping ingestion")
        return []

    log.info("Connecting to OpenCTI at %s", url)
    try:
        api = OpenCTIApiClient(url, token, log_level="error")
        log.info("Fetching Domain-Name observables...")
        observables = api.stix_cyber_observable.list(
            types=["Domain-Name"],
            getAll=True,
        )
        domains = []
        for obs in observables:
            val = obs.get("value") or obs.get("observable_value") or ""
            val = val.strip().lower()
            if val:
                domains.append(val)
        log.info("Fetched %d Domain-Name observables from OpenCTI", len(domains))
        return domains
    except Exception as exc:
        log.error("OpenCTI connection error: %s", exc)
        return []


def _run(force_reanalyse: bool = False) -> None:
    """Worker: fetch domains from OpenCTI and analyse each one (basic scan only)."""
    global _ingest_running
    mode = "re-run-all" if force_reanalyse else "incremental"
    fatal_error = None

    with _ingest_lock:
        if _ingest_running:
            log.info("Ingestion already running — skipping duplicate start")
            return
        _ingest_running = True

    _status.update({
        "running":      True,
        "started_at":   time.strftime("%Y-%m-%d %H:%M:%S"),
        "completed_at": None,
        "total":        0,
        "done":         0,
        "skipped":      0,
        "current":      None,
        "last_error":   None,
        "mode":         mode,
    })

    try:
        log.info("OpenCTI ingestion starting (force_reanalyse=%s)", force_reanalyse)
        domains = _get_domains()
        if not domains:
            log.info("OpenCTI ingestion: nothing to do")
            return

        if force_reanalyse:
            new_domains = domains
            skipped_count = 0
        else:
            try:
                recent = get_recent(limit=10_000)
                already_done = {r["target"].lower() for r in recent}
            except Exception as exc:
                log.error("Failed to fetch recent DB entries — %s", exc)
                already_done = set()
            new_domains   = [d for d in domains if d not in already_done]
            skipped_count = len(domains) - len(new_domains)

        log.info("%d new domains to analyse, %d already in DB", len(new_domains), skipped_count)
        _status.update({"total": len(new_domains), "skipped": skipped_count})

        for i, domain in enumerate(new_domains, 1):
            _status["current"] = domain
            _status["done"]    = i - 1
            log.info("[%d/%d] Analysing %s", i, len(new_domains), domain)
            try:
                ip_intel.analyze_domain(domain, **_run_kwargs())
            except Exception as exc:
                log.error("Error on %s — %s", domain, exc)
                _status["last_error"] = f"{domain}: {exc}"
            time.sleep(1.5)

        _status["done"]    = len(new_domains)
        _status["current"] = None
        log.info("OpenCTI ingestion complete")
    except Exception as exc:
        fatal_error = str(exc)
        _status["last_error"] = fatal_error
        log.exception("OpenCTI ingestion failed")

    finally:
        _status.update({"running": False, "completed_at": time.strftime("%Y-%m-%d %H:%M:%S")})
        send_opencti_notification(
            "failed" if fatal_error else ("completed_with_errors" if _status.get("last_error") else "completed"),
            {
                "mode": _status.get("mode"),
                "done": _status.get("done", 0),
                "total": _status.get("total", 0),
                "skipped": _status.get("skipped", 0),
                "started_at": _status.get("started_at"),
                "completed_at": _status.get("completed_at"),
                "last_error": _status.get("last_error"),
                "note": "No domains to ingest." if _status.get("total", 0) == 0 and not fatal_error else None,
            },
        )
        with _ingest_lock:
            _ingest_running = False


def start_background_ingestion() -> None:
    """
    Launch the ingestion worker as a daemon thread on first call.
    Safe to call multiple times — only starts once per process.
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

    force_reanalyse=False  — skips domains already in the DB
    force_reanalyse=True   — re-analyses every domain from OpenCTI regardless

    Returns False if ingestion is already running.
    """
    global _started
    with _ingest_lock:
        if _ingest_running:
            log.info("restart_ingestion called but already running")
            return False

    # Allow future calls to start_background_ingestion to be no-ops, but we
    # are deliberately restarting so reset _started so callers don't need to
    # track it themselves.
    with _start_lock:
        _started = True   # keep True so the auto-start guard stays inactive

    t = threading.Thread(
        target=_run,
        args=(force_reanalyse,),
        name="opencti-ingest",
        daemon=True,
    )
    t.start()
    log.info("OpenCTI ingestion restarted (force_reanalyse=%s)", force_reanalyse)
    return True
