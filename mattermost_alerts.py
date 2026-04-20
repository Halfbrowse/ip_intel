"""
Optional Mattermost completion alerts.

Set MATTERMOST_WEBHOOK_URL in the environment or .env file to enable alerts.
Calls are non-blocking: the webhook POST runs in a short-lived daemon thread.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime
from typing import Any, Mapping

import requests
from dotenv import load_dotenv

load_dotenv()

LOGGER = logging.getLogger("ip_intel.mattermost")
_WEBHOOK_TIMEOUT_SECONDS = 10
_DETAIL_VALUE_LIMIT = 500


def _webhook_url() -> str:
    return os.getenv("MATTERMOST_WEBHOOK_URL", "").strip()


def _parse_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None

    for parser in (datetime.fromisoformat,):
        try:
            return parser(text)
        except ValueError:
            pass

    for fmt in ("%Y-%m-%d %H:%M:%S",):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _duration_label(started_at: Any, finished_at: Any) -> str | None:
    started = _parse_timestamp(started_at)
    finished = _parse_timestamp(finished_at)
    if started is None or finished is None:
        return None

    seconds = max(0, int((finished - started).total_seconds()))
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {seconds}s"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def _format_detail_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
    elif isinstance(value, bool):
        text = "yes" if value else "no"
    elif isinstance(value, (int, float)):
        text = str(value)
    elif isinstance(value, Mapping):
        parts = [f"{key}={item}" for key, item in value.items()]
        text = ", ".join(parts)
    elif isinstance(value, (list, tuple, set)):
        items = [str(item) for item in value if str(item).strip()]
        if not items:
            return None
        text = ", ".join(items[:8])
        if len(items) > 8:
            text = f"{text} (+{len(items) - 8} more)"
    else:
        text = str(value).strip()
        if not text:
            return None

    if len(text) > _DETAIL_VALUE_LIMIT:
        text = f"{text[:_DETAIL_VALUE_LIMIT - 3]}..."
    return f"`{text}`"


def _deliver_message(webhook_url: str, payload: dict[str, Any]) -> None:
    try:
        response = requests.post(webhook_url, json=payload, timeout=_WEBHOOK_TIMEOUT_SECONDS)
        response.raise_for_status()
    except Exception:  # noqa: BLE001
        LOGGER.exception("Mattermost alert delivery failed")


def send_process_alert(
    *,
    title: str,
    status: str,
    summary: str | None = None,
    details: Mapping[str, Any] | None = None,
    started_at: Any = None,
    finished_at: Any = None,
) -> bool:
    webhook_url = _webhook_url()
    if not webhook_url:
        return False

    lines = [f"**{title}**", f"- Status: `{status}`"]
    if summary:
        lines.append(summary)

    if started_at:
        lines.append(f"- Started: `{started_at}`")
    if finished_at:
        lines.append(f"- Finished: `{finished_at}`")

    duration = _duration_label(started_at, finished_at)
    if duration:
        lines.append(f"- Duration: `{duration}`")

    for label, value in (details or {}).items():
        formatted = _format_detail_value(value)
        if formatted is None:
            continue
        lines.append(f"- {label}: {formatted}")

    payload = {"text": "\n".join(lines)}
    thread = threading.Thread(
        target=_deliver_message,
        args=(webhook_url, payload),
        name="mattermost-alert",
        daemon=True,
    )
    thread.start()
    return True


def send_analysis_notification(job: Mapping[str, Any]) -> bool:
    status = str(job.get("status") or "unknown")
    target = str(job.get("target") or "unknown")
    result = job.get("result") if isinstance(job.get("result"), Mapping) else {}
    partial = job.get("partial_result") if isinstance(job.get("partial_result"), Mapping) else {}
    progress = job.get("progress") if isinstance(job.get("progress"), Mapping) else {}

    target_type = result.get("type") or partial.get("type")
    details: dict[str, Any] = {
        "Target": target,
        "Type": target_type,
        "Job ID": job.get("id"),
    }

    total_phases = progress.get("total")
    completed_phases = progress.get("completed_count")
    if total_phases and completed_phases is not None:
        details["Phases"] = f"{completed_phases}/{total_phases}"

    if status == "failed":
        details["Error"] = job.get("error")
        summary = f"Analysis failed for `{target}`."
    else:
        summary = f"Analysis completed for `{target}`."

    return send_process_alert(
        title="IP Intel analysis",
        status=status,
        summary=summary,
        details=details,
        started_at=job.get("created_at"),
        finished_at=job.get("updated_at"),
    )


def send_opencti_notification(status: str, details: Mapping[str, Any] | None = None) -> bool:
    values = dict(details or {})
    total = values.get("total")
    done = values.get("done")

    formatted_details: dict[str, Any] = {
        "Mode": values.get("mode"),
        "Processed": f"{done}/{total}" if total is not None and done is not None else None,
        "Skipped": values.get("skipped"),
        "Last error": values.get("last_error"),
        "Note": values.get("note"),
    }

    if status == "failed":
        summary = "OpenCTI ingestion failed."
    elif status == "completed_with_errors":
        summary = "OpenCTI ingestion completed with errors."
    else:
        summary = "OpenCTI ingestion completed."

    return send_process_alert(
        title="OpenCTI ingestion",
        status=status,
        summary=summary,
        details=formatted_details,
        started_at=values.get("started_at"),
        finished_at=values.get("completed_at") or values.get("finished_at"),
    )


def send_retry_notification(status: str, details: Mapping[str, Any] | None = None) -> bool:
    values = dict(details or {})
    summary = "Source-error retry completed." if status != "failed" else "Source-error retry failed."

    return send_process_alert(
        title="OpenCTI retry",
        status=status,
        summary=summary,
        details={
            "Source": values.get("source") or "any",
            "Retried": values.get("retried"),
            "Last error": values.get("last_error"),
        },
        started_at=values.get("started_at"),
        finished_at=values.get("completed_at") or values.get("finished_at"),
    )
