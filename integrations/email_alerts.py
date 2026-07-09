"""
Optional SMTP email completion alerts.

Set SMTP_HOST and ALERT_EMAIL_TO in the environment or .env file to enable alerts.
Calls are non-blocking: the SMTP delivery runs in a short-lived daemon thread.

Environment variables:
  SMTP_HOST        - SMTP server hostname (required to enable alerts)
  SMTP_PORT        - SMTP server port (default 587)
  SMTP_USERNAME    - optional SMTP auth username
  SMTP_PASSWORD    - optional SMTP auth password
  SMTP_STARTTLS    - upgrade the connection with STARTTLS (default true)
  ALERT_EMAIL_FROM - sender address
  ALERT_EMAIL_TO   - comma-separated recipient addresses (required to enable alerts)
"""

from __future__ import annotations

import logging
import os
import smtplib
import threading
from email.message import EmailMessage
from typing import Any, Mapping

from dotenv import load_dotenv

from integrations.mattermost_alerts import (
    _duration_label,
    _interesting_findings,
    _safe_dict,
    _safe_list,
)

load_dotenv()

LOGGER = logging.getLogger("ip_intel.email")
_SMTP_TIMEOUT_SECONDS = 10
_DEFAULT_SMTP_PORT = 587
_DETAIL_VALUE_LIMIT = 500
_SUBJECT_PREFIX = "[IP Intel]"


def _smtp_host() -> str:
    return os.getenv("SMTP_HOST", "").strip()


def _smtp_port() -> int:
    raw = os.getenv("SMTP_PORT", "").strip()
    if not raw:
        return _DEFAULT_SMTP_PORT
    try:
        return int(raw)
    except ValueError:
        LOGGER.warning("Invalid SMTP_PORT %r - falling back to %d", raw, _DEFAULT_SMTP_PORT)
        return _DEFAULT_SMTP_PORT


def _smtp_starttls() -> bool:
    raw = os.getenv("SMTP_STARTTLS", "true").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _sender() -> str:
    sender = os.getenv("ALERT_EMAIL_FROM", "").strip()
    if sender:
        return sender
    return os.getenv("SMTP_USERNAME", "").strip() or "ip-intel@localhost"


def _recipients() -> list[str]:
    raw = os.getenv("ALERT_EMAIL_TO", "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def email_enabled() -> bool:
    return bool(_smtp_host()) and bool(_recipients())


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
    return text


def _deliver_email(message: EmailMessage, recipients: list[str]) -> None:
    try:
        with smtplib.SMTP(_smtp_host(), _smtp_port(), timeout=_SMTP_TIMEOUT_SECONDS) as client:
            if _smtp_starttls():
                client.starttls()
            username = os.getenv("SMTP_USERNAME", "").strip()
            password = os.getenv("SMTP_PASSWORD", "")
            if username and password:
                client.login(username, password)
            client.send_message(message, to_addrs=recipients)
        LOGGER.info("Email alert delivered successfully to %d recipient(s)", len(recipients))
    except Exception:  # noqa: BLE001
        LOGGER.exception("Email alert delivery failed")


def send_process_email(
    *,
    title: str,
    status: str,
    summary: str | None = None,
    details: Mapping[str, Any] | None = None,
    started_at: Any = None,
    finished_at: Any = None,
) -> bool:
    if not email_enabled():
        LOGGER.debug("Email alert skipped because SMTP_HOST or ALERT_EMAIL_TO is not set")
        return False

    lines = [title, f"Status: {status}"]
    if summary:
        lines.append(summary)

    if started_at:
        lines.append(f"Started: {started_at}")
    if finished_at:
        lines.append(f"Finished: {finished_at}")

    duration = _duration_label(started_at, finished_at)
    if duration:
        lines.append(f"Duration: {duration}")

    for label, value in (details or {}).items():
        formatted = _format_detail_value(value)
        if formatted is None:
            continue
        lines.append(f"{label}: {formatted}")

    recipients = _recipients()
    message = EmailMessage()
    message["Subject"] = f"{_SUBJECT_PREFIX} {title}: {status}"
    message["From"] = _sender()
    message["To"] = ", ".join(recipients)
    message.set_content("\n".join(lines))

    LOGGER.info("Queueing email alert for title=%r status=%r", title, status)
    thread = threading.Thread(
        target=_deliver_email,
        args=(message, recipients),
        name="email-alert",
        daemon=True,
    )
    thread.start()
    return True


def send_analysis_email(job: Mapping[str, Any]) -> bool:
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

    findings = _interesting_findings(result if result else partial)
    if findings:
        details["Interesting findings"] = findings

    if status == "failed":
        details["Error"] = job.get("error")
        summary = f"Analysis failed for {target}."
    else:
        summary = f"Analysis completed for {target}."

    return send_process_email(
        title="IP Intel analysis",
        status=status,
        summary=summary,
        details=details,
        started_at=job.get("created_at"),
        finished_at=job.get("updated_at"),
    )


def send_case_email(case: Mapping[str, Any], job: Mapping[str, Any]) -> bool:
    """
    Alert for a completed ingest. See send_case_notification's docstring in
    mattermost_alerts.py -- connections are read from the shared pool summary
    (case_runtime._build_pool_summary), not a per-ingest comparison.
    """
    case_id = str(case.get("id") or "")
    status = str(case.get("status") or job.get("status") or "unknown")
    summary = _safe_dict(case.get("summary"))
    top_findings = _safe_list(summary.get("top_findings"))[:5]
    targets = _safe_list(case.get("targets"))
    target_count = case.get("total_targets") or summary.get("target_count") or len(targets)
    successful = case.get("successful_targets")
    failed = case.get("failed_targets")

    base_url = os.getenv("APP_BASE_URL", "").rstrip("/")
    first_target = str(targets[0]) if targets else None
    summary_url = f"{base_url}/domain/{first_target}" if base_url and first_target else None

    highlights = []
    for item in top_findings:
        target = str(item.get("target") or "").strip()
        linked_target = str(item.get("linked_target") or "").strip()
        score = item.get("score")
        line = f"{target} ↔ {linked_target}".strip()
        if score is not None:
            line = f"{line} ({score})"
        if line:
            highlights.append(line)

    details: dict[str, Any] = {
        "Submitted": target_count or 0,
        "Succeeded": successful or 0,
        "Failed": failed or 0,
        "Pool connections found": len(top_findings),
        "Top findings": highlights,
        "Summary": summary_url,
    }

    if status == "failed":
        text = f"Case {case_id or 'unknown'} failed."
    else:
        text = f"Case {case_id or 'unknown'} completed."

    return send_process_email(
        title=f"IP Intel case {case_id or 'unknown'}",
        status=status,
        summary=text,
        details=details,
        started_at=case.get("started_at") or job.get("started_at"),
        finished_at=case.get("finished_at") or job.get("finished_at"),
    )


def send_network_graph_email(
    png_bytes: bytes, *, domains: list[str] | None = None, html_bytes: bytes | None = None
) -> bool:
    """Email an exported network-graph PNG (from the domain comparison page) to
    the configured alert recipients. User-triggered (someone clicked "Email
    graph"), not an automatic job-completion alert like the senders above --
    but it reuses the same SMTP plumbing and the same ALERT_EMAIL_TO recipient
    list, so no separate configuration is needed.

    A PNG is a flat picture -- nothing in it can be clicked once it lands in
    an inbox. When the caller also has the self-contained interactive HTML
    report (inline SVG + vanilla JS, no server needed), attach that too: the
    PNG guarantees a preview renders even in clients that block HTML
    attachments, and the HTML file is what the recipient actually opens to
    click a line and see the evidence behind it.
    """
    if not email_enabled():
        LOGGER.debug("Network graph email skipped because SMTP_HOST or ALERT_EMAIL_TO is not set")
        return False

    names = [str(d).strip() for d in (domains or []) if str(d).strip()]
    preview = ", ".join(names[:5]) + (f" +{len(names) - 5} more" if len(names) > 5 else "")
    subject_target = preview or "selected domains"

    recipients = _recipients()
    message = EmailMessage()
    message["Subject"] = f"{_SUBJECT_PREFIX} Network graph: {subject_target}"
    message["From"] = _sender()
    message["To"] = ", ".join(recipients)
    body_lines = [f"Network graph for: {subject_target}", "See the attached image for a quick preview."]
    if html_bytes:
        body_lines.append(
            "Open the attached network-graph-interactive.html file in a browser for a clickable "
            "version -- click a line or a domain to see the evidence behind it."
        )
    message.set_content("\n".join(body_lines))
    message.add_attachment(png_bytes, maintype="image", subtype="png", filename="network-graph.png")
    if html_bytes:
        message.add_attachment(
            html_bytes, maintype="text", subtype="html", filename="network-graph-interactive.html"
        )

    LOGGER.info("Queueing network graph email for %d recipient(s)", len(recipients))
    thread = threading.Thread(
        target=_deliver_email,
        args=(message, recipients),
        name="email-network-graph",
        daemon=True,
    )
    thread.start()
    return True


def send_opencti_email(status: str, details: Mapping[str, Any] | None = None) -> bool:
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

    return send_process_email(
        title="OpenCTI ingestion",
        status=status,
        summary=summary,
        details=formatted_details,
        started_at=values.get("started_at"),
        finished_at=values.get("completed_at") or values.get("finished_at"),
    )


def send_retry_email(status: str, details: Mapping[str, Any] | None = None) -> bool:
    values = dict(details or {})
    summary = "Source-error retry completed." if status != "failed" else "Source-error retry failed."

    return send_process_email(
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
