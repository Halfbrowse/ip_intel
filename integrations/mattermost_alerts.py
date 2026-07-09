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
_RESPONSE_BODY_LIMIT = 300
_INTERESTING_FINDINGS_LIMIT = 6
_LOW_SIGNAL_SERVER_TYPES = {"shared_hosting", "cdn_proxy", "mail"}
_LOW_SIGNAL_HOSTING_PATTERNS = (
    "amazonaws.com",
    "automattic.com",
    "azurefd.net",
    "azurewebsites.net",
    "bluehost.com",
    "cloudflare.com",
    "cloudflare.net",
    "cloudfront.net",
    "cloudways",
    "digitaloceanspaces.com",
    "dreamhost.com",
    "fastly.net",
    "github.io",
    "gitlab.io",
    "godaddy.com",
    "googleapis.com",
    "googlehosted.com",
    "googleusercontent.com",
    "hostgator.com",
    "hostinger.com",
    "kinsta",
    "namecheap.com",
    "o2switch.net",
    "ovh.net",
    "pantheonsite.io",
    "pressable.com",
    "shopify.com",
    "siteground",
    "squarespace.com",
    "webflow.io",
    "weebly.com",
    "wix.com",
    "wixsite.com",
    "wordpress.com",
    "wpengine.com",
    "wpenginepowered.com",
)


def _webhook_url() -> str:
    return os.getenv("MATTERMOST_WEBHOOK_URL", "").strip()


def mattermost_enabled() -> bool:
    return bool(_webhook_url())


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


def _safe_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def _safe_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _collect_unique_texts(values: list[Any], *, limit: int = 3) -> list[str]:
    seen: set[str] = set()
    collected: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        collected.append(text)
        if len(collected) >= limit:
            break
    return collected


def _text_contains_any(value: Any, patterns: tuple[str, ...]) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    return any(pattern in text for pattern in patterns)


def _count_origin_hits(origin_candidates: Mapping[str, Any]) -> int:
    total = 0
    for key in ("scan", "provider_scan", "country_scan", "censys", "shodan", "netlas"):
        total += len(_safe_list(_safe_dict(origin_candidates.get(key)).get("hits")))
    for key in ("subdomain_leaks", "mx_leaks", "wordlist_leaks", "hackertarget", "urlscan"):
        total += len(_safe_list(origin_candidates.get(key)))
    return total


def _meaningful_non_cf_ips(result: Mapping[str, Any], ip_details: Mapping[str, Any]) -> list[str]:
    meaningful: list[str] = []
    for ip in _safe_list(result.get("non_cf_ips")):
        ip_text = str(ip or "").strip()
        if not ip_text:
            continue
        details = _safe_dict(ip_details.get(ip_text))
        server_type = str(details.get("server_type") or "")
        if server_type == "direct":
            meaningful.append(ip_text)
            continue
        if server_type in _LOW_SIGNAL_SERVER_TYPES:
            continue
        if any(
            _text_contains_any(value, _LOW_SIGNAL_HOSTING_PATTERNS)
            for value in (
                details.get("ptr"),
                details.get("network_name"),
                _safe_dict(details.get("asn_info")).get("asn_description"),
            )
        ):
            continue
        meaningful.append(ip_text)
    return _collect_unique_texts(meaningful, limit=20)


def _is_low_signal_cert(cert: Mapping[str, Any], ip_details: Mapping[str, Any]) -> bool:
    cert_ip = str(cert.get("ip") or "").strip()
    details = _safe_dict(ip_details.get(cert_ip)) if cert_ip else {}
    server_type = str(details.get("server_type") or "")
    if server_type in _LOW_SIGNAL_SERVER_TYPES:
        return True

    cert_texts = [
        cert.get("cn"),
        cert.get("issuer"),
        cert.get("issuer_cn"),
        cert.get("issuer_org"),
        details.get("ptr"),
        details.get("network_name"),
        _safe_dict(details.get("asn_info")).get("asn_description"),
    ]
    cert_texts.extend(_safe_list(cert.get("sans")))
    return any(_text_contains_any(value, _LOW_SIGNAL_HOSTING_PATTERNS) for value in cert_texts)


def _interesting_findings(result: Mapping[str, Any]) -> list[str]:
    findings: list[str] = []
    result_type = str(result.get("type") or "")
    page_metadata = _safe_dict(result.get("page_metadata"))
    cert_transparency = _safe_dict(result.get("cert_transparency"))
    origin_candidates = _safe_dict(result.get("origin_candidates"))
    ip_details = _safe_dict(result.get("ip_details"))
    meaningful_non_cf_ips = _meaningful_non_cf_ips(result, ip_details)

    if result_type == "domain" and result.get("cloudflare_fronted") and meaningful_non_cf_ips:
        findings.append(
            f"Cloudflare is in front, but {len(meaningful_non_cf_ips)} likely direct origin IP(s) were discovered."
        )

    non_cf_tls_certs = _safe_list(result.get("non_cf_tls_certs"))
    meaningful_tls_certs = [
        cert
        for cert in non_cf_tls_certs
        if isinstance(cert, Mapping) and not _is_low_signal_cert(cert, ip_details)
    ]
    if meaningful_tls_certs:
        cert_names = _collect_unique_texts(
            [cert.get("cn") for cert in meaningful_tls_certs],
            limit=2,
        )
        findings.append(
            "Live TLS certs recovered from non-Cloudflare infrastructure"
            + (f": {', '.join(cert_names)}." if cert_names else ".")
        )

    cross_domain_sans = _safe_list(cert_transparency.get("cross_domain_sans"))
    if cross_domain_sans:
        examples = _collect_unique_texts(cross_domain_sans, limit=3)
        findings.append(
            f"Cross-domain SAN overlap found ({len(cross_domain_sans)} names)"
            + (f": {', '.join(examples)}." if examples else ".")
        )

    ct_subdomains = _safe_list(result.get("subdomains")) + _safe_list(result.get("zone_transfer"))
    if ct_subdomains:
        findings.append(f"Subdomain discovery surfaced {len(ct_subdomains)} candidate hosts.")

    source_errors = _collect_unique_texts(_safe_list(result.get("source_errors")), limit=4)
    if source_errors:
        findings.append(f"Some sources degraded or failed: {', '.join(source_errors)}.")

    origin_hits = _count_origin_hits(origin_candidates)
    if origin_hits:
        findings.append(f"Origin discovery produced {origin_hits} lead(s) across passive, provider, and scan sources.")

    tracking_count = sum(
        len(_safe_list(page_metadata.get(key)))
        for key in ("google_analytics", "gtm_ids", "facebook_pixel", "tiktok_pixel", "yandex_metrika")
    )
    if tracking_count:
        findings.append(f"Tracking or analytics identifiers found: {tracking_count}.")

    social_handle_count = sum(len(_safe_list(handles)) for handles in _safe_dict(page_metadata.get("social_handles")).values())
    if social_handle_count:
        findings.append(f"Social account handles extracted: {social_handle_count}.")

    ip_count = len(ip_details)
    if ip_count:
        direct_like = sum(
            1
            for details in ip_details.values()
            if isinstance(details, Mapping) and str(details.get("server_type") or "") == "direct"
        )
        findings.append(
            f"IP enrichment covered {ip_count} IP(s)"
            + (f", including {direct_like} likely direct-server lead(s)." if direct_like else ".")
        )

    reverse_ip_domains = _collect_unique_texts(
        [
            domain
            for details in ip_details.values()
            if isinstance(details, Mapping)
            for domain in _safe_list(details.get("other_domains_on_ip"))
        ],
        limit=3,
    )
    if reverse_ip_domains:
        findings.append(f"Reverse-IP overlap surfaced related domains such as {', '.join(reverse_ip_domains)}.")

    related_summary = _safe_dict(result.get("related_targets_summary"))
    if related_summary.get("total"):
        findings.append(
            f"Related-target extraction found {int(related_summary.get('total') or 0)} pivots"
            f" ({int(related_summary.get('domains') or 0)} domains, {int(related_summary.get('ips') or 0)} IPs)."
        )

    recursive = _safe_dict(result.get("recursive_expansion"))
    if recursive.get("analysed_count"):
        findings.append(
            f"Recursive expansion auto-analysed {int(recursive.get('analysed_count') or 0)} child target(s)."
        )

    if result_type == "ip":
        other_domains = _safe_list(result.get("other_domains_on_ip"))
        if other_domains:
            examples = _collect_unique_texts(other_domains, limit=3)
            findings.append(
                f"Reverse-IP search found {len(other_domains)} other domain(s)"
                + (f": {', '.join(examples)}." if examples else ".")
            )
        tls_cert = _safe_dict(result.get("tls_cert"))
        server_type = str(result.get("server_type") or "")
        if tls_cert.get("cn") and server_type not in _LOW_SIGNAL_SERVER_TYPES and not _is_low_signal_cert(tls_cert, ip_details):
            findings.append(f"TLS certificate CN observed on the IP: {tls_cert.get('cn')}.")

    deduped = _collect_unique_texts(findings, limit=_INTERESTING_FINDINGS_LIMIT)
    return deduped


def _deliver_message(webhook_url: str, payload: dict[str, Any]) -> None:
    try:
        # MATTERMOST_WEBHOOK_URL points at an internal-only host whose cert
        # chain isn't in the container's trust store — verification is
        # disabled for this internal call only (see core/basic.py's
        # page_metadata fetch for the same pattern).
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.post(webhook_url, json=payload, timeout=_WEBHOOK_TIMEOUT_SECONDS, verify=False)
        response.raise_for_status()
        LOGGER.info("Mattermost alert delivered successfully")
    except requests.HTTPError as exc:
        response = exc.response
        response_body = ""
        if response is not None:
            response_body = (response.text or "").strip()
            if len(response_body) > _RESPONSE_BODY_LIMIT:
                response_body = f"{response_body[:_RESPONSE_BODY_LIMIT - 3]}..."
        LOGGER.exception(
            "Mattermost alert delivery failed with HTTP %s%s",
            response.status_code if response is not None else "unknown",
            f": {response_body}" if response_body else "",
        )
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
        LOGGER.warning("Mattermost alert skipped because MATTERMOST_WEBHOOK_URL is not set")
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
    LOGGER.info("Queueing Mattermost alert for title=%r status=%r", title, status)
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

    findings = _interesting_findings(result if result else partial)
    if findings:
        details["Interesting findings"] = findings

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


def send_case_notification(case: Mapping[str, Any], job: Mapping[str, Any]) -> bool:
    """
    Alert for a completed ingest. The submission joins the one global pool
    (no per-ingest scope), so "what did this connect to" is read from the
    same cross-corpus pool linkage the /api/graph/* endpoints expose
    (case_runtime._build_pool_summary -> utils.check.links_for), not a
    per-ingest pairwise comparison.
    """
    webhook_url = _webhook_url()
    if not webhook_url:
        LOGGER.warning("Mattermost alert skipped because MATTERMOST_WEBHOOK_URL is not set")
        return False

    case_id = str(case.get("id") or "")
    status = str(case.get("status") or job.get("status") or "unknown")
    summary = _safe_dict(case.get("summary"))
    top_findings = _safe_list(summary.get("top_findings"))[:5]
    targets = _safe_list(case.get("targets"))
    target_count = case.get("total_targets") or summary.get("target_count") or len(targets)
    successful = case.get("successful_targets")
    failed = case.get("failed_targets")
    duration = _duration_label(case.get("started_at") or job.get("started_at"), case.get("finished_at") or job.get("finished_at"))

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

    text_lines = [
        f"**IP Intel ingest {case_id or 'unknown'}**",
        f"Status: `{status}`",
    ]
    if duration:
        text_lines.append(f"Duration: `{duration}`")
    text_lines.append(f"Submitted: `{target_count or 0}`")
    text_lines.append(f"Succeeded: `{successful or 0}`")
    text_lines.append(f"Failed: `{failed or 0}`")
    text_lines.append(f"Pool connections found: `{len(top_findings)}`")
    if highlights:
        text_lines.append("Strongest pool connections:")
        text_lines.extend(f"- {item}" for item in highlights)
    if summary_url:
        text_lines.append(f"[Open in pool]({summary_url})")

    card_lines = [
        "<h2>IP Intel Ingest Complete</h2>",
        f"<p><strong>Ingest:</strong> {case_id or 'unknown'}</p>",
        f"<p><strong>Status:</strong> {status}</p>",
        f"<p><strong>Duration:</strong> {duration or 'n/a'}</p>",
        f"<p><strong>Targets:</strong> submitted {target_count or 0}, succeeded {successful or 0}, failed {failed or 0}</p>",
        f"<p><strong>Pool connections found:</strong> {len(top_findings)}</p>",
    ]
    if highlights:
        card_lines.append("<ul>")
        card_lines.extend(f"<li>{item}</li>" for item in highlights)
        card_lines.append("</ul>")
    if summary_url:
        card_lines.append(f'<p><a href="{summary_url}">Open in pool</a></p>')

    payload = {
        "text": "\n".join(text_lines),
        "props": {"card": "".join(card_lines)},
        "attachments": [
            {
                "color": "#1c8a5d" if status == "completed" else "#ba4a3d",
                "title": f"Ingest {case_id or 'unknown'}",
                "title_link": summary_url,
                "fields": [
                    {"short": True, "title": "Submitted", "value": str(target_count or 0)},
                    {"short": True, "title": "Duration", "value": duration or "n/a"},
                    {"short": True, "title": "Succeeded", "value": str(successful or 0)},
                    {"short": True, "title": "Failed", "value": str(failed or 0)},
                    {"short": True, "title": "Pool connections", "value": str(len(top_findings))},
                    {"short": True, "title": "Status", "value": status},
                ],
            }
        ],
    }
    LOGGER.info("Queueing Mattermost case alert for case=%r status=%r", case_id, status)
    thread = threading.Thread(
        target=_deliver_message,
        args=(webhook_url, payload),
        name="mattermost-case-alert",
        daemon=True,
    )
    thread.start()
    return True


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
