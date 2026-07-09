from __future__ import annotations

import threading

import pytest

from integrations import email_alerts

_ENV_VARS = (
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USERNAME",
    "SMTP_PASSWORD",
    "SMTP_STARTTLS",
    "ALERT_EMAIL_FROM",
    "ALERT_EMAIL_TO",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch) -> None:
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def _install_fake_smtp(monkeypatch, *, fail_send: bool = False) -> tuple[dict, threading.Event]:
    delivered = threading.Event()
    calls: dict = {}

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
            calls["host"] = host
            calls["port"] = port
            calls["timeout"] = timeout
            calls["starttls"] = False
            calls["login"] = None

        def __enter__(self) -> "FakeSMTP":
            return self

        def __exit__(self, *_args) -> bool:
            return False

        def starttls(self) -> None:
            calls["starttls"] = True

        def login(self, username: str, password: str) -> None:
            calls["login"] = (username, password)

        def send_message(self, message, to_addrs=None) -> None:
            calls["message"] = message
            calls["to_addrs"] = to_addrs
            delivered.set()
            if fail_send:
                raise RuntimeError("boom")

    monkeypatch.setattr(email_alerts.smtplib, "SMTP", FakeSMTP)
    return calls, delivered


def test_email_disabled_without_smtp_host(monkeypatch) -> None:
    monkeypatch.setenv("ALERT_EMAIL_TO", "analyst@example.com")
    assert email_alerts.email_enabled() is False


def test_email_disabled_without_recipients(monkeypatch) -> None:
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    assert email_alerts.email_enabled() is False


def test_send_functions_are_noops_when_disabled(monkeypatch) -> None:
    calls, _delivered = _install_fake_smtp(monkeypatch)

    assert email_alerts.send_process_email(title="IP Intel analysis", status="completed") is False
    assert email_alerts.send_analysis_email({"status": "completed", "target": "example.com"}) is False
    assert email_alerts.send_case_email({"id": "case-1"}, {"status": "completed"}) is False
    assert email_alerts.send_opencti_email("completed", {"done": 1, "total": 1}) is False
    assert email_alerts.send_retry_email("completed", {"retried": 0}) is False
    assert calls == {}


def test_recipient_parsing_strips_and_skips_blanks(monkeypatch) -> None:
    monkeypatch.setenv("ALERT_EMAIL_TO", " soc@example.com , lead@example.com ,, ")
    assert email_alerts._recipients() == ["soc@example.com", "lead@example.com"]


def test_send_process_email_delivers_with_auth_and_starttls(monkeypatch) -> None:
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_USERNAME", "alerts")
    monkeypatch.setenv("SMTP_PASSWORD", "secret")
    monkeypatch.setenv("ALERT_EMAIL_FROM", "ip-intel@example.com")
    monkeypatch.setenv("ALERT_EMAIL_TO", "soc@example.com, lead@example.com")
    calls, delivered = _install_fake_smtp(monkeypatch)

    assert (
        email_alerts.send_process_email(
            title="IP Intel analysis",
            status="completed",
            summary="Analysis completed for example.com.",
            details={"Target": "example.com", "Empty": None},
            started_at="2026-06-10 10:00:00",
            finished_at="2026-06-10 10:01:30",
        )
        is True
    )
    assert delivered.wait(timeout=5)

    assert calls["host"] == "smtp.example.com"
    assert calls["port"] == 587
    assert calls["starttls"] is True
    assert calls["login"] == ("alerts", "secret")
    assert calls["to_addrs"] == ["soc@example.com", "lead@example.com"]

    message = calls["message"]
    assert message["Subject"] == "[IP Intel] IP Intel analysis: completed"
    assert message["From"] == "ip-intel@example.com"
    assert message["To"] == "soc@example.com, lead@example.com"
    body = message.get_content()
    assert "Analysis completed for example.com." in body
    assert "Target: example.com" in body
    assert "Duration: 1m 30s" in body
    assert "Empty" not in body


def test_send_process_email_honours_port_and_starttls_off(monkeypatch) -> None:
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_PORT", "2525")
    monkeypatch.setenv("SMTP_STARTTLS", "false")
    monkeypatch.setenv("ALERT_EMAIL_TO", "soc@example.com")
    calls, delivered = _install_fake_smtp(monkeypatch)

    assert email_alerts.send_process_email(title="IP Intel analysis", status="failed") is True
    assert delivered.wait(timeout=5)
    assert calls["port"] == 2525
    assert calls["starttls"] is False
    assert calls["login"] is None
    assert calls["message"]["From"] == "ip-intel@localhost"


def test_delivery_failure_does_not_raise(monkeypatch) -> None:
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("ALERT_EMAIL_TO", "soc@example.com")
    _calls, delivered = _install_fake_smtp(monkeypatch, fail_send=True)

    assert email_alerts.send_process_email(title="IP Intel analysis", status="completed") is True
    assert delivered.wait(timeout=5)


def test_send_case_email_includes_counts_and_findings(monkeypatch) -> None:
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("ALERT_EMAIL_TO", "soc@example.com")
    monkeypatch.setenv("APP_BASE_URL", "https://intel.example.com/")
    calls, delivered = _install_fake_smtp(monkeypatch)

    case = {
        "id": "case-1",
        "status": "completed",
        "total_targets": 3,
        "successful_targets": 2,
        "failed_targets": 1,
        "started_at": "2026-06-10 10:00:00",
        "finished_at": "2026-06-10 10:05:00",
        "targets": ["alpha.example"],
        "summary": {
            "target_count": 1,
            "top_findings": [
                {"target": "alpha.example", "linked_target": "beta.example", "score": 72},
            ],
        },
    }

    assert email_alerts.send_case_email(case, {"status": "completed"}) is True
    assert delivered.wait(timeout=5)

    message = calls["message"]
    assert message["Subject"] == "[IP Intel] IP Intel case case-1: completed"
    body = message.get_content()
    assert "Submitted: 3" in body
    assert "Succeeded: 2" in body
    assert "Failed: 1" in body
    assert "Pool connections found: 1" in body
    assert "alpha.example ↔ beta.example (72)" in body
    assert "https://intel.example.com/domain/alpha.example" in body


def test_send_opencti_email_formats_progress(monkeypatch) -> None:
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("ALERT_EMAIL_TO", "soc@example.com")
    calls, delivered = _install_fake_smtp(monkeypatch)

    assert (
        email_alerts.send_opencti_email(
            "completed_with_errors",
            {"mode": "full_queue", "done": 4, "total": 5, "last_error": "x.example: timeout"},
        )
        is True
    )
    assert delivered.wait(timeout=5)

    message = calls["message"]
    assert message["Subject"] == "[IP Intel] OpenCTI ingestion: completed_with_errors"
    body = message.get_content()
    assert "OpenCTI ingestion completed with errors." in body
    assert "Processed: 4/5" in body
    assert "Last error: x.example: timeout" in body


def test_send_retry_email_reports_source(monkeypatch) -> None:
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("ALERT_EMAIL_TO", "soc@example.com")
    calls, delivered = _install_fake_smtp(monkeypatch)

    assert email_alerts.send_retry_email("completed", {"source": "urlscan", "retried": 7}) is True
    assert delivered.wait(timeout=5)

    body = calls["message"].get_content()
    assert "Source-error retry completed." in body
    assert "Source: urlscan" in body
    assert "Retried: 7" in body
