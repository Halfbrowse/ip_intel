"""
Tests for the certificate-transparency fallback (crt.sh → Cert Spotter).

Covers, for both core.basic (get_crt_sh/get_certspotter) and core.ip_intel
(crt_sh_data/certspotter_data + the async _acrt_sh_data/_acertspotter_data):

  - crt.sh success           → no fallback call is made
  - crt.sh zero rows (200)   → no fallback call is made (legit empty result)
  - crt.sh 429 / exception   → Cert Spotter used, normalized to crt.sh shape
  - both sources fail        → graceful empty result
  - Cert Spotter pagination  → follows the `after` parameter until empty page

All HTTP is mocked — no network access.
"""

from __future__ import annotations

import asyncio
import os
import unittest
from unittest.mock import patch

import requests

import core.basic as basic
import core.ip_intel as ip_intel


DOMAIN = "example.com"

CRT_SH_ENTRIES = [
    {
        "id": 111,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "name_value": "example.com\n*.example.com\napi.example.com\nshared.other-org.net",
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2026-04-01T00:00:00",
        "entry_timestamp": "2026-01-01T01:00:00",
    },
]

CERTSPOTTER_PAGE = [
    {
        "id": "648494876",
        "tbs_sha256": "abc123",
        "dns_names": ["example.com", "www.example.com", "api.example.com", "shared.other-org.net"],
        "issuer": {
            "friendly_name": "Let's Encrypt",
            "name": "C=US, O=Let's Encrypt, CN=R3",
        },
        "not_before": "2026-01-01T00:00:00-00:00",
        "not_after": "2026-04-01T00:00:00-00:00",
    },
]


class FakeResponse:
    def __init__(self, status_code: int = 200, json_data=None):
        self.status_code = status_code
        self._json_data = json_data

    def json(self):
        return self._json_data


def make_fake_get(crt_sh_response, certspotter_pages, calls):
    """
    Build a requests.get replacement.

    crt_sh_response:   FakeResponse or Exception for any crt.sh URL.
    certspotter_pages: list of FakeResponse / list (a 200 JSON page) /
                       Exception, consumed one per Cert Spotter call; once
                       exhausted an empty 200 page is returned.
    calls:             list collecting {"url", "params", "headers"} per call.
    """
    pages = list(certspotter_pages)

    def fake_get(url, params=None, headers=None, timeout=None, **kwargs):
        calls.append({
            "url": url,
            "params": dict(params or {}),
            "headers": dict(headers or {}),
        })
        if "crt.sh" in url:
            if isinstance(crt_sh_response, Exception):
                raise crt_sh_response
            return crt_sh_response
        if "certspotter" in url:
            if not pages:
                return FakeResponse(200, [])
            page = pages.pop(0)
            if isinstance(page, Exception):
                raise page
            if isinstance(page, FakeResponse):
                return page
            return FakeResponse(200, page)
        raise AssertionError(f"unexpected URL in test: {url}")

    return fake_get


def certspotter_calls(calls):
    return [c for c in calls if "certspotter" in c["url"]]


class FakeAsyncClient:
    """Minimal httpx.AsyncClient stand-in driven by a fake_get dispatcher."""

    def __init__(self, fake_get):
        self._fake_get = fake_get

    async def get(self, url, params=None, headers=None, timeout=None, **kwargs):
        return self._fake_get(url, params=params, headers=headers, timeout=timeout, **kwargs)


# ── core.basic ────────────────────────────────────────────────────────────────

class BasicCtFallbackTests(unittest.TestCase):
    def test_crt_sh_success_does_not_call_fallback(self) -> None:
        calls: list[dict] = []
        fake = make_fake_get(FakeResponse(200, CRT_SH_ENTRIES), [], calls)
        with patch("core.basic.requests.get", side_effect=fake):
            result = basic.get_crt_sh(DOMAIN)

        self.assertEqual(len(calls), 1)
        self.assertIn("crt.sh", calls[0]["url"])
        self.assertEqual(certspotter_calls(calls), [])
        self.assertEqual(result["source"], "crt.sh")
        self.assertEqual(result["total_certs"], 1)
        self.assertEqual(result["subdomains"], ["api.example.com"])
        self.assertEqual(result["issuers"], ["R3"])
        self.assertEqual(result["certs"][0]["id"], 111)

    def test_crt_sh_zero_rows_is_not_a_failure(self) -> None:
        calls: list[dict] = []
        fake = make_fake_get(FakeResponse(200, []), [], calls)
        with patch("core.basic.requests.get", side_effect=fake):
            result = basic.get_crt_sh(DOMAIN)

        self.assertEqual(len(calls), 1)
        self.assertEqual(certspotter_calls(calls), [])
        self.assertNotIn("error", result)
        self.assertEqual(result["source"], "crt.sh")
        self.assertEqual(result["total_certs"], 0)
        self.assertEqual(result["subdomains"], [])
        self.assertEqual(result["certs"], [])

    def test_crt_sh_429_falls_back_and_normalizes(self) -> None:
        calls: list[dict] = []
        fake = make_fake_get(FakeResponse(429, None), [CERTSPOTTER_PAGE], calls)
        with patch("core.basic.requests.get", side_effect=fake):
            result = basic.get_crt_sh(DOMAIN)

        self.assertGreaterEqual(len(certspotter_calls(calls)), 1)
        self.assertEqual(result["source"], "certspotter")
        # Exact crt.sh result shape.
        self.assertEqual(
            set(result),
            {"total_certs", "subdomains", "issuers", "certs", "source"},
        )
        self.assertEqual(result["total_certs"], 1)
        self.assertEqual(result["subdomains"], ["api.example.com", "www.example.com"])
        self.assertEqual(result["issuers"], ["R3"])
        cert = result["certs"][0]
        self.assertEqual(
            set(cert), {"id", "issuer", "not_before", "not_after", "sans"}
        )
        self.assertEqual(cert["id"], 648494876)  # string id coerced to int
        self.assertEqual(cert["issuer"], "R3")
        self.assertEqual(cert["not_before"], "2026-01-01T00:00:00-00:00")
        self.assertEqual(
            cert["sans"],
            ["api.example.com", "example.com", "shared.other-org.net", "www.example.com"],
        )

    def test_crt_sh_exception_falls_back(self) -> None:
        calls: list[dict] = []
        fake = make_fake_get(
            requests.exceptions.ConnectTimeout("crt.sh timed out"),
            [CERTSPOTTER_PAGE],
            calls,
        )
        with patch("core.basic.requests.get", side_effect=fake):
            result = basic.get_crt_sh(DOMAIN)

        self.assertEqual(result["source"], "certspotter")
        self.assertEqual(result["total_certs"], 1)

    def test_both_sources_fail_returns_graceful_error(self) -> None:
        calls: list[dict] = []
        fake = make_fake_get(FakeResponse(503, None), [FakeResponse(429, None)], calls)
        with patch("core.basic.requests.get", side_effect=fake):
            result = basic.get_crt_sh(DOMAIN)

        self.assertIn("error", result)
        self.assertEqual(result["source"], "certspotter")

    def test_certspotter_pagination_follows_after(self) -> None:
        page1 = [
            {"id": "100", "dns_names": ["a.example.com"],
             "issuer": {"name": "CN=R3"}, "not_before": "2026-01-01T00:00:00-00:00",
             "not_after": "2026-04-01T00:00:00-00:00"},
            {"id": "101", "dns_names": ["b.example.com"],
             "issuer": {"name": "CN=R3"}, "not_before": "2026-01-02T00:00:00-00:00",
             "not_after": "2026-04-02T00:00:00-00:00"},
        ]
        page2 = [
            {"id": "200", "dns_names": ["c.example.com"],
             "issuer": {"name": "CN=R3"}, "not_before": "2026-01-03T00:00:00-00:00",
             "not_after": "2026-04-03T00:00:00-00:00"},
        ]
        calls: list[dict] = []
        fake = make_fake_get(FakeResponse(503, None), [page1, page2, []], calls)
        with patch("core.basic.requests.get", side_effect=fake):
            result = basic.get_certspotter(DOMAIN)

        cs_calls = certspotter_calls(calls)
        self.assertEqual(len(cs_calls), 3)
        self.assertNotIn("after", cs_calls[0]["params"])
        self.assertEqual(cs_calls[1]["params"]["after"], "101")
        self.assertEqual(cs_calls[2]["params"]["after"], "200")
        for call in cs_calls:
            self.assertEqual(call["params"]["domain"], DOMAIN)
            self.assertEqual(call["params"]["include_subdomains"], "true")
            self.assertIn("dns_names", call["params"]["expand"])
        self.assertEqual(result["total_certs"], 3)
        self.assertEqual(
            result["subdomains"],
            ["a.example.com", "b.example.com", "c.example.com"],
        )

    def test_certspotter_api_key_sent_as_bearer(self) -> None:
        calls: list[dict] = []
        fake = make_fake_get(FakeResponse(503, None), [[]], calls)
        with (
            patch("core.basic.requests.get", side_effect=fake),
            patch.dict(os.environ, {"CERTSPOTTER_API_KEY": "sekrit"}),
        ):
            basic.get_certspotter(DOMAIN)
        self.assertEqual(
            certspotter_calls(calls)[0]["headers"].get("Authorization"),
            "Bearer sekrit",
        )

    def test_certspotter_no_key_no_auth_header(self) -> None:
        calls: list[dict] = []
        fake = make_fake_get(FakeResponse(503, None), [[]], calls)
        env = {k: v for k, v in os.environ.items() if k != "CERTSPOTTER_API_KEY"}
        with (
            patch("core.basic.requests.get", side_effect=fake),
            patch.dict(os.environ, env, clear=True),
        ):
            basic.get_certspotter(DOMAIN)
        self.assertNotIn("Authorization", certspotter_calls(calls)[0]["headers"])


# ── core.ip_intel (sync) ──────────────────────────────────────────────────────

class IpIntelCtFallbackTests(unittest.TestCase):
    def test_crt_sh_success_does_not_call_fallback(self) -> None:
        calls: list[dict] = []
        fake = make_fake_get(FakeResponse(200, CRT_SH_ENTRIES), [], calls)
        with patch("core.ip_intel.requests.get", side_effect=fake):
            result = ip_intel.crt_sh_data(DOMAIN)

        self.assertEqual(len(calls), 1)
        self.assertEqual(certspotter_calls(calls), [])
        self.assertEqual(result["ct_source"], "crt.sh")
        self.assertEqual(result["subdomains"], ["api.example.com"])
        self.assertEqual(result["cross_domain_sans"], ["shared.other-org.net"])

    def test_crt_sh_zero_rows_is_not_a_failure(self) -> None:
        calls: list[dict] = []
        fake = make_fake_get(FakeResponse(200, []), [], calls)
        with patch("core.ip_intel.requests.get", side_effect=fake):
            result = ip_intel.crt_sh_data(DOMAIN)

        self.assertEqual(certspotter_calls(calls), [])
        self.assertEqual(result["ct_source"], "crt.sh")
        self.assertEqual(result["total_certs"], 0)
        self.assertEqual(result["certs"], [])

    def test_crt_sh_429_falls_back_and_normalizes(self) -> None:
        calls: list[dict] = []
        fake = make_fake_get(FakeResponse(429, None), [CERTSPOTTER_PAGE], calls)
        with patch("core.ip_intel.requests.get", side_effect=fake):
            result = ip_intel.crt_sh_data(DOMAIN)

        self.assertGreaterEqual(len(certspotter_calls(calls)), 1)
        self.assertEqual(result["ct_source"], "certspotter")
        self.assertNotIn("_failed", result)
        # Exact crt_sh_data shape (what intel_db ct_certs + clustering consume).
        self.assertEqual(
            set(result),
            {"subdomains", "total_certs", "issuers", "cross_domain_sans", "certs", "ct_source"},
        )
        self.assertEqual(result["subdomains"], ["api.example.com", "www.example.com"])
        self.assertEqual(result["issuers"], ["R3"])
        self.assertEqual(result["cross_domain_sans"], ["shared.other-org.net"])
        cert = result["certs"][0]
        self.assertEqual(
            set(cert),
            {"id", "issuer", "not_before", "not_after", "logged_at", "sans"},
        )
        self.assertEqual(cert["id"], 648494876)
        self.assertEqual(cert["issuer"], "R3")
        self.assertIsNone(cert["logged_at"])

    def test_crt_sh_exception_falls_back(self) -> None:
        calls: list[dict] = []
        fake = make_fake_get(
            requests.exceptions.ReadTimeout("crt.sh timed out"),
            [CERTSPOTTER_PAGE],
            calls,
        )
        with patch("core.ip_intel.requests.get", side_effect=fake):
            result = ip_intel.crt_sh_data(DOMAIN)

        self.assertEqual(result["ct_source"], "certspotter")
        self.assertEqual(result["total_certs"], 1)

    def test_both_sources_fail_returns_empty_shape(self) -> None:
        calls: list[dict] = []
        fake = make_fake_get(
            FakeResponse(503, None),
            [requests.exceptions.ConnectTimeout("certspotter down")],
            calls,
        )
        with patch("core.ip_intel.requests.get", side_effect=fake):
            result = ip_intel.crt_sh_data(DOMAIN)

        self.assertEqual(result["subdomains"], [])
        self.assertEqual(result["total_certs"], 0)
        self.assertEqual(result["issuers"], [])
        self.assertEqual(result["cross_domain_sans"], [])
        self.assertEqual(result["certs"], [])

    def test_certspotter_pagination_follows_after(self) -> None:
        page1 = [
            {"id": "100", "dns_names": ["a.example.com"], "issuer": {"name": "CN=R3"},
             "not_before": "2026-01-01T00:00:00-00:00", "not_after": "2026-04-01T00:00:00-00:00"},
        ]
        page2 = [
            {"id": "200", "dns_names": ["b.example.com"], "issuer": {"name": "CN=R3"},
             "not_before": "2026-01-02T00:00:00-00:00", "not_after": "2026-04-02T00:00:00-00:00"},
        ]
        calls: list[dict] = []
        fake = make_fake_get(FakeResponse(503, None), [page1, page2, []], calls)
        with patch("core.ip_intel.requests.get", side_effect=fake):
            result = ip_intel.certspotter_data(DOMAIN)

        cs_calls = certspotter_calls(calls)
        self.assertEqual(len(cs_calls), 3)
        self.assertNotIn("after", cs_calls[0]["params"])
        self.assertEqual(cs_calls[1]["params"]["after"], "100")
        self.assertEqual(cs_calls[2]["params"]["after"], "200")
        self.assertEqual(result["total_certs"], 2)
        self.assertEqual(result["subdomains"], ["a.example.com", "b.example.com"])


# ── core.ip_intel (async) ─────────────────────────────────────────────────────

class AsyncCtFallbackTests(unittest.TestCase):
    def test_success_does_not_call_fallback(self) -> None:
        calls: list[dict] = []
        client = FakeAsyncClient(make_fake_get(FakeResponse(200, CRT_SH_ENTRIES), [], calls))
        result = asyncio.run(ip_intel._acrt_sh_data(DOMAIN, client))

        self.assertEqual(certspotter_calls(calls), [])
        self.assertEqual(result["ct_source"], "crt.sh")
        self.assertNotIn("_failed", result)

    def test_429_falls_back_with_pagination(self) -> None:
        page2 = [
            {"id": "900", "dns_names": ["extra.example.com"], "issuer": {"name": "CN=R3"},
             "not_before": "2026-02-01T00:00:00-00:00", "not_after": "2026-05-01T00:00:00-00:00"},
        ]
        calls: list[dict] = []
        client = FakeAsyncClient(
            make_fake_get(FakeResponse(429, None), [CERTSPOTTER_PAGE, page2, []], calls)
        )
        result = asyncio.run(ip_intel._acrt_sh_data(DOMAIN, client))

        cs_calls = certspotter_calls(calls)
        self.assertEqual(len(cs_calls), 3)
        self.assertNotIn("after", cs_calls[0]["params"])
        self.assertEqual(cs_calls[1]["params"]["after"], "648494876")
        self.assertEqual(cs_calls[2]["params"]["after"], "900")
        self.assertEqual(result["ct_source"], "certspotter")
        self.assertNotIn("_failed", result)  # crt_sh_status stays "ok" downstream
        self.assertEqual(result["total_certs"], 2)
        self.assertEqual(
            result["subdomains"],
            ["api.example.com", "extra.example.com", "www.example.com"],
        )

    def test_both_fail_marks_failed_for_retry_sweep(self) -> None:
        calls: list[dict] = []
        client = FakeAsyncClient(
            make_fake_get(FakeResponse(503, None), [FakeResponse(429, None)], calls)
        )
        result = asyncio.run(ip_intel._acrt_sh_data(DOMAIN, client))

        self.assertTrue(result.get("_failed"))
        self.assertEqual(result["subdomains"], [])
        self.assertEqual(result["certs"], [])


if __name__ == "__main__":
    unittest.main()
