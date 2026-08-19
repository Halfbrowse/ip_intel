"""Censys cost/correctness hygiene: matched-service cert selection, the
opt-in cert-history pivot, and the single shared cert-search implementation."""

from __future__ import annotations

import os
import sys
import unittest
from enum import Enum
from types import SimpleNamespace
from unittest.mock import patch

import core.basic as basic
import core.ip_intel as ip_intel


class _Transport(str, Enum):
    """Stand-in for the SDK's ServiceTransportProtocol: a str Enum whose str()
    is the member name, which is exactly why the parser reads .value."""

    TCP = "tcp"


def _hit(services, matched_services=None, ip="203.0.113.7"):
    host_v1 = {
        "resource": {
            "ip": ip,
            "autonomous_system": {"asn": 64512, "description": "EXAMPLE-AS"},
            "location": {"country_code": "IE"},
            "services": services,
        }
    }
    if matched_services is not None:
        host_v1["matched_services"] = matched_services
    return {"host_v1": host_v1}


class CensysParseHostHitTests(unittest.TestCase):
    def test_matched_service_cert_wins_over_first_cert_on_shared_host(self) -> None:
        """The whole point: on shared hosting the first cert-bearing service is
        frequently another tenant's, and that fingerprint is what the 25-credit
        history pivot would chase."""
        entry, fingerprint = ip_intel._censys_parse_host_hit(
            _hit(
                services=[
                    {"port": 443, "transport_protocol": "tcp", "cert": {"fingerprint_sha256": "other-tenant"}},
                    {"port": 8443, "transport_protocol": "tcp", "cert": {"fingerprint_sha256": "ours"}},
                ],
                matched_services=[{"port": 8443, "transport_protocol": "tcp", "protocol": "HTTP"}],
            )
        )
        self.assertEqual(fingerprint, "ours")
        self.assertEqual(entry["ip"], "203.0.113.7")
        self.assertEqual(entry["asn"], 64512)
        self.assertEqual(entry["asn_name"], "EXAMPLE-AS")
        self.assertEqual(entry["country"], "IE")
        self.assertEqual(entry["services"], ["443/tcp", "8443/tcp"])

    def test_transport_protocol_enum_is_read_by_value(self) -> None:
        entry, fingerprint = ip_intel._censys_parse_host_hit(
            _hit(
                services=[
                    {"port": 443, "transport_protocol": _Transport.TCP, "cert": {"fingerprint_sha256": "other"}},
                    {"port": 993, "transport_protocol": _Transport.TCP, "cert": {"fingerprint_sha256": "ours"}},
                ],
                matched_services=[{"port": 993, "transport_protocol": _Transport.TCP}],
            )
        )
        self.assertEqual(fingerprint, "ours")
        self.assertEqual(entry["services"], ["443/tcp", "993/tcp"])

    def test_missing_transport_on_either_side_still_matches_on_port(self) -> None:
        _, fingerprint = ip_intel._censys_parse_host_hit(
            _hit(
                services=[
                    {"port": 443, "cert": {"fingerprint_sha256": "other"}},
                    {"port": 8443, "transport_protocol": "tcp", "cert": {"fingerprint_sha256": "ours"}},
                ],
                matched_services=[{"port": 8443}],
            )
        )
        self.assertEqual(fingerprint, "ours")

    def test_falls_back_to_first_cert_when_matched_services_absent(self) -> None:
        """Documented fallback for responses that carry no matched_services."""
        _, fingerprint = ip_intel._censys_parse_host_hit(
            _hit(
                services=[
                    {"port": 443, "transport_protocol": "tcp", "cert": {"fingerprint_sha256": "first"}},
                    {"port": 8443, "transport_protocol": "tcp", "cert": {"fingerprint_sha256": "second"}},
                ]
            )
        )
        self.assertEqual(fingerprint, "first")

    def test_null_matched_services_uses_the_fallback(self) -> None:
        """matched_services is Nullable in the SDK, so it can serialize to None."""
        _, fingerprint = ip_intel._censys_parse_host_hit(
            _hit(
                services=[{"port": 443, "cert": {"fingerprint_sha256": "first"}}],
                matched_services=None,
            )
        )
        self.assertEqual(fingerprint, "first")

    def test_no_fingerprint_when_matched_service_carries_no_cert(self) -> None:
        """Better to pivot on nothing than to pivot on someone else's cert."""
        _, fingerprint = ip_intel._censys_parse_host_hit(
            _hit(
                services=[
                    {"port": 443, "transport_protocol": "tcp", "cert": {"fingerprint_sha256": "other-tenant"}},
                    {"port": 22, "transport_protocol": "tcp"},
                ],
                matched_services=[{"port": 22, "transport_protocol": "tcp"}],
            )
        )
        self.assertIsNone(fingerprint)

    def test_hit_without_ip_is_dropped(self) -> None:
        entry, fingerprint = ip_intel._censys_parse_host_hit({"host_v1": {"resource": {}}})
        self.assertIsNone(entry)
        self.assertIsNone(fingerprint)


class CensysHistoryOptInTests(unittest.TestCase):
    def test_history_defaults_off(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CENSYS_CERT_HISTORY", None)
            self.assertFalse(ip_intel._censys_history_enabled())

    def test_history_env_flag_accepts_truthy_spellings(self) -> None:
        for value in ("1", "true", "TRUE", "yes", "on"):
            with patch.dict(os.environ, {"CENSYS_CERT_HISTORY": value}):
                self.assertTrue(ip_intel._censys_history_enabled(), value)
        for value in ("0", "", "false", "no"):
            with patch.dict(os.environ, {"CENSYS_CERT_HISTORY": value}):
                self.assertFalse(ip_intel._censys_history_enabled(), value)

    def _run_search(self, env, **kwargs):
        """Drive censys_cert_search against a stubbed SDK — one page, one hit —
        so nothing leaves the machine."""
        page = {
            "result": {
                "result": {
                    "hits": [
                        _hit(
                            services=[{"port": 443, "transport_protocol": "tcp",
                                       "cert": {"fingerprint_sha256": "ours"}}],
                            matched_services=[{"port": 443, "transport_protocol": "tcp"}],
                        )
                    ],
                    "next_page_token": "",
                    "total_hits": 1,
                }
            }
        }

        class _StubSDK:
            def __init__(self, **_):
                self.global_data = self

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def search(self, **_):
                return SimpleNamespace(result=page["result"])

        sdk_module = SimpleNamespace(SDK=_StubSDK)
        with patch.dict(os.environ, env), \
                patch.dict(sys.modules, {"censys_platform": sdk_module}), \
                patch.object(ip_intel, "_censys_cert_history", return_value=[]) as history:
            result = ip_intel.censys_cert_search("example.com", **kwargs)
        return result, history

    def test_search_skips_the_history_pivot_by_default(self) -> None:
        env = {"CENSYS_API_KEY": "k", "CENSYS_ORG_ID": "o"}
        result, history = self._run_search(env)
        self.assertNotIn("error", result)
        self.assertEqual(result["hits"][0]["ip"], "203.0.113.7")
        history.assert_not_called()
        self.assertEqual(result["history"], [])

    def test_search_runs_the_history_pivot_when_opted_in(self) -> None:
        env = {"CENSYS_API_KEY": "k", "CENSYS_ORG_ID": "o", "CENSYS_CERT_HISTORY": "1"}
        _, history = self._run_search(env)
        history.assert_called_once()
        self.assertEqual(history.call_args.args[1], ["ours"])

    def test_explicit_argument_overrides_the_env_default(self) -> None:
        env = {"CENSYS_API_KEY": "k", "CENSYS_ORG_ID": "o", "CENSYS_CERT_HISTORY": "1"}
        _, history = self._run_search(env, include_history=False)
        history.assert_not_called()

    def test_missing_credentials_skip_without_calling_the_api(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertTrue(ip_intel.censys_cert_search("example.com")["skipped"])


class CensysServiceConsolidationTests(unittest.TestCase):
    def test_basic_get_censys_delegates_to_the_shared_implementation(self) -> None:
        rich = {
            "hits": [{"ip": "203.0.113.7", "asn": 64512, "country": "IE", "services": ["443/tcp"]}],
            "origin_candidates": [{"ip": "203.0.113.7", "cloudflare": False}],
            "history": [],
            "total": 1,
        }
        with patch.object(basic, "censys_cert_search", return_value=rich) as search:
            result = basic.get_censys("example.com")
        search.assert_called_once_with("example.com")
        self.assertEqual(result, rich)

    def test_censys_is_still_the_registered_service(self) -> None:
        registered = dict(basic.SERVICES)
        self.assertIs(registered["censys"], basic.get_censys)
        self.assertIn("censys", basic._PROVIDER_SERVICES)

    def test_skipped_and_error_markers_pass_through_unchanged(self) -> None:
        for marker in ({"skipped": True, "reason": "no key"}, {"error": "boom"}):
            with patch.object(basic, "censys_cert_search", return_value=marker):
                self.assertEqual(basic.get_censys("example.com"), marker)


if __name__ == "__main__":
    unittest.main()
