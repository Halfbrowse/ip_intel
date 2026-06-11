from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

import sources.signal_dns as signal_dns
from sources.signal_dns import (
    extract_mailto_addresses,
    extract_txt_tenancy_tokens,
    lookup_txt_records,
    probe_microsoft_tenant_guid,
    parse_caa_records,
    parse_dmarc_record,
    parse_spf_record,
)


class SignalDnsTests(unittest.TestCase):
    def test_extract_txt_tenancy_tokens(self) -> None:
        records = [
            "google-site-verification=abc123",
            "MS=ms12345678",
            "stripe-verification=acct_123",
        ]
        tokens = extract_txt_tenancy_tokens(records)
        self.assertIn({"provider": "google_site_verification", "token": "abc123"}, tokens)
        self.assertIn({"provider": "microsoft_365", "token": "ms12345678"}, tokens)
        self.assertIn({"provider": "stripe_verification", "token": "acct_123"}, tokens)

    def test_parse_dmarc_record(self) -> None:
        parsed = parse_dmarc_record(
            "v=DMARC1; p=reject; rua=mailto:reports@example.com,mailto:agg@example.net!10m; "
            "ruf=mailto:forensic@example.org"
        )
        self.assertEqual(parsed["rua"], ["reports@example.com", "agg@example.net"])
        self.assertEqual(parsed["ruf"], ["forensic@example.org"])

    def test_extract_mailto_addresses(self) -> None:
        self.assertEqual(
            extract_mailto_addresses("mailto:One@Example.com,mailto:two@example.com!50m"),
            ["one@example.com", "two@example.com"],
        )

    def test_parse_spf_record(self) -> None:
        parsed = parse_spf_record("v=spf1 ip4:203.0.113.10 include:_spf.example.net -all")
        self.assertIn("203.0.113.10", parsed["ip4"])
        self.assertEqual(parsed["includes"], ["_spf.example.net"])

    def test_parse_caa_records(self) -> None:
        parsed = parse_caa_records(['0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123"'])
        self.assertEqual(parsed[0]["tag"], "issue")
        self.assertEqual(parsed[0]["accounturi"], "https://acme-v02.api.letsencrypt.org/acme/acct/123")

    def test_lookup_txt_records_handles_resolver_init_failure(self) -> None:
        with patch.object(
            signal_dns.dns.asyncresolver,
            "Resolver",
            side_effect=RuntimeError("cannot open /etc/resolv.conf"),
            create=True,
        ):
            records = asyncio.run(lookup_txt_records("example.com"))

        self.assertEqual(records, [])

    def test_probe_microsoft_tenant_guid_handles_non_mapping_json(self) -> None:
        class FakeResponse:
            status_code = 200

            @staticmethod
            def json():
                return "not-a-json-object"

        class FakeClient:
            async def get(self, _url):
                return FakeResponse()

        result = asyncio.run(
            probe_microsoft_tenant_guid(
                "example.com",
                client=FakeClient(),
                endpoints=("https://example.invalid/{domain}",),
            )
        )

        self.assertIsNone(result["tenant_id"])
        self.assertEqual(result["results"][0]["error"], "invalid_payload:str")


if __name__ == "__main__":
    unittest.main()
