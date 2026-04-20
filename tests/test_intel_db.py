from __future__ import annotations

import unittest

from intel_db import extract_search_identifiers


class IntelDbTests(unittest.TestCase):
    def test_extract_search_identifiers_includes_subdomain_followups(self) -> None:
        payload = {
            "input": "example.com",
            "type": "domain",
            "timestamp": "2026-04-20T18:30:00+00:00",
            "ip_details": {},
            "subdomain_followups": [
                {
                    "subdomain": "app.example.com",
                    "source": "wordlist_probe",
                    "status": "completed",
                    "ips": ["198.51.100.10"],
                    "result": {
                        "input": "app.example.com",
                        "type": "domain",
                        "timestamp": "2026-04-20T18:31:00+00:00",
                        "ip_details": {},
                        "page_metadata": {
                            "ga_ids": ["G-TEST123"],
                        },
                        "well_known": {
                            "assetlinks": [
                                {
                                    "target": {
                                        "namespace": "android_app",
                                        "package_name": "com.example.app",
                                        "sha256_cert_fingerprints": ["AA:BB"],
                                    }
                                }
                            ]
                        },
                        "non_cf_tls_certs": [
                            {
                                "ip": "198.51.100.10",
                                "port": 443,
                                "cn": "app.example.com",
                                "sans": ["app.example.com"],
                                "issuer_cn": "Example Issuer",
                                "not_before": "2026-01-01T00:00:00+00:00",
                                "not_after": "2026-02-01T00:00:00+00:00",
                                "sha256": "DEF456",
                                "spki_sha256": "ABC123",
                            }
                        ],
                    },
                }
            ],
        }

        identifiers = {
            (item["id_type"], item["id_value"], item["source"])
            for item in extract_search_identifiers(payload)
        }

        self.assertIn(("subdomain_name", "app.example.com", "subdomain_followups"), identifiers)
        self.assertIn(
            ("ga_property", "g-test123", "subdomain_followups.app.example.com.page_metadata.ga_ids"),
            identifiers,
        )
        self.assertIn(
            ("android_cert_sha256", "aabb", "subdomain_followups.app.example.com.well_known.assetlinks"),
            identifiers,
        )
        self.assertIn(
            ("tls_spki_sha256", "abc123", "subdomain_followups.app.example.com.tls_certs"),
            identifiers,
        )


if __name__ == "__main__":
    unittest.main()
