from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

import intel_db
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

    def test_save_search_handles_policy_and_mail_client_mappings(self) -> None:
        payload = {
            "input": "example.com",
            "type": "domain",
            "timestamp": "2026-04-21T09:00:00+00:00",
            "ip_details": {},
            "email_security": {
                "bimi": {
                    "default": {
                        "name": "default._bimi.example.com",
                        "records": ["https://cdn.example.com/logo.svg"],
                    }
                },
                "mta_sts": {
                    "name": "_mta-sts.example.com",
                    "records": [],
                },
                "tls_rpt": {
                    "name": "_smtp._tls.example.com",
                    "records": [],
                },
                "dmarc_report_uris": {
                    "rua": ["mailto:dmarc@example.com"],
                    "ruf": [],
                },
            },
            "mail_client_config": {
                "autoconfig": [
                    {
                        "label": "well_known",
                        "url": "https://autoconfig.example.com/mail/config-v1.1.xml",
                        "parsed": {
                            "domains": ["mail.example.com"],
                            "emails": ["admin@example.com"],
                            "servers": ["imap.example.com"],
                        },
                    }
                ],
                "domains": ["mx.example.com"],
                "servers": ["smtp.example.com"],
            },
        }

        original_db_path = intel_db.DB_PATH
        fd, temp_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        intel_db.DB_PATH = Path(temp_path)
        try:
            sid = intel_db.save_search(payload)
            self.assertGreater(sid, 0)

            history = intel_db.get_history_for_target("example.com")
            self.assertEqual(len(history), 1)

            with sqlite3.connect(intel_db.DB_PATH) as conn:
                identifiers = {
                    (row[0], row[1])
                    for row in conn.execute("SELECT id_type, id_value FROM identifiers")
                }

            self.assertIn(("bimi", "https://default._bimi.example.com"), identifiers)
            self.assertIn(("bimi", "https://cdn.example.com/logo.svg"), identifiers)
            self.assertIn(("mta_sts", "https://_mta-sts.example.com"), identifiers)
            self.assertIn(("tls_rpt", "https://_smtp._tls.example.com"), identifiers)
            self.assertIn(("dmarc_rua", "dmarc@example.com"), identifiers)
            self.assertIn(("mail_client_url", "https://autoconfig.example.com/mail/config-v1.1.xml"), identifiers)
            self.assertIn(("mail_client_domain", "mail.example.com"), identifiers)
            self.assertIn(("mail_client_domain", "mx.example.com"), identifiers)
            self.assertIn(("mail_client_email", "admin@example.com"), identifiers)
            self.assertIn(("mail_client_server", "imap.example.com"), identifiers)
            self.assertIn(("mail_client_server", "smtp.example.com"), identifiers)
        finally:
            intel_db.DB_PATH = original_db_path
            try:
                os.remove(temp_path)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
