from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest

import psycopg

import db.intel_db as intel_db
from db.intel_db import extract_search_identifiers
from scripts.migrate_sqlite_to_postgres import migrate

DEFAULT_TEST_DATABASE_URL = "postgresql://intel_test:intel_test@127.0.0.1:5433/intel_test"
TEST_DATABASE_URL = os.getenv("TEST_INTEL_DATABASE_URL", DEFAULT_TEST_DATABASE_URL)


def _database_unreachable_reason() -> str | None:
    try:
        with psycopg.connect(TEST_DATABASE_URL, connect_timeout=3):
            return None
    except psycopg.Error as exc:
        return str(exc).strip() or exc.__class__.__name__


class IdentifierExtractionTests(unittest.TestCase):
    """Pure extraction logic — no database required."""

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


class EntityClassificationTests(unittest.TestCase):
    """Pure classification logic for the correlation layer — no database."""

    def test_registrable_domain(self) -> None:
        self.assertEqual(intel_db.registrable_domain("example.com"), "example.com")
        self.assertEqual(intel_db.registrable_domain("www.example.com"), "example.com")
        self.assertEqual(intel_db.registrable_domain("x.a.example.com"), "example.com")
        self.assertEqual(intel_db.registrable_domain("*.example.com"), "example.com")
        self.assertIsNone(intel_db.registrable_domain("203.0.113.5"))
        self.assertIsNone(intel_db.registrable_domain("localhost"))

    def test_classify_entity(self) -> None:
        self.assertEqual(
            intel_db.classify_entity("example.com"),
            {"kind": "domain", "value": "example.com", "registrable_domain": "example.com"},
        )
        self.assertEqual(
            intel_db.classify_entity("x.a.example.com"),
            {"kind": "subdomain", "value": "x.a.example.com", "registrable_domain": "example.com"},
        )
        self.assertEqual(
            intel_db.classify_entity("203.0.113.5"),
            {"kind": "ip", "value": "203.0.113.5", "registrable_domain": None},
        )
        self.assertEqual(
            intel_db.classify_entity("HTTPS://WWW.Example.com/path"),
            {"kind": "domain", "value": "example.com", "registrable_domain": "example.com"},
        )
        self.assertIsNone(intel_db.classify_entity("not a host"))


class IntelDbTests(unittest.TestCase):
    """Persistence tests against a disposable PostgreSQL database.

    Set TEST_INTEL_DATABASE_URL to point at a different test database; the
    intel tables are dropped and recreated for every test so each run starts
    from a clean state.
    """

    _previous_env: str | None = None

    @classmethod
    def setUpClass(cls) -> None:
        reason = _database_unreachable_reason()
        if reason is not None:
            raise unittest.SkipTest(
                f"PostgreSQL test database unreachable at {TEST_DATABASE_URL} "
                f"({reason}); set TEST_INTEL_DATABASE_URL to override."
            )
        cls._previous_env = os.environ.get("INTEL_DATABASE_URL")
        os.environ["INTEL_DATABASE_URL"] = TEST_DATABASE_URL

    @classmethod
    def tearDownClass(cls) -> None:
        if cls._previous_env is None:
            os.environ.pop("INTEL_DATABASE_URL", None)
        else:
            os.environ["INTEL_DATABASE_URL"] = cls._previous_env
        intel_db.reset_schema_cache()

    def setUp(self) -> None:
        with psycopg.connect(TEST_DATABASE_URL) as conn:
            for table in reversed(intel_db._ALL_TABLES):
                conn.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
        intel_db.reset_schema_cache()
        intel_db.init_db()

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

        sid = intel_db.save_search(payload)
        self.assertGreater(sid, 0)

        history = intel_db.get_history_for_target("example.com")
        self.assertEqual(len(history), 1)

        with psycopg.connect(TEST_DATABASE_URL) as conn:
            identifiers = {
                (row[0], row[1])
                for row in conn.execute("SELECT id_type, id_value FROM identifiers").fetchall()
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

    def test_append_only_runs_and_round_trip(self) -> None:
        first = {
            "input": "example.org",
            "type": "domain",
            "timestamp": "2026-04-21T09:00:00+00:00",
            "ip_details": {
                "203.0.113.5": {
                    "sources": ["dns"],
                    "asn_info": {"asn": "AS64500", "asn_description": "EXAMPLE-NET"},
                }
            },
            "dns": {"A": ["203.0.113.5"]},
        }
        second = dict(first, timestamp="2026-04-22T10:00:00+00:00")

        sid_a = intel_db.save_search(first)
        sid_b = intel_db.save_search(second)
        self.assertGreater(sid_b, sid_a)

        history = intel_db.get_history_for_target("example.org")
        self.assertEqual(len(history), 2)
        self.assertTrue(history[0]["is_latest"])
        self.assertEqual(history[0]["id"], sid_b)

        result = intel_db.get_result(sid_a)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["input"], "example.org")
        self.assertEqual(result["dns"], {"A": ["203.0.113.5"]})

        matches = intel_db.find_by_ip("203.0.113.5")
        self.assertEqual({match["id"] for match in matches}, {sid_a, sid_b})

        recent = intel_db.get_recent(limit=10)
        self.assertEqual([row["id"] for row in recent], [sid_b, sid_a])

    def test_query_surface_round_trip(self) -> None:
        """Exercise every translated SQL path against PostgreSQL."""
        payload = {
            "input": "smoke.example",
            "type": "domain",
            "timestamp": "2026-05-01T00:00:00+00:00",
            "cloudflare_fronted": False,
            "source_errors": ["crt_sh"],
            "ip_details": {
                "51.15.23.7": {
                    "sources": ["dns"],
                    "ptr": "host.smoke.example",
                    "cloudflare": False,
                    "asn_info": {
                        "asn": "AS64501",
                        "asn_description": "SMOKE-NET",
                        "network_cidr": "203.0.113.0/24",
                    },
                }
            },
            "dns": {
                "A": ["51.15.23.7"],
                "MX": [{"exchange": "mx.smoke.example", "priority": 10}],
                "TXT": ["google-site-verification=abc123"],
            },
            "subdomains": ["dev.smoke.example"],
            "zone_transfer": [],
            "historical_dns": {
                "records": [
                    {
                        "rrtype": "A",
                        "rdata": "198.51.100.4",
                        "first_seen": "2025-01-01",
                        "last_seen": "2025-06-01",
                    }
                ]
            },
            "spf_origins": [{"ip": "203.0.113.8", "cidr": "203.0.113.0/24"}],
            "whois": {
                "registrar": "Reg Inc",
                "creation_date": "2020-01-01",
                "expiry_date": "2030-01-01",
                "org": "Smoke Org",
                "country": "DE",
                "emails": ["owner@smoke.example"],
                "nameservers": ["ns1.smoke.example"],
            },
            "page_metadata": {
                "google_analytics": ["UA-1"],
                "favicon_md5": "f00d",
                "html_lang": "en",
                "social_handles": {"x": ["smoke"]},
                "social_links": {"x": ["https://x.com/smoke"]},
            },
            "email_security": {"dmarc": "v=DMARC1"},
            "cert_transparency": {
                "certs": [
                    {
                        "id": 1,
                        "issuer": "R3",
                        "not_before": "2026-01-01",
                        "not_after": "2026-04-01",
                        "sans": ["smoke.example"],
                    }
                ],
                "cross_domain_sans": ["other.example"],
            },
            "non_cf_tls_certs": [
                {
                    "ip": "51.15.23.7",
                    "port": 443,
                    "cn": "smoke.example",
                    "sans": ["smoke.example"],
                    "issuer_cn": "R3",
                    "issuer_org": "LE",
                    "not_before": "2026-01-01",
                    "not_after": "2026-04-01",
                    "sha256": "abc",
                    "spki_sha256": "def",
                }
            ],
            "origin_candidates": {
                "censys": {
                    "hits": [
                        {
                            "ip": "51.15.23.9",
                            "port": 443,
                            "hostnames": ["h.smoke.example"],
                            "asn": "AS64501",
                        }
                    ],
                    "mode": "basic",
                    "status": "ok",
                    "query_type": "host",
                    "total": 1,
                },
                "scan": {
                    "hits": [
                        {
                            "ip": "203.0.113.10",
                            "port": 443,
                            "cn": "smoke.example",
                            "sans": ["smoke.example"],
                            "sha256": "abc",
                        }
                    ]
                },
            },
        }

        sid = intel_db.save_search(payload)
        sid2 = intel_db.save_search(dict(payload, input="smoke2.example"))
        self.assertGreater(sid2, sid)

        self.assertEqual(len(intel_db.get_recent(5)), 2)
        self.assertEqual(
            set(intel_db.get_domain_targets()), {"smoke.example", "smoke2.example"}
        )
        errored = intel_db.get_domains_with_source_errors("crt_sh")
        self.assertEqual({entry["id"] for entry in errored}, {sid, sid2})
        self.assertEqual(intel_db.get_by_id(sid)["target"], "smoke.example")
        self.assertEqual(intel_db.get_latest_search_id_for_target("smoke.example"), sid)
        self.assertEqual(len(intel_db.get_history_for_target("smoke.example")), 1)

        self.assertEqual(len(intel_db.find_by_ip("51.15.23.7")), 2)
        self.assertEqual(len(intel_db.find_by_tls_sha256("abc")), 2)
        self.assertEqual(len(intel_db.find_by_tracking_id("ga", "UA-1")), 2)
        self.assertEqual(len(intel_db.find_by_favicon("f00d")), 2)
        self.assertEqual(len(intel_db.find_by_registrant_email("owner@smoke.example")), 2)
        self.assertEqual(len(intel_db.find_by_social_handle("x", "smoke")), 2)
        self.assertEqual(len(intel_db.find_by_nameserver("ns1.smoke.example")), 2)
        self.assertEqual(len(intel_db.find_by_cross_san("other.example")), 2)
        self.assertEqual(len(intel_db.find_by_identifier("resolved_ip", "51.15.23.7")), 2)
        self.assertTrue(intel_db.find_searches_touching_target("51.15.23.7"))
        self.assertGreaterEqual(intel_db.summarize_result_db_matches(payload)["total"], 1)

        comparison = intel_db.compare_domains("smoke.example", "smoke2.example")
        self.assertIsNotNone(comparison)
        assert comparison is not None
        self.assertGreater(comparison["score"], 0)
        cluster = intel_db.traverse_identifier_cluster("smoke.example")
        self.assertIn("smoke2.example", cluster["component"]["domains"])

        self.assertTrue(intel_db.cluster_by_ip())
        self.assertTrue(intel_db.cluster_by_tracking_id())
        self.assertTrue(intel_db.cluster_by_favicon())
        self.assertTrue(intel_db.cluster_by_tls_cert("all"))
        self.assertTrue(intel_db.cluster_by_asn("all"))

        connections = intel_db.get_connections_for_target("smoke.example")
        assert connections is not None
        self.assertEqual(connections["sid"], sid)
        self.assertIn("tls_certs", connections["connections"])
        self.assertEqual(
            connections["connections"]["favicons"][0]["shared_with"], ["smoke2.example"]
        )

        # Patching a payload merges fields and refreshes identifiers from the
        # patched payload (so identifier-based pivots reflect only its content).
        intel_db.update_search_payload(sid, {"timestamp": "2026-05-02T00:00:00+00:00", "extra": {"a": 1}})
        result = intel_db.get_result(sid)
        assert result is not None
        self.assertEqual(result["extra"], {"a": 1})
        self.assertEqual(len(intel_db.find_by_identifier("resolved_ip", "51.15.23.7")), 1)

    def test_correlation_layer_upserts(self) -> None:
        """entities/selectors/observations/entity_edges upserts are idempotent,
        widen time windows, and maintain selector degree."""
        with intel_db._conn() as c:
            # Two subdomains of two different apexes sharing one leaf cert.
            e_sub_a = intel_db.upsert_entity_value(
                c, "x.a.com", first_seen="2026-01-01T00:00:00+00:00", last_seen="2026-01-01T00:00:00+00:00"
            )
            e_sub_b = intel_db.upsert_entity_value(
                c, "y.b.com", first_seen="2026-02-01T00:00:00+00:00", last_seen="2026-02-01T00:00:00+00:00"
            )
            e_apex_a = intel_db.upsert_entity_value(c, "a.com")
            e_ip = intel_db.upsert_entity_value(c, "203.0.113.9")
            assert e_sub_a and e_sub_b and e_apex_a and e_ip

            sel = intel_db.upsert_selector(
                c, kind="tls_cert_sha256", value="deadbeef",
                first_seen="2026-01-01T00:00:00+00:00", last_seen="2026-01-01T00:00:00+00:00",
            )

            intel_db.record_observation(
                c, entity_id=e_sub_a, selector_id=sel, source="self_scan",
                first_seen="2026-01-01T00:00:00+00:00", last_seen="2026-01-15T00:00:00+00:00", search_id=None,
            )
            intel_db.record_observation(
                c, entity_id=e_sub_b, selector_id=sel, source="censys",
                first_seen="2026-02-01T00:00:00+00:00", last_seen="2026-02-10T00:00:00+00:00",
            )
            # Re-observe the same edge with a wider window: must widen, not duplicate.
            intel_db.record_observation(
                c, entity_id=e_sub_a, selector_id=sel, source="self_scan",
                first_seen="2025-12-01T00:00:00+00:00", last_seen="2026-03-01T00:00:00+00:00",
            )

            intel_db.record_entity_edge(
                c, src_entity_id=e_sub_a, dst_entity_id=e_apex_a, kind="subdomain_of", source="dns",
            )
            intel_db.record_entity_edge(
                c, src_entity_id=e_apex_a, dst_entity_id=e_ip, kind="resolves_to", source="dns_a",
            )
            intel_db.record_entity_edge(  # idempotent
                c, src_entity_id=e_sub_a, dst_entity_id=e_apex_a, kind="subdomain_of", source="dns",
            )

            degree = intel_db.recompute_selector_degree(c, sel)
            self.assertEqual(degree, 2)  # two distinct entities exhibit the cert

            obs_count = c.execute(
                "SELECT count(*) AS n FROM observations WHERE selector_id = %s", (sel,)
            ).fetchone()["n"]
            self.assertEqual(obs_count, 2)  # (e_sub_a, self_scan) widened; (e_sub_b, censys)

            widened = c.execute(
                "SELECT first_seen, last_seen FROM observations WHERE entity_id = %s AND selector_id = %s AND source = 'self_scan'",
                (e_sub_a, sel),
            ).fetchone()
            self.assertEqual(widened["first_seen"], "2025-12-01T00:00:00+00:00")
            self.assertEqual(widened["last_seen"], "2026-03-01T00:00:00+00:00")

            edge_count = c.execute("SELECT count(*) AS n FROM entity_edges").fetchone()["n"]
            self.assertEqual(edge_count, 2)

            # Subdomain rollup is recorded on the entity.
            rd = c.execute(
                "SELECT registrable_domain, kind FROM entities WHERE id = %s", (e_sub_b,)
            ).fetchone()
            self.assertEqual(rd["registrable_domain"], "b.com")
            self.assertEqual(rd["kind"], "subdomain")

            # Denylist flag and batch degree recompute.
            intel_db.set_selector_attributing(c, sel, False)
            intel_db.recompute_all_selector_degrees(c)
            final = c.execute(
                "SELECT entity_count, attributing FROM selectors WHERE id = %s", (sel,)
            ).fetchone()
            self.assertEqual(final["entity_count"], 2)
            self.assertFalse(final["attributing"])
            c.commit()

    def _scan_with_subdomain_cert(self, apex: str, sub: str, sha256: str, ts: str) -> dict:
        return {
            "input": apex,
            "type": "domain",
            "timestamp": ts,
            "ip_details": {},
            "subdomains": [sub],
            "subdomain_followups": [
                {
                    "subdomain": sub,
                    "status": "completed",
                    "result": {
                        "input": sub,
                        "type": "domain",
                        "timestamp": ts,
                        "ip_details": {
                            "203.0.113.50": {
                                "sources": ["dns"],
                                "asn_info": {"asn": "AS64600", "network_cidr": "203.0.113.0/24"},
                            }
                        },
                        "non_cf_tls_certs": [
                            {
                                "ip": "203.0.113.50",
                                "port": 443,
                                "cn": sub,
                                "sans": [sub],
                                "not_before": "2026-01-01T00:00:00+00:00",
                                "not_after": "2026-04-01T00:00:00+00:00",
                                "sha256": sha256,
                                "spki_sha256": "spki-" + sha256,
                            }
                        ],
                    },
                }
            ],
        }

    def test_correlation_transitive_and_backfill_determinism(self) -> None:
        """A leaf cert shared only between x.a.com and y.b.com links the two
        registrable apexes through the subdomain entities — and a global rebuild
        reproduces the identical graph from stored intel."""
        shared = "deadbeefcert"
        intel_db.save_search(self._scan_with_subdomain_cert("a.com", "x.a.com", shared, "2026-03-01T00:00:00+00:00"))
        intel_db.save_search(self._scan_with_subdomain_cert("b.com", "y.b.com", shared, "2026-03-02T00:00:00+00:00"))

        def assert_graph() -> None:
            with psycopg.connect(TEST_DATABASE_URL, row_factory=psycopg.rows.dict_row) as conn:
                sel = conn.execute(
                    "SELECT id, entity_count, attributing FROM selectors WHERE kind = 'tls_cert_sha256' AND value = %s",
                    (shared,),
                ).fetchone()
                self.assertIsNotNone(sel)
                self.assertEqual(sel["entity_count"], 2)
                self.assertTrue(sel["attributing"])

                exhibitors = {
                    row["value"]
                    for row in conn.execute(
                        """SELECT e.value FROM observations o
                           JOIN entities e ON e.id = o.entity_id
                           WHERE o.selector_id = %s""",
                        (sel["id"],),
                    ).fetchall()
                }
                self.assertEqual(exhibitors, {"x.a.com", "y.b.com"})

                # Subdomain entities roll up to their apex via subdomain_of edges.
                edges = {
                    (row["src"], row["dst"], row["kind"])
                    for row in conn.execute(
                        """SELECT s.value AS src, d.value AS dst, ee.kind
                           FROM entity_edges ee
                           JOIN entities s ON s.id = ee.src_entity_id
                           JOIN entities d ON d.id = ee.dst_entity_id
                           WHERE ee.kind = 'subdomain_of'"""
                    ).fetchall()
                }
                self.assertIn(("x.a.com", "a.com", "subdomain_of"), edges)
                self.assertIn(("y.b.com", "b.com", "subdomain_of"), edges)

                rd = conn.execute(
                    "SELECT registrable_domain FROM entities WHERE kind = 'subdomain' AND value = 'x.a.com'"
                ).fetchone()
                self.assertEqual(rd["registrable_domain"], "a.com")

        # Inline path (finalize_search) populated and counted degree to 2.
        assert_graph()

        # Global recompute rebuilds the identical graph from stored intel only.
        counts = intel_db.rebuild_all_correlation()
        self.assertEqual(counts["searches"], 2)
        self.assertGreaterEqual(counts["observations"], 2)
        assert_graph()

    def test_correlation_denylist_seeds_noise(self) -> None:
        intel_db.save_search(
            {
                "input": "noisy.example",
                "type": "domain",
                "timestamp": "2026-03-03T00:00:00+00:00",
                "ip_details": {},
                "dns": {"NS": ["ns1.cloudflare.com", "ns2.cloudflare.com"]},
                "non_cf_tls_certs": [
                    {"ip": "203.0.113.51", "port": 443, "cn": "noisy.example",
                     "sans": ["localhost"], "sha256": "abc123"}
                ],
            }
        )
        intel_db.rebuild_all_correlation()
        with psycopg.connect(TEST_DATABASE_URL, row_factory=psycopg.rows.dict_row) as conn:
            ns = conn.execute(
                "SELECT attributing FROM selectors WHERE kind = 'nameserver' AND value = 'ns1.cloudflare.com'"
            ).fetchone()
            self.assertIsNotNone(ns)
            self.assertFalse(ns["attributing"])  # boring-NS provider → non-attributing

            san = conn.execute(
                "SELECT attributing FROM selectors WHERE kind = 'tls_san' AND value = 'localhost'"
            ).fetchone()
            self.assertIsNotNone(san)
            self.assertFalse(san["attributing"])  # default/shared-host cert SAN → non-attributing

    def test_sqlite_migration_preserves_ids_and_json(self) -> None:
        fd, sqlite_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            src = sqlite3.connect(sqlite_path)
            src.executescript(
                """
                CREATE TABLE searches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL, type TEXT NOT NULL, timestamp TEXT NOT NULL,
                    cloudflare_fronted INTEGER, raw_json TEXT NOT NULL, source_errors TEXT
                );
                CREATE TABLE ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    search_id INTEGER NOT NULL REFERENCES searches(id),
                    ip TEXT NOT NULL, source TEXT, cloudflare INTEGER, ptr TEXT,
                    asn TEXT, asn_desc TEXT, asn_registry TEXT, country TEXT,
                    network_name TEXT, network_cidr TEXT, proxy_family TEXT,
                    proxy_confidence REAL, observed_at TEXT, port INTEGER
                );
                CREATE TABLE tls_certs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    search_id INTEGER NOT NULL REFERENCES searches(id),
                    ip TEXT NOT NULL, port INTEGER NOT NULL, sni_used TEXT, cn TEXT,
                    sans TEXT, issuer_cn TEXT, issuer_org TEXT, not_before TEXT,
                    not_after TEXT, sha256 TEXT, spki_sha256 TEXT, observed_at TEXT
                );
                CREATE TABLE identifiers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    search_id INTEGER NOT NULL REFERENCES searches(id),
                    id_type TEXT NOT NULL, id_value TEXT NOT NULL, tier TEXT NOT NULL,
                    category TEXT NOT NULL, source TEXT NOT NULL, observed_at TEXT,
                    first_seen TEXT, last_seen TEXT, raw_json TEXT
                );
                CREATE TABLE search_fields (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    search_id INTEGER NOT NULL REFERENCES searches(id),
                    key TEXT NOT NULL, json_value TEXT NOT NULL,
                    UNIQUE(search_id, key)
                );
                """
            )
            src.execute(
                "INSERT INTO searches (id, target, type, timestamp, cloudflare_fronted, raw_json, source_errors)"
                " VALUES (1, 'example.com', 'domain', '2026-01-01T00:00:00+00:00', 0, '', ?)",
                (json.dumps(["crt_sh"]),),
            )
            src.execute(
                "INSERT INTO searches (id, target, type, timestamp, cloudflare_fronted, raw_json)"
                " VALUES (5, 'example.net', 'domain', '2026-01-02T00:00:00+00:00', NULL, '')",
            )
            src.execute(
                "INSERT INTO ips (search_id, ip, source, cloudflare, asn, proxy_confidence, observed_at, port)"
                " VALUES (5, '203.0.113.9', 'dns', 0, '64500', 0.5, '2026-01-02T00:00:00+00:00', 443)",
            )
            src.execute(
                "INSERT INTO tls_certs (search_id, ip, port, cn, sans, sha256)"
                " VALUES (1, '203.0.113.9', 443, 'example.com', ?, 'cafebabe')",
                (json.dumps(["example.com", "www.example.com"]),),
            )
            src.execute(
                "INSERT INTO identifiers (search_id, id_type, id_value, tier, category, source, raw_json)"
                " VALUES (1, 'resolved_ip', '203.0.113.9', 'tier_2', 'infrastructure', 'dns.A', 'null')",
            )
            src.execute(
                "INSERT INTO search_fields (search_id, key, json_value) VALUES (1, 'dns', ?)",
                (json.dumps({"A": ["203.0.113.9"]}),),
            )
            src.commit()
            src.close()

            from pathlib import Path

            total = migrate(Path(sqlite_path), TEST_DATABASE_URL, force=False)
            self.assertEqual(total, 6)

            # IDs (and FK relationships) are preserved.
            self.assertEqual(
                {row["id"] for row in intel_db.get_recent(limit=10)},
                {1, 5},
            )
            matches = intel_db.find_by_ip("203.0.113.9")
            self.assertEqual([match["id"] for match in matches], [5])

            # JSON-text columns landed as parsed JSONB.
            with psycopg.connect(TEST_DATABASE_URL, row_factory=psycopg.rows.dict_row) as conn:
                errors = conn.execute(
                    "SELECT source_errors FROM searches WHERE id = 1"
                ).fetchone()["source_errors"]
                self.assertEqual(errors, ["crt_sh"])
                sans = conn.execute(
                    "SELECT sans FROM tls_certs WHERE search_id = 1"
                ).fetchone()["sans"]
                self.assertEqual(sans, ["example.com", "www.example.com"])

            result = intel_db.get_result(1)
            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result["dns"], {"A": ["203.0.113.9"]})

            # Identity sequences continue after the migrated IDs.
            new_sid = intel_db.create_search("example.org", "domain", "2026-01-03T00:00:00+00:00")
            self.assertGreater(new_sid, 5)
        finally:
            try:
                os.remove(sqlite_path)
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
