from __future__ import annotations

import os
import unittest

import psycopg

import db.intel_db as intel_db
from utils import check
from utils import evidence_meta

DEFAULT_TEST_DATABASE_URL = "postgresql://intel_test:intel_test@127.0.0.1:5433/intel_test"
TEST_DATABASE_URL = os.getenv("TEST_INTEL_DATABASE_URL", DEFAULT_TEST_DATABASE_URL)


def _database_unreachable_reason() -> str | None:
    try:
        with psycopg.connect(TEST_DATABASE_URL, connect_timeout=3):
            return None
    except psycopg.Error as exc:
        return str(exc).strip() or exc.__class__.__name__


class GraphScoringMathTests(unittest.TestCase):
    """Pure scoring math — no database."""

    def test_rarity_decays_with_degree(self) -> None:
        self.assertEqual(check.rarity_weight(2), 1.0)
        self.assertLess(check.rarity_weight(8), check.rarity_weight(3))
        self.assertGreaterEqual(check.rarity_weight(40000), check._RARITY_FLOOR)
        self.assertLess(check.rarity_weight(40000), 0.1)

    def test_time_overlap(self) -> None:
        # Overlapping windows → full credit.
        self.assertEqual(
            check.time_overlap_factor("2026-01-01", "2026-03-01", "2026-02-01", "2026-04-01"), 1.0
        )
        # Years apart → attenuated toward the floor.
        far = check.time_overlap_factor("2020-01-01", "2020-02-01", "2026-01-01", "2026-02-01")
        self.assertLess(far, 0.5)
        self.assertGreaterEqual(far, check._OVERLAP_FLOOR)
        # Unknown windows → full credit.
        self.assertEqual(check.time_overlap_factor(None, None, None, None), 1.0)


class GraphLinkageDbTests(unittest.TestCase):
    _previous_env: str | None = None

    @classmethod
    def setUpClass(cls) -> None:
        reason = _database_unreachable_reason()
        if reason is not None:
            raise unittest.SkipTest(f"PostgreSQL test database unreachable at {TEST_DATABASE_URL} ({reason})")
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

    # ── helpers ──────────────────────────────────────────────────────────
    def _apex_cert_scan(self, domain: str, ip: str, sha256: str, ts: str) -> dict:
        return {
            "input": domain, "type": "domain", "timestamp": ts, "ip_details": {},
            "non_cf_tls_certs": [{
                "ip": ip, "port": 443, "cn": domain, "sans": [domain],
                "not_before": "2026-01-01T00:00:00+00:00", "not_after": "2026-04-01T00:00:00+00:00",
                "sha256": sha256, "spki_sha256": "spki-" + sha256,
            }],
        }

    def _subdomain_cert_scan(self, apex: str, sub: str, ip: str, sha256: str, ts: str) -> dict:
        return {
            "input": apex, "type": "domain", "timestamp": ts, "ip_details": {},
            "subdomains": [sub],
            "subdomain_followups": [{
                "subdomain": sub, "status": "completed",
                "result": self._apex_cert_scan(sub, ip, sha256, ts),
            }],
        }

    def _cdn_scan(self, domain: str, ip: str, ts: str) -> dict:
        return {
            "input": domain, "type": "domain", "timestamp": ts,
            "ip_details": {ip: {"sources": ["dns"], "asn_info": {"asn": "AS13335", "network_cidr": "104.16.0.0/13"}}},
            "dns": {"A": [ip], "NS": ["ns1.cloudflare.com", "ns2.cloudflare.com"]},
        }

    def _shared_ip_scan(self, domain: str, ip: str, ts: str) -> dict:
        return {
            "input": domain, "type": "domain", "timestamp": ts,
            "ip_details": {ip: {"sources": ["dns"], "asn_info": {"asn": "AS64600", "network_cidr": "203.0.113.0/24"}}},
            "dns": {"A": [ip]},
        }

    # ── acceptance criteria ──────────────────────────────────────────────
    def test_apex_to_apex_shared_leaf_cert(self) -> None:
        intel_db.save_search(self._apex_cert_scan("a.com", "203.0.113.1", "rarecert", "2026-03-01T00:00:00+00:00"))
        intel_db.save_search(self._apex_cert_scan("b.com", "203.0.113.2", "rarecert", "2026-03-02T00:00:00+00:00"))

        link = check.link_evidence("a.com", "b.com")
        self.assertEqual(link["strength"], "strong")
        cert_ev = [e for e in link["evidence"] if e["kind"] == "tls_cert_sha256"]
        self.assertEqual(len(cert_ev), 1)
        self.assertEqual(cert_ev[0]["value"], "rarecert")
        self.assertEqual(cert_ev[0]["degree"], 2)

    def test_transitive_subdomain_cert_links_apexes(self) -> None:
        intel_db.save_search(self._subdomain_cert_scan("a.com", "x.a.com", "203.0.113.10", "sharedleaf", "2026-03-01T00:00:00+00:00"))
        intel_db.save_search(self._subdomain_cert_scan("b.com", "y.b.com", "203.0.113.11", "sharedleaf", "2026-03-02T00:00:00+00:00"))
        intel_db.rebuild_all_correlation()  # global recompute resolves the apex rollup

        # Same code path as the apex test, keyed on registrable domains.
        link = check.link_evidence("a.com", "b.com")
        self.assertEqual(link["strength"], "strong")
        cert_ev = [e for e in link["evidence"] if e["kind"] == "tls_cert_sha256" and e["value"] == "sharedleaf"]
        self.assertEqual(len(cert_ev), 1)
        self.assertIsNotNone(cert_ev[0]["window_a"][0])  # provenance window present

    def test_lake_global_pivot_across_separate_batches(self) -> None:
        # Batch 1, earlier.
        intel_db.save_search(self._apex_cert_scan("old.com", "203.0.113.20", "campaigncert", "2026-01-01T00:00:00+00:00"))
        # Batch 2, separate ingest, no shared case/collection.
        intel_db.save_search(self._apex_cert_scan("new.com", "203.0.113.21", "campaigncert", "2026-05-01T00:00:00+00:00"))

        links = check.links_for("new.com")
        targets = {link["target"] for link in links}
        self.assertIn("old.com", targets)
        old_link = next(link for link in links if link["target"] == "old.com")
        self.assertTrue(any(e["kind"] == "tls_cert_sha256" for e in old_link["evidence"]))

    def test_noise_shared_cdn_ip_and_nameserver_do_not_link(self) -> None:
        for i in range(3):
            intel_db.save_search(self._cdn_scan(f"unrelated{i}.com", "104.16.1.1", "2026-03-01T00:00:00+00:00"))
        intel_db.rebuild_all_correlation()  # seeds the denylist (CDN ASN, boring NS)

        link = check.link_evidence("unrelated0.com", "unrelated1.com")
        self.assertEqual(link["score"], 0.0)
        self.assertEqual(link["evidence"], [])
        # The shared CDN IP exists in the graph but is non-attributing.
        shared = intel_db.shared_ips_between("unrelated0.com", "unrelated1.com")
        self.assertTrue(shared)
        self.assertTrue(shared[0]["noisy_net"])

    def test_global_clustering_groups_linked_domains(self) -> None:
        intel_db.save_search(self._apex_cert_scan("a.com", "203.0.113.1", "rarecert", "2026-03-01T00:00:00+00:00"))
        intel_db.save_search(self._apex_cert_scan("b.com", "203.0.113.2", "rarecert", "2026-03-02T00:00:00+00:00"))
        intel_db.save_search(self._apex_cert_scan("c.com", "203.0.113.3", "loner", "2026-03-03T00:00:00+00:00"))
        intel_db.rebuild_all_correlation()  # global recompute rebuilds clusters too

        a_cluster = intel_db.graph_cluster_for("a.com")
        self.assertIsNotNone(a_cluster)
        self.assertEqual(set(a_cluster["members"]), {"a.com", "b.com"})
        self.assertEqual(
            intel_db.graph_cluster_for("a.com")["cluster_id"],
            intel_db.graph_cluster_for("b.com")["cluster_id"],
        )
        # An unrelated domain sharing nothing is in no cluster.
        self.assertIsNone(intel_db.graph_cluster_for("c.com"))

        clusters = intel_db.list_graph_clusters()
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["component_size"], 2)

    def test_global_clustering_excludes_noise(self) -> None:
        for i in range(3):
            intel_db.save_search(self._cdn_scan(f"noise{i}.com", "104.16.1.1", "2026-03-01T00:00:00+00:00"))
        intel_db.rebuild_all_correlation()
        # CDN IP is noisy and the nameserver is denylisted → no cluster forms.
        self.assertIsNone(intel_db.graph_cluster_for("noise0.com"))
        self.assertEqual(intel_db.list_graph_clusters(), [])

    def test_shared_ip_evidence_carries_real_source(self) -> None:
        intel_db.save_search(self._shared_ip_scan("a.com", "203.0.113.99", "2026-03-01T00:00:00+00:00"))
        intel_db.save_search(self._shared_ip_scan("b.com", "203.0.113.99", "2026-03-02T00:00:00+00:00"))

        link = check.link_evidence("a.com", "b.com")
        ip_nodes = [e for e in link["evidence"] if e["node_type"] == "ip"]
        self.assertEqual(len(ip_nodes), 1)
        self.assertEqual(ip_nodes[0]["value"], "203.0.113.99")
        self.assertEqual(ip_nodes[0]["degree"], 2)
        # Provenance is the actual resolution source, not a generic placeholder.
        self.assertIn("dns_a", ip_nodes[0]["sources"])
        self.assertNotIn("resolves_to", ip_nodes[0]["sources"])

    def test_link_evidence_self_is_not_a_link(self) -> None:
        intel_db.save_search(self._apex_cert_scan("a.com", "203.0.113.1", "rarecert", "2026-03-01T00:00:00+00:00"))
        link = check.link_evidence("a.com", "a.com")
        self.assertTrue(link.get("self"))
        self.assertEqual(link["score"], 0.0)
        self.assertEqual(link["evidence"], [])

    def test_pool_listing_and_browse_by_edge(self) -> None:
        intel_db.save_search(self._apex_cert_scan("a.com", "203.0.113.1", "rarecert", "2026-03-01T00:00:00+00:00"))
        intel_db.save_search(self._apex_cert_scan("b.com", "203.0.113.2", "rarecert", "2026-03-02T00:00:00+00:00"))
        intel_db.rebuild_all_correlation()

        pool = {row["domain"] for row in intel_db.list_pool_domains()}
        self.assertIn("a.com", pool)
        self.assertIn("b.com", pool)

        # Browse by edge type: the shared cert groups a.com + b.com together.
        groups = intel_db.domains_by_selector(kind="tls_cert_sha256")
        cert_group = next(g for g in groups if g["value"] == "rarecert")
        self.assertEqual(set(cert_group["domains"]), {"a.com", "b.com"})

        kinds = {row["kind"] for row in intel_db.selector_kind_counts()}
        self.assertIn("tls_cert_sha256", kinds)

        # A single-domain selector (only one registrable domain) is not a group.
        self.assertEqual(
            [g for g in intel_db.domains_by_selector(kind="favicon_mmh3")], []
        )

    def test_connections_among_selected_set(self) -> None:
        intel_db.save_search(self._apex_cert_scan("a.com", "203.0.113.1", "rarecert", "2026-03-01T00:00:00+00:00"))
        intel_db.save_search(self._apex_cert_scan("b.com", "203.0.113.2", "rarecert", "2026-03-02T00:00:00+00:00"))
        intel_db.save_search(self._apex_cert_scan("c.com", "203.0.113.3", "loner", "2026-03-03T00:00:00+00:00"))

        result = check.connections_among(["a.com", "b.com", "c.com"])
        self.assertEqual(set(result["domains"]), {"a.com", "b.com", "c.com"})
        self.assertEqual(len(result["pairs"]), 3)  # 3 choose 2
        self.assertEqual(result["connected_pair_count"], 1)  # only a.com<->b.com
        top = result["pairs"][0]
        self.assertEqual({top["a"], top["b"]}, {"a.com", "b.com"})
        self.assertTrue(top["connected"])

    def test_recompute_free_rescore_on_weight_change(self) -> None:
        intel_db.save_search(self._apex_cert_scan("a.com", "203.0.113.1", "rarecert", "2026-03-01T00:00:00+00:00"))
        intel_db.save_search(self._apex_cert_scan("b.com", "203.0.113.2", "rarecert", "2026-03-02T00:00:00+00:00"))

        before = check.link_evidence("a.com", "b.com")["score"]
        original = dict(evidence_meta.SELECTOR_BASE_WEIGHTS)
        try:
            evidence_meta.SELECTOR_BASE_WEIGHTS["tls_cert_sha256"] = original["tls_cert_sha256"] / 2
            after = check.link_evidence("a.com", "b.com")["score"]
        finally:
            evidence_meta.SELECTOR_BASE_WEIGHTS.clear()
            evidence_meta.SELECTOR_BASE_WEIGHTS.update(original)
        # Halving the cert base weight (100→50) drops the link score by exactly
        # the cert's contribution (rarity=overlap=1), purely from the edit — no
        # rescan or re-ingest.
        self.assertAlmostEqual(before - after, 50.0, places=1)


if __name__ == "__main__":
    unittest.main()
