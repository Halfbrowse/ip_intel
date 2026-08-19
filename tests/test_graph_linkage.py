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


class ProjectionTests(unittest.TestCase):
    """What extract_selectors pulls out of a stored result — no database.

    Covers the raw sources added after the projection was first written (WHOIS
    registrant identity, SPF origins, historical DNS), which were all being
    stored and then ignored.
    """

    @staticmethod
    def _project(result: dict) -> dict:
        base = {"input": "example.com", "type": "domain", "timestamp": "2026-08-01T00:00:00+00:00"}
        return intel_db.extract_selectors({**base, **result})

    def _obs(self, result: dict, kind: str) -> list[dict]:
        return [o for o in self._project(result)["observations"] if o["kind"] == kind]

    # ── WHOIS registrant identity ──
    def test_registrant_email_lands_on_contact_email(self) -> None:
        obs = self._obs({"whois": {"emails": ["Admin@Operator.example"]}}, "contact_email")
        self.assertEqual([o["value"] for o in obs], ["admin@operator.example"])
        # Provenance is what distinguishes it from an imprint-page address;
        # the selector itself is deliberately shared so the two can match.
        self.assertEqual(obs[0]["source"], "whois")

    def test_registrant_email_accepts_a_bare_string(self) -> None:
        # python-whois returns either a string or a list for this field.
        obs = self._obs({"whois": {"emails": "solo@operator.example"}}, "contact_email")
        self.assertEqual([o["value"] for o in obs], ["solo@operator.example"])

    def test_redacted_and_registrar_emails_are_dropped(self) -> None:
        obs = self._obs(
            {"whois": {"emails": [
                "REDACTED FOR PRIVACY",
                "abuse@namecheap.com",          # registrar role address
                "owner@operator.example",
            ]}},
            "contact_email",
        )
        self.assertEqual([o["value"] for o in obs], ["owner@operator.example"])

    def test_registrant_name_lands_on_legal_entity(self) -> None:
        obs = self._obs({"whois": {"name": "Operator  Holdings BV"}}, "legal_entity")
        # Case-folded and whitespace-collapsed by _normalize_generic_identifier,
        # so the same company registered under different casing in WHOIS and on
        # an imprint page still lands on one selector.
        self.assertEqual([o["value"] for o in obs], ["operator holdings bv"])
        self.assertEqual(obs[0]["source"], "whois")

    def test_redacted_registrant_name_is_dropped(self) -> None:
        self.assertEqual(self._obs({"whois": {"name": "Data Protected"}}, "legal_entity"), [])

    def test_whois_error_blocks_registrant_projection(self) -> None:
        result = {"whois": {"error": "lookup failed", "emails": ["x@operator.example"]}}
        self.assertEqual(self._obs(result, "contact_email"), [])

    # ── SPF origins ──
    def test_spf_origin_prefers_cidr_over_ip(self) -> None:
        obs = self._obs(
            {"spf_origins": [{"ip": "203.0.113.7", "cidr": "203.0.113.0/24"},
                             {"ip": "198.51.100.9"}]},
            "spf_origin",
        )
        self.assertEqual([o["value"] for o in obs], ["203.0.113.0/24", "198.51.100.9"])

    # ── Historical DNS ──
    def test_historical_a_records_become_dated_resolves_edges(self) -> None:
        edges = self._project({"historical_dns": {"records": [
            {"rrtype": "A", "rdata": "203.0.113.7",
             "first_seen": "2019-01-01T00:00:00+00:00", "last_seen": "2019-06-01T00:00:00+00:00"},
            {"rrtype": "MX", "rdata": "mail.other.example"},
        ]}})["edges"]
        historical = [e for e in edges if e["source"] == "historical_dns"]
        self.assertEqual(len(historical), 1, "only A/AAAA records should become resolves_to edges")
        self.assertEqual(historical[0]["dst"], "203.0.113.7")
        self.assertEqual(historical[0]["kind"], "resolves_to")
        # The record's own window, not the scan timestamp — this is what lets
        # recency_weight discount an old co-location for its real age.
        self.assertTrue(historical[0]["last_seen"].startswith("2019-06-01"))

    def test_historical_edge_scores_below_an_identical_current_one(self) -> None:
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        current = check.recency_weight(now)
        historical = check.recency_weight(now - timedelta(days=365 * 7))
        self.assertEqual(current, 1.0)
        self.assertLess(historical, current / 2)

    # ── Every emitted kind must be renderable ──
    def test_new_kinds_have_a_weight_and_an_explanation(self) -> None:
        for kind in ("contact_email", "legal_entity", "spf_origin"):
            self.assertGreater(evidence_meta.selector_base_weight(kind), 0, kind)
            self.assertIsNotNone(check._explain_selector(kind, None), kind)


class BatchedWriteFoldingTests(unittest.TestCase):
    """The Python-side fold that the batched projection writers depend on.

    Postgres refuses an ON CONFLICT DO UPDATE that would touch one row twice in
    a single statement, so duplicates within a batch have to be merged before
    they are sent — and the merge has to agree with the LEAST/GREATEST the
    single-row upserts used, or reprojecting would quietly narrow observation
    windows instead of widening them.
    """

    def test_folds_to_the_widest_window(self) -> None:
        window = intel_db._merge_window(None, "2026-03-01", "2026-03-02")
        window = intel_db._merge_window(window, "2026-01-01", "2026-01-15")
        window = intel_db._merge_window(window, "2026-06-01", "2026-07-01")
        self.assertEqual(window, ("2026-01-01", "2026-07-01"))

    def test_null_means_no_opinion_not_a_minimum(self) -> None:
        # LEAST/GREATEST ignore NULL rather than treating it as smallest, so a
        # timestamp-less observation must not erase a known window. This is the
        # reason the fold cannot just be min()/max().
        self.assertEqual(
            intel_db._merge_window(("2026-03-01", "2026-03-02"), None, None),
            ("2026-03-01", "2026-03-02"),
        )
        self.assertEqual(intel_db._merge_window((None, None), "2026-03-01", None), ("2026-03-01", None))
        self.assertEqual(intel_db._merge_window(None, None, None), (None, None))


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
        # The cluster carries *what* connects it: the shared cert both members exhibit.
        self.assertEqual(a_cluster["link_count"], len(a_cluster["links"]))
        cert = next(l for l in a_cluster["links"] if l["kind"] == "tls_cert_sha256")
        self.assertEqual(cert["node_type"], "selector")
        self.assertEqual(cert["value"], "rarecert")
        self.assertEqual(cert["member_count"], 2)
        # An unrelated domain sharing nothing is in no cluster.
        self.assertIsNone(intel_db.graph_cluster_for("c.com"))

        clusters = intel_db.list_graph_clusters()
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["component_size"], 2)
        # The list view previews the connectors too.
        self.assertIn(("tls_cert_sha256", "rarecert"), [(l["kind"], l["value"]) for l in clusters[0]["links"]])
        self.assertEqual(clusters[0]["link_count"], len(clusters[0]["links"]))
        # Connectors are ordered strongest (most members) first.
        counts = [l["member_count"] for l in clusters[0]["links"]]
        self.assertEqual(counts, sorted(counts, reverse=True))

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

    def test_domain_profile_shows_intel_without_connections(self) -> None:
        # A lone channel with no shared evidence still has a full profile.
        intel_db.save_search({
            "input": "lonely.com", "type": "domain", "timestamp": "2026-03-01T00:00:00+00:00",
            "ip_details": {"203.0.113.7": {"sources": ["dns"], "asn_info": {"asn": "AS64600"}}},
            "dns": {"A": ["203.0.113.7"], "NS": ["ns1.registrar.example"]},
            "whois": {"registrar": "Reg Inc", "org": "Lonely Org"},
            "subdomains": ["api.lonely.com"],
            "non_cf_tls_certs": [{"ip": "203.0.113.7", "cn": "lonely.com", "sans": ["lonely.com"], "sha256": "uniquecert"}],
            "page_metadata": {"google_analytics": ["UA-LONE"], "favicon_mmh3": "12345"},
        })

        profile = intel_db.domain_profile("lonely.com")
        self.assertIsNotNone(profile)
        self.assertEqual(profile["domain"], "lonely.com")
        self.assertIn("lonely.com", {h["value"] for h in profile["hosts"]})
        self.assertIn("203.0.113.7", {ip["ip"] for ip in profile["ips"]})
        kinds = {s["kind"] for s in profile["selectors"]}
        self.assertIn("tls_cert_sha256", kinds)
        self.assertIn("tracking_id", kinds)
        # Raw gathered intel is present even though the domain links to nothing.
        self.assertEqual(profile["intel"]["whois"]["registrar"], "Reg Inc")
        self.assertEqual(profile["intel"]["dns"]["A"], ["203.0.113.7"])
        self.assertIn("api.lonely.com", profile["intel"]["subdomains"])
        self.assertEqual(profile["intel"]["tls_certs"][0]["sha256"], "uniquecert")
        # And it has no connections.
        self.assertEqual(check.links_for("lonely.com"), [])

    def test_domain_profile_unknown_returns_none(self) -> None:
        self.assertIsNone(intel_db.domain_profile("never-seen.example"))

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
        # Halving the cert base weight drops the link score by exactly the half
        # it removed (rarity = overlap = 1 for a cert on two domains), purely
        # from the edit — no rescan or re-ingest. Derived from the live weight
        # rather than written out, so retuning tls_cert_sha256 cannot silently
        # turn this into a failure about a number instead of the behaviour.
        self.assertAlmostEqual(before - after, original["tls_cert_sha256"] / 2, places=1)

    # ── multi-hop path precompute (graph_paths) ───────────────────────────

    def _chain_fixture(self) -> None:
        # a.com <-cert-ab-> b.com <-cert-bc-> c.com, a.com and c.com share
        # nothing directly. d.com is fully disconnected.
        intel_db.save_search(self._apex_cert_scan("a.com", "203.0.113.1", "cert-ab", "2026-03-01T00:00:00+00:00"))
        intel_db.save_search(self._apex_cert_scan("b.com", "203.0.113.2", "cert-ab", "2026-03-02T00:00:00+00:00"))
        intel_db.save_search(self._apex_cert_scan("b.com", "203.0.113.3", "cert-bc", "2026-03-03T00:00:00+00:00"))
        intel_db.save_search(self._apex_cert_scan("c.com", "203.0.113.4", "cert-bc", "2026-03-04T00:00:00+00:00"))
        intel_db.save_search(self._apex_cert_scan("d.com", "203.0.113.5", "loner-d", "2026-03-05T00:00:00+00:00"))
        intel_db.rebuild_all_correlation()

    def test_path_between_precomputed_multihop_chain(self) -> None:
        self._chain_fixture()
        # No direct evidence between a.com and c.com.
        self.assertEqual(check.link_evidence("a.com", "c.com")["score"], 0.0)

        path = intel_db.path_between("a.com", "c.com")
        self.assertIsNotNone(path)
        self.assertEqual(path["hops"], 2)
        chain = path["chain"]
        self.assertEqual(len(chain), 2)
        self.assertEqual((chain[0]["from"], chain[0]["to"]), ("a.com", "b.com"))
        self.assertEqual((chain[1]["from"], chain[1]["to"]), ("b.com", "c.com"))
        self.assertTrue(any(e["value"] == "cert-ab" for e in chain[0]["evidence"]))
        self.assertTrue(any(e["value"] == "cert-bc" for e in chain[1]["evidence"]))

        # A direct (1-hop) pair is in graph_paths too — it's a superset of graph_links.
        direct = intel_db.path_between("a.com", "b.com")
        self.assertEqual(direct["hops"], 1)

        # Fully disconnected domain: no row at all.
        self.assertIsNone(intel_db.path_between("a.com", "d.com"))
        # Same domain on both sides is never a path.
        self.assertIsNone(intel_db.path_between("a.com", "a.com"))

    def test_path_between_respects_max_hops_env(self) -> None:
        previous = os.environ.get("GRAPH_PATH_MAX_HOPS")
        os.environ["GRAPH_PATH_MAX_HOPS"] = "1"
        try:
            self._chain_fixture()
            # c.com is 2 hops out — beyond the configured cap.
            self.assertIsNone(intel_db.path_between("a.com", "c.com"))
            # b.com is still 1 hop out — within the cap.
            self.assertEqual(intel_db.path_between("a.com", "b.com")["hops"], 1)
        finally:
            if previous is None:
                os.environ.pop("GRAPH_PATH_MAX_HOPS", None)
            else:
                os.environ["GRAPH_PATH_MAX_HOPS"] = previous

    def test_related_through_includes_direct_and_multihop(self) -> None:
        self._chain_fixture()
        related = intel_db.related_through("a.com")
        by_target = {row["target"]: row for row in related}
        self.assertEqual(by_target["b.com"]["hops"], 1)
        self.assertEqual(by_target["c.com"]["hops"], 2)
        self.assertNotIn("d.com", by_target)
        # Shortest hop count sorts first.
        self.assertEqual([row["target"] for row in related][:2], ["b.com", "c.com"])

        one_hop_only = intel_db.related_through("a.com", max_hops=1)
        self.assertEqual({row["target"] for row in one_hop_only}, {"b.com"})

    def test_search_targets_matches_domain_and_selector(self) -> None:
        self._chain_fixture()
        by_domain = intel_db.search_targets("a.co")
        self.assertIn("a.com", {row["domain"] for row in by_domain["domains"]})

        by_selector = intel_db.search_targets("cert-ab")
        selector_hit = next(row for row in by_selector["selectors"] if row["value"] == "cert-ab")
        self.assertEqual(selector_hit["kind"], "tls_cert_sha256")
        self.assertEqual(set(selector_hit["sample_domains"]), {"a.com", "b.com"})

        empty = intel_db.search_targets("")
        self.assertEqual(empty, {"query": "", "domains": [], "selectors": []})


if __name__ == "__main__":
    unittest.main()
