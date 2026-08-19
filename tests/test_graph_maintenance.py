"""Continuous graph maintenance: tier scheduling, degree-staleness expansion,
and the incremental rescore path.

The classes that need PostgreSQL skip themselves when it is unreachable, the
same way tests/test_graph_linkage.py does. Everything that can be checked
without a database (which tier a tick picks, which nodes get expanded into a
rescore set, what happens when the rebuild lock is held) is checked against a
recording fake connection instead, so the control flow is covered even where
the SQL cannot be executed.
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

import psycopg

import db.intel_db as intel_db
from utils import check

DEFAULT_TEST_DATABASE_URL = "postgresql://intel_test:intel_test@127.0.0.1:5433/intel_test"
TEST_DATABASE_URL = os.getenv("TEST_INTEL_DATABASE_URL", DEFAULT_TEST_DATABASE_URL)


def _database_unreachable_reason() -> str | None:
    try:
        with psycopg.connect(TEST_DATABASE_URL, connect_timeout=3):
            return None
    except psycopg.Error as exc:
        return str(exc).strip() or exc.__class__.__name__


class _FakeCursor:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


class _FakeConn:
    """Records SQL and answers it from substring-keyed canned rows."""

    def __init__(self, answers: list[tuple[str, list[dict]]] | None = None) -> None:
        self.answers = answers or []
        self.executed: list[tuple[str, object]] = []

    def execute(self, sql, params=None):
        self.executed.append((" ".join(str(sql).split()), params))
        for needle, rows in self.answers:
            if needle in " ".join(str(sql).split()):
                return _FakeCursor(rows)
        return _FakeCursor([])

    def cursor(self):
        return self

    def executemany(self, sql, rows):
        self.executed.append((" ".join(str(sql).split()), list(rows)))

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def sql_matching(self, needle: str) -> list[tuple[str, object]]:
        return [entry for entry in self.executed if needle in entry[0]]


class MaintenanceTierTests(unittest.TestCase):
    """Which of the three tiers a maintenance tick picks."""

    def _run(self, state: dict, **env: str) -> dict:
        patches = {
            "rebuild_all_correlation": mock.Mock(return_value={"searches": 7}),
            "rebuild_clusters": mock.Mock(return_value={"clusters": 3}),
            "apply_pending_graph_rescores": mock.Mock(return_value={"rescored_domains": 2}),
            "graph_maintenance_state": mock.Mock(return_value=state),
        }
        with mock.patch.dict(os.environ, env), mock.patch.multiple(intel_db, **patches):
            result = intel_db.run_graph_maintenance()
        self.calls = {name: patch for name, patch in patches.items()}
        return result

    def test_full_reconcile_wins_when_due(self) -> None:
        result = self._run(
            {"dirty": True, "pending": 40, "since_clean": 99999.0, "since_full": 90000.0}
        )
        self.assertEqual(result["tier"], "full_reconcile")
        self.assertEqual(result["searches"], 7)
        # A reconcile reprojects and rescores everything, so neither cheaper
        # tier should also run in the same tick.
        self.calls["rebuild_clusters"].assert_not_called()
        self.calls["apply_pending_graph_rescores"].assert_not_called()

    def test_full_reconcile_schedule_can_be_disabled(self) -> None:
        result = self._run(
            {"dirty": False, "pending": 0, "since_clean": 10.0, "since_full": 10_000_000.0},
            GRAPH_FULL_RECONCILE_INTERVAL="0",
        )
        self.assertEqual(result["tier"], "idle")
        self.calls["rebuild_all_correlation"].assert_not_called()

    def test_cluster_rebuild_when_dirty_and_interval_elapsed(self) -> None:
        result = self._run(
            {"dirty": True, "pending": 5, "since_clean": 1000.0, "since_full": 10.0}
        )
        self.assertEqual(result["tier"], "clusters")
        self.calls["apply_pending_graph_rescores"].assert_not_called()

    def test_incremental_between_cluster_rebuilds(self) -> None:
        result = self._run(
            {"dirty": True, "pending": 5, "since_clean": 30.0, "since_full": 10.0}
        )
        self.assertEqual(result["tier"], "incremental")
        self.assertEqual(result["rescored_domains"], 2)
        self.calls["rebuild_clusters"].assert_not_called()

    def test_idle_tick_does_no_work(self) -> None:
        result = self._run(
            {"dirty": False, "pending": 0, "since_clean": 30.0, "since_full": 10.0}
        )
        self.assertEqual(result, {"tier": "idle"})
        for patch in self.calls.values():
            if patch is not self.calls["graph_maintenance_state"]:
                patch.assert_not_called()


class InvalidationHookTests(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = list(intel_db._GRAPH_INVALIDATION_HOOKS)
        intel_db._GRAPH_INVALIDATION_HOOKS.clear()

    def tearDown(self) -> None:
        intel_db._GRAPH_INVALIDATION_HOOKS[:] = self._saved

    def test_hook_receives_scope_and_domains(self) -> None:
        seen: list[tuple[str, tuple[str, ...]]] = []
        intel_db.register_graph_invalidation_hook(lambda scope, domains: seen.append((scope, domains)))
        intel_db._notify_graph_invalidation("domains", ["b.com", "a.com"])
        intel_db._notify_graph_invalidation("all")
        self.assertEqual(seen, [("domains", ("b.com", "a.com")), ("all", ())])

    def test_registration_is_idempotent(self) -> None:
        hook = lambda scope, domains: None  # noqa: E731
        intel_db.register_graph_invalidation_hook(hook)
        intel_db.register_graph_invalidation_hook(hook)
        self.assertEqual(len(intel_db._GRAPH_INVALIDATION_HOOKS), 1)

    def test_failing_hook_never_propagates(self) -> None:
        def boom(scope, domains):
            raise RuntimeError("redis is down")

        calls: list[str] = []
        intel_db.register_graph_invalidation_hook(boom)
        intel_db.register_graph_invalidation_hook(lambda scope, domains: calls.append(scope))
        intel_db._notify_graph_invalidation("all")
        self.assertEqual(calls, ["all"])


class AffectedDomainExpansionTests(unittest.TestCase):
    """The degree-staleness expansion — what a write drags in for rescore."""

    def test_noise_only_touch_expands_to_nothing(self) -> None:
        conn = _FakeConn()
        touch = intel_db.CorrelationTouch(
            selector_ids={1, 2, 3},
            rescore_selector_ids=set(),
            rescore_ip_entity_ids=set(),
            registrable_domains={"a.com"},
        )
        affected = intel_db._affected_registrable_domains(conn, touch)
        self.assertEqual(affected, {"a.com"})
        # A selector that was noise before and after moves nobody's score, so
        # the expansion must not even go looking for its co-sharers — that is
        # what keeps a 40,000-domain nameserver free.
        self.assertEqual(conn.executed, [])

    def test_scoring_selectors_and_ips_pull_in_co_sharers(self) -> None:
        conn = _FakeConn(
            [
                ("FROM observations o", [{"rd": "b.com"}, {"rd": "c.com"}]),
                ("FROM entity_edges ee", [{"rd": "d.com"}]),
            ]
        )
        touch = intel_db.CorrelationTouch(
            selector_ids={1},
            rescore_selector_ids={1},
            rescore_ip_entity_ids={9},
            registrable_domains={"a.com"},
        )
        affected = intel_db._affected_registrable_domains(conn, touch)
        self.assertEqual(affected, {"a.com", "b.com", "c.com", "d.com"})
        self.assertEqual(len(conn.sql_matching("FROM observations o")), 1)
        self.assertEqual(len(conn.sql_matching("resolves_to")), 1)


class DenylistDegreeRuleTests(unittest.TestCase):
    """Which selectors the degree rule is allowed to discard."""

    def _degree_rule(self, conn: _FakeConn) -> tuple[str, object]:
        matches = [
            (sql, params)
            for sql, params in conn.executed
            if "attributing = FALSE" in sql and "entity_count >" in sql
        ]
        self.assertEqual(len(matches), 1, "expected exactly one degree rule")
        return matches[0]

    def test_account_bound_kinds_get_the_higher_ceiling(self) -> None:
        conn = _FakeConn([("count(*) AS n", [{"n": 0}])])
        with mock.patch.dict(
            os.environ,
            {
                "CORRELATION_DEGREE_THRESHOLD": "50",
                "CORRELATION_ACCOUNT_DEGREE_THRESHOLD": "500",
            },
        ):
            intel_db.seed_denylist(conn)
        sql, params = self._degree_rule(conn)
        self.assertIn("site_verification", sql)
        # A verification code proves control of one webmaster account, so a
        # broadcaster running it across its whole network must not be discarded
        # as shared infrastructure the way a CDN ASN is.
        self.assertEqual(
            list(params), [["adsense_publisher", "ga_property"], 500, 50]
        )

    def test_infrastructure_kinds_keep_the_strict_ceiling(self) -> None:
        # The CASE has to fall through to the strict threshold for everything
        # else — an exemption that leaked to nameservers or ASNs would readmit
        # the 40,000-domain hubs the rule exists to remove.
        conn = _FakeConn([("count(*) AS n", [{"n": 0}])])
        intel_db.seed_denylist(conn)
        sql, _ = self._degree_rule(conn)
        self.assertIn("ELSE %s END", sql)
        for kind in ("nameserver", "asn", "tls_san", "shared_ip"):
            self.assertNotIn(f"'{kind}'", sql.split("CASE")[1].split("END")[0])


class IncrementalRescoreControlFlowTests(unittest.TestCase):
    def test_empty_queue_scores_nothing(self) -> None:
        conn = _FakeConn([("SELECT dirty_domains", [{"dirty_domains": []}])])
        with mock.patch.object(intel_db, "init_db"), \
             mock.patch.object(intel_db, "_conn", return_value=conn), \
             mock.patch.object(check, "links_for") as links_for:
            result = intel_db.apply_pending_graph_rescores()
        links_for.assert_not_called()
        self.assertEqual(result["rescored_domains"], 0)

    def test_defers_while_a_full_rebuild_holds_the_lock(self) -> None:
        conn = _FakeConn(
            [
                ("SELECT dirty_domains", [{"dirty_domains": ["a.com", "b.com"]}]),
                ("pg_try_advisory_xact_lock", [{"locked": False}]),
            ]
        )
        with mock.patch.object(intel_db, "init_db"), \
             mock.patch.object(intel_db, "_conn", return_value=conn), \
             mock.patch.object(check, "links_for", return_value=[]):
            result = intel_db.apply_pending_graph_rescores()
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(result["pending"], 2)
        # Nothing was written and, crucially, the queue was not drained — the
        # next tick retries the same domains.
        self.assertEqual(conn.sql_matching("DELETE FROM graph_links"), [])
        self.assertEqual(conn.sql_matching("SET dirty_domains"), [])

    def test_patches_only_the_batch_and_drains_exactly_it(self) -> None:
        conn = _FakeConn(
            [
                ("SELECT dirty_domains", [{"dirty_domains": ["b.com", "a.com"]}]),
                ("pg_try_advisory_xact_lock", [{"locked": True}]),
            ]
        )
        link = {
            "target": "z.com", "score": 42.0, "confidence": 70, "strength": "moderate",
            "shared_node_count": 1, "evidence": [{"kind": "tls_cert_sha256"}],
        }
        with mock.patch.object(intel_db, "init_db"), \
             mock.patch.object(intel_db, "_conn", return_value=conn), \
             mock.patch.object(check, "links_for", return_value=[link]):
            result = intel_db.apply_pending_graph_rescores()
        self.assertEqual(result, {"rescored_domains": 2, "links": 2, "pending": 0})
        deletes = conn.sql_matching("DELETE FROM graph_links")
        self.assertEqual(len(deletes), 1)
        self.assertEqual(deletes[0][1], (["a.com", "b.com"],))
        drain = conn.sql_matching("SET dirty_domains")
        self.assertEqual(len(drain), 1)
        self.assertEqual(drain[0][1], (["a.com", "b.com"],))


class ContinuousGraphDbTests(unittest.TestCase):
    """End-to-end: a save keeps the graph current without a manual recompute."""

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

    def _cert_scan(self, domain: str, ip: str, sha256: str, ts: str) -> dict:
        return {
            "input": domain, "type": "domain", "timestamp": ts, "ip_details": {},
            "non_cf_tls_certs": [{
                "ip": ip, "port": 443, "cn": domain, "sans": [domain],
                "not_before": "2026-01-01T00:00:00+00:00", "not_after": "2026-04-01T00:00:00+00:00",
                "sha256": sha256, "spki_sha256": "spki-" + sha256,
            }],
        }

    def _stored_score(self, a: str, b: str) -> float | None:
        with psycopg.connect(TEST_DATABASE_URL, row_factory=psycopg.rows.dict_row) as conn:
            row = conn.execute(
                "SELECT score FROM graph_links WHERE registrable_domain = %s AND target = %s", (a, b)
            ).fetchone()
        return None if row is None else float(row["score"])

    def test_save_queues_its_neighbourhood_and_rescore_materializes_links(self) -> None:
        intel_db.save_search(self._cert_scan("alpha.com", "203.0.113.10", "cert-a", "2026-02-01T00:00:00+00:00"))
        intel_db.save_search(self._cert_scan("beta.com", "203.0.113.11", "cert-a", "2026-02-02T00:00:00+00:00"))

        state = intel_db.graph_maintenance_state()
        # beta's save must have queued alpha too: they share the certificate
        # whose degree just changed.
        self.assertGreaterEqual(state["pending"], 2)

        applied = intel_db.apply_pending_graph_rescores()
        self.assertGreaterEqual(applied["rescored_domains"], 2)
        self.assertEqual(intel_db.graph_maintenance_state()["pending"], 0)
        self.assertIsNotNone(self._stored_score("alpha.com", "beta.com"))
        self.assertIsNotNone(self._stored_score("beta.com", "alpha.com"))

    def test_third_domain_restates_the_first_pairs_score(self) -> None:
        """The degree-staleness case: a later, unrelated save shares the same
        certificate, so the original pair's rarity — and therefore its stored
        score — must come down without anyone touching those two domains."""
        intel_db.save_search(self._cert_scan("alpha.com", "203.0.113.10", "cert-a", "2026-02-01T00:00:00+00:00"))
        intel_db.save_search(self._cert_scan("beta.com", "203.0.113.11", "cert-a", "2026-02-02T00:00:00+00:00"))
        intel_db.apply_pending_graph_rescores()
        before = self._stored_score("alpha.com", "beta.com")
        self.assertIsNotNone(before)

        intel_db.save_search(self._cert_scan("gamma.com", "203.0.113.12", "cert-a", "2026-02-03T00:00:00+00:00"))
        intel_db.apply_pending_graph_rescores()
        after = self._stored_score("alpha.com", "beta.com")
        self.assertIsNotNone(after)
        self.assertLess(after, before)

    def test_full_reconcile_agrees_with_the_incremental_path(self) -> None:
        """The reconcile is only a safety net if it lands on the same numbers —
        a systematic disagreement would mean the incremental path is wrong."""
        for i, name in enumerate(("alpha.com", "beta.com", "gamma.com")):
            intel_db.save_search(
                self._cert_scan(name, f"203.0.113.1{i}", "cert-a", f"2026-02-0{i + 1}T00:00:00+00:00")
            )
        intel_db.apply_pending_graph_rescores()
        incremental = {
            pair: self._stored_score(*pair)
            for pair in (("alpha.com", "beta.com"), ("beta.com", "gamma.com"))
        }
        intel_db.rebuild_all_correlation()
        for pair, score in incremental.items():
            self.assertAlmostEqual(self._stored_score(*pair), score, places=2)

    def test_full_reconcile_resets_the_schedule(self) -> None:
        intel_db.rebuild_all_correlation()
        state = intel_db.graph_maintenance_state()
        self.assertIsNotNone(state["since_full"])
        self.assertLess(state["since_full"], 60)
        self.assertFalse(state["dirty"])


if __name__ == "__main__":
    unittest.main()
