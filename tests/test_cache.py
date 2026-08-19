from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest

from cases import cache


class FakeRedis:
    """Minimal stand-in for the handful of commands cases/cache.py uses."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.raise_on: set[str] = set()

    def _guard(self, command: str) -> None:
        if command in self.raise_on:
            raise RuntimeError(f"redis {command} failed")

    def ping(self) -> bool:
        self._guard("ping")
        return True

    def get(self, key: str) -> str | None:
        self._guard("get")
        return self.store.get(key)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._guard("set")
        self.store[key] = value

    def incr(self, key: str) -> int:
        self._guard("incr")
        value = int(self.store.get(key) or 0) + 1
        self.store[key] = str(value)
        return value


@pytest.fixture
def fake_redis(monkeypatch):
    client = FakeRedis()
    monkeypatch.setattr(cache, "_client", client)
    monkeypatch.setattr(cache, "_down_until", 0.0)
    yield client
    monkeypatch.setattr(cache, "_client", None)


@pytest.fixture
def no_redis(monkeypatch):
    monkeypatch.setattr(cache, "_client", None)
    monkeypatch.setattr(cache, "redis_lib", None)
    monkeypatch.setattr(cache, "_down_until", 0.0)


class TestPassThrough:
    def test_computes_every_call_without_redis(self, no_redis):
        calls = []

        def compute():
            calls.append(1)
            return {"value": len(calls)}

        assert cache.cached("ns", {"a": 1}, compute) == {"value": 1}
        assert cache.cached("ns", {"a": 1}, compute) == {"value": 2}
        assert not cache.enabled()

    def test_invalidate_and_warm_are_noops_without_redis(self, no_redis):
        cache.invalidate()
        assert cache.warm() == 0

    def test_redis_error_degrades_to_compute(self, fake_redis):
        fake_redis.raise_on.add("get")
        assert cache.cached("ns", {}, lambda: "live") == "live"
        # The failure takes the client out of rotation instead of being retried
        # on every request.
        assert cache._client is None
        assert not cache.enabled()


class TestCaching:
    def test_second_call_is_served_from_redis(self, fake_redis):
        calls = []

        def compute():
            calls.append(1)
            return {"n": len(calls)}

        assert cache.cached("ns", {"a": 1}, compute) == {"n": 1}
        assert cache.cached("ns", {"a": 1}, compute) == {"n": 1}
        assert len(calls) == 1

    def test_different_params_are_different_entries(self, fake_redis):
        cache.cached("ns", {"a": 1}, lambda: "one")
        assert cache.cached("ns", {"a": 2}, lambda: "two") == "two"

    def test_param_order_does_not_change_the_key(self, fake_redis):
        cache.cached("ns", {"a": 1, "b": 2}, lambda: "first")
        assert cache.cached("ns", {"b": 2, "a": 1}, lambda: "second") == "first"

    def test_values_are_json_encodable_on_both_paths(self, fake_redis):
        stamp = datetime(2026, 8, 12, 9, 30, tzinfo=timezone.utc)
        miss = cache.cached("ns", {}, lambda: {"seen": stamp})
        hit = cache.cached("ns", {}, lambda: {"seen": stamp})
        # Identical on hit and miss, which is what keeps the endpoint's ETag
        # stable across a cache fill.
        assert miss == hit
        assert isinstance(miss["seen"], str)


class TestInvalidation:
    def test_invalidate_orphans_every_namespace(self, fake_redis):
        cache.cached("pool", {}, lambda: "old-pool")
        cache.cached("clusters", {}, lambda: "old-clusters")

        cache.invalidate()

        assert cache.cached("pool", {}, lambda: "new-pool") == "new-pool"
        assert cache.cached("clusters", {}, lambda: "new-clusters") == "new-clusters"

    def test_warm_fills_entries_and_survives_failures(self, fake_redis, monkeypatch):
        monkeypatch.setattr(
            cache,
            "_WARM_TASKS",
            (
                ("ok", lambda: cache.cached("pool", {}, lambda: "warmed")),
                ("broken", lambda: (_ for _ in ()).throw(RuntimeError("db down"))),
            ),
        )
        assert cache.warm() == 1
        assert cache.cached("pool", {}, lambda: "recomputed") == "warmed"

    def test_refresh_invalidates_before_warming(self, fake_redis, monkeypatch):
        cache.cached("pool", {}, lambda: "stale")
        monkeypatch.setattr(
            cache, "_WARM_TASKS", (("ok", lambda: cache.cached("pool", {}, lambda: "fresh")),)
        )
        assert cache.refresh() == 1
        assert cache.cached("pool", {}, lambda: "unused") == "fresh"


class TestAutomaticRewarm:
    """Invalidation must refill the cache on its own.

    Invalidating alone would leave every hot key cold until a user happened to
    hit the endpoint and paid the full query cost, which is the slowness the
    cache exists to remove.
    """

    @pytest.fixture(autouse=True)
    def _fast_debounce(self, monkeypatch):
        # Real value is 5s; the worker's behaviour is identical at 50ms and the
        # suite stays fast.
        monkeypatch.setattr(cache, "REWARM_DEBOUNCE_SECONDS", 0.05)
        yield
        cache.stop_rewarm_worker()

    @staticmethod
    def _wait_for(predicate, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.01)
        return predicate()

    def test_invalidate_triggers_a_warm_with_no_endpoint_call(self, fake_redis, monkeypatch):
        warms = []
        monkeypatch.setattr(cache, "_WARM_TASKS", (("ok", lambda: warms.append(1)),))

        cache.start_rewarm_worker()
        assert self._wait_for(lambda: len(warms) >= 1), "startup warm never ran"
        before = len(warms)

        cache.invalidate()
        assert self._wait_for(lambda: len(warms) > before), "invalidation did not re-warm"

    def test_a_burst_of_invalidations_coalesces_into_one_warm(self, fake_redis, monkeypatch):
        warms = []
        monkeypatch.setattr(cache, "_WARM_TASKS", (("ok", lambda: warms.append(1)),))

        cache.start_rewarm_worker()
        assert self._wait_for(lambda: len(warms) >= 1)
        before = len(warms)

        # A reconcile fires one invalidation per projected search; warming per
        # event would bury Postgres under the queries the cache exists to avoid.
        for _ in range(200):
            cache.invalidate()

        assert self._wait_for(lambda: len(warms) > before)
        time.sleep(cache.REWARM_DEBOUNCE_SECONDS * 4)
        assert len(warms) - before == 1, f"expected one coalesced warm, got {len(warms) - before}"

    def test_stop_is_idempotent_and_start_can_resume(self, fake_redis, monkeypatch):
        monkeypatch.setattr(cache, "_WARM_TASKS", ())
        cache.start_rewarm_worker()
        cache.stop_rewarm_worker()
        cache.stop_rewarm_worker()
        cache.start_rewarm_worker()
        assert cache._rewarm_thread is not None and cache._rewarm_thread.is_alive()
