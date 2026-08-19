"""Server-side response cache for the read endpoints, held in Redis.

Why Redis and not an in-process dict: the payloads cached here are the same for
every viewer (there is no per-user scoping in this product — one global pool,
one correlation graph), they survive an app restart, and a rebuild can drop all
of them in one command from anywhere, including an out-of-process
``scripts/backfill_correlation`` run. A process-local dict would give none of
that and would double the memory of an already 6g-capped container.

**What is cached and why** — only the endpoints that genuinely recompute from
Postgres on every request:

* ``pool_page`` (``/api/pool``) — the worst offender. ``list_pool_domains``
  aggregates every row of ``entities`` LEFT JOINed to the append-only
  ``searches``/``search_fields`` tables, runs three correlated
  "latest search field" subqueries *per domain*, and the whole statement is
  executed **twice** (once wrapped in ``count(*)`` for the total, once for the
  page). Both the pool page and the connections explorer request it on every
  visit, the latter with ``limit=5000``.
* ``domain_profile`` (``/api/domain/{value}``) — a LATERAL per host that does an
  EXISTS over ``searches`` + ``search_fields`` plus three more scalar
  subqueries, a correlated ``count(DISTINCT registrable_domain)`` per resolved
  IP, and then loads and curates the full raw intel JSON of the latest search.
  Cost scales with a channel's subdomain count.
* ``graph_links`` (``/api/graph/links/{value}``) — ``check.links_for`` scores
  **live**: ``link_candidates_for`` self-joins ``observations`` against itself
  over every attributing selector, then Python-scores every candidate. This is
  precisely the query the codebase invented ``links_for_fast`` to avoid, and
  the domain page fires it on every open.
* ``graph_connections`` (``/api/graph/connections``) — one ``links_for_fast``
  read per selected domain (up to 30), each of which falls back to the live
  ``links_for`` above for any domain not yet through a rebuild pass, plus a
  tier lookup over the whole expanded set.
* ``graph_clusters`` (``/api/graph/clusters``) — full scan + group + array_agg
  over ``graph_clusters``, then the connector rows for every cluster returned.
  It is the clusters page's landing request.
* ``selector_kinds`` / ``by_selector`` (``/api/graph/selector-kinds``,
  ``/api/graph/by-selector``) — a full aggregate over
  ``graph_selector_groups``, and a ``degree DESC`` sort that only has an index
  when a ``kind`` is supplied (the "all kinds" default sorts the whole table).
* ``search`` (``/api/search``) — ``SELECT DISTINCT registrable_domain FROM
  entities`` followed by two unanchored ``ILIKE '%…%'`` scans, fired once per
  debounced keystroke from the global search box.

**What is deliberately NOT cached**: ``/api/graph/path`` and
``/api/graph/related/{value}`` (single indexed reads of ``graph_paths`` on its
primary key / ``idx_graph_paths_rd``), ``/api/graph/cluster/{value}`` and
``/api/graph/link`` (indexed point lookups), ``/api/meta/evidence`` (a
constant built in-process), and ``/api/jobs/{id}`` + ``/api/health``, which
report live state and must never be served stale. Fronting an indexed
single-row read with a network round trip buys nothing and adds a staleness
surface.

**Invalidation model.** Every entry lives under a generation number read from
Redis, so ``invalidate()`` is a single ``INCR``: every key derived from the
previous graph state is orphaned atomically and ages out on its own TTL — no
SCAN sweep, no key bookkeeping, and it works across processes. The TTL is only
a backstop for a missed invalidation (and a memory bound on the high-cardinality
search keys); correctness comes from invalidating whenever the graph is
rematerialized.

Redis is optional. A missing client library, an unreachable server, or any
Redis error at request time degrades to computing the value directly — the same
"missing provider degrades, never aborts" rule the rest of this codebase
follows.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from typing import Any, Callable, Mapping

from fastapi.encoders import jsonable_encoder

from db import intel_db
from utils import check

try:
    import redis as redis_lib
except ImportError:  # the service is optional; see module docstring
    redis_lib = None  # type: ignore[assignment]


LOGGER = logging.getLogger("ip_intel.cache")

DEFAULT_REDIS_URL = "redis://redis:6379/0"

_KEY_PREFIX = "ipintel:cache"
_GENERATION_KEY = f"{_KEY_PREFIX}:generation"

# Graph-derived payloads are invalidated explicitly on every rematerialization
# (see invalidate()), so this TTL only bounds how long a *missed* invalidation
# could serve stale data.
DEFAULT_TTL = 900
# Search keys are per-query and unbounded in cardinality (every prefix the user
# types is its own key), so they expire fast to keep Redis small. Repeat
# keystrokes within one search session — the case that actually hurts — still
# hit.
SEARCH_TTL = 60

# A dead Redis must cost one connect attempt, not one per request: after a
# failure we stay in pass-through mode for this long before probing again.
_RETRY_INTERVAL_SECONDS = 30.0
_CONNECT_TIMEOUT_SECONDS = 0.5
_COMMAND_TIMEOUT_SECONDS = 1.0

_client: Any = None
_down_until = 0.0


def _redis_client() -> Any:
    """The shared client, or None while Redis is unavailable."""
    global _client, _down_until

    if _client is not None:
        return _client
    if redis_lib is None:
        return None
    if time.monotonic() < _down_until:
        return None

    url = os.getenv("REDIS_URL", DEFAULT_REDIS_URL)
    try:
        client = redis_lib.Redis.from_url(
            url,
            decode_responses=True,
            socket_connect_timeout=_CONNECT_TIMEOUT_SECONDS,
            socket_timeout=_COMMAND_TIMEOUT_SECONDS,
        )
        client.ping()
    except Exception as exc:
        _down_until = time.monotonic() + _RETRY_INTERVAL_SECONDS
        LOGGER.warning("Cache disabled: Redis at %s unreachable (%s)", url, exc)
        return None

    _client = client
    LOGGER.info("Cache enabled: Redis at %s", url)
    return client


def _drop_client(exc: Exception) -> None:
    global _client, _down_until
    _client = None
    _down_until = time.monotonic() + _RETRY_INTERVAL_SECONDS
    LOGGER.warning("Cache disabled after Redis error: %s", exc)


def enabled() -> bool:
    """True when Redis is currently usable (a probe, so it also recovers)."""
    return _redis_client() is not None


def _cache_key(client: Any, namespace: str, params: Mapping[str, Any]) -> str:
    generation = client.get(_GENERATION_KEY) or "0"
    digest = hashlib.sha256(
        json.dumps(params, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:32]
    return f"{_KEY_PREFIX}:{generation}:{namespace}:{digest}"


def cached(
    namespace: str,
    params: Mapping[str, Any],
    compute: Callable[[], Any],
    *,
    ttl: int = DEFAULT_TTL,
) -> Any:
    """`compute()`'s result, served from Redis when a fresh copy is there.

    Values are stored as the same JSON the endpoint would serialize
    (``jsonable_encoder`` first), so a cache hit and a cache miss produce a
    byte-identical response body — and therefore the same ETag, which is what
    the frontend's If-None-Match revalidation depends on.
    """
    client = _redis_client()
    if client is None:
        return compute()

    try:
        key = _cache_key(client, namespace, params)
        hit = client.get(key)
        if hit is not None:
            return json.loads(hit)
    except Exception as exc:
        _drop_client(exc)
        return compute()

    value = jsonable_encoder(compute())
    try:
        client.set(key, json.dumps(value, separators=(",", ":")), ex=ttl)
    except Exception as exc:
        _drop_client(exc)
    return value


def invalidate() -> None:
    """Drop everything derived from the correlation graph, then queue a re-warm.

    One INCR of the generation counter: every existing key was built under the
    old generation, so nothing can read them again and Redis reclaims them on
    their TTL. Call this after any pass that rematerializes the graph.

    Invalidating alone would leave the cache cold until a user happened to hit
    each endpoint and paid the full query cost — the slowness this module
    exists to remove, merely deferred. So the re-warm worker is signalled here
    and refills the hot keys on its own. The signal is unconditional: warm()
    re-probes Redis itself and no-ops while it is down, so a cache that comes
    back after an outage still gets refilled.
    """
    client = _redis_client()
    if client is not None:
        try:
            client.incr(_GENERATION_KEY)
        except Exception as exc:
            _drop_client(exc)
    _rewarm_wanted.set()


# The requests the UI makes before the user has touched anything: the pool
# page's first page (frontend/src/utils/poolQuery.js DEFAULT_PAGE_SIZE = 24),
# the connections explorer's full domain list, the clusters landing page, and
# the "browse by edge type" defaults. Warming exactly these keys — same
# arguments, same key — is what makes the first click after a boot or a
# recompute fast instead of the one that pays for the rebuild.
_WARM_TASKS: tuple[tuple[str, Callable[[], Any]], ...] = (
    ("pool:first-page", lambda: pool_page(limit=24, offset=0)),
    ("pool:connections-explorer", lambda: pool_page(limit=5000, sort="domain")),
    ("graph:clusters", lambda: graph_clusters()),
    ("graph:selector-kinds", lambda: selector_kinds()),
    ("graph:by-selector", lambda: by_selector()),
)


def warm() -> int:
    """Populate the slow payloads the UI asks for first. Returns entries filled.

    Blocking (it runs the real queries), so call it off the event loop. A
    failing task is logged and skipped: warming is an optimization and must
    never take the app down — if Postgres or Redis is unhappy the endpoints
    still work, they are just cold.
    """
    if not enabled():
        return 0

    filled = 0
    for label, task in _WARM_TASKS:
        started = time.monotonic()
        try:
            task()
        except Exception as exc:
            LOGGER.warning("Cache warm skipped %s: %s", label, exc)
            continue
        filled += 1
        LOGGER.info("Cache warm %s in %.2fs", label, time.monotonic() - started)
    return filled


def refresh() -> int:
    """Invalidate, then immediately re-warm — the "a major recompute happened"
    entry point. Blocking, same as warm(). Prefer letting invalidate() and the
    background worker handle it; this is for callers that must not return until
    the cache is hot again."""
    invalidate()
    return warm()


# ── Automatic re-warm worker ────────────────────────────────────────────────
#
# A plain thread rather than an asyncio task: invalidate() is reached from
# db.intel_db's graph-invalidation hook, which runs on scan/maintenance worker
# threads with no event loop bound, so there is nothing to schedule onto at the
# call site.

# How long the graph must stay quiet before re-warming. _notify_graph_
# invalidation fires once per projected search, so a reconcile or a pool-wide
# enrichment sweep emits invalidations in the thousands; warming per event
# would bury Postgres under exactly the queries this module exists to avoid.
# Coalescing collapses any burst into a single warm once it settles.
REWARM_DEBOUNCE_SECONDS = float(os.getenv("CACHE_REWARM_DEBOUNCE_SECONDS") or 5.0)

_rewarm_wanted = threading.Event()
_rewarm_stop = threading.Event()
_rewarm_thread: threading.Thread | None = None


def _rewarm_loop() -> None:
    while not _rewarm_stop.is_set():
        # Short poll so a stop is noticed promptly even with no invalidations.
        if not _rewarm_wanted.wait(timeout=1.0):
            continue
        # Cleared *before* warming, never after: an invalidation that lands
        # while warm() is running has to schedule another pass, and clearing
        # afterwards would swallow it and leave the cache holding data from
        # before that invalidation.
        _rewarm_wanted.clear()
        if _rewarm_stop.is_set():
            return
        while _rewarm_wanted.wait(timeout=REWARM_DEBOUNCE_SECONDS):
            _rewarm_wanted.clear()
            if _rewarm_stop.is_set():
                return
        try:
            warm()
        except Exception as exc:  # pragma: no cover - warm() already guards each task
            LOGGER.warning("Cache re-warm failed: %s", exc)


def start_rewarm_worker() -> None:
    """Start re-warming the cache automatically after every invalidation.

    Idempotent. Also queues the initial warm, so boot and post-recompute
    warming take the same path instead of the app having its own startup call.
    """
    global _rewarm_thread
    if _rewarm_thread is not None and _rewarm_thread.is_alive():
        _rewarm_wanted.set()
        return
    _rewarm_stop.clear()
    _rewarm_thread = threading.Thread(target=_rewarm_loop, name="cache-rewarm", daemon=True)
    _rewarm_thread.start()
    _rewarm_wanted.set()


def stop_rewarm_worker(timeout: float = 2.0) -> None:
    """Stop the worker. A warm already in flight is left to finish — the thread
    is a daemon, so it cannot hold up interpreter exit."""
    global _rewarm_thread
    _rewarm_stop.set()
    _rewarm_wanted.set()  # wake it so it can see the stop flag
    thread, _rewarm_thread = _rewarm_thread, None
    if thread is not None:
        thread.join(timeout=timeout)


# ── Cached reads (drop-in replacements for the endpoints' current calls) ─────

def pool_page(
    *,
    search: str | None = None,
    limit: int = 1000,
    offset: int = 0,
    provenance: str | None = None,
    sort: str = "recent",
    min_connections: int | None = None,
    max_connections: int | None = None,
    ingested_after: str | None = None,
    ingested_before: str | None = None,
    discovered_after: str | None = None,
    discovered_before: str | None = None,
) -> dict[str, Any]:
    params = {
        "search": search,
        "limit": limit,
        "offset": offset,
        "provenance": provenance,
        "sort": sort,
        "min_connections": min_connections,
        "max_connections": max_connections,
        "ingested_after": ingested_after,
        "ingested_before": ingested_before,
        "discovered_after": discovered_after,
        "discovered_before": discovered_before,
    }
    return cached(
        "pool",
        params,
        lambda: intel_db.list_pool_domains(include_total=True, **params),
    )


def domain_profile(value: str) -> dict[str, Any] | None:
    return cached("domain", {"value": value}, lambda: intel_db.domain_profile(value))


def graph_links(value: str) -> list[dict[str, Any]]:
    return cached("links", {"value": value}, lambda: check.links_for(value))


def graph_connections(domains: list[str], *, pool_links: bool = False) -> dict[str, Any]:
    # Keyed on the domain list as given, not a sorted copy: the response echoes
    # the caller's order back in `domains`/`pairs`.
    return cached(
        "connections",
        {"domains": domains, "pool_links": pool_links},
        lambda: check.connections_among(domains, pool_links=pool_links),
    )


def graph_clusters(*, min_size: int = 2, limit: int = 100) -> list[dict[str, Any]]:
    return cached(
        "clusters",
        {"min_size": min_size, "limit": limit},
        lambda: intel_db.list_graph_clusters(min_size=min_size, limit=limit),
    )


def selector_kinds(*, min_domains: int = 2) -> list[dict[str, Any]]:
    return cached(
        "selector-kinds",
        {"min_domains": min_domains},
        lambda: intel_db.selector_kind_counts(min_domains=min_domains),
    )


def by_selector(
    *, kind: str | None = None, min_domains: int = 2, limit: int = 200
) -> list[dict[str, Any]]:
    return cached(
        "by-selector",
        {"kind": kind, "min_domains": min_domains, "limit": limit},
        lambda: intel_db.domains_by_selector(kind=kind, min_domains=min_domains, limit=limit),
    )


def search(query: str, *, limit: int = 20) -> dict[str, Any]:
    return cached(
        "search",
        {"query": query, "limit": limit},
        lambda: intel_db.search_targets(query, limit=limit),
        ttl=SEARCH_TTL,
    )
