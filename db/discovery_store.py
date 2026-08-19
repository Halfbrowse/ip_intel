"""Persistence for Censys reverse-lookup discoveries.

No new tables: the user has ruled that out, and both halves of a reverse lookup
already have a home in the existing schema.

* **`search_fields`** takes the per-selector record under the
  `censys_reverse_lookup` key — the Censys field queried, the selector value,
  and its global `total_hits`. That table is the raw, append-only substrate
  (`is_seed`, `discovery_kind`, `opencti_labels` all live there), so the
  prevalence counts survive a `rebuild_clusters()` / global recompute, which
  wipes and rematerializes the derived `selectors` projection. Recording the
  count here rather than on `selectors.entity_count` also keeps the two honest:
  `entity_count` means "degree inside our corpus" and must keep meaning that.
  `finalize_search` already upserts every payload key into this table, so the
  write below is the same upsert — it is here so the function is correct when
  called with a lookup that did not ride in on a scan payload (a backfill).

* **`discovered_targets`** takes one row per domain the lookup surfaced, with
  the evidence that found it in `raw_json`. It is the same table every other
  pivot (DNS, cross-SAN, reverse-IP, provider hits) lands in, so a reverse-lookup
  discovery is queryable alongside them without a special case.
"""

from __future__ import annotations

from typing import Any

from db.intel_db import _conn, _json, init_db, save_search_fields

REVERSE_LOOKUP_FIELD_KEY = "censys_reverse_lookup"
REVERSE_LOOKUP_RELATION = "censys_reverse_lookup"


def _pivot_score(global_hits: Any) -> int:
    """Rank a discovery on the global rarity of the selector that found it.

    Scored on `db/intel_db.py`'s 1-10 `_PIVOT_SOURCE_SCORES` scale so a reverse
    -lookup pivot sorts sensibly against DNS/cross-SAN pivots. A selector Censys
    sees on two web properties is near-proof of shared operation and outranks a
    CNAME; one it sees on hundreds is barely worth following.
    """
    if not isinstance(global_hits, int) or global_hits < 0:
        return 4
    if global_hits <= 2:
        return 9
    if global_hits <= 10:
        return 8
    if global_hits <= 50:
        return 6
    if global_hits <= 200:
        return 4
    return 2


def record_reverse_lookup(search_id: int, lookup: dict[str, Any]) -> int:
    """Persist one scan's reverse-lookup result. Returns rows written to
    `discovered_targets`."""
    if not isinstance(lookup, dict) or not lookup:
        return 0

    init_db()
    save_search_fields(search_id, {REVERSE_LOOKUP_FIELD_KEY: lookup})

    rows = []
    for candidate in lookup.get("discovered") or []:
        target = str(candidate.get("target") or "").strip().lower()
        if not target:
            continue
        rows.append(
            (
                search_id,
                target,
                # Not hardcoded "domain": a Censys web property can be keyed on
                # a bare IP, and storing one as a domain puts a value in the
                # pool that no domain view can render and no domain scan can
                # take. censys_discovery classifies it; this records what it said.
                str(candidate.get("target_type") or "domain"),
                REVERSE_LOOKUP_RELATION,
                # Distinct source per selector kind so `GET /api/graph/by-selector`
                # style grouping can tell a favicon pivot from a GA-tag pivot.
                f"censys_{candidate.get('selector_kind') or 'selector'}",
                _pivot_score(candidate.get("global_hits")),
                lookup.get("observed_at"),
                _json(candidate),
            )
        )
    if not rows:
        return 0

    with _conn() as c:
        c.cursor().executemany(
            """INSERT INTO discovered_targets
               (search_id, target, target_type, relation, source, score, observed_at, raw_json)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            rows,
        )
    return len(rows)


def global_prevalence(kind: str, value: str) -> int | None:
    """Most recently observed Censys `total_hits` for one selector.

    The point of storing the count: `utils/check.py`'s `rarity_weight` can only
    measure a selector's degree inside our own corpus, so a tag Censys sees on
    40,000 sites looks maximally rare to it if only two of our domains carry it.
    This is the global number, for whoever wants to weight on it.
    """
    return global_prevalence_map([(kind, value)]).get((str(kind), str(value)))


def global_prevalence_map(
    pairs: list[tuple[str, str]] | None,
) -> dict[tuple[str, str], int]:
    """Latest recorded `total_hits` for many selectors, in one round trip.

    `sources.censys_discovery.rank_selectors` needs the prevalence of every
    selector a page carried before it can choose which two to spend credits on,
    and that happens on the critical path of every ingested domain. Asking
    per-selector would be a dozen sequential queries against a `LATERAL`
    expansion of the whole `search_fields` table; this is one.

    `DISTINCT ON (kind, value)` with `search_id DESC` takes the most recent
    observation of each selector, matching the single-selector behaviour: a
    prevalence count is a point-in-time fact about the internet, so the newest
    reading wins rather than the largest or an average.

    Selectors never queried before are simply absent from the result — callers
    must distinguish "no history" from "prevalence zero", because the two lead
    to opposite decisions about whether to spend a credit.
    """
    wanted = [(str(kind), str(value)) for kind, value in (pairs or [])]
    if not wanted:
        return {}

    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT ON (sel->>'kind', sel->>'value')
                      sel->>'kind'         AS kind,
                      sel->>'value'        AS value,
                      sel->>'global_hits'  AS hits
                 FROM search_fields sf,
                      LATERAL jsonb_array_elements(sf.json_value->'selectors') AS sel
                WHERE sf.key = %(key)s
                  AND sel->>'value' = ANY(%(values)s)
                  AND sel->>'global_hits' IS NOT NULL
                ORDER BY sel->>'kind', sel->>'value', sf.search_id DESC""",
            {
                "key": REVERSE_LOOKUP_FIELD_KEY,
                # Filtered on value alone so the index-free LATERAL scan is
                # narrowed by the selective half of the key; the (kind, value)
                # pair is re-checked below, since two kinds can share a value.
                "values": sorted({value for _, value in wanted}),
            },
        ).fetchall()

    keys = set(wanted)
    out: dict[tuple[str, str], int] = {}
    for row in rows:
        key = (row["kind"], row["value"])
        if key not in keys or row["hits"] is None:
            continue
        try:
            out[key] = int(row["hits"])
        except (TypeError, ValueError):
            continue
    return out
