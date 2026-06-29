"""backfill_correlation.py — build the correlation graph from stored intel.

Walks every existing `searches` row (plus its reconstructed result) and projects
it into the derived entities/selectors/observations/entity_edges layer, then
computes initial selector degrees and seeds the denylist. The whole historical
corpus gains transitive and apex-level linkage without rescanning.

This is the global-recompute path: it is idempotent and rebuildable. Run it
after a fresh deploy, after a SQLite→Postgres migration, or any time selector
extraction / weighting logic changes.

Usage:
    uv run python -m scripts.backfill_correlation
    uv run python -m scripts.backfill_correlation --database-url postgresql://...
"""

from __future__ import annotations

import argparse
import os

import db.intel_db as intel_db


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-url",
        help="Override INTEL_DATABASE_URL/DATABASE_URL for this run.",
    )
    args = parser.parse_args()

    if args.database_url:
        os.environ["INTEL_DATABASE_URL"] = args.database_url
        intel_db.reset_schema_cache()

    print(f"Rebuilding correlation graph in {intel_db.database_url()} ...")
    counts = intel_db.rebuild_all_correlation()
    width = max(len(k) for k in counts)
    for key, value in counts.items():
        print(f"  {key.rjust(width)} : {value}")
    print("Done.")


if __name__ == "__main__":
    main()
