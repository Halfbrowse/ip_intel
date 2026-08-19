"""backfill_correlation.py — build the correlation graph from stored intel.

Walks every existing `searches` row (plus its reconstructed result) and projects
it into the derived entities/selectors/observations/entity_edges layer, then
computes initial selector degrees and seeds the denylist. The whole historical
corpus gains transitive and apex-level linkage without rescanning.

This is the global-recompute path: it is idempotent and rebuildable. Run it
after a fresh deploy, after a SQLite→Postgres migration, or any time selector
extraction / weighting logic changes.

The same pass now also runs unattended: the app's maintenance loop calls
rebuild_all_correlation() every GRAPH_FULL_RECONCILE_INTERVAL seconds as the
reconcile behind the incremental on-write rescore (see the maintenance-tier
comment in db/intel_db.py). Running it here is therefore no longer the only
thing keeping the graph current — it is the way to force that reconcile *now*,
e.g. immediately after editing weights or a denylist, without waiting for the
schedule. Finishing resets the schedule, so an automatic reconcile will not
duplicate the work minutes later.

Usage:
    uv run python -m scripts.backfill_correlation
    uv run python -m scripts.backfill_correlation --database-url postgresql://...
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

import db.intel_db as intel_db


def _configure_logging() -> None:
    """Surface the ``ip_intel.*`` loggers (rebuild_all_correlation/rebuild_clusters
    progress) on stdout for this one-shot CLI run.

    Nothing else attaches a handler to the ``ip_intel`` logger family when this
    script runs standalone (it never imports ``cases/case_app.py``), so without
    this the INFO-level progress logging in db/intel_db.py would be silently
    dropped and a rebuild over a large pool would look hung. Mirrors
    ``scripts/ingest_opencti_channels.py``'s ``_configure_logging`` rather than
    sharing it, to avoid pulling in that script's OpenCTI-specific imports.
    Level honours IP_INTEL_LOG_LEVEL (default INFO).
    """
    level_name = os.environ.get("IP_INTEL_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger("ip_intel")
    root.setLevel(level)
    if not any(getattr(h, "_ip_intel", False) for h in root.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler._ip_intel = True  # type: ignore[attr-defined]
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
        root.addHandler(handler)
    root.propagate = False


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database-url",
        help="Override INTEL_DATABASE_URL/DATABASE_URL for this run.",
    )
    args = parser.parse_args()
    _configure_logging()

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
