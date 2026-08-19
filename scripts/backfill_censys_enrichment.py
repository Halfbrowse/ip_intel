"""backfill_censys_enrichment.py — host-enrich the IPs behind every channel.

Walks the distinct IPs in the pool and calls the Censys host-enrichment
endpoint for each, storing the result on the matching `ips` rows. It fills any
ASN/network column ipinfo Lite left empty, and overwrites `country` when
enrichment answers — enrichment owns geo now, with ipinfo Lite's country as the
fallback (see utils.censys_enrichment.merge_censys_enrichment). The RDAP leg
that used to contribute here was removed.

The scan path already enriches each IP it resolves (see
core.basic.get_ip_whois); this is the other half — the channels already in
the pool, which would otherwise stay un-enriched until something rescanned
them.

Every call is claimed against the shared daily budget
(db.intel_db.claim_censys_enrichment_calls, 20,000/day on the Censys Core
plan), so this is safe to run alongside live scanning and safe to re-run: it
stops when the budget is spent and picks up where it left off next time.
IPs are processed most-referenced first, so a partial run spends the budget on
the addresses the most channels depend on.

Usage:
    uv run python -m scripts.backfill_censys_enrichment
    uv run python -m scripts.backfill_censys_enrichment --limit 5000
    uv run python -m scripts.backfill_censys_enrichment --refresh-all
"""

from __future__ import annotations

import argparse
import os
import sys

import db.intel_db as intel_db
from utils.censys_enrichment import get_censys_host_enrichment


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=1000,
                        help="Maximum IPs to enrich in this run (default: 1000).")
    parser.add_argument("--refresh-all", action="store_true",
                        help="Re-enrich already-enriched IPs (oldest first) instead of "
                             "only those never enriched.")
    parser.add_argument("--database-url",
                        help="Override INTEL_DATABASE_URL/DATABASE_URL for this run.")
    args = parser.parse_args()

    if args.database_url:
        os.environ["INTEL_DATABASE_URL"] = args.database_url
        intel_db.reset_schema_cache()

    usage = intel_db.censys_enrichment_usage()
    print(f"Censys enrichment budget: {usage['used']}/{usage['limit']} used today, "
          f"{usage['remaining']} remaining")
    if not usage["remaining"]:
        print("Daily budget already spent — nothing to do.")
        return

    targets = intel_db.ips_pending_censys_enrichment(args.limit, refresh_all=args.refresh_all)
    if not targets:
        print("No IPs pending enrichment.")
        return

    print(f"Enriching {len(targets)} IP(s) in {intel_db.database_url()} ...")
    counts = {"enriched": 0, "not_found": 0, "skipped": 0, "errors": 0}
    # Reprojected once at the end rather than per IP: a pool-wide sweep touches
    # the same searches repeatedly (one search owns many IPs), so doing it
    # inline would reproject the same rows thousands of times.
    affected_searches: set[int] = set()
    for index, ip in enumerate(targets, 1):
        enrichment = get_censys_host_enrichment(ip)
        if enrichment.get("skipped"):
            # Budget exhausted mid-run (or credentials missing) — stop rather
            # than burn the rest of the loop on calls we already know we won't
            # make.
            counts["skipped"] += 1
            print(f"  [{index}/{len(targets)}] {ip}: {enrichment.get('reason')} — stopping")
            break
        if enrichment.get("error"):
            counts["errors"] += 1
            print(f"  [{index}/{len(targets)}] {ip}: error — {enrichment['error']}", file=sys.stderr)
            continue
        # A not_found result is still recorded, so the sweep doesn't retry an
        # IP Censys has never scanned on every subsequent run.
        affected_searches.update(intel_db.store_censys_enrichment(ip, enrichment))
        counts["not_found" if enrichment.get("not_found") else "enriched"] += 1
        if index % 50 == 0 or index == len(targets):
            print(f"  [{index}/{len(targets)}] enriched={counts['enriched']} "
                  f"not_found={counts['not_found']} errors={counts['errors']}")

    # A filled-in ASN/CIDR only becomes graph evidence once its search is
    # reprojected — the projection reads the `ips` columns, and nothing else
    # will revisit them until the domain is rescanned.
    if affected_searches:
        print(f"Reprojecting {len(affected_searches)} affected search(es) into the graph ...")
        reprojected = 0
        for sid in sorted(affected_searches):
            try:
                intel_db.rebuild_correlation_for_search(sid)
            except Exception as exc:  # one bad search must not lose the sweep's work
                print(f"  search {sid}: reprojection failed — {exc}", file=sys.stderr)
                continue
            reprojected += 1
        print(f"Reprojected {reprojected}/{len(affected_searches)} search(es).")

    final = intel_db.censys_enrichment_usage()
    print(f"Done. enriched={counts['enriched']} not_found={counts['not_found']} "
          f"errors={counts['errors']} — budget now {final['used']}/{final['limit']}")


if __name__ == "__main__":
    main()
