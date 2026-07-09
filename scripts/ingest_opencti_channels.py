"""ingest_opencti_channels.py — sweep every OpenCTI website Channel into the pool.

Fetches *all* Channel SDOs on OpenCTI with channel_types containing
"website" (no 100-channel cap, unlike the frontend's "ingest website
channels" button), runs each resolved domain through the same full
ingestion pipeline as a normal case submission (core/basic.py's analyze()
plus analysis_service's parity enrichments, subdomain/sibling follow-ups,
and db/intel_db.py correlation).

Two kinds of OpenCTI label data get attached to each domain:

- tier (tier-1..tier-5, the only labels that matter for classification —
  see integrations/opencti_ingest._extract_tier) is written to the durable
  domain_tiers table, keyed by registrable domain rather than a specific
  scan. It survives rescans and is what colours nodes in the network graph.
- the full label list is attached to the scan's own result as
  `opencti_labels`, same as before — informational only.

Meant to run inside the app container, not through the frontend:

    docker compose exec ip-intel python -m scripts.ingest_opencti_channels

Requires OPENCTI_URL / OPENCTI_TOKEN (already set via .env in the container).
"""

from __future__ import annotations

import argparse
import sys
import time

from cases.case_runtime import CaseRuntime
from cases.case_store import get_job
from core.analysis_service import clean_target, normalize_inputs
from db.intel_db import get_latest_search_id_for_target, registrable_domain, save_search_fields, set_domain_tier
from integrations.opencti_ingest import fetch_all_website_channel_data


def _print_progress(job: dict) -> None:
    stage = job.get("stage") or "?"
    percent = job.get("percent") or 0
    done = job.get("completed_targets") or 0
    failed = job.get("failed_targets") or 0
    total = job.get("total_targets") or 0
    current = job.get("current_target") or ""
    print(
        f"  [{percent:3d}%] stage={stage:<12} done={done}/{total} failed={failed}  {current}",
        flush=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and print the domain/tier/label list from OpenCTI without ingesting anything.",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=5.0,
        help="Seconds between job-status polls while ingestion runs (default: 5).",
    )
    args = parser.parse_args()

    print("Fetching website channels from OpenCTI...")
    try:
        domain_data = fetch_all_website_channel_data()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    if not domain_data:
        print("No website-channel domains found on OpenCTI. Nothing to do.")
        return

    tiered_count = sum(1 for entry in domain_data.values() if entry["tier"] is not None)
    print(f"Found {len(domain_data)} domain(s) from website channels ({tiered_count} with a tier label).")

    if args.dry_run:
        for domain in sorted(domain_data):
            entry = domain_data[domain]
            tier_text = f"tier {entry['tier']}" if entry["tier"] is not None else "no tier"
            labels_text = f"  [{', '.join(entry['labels'])}]" if entry["labels"] else ""
            print(f"  {domain}  ({tier_text}){labels_text}")
        return

    # Tier is durable, per-domain classification, independent of any one
    # scan's success — set it up front so it's recorded even if a domain's
    # analysis below fails or times out. domain_tiers is keyed on the
    # *registrable* domain (same rollup key domain_profile/graph lookups
    # use), so a channel resolving to a subdomain still needs collapsing to
    # its apex here, or the tier would be stored under a key nothing ever
    # looks up.
    print("Recording domain tiers...")
    tier_written = 0
    for domain, entry in domain_data.items():
        if entry["tier"] is None:
            continue
        apex = registrable_domain(clean_target(domain))
        if not apex:
            continue
        set_domain_tier(apex, entry["tier"], source="opencti")
        tier_written += 1
    print(f"  set tier on {tier_written} domain(s).")

    inputs = normalize_inputs(list(domain_data.keys()))
    if not inputs:
        print("No valid domains after normalization. Nothing to do.")
        return

    runtime = CaseRuntime()
    identifiers = runtime.submit_case(inputs, input_mode="opencti_website_full")
    case_id, job_id = identifiers["case_id"], identifiers["job_id"]
    print(f"Submitted case {case_id} (job {job_id}) with {len(inputs)} domain(s). Waiting for it to finish...")

    while True:
        job = get_job(job_id)
        if job is None:
            print("error: job disappeared mid-run", file=sys.stderr)
            sys.exit(1)
        _print_progress(job)
        if job.get("status") in ("completed", "failed"):
            break
        time.sleep(args.poll_interval)

    status = job.get("status")
    print(f"Case {status}.")
    if job.get("error"):
        print(f"  error: {job['error']}")

    print("Attaching OpenCTI labels to their domains...")
    # Re-key by clean_target() so lookups line up exactly with the
    # normalized_target each search was actually saved under.
    normalized_labels = {
        clean_target(domain): entry["labels"] for domain, entry in domain_data.items() if entry["labels"]
    }
    attached = 0
    missing = 0
    for domain, labels in normalized_labels.items():
        sid = get_latest_search_id_for_target(domain)
        if sid is None:
            missing += 1
            continue
        save_search_fields(sid, {"opencti_labels": labels})
        attached += 1
    print(f"  attached labels to {attached} domain(s); {missing} had labels but no matching search result.")

    if status == "failed":
        sys.exit(1)


if __name__ == "__main__":
    main()
