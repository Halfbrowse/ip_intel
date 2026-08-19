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
import logging
import os
import sys
import time

from cases.case_runtime import CaseRuntime
from cases.case_store import get_job
from core.analysis_service import clean_target, normalize_inputs
from db.intel_db import (
    existing_search_targets,
    get_latest_search_id_for_target,
    rebuild_clusters,
    registrable_domain,
    save_search_fields,
    set_domain_tier,
)
from integrations.opencti_ingest import fetch_all_website_channel_data


def _configure_logging() -> None:
    """Surface the ``ip_intel.*`` loggers on stdout for this detached sweep.

    The analysis pipeline runs on CaseRuntime background threads and reports
    progress through the ``ip_intel`` logger family (see
    ``cases/case_runtime.CaseRuntime._log`` and ``core/basic.py``'s log hook).
    Unlike the web app, this script never imports ``cases/case_app.py``, so
    nothing has attached a handler to that logger — INFO lines would be dropped
    and only WARNING+ would leak to stderr via logging's last-resort handler.
    Attach a stdout handler on the shared ``ip_intel`` parent (children
    propagate to it) so *all* per-domain scan progress lands in the logfile the
    operator redirects stdout to. This mirrors
    ``cases/case_app._configure_logging`` intentionally rather than importing
    it, to avoid spinning up the FastAPI app and a second CaseRuntime just for
    log setup. Level honours IP_INTEL_LOG_LEVEL (default INFO).
    """
    level_name = os.environ.get("IP_INTEL_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger("ip_intel")
    root.setLevel(level)
    if not any(getattr(h, "_ip_intel", False) for h in root.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler._ip_intel = True  # type: ignore[attr-defined]
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
        )
        root.addHandler(handler)
    root.propagate = False


def _progress_signature(job: dict) -> tuple:
    """The fields whose change is worth a new progress line.

    Excludes `current_target`: with a concurrent analysis pool it flips on every
    poll without any real forward motion, which is what produced pages of
    identical `[10%] ... done=23/303` lines. Keying on the counts instead means
    one line per actual completion/failure or stage change."""
    return (
        job.get("stage"),
        job.get("percent") or 0,
        job.get("completed_targets") or 0,
        job.get("failed_targets") or 0,
        job.get("total_targets") or 0,
    )


def _print_progress(job: dict) -> None:
    stage = job.get("stage") or "?"
    percent = job.get("percent") or 0
    done = job.get("completed_targets") or 0
    failed = job.get("failed_targets") or 0
    total = job.get("total_targets") or 0
    # In-flight/queued = everything not yet resolved. Surfacing it makes clear
    # the job is progressing even while `done` sits still (targets being
    # analyzed concurrently) and explains why `total` climbs as discovered
    # follow-ups get queued.
    remaining = max(total - done - failed, 0)
    current = job.get("current_target") or ""
    print(
        f"  [{percent:3d}%] stage={stage:<12} done={done}/{total} "
        f"failed={failed} pending={remaining}  last={current}",
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
    parser.add_argument(
        "--batch-size",
        type=int,
        default=250,
        help=(
            "Number of domains per case. The sweep is split into sequential "
            "batches so each one completes and persists (tiers, labels, scans) "
            "before the next starts — a crash or restart only loses the batch "
            "in flight, not the whole run. Set to 0 for a single case (default: 250)."
        ),
    )
    parser.add_argument(
        "--rescan-existing",
        action="store_true",
        help=(
            "Re-run the full analysis pipeline on channels that already have a "
            "search in the DB. By default those are skipped (only their tier and "
            "labels are refreshed) so a sweep only scans channels new to the pool."
        ),
    )
    args = parser.parse_args()

    # Route the analysis pipeline's ip_intel.* log lines to stdout so a
    # detached run (stdout redirected to a logfile) shows live per-domain
    # scan progress, not just the coarse _print_progress percentages.
    _configure_logging()

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

    # Labels are keyed by clean_target() so lookups line up exactly with the
    # normalized_target each search was actually saved under.
    normalized_labels = {
        clean_target(domain): entry["labels"]
        for domain, entry in domain_data.items()
        if entry["labels"]
    }

    # Skip channels already in the pool: the analysis pipeline is the expensive
    # part, and a channel with an existing search has already been through it.
    # Tiers were recorded above for *every* channel regardless, and labels for
    # skipped channels are refreshed here (they already have a search to attach
    # to), so only the re-scan is avoided — not the durable metadata. --rescan-
    # existing forces a full re-run.
    if args.rescan_existing:
        new_inputs = inputs
    else:
        already = existing_search_targets([item["normalized_target"] for item in inputs])
        new_inputs = [item for item in inputs if item["normalized_target"] not in already]
        skipped = len(inputs) - len(new_inputs)
        if skipped:
            skipped_inputs = [item for item in inputs if item["normalized_target"] in already]
            attached, missing = _attach_labels(skipped_inputs, normalized_labels)
            print(
                f"Skipping {skipped} channel(s) already in the DB "
                f"(refreshed labels on {attached}). {len(new_inputs)} new channel(s) to scan."
            )

    if not new_inputs:
        print("No new channels to scan.")
        print("Rebuilding graph materializations...")
        graph_counts = rebuild_clusters()
        print(f"  graph rebuild: {graph_counts}")
        return

    inputs = new_inputs

    # Split into sequential batches so each case completes and persists before
    # the next starts. With thousands of domains this keeps a single job from
    # running for many hours, makes progress durable (a crash only loses the
    # in-flight batch), and attaches labels incrementally rather than only at
    # the very end. batch_size <= 0 means "one case for everything".
    batch_size = args.batch_size if args.batch_size and args.batch_size > 0 else len(inputs)
    batches = [inputs[i : i + batch_size] for i in range(0, len(inputs), batch_size)]

    runtime = CaseRuntime()
    total_attached = 0
    total_missing = 0
    failed_batches = 0

    for batch_num, batch_inputs in enumerate(batches, 1):
        print(
            f"\n=== Batch {batch_num}/{len(batches)} "
            f"({len(batch_inputs)} domain(s)) ==="
        )
        status = _run_batch(runtime, batch_inputs, poll_interval=args.poll_interval)
        if status == "failed":
            failed_batches += 1

        attached, missing = _attach_labels(batch_inputs, normalized_labels)
        total_attached += attached
        total_missing += missing
        print(f"  attached labels to {attached} domain(s); {missing} had labels but no matching search result.")

    print(
        f"\nAll batches done: {len(batches) - failed_batches}/{len(batches)} completed, "
        f"{failed_batches} failed. Attached labels to {total_attached} domain(s) "
        f"({total_missing} unmatched)."
    )

    print("Rebuilding graph materializations...")
    graph_counts = rebuild_clusters()
    print(f"  graph rebuild: {graph_counts}")

    if failed_batches:
        sys.exit(1)


def _run_batch(runtime: CaseRuntime, batch_inputs: list, *, poll_interval: float) -> str:
    """Submit one batch as a case and block until it finishes, printing progress.

    Returns the job's terminal status ("completed" or "failed"). A failed batch
    does not abort the sweep — the remaining batches still run, and the caller
    reports the overall tally at the end.
    """
    identifiers = runtime.submit_case(batch_inputs, input_mode="opencti_website_full")
    case_id, job_id = identifiers["case_id"], identifiers["job_id"]
    print(f"Submitted case {case_id} (job {job_id}). Waiting for it to finish...")

    last_signature = None
    while True:
        job = get_job(job_id)
        if job is None:
            print("error: job disappeared mid-run", file=sys.stderr)
            return "failed"
        # Only emit a line when the counts/stage actually moved, so the poll
        # cadence no longer floods the log with identical snapshots.
        signature = _progress_signature(job)
        if signature != last_signature:
            _print_progress(job)
            last_signature = signature
        if job.get("status") in ("completed", "failed"):
            break
        time.sleep(poll_interval)

    status = job.get("status")
    print(f"Case {status}.")
    if job.get("error"):
        print(f"  error: {job['error']}")
    return status


def _attach_labels(batch_inputs: list, normalized_labels: dict) -> tuple[int, int]:
    """Attach OpenCTI labels to the just-scanned domains in this batch."""
    attached = 0
    missing = 0
    for item in batch_inputs:
        domain = item["normalized_target"]
        labels = normalized_labels.get(domain)
        if not labels:
            continue
        sid = get_latest_search_id_for_target(domain)
        if sid is None:
            missing += 1
            continue
        save_search_fields(sid, {"opencti_labels": labels})
        attached += 1
    return attached, missing


if __name__ == "__main__":
    main()
