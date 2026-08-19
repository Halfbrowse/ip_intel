from __future__ import annotations

import logging
import os
import threading
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from typing import Any

from utils import check
from core import ip_intel
from core import basic
from core.analysis_service import (
    AnalysisRun,
    analyze_target,
    clean_target,
    normalize_inputs,
    pairing_label,
    parse_csv_targets,
)
from cases.case_store import (
    JOB_STAGES,
    append_job_log,
    complete_case,
    create_case,
    get_case,
    get_job,
    get_pending_crt_sh_retries,
    load_case_inputs,
    mark_case_started,
    patch_search_run_payload,
    recoverable_jobs,
    save_search_run,
    update_job_progress,
)
from integrations.mattermost_alerts import send_case_notification
from integrations.email_alerts import send_case_email


LOGGER = logging.getLogger("ip_intel.case_runtime")

# Map the job-log levels we stream to the frontend onto Python logging levels.
# "success" is a frontend-only notion, so it lands on INFO in the server logs.
_JOB_LOG_LEVELS = {
    "debug":   logging.DEBUG,
    "info":    logging.INFO,
    "success": logging.INFO,
    "warning": logging.WARNING,
    "error":   logging.ERROR,
}


# Per-case concurrency for target analysis. Each target spends most of its
# time waiting on network I/O (DNS, WHOIS, TLS probes, provider APIs), so a
# larger pool cuts wall-clock time roughly linearly. Configurable via
# ANALYSIS_WORKERS so a bulk sweep (e.g. the OpenCTI ingest of thousands of
# domains) can scale up without a code change, while leaving room to dial back
# if a paid provider's own rate limit — not the source IP — becomes the
# ceiling. Each target itself fans out ~12 service threads plus probe pools, so
# the real thread count is this value multiplied by that; 12 keeps it sane.
def _analysis_workers() -> int:
    try:
        value = int(os.environ.get("ANALYSIS_WORKERS", "12"))
    except ValueError:
        return 12
    return max(1, value)


ANALYSIS_WORKERS = _analysis_workers()


class CaseRuntime:
    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="case-runtime")
        self._lock = threading.Lock()
        self._futures: dict[str, Future[Any]] = {}

    def submit_existing(self, case_id: str, job_id: str) -> None:
        with self._lock:
            if job_id in self._futures and not self._futures[job_id].done():
                return
            self._futures[job_id] = self._executor.submit(self._run_case, case_id, job_id)

    def submit_case(self, inputs: list[dict[str, Any]], *, input_mode: str) -> dict[str, str]:
        identifiers = create_case(inputs, input_mode=input_mode)
        self.submit_existing(identifiers["case_id"], identifiers["job_id"])
        return identifiers

    def recover(self) -> None:
        for job in recoverable_jobs():
            self.submit_existing(job["case_id"], job["id"])

    def retry_crt_sh_pending(self) -> int:
        """
        Re-query crt.sh for any search runs that previously failed.
        Returns the number of runs successfully updated.
        """
        import asyncio
        import httpx

        pending = get_pending_crt_sh_retries()
        if not pending:
            return 0

        updated = 0
        for row in pending:
            run_id = row["id"]
            domain = row["normalized_target"]
            try:
                async def _fetch(d: str) -> dict:
                    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0), follow_redirects=True) as client:
                        return await ip_intel._acrt_sh_data(d, client)

                result = asyncio.run(_fetch(domain))
                if result.get("_failed"):
                    continue

                subdomains = result.pop("subdomains", [])
                patch_search_run_payload(run_id, {
                    "cert_transparency": result,
                    "subdomains": subdomains,
                    "crt_sh_status": "ok",
                })
                updated += 1
            except Exception:
                pass

        return updated

    def _run_case(self, case_id: str, job_id: str) -> None:
        basic._SCANNED_DOMAINS.clear()
        mark_case_started(case_id, job_id)
        self._log(job_id, "info", "Case started", stage="intake")
        inputs = load_case_inputs(case_id)
        queue = [
            {
                "target": item["normalized_target"],
                "root_input": item["normalized_target"],
                "depth": 0,
                "discovered_from": None,
                "discovery_reason": "submitted input",
                "discovery_kind": "seed",
                "is_seed": True,
            }
            for item in inputs
        ]
        seen_targets = {item["normalized_target"] for item in inputs}
        total_targets = len(queue)
        completed_targets = 0
        failed_targets = 0
        saved_runs: list[dict[str, Any]] = []

        update_job_progress(
            job_id,
            stage="enrichment",
            status="running",
            total_targets=total_targets,
            completed_targets=0,
            failed_targets=0,
            percent=5,
        )

        analysis_pool = ThreadPoolExecutor(
            max_workers=ANALYSIS_WORKERS, thread_name_prefix="target-analysis"
        )
        pending: dict[Future[AnalysisRun], dict[str, Any]] = {}

        def _analyze(item: dict[str, Any]) -> AnalysisRun:
            item["_started"] = time.monotonic()
            origin = item.get("discovered_from")
            reason = item.get("discovery_reason")
            detail = f" (depth {item['depth']}"
            if origin:
                detail += f", from {origin}"
            if reason:
                detail += f", {reason}"
            detail += ")"
            self._log(
                job_id, "info", f"Analyzing {item['target']}{detail}", stage="enrichment"
            )
            return analyze_target(
                item["target"],
                depth=item["depth"],
                discovered_from=item["discovered_from"],
                discovery_reason=item["discovery_reason"],
                discovery_kind=item["discovery_kind"],
                is_seed=item["is_seed"],
                logger=lambda level, message: self._log(
                    job_id,
                    level,
                    message,
                    stage="enrichment",
                ),
            )

        def _submit(item: dict[str, Any]) -> None:
            pending[analysis_pool.submit(_analyze, item)] = item

        try:
            # Targets are analyzed concurrently: seeds first, then follow-up
            # targets discovered along the way are fed back into the pool.
            for item in queue:
                _submit(item)
            queue.clear()

            while pending:
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    item = pending.pop(future)
                    current_target = item["target"]
                    try:
                        run = future.result()
                        run_id = save_search_run(
                            case_id,
                            root_input=item["root_input"],
                            normalized_target=run.normalized_target,
                            target_type=run.target_type,
                            depth=run.depth,
                            discovered_from=run.discovered_from,
                            discovery_reason=run.discovery_reason,
                            discovery_kind=run.discovery_kind,
                            is_seed=run.is_seed,
                            status=run.status,
                            error=run.error,
                            payload=run.payload,
                            helpers=run.helpers,
                        )
                        saved_runs.append({"id": run_id, "analysis": run})
                        completed_targets += 1
                        started_at = item.get("_started")
                        elapsed = time.monotonic() - started_at if started_at else 0.0
                        self._log(
                            job_id,
                            "success",
                            f"Completed {current_target} in {elapsed:.1f}s "
                            f"({completed_targets}/{total_targets} done, {failed_targets} failed)",
                            stage="enrichment",
                        )

                        for discovered in run.discovered_targets:
                            target = clean_target(str(discovered.get("target") or ""))
                            if (
                                not target
                                or target in seen_targets
                                or target == run.normalized_target
                                or item["depth"] >= 1
                            ):
                                continue
                            seen_targets.add(target)
                            total_targets += 1
                            reason = discovered.get("reason") or "discovered"
                            kind = discovered.get("kind") or "?"
                            self._log(
                                job_id,
                                "info",
                                f"Queued follow-up {target} "
                                f"(kind={kind}, reason: {reason}, from {run.normalized_target})",
                                stage="enrichment",
                            )
                            _submit(
                                {
                                    "target": target,
                                    "root_input": item["root_input"],
                                    "depth": item["depth"] + 1,
                                    "discovered_from": run.normalized_target,
                                    "discovery_reason": discovered.get("reason"),
                                    "discovery_kind": discovered.get("kind"),
                                    "is_seed": False,
                                }
                            )
                    except Exception as exc:  # noqa: BLE001
                        failed_targets += 1
                        self._log(job_id, "warning", f"Failed {current_target}: {exc}", stage="enrichment")

                    update_job_progress(
                        job_id,
                        stage="enrichment",
                        current_target=current_target,
                        total_targets=total_targets,
                        completed_targets=completed_targets,
                        failed_targets=failed_targets,
                        percent=_job_percent("enrichment", completed_targets, failed_targets, total_targets),
                    )

            update_job_progress(
                job_id,
                stage="comparison",
                percent=80,
                current_target=None,
                total_targets=total_targets,
                completed_targets=completed_targets,
                failed_targets=failed_targets,
            )
            self._log(job_id, "info", "Checking pool connections", stage="comparison")
            update_job_progress(
                job_id,
                stage="clustering",
                percent=90,
                total_targets=total_targets,
                completed_targets=completed_targets,
                failed_targets=failed_targets,
            )
            summary = self._build_pool_summary(saved_runs)
            update_job_progress(
                job_id,
                stage="notification",
                percent=95,
                total_targets=total_targets,
                completed_targets=completed_targets,
                failed_targets=failed_targets,
            )
            self._log(job_id, "info", "Sending completion notification", stage="notification")
            complete_case(
                case_id,
                job_id,
                status="completed",
                summary=summary,
                successful_targets=completed_targets,
                failed_targets=failed_targets,
            )
            case_row = get_case(case_id)
            job_row = get_job(job_id)
            if case_row and job_row:
                send_case_notification(case_row, job_row)
                send_case_email(case_row, job_row)
        except Exception as exc:  # noqa: BLE001
            self._log(job_id, "warning", f"Case failed: {exc}", stage="notification")
            complete_case(
                case_id,
                job_id,
                status="failed",
                summary={"error": str(exc)},
                successful_targets=completed_targets,
                failed_targets=failed_targets + 1,
                percent=100,
                error=str(exc),
            )
        finally:
            analysis_pool.shutdown(wait=False, cancel_futures=True)

    def _build_pool_summary(self, runs: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Completion summary for a job, built from the shared correlation pool
        instead of a case-scoped pairwise comparison. Every target this job
        scanned already joined the one global graph inline (analyze_target ->
        intel_db.save_search), so "what did this submission connect to" is
        just the same cross-corpus linkage the /api/graph/* endpoints expose
        (utils.check.links_for) -- there is no separate per-case comparison
        to run.
        """
        seeds = [item for item in runs if item["analysis"].is_seed]
        top_findings: list[dict[str, Any]] = []
        for item in seeds:
            label = pairing_label(item["analysis"].payload)
            try:
                links = check.links_for(label, limit=3)
            except Exception:
                links = []
            for link in links:
                top_findings.append(
                    {
                        "target": label,
                        "linked_target": link.get("target"),
                        "score": link.get("score"),
                        "confidence": link.get("confidence"),
                        "strength": link.get("strength"),
                    }
                )
        top_findings.sort(key=lambda entry: entry.get("score") or 0, reverse=True)
        top_findings = top_findings[:5]
        return {
            "target_count": len(seeds),
            "run_count": len(runs),
            "top_findings": top_findings,
            "highlights": [
                f"{entry['target']} ↔ {entry['linked_target']} (score {entry['score']})"
                for entry in top_findings
            ],
        }

    def _log(self, job_id: str, level: str, message: str, *, stage: str | None = None) -> None:
        # Persist for the frontend's live progress feed...
        append_job_log(job_id, level=level, message=message, stage=stage)
        # ...and mirror the same human-readable line to the server logs so
        # `docker compose logs` shows the actual analysis progress (what the
        # user sees streamed in the UI), not just the HTTP endpoint hits.
        stage_tag = f"/{stage}" if stage else ""
        LOGGER.log(
            _JOB_LOG_LEVELS.get(level, logging.INFO),
            "[job %s%s] %s", job_id, stage_tag, message,
        )


def _job_percent(stage: str, completed_targets: int, failed_targets: int, total_targets: int) -> int:
    if total_targets <= 0:
        return 5
    progress = min(1.0, (completed_targets + failed_targets) / max(total_targets, 1))
    if stage == "enrichment":
        return min(79, max(5, int(progress * 70) + 5))
    if stage == "comparison":
        return 80
    if stage == "clustering":
        return 90
    if stage == "notification":
        return 95
    return 0


def build_job_response(row: dict[str, Any]) -> dict[str, Any]:
    stage = row.get("stage") or row.get("job_stage") or "intake"
    current_stage_index = JOB_STAGES.index(stage) if stage in JOB_STAGES else -1
    status = row.get("job_status") or row.get("status") or "unknown"
    steps: list[dict[str, Any]] = []
    for index, item in enumerate(JOB_STAGES):
        if status in {"completed", "failed"} and index <= current_stage_index:
            status_value = "completed"
        elif index < current_stage_index:
            status_value = "completed"
        elif index == current_stage_index:
            status_value = status
        else:
            status_value = "pending"
        steps.append(
            {
                "id": item,
                "label": item.replace("_", " ").title(),
                "status": status_value,
                "detail": row.get("current_target") if item == stage else None,
            }
        )

    return {
        "id": row.get("id") or row.get("job_id"),
        "status": status,
        "stage": stage,
        "current_step": row.get("current_target") or stage.replace("_", " ").title(),
        "percent": row.get("percent") or row.get("job_percent") or 0,
        "completed_steps": row.get("completed_targets", 0),
        "total_steps": row.get("total_targets", 0),
        "failed_targets": row.get("failed_targets", 0),
        "updated_at": row.get("updated_at") or row.get("job_updated_at"),
        "logs": list(row.get("logs") or []),
        "steps": steps,
        "summary": _job_summary(row),
        "error": row.get("error"),
    }


def _job_summary(row: dict[str, Any]) -> str:
    status = row.get("job_status") or row.get("status") or "unknown"
    completed = row.get("completed_targets", 0)
    total = row.get("total_targets", 0)
    failed = row.get("failed_targets", 0)
    current = row.get("current_target")
    if status == "completed":
        return f"Completed {completed} of {total} target scans."
    if status == "failed":
        return row.get("error") or "The job failed before finishing."
    if current:
        return f"Scanning {current}. {completed} of {total} targets completed, {failed} failed."
    return f"{completed} of {total} targets completed."


def parse_submission(target: str | None = None, csv_content: bytes | None = None) -> tuple[list[dict[str, Any]], str]:
    if csv_content:
        targets = parse_csv_targets(csv_content)
        inputs = normalize_inputs(targets)
        return inputs, "csv"
    if target:
        normalized = clean_target(target)
        if not normalized:
            return [], "single"
        return (
            [
                {
                    "input_value": target,
                    "normalized_target": normalized,
                    "target_type": "ip" if ip_intel.is_ip(normalized) else "domain",
                    "upload_row": 1,
                    "source": "single",
                }
            ],
            "single",
        )
    return [], "single"
