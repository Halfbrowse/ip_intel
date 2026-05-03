from __future__ import annotations

import itertools
import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any

import cluster
import check
import ip_intel
import basic
from analysis_service import AnalysisRun, analyze_target, clean_target, normalize_inputs, pairing_label, parse_csv_targets
from case_store import (
    JOB_STAGES,
    append_job_log,
    complete_case,
    create_case,
    find_historical_candidates,
    get_case,
    get_job,
    list_search_runs_by_ids,
    list_pairings,
    list_search_runs,
    load_case_inputs,
    mark_case_started,
    recoverable_jobs,
    replace_cluster,
    replace_pairings,
    save_search_run,
    update_job_progress,
)
from evidence_meta import evidence_definition
from mattermost_alerts import send_case_notification


DEFAULT_CLUSTER_THRESHOLD = 30


class CaseRuntime:
    def __init__(self, *, cluster_threshold: int = DEFAULT_CLUSTER_THRESHOLD) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="case-runtime")
        self._lock = threading.Lock()
        self._futures: dict[str, Future[Any]] = {}
        self._cluster_threshold = cluster_threshold

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

        try:
            while queue:
                item = queue.pop(0)
                current_target = item["target"]
                update_job_progress(
                    job_id,
                    stage="enrichment",
                    current_target=current_target,
                    total_targets=total_targets,
                    completed_targets=completed_targets,
                    failed_targets=failed_targets,
                    percent=_job_percent("enrichment", completed_targets, failed_targets, total_targets),
                )
                self._log(job_id, "info", f"Analyzing {current_target}", stage="enrichment")

                try:
                    run = analyze_target(
                        current_target,
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
                    self._log(job_id, "success", f"Completed {current_target}", stage="enrichment")

                    for discovered in run.discovered_targets:
                        target = clean_target(str(discovered.get("target") or ""))
                        if not target or target in seen_targets or item["depth"] >= 1:
                            continue
                        seen_targets.add(target)
                        queue.append(
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
                        total_targets += 1
                        self._log(
                            job_id,
                            "info",
                            f"Queued follow-up target {target}",
                            stage="enrichment",
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
            self._log(job_id, "info", "Building overlap pairings", stage="comparison")
            pairings = self._build_pairings(case_id, saved_runs)
            replace_pairings(case_id, pairings)

            update_job_progress(
                job_id,
                stage="clustering",
                percent=90,
                total_targets=total_targets,
                completed_targets=completed_targets,
                failed_targets=failed_targets,
            )
            self._log(job_id, "info", "Building cluster graph", stage="clustering")
            cluster_payload, graph_payload = self._build_clusters(saved_runs, pairings)
            replace_cluster(
                case_id,
                threshold=self._cluster_threshold,
                payload=cluster_payload,
                graph_payload=graph_payload,
            )

            summary = self._build_summary(saved_runs, pairings, cluster_payload)
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

    def _build_pairings(self, case_id: str, runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        pairings: list[dict[str, Any]] = []
        successful = [item for item in runs if item["analysis"].status == "completed"]

        for left, right in itertools.combinations(successful, 2):
            pairing = _pair_record(
                scope="within_case",
                left_run_id=left["id"],
                right_run_id=right["id"],
                left=left["analysis"],
                right=right["analysis"],
            )
            if pairing is not None:
                pairings.append(pairing)

        for left in successful:
            for historical in find_historical_candidates(
                case_id,
                left["analysis"].normalized_target,
                left["analysis"].helpers,
            ):
                right_payload = dict(historical["payload"] or {})
                right_analysis = AnalysisRun(
                    target=historical["root_input"],
                    normalized_target=historical["normalized_target"],
                    target_type=historical["target_type"],
                    depth=historical["depth"],
                    discovered_from=historical.get("discovered_from"),
                    discovery_reason=historical.get("discovery_reason"),
                    discovery_kind=historical.get("discovery_kind"),
                    is_seed=historical.get("is_seed", False),
                    payload=right_payload,
                    helpers={},
                )
                pairing = _pair_record(
                    scope="historical",
                    left_run_id=left["id"],
                    right_run_id=historical["id"],
                    left=left["analysis"],
                    right=right_analysis,
                )
                if pairing is not None:
                    pairings.append(pairing)

        pairings.sort(key=lambda item: (item["scope"], -item["score"], item["left_target"], item["right_target"]))
        return pairings

    def _build_clusters(
        self,
        runs: list[dict[str, Any]],
        pairings: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        member_details = _cluster_member_details(runs, pairings)
        labels = {pairing_label(item["analysis"].payload) for item in runs}
        labels.update(member_details)
        labels.update(item["left_target"] for item in pairings)
        labels.update(item["right_target"] for item in pairings)

        union_find = cluster.UnionFind()
        for label in labels:
            union_find.find(label)

        edges_used: list[dict[str, Any]] = []
        for item in pairings:
            if item["score"] < self._cluster_threshold:
                continue
            payload = item["payload"]
            matches = payload.get("matches", {}) or {}
            left = item["left_target"]
            right = item["right_target"]
            union_find.union(left, right)
            edges_used.append(
                {
                    "a": left,
                    "b": right,
                    "score": item["score"],
                    "paths": list(matches.keys()),
                    "has_strong": bool(cluster.STRONG_PATHS & set(matches.keys())),
                }
            )

        groups = union_find.groups()
        cluster_items: list[dict[str, Any]] = []
        isolates: list[str] = []
        for members in groups.values():
            target_members = sorted(members)
            if len(target_members) < 2:
                isolates.extend(target_members)
                continue
            members, observation_edges = _cluster_entity_members(target_members, member_details)
            item = cluster._summarize_cluster(target_members, edges_used)
            item["members"] = members
            item["member_count"] = len(members)
            item["target_count"] = len(target_members)
            item["related_ips"] = [member for member in members if member not in target_members]
            item["related_ip_count"] = len(item["related_ips"])
            item["edges"] = [*item.get("edges", []), *observation_edges]
            cluster_items.append(item)
        cluster_items.sort(key=lambda item: (-item["max_edge_score"], -item.get("target_count", len(item["members"]))))
        isolates.sort()

        all_entities = set(isolates)
        for item in cluster_items:
            all_entities.update(item["members"])

        result = {
            "threshold": self._cluster_threshold,
            "domain_count": len(labels),
            "entity_count": len(all_entities),
            "cluster_count": len(cluster_items),
            "edge_count": len(edges_used),
            "clusters": cluster_items,
            "isolates": isolates,
        }
        return result, cluster.build_graph_payload(result)

    def _build_summary(
        self,
        runs: list[dict[str, Any]],
        pairings: list[dict[str, Any]],
        cluster_payload: dict[str, Any],
    ) -> dict[str, Any]:
        within_case = [item for item in pairings if item["scope"] == "within_case"]
        historical = [item for item in pairings if item["scope"] == "historical"]
        top_findings = [
            {
                "pairing_id": item["id"],
                "scope": item["scope"],
                "left_target": item["left_target"],
                "right_target": item["right_target"],
                "score": item["score"],
                "top_evidence": item["payload"].get("top_paths", []),
                "summary": item["payload"].get("summary"),
            }
            for item in sorted(pairings, key=lambda entry: entry["score"], reverse=True)[:3]
        ]
        return {
            "target_count": len([item for item in runs if item["analysis"].is_seed]),
            "run_count": len(runs),
            "within_case_pair_count": len(within_case),
            "historical_pair_count": len(historical),
            "cluster_count": cluster_payload.get("cluster_count", 0),
            "top_findings": top_findings,
            "highlights": [item["summary"] for item in top_findings if item.get("summary")],
        }

    def _log(self, job_id: str, level: str, message: str, *, stage: str | None = None) -> None:
        append_job_log(job_id, level=level, message=message, stage=stage)


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


def _cluster_member_details(
    runs: list[dict[str, Any]],
    pairings: list[dict[str, Any]],
) -> dict[str, list[dict[str, str]]]:
    details: dict[str, list[dict[str, str]]] = {}
    current_run_ids = {item["id"] for item in runs}

    def merge(label: str, observed_ips: list[dict[str, Any]]) -> None:
        entries = details.setdefault(label, [])
        seen = {(item["ip"], item["source"]) for item in entries}
        for item in observed_ips:
            ip = str(item.get("ip") or "").strip()
            source = str(item.get("source") or "observed").strip() or "observed"
            key = (ip, source)
            if not ip or key in seen:
                continue
            seen.add(key)
            entries.append({"ip": ip, "source": source})
        entries.sort(key=lambda item: (item["ip"], item["source"]))

    for item in runs:
        analysis = item["analysis"]
        merge(
            pairing_label(analysis.payload),
            list(analysis.helpers.get("observed_ips") or []),
        )

    historical_ids = {
        pair["left_run_id"]
        for pair in pairings
        if pair["left_run_id"] not in current_run_ids
    } | {
        pair["right_run_id"]
        for pair in pairings
        if pair["right_run_id"] not in current_run_ids
    }
    for row in list_search_runs_by_ids(sorted(historical_ids)):
        payload = row.get("payload") or {}
        merge(pairing_label(payload), list(row.get("observed_ips") or []))

    return details


def _cluster_entity_members(
    target_members: list[str],
    member_details: dict[str, list[dict[str, str]]],
) -> tuple[list[str], list[dict[str, Any]]]:
    members = list(target_members)
    member_set = set(target_members)
    observation_edges: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str, str]] = set()

    for label in target_members:
        for item in member_details.get(label, []):
            ip = item["ip"]
            source = item["source"]
            if ip not in member_set:
                member_set.add(ip)
                members.append(ip)
            edge_key = (label, ip, source)
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)
            observation_edges.append(
                {
                    "a": label,
                    "b": ip,
                    "score": 1,
                    "paths": [f"observed_ip:{source}"],
                    "has_strong": False,
                }
            )

    return members, observation_edges


def _pair_record(
    *,
    scope: str,
    left_run_id: str,
    right_run_id: str,
    left: AnalysisRun,
    right: AnalysisRun,
) -> dict[str, Any] | None:
    pair = check.compare_pair(left.payload, right.payload)
    if pair["match_count"] == 0 and not pair["urlscan_cross_refs"]:
        return None

    left_target = pairing_label(left.payload)
    right_target = pairing_label(right.payload)
    pair["scope"] = scope
    pair["a_domain"] = left_target
    pair["b_domain"] = right_target
    pair["top_paths"] = sorted(
        pair["matches"].keys(),
        key=lambda value: -check.MATCH_WEIGHTS.get(value, 5),
    )[:5]
    pair["summary"] = _pair_summary(pair)
    pair["evidence_items"] = _pair_evidence(pair)

    return {
        "id": str(uuid.uuid4()),
        "scope": scope,
        "left_run_id": left_run_id,
        "right_run_id": right_run_id,
        "left_target": left_target,
        "right_target": right_target,
        "score": int(pair["score"]),
        "match_count": int(pair["match_count"]),
        "payload": pair,
    }


def _pair_summary(pair: dict[str, Any]) -> str:
    paths = pair.get("top_paths", []) or []
    if not paths:
        return "The pair only shared low-level context."
    labels = [evidence_definition(path).label for path in paths[:3]]
    summary = ", ".join(labels[:-1] + [labels[-1]]) if len(labels) == 1 else ", ".join(labels[:-1]) + f", and {labels[-1]}"
    return f"Overlap driven by {summary.lower()}."


def _pair_evidence(pair: dict[str, Any]) -> list[dict[str, Any]]:
    evidence_items: list[dict[str, Any]] = []
    cert_quality = pair.get("cert_quality") or {}
    freshness = pair.get("freshness") or {}

    for path, value in (pair.get("matches") or {}).items():
        definition = evidence_definition(path)
        importance = _evidence_importance(path, definition.base_importance, cert_quality, freshness)
        evidence_items.append(
            {
                "id": path,
                "type": path,
                "label": definition.label,
                "category": definition.category,
                "importance": importance,
                "description": definition.description,
                "why_it_matters": definition.why_it_matters,
                "caveat": _evidence_caveat(path, definition.caveat, cert_quality, freshness),
                "matched_values": value if isinstance(value, list) else [value],
            }
        )

    for index, item in enumerate(pair.get("urlscan_cross_refs") or []):
        evidence_items.append(
            {
                "id": f"urlscan-cross-ref-{index}",
                "type": "urlscan_cross_refs",
                "label": "Shared urlscan cross-reference",
                "category": "Web content",
                "importance": "supporting" if item.get("relationship") != "shared_referrer" else "strong",
                "description": "urlscan observed both targets on a shared or related rendered page context.",
                "why_it_matters": "It can show embedding, shared referrers, or adjacent hosting history.",
                "caveat": "Rendered-scan data needs manual review because edges and third-party content can add noise.",
                "matched_values": [item],
            }
        )
    return evidence_items


def _evidence_importance(
    path: str,
    base_importance: str,
    cert_quality: dict[str, Any],
    freshness: dict[str, Any],
) -> str:
    if path == "tls_certs.probes[*].fingerprint_sha256":
        quality = cert_quality.get("quality")
        if quality == "junk":
            return "low-signal"
        if quality == "weak":
            return "strong"
        return "decisive"
    if path == "ssh_host_keys.probes[*].fingerprint_sha256" and freshness.get("platform_demotes_ssh"):
        return "supporting"
    if path in {"non_cf_ips", "dns.A", "hackertarget.hits[*].ip", "urlscan.hits[*].ip", "circl_pdns.records[*].rdata"}:
        quality = freshness.get("ip_match_quality")
        if quality == "historical":
            return "supporting"
        if quality == "mixed":
            return "strong"
        if quality == "current":
            return "strong"
    return base_importance


def _evidence_caveat(
    path: str,
    default_caveat: str,
    cert_quality: dict[str, Any],
    freshness: dict[str, Any],
) -> str:
    caveats = [default_caveat]
    if path == "tls_certs.probes[*].fingerprint_sha256" and cert_quality.get("reason"):
        caveats.append(str(cert_quality["reason"]))
    if path == "ssh_host_keys.probes[*].fingerprint_sha256" and freshness.get("platform_demotes_ssh"):
        caveats.append("The hosting platform context suggests this SSH key may belong to shared platform infrastructure.")
    if path in {"non_cf_ips", "dns.A", "hackertarget.hits[*].ip", "urlscan.hits[*].ip", "circl_pdns.records[*].rdata"} and freshness.get("ip_match_quality"):
        caveats.append(f"IP overlap context: {freshness['ip_match_quality']}.")
    return " ".join(caveats)


def build_case_response(case_row: dict[str, Any]) -> dict[str, Any]:
    summary = case_row.get("summary") or {}
    return {
        "id": case_row["id"],
        "title": case_row["title"],
        "status": case_row["status"],
        "input_mode": case_row["input_mode"],
        "summary": _summary_text(summary),
        "progress": case_row.get("job_percent", 0),
        "job_status": case_row.get("job_status"),
        "pair_count": summary.get("within_case_pair_count", 0) + summary.get("historical_pair_count", 0),
        "cluster_count": summary.get("cluster_count", 0),
        "targets": list(case_row.get("targets") or []),
        "created_at": case_row.get("created_at"),
        "updated_at": case_row.get("updated_at"),
        "started_at": case_row.get("started_at"),
        "finished_at": case_row.get("finished_at"),
        "job_id": case_row.get("job_id"),
        "job": build_job_response(case_row),
        "metrics": {
            "pairs": summary.get("within_case_pair_count", 0) + summary.get("historical_pair_count", 0),
            "clusters": summary.get("cluster_count", 0),
            "targets": summary.get("target_count", case_row.get("total_targets", 0)),
        },
        "highlights": summary.get("highlights", []),
        "counts": {
            "submitted": case_row.get("total_targets", 0),
            "successful": case_row.get("successful_targets", 0),
            "failed": case_row.get("failed_targets", 0),
        },
        "raw_summary": summary,
    }


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


def build_pairs_response(case_id: str) -> dict[str, Any]:
    rows = list_pairings(case_id)
    items = []
    within_case = []
    historical = []
    for row in rows:
        payload = row.get("payload") or {}
        item = {
            "id": row["id"],
            "scope": row["scope"],
            "status": "completed",
            "left": row["left_target"],
            "right": row["right_target"],
            "score": row["score"],
            "summary": payload.get("summary"),
            "evidence": payload.get("evidence_items", []),
            "top_paths": payload.get("top_paths", []),
            "match_count": row["match_count"],
        }
        items.append(item)
        if row["scope"] == "within_case":
            within_case.append(item)
        else:
            historical.append(item)
    return {
        "pairs": items,
        "within_case": within_case,
        "historical": historical,
    }


def _summary_text(summary: dict[str, Any]) -> str:
    target_count = int(summary.get("target_count", 0))
    overlap_count = int(summary.get("within_case_pair_count", 0)) + int(summary.get("historical_pair_count", 0))
    cluster_count = int(summary.get("cluster_count", 0))
    return f"{target_count} targets scanned, {overlap_count} overlaps recorded, {cluster_count} clusters built."


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
