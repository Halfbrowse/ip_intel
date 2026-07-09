from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from core import basic
from core.analysis_service import AnalysisRun, _merge_page_metadata
from cases.case_runtime import (
    CaseRuntime,
    build_job_response,
    parse_submission,
)


def test_basic_runtime_hooks_are_context_local() -> None:
    def _run(label: str) -> list[tuple[str, str, object]]:
        events: list[tuple[str, str, object]] = []

        def _log(message: str, level: str = "*") -> None:
            events.append((label, level, message))

        def _save(results: dict) -> None:
            events.append((label, "save", results["label"]))

        with basic.runtime_hooks(log_hook=_log, save_hook=_save):
            basic.log(f"log-{label}", "+")
            basic.save_results({"label": label})
        return events

    with ThreadPoolExecutor(max_workers=2) as executor:
        left, right = executor.map(_run, ["left", "right"])

    assert left == [("left", "+", "log-left"), ("left", "save", "left")]
    assert right == [("right", "+", "log-right"), ("right", "save", "right")]


def test_parse_submission_single_target() -> None:
    inputs, mode = parse_submission(target="https://Example.com/")
    assert mode == "single"
    assert len(inputs) == 1
    assert inputs[0]["normalized_target"] == "example.com"
    assert inputs[0]["target_type"] == "domain"


def test_parse_submission_csv_deduplicates_first_column() -> None:
    csv_content = b"example.com,ignored\nhttps://example.com/\n203.0.113.10\n"
    inputs, mode = parse_submission(csv_content=csv_content)
    assert mode == "csv"
    assert [item["normalized_target"] for item in inputs] == ["example.com", "203.0.113.10"]


def test_build_job_response_exposes_stage_and_steps() -> None:
    payload = build_job_response(
        {
            "job_id": "job-1",
            "job_status": "running",
            "job_stage": "comparison",
            "job_percent": 80,
            "completed_targets": 3,
            "failed_targets": 1,
            "total_targets": 5,
            "current_target": "alpha.example",
            "logs": [{"level": "info", "message": "hello"}],
        }
    )
    assert payload["id"] == "job-1"
    assert payload["status"] == "running"
    assert payload["stage"] == "comparison"
    assert payload["steps"][2]["status"] == "running"
    assert payload["failed_targets"] == 1


def test_build_pool_summary_ranks_findings_from_pool_links(monkeypatch) -> None:
    def _fake_links_for(value, limit=3):
        if value == "alpha.example":
            return [
                {"target": "beta.example", "score": 72, "confidence": 60, "strength": "strong"},
                {"target": "gamma.example", "score": 12, "confidence": 15, "strength": "weak"},
            ]
        return []

    monkeypatch.setattr("cases.case_runtime.check.links_for", _fake_links_for)

    runtime = CaseRuntime()
    runs = [
        {
            "id": "run-a",
            "analysis": AnalysisRun(
                target="alpha.example",
                normalized_target="alpha.example",
                target_type="domain",
                depth=0,
                discovered_from=None,
                discovery_reason=None,
                discovery_kind=None,
                is_seed=True,
                payload={"domain": "alpha.example", "comparison_labels": {"display": "alpha.example"}},
            ),
        },
        {
            "id": "run-b",
            "analysis": AnalysisRun(
                target="vpn.alpha.example",
                normalized_target="vpn.alpha.example",
                target_type="domain",
                depth=1,
                discovered_from="alpha.example",
                discovery_reason="follow-up subdomain leak",
                discovery_kind="subdomain_followup",
                is_seed=False,
                payload={"domain": "vpn.alpha.example", "comparison_labels": {"display": "vpn.alpha.example"}},
            ),
        },
    ]

    summary = runtime._build_pool_summary(runs)

    assert summary["target_count"] == 1  # only the seed, not the follow-up subdomain
    assert summary["run_count"] == 2
    assert [f["linked_target"] for f in summary["top_findings"]] == ["beta.example", "gamma.example"]
    assert summary["highlights"][0] == "alpha.example ↔ beta.example (score 72)"


def test_merge_page_metadata_handles_list_entries_with_dicts() -> None:
    merged = _merge_page_metadata(
        {
            "script_assets": [{"src": "https://example.com/app.js"}],
            "google_analytics": ["G-BASE"],
        },
        {
            "script_assets": [
                {"src": "https://example.com/app.js"},
                {"src": "https://example.com/runtime.js"},
            ],
            "google_analytics": ["G-BASE", "G-EXTRA"],
        },
    )

    assert merged["script_assets"] == [
        {"src": "https://example.com/app.js"},
        {"src": "https://example.com/runtime.js"},
    ]
    assert merged["google_analytics"] == ["G-BASE", "G-EXTRA"]
