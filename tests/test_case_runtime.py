from __future__ import annotations

from core.analysis_service import AnalysisRun, _merge_page_metadata
from cases.case_runtime import (
    CaseRuntime,
    build_case_response,
    build_job_response,
    build_pairs_response,
    parse_submission,
)


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


def test_build_case_response_surfaces_progress_and_counts() -> None:
    payload = build_case_response(
        {
            "id": "case-1",
            "title": "Example case",
            "status": "running",
            "input_mode": "single",
            "job_percent": 44,
            "job_status": "running",
            "job_id": "job-1",
            "targets": ["example.com"],
            "total_targets": 1,
            "successful_targets": 0,
            "failed_targets": 0,
            "summary": {
                "target_count": 1,
                "within_case_pair_count": 0,
                "historical_pair_count": 2,
                "cluster_count": 1,
                "highlights": ["Example highlight"],
            },
        }
    )
    assert payload["progress"] == 44
    assert payload["pair_count"] == 2
    assert payload["cluster_count"] == 1
    assert payload["counts"]["submitted"] == 1


def test_build_pairs_response_returns_slim_summaries(monkeypatch) -> None:
    evidence_items = [
        {"id": "e-dns", "category": "DNS", "importance": "low-signal", "matched_values": ["ns1"]},
        {
            "id": "e-tls",
            "category": "Transport",
            "importance": "decisive",
            "matched_values": ["a", "b", "c", "d", "e"],
        },
        {"id": "e-ssh", "category": "Transport", "importance": "strong", "matched_values": ["x"]},
        {"id": "e-ip", "category": "Infrastructure", "importance": "supporting", "matched_values": ["y"]},
        {"id": "e-ip2", "category": "Infrastructure", "importance": "supporting", "matched_values": ["z"]},
    ]
    monkeypatch.setattr(
        "cases.case_runtime.list_pairings",
        lambda case_id: [
            {
                "id": "pair-1",
                "scope": "within_case",
                "left_target": "alpha.example",
                "right_target": "beta.example",
                "score": 72,
                "match_count": 5,
                "payload": {
                    "summary": "Overlap driven by shared TLS certificates.",
                    "top_paths": ["tls_certs.probes[*].fingerprint_sha256"],
                    "evidence_items": evidence_items,
                },
            },
            {
                "id": "pair-2",
                "scope": "historical",
                "left_target": "alpha.example",
                "right_target": "gamma.example",
                "score": 31,
                "match_count": 1,
                "payload": {"evidence_items": []},
            },
        ],
    )
    monkeypatch.setattr(
        "cases.case_runtime.load_case_inputs",
        lambda case_id: [
            {"normalized_target": "beta.example"},
            {"normalized_target": "alpha.example"},
        ],
    )

    response = build_pairs_response("case-1")

    # The duplicated within_case/historical arrays are gone; the frontend
    # filters the single pairs list by scope.
    assert set(response.keys()) == {"pairs", "seed_targets"}
    assert response["seed_targets"] == ["alpha.example", "beta.example"]

    first = response["pairs"][0]
    assert first["id"] == "pair-1"
    assert first["scope"] == "within_case"
    assert first["left"] == "alpha.example"
    assert first["right"] == "beta.example"
    assert first["score"] == 72
    assert first["match_count"] == 5
    assert first["is_seed_pair"] is True
    assert first["summary"] == "Overlap driven by shared TLS certificates."
    assert first["top_paths"] == ["tls_certs.probes[*].fingerprint_sha256"]
    # Only the strongest evidence ships inline, ordered by importance.
    assert [item["id"] for item in first["evidence"]] == ["e-tls", "e-ssh", "e-ip"]
    assert first["evidence_count"] == 5
    assert first["evidence_counts"] == {"Transport": 2, "Infrastructure": 2, "DNS": 1}
    # Inline matched values are capped, with the original count preserved.
    assert first["evidence"][0]["matched_values"] == ["a", "b", "c"]
    assert first["evidence"][0]["matched_value_count"] == 5
    assert "evidence_items" not in first

    second = response["pairs"][1]
    assert second["is_seed_pair"] is False
    assert second["evidence"] == []
    assert second["evidence_count"] == 0
    assert second["evidence_counts"] == {}


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


def test_build_clusters_include_observed_ips_from_current_and_historical_runs(monkeypatch) -> None:
    monkeypatch.setattr(
        "cases.case_runtime.list_search_runs_by_ids",
        lambda run_ids: [
            {
                "id": "run-b",
                "payload": {
                    "domain": "beta.example",
                    "comparison_labels": {"display": "beta.example"},
                },
                "observed_ips": [{"ip": "198.51.100.20", "source": "dns:A"}],
            }
        ]
        if run_ids == ["run-b"]
        else [],
    )

    runtime = CaseRuntime(cluster_threshold=30)
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
                payload={
                    "domain": "alpha.example",
                    "comparison_labels": {"display": "alpha.example"},
                },
                helpers={"observed_ips": [{"ip": "198.51.100.10", "source": "dns:A"}]},
            ),
        }
    ]
    pairings = [
        {
            "id": "pair-1",
            "scope": "historical",
            "left_run_id": "run-a",
            "right_run_id": "run-b",
            "left_target": "alpha.example",
            "right_target": "beta.example",
            "score": 72,
            "match_count": 1,
            "payload": {"matches": {"non_cf_ips": ["198.51.100.10"]}},
        }
    ]

    payload, graph = runtime._build_clusters(runs, pairings)

    assert payload["cluster_count"] == 1
    assert payload["entity_count"] == 4
    assert payload["clusters"][0]["members"] == [
        "alpha.example",
        "beta.example",
        "198.51.100.10",
        "198.51.100.20",
    ]
    assert payload["clusters"][0]["related_ip_count"] == 2
    # Observed IPs stay in the cluster payload (above), but the connection map is
    # now limited to submitted domains and the subdomains that bridge them. IP
    # nodes and non-submitted historical partners (beta.example here) are left
    # off the graph, so with a single submitted domain there are no qualifying
    # cross-submitted links to draw.
    graph_labels = {node["label"] for node in graph["nodes"]}
    assert "198.51.100.10" not in graph_labels
    assert "198.51.100.20" not in graph_labels
    assert graph_labels <= {"alpha.example"}
