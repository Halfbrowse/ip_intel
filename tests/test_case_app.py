from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

import case_app


def test_create_case_json_submission(monkeypatch) -> None:
    monkeypatch.setattr(case_app, "init_db", lambda: None)
    monkeypatch.setattr(case_app.runtime, "recover", lambda: None)
    monkeypatch.setattr(
        case_app.runtime,
        "submit_case",
        lambda inputs, input_mode: {"case_id": "case-1", "job_id": "job-1"},
    )
    monkeypatch.setattr(
        case_app,
        "get_case",
        lambda case_id: {
            "id": case_id,
            "title": "Example case",
            "status": "queued",
            "input_mode": "single",
            "job_percent": 0,
            "job_status": "queued",
            "job_id": "job-1",
            "targets": ["example.com"],
            "total_targets": 1,
            "successful_targets": 0,
            "failed_targets": 0,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "started_at": None,
            "finished_at": None,
            "summary": {
                "target_count": 1,
                "within_case_pair_count": 0,
                "historical_pair_count": 0,
                "cluster_count": 0,
                "highlights": [],
            },
        },
    )
    monkeypatch.setattr(
        case_app,
        "get_job",
        lambda job_id: {
            "id": job_id,
            "status": "queued",
            "stage": "intake",
            "percent": 0,
            "total_targets": 1,
            "completed_targets": 0,
            "failed_targets": 0,
            "updated_at": datetime.now(timezone.utc),
            "logs": [],
        },
    )

    with TestClient(case_app.app) as client:
        response = client.post("/api/cases", json={"target": "example.com"})

    assert response.status_code == 202
    body = response.json()
    assert body["case_id"] == "case-1"
    assert body["job_id"] == "job-1"
    assert body["case"]["targets"] == ["example.com"]


def test_evidence_meta_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(case_app, "init_db", lambda: None)
    monkeypatch.setattr(case_app.runtime, "recover", lambda: None)

    with TestClient(case_app.app) as client:
        response = client.get("/api/meta/evidence")

    assert response.status_code == 200
    body = response.json()
    assert any(item["type"] == "tls_certs.probes[*].fingerprint_sha256" for item in body["evidence"])
