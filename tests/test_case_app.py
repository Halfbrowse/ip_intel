from __future__ import annotations

from datetime import datetime, timezone

from fastapi.middleware.gzip import GZipMiddleware
from fastapi.testclient import TestClient

import cases.case_app as case_app


def _case_row(case_id: str = "case-1") -> dict:
    return {
        "id": case_id,
        "title": "Example case",
        "status": "completed",
        "input_mode": "single",
        "job_percent": 100,
        "job_status": "completed",
        "job_id": "job-1",
        "targets": ["example.com"],
        "total_targets": 1,
        "successful_targets": 1,
        "failed_targets": 0,
        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "updated_at": datetime(2026, 1, 2, tzinfo=timezone.utc),
        "started_at": None,
        "finished_at": None,
        "summary": {
            "target_count": 1,
            "within_case_pair_count": 1,
            "historical_pair_count": 0,
            "cluster_count": 1,
            "highlights": [],
        },
    }


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


def test_ingest_delegates_to_runtime(monkeypatch) -> None:
    monkeypatch.setattr(case_app, "init_db", lambda: None)
    monkeypatch.setattr(case_app.runtime, "recover", lambda: None)
    captured: dict = {}

    def _submit(inputs, input_mode):
        captured["input_mode"] = input_mode
        return {"case_id": "case-9", "job_id": "job-9"}

    monkeypatch.setattr(case_app.runtime, "submit_case", _submit)
    monkeypatch.setattr(case_app, "get_case", lambda case_id: None)
    monkeypatch.setattr(case_app, "get_job", lambda job_id: None)

    with TestClient(case_app.app) as client:
        response = client.post("/api/ingest", json={"target": "example.com", "label": "campaign-x"})

    assert response.status_code == 202
    body = response.json()
    assert body["case_id"] == "case-9"
    assert body["label"] == "campaign-x"
    # The optional label becomes the collection tag (input_mode), scoping nothing.
    assert captured["input_mode"] == "campaign-x"


def test_graph_links_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(case_app, "init_db", lambda: None)
    monkeypatch.setattr(case_app.runtime, "recover", lambda: None)
    monkeypatch.setattr(
        case_app.check,
        "links_for",
        lambda value: [
            {"target": "b.com", "score": 100.0, "strength": "strong",
             "evidence": [{"kind": "tls_cert_sha256", "value": "abc", "degree": 2, "weight": 100.0}]}
        ],
    )

    with TestClient(case_app.app) as client:
        response = client.get("/api/graph/links/a.com")

    assert response.status_code == 200
    body = response.json()
    assert body["target"] == "a.com"
    assert body["links"][0]["target"] == "b.com"
    assert body["links"][0]["evidence"][0]["kind"] == "tls_cert_sha256"


def test_graph_link_pair_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(case_app, "init_db", lambda: None)
    monkeypatch.setattr(case_app.runtime, "recover", lambda: None)
    monkeypatch.setattr(
        case_app.check,
        "link_evidence",
        lambda a, b: {"a": a, "b": b, "score": 80.0, "evidence": []},
    )

    with TestClient(case_app.app) as client:
        response = client.get("/api/graph/link", params={"a": "a.com", "b": "b.com"})

    assert response.status_code == 200
    assert response.json()["link"]["a"] == "a.com"


def test_graph_clusters_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(case_app, "init_db", lambda: None)
    monkeypatch.setattr(case_app.runtime, "recover", lambda: None)
    monkeypatch.setattr(
        case_app.intel_db,
        "list_graph_clusters",
        lambda *, min_size, limit: [{"cluster_id": "a.com", "component_size": 2, "members": ["a.com", "b.com"]}],
    )

    with TestClient(case_app.app) as client:
        response = client.get("/api/graph/clusters")

    assert response.status_code == 200
    assert response.json()["clusters"][0]["members"] == ["a.com", "b.com"]


def test_graph_recompute_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(case_app, "init_db", lambda: None)
    monkeypatch.setattr(case_app.runtime, "recover", lambda: None)
    monkeypatch.setattr(case_app.intel_db, "rebuild_all_correlation", lambda: {"searches": 3, "clusters": 1})

    with TestClient(case_app.app) as client:
        response = client.post("/api/graph/recompute")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "recomputed"
    assert body["searches"] == 3


def test_gzip_middleware_is_installed() -> None:
    assert any(middleware.cls is GZipMiddleware for middleware in case_app.app.user_middleware)


def test_cases_list_etag_and_304(monkeypatch) -> None:
    monkeypatch.setattr(case_app, "init_db", lambda: None)
    monkeypatch.setattr(case_app.runtime, "recover", lambda: None)
    monkeypatch.setattr(case_app, "list_cases", lambda: [_case_row()])

    with TestClient(case_app.app) as client:
        first = client.get("/api/cases")
        assert first.status_code == 200
        etag = first.headers["etag"]
        assert etag.startswith('"') and etag.endswith('"')
        assert first.json()["cases"][0]["id"] == "case-1"

        unchanged = client.get("/api/cases", headers={"If-None-Match": etag})
        assert unchanged.status_code == 304
        assert unchanged.headers["etag"] == etag
        assert unchanged.content == b""

        stale = client.get("/api/cases", headers={"If-None-Match": '"different"'})
        assert stale.status_code == 200


def test_case_detail_etag_and_304(monkeypatch) -> None:
    monkeypatch.setattr(case_app, "init_db", lambda: None)
    monkeypatch.setattr(case_app.runtime, "recover", lambda: None)
    monkeypatch.setattr(case_app, "get_case", lambda case_id: _case_row(case_id))

    with TestClient(case_app.app) as client:
        first = client.get("/api/cases/case-1")
        assert first.status_code == 200
        etag = first.headers["etag"]
        assert first.json()["case"]["id"] == "case-1"

        unchanged = client.get("/api/cases/case-1", headers={"If-None-Match": etag})
        assert unchanged.status_code == 304
        assert unchanged.headers["etag"] == etag


def test_pairs_endpoint_etag_and_304(monkeypatch) -> None:
    monkeypatch.setattr(case_app, "init_db", lambda: None)
    monkeypatch.setattr(case_app.runtime, "recover", lambda: None)
    monkeypatch.setattr(case_app, "get_case", lambda case_id: _case_row(case_id))
    monkeypatch.setattr(
        case_app,
        "build_pairs_response",
        lambda case_id: {
            "pairs": [
                {
                    "id": "pair-1",
                    "scope": "within_case",
                    "status": "completed",
                    "left": "alpha.example",
                    "right": "beta.example",
                    "score": 72,
                    "summary": "Overlap driven by shared TLS certificates.",
                    "evidence": [],
                    "evidence_count": 0,
                    "evidence_counts": {},
                    "top_paths": [],
                    "match_count": 1,
                    "is_seed_pair": True,
                }
            ],
            "seed_targets": ["alpha.example", "beta.example"],
        },
    )

    with TestClient(case_app.app) as client:
        first = client.get("/api/cases/case-1/pairs")
        assert first.status_code == 200
        etag = first.headers["etag"]
        body = first.json()
        assert body["pairs"][0]["id"] == "pair-1"
        assert "within_case" not in body
        assert "historical" not in body

        unchanged = client.get("/api/cases/case-1/pairs", headers={"If-None-Match": etag})
        assert unchanged.status_code == 304
        assert unchanged.headers["etag"] == etag
