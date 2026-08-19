from __future__ import annotations

from fastapi.middleware.gzip import GZipMiddleware
from fastapi.testclient import TestClient

import cases.case_app as case_app


def _quiet(monkeypatch) -> None:
    monkeypatch.setattr(case_app, "init_db", lambda: None)
    monkeypatch.setattr(case_app.runtime, "recover", lambda: None)
    # Take Redis out of the picture for every endpoint test. Without this the
    # app's lifespan warms a live cache from a live database, and the endpoint
    # then answers from that cache instead of calling the intel_db function the
    # test just monkeypatched — so the assertions run against whatever real
    # data happens to be in the pool. Nulling the client is the single lever:
    # reads, warming and invalidation all go through it, and cases.cache is
    # built to run degraded (computing live) whenever it returns None.
    monkeypatch.setattr(case_app.cache, "_redis_client", lambda: None)


def test_evidence_meta_endpoint(monkeypatch) -> None:
    _quiet(monkeypatch)
    with TestClient(case_app.app) as client:
        response = client.get("/api/meta/evidence")
    assert response.status_code == 200
    body = response.json()
    assert any(item["type"] == "tls_certs.probes[*].fingerprint_sha256" for item in body["evidence"])


def test_gzip_middleware_is_installed() -> None:
    assert any(middleware.cls is GZipMiddleware for middleware in case_app.app.user_middleware)


def test_no_case_routes_remain() -> None:
    paths = {route.path for route in case_app.app.routes}
    assert not any(p.startswith("/api/cases") for p in paths)
    # The pool + connections surface replaces them.
    assert "/api/pool" in paths
    assert "/api/graph/connections" in paths


def test_ingest_adds_to_pool(monkeypatch) -> None:
    _quiet(monkeypatch)
    captured: dict = {}

    def _submit(inputs, input_mode):
        captured["input_mode"] = input_mode
        captured["count"] = len(inputs)
        return {"case_id": "ingest-1", "job_id": "job-9"}

    monkeypatch.setattr(case_app.runtime, "submit_case", _submit)
    monkeypatch.setattr(case_app, "get_job", lambda job_id: None)

    with TestClient(case_app.app) as client:
        response = client.post("/api/ingest", json={"target": "example.com", "label": "campaign-x"})

    assert response.status_code == 202
    body = response.json()
    assert body["job_id"] == "job-9"
    assert body["label"] == "campaign-x"
    assert body["accepted"] == 1
    # The label becomes the ingest tag (input_mode); it scopes nothing.
    assert captured["input_mode"] == "campaign-x"


def test_pool_endpoint(monkeypatch) -> None:
    _quiet(monkeypatch)
    monkeypatch.setattr(
        case_app.intel_db,
        "list_pool_domains",
        lambda **kwargs: {
            "total": 1,
            "offset": kwargs["offset"],
            "limit": kwargs["limit"],
            "domains": [
                {"domain": "a.com", "host_count": 3, "last_seen": "2026-06-01", "cluster_id": "a.com", "cluster_size": 2}
            ],
        },
    )
    with TestClient(case_app.app) as client:
        response = client.get("/api/pool")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["domains"][0]["domain"] == "a.com"


def test_pool_endpoint_passes_server_side_filters(monkeypatch) -> None:
    _quiet(monkeypatch)
    captured: dict = {}

    def _pool(**kwargs):
        captured.update(kwargs)
        return {"total": 7, "offset": kwargs["offset"], "limit": kwargs["limit"], "domains": []}

    monkeypatch.setattr(case_app.intel_db, "list_pool_domains", _pool)
    with TestClient(case_app.app) as client:
        response = client.get(
            "/api/pool",
            params={
                "search": "alpha",
                "provenance": "ingested",
                "sort": "connections",
                "offset": 24,
                "limit": 12,
                "min_connections": 2,
                "max_connections": 20,
                "discovered_after": "2026-01-01",
                "ingested_before": "2026-06-01",
            },
        )

    assert response.status_code == 200
    assert response.json()["total"] == 7
    assert captured["search"] == "alpha"
    assert captured["provenance"] == "ingested"
    assert captured["sort"] == "connections"
    assert captured["offset"] == 24
    assert captured["limit"] == 12
    assert captured["min_connections"] == 2
    assert captured["max_connections"] == 20
    assert captured["discovered_after"] == "2026-01-01"
    assert captured["ingested_before"] == "2026-06-01"
    assert captured["include_total"] is True


def test_domain_endpoint(monkeypatch) -> None:
    _quiet(monkeypatch)
    monkeypatch.setattr(
        case_app.intel_db,
        "domain_profile",
        lambda value: {"domain": value, "hosts": [{"value": value, "kind": "domain"}],
                       "ips": [], "selectors": [], "intel": {"dns": {"A": ["1.2.3.4"]}}},
    )
    with TestClient(case_app.app) as client:
        response = client.get("/api/domain/lonely.com")
    assert response.status_code == 200
    assert response.json()["intel"]["dns"]["A"] == ["1.2.3.4"]


def test_domain_endpoint_404(monkeypatch) -> None:
    _quiet(monkeypatch)
    monkeypatch.setattr(case_app.intel_db, "domain_profile", lambda value: None)
    with TestClient(case_app.app) as client:
        response = client.get("/api/domain/nope.example")
    assert response.status_code == 404


def test_connections_among_endpoint(monkeypatch) -> None:
    _quiet(monkeypatch)
    captured: dict = {}

    def _connections(domains, *, pool_links=False, **_):
        captured["domains"] = domains
        captured["pool_links"] = pool_links
        return {
            "domains": domains,
            "pairs": [{"a": "a.com", "b": "b.com", "score": 82.0, "connected": True, "evidence": []}],
            "connected_pair_count": 1,
        }

    monkeypatch.setattr(case_app.check, "connections_among", _connections)
    with TestClient(case_app.app) as client:
        response = client.post("/api/graph/connections", json={"domains": ["a.com", "b.com"]})
    assert response.status_code == 200
    body = response.json()
    assert body["connected_pair_count"] == 1
    assert captured["domains"] == ["a.com", "b.com"]


def test_connections_requires_domains(monkeypatch) -> None:
    _quiet(monkeypatch)
    with TestClient(case_app.app) as client:
        response = client.post("/api/graph/connections", json={"domains": []})
    assert response.status_code == 400


def test_by_selector_endpoint(monkeypatch) -> None:
    _quiet(monkeypatch)
    monkeypatch.setattr(
        case_app.intel_db,
        "domains_by_selector",
        lambda *, kind, min_domains, limit: [
            {"kind": "tls_cert_sha256", "value": "abc", "degree": 2, "domains": ["a.com", "b.com"]}
        ],
    )
    with TestClient(case_app.app) as client:
        response = client.get("/api/graph/by-selector", params={"kind": "tls_cert_sha256"})
    assert response.status_code == 200
    body = response.json()
    assert body["kind"] == "tls_cert_sha256"
    assert body["groups"][0]["domains"] == ["a.com", "b.com"]


def test_selector_kinds_endpoint(monkeypatch) -> None:
    _quiet(monkeypatch)
    monkeypatch.setattr(
        case_app.intel_db,
        "selector_kind_counts",
        lambda *, min_domains: [{"kind": "tls_cert_sha256", "groups": 5}, {"kind": "shared_ip", "groups": 3}],
    )
    with TestClient(case_app.app) as client:
        response = client.get("/api/graph/selector-kinds")
    assert response.status_code == 200
    assert response.json()["kinds"][0]["kind"] == "tls_cert_sha256"


def test_graph_links_endpoint(monkeypatch) -> None:
    _quiet(monkeypatch)
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


def test_graph_link_pair_endpoint(monkeypatch) -> None:
    _quiet(monkeypatch)
    monkeypatch.setattr(case_app.check, "link_evidence", lambda a, b: {"a": a, "b": b, "score": 80.0, "evidence": []})
    with TestClient(case_app.app) as client:
        response = client.get("/api/graph/link", params={"a": "a.com", "b": "b.com"})
    assert response.status_code == 200
    assert response.json()["link"]["a"] == "a.com"


def test_graph_path_endpoint(monkeypatch) -> None:
    _quiet(monkeypatch)
    monkeypatch.setattr(
        case_app.intel_db,
        "path_between",
        lambda a, b: {"a": a, "b": b, "hops": 2, "chain": [
            {"from": "a.com", "to": "b.com", "score": 90.0, "evidence": []},
            {"from": "b.com", "to": "c.com", "score": 85.0, "evidence": []},
        ]},
    )
    with TestClient(case_app.app) as client:
        response = client.get("/api/graph/path", params={"a": "a.com", "b": "c.com"})
    assert response.status_code == 200
    body = response.json()
    assert body["path"]["hops"] == 2
    assert body["path"]["chain"][0]["to"] == "b.com"


def test_graph_path_endpoint_404_when_unreachable(monkeypatch) -> None:
    _quiet(monkeypatch)
    monkeypatch.setattr(case_app.intel_db, "path_between", lambda a, b: None)
    with TestClient(case_app.app) as client:
        response = client.get("/api/graph/path", params={"a": "a.com", "b": "z.com"})
    assert response.status_code == 404


def test_graph_path_requires_both_params(monkeypatch) -> None:
    _quiet(monkeypatch)
    with TestClient(case_app.app) as client:
        response = client.get("/api/graph/path", params={"a": "a.com"})
    assert response.status_code == 422  # FastAPI's own required-query-param validation


def test_graph_related_endpoint(monkeypatch) -> None:
    _quiet(monkeypatch)
    monkeypatch.setattr(
        case_app.intel_db,
        "related_through",
        lambda value, *, max_hops, limit: [{"target": "b.com", "hops": 1, "min_hop_score": 90.0, "chain": []}],
    )
    with TestClient(case_app.app) as client:
        response = client.get("/api/graph/related/a.com")
    assert response.status_code == 200
    body = response.json()
    assert body["target"] == "a.com"
    assert body["total"] == 1
    assert body["related"][0]["target"] == "b.com"


def test_search_endpoint(monkeypatch) -> None:
    _quiet(monkeypatch)
    captured: dict = {}

    def _search(q, *, limit):
        captured["q"] = q
        captured["limit"] = limit
        return {"query": q, "domains": [{"domain": "a.com", "connection_count": 2, "cluster_id": None, "tier": None}], "selectors": []}

    monkeypatch.setattr(case_app.intel_db, "search_targets", _search)
    with TestClient(case_app.app) as client:
        response = client.get("/api/search", params={"q": "a.co", "limit": 5})
    assert response.status_code == 200
    body = response.json()
    assert body["domains"][0]["domain"] == "a.com"
    assert captured["q"] == "a.co"
    assert captured["limit"] == 5


def test_graph_clusters_endpoint(monkeypatch) -> None:
    _quiet(monkeypatch)
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
    _quiet(monkeypatch)
    monkeypatch.setattr(case_app.intel_db, "rebuild_all_correlation", lambda: {"searches": 3, "clusters": 1})
    with TestClient(case_app.app) as client:
        response = client.post("/api/graph/recompute")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "recomputed"
    assert body["searches"] == 3
