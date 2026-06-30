from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from cases.case_runtime import CaseRuntime, build_job_response, parse_submission
from core.analysis_service import normalize_inputs
from cases.case_store import get_job, healthcheck, init_db
from utils.evidence_meta import evidence_catalog
from utils import check
from db import intel_db


BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIST = BASE_DIR.parent / "frontend" / "dist"
runtime = CaseRuntime()
LOGGER = logging.getLogger("ip_intel.case_app")


def _configure_logging() -> None:
    """Surface our own ``ip_intel.*`` loggers on stdout.

    Uvicorn only configures its own loggers, so by default the container logs
    show nothing but HTTP access lines (which endpoints got hit). We want the
    actual analysis progress — the same messages streamed to the user in the
    frontend — to appear in ``docker compose logs``, so we attach a stdout
    handler to the shared ``ip_intel`` parent logger and let children
    propagate to it. Level is controlled by IP_INTEL_LOG_LEVEL (default INFO).

    The chatty uvicorn.access logger (one line per UI poll of the case/job
    endpoints) is bumped to WARNING so the analysis log isn't drowned out.
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

    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


_configure_logging()


_CRT_SH_RETRY_INTERVAL = 300  # seconds between retry sweeps


async def _crt_sh_retry_loop() -> None:
    while True:
        await asyncio.sleep(_CRT_SH_RETRY_INTERVAL)
        try:
            updated = await asyncio.to_thread(runtime.retry_crt_sh_pending)
            if updated:
                LOGGER.info("crt.sh retry: updated %d run(s)", updated)
        except Exception as exc:
            LOGGER.warning("crt.sh retry sweep failed: %s", exc)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    runtime.recover()
    retry_task = asyncio.create_task(_crt_sh_retry_loop())
    yield
    retry_task.cancel()


app = FastAPI(title="IP Intel", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1024)


def _etag_json_response(request: Request, content: Any) -> Response:
    """
    Serialize `content` to JSON, attach a strong ETag (hash of the body), and
    answer with 304 Not Modified when the client already holds this version.
    """
    body = json.dumps(jsonable_encoder(content), separators=(",", ":")).encode("utf-8")
    etag = f'"{hashlib.sha256(body).hexdigest()}"'
    if_none_match = request.headers.get("if-none-match")
    if if_none_match:
        client_tags = {tag.strip() for tag in if_none_match.split(",")}
        if etag in client_tags or f"W/{etag}" in client_tags or "*" in client_tags:
            return Response(status_code=304, headers={"ETag": etag})
    return Response(content=body, media_type="application/json", headers={"ETag": etag})


@app.get("/api/health")
def api_health() -> dict[str, Any]:
    return {"status": "ok", "database": healthcheck()}


@app.get("/api/meta/evidence")
def api_evidence_meta() -> dict[str, Any]:
    return {"evidence": evidence_catalog()}


def _ingest_response(identifiers: dict[str, str], *, label: str | None, count: int) -> JSONResponse:
    """Shared ingest acknowledgement: a job id to poll for progress. The scanned
    targets flow straight into the global pool — there is no case to open."""
    job_row = get_job(identifiers["job_id"])
    return JSONResponse(
        status_code=202,
        content=jsonable_encoder(
            {
                "job": build_job_response(job_row) if job_row else {"id": identifiers["job_id"]},
                "job_id": identifiers["job_id"],
                "label": label,
                "accepted": count,
                "status": "queued",
            }
        ),
    )


@app.post("/api/ingest/opencti-website")
async def api_ingest_opencti_website() -> JSONResponse:
    """Add the domains from OpenCTI's 100 most recently created website-type
    Channel SDOs to the pool."""
    # Imported lazily so the app starts even when pycti / OpenCTI config is
    # absent; the dependency is only needed when this button is used.
    from integrations.opencti_ingest import fetch_website_channel_domains

    try:
        domains = await asyncio.to_thread(fetch_website_channel_domains, 100)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"OpenCTI fetch failed: {exc}")

    inputs = normalize_inputs(domains)
    if not inputs:
        raise HTTPException(status_code=404, detail="No website-channel domains found on OpenCTI.")

    identifiers = runtime.submit_case(inputs, input_mode="opencti_website")
    return _ingest_response(identifiers, label="opencti_website", count=len(inputs))


@app.post("/api/ingest")
async def api_ingest(request: Request) -> JSONResponse:
    """Add a domain / IP / CSV to the global pool. Runs the analysis pipeline;
    the results join the one shared correlation graph (no case scoping). An
    optional `label` is just a free-text tag on the ingest. Poll the returned
    job for progress; connections then surface via the /api/graph/* endpoints.
    """
    content_type = (request.headers.get("content-type") or "").lower()
    target: str | None = None
    csv_content: bytes | None = None
    label: str | None = None

    if "application/json" in content_type:
        payload = await request.json()
        target = str((payload or {}).get("target") or "").strip() or None
        label = str((payload or {}).get("label") or "").strip() or None
    elif "multipart/form-data" in content_type:
        form = await request.form()
        target = str(form.get("target") or "").strip() or None
        label = str(form.get("label") or "").strip() or None
        upload = form.get("file")
        if upload is not None and hasattr(upload, "read"):
            csv_content = await upload.read()
    else:
        raise HTTPException(status_code=415, detail="Use JSON or multipart form data.")

    inputs, input_mode = parse_submission(target=target, csv_content=csv_content)
    if not inputs:
        raise HTTPException(status_code=400, detail="Submit a domain, IP, or CSV with at least one valid target.")

    identifiers = runtime.submit_case(inputs, input_mode=label or input_mode)
    return _ingest_response(identifiers, label=label, count=len(inputs))


# ── The pool ─────────────────────────────────────────────────────────────────

@app.get("/api/pool")
def api_pool(request: Request, search: str | None = None, limit: int = 1000) -> Response:
    """Every channel (registrable domain) in the pool, with host count, recency,
    and cluster membership."""
    domains = intel_db.list_pool_domains(search=search, limit=limit)
    return _etag_json_response(request, {"total": len(domains), "domains": domains})


@app.get("/api/domain/{value:path}")
def api_domain(value: str, request: Request) -> Response:
    """Everything gathered on one channel — hosts, extracted selectors, resolved
    IPs, and the raw intel (DNS/WHOIS/TLS/subdomains/trackers) — whether or not
    it has any connections."""
    profile = intel_db.domain_profile(value)
    if profile is None:
        raise HTTPException(status_code=404, detail="Nothing in the pool for this channel yet.")
    return _etag_json_response(request, profile)


# ── Global correlation graph (case-free) ─────────────────────────────────────

@app.post("/api/graph/connections")
async def api_graph_connections(request: Request) -> dict[str, Any]:
    """Connections within a selected set of channels: which of them link to each
    other (with evidence), plus each one's strongest connections to the pool.

    Body: {"domains": ["a.com", "b.com", ...], "pool_links": bool}
    """
    payload = await request.json()
    domains = [str(d).strip() for d in (payload or {}).get("domains") or [] if str(d).strip()]
    if len(domains) < 1:
        raise HTTPException(status_code=400, detail="Provide a 'domains' list.")
    pool_links = bool((payload or {}).get("pool_links"))
    return check.connections_among(domains, pool_links=pool_links)


@app.get("/api/graph/selector-kinds")
def api_graph_selector_kinds(request: Request, min_domains: int = 2) -> Response:
    """Edge types available for browsing (selector kind / shared_ip) + group counts."""
    return _etag_json_response(request, {"kinds": intel_db.selector_kind_counts(min_domains=min_domains)})


@app.get("/api/graph/by-selector")
def api_graph_by_selector(
    request: Request, kind: str | None = None, min_domains: int = 2, limit: int = 200
) -> Response:
    """Browse by edge type: groups of domains that share a selector of `kind`
    (or any kind), e.g. all domain sets sharing a TLS cert / SSH key / IP."""
    groups = intel_db.domains_by_selector(kind=kind, min_domains=min_domains, limit=limit)
    return _etag_json_response(request, {"kind": kind, "total": len(groups), "groups": groups})


@app.get("/api/graph/links/{value:path}")
def api_graph_links(value: str, request: Request) -> Response:
    """Ranked cross-corpus connections for an entity / registrable domain, each
    with its shared-node evidence breakdown."""
    links = check.links_for(value)
    return _etag_json_response(request, {"target": value, "total": len(links), "links": links})


@app.get("/api/graph/link")
def api_graph_link(a: str, b: str, request: Request) -> Response:
    """Connecting evidence (shared selectors / IPs) between two domains."""
    if not a or not b:
        raise HTTPException(status_code=400, detail="Provide both 'a' and 'b' query parameters.")
    return _etag_json_response(request, {"link": check.link_evidence(a, b)})


@app.get("/api/graph/clusters")
def api_graph_clusters(request: Request, min_size: int = 2, limit: int = 100) -> Response:
    """Strongest clusters lake-wide."""
    clusters = intel_db.list_graph_clusters(min_size=min_size, limit=limit)
    return _etag_json_response(request, {"total": len(clusters), "clusters": clusters})


@app.get("/api/graph/cluster/{value:path}")
def api_graph_cluster(value: str) -> dict[str, Any]:
    """The cluster a registrable domain belongs to, with its members."""
    cluster = intel_db.graph_cluster_for(value)
    if cluster is None:
        raise HTTPException(status_code=404, detail="No cluster for this target.")
    return {"target": value, **cluster}


@app.post("/api/graph/recompute")
async def api_graph_recompute() -> dict[str, Any]:
    """Global recompute: rebuild the whole correlation graph + clusters from
    stored intel (no rescanning). Run after changing extraction/weight logic."""
    counts = await asyncio.to_thread(intel_db.rebuild_all_correlation)
    return {"status": "recomputed", **counts}


@app.get("/api/jobs/{job_id}")
def api_get_job(job_id: str) -> dict[str, Any]:
    job_row = get_job(job_id)
    if job_row is None:
        raise HTTPException(status_code=404, detail="Job not found.")
    return {"job": build_job_response(job_row)}


@app.exception_handler(Exception)
async def api_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    LOGGER.exception("Unhandled request error on %s", request.url.path)
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            status_code=500,
            content={
                "detail": str(exc) or "Internal Server Error",
                "path": request.url.path,
            },
        )
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})


if FRONTEND_DIST.exists():
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")


@app.get("/{full_path:path}")
def spa_fallback(full_path: str) -> FileResponse:
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="Route not found.")
    candidate = FRONTEND_DIST / full_path
    if candidate.exists() and candidate.is_file():
        return FileResponse(candidate)
    index_file = FRONTEND_DIST / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Frontend build not found.")
    return FileResponse(index_file)
