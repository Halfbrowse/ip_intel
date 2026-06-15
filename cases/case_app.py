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

from cases.case_runtime import CaseRuntime, build_case_response, build_job_response, build_pairs_response, parse_submission
from cases.case_store import get_case, get_cluster, get_job, get_pairing, healthcheck, init_db, list_cases, load_case_inputs
from utils.evidence_meta import evidence_catalog


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


@app.get("/api/cases")
def api_list_cases(request: Request) -> Response:
    return _etag_json_response(
        request,
        {"cases": [build_case_response(row) for row in list_cases()]},
    )


@app.post("/api/cases")
async def api_create_case(request: Request) -> JSONResponse:
    content_type = (request.headers.get("content-type") or "").lower()
    target: str | None = None
    csv_content: bytes | None = None

    if "application/json" in content_type:
        payload = await request.json()
        target = str((payload or {}).get("target") or "").strip() or None
    elif "multipart/form-data" in content_type:
        form = await request.form()
        target = str(form.get("target") or "").strip() or None
        upload = form.get("file")
        if upload is not None and hasattr(upload, "read"):
            csv_content = await upload.read()
    else:
        raise HTTPException(status_code=415, detail="Use JSON or multipart form data.")

    inputs, input_mode = parse_submission(target=target, csv_content=csv_content)
    if not inputs:
        raise HTTPException(status_code=400, detail="Submit a domain, IP, or CSV with at least one valid target.")

    identifiers = runtime.submit_case(inputs, input_mode=input_mode)
    case_row = get_case(identifiers["case_id"])
    job_row = get_job(identifiers["job_id"])
    return JSONResponse(
        status_code=202,
        content=jsonable_encoder(
            {
                "case": build_case_response(case_row) if case_row else {"id": identifiers["case_id"]},
                "job": build_job_response(job_row) if job_row else {"id": identifiers["job_id"]},
                "case_id": identifiers["case_id"],
                "job_id": identifiers["job_id"],
                "status": "queued",
            }
        ),
    )


@app.post("/api/cases/{case_id}/recompute")
async def api_recompute_case(case_id: str) -> dict[str, Any]:
    """Re-score an existing case's pairs and clusters from stored scan data."""
    case_row = get_case(case_id)
    if case_row is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    counts = await asyncio.to_thread(runtime.recompute_case, case_id)
    return {"case_id": case_id, "status": "recomputed", **counts}


@app.get("/api/cases/{case_id}")
def api_get_case(case_id: str, request: Request) -> Response:
    case_row = get_case(case_id)
    if case_row is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return _etag_json_response(request, {"case": build_case_response(case_row)})


@app.get("/api/jobs/{job_id}")
def api_get_job(job_id: str) -> dict[str, Any]:
    job_row = get_job(job_id)
    if job_row is None:
        raise HTTPException(status_code=404, detail="Job not found.")
    return {"job": build_job_response(job_row)}


@app.get("/api/cases/{case_id}/pairs")
def api_get_case_pairs(case_id: str, request: Request) -> Response:
    case_row = get_case(case_id)
    if case_row is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return _etag_json_response(request, build_pairs_response(case_id))


@app.get("/api/cases/{case_id}/pairs/{pair_id}")
def api_get_pair(case_id: str, pair_id: str) -> dict[str, Any]:
    pair_row = get_pairing(case_id, pair_id)
    if pair_row is None:
        raise HTTPException(status_code=404, detail="Pair not found.")
    payload = dict(pair_row.get("payload") or {})
    payload.update(
        {
            "id": pair_row["id"],
            "scope": pair_row["scope"],
            "left": pair_row["left_target"],
            "right": pair_row["right_target"],
            "score": pair_row["score"],
            "match_count": pair_row["match_count"],
            "status": "completed",
            "evidence": payload.get("evidence_items", []),
            "left_subject": {
                "label": pair_row["left_target"],
                "payload": pair_row.get("left_payload") or {},
            },
            "right_subject": {
                "label": pair_row["right_target"],
                "payload": pair_row.get("right_payload") or {},
            },
        }
    )
    return {"pair": payload}


@app.get("/api/cases/{case_id}/clusters")
def api_get_clusters(case_id: str) -> dict[str, Any]:
    cluster_row = get_cluster(case_id)
    if cluster_row is None:
        raise HTTPException(status_code=404, detail="Cluster data not found.")
    payload = dict(cluster_row.get("payload") or {})
    payload["graph"] = cluster_row.get("graph_payload") or {}
    payload["threshold"] = cluster_row.get("threshold")
    case_inputs = load_case_inputs(case_id)
    payload["seed_targets"] = [
        inp["normalized_target"]
        for inp in case_inputs
        if inp.get("normalized_target") and inp.get("is_seed")
    ]
    return payload


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
