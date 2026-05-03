from __future__ import annotations

from contextlib import asynccontextmanager
import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from case_runtime import CaseRuntime, build_case_response, build_job_response, build_pairs_response, parse_submission
from case_store import get_case, get_cluster, get_job, get_pairing, healthcheck, init_db, list_cases
from evidence_meta import evidence_catalog


BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"
runtime = CaseRuntime()
LOGGER = logging.getLogger("ip_intel.case_app")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    runtime.recover()
    yield


app = FastAPI(title="IP Intel", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
def api_health() -> dict[str, Any]:
    return {"status": "ok", "database": healthcheck()}


@app.get("/api/meta/evidence")
def api_evidence_meta() -> dict[str, Any]:
    return {"evidence": evidence_catalog()}


@app.get("/api/cases")
def api_list_cases() -> dict[str, Any]:
    return {"cases": [build_case_response(row) for row in list_cases()]}


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


@app.get("/api/cases/{case_id}")
def api_get_case(case_id: str) -> dict[str, Any]:
    case_row = get_case(case_id)
    if case_row is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return {"case": build_case_response(case_row)}


@app.get("/api/jobs/{job_id}")
def api_get_job(job_id: str) -> dict[str, Any]:
    job_row = get_job(job_id)
    if job_row is None:
        raise HTTPException(status_code=404, detail="Job not found.")
    return {"job": build_job_response(job_row)}


@app.get("/api/cases/{case_id}/pairs")
def api_get_case_pairs(case_id: str) -> dict[str, Any]:
    case_row = get_case(case_id)
    if case_row is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return build_pairs_response(case_id)


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
