#!/usr/bin/env python3
"""
FastAPI backend for the IP Intel React frontend.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field, field_validator

import ip_intel
from intel_db import (
    classify_ip,
    cluster_by_asn,
    cluster_by_favicon,
    cluster_by_ip,
    cluster_by_tls_cert,
    cluster_by_tracking_id,
    get_by_id,
    get_connections_for_target,
    get_domains_with_source_errors,
    get_history_for_target,
    get_recent,
    init_db,
)

try:
    import opencti_ingest as opencti
except Exception:  # noqa: BLE001
    opencti = None

try:
    from mattermost_alerts import send_analysis_notification
except Exception:  # noqa: BLE001
    def send_analysis_notification(job: dict[str, Any]) -> bool:
        return False


LOGGER = logging.getLogger("ip_intel.api")
BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"

PHASES = [
    "WHOIS",
    "DNS",
    "crt.sh",
    "CIRCL pDNS",
    "Page metadata",
    "Subdomain probe",
    "MX probe",
    "Wordlist probe",
    "HackerTarget",
    "urlscan",
    "Censys",
    "Shodan",
    "Netlas",
    "Origin scan",
    "IP enrichment",
    "TLS probe",
]

PHASE_KEYWORDS = {
    "WHOIS": ["whois"],
    "DNS": ["dns records"],
    "crt.sh": ["certificate transparency", "crt.sh"],
    "CIRCL pDNS": ["circl", "passive dns"],
    "Page metadata": ["page metadata", "whois / dns / crt.sh / circl pdns / page metadata"],
    "Subdomain probe": ["subdomain probe"],
    "MX probe": ["mx probe"],
    "Wordlist probe": ["wordlist"],
    "HackerTarget": ["hackertarget"],
    "urlscan": ["urlscan"],
    "Censys": ["censys"],
    "Shodan": ["shodan"],
    "Netlas": ["netlas"],
    "Origin scan": ["origin scan", "masscan", "phase 1", "phase 2", "fetching gcp", "fetching ip ranges"],
    "IP enrichment": ["ip enrichment", "ptr record", "asn"],
    "TLS probe": ["tls probe"],
}

CERT_TYPE_DEFINITIONS = {
    "cloudflare_edge": {
        "label": "Cloudflare edge",
        "summary": "This is the certificate Cloudflare shows to visitors. It confirms Cloudflare is in front, but it usually does not reveal the real origin server.",
    },
    "gcp_google": {
        "label": "Google / GCP",
        "summary": "A Google Trust Services certificate usually means the site was hosted on Google infrastructure, often Google Cloud.",
    },
    "commercial_ca": {
        "label": "Commercial CA",
        "summary": "A paid certificate from a provider like DigiCert, Sectigo, or Comodo often belongs to the real server or its hosting environment.",
    },
    "lets_encrypt": {
        "label": "Let's Encrypt",
        "summary": "A free, auto-renewing certificate. It often appears on the real server because it is easy to deploy directly on origin hosts.",
    },
    "zerossl": {
        "label": "ZeroSSL",
        "summary": "Another common free certificate authority. Like Let's Encrypt, it often points to the actual server rather than a CDN edge.",
    },
    "aws_amazon": {
        "label": "Amazon / AWS",
        "summary": "Amazon-issued certificates usually mean the site was served from AWS, such as CloudFront, an ELB, or an EC2-hosted service.",
    },
    "local_ca": {
        "label": "Local CA",
        "summary": "A local certificate authority such as Caddy's internal CA often suggests a self-managed server, staging system, or internal reverse proxy.",
    },
    "interception_proxy": {
        "label": "Interception proxy",
        "summary": "Certificates from tools like mitmproxy or Burp mean traffic was intercepted by a proxy rather than served normally by the site.",
    },
    "unknown": {
        "label": "Other / unknown",
        "summary": "The certificate issuer does not match one of the common patterns above. It can still be useful, but it needs manual interpretation.",
    },
}

SERVER_TYPE_DEFINITIONS = {
    "direct": {
        "label": "Direct server",
        "summary": "This looks like a dedicated or VPS-style host. It is often a strong lead for the real origin server.",
    },
    "shared_hosting": {
        "label": "Shared hosting",
        "summary": "This IP likely belongs to a multi-tenant hosting platform. It can still matter, but by itself it is a weaker ownership signal.",
    },
    "cdn_proxy": {
        "label": "CDN / proxy",
        "summary": "This looks like an edge network or reverse proxy. It usually serves traffic on behalf of the site rather than being the real backend server.",
    },
    "mail": {
        "label": "Mail server",
        "summary": "This host appears to be tied to email delivery or mail security. It is usually not the web origin unless other evidence points that way.",
    },
}

SCAN_OPTION_DEFINITIONS = {
    "scan": "Search Google Cloud regions closest to Russia and Ukraine. Best when certificate history already hints at Google hosting.",
    "scan_europe": "Search all European Google Cloud regions plus Turkey. Broader than the default GCP scan and skips the Google-only hint check.",
    "scan_providers": "Search known RU/EU hosting providers such as Hetzner, OVH, Selectel, Timeweb, Beget, and similar networks.",
    "scan_eu_countries": "Search IPv4 space allocated to all EU member states. Useful when hosting is likely somewhere in Europe but the provider is unclear.",
    "scan_full": "Run the broadest preset: EU countries, provider ranges, and European Google Cloud in one pass.",
    "scan_all": "Search all published Google Cloud regions globally. This is the slowest option and is best reserved for strong Google-hosting leads.",
}

SOURCE_LABELS = {
    "dns": "DNS record",
    "hackertarget": "HackerTarget",
    "wordlist_probe": "Wordlist probe",
    "mx_record": "MX record",
    "subdomain_probe": "Subdomain probe",
    "censys": "Censys",
    "shodan": "Shodan",
    "netlas": "Netlas",
    "scan_gcp": "GCP scan",
    "scan_provider": "Provider scan",
    "scan_country": "Country scan",
    "urlscan": "urlscan.io",
    "historical_dns": "Historical DNS",
    "spf": "SPF record",
}

DB_ERROR_DETAIL = (
    "The SQLite database is corrupted or unreadable. Explorer data can appear empty "
    "until the database is repaired, restored from backup, or replaced."
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _raise_db_http_error(exc: sqlite3.DatabaseError) -> None:
    raise HTTPException(status_code=503, detail=DB_ERROR_DETAIL) from exc


def _classify_cert_type(issuer: str | None) -> str:
    value = (issuer or "").strip()
    lower = value.lower()
    if "we1" in value:
        return "cloudflare_edge"
    if "gts" in value or "google trust services" in lower:
        return "gcp_google"
    if "sectigo" in lower or "comodo" in lower or "digicert" in lower:
        return "commercial_ca"
    if "let's encrypt" in lower:
        return "lets_encrypt"
    if "zerossl" in lower:
        return "zerossl"
    if "amazon" in value or "arca" in value:
        return "aws_amazon"
    if "caddy" in lower:
        return "local_ca"
    if "mitmproxy" in lower or "burp" in lower:
        return "interception_proxy"
    return "unknown"


def _annotate_cert(cert: dict[str, Any]) -> dict[str, Any]:
    item = dict(cert)
    issuer = item.get("issuer") or item.get("issuer_cn") or item.get("issuer_org")
    cert_type = _classify_cert_type(issuer)
    item["cert_type"] = cert_type
    item["cert_type_label"] = CERT_TYPE_DEFINITIONS[cert_type]["label"]
    return item


def _attach_ip_context(item: dict[str, Any], ip_details: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(item)
    ip_address = enriched.get("ip")
    details = ip_details.get(ip_address) if ip_address else None
    if details:
        enriched["server_type"] = details.get("server_type")
        enriched["server_type_label"] = details.get("server_type_label")
        enriched["server_sources"] = details.get("sources", [])
        enriched["asn_registry"] = details.get("asn_registry")
        enriched["network_name"] = details.get("network_name")
        enriched["proxy_family"] = details.get("proxy_family")
        enriched["proxy_confidence"] = details.get("proxy_confidence")
        enriched["network_cidr"] = details.get("network_cidr")
    return enriched


def _annotate_result(payload: dict[str, Any]) -> dict[str, Any]:
    data = jsonable_encoder(payload)
    ip_details = data.get("ip_details") or {}

    for ip_address, info in ip_details.items():
        sources = sorted(set(info.get("sources") or []))
        asn_info = info.get("asn_info") or {}
        info["asn_registry"] = asn_info.get("asn_registry")
        info["network_name"] = asn_info.get("network_name")
        info["network_cidr"] = asn_info.get("network_cidr") or asn_info.get("asn_cidr")
        server_type = classify_ip(ip_address, info.get("ptr"), asn_info.get("asn"), ",".join(sources), info.get("proxy_family"))
        info["sources"] = sources
        info["server_type"] = server_type
        info["server_type_label"] = SERVER_TYPE_DEFINITIONS.get(server_type, SERVER_TYPE_DEFINITIONS["direct"])["label"]

    cert_transparency = data.get("cert_transparency") or {}
    issuers = cert_transparency.get("issuers") or []
    cert_transparency["issuer_details"] = [
        {
            "issuer": issuer,
            "cert_type": _classify_cert_type(issuer),
            "cert_type_label": CERT_TYPE_DEFINITIONS[_classify_cert_type(issuer)]["label"],
        }
        for issuer in issuers
    ]
    cert_transparency["certs"] = [_annotate_cert(cert) for cert in cert_transparency.get("certs") or []]

    if data.get("tls_cert"):
        data["tls_cert"] = _annotate_cert(data["tls_cert"])
    data["non_cf_tls_certs"] = [_annotate_cert(cert) for cert in data.get("non_cf_tls_certs") or []]

    origin_candidates = data.get("origin_candidates") or {}
    for key in ("subdomain_leaks", "mx_leaks", "wordlist_leaks", "hackertarget", "urlscan"):
        origin_candidates[key] = [
            _attach_ip_context(entry, ip_details)
            for entry in origin_candidates.get(key) or []
        ]

    for provider_key in ("censys", "shodan", "netlas"):
        provider_result = origin_candidates.get(provider_key)
        if isinstance(provider_result, dict):
            provider_result["hits"] = [
                _attach_ip_context(entry, ip_details)
                for entry in provider_result.get("hits") or []
            ]

    for scan_key in ("scan", "provider_scan", "country_scan"):
        scan_result = origin_candidates.get(scan_key)
        if isinstance(scan_result, dict):
            scan_result["hits"] = [
                _attach_ip_context(_annotate_cert(hit), ip_details)
                for hit in scan_result.get("hits") or []
            ]

    if data.get("type") == "ip":
        asn_info = data.get("asn_info") or {}
        data["asn_registry"] = asn_info.get("asn_registry")
        data["network_name"] = asn_info.get("network_name")
        data["network_cidr"] = asn_info.get("network_cidr") or asn_info.get("asn_cidr")
        server_type = classify_ip(data.get("input", ""), data.get("ptr"), asn_info.get("asn"), "direct", data.get("proxy_family"))
        data["server_type"] = server_type
        data["server_type_label"] = SERVER_TYPE_DEFINITIONS.get(server_type, SERVER_TYPE_DEFINITIONS["direct"])["label"]

    return data


def _build_progress(logs: list[str], status: str) -> dict[str, Any]:
    completed = []
    for phase in PHASES:
        keywords = PHASE_KEYWORDS.get(phase, [])
        if any(any(keyword in entry.lower() for keyword in keywords) for entry in logs):
            completed.append(phase)

    if status == "completed":
        completed = list(PHASES)

    current = None
    if status == "running":
        remaining = [phase for phase in PHASES if phase not in completed]
        current = remaining[0] if remaining else PHASES[-1]

    return {
        "total": len(PHASES),
        "completed_count": len(completed),
        "fraction": len(completed) / len(PHASES),
        "completed": completed,
        "current": current,
    }


def _frontend_missing_page() -> HTMLResponse:
    return HTMLResponse(
        """
        <html>
          <head><title>IP Intel</title></head>
          <body style="font-family: ui-sans-serif, sans-serif; padding: 32px;">
            <h1>Frontend build missing</h1>
            <p>Run <code>npm install</code> and <code>npm run build</code> inside <code>frontend/</code>, then start the API again.</p>
          </body>
        </html>
        """,
        status_code=503,
    )


def _safe_frontend_path(full_path: str) -> Path | None:
    dist_root = FRONTEND_DIST.resolve(strict=False)
    candidate = (FRONTEND_DIST / full_path).resolve(strict=False)
    try:
        candidate.relative_to(dist_root)
    except ValueError:
        return None
    return candidate


@dataclass
class JobState:
    id: str
    target: str
    options: dict[str, Any]
    created_at: str
    updated_at: str
    status: str = "queued"
    logs: list[str] = field(default_factory=list)
    partial_result: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: str | None = None


class JobManager:
    def __init__(self, max_workers: int = 3) -> None:
        self._jobs: dict[str, JobState] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ip-intel-job")

    def create(self, target: str, options: dict[str, Any]) -> JobState:
        job = JobState(
            id=str(uuid.uuid4()),
            target=target,
            options=options,
            created_at=_utc_now(),
            updated_at=_utc_now(),
            partial_result={
                "input": target,
                "type": "ip" if ip_intel.is_ip(target) else "domain",
                "origin_candidates": {},
            },
        )
        with self._lock:
            self._jobs[job.id] = job
        return job

    def submit(self, job_id: str) -> None:
        self._executor.submit(self._run_job, job_id)

    def _mutate(self, job_id: str, fn) -> JobState:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise KeyError(job_id)
            fn(job)
            job.updated_at = _utc_now()
            return job

    def append_log(self, job_id: str, message: str) -> None:
        def _update(job: JobState) -> None:
            job.logs.append(message)
            if len(job.logs) > 400:
                job.logs = job.logs[-400:]

        self._mutate(job_id, _update)

    def update_partial(self, job_id: str, key: str, value: Any) -> None:
        def _update(job: JobState) -> None:
            target = job.partial_result
            if "." in key:
                top, sub = key.split(".", 1)
                target.setdefault(top, {})[sub] = value
            else:
                target[key] = value

        self._mutate(job_id, _update)

    def mark_running(self, job_id: str) -> None:
        self._mutate(job_id, lambda job: setattr(job, "status", "running"))

    def mark_complete(self, job_id: str, result: dict[str, Any]) -> None:
        def _update(job: JobState) -> None:
            job.status = "completed"
            job.result = _annotate_result(result)
            job.partial_result = copy.deepcopy(job.result)
            job.error = None

        self._mutate(job_id, _update)
        send_analysis_notification(self.snapshot(job_id))

    def mark_failed(self, job_id: str, error: str) -> None:
        def _update(job: JobState) -> None:
            job.status = "failed"
            job.error = error

        self._mutate(job_id, _update)
        send_analysis_notification(self.snapshot(job_id))

    def snapshot(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise KeyError(job_id)
            payload = {
                "id": job.id,
                "target": job.target,
                "status": job.status,
                "created_at": job.created_at,
                "updated_at": job.updated_at,
                "error": job.error,
                "logs": copy.deepcopy(job.logs),
                "partial_result": copy.deepcopy(job.partial_result),
                "result": copy.deepcopy(job.result),
            }
        payload["progress"] = _build_progress(payload["logs"], payload["status"])
        return payload

    def _run_job(self, job_id: str) -> None:
        try:
            snapshot = self.snapshot(job_id)
            options = self._jobs[job_id].options
            target = snapshot["target"]
            self.mark_running(job_id)
            log_token = ip_intel.set_log_handler(lambda message: self.append_log(job_id, message))

            try:
                if ip_intel.is_ip(target):
                    result = ip_intel.analyze_ip(target)
                else:
                    result = ip_intel.analyze_domain(
                        target,
                        scan=options["scan"],
                        scan_europe=options["scan_europe"],
                        scan_all=options["scan_all"],
                        scan_providers=options["scan_providers"],
                        scan_countries=options["scan_countries"],
                        scan_eu_countries=options["scan_eu_countries"],
                        scan_full=options["scan_full"],
                        concurrency=options["concurrency"],
                        rate=options["rate"],
                        on_partial=lambda key, value: self.update_partial(job_id, key, value),
                    )
                self.mark_complete(job_id, result)
            finally:
                ip_intel.reset_log_handler(log_token)
        except Exception as exc:  # noqa: BLE001
            LOGGER.exception("Analysis job %s failed", job_id)
            self.mark_failed(job_id, str(exc))


JOBS = JobManager()


class AnalyzeRequest(BaseModel):
    target: str = Field(min_length=1)
    scan: bool = False
    scan_europe: bool = False
    scan_all: bool = False
    scan_providers: bool = False
    scan_countries: list[str] = Field(default_factory=list)
    scan_eu_countries: bool = False
    scan_full: bool = False
    concurrency: int = Field(default=5_000, ge=100, le=50_000)
    rate: int = Field(default=100_000, ge=100, le=500_000)

    @field_validator("scan_countries", mode="before")
    @classmethod
    def _normalise_countries(cls, value):
        if value is None:
            return []
        if isinstance(value, str):
            return [part for part in value.split() if part]
        return value


app = FastAPI(title="IP Intel API", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/api/health")
def health() -> dict[str, str]:
    try:
        get_recent(limit=1)
    except sqlite3.DatabaseError as exc:
        _raise_db_http_error(exc)
    return {"status": "ok"}


@app.get("/api/meta")
def meta() -> dict[str, Any]:
    return {
        "phases": PHASES,
        "scan_options": SCAN_OPTION_DEFINITIONS,
        "cert_types": CERT_TYPE_DEFINITIONS,
        "server_types": SERVER_TYPE_DEFINITIONS,
        "source_labels": SOURCE_LABELS,
    }


@app.post("/api/analyze")
def analyze(request: AnalyzeRequest) -> dict[str, Any]:
    target = ip_intel.clean_target(request.target)
    if not target:
        raise HTTPException(status_code=400, detail="Target is required.")

    options = request.model_dump()
    options["scan_countries"] = sorted({country.upper() for country in options["scan_countries"]})
    job = JOBS.create(target, options)
    JOBS.submit(job.id)
    return JOBS.snapshot(job.id)


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str) -> dict[str, Any]:
    try:
        return JOBS.snapshot(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Job not found.") from exc


@app.get("/api/history/recent")
def recent_history(limit: int = 100) -> dict[str, Any]:
    try:
        return {"items": get_recent(limit=limit)}
    except sqlite3.DatabaseError as exc:
        _raise_db_http_error(exc)


@app.get("/api/history/source-errors")
def source_errors(source: str | None = None) -> dict[str, Any]:
    try:
        return {"items": get_domains_with_source_errors(source=source)}
    except sqlite3.DatabaseError as exc:
        _raise_db_http_error(exc)


@app.get("/api/history/{search_id}")
def history_detail(search_id: int) -> dict[str, Any]:
    try:
        row = get_by_id(search_id)
    except sqlite3.DatabaseError as exc:
        _raise_db_http_error(exc)
    if row is None:
        raise HTTPException(status_code=404, detail="Search not found.")

    raw = row.get("raw_json")
    parsed = _annotate_result(json.loads(raw)) if raw else None
    return {"search": {k: v for k, v in row.items() if k != "raw_json"}, "result": parsed}


@app.get("/api/history/target/{target:path}")
def history_for_target(target: str) -> dict[str, Any]:
    try:
        return {"items": get_history_for_target(target)}
    except sqlite3.DatabaseError as exc:
        _raise_db_http_error(exc)


@app.get("/api/clusters/ip")
def ip_clusters() -> dict[str, Any]:
    try:
        return {"items": cluster_by_ip()}
    except sqlite3.DatabaseError as exc:
        _raise_db_http_error(exc)


@app.get("/api/clusters/tracking")
def tracking_clusters() -> dict[str, Any]:
    try:
        return {"items": cluster_by_tracking_id()}
    except sqlite3.DatabaseError as exc:
        _raise_db_http_error(exc)


@app.get("/api/clusters/favicon")
def favicon_clusters() -> dict[str, Any]:
    try:
        return {"items": cluster_by_favicon()}
    except sqlite3.DatabaseError as exc:
        _raise_db_http_error(exc)


@app.get("/api/clusters/tls")
def tls_clusters(scope: str = "current") -> dict[str, Any]:
    try:
        return {"items": cluster_by_tls_cert(scope=scope)}
    except sqlite3.DatabaseError as exc:
        _raise_db_http_error(exc)


@app.get("/api/clusters/asn")
def asn_clusters(scope: str = "current") -> dict[str, Any]:
    try:
        return {"items": cluster_by_asn(scope=scope)}
    except sqlite3.DatabaseError as exc:
        _raise_db_http_error(exc)


@app.get("/api/connections/{target:path}")
def target_connections(target: str) -> dict[str, Any]:
    try:
        result = get_connections_for_target(target)
    except sqlite3.DatabaseError as exc:
        _raise_db_http_error(exc)
    if result is None:
        raise HTTPException(status_code=404, detail="Target not found in the database.")
    return result


@app.get("/api/opencti/status")
def opencti_status() -> dict[str, Any]:
    if opencti is None:
        return {"available": False}
    return {"available": True, **opencti.get_ingestion_status()}


@app.post("/api/opencti/run")
def opencti_run(force_reanalyse: bool = False) -> dict[str, Any]:
    if opencti is None:
        raise HTTPException(status_code=404, detail="OpenCTI ingestion is not available.")
    return {"started": opencti.restart_ingestion(force_reanalyse=force_reanalyse)}


@app.post("/api/opencti/retry-failures")
def opencti_retry_failures(source: str | None = None) -> dict[str, Any]:
    if opencti is None:
        raise HTTPException(status_code=404, detail="OpenCTI ingestion is not available.")
    return {"started": opencti.start_retry_in_background(source=source)}


@app.get("/")
def frontend_index():
    index_file = FRONTEND_DIST / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return _frontend_missing_page()


@app.get("/{full_path:path}")
def frontend_files(full_path: str):
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="Not found.")

    if not FRONTEND_DIST.exists():
        return _frontend_missing_page()

    candidate = _safe_frontend_path(full_path)
    if candidate is None:
        raise HTTPException(status_code=404, detail="Not found.")

    if candidate.is_file():
        return FileResponse(candidate)

    index_file = FRONTEND_DIST / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return _frontend_missing_page()


def run() -> None:
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=False)


if __name__ == "__main__":
    run()
