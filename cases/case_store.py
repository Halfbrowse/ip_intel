from __future__ import annotations

import os
import uuid
from typing import Any

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


DEFAULT_DATABASE_URL = "postgresql://ip_intel:ip_intel@postgres:5432/ip_intel"
JOB_STAGES = ["intake", "enrichment", "comparison", "clustering", "notification"]


def database_url() -> str:
    return os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL).strip()


def connect() -> psycopg.Connection[Any]:
    return psycopg.connect(database_url(), row_factory=dict_row)


def init_db() -> None:
    statements = [
        """
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            status TEXT NOT NULL,
            input_mode TEXT NOT NULL,
            total_targets INTEGER NOT NULL DEFAULT 0,
            successful_targets INTEGER NOT NULL DEFAULT 0,
            failed_targets INTEGER NOT NULL DEFAULT 0,
            summary JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            started_at TIMESTAMPTZ,
            finished_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            status TEXT NOT NULL,
            stage TEXT NOT NULL,
            percent INTEGER NOT NULL DEFAULT 0,
            total_targets INTEGER NOT NULL DEFAULT 0,
            completed_targets INTEGER NOT NULL DEFAULT 0,
            failed_targets INTEGER NOT NULL DEFAULT 0,
            current_target TEXT,
            logs JSONB NOT NULL DEFAULT '[]'::jsonb,
            error TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            started_at TIMESTAMPTZ,
            finished_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS job_logs (
            id BIGSERIAL PRIMARY KEY,
            job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            stage TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS case_inputs (
            id BIGSERIAL PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            input_value TEXT NOT NULL,
            normalized_target TEXT NOT NULL,
            target_type TEXT NOT NULL,
            upload_row INTEGER,
            source TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS search_runs (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            root_input TEXT NOT NULL,
            normalized_target TEXT NOT NULL,
            target_type TEXT NOT NULL,
            depth INTEGER NOT NULL DEFAULT 0,
            discovered_from TEXT,
            discovery_reason TEXT,
            discovery_kind TEXT,
            is_seed BOOLEAN NOT NULL DEFAULT FALSE,
            status TEXT NOT NULL,
            error TEXT,
            payload JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            completed_at TIMESTAMPTZ
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS pairings (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            scope TEXT NOT NULL,
            left_run_id TEXT NOT NULL REFERENCES search_runs(id) ON DELETE CASCADE,
            right_run_id TEXT NOT NULL REFERENCES search_runs(id) ON DELETE CASCADE,
            left_target TEXT NOT NULL,
            right_target TEXT NOT NULL,
            score INTEGER NOT NULL DEFAULT 0,
            match_count INTEGER NOT NULL DEFAULT 0,
            payload JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS clusters (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            threshold INTEGER NOT NULL,
            payload JSONB NOT NULL DEFAULT '{}'::jsonb,
            graph_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS search_run_observed_ips (
            search_run_id TEXT NOT NULL REFERENCES search_runs(id) ON DELETE CASCADE,
            ip TEXT NOT NULL,
            source TEXT NOT NULL,
            PRIMARY KEY (search_run_id, ip, source)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS search_run_tls_fingerprints (
            search_run_id TEXT NOT NULL REFERENCES search_runs(id) ON DELETE CASCADE,
            fingerprint_sha256 TEXT NOT NULL,
            cn TEXT,
            issuer TEXT,
            PRIMARY KEY (search_run_id, fingerprint_sha256)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS search_run_identifiers (
            search_run_id TEXT NOT NULL REFERENCES search_runs(id) ON DELETE CASCADE,
            category TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY (search_run_id, category, value)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS search_run_provider_hits (
            search_run_id TEXT NOT NULL REFERENCES search_runs(id) ON DELETE CASCADE,
            provider TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY (search_run_id, provider, value)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS search_run_discovered_targets (
            search_run_id TEXT NOT NULL REFERENCES search_runs(id) ON DELETE CASCADE,
            discovered_target TEXT NOT NULL,
            discovery_kind TEXT NOT NULL,
            discovery_reason TEXT,
            PRIMARY KEY (search_run_id, discovered_target, discovery_kind)
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)",
        "CREATE INDEX IF NOT EXISTS idx_jobs_case_id ON jobs(case_id)",
        "CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)",
        "CREATE INDEX IF NOT EXISTS idx_job_logs_job_id_id ON job_logs(job_id, id)",
        "CREATE INDEX IF NOT EXISTS idx_search_runs_case_id ON search_runs(case_id)",
        "CREATE INDEX IF NOT EXISTS idx_search_runs_normalized_target ON search_runs(normalized_target)",
        "CREATE INDEX IF NOT EXISTS idx_pairings_case_scope ON pairings(case_id, scope)",
        "CREATE INDEX IF NOT EXISTS idx_observed_ips_ip ON search_run_observed_ips(ip)",
        "CREATE INDEX IF NOT EXISTS idx_tls_fp_value ON search_run_tls_fingerprints(fingerprint_sha256)",
        "CREATE INDEX IF NOT EXISTS idx_identifiers_value ON search_run_identifiers(category, value)",
        "CREATE INDEX IF NOT EXISTS idx_provider_hits_value ON search_run_provider_hits(provider, value)",
        "CREATE INDEX IF NOT EXISTS idx_discovered_targets_value ON search_run_discovered_targets(discovered_target)",
    ]
    with connect() as conn:
        with conn.cursor() as cur:
            for statement in statements:
                cur.execute(statement)
        conn.commit()


def create_case(inputs: list[dict[str, Any]], *, input_mode: str) -> dict[str, str]:
    case_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    title = ", ".join(item["normalized_target"] for item in inputs[:3]) or "New case"
    if len(inputs) > 3:
        title = f"{title} (+{len(inputs) - 3} more)"
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO cases (
                    id, title, status, input_mode, total_targets, summary
                ) VALUES (%s, %s, 'queued', %s, %s, %s)
                """,
                (
                    case_id,
                    title,
                    input_mode,
                    len(inputs),
                    Jsonb(
                        {
                            "target_count": len(inputs),
                            "within_case_pair_count": 0,
                            "historical_pair_count": 0,
                            "cluster_count": 0,
                            "top_findings": [],
                        }
                    ),
                ),
            )
            cur.execute(
                """
                INSERT INTO jobs (
                    id, case_id, status, stage, percent, total_targets, logs
                ) VALUES (%s, %s, 'queued', 'intake', 0, %s, %s)
                """,
                (job_id, case_id, len(inputs), Jsonb([])),
            )
            for item in inputs:
                cur.execute(
                    """
                    INSERT INTO case_inputs (
                        case_id, input_value, normalized_target, target_type, upload_row, source
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        case_id,
                        item["input_value"],
                        item["normalized_target"],
                        item["target_type"],
                        item.get("upload_row"),
                        item.get("source", input_mode),
                    ),
                )
        conn.commit()
    return {"case_id": case_id, "job_id": job_id}


def list_cases() -> list[dict[str, Any]]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    c.*,
                    j.id AS job_id,
                    j.status AS job_status,
                    j.percent AS job_percent,
                    j.stage AS job_stage,
                    j.updated_at AS job_updated_at,
                    COALESCE((
                        SELECT json_agg(ci.normalized_target ORDER BY ci.upload_row, ci.id)
                        FROM case_inputs ci
                        WHERE ci.case_id = c.id
                    ), '[]'::json) AS targets
                FROM cases c
                LEFT JOIN jobs j ON j.case_id = c.id
                ORDER BY c.created_at DESC
                """
            )
            return list(cur.fetchall())


def get_case(case_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    c.*,
                    j.id AS job_id,
                    j.status AS job_status,
                    j.percent AS job_percent,
                    j.stage AS job_stage,
                    j.updated_at AS job_updated_at,
                    j.completed_targets,
                    j.failed_targets,
                    j.total_targets,
                    j.current_target,
                    j.logs,
                    j.error,
                    COALESCE((
                        SELECT json_agg(ci.normalized_target ORDER BY ci.upload_row, ci.id)
                        FROM case_inputs ci
                        WHERE ci.case_id = c.id
                    ), '[]'::json) AS targets
                FROM cases c
                LEFT JOIN jobs j ON j.case_id = c.id
                WHERE c.id = %s
                """,
                (case_id,),
            )
            return cur.fetchone()


def get_job(job_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    j.*,
                    COALESCE(log_rows.logs, j.logs, '[]'::jsonb) AS logs
                FROM jobs j
                LEFT JOIN LATERAL (
                    SELECT jsonb_agg(
                        jsonb_build_object(
                            'level', ordered.level,
                            'message', ordered.message,
                            'stage', ordered.stage,
                            'created_at', ordered.created_at
                        )
                        ORDER BY ordered.id
                    ) AS logs
                    FROM (
                        SELECT id, level, message, stage, created_at
                        FROM job_logs
                        WHERE job_id = j.id
                        ORDER BY id DESC
                        LIMIT 200
                    ) ordered
                ) log_rows ON TRUE
                WHERE j.id = %s
                """,
                (job_id,),
            )
            return cur.fetchone()


def load_case_inputs(case_id: str) -> list[dict[str, Any]]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT input_value, normalized_target, target_type, upload_row, source
                FROM case_inputs
                WHERE case_id = %s
                ORDER BY upload_row NULLS LAST, id
                """,
                (case_id,),
            )
            return list(cur.fetchall())


def append_job_log(job_id: str, *, level: str, message: str, stage: str | None = None) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO job_logs (job_id, level, message, stage)
                VALUES (%s, %s, %s, %s)
                """,
                (job_id, level, message, stage),
            )
            cur.execute(
                """
                UPDATE jobs
                SET logs = COALESCE((
                        SELECT jsonb_agg(
                            jsonb_build_object(
                                'level', ordered.level,
                                'message', ordered.message,
                                'stage', ordered.stage,
                                'created_at', ordered.created_at
                            )
                            ORDER BY ordered.id
                        )
                        FROM (
                            SELECT id, level, message, stage, created_at
                            FROM job_logs
                            WHERE job_id = jobs.id
                            ORDER BY id DESC
                            LIMIT 200
                        ) ordered
                    ), '[]'::jsonb),
                    stage = COALESCE(%s, stage),
                    updated_at = NOW()
                WHERE id = %s
                """,
                (stage, job_id),
            )
        conn.commit()


def mark_case_started(case_id: str, job_id: str) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE cases
                SET status = 'running',
                    started_at = COALESCE(started_at, NOW()),
                    updated_at = NOW()
                WHERE id = %s
                """,
                (case_id,),
            )
            cur.execute(
                """
                UPDATE jobs
                SET status = 'running',
                    started_at = COALESCE(started_at, NOW()),
                    updated_at = NOW()
                WHERE id = %s
                """,
                (job_id,),
            )
        conn.commit()


def update_job_progress(
    job_id: str,
    *,
    stage: str | None = None,
    percent: int | None = None,
    total_targets: int | None = None,
    completed_targets: int | None = None,
    failed_targets: int | None = None,
    current_target: str | None = None,
    status: str | None = None,
    error: str | None = None,
) -> None:
    assignments = []
    params: list[Any] = []
    for column, value in (
        ("stage", stage),
        ("percent", percent),
        ("total_targets", total_targets),
        ("completed_targets", completed_targets),
        ("failed_targets", failed_targets),
        ("current_target", current_target),
        ("status", status),
        ("error", error),
    ):
        if value is not None:
            assignments.append(sql.SQL("{} = %s").format(sql.Identifier(column)))
            params.append(value)
    assignments.append(sql.SQL("updated_at = NOW()"))
    params.append(job_id)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                sql.SQL("UPDATE jobs SET {} WHERE id = %s").format(sql.SQL(", ").join(assignments)),
                params,
            )
        conn.commit()


def save_search_run(
    case_id: str,
    *,
    root_input: str,
    normalized_target: str,
    target_type: str,
    depth: int,
    discovered_from: str | None,
    discovery_reason: str | None,
    discovery_kind: str | None,
    is_seed: bool,
    status: str,
    error: str | None,
    payload: dict[str, Any],
    helpers: dict[str, Any],
) -> str:
    run_id = str(uuid.uuid4())
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO search_runs (
                    id, case_id, root_input, normalized_target, target_type, depth,
                    discovered_from, discovery_reason, discovery_kind, is_seed,
                    status, error, payload, completed_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                """,
                (
                    run_id,
                    case_id,
                    root_input,
                    normalized_target,
                    target_type,
                    depth,
                    discovered_from,
                    discovery_reason,
                    discovery_kind,
                    is_seed,
                    status,
                    error,
                    Jsonb(payload),
                ),
            )
            _replace_helper_rows(cur, run_id, helpers)
        conn.commit()
    return run_id


def _replace_helper_rows(cur: psycopg.Cursor[Any], run_id: str, helpers: dict[str, Any]) -> None:
    for entry in helpers.get("observed_ips", []) or []:
        cur.execute(
            """
            INSERT INTO search_run_observed_ips (search_run_id, ip, source)
            VALUES (%s, %s, %s)
            ON CONFLICT DO NOTHING
            """,
            (run_id, entry.get("ip"), entry.get("source")),
        )
    for entry in helpers.get("tls_fingerprints", []) or []:
        cur.execute(
            """
            INSERT INTO search_run_tls_fingerprints (search_run_id, fingerprint_sha256, cn, issuer)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT DO NOTHING
            """,
            (run_id, entry.get("fingerprint_sha256"), entry.get("cn"), entry.get("issuer")),
        )
    for entry in helpers.get("identifiers", []) or []:
        cur.execute(
            """
            INSERT INTO search_run_identifiers (search_run_id, category, value)
            VALUES (%s, %s, %s)
            ON CONFLICT DO NOTHING
            """,
            (run_id, entry.get("category"), entry.get("value")),
        )
    for entry in helpers.get("provider_hits", []) or []:
        cur.execute(
            """
            INSERT INTO search_run_provider_hits (search_run_id, provider, value)
            VALUES (%s, %s, %s)
            ON CONFLICT DO NOTHING
            """,
            (run_id, entry.get("provider"), entry.get("value")),
        )
    for entry in helpers.get("discovered_targets", []) or []:
        cur.execute(
            """
            INSERT INTO search_run_discovered_targets (
                search_run_id, discovered_target, discovery_kind, discovery_reason
            ) VALUES (%s, %s, %s, %s)
            ON CONFLICT DO NOTHING
            """,
            (
                run_id,
                entry.get("target"),
                entry.get("kind"),
                entry.get("reason"),
            ),
        )


def patch_search_run_payload(run_id: str, fields: dict[str, Any]) -> None:
    """Merge fields into an existing search run's payload."""
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE search_runs SET payload = payload || %s WHERE id = %s",
                (Jsonb(fields), run_id),
            )
        conn.commit()


def get_pending_crt_sh_retries() -> list[dict[str, Any]]:
    """Return search runs where crt.sh failed and has not yet been retried."""
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, normalized_target
                FROM search_runs
                WHERE payload->>'crt_sh_status' = 'pending_retry'
                  AND status = 'completed'
                ORDER BY created_at
                """
            )
            return cur.fetchall()


def list_search_runs(case_id: str, *, only_success: bool = False) -> list[dict[str, Any]]:
    query = """
        SELECT *
        FROM search_runs
        WHERE case_id = %s
    """
    params: list[Any] = [case_id]
    if only_success:
        query += " AND status = 'completed'"
    query += " ORDER BY depth, created_at, normalized_target"
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            return list(cur.fetchall())


def list_search_runs_by_ids(run_ids: list[str]) -> list[dict[str, Any]]:
    if not run_ids:
        return []
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    sr.*,
                    COALESCE((
                        SELECT json_agg(
                            json_build_object('ip', sri.ip, 'source', sri.source)
                            ORDER BY sri.ip, sri.source
                        )
                        FROM search_run_observed_ips sri
                        WHERE sri.search_run_id = sr.id
                    ), '[]'::json) AS observed_ips
                FROM search_runs sr
                WHERE sr.id = ANY(%s)
                ORDER BY sr.completed_at DESC NULLS LAST, sr.created_at DESC
                """,
                (run_ids,),
            )
            return list(cur.fetchall())


def find_historical_candidates(
    current_case_id: str,
    normalized_target: str,
    helpers: dict[str, Any],
    *,
    limit: int = 24,
) -> list[dict[str, Any]]:
    candidate_ids: set[str] = set()
    observed_ips = [entry["ip"] for entry in helpers.get("observed_ips", []) if entry.get("ip")]
    fingerprints = [
        entry["fingerprint_sha256"]
        for entry in helpers.get("tls_fingerprints", [])
        if entry.get("fingerprint_sha256")
    ]
    identifiers = [
        (entry["category"], entry["value"])
        for entry in helpers.get("identifiers", [])
        if entry.get("category") and entry.get("value")
    ]

    with connect() as conn:
        with conn.cursor() as cur:
            if observed_ips:
                cur.execute(
                    """
                    SELECT DISTINCT sri.search_run_id
                    FROM search_run_observed_ips sri
                    JOIN search_runs sr ON sr.id = sri.search_run_id
                    JOIN cases c ON c.id = sr.case_id
                    WHERE sri.ip = ANY(%s)
                      AND sr.case_id <> %s
                      AND sr.normalized_target <> %s
                      AND sr.status = 'completed'
                      AND c.status = 'completed'
                    """,
                    (observed_ips, current_case_id, normalized_target),
                )
                candidate_ids.update(row["search_run_id"] for row in cur.fetchall())

            if fingerprints:
                cur.execute(
                    """
                    SELECT DISTINCT srt.search_run_id
                    FROM search_run_tls_fingerprints srt
                    JOIN search_runs sr ON sr.id = srt.search_run_id
                    JOIN cases c ON c.id = sr.case_id
                    WHERE srt.fingerprint_sha256 = ANY(%s)
                      AND sr.case_id <> %s
                      AND sr.normalized_target <> %s
                      AND sr.status = 'completed'
                      AND c.status = 'completed'
                    """,
                    (fingerprints, current_case_id, normalized_target),
                )
                candidate_ids.update(row["search_run_id"] for row in cur.fetchall())

            if identifiers:
                values_sql = sql.SQL(", ").join(sql.SQL("(%s, %s)") for _ in identifiers)
                params: list[Any] = []
                for category, value in identifiers:
                    params.extend([category, value])
                params.extend([current_case_id, normalized_target])
                query = sql.SQL(
                    """
                    SELECT DISTINCT sri.search_run_id
                    FROM search_run_identifiers sri
                    JOIN search_runs sr ON sr.id = sri.search_run_id
                    JOIN cases c ON c.id = sr.case_id
                    WHERE (sri.category, sri.value) IN ({values})
                      AND sr.case_id <> %s
                      AND sr.normalized_target <> %s
                      AND sr.status = 'completed'
                      AND c.status = 'completed'
                    """
                ).format(values=values_sql)
                cur.execute(query, params)
                candidate_ids.update(row["search_run_id"] for row in cur.fetchall())

            if not candidate_ids:
                return []

            cur.execute(
                """
                SELECT DISTINCT ON (sr.normalized_target) sr.*
                FROM search_runs sr
                JOIN cases c ON c.id = sr.case_id
                WHERE sr.id = ANY(%s)
                  AND sr.case_id <> %s
                  AND sr.normalized_target <> %s
                  AND sr.status = 'completed'
                  AND c.status = 'completed'
                ORDER BY sr.normalized_target, sr.completed_at DESC NULLS LAST, sr.created_at DESC
                LIMIT %s
                """,
                (list(candidate_ids), current_case_id, normalized_target, limit),
            )
            return list(cur.fetchall())


def replace_pairings(case_id: str, pairings: list[dict[str, Any]]) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM pairings WHERE case_id = %s", (case_id,))
            for item in pairings:
                cur.execute(
                    """
                    INSERT INTO pairings (
                        id, case_id, scope, left_run_id, right_run_id,
                        left_target, right_target, score, match_count, payload
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        item["id"],
                        case_id,
                        item["scope"],
                        item["left_run_id"],
                        item["right_run_id"],
                        item["left_target"],
                        item["right_target"],
                        item["score"],
                        item["match_count"],
                        Jsonb(item["payload"]),
                    ),
                )
        conn.commit()


def list_pairings(case_id: str) -> list[dict[str, Any]]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM pairings
                WHERE case_id = %s
                ORDER BY scope, score DESC, created_at
                """,
                (case_id,),
            )
            return list(cur.fetchall())


def get_pairing(case_id: str, pairing_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT p.*,
                       lr.payload AS left_payload,
                       rr.payload AS right_payload
                FROM pairings p
                JOIN search_runs lr ON lr.id = p.left_run_id
                JOIN search_runs rr ON rr.id = p.right_run_id
                WHERE p.case_id = %s AND p.id = %s
                """,
                (case_id, pairing_id),
            )
            return cur.fetchone()


def replace_cluster(
    case_id: str,
    *,
    threshold: int,
    payload: dict[str, Any],
    graph_payload: dict[str, Any],
) -> str:
    cluster_id = str(uuid.uuid4())
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM clusters WHERE case_id = %s", (case_id,))
            cur.execute(
                """
                INSERT INTO clusters (id, case_id, threshold, payload, graph_payload)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (cluster_id, case_id, threshold, Jsonb(payload), Jsonb(graph_payload)),
            )
        conn.commit()
    return cluster_id


def get_cluster(case_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT *
                FROM clusters
                WHERE case_id = %s
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (case_id,),
            )
            return cur.fetchone()


def update_case_summary(case_id: str, summary: dict[str, Any]) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE cases
                SET summary = %s,
                    updated_at = NOW()
                WHERE id = %s
                """,
                (Jsonb(summary), case_id),
            )


def complete_case(
    case_id: str,
    job_id: str,
    *,
    status: str,
    summary: dict[str, Any],
    successful_targets: int,
    failed_targets: int,
    percent: int = 100,
    error: str | None = None,
) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE cases
                SET status = %s,
                    summary = %s,
                    successful_targets = %s,
                    failed_targets = %s,
                    finished_at = NOW(),
                    updated_at = NOW()
                WHERE id = %s
                """,
                (status, Jsonb(summary), successful_targets, failed_targets, case_id),
            )
            cur.execute(
                """
                UPDATE jobs
                SET status = %s,
                    stage = 'notification',
                    percent = %s,
                    error = %s,
                    finished_at = NOW(),
                    updated_at = NOW()
                WHERE id = %s
                """,
                (status, percent, error, job_id),
            )
        conn.commit()


def recoverable_jobs() -> list[dict[str, Any]]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT j.*, c.input_mode
                FROM jobs j
                JOIN cases c ON c.id = j.case_id
                WHERE j.status IN ('queued', 'running')
                ORDER BY j.created_at
                """
            )
            return list(cur.fetchall())


def healthcheck() -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT NOW() AS now")
            return cur.fetchone() or {"now": None}
