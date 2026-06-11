#!/usr/bin/env python3
"""
Copy a legacy SQLite intel database (data/ip_intel.db) into PostgreSQL.

The script preserves row IDs (and therefore all search_id foreign-key
relationships) and converts legacy JSON-text columns into JSONB.

Usage:
    python3 scripts/migrate_sqlite_to_postgres.py [path/to/ip_intel.db] \
        [--database-url postgresql://...] [--force]

The target database defaults to INTEL_DATABASE_URL, then DATABASE_URL.
The target intel tables must be empty unless --force is given.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

# Allow running as `python3 scripts/migrate_sqlite_to_postgres.py` from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db import intel_db  # noqa: E402

# Columns that were JSON-as-TEXT in SQLite and are JSONB in PostgreSQL.
_JSONB_COLUMNS: dict[str, set[str]] = {
    "searches": {"source_errors"},
    "tls_certs": {"sans"},
    "ct_certs": {"sans"},
    "scan_hits": {"sans"},
    "provider_hits": {"services", "hostnames", "raw_json"},
    "whois_data": {"emails", "nameservers"},
    "identifiers": {"raw_json"},
    "discovered_targets": {"raw_json"},
    "search_fields": {"json_value"},
}

_BATCH_SIZE = 1000


def _sqlite_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]


def _pg_columns(conn: psycopg.Connection, table: str) -> list[str]:
    rows = conn.execute(
        """
        SELECT column_name FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = %s
        ORDER BY ordinal_position
        """,
        (table,),
    ).fetchall()
    return [row["column_name"] for row in rows]


def _to_jsonb(value: object) -> Jsonb | None:
    if value is None:
        return None
    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    if not text.strip():
        return None
    try:
        return Jsonb(json.loads(text))
    except (json.JSONDecodeError, TypeError):
        # Not valid JSON: preserve it as a JSON string.
        return Jsonb(text)


def _convert_row(table: str, columns: list[str], row: sqlite3.Row) -> tuple:
    jsonb_cols = _JSONB_COLUMNS.get(table, set())
    values = []
    for column in columns:
        value = row[column]
        if column in jsonb_cols:
            value = _to_jsonb(value)
        elif table == "searches" and column == "raw_json" and value is None:
            value = ""
        values.append(value)
    return tuple(values)


def migrate(sqlite_path: Path, database_url: str, *, force: bool) -> int:
    if not sqlite_path.is_file():
        raise SystemExit(f"SQLite database not found: {sqlite_path}")

    src = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
    src.row_factory = sqlite3.Row

    total_rows = 0
    with psycopg.connect(database_url, row_factory=dict_row) as dst:
        # Create the schema directly on the target connection.
        for statement in intel_db.schema_statements():
            dst.execute(statement)

        existing = dst.execute("SELECT COUNT(*) AS n FROM searches").fetchone()["n"]
        if existing and not force:
            raise SystemExit(
                f"Target database already has {existing} searches rows; "
                "re-run with --force to append anyway."
            )

        for table in intel_db._ALL_TABLES:
            src_columns = _sqlite_columns(src, table)
            if not src_columns:
                print(f"  {table}: not present in SQLite database, skipped")
                continue
            columns = [col for col in src_columns if col in set(_pg_columns(dst, table))]
            if not columns:
                print(f"  {table}: no overlapping columns, skipped")
                continue

            column_sql = ", ".join(columns)
            placeholder_sql = ", ".join(["%s"] * len(columns))
            insert_sql = (
                f"INSERT INTO {table} ({column_sql}) OVERRIDING SYSTEM VALUE "
                f"VALUES ({placeholder_sql})"
            )

            cursor = src.execute(f"SELECT {column_sql} FROM {table} ORDER BY rowid")
            copied = 0
            while True:
                rows = cursor.fetchmany(_BATCH_SIZE)
                if not rows:
                    break
                batch = [_convert_row(table, columns, row) for row in rows]
                with dst.cursor() as cur:
                    cur.executemany(insert_sql, batch)
                copied += len(batch)
            total_rows += copied
            print(f"  {table}: copied {copied} rows")

            if "id" in columns:
                dst.execute(
                    f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
                    f"COALESCE((SELECT MAX(id) FROM {table}), 0) + 1, false)"
                )

        dst.commit()

    src.close()
    return total_rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument(
        "sqlite_path",
        nargs="?",
        default="data/ip_intel.db",
        help="Path to the legacy SQLite database (default: data/ip_intel.db)",
    )
    parser.add_argument(
        "--database-url",
        default=None,
        help="Target PostgreSQL URL (default: INTEL_DATABASE_URL, then DATABASE_URL)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Copy even if the target database already contains intel rows",
    )
    args = parser.parse_args()

    database_url = args.database_url or intel_db.database_url()
    print(f"Migrating {args.sqlite_path} -> {database_url}")
    total = migrate(Path(args.sqlite_path).expanduser(), database_url, force=args.force)
    print(f"Done: {total} rows migrated.")


if __name__ == "__main__":
    main()
