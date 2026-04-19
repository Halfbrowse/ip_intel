"""
db.py — SQLite persistence for ip-intel.

This module stores every analysis run append-only, then builds "latest run"
views in query code so the UI can default to current relationships while still
preserving enough history to answer "was this shared in the past?"
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = BASE_DIR / "data" / "ip_intel.db"
DB_PATH = Path(os.getenv("IP_INTEL_DB_PATH", str(DEFAULT_DB_PATH))).expanduser()
if not DB_PATH.is_absolute():
    DB_PATH = (BASE_DIR / DB_PATH).resolve()
else:
    DB_PATH = DB_PATH.resolve()


# ── Connection ────────────────────────────────────────────────────────────────

def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(DB_PATH))
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c


# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS searches (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    target              TEXT    NOT NULL,
    type                TEXT    NOT NULL,
    timestamp           TEXT    NOT NULL,
    cloudflare_fronted  INTEGER,
    raw_json            TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_searches_target     ON searches(target);
CREATE INDEX IF NOT EXISTS idx_searches_ts         ON searches(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_searches_target_ts  ON searches(target, timestamp DESC, id DESC);

CREATE TABLE IF NOT EXISTS ips (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id           INTEGER NOT NULL REFERENCES searches(id),
    ip                  TEXT    NOT NULL,
    source              TEXT,
    cloudflare          INTEGER,
    ptr                 TEXT,
    asn                 TEXT,
    asn_desc            TEXT,
    asn_registry        TEXT,
    country             TEXT,
    network_name        TEXT,
    network_cidr        TEXT,
    proxy_family        TEXT,
    proxy_confidence    REAL,
    observed_at         TEXT,
    port                INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ips_ip             ON ips(ip);
CREATE INDEX IF NOT EXISTS idx_ips_search_id      ON ips(search_id);
CREATE INDEX IF NOT EXISTS idx_ips_ip_observed    ON ips(ip, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ips_asn_observed   ON ips(asn, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ips_cidr           ON ips(network_cidr);
CREATE INDEX IF NOT EXISTS idx_ips_proxy_family   ON ips(proxy_family);

CREATE TABLE IF NOT EXISTS tls_certs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    ip          TEXT    NOT NULL,
    port        INTEGER NOT NULL,
    sni_used    TEXT,
    cn          TEXT,
    sans        TEXT,
    issuer_cn   TEXT,
    issuer_org  TEXT,
    not_before  TEXT,
    not_after   TEXT,
    sha256      TEXT,
    observed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_tls_search_id         ON tls_certs(search_id);
CREATE INDEX IF NOT EXISTS idx_tls_sha256            ON tls_certs(sha256);
CREATE INDEX IF NOT EXISTS idx_tls_cn                ON tls_certs(cn);
CREATE INDEX IF NOT EXISTS idx_tls_ip                ON tls_certs(ip);
CREATE INDEX IF NOT EXISTS idx_tls_sha256_observed   ON tls_certs(sha256, observed_at DESC);

CREATE TABLE IF NOT EXISTS ct_certs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    cert_id     INTEGER,
    issuer      TEXT,
    not_before  TEXT,
    not_after   TEXT,
    sans        TEXT,
    observed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_ct_search_id       ON ct_certs(search_id);
CREATE INDEX IF NOT EXISTS idx_ct_issuer          ON ct_certs(issuer);
CREATE INDEX IF NOT EXISTS idx_ct_cert_id         ON ct_certs(cert_id);

CREATE TABLE IF NOT EXISTS subdomains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    subdomain   TEXT    NOT NULL,
    source      TEXT
);
CREATE INDEX IF NOT EXISTS idx_sub_search_id ON subdomains(search_id);
CREATE INDEX IF NOT EXISTS idx_sub_subdomain ON subdomains(subdomain);

CREATE TABLE IF NOT EXISTS dns_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    rtype       TEXT    NOT NULL,
    value       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dns_search_id ON dns_records(search_id);
CREATE INDEX IF NOT EXISTS idx_dns_value     ON dns_records(value);

CREATE TABLE IF NOT EXISTS historical_dns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    rrtype      TEXT,
    rdata       TEXT,
    first_seen  TEXT,
    last_seen   TEXT
);
CREATE INDEX IF NOT EXISTS idx_hist_search_id ON historical_dns(search_id);
CREATE INDEX IF NOT EXISTS idx_hist_rdata     ON historical_dns(rdata);

CREATE TABLE IF NOT EXISTS tracking_ids (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    id_type     TEXT    NOT NULL,
    id_value    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_track_search_id ON tracking_ids(search_id);
CREATE INDEX IF NOT EXISTS idx_track_value     ON tracking_ids(id_type, id_value);

CREATE TABLE IF NOT EXISTS social_accounts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    platform    TEXT    NOT NULL,
    handle      TEXT    NOT NULL,
    url         TEXT
);
CREATE INDEX IF NOT EXISTS idx_social_search_id ON social_accounts(search_id);
CREATE INDEX IF NOT EXISTS idx_social_handle    ON social_accounts(platform, handle);

CREATE TABLE IF NOT EXISTS favicons (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    md5         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fav_search_id ON favicons(search_id);
CREATE INDEX IF NOT EXISTS idx_fav_md5       ON favicons(md5);

CREATE TABLE IF NOT EXISTS whois_data (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id       INTEGER NOT NULL REFERENCES searches(id),
    registrar       TEXT,
    creation_date   TEXT,
    expiry_date     TEXT,
    org             TEXT,
    country         TEXT,
    emails          TEXT,
    nameservers     TEXT
);
CREATE INDEX IF NOT EXISTS idx_whois_search_id ON whois_data(search_id);
CREATE INDEX IF NOT EXISTS idx_whois_registrar ON whois_data(registrar);

CREATE TABLE IF NOT EXISTS registrant_emails (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    email       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_email_search_id ON registrant_emails(search_id);
CREATE INDEX IF NOT EXISTS idx_email_value     ON registrant_emails(email);

CREATE TABLE IF NOT EXISTS nameservers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    nameserver  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ns_search_id ON nameservers(search_id);
CREATE INDEX IF NOT EXISTS idx_ns_value     ON nameservers(nameserver);

CREATE TABLE IF NOT EXISTS spf_origins (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    ip          TEXT    NOT NULL,
    cidr        TEXT
);
CREATE INDEX IF NOT EXISTS idx_spf_search_id ON spf_origins(search_id);
CREATE INDEX IF NOT EXISTS idx_spf_ip        ON spf_origins(ip);

CREATE TABLE IF NOT EXISTS cross_sans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    san         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_csan_search_id ON cross_sans(search_id);
CREATE INDEX IF NOT EXISTS idx_csan_san       ON cross_sans(san);

CREATE TABLE IF NOT EXISTS scan_hits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    scan_type   TEXT    NOT NULL,
    ip          TEXT    NOT NULL,
    port        INTEGER,
    cn          TEXT,
    sans        TEXT,
    issuer      TEXT,
    not_before  TEXT,
    not_after   TEXT,
    sha256      TEXT,
    cloudflare  INTEGER,
    observed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_search_id       ON scan_hits(search_id);
CREATE INDEX IF NOT EXISTS idx_scan_ip              ON scan_hits(ip);
CREATE INDEX IF NOT EXISTS idx_scan_cn              ON scan_hits(cn);
CREATE INDEX IF NOT EXISTS idx_scan_sha256          ON scan_hits(sha256);
CREATE INDEX IF NOT EXISTS idx_scan_sha256_observed ON scan_hits(sha256, observed_at DESC);

CREATE TABLE IF NOT EXISTS provider_hits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    provider    TEXT    NOT NULL,
    ip          TEXT,
    port        INTEGER,
    protocol    TEXT,
    asn         TEXT,
    asn_desc    TEXT,
    org         TEXT,
    country     TEXT,
    cloudflare  INTEGER,
    services    TEXT,
    hostnames   TEXT,
    mode        TEXT,
    status      TEXT,
    query_type  TEXT,
    total       INTEGER,
    observed_at TEXT,
    raw_json    TEXT
);
CREATE INDEX IF NOT EXISTS idx_provider_search_id    ON provider_hits(search_id);
CREATE INDEX IF NOT EXISTS idx_provider_name         ON provider_hits(provider);
CREATE INDEX IF NOT EXISTS idx_provider_ip_observed  ON provider_hits(ip, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_provider_status       ON provider_hits(status);

CREATE TABLE IF NOT EXISTS page_metadata (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id       INTEGER NOT NULL REFERENCES searches(id),
    html_lang       TEXT,
    cms_generator   TEXT,
    favicon_md5     TEXT,
    dmarc           TEXT
);
CREATE INDEX IF NOT EXISTS idx_meta_search_id ON page_metadata(search_id);
CREATE INDEX IF NOT EXISTS idx_meta_lang      ON page_metadata(html_lang);
CREATE INDEX IF NOT EXISTS idx_meta_cms       ON page_metadata(cms_generator);
"""


_CHILD_TABLES = [
    "ips", "tls_certs", "ct_certs", "subdomains", "dns_records",
    "historical_dns", "tracking_ids", "social_accounts", "favicons",
    "whois_data", "registrant_emails", "nameservers", "spf_origins",
    "cross_sans", "scan_hits", "provider_hits", "page_metadata",
]


def _table_columns(c: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in c.execute(f"PRAGMA table_info({table})").fetchall()}


def _add_column_if_missing(c: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    if column not in _table_columns(c, table):
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _migrate_schema(c: sqlite3.Connection) -> None:
    c.execute("DROP INDEX IF EXISTS idx_searches_target_unique")

    for column, definition in [
        ("asn_registry", "TEXT"),
        ("network_name", "TEXT"),
        ("network_cidr", "TEXT"),
        ("proxy_family", "TEXT"),
        ("proxy_confidence", "REAL"),
        ("observed_at", "TEXT"),
        ("port", "INTEGER"),
    ]:
        _add_column_if_missing(c, "ips", column, definition)

    _add_column_if_missing(c, "tls_certs", "sha256", "TEXT")
    _add_column_if_missing(c, "tls_certs", "observed_at", "TEXT")
    _add_column_if_missing(c, "ct_certs", "observed_at", "TEXT")
    _add_column_if_missing(c, "scan_hits", "sha256", "TEXT")
    _add_column_if_missing(c, "scan_hits", "observed_at", "TEXT")


def init_db() -> None:
    with _conn() as c:
        schema_statements = [stmt.strip() for stmt in _SCHEMA.strip().split(";") if stmt.strip()]
        table_statements = [stmt for stmt in schema_statements if not stmt.upper().startswith("CREATE INDEX")]
        index_statements = [stmt for stmt in schema_statements if stmt.upper().startswith("CREATE INDEX")]

        for stmt in table_statements:
            stmt = stmt.strip()
            c.execute(stmt)
        _migrate_schema(c)
        for stmt in index_statements:
            c.execute(stmt)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _json(value: Any) -> str:
    return json.dumps(value, default=str)


def _normalize_asn(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().upper()
    if not text:
        return None
    return text[2:] if text.startswith("AS") else text


def _normalize_target(value: str) -> str:
    target = (value or "").strip().lower()
    return target[4:] if target.startswith("www.") else target


def _dedup_targets(targets_str: str) -> list[str]:
    seen: dict[str, str] = {}
    for target in str(targets_str or "").split(","):
        target = target.strip()
        if not target:
            continue
        norm = _normalize_target(target)
        if norm not in seen or target == norm:
            seen[norm] = target
    return list(seen.values())


def _safe_iso(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def _latest_search_rows(c: sqlite3.Connection) -> list[sqlite3.Row]:
    rows = c.execute(
        "SELECT id, target, type, timestamp, cloudflare_fronted FROM searches ORDER BY target, timestamp DESC, id DESC"
    ).fetchall()
    latest: dict[str, sqlite3.Row] = {}
    for row in rows:
        norm = _normalize_target(row["target"])
        latest.setdefault(norm, row)
    return list(latest.values())


def _latest_search_id_map(c: sqlite3.Connection) -> dict[str, int]:
    return {_normalize_target(row["target"]): int(row["id"]) for row in _latest_search_rows(c)}


def _search_rows_for_target(c: sqlite3.Connection, target: str) -> list[sqlite3.Row]:
    norm = _normalize_target(target)
    rows = c.execute(
        "SELECT id, target, type, timestamp, cloudflare_fronted FROM searches ORDER BY timestamp DESC, id DESC"
    ).fetchall()
    return [row for row in rows if _normalize_target(row["target"]) == norm]


def _latest_row_for_target(c: sqlite3.Connection, target: str) -> sqlite3.Row | None:
    rows = _search_rows_for_target(c, target)
    return rows[0] if rows else None


def _query_rows_for_ids(c: sqlite3.Connection, query: str, ids: list[int], params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    if not ids:
        return []
    placeholders = ",".join("?" for _ in ids)
    return c.execute(query.format(placeholders=placeholders), (*ids, *params)).fetchall()


def _parse_json_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    text = str(value).strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else []
    except json.JSONDecodeError:
        return []


def _normalize_nameservers(values: Any) -> list[str]:
    raw = values or []
    if isinstance(raw, str):
        raw = [raw]

    cleaned: list[str] = []
    seen: set[str] = set()
    for value in raw:
        text = str(value or "").strip().rstrip(".").lower()
        if not text:
            continue
        if text in {"creation", "updated"}:
            continue
        if "." not in text:
            continue
        if text not in seen:
            seen.add(text)
            cleaned.append(text)
    return cleaned


def _extract_ip_port_map(result: dict[str, Any]) -> dict[tuple[str, str], int | None]:
    mapping: dict[tuple[str, str], int | None] = {}
    origin = result.get("origin_candidates") or {}

    for provider in ("censys", "shodan", "netlas"):
        provider_result = origin.get(provider) or {}
        for hit in provider_result.get("hits") or []:
            ip = hit.get("ip")
            if ip:
                mapping[(ip, provider)] = hit.get("port")

    for scan_key, source in [
        ("scan", "scan_gcp"),
        ("provider_scan", "scan_provider"),
        ("country_scan", "scan_country"),
    ]:
        scan_result = origin.get(scan_key) or {}
        for hit in scan_result.get("hits") or []:
            ip = hit.get("ip")
            if ip:
                mapping[(ip, source)] = hit.get("port") or 443

    if result.get("type") == "ip":
        mapping[(result.get("input", ""), "direct")] = 443

    return mapping


def _row_target_list(rows: list[sqlite3.Row], exclude_norm: str | None = None) -> list[str]:
    targets = []
    for row in rows:
        target = row["target"]
        if exclude_norm and _normalize_target(target) == exclude_norm:
            continue
        targets.append(target)
    return _dedup_targets(",".join(targets))


# ── Save ──────────────────────────────────────────────────────────────────────

def save_search(result: dict) -> int:
    """
    Insert a completed analysis result append-only and persist all observations.
    """
    init_db()

    target = result.get("input", "")
    typ = result.get("type", "unknown")
    timestamp = result.get("timestamp", datetime.now(timezone.utc).isoformat())
    cf = result.get("cloudflare_fronted")
    cf_val = 1 if cf else (0 if cf is not None else None)

    payload = json.dumps(result, default=str)

    with _conn() as c:
        c.execute("BEGIN IMMEDIATE")
        c.execute(
            "INSERT INTO searches (target, type, timestamp, cloudflare_fronted, raw_json) VALUES (?,?,?,?,?)",
            (target, typ, timestamp, cf_val, payload),
        )
        sid = int(c.execute("SELECT last_insert_rowid()").fetchone()[0])

        ip_details = result.get("ip_details", {})
        ip_ports = _extract_ip_port_map(result)

        if typ == "domain":
            for ip, info in ip_details.items():
                sources = sorted(set(info.get("sources") or []))
                asn = info.get("asn_info") or {}
                info_cf = info.get("cloudflare")
                cf_value = 1 if info_cf else (0 if info_cf is not None else None)
                for source in sources:
                    c.execute(
                        """INSERT INTO ips
                           (search_id, ip, source, cloudflare, ptr, asn, asn_desc, asn_registry, country,
                            network_name, network_cidr, proxy_family, proxy_confidence, observed_at, port)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            sid,
                            ip,
                            source,
                            cf_value,
                            info.get("ptr"),
                            _normalize_asn(asn.get("asn")),
                            asn.get("asn_description"),
                            asn.get("asn_registry"),
                            asn.get("asn_country") or asn.get("network_country"),
                            asn.get("network_name"),
                            asn.get("network_cidr") or asn.get("asn_cidr"),
                            info.get("proxy_family"),
                            info.get("proxy_confidence"),
                            timestamp,
                            ip_ports.get((ip, source)),
                        ),
                    )
        elif typ == "ip":
            asn = result.get("asn_info", {})
            c.execute(
                """INSERT INTO ips
                   (search_id, ip, source, cloudflare, ptr, asn, asn_desc, asn_registry, country,
                    network_name, network_cidr, proxy_family, proxy_confidence, observed_at, port)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    sid,
                    target,
                    "direct",
                    1 if result.get("cloudflare") else 0,
                    result.get("ptr"),
                    _normalize_asn(asn.get("asn")),
                    asn.get("asn_description"),
                    asn.get("asn_registry"),
                    asn.get("asn_country") or asn.get("network_country"),
                    asn.get("network_name"),
                    asn.get("network_cidr") or asn.get("asn_cidr"),
                    result.get("proxy_family"),
                    result.get("proxy_confidence"),
                    timestamp,
                    443,
                ),
            )

        tls_list = result.get("non_cf_tls_certs") or ([result["tls_cert"]] if result.get("tls_cert") else [])
        for cert in tls_list:
            if not cert:
                continue
            c.execute(
                """INSERT INTO tls_certs
                   (search_id, ip, port, sni_used, cn, sans, issuer_cn, issuer_org, not_before, not_after, sha256, observed_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    sid,
                    cert.get("ip"),
                    cert.get("port", 443),
                    cert.get("sni_used"),
                    cert.get("cn"),
                    _json(cert.get("sans", [])),
                    cert.get("issuer_cn"),
                    cert.get("issuer_org"),
                    cert.get("not_before"),
                    cert.get("not_after"),
                    cert.get("sha256"),
                    timestamp,
                ),
            )

        origin = result.get("origin_candidates") or {}
        for scan_key, scan_label in [
            ("scan", "gcp"),
            ("provider_scan", "asn"),
            ("country_scan", "country"),
        ]:
            scan_result = origin.get(scan_key) or {}
            if not isinstance(scan_result, dict) or scan_result.get("skipped"):
                continue
            for hit in scan_result.get("hits") or []:
                if not hit.get("ip"):
                    continue
                c.execute(
                    """INSERT INTO scan_hits
                       (search_id, scan_type, ip, port, cn, sans, issuer, not_before, not_after, sha256, cloudflare, observed_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        sid,
                        scan_label,
                        hit.get("ip"),
                        hit.get("port", 443),
                        hit.get("cn"),
                        _json(hit.get("sans", [])),
                        hit.get("issuer") or hit.get("issuer_cn"),
                        hit.get("not_before"),
                        hit.get("not_after"),
                        hit.get("sha256"),
                        1 if hit.get("cloudflare") else 0,
                        timestamp,
                    ),
                )

        for provider in ("censys", "shodan", "netlas"):
            provider_result = origin.get(provider) or {}
            if not isinstance(provider_result, dict):
                continue
            for hit in provider_result.get("hits") or []:
                c.execute(
                    """INSERT INTO provider_hits
                       (search_id, provider, ip, port, protocol, asn, asn_desc, org, country, cloudflare,
                        services, hostnames, mode, status, query_type, total, observed_at, raw_json)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        sid,
                        provider,
                        hit.get("ip"),
                        hit.get("port"),
                        hit.get("protocol"),
                        _normalize_asn(hit.get("asn")),
                        hit.get("asn_name") or hit.get("asn_desc"),
                        hit.get("org"),
                        hit.get("country"),
                        1 if hit.get("cloudflare") else 0,
                        _json(hit.get("services", [])),
                        _json(hit.get("hostnames", [])),
                        provider_result.get("mode"),
                        provider_result.get("status"),
                        provider_result.get("query_type"),
                        provider_result.get("total"),
                        timestamp,
                        _json(hit),
                    ),
                )

        ct = result.get("cert_transparency", {})
        for cert in ct.get("certs", []):
            c.execute(
                "INSERT INTO ct_certs (search_id, cert_id, issuer, not_before, not_after, sans, observed_at) VALUES (?,?,?,?,?,?,?)",
                (
                    sid,
                    cert.get("id"),
                    cert.get("issuer"),
                    cert.get("not_before"),
                    cert.get("not_after"),
                    _json(cert.get("sans", [])),
                    timestamp,
                ),
            )

        for san in ct.get("cross_domain_sans", []):
            c.execute("INSERT INTO cross_sans (search_id, san) VALUES (?,?)", (sid, san))

        for sub in result.get("subdomains", []):
            c.execute("INSERT INTO subdomains (search_id, subdomain, source) VALUES (?,?,?)", (sid, sub, "crt.sh"))
        for sub in result.get("zone_transfer", []):
            c.execute("INSERT INTO subdomains (search_id, subdomain, source) VALUES (?,?,?)", (sid, sub, "zone_transfer"))

        dns = result.get("dns", {})
        for rtype, values in dns.items():
            if not values:
                continue
            if isinstance(values, list):
                for value in values:
                    c.execute(
                        "INSERT INTO dns_records (search_id, rtype, value) VALUES (?,?,?)",
                        (sid, rtype, _json(value) if isinstance(value, dict) else str(value)),
                    )
            elif isinstance(values, dict):
                c.execute("INSERT INTO dns_records (search_id, rtype, value) VALUES (?,?,?)", (sid, rtype, _json(values)))

        for rec in result.get("historical_dns", {}).get("records", []):
            c.execute(
                "INSERT INTO historical_dns (search_id, rrtype, rdata, first_seen, last_seen) VALUES (?,?,?,?,?)",
                (sid, rec.get("rrtype"), rec.get("rdata"), rec.get("first_seen"), rec.get("last_seen")),
            )

        for entry in result.get("spf_origins", []):
            c.execute(
                "INSERT INTO spf_origins (search_id, ip, cidr) VALUES (?,?,?)",
                (sid, entry.get("ip"), entry.get("cidr")),
            )

        whois_row = result.get("whois", {})
        if whois_row and not whois_row.get("error"):
            emails_raw = whois_row.get("emails") or []
            if isinstance(emails_raw, str):
                emails_raw = [emails_raw]
            ns_raw = _normalize_nameservers(whois_row.get("nameservers") or [])

            c.execute(
                """INSERT INTO whois_data
                   (search_id, registrar, creation_date, expiry_date, org, country, emails, nameservers)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    sid,
                    str(whois_row.get("registrar") or ""),
                    str(whois_row.get("creation_date") or "")[:30],
                    str(whois_row.get("expiry_date") or "")[:30],
                    str(whois_row.get("org") or ""),
                    str(whois_row.get("country") or ""),
                    _json(emails_raw),
                    _json(ns_raw),
                ),
            )

            for email in emails_raw:
                if email and isinstance(email, str):
                    c.execute("INSERT INTO registrant_emails (search_id, email) VALUES (?,?)", (sid, email.lower().strip()))

            for nameserver in ns_raw:
                c.execute("INSERT INTO nameservers (search_id, nameserver) VALUES (?,?)", (sid, nameserver))

        meta = result.get("page_metadata", {})
        for id_type, key in [
            ("ga", "google_analytics"),
            ("gtm", "gtm_ids"),
            ("fb_pixel", "facebook_pixel"),
            ("tiktok_pixel", "tiktok_pixel"),
            ("yandex_metrika", "yandex_metrika"),
        ]:
            for value in (meta.get(key) or []):
                c.execute("INSERT INTO tracking_ids (search_id, id_type, id_value) VALUES (?,?,?)", (sid, id_type, str(value)))

        handles = meta.get("social_handles", {})
        links = meta.get("social_links", {})
        for platform in set(handles) | set(links):
            urls = links.get(platform) or []
            for handle in (handles.get(platform) or []):
                c.execute(
                    "INSERT INTO social_accounts (search_id, platform, handle, url) VALUES (?,?,?,?)",
                    (sid, platform, handle, urls[0] if urls else None),
                )

        favicon_md5 = meta.get("favicon_md5")
        if favicon_md5:
            c.execute("INSERT INTO favicons (search_id, md5) VALUES (?,?)", (sid, favicon_md5))

        email_security = result.get("email_security", {})
        c.execute(
            "INSERT INTO page_metadata (search_id, html_lang, cms_generator, favicon_md5, dmarc) VALUES (?,?,?,?,?)",
            (sid, meta.get("html_lang"), meta.get("cms_generator"), favicon_md5, email_security.get("dmarc")),
        )

    return sid


# ── Queries ───────────────────────────────────────────────────────────────────

def get_recent(limit: int = 100) -> list[dict]:
    init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT id, target, type, timestamp, cloudflare_fronted FROM searches ORDER BY timestamp DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_domains_with_source_errors(source: str | None = None) -> list[dict]:
    init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT id, target, timestamp, json_extract(raw_json, '$.source_errors') AS errors "
            "FROM searches WHERE json_extract(raw_json, '$.source_errors') IS NOT NULL "
            "ORDER BY timestamp DESC, id DESC"
        ).fetchall()

    results = []
    for row in rows:
        errors = _parse_json_list(row["errors"])
        if source is None or source in errors:
            results.append({"id": row["id"], "target": row["target"], "timestamp": row["timestamp"], "errors": errors})
    return results


def get_by_id(sid: int) -> dict | None:
    init_db()
    with _conn() as c:
        row = c.execute("SELECT * FROM searches WHERE id = ?", (sid,)).fetchone()
    return dict(row) if row else None


def get_history_for_target(target: str) -> list[dict]:
    init_db()
    with _conn() as c:
        rows = _search_rows_for_target(c, target)
    latest_id = rows[0]["id"] if rows else None
    return [
        {
            "id": row["id"],
            "target": row["target"],
            "type": row["type"],
            "timestamp": row["timestamp"],
            "cloudflare_fronted": row["cloudflare_fronted"],
            "is_latest": row["id"] == latest_id,
        }
        for row in rows
    ]


# ── Historical pivots ─────────────────────────────────────────────────────────

def find_by_ip(ip: str) -> list[dict]:
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT s.id, s.target, s.type, s.timestamp, i.source
               FROM searches s JOIN ips i ON s.id = i.search_id
               WHERE i.ip = ?
               ORDER BY s.timestamp DESC, s.id DESC""",
            (ip,),
        ).fetchall()
    return [dict(row) for row in rows]


def find_by_tls_sha256(sha256: str) -> list[dict]:
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT s.id, s.target, s.type, s.timestamp, t.cn, t.issuer_cn
               FROM searches s JOIN tls_certs t ON s.id = t.search_id
               WHERE t.sha256 = ?
               ORDER BY s.timestamp DESC, s.id DESC""",
            (sha256,),
        ).fetchall()
    return [dict(row) for row in rows]


def find_by_tracking_id(id_type: str, id_value: str) -> list[dict]:
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT s.id, s.target, s.type, s.timestamp
               FROM searches s JOIN tracking_ids t ON s.id = t.search_id
               WHERE t.id_type = ? AND t.id_value = ?
               ORDER BY s.timestamp DESC, s.id DESC""",
            (id_type, id_value),
        ).fetchall()
    return [dict(row) for row in rows]


def find_by_favicon(md5: str) -> list[dict]:
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT s.id, s.target, s.type, s.timestamp
               FROM searches s JOIN favicons f ON s.id = f.search_id
               WHERE f.md5 = ?
               ORDER BY s.timestamp DESC, s.id DESC""",
            (md5,),
        ).fetchall()
    return [dict(row) for row in rows]


def find_by_registrant_email(email: str) -> list[dict]:
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT s.id, s.target, s.type, s.timestamp
               FROM searches s JOIN registrant_emails e ON s.id = e.search_id
               WHERE e.email = ?
               ORDER BY s.timestamp DESC, s.id DESC""",
            (email.lower().strip(),),
        ).fetchall()
    return [dict(row) for row in rows]


def find_by_social_handle(platform: str, handle: str) -> list[dict]:
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT s.id, s.target, s.type, s.timestamp
               FROM searches s JOIN social_accounts a ON s.id = a.search_id
               WHERE a.platform = ? AND a.handle = ?
               ORDER BY s.timestamp DESC, s.id DESC""",
            (platform, handle),
        ).fetchall()
    return [dict(row) for row in rows]


def find_by_nameserver(ns: str) -> list[dict]:
    nameserver = str(ns or "").strip().rstrip(".").lower()
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT s.id, s.target, s.type, s.timestamp
               FROM searches s JOIN nameservers n ON s.id = n.search_id
               WHERE n.nameserver = ?
               ORDER BY s.timestamp DESC, s.id DESC""",
            (nameserver,),
        ).fetchall()
    return [dict(row) for row in rows]


def find_by_cross_san(san: str) -> list[dict]:
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT s.id, s.target, s.type, s.timestamp
               FROM searches s JOIN cross_sans cs ON s.id = cs.search_id
               WHERE cs.san = ?
               ORDER BY s.timestamp DESC, s.id DESC""",
            (san,),
        ).fetchall()
    return [dict(row) for row in rows]


# ── Classification ────────────────────────────────────────────────────────────

_MAIL_ASNS = {"15169", "16276", "8075", "3215", "394161"}
_CDN_PROXY_ASNS = {"13335", "19551", "54113", "20940", "60626", "394536", "22822", "16625", "16509", "8075", "15169", "20473"}
_SHARED_HOSTING_ASNS = {"2635", "27647", "61493", "2025"}

_MAIL_PTR_PATTERNS = ("1e100.net", "google.com", "mail.ovh.", "smtp.", "mx.", "-mx-", "mail-", "mailout", "mxbiz")
_CDN_PROXY_PTR_PATTERNS = (
    "incapsula.com", "cloudflare.com", "cloudflare.net", "fastly.net",
    "akamai.net", "akamaiedge.net", "akamaized.net", "edgecast.net",
    "sucuri.net", "imperva.com", "cdn.", "cloudfront.net", "azurefd.net",
    "googleusercontent.com", "googlehosted.com", "b-cdn.net",
)
_SHARED_HOSTING_PTR_PATTERNS = ("wildcard.", "weebly.com", "wordpress.com", "wix.com", "squarespace.com", "cluster", "shared-", "hosting.")
_EMAIL_SOURCES = {"mx_record", "spf"}


def classify_ip(
    ip: str,
    ptr: str | None,
    asn: str | None,
    sources: str | None,
    proxy_family: str | None = None,
) -> str:
    ptr_lower = (ptr or "").lower()
    src_set = {item for item in str(sources or "").split(",") if item}
    norm_asn = _normalize_asn(asn)

    if src_set and src_set <= _EMAIL_SOURCES:
        return "mail"
    if norm_asn in _MAIL_ASNS and src_set <= _EMAIL_SOURCES | {"dns"}:
        return "mail"
    if any(pattern in ptr_lower for pattern in _MAIL_PTR_PATTERNS):
        return "mail"

    if proxy_family:
        return "cdn_proxy"
    if norm_asn in _CDN_PROXY_ASNS:
        return "cdn_proxy"
    if any(pattern in ptr_lower for pattern in _CDN_PROXY_PTR_PATTERNS):
        return "cdn_proxy"

    if norm_asn in _SHARED_HOSTING_ASNS:
        return "shared_hosting"
    if any(pattern in ptr_lower for pattern in _SHARED_HOSTING_PTR_PATTERNS):
        return "shared_hosting"

    return "direct"


def _is_noise_label(label: str | None) -> bool:
    return label in {"mail", "cdn_proxy", "shared_hosting"}


# ── Cluster helpers ───────────────────────────────────────────────────────────

def _latest_ids(c: sqlite3.Connection) -> list[int]:
    return [int(row["id"]) for row in _latest_search_rows(c)]


def _aggregate_targets(rows: list[sqlite3.Row], key_fn) -> dict[Any, dict[str, Any]]:
    grouped: dict[Any, dict[str, Any]] = {}
    for row in rows:
        key = key_fn(row)
        entry = grouped.setdefault(key, {"targets": [], "rows": []})
        entry["targets"].append(row["target"])
        entry["rows"].append(row)
    return grouped


def _finalize_cluster_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for item in items:
        targets = _dedup_targets(",".join(item.get("targets", [])))
        if len(targets) < 2:
            continue
        enriched = dict(item)
        enriched["targets"] = ",".join(targets)
        enriched["target_count"] = len(targets)
        output.append(enriched)
    return output


def cluster_by_ip() -> list[dict]:
    init_db()
    with _conn() as c:
        rows = _query_rows_for_ids(
            c,
            """SELECT s.target, i.ip, i.source, i.ptr, i.asn, i.asn_desc, i.network_cidr, i.proxy_family, i.cloudflare
               FROM ips i JOIN searches s ON s.id = i.search_id
               WHERE i.search_id IN ({placeholders}) AND (i.cloudflare = 0 OR i.cloudflare IS NULL)""",
            _latest_ids(c),
        )

    grouped = _aggregate_targets(rows, lambda row: row["ip"])
    items = []
    for ip, payload in grouped.items():
        source_list = sorted({row["source"] for row in payload["rows"] if row["source"]})
        sample = payload["rows"][-1]
        label = classify_ip(ip, sample["ptr"], sample["asn"], ",".join(source_list), sample["proxy_family"])
        items.append(
            {
                "ip": ip,
                "ptr": sample["ptr"],
                "asn": _normalize_asn(sample["asn"]),
                "asn_desc": sample["asn_desc"],
                "network_cidr": sample["network_cidr"],
                "proxy_family": sample["proxy_family"],
                "sources": ",".join(source_list),
                "label": label,
                "targets": payload["targets"],
                "is_noise": _is_noise_label(label),
            }
        )
    return sorted(_finalize_cluster_items(items), key=lambda item: (-item["target_count"], item["ip"]))


def cluster_by_tracking_id() -> list[dict]:
    init_db()
    with _conn() as c:
        rows = _query_rows_for_ids(
            c,
            """SELECT s.target, t.id_type, t.id_value
               FROM tracking_ids t JOIN searches s ON s.id = t.search_id
               WHERE t.search_id IN ({placeholders})""",
            _latest_ids(c),
        )

    grouped = _aggregate_targets(rows, lambda row: (row["id_type"], row["id_value"]))
    items = [{"id_type": id_type, "id_value": id_value, "targets": payload["targets"]} for (id_type, id_value), payload in grouped.items()]
    return sorted(_finalize_cluster_items(items), key=lambda item: (-item["target_count"], item["id_type"], item["id_value"]))


def cluster_by_favicon() -> list[dict]:
    init_db()
    with _conn() as c:
        rows = _query_rows_for_ids(
            c,
            """SELECT s.target, f.md5
               FROM favicons f JOIN searches s ON s.id = f.search_id
               WHERE f.search_id IN ({placeholders})""",
            _latest_ids(c),
        )

    grouped = _aggregate_targets(rows, lambda row: row["md5"])
    items = [{"md5": md5, "targets": payload["targets"]} for md5, payload in grouped.items()]
    return sorted(_finalize_cluster_items(items), key=lambda item: (-item["target_count"], item["md5"]))


def _load_tls_observations(c: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = c.execute(
        """SELECT s.id AS search_id, s.target, t.sha256, t.cn, t.issuer_cn AS issuer, t.not_before, t.not_after,
                  t.observed_at, 'tls_probe' AS source
           FROM tls_certs t JOIN searches s ON s.id = t.search_id
           WHERE t.sha256 IS NOT NULL AND t.sha256 != ''
           UNION ALL
           SELECT s.id AS search_id, s.target, h.sha256, h.cn, h.issuer AS issuer, h.not_before, h.not_after,
                  h.observed_at, 'scan' AS source
           FROM scan_hits h JOIN searches s ON s.id = h.search_id
           WHERE h.sha256 IS NOT NULL AND h.sha256 != ''"""
    ).fetchall()
    return [dict(row) for row in rows]


def cluster_by_tls_cert(scope: str = "current") -> list[dict]:
    scope = (scope or "current").lower()
    if scope not in {"current", "historical", "all"}:
        scope = "current"

    init_db()
    with _conn() as c:
        latest_map = _latest_search_id_map(c)
        latest_ids = set(latest_map.values())
        grouped: dict[str, dict[str, Any]] = {}
        for row in _load_tls_observations(c):
            fingerprint = row["sha256"]
            entry = grouped.setdefault(
                fingerprint,
                {
                    "sha256": fingerprint,
                    "cn": row.get("cn"),
                    "issuer_cn": row.get("issuer"),
                    "targets_all": set(),
                    "targets_current": set(),
                    "first_observed": row.get("observed_at"),
                    "last_observed": row.get("observed_at"),
                    "overlap_start": row.get("not_before"),
                    "overlap_end": row.get("not_after"),
                },
            )
            entry["targets_all"].add(row["target"])
            if row["search_id"] in latest_ids:
                entry["targets_current"].add(row["target"])
                if row.get("cn"):
                    entry["cn"] = row["cn"]
                if row.get("issuer"):
                    entry["issuer_cn"] = row["issuer"]

            observed_at = row.get("observed_at")
            if observed_at and (not entry["first_observed"] or observed_at < entry["first_observed"]):
                entry["first_observed"] = observed_at
            if observed_at and (not entry["last_observed"] or observed_at > entry["last_observed"]):
                entry["last_observed"] = observed_at

            not_before = row.get("not_before")
            not_after = row.get("not_after")
            if not_before and (not entry["overlap_start"] or not_before > entry["overlap_start"]):
                entry["overlap_start"] = not_before
            if not_after and (not entry["overlap_end"] or not_after < entry["overlap_end"]):
                entry["overlap_end"] = not_after

    items = []
    for entry in grouped.values():
        current_targets = _dedup_targets(",".join(entry["targets_current"]))
        all_targets = _dedup_targets(",".join(entry["targets_all"]))
        current_count = len(current_targets)
        all_count = len(all_targets)
        if all_count < 2:
            continue

        relationship_status = "current" if current_count > 1 else "historical"
        if scope == "current" and relationship_status != "current":
            continue
        if scope == "historical" and relationship_status != "historical":
            continue

        scoped_targets = current_targets if scope == "current" else all_targets
        items.append(
            {
                "sha256": entry["sha256"],
                "cn": entry["cn"],
                "issuer_cn": entry["issuer_cn"],
                "targets": scoped_targets,
                "current_target_count": current_count,
                "historical_target_count": all_count,
                "relationship_status": relationship_status,
                "first_observed": entry["first_observed"],
                "last_observed": entry["last_observed"],
                "overlap_start": entry["overlap_start"],
                "overlap_end": entry["overlap_end"],
            }
        )
    return sorted(_finalize_cluster_items(items), key=lambda item: (-item["target_count"], item["sha256"]))


def cluster_by_asn(scope: str = "current") -> list[dict]:
    scope = (scope or "current").lower()
    if scope not in {"current", "historical", "all"}:
        scope = "current"

    init_db()
    with _conn() as c:
        latest_ids = set(_latest_ids(c))
        rows = c.execute(
            """SELECT s.id AS search_id, s.target, i.asn, i.asn_desc, i.network_cidr, i.ptr, i.source, i.proxy_family,
                      i.cloudflare
               FROM ips i JOIN searches s ON s.id = i.search_id
               WHERE (i.cloudflare = 0 OR i.cloudflare IS NULL) AND i.asn IS NOT NULL AND i.asn != ''"""
        ).fetchall()

    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        asn = _normalize_asn(row["asn"])
        if not asn:
            continue
        entry = grouped.setdefault(
            asn,
            {
                "asn": asn,
                "asn_desc": row["asn_desc"],
                "targets_all": set(),
                "targets_current": set(),
                "network_cidrs": set(),
                "proxy_families": set(),
                "sources": set(),
                "label": None,
            },
        )
        entry["targets_all"].add(row["target"])
        if row["search_id"] in latest_ids:
            entry["targets_current"].add(row["target"])
        if row["network_cidr"]:
            entry["network_cidrs"].add(row["network_cidr"])
        if row["proxy_family"]:
            entry["proxy_families"].add(row["proxy_family"])
        if row["source"]:
            entry["sources"].add(row["source"])
        entry["label"] = classify_ip("0.0.0.0", row["ptr"], asn, row["source"], row["proxy_family"])

    items = []
    for entry in grouped.values():
        current_targets = _dedup_targets(",".join(entry["targets_current"]))
        all_targets = _dedup_targets(",".join(entry["targets_all"]))
        if len(all_targets) < 2:
            continue
        relationship_status = "current" if len(current_targets) > 1 else "historical"
        if scope == "current" and relationship_status != "current":
            continue
        if scope == "historical" and relationship_status != "historical":
            continue
        scoped_targets = current_targets if scope == "current" else all_targets
        items.append(
            {
                "asn": entry["asn"],
                "asn_desc": entry["asn_desc"],
                "network_cidrs": sorted(entry["network_cidrs"]),
                "proxy_families": sorted(entry["proxy_families"]),
                "sources": ",".join(sorted(entry["sources"])),
                "label": entry["label"],
                "is_noise": _is_noise_label(entry["label"]),
                "relationship_status": relationship_status,
                "current_target_count": len(current_targets),
                "historical_target_count": len(all_targets),
                "targets": scoped_targets,
            }
        )
    return sorted(_finalize_cluster_items(items), key=lambda item: (-item["target_count"], item["asn"]))


# ── Per-target connections ────────────────────────────────────────────────────

_GENERIC_EMAILS = {
    "abuse@godaddy.com", "domain.operations@web.com",
    "abuse@namecheap.com", "abuse@networksolutions.com",
    "noreply@domains.google.com", "registrar@enom.com",
    "abuse@tucows.com", "abuse@pairdomains.com",
}


def get_connections_for_target(target: str) -> dict | None:
    init_db()
    with _conn() as c:
        current_row = _latest_row_for_target(c, target)
        if current_row is None:
            return None

        current_sid = int(current_row["id"])
        norm_target = _normalize_target(current_row["target"])
        history_rows = _search_rows_for_target(c, current_row["target"])
        target_sids = [int(row["id"]) for row in history_rows]

        latest_rows = _latest_search_rows(c)
        latest_ids = [int(row["id"]) for row in latest_rows]
        latest_norms = {_normalize_target(row["target"]): int(row["id"]) for row in latest_rows}

        def _others_by(table: str, column: str, value: Any) -> list[str]:
            rows = _query_rows_for_ids(
                c,
                f"""SELECT DISTINCT s.target
                    FROM {table} x JOIN searches s ON s.id = x.search_id
                    WHERE x.search_id IN ({{placeholders}}) AND x.{column} = ?""",
                latest_ids,
                (value,),
            )
            return _row_target_list(rows, exclude_norm=norm_target)

        whois = c.execute(
            "SELECT registrar, creation_date, expiry_date, org, country FROM whois_data WHERE search_id = ? ORDER BY id DESC LIMIT 1",
            (current_sid,),
        ).fetchone()

        tracking = []
        for row in c.execute("SELECT id_type, id_value FROM tracking_ids WHERE search_id = ?", (current_sid,)).fetchall():
            tracking.append({"id_type": row["id_type"], "id_value": row["id_value"], "shared_with": _others_by("tracking_ids", "id_value", row["id_value"])})

        ips = []
        seen_ips: set[str] = set()
        for row in c.execute(
            """SELECT ip, source, ptr, asn, asn_desc, country, cloudflare, network_cidr, proxy_family
               FROM ips WHERE search_id = ?""",
            (current_sid,),
        ).fetchall():
            ip = row["ip"]
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            asn = _normalize_asn(row["asn"])
            label = classify_ip(ip, row["ptr"], asn, row["source"], row["proxy_family"])
            network_shared_with = _others_by("ips", "network_cidr", row["network_cidr"]) if row["network_cidr"] else []
            ips.append(
                {
                    "ip": ip,
                    "source": row["source"],
                    "ptr": row["ptr"],
                    "asn": asn,
                    "asn_desc": row["asn_desc"],
                    "country": row["country"],
                    "cloudflare": row["cloudflare"],
                    "network_cidr": row["network_cidr"],
                    "proxy_family": row["proxy_family"],
                    "label": label,
                    "shared_with": _others_by("ips", "ip", ip),
                    "shared_network_with": network_shared_with,
                }
            )

        asns = []
        seen_asns: set[str] = set()
        for row in c.execute(
            """SELECT asn, asn_desc, network_cidr, ptr, source, proxy_family
               FROM ips WHERE search_id = ? AND asn IS NOT NULL AND asn != ''""",
            (current_sid,),
        ).fetchall():
            asn = _normalize_asn(row["asn"])
            if not asn or asn in seen_asns:
                continue
            seen_asns.add(asn)
            label = classify_ip("0.0.0.0", row["ptr"], asn, row["source"], row["proxy_family"])
            shared_network = _others_by("ips", "network_cidr", row["network_cidr"]) if row["network_cidr"] else []
            asns.append(
                {
                    "asn": asn,
                    "asn_desc": row["asn_desc"],
                    "network_cidr": row["network_cidr"],
                    "proxy_family": row["proxy_family"],
                    "label": label,
                    "is_noise": _is_noise_label(label),
                    "shared_with": _others_by("ips", "asn", asn),
                    "shared_network_with": shared_network,
                }
            )

        tls = []
        seen_tls: set[str] = set()
        for row in c.execute(
            """SELECT sha256, cn, sans, issuer_cn, ip, not_before, not_after
               FROM tls_certs WHERE search_id = ?""",
            (current_sid,),
        ).fetchall():
            fingerprint = row["sha256"]
            if not fingerprint or fingerprint in seen_tls:
                continue
            seen_tls.add(fingerprint)
            tls.append(
                {
                    "sha256": fingerprint,
                    "cn": row["cn"],
                    "sans": row["sans"],
                    "issuer_cn": row["issuer_cn"],
                    "ip": row["ip"],
                    "not_before": row["not_before"],
                    "not_after": row["not_after"],
                    "shared_with": _others_by("tls_certs", "sha256", fingerprint),
                }
            )

        provider_hits = []
        seen_provider_hits: set[tuple[str, str | None]] = set()
        for row in c.execute(
            """SELECT provider, ip, port, protocol, asn, asn_desc, org, country, mode, status, query_type
               FROM provider_hits WHERE search_id = ?""",
            (current_sid,),
        ).fetchall():
            key = (row["provider"], row["ip"])
            if key in seen_provider_hits:
                continue
            seen_provider_hits.add(key)
            provider_hits.append(
                {
                    "provider": row["provider"],
                    "ip": row["ip"],
                    "port": row["port"],
                    "protocol": row["protocol"],
                    "asn": _normalize_asn(row["asn"]),
                    "asn_desc": row["asn_desc"],
                    "org": row["org"],
                    "country": row["country"],
                    "mode": row["mode"],
                    "status": row["status"],
                    "query_type": row["query_type"],
                    "shared_with": _row_target_list(
                        _query_rows_for_ids(
                            c,
                            """SELECT DISTINCT s.target
                               FROM provider_hits p JOIN searches s ON s.id = p.search_id
                               WHERE p.search_id IN ({placeholders}) AND p.provider = ? AND p.ip = ?""",
                            latest_ids,
                            (row["provider"], row["ip"]),
                        ),
                        exclude_norm=norm_target,
                    ),
                }
            )

        tls_history = []
        tls_observations = _load_tls_observations(c)
        grouped_tls: dict[str, dict[str, Any]] = defaultdict(lambda: {"target_rows": [], "other_rows": [], "cn": None, "issuer": None, "not_before": None, "not_after": None})
        for observation in tls_observations:
            fingerprint = observation["sha256"]
            entry = grouped_tls[fingerprint]
            if observation.get("cn"):
                entry["cn"] = observation["cn"]
            if observation.get("issuer"):
                entry["issuer"] = observation["issuer"]
            if observation.get("not_before") and (not entry["not_before"] or observation["not_before"] > entry["not_before"]):
                entry["not_before"] = observation["not_before"]
            if observation.get("not_after") and (not entry["not_after"] or observation["not_after"] < entry["not_after"]):
                entry["not_after"] = observation["not_after"]
            if int(observation["search_id"]) in target_sids:
                entry["target_rows"].append(observation)
            elif _normalize_target(observation["target"]) != norm_target:
                entry["other_rows"].append(observation)

        for fingerprint, payload in grouped_tls.items():
            if not payload["target_rows"] or not payload["other_rows"]:
                continue
            current_shared = _dedup_targets(",".join(
                row["target"]
                for row in payload["other_rows"]
                if latest_norms.get(_normalize_target(row["target"])) == row["search_id"]
            ))
            historical_shared = [item for item in _dedup_targets(",".join(row["target"] for row in payload["other_rows"])) if item not in current_shared]
            target_observed = [_safe_iso(row.get("observed_at")) for row in payload["target_rows"]]
            target_observed = [value for value in target_observed if value]
            other_observed = [_safe_iso(row.get("observed_at")) for row in payload["other_rows"]]
            other_observed = [value for value in other_observed if value]
            target_first = min(target_observed) if target_observed else None
            target_last = max(target_observed) if target_observed else None
            other_first = min(other_observed) if other_observed else None
            other_last = max(other_observed) if other_observed else None
            overlap_start_candidates = [value for value in [target_first, other_first, payload["not_before"]] if value]
            overlap_start = max(overlap_start_candidates) if overlap_start_candidates else None
            overlap_end_candidates = [value for value in [target_last, other_last, payload["not_after"]] if value]
            overlap_end = min(overlap_end_candidates) if overlap_end_candidates else None
            first_observed_candidates = [value for value in [target_first, other_first] if value]
            last_observed_candidates = [value for value in [target_last, other_last] if value]
            tls_history.append(
                {
                    "sha256": fingerprint,
                    "cn": payload["cn"],
                    "issuer_cn": payload["issuer"],
                    "current_shared_with": current_shared,
                    "historical_shared_with": historical_shared,
                    "shared_with": current_shared + [item for item in historical_shared if item not in current_shared],
                    "relationship_status": "current" if current_shared else "historical",
                    "first_observed": min(first_observed_candidates) if first_observed_candidates else None,
                    "last_observed": max(last_observed_candidates) if last_observed_candidates else None,
                    "overlap_start": overlap_start,
                    "overlap_end": overlap_end,
                    "not_before": payload["not_before"],
                    "not_after": payload["not_after"],
                }
            )

        favicons = []
        for row in c.execute("SELECT md5 FROM favicons WHERE search_id = ?", (current_sid,)).fetchall():
            favicons.append({"md5": row["md5"], "shared_with": _others_by("favicons", "md5", row["md5"])})

        emails = []
        for row in c.execute("SELECT email FROM registrant_emails WHERE search_id = ?", (current_sid,)).fetchall():
            email = row["email"]
            if email in _GENERIC_EMAILS:
                continue
            emails.append({"email": email, "shared_with": _others_by("registrant_emails", "email", email)})

        nameservers = []
        for row in c.execute("SELECT nameserver FROM nameservers WHERE search_id = ?", (current_sid,)).fetchall():
            nameservers.append({"nameserver": row["nameserver"], "shared_with": _others_by("nameservers", "nameserver", row["nameserver"])})

        social = [dict(row) for row in c.execute("SELECT platform, handle, url FROM social_accounts WHERE search_id = ?", (current_sid,)).fetchall()]
        history = [
            {
                "id": row["id"],
                "target": row["target"],
                "type": row["type"],
                "timestamp": row["timestamp"],
                "cloudflare_fronted": row["cloudflare_fronted"],
                "is_latest": row["id"] == current_sid,
            }
            for row in history_rows
        ]

        return {
            "target": current_row["target"],
            "sid": current_sid,
            "type": current_row["type"],
            "timestamp": current_row["timestamp"],
            "cloudflare_fronted": current_row["cloudflare_fronted"],
            "whois": dict(whois) if whois else {},
            "history": history,
            "connections": {
                "tracking_ids": tracking,
                "ips": ips,
                "asns": asns,
                "tls_certs": tls,
                "tls_history": sorted(tls_history, key=lambda item: (item["relationship_status"] != "current", item["sha256"])),
                "provider_hits": provider_hits,
                "favicons": favicons,
                "registrant_emails": emails,
                "nameservers": nameservers,
            },
            "social": social,
        }
