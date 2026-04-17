#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

COMMON_SECOND_LEVEL_SUFFIXES = {"ac", "co", "com", "edu", "gov", "net", "org"}
PROVIDER_SUFFIXES = {
    "amazonaws.com",
    "azurewebsites.net",
    "bluehost.com",
    "cloudflare.com",
    "cloudflare.net",
    "digitaloceanspaces.com",
    "fastly.net",
    "github.io",
    "gitlab.io",
    "google.com",
    "googleapis.com",
    "googlehosted.com",
    "googleusercontent.com",
    "mail.protection.outlook.com",
    "o2switch.net",
    "outlook.com",
    "ovh.net",
    "pantheonsite.io",
    "shopify.com",
    "squarespace.com",
    "webflow.io",
    "weebly.com",
    "wix.com",
    "wixsite.com",
    "wordpress.com",
    "wpengine.com",
}
TABLE_INSERT_ORDER = [
    "ips",
    "tls_certs",
    "ct_certs",
    "subdomains",
    "dns_records",
    "historical_dns",
    "tracking_ids",
    "social_accounts",
    "favicons",
    "whois_data",
    "registrant_emails",
    "nameservers",
    "spf_origins",
    "cross_sans",
    "scan_hits",
    "page_metadata",
    "provider_hits",
]
SUMMARY_LIMITS = {
    "subdomains": 100,
    "ips": 80,
    "tls": 40,
    "tracking_ids": 80,
    "social_accounts": 80,
    "certs": 30,
    "cross_sans": 80,
}


@dataclass
class SearchInference:
    target: str
    search_type: str
    cloudflare_fronted: int | None
    timestamp: str
    reasons: list[str] = field(default_factory=list)


def normalize_host(value: Any) -> str:
    text = str(value or "").strip().lower().strip(".")
    if not text:
        return ""
    if text.startswith("*."):
        text = text[2:]
    try:
        ipaddress.ip_address(text)
        return text
    except ValueError:
        pass
    if any(ch.isspace() for ch in text):
        return ""
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    if any(ch not in allowed for ch in text):
        return ""
    return text


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def registrable_domain(value: Any) -> str:
    host = normalize_host(value)
    if not host:
        return ""
    if is_ip_address(host):
        return host
    parts = host.split(".")
    if len(parts) < 2:
        return host
    if len(parts[-1]) == 2 and len(parts) >= 3 and parts[-2] in COMMON_SECOND_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def looks_like_provider_domain(domain: str) -> bool:
    if not domain or is_ip_address(domain):
        return False
    return any(domain == suffix or domain.endswith(f".{suffix}") for suffix in PROVIDER_SUFFIXES)


def parse_json_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    text = str(value).strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except Exception:
        return []
    return parsed if isinstance(parsed, list) else []


def iter_rowids(conn: sqlite3.Connection, table: str, columns: list[str], max_rowid: int):
    sql = f"SELECT {', '.join(columns)} FROM {table} WHERE rowid = ?"
    cursor = conn.cursor()
    for rowid in range(1, max_rowid + 1):
        try:
            cursor.execute(sql, (rowid,))
            row = cursor.fetchone()
        except sqlite3.DatabaseError:
            continue
        if row is not None:
            yield row


def load_sequences(conn: sqlite3.Connection) -> dict[str, int]:
    cursor = conn.cursor()
    cursor.execute("SELECT name, seq FROM sqlite_sequence")
    return {str(name): int(seq) for name, seq in cursor.fetchall()}


def source_connection(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def destination_connection(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def build_inference(source_db: Path) -> tuple[dict[int, SearchInference], dict[str, Any]]:
    conn = source_connection(source_db)
    try:
        sequences = load_sequences(conn)
        max_search_id = sequences.get("searches", 0)
        base_time = datetime.fromtimestamp(source_db.stat().st_mtime, tz=timezone.utc)

        subdomain_candidates: dict[int, Counter[str]] = defaultdict(Counter)
        ct_candidates: dict[int, Counter[str]] = defaultdict(Counter)
        tls_candidates: dict[int, Counter[str]] = defaultdict(Counter)
        ip_candidates: dict[int, Counter[str]] = defaultdict(Counter)
        cloudflare_fronted: dict[int, bool] = defaultdict(bool)
        observed_at_values: dict[int, list[str]] = defaultdict(list)

        for row in iter_rowids(conn, "subdomains", ["search_id", "subdomain"], sequences.get("subdomains", 0)):
            sid = int(row["search_id"])
            domain = registrable_domain(row["subdomain"])
            if domain and not is_ip_address(domain):
                subdomain_candidates[sid][domain] += 4

        for row in iter_rowids(conn, "ct_certs", ["search_id", "sans", "observed_at"], sequences.get("ct_certs", 0)):
            sid = int(row["search_id"])
            for san in parse_json_list(row["sans"]):
                domain = registrable_domain(san)
                if domain and not is_ip_address(domain):
                    ct_candidates[sid][domain] += 1
            if row["observed_at"]:
                observed_at_values[sid].append(str(row["observed_at"]))

        for row in iter_rowids(conn, "tls_certs", ["search_id", "cn", "sans", "observed_at"], sequences.get("tls_certs", 0)):
            sid = int(row["search_id"])
            domain = registrable_domain(row["cn"])
            if domain and not is_ip_address(domain):
                tls_candidates[sid][domain] += 2
            for san in parse_json_list(row["sans"]):
                domain = registrable_domain(san)
                if domain and not is_ip_address(domain):
                    tls_candidates[sid][domain] += 1
            if row["observed_at"]:
                observed_at_values[sid].append(str(row["observed_at"]))

        for row in iter_rowids(conn, "ips", ["search_id", "ip", "cloudflare", "observed_at"], sequences.get("ips", 0)):
            sid = int(row["search_id"])
            ip = normalize_host(row["ip"])
            if ip and is_ip_address(ip):
                ip_candidates[sid][ip] += 1
            if row["cloudflare"]:
                cloudflare_fronted[sid] = True
            if row["observed_at"]:
                observed_at_values[sid].append(str(row["observed_at"]))

        recovered: dict[int, SearchInference] = {}
        skipped_provider_only = 0
        skipped_no_target = 0

        for sid in range(1, max_search_id + 1):
            reasons: list[str] = []
            target = ""

            if subdomain_candidates[sid]:
                target = subdomain_candidates[sid].most_common(1)[0][0]
                reasons.append("subdomains")

            if not target and ct_candidates[sid]:
                viable = [(domain, score) for domain, score in ct_candidates[sid].most_common() if not looks_like_provider_domain(domain)]
                if viable:
                    target = viable[0][0]
                    reasons.append("ct_certs")

            if not target and tls_candidates[sid]:
                viable = [(domain, score) for domain, score in tls_candidates[sid].most_common() if not looks_like_provider_domain(domain)]
                if viable and viable[0][1] >= 2:
                    target = viable[0][0]
                    reasons.append("tls_certs")
                elif any(score > 0 for _, score in tls_candidates[sid].most_common()):
                    skipped_provider_only += 1

            if not target and ip_candidates[sid]:
                target = ip_candidates[sid].most_common(1)[0][0]
                reasons.append("ips")

            if not target:
                skipped_no_target += 1
                continue

            observed = sorted(value for value in observed_at_values.get(sid, []) if value)
            if observed:
                timestamp = observed[-1]
            else:
                timestamp = (base_time - timedelta(seconds=max_search_id - sid)).isoformat()

            recovered[sid] = SearchInference(
                target=target,
                search_type="ip" if is_ip_address(target) else "domain",
                cloudflare_fronted=1 if cloudflare_fronted.get(sid) else 0,
                timestamp=timestamp,
                reasons=reasons,
            )

        stats = {
            "max_search_id": max_search_id,
            "recovered_searches": len(recovered),
            "skipped_provider_only": skipped_provider_only,
            "skipped_no_target": skipped_no_target,
            "sequences": sequences,
        }
        return recovered, stats
    finally:
        conn.close()


def empty_result(search: SearchInference) -> dict[str, Any]:
    return {
        "input": search.target,
        "type": search.search_type,
        "timestamp": search.timestamp,
        "cloudflare_fronted": search.cloudflare_fronted,
        "salvaged": True,
        "source_errors": ["salvaged-from-corrupt-db"],
        "dns_records": {},
        "subdomains": [],
        "ip_details": [],
        "non_cf_tls_certs": [],
        "cert_transparency": {"subdomains": [], "total_certs": 0, "issuers": [], "cross_domain_sans": [], "certs": []},
        "page_metadata": {"social_handles": {}, "social_links": {}},
        "whois": {},
    }


def update_summary(summary: dict[str, Any], table: str, row: sqlite3.Row):
    if table == "subdomains":
        values = summary["subdomains"]
        if len(values) < SUMMARY_LIMITS["subdomains"]:
            sub = str(row["subdomain"])
            if sub not in values:
                values.append(sub)
        return

    if table == "dns_records":
        records = summary["dns_records"].setdefault(str(row["rtype"]), [])
        if len(records) < 50:
            records.append(row["value"])
        return

    if table == "ips":
        ips = summary["ip_details"]
        if len(ips) < SUMMARY_LIMITS["ips"]:
            ips.append(
                {
                    "ip": row["ip"],
                    "source": row["source"],
                    "cloudflare": row["cloudflare"],
                    "ptr": row["ptr"],
                    "asn": row["asn"],
                    "asn_desc": row["asn_desc"],
                    "asn_registry": row["asn_registry"],
                    "country": row["country"],
                    "network_name": row["network_name"],
                    "network_cidr": row["network_cidr"],
                    "proxy_family": row["proxy_family"],
                    "proxy_confidence": row["proxy_confidence"],
                    "observed_at": row["observed_at"],
                    "port": row["port"],
                }
            )
        return

    if table == "tls_certs":
        tls = summary["non_cf_tls_certs"]
        if len(tls) < SUMMARY_LIMITS["tls"]:
            tls.append(
                {
                    "ip": row["ip"],
                    "port": row["port"],
                    "sni_used": row["sni_used"],
                    "cn": row["cn"],
                    "sans": parse_json_list(row["sans"]),
                    "issuer_cn": row["issuer_cn"],
                    "issuer_org": row["issuer_org"],
                    "not_before": row["not_before"],
                    "not_after": row["not_after"],
                    "sha256": row["sha256"],
                }
            )
        return

    if table == "ct_certs":
        cert_transparency = summary["cert_transparency"]
        cert_transparency["total_certs"] = int(cert_transparency.get("total_certs", 0)) + 1
        issuers = cert_transparency.setdefault("issuers", [])
        issuer = row["issuer"]
        if issuer and issuer not in issuers and len(issuers) < SUMMARY_LIMITS["certs"]:
            issuers.append(issuer)
        certs = cert_transparency.setdefault("certs", [])
        if len(certs) < SUMMARY_LIMITS["certs"]:
            certs.append(
                {
                    "cert_id": row["cert_id"],
                    "issuer": row["issuer"],
                    "not_before": row["not_before"],
                    "not_after": row["not_after"],
                    "sans": parse_json_list(row["sans"]),
                }
            )
        return

    if table == "cross_sans":
        cert_transparency = summary["cert_transparency"]
        values = cert_transparency.setdefault("cross_domain_sans", [])
        san = str(row["san"])
        if san not in values and len(values) < SUMMARY_LIMITS["cross_sans"]:
            values.append(san)
        return

    if table == "whois_data":
        summary["whois"] = {
            "registrar": row["registrar"],
            "creation_date": row["creation_date"],
            "expiry_date": row["expiry_date"],
            "org": row["org"],
            "country": row["country"],
            "emails": parse_json_list(row["emails"]),
            "nameservers": parse_json_list(row["nameservers"]),
        }
        return

    if table == "tracking_ids":
        ids = summary["page_metadata"].setdefault("tracking_ids", [])
        if len(ids) < SUMMARY_LIMITS["tracking_ids"]:
            ids.append({"id_type": row["id_type"], "id_value": row["id_value"]})
        return

    if table == "social_accounts":
        handles = summary["page_metadata"].setdefault("social_handles", {})
        links = summary["page_metadata"].setdefault("social_links", {})
        platform = str(row["platform"])
        handle = str(row["handle"])
        handles.setdefault(platform, [])
        if handle not in handles[platform] and len(handles[platform]) < SUMMARY_LIMITS["social_accounts"]:
            handles[platform].append(handle)
        if row["url"]:
            links.setdefault(platform, [])
            if row["url"] not in links[platform] and len(links[platform]) < SUMMARY_LIMITS["social_accounts"]:
                links[platform].append(row["url"])
        return

    if table == "page_metadata":
        page_metadata = summary["page_metadata"]
        page_metadata["html_lang"] = row["html_lang"]
        page_metadata["cms_generator"] = row["cms_generator"]
        page_metadata["favicon_md5"] = row["favicon_md5"]
        summary.setdefault("email_security", {})["dmarc"] = row["dmarc"]
        return

    if table == "favicons":
        if row["md5"]:
            summary["page_metadata"]["favicon_md5"] = row["md5"]


def create_destination(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        backup = path.with_suffix(path.suffix + f".bak-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
        shutil.move(path, backup)
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if sidecar.exists():
            sidecar.unlink()
    os.environ["IP_INTEL_DB_PATH"] = str(path)
    import intel_db  # imported lazily so the env var takes effect

    intel_db.init_db()


def insert_searches(dest: sqlite3.Connection, recovered: dict[int, SearchInference], summaries: dict[int, dict[str, Any]]):
    cursor = dest.cursor()
    for sid, search in recovered.items():
        summary = summaries.setdefault(sid, empty_result(search))
        summary["input"] = search.target
        summary["type"] = search.search_type
        summary["timestamp"] = search.timestamp
        summary["cloudflare_fronted"] = search.cloudflare_fronted
        summary["salvage_reasons"] = search.reasons
        cursor.execute(
            """INSERT INTO searches (id, target, type, timestamp, cloudflare_fronted, raw_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (sid, search.target, search.search_type, search.timestamp, search.cloudflare_fronted, json.dumps(summary, ensure_ascii=True)),
        )
    dest.commit()


def salvage_rows(source_db: Path, dest_db: Path, recovered: dict[int, SearchInference], stats: dict[str, Any]) -> dict[str, int]:
    src = source_connection(source_db)
    dest = destination_connection(dest_db)
    dest.execute("PRAGMA foreign_keys=ON")
    sequences = stats["sequences"]
    inserted_counts: dict[str, int] = {}
    summaries = {sid: empty_result(search) for sid, search in recovered.items()}

    try:
        insert_searches(dest, recovered, summaries)
        for table in TABLE_INSERT_ORDER:
            cursor = src.cursor()
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [str(row["name"]) for row in cursor.fetchall()]
            if not columns:
                continue
            placeholders = ", ".join("?" for _ in columns)
            insert_sql = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"
            table_count = 0

            for row in iter_rowids(src, table, columns, sequences.get(table, 0)):
                sid = int(row["search_id"]) if "search_id" in row.keys() else None
                if sid is None or sid not in recovered:
                    continue
                values = [row[column] for column in columns]
                try:
                    dest.execute(insert_sql, values)
                except sqlite3.IntegrityError:
                    continue
                table_count += 1
                update_summary(summaries[sid], table, row)

            inserted_counts[table] = table_count
            dest.commit()

        update_cursor = dest.cursor()
        for sid, search in recovered.items():
            summary = summaries[sid]
            summary["input"] = search.target
            summary["type"] = search.search_type
            summary["timestamp"] = search.timestamp
            summary["cloudflare_fronted"] = search.cloudflare_fronted
            summary["salvage_reasons"] = search.reasons
            summary["salvaged"] = True
            update_cursor.execute(
                "UPDATE searches SET raw_json = ? WHERE id = ?",
                (json.dumps(summary, ensure_ascii=True), sid),
            )
        dest.commit()
        return inserted_counts
    finally:
        src.close()
        dest.close()


def verify_database(path: Path) -> dict[str, Any]:
    conn = destination_connection(path)
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA quick_check")
        quick_check = cursor.fetchone()[0]
        cursor.execute("SELECT count(*) FROM searches")
        searches = cursor.fetchone()[0]
        cursor.execute("SELECT count(*) FROM ips")
        ips = cursor.fetchone()[0]
        cursor.execute("SELECT count(*) FROM tls_certs")
        tls = cursor.fetchone()[0]
        return {
            "quick_check": quick_check,
            "searches": searches,
            "ips": ips,
            "tls_certs": tls,
        }
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Best-effort salvage for a corrupted IP Intel SQLite database.")
    parser.add_argument("--source", default="backups/ip_intel.corrupt-20260417-143846.db", help="Path to the corrupted source database.")
    parser.add_argument("--dest", default="data/ip_intel.db", help="Path for the recovered destination database.")
    args = parser.parse_args()

    source_db = Path(args.source).resolve()
    dest_db = Path(args.dest).resolve()
    if not source_db.exists():
        raise SystemExit(f"Source database not found: {source_db}")

    recovered, stats = build_inference(source_db)
    print(f"Recovered search ids with inferred target: {stats['recovered_searches']} / {stats['max_search_id']}")
    print(f"Skipped provider-only candidates: {stats['skipped_provider_only']}")
    print(f"Skipped without target inference: {stats['skipped_no_target']}")

    create_destination(dest_db)
    inserted = salvage_rows(source_db, dest_db, recovered, stats)
    verification = verify_database(dest_db)

    print("Inserted rows:")
    for table in TABLE_INSERT_ORDER:
        print(f"  {table}: {inserted.get(table, 0)}")
    print("Verification:")
    for key, value in verification.items():
        print(f"  {key}: {value}")
    print(f"Recovered database written to: {dest_db}")


if __name__ == "__main__":
    main()
