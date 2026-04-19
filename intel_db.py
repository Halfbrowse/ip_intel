"""
db.py — SQLite persistence for ip-intel.

Schema design: one row per search in `searches` (with full raw_json),
plus normalised pivot tables for every data point so you can cross-reference
across targets — e.g. "what other domains share this GA ID / IP / TLS cert /
favicon hash / registrar email?"
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent / "ip_intel.db"


# ── Connection ────────────────────────────────────────────────────────────────

def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(str(DB_PATH))
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")   # safe for concurrent Streamlit threads
    c.execute("PRAGMA foreign_keys=ON")
    return c


# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS searches (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    target              TEXT    NOT NULL,
    type                TEXT    NOT NULL,        -- 'domain' | 'ip'
    timestamp           TEXT    NOT NULL,
    cloudflare_fronted  INTEGER,                 -- 1/0/NULL
    raw_json            TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_searches_target ON searches(target);
CREATE INDEX IF NOT EXISTS idx_searches_ts     ON searches(timestamp DESC);

-- Every IP encountered from any source
CREATE TABLE IF NOT EXISTS ips (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    ip          TEXT    NOT NULL,
    source      TEXT,           -- dns / subdomain_probe / mx_record / wordlist_probe / hackertarget / urlscan / scan / historical_dns / spf / direct
    cloudflare  INTEGER,        -- 1/0
    ptr         TEXT,
    asn         TEXT,
    asn_desc    TEXT,
    country     TEXT,
    port        INTEGER
);
CREATE INDEX IF NOT EXISTS idx_ips_ip        ON ips(ip);
CREATE INDEX IF NOT EXISTS idx_ips_search_id ON ips(search_id);

-- TLS certificates grabbed live from non-CF IPs
CREATE TABLE IF NOT EXISTS tls_certs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    ip          TEXT    NOT NULL,
    port        INTEGER NOT NULL,
    sni_used    TEXT,
    cn          TEXT,
    sans        TEXT,           -- JSON array
    issuer_cn   TEXT,
    issuer_org  TEXT,
    not_before  TEXT,
    not_after   TEXT,
    sha256      TEXT            -- fingerprint of DER bytes
);
CREATE INDEX IF NOT EXISTS idx_tls_search_id ON tls_certs(search_id);
CREATE INDEX IF NOT EXISTS idx_tls_sha256    ON tls_certs(sha256);
CREATE INDEX IF NOT EXISTS idx_tls_cn        ON tls_certs(cn);
CREATE INDEX IF NOT EXISTS idx_tls_ip        ON tls_certs(ip);

-- Certificate transparency (crt.sh) records
CREATE TABLE IF NOT EXISTS ct_certs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    cert_id     INTEGER,        -- crt.sh cert id
    issuer      TEXT,
    not_before  TEXT,
    not_after   TEXT,
    sans        TEXT            -- JSON array
);
CREATE INDEX IF NOT EXISTS idx_ct_search_id ON ct_certs(search_id);
CREATE INDEX IF NOT EXISTS idx_ct_issuer    ON ct_certs(issuer);

-- Subdomains (crt.sh + zone transfer)
CREATE TABLE IF NOT EXISTS subdomains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    subdomain   TEXT    NOT NULL,
    source      TEXT            -- 'crt.sh' | 'zone_transfer'
);
CREATE INDEX IF NOT EXISTS idx_sub_search_id ON subdomains(search_id);
CREATE INDEX IF NOT EXISTS idx_sub_subdomain ON subdomains(subdomain);

-- DNS records (live)
CREATE TABLE IF NOT EXISTS dns_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    rtype       TEXT    NOT NULL,
    value       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dns_search_id ON dns_records(search_id);
CREATE INDEX IF NOT EXISTS idx_dns_value     ON dns_records(value);

-- Historical / passive DNS (CIRCL pDNS)
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

-- Tracking / analytics IDs (GA, GTM, FB Pixel, TikTok Pixel, Yandex Metrika)
CREATE TABLE IF NOT EXISTS tracking_ids (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    id_type     TEXT    NOT NULL,   -- 'ga' | 'gtm' | 'fb_pixel' | 'tiktok_pixel' | 'yandex_metrika'
    id_value    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_track_search_id ON tracking_ids(search_id);
CREATE INDEX IF NOT EXISTS idx_track_value     ON tracking_ids(id_type, id_value);

-- Social media accounts
CREATE TABLE IF NOT EXISTS social_accounts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    platform    TEXT    NOT NULL,
    handle      TEXT    NOT NULL,
    url         TEXT
);
CREATE INDEX IF NOT EXISTS idx_social_search_id ON social_accounts(search_id);
CREATE INDEX IF NOT EXISTS idx_social_handle    ON social_accounts(platform, handle);

-- Favicon MD5 hashes
CREATE TABLE IF NOT EXISTS favicons (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    md5         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fav_search_id ON favicons(search_id);
CREATE INDEX IF NOT EXISTS idx_fav_md5       ON favicons(md5);

-- WHOIS / registration data
CREATE TABLE IF NOT EXISTS whois_data (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id       INTEGER NOT NULL REFERENCES searches(id),
    registrar       TEXT,
    creation_date   TEXT,
    expiry_date     TEXT,
    org             TEXT,
    country         TEXT,
    emails          TEXT,   -- JSON array
    nameservers     TEXT    -- JSON array
);
CREATE INDEX IF NOT EXISTS idx_whois_search_id ON whois_data(search_id);
CREATE INDEX IF NOT EXISTS idx_whois_registrar ON whois_data(registrar);

-- Registrant / WHOIS emails (also indexed standalone for cross-referencing)
CREATE TABLE IF NOT EXISTS registrant_emails (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    email       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_email_search_id ON registrant_emails(search_id);
CREATE INDEX IF NOT EXISTS idx_email_value     ON registrant_emails(email);

-- Nameservers
CREATE TABLE IF NOT EXISTS nameservers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    nameserver  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ns_search_id ON nameservers(search_id);
CREATE INDEX IF NOT EXISTS idx_ns_value     ON nameservers(nameserver);

-- SPF ip4/ip6 directives
CREATE TABLE IF NOT EXISTS spf_origins (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    ip          TEXT    NOT NULL,
    cidr        TEXT
);
CREATE INDEX IF NOT EXISTS idx_spf_search_id ON spf_origins(search_id);
CREATE INDEX IF NOT EXISTS idx_spf_ip        ON spf_origins(ip);

-- Cross-domain SANs from crt.sh
CREATE TABLE IF NOT EXISTS cross_sans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    san         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_csan_search_id ON cross_sans(search_id);
CREATE INDEX IF NOT EXISTS idx_csan_san       ON cross_sans(san);

-- Scan hits (GCP / provider / country two-phase TLS scan)
CREATE TABLE IF NOT EXISTS scan_hits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id   INTEGER NOT NULL REFERENCES searches(id),
    scan_type   TEXT    NOT NULL,   -- 'gcp' | 'asn' | 'country'
    ip          TEXT    NOT NULL,
    port        INTEGER,
    cn          TEXT,
    sans        TEXT,               -- JSON array
    issuer      TEXT,
    not_before  TEXT,
    not_after   TEXT,
    cloudflare  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_scan_search_id ON scan_hits(search_id);
CREATE INDEX IF NOT EXISTS idx_scan_ip        ON scan_hits(ip);
CREATE INDEX IF NOT EXISTS idx_scan_cn        ON scan_hits(cn);

-- Page metadata (CMS, language)
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


def init_db() -> None:
    with _conn() as c:
        for stmt in _SCHEMA.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                c.execute(stmt)


# ── Child tables — all pivot tables that belong to a search_id ────────────────
_CHILD_TABLES = [
    "ips", "tls_certs", "ct_certs", "subdomains", "dns_records",
    "historical_dns", "tracking_ids", "social_accounts", "favicons",
    "whois_data", "registrant_emails", "nameservers", "spf_origins",
    "cross_sans", "scan_hits", "page_metadata",
]


# ── Save ─────────────────────────────────────────────────────────────────────

def save_search(result: dict) -> int:
    """
    Upsert a completed analysis result.

    If this target has been searched before, the existing row is updated and
    all child pivot-table rows are replaced with the latest data.
    If it's a new target, a fresh row is inserted.
    Returns the searches.id.
    """
    init_db()

    target    = result.get("input", "")
    typ       = result.get("type", "unknown")
    timestamp = result.get("timestamp", datetime.now(timezone.utc).isoformat())
    cf        = result.get("cloudflare_fronted")
    cf_val    = 1 if cf else (0 if cf is not None else None)

    with _conn() as c:
        existing = c.execute(
            "SELECT id FROM searches WHERE target = ?", (target,)
        ).fetchone()

        if existing:
            sid = existing["id"]
            # Update the main row
            c.execute(
                "UPDATE searches SET type=?, timestamp=?, cloudflare_fronted=?, raw_json=? WHERE id=?",
                (typ, timestamp, cf_val, json.dumps(result, default=str), sid),
            )
            # Wipe all child rows so we re-insert fresh data below
            for table in _CHILD_TABLES:
                c.execute(f"DELETE FROM {table} WHERE search_id = ?", (sid,))
        else:
            cur = c.execute(
                "INSERT INTO searches (target, type, timestamp, cloudflare_fronted, raw_json) VALUES (?,?,?,?,?)",
                (target, typ, timestamp, cf_val, json.dumps(result, default=str)),
            )
            sid = cur.lastrowid

        # ── IPs ───────────────────────────────────────────────────────────────
        ip_details = result.get("ip_details", {})

        def _insert_ip(ip, source, cf_flag=None, port=None):
            info  = ip_details.get(ip, {})
            asn   = info.get("asn_info", {})
            c.execute(
                "INSERT INTO ips (search_id,ip,source,cloudflare,ptr,asn,asn_desc,country,port) VALUES (?,?,?,?,?,?,?,?,?)",
                (sid, ip, source,
                 1 if cf_flag else (0 if cf_flag is not None else None),
                 info.get("ptr"),
                 asn.get("asn"), asn.get("asn_description"), asn.get("asn_country"),
                 port),
            )

        # DNS A/AAAA records
        dns = result.get("dns", {})
        for rtype in ("A", "AAAA"):
            for ip in (dns.get(rtype) or []):
                if isinstance(ip, str):
                    _insert_ip(ip, "dns")

        # Origin candidates
        oc = result.get("origin_candidates", {})
        for entry in oc.get("subdomain_leaks", []):
            if entry.get("ip"):
                _insert_ip(entry["ip"], "subdomain_probe")
        for entry in oc.get("mx_leaks", []):
            if entry.get("ip"):
                _insert_ip(entry["ip"], "mx_record")
        for entry in oc.get("wordlist_leaks", []):
            if entry.get("ip"):
                _insert_ip(entry["ip"], "wordlist_probe")
        for entry in oc.get("hackertarget", []):
            if entry.get("ip"):
                _insert_ip(entry["ip"], "hackertarget", cf_flag=entry.get("cf"))
        for entry in oc.get("urlscan", []):
            if entry.get("ip"):
                _insert_ip(entry["ip"], "urlscan", cf_flag=entry.get("cf"))

        # SPF origins
        for entry in result.get("spf_origins", []):
            if entry.get("ip"):
                _insert_ip(entry["ip"], "spf")

        # IP-type target
        if typ == "ip":
            cf_flag = result.get("cloudflare", False)
            info = {
                "ptr":     result.get("ptr"),
                "asn_info": result.get("asn_info", {}),
            }
            asn = result.get("asn_info", {})
            c.execute(
                "INSERT INTO ips (search_id,ip,source,cloudflare,ptr,asn,asn_desc,country,port) VALUES (?,?,?,?,?,?,?,?,?)",
                (sid, target, "direct",
                 1 if cf_flag else 0,
                 result.get("ptr"),
                 asn.get("asn"), asn.get("asn_description"), asn.get("asn_country"),
                 None),
            )

        # ── TLS certs (live-grabbed from non-CF IPs) ──────────────────────────
        tls_list = result.get("non_cf_tls_certs") or (
            [result["tls_cert"]] if result.get("tls_cert") else []
        )
        for cert in tls_list:
            if not cert:
                continue
            c.execute(
                """INSERT INTO tls_certs
                   (search_id,ip,port,sni_used,cn,sans,issuer_cn,issuer_org,not_before,not_after,sha256)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (sid, cert.get("ip"), cert.get("port", 443), cert.get("sni_used"),
                 cert.get("cn"), json.dumps(cert.get("sans", [])),
                 cert.get("issuer_cn"), cert.get("issuer_org"),
                 cert.get("not_before"), cert.get("not_after"), cert.get("sha256")),
            )

        # ── Scan hits ─────────────────────────────────────────────────────────
        for scan_key, scan_label in [
            ("scan",          "gcp"),
            ("provider_scan", "asn"),
            ("country_scan",  "country"),
        ]:
            sr = oc.get(scan_key, {})
            if not isinstance(sr, dict) or sr.get("skipped"):
                continue
            for h in sr.get("hits", []):
                if not h.get("ip"):
                    continue
                c.execute(
                    """INSERT INTO scan_hits
                       (search_id,scan_type,ip,port,cn,sans,issuer,not_before,not_after,cloudflare)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (sid, scan_label, h["ip"], h.get("port", 443),
                     h.get("cn"), json.dumps(h.get("sans", [])),
                     h.get("issuer"), h.get("not_before"), h.get("not_after"),
                     1 if h.get("cloudflare") else 0),
                )

        # ── CT / crt.sh certs ─────────────────────────────────────────────────
        ct = result.get("cert_transparency", {})
        for cert in ct.get("certs", []):
            c.execute(
                "INSERT INTO ct_certs (search_id,cert_id,issuer,not_before,not_after,sans) VALUES (?,?,?,?,?,?)",
                (sid, cert.get("id"), cert.get("issuer"),
                 cert.get("not_before"), cert.get("not_after"),
                 json.dumps(cert.get("sans", []))),
            )

        # Cross-domain SANs
        for san in ct.get("cross_domain_sans", []):
            c.execute("INSERT INTO cross_sans (search_id,san) VALUES (?,?)", (sid, san))

        # ── Subdomains ────────────────────────────────────────────────────────
        for sub in result.get("subdomains", []):
            c.execute("INSERT INTO subdomains (search_id,subdomain,source) VALUES (?,?,?)", (sid, sub, "crt.sh"))
        for sub in result.get("zone_transfer", []):
            c.execute("INSERT INTO subdomains (search_id,subdomain,source) VALUES (?,?,?)", (sid, sub, "zone_transfer"))

        # ── DNS records ───────────────────────────────────────────────────────
        for rtype, values in dns.items():
            if not values:
                continue
            if isinstance(values, list):
                for v in values:
                    c.execute("INSERT INTO dns_records (search_id,rtype,value) VALUES (?,?,?)",
                              (sid, rtype, json.dumps(v) if isinstance(v, dict) else str(v)))
            elif isinstance(values, dict):
                c.execute("INSERT INTO dns_records (search_id,rtype,value) VALUES (?,?,?)",
                          (sid, rtype, json.dumps(values)))

        # ── Historical / passive DNS ──────────────────────────────────────────
        for rec in result.get("historical_dns", {}).get("records", []):
            c.execute(
                "INSERT INTO historical_dns (search_id,rrtype,rdata,first_seen,last_seen) VALUES (?,?,?,?,?)",
                (sid, rec.get("rrtype"), rec.get("rdata"),
                 rec.get("first_seen"), rec.get("last_seen")),
            )

        # ── SPF origins ───────────────────────────────────────────────────────
        for entry in result.get("spf_origins", []):
            c.execute("INSERT INTO spf_origins (search_id,ip,cidr) VALUES (?,?,?)",
                      (sid, entry.get("ip"), entry.get("cidr")))

        # ── WHOIS ─────────────────────────────────────────────────────────────
        w = result.get("whois", {})
        if w and not w.get("error"):
            emails_raw = w.get("emails") or []
            if isinstance(emails_raw, str):
                emails_raw = [emails_raw]
            ns_raw = w.get("nameservers") or []
            if isinstance(ns_raw, str):
                ns_raw = [ns_raw]

            c.execute(
                """INSERT INTO whois_data
                   (search_id,registrar,creation_date,expiry_date,org,country,emails,nameservers)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (sid,
                 str(w.get("registrar") or ""),
                 str(w.get("creation_date") or "")[:30],
                 str(w.get("expiry_date") or "")[:30],
                 str(w.get("org") or ""),
                 str(w.get("country") or ""),
                 json.dumps(emails_raw, default=str),
                 json.dumps(ns_raw, default=str)),
            )

            for email in emails_raw:
                if email and isinstance(email, str):
                    c.execute("INSERT INTO registrant_emails (search_id,email) VALUES (?,?)",
                              (sid, email.lower().strip()))

            for ns in ns_raw:
                if ns and isinstance(ns, str):
                    c.execute("INSERT INTO nameservers (search_id,nameserver) VALUES (?,?)",
                              (sid, ns.lower().strip()))

        # ── Tracking IDs ──────────────────────────────────────────────────────
        meta = result.get("page_metadata", {})
        for id_type, key in [
            ("ga",              "google_analytics"),
            ("gtm",             "gtm_ids"),
            ("fb_pixel",        "facebook_pixel"),
            ("tiktok_pixel",    "tiktok_pixel"),
            ("yandex_metrika",  "yandex_metrika"),
        ]:
            for val in (meta.get(key) or []):
                c.execute("INSERT INTO tracking_ids (search_id,id_type,id_value) VALUES (?,?,?)",
                          (sid, id_type, str(val)))

        # ── Social media handles ──────────────────────────────────────────────
        handles = meta.get("social_handles", {})
        links   = meta.get("social_links", {})
        all_plats = set(handles) | set(links)
        for plat in all_plats:
            for handle in (handles.get(plat) or []):
                url_list = links.get(plat, [])
                url = url_list[0] if url_list else None
                c.execute("INSERT INTO social_accounts (search_id,platform,handle,url) VALUES (?,?,?,?)",
                          (sid, plat, handle, url))

        # ── Favicon ───────────────────────────────────────────────────────────
        fav_md5 = meta.get("favicon_md5")
        if fav_md5:
            c.execute("INSERT INTO favicons (search_id,md5) VALUES (?,?)", (sid, fav_md5))

        # ── Page metadata ─────────────────────────────────────────────────────
        email_sec = result.get("email_security", {})
        c.execute(
            "INSERT INTO page_metadata (search_id,html_lang,cms_generator,favicon_md5,dmarc) VALUES (?,?,?,?,?)",
            (sid, meta.get("html_lang"), meta.get("cms_generator"),
             fav_md5, email_sec.get("dmarc")),
        )

    return sid


# ── Queries ───────────────────────────────────────────────────────────────────

def get_recent(limit: int = 100) -> list[dict]:
    """Recent searches, newest first, no raw_json."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT id, target, type, timestamp, cloudflare_fronted FROM searches ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_domains_with_source_errors(source: str | None = None) -> list[dict]:
    """Searches where one or more external sources returned an error (e.g. 429 rate limit)."""
    import json as _json
    init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT id, target, timestamp, json_extract(raw_json, '$.source_errors') AS errors "
            "FROM searches WHERE json_extract(raw_json, '$.source_errors') IS NOT NULL",
        ).fetchall()
    results = []
    for row in rows:
        errors = _json.loads(row["errors"]) if row["errors"] else []
        if source is None or source in errors:
            results.append({"id": row["id"], "target": row["target"], "timestamp": row["timestamp"], "errors": errors})
    return results


def get_by_id(sid: int) -> dict | None:
    """Full row including raw_json."""
    init_db()
    with _conn() as c:
        row = c.execute("SELECT * FROM searches WHERE id = ?", (sid,)).fetchone()
    return dict(row) if row else None


def get_history_for_target(target: str) -> list[dict]:
    """All searches for a specific domain/IP, newest first."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT id, target, type, timestamp, cloudflare_fronted FROM searches WHERE target = ? ORDER BY id DESC",
            (target,),
        ).fetchall()
    return [dict(r) for r in rows]


# ── Cross-reference pivot queries ────────────────────────────────────────────

def find_by_ip(ip: str) -> list[dict]:
    """All targets that were ever observed using this IP."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT s.id, s.target, s.type, s.timestamp, i.source
               FROM searches s JOIN ips i ON s.id = i.search_id
               WHERE i.ip = ? ORDER BY s.id DESC""",
            (ip,),
        ).fetchall()
    return [dict(r) for r in rows]


def find_by_tls_sha256(sha256: str) -> list[dict]:
    """All targets that served a cert with this SHA-256 fingerprint."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT s.id, s.target, s.type, s.timestamp, t.cn, t.issuer_cn
               FROM searches s JOIN tls_certs t ON s.id = t.search_id
               WHERE t.sha256 = ? ORDER BY s.id DESC""",
            (sha256,),
        ).fetchall()
    return [dict(r) for r in rows]


def find_by_tracking_id(id_type: str, id_value: str) -> list[dict]:
    """All targets that embedded a specific tracking / analytics ID."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT s.id, s.target, s.type, s.timestamp
               FROM searches s JOIN tracking_ids t ON s.id = t.search_id
               WHERE t.id_type = ? AND t.id_value = ? ORDER BY s.id DESC""",
            (id_type, id_value),
        ).fetchall()
    return [dict(r) for r in rows]


def find_by_favicon(md5: str) -> list[dict]:
    """All targets sharing a favicon MD5 (infrastructure fingerprint)."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT s.id, s.target, s.type, s.timestamp
               FROM searches s JOIN favicons f ON s.id = f.search_id
               WHERE f.md5 = ? ORDER BY s.id DESC""",
            (md5,),
        ).fetchall()
    return [dict(r) for r in rows]


def find_by_registrant_email(email: str) -> list[dict]:
    """All targets registered with a given email address."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT s.id, s.target, s.type, s.timestamp
               FROM searches s JOIN registrant_emails e ON s.id = e.search_id
               WHERE e.email = ? ORDER BY s.id DESC""",
            (email.lower().strip(),),
        ).fetchall()
    return [dict(r) for r in rows]


def find_by_social_handle(platform: str, handle: str) -> list[dict]:
    """All targets linking to a specific social media account."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT s.id, s.target, s.type, s.timestamp
               FROM searches s JOIN social_accounts a ON s.id = a.search_id
               WHERE a.platform = ? AND a.handle = ? ORDER BY s.id DESC""",
            (platform, handle),
        ).fetchall()
    return [dict(r) for r in rows]


def find_by_nameserver(ns: str) -> list[dict]:
    """All targets using a specific nameserver."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT s.id, s.target, s.type, s.timestamp
               FROM searches s JOIN nameservers n ON s.id = n.search_id
               WHERE n.nameserver = ? ORDER BY s.id DESC""",
            (ns.lower().strip(),),
        ).fetchall()
    return [dict(r) for r in rows]


def find_by_cross_san(san: str) -> list[dict]:
    """All targets that appeared in the same crt.sh cert as this SAN."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT s.id, s.target, s.type, s.timestamp
               FROM searches s JOIN cross_sans cs ON s.id = cs.search_id
               WHERE cs.san = ? ORDER BY s.id DESC""",
            (san,),
        ).fetchall()
    return [dict(r) for r in rows]


# ── Passive IP classification ─────────────────────────────────────────────────
# Labels: "mail", "cdn_proxy", "shared_hosting", "direct"
# Used to surface noise in the cluster UI without hard-filtering anything —
# callers can decide what to show or hide.

_MAIL_ASNS = {"15169", "16276", "8075", "3215", "394161"}  # Google, OVH, Microsoft, Orange, Google Workspace
_CDN_PROXY_ASNS = {"13335", "19551", "54113", "20940", "60626", "394536", "22822", "16625"}  # CF, Incapsula, Fastly, Akamai, etc.
_SHARED_HOSTING_ASNS = {"2635", "27647", "61493", "2025"}  # Automattic, Weebly, Squarespace, Tumblr

_MAIL_PTR_PATTERNS = ("1e100.net", "google.com", "mail.ovh.", "smtp.", "mx.", "-mx-", "mail-", "mailout", "mxbiz")
_CDN_PROXY_PTR_PATTERNS = ("incapsula.com", "cloudflare.com", "cloudflare.net", "fastly.net",
                            "akamai.net", "akamaiedge.net", "akamaized.net", "edgecast.net",
                            "sucuri.net", "imperva.com", "cdn.")
_SHARED_HOSTING_PTR_PATTERNS = ("wildcard.", "weebly.com", "wordpress.com", "wix.com",
                                 "squarespace.com", "cluster", "shared-", "hosting.")
_EMAIL_SOURCES = {"mx_record", "spf"}


def classify_ip(ip: str, ptr: str | None, asn: str | None, sources: str | None) -> str:
    """
    Passively classify an IP using PTR hostname, ASN, and discovery sources.
    Returns one of: 'mail', 'cdn_proxy', 'shared_hosting', 'direct'.
    """
    ptr_l = (ptr or "").lower()
    src_set = set((sources or "").split(","))

    # Mail: came exclusively from MX/SPF lookups, or PTR/ASN screams mail
    if src_set and src_set <= _EMAIL_SOURCES:
        return "mail"
    if asn in _MAIL_ASNS and src_set <= _EMAIL_SOURCES | {"dns"}:
        return "mail"
    if any(p in ptr_l for p in _MAIL_PTR_PATTERNS):
        return "mail"

    # CDN / reverse proxy
    if asn in _CDN_PROXY_ASNS:
        return "cdn_proxy"
    if any(p in ptr_l for p in _CDN_PROXY_PTR_PATTERNS):
        return "cdn_proxy"

    # Shared hosting platforms
    if asn in _SHARED_HOSTING_ASNS:
        return "shared_hosting"
    if any(p in ptr_l for p in _SHARED_HOSTING_PTR_PATTERNS):
        return "shared_hosting"

    return "direct"


def _dedup_targets(targets_str: str) -> list[str]:
    """
    Normalize and deduplicate a comma-separated target list.
    Strips www. prefix so 'www.example.com' and 'example.com' collapse into one.
    Prefers the non-www form when both exist.
    """
    seen: dict[str, str] = {}  # norm -> display
    for t in targets_str.split(","):
        t = t.strip()
        if not t:
            continue
        norm = t[4:] if t.lower().startswith("www.") else t
        if norm not in seen or t == norm:   # prefer bare domain
            seen[norm] = t
    return list(seen.values())


def _recount(raw_rows: list[dict]) -> list[dict]:
    """
    Post-process cluster query results: deduplicate targets (www. collapse),
    recompute target_count, and drop any row that falls to < 2 unique targets.
    """
    out = []
    for row in raw_rows:
        deduped = _dedup_targets(str(row.get("targets", "")))
        if len(deduped) < 2:
            continue
        d = dict(row)
        d["targets"] = ",".join(deduped)
        d["target_count"] = len(deduped)
        out.append(d)
    return out


def cluster_by_ip() -> list[dict]:
    """
    IPs seen across multiple targets, with passive classification.
    Returns all shared IPs including mail/CDN/shared-hosting so the UI
    can filter or highlight them rather than silently dropping them.
    """
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT i.ip, MAX(i.ptr) AS ptr, MAX(i.asn) AS asn, MAX(i.asn_desc) AS asn_desc,
                      GROUP_CONCAT(DISTINCT i.source) AS sources,
                      COUNT(DISTINCT s.target) AS target_count,
                      GROUP_CONCAT(DISTINCT s.target) AS targets
               FROM ips i JOIN searches s ON i.search_id = s.id
               WHERE i.cloudflare = 0 OR i.cloudflare IS NULL
               GROUP BY i.ip HAVING target_count > 1
               ORDER BY target_count DESC""",
        ).fetchall()
    raw = []
    for row in rows:
        d = dict(row)
        d["label"] = classify_ip(d["ip"], d.get("ptr"), d.get("asn"), d.get("sources"))
        raw.append(d)
    # Dedup www./non-www targets, then re-apply label on surviving rows
    results = []
    for d in _recount(raw):
        if "label" not in d:
            d["label"] = classify_ip(d["ip"], d.get("ptr"), d.get("asn"), d.get("sources"))
        results.append(d)
    return results


def cluster_by_tracking_id() -> list[dict]:
    """Tracking IDs shared across multiple targets — strong operator link."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT t.id_type, t.id_value, COUNT(DISTINCT s.target) AS target_count,
                      GROUP_CONCAT(DISTINCT s.target) AS targets
               FROM tracking_ids t JOIN searches s ON t.search_id = s.id
               GROUP BY t.id_type, t.id_value HAVING target_count > 1
               ORDER BY target_count DESC""",
        ).fetchall()
    return _recount([dict(r) for r in rows])


def cluster_by_favicon() -> list[dict]:
    """Favicon hashes shared across multiple targets."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT f.md5, COUNT(DISTINCT s.target) AS target_count,
                      GROUP_CONCAT(DISTINCT s.target) AS targets
               FROM favicons f JOIN searches s ON f.search_id = s.id
               GROUP BY f.md5 HAVING target_count > 1
               ORDER BY target_count DESC""",
        ).fetchall()
    return _recount([dict(r) for r in rows])


def cluster_by_tls_cert() -> list[dict]:
    """TLS fingerprints shared across multiple targets."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT t.sha256, t.cn, t.issuer_cn, COUNT(DISTINCT s.target) AS target_count,
                      GROUP_CONCAT(DISTINCT s.target) AS targets
               FROM tls_certs t JOIN searches s ON t.search_id = s.id
               GROUP BY t.sha256 HAVING target_count > 1
               ORDER BY target_count DESC""",
        ).fetchall()
    return _recount([dict(r) for r in rows])


# ── Per-target connections breakdown ─────────────────────────────────────────

# Generic registrar/abuse emails that aren't meaningful operator signals
_GENERIC_EMAILS = {
    "abuse@godaddy.com", "domain.operations@web.com",
    "abuse@namecheap.com", "abuse@networksolutions.com",
    "noreply@domains.google.com", "registrar@enom.com",
    "abuse@tucows.com", "abuse@pairdomains.com",
}


def get_connections_for_target(target: str) -> dict | None:
    """
    Full cross-reference breakdown for a single target against every other
    domain in the database.

    Tries both the raw target and its www./non-www variant.
    Returns None if the target is not in the database.
    """
    init_db()
    norm = target.strip()
    alt  = norm[4:] if norm.startswith("www.") else "www." + norm

    with _conn() as c:
        row = (
            c.execute("SELECT * FROM searches WHERE target=?", (norm,)).fetchone()
            or c.execute("SELECT * FROM searches WHERE target=?", (alt,)).fetchone()
        )
        if not row:
            return None

        sid = row["id"]

        def _others_by(table: str, col: str, val: str) -> list[str]:
            """All targets that share a single attribute value, deduped."""
            rows = c.execute(
                f"SELECT DISTINCT s.target FROM searches s "
                f"JOIN {table} x ON s.id=x.search_id "
                f"WHERE x.{col}=? AND s.id!=?",
                (val, sid),
            ).fetchall()
            return _dedup_targets(",".join(r["target"] for r in rows))

        # ── WHOIS summary ─────────────────────────────────────────────────────
        w = c.execute(
            "SELECT registrar, creation_date, expiry_date, org, country FROM whois_data WHERE search_id=?",
            (sid,),
        ).fetchone()

        # ── Tracking IDs ──────────────────────────────────────────────────────
        tracking = []
        for t in c.execute("SELECT id_type, id_value FROM tracking_ids WHERE search_id=?", (sid,)).fetchall():
            tracking.append({
                "id_type":     t["id_type"],
                "id_value":    t["id_value"],
                "shared_with": _others_by("tracking_ids", "id_value", t["id_value"]),
            })

        # ── IPs (non-CF) ──────────────────────────────────────────────────────
        ips = []
        seen_ips: set[str] = set()
        for ip_row in c.execute(
            "SELECT ip, source, ptr, asn, asn_desc, country, cloudflare "
            "FROM ips WHERE search_id=?", (sid,)
        ).fetchall():
            ip = ip_row["ip"]
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            others = c.execute(
                "SELECT DISTINCT s.target, i.source FROM searches s "
                "JOIN ips i ON s.id=i.search_id WHERE i.ip=? AND s.id!=?",
                (ip, sid),
            ).fetchall()
            deduped = _dedup_targets(",".join(r["target"] for r in others))
            ips.append({
                "ip":          ip,
                "source":      ip_row["source"],
                "ptr":         ip_row["ptr"],
                "asn_desc":    ip_row["asn_desc"],
                "country":     ip_row["country"],
                "cloudflare":  ip_row["cloudflare"],
                "shared_with": deduped,
            })

        # ── TLS certs ─────────────────────────────────────────────────────────
        tls = []
        seen_fp: set[str] = set()
        for cert in c.execute(
            "SELECT sha256, cn, sans, issuer_cn, ip, not_before, not_after "
            "FROM tls_certs WHERE search_id=?", (sid,)
        ).fetchall():
            fp = cert["sha256"]
            if not fp or fp in seen_fp:
                continue
            seen_fp.add(fp)
            tls.append({
                "sha256":      fp,
                "cn":          cert["cn"],
                "sans":        cert["sans"],
                "issuer_cn":   cert["issuer_cn"],
                "ip":          cert["ip"],
                "not_before":  cert["not_before"],
                "not_after":   cert["not_after"],
                "shared_with": _others_by("tls_certs", "sha256", fp),
            })

        # ── Favicons ──────────────────────────────────────────────────────────
        favicons = []
        for fav in c.execute("SELECT md5 FROM favicons WHERE search_id=?", (sid,)).fetchall():
            favicons.append({
                "md5":         fav["md5"],
                "shared_with": _others_by("favicons", "md5", fav["md5"]),
            })

        # ── Registrant emails (skip generic ones) ─────────────────────────────
        emails = []
        for e in c.execute("SELECT email FROM registrant_emails WHERE search_id=?", (sid,)).fetchall():
            em = e["email"]
            if em in _GENERIC_EMAILS:
                continue
            emails.append({
                "email":       em,
                "shared_with": _others_by("registrant_emails", "email", em),
            })

        # ── Nameservers ───────────────────────────────────────────────────────
        nameservers = []
        for ns in c.execute("SELECT nameserver FROM nameservers WHERE search_id=?", (sid,)).fetchall():
            nameservers.append({
                "nameserver":  ns["nameserver"],
                "shared_with": _others_by("nameservers", "nameserver", ns["nameserver"]),
            })

        # ── Social handles ────────────────────────────────────────────────────
        social = [
            dict(r) for r in c.execute(
                "SELECT platform, handle, url FROM social_accounts WHERE search_id=?", (sid,)
            ).fetchall()
        ]

        return {
            "target":             row["target"],
            "sid":                sid,
            "type":               row["type"],
            "timestamp":          row["timestamp"],
            "cloudflare_fronted": row["cloudflare_fronted"],
            "whois":              dict(w) if w else {},
            "connections": {
                "tracking_ids":      tracking,
                "ips":               ips,
                "tls_certs":         tls,
                "favicons":          favicons,
                "registrant_emails": emails,
                "nameservers":       nameservers,
            },
            "social": social,
        }
