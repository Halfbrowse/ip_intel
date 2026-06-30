"""
intel_db.py — PostgreSQL persistence for raw ip-intel runs.

This module stores every analysis run append-only, then builds "latest run"
views in query code so the UI can default to current relationships while still
preserving enough history to answer "was this shared in the past?"

Connection conventions mirror cases/case_store.py: psycopg3, short-lived
connections opened per operation so multiple workers can hit the database
concurrently. The connection string comes from INTEL_DATABASE_URL when set,
otherwise DATABASE_URL (the same database used for case storage).
"""

from __future__ import annotations

import hashlib
import json
import os
import ipaddress
import re
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Mapping
from urllib.parse import urlsplit

from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

DEFAULT_DATABASE_URL = "postgresql://ip_intel:ip_intel@postgres:5432/ip_intel"


def database_url() -> str:
    return (
        os.getenv("INTEL_DATABASE_URL")
        or os.getenv("DATABASE_URL")
        or DEFAULT_DATABASE_URL
    ).strip()


# ── Connection ────────────────────────────────────────────────────────────────

def _conn() -> psycopg.Connection[Any]:
    return psycopg.connect(database_url(), row_factory=dict_row)


# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS searches (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target              TEXT    NOT NULL,
    type                TEXT    NOT NULL,
    timestamp           TEXT    NOT NULL,
    cloudflare_fronted  INTEGER,
    raw_json            TEXT    NOT NULL DEFAULT '',
    source_errors       JSONB
);
CREATE INDEX IF NOT EXISTS idx_searches_target     ON searches(target);
CREATE INDEX IF NOT EXISTS idx_searches_ts         ON searches(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_searches_target_ts  ON searches(target, timestamp DESC, id DESC);

CREATE TABLE IF NOT EXISTS ips (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id           BIGINT  NOT NULL REFERENCES searches(id),
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
    proxy_confidence    DOUBLE PRECISION,
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
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id   BIGINT  NOT NULL REFERENCES searches(id),
    ip          TEXT    NOT NULL,
    port        INTEGER NOT NULL,
    sni_used    TEXT,
    cn          TEXT,
    sans        JSONB,
    issuer_cn   TEXT,
    issuer_org  TEXT,
    not_before  TEXT,
    not_after   TEXT,
    sha256      TEXT,
    spki_sha256 TEXT,
    observed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_tls_search_id         ON tls_certs(search_id);
CREATE INDEX IF NOT EXISTS idx_tls_sha256            ON tls_certs(sha256);
CREATE INDEX IF NOT EXISTS idx_tls_cn                ON tls_certs(cn);
CREATE INDEX IF NOT EXISTS idx_tls_ip                ON tls_certs(ip);
CREATE INDEX IF NOT EXISTS idx_tls_sha256_observed   ON tls_certs(sha256, observed_at DESC);

CREATE TABLE IF NOT EXISTS ct_certs (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id   BIGINT  NOT NULL REFERENCES searches(id),
    cert_id     BIGINT,
    issuer      TEXT,
    not_before  TEXT,
    not_after   TEXT,
    sans        JSONB,
    observed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_ct_search_id       ON ct_certs(search_id);
CREATE INDEX IF NOT EXISTS idx_ct_issuer          ON ct_certs(issuer);
CREATE INDEX IF NOT EXISTS idx_ct_cert_id         ON ct_certs(cert_id);

CREATE TABLE IF NOT EXISTS subdomains (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id   BIGINT  NOT NULL REFERENCES searches(id),
    subdomain   TEXT    NOT NULL,
    source      TEXT
);
CREATE INDEX IF NOT EXISTS idx_sub_search_id ON subdomains(search_id);
CREATE INDEX IF NOT EXISTS idx_sub_subdomain ON subdomains(subdomain);

CREATE TABLE IF NOT EXISTS dns_records (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id   BIGINT  NOT NULL REFERENCES searches(id),
    rtype       TEXT    NOT NULL,
    value       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dns_search_id ON dns_records(search_id);
CREATE INDEX IF NOT EXISTS idx_dns_value     ON dns_records(value);

CREATE TABLE IF NOT EXISTS historical_dns (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id   BIGINT  NOT NULL REFERENCES searches(id),
    rrtype      TEXT,
    rdata       TEXT,
    first_seen  TEXT,
    last_seen   TEXT
);
CREATE INDEX IF NOT EXISTS idx_hist_search_id ON historical_dns(search_id);
CREATE INDEX IF NOT EXISTS idx_hist_rdata     ON historical_dns(rdata);

CREATE TABLE IF NOT EXISTS tracking_ids (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id   BIGINT  NOT NULL REFERENCES searches(id),
    id_type     TEXT    NOT NULL,
    id_value    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_track_search_id ON tracking_ids(search_id);
CREATE INDEX IF NOT EXISTS idx_track_value     ON tracking_ids(id_type, id_value);

CREATE TABLE IF NOT EXISTS social_accounts (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id   BIGINT  NOT NULL REFERENCES searches(id),
    platform    TEXT    NOT NULL,
    handle      TEXT    NOT NULL,
    url         TEXT
);
CREATE INDEX IF NOT EXISTS idx_social_search_id ON social_accounts(search_id);
CREATE INDEX IF NOT EXISTS idx_social_handle    ON social_accounts(platform, handle);

CREATE TABLE IF NOT EXISTS favicons (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id   BIGINT  NOT NULL REFERENCES searches(id),
    md5         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fav_search_id ON favicons(search_id);
CREATE INDEX IF NOT EXISTS idx_fav_md5       ON favicons(md5);

CREATE TABLE IF NOT EXISTS identifiers (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id       BIGINT  NOT NULL REFERENCES searches(id),
    id_type         TEXT    NOT NULL,
    id_value        TEXT    NOT NULL,
    tier            TEXT    NOT NULL,
    category        TEXT    NOT NULL,
    source          TEXT    NOT NULL,
    observed_at     TEXT,
    first_seen      TEXT,
    last_seen       TEXT,
    raw_json        JSONB
);
CREATE INDEX IF NOT EXISTS idx_identifiers_search_id     ON identifiers(search_id);
CREATE INDEX IF NOT EXISTS idx_identifiers_type_value    ON identifiers(id_type, id_value);

CREATE TABLE IF NOT EXISTS whois_data (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id       BIGINT  NOT NULL REFERENCES searches(id),
    registrar       TEXT,
    creation_date   TEXT,
    expiry_date     TEXT,
    org             TEXT,
    country         TEXT,
    emails          JSONB,
    nameservers     JSONB
);
CREATE INDEX IF NOT EXISTS idx_whois_search_id ON whois_data(search_id);
CREATE INDEX IF NOT EXISTS idx_whois_registrar ON whois_data(registrar);

CREATE TABLE IF NOT EXISTS registrant_emails (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id   BIGINT  NOT NULL REFERENCES searches(id),
    email       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_email_search_id ON registrant_emails(search_id);
CREATE INDEX IF NOT EXISTS idx_email_value     ON registrant_emails(email);

CREATE TABLE IF NOT EXISTS nameservers (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id   BIGINT  NOT NULL REFERENCES searches(id),
    nameserver  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ns_search_id ON nameservers(search_id);
CREATE INDEX IF NOT EXISTS idx_ns_value     ON nameservers(nameserver);

CREATE TABLE IF NOT EXISTS spf_origins (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id   BIGINT  NOT NULL REFERENCES searches(id),
    ip          TEXT    NOT NULL,
    cidr        TEXT
);
CREATE INDEX IF NOT EXISTS idx_spf_search_id ON spf_origins(search_id);
CREATE INDEX IF NOT EXISTS idx_spf_ip        ON spf_origins(ip);

CREATE TABLE IF NOT EXISTS cross_sans (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id   BIGINT  NOT NULL REFERENCES searches(id),
    san         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_csan_search_id ON cross_sans(search_id);
CREATE INDEX IF NOT EXISTS idx_csan_san       ON cross_sans(san);

CREATE TABLE IF NOT EXISTS scan_hits (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id   BIGINT  NOT NULL REFERENCES searches(id),
    scan_type   TEXT    NOT NULL,
    ip          TEXT    NOT NULL,
    port        INTEGER,
    cn          TEXT,
    sans        JSONB,
    issuer      TEXT,
    not_before  TEXT,
    not_after   TEXT,
    sha256      TEXT,
    spki_sha256 TEXT,
    cloudflare  INTEGER,
    observed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_search_id       ON scan_hits(search_id);
CREATE INDEX IF NOT EXISTS idx_scan_ip              ON scan_hits(ip);
CREATE INDEX IF NOT EXISTS idx_scan_cn              ON scan_hits(cn);
CREATE INDEX IF NOT EXISTS idx_scan_sha256          ON scan_hits(sha256);
CREATE INDEX IF NOT EXISTS idx_scan_sha256_observed ON scan_hits(sha256, observed_at DESC);

CREATE TABLE IF NOT EXISTS provider_hits (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id   BIGINT  NOT NULL REFERENCES searches(id),
    provider    TEXT    NOT NULL,
    ip          TEXT,
    port        INTEGER,
    protocol    TEXT,
    asn         TEXT,
    asn_desc    TEXT,
    org         TEXT,
    country     TEXT,
    cloudflare  INTEGER,
    services    JSONB,
    hostnames   JSONB,
    mode        TEXT,
    status      TEXT,
    query_type  TEXT,
    total       INTEGER,
    observed_at TEXT,
    raw_json    JSONB
);
CREATE INDEX IF NOT EXISTS idx_provider_search_id    ON provider_hits(search_id);
CREATE INDEX IF NOT EXISTS idx_provider_name         ON provider_hits(provider);
CREATE INDEX IF NOT EXISTS idx_provider_ip_observed  ON provider_hits(ip, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_provider_status       ON provider_hits(status);

CREATE TABLE IF NOT EXISTS page_metadata (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id       BIGINT  NOT NULL REFERENCES searches(id),
    html_lang       TEXT,
    cms_generator   TEXT,
    favicon_md5     TEXT,
    dmarc           TEXT
);
CREATE INDEX IF NOT EXISTS idx_meta_search_id ON page_metadata(search_id);
CREATE INDEX IF NOT EXISTS idx_meta_lang      ON page_metadata(html_lang);
CREATE INDEX IF NOT EXISTS idx_meta_cms       ON page_metadata(cms_generator);

CREATE TABLE IF NOT EXISTS discovered_targets (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id       BIGINT  NOT NULL REFERENCES searches(id),
    target          TEXT    NOT NULL,
    target_type     TEXT    NOT NULL,
    relation        TEXT    NOT NULL,
    source          TEXT    NOT NULL,
    score           INTEGER NOT NULL DEFAULT 0,
    observed_at     TEXT,
    raw_json        JSONB
);
CREATE INDEX IF NOT EXISTS idx_discovered_search_id      ON discovered_targets(search_id);
CREATE INDEX IF NOT EXISTS idx_discovered_target         ON discovered_targets(target);
CREATE INDEX IF NOT EXISTS idx_discovered_target_type    ON discovered_targets(target_type);
CREATE INDEX IF NOT EXISTS idx_discovered_target_source  ON discovered_targets(target, source);

CREATE TABLE IF NOT EXISTS search_fields (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id   BIGINT  NOT NULL REFERENCES searches(id),
    key         TEXT    NOT NULL,
    json_value  JSONB   NOT NULL,
    UNIQUE(search_id, key)
);
CREATE INDEX IF NOT EXISTS idx_sf_search_id ON search_fields(search_id);

-- ── Correlation layer (derived, rebuildable by global recompute) ─────────────
-- These tables are NOT part of the append-only raw substrate. They are a
-- normalized projection of the raw `searches`/child tables built so that
-- linkage becomes graph reachability over shared observables. Everything here
-- can be dropped and rebuilt from the raw intel by the backfill / recompute.

CREATE TABLE IF NOT EXISTS entities (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind                TEXT    NOT NULL,   -- 'domain' | 'subdomain' | 'ip'
    value               TEXT    NOT NULL,   -- fqdn or IP
    registrable_domain  TEXT,               -- eTLD+1 rollup (parent of a subdomain, NULL for ip)
    first_seen          TEXT,
    last_seen           TEXT,
    UNIQUE (kind, value)
);
CREATE INDEX IF NOT EXISTS idx_entities_value        ON entities(value);
CREATE INDEX IF NOT EXISTS idx_entities_registrable  ON entities(registrable_domain);
CREATE INDEX IF NOT EXISTS idx_entities_kind         ON entities(kind);

CREATE TABLE IF NOT EXISTS selectors (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind            TEXT    NOT NULL,   -- 'tls_cert_sha256' | 'tls_spki' | 'tls_san'
                                        -- | 'favicon_mmh3' | 'tracking_id' | 'ssh_fp'
                                        -- | 'jarm' | 'asn' | 'network_cidr' | 'nameserver' ...
    value           TEXT    NOT NULL,
    entity_count    INTEGER NOT NULL DEFAULT 0,   -- global degree: distinct entities exhibiting this selector
    attributing     BOOLEAN NOT NULL DEFAULT TRUE, -- false = known-shared noise, never links
    first_seen      TEXT,
    last_seen       TEXT,
    UNIQUE (kind, value)
);
CREATE INDEX IF NOT EXISTS idx_selectors_kind_value  ON selectors(kind, value);
CREATE INDEX IF NOT EXISTS idx_selectors_attributing ON selectors(attributing);

CREATE TABLE IF NOT EXISTS observations (
    entity_id   BIGINT  NOT NULL REFERENCES entities(id),
    selector_id BIGINT  NOT NULL REFERENCES selectors(id),
    first_seen  TEXT,                  -- when this entity was seen with this selector
    last_seen   TEXT,
    source      TEXT    NOT NULL DEFAULT '',  -- 'crtsh' | 'censys' | 'censys_history' | 'self_scan' | ...
    search_id   BIGINT  REFERENCES searches(id),  -- raw searches row that produced it
    PRIMARY KEY (entity_id, selector_id, source)
);
CREATE INDEX IF NOT EXISTS idx_observations_selector ON observations(selector_id);
CREATE INDEX IF NOT EXISTS idx_observations_entity   ON observations(entity_id);
CREATE INDEX IF NOT EXISTS idx_observations_search   ON observations(search_id);

CREATE TABLE IF NOT EXISTS entity_edges (
    src_entity_id   BIGINT  NOT NULL REFERENCES entities(id),
    dst_entity_id   BIGINT  NOT NULL REFERENCES entities(id),
    kind            TEXT    NOT NULL,   -- 'resolves_to' | 'subdomain_of'
    first_seen      TEXT,
    last_seen       TEXT,
    source          TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (src_entity_id, dst_entity_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_entity_edges_dst ON entity_edges(dst_entity_id, kind);
CREATE INDEX IF NOT EXISTS idx_entity_edges_src ON entity_edges(src_entity_id, kind);

-- Materialized global clusters: connected components over the attributing graph,
-- rolled up to registrable_domain. Rebuilt by recompute / on schedule, never
-- inline on ingest (full-graph clustering is too heavy per-ingest at lake scale).
CREATE TABLE IF NOT EXISTS graph_clusters (
    registrable_domain  TEXT    PRIMARY KEY,
    cluster_id          TEXT    NOT NULL,   -- stable representative (min member)
    component_size      INTEGER NOT NULL,
    computed_at         TEXT
);
CREATE INDEX IF NOT EXISTS idx_graph_clusters_cid ON graph_clusters(cluster_id);

"""


_CHILD_TABLES = [
    "ips", "tls_certs", "ct_certs", "subdomains", "dns_records",
    "historical_dns", "tracking_ids", "social_accounts", "favicons",
    "whois_data", "registrant_emails", "nameservers", "spf_origins",
    "cross_sans", "scan_hits", "provider_hits", "page_metadata", "discovered_targets",
]

_HOSTNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")

_PIVOT_SOURCE_SCORES = {
    "dns_a": 10,
    "dns_aaaa": 10,
    "historical_dns": 8,
    "origin_hit": 8,
    "provider_hit": 8,
    "scan_hit": 9,
    "reverse_ip": 9,
    "zone_transfer": 9,
    "subdomain": 7,
    "subdomain_leak": 8,
    "mx_leak": 7,
    "wordlist_leak": 7,
    "cname": 6,
    "mx": 5,
    "nameserver": 3,
    "whois_nameserver": 3,
    "cross_san": 6,
    "ct_san": 5,
    "tls_cn": 8,
    "tls_san": 7,
    "ptr": 4,
    "spf": 4,
    "urlscan_url": 7,
}

_NOISY_PIVOT_SUFFIXES = {
    "amazonaws.com",
    "azurewebsites.net",
    "bluehost.com",
    "cloudflare.com",
    "cloudflare.net",
    "cloudfront.net",
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

_LOW_SIGNAL_HOSTING_PATTERNS = (
    "amazonaws.com",
    "automattic.com",
    "azurefd.net",
    "azurewebsites.net",
    "bluehost.com",
    "cloudflare.com",
    "cloudflare.net",
    "cloudfront.net",
    "cloudways",
    "digitaloceanspaces.com",
    "dreamhost.com",
    "fastly.net",
    "github.io",
    "gitlab.io",
    "godaddy.com",
    "googleapis.com",
    "googlehosted.com",
    "googleusercontent.com",
    "hostgator.com",
    "hostinger.com",
    "kinsta",
    "namecheap.com",
    "o2switch.net",
    "ovh.net",
    "pantheonsite.io",
    "pressable.com",
    "shopify.com",
    "siteground",
    "squarespace.com",
    "webflow.io",
    "weebly.com",
    "wix.com",
    "wixsite.com",
    "wordpress.com",
    "wpengine.com",
    "wpenginepowered.com",
)

_LOW_SIGNAL_TLS_IDENTITIES = {
    "localhost",
    "localhost.localdomain",
    "localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "example.com",
    "example.org",
    "example.net",
    "example.local",
}

_LOW_SIGNAL_TLS_PATTERNS = (
    "acme staging",
    "default certificate",
    "dummy certificate",
    "fake certificate",
    "ingress controller fake certificate",
    "kubernetes ingress controller fake certificate",
    "mkcert development",
    "snakeoil",
)

_IDENTIFIER_TIER_ORDER = {
    "tier_1": 4,
    "tier_2": 3,
    "tier_3": 2,
    "tier_4": 1,
}

_IDENTIFIER_TIER_LABELS = {
    "tier_1": "strong",
    "tier_2": "high",
    "tier_3": "medium",
    "tier_4": "supporting",
}

_IDENTIFIER_TIER_BASE_SCORES = {
    "tier_1": 74,
    "tier_2": 46,
    "tier_3": 28,
    "tier_4": 14,
}

_IDENTIFIER_CATEGORY_SCORE_MODIFIERS = {
    "tls": 18,
    "tls_ct": 14,
    "ssh": 18,
    "identity": 14,
    "tracking": 12,
    "content": 10,
    "infrastructure": 8,
    "legal": 8,
    "policy": 6,
    "email": 5,
    "social": 4,
    "nameserver": 3,
    "dns": 2,
    "generic": 0,
}

_IDENTIFIER_FREQUENCY_RULES = {
    "tls": {"downweight_after": 10, "exclude_after": 60},
    "tls_ct": {"downweight_after": 8, "exclude_after": 40},
    "ssh": {"downweight_after": 4, "exclude_after": 20},
    "identity": {"downweight_after": 5, "exclude_after": 25},
    "tracking": {"downweight_after": 6, "exclude_after": 30},
    "content": {"downweight_after": 4, "exclude_after": 20},
    "infrastructure": {"downweight_after": 3, "exclude_after": 12},
    "legal": {"downweight_after": 5, "exclude_after": 25},
    "policy": {"downweight_after": 5, "exclude_after": 24},
    "email": {"downweight_after": 5, "exclude_after": 24},
    "social": {"downweight_after": 4, "exclude_after": 18},
    "nameserver": {"downweight_after": 3, "exclude_after": 10},
    "dns": {"downweight_after": 4, "exclude_after": 16},
    "generic": {"downweight_after": 4, "exclude_after": 16},
}

_IDENTIFIER_HASH_TYPES = {
    "favicon_md5",
    "favicon_mmh3",
    "homepage_html_hash",
    "http_fingerprint",
    "legal_text_hash",
    "well_known_text_hash",
    "tls_sha256",
    "tls_spki_sha256",
    "tls_transport_fingerprint",
    "ssh_host_key_sha256",
    "ssh_host_key_md5",
    "android_cert_sha256",
}

_IDENTIFIER_EMAIL_TYPES = {
    "registrant_email",
    "contact_email",
    "mail_client_email",
    "dmarc_rua",
    "dmarc_ruf",
    "tls_rpt_rua",
}

_IDENTIFIER_URL_TYPES = {
    "openid_issuer",
    "openid_authorization_endpoint",
    "openid_token_endpoint",
    "openid_userinfo_endpoint",
    "openid_jwks_uri",
    "openid_registration_endpoint",
    "rel_me_url",
    "social_url",
    "script_asset_url",
    "source_map_url",
    "mail_client_url",
    "well_known_url",
    "policy_url",
    "bimi",
    "mta_sts",
    "tls_rpt",
}

_IDENTIFIER_HOST_TYPES = {
    "resolved_ip",
    "historical_ip",
    "origin_ip",
    "provider_ip",
    "provider_hostname",
    "scan_ip",
    "dns_alias",
    "mx_host",
    "nameserver",
    "nameserver_vanity",
    "mail_client_domain",
    "mail_client_server",
    "script_asset_host",
    "source_map_host",
    "spf_include",
    "dns_caa",
    "subdomain_name",
    "cross_san_domain",
    "certificate_san",
}

_IDENTIFIER_HANDLE_TYPES = {
    "social_handle",
    "meta_social_handle",
    "twitter_site",
    "twitter_creator",
    "author",
}


# Derived correlation-layer tables. Kept separate from _CHILD_TABLES because
# they are NOT append-only children of a single search — they are a global
# projection rebuildable from the raw intel. Listed in _ALL_TABLES so schema
# resets (tests) drop them too; ordered so dependents precede their referents.
_CORRELATION_TABLES = ["graph_clusters", "entity_edges", "observations", "selectors", "entities"]

_ALL_TABLES = ["searches", *_CHILD_TABLES, "identifiers", "search_fields", *_CORRELATION_TABLES]

_SCHEMA_LOCK = threading.Lock()
_SCHEMA_READY = False

# Arbitrary constant used as a Postgres advisory lock key so concurrent workers
# do not race each other while creating the schema.
_SCHEMA_ADVISORY_LOCK_KEY = 882_417_309


def schema_statements() -> list[str]:
    return [stmt.strip() for stmt in _SCHEMA.strip().split(";") if stmt.strip()]


def init_db() -> None:
    """Create the schema once per process (idempotent and concurrency-safe)."""
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return
    with _SCHEMA_LOCK:
        if _SCHEMA_READY:
            return
        with _conn() as c:
            c.execute("SELECT pg_advisory_xact_lock(%s)", (_SCHEMA_ADVISORY_LOCK_KEY,))
            for stmt in schema_statements():
                c.execute(stmt)
        _SCHEMA_READY = True


def reset_schema_cache() -> None:
    """Forget that the schema was initialized (used by tests)."""
    global _SCHEMA_READY
    with _SCHEMA_LOCK:
        _SCHEMA_READY = False


# ── Helpers ───────────────────────────────────────────────────────────────────

def _json_dumps(value: Any) -> str:
    return json.dumps(value, default=str)


def _json(value: Any) -> Jsonb:
    """Wrap a value for insertion into a JSONB column."""
    return Jsonb(value, dumps=_json_dumps)


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


def _normalize_candidate_target(value: Any) -> tuple[str | None, str | None]:
    text = str(value or "").strip()
    if not text:
        return None, None

    if "://" in text:
        text = urlsplit(text).hostname or ""
    elif "/" in text and " " not in text:
        text = urlsplit(f"//{text}").hostname or text

    text = text.strip().strip("[]").rstrip(".").lower()
    if text.startswith("*."):
        text = text[2:]
    if "@" in text and " " not in text:
        maybe_host = text.rsplit("@", 1)[-1]
        if "." in maybe_host:
            text = maybe_host

    try:
        ip = ipaddress.ip_address(text)
        return str(ip), "ip"
    except ValueError:
        pass

    if not _HOSTNAME_RE.fullmatch(text):
        return None, None
    return text, "domain"


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or ip.is_link_local
    )


@lru_cache(maxsize=1)
def _tld_extractor() -> Any:
    """A tldextract extractor pinned to its bundled Public Suffix List snapshot.

    `suffix_list_urls=()` + `cache_dir=None` make it fully offline: it never
    touches the network (important behind the VPN/proxy), using the PSL baked
    into the installed package. Returns None if tldextract is unavailable so the
    caller can fall back to the naive heuristic.

    `include_psl_private_domains=True` treats the PSL *private* section
    (vercel.app, github.io, netlify.app, herokuapp.com, web.app, pages.dev,
    blogspot.com, …) as public suffixes, so each PaaS deployment is its own
    registrable domain (`v0-meta-t.vercel.app`, not `vercel.app`). Without this
    every deployment on a platform would be merged under the platform apex,
    which is wrong for attribution — each `*.vercel.app` is a different operator.
    """
    try:
        import tldextract

        return tldextract.TLDExtract(
            suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
        )
    except Exception:  # pragma: no cover - defensive: any import/init failure
        return None


def registrable_domain(value: Any) -> str | None:
    """eTLD+1 (registrable apex) for a hostname, public-suffix aware.

    Uses the Public Suffix List (via tldextract's offline snapshot) so multi-
    label suffixes like `co.uk`, `com.au`, `co.jp` roll up correctly — e.g.
    `news.bbc.co.uk` -> `bbc.co.uk`, not `co.uk`. Getting this right matters at
    graph scale: the registrable domain is the entity-rollup key, so a wrong
    apex would merge unrelated ccTLD domains into one node. Falls back to the
    last-two-labels heuristic if tldextract is unavailable. Returns None for IPs
    or anything that is not a hostname.
    """
    text = str(value or "").strip().lower().strip("[]").rstrip(".").lstrip(".")
    if not text:
        return None
    if text.startswith("*."):
        text = text[2:]
    try:
        ipaddress.ip_address(text)
        return None
    except ValueError:
        pass

    extractor = _tld_extractor()
    if extractor is not None:
        try:
            extracted = extractor(text)
            if extracted.domain and extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}"
        except Exception:  # pragma: no cover - fall through to the heuristic
            pass

    # Fallback: last two labels (also covers a bare apex with an unknown suffix).
    if text.startswith("www."):
        text = text[4:]
    parts = [p for p in text.split(".") if p]
    if len(parts) < 2:
        return None
    return ".".join(parts[-2:])


def classify_entity(value: Any) -> dict[str, Any] | None:
    """Map a raw value to an entity record: {kind, value, registrable_domain}.

    kind is 'ip', 'domain' (the value *is* its registrable apex) or 'subdomain'
    (a hostname below its registrable apex). Returns None when the value cannot
    be normalized into an IP or a hostname.
    """
    norm, typ = _normalize_candidate_target(value)
    if not norm or not typ:
        return None
    if typ == "ip":
        return {"kind": "ip", "value": norm, "registrable_domain": None}
    # Collapse a leading www. so the apex site and "www" host are one entity,
    # matching how _normalize_target dedups targets everywhere else.
    if norm.startswith("www."):
        norm = norm[4:]
    apex = registrable_domain(norm)
    if not apex:
        return None
    kind = "domain" if norm == apex else "subdomain"
    return {"kind": kind, "value": norm, "registrable_domain": apex}


def _is_noisy_pivot_domain(target: str) -> bool:
    if not target or target.count(".") < 1:
        return True
    return any(target == suffix or target.endswith(f".{suffix}") for suffix in _NOISY_PIVOT_SUFFIXES)


def _normalize_text_list(values: Any) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)):
        raw_values = [values]
    elif isinstance(values, list | tuple | set):
        raw_values = list(values)
    else:
        raw_values = [values]

    cleaned: list[str] = []
    seen: set[str] = set()
    for value in raw_values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        cleaned.append(text)
    return cleaned


def _merge_ip_detail_entry(
    normalized: dict[str, dict[str, Any]],
    ip_address: str,
    payload: Any,
) -> None:
    ip_text = str(ip_address or "").strip()
    if not ip_text:
        return

    raw = dict(payload) if isinstance(payload, Mapping) else {}
    entry = normalized.setdefault(
        ip_text,
        {
            "sources": [],
            "other_domains_on_ip": [],
            "asn_info": {},
        },
    )

    sources = _normalize_text_list(raw.get("sources"))
    if not sources:
        sources = _normalize_text_list(raw.get("source"))
    for source in sources:
        if source not in entry["sources"]:
            entry["sources"].append(source)

    for domain in _normalize_text_list(raw.get("other_domains_on_ip")):
        if domain not in entry["other_domains_on_ip"]:
            entry["other_domains_on_ip"].append(domain)

    if raw.get("ptr") and not entry.get("ptr"):
        entry["ptr"] = raw.get("ptr")

    for key in ("cloudflare", "proxy_family", "proxy_confidence"):
        if key in raw and raw.get(key) is not None and entry.get(key) is None:
            entry[key] = raw.get(key)

    asn_info = entry.setdefault("asn_info", {})
    nested_asn = raw.get("asn_info")
    if isinstance(nested_asn, Mapping):
        for key, value in nested_asn.items():
            if value not in (None, "") and asn_info.get(key) in (None, ""):
                asn_info[key] = value

    for key, value in {
        "asn": raw.get("asn"),
        "asn_description": raw.get("asn_desc"),
        "asn_registry": raw.get("asn_registry"),
        "asn_country": raw.get("country"),
        "network_name": raw.get("network_name"),
        "network_cidr": raw.get("network_cidr"),
    }.items():
        if value not in (None, "") and asn_info.get(key) in (None, ""):
            asn_info[key] = value


def normalize_ip_details(value: Any) -> dict[str, dict[str, Any]]:
    normalized: dict[str, dict[str, Any]] = {}
    if isinstance(value, Mapping):
        for ip_address, payload in value.items():
            _merge_ip_detail_entry(normalized, str(ip_address or ""), payload)
        return normalized

    if isinstance(value, list):
        for item in value:
            if not isinstance(item, Mapping):
                continue
            _merge_ip_detail_entry(normalized, str(item.get("ip") or ""), item)
    return normalized


def _iter_dns_host_values(values: Any, *, key: str | None = None) -> list[str]:
    if not values:
        return []
    if isinstance(values, list):
        output: list[str] = []
        for item in values:
            if isinstance(item, dict):
                lookup_keys = [key] if key else ["value", "exchange"]
                for lookup_key in lookup_keys:
                    candidate = item.get(lookup_key)
                    if candidate:
                        output.append(str(candidate))
                        break
            else:
                output.append(str(item))
        return output
    if isinstance(values, dict):
        lookup_keys = [key] if key else ["value", "exchange"]
        for lookup_key in lookup_keys:
            candidate = values.get(lookup_key)
            if candidate:
                return [str(candidate)]
        return []
    return [str(values)]


def extract_related_targets(result: dict[str, Any], *, include_self: bool = False) -> list[dict[str, Any]]:
    current_target, current_type = _normalize_candidate_target(result.get("input"))
    seen: set[tuple[str, str, str, str]] = set()
    items: list[dict[str, Any]] = []

    def add(value: Any, relation: str, source: str, raw: Any = None) -> None:
        target, target_type = _normalize_candidate_target(value)
        if not target or not target_type:
            return
        if not include_self and current_target and current_type:
            if target_type == "domain" and current_type == "domain" and _normalize_target(target) == _normalize_target(current_target):
                return
            if target_type == "ip" and current_type == "ip" and target == current_target:
                return
        key = (target, target_type, relation, source)
        if key in seen:
            return
        seen.add(key)
        items.append(
            {
                "target": target,
                "target_type": target_type,
                "relation": relation,
                "source": source,
                "score": _PIVOT_SOURCE_SCORES.get(source, 1),
                "raw_json": raw,
            }
        )

    dns = result.get("dns", {})
    for ip in _iter_dns_host_values(dns.get("A")):
        add(ip, "resolved_ip", "dns_a")
    for ip in _iter_dns_host_values(dns.get("AAAA")):
        add(ip, "resolved_ip", "dns_aaaa")
    for host in _iter_dns_host_values(dns.get("CNAME")):
        add(host, "cname", "cname")
    for host in _iter_dns_host_values(dns.get("MX"), key="exchange"):
        add(host, "mx_host", "mx")
    for host in _iter_dns_host_values(dns.get("NS")):
        add(host, "nameserver", "nameserver")

    for whois_ns in _parse_json_list((result.get("whois") or {}).get("nameservers")):
        add(whois_ns, "whois_nameserver", "whois_nameserver")

    for subdomain in result.get("subdomains", []) or []:
        add(subdomain, "subdomain", "subdomain")
    for subdomain in result.get("zone_transfer", []) or []:
        add(subdomain, "zone_transfer", "zone_transfer")

    historical = result.get("historical_dns", {}) or {}
    for record in historical.get("records", []) or []:
        if str(record.get("rrtype") or "").upper() in {"A", "AAAA"}:
            add(record.get("rdata"), "historical_ip", "historical_dns", record)

    for entry in result.get("spf_origins", []) or []:
        add(entry.get("ip"), "spf_origin", "spf", entry)

    cert_transparency = result.get("cert_transparency", {}) or {}
    for san in cert_transparency.get("cross_domain_sans", []) or []:
        add(san, "cross_domain_san", "cross_san")
    for cert in cert_transparency.get("certs", []) or []:
        for san in cert.get("sans", []) or []:
            add(san, "certificate_san", "ct_san")

    origin = result.get("origin_candidates", {}) or {}
    for key, source_name, relation_name, subdomain_key in [
        ("subdomain_leaks", "subdomain_leak", "subdomain_leak", "subdomain"),
        ("mx_leaks", "mx_leak", "mx_leak", "subdomain"),
        ("wordlist_leaks", "wordlist_leak", "wordlist_leak", "subdomain"),
        ("hackertarget", "subdomain_leak", "hackertarget_host", "subdomain"),
    ]:
        for entry in origin.get(key, []) or []:
            add(entry.get("ip"), "origin_ip", source_name, entry)
            add(entry.get(subdomain_key), relation_name, source_name, entry)

    for entry in origin.get("urlscan", []) or []:
        add(entry.get("ip"), "origin_ip", "origin_hit", entry)
        add(entry.get("url"), "urlscan_url", "urlscan_url", entry)

    for provider_key in ("censys", "shodan", "netlas"):
        provider_result = origin.get(provider_key) or {}
        for hit in provider_result.get("hits", []) or []:
            add(hit.get("ip"), "provider_ip", "provider_hit", hit)
            for hostname in hit.get("hostnames", []) or []:
                add(hostname, "provider_hostname", "provider_hit", hit)

    for scan_key in ("scan", "provider_scan", "country_scan"):
        scan_result = origin.get(scan_key) or {}
        for hit in scan_result.get("hits", []) or []:
            add(hit.get("ip"), "scan_ip", "scan_hit", hit)
            add(hit.get("cn"), "scan_certificate_cn", "tls_cn", hit)
            for san in hit.get("sans", []) or []:
                add(san, "scan_certificate_san", "tls_san", hit)

    ip_details = normalize_ip_details(result.get("ip_details"))
    for ip, info in ip_details.items():
        add(ip, "observed_ip", "origin_hit", {"ip": ip, "sources": info.get("sources")})
        add(info.get("ptr"), "ptr", "ptr", {"ip": ip, "ptr": info.get("ptr")})
        for domain in info.get("other_domains_on_ip", []) or []:
            add(domain, "reverse_ip_domain", "reverse_ip", {"ip": ip, "domain": domain})

    for cert in result.get("non_cf_tls_certs", []) or []:
        add(cert.get("ip"), "tls_ip", "origin_hit", cert)
        add(cert.get("cn"), "tls_cn", "tls_cn", cert)
        for san in cert.get("sans", []) or []:
            add(san, "tls_san", "tls_san", cert)

    if result.get("tls_cert"):
        cert = result.get("tls_cert") or {}
        add(cert.get("ip"), "tls_ip", "origin_hit", cert)
        add(cert.get("cn"), "tls_cn", "tls_cn", cert)
        for san in cert.get("sans", []) or []:
            add(san, "tls_san", "tls_san", cert)

    if result.get("ptr"):
        add(result.get("ptr"), "ptr", "ptr")
    for domain in result.get("other_domains_on_ip", []) or []:
        add(domain, "reverse_ip_domain", "reverse_ip")

    return items


_HARD_CONNECTION_RELATIONS = {
    "resolved_ip",
    "historical_ip",
    "origin_ip",
    "provider_ip",
    "scan_ip",
    "tls_ip",
    "cname",
    "tls_cn",
    "tls_san",
    "scan_certificate_cn",
    "scan_certificate_san",
    "cross_domain_san",
    "certificate_san",
    "subdomain",
    "zone_transfer",
}

_SUPPORTING_CONNECTION_RELATIONS = {
    "spf_origin",
    "mx_host",
    "whois_nameserver",
    "nameserver",
    "provider_hostname",
    "ptr",
    "reverse_ip_domain",
    "subdomain_leak",
    "mx_leak",
    "wordlist_leak",
    "hackertarget_host",
    "urlscan_url",
}


def _classify_connection_strength(relations: set[str]) -> tuple[str, list[str], list[str]]:
    hard_relations = sorted(relation for relation in relations if relation in _HARD_CONNECTION_RELATIONS)
    supporting_relations = sorted(relation for relation in relations if relation in _SUPPORTING_CONNECTION_RELATIONS)
    if hard_relations:
        return "hard", hard_relations, supporting_relations
    if supporting_relations:
        return "supporting", hard_relations, supporting_relations
    return "weak", hard_relations, supporting_relations


def _build_connection_rationale(target_type: str, hard_relations: list[str], supporting_relations: list[str]) -> str:
    relation_set = set(hard_relations)
    if target_type == "ip":
        if "resolved_ip" in relation_set:
            return "This IP is in the seed's live DNS, which is a direct infrastructure tie."
        if "origin_ip" in relation_set:
            return "This IP surfaced as a likely origin from nearby evidence rather than a generic shared-hosting guess."
        if "provider_ip" in relation_set or "scan_ip" in relation_set:
            return "This IP was rediscovered during provider or targeted scan work, which makes it a concrete infrastructure candidate."
        if "historical_ip" in relation_set:
            return "This IP was historically assigned to the seed, so it is a concrete past infrastructure link."
        if "tls_ip" in relation_set:
            return "This IP presented a live certificate during validation, which makes it a concrete HTTPS endpoint tie."
    else:
        if "subdomain" in relation_set or "zone_transfer" in relation_set:
            return "This domain was discovered as part of the seed's own DNS namespace, which is a direct domain relationship."
        if "cname" in relation_set:
            return "This domain is directly referenced in the seed's live DNS via CNAME."
        if {"tls_san", "certificate_san", "scan_certificate_san", "cross_domain_san"} & relation_set:
            return "This domain shares certificate naming evidence with the seed, which is a strong technical overlap."
        if "tls_cn" in relation_set or "scan_certificate_cn" in relation_set:
            return "This domain appears as a certificate common name tied to the seed's infrastructure."

    if supporting_relations:
        return "This target is backed by multiple supporting signals around the seed, but it is not yet a hard link."
    return "This target was discovered near the seed, but the evidence is still limited."


def summarize_related_targets(result: dict[str, Any]) -> dict[str, Any]:
    extracted = extract_related_targets(result)
    grouped: dict[tuple[str, str], dict[str, Any]] = {}

    for item in extracted:
        key = (item["target"], item["target_type"])
        entry = grouped.setdefault(
            key,
            {
                "target": item["target"],
                "target_type": item["target_type"],
                "score": 0,
                "sources": set(),
                "relations": set(),
                "auto_expand": False,
            },
        )
        entry["score"] += int(item.get("score") or 0)
        entry["sources"].add(item["source"])
        entry["relations"].add(item["relation"])

    items = []
    for entry in grouped.values():
        auto_expand = False
        if entry["target_type"] == "ip":
            auto_expand = _is_public_ip(entry["target"])
        elif entry["target_type"] == "domain":
            reverse_ip_only = entry["relations"] == {"reverse_ip_domain"}
            auto_expand = not reverse_ip_only and not _is_noisy_pivot_domain(entry["target"])

        connection_strength, hard_relations, supporting_relations = _classify_connection_strength(entry["relations"])

        items.append(
            {
                "target": entry["target"],
                "target_type": entry["target_type"],
                "score": entry["score"],
                "sources": sorted(entry["sources"]),
                "relations": sorted(entry["relations"]),
                "connection_strength": connection_strength,
                "hard_relations": hard_relations,
                "supporting_relations": supporting_relations,
                "hard_evidence_count": len(hard_relations),
                "evidence_rationale": _build_connection_rationale(entry["target_type"], hard_relations, supporting_relations),
                "auto_expand": auto_expand,
            }
        )

    items.sort(
        key=lambda item: (
            item["connection_strength"] == "hard",
            item["hard_evidence_count"],
            item["score"],
            item["target_type"] == "ip",
            item["target"],
        ),
        reverse=True,
    )
    return {
        "items": items,
        "total": len(items),
        "domains": sum(1 for item in items if item["target_type"] == "domain"),
        "ips": sum(1 for item in items if item["target_type"] == "ip"),
        "expandable": sum(1 for item in items if item["auto_expand"]),
        "hard_total": sum(1 for item in items if item["connection_strength"] == "hard"),
    }


def summarize_hard_connections(
    result: dict[str, Any],
    *,
    related_summary: dict[str, Any] | None = None,
    limit: int = 8,
) -> dict[str, Any]:
    summary = related_summary or result.get("related_targets_summary") or summarize_related_targets(result)
    all_items = [
        item
        for item in (summary.get("items") or [])
        if item.get("connection_strength") == "hard"
    ]
    all_items.sort(
        key=lambda item: (
            item.get("hard_evidence_count", 0),
            item.get("score", 0),
            item.get("target_type") == "ip",
            item.get("target", ""),
        ),
        reverse=True,
    )
    items = all_items[:limit]
    return {
        "items": items,
        "total": len(all_items),
        "shown": len(items),
        "domains": sum(1 for item in all_items if item.get("target_type") == "domain"),
        "ips": sum(1 for item in all_items if item.get("target_type") == "ip"),
    }



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


def _normalize_tls_identity(value: Any) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    if text.startswith("*."):
        text = text[2:]
    return text[4:] if text.startswith("www.") else text


def _text_contains_any(value: Any, patterns: tuple[str, ...]) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    return any(pattern in text for pattern in patterns)


def _is_low_signal_tls_identity(value: Any) -> bool:
    text = _normalize_tls_identity(value)
    if not text:
        return False
    if text in _LOW_SIGNAL_TLS_IDENTITIES:
        return True
    return _text_contains_any(text, _LOW_SIGNAL_TLS_PATTERNS)


def _latest_search_rows(c: psycopg.Connection[Any]) -> list[dict[str, Any]]:
    rows = c.execute(
        "SELECT id, target, type, timestamp, cloudflare_fronted FROM searches ORDER BY target, timestamp DESC, id DESC"
    ).fetchall()
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        norm = _normalize_target(row["target"])
        latest.setdefault(norm, row)
    return list(latest.values())


def _latest_search_id_map(c: psycopg.Connection[Any]) -> dict[str, int]:
    return {_normalize_target(row["target"]): int(row["id"]) for row in _latest_search_rows(c)}


def _search_rows_for_target(c: psycopg.Connection[Any], target: str) -> list[dict[str, Any]]:
    norm = _normalize_target(target)
    rows = c.execute(
        "SELECT id, target, type, timestamp, cloudflare_fronted FROM searches ORDER BY timestamp DESC, id DESC"
    ).fetchall()
    return [row for row in rows if _normalize_target(row["target"]) == norm]


def _latest_row_for_target(c: psycopg.Connection[Any], target: str) -> dict[str, Any] | None:
    rows = _search_rows_for_target(c, target)
    return rows[0] if rows else None


def _query_rows_for_ids(c: psycopg.Connection[Any], query: str, ids: list[int], params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    if not ids:
        return []
    placeholders = ",".join("%s" for _ in ids)
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


def _row_target_list(rows: list[dict[str, Any]], exclude_norm: str | None = None) -> list[str]:
    targets = []
    for row in rows:
        target = row["target"]
        if exclude_norm and _normalize_target(target) == exclude_norm:
            continue
        targets.append(target)
    return _dedup_targets(",".join(targets))


def _stable_text_hash(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (dict, list, tuple, set)):
        text = json.dumps(value, sort_keys=True, default=str)
    else:
        text = str(value)
    text = text.strip()
    if not text:
        return None
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def _normalize_identifier_hash(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    text = re.sub(r"^(sha256|spki|md5):", "", text)
    text = re.sub(r"\s+", "", text)
    if ":" in text and re.fullmatch(r"[0-9a-f:]+", text):
        text = text.replace(":", "")
    return text or None


def _normalize_identifier_email(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if text.startswith("mailto:"):
        text = text[7:]
    if "?" in text:
        text = text.split("?", 1)[0]
    if not text or "@" not in text or " " in text:
        return None
    return text


def _normalize_identifier_phone(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    keep_plus = text.startswith("+")
    digits = re.sub(r"\D+", "", text)
    if len(digits) < 7:
        return None
    return f"+{digits}" if keep_plus else digits


def _normalize_identifier_guid(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    match = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text)
    if match:
        return match.group(0)
    return text if re.fullmatch(r"[0-9a-f]{32}", text) else None


def _normalize_identifier_url(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    email = _normalize_identifier_email(text)
    if email and text.lower().startswith("mailto:"):
        return email

    candidate = text if "://" in text else f"https://{text.lstrip('/')}"
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return None
    host = (parts.hostname or "").strip().lower()
    if not host:
        return None
    scheme = (parts.scheme or "https").lower()
    port = f":{parts.port}" if parts.port and parts.port not in {80, 443} else ""
    path = parts.path.rstrip("/")
    normalized = f"{scheme}://{host}{port}{path}"
    return normalized or None


def _normalize_identifier_host(value: Any, *, allow_generic: bool = False) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None

    target, target_type = _normalize_candidate_target(text)
    if target and target_type in {"domain", "ip"}:
        return target

    if "://" in text:
        try:
            host = urlsplit(text).hostname
        except ValueError:
            host = None
        if host:
            target, _ = _normalize_candidate_target(host)
            if target:
                return target

    if allow_generic:
        return re.sub(r"\s+", " ", text.strip().lower())
    return None


def _normalize_generic_identifier(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    text = text.strip("\"'`")
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text or None


def _normalize_identifier_value(id_type: str, value: Any) -> str | None:
    id_type = str(id_type or "").strip()
    if not id_type:
        return None
    if id_type in _IDENTIFIER_HASH_TYPES:
        return _normalize_identifier_hash(value)
    if id_type in _IDENTIFIER_EMAIL_TYPES:
        return _normalize_identifier_email(value)
    if id_type in _IDENTIFIER_URL_TYPES:
        normalized_url = _normalize_identifier_url(value)
        if normalized_url:
            return normalized_url
        if id_type in {"bimi", "mta_sts", "tls_rpt"}:
            return _normalize_identifier_host(value)
        return None
    if id_type in _IDENTIFIER_HOST_TYPES:
        return _normalize_identifier_host(value, allow_generic=id_type == "nameserver_vanity")
    if id_type in _IDENTIFIER_HANDLE_TYPES:
        text = _normalize_generic_identifier(value)
        return text.lstrip("@") if text else None
    if "guid" in id_type or id_type.endswith("_tenant"):
        normalized = _normalize_identifier_guid(value)
        return normalized or _normalize_generic_identifier(value)
    if id_type.endswith("_phone"):
        return _normalize_identifier_phone(value)
    if id_type.endswith("_email"):
        return _normalize_identifier_email(value)
    if id_type.endswith("_url") or id_type.endswith("_endpoint") or id_type.endswith("_issuer"):
        return _normalize_identifier_url(value)
    return _normalize_generic_identifier(value)


def _iter_flat_scalars(value: Any, *, max_depth: int = 4) -> list[str]:
    if max_depth < 0 or value is None:
        return []
    if isinstance(value, Mapping):
        values: list[str] = []
        for nested in value.values():
            values.extend(_iter_flat_scalars(nested, max_depth=max_depth - 1))
        return values
    if isinstance(value, list | tuple | set):
        values = []
        for nested in value:
            values.extend(_iter_flat_scalars(nested, max_depth=max_depth - 1))
        return values
    text = str(value).strip()
    return [text] if text else []


def _collect_values_for_key_substrings(
    value: Any,
    substrings: tuple[str, ...],
    *,
    max_depth: int = 4,
) -> list[str]:
    if max_depth < 0 or value is None:
        return []
    values: list[str] = []
    if isinstance(value, Mapping):
        for key, nested in value.items():
            key_text = str(key).strip().lower()
            if any(sub in key_text for sub in substrings):
                values.extend(_iter_flat_scalars(nested, max_depth=2))
            values.extend(_collect_values_for_key_substrings(nested, substrings, max_depth=max_depth - 1))
    elif isinstance(value, list | tuple | set):
        for nested in value:
            values.extend(_collect_values_for_key_substrings(nested, substrings, max_depth=max_depth - 1))
    return values


def _collect_url_like_values(value: Any) -> list[str]:
    values = []
    for item in _iter_flat_scalars(value):
        if "://" in item or item.lower().startswith("mailto:"):
            values.append(item)
    return values


def _iter_mapping_entries(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, list | tuple | set):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _extract_dns_txt_token_candidates(dns: Mapping[str, Any]) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    txt_records = _iter_dns_host_values(dns.get("TXT"))
    patterns = [
        ("google_site_verification", re.compile(r"google-site-verification=([A-Za-z0-9._-]+)", re.I)),
        ("facebook_domain_verification", re.compile(r"facebook-domain-verification=([A-Za-z0-9._-]+)", re.I)),
        ("microsoft", re.compile(r"\bms=([A-Za-z0-9._-]+)", re.I)),
        ("stripe_verification", re.compile(r"stripe-verification=([A-Za-z0-9._-]+)", re.I)),
        ("apple_domain_verification", re.compile(r"apple-domain-verification=([A-Za-z0-9._-]+)", re.I)),
        ("zoom_verification", re.compile(r"zoom-domain-verification=([A-Za-z0-9._-]+)", re.I)),
        ("atlassian_domain_verification", re.compile(r"atlassian-domain-verification=([A-Za-z0-9._-]+)", re.I)),
    ]
    for record in txt_records:
        for provider, pattern in patterns:
            for match in pattern.findall(record):
                token = _normalize_generic_identifier(match)
                if token:
                    tokens.append((provider, token))
    return tokens


def _identifier_confidence_label(score: int) -> str:
    if score >= 85:
        return "high"
    if score >= 60:
        return "medium"
    if score >= 30:
        return "low"
    return "very_low"


def _identifier_score(tier: str, category: str, *, multiplier: float = 1.0, bonus: int = 0) -> dict[str, Any]:
    base_score = _IDENTIFIER_TIER_BASE_SCORES.get(tier, 12) + _IDENTIFIER_CATEGORY_SCORE_MODIFIERS.get(category, 0) + bonus
    base_score = max(1, min(100, base_score))
    score = max(0, min(100, int(round(base_score * multiplier))))
    return {
        "base_score": base_score,
        "score": score,
        "confidence": _identifier_confidence_label(score),
        "tier_label": _IDENTIFIER_TIER_LABELS.get(tier, tier),
    }


def _append_identifier(
    items: list[dict[str, Any]],
    seen: set[tuple[str, str, str]],
    *,
    id_type: str,
    value: Any,
    tier: str,
    category: str,
    source: str,
    observed_at: str,
    first_seen: Any = None,
    last_seen: Any = None,
    raw: Any = None,
) -> None:
    normalized = _normalize_identifier_value(id_type, value)
    if not normalized:
        return
    key = (id_type, normalized, source)
    if key in seen:
        return
    seen.add(key)
    items.append(
        {
            "id_type": id_type,
            "id_value": normalized,
            "tier": tier,
            "category": category,
            "source": source,
            "observed_at": observed_at,
            "first_seen": _safe_iso(first_seen),
            "last_seen": _safe_iso(last_seen),
            "raw_json": raw,
        }
    )


def _append_cert_identifiers(
    items: list[dict[str, Any]],
    seen: set[tuple[str, str, str]],
    cert: Mapping[str, Any],
    *,
    source: str,
    observed_at: str,
) -> None:
    not_before = cert.get("not_before")
    not_after = cert.get("not_after")

    _append_identifier(
        items,
        seen,
        id_type="tls_spki_sha256",
        value=cert.get("spki_sha256"),
        tier="tier_1",
        category="tls",
        source=source,
        observed_at=observed_at,
        first_seen=not_before,
        last_seen=not_after,
        raw=cert,
    )
    _append_identifier(
        items,
        seen,
        id_type="tls_sha256",
        value=cert.get("sha256"),
        tier="tier_1",
        category="tls",
        source=source,
        observed_at=observed_at,
        first_seen=not_before,
        last_seen=not_after,
        raw=cert,
    )
    _append_identifier(
        items,
        seen,
        id_type="tls_transport_fingerprint",
        value=cert.get("transport_fingerprint"),
        tier="tier_2",
        category="tls",
        source=source,
        observed_at=observed_at,
        first_seen=not_before,
        last_seen=not_after,
        raw=cert,
    )
    sans = cert.get("sans") or []
    if isinstance(sans, str):
        parsed_sans = _parse_json_list(sans)
        sans = parsed_sans if parsed_sans else [sans]
    for san in sans:
        _append_identifier(
            items,
            seen,
            id_type="certificate_san",
            value=san,
            tier="tier_4",
            category="tls",
            source=f"{source}.sans",
            observed_at=observed_at,
            first_seen=not_before,
            last_seen=not_after,
            raw=cert,
        )

    issuer = cert.get("issuer") or cert.get("issuer_cn") or cert.get("issuer_org")
    issuer_text = _normalize_generic_identifier(issuer)
    if issuer_text and _safe_iso(not_before):
        _append_identifier(
            items,
            seen,
            id_type="cert_issuer_not_before",
            value=f"{issuer_text}|{_safe_iso(not_before)}",
            tier="tier_3",
            category="tls_ct",
            source=source,
            observed_at=observed_at,
            first_seen=not_before,
            last_seen=not_after,
            raw={"issuer": issuer, "not_before": not_before, "not_after": not_after},
        )


def extract_search_identifiers(result: dict[str, Any]) -> list[dict[str, Any]]:
    observed_at = str(result.get("timestamp") or datetime.now(timezone.utc).isoformat())
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    ip_details = normalize_ip_details(result.get("ip_details"))

    def add(
        value: Any,
        *,
        id_type: str,
        tier: str,
        category: str,
        source: str,
        first_seen: Any = None,
        last_seen: Any = None,
        raw: Any = None,
    ) -> None:
        _append_identifier(
            items,
            seen,
            id_type=id_type,
            value=value,
            tier=tier,
            category=category,
            source=source,
            observed_at=observed_at,
            first_seen=first_seen,
            last_seen=last_seen,
            raw=raw,
        )

    def meaningful_ip(ip: Any, *, fallback_sources: list[str] | None = None) -> bool:
        ip_text = str(ip or "").strip()
        if not ip_text or not _is_public_ip(ip_text):
            return False

        info = ip_details.get(ip_text) or {}
        if info.get("cloudflare"):
            return False

        asn_info = info.get("asn_info") or {}
        label = classify_ip(
            ip_text,
            info.get("ptr"),
            asn_info.get("asn"),
            ",".join(info.get("sources") or fallback_sources or []),
            info.get("proxy_family"),
        )
        return not _is_noise_label(label)

    dns = result.get("dns") or {}
    for ip in _iter_dns_host_values(dns.get("A")):
        if meaningful_ip(ip, fallback_sources=["dns"]):
            add(ip, id_type="resolved_ip", tier="tier_2", category="infrastructure", source="dns.A")
    for ip in _iter_dns_host_values(dns.get("AAAA")):
        if meaningful_ip(ip, fallback_sources=["dns"]):
            add(ip, id_type="resolved_ip", tier="tier_2", category="infrastructure", source="dns.AAAA")
    for alias in _iter_dns_host_values(dns.get("CNAME")):
        add(alias, id_type="dns_alias", tier="tier_4", category="dns", source="dns.CNAME")
    for mx in _iter_dns_host_values(dns.get("MX"), key="exchange"):
        add(mx, id_type="mx_host", tier="tier_4", category="email", source="dns.MX")

    for ns in _iter_dns_host_values(dns.get("NS")):
        add(ns, id_type="nameserver", tier="tier_4", category="nameserver", source="dns.NS")

    caa_values = dns.get("CAA") or []
    if isinstance(caa_values, list):
        iterable_caa = caa_values
    else:
        iterable_caa = [caa_values]
    for value in iterable_caa:
        candidate = None
        if isinstance(value, Mapping):
            candidate = value.get("value") or value.get("issuer") or value.get("ca")
        else:
            text = str(value or "").strip()
            match = re.search(r'"([^"]+\.[^"]+)"', text)
            candidate = match.group(1) if match else text
        add(candidate, id_type="dns_caa", tier="tier_4", category="dns", source="dns.CAA", raw=value)

    for provider, token in _extract_dns_txt_token_candidates(dns):
        add(f"{provider}|{token}", id_type="dns_txt_token", tier="tier_3", category="dns", source="dns.TXT")

    for token_entry in result.get("dns_txt_tokens") or result.get("dns_txt_verification_tokens") or []:
        if isinstance(token_entry, Mapping):
            provider = _normalize_generic_identifier(token_entry.get("provider")) or "unknown"
            token = _normalize_generic_identifier(token_entry.get("token") or token_entry.get("value"))
            if token:
                add(
                    f"{provider}|{token}",
                    id_type="dns_txt_token",
                    tier="tier_3",
                    category="dns",
                    source="dns_txt_tokens",
                    raw=token_entry,
                )

    historical = result.get("historical_dns") or {}
    for record in historical.get("records") or []:
        rrtype = str(record.get("rrtype") or "").upper()
        if rrtype in {"A", "AAAA"} and meaningful_ip(record.get("rdata"), fallback_sources=["historical_dns"]):
            add(
                record.get("rdata"),
                id_type="historical_ip",
                tier="tier_4",
                category="infrastructure",
                source="historical_dns",
                first_seen=record.get("first_seen"),
                last_seen=record.get("last_seen"),
                raw=record,
            )

    for subdomain in _normalize_text_list(result.get("subdomains") or []):
        add(subdomain, id_type="subdomain_name", tier="tier_4", category="dns", source="subdomains")
    for subdomain in _normalize_text_list(result.get("zone_transfer") or []):
        add(subdomain, id_type="subdomain_name", tier="tier_4", category="dns", source="zone_transfer")

    for entry in result.get("spf_origins") or []:
        if meaningful_ip(entry.get("ip"), fallback_sources=["spf"]):
            add(
                entry.get("ip"),
                id_type="origin_ip",
                tier="tier_4",
                category="email",
                source="spf_origins",
                raw=entry,
            )

    whois_row = result.get("whois") or {}
    if isinstance(whois_row, Mapping) and not whois_row.get("error"):
        for email in _normalize_text_list(whois_row.get("emails")):
            add(email, id_type="registrant_email", tier="tier_3", category="identity", source="whois.emails")
        for nameserver in _normalize_nameservers(whois_row.get("nameservers")):
            add(nameserver, id_type="nameserver", tier="tier_4", category="nameserver", source="whois.nameservers")

    nameserver_analysis = result.get("nameserver_analysis") or {}
    for candidate in _iter_flat_scalars(nameserver_analysis.get("vanity_candidates")):
        add(
            candidate,
            id_type="nameserver_vanity",
            tier="tier_3",
            category="nameserver",
            source="nameserver_analysis.vanity_candidates",
            raw=candidate,
        )

    page = result.get("page_metadata") or {}
    for id_type, keys in [
        ("ga_property", ("google_analytics", "ga_ids")),
        ("gtm_container", ("gtm_ids", "google_tag_manager")),
        ("fb_pixel", ("facebook_pixel",)),
        ("tiktok_pixel", ("tiktok_pixel",)),
        ("yandex_metrika", ("yandex_metrika",)),
        ("adsense_publisher", ("adsense_publisher_ids",)),
        ("fb_app_id", ("fb_app_id", "facebook_app_id")),
    ]:
        for key in keys:
            for value in _normalize_text_list(page.get(key) or []):
                add(value, id_type=id_type, tier="tier_2", category="tracking", source=f"page_metadata.{key}")

    add(page.get("favicon_mmh3"), id_type="favicon_mmh3", tier="tier_2", category="content", source="page_metadata.favicon_mmh3")
    add(page.get("favicon_md5"), id_type="favicon_md5", tier="tier_3", category="content", source="page_metadata.favicon_md5")
    add(page.get("homepage_html_hash"), id_type="homepage_html_hash", tier="tier_2", category="content", source="page_metadata.homepage_html_hash")
    if page.get("http_fingerprint"):
        add(
            _stable_text_hash(page.get("http_fingerprint")),
            id_type="http_fingerprint",
            tier="tier_2",
            category="content",
            source="page_metadata.http_fingerprint",
            raw=page.get("http_fingerprint"),
        )

    for value in _normalize_text_list(page.get("rel_me") or []):
        add(value, id_type="rel_me_url", tier="tier_3", category="social", source="page_metadata.rel_me")

    for value in _normalize_text_list(page.get("authors") or []):
        add(value, id_type="author", tier="tier_4", category="social", source="page_metadata.authors")

    for value in _normalize_text_list(page.get("twitter_site") or []):
        add(value, id_type="twitter_site", tier="tier_3", category="social", source="page_metadata.twitter_site")
    for value in _normalize_text_list(page.get("twitter_creator") or []):
        add(value, id_type="twitter_creator", tier="tier_3", category="social", source="page_metadata.twitter_creator")

    handles = page.get("social_handles") or {}
    for platform, platform_handles in handles.items():
        for handle in _normalize_text_list(platform_handles or []):
            add(
                f"{_normalize_generic_identifier(platform) or platform}|{handle}",
                id_type="social_handle",
                tier="tier_3",
                category="social",
                source=f"page_metadata.social_handles.{platform}",
            )

    social_links = page.get("social_links") or {}
    for platform, urls in social_links.items():
        for url in _normalize_text_list(urls or []):
            add(
                url,
                id_type="social_url",
                tier="tier_4",
                category="social",
                source=f"page_metadata.social_links.{platform}",
            )

    meta_tags = page.get("meta_tags") or {}
    for value in _collect_values_for_key_substrings(meta_tags, ("twitter:", "og:", "social", "author")):
        if "://" in value:
            add(value, id_type="social_url", tier="tier_4", category="social", source="page_metadata.meta_tags")
        else:
            add(value, id_type="meta_social_handle", tier="tier_4", category="social", source="page_metadata.meta_tags")

    for url in _normalize_text_list(page.get("script_assets") or []):
        add(url, id_type="script_asset_url", tier="tier_4", category="content", source="page_metadata.script_assets")
        add(url, id_type="script_asset_host", tier="tier_4", category="content", source="page_metadata.script_assets")

    for leak in page.get("source_map_leaks") or []:
        leak_urls = []
        if isinstance(leak, Mapping):
            for key in ("url", "asset_url", "source_map_url", "map_url"):
                if leak.get(key):
                    leak_urls.append(leak.get(key))
        else:
            leak_urls.append(leak)
        for url in leak_urls:
            add(url, id_type="source_map_url", tier="tier_3", category="content", source="page_metadata.source_map_leaks", raw=leak)
            add(url, id_type="source_map_host", tier="tier_4", category="content", source="page_metadata.source_map_leaks", raw=leak)

    email_security = result.get("email_security") or {}
    for include in _normalize_text_list(email_security.get("spf_includes") or []):
        add(include, id_type="spf_include", tier="tier_4", category="email", source="email_security.spf_includes")

    dmarc_report_uris = email_security.get("dmarc_report_uris") or {}
    for key, id_type in [
        ("dmarc_rua", "dmarc_rua"),
        ("dmarc_ruf", "dmarc_ruf"),
        ("tls_rpt_rua", "tls_rpt_rua"),
    ]:
        for value in _normalize_text_list(email_security.get(key)):
            add(value, id_type=id_type, tier="tier_3", category="email", source=f"email_security.{key}")
    for key, id_type in [
        ("rua", "dmarc_rua"),
        ("ruf", "dmarc_ruf"),
    ]:
        for value in _normalize_text_list((dmarc_report_uris or {}).get(key)):
            add(value, id_type=id_type, tier="tier_3", category="email", source=f"email_security.dmarc_report_uris.{key}")

    for key, id_type in [
        ("tls_rpt", "tls_rpt"),
        ("bimi", "bimi"),
        ("mta_sts", "mta_sts"),
    ]:
        field = email_security.get(key)
        if not field:
            continue
        if isinstance(field, Mapping):
            for value in _collect_url_like_values(field):
                add(value, id_type=id_type, tier="tier_3", category="policy", source=f"email_security.{key}", raw=field)
            for value in _collect_values_for_key_substrings(field, ("name", "url", "location", "host", "domain")):
                add(value, id_type=id_type, tier="tier_3", category="policy", source=f"email_security.{key}", raw=field)
        else:
            add(field, id_type=id_type, tier="tier_3", category="policy", source=f"email_security.{key}", raw=field)

    microsoft_tenant = result.get("microsoft_tenant") or {}
    add(
        microsoft_tenant.get("tenant_guid") or microsoft_tenant.get("tenant_id"),
        id_type="microsoft_tenant_guid",
        tier="tier_1",
        category="identity",
        source="microsoft_tenant.tenant_guid",
        raw=microsoft_tenant,
    )
    for key, id_type in [
        ("issuer", "openid_issuer"),
        ("authorization_endpoint", "openid_authorization_endpoint"),
        ("token_endpoint", "openid_token_endpoint"),
        ("userinfo_endpoint", "openid_userinfo_endpoint"),
        ("jwks_uri", "openid_jwks_uri"),
        ("registration_endpoint", "openid_registration_endpoint"),
    ]:
        if microsoft_tenant.get(key):
            add(microsoft_tenant.get(key), id_type=id_type, tier="tier_2", category="identity", source=f"microsoft_tenant.{key}", raw=microsoft_tenant)

    mail_client_config = result.get("mail_client_config") or result.get("mail_config") or {}
    for key, payload in (mail_client_config.items() if isinstance(mail_client_config, Mapping) else []):
        source = f"mail_client_config.{key}"
        mapping_entries = _iter_mapping_entries(payload)
        if not mapping_entries:
            mapping_entries = [{key: payload}]

        for entry in mapping_entries:
            for value in _collect_url_like_values(entry):
                add(value, id_type="mail_client_url", tier="tier_3", category="email", source=source, raw=entry)
            for domain in _normalize_text_list(entry.get("domains") or []):
                add(domain, id_type="mail_client_domain", tier="tier_3", category="email", source=source, raw=entry)
            for domain in _collect_values_for_key_substrings(entry.get("parsed"), ("domain",)):
                add(domain, id_type="mail_client_domain", tier="tier_3", category="email", source=source, raw=entry)
            for email in _normalize_text_list(entry.get("emails") or []):
                add(email, id_type="mail_client_email", tier="tier_3", category="email", source=source, raw=entry)
            for email in _collect_values_for_key_substrings(entry.get("parsed"), ("email",)):
                add(email, id_type="mail_client_email", tier="tier_3", category="email", source=source, raw=entry)
            for server in _normalize_text_list(entry.get("servers") or []):
                add(server, id_type="mail_client_server", tier="tier_3", category="email", source=source, raw=entry)
            for server in _collect_values_for_key_substrings(entry.get("parsed"), ("server", "hostname", "host")):
                add(server, id_type="mail_client_server", tier="tier_3", category="email", source=source, raw=entry)

    well_known = result.get("well_known") or {}
    apple = well_known.get("apple_app_site_association") or {}
    for value in _collect_values_for_key_substrings(apple, ("appid", "app_id")):
        add(value, id_type="apple_app_id", tier="tier_2", category="identity", source="well_known.apple_app_site_association", raw=apple)

    assetlinks = well_known.get("assetlinks") or []
    for value in _collect_values_for_key_substrings(assetlinks, ("package",)):
        add(value, id_type="android_package", tier="tier_2", category="identity", source="well_known.assetlinks", raw=assetlinks)
    for value in _collect_values_for_key_substrings(assetlinks, ("sha256", "fingerprint")):
        add(value, id_type="android_cert_sha256", tier="tier_1", category="identity", source="well_known.assetlinks", raw=assetlinks)

    security_txt = well_known.get("security_txt") or {}
    for value in _collect_values_for_key_substrings(security_txt, ("contact", "mail", "email")):
        add(value, id_type="contact_email", tier="tier_3", category="policy", source="well_known.security_txt", raw=security_txt)
    for value in _collect_url_like_values(security_txt):
        add(value, id_type="policy_url", tier="tier_4", category="policy", source="well_known.security_txt", raw=security_txt)

    openid_configuration = well_known.get("openid_configuration") or {}
    for key, id_type in [
        ("issuer", "openid_issuer"),
        ("authorization_endpoint", "openid_authorization_endpoint"),
        ("token_endpoint", "openid_token_endpoint"),
        ("userinfo_endpoint", "openid_userinfo_endpoint"),
        ("jwks_uri", "openid_jwks_uri"),
        ("registration_endpoint", "openid_registration_endpoint"),
    ]:
        if openid_configuration.get(key):
            add(openid_configuration.get(key), id_type=id_type, tier="tier_2", category="identity", source=f"well_known.openid_configuration.{key}", raw=openid_configuration)

    for key in ("mta_sts_file", "humans_txt", "ads_txt"):
        payload = well_known.get(key)
        if payload:
            add(
                _stable_text_hash(payload.get("raw") if isinstance(payload, Mapping) else payload),
                id_type="well_known_text_hash",
                tier="tier_4",
                category="content",
                source=f"well_known.{key}",
                raw={"artifact": key},
            )

    legal_pages = result.get("legal_pages") or []
    for page_entry in legal_pages:
        if not isinstance(page_entry, Mapping):
            continue
        add(page_entry.get("text_hash"), id_type="legal_text_hash", tier="tier_2", category="legal", source="legal_pages.text_hash", raw={"url": page_entry.get("url")})
        for value in _collect_values_for_key_substrings(page_entry, ("email", "mail")):
            add(value, id_type="contact_email", tier="tier_3", category="legal", source="legal_pages.contact", raw=page_entry)
        for value in _collect_values_for_key_substrings(page_entry, ("phone", "tel", "mobile")):
            add(value, id_type="legal_phone", tier="tier_3", category="legal", source="legal_pages.phone", raw=page_entry)
        for value in _collect_values_for_key_substrings(page_entry, ("address", "street", "city", "postal")):
            add(value, id_type="legal_address", tier="tier_4", category="legal", source="legal_pages.address", raw=page_entry)
        for value in _collect_values_for_key_substrings(page_entry, ("entity", "company", "organisation", "organization", "holder", "owner")):
            add(value, id_type="legal_entity", tier="tier_4", category="legal", source="legal_pages.entity", raw=page_entry)
        for value in _collect_values_for_key_substrings(page_entry, ("vat", "register", "registry", "registration", "company_number", "company-id", "reg")):
            add(value, id_type="legal_registration", tier="tier_3", category="legal", source="legal_pages.registration", raw=page_entry)

    for cert in result.get("non_cf_tls_certs") or ([] if not result.get("tls_cert") else [result.get("tls_cert")]):
        if isinstance(cert, Mapping):
            _append_cert_identifiers(items, seen, cert, source="tls_certs", observed_at=observed_at)

    for followup in result.get("subdomain_followups") or []:
        if not isinstance(followup, Mapping):
            continue
        subdomain = _normalize_identifier_host(followup.get("subdomain"))
        if subdomain:
            add(subdomain, id_type="subdomain_name", tier="tier_4", category="dns", source="subdomain_followups")

        nested_result = followup.get("result")
        if not isinstance(nested_result, Mapping):
            continue

        nested_source_prefix = f"subdomain_followups.{subdomain or _normalize_identifier_host(nested_result.get('input')) or 'unknown'}"
        for nested_item in extract_search_identifiers(dict(nested_result)):
            _append_identifier(
                items,
                seen,
                id_type=nested_item["id_type"],
                value=nested_item["id_value"],
                tier=nested_item["tier"],
                category=nested_item["category"],
                source=f"{nested_source_prefix}.{nested_item['source']}",
                observed_at=nested_item.get("observed_at") or observed_at,
                first_seen=nested_item.get("first_seen"),
                last_seen=nested_item.get("last_seen"),
                raw={
                    "subdomain": subdomain,
                    "status": followup.get("status"),
                    "identifier": nested_item.get("raw_json"),
                },
            )

    origin = result.get("origin_candidates") or {}
    for key in ("subdomain_leaks", "mx_leaks", "wordlist_leaks", "hackertarget", "urlscan"):
        for entry in origin.get(key) or []:
            if meaningful_ip((entry or {}).get("ip"), fallback_sources=[key]):
                add((entry or {}).get("ip"), id_type="origin_ip", tier="tier_4", category="infrastructure", source=f"origin_candidates.{key}", raw=entry)

    for provider_key in ("censys", "shodan", "netlas"):
        provider_result = origin.get(provider_key) or {}
        for hit in provider_result.get("hits") or []:
            if meaningful_ip(hit.get("ip"), fallback_sources=[provider_key]):
                add(hit.get("ip"), id_type="provider_ip", tier="tier_3", category="infrastructure", source=f"origin_candidates.{provider_key}", raw=hit)
            for hostname in hit.get("hostnames") or []:
                add(hostname, id_type="provider_hostname", tier="tier_4", category="infrastructure", source=f"origin_candidates.{provider_key}.hostnames", raw=hit)
            _append_cert_identifiers(items, seen, hit, source=f"origin_candidates.{provider_key}", observed_at=observed_at)

    for scan_key in ("scan", "provider_scan", "country_scan"):
        scan_result = origin.get(scan_key) or {}
        if not isinstance(scan_result, Mapping) or scan_result.get("skipped"):
            continue
        for hit in scan_result.get("hits") or []:
            if meaningful_ip(hit.get("ip"), fallback_sources=[scan_key]):
                add(hit.get("ip"), id_type="scan_ip", tier="tier_3", category="infrastructure", source=f"origin_candidates.{scan_key}", raw=hit)
            _append_cert_identifiers(items, seen, hit, source=f"origin_candidates.{scan_key}", observed_at=observed_at)

    cert_transparency = result.get("cert_transparency") or {}
    for san in _normalize_text_list(cert_transparency.get("cross_domain_sans") or []):
        add(san, id_type="cross_san_domain", tier="tier_3", category="tls_ct", source="cert_transparency.cross_domain_sans")
    for cert in cert_transparency.get("certs") or []:
        if isinstance(cert, Mapping):
            _append_cert_identifiers(items, seen, cert, source="cert_transparency", observed_at=observed_at)

    for ssh_key in result.get("ssh_host_keys") or []:
        if not isinstance(ssh_key, Mapping):
            continue
        add(ssh_key.get("sha256") or ssh_key.get("fingerprint_sha256"), id_type="ssh_host_key_sha256", tier="tier_1", category="ssh", source="ssh_host_keys", raw=ssh_key)
        add(ssh_key.get("md5") or ssh_key.get("fingerprint_md5"), id_type="ssh_host_key_md5", tier="tier_2", category="ssh", source="ssh_host_keys", raw=ssh_key)

    return items


def _refresh_search_identifiers(c: psycopg.Connection[Any], search_id: int, payload: dict[str, Any]) -> None:
    observed_at = str(payload.get("timestamp") or datetime.now(timezone.utc).isoformat())
    c.execute("DELETE FROM identifiers WHERE search_id = %s", (search_id,))
    for item in extract_search_identifiers(payload):
        c.execute(
            """INSERT INTO identifiers
               (search_id, id_type, id_value, tier, category, source, observed_at, first_seen, last_seen, raw_json)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                search_id,
                item["id_type"],
                item["id_value"],
                item["tier"],
                item["category"],
                item["source"],
                item.get("observed_at") or observed_at,
                item.get("first_seen"),
                item.get("last_seen"),
                _json(item.get("raw_json")),
            ),
        )



# ── Incremental persistence helpers ──────────────────────────────────────────

def _load_result_from_fields(c: psycopg.Connection[Any], search_id: int) -> dict | None:
    rows = c.execute(
        "SELECT key, json_value FROM search_fields WHERE search_id = %s", (search_id,)
    ).fetchall()
    if not rows:
        return None
    # json_value is JSONB, so psycopg already returns parsed Python values.
    return {row["key"]: row["json_value"] for row in rows}


def create_search(target: str, typ: str, timestamp: str) -> int:
    """Insert the searches row upfront and return search_id; fields written later."""
    init_db()
    with _conn() as c:
        row = c.execute(
            "INSERT INTO searches (target, type, timestamp, raw_json) VALUES (%s,%s,%s,'') RETURNING id",
            (target, typ, timestamp),
        ).fetchone()
        return int(row["id"])


def save_search_fields(search_id: int, fields: dict[str, Any]) -> None:
    """Upsert a batch of result fields into search_fields."""
    with _conn() as c:
        for key, value in fields.items():
            c.execute(
                "INSERT INTO search_fields (search_id, key, json_value) VALUES (%s,%s,%s) "
                "ON CONFLICT (search_id, key) DO UPDATE SET json_value = EXCLUDED.json_value",
                (search_id, key, _json(value)),
            )


def _save_child_tables(c: psycopg.Connection[Any], sid: int, result: dict, timestamp: str) -> None:
    """Write all structured child table rows from a result dict."""
    typ = result.get("type", "unknown")
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
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        sid, ip, source, cf_value,
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
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                sid, result.get("input", ""), "direct",
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
               (search_id, ip, port, sni_used, cn, sans, issuer_cn, issuer_org, not_before, not_after, sha256, spki_sha256, observed_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                sid,
                cert.get("ip"), cert.get("port", 443), cert.get("sni_used"),
                cert.get("cn"), _json(cert.get("sans", [])),
                cert.get("issuer_cn"), cert.get("issuer_org"),
                cert.get("not_before"), cert.get("not_after"),
                cert.get("sha256"), cert.get("spki_sha256"), timestamp,
            ),
        )

    origin = result.get("origin_candidates") or {}
    for scan_key, scan_label in [("scan", "gcp"), ("provider_scan", "asn"), ("country_scan", "country")]:
        scan_result = origin.get(scan_key) or {}
        if not isinstance(scan_result, dict) or scan_result.get("skipped"):
            continue
        for hit in scan_result.get("hits") or []:
            if not hit.get("ip"):
                continue
            c.execute(
                """INSERT INTO scan_hits
                   (search_id, scan_type, ip, port, cn, sans, issuer, not_before, not_after, sha256, spki_sha256, cloudflare, observed_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    sid, scan_label, hit.get("ip"), hit.get("port", 443),
                    hit.get("cn"), _json(hit.get("sans", [])),
                    hit.get("issuer") or hit.get("issuer_cn"),
                    hit.get("not_before"), hit.get("not_after"),
                    hit.get("sha256"), hit.get("spki_sha256"),
                    1 if hit.get("cloudflare") else 0, timestamp,
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
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    sid, provider, hit.get("ip"), hit.get("port"), hit.get("protocol"),
                    _normalize_asn(hit.get("asn")),
                    hit.get("asn_name") or hit.get("asn_desc"),
                    hit.get("org"), hit.get("country"),
                    1 if hit.get("cloudflare") else 0,
                    _json(hit.get("services", [])), _json(hit.get("hostnames", [])),
                    provider_result.get("mode"), provider_result.get("status"),
                    provider_result.get("query_type"), provider_result.get("total"),
                    timestamp, _json(hit),
                ),
            )

    ct = result.get("cert_transparency", {})
    for cert in ct.get("certs", []):
        c.execute(
            "INSERT INTO ct_certs (search_id, cert_id, issuer, not_before, not_after, sans, observed_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (sid, cert.get("id"), cert.get("issuer"), cert.get("not_before"), cert.get("not_after"), _json(cert.get("sans", [])), timestamp),
        )
    for san in ct.get("cross_domain_sans", []):
        c.execute("INSERT INTO cross_sans (search_id, san) VALUES (%s,%s)", (sid, san))

    for sub in result.get("subdomains", []):
        c.execute("INSERT INTO subdomains (search_id, subdomain, source) VALUES (%s,%s,%s)", (sid, sub, "crt.sh"))
    for sub in result.get("zone_transfer", []):
        c.execute("INSERT INTO subdomains (search_id, subdomain, source) VALUES (%s,%s,%s)", (sid, sub, "zone_transfer"))

    dns = result.get("dns", {})
    for rtype, values in dns.items():
        if not values:
            continue
        if isinstance(values, list):
            for value in values:
                c.execute(
                    "INSERT INTO dns_records (search_id, rtype, value) VALUES (%s,%s,%s)",
                    (sid, rtype, _json(value) if isinstance(value, dict) else str(value)),
                )
        elif isinstance(values, dict):
            c.execute("INSERT INTO dns_records (search_id, rtype, value) VALUES (%s,%s,%s)", (sid, rtype, _json(values)))

    for rec in result.get("historical_dns", {}).get("records", []):
        c.execute(
            "INSERT INTO historical_dns (search_id, rrtype, rdata, first_seen, last_seen) VALUES (%s,%s,%s,%s,%s)",
            (sid, rec.get("rrtype"), rec.get("rdata"), rec.get("first_seen"), rec.get("last_seen")),
        )

    for entry in result.get("spf_origins", []):
        c.execute("INSERT INTO spf_origins (search_id, ip, cidr) VALUES (%s,%s,%s)", (sid, entry.get("ip"), entry.get("cidr")))

    whois_row = result.get("whois", {})
    if whois_row and not whois_row.get("error"):
        emails_raw = whois_row.get("emails") or []
        if isinstance(emails_raw, str):
            emails_raw = [emails_raw]
        ns_raw = _normalize_nameservers(whois_row.get("nameservers") or [])
        c.execute(
            """INSERT INTO whois_data
               (search_id, registrar, creation_date, expiry_date, org, country, emails, nameservers)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                sid,
                str(whois_row.get("registrar") or ""),
                str(whois_row.get("creation_date") or "")[:30],
                str(whois_row.get("expiry_date") or "")[:30],
                str(whois_row.get("org") or ""),
                str(whois_row.get("country") or ""),
                _json(emails_raw), _json(ns_raw),
            ),
        )
        for email in emails_raw:
            if email and isinstance(email, str):
                c.execute("INSERT INTO registrant_emails (search_id, email) VALUES (%s,%s)", (sid, email.lower().strip()))
        for nameserver in ns_raw:
            c.execute("INSERT INTO nameservers (search_id, nameserver) VALUES (%s,%s)", (sid, nameserver))

    meta = result.get("page_metadata", {})
    for id_type, key in [
        ("ga", "google_analytics"), ("gtm", "gtm_ids"), ("fb_pixel", "facebook_pixel"),
        ("tiktok_pixel", "tiktok_pixel"), ("yandex_metrika", "yandex_metrika"), ("adsense", "adsense_publisher_ids"),
    ]:
        for value in (meta.get(key) or []):
            c.execute("INSERT INTO tracking_ids (search_id, id_type, id_value) VALUES (%s,%s,%s)", (sid, id_type, str(value)))

    handles = meta.get("social_handles", {})
    links = meta.get("social_links", {})
    for platform in set(handles) | set(links):
        urls = links.get(platform) or []
        for handle in (handles.get(platform) or []):
            c.execute(
                "INSERT INTO social_accounts (search_id, platform, handle, url) VALUES (%s,%s,%s,%s)",
                (sid, platform, handle, urls[0] if urls else None),
            )

    favicon_md5 = meta.get("favicon_md5")
    if favicon_md5:
        c.execute("INSERT INTO favicons (search_id, md5) VALUES (%s,%s)", (sid, favicon_md5))

    email_security = result.get("email_security", {})
    c.execute(
        "INSERT INTO page_metadata (search_id, html_lang, cms_generator, favicon_md5, dmarc) VALUES (%s,%s,%s,%s,%s)",
        (sid, meta.get("html_lang"), meta.get("cms_generator"), favicon_md5, email_security.get("dmarc")),
    )

    for item in extract_related_targets(result):
        c.execute(
            """INSERT INTO discovered_targets
               (search_id, target, target_type, relation, source, score, observed_at, raw_json)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                sid, item["target"], item["target_type"], item["relation"],
                item["source"], int(item.get("score") or 0), timestamp, _json(item.get("raw_json")),
            ),
        )

    _refresh_search_identifiers(c, sid, result)


def finalize_search(search_id: int, result: dict, *, timestamp: str) -> None:
    """Complete a search: save all fields to search_fields + child tables, update searches row."""
    cf = result.get("cloudflare_fronted")
    cf_val = 1 if cf else (0 if cf is not None else None)
    source_errors = result.get("source_errors")
    related_summary = summarize_related_targets(result)

    result["search_id"] = search_id
    result["related_targets_summary"] = related_summary

    with _conn() as c:
        c.execute(
            "UPDATE searches SET cloudflare_fronted = %s, source_errors = %s WHERE id = %s",
            (cf_val, _json(source_errors) if source_errors else None, search_id),
        )
        _save_child_tables(c, search_id, result, timestamp)
        for key, value in result.items():
            c.execute(
                "INSERT INTO search_fields (search_id, key, json_value) VALUES (%s,%s,%s) "
                "ON CONFLICT (search_id, key) DO UPDATE SET json_value = EXCLUDED.json_value",
                (search_id, key, _json(value)),
            )
        c.execute(
            "INSERT INTO search_fields (search_id, key, json_value) VALUES (%s,%s,%s) "
                "ON CONFLICT (search_id, key) DO UPDATE SET json_value = EXCLUDED.json_value",
            (search_id, "related_targets_summary", _json(related_summary)),
        )

    # Derived correlation layer, in its own transaction: the raw append-only save
    # above is already committed, so a projection failure can never lose intel.
    try:
        with _conn() as c:
            persist_correlation(c, result, search_id=search_id, recount=True)
    except Exception:  # pragma: no cover - defensive; correlation is rebuildable
        pass


def get_result(search_id: int) -> dict | None:
    init_db()
    with _conn() as c:
        meta = c.execute(
            "SELECT target, type, timestamp, cloudflare_fronted FROM searches WHERE id = %s",
            (search_id,),
        ).fetchone()
        if not meta:
            return None
        result = _load_result_from_fields(c, search_id)
    if result is None:
        return None
    result.setdefault("input", meta["target"])
    result.setdefault("type", meta["type"])
    result.setdefault("timestamp", meta["timestamp"])
    result["search_id"] = search_id
    return result


# ── Save ──────────────────────────────────────────────────────────────────────

def save_search(result: dict) -> int:
    """Insert a completed analysis result; delegates to create_search + finalize_search."""
    init_db()
    target = result.get("input", "")
    typ = result.get("type", "unknown")
    timestamp = result.get("timestamp", datetime.now(timezone.utc).isoformat())
    sid = create_search(target, typ, timestamp)
    finalize_search(sid, result, timestamp=timestamp)
    return sid




# ── Correlation layer: upsert helpers ───────────────────────────────────────
#
# These operate on a caller-supplied connection so a single ingest/backfill can
# batch many upserts inside one transaction (mirroring _save_child_tables). They
# are idempotent: re-running widens the observed time window rather than
# duplicating rows, which is what makes a global recompute deterministic.
#
# Time columns are ISO-8601 TEXT, matching the rest of the schema. LEAST/GREATEST
# ignore NULLs and compare ISO strings lexicographically (correct for a fixed
# format), so windows widen monotonically across repeated observations.

def upsert_entity(
    c: psycopg.Connection[Any],
    *,
    kind: str,
    value: str,
    registrable_domain: str | None,
    first_seen: str | None = None,
    last_seen: str | None = None,
) -> int:
    """Insert-or-widen an entity; returns its id. Unique on (kind, value)."""
    row = c.execute(
        """INSERT INTO entities (kind, value, registrable_domain, first_seen, last_seen)
           VALUES (%s,%s,%s,%s,%s)
           ON CONFLICT (kind, value) DO UPDATE SET
               registrable_domain = COALESCE(EXCLUDED.registrable_domain, entities.registrable_domain),
               first_seen = LEAST(entities.first_seen, EXCLUDED.first_seen),
               last_seen  = GREATEST(entities.last_seen, EXCLUDED.last_seen)
           RETURNING id""",
        (kind, value, registrable_domain, _safe_iso(first_seen), _safe_iso(last_seen)),
    ).fetchone()
    return int(row["id"])


def upsert_entity_value(
    c: psycopg.Connection[Any],
    value: Any,
    *,
    first_seen: str | None = None,
    last_seen: str | None = None,
) -> int | None:
    """Classify a raw value and upsert it as an entity; None if not a host/IP."""
    info = classify_entity(value)
    if info is None:
        return None
    return upsert_entity(
        c,
        kind=info["kind"],
        value=info["value"],
        registrable_domain=info["registrable_domain"],
        first_seen=first_seen,
        last_seen=last_seen,
    )


def upsert_selector(
    c: psycopg.Connection[Any],
    *,
    kind: str,
    value: str,
    first_seen: str | None = None,
    last_seen: str | None = None,
) -> int:
    """Insert-or-widen a selector; returns its id. Unique on (kind, value).

    Does not touch `attributing` or `entity_count` on conflict: the denylist
    (attributing) and degree (entity_count) are maintained by dedicated helpers
    so repeated observation never clobbers a noise decision.
    """
    row = c.execute(
        """INSERT INTO selectors (kind, value, entity_count, attributing, first_seen, last_seen)
           VALUES (%s,%s,0,TRUE,%s,%s)
           ON CONFLICT (kind, value) DO UPDATE SET
               first_seen = LEAST(selectors.first_seen, EXCLUDED.first_seen),
               last_seen  = GREATEST(selectors.last_seen, EXCLUDED.last_seen)
           RETURNING id""",
        (kind, value, _safe_iso(first_seen), _safe_iso(last_seen)),
    ).fetchone()
    return int(row["id"])


def record_observation(
    c: psycopg.Connection[Any],
    *,
    entity_id: int,
    selector_id: int,
    source: str,
    first_seen: str | None = None,
    last_seen: str | None = None,
    search_id: int | None = None,
) -> None:
    """Insert-or-widen a provenance-bearing entity→selector edge."""
    c.execute(
        """INSERT INTO observations (entity_id, selector_id, source, first_seen, last_seen, search_id)
           VALUES (%s,%s,%s,%s,%s,%s)
           ON CONFLICT (entity_id, selector_id, source) DO UPDATE SET
               first_seen = LEAST(observations.first_seen, EXCLUDED.first_seen),
               last_seen  = GREATEST(observations.last_seen, EXCLUDED.last_seen),
               search_id  = COALESCE(observations.search_id, EXCLUDED.search_id)""",
        (entity_id, selector_id, str(source or ""), _safe_iso(first_seen), _safe_iso(last_seen), search_id),
    )


def record_entity_edge(
    c: psycopg.Connection[Any],
    *,
    src_entity_id: int,
    dst_entity_id: int,
    kind: str,
    source: str = "",
    first_seen: str | None = None,
    last_seen: str | None = None,
) -> None:
    """Insert-or-widen a structural entity→entity edge (resolves_to / subdomain_of)."""
    c.execute(
        """INSERT INTO entity_edges (src_entity_id, dst_entity_id, kind, source, first_seen, last_seen)
           VALUES (%s,%s,%s,%s,%s,%s)
           ON CONFLICT (src_entity_id, dst_entity_id, kind) DO UPDATE SET
               first_seen = LEAST(entity_edges.first_seen, EXCLUDED.first_seen),
               last_seen  = GREATEST(entity_edges.last_seen, EXCLUDED.last_seen)""",
        (src_entity_id, dst_entity_id, str(kind), str(source or ""), _safe_iso(first_seen), _safe_iso(last_seen)),
    )


def set_selector_attributing(c: psycopg.Connection[Any], selector_id: int, attributing: bool) -> None:
    """Flag (or unflag) a selector as non-attributing noise (denylist)."""
    c.execute("UPDATE selectors SET attributing = %s WHERE id = %s", (bool(attributing), selector_id))


def recompute_selector_degree(c: psycopg.Connection[Any], selector_id: int) -> int:
    """Recompute one selector's degree (distinct entities) and return it."""
    c.execute(
        """UPDATE selectors SET entity_count = (
               SELECT count(DISTINCT entity_id) FROM observations WHERE selector_id = %s
           ) WHERE id = %s""",
        (selector_id, selector_id),
    )
    row = c.execute("SELECT entity_count FROM selectors WHERE id = %s", (selector_id,)).fetchone()
    return int(row["entity_count"]) if row else 0


def recompute_all_selector_degrees(c: psycopg.Connection[Any]) -> None:
    """Recompute every selector's degree from observations (batch; used by backfill)."""
    c.execute(
        """UPDATE selectors s SET entity_count = COALESCE(o.cnt, 0)
           FROM (
               SELECT selector_id, count(DISTINCT entity_id) AS cnt
               FROM observations GROUP BY selector_id
           ) o
           WHERE s.id = o.selector_id"""
    )
    c.execute(
        "UPDATE selectors SET entity_count = 0 "
        "WHERE id NOT IN (SELECT selector_id FROM observations)"
    )


# ── Correlation layer: selector extraction ──────────────────────────────────
#
# extract_selectors() is THE single place that maps a raw analysis result (the
# same dict the signal sources build and finalize_search persists) into the
# normalized correlation model: entities, selector observations, and structural
# entity edges. It is run both inline (finalize_search) and by the backfill /
# global recompute, so live ingest and a from-scratch rebuild go through the
# identical code path — which is what makes recompute deterministic.
#
# The owning entity of a selector is the host that *exhibits* it (the scanned
# domain/subdomain for content/cert selectors, the IP for asn/cidr/ssh). Two
# entities sharing a selector are linkage candidates; rarity + denylist scoring
# (utils/check.py) decides how strong, so extraction is deliberately generous.

# Page-metadata tracking IDs → namespaced tracking_id selector values.
_TRACKING_SELECTOR_MAP = [
    ("ga_property", ("google_analytics", "ga_ids")),
    ("gtm_container", ("gtm_ids", "google_tag_manager")),
    ("fb_pixel", ("facebook_pixel",)),
    ("tiktok_pixel", ("tiktok_pixel",)),
    ("yandex_metrika", ("yandex_metrika",)),
    ("adsense_publisher", ("adsense_publisher_ids",)),
    ("fb_app_id", ("fb_app_id", "facebook_app_id")),
]


def extract_selectors(result: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Project one analysis result into {entities, observations, edges}.

    Values are raw (host/IP strings + selector values); persistence classifies
    and upserts them. Recurses into subdomain_followups so a subdomain's own
    certs/selectors are attributed to the subdomain entity (the mechanism behind
    transitive, subdomain-mediated linkage).
    """
    out_entities: list[dict[str, Any]] = []
    out_obs: list[dict[str, Any]] = []
    out_edges: list[dict[str, Any]] = []
    seen_ent: dict[str, dict[str, Any]] = {}
    seen_obs: set[tuple[str, str, str, str]] = set()
    seen_edges: set[tuple[str, str, str]] = set()

    def add_entity(value: Any, first: str | None, last: str | None) -> str | None:
        info = classify_entity(value)
        if not info:
            return None
        v = info["value"]
        rec = seen_ent.get(v)
        if rec is None:
            seen_ent[v] = {"value": v, "first_seen": first, "last_seen": last}
            out_entities.append(seen_ent[v])
        return v

    def add_edge_raw(src: str, dst: str, kind: str, source: str, first: str | None, last: str | None) -> None:
        if not src or not dst or src == dst:
            return
        key = (src, dst, kind)
        if key in seen_edges:
            return
        seen_edges.add(key)
        out_edges.append({"src": src, "dst": dst, "kind": kind, "source": source, "first_seen": first, "last_seen": last})

    def register_host(value: Any, first: str | None, last: str | None) -> str | None:
        """Add a host/IP entity; for a subdomain also add its apex + subdomain_of edge."""
        info = classify_entity(value)
        if not info:
            return None
        add_entity(info["value"], first, last)
        if info["kind"] == "subdomain" and info["registrable_domain"]:
            add_entity(info["registrable_domain"], first, last)
            add_edge_raw(info["value"], info["registrable_domain"], "subdomain_of", "dns", first, last)
        return info["value"]

    def add_obs(entity: Any, kind: str, value: Any, source: str, first: str | None, last: str | None) -> None:
        ev = register_host(entity, first, last)
        sv = str(value or "").strip()
        if not ev or not sv:
            return
        key = (ev, kind, sv, source)
        if key in seen_obs:
            return
        seen_obs.add(key)
        out_obs.append({"entity": ev, "kind": kind, "value": sv, "source": source, "first_seen": first, "last_seen": last})

    def add_resolves(host: Any, ip: Any, source: str, first: str | None, last: str | None) -> None:
        hv = register_host(host, first, last)
        iv = register_host(ip, first, last)
        if hv and iv:
            add_edge_raw(hv, iv, "resolves_to", source, first, last)

    def _collect(res: dict[str, Any]) -> None:
        if not isinstance(res, Mapping):
            return
        ts = str(res.get("timestamp") or datetime.now(timezone.utc).isoformat())
        owner = register_host(res.get("input"), ts, ts)

        # ── TLS certs (live probes + origin scans) exhibited by the owner ──
        tls_list = list(res.get("non_cf_tls_certs") or [])
        if res.get("tls_cert"):
            tls_list.append(res["tls_cert"])
        for cert in tls_list:
            if not isinstance(cert, Mapping):
                continue
            nb, na = _safe_iso(cert.get("not_before")), _safe_iso(cert.get("not_after"))
            if owner:
                add_obs(owner, "tls_cert_sha256", _normalize_identifier_hash(cert.get("sha256")), "self_scan", nb, na)
                add_obs(owner, "tls_spki", _normalize_identifier_hash(cert.get("spki_sha256")), "self_scan", nb, na)
                for san in cert.get("sans") or []:
                    add_obs(owner, "tls_san", _normalize_tls_identity(san), "self_scan", nb, na)
            if cert.get("ip") and owner:
                add_resolves(owner, cert.get("ip"), "tls", ts, ts)

        origin = res.get("origin_candidates") or {}
        for scan_key, scan_src in [("scan", "self_scan"), ("provider_scan", "self_scan"), ("country_scan", "self_scan")]:
            scan_result = origin.get(scan_key) or {}
            if not isinstance(scan_result, Mapping):
                continue
            for hit in scan_result.get("hits") or []:
                if not isinstance(hit, Mapping):
                    continue
                nb, na = _safe_iso(hit.get("not_before")), _safe_iso(hit.get("not_after"))
                if owner:
                    add_obs(owner, "tls_cert_sha256", _normalize_identifier_hash(hit.get("sha256")), scan_src, nb, na)
                    add_obs(owner, "tls_spki", _normalize_identifier_hash(hit.get("spki_sha256")), scan_src, nb, na)
                    for san in hit.get("sans") or []:
                        add_obs(owner, "tls_san", _normalize_tls_identity(san), scan_src, nb, na)
                    if hit.get("ip"):
                        add_resolves(owner, hit.get("ip"), scan_src, ts, ts)

        # ── Provider hits: origin IPs (+ ASN), time-tagged by source ──
        for provider in ("censys", "shodan", "netlas"):
            provider_result = origin.get(provider) or {}
            if not isinstance(provider_result, Mapping):
                continue
            for hit in provider_result.get("hits") or []:
                if not isinstance(hit, Mapping) or not hit.get("ip"):
                    continue
                hit_source = str(hit.get("source") or provider)  # honours censys_history tagging
                if owner:
                    add_resolves(owner, hit.get("ip"), hit_source, ts, ts)
                if hit.get("asn"):
                    add_obs(hit.get("ip"), "asn", _normalize_asn(hit.get("asn")), hit_source, ts, ts)

        # ── Resolved + observed IPs and their ASN / CIDR ──
        dns = res.get("dns") or {}
        for ip in _iter_dns_host_values(dns.get("A")):
            if owner:
                add_resolves(owner, ip, "dns_a", ts, ts)
        for ip in _iter_dns_host_values(dns.get("AAAA")):
            if owner:
                add_resolves(owner, ip, "dns_aaaa", ts, ts)

        ip_details = normalize_ip_details(res.get("ip_details"))
        for ip, info in ip_details.items():
            if owner:
                src = (info.get("sources") or ["dns"])[0]
                add_resolves(owner, ip, str(src), ts, ts)
            asn_info = info.get("asn_info") or {}
            add_obs(ip, "asn", _normalize_asn(asn_info.get("asn")), "rdap", ts, ts)
            add_obs(ip, "network_cidr", asn_info.get("network_cidr") or asn_info.get("asn_cidr"), "rdap", ts, ts)
            for domain in info.get("other_domains_on_ip") or []:
                add_resolves(domain, ip, "reverse_ip", ts, ts)

        if res.get("type") == "ip" and owner:
            asn_info = res.get("asn_info") or {}
            add_obs(owner, "asn", _normalize_asn(asn_info.get("asn")), "rdap", ts, ts)
            add_obs(owner, "network_cidr", asn_info.get("network_cidr") or asn_info.get("asn_cidr"), "rdap", ts, ts)

        # ── SSH host keys exhibited by the IP they were grabbed from ──
        for probe in (res.get("ssh_host_keys") or {}).get("probes") or []:
            if not isinstance(probe, Mapping) or probe.get("error"):
                continue
            fp = _normalize_identifier_hash(probe.get("fingerprint_sha256"))
            if probe.get("ip") and fp:
                add_obs(probe.get("ip"), "ssh_fp", fp, "self_scan", ts, ts)
                if owner:
                    add_resolves(owner, probe.get("ip"), "ssh", ts, ts)

        # ── Web content selectors exhibited by the owner ──
        page = res.get("page_metadata") or {}
        if owner:
            add_obs(owner, "favicon_mmh3", page.get("favicon_mmh3"), "self_scan", ts, ts)
            add_obs(owner, "favicon_md5", page.get("favicon_md5"), "self_scan", ts, ts)
            add_obs(owner, "html_hash", page.get("homepage_html_hash"), "self_scan", ts, ts)
            for selector_name, keys in _TRACKING_SELECTOR_MAP:
                for key in keys:
                    for value in _normalize_text_list(page.get(key) or []):
                        add_obs(owner, "tracking_id", f"{selector_name}|{value}", "self_scan", ts, ts)

        # ── Nameservers exhibited by the owner domain ──
        if owner:
            for ns in _iter_dns_host_values(dns.get("NS")):
                add_obs(owner, "nameserver", _normalize_tls_identity(ns), "dns", ts, ts)
            whois_row = res.get("whois") or {}
            if isinstance(whois_row, Mapping) and not whois_row.get("error"):
                for ns in _normalize_nameservers(whois_row.get("nameservers")):
                    add_obs(owner, "nameserver", ns, "whois", ts, ts)

        # ── CT certs (crt.sh) SANs exhibited by the owner ──
        ct = res.get("cert_transparency") or {}
        if owner:
            for cert in ct.get("certs") or []:
                if not isinstance(cert, Mapping):
                    continue
                nb, na = _safe_iso(cert.get("not_before")), _safe_iso(cert.get("not_after"))
                for san in cert.get("sans") or []:
                    add_obs(owner, "tls_san", _normalize_tls_identity(san), "crtsh", nb, na)
            for san in ct.get("cross_domain_sans") or []:
                add_obs(owner, "tls_san", _normalize_tls_identity(san), "crtsh", ts, ts)

        # ── Discovered subdomains become entities under their apex ──
        for sub in _normalize_text_list(res.get("subdomains") or []):
            register_host(sub, ts, ts)
        for sub in _normalize_text_list(res.get("zone_transfer") or []):
            register_host(sub, ts, ts)

        # ── Recurse into subdomain followups (subdomain owns its own selectors) ──
        for followup in res.get("subdomain_followups") or []:
            if isinstance(followup, Mapping) and isinstance(followup.get("result"), Mapping):
                _collect(dict(followup["result"]))

    _collect(result)
    return {"entities": out_entities, "observations": out_obs, "edges": out_edges}


# ── Correlation layer: persistence / rebuild ────────────────────────────────

def persist_correlation(
    c: psycopg.Connection[Any],
    result: dict[str, Any],
    *,
    search_id: int | None = None,
    recount: bool = True,
) -> set[int]:
    """Upsert the correlation projection of one result. Returns touched selector ids.

    When recount is True (live ingest), the degree of every touched selector is
    refreshed immediately. Backfill passes recount=False and batch-recomputes
    all degrees once at the end.
    """
    data = extract_selectors(result)
    ent_ids: dict[str, int] = {}
    for ent in data["entities"]:
        info = classify_entity(ent["value"])
        if not info:
            continue
        ent_ids[info["value"]] = upsert_entity(
            c,
            kind=info["kind"],
            value=info["value"],
            registrable_domain=info["registrable_domain"],
            first_seen=ent.get("first_seen"),
            last_seen=ent.get("last_seen"),
        )

    touched: set[int] = set()
    for obs in data["observations"]:
        eid = ent_ids.get(obs["entity"])
        if eid is None:
            eid = upsert_entity_value(c, obs["entity"], first_seen=obs.get("first_seen"), last_seen=obs.get("last_seen"))
            if eid is None:
                continue
            ent_ids[obs["entity"]] = eid
        sel_id = upsert_selector(
            c, kind=obs["kind"], value=obs["value"],
            first_seen=obs.get("first_seen"), last_seen=obs.get("last_seen"),
        )
        record_observation(
            c, entity_id=eid, selector_id=sel_id, source=obs["source"],
            first_seen=obs.get("first_seen"), last_seen=obs.get("last_seen"), search_id=search_id,
        )
        touched.add(sel_id)

    for edge in data["edges"]:
        s = ent_ids.get(edge["src"])
        d = ent_ids.get(edge["dst"])
        if s is None or d is None:
            continue
        record_entity_edge(
            c, src_entity_id=s, dst_entity_id=d, kind=edge["kind"], source=edge["source"],
            first_seen=edge.get("first_seen"), last_seen=edge.get("last_seen"),
        )

    if recount:
        for sel_id in touched:
            recompute_selector_degree(c, sel_id)
    return touched


def _truncate_correlation(c: psycopg.Connection[Any]) -> None:
    c.execute("TRUNCATE entity_edges, observations, selectors, entities RESTART IDENTITY CASCADE")


def rebuild_all_correlation() -> dict[str, int]:
    """Global recompute: rebuild the whole correlation graph from raw intel.

    Drops the derived tables and re-projects every stored search (oldest first
    so time windows widen monotonically), then recomputes degrees and seeds the
    denylist. This is the deterministic "recompute without rescanning" path.
    """
    init_db()
    with _conn() as c:
        _truncate_correlation(c)
        ids = [int(row["id"]) for row in c.execute("SELECT id FROM searches ORDER BY id ASC").fetchall()]
        for sid in ids:
            result = get_result(sid)
            if result is not None:
                persist_correlation(c, result, search_id=sid, recount=False)
        recompute_all_selector_degrees(c)
        denylisted = seed_denylist(c)
        counts = {
            "searches": len(ids),
            "entities": c.execute("SELECT count(*) AS n FROM entities").fetchone()["n"],
            "selectors": c.execute("SELECT count(*) AS n FROM selectors").fetchone()["n"],
            "observations": c.execute("SELECT count(*) AS n FROM observations").fetchone()["n"],
            "entity_edges": c.execute("SELECT count(*) AS n FROM entity_edges").fetchone()["n"],
            "denylisted_selectors": denylisted,
        }
    # Clusters depend on the freshly seeded denylist, so rebuild them last.
    counts.update(rebuild_clusters())
    return counts


def rebuild_correlation_for_search(search_id: int) -> set[int]:
    """Incrementally (re)project a single search into the correlation graph."""
    init_db()
    result = get_result(search_id)
    if result is None:
        return set()
    with _conn() as c:
        touched = persist_correlation(c, result, search_id=search_id, recount=True)
    return touched


# ── Correlation layer: denylist seeding ─────────────────────────────────────

def _degree_threshold() -> int:
    try:
        return int(os.getenv("CORRELATION_DEGREE_THRESHOLD", "50"))
    except ValueError:
        return 50


_BORING_NS_PROVIDERS_CACHE: set[str] | None = None


def _boring_ns_providers() -> set[str]:
    global _BORING_NS_PROVIDERS_CACHE
    if _BORING_NS_PROVIDERS_CACHE is None:
        path = Path(__file__).resolve().parent.parent / "config" / "boring_ns_providers.txt"
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        _BORING_NS_PROVIDERS_CACHE = {
            line.strip().lower() for line in lines if line.strip() and not line.strip().startswith("#")
        }
    return _BORING_NS_PROVIDERS_CACHE


def _is_boring_nameserver(value: str) -> bool:
    text = str(value or "").strip().lower().rstrip(".")
    return any(token and (text == token or token in text) for token in _boring_ns_providers())


def seed_denylist(c: psycopg.Connection[Any]) -> int:
    """Mark non-attributing (noise) selectors. Returns how many were flagged.

    Complementary to rarity weighting: a denylisted selector NEVER creates a
    link regardless of degree. Re-runnable (also resets known-good selectors to
    attributing so a lowered threshold or edited list takes effect on recompute).
    """
    # Start from a clean slate so recompute is deterministic w.r.t. the rules below.
    c.execute("UPDATE selectors SET attributing = TRUE")

    threshold = _degree_threshold()
    # 1) High-degree selectors of any kind are shared infrastructure noise
    #    (Cloudflare universal-SSL SAN sets, big nameservers/ASNs, ...).
    c.execute("UPDATE selectors SET attributing = FALSE WHERE entity_count > %s", (threshold,))

    # 2) Known noise ASNs (CDN/proxy, shared-hosting, big mail).
    noise_asns = sorted(_CDN_PROXY_ASNS | _SHARED_HOSTING_ASNS | _MAIL_ASNS)
    if noise_asns:
        c.execute(
            "UPDATE selectors SET attributing = FALSE WHERE kind = 'asn' AND value = ANY(%s)",
            (noise_asns,),
        )

    # 3) Big-provider / registrar nameservers from the boring-NS list.
    for row in c.execute("SELECT id, value FROM selectors WHERE kind = 'nameserver'").fetchall():
        if _is_boring_nameserver(row["value"]):
            c.execute("UPDATE selectors SET attributing = FALSE WHERE id = %s", (row["id"],))

    # 4) Shared-host / default certificate SANs (cPanel/Apache defaults, localhost…).
    for row in c.execute("SELECT id, value FROM selectors WHERE kind = 'tls_san'").fetchall():
        value = row["value"]
        if _is_low_signal_tls_identity(value) or _text_contains_any(value, _LOW_SIGNAL_HOSTING_PATTERNS):
            c.execute("UPDATE selectors SET attributing = FALSE WHERE id = %s", (row["id"],))

    return c.execute("SELECT count(*) AS n FROM selectors WHERE attributing = FALSE").fetchone()["n"]


# ── Correlation layer: linkage queries ──────────────────────────────────────
#
# The "what else exhibits this selector / resolves to this IP" lookups that turn
# linkage into a single indexed query. They return rows; rarity × time-overlap ×
# base-weight scoring and evidence shaping live in utils/check.py.

def _resolve_side(value: Any) -> tuple[str, str, str] | None:
    """Map an input to (mode, key, self_key): mode 'rd' (registrable domain) or
    'ip', key is what we filter the entity set on, self_key excludes self-links.
    """
    info = classify_entity(value)
    if not info:
        return None
    if info["kind"] == "ip":
        return ("ip", info["value"], info["value"])
    rd = info["registrable_domain"]
    if not rd:
        return None
    return ("rd", rd, rd)


def _side_entity_sql(mode: str) -> str:
    if mode == "ip":
        return "SELECT id FROM entities WHERE kind = 'ip' AND value = %s"
    return "SELECT id FROM entities WHERE registrable_domain = %s"


def shared_selectors_between(a_value: str, b_value: str) -> list[dict[str, Any]]:
    """Attributing selectors exhibited by both sides, with per-side windows."""
    init_db()
    a = _resolve_side(a_value)
    b = _resolve_side(b_value)
    if not a or not b:
        return []
    a_sql, b_sql = _side_entity_sql(a[0]), _side_entity_sql(b[0])
    with _conn() as c:
        rows = c.execute(
            f"""WITH a_ent AS ({a_sql}), b_ent AS ({b_sql})
                SELECT sel.kind, sel.value, sel.entity_count,
                       min(oa.first_seen) AS a_first, max(oa.last_seen) AS a_last,
                       min(ob.first_seen) AS b_first, max(ob.last_seen) AS b_last,
                       array_agg(DISTINCT oa.source) AS a_sources,
                       array_agg(DISTINCT ob.source) AS b_sources
                FROM selectors sel
                JOIN observations oa ON oa.selector_id = sel.id AND oa.entity_id IN (SELECT id FROM a_ent)
                JOIN observations ob ON ob.selector_id = sel.id AND ob.entity_id IN (SELECT id FROM b_ent)
                WHERE sel.attributing
                GROUP BY sel.kind, sel.value, sel.entity_count""",
            (a[1], b[1]),
        ).fetchall()
    return [dict(row) for row in rows]


def shared_ips_between(a_value: str, b_value: str) -> list[dict[str, Any]]:
    """Shared `ip` entities both sides resolve to, with degree + noise flag."""
    init_db()
    a = _resolve_side(a_value)
    b = _resolve_side(b_value)
    if not a or not b:
        return []
    a_sql, b_sql = _side_entity_sql(a[0]), _side_entity_sql(b[0])
    with _conn() as c:
        rows = c.execute(
            f"""WITH a_ent AS ({a_sql}), b_ent AS ({b_sql}),
                     a_ip AS (SELECT dst_entity_id AS ip_id, min(first_seen) AS f, max(last_seen) AS l,
                                     array_agg(DISTINCT source) AS srcs
                              FROM entity_edges WHERE kind='resolves_to' AND src_entity_id IN (SELECT id FROM a_ent)
                              GROUP BY dst_entity_id),
                     b_ip AS (SELECT dst_entity_id AS ip_id, min(first_seen) AS f, max(last_seen) AS l,
                                     array_agg(DISTINCT source) AS srcs
                              FROM entity_edges WHERE kind='resolves_to' AND src_entity_id IN (SELECT id FROM b_ent)
                              GROUP BY dst_entity_id)
                SELECT ip.value,
                       a_ip.f AS a_first, a_ip.l AS a_last, a_ip.srcs AS a_sources,
                       b_ip.f AS b_first, b_ip.l AS b_last, b_ip.srcs AS b_sources,
                       (SELECT count(DISTINCT e.registrable_domain)
                          FROM entity_edges ee JOIN entities e ON e.id = ee.src_entity_id
                          WHERE ee.dst_entity_id = ip.id AND ee.kind='resolves_to') AS degree,
                       EXISTS (SELECT 1 FROM observations o JOIN selectors s ON s.id = o.selector_id
                               WHERE o.entity_id = ip.id AND s.kind IN ('asn','network_cidr')
                                 AND s.attributing = FALSE) AS noisy_net
                FROM entities ip
                JOIN a_ip ON a_ip.ip_id = ip.id
                JOIN b_ip ON b_ip.ip_id = ip.id
                WHERE ip.kind = 'ip'""",
            (a[1], b[1]),
        ).fetchall()
    return [dict(row) for row in rows]


def link_candidates_for(value: str) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """Cross-corpus pivot: every other registrable domain that shares an
    attributing selector or a shared IP with `value`.

    Returns {rd: {"selectors": [...], "ips": [...]}} for aggregation/scoring by
    the caller. This is the engine behind "add a domain, surface connections".
    """
    init_db()
    side = _resolve_side(value)
    if not side:
        return {}
    side_sql = _side_entity_sql(side[0])
    out: dict[str, dict[str, list[dict[str, Any]]]] = {}

    def bucket(rd: str) -> dict[str, list[dict[str, Any]]]:
        return out.setdefault(rd, {"selectors": [], "ips": []})

    with _conn() as c:
        sel_rows = c.execute(
            f"""WITH a_ent AS ({side_sql})
                SELECT e2.registrable_domain AS rd, sel.kind, sel.value, sel.entity_count,
                       min(oa.first_seen) AS a_first, max(oa.last_seen) AS a_last,
                       min(ob.first_seen) AS b_first, max(ob.last_seen) AS b_last,
                       array_agg(DISTINCT oa.source) AS a_sources,
                       array_agg(DISTINCT ob.source) AS b_sources
                FROM selectors sel
                JOIN observations oa ON oa.selector_id = sel.id AND oa.entity_id IN (SELECT id FROM a_ent)
                JOIN observations ob ON ob.selector_id = sel.id
                JOIN entities e2 ON e2.id = ob.entity_id
                WHERE sel.attributing
                  AND e2.registrable_domain IS NOT NULL
                  AND e2.registrable_domain <> %s
                GROUP BY e2.registrable_domain, sel.kind, sel.value, sel.entity_count""",
            (side[1], side[2]),
        ).fetchall()
        for row in sel_rows:
            bucket(row["rd"])["selectors"].append(dict(row))

        ip_rows = c.execute(
            f"""WITH a_ent AS ({side_sql}),
                     a_ip AS (SELECT dst_entity_id AS ip_id, min(first_seen) AS f, max(last_seen) AS l,
                                     array_agg(DISTINCT source) AS srcs
                              FROM entity_edges WHERE kind='resolves_to' AND src_entity_id IN (SELECT id FROM a_ent)
                              GROUP BY dst_entity_id)
                SELECT e2.registrable_domain AS rd, ip.value,
                       a_ip.f AS a_first, a_ip.l AS a_last, a_ip.srcs AS a_sources,
                       min(ee.first_seen) AS b_first, max(ee.last_seen) AS b_last,
                       array_agg(DISTINCT ee.source) AS b_sources,
                       (SELECT count(DISTINCT e3.registrable_domain)
                          FROM entity_edges ee2 JOIN entities e3 ON e3.id = ee2.src_entity_id
                          WHERE ee2.dst_entity_id = ip.id AND ee2.kind='resolves_to') AS degree,
                       EXISTS (SELECT 1 FROM observations o JOIN selectors s ON s.id = o.selector_id
                               WHERE o.entity_id = ip.id AND s.kind IN ('asn','network_cidr')
                                 AND s.attributing = FALSE) AS noisy_net
                FROM a_ip
                JOIN entities ip ON ip.id = a_ip.ip_id
                JOIN entity_edges ee ON ee.dst_entity_id = ip.id AND ee.kind='resolves_to'
                JOIN entities e2 ON e2.id = ee.src_entity_id
                WHERE e2.registrable_domain IS NOT NULL
                  AND e2.registrable_domain <> %s
                GROUP BY e2.registrable_domain, ip.id, ip.value, a_ip.f, a_ip.l, a_ip.srcs""",
            (side[1], side[2]),
        ).fetchall()
        for row in ip_rows:
            bucket(row["rd"])["ips"].append(dict(row))

    return out


# ── Correlation layer: global clustering ────────────────────────────────────
#
# Clusters are connected components over the *whole* attributing graph, rolled
# up to registrable_domain. Two registrable domains are unioned when they share
# an attributing selector or a (non-noise) shared IP whose fan-out is small
# enough to be meaningful — the same rarity intuition the scorer uses, applied
# as a binary edge so one moderately-shared node can't merge the whole lake.
# Materialized into graph_clusters; rebuilt by recompute / on schedule, not
# inline on ingest.

def _cluster_max_fanout() -> int:
    try:
        return int(os.getenv("CORRELATION_CLUSTER_MAX_FANOUT", "25"))
    except ValueError:
        return 25


def rebuild_clusters() -> dict[str, int]:
    """Recompute and materialize global clusters from the attributing graph."""
    init_db()
    fanout = _cluster_max_fanout()
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            # Keep the lexicographically smaller representative for stable ids.
            if rb < ra:
                ra, rb = rb, ra
            parent[rb] = ra

    def union_group(rds: list[str]) -> None:
        members = [rd for rd in rds if rd]
        for other in members[1:]:
            union(members[0], other)

    with _conn() as c:
        for row in c.execute(
            """SELECT array_agg(DISTINCT e.registrable_domain) AS rds
               FROM selectors sel
               JOIN observations o ON o.selector_id = sel.id
               JOIN entities e ON e.id = o.entity_id
               WHERE sel.attributing AND e.registrable_domain IS NOT NULL
               GROUP BY sel.id
               HAVING count(DISTINCT e.registrable_domain) BETWEEN 2 AND %s""",
            (fanout,),
        ).fetchall():
            union_group(row["rds"])

        for row in c.execute(
            """SELECT array_agg(DISTINCT e.registrable_domain) AS rds
               FROM entities ip
               JOIN entity_edges ee ON ee.dst_entity_id = ip.id AND ee.kind = 'resolves_to'
               JOIN entities e ON e.id = ee.src_entity_id
               WHERE ip.kind = 'ip' AND e.registrable_domain IS NOT NULL
                 AND NOT EXISTS (
                     SELECT 1 FROM observations o JOIN selectors s ON s.id = o.selector_id
                     WHERE o.entity_id = ip.id AND s.kind IN ('asn','network_cidr') AND s.attributing = FALSE
                 )
               GROUP BY ip.id
               HAVING count(DISTINCT e.registrable_domain) BETWEEN 2 AND %s""",
            (fanout,),
        ).fetchall():
            union_group(row["rds"])

        components: dict[str, list[str]] = defaultdict(list)
        for rd in list(parent):
            components[find(rd)].append(rd)

        now = datetime.now(timezone.utc).isoformat()
        c.execute("TRUNCATE graph_clusters")
        cluster_count = 0
        clustered = 0
        for members in components.values():
            if len(members) < 2:
                continue
            cluster_count += 1
            cluster_id = min(members)
            size = len(members)
            for member in members:
                c.execute(
                    """INSERT INTO graph_clusters (registrable_domain, cluster_id, component_size, computed_at)
                       VALUES (%s,%s,%s,%s)
                       ON CONFLICT (registrable_domain) DO UPDATE SET
                           cluster_id = EXCLUDED.cluster_id,
                           component_size = EXCLUDED.component_size,
                           computed_at = EXCLUDED.computed_at""",
                    (member, cluster_id, size, now),
                )
                clustered += 1

    return {"clusters": cluster_count, "clustered_domains": clustered}


def list_graph_clusters(*, min_size: int = 2, limit: int = 100) -> list[dict[str, Any]]:
    """Strongest clusters lake-wide (largest first)."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT cluster_id, component_size,
                      array_agg(registrable_domain ORDER BY registrable_domain) AS members
               FROM graph_clusters
               WHERE component_size >= %s
               GROUP BY cluster_id, component_size
               ORDER BY component_size DESC, cluster_id
               LIMIT %s""",
            (min_size, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def graph_cluster_for(value: str) -> dict[str, Any] | None:
    """The cluster a registrable domain belongs to (with its members), if any."""
    side = _resolve_side(value)
    if not side or side[0] != "rd":
        return None
    init_db()
    with _conn() as c:
        row = c.execute(
            "SELECT cluster_id, component_size FROM graph_clusters WHERE registrable_domain = %s",
            (side[1],),
        ).fetchone()
        if not row:
            return None
        members = [
            r["registrable_domain"]
            for r in c.execute(
                "SELECT registrable_domain FROM graph_clusters WHERE cluster_id = %s ORDER BY registrable_domain",
                (row["cluster_id"],),
            ).fetchall()
        ]
    return {"cluster_id": row["cluster_id"], "component_size": row["component_size"], "members": members}


# ── Pool + by-edge browsing ─────────────────────────────────────────────────
#
# The product is one global pool of channels (registrable domains). These power
# the pool listing and the "browse by edge type" discovery mode (filter by a
# selector kind — shared TLS cert / SSH fp / shared IP / nameserver / … — and
# see which domains carry that connection).

def list_pool_domains(*, search: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
    """Every registrable domain in the pool with host count, recency, cluster."""
    init_db()
    like = f"%{search.strip().lower()}%" if search and search.strip() else None
    with _conn() as c:
        rows = c.execute(
            """SELECT e.registrable_domain AS domain,
                      count(*) AS host_count,
                      max(e.last_seen) AS last_seen,
                      gc.cluster_id,
                      gc.component_size AS cluster_size
               FROM entities e
               LEFT JOIN graph_clusters gc ON gc.registrable_domain = e.registrable_domain
               WHERE e.registrable_domain IS NOT NULL
                 AND (%s::text IS NULL OR e.registrable_domain LIKE %s::text)
               GROUP BY e.registrable_domain, gc.cluster_id, gc.component_size
               ORDER BY max(e.last_seen) DESC NULLS LAST, e.registrable_domain
               LIMIT %s""",
            (like, like, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def selector_kind_counts(*, min_domains: int = 2) -> list[dict[str, Any]]:
    """Edge types available for browsing: each selector kind (+ shared_ip) with
    the number of cross-domain groups it forms."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT kind, count(*) AS groups FROM (
                   SELECT sel.kind, sel.id
                   FROM selectors sel
                   JOIN observations o ON o.selector_id = sel.id
                   JOIN entities e ON e.id = o.entity_id
                   WHERE sel.attributing AND e.registrable_domain IS NOT NULL
                   GROUP BY sel.kind, sel.id
                   HAVING count(DISTINCT e.registrable_domain) >= %s
               ) t GROUP BY kind""",
            (min_domains,),
        ).fetchall()
        out = [dict(row) for row in rows]
        ip_groups = c.execute(
            """SELECT count(*) AS groups FROM (
                   SELECT ip.id
                   FROM entities ip
                   JOIN entity_edges ee ON ee.dst_entity_id = ip.id AND ee.kind = 'resolves_to'
                   JOIN entities e ON e.id = ee.src_entity_id
                   WHERE ip.kind = 'ip' AND e.registrable_domain IS NOT NULL
                     AND NOT EXISTS (
                         SELECT 1 FROM observations o JOIN selectors s ON s.id = o.selector_id
                         WHERE o.entity_id = ip.id AND s.kind IN ('asn','network_cidr') AND s.attributing = FALSE
                     )
                   GROUP BY ip.id
                   HAVING count(DISTINCT e.registrable_domain) >= %s
               ) t""",
            (min_domains,),
        ).fetchone()
    if ip_groups and ip_groups["groups"]:
        out.append({"kind": "shared_ip", "groups": int(ip_groups["groups"])})
    out.sort(key=lambda row: row["groups"], reverse=True)
    return out


def domains_by_selector(
    *, kind: str | None = None, min_domains: int = 2, limit: int = 200
) -> list[dict[str, Any]]:
    """Groups of registrable domains that share an attributing selector (or a
    non-noise shared IP when kind='shared_ip'), strongest fan-in first."""
    init_db()
    with _conn() as c:
        if kind == "shared_ip":
            rows = c.execute(
                """SELECT 'shared_ip' AS kind, ip.value AS value,
                          count(DISTINCT e.registrable_domain) AS degree,
                          array_agg(DISTINCT e.registrable_domain) AS domains
                   FROM entities ip
                   JOIN entity_edges ee ON ee.dst_entity_id = ip.id AND ee.kind = 'resolves_to'
                   JOIN entities e ON e.id = ee.src_entity_id
                   WHERE ip.kind = 'ip' AND e.registrable_domain IS NOT NULL
                     AND NOT EXISTS (
                         SELECT 1 FROM observations o JOIN selectors s ON s.id = o.selector_id
                         WHERE o.entity_id = ip.id AND s.kind IN ('asn','network_cidr') AND s.attributing = FALSE
                     )
                   GROUP BY ip.id, ip.value
                   HAVING count(DISTINCT e.registrable_domain) >= %s
                   ORDER BY count(DISTINCT e.registrable_domain) DESC, ip.value
                   LIMIT %s""",
                (min_domains, limit),
            ).fetchall()
        else:
            rows = c.execute(
                """SELECT sel.kind, sel.value, sel.entity_count AS degree,
                          array_agg(DISTINCT e.registrable_domain) AS domains
                   FROM selectors sel
                   JOIN observations o ON o.selector_id = sel.id
                   JOIN entities e ON e.id = o.entity_id
                   WHERE sel.attributing AND e.registrable_domain IS NOT NULL
                     AND (%s::text IS NULL OR sel.kind = %s::text)
                   GROUP BY sel.id, sel.kind, sel.value, sel.entity_count
                   HAVING count(DISTINCT e.registrable_domain) >= %s
                   ORDER BY count(DISTINCT e.registrable_domain) DESC, sel.kind, sel.value
                   LIMIT %s""",
                (kind, kind, min_domains, limit),
            ).fetchall()
    return [dict(row) for row in rows]


# ── Queries ───────────────────────────────────────────────────────────────────

def get_recent(limit: int = 100) -> list[dict]:
    init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT id, target, type, timestamp, cloudflare_fronted FROM searches ORDER BY timestamp DESC, id DESC LIMIT %s",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_domain_targets() -> list[str]:
    init_db()
    with _conn() as c:
        rows = [
            row
            for row in _latest_search_rows(c)
            if row["type"] == "domain" and str(row["target"] or "").strip()
        ]
    rows.sort(key=lambda row: (row["timestamp"] or "", int(row["id"])), reverse=True)
    return [str(row["target"]) for row in rows if row["target"]]


def get_domains_with_source_errors(source: str | None = None) -> list[dict]:
    init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT id, target, timestamp, source_errors FROM searches "
            "WHERE source_errors IS NOT NULL ORDER BY timestamp DESC, id DESC"
        ).fetchall()

    results = []
    for row in rows:
        # source_errors is JSONB, so psycopg returns parsed values; older callers
        # may still hand us JSON text, so stay tolerant.
        errors = row["source_errors"] or []
        if isinstance(errors, (str, bytes)):
            try:
                errors = json.loads(errors)
            except (json.JSONDecodeError, TypeError):
                errors = []
        if not isinstance(errors, list):
            errors = [errors] if errors else []
        if source is None or source in errors:
            results.append({"id": row["id"], "target": row["target"], "timestamp": row["timestamp"], "errors": errors})
    return results


def get_by_id(sid: int) -> dict | None:
    init_db()
    with _conn() as c:
        row = c.execute(
            "SELECT id, target, type, timestamp, cloudflare_fronted, source_errors FROM searches WHERE id = %s",
            (sid,),
        ).fetchone()
    return dict(row) if row else None


def get_latest_search_id_for_target(target: str) -> int | None:
    init_db()
    with _conn() as c:
        row = _latest_row_for_target(c, target)
    return int(row["id"]) if row else None


def update_search_payload(search_id: int, payload: dict[str, Any]) -> None:
    init_db()
    timestamp = str(payload.get("timestamp") or datetime.now(timezone.utc).isoformat())
    with _conn() as c:
        c.execute("UPDATE searches SET timestamp = %s WHERE id = %s", (timestamp, search_id))
        for key, value in payload.items():
            c.execute(
                "INSERT INTO search_fields (search_id, key, json_value) VALUES (%s,%s,%s) "
                "ON CONFLICT (search_id, key) DO UPDATE SET json_value = EXCLUDED.json_value",
                (search_id, key, _json(value)),
            )
        _refresh_search_identifiers(c, search_id, payload)


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
               WHERE i.ip = %s
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
               WHERE t.sha256 = %s
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
               WHERE t.id_type = %s AND t.id_value = %s
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
               WHERE f.md5 = %s
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
               WHERE e.email = %s
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
               WHERE a.platform = %s AND a.handle = %s
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
               WHERE n.nameserver = %s
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
               WHERE cs.san = %s
               ORDER BY s.timestamp DESC, s.id DESC""",
            (san,),
        ).fetchall()
    return [dict(row) for row in rows]


def find_by_identifier(id_type: str, id_value: str) -> list[dict]:
    normalized_value = _normalize_identifier_value(id_type, id_value)
    if not normalized_value:
        return []

    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT s.id, s.target, s.type, s.timestamp, i.tier, i.category
               FROM searches s JOIN identifiers i ON s.id = i.search_id
               WHERE i.id_type = %s AND i.id_value = %s
               ORDER BY s.timestamp DESC, s.id DESC""",
            (id_type, normalized_value),
        ).fetchall()
    return [dict(row) for row in rows]


def _targets_match_exact(left: str, right: str, target_type: str) -> bool:
    if target_type == "domain":
        return _normalize_target(left) == _normalize_target(right)
    return str(left or "").strip() == str(right or "").strip()


def find_searches_touching_target(
    target: str,
    *,
    exclude_search_id: int | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    normalized_target, target_type = _normalize_candidate_target(target)
    if not normalized_target or not target_type:
        return []

    init_db()
    with _conn() as c:
        search_rows = c.execute(
            "SELECT id, target, type, timestamp, cloudflare_fronted FROM searches ORDER BY timestamp DESC, id DESC"
        ).fetchall()
        discovered_rows = c.execute(
            """SELECT d.search_id, d.target AS discovered_target, d.target_type, d.relation, d.source, d.score,
                      s.target, s.type, s.timestamp, s.cloudflare_fronted
               FROM discovered_targets d
               JOIN searches s ON s.id = d.search_id
               ORDER BY s.timestamp DESC, s.id DESC""",
        ).fetchall()

    grouped: dict[int, dict[str, Any]] = {}

    for row in search_rows:
        sid = int(row["id"])
        if exclude_search_id is not None and sid == int(exclude_search_id):
            continue
        if not _targets_match_exact(str(row["target"] or ""), normalized_target, target_type):
            continue
        grouped.setdefault(
            sid,
            {
                "search_id": sid,
                "target": row["target"],
                "type": row["type"],
                "timestamp": row["timestamp"],
                "cloudflare_fronted": row["cloudflare_fronted"],
                "matched_as_target": True,
                "matched_relations": set(),
                "matched_sources": set(),
                "best_score": 0,
            },
        )["matched_as_target"] = True

    for row in discovered_rows:
        sid = int(row["search_id"])
        if exclude_search_id is not None and sid == int(exclude_search_id):
            continue
        if not _targets_match_exact(str(row["discovered_target"] or ""), normalized_target, target_type):
            continue
        entry = grouped.setdefault(
            sid,
            {
                "search_id": sid,
                "target": row["target"],
                "type": row["type"],
                "timestamp": row["timestamp"],
                "cloudflare_fronted": row["cloudflare_fronted"],
                "matched_as_target": False,
                "matched_relations": set(),
                "matched_sources": set(),
                "best_score": 0,
            },
        )
        if row["relation"]:
            entry["matched_relations"].add(row["relation"])
        if row["source"]:
            entry["matched_sources"].add(row["source"])
        entry["best_score"] = max(entry["best_score"], int(row["score"] or 0))

    items = []
    for entry in grouped.values():
        item = dict(entry)
        item["matched_relations"] = sorted(entry["matched_relations"])
        item["matched_sources"] = sorted(entry["matched_sources"])
        items.append(item)

    items.sort(
        key=lambda item: (
            item["matched_as_target"],
            item["best_score"],
            item["timestamp"] or "",
            item["search_id"],
        ),
        reverse=True,
    )
    return items[:limit]


def summarize_result_db_matches(
    result: dict[str, Any],
    *,
    exclude_search_id: int | None = None,
    limit_targets: int = 10,
    limit_matches_per_target: int = 4,
) -> dict[str, Any]:
    related_summary = result.get("related_targets_summary") or summarize_related_targets(result)
    related_items = list(related_summary.get("items") or [])
    seed_target, seed_type = _normalize_candidate_target(result.get("input"))

    if result.get("type") == "ip" and seed_target and seed_type == "ip":
        related_items.insert(
            0,
            {
                "target": seed_target,
                "target_type": "ip",
                "score": 99,
                "sources": ["input"],
                "relations": ["seed_ip"],
                "auto_expand": True,
            },
        )

    seen: set[tuple[str, str]] = set()
    matched_items: list[dict[str, Any]] = []
    for item in related_items:
        target = str(item.get("target") or "").strip()
        target_type = str(item.get("target_type") or "").strip()
        if not target or not target_type:
            continue

        key = (target, target_type)
        if key in seen:
            continue
        seen.add(key)

        if target_type == "domain" and _is_noisy_pivot_domain(target):
            continue
        if seed_target and seed_type and target == seed_target and target_type == seed_type and result.get("type") == "domain":
            continue

        all_matches = find_searches_touching_target(
            target,
            exclude_search_id=exclude_search_id,
            limit=50,
        )
        if not all_matches:
            continue

        matched_items.append(
            {
                "target": target,
                "target_type": target_type,
                "score": int(item.get("score") or 0),
                "sources": list(item.get("sources") or []),
                "relations": list(item.get("relations") or []),
                "auto_expand": bool(item.get("auto_expand")),
                "match_count": len(all_matches),
                "direct_target_hits": sum(1 for match in all_matches if match.get("matched_as_target")),
                "matches": all_matches[:limit_matches_per_target],
            }
        )

    matched_items.sort(
        key=lambda item: (
            item["direct_target_hits"],
            item["match_count"],
            item["score"],
            item["target_type"] == "ip",
            item["target"],
        ),
        reverse=True,
    )
    matched_items = matched_items[:limit_targets]

    return {
        "items": matched_items,
        "total": len(matched_items),
        "matched_domains": sum(1 for item in matched_items if item["target_type"] == "domain"),
        "matched_ips": sum(1 for item in matched_items if item["target_type"] == "ip"),
        "direct_target_hits": sum(item["direct_target_hits"] for item in matched_items),
    }


def _latest_domain_rows(c: psycopg.Connection[Any]) -> list[dict[str, Any]]:
    return [
        row
        for row in _latest_search_rows(c)
        if row["type"] == "domain" and str(row["target"] or "").strip()
    ]


def _parse_dt(value: Any) -> datetime | None:
    text = _safe_iso(value)
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _humanize_identifier_type(id_type: str) -> str:
    return str(id_type or "").replace("_", " ").strip().title()


def _identifier_rationale(category: str, tier: str, frequency_status: str, domain_count: int | None) -> str:
    tier_label = _IDENTIFIER_TIER_LABELS.get(tier, tier).capitalize()
    category_label = str(category or "generic").replace("_", " ")
    if frequency_status == "excluded" and domain_count is not None:
        return f"{tier_label} {category_label} evidence, but it is shared by {domain_count} stored domains so it was excluded."
    if frequency_status == "downweighted" and domain_count is not None:
        return f"{tier_label} {category_label} evidence that was downweighted because it appears on {domain_count} stored domains."
    if domain_count is not None:
        return f"{tier_label} {category_label} evidence shared by {domain_count} stored domains."
    return f"{tier_label} {category_label} evidence derived from pairwise timing."


def _load_latest_domain_identifier_state(c: psycopg.Connection[Any]) -> dict[str, Any]:
    latest_rows = _latest_domain_rows(c)
    latest_ids = [int(row["id"]) for row in latest_rows]

    domains: dict[str, dict[str, Any]] = {}
    for row in latest_rows:
        norm = _normalize_target(str(row["target"] or ""))
        domains[norm] = {
            "target": str(row["target"]),
            "search_id": int(row["id"]),
            "timestamp": row["timestamp"],
            "identifiers": {},
        }

    if not latest_ids:
        return {
            "domains": domains,
            "identifier_domains": {},
            "identifier_meta": {},
            "cert_issuance": {},
            "frequency_cache": {},
        }

    identifier_rows = _query_rows_for_ids(
        c,
        """SELECT i.search_id, s.target, i.id_type, i.id_value, i.tier, i.category, i.source,
                  i.observed_at, i.first_seen, i.last_seen, i.raw_json
           FROM identifiers i
           JOIN searches s ON s.id = i.search_id
           WHERE i.search_id IN ({placeholders})""",
        latest_ids,
    )

    identifier_domains: dict[tuple[str, str], set[str]] = defaultdict(set)
    identifier_meta: dict[tuple[str, str], dict[str, Any]] = {}

    for row in identifier_rows:
        norm_target = _normalize_target(str(row["target"] or ""))
        domain_entry = domains.get(norm_target)
        if not domain_entry:
            continue

        key = (str(row["id_type"]), str(row["id_value"]))
        payload = domain_entry["identifiers"].setdefault(
            key,
            {
                "id_type": str(row["id_type"]),
                "id_value": str(row["id_value"]),
                "tier": str(row["tier"]),
                "category": str(row["category"]),
                "sources": set(),
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "observed_at": row["observed_at"],
                "raw_examples": [],
            },
        )
        if row["source"]:
            payload["sources"].add(str(row["source"]))
        if row["first_seen"] and (not payload["first_seen"] or str(row["first_seen"]) < str(payload["first_seen"])):
            payload["first_seen"] = row["first_seen"]
        if row["last_seen"] and (not payload["last_seen"] or str(row["last_seen"]) > str(payload["last_seen"])):
            payload["last_seen"] = row["last_seen"]
        if row["observed_at"] and (not payload["observed_at"] or str(row["observed_at"]) < str(payload["observed_at"])):
            payload["observed_at"] = row["observed_at"]
        raw_example = row["raw_json"]
        if raw_example is not None and len(payload["raw_examples"]) < 3:
            # raw_json is JSONB, so psycopg returns parsed values already.
            if isinstance(raw_example, (str, bytes)):
                try:
                    raw_example = json.loads(raw_example)
                except json.JSONDecodeError:
                    pass
            payload["raw_examples"].append(raw_example)

        identifier_domains[key].add(norm_target)
        identifier_meta.setdefault(
            key,
            {
                "id_type": str(row["id_type"]),
                "id_value": str(row["id_value"]),
                "tier": str(row["tier"]),
                "category": str(row["category"]),
            },
        )

    cert_issuance: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for query, issuer_col, source_label in [
        (
            """SELECT s.target, ct.issuer AS issuer, ct.not_before, ct.not_after
               FROM ct_certs ct JOIN searches s ON s.id = ct.search_id
               WHERE ct.search_id IN ({placeholders}) AND ct.not_before IS NOT NULL AND ct.not_before != ''""",
            "issuer",
            "ct_certs",
        ),
        (
            """SELECT s.target, t.issuer_cn AS issuer, t.not_before, t.not_after
               FROM tls_certs t JOIN searches s ON s.id = t.search_id
               WHERE t.search_id IN ({placeholders}) AND t.not_before IS NOT NULL AND t.not_before != ''""",
            "issuer",
            "tls_certs",
        ),
        (
            """SELECT s.target, h.issuer AS issuer, h.not_before, h.not_after
               FROM scan_hits h JOIN searches s ON s.id = h.search_id
               WHERE h.search_id IN ({placeholders}) AND h.not_before IS NOT NULL AND h.not_before != ''""",
            "issuer",
            "scan_hits",
        ),
    ]:
        for row in _query_rows_for_ids(c, query, latest_ids):
            norm_target = _normalize_target(str(row["target"] or ""))
            issuer = _normalize_generic_identifier(row[issuer_col])
            not_before = _safe_iso(row["not_before"])
            if not issuer or not not_before:
                continue
            cert_issuance[norm_target].append(
                {
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": _safe_iso(row["not_after"]),
                    "source": source_label,
                    "not_before_dt": _parse_dt(not_before),
                }
            )

    for domain_entry in domains.values():
        for payload in domain_entry["identifiers"].values():
            payload["sources"] = sorted(payload["sources"])

    return {
        "domains": domains,
        "identifier_domains": identifier_domains,
        "identifier_meta": identifier_meta,
        "cert_issuance": cert_issuance,
        "frequency_cache": {},
    }


def _identifier_frequency_profile(state: Mapping[str, Any], key: tuple[str, str], category: str) -> dict[str, Any]:
    cache_key = (key[0], key[1], category)
    cached = state["frequency_cache"].get(cache_key)
    if cached is not None:
        return cached

    domains = state["identifier_domains"].get(key, set())
    domain_count = len(domains)
    rules = _IDENTIFIER_FREQUENCY_RULES.get(category, _IDENTIFIER_FREQUENCY_RULES["generic"])
    downweight_after = int(rules["downweight_after"])
    exclude_after = int(rules["exclude_after"])

    if domain_count > exclude_after:
        status = "excluded"
        multiplier = 0.0
    elif domain_count > downweight_after:
        status = "downweighted"
        multiplier = max(0.2, downweight_after / max(domain_count, 1))
    else:
        status = "normal"
        multiplier = 1.0

    payload = {
        "domain_count": domain_count,
        "downweight_after": downweight_after,
        "exclude_after": exclude_after,
        "status": status,
        "multiplier": multiplier,
    }
    state["frequency_cache"][cache_key] = payload
    return payload


def _build_identifier_evidence(
    identifier_a: Mapping[str, Any],
    identifier_b: Mapping[str, Any],
    *,
    state: Mapping[str, Any],
) -> dict[str, Any]:
    key = (str(identifier_a["id_type"]), str(identifier_a["id_value"]))
    frequency = _identifier_frequency_profile(state, key, str(identifier_a["category"]))
    score_payload = _identifier_score(
        str(identifier_a["tier"]),
        str(identifier_a["category"]),
        multiplier=float(frequency["multiplier"]),
    )
    return {
        "id_type": identifier_a["id_type"],
        "id_value": identifier_a["id_value"],
        "label": _humanize_identifier_type(str(identifier_a["id_type"])),
        "tier": identifier_a["tier"],
        "category": identifier_a["category"],
        "sources_a": list(identifier_a.get("sources") or []),
        "sources_b": list(identifier_b.get("sources") or []),
        "first_seen_a": identifier_a.get("first_seen") or identifier_a.get("observed_at"),
        "first_seen_b": identifier_b.get("first_seen") or identifier_b.get("observed_at"),
        "last_seen_a": identifier_a.get("last_seen"),
        "last_seen_b": identifier_b.get("last_seen"),
        "domain_frequency": frequency["domain_count"],
        "frequency_status": frequency["status"],
        "frequency_multiplier": frequency["multiplier"],
        "base_score": score_payload["base_score"],
        "score": score_payload["score"],
        "confidence": score_payload["confidence"],
        "tier_label": score_payload["tier_label"],
        "rationale": _identifier_rationale(
            str(identifier_a["category"]),
            str(identifier_a["tier"]),
            str(frequency["status"]),
            int(frequency["domain_count"]),
        ),
    }


def _build_ct_timing_evidence(norm_a: str, norm_b: str, state: Mapping[str, Any]) -> list[dict[str, Any]]:
    left_rows = state["cert_issuance"].get(norm_a, [])
    right_rows = state["cert_issuance"].get(norm_b, [])
    if not left_rows or not right_rows:
        return []

    best_by_issuer: dict[tuple[str, str], dict[str, Any]] = {}
    for left in left_rows:
        left_dt = left.get("not_before_dt")
        if left_dt is None:
            continue
        for right in right_rows:
            right_dt = right.get("not_before_dt")
            if right_dt is None:
                continue
            if left["issuer"] != right["issuer"]:
                continue

            delta_hours = abs((left_dt - right_dt).total_seconds()) / 3600
            if delta_hours == 0:
                continue
            if delta_hours <= 24:
                id_type = "ct_issuer_timing_24h"
                tier = "tier_3"
                bonus = 6
            elif delta_hours <= 24 * 7:
                id_type = "ct_issuer_timing_7d"
                tier = "tier_4"
                bonus = 2
            else:
                continue

            score_payload = _identifier_score(tier, "tls_ct", bonus=bonus)
            evidence = {
                "id_type": id_type,
                "id_value": left["issuer"],
                "label": "CT Issuance Timing",
                "tier": tier,
                "category": "tls_ct",
                "sources_a": [left["source"]],
                "sources_b": [right["source"]],
                "first_seen_a": left["not_before"],
                "first_seen_b": right["not_before"],
                "last_seen_a": left.get("not_after"),
                "last_seen_b": right.get("not_after"),
                "domain_frequency": None,
                "frequency_status": "pairwise",
                "frequency_multiplier": 1.0,
                "base_score": score_payload["base_score"],
                "score": score_payload["score"],
                "confidence": score_payload["confidence"],
                "tier_label": score_payload["tier_label"],
                "delta_hours": round(delta_hours, 2),
                "rationale": _identifier_rationale("tls_ct", tier, "pairwise", None),
            }
            key = (left["issuer"], id_type)
            if key not in best_by_issuer or evidence["score"] > best_by_issuer[key]["score"] or evidence["delta_hours"] < best_by_issuer[key]["delta_hours"]:
                best_by_issuer[key] = evidence

    return sorted(best_by_issuer.values(), key=lambda item: (item["score"], -item["delta_hours"]), reverse=True)


def _tier_sort_key(value: str) -> int:
    return _IDENTIFIER_TIER_ORDER.get(str(value or ""), 0)


def _compare_domains_from_state(
    domain_a: str,
    domain_b: str,
    state: Mapping[str, Any],
    *,
    include_filtered: bool = False,
) -> dict[str, Any] | None:
    normalized_a, type_a = _normalize_candidate_target(domain_a)
    normalized_b, type_b = _normalize_candidate_target(domain_b)
    if type_a != "domain" or type_b != "domain" or not normalized_a or not normalized_b:
        return None

    norm_a = _normalize_target(normalized_a)
    norm_b = _normalize_target(normalized_b)
    node_a = state["domains"].get(norm_a)
    node_b = state["domains"].get(norm_b)
    if node_a is None or node_b is None:
        return None

    shared_keys = set(node_a["identifiers"]).intersection(node_b["identifiers"])
    kept_evidence: list[dict[str, Any]] = []
    filtered_out: list[dict[str, Any]] = []

    for key in sorted(
        shared_keys,
        key=lambda item: (
            _tier_sort_key(node_a["identifiers"][item]["tier"]),
            node_a["identifiers"][item]["category"],
            item[0],
            item[1],
        ),
        reverse=True,
    ):
        evidence = _build_identifier_evidence(node_a["identifiers"][key], node_b["identifiers"][key], state=state)
        if evidence["frequency_status"] == "excluded" and not include_filtered:
            filtered_out.append(evidence)
            continue
        kept_evidence.append(evidence)

    kept_evidence.extend(_build_ct_timing_evidence(norm_a, norm_b, state))
    kept_evidence.sort(
        key=lambda item: (
            _tier_sort_key(str(item["tier"])),
            int(item["score"]),
            str(item["category"]),
            str(item["id_type"]),
            str(item["id_value"]),
        ),
        reverse=True,
    )

    tier_groups: dict[str, dict[str, Any]] = {}
    for evidence in kept_evidence:
        group = tier_groups.setdefault(
            str(evidence["tier"]),
            {
                "tier": evidence["tier"],
                "tier_label": _IDENTIFIER_TIER_LABELS.get(str(evidence["tier"]), str(evidence["tier"])),
                "score": 0,
                "confidence": "very_low",
                "categories": set(),
                "evidence": [],
            },
        )
        group["score"] += int(evidence["score"])
        group["categories"].add(str(evidence["category"]))
        group["evidence"].append(evidence)

    tiers = []
    for tier, payload in sorted(tier_groups.items(), key=lambda item: _tier_sort_key(item[0]), reverse=True):
        tier_score = min(100, int(payload["score"]))
        tiers.append(
            {
                "tier": tier,
                "tier_label": payload["tier_label"],
                "score": tier_score,
                "confidence": _identifier_confidence_label(tier_score),
                "categories": sorted(payload["categories"]),
                "evidence_count": len(payload["evidence"]),
                "evidence": payload["evidence"],
            }
        )

    distinct_categories = len({(item["tier"], item["category"]) for item in kept_evidence})
    distinct_tiers = len({item["tier"] for item in kept_evidence})
    score = min(
        100,
        sum(int(item["score"]) for item in kept_evidence)
        + max(0, distinct_categories - 1) * 4
        + max(0, distinct_tiers - 1) * 6,
    )

    return {
        "domain_a": node_a["target"],
        "domain_b": node_b["target"],
        "search_id_a": node_a["search_id"],
        "search_id_b": node_b["search_id"],
        "timestamp_a": node_a["timestamp"],
        "timestamp_b": node_b["timestamp"],
        "score": score,
        "confidence": _identifier_confidence_label(score),
        "shared_identifier_count": len(kept_evidence),
        "filtered_identifier_count": len(filtered_out),
        "matched_categories": sorted({item["category"] for item in kept_evidence}),
        "matched_tiers": [item["tier"] for item in tiers],
        "tiers": tiers,
        "filtered_out": filtered_out,
    }


def compare_domains(domain_a: str, domain_b: str) -> dict | None:
    init_db()
    with _conn() as c:
        state = _load_latest_domain_identifier_state(c)
    return _compare_domains_from_state(domain_a, domain_b, state)


def traverse_identifier_cluster(
    seed_domains: str | list[str],
    *,
    max_depth: int = 2,
    min_edge_score: int = 20,
    include_filtered: bool = False,
) -> dict[str, Any]:
    if isinstance(seed_domains, str):
        requested_seeds = [seed_domains]
    else:
        requested_seeds = [str(item) for item in (seed_domains or []) if str(item or "").strip()]

    init_db()
    with _conn() as c:
        state = _load_latest_domain_identifier_state(c)

    found_seeds: list[str] = []
    missing_seeds: list[str] = []
    seed_norms: list[str] = []
    seen_seed_norms: set[str] = set()
    for seed in requested_seeds:
        normalized, target_type = _normalize_candidate_target(seed)
        norm = _normalize_target(normalized) if normalized and target_type == "domain" else None
        if not norm or norm not in state["domains"]:
            missing_seeds.append(seed)
            continue
        if norm in seen_seed_norms:
            continue
        seen_seed_norms.add(norm)
        seed_norms.append(norm)
        found_seeds.append(state["domains"][norm]["target"])

    if not seed_norms:
        return {
            "seeds": [],
            "missing": missing_seeds,
            "component": {"domains": [], "identifiers": []},
            "edges": [],
        }

    visited = set(seed_norms)
    depth_map = {norm: 0 for norm in seed_norms}
    queue: deque[tuple[str, int]] = deque((norm, 0) for norm in seed_norms)
    component_identifier_keys: set[tuple[str, str]] = set()
    candidate_pairs: set[tuple[str, str]] = set()

    while queue:
        current, depth = queue.popleft()
        domain_entry = state["domains"][current]
        for key, identifier in domain_entry["identifiers"].items():
            frequency = _identifier_frequency_profile(state, key, str(identifier["category"]))
            if frequency["status"] == "excluded" and not include_filtered:
                continue

            domains_for_identifier = state["identifier_domains"].get(key, set())
            if len(domains_for_identifier) < 2:
                continue

            component_identifier_keys.add(key)
            for neighbor in domains_for_identifier:
                if neighbor == current:
                    continue
                candidate_pairs.add(tuple(sorted((current, neighbor))))
                if depth < max_depth and neighbor not in visited:
                    visited.add(neighbor)
                    depth_map[neighbor] = depth + 1
                    queue.append((neighbor, depth + 1))

    edges = []
    for left, right in sorted(candidate_pairs):
        comparison = _compare_domains_from_state(left, right, state, include_filtered=include_filtered)
        if not comparison or comparison["score"] < min_edge_score:
            continue
        comparison["hop_distance"] = min(depth_map.get(left, max_depth + 1), depth_map.get(right, max_depth + 1))
        edges.append(comparison)
        for tier_group in comparison["tiers"]:
            for evidence in tier_group["evidence"]:
                if evidence["domain_frequency"] is None:
                    continue
                component_identifier_keys.add((str(evidence["id_type"]), str(evidence["id_value"])))

    edges.sort(
        key=lambda item: (
            int(item["score"]),
            len(item["matched_categories"]),
            item["shared_identifier_count"],
            item["domain_a"],
            item["domain_b"],
        ),
        reverse=True,
    )

    identifier_nodes = []
    for key in sorted(
        component_identifier_keys,
        key=lambda item: (
            _tier_sort_key(state["identifier_meta"].get(item, {}).get("tier", "")),
            state["identifier_meta"].get(item, {}).get("category", ""),
            item[0],
            item[1],
        ),
        reverse=True,
    ):
        meta = state["identifier_meta"].get(key)
        if not meta:
            continue
        frequency = _identifier_frequency_profile(state, key, str(meta["category"]))
        component_domains = sorted(
            state["domains"][norm]["target"]
            for norm in state["identifier_domains"].get(key, set())
            if norm in visited and norm in state["domains"]
        )
        identifier_nodes.append(
            {
                "id_type": meta["id_type"],
                "id_value": meta["id_value"],
                "tier": meta["tier"],
                "tier_label": _IDENTIFIER_TIER_LABELS.get(str(meta["tier"]), str(meta["tier"])),
                "category": meta["category"],
                "domain_count": frequency["domain_count"],
                "component_domain_count": len(component_domains),
                "domains": component_domains,
                "frequency_status": frequency["status"],
            }
        )

    return {
        "seeds": found_seeds,
        "missing": missing_seeds,
        "component": {
            "domains": [state["domains"][norm]["target"] for norm in sorted(visited)],
            "identifiers": identifier_nodes,
        },
        "edges": edges,
    }


# ── Classification ────────────────────────────────────────────────────────────

_MAIL_ASNS = {"15169", "16276", "8075", "3215", "394161"}
_CDN_PROXY_ASNS = {"13335", "19551", "54113", "20940", "60626", "394536", "22822", "16625", "20473"}
_SHARED_HOSTING_ASNS = {"2635", "27647", "61493", "2025"}

_MAIL_PTR_PATTERNS = ("1e100.net", "google.com", "mail.ovh.", "smtp.", "mx.", "-mx-", "mail-", "mailout", "mxbiz")
_CDN_PROXY_PTR_PATTERNS = (
    "incapsula.com", "cloudflare.com", "cloudflare.net", "fastly.net",
    "akamai.net", "akamaiedge.net", "akamaized.net", "edgecast.net",
    "sucuri.net", "imperva.com", "cdn.", "cloudfront.net", "azurefd.net",
    "googleusercontent.com", "googlehosted.com", "b-cdn.net", "edgekey.net",
    "edgesuite.net", "trafficmanager.net", "myshopify.com", "pantheonsite.io",
    "webflow.io", "wixsite.com", "wpenginepowered.com",
)
_SHARED_HOSTING_PTR_PATTERNS = (
    "wildcard.", "weebly.com", "wordpress.com", "wix.com", "squarespace.com",
    "cluster", "shared-", "hosting.", "hostinger", "bluehost", "siteground",
    "dreamhost", "namecheap", "godaddy", "ovh.net", "o2switch.net",
)
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


def _build_ip_label_index(c: psycopg.Connection[Any]) -> dict[tuple[int, str], str]:
    rows = c.execute(
        """SELECT search_id, ip, ptr, asn, source, proxy_family
           FROM ips"""
    ).fetchall()
    labels: dict[tuple[int, str], str] = {}
    for row in rows:
        ip = str(row["ip"] or "").strip()
        if not ip:
            continue
        key = (int(row["search_id"]), ip)
        label = classify_ip(ip, row["ptr"], row["asn"], row["source"], row["proxy_family"])
        if key not in labels or labels[key] != "direct":
            labels[key] = label
    return labels


def _is_low_signal_tls_observation(row: Mapping[str, Any], ip_label_index: Mapping[tuple[int, str], str]) -> bool:
    ip = str(row.get("ip") or "").strip()
    search_id = row.get("search_id")
    if ip and search_id is not None:
        label = ip_label_index.get((int(search_id), ip))
        if _is_noise_label(label):
            return True

    texts = [row.get("cn"), row.get("issuer")]
    if any(_text_contains_any(value, _LOW_SIGNAL_HOSTING_PATTERNS) for value in texts):
        return True
    return any(_is_low_signal_tls_identity(value) for value in texts)


# ── Cluster helpers ───────────────────────────────────────────────────────────

def _latest_ids(c: psycopg.Connection[Any]) -> list[int]:
    return [int(row["id"]) for row in _latest_search_rows(c)]


def _aggregate_targets(rows: list[dict[str, Any]], key_fn) -> dict[Any, dict[str, Any]]:
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
        if _is_noise_label(label):
            continue
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


def _load_tls_observations(c: psycopg.Connection[Any]) -> list[dict[str, Any]]:
    rows = c.execute(
        """SELECT s.id AS search_id, s.target, t.ip, t.sha256, t.cn, t.issuer_cn AS issuer, t.not_before, t.not_after,
                  t.observed_at, 'tls_probe' AS source
           FROM tls_certs t JOIN searches s ON s.id = t.search_id
           WHERE t.sha256 IS NOT NULL AND t.sha256 != ''
           UNION ALL
           SELECT s.id AS search_id, s.target, h.ip, h.sha256, h.cn, h.issuer AS issuer, h.not_before, h.not_after,
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
        ip_label_index = _build_ip_label_index(c)
        grouped: dict[str, dict[str, Any]] = {}
        for row in _load_tls_observations(c):
            if _is_low_signal_tls_observation(row, ip_label_index):
                continue
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
        if _is_noise_label(entry["label"]):
            continue
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
                    WHERE x.search_id IN ({{placeholders}}) AND x.{column} = %s""",
                latest_ids,
                (value,),
            )
            return _row_target_list(rows, exclude_norm=norm_target)

        whois = c.execute(
            "SELECT registrar, creation_date, expiry_date, org, country FROM whois_data WHERE search_id = %s ORDER BY id DESC LIMIT 1",
            (current_sid,),
        ).fetchone()

        tracking = []
        for row in c.execute("SELECT id_type, id_value FROM tracking_ids WHERE search_id = %s", (current_sid,)).fetchall():
            tracking.append({"id_type": row["id_type"], "id_value": row["id_value"], "shared_with": _others_by("tracking_ids", "id_value", row["id_value"])})

        ips = []
        seen_ips: set[str] = set()
        for row in c.execute(
            """SELECT ip, source, ptr, asn, asn_desc, country, cloudflare, network_cidr, proxy_family
               FROM ips WHERE search_id = %s""",
            (current_sid,),
        ).fetchall():
            ip = row["ip"]
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            asn = _normalize_asn(row["asn"])
            label = classify_ip(ip, row["ptr"], asn, row["source"], row["proxy_family"])
            if _is_noise_label(label):
                continue
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
               FROM ips WHERE search_id = %s AND asn IS NOT NULL AND asn != ''""",
            (current_sid,),
        ).fetchall():
            asn = _normalize_asn(row["asn"])
            if not asn or asn in seen_asns:
                continue
            label = classify_ip("0.0.0.0", row["ptr"], asn, row["source"], row["proxy_family"])
            if _is_noise_label(label):
                continue
            seen_asns.add(asn)
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
        ip_label_index = _build_ip_label_index(c)
        for row in c.execute(
            """SELECT sha256, cn, sans, issuer_cn, ip, not_before, not_after
               FROM tls_certs WHERE search_id = %s""",
            (current_sid,),
        ).fetchall():
            fingerprint = row["sha256"]
            if not fingerprint or fingerprint in seen_tls:
                continue
            tls_row = {
                "search_id": current_sid,
                "ip": row["ip"],
                "cn": row["cn"],
                "issuer": row["issuer_cn"],
            }
            if _is_low_signal_tls_observation(tls_row, ip_label_index):
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
               FROM provider_hits WHERE search_id = %s""",
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
                               WHERE p.search_id IN ({placeholders}) AND p.provider = %s AND p.ip = %s""",
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
            if _is_low_signal_tls_observation(observation, ip_label_index):
                continue
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
        for row in c.execute("SELECT md5 FROM favicons WHERE search_id = %s", (current_sid,)).fetchall():
            favicons.append({"md5": row["md5"], "shared_with": _others_by("favicons", "md5", row["md5"])})

        emails = []
        for row in c.execute("SELECT email FROM registrant_emails WHERE search_id = %s", (current_sid,)).fetchall():
            email = row["email"]
            if email in _GENERIC_EMAILS:
                continue
            emails.append({"email": email, "shared_with": _others_by("registrant_emails", "email", email)})

        nameservers = []
        for row in c.execute("SELECT nameserver FROM nameservers WHERE search_id = %s", (current_sid,)).fetchall():
            nameservers.append({"nameserver": row["nameserver"], "shared_with": _others_by("nameservers", "nameserver", row["nameserver"])})

        identifiers = []
        if current_row["type"] == "domain":
            identifier_state = _load_latest_domain_identifier_state(c)
            current_identifier_node = identifier_state["domains"].get(norm_target)
            if current_identifier_node:
                for key, payload in sorted(
                    current_identifier_node["identifiers"].items(),
                    key=lambda item: (
                        _tier_sort_key(str(item[1]["tier"])),
                        str(item[1]["category"]),
                        str(item[1]["id_type"]),
                        str(item[1]["id_value"]),
                    ),
                    reverse=True,
                ):
                    shared_domains = [
                        identifier_state["domains"][domain_norm]["target"]
                        for domain_norm in sorted(identifier_state["identifier_domains"].get(key, set()))
                        if domain_norm != norm_target
                    ]
                    if not shared_domains:
                        continue
                    frequency = _identifier_frequency_profile(identifier_state, key, str(payload["category"]))
                    score_payload = _identifier_score(
                        str(payload["tier"]),
                        str(payload["category"]),
                        multiplier=float(frequency["multiplier"]),
                    )
                    identifiers.append(
                        {
                            "id_type": payload["id_type"],
                            "id_value": payload["id_value"],
                            "tier": payload["tier"],
                            "tier_label": _IDENTIFIER_TIER_LABELS.get(str(payload["tier"]), str(payload["tier"])),
                            "category": payload["category"],
                            "sources": list(payload.get("sources") or []),
                            "first_seen": payload.get("first_seen") or payload.get("observed_at"),
                            "last_seen": payload.get("last_seen"),
                            "shared_with": shared_domains,
                            "domain_frequency": frequency["domain_count"],
                            "frequency_status": frequency["status"],
                            "score": score_payload["score"],
                            "confidence": score_payload["confidence"],
                        }
                    )

        discovered_groups: dict[tuple[str, str], dict[str, Any]] = {}
        for row in c.execute(
            """SELECT target, target_type, relation, source, score
               FROM discovered_targets
               WHERE search_id = %s
               ORDER BY score DESC, target ASC""",
            (current_sid,),
        ).fetchall():
            key = (row["target"], row["target_type"])
            entry = discovered_groups.setdefault(
                key,
                {
                    "target": row["target"],
                    "target_type": row["target_type"],
                    "score": 0,
                    "sources": set(),
                    "relations": set(),
                },
            )
            entry["score"] += int(row["score"] or 0)
            entry["sources"].add(row["source"])
            entry["relations"].add(row["relation"])

        discovered_domains = []
        discovered_ips = []
        for entry in sorted(discovered_groups.values(), key=lambda item: (-item["score"], item["target"])):
            payload = {
                "target": entry["target"],
                "target_type": entry["target_type"],
                "score": entry["score"],
                "sources": sorted(entry["sources"]),
                "relations": sorted(entry["relations"]),
                "shared_with": _others_by("discovered_targets", "target", entry["target"]),
            }
            if entry["target_type"] == "domain":
                discovered_domains.append(payload)
            else:
                discovered_ips.append(payload)

        social = [dict(row) for row in c.execute("SELECT platform, handle, url FROM social_accounts WHERE search_id = %s", (current_sid,)).fetchall()]
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
                "identifiers": identifiers,
                "discovered_domains": discovered_domains,
                "discovered_ips": discovered_ips,
            },
            "social": social,
        }
