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

import base64
import binascii
import hashlib
import json
import logging
import os
import ipaddress
import re
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Mapping, NamedTuple
from urllib.parse import urlsplit

from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

LOGGER = logging.getLogger("ip_intel.intel_db")

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


_PROVIDER_ORIGIN_KEYS = ("censys", "shodan", "netlas")
_GRAPH_REBUILD_LOCK_KEY = 882_417_310


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

CREATE TABLE IF NOT EXISTS registrant_names (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    search_id   BIGINT  NOT NULL REFERENCES searches(id),
    name        TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_registrant_name_search_id ON registrant_names(search_id);
CREATE INDEX IF NOT EXISTS idx_registrant_name_value     ON registrant_names(name);

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

-- ── Domain tier classification (curated, durable — NOT rebuildable) ──────────
-- Keyed on registrable_domain rather than search_id, so it survives rescans
-- instead of living and dying with one point-in-time search result the way
-- search_fields does. Not part of the append-only raw substrate (it isn't
-- something a scan observed) and not part of the derived/rebuildable
-- correlation layer below either (rebuild_clusters / rebuild_all_correlation
-- must never touch it) — it's authoritative curated metadata, currently fed
-- by the OpenCTI tier-1..tier-5 channel labels (see
-- integrations/opencti_ingest.py), edited only by whoever sets it.
CREATE TABLE IF NOT EXISTS domain_tiers (
    registrable_domain  TEXT PRIMARY KEY,
    tier                SMALLINT NOT NULL CHECK (tier BETWEEN 1 AND 5),
    source              TEXT,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_domain_tiers_tier ON domain_tiers(tier);

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

-- The shared nodes that actually tie each cluster together: for every attributing
-- selector / non-noise shared IP that unioned two or more of a cluster's members,
-- one row saying what it is and how many members it connects. This is the "why"
-- behind a cluster — rebuilt alongside graph_clusters.
CREATE TABLE IF NOT EXISTS graph_cluster_links (
    cluster_id    TEXT    NOT NULL,   -- matches graph_clusters.cluster_id
    node_type     TEXT    NOT NULL,   -- 'selector' | 'ip'
    kind          TEXT    NOT NULL,   -- selector kind, or 'shared_ip'
    value         TEXT    NOT NULL,
    member_count  INTEGER NOT NULL,   -- cluster members that share this node
    computed_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_graph_cluster_links_cid ON graph_cluster_links(cluster_id);

-- Direct, pairwise connection degree per registrable domain: the count of
-- distinct *other* domains it has a scored connection to (check.links_for's
-- min_score threshold — the same engine and cutoff used everywhere else a
-- connection is shown), never crossing an intermediary the way graph_clusters'
-- transitive components can. This is the "connections" count on the pool page.
-- Rebuilt alongside graph_clusters.
CREATE TABLE IF NOT EXISTS graph_connection_counts (
    registrable_domain  TEXT    PRIMARY KEY,
    connection_count    INTEGER NOT NULL,
    computed_at         TEXT
);

-- Every domain's full scored connection list (check.links_for's own output,
-- not just the count above) — computed once per rebuild pass instead of live
-- on every /api/graph/connections request. This is what makes opening a large
-- cluster's network graph fast: connections_among() reads each member's row
-- here (an O(1) indexed lookup) instead of running the pairwise
-- shared_selectors_between/shared_ips_between queries for every pair in the
-- set. A domain with no row in graph_connection_counts hasn't been through a
-- rebuild pass yet (e.g. ingested in the last _CLUSTER_REBUILD_INTERVAL
-- seconds) — intel_db.cached_links_for() signals that with None so the caller
-- can fall back to a live score instead of misreading "not yet computed" as
-- "no connections". Rebuilt alongside graph_clusters.
CREATE TABLE IF NOT EXISTS graph_links (
    registrable_domain  TEXT    NOT NULL,
    target              TEXT    NOT NULL,
    score               NUMERIC NOT NULL,
    confidence          INTEGER NOT NULL,
    strength            TEXT    NOT NULL,
    shared_node_count   INTEGER NOT NULL,
    evidence            JSONB   NOT NULL,
    computed_at         TEXT,
    PRIMARY KEY (registrable_domain, target)
);
CREATE INDEX IF NOT EXISTS idx_graph_links_rd ON graph_links(registrable_domain);

-- Materialized "browse by shared edge" groups: every attributing selector (or
-- non-noise shared IP) that ties 2+ registrable domains together, independent
-- of the clustering fanout cap (this is enumeration, not graph unioning).
-- Rebuilt alongside graph_clusters, never live on request.
CREATE TABLE IF NOT EXISTS graph_selector_groups (
    kind          TEXT    NOT NULL,   -- selector kind, or 'shared_ip'
    value         TEXT    NOT NULL,
    degree        INTEGER NOT NULL,
    domains       TEXT[]  NOT NULL,
    computed_at   TEXT,
    PRIMARY KEY (kind, value)
);
CREATE INDEX IF NOT EXISTS idx_graph_selector_groups_kind ON graph_selector_groups(kind, degree DESC);

-- Precomputed multi-hop reachability: for every registrable domain, every
-- OTHER domain reachable within GRAPH_PATH_MAX_HOPS through the scored
-- adjacency in graph_links, with the actual hop-by-hop evidence chain baked
-- in. Rebuilt in the same pass as graph_links (rebuild_clusters), so "why is
-- A related to C" is always an indexed SELECT, never a live traversal
-- triggered by a search or page load.
CREATE TABLE IF NOT EXISTS graph_paths (
    registrable_domain  TEXT    NOT NULL,
    target              TEXT    NOT NULL,
    hops                INTEGER NOT NULL,
    min_hop_score       NUMERIC NOT NULL,
    chain               JSONB   NOT NULL,
    computed_at         TEXT,
    PRIMARY KEY (registrable_domain, target)
);
CREATE INDEX IF NOT EXISTS idx_graph_paths_rd ON graph_paths(registrable_domain, hops);

CREATE TABLE IF NOT EXISTS graph_state (
    id                  BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    dirty               BOOLEAN NOT NULL DEFAULT TRUE,
    dirty_at            TIMESTAMPTZ,
    clean_at            TIMESTAMPTZ,
    rebuild_started_at  TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO graph_state (id, dirty, dirty_at)
VALUES (TRUE, TRUE, NOW())
ON CONFLICT (id) DO NOTHING;

-- Censys host-enrichment daily budget. It lives on graph_state because that is
-- the schema's only singleton state row, and unlike the rest of the
-- correlation tables it is never DELETEd/TRUNCATEd by a graph rebuild (see
-- rebuild_graph) — a counter that reset on every rebuild would let a sweep
-- blow straight through the plan's 20k/day cap. Added as ALTERs rather than
-- new columns in the CREATE above so existing deployments pick them up:
-- init_db() re-runs every statement here on each process start.
ALTER TABLE graph_state ADD COLUMN IF NOT EXISTS censys_enrichment_day   DATE;
ALTER TABLE graph_state ADD COLUMN IF NOT EXISTS censys_enrichment_count INTEGER NOT NULL DEFAULT 0;

-- Continuous-maintenance state for the derived graph, same singleton row and
-- same reasoning as the Censys counters above: it must survive the rebuilds
-- that empty every other correlation table, so it cannot live in one of them.
-- dirty_domains is the incremental rescore queue -- the registrable domains
-- whose materialized link scores a recent write invalidated (see
-- _mark_graph_dirty / apply_pending_graph_rescores). full_reconcile_at is when
-- the last full rebuild_all_correlation finished, which is what paces the
-- periodic reconcile, and incremental_at is purely observability.
-- Note: schema_statements() splits this string on semicolons, so prose here
-- must never contain one.
ALTER TABLE graph_state ADD COLUMN IF NOT EXISTS dirty_domains     TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE graph_state ADD COLUMN IF NOT EXISTS full_reconcile_at TIMESTAMPTZ;
ALTER TABLE graph_state ADD COLUMN IF NOT EXISTS incremental_at    TIMESTAMPTZ;
-- Seed the reconcile clock on first upgrade only (the column is NULL exactly
-- once, on the deployment that introduces it). Without this a NULL would read
-- as "infinitely overdue" and every process start would kick off a full
-- reconcile of the whole corpus.
UPDATE graph_state SET full_reconcile_at = NOW() WHERE full_reconcile_at IS NULL;

-- Per-IP home for host enrichment. The scalar fields it can improve (asn,
-- asn_desc, country, network_name, network_cidr) already have columns above and
-- are filled by merge_censys_enrichment on the scan path. These two carry what
-- no other provider gives us (reputation, GreyNoise, VPN/proxy/hosting
-- classification, service labels) plus the marker the pool sweep uses to tell
-- an un-enriched IP from one Censys has simply never seen.
-- Note: schema_statements() splits this string on semicolons, so prose here
-- must never contain one.
ALTER TABLE ips ADD COLUMN IF NOT EXISTS censys_enrichment  JSONB;
ALTER TABLE ips ADD COLUMN IF NOT EXISTS censys_enriched_at TEXT;
CREATE INDEX IF NOT EXISTS idx_ips_censys_enriched ON ips(censys_enriched_at);

"""


_CHILD_TABLES = [
    "ips", "tls_certs", "ct_certs", "subdomains", "dns_records",
    "historical_dns", "tracking_ids", "social_accounts", "favicons",
    "whois_data", "registrant_emails", "registrant_names", "nameservers", "spf_origins",
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
    "firebaseapp.com",
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
    "web.app",
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
    "firebaseapp.com",
    "github.com",
    "github.io",
    "githubusercontent.com",
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
    "web.app",
    "webflow.io",
    "weebly.com",
    "wix.com",
    "wixsite.com",
    "wordpress.com",
    "wpengine.com",
    "wpenginepowered.com",
    # Google's front-end (GFE) certs bundle dozens of unrelated Google
    # products/services as SANs on one shared cert served off shared IPs —
    # translate.goog (the Google Translate proxy many sites are viewed
    # through), blogspot.com (Blogger), and ad/asset domains like
    # doubleclickusercontent.com or usercontent.goog. Any two sites that each
    # touch Google's infrastructure anywhere (a translated page, an ad slot, a
    # Blogger-hosted property) end up sharing 20+ of these SANs even though
    # neither controls the cert — without this, that repetition alone was
    # enough to push unrelated pairs to "strong" (e.g. a Blogger blog and a
    # site that gets fetched through Google Translate).
    "blogger.com",
    "blogspot.com",
    "doubleclick.net",
    "doubleclickusercontent.com",
    "ggpht.com",
    "google.com",
    "googleadservices.com",
    "googledrive.com",
    "googlesyndication.com",
    "googletagmanager.com",
    "googleweblight.com",
    "gstatic.com",
    "translate.goog",
    "usercontent.goog",
    "youtube.com",
    "ytimg.com",
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

# WHOIS privacy-service boilerplate: registrar-inserted placeholder text
# standing in for a redacted registrant, or a registrar's own generic
# abuse/support contact. Neither identifies a specific registrant, so
# matching one across two domains is not evidence of common ownership —
# without this filter, e.g. every GDPR-masked .com domain or every
# reg.ru customer would spuriously "connect" to every other one.
_WHOIS_REDACTED_VALUES = {
    "redacted",
    "redacted for privacy",
    "not disclosed",
    "n/a",
    "na",
    "none",
    "unknown",
    "withheld",
}

_WHOIS_REDACTED_PATTERNS = (
    "redacted for privacy",
    "data protected",
    "not disclosed",
    "not publicly disclosed",
    "non-public data",
    "personal data",
    "gdpr masked",
    "statutory masking",
    "withheld for privacy",
    "privacy protect",
    "privacy service",
    "whoisguard",
    "whois privacy",
    "whois agent",
    "domains by proxy",
    "perfect privacy",
    "contact privacy",
    "identity protection",
    "private registration",
    "privacydotlink",
    "see privacyguardian",
    "on behalf of",
    "registration private",
)


def _is_redacted_whois_value(value: Any) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return True
    if text in _WHOIS_REDACTED_VALUES:
        return True
    return _text_contains_any(text, _WHOIS_REDACTED_PATTERNS)


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
_CORRELATION_TABLES = ["graph_state", "graph_links", "graph_connection_counts", "graph_selector_groups", "graph_cluster_links", "graph_clusters", "entity_edges", "observations", "selectors", "entities"]

_ALL_TABLES = ["searches", *_CHILD_TABLES, "identifiers", "search_fields", *_CORRELATION_TABLES]

_SCHEMA_LOCK = threading.Lock()
_SCHEMA_READY = False

# Arbitrary constant used as a Postgres advisory lock key so concurrent workers
# do not race each other while creating the schema.
_SCHEMA_ADVISORY_LOCK_KEY = 882_417_309


def schema_statements() -> list[str]:
    return [stmt.strip() for stmt in _SCHEMA.strip().split(";") if stmt.strip()]


# How long a schema statement will wait for a lock before giving up. The DDL is
# all `IF NOT EXISTS`, so on an initialized database every statement is a no-op
# — but a no-op `CREATE INDEX IF NOT EXISTS` still takes a lock on its table to
# decide that, and a lock request that cannot be granted *queues*, blocking
# every later request on that table behind it. See _schema_objects_present.
_SCHEMA_LOCK_TIMEOUT = os.environ.get("SCHEMA_LOCK_TIMEOUT", "5s")


def _expected_schema_relations() -> list[str]:
    """Every table and index name the schema declares.

    Parsed from the DDL rather than hardcoded so a relation added to _SCHEMA is
    covered automatically — a hardcoded list would silently stop creating new
    indexes the moment someone added one.
    """
    names: list[str] = list(_ALL_TABLES)
    for stmt in schema_statements():
        match = re.search(
            r"CREATE\s+INDEX\s+IF\s+NOT\s+EXISTS\s+(\w+)", stmt, re.IGNORECASE
        )
        if match:
            names.append(match.group(1))
    return names


def _schema_objects_present() -> bool:
    """Is every declared table and index already there?

    One indexed catalog read, taking no locks on any application table. This is
    the fast path that makes init_db free on an already-initialized database.

    It exists because the old unconditional DDL loop was a live hazard, not a
    micro-optimization. Every statement ran in ONE transaction, so blocking on
    the last table meant holding locks on every earlier one — and a scan's
    `INSERT INTO searches` was observed waiting 9 minutes behind a
    `CREATE INDEX ... ON graph_clusters` that was itself waiting on a long
    rebuild transaction. Two unrelated tables, one stalled pipeline, purely
    because re-asserting an existing schema is not actually free.
    """
    expected = _expected_schema_relations()
    try:
        with _conn() as c:
            row = c.execute(
                # DISTINCT and visibility-scoped: pg_class spans every schema,
                # so a same-named relation in another one would otherwise count
                # towards ours and let a genuinely incomplete schema pass.
                "SELECT count(DISTINCT relname) AS n FROM pg_class "
                " WHERE relname = ANY(%s) AND pg_table_is_visible(oid)",
                (expected,),
            ).fetchone()
    except Exception:
        # Cannot tell — fall through to the DDL, which will raise a better error.
        return False
    return int((row or {}).get("n") or 0) >= len(set(expected))


def init_db() -> None:
    """Create the schema once per process (idempotent and concurrency-safe)."""
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return
    with _SCHEMA_LOCK:
        if _SCHEMA_READY:
            return
        if _schema_objects_present():
            _SCHEMA_READY = True
            return
        with _conn() as c:
            # Belt and braces for the genuinely-missing-schema path: even here a
            # statement must fail fast rather than queue behind a long
            # transaction while holding locks on everything it already touched.
            # The caller sees the error and retries on the next call, which is
            # strictly better than stalling every writer in the process.
            c.execute(f"SET LOCAL lock_timeout = '{_SCHEMA_LOCK_TIMEOUT}'")
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


# PSL entries that are technically registrable suffixes (like `co.uk`) but
# that, unlike `co.uk`, aren't independently-registered per second-level
# label in practice — everything under them belongs to one organization.
# Without this override each of sso.gov.il / login.gov.il / maintenance.gov.il
# would roll up to itself instead of to gov.il, silently splitting one entity
# into many and hiding the fact they're all the same government network.
_APEX_SUFFIX_OVERRIDES = frozenset({"gov.il"})


def registrable_domain(value: Any) -> str | None:
    """eTLD+1 (registrable apex) for a hostname, public-suffix aware.

    Uses the Public Suffix List (via tldextract's offline snapshot) so multi-
    label suffixes like `co.uk`, `com.au`, `co.jp` roll up correctly — e.g.
    `news.bbc.co.uk` -> `bbc.co.uk`, not `co.uk`. Getting this right matters at
    graph scale: the registrable domain is the entity-rollup key, so a wrong
    apex would merge unrelated ccTLD domains into one node. Falls back to the
    last-two-labels heuristic if tldextract is unavailable. Returns None for IPs
    or anything that is not a hostname.

    `_APEX_SUFFIX_OVERRIDES` handles the inverse case: a handful of PSL
    suffixes (e.g. `gov.il`) are registered as suffixes but are, for this
    product's purposes, really just one apex — so the suffix itself is
    returned as the apex rather than `<label>.<suffix>`.
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
            if extracted.suffix in _APEX_SUFFIX_OVERRIDES:
                return extracted.suffix
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


def _as_dict(value: Any) -> dict[str, Any]:
    """Return `value` if it's a dict, else an empty dict.

    Guards the persistence layer against upstream shape drift: a payload field
    that is normally a dict (e.g. `whois`, `page_metadata`, a provider result)
    occasionally arrives as a list. The common ``result.get("x") or {}`` idiom
    does *not* catch that — a non-empty list is truthy, so it passes through and
    the following ``.get(...)`` raises ``'list' object has no attribute 'get'``,
    which aborts the whole best-effort save and drops the result from the pool.
    Coercing at each dict access keeps one malformed field from losing the row.
    """
    return value if isinstance(value, dict) else {}


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

    dns = _as_dict(result.get("dns"))
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

    for whois_ns in _parse_json_list(_as_dict(result.get("whois")).get("nameservers")):
        add(whois_ns, "whois_nameserver", "whois_nameserver")

    for subdomain in result.get("subdomains", []) or []:
        add(subdomain, "subdomain", "subdomain")
    for subdomain in result.get("zone_transfer", []) or []:
        add(subdomain, "zone_transfer", "zone_transfer")

    historical = _as_dict(result.get("historical_dns"))
    for record in historical.get("records", []) or []:
        if not isinstance(record, dict):
            continue
        if str(record.get("rrtype") or "").upper() in {"A", "AAAA"}:
            add(record.get("rdata"), "historical_ip", "historical_dns", record)

    for entry in result.get("spf_origins", []) or []:
        if isinstance(entry, dict):
            add(entry.get("ip"), "spf_origin", "spf", entry)

    # See the ct_certs projection below for why this reads `crt_sh` first: the
    # `cert_transparency` spelling is never present in any payload, so every
    # CT-derived observation here was silently empty. Note `cross_domain_sans`
    # genuinely does not exist under crt_sh (that key came from the retired
    # async engine) — the SANs on each cert are what carries the signal now.
    cert_transparency = _as_dict(result.get("crt_sh")) or _as_dict(result.get("cert_transparency"))
    for san in cert_transparency.get("cross_domain_sans", []) or []:
        add(san, "cross_domain_san", "cross_san")
    for cert in cert_transparency.get("certs", []) or []:
        for san in cert.get("sans", []) or []:
            add(san, "certificate_san", "ct_san")

    origin = _origin_candidates(result)
    for key, source_name, relation_name, subdomain_key in [
        ("subdomain_leaks", "subdomain_leak", "subdomain_leak", "subdomain"),
        ("mx_leaks", "mx_leak", "mx_leak", "subdomain"),
        ("wordlist_leaks", "wordlist_leak", "wordlist_leak", "subdomain"),
        ("hackertarget", "subdomain_leak", "hackertarget_host", "subdomain"),
        ("viewdns", "subdomain_leak", "viewdns_host", "subdomain"),
    ]:
        for entry in origin.get(key, []) or []:
            if not isinstance(entry, dict):
                continue
            add(entry.get("ip"), "origin_ip", source_name, entry)
            add(entry.get(subdomain_key), relation_name, source_name, entry)

    for entry in origin.get("urlscan", []) or []:
        if not isinstance(entry, dict):
            continue
        add(entry.get("ip"), "origin_ip", "origin_hit", entry)
        add(entry.get("url"), "urlscan_url", "urlscan_url", entry)

    for provider_key in ("censys", "shodan", "netlas"):
        provider_result = _as_dict(origin.get(provider_key))
        for hit in provider_result.get("hits", []) or []:
            if not isinstance(hit, dict):
                continue
            add(hit.get("ip"), "provider_ip", "provider_hit", hit)
            for hostname in hit.get("hostnames", []) or []:
                add(hostname, "provider_hostname", "provider_hit", hit)

    for scan_key in ("scan", "provider_scan", "country_scan"):
        scan_result = _as_dict(origin.get(scan_key))
        for hit in scan_result.get("hits", []) or []:
            if not isinstance(hit, dict):
                continue
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
        if not isinstance(cert, dict):
            continue
        add(cert.get("ip"), "tls_ip", "origin_hit", cert)
        add(cert.get("cn"), "tls_cn", "tls_cn", cert)
        for san in cert.get("sans", []) or []:
            add(san, "tls_san", "tls_san", cert)

    if isinstance(result.get("tls_cert"), dict):
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
    "viewdns_host",
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


def _origin_candidates(result: Mapping[str, Any]) -> dict[str, Any]:
    """Return origin candidates, backfilling legacy top-level provider hits.

    Live ingest promotes the active Censys result into ``origin_candidates``
    before persistence. This fallback keeps older raw search rows replayable
    during recompute without making dormant Shodan/Netlas paths active again.
    """
    raw_origin = result.get("origin_candidates")
    origin = dict(raw_origin) if isinstance(raw_origin, Mapping) else {}
    for provider in _PROVIDER_ORIGIN_KEYS:
        provider_result = result.get(provider)
        if provider not in origin and isinstance(provider_result, Mapping):
            origin[provider] = dict(provider_result)
    return origin


def _extract_ip_port_map(result: dict[str, Any]) -> dict[tuple[str, str], int | None]:
    mapping: dict[tuple[str, str], int | None] = {}
    origin = _origin_candidates(result)

    for provider in ("censys", "shodan", "netlas"):
        provider_result = _as_dict(origin.get(provider))
        for hit in provider_result.get("hits") or []:
            if not isinstance(hit, dict):
                continue
            ip = hit.get("ip")
            if ip:
                mapping[(ip, provider)] = hit.get("port")

    for scan_key, source in [
        ("scan", "scan_gcp"),
        ("provider_scan", "scan_provider"),
        ("country_scan", "scan_country"),
    ]:
        scan_result = _as_dict(origin.get(scan_key))
        for hit in scan_result.get("hits") or []:
            if not isinstance(hit, dict):
                continue
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
    """Reduce any spelling of a digest to lowercase hex, the stored form.

    Two producers disagree on how an SSH host-key SHA-256 is written:
    core/basic.py's probe emits raw lowercase hex, while
    sources/signal_transport.py emits OpenSSH's `SHA256:<base64>`. Lowercasing
    the latter used to be the *whole* of the handling here, which both failed
    to convert it to hex (so the same host key produced two unrelated values
    and never correlated) and destroyed base64's significant case (so two
    distinct keys could collide). Decode the base64 form to hex before any
    case folding; everything else keeps the previous behavior.
    """
    text = str(value or "").strip()
    if not text:
        return None

    base64_body = re.fullmatch(r"(?i:sha256):([A-Za-z0-9+/]{40,50}={0,2})", text)
    if base64_body:
        candidate = base64_body.group(1)
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            digest = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            digest = b""
        if len(digest) == 32:
            return digest.hex()

    text = text.lower()
    text = re.sub(r"^(sha256|spki|md5):", "", text)
    text = re.sub(r"\s+", "", text)
    if ":" in text and re.fullmatch(r"[0-9a-f:]+", text):
        text = text.replace(":", "")
    return text or None


def _ssh_host_key_records(result: Mapping[str, Any] | Any) -> list[Mapping[str, Any]]:
    """Every SSH host-key probe in a result, whichever engine wrote it.

    core/analysis_service.py stores `{"probes": [...]}` while core/ip_intel.py
    stores a bare list, and the two read sites here each understood only one of
    them: identifier extraction iterated the dict's *keys* (so case-pipeline
    scans contributed no tier-1 SSH identifiers at all), and the graph
    projection called `.get("probes")` on a list (the `'list' object has no
    attribute 'get'` that core/analysis_service.py's save-failure logging was
    written to chase down). Accept both here instead.
    """
    raw = result.get("ssh_host_keys") if isinstance(result, Mapping) else None
    if isinstance(raw, Mapping):
        raw = raw.get("probes")
    if not isinstance(raw, (list, tuple)):
        return []
    return [entry for entry in raw if isinstance(entry, Mapping) and not entry.get("error")]


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
    # Delegates to the extractor's normalizer so a number filed from a legal
    # page lands on the same key as the identical number seen on the homepage,
    # and so template/placeholder numbers are rejected here too rather than
    # only at scan time.
    from sources.signal_web import normalize_contact_phone

    return normalize_contact_phone(value)


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
    if id_type == "crypto_wallet":
        # "<chain>|<address>" — only the chain half is safe to fold; see
        # sources.signal_web.normalize_crypto_address.
        from sources.signal_web import normalize_crypto_address

        chain, _, address = str(value or "").partition("|")
        chain_key = _normalize_generic_identifier(chain)
        normalized = normalize_crypto_address(chain_key, address)
        return f"{chain_key}|{normalized}" if chain_key and normalized else None
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
            if not _is_redacted_whois_value(email):
                add(email, id_type="registrant_email", tier="tier_3", category="identity", source="whois.emails")
        for name in _normalize_text_list(whois_row.get("name")):
            if not _is_redacted_whois_value(name):
                add(name, id_type="registrant_name", tier="tier_3", category="identity", source="whois.name")
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

    for value in _normalize_text_list(page.get("phone_numbers") or []):
        add(value, id_type="contact_phone", tier="tier_3", category="identity", source="page_metadata.phone_numbers")

    wallets = page.get("crypto_wallets") or {}
    for chain, addresses in wallets.items():
        for address in _normalize_text_list(addresses or []):
            add(
                f"{_normalize_generic_identifier(chain) or chain}|{address}",
                id_type="crypto_wallet",
                tier="tier_1",
                category="identity",
                source=f"page_metadata.crypto_wallets.{chain}",
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

    # Prefer the structured {"rua": [...], "ruf": [...]} map. core/analysis_service
    # replaces `dmarc_report_uris` itself with a flat list of addresses (utils/
    # pairwise.py can only score that exact path, and a dict there scores
    # nothing), and stashes the tagged form under `dmarc_report_uris_by_tag`.
    # The isinstance guard is the load-bearing part: this used to be a bare
    # `or {}`, which passes a list straight through to `.get()` below and raises
    # AttributeError. save_search is called inside a try/except in
    # analyze_target, so that aborted persistence for the whole scan and
    # reported it as a warning — a searches row with no identifiers, no IPs and
    # no certs, from a scan that otherwise looked like it succeeded.
    dmarc_report_uris = email_security.get("dmarc_report_uris_by_tag")
    if not isinstance(dmarc_report_uris, Mapping):
        legacy = email_security.get("dmarc_report_uris")
        # Payloads stored before the split still carry the tagged dict here.
        dmarc_report_uris = legacy if isinstance(legacy, Mapping) else {}
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

    # `legal_pages` is the dict signal_web.scrape_legal_pages returns (per-page
    # entries under "pages", plus those pages' signals deduped up to the top
    # level). Iterating it directly walked its *keys* — six strings, every one
    # rejected by the Mapping guard below — so this whole block silently
    # produced no legal identifiers at all. The per-page entries are what we
    # want: same signals, but each carries the url that sourced it. A bare list
    # is the older payload shape, still accepted.
    legal_raw = result.get("legal_pages")
    if isinstance(legal_raw, Mapping):
        legal_pages = list(legal_raw.get("pages") or []) or [legal_raw]
    elif isinstance(legal_raw, list):
        legal_pages = legal_raw
    else:
        legal_pages = []
    for page_entry in legal_pages:
        if not isinstance(page_entry, Mapping):
            continue
        # extract_legal_page_signals names this `normalized_text_hash`; the old
        # `text_hash` key it looked for has never existed on these entries.
        add(page_entry.get("normalized_text_hash"), id_type="legal_text_hash", tier="tier_2", category="legal", source="legal_pages.text_hash", raw={"url": page_entry.get("url")})
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

    # Both engines' cert shapes, deduplicated — see the tls_certs insert for why
    # `tls_cert` and `tls_certs["probes"]` can be the same object. Reading only
    # the ip_intel spelling meant every case-pipeline domain scan contributed
    # zero cert-derived tier-1 identifiers.
    _cert_candidates = list(result.get("non_cf_tls_certs") or [])
    if result.get("tls_cert"):
        _cert_candidates.append(result["tls_cert"])
    _cert_candidates.extend((result.get("tls_certs") or {}).get("probes") or [])
    _seen_cert_ids: set[Any] = set()
    for cert in _cert_candidates:
        if not isinstance(cert, Mapping) or cert.get("error"):
            continue
        _fp = _normalize_identifier_hash(cert.get("sha256") or cert.get("fingerprint_sha256"))
        _identity = _fp or id(cert)
        if _identity in _seen_cert_ids:
            continue
        _seen_cert_ids.add(_identity)
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

    origin = _origin_candidates(result)
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

    # Same key fix as above: crt_sh is what the pipeline writes, so reading
    # `cert_transparency` alone meant no cert SAN ever became an identifier.
    cert_transparency = result.get("crt_sh") or result.get("cert_transparency") or {}
    for san in _normalize_text_list(cert_transparency.get("cross_domain_sans") or []):
        add(san, id_type="cross_san_domain", tier="tier_3", category="tls_ct", source="cert_transparency.cross_domain_sans")
    for cert in cert_transparency.get("certs") or []:
        if isinstance(cert, Mapping):
            _append_cert_identifiers(items, seen, cert, source="cert_transparency", observed_at=observed_at)

    for ssh_key in _ssh_host_key_records(result):
        # `fingerprint_sha256` first: signal_transport emits BOTH a prefixed
        # "SHA256:<b64>" (which _normalize_identifier_hash decodes to hex) and a
        # bare `sha256` base64 string (which it cannot recognise, and would
        # merely lowercase — losing base64's significant case and never joining
        # core/basic.py's hex). The graph projection already prefers this order;
        # this site had the opposite preference, so the two disagreed.
        add(ssh_key.get("fingerprint_sha256") or ssh_key.get("sha256"), id_type="ssh_host_key_sha256", tier="tier_1", category="ssh", source="ssh_host_keys", raw=ssh_key)
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


def set_domain_tier(registrable_domain: str, tier: int, *, source: str = "opencti") -> None:
    """Upsert a domain's tier classification (1-5). Durable — keyed on the
    registrable domain itself, not a search_id, so it survives rescans."""
    domain = str(registrable_domain or "").strip().lower()
    if not domain:
        return
    tier = int(tier)
    if tier < 1 or tier > 5:
        raise ValueError(f"tier must be 1-5, got {tier}")
    init_db()
    with _conn() as c:
        c.execute(
            """INSERT INTO domain_tiers (registrable_domain, tier, source, updated_at)
               VALUES (%s, %s, %s, NOW())
               ON CONFLICT (registrable_domain)
               DO UPDATE SET tier = EXCLUDED.tier, source = EXCLUDED.source, updated_at = NOW()""",
            (domain, tier, source),
        )


def clear_domain_tier(registrable_domain: str) -> None:
    """Remove a domain's tier classification. Rarely needed in practice (the
    tier is meant to stick once set) but the field is a normal editable
    column, not a one-way flag, so this exists for when it's wrong."""
    domain = str(registrable_domain or "").strip().lower()
    if not domain:
        return
    init_db()
    with _conn() as c:
        c.execute("DELETE FROM domain_tiers WHERE registrable_domain = %s", (domain,))


def get_domain_tier(registrable_domain: str) -> int | None:
    domain = str(registrable_domain or "").strip().lower()
    if not domain:
        return None
    init_db()
    with _conn() as c:
        row = c.execute(
            "SELECT tier FROM domain_tiers WHERE registrable_domain = %s", (domain,)
        ).fetchone()
    return int(row["tier"]) if row else None


def get_domain_tiers(domains: Iterable[str]) -> dict[str, int]:
    """Bulk lookup for graph/listing views — one query instead of one per node."""
    values = sorted({str(d or "").strip().lower() for d in domains if str(d or "").strip()})
    if not values:
        return {}
    init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT registrable_domain, tier FROM domain_tiers WHERE registrable_domain = ANY(%s)",
            (values,),
        ).fetchall()
    return {row["registrable_domain"]: int(row["tier"]) for row in rows}


def _save_child_tables(c: psycopg.Connection[Any], sid: int, result: dict, timestamp: str) -> None:
    """Write all structured child table rows from a result dict."""
    typ = result.get("type", "unknown")
    ip_details = _as_dict(result.get("ip_details"))
    ip_ports = _extract_ip_port_map(result)

    if typ == "domain":
        for ip, info in ip_details.items():
            info = _as_dict(info)
            sources = sorted(set(info.get("sources") or []))
            asn = _as_dict(info.get("asn_info"))
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
        asn = _as_dict(result.get("asn_info"))
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

    # Both engines' cert shapes. This used to read only `non_cf_tls_certs` /
    # `tls_cert` (core/ip_intel.py's spelling), so every cert the live case
    # pipeline probed — which writes `tls_certs.probes` with the fingerprint
    # under `fingerprint_sha256` — was dropped on the floor and this table
    # stayed empty for the whole web pipeline. The denylist's shared-hosting
    # bundle rules read these rows for each certificate's true SAN list, so an
    # empty table meant no bundle was ever detected.
    tls_list = list(result.get("non_cf_tls_certs") or [])
    if result.get("tls_cert"):
        tls_list.append(result["tls_cert"])
    tls_list.extend((result.get("tls_certs") or {}).get("probes") or [])
    # Deduplicate: core/analysis_service.py's IP path sets `tls_certs["probes"]`
    # to a list containing the very same dict as `tls_cert`, so reading both
    # shapes (which is what makes the case pipeline populate this table at all)
    # would otherwise write two identical rows per IP scan and double-count
    # every cert in _load_tls_observations and cluster_by_tls_cert.
    seen_certs: set[Any] = set()
    for cert in tls_list:
        if not isinstance(cert, dict) or cert.get("error"):
            continue
        fingerprint = _normalize_identifier_hash(
            cert.get("sha256") or cert.get("fingerprint_sha256")
        )
        # Keyed on (fingerprint, ip, port), not the fingerprint alone: one cert
        # served from several IPs is several genuine observations, and this
        # table records the ip/port it was seen on. Fingerprint-only dedupe
        # would silently drop every origin after the first. Falls back to object
        # identity when there is no usable hash, so such a cert is still
        # written exactly once.
        identity = (
            (fingerprint, cert.get("ip"), cert.get("port", 443)) if fingerprint else id(cert)
        )
        if identity in seen_certs:
            continue
        seen_certs.add(identity)
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
                _normalize_identifier_hash(cert.get("sha256") or cert.get("fingerprint_sha256")),
                _normalize_identifier_hash(cert.get("spki_sha256")), timestamp,
            ),
        )

    origin = _origin_candidates(result)
    for scan_key, scan_label in [("scan", "gcp"), ("provider_scan", "asn"), ("country_scan", "country")]:
        scan_result = _as_dict(origin.get(scan_key))
        if scan_result.get("skipped"):
            continue
        for hit in scan_result.get("hits") or []:
            if not isinstance(hit, dict) or not hit.get("ip"):
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
        provider_result = _as_dict(origin.get(provider))
        for hit in provider_result.get("hits") or []:
            if not isinstance(hit, dict):
                continue
            # `services` is deliberately no longer promoted out of the hit.
            # Censys host enrichment owns port/protocol data now
            # (censys_enrichment.services), and the cert search was billing
            # search credits for an overlapping port list on a second meter.
            # Nothing ever read this column — the provider_hits SELECT below
            # does not include it — and the full hit, services included, is
            # still archived in `raw_json`, so nothing is actually lost.
            c.execute(
                """INSERT INTO provider_hits
                   (search_id, provider, ip, port, protocol, asn, asn_desc, org, country, cloudflare,
                    hostnames, mode, status, query_type, total, observed_at, raw_json)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    sid, provider, hit.get("ip"), hit.get("port"), hit.get("protocol"),
                    _normalize_asn(hit.get("asn")),
                    hit.get("asn_name") or hit.get("asn_desc"),
                    hit.get("org"), hit.get("country"),
                    1 if hit.get("cloudflare") else 0,
                    _json(hit.get("hostnames", [])),
                    provider_result.get("mode"), provider_result.get("status"),
                    provider_result.get("query_type"), provider_result.get("total"),
                    timestamp, _json(hit),
                ),
            )

    # `crt_sh` first: that is the key core/basic.py's SERVICES registry writes
    # and the only one any current payload carries. This read used to be
    # `cert_transparency` alone — a spelling no pipeline has ever produced — so
    # `_as_dict` returned {} on every single scan and ct_certs/cross_sans stayed
    # empty database-wide (0 rows across 2,983 searches) while 1,291 payloads
    # sat there holding the certs. Same class of bug as the tls_certs one fixed
    # above, and found the same way: comparing what the JSONB payload holds
    # against what the relational table actually got.
    ct = _as_dict(result.get("crt_sh")) or _as_dict(result.get("cert_transparency"))
    for cert in ct.get("certs", []):
        if not isinstance(cert, dict):
            continue
        c.execute(
            "INSERT INTO ct_certs (search_id, cert_id, issuer, not_before, not_after, sans, observed_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (sid, cert.get("id"), cert.get("issuer"), cert.get("not_before"), cert.get("not_after"), _json(cert.get("sans", [])), timestamp),
        )
    for san in ct.get("cross_domain_sans", []):
        c.execute("INSERT INTO cross_sans (search_id, san) VALUES (%s,%s)", (sid, san))

    # crt.sh alone can return thousands of subdomains for a large org, so this
    # is batched with executemany instead of one INSERT round-trip per row.
    # Also read out of the crt_sh block. The top-level `subdomains` key this
    # used to read is likewise never present — crt.sh's subdomain list is nested
    # under `crt_sh.subdomains` (1,291 payloads carry it, and the table had 0
    # rows). The top-level spelling is kept as a fallback for any payload shape
    # that does supply it.
    subdomain_rows = [
        (sid, sub, "crt.sh")
        for sub in (ct.get("subdomains") or result.get("subdomains") or [])
        if isinstance(sub, str) and sub.strip()
    ] + [
        (sid, sub, "zone_transfer") for sub in result.get("zone_transfer", [])
    ]
    if subdomain_rows:
        c.cursor().executemany(
            "INSERT INTO subdomains (search_id, subdomain, source) VALUES (%s,%s,%s)",
            subdomain_rows,
        )

    dns = _as_dict(result.get("dns"))
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

    historical_rows = [
        (sid, rec.get("rrtype"), rec.get("rdata"), rec.get("first_seen"), rec.get("last_seen"))
        for rec in _as_dict(result.get("historical_dns")).get("records", [])
        if isinstance(rec, dict)
    ]
    if historical_rows:
        c.cursor().executemany(
            "INSERT INTO historical_dns (search_id, rrtype, rdata, first_seen, last_seen) VALUES (%s,%s,%s,%s,%s)",
            historical_rows,
        )

    for entry in result.get("spf_origins", []):
        c.execute("INSERT INTO spf_origins (search_id, ip, cidr) VALUES (%s,%s,%s)", (sid, entry.get("ip"), entry.get("cidr")))

    whois_row = _as_dict(result.get("whois"))
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
            if email and isinstance(email, str) and not _is_redacted_whois_value(email):
                c.execute("INSERT INTO registrant_emails (search_id, email) VALUES (%s,%s)", (sid, email.lower().strip()))
        for name in _normalize_text_list(whois_row.get("name")):
            if not _is_redacted_whois_value(name):
                c.execute("INSERT INTO registrant_names (search_id, name) VALUES (%s,%s)", (sid, name.strip()))
        for nameserver in ns_raw:
            c.execute("INSERT INTO nameservers (search_id, nameserver) VALUES (%s,%s)", (sid, nameserver))

    meta = _as_dict(result.get("page_metadata"))
    for id_type, key in [
        ("ga", "google_analytics"), ("gtm", "gtm_ids"), ("fb_pixel", "facebook_pixel"),
        ("tiktok_pixel", "tiktok_pixel"), ("yandex_metrika", "yandex_metrika"), ("adsense", "adsense_publisher_ids"),
    ]:
        for value in (meta.get(key) or []):
            c.execute("INSERT INTO tracking_ids (search_id, id_type, id_value) VALUES (%s,%s,%s)", (sid, id_type, str(value)))

    handles = _as_dict(meta.get("social_handles"))
    links = _as_dict(meta.get("social_links"))
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

    email_security = _as_dict(result.get("email_security"))
    c.execute(
        "INSERT INTO page_metadata (search_id, html_lang, cms_generator, favicon_md5, dmarc) VALUES (%s,%s,%s,%s,%s)",
        (sid, meta.get("html_lang"), meta.get("cms_generator"), favicon_md5, email_security.get("dmarc")),
    )

    discovered_rows = [
        (
            sid, item["target"], item["target_type"], item["relation"],
            item["source"], int(item.get("score") or 0), timestamp, _json(item.get("raw_json")),
        )
        for item in extract_related_targets(result)
    ]
    if discovered_rows:
        c.cursor().executemany(
            """INSERT INTO discovered_targets
               (search_id, target, target_type, relation, source, score, observed_at, raw_json)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            discovered_rows,
        )

    _refresh_search_identifiers(c, sid, result)


def finalize_search(search_id: int, result: dict, *, timestamp: str) -> None:
    """Complete a search: save all fields to search_fields + child tables, update searches row."""
    cf = result.get("cloudflare_fronted")
    cf_val = 1 if cf else (0 if cf is not None else None)
    related_summary = summarize_related_targets(result)

    result["search_id"] = search_id
    result["related_targets_summary"] = related_summary

    with _conn() as c:
        # `searches.source_errors` is no longer written: the retry path that was
        # its only consumer is gone. The column stays (nullable) so rows written
        # before this change still read back rather than needing a migration.
        c.execute(
            "UPDATE searches SET cloudflare_fronted = %s WHERE id = %s",
            (cf_val, search_id),
        )
        _save_child_tables(c, search_id, result, timestamp)
        # `related_targets_summary` was set on `result` above, so the loop below
        # already persists it — no separate INSERT needed.
        for key, value in result.items():
            c.execute(
                "INSERT INTO search_fields (search_id, key, json_value) VALUES (%s,%s,%s) "
                "ON CONFLICT (search_id, key) DO UPDATE SET json_value = EXCLUDED.json_value",
                (search_id, key, _json(value)),
            )

    # Derived correlation layer, in its own transaction: the raw append-only save
    # above is already committed, so a projection failure can never lose intel.
    #
    # The projection and the affected-domain expansion run inline (both are
    # bounded, indexed work on the rows this search just wrote), but the actual
    # rescore does not: it is queued for the maintenance loop, which drains it
    # within one tick. That keeps a scan's own commit path free of the
    # I/O-bound per-domain scoring pass while still making the whole
    # neighbourhood correct seconds later, rather than whenever someone
    # remembers to press "Recompute graph".
    try:
        with _conn() as c:
            touch = persist_correlation(c, result, search_id=search_id, recount=True)
            affected = _affected_registrable_domains(c, touch)
        _mark_graph_dirty(affected)
    except Exception:  # pragma: no cover - defensive; correlation is rebuildable
        pass


def _hydrate_result(meta: Mapping[str, Any], fields: dict | None, search_id: int) -> dict | None:
    """Stitch a `searches` row together with its `search_fields` payload.

    Split out of get_result so a caller that already holds a connection — the
    rebuild loop, which reprojects every stored search — can supply both halves
    itself instead of paying a fresh connection per search.
    """
    if fields is None:
        return None
    fields.setdefault("input", meta["target"])
    fields.setdefault("type", meta["type"])
    fields.setdefault("timestamp", meta["timestamp"])
    fields["search_id"] = search_id
    # Canonicalize the stored page metadata on the way out rather than only at
    # scrape time. Every search saved before the collectors agreed on one
    # vocabulary carries keys no consumer reads — `adsense_ids` instead of
    # `adsense_publisher_ids`, `favicon_murmurhash3` without `favicon_mmh3`,
    # scalar `fb_app_id` — and those searches are the whole historical corpus.
    # Doing it here means the periodic rebuild_all_correlation() reconcile
    # recovers the missing selectors from stored intel on its own schedule; no
    # rescan, and nothing to remember to run.
    #
    # Local import: sources.signal_web pulls httpx, and this module is imported
    # by migration/CLI paths that have no reason to load the scraping stack.
    from sources.signal_web import canonicalize_page_metadata

    page_metadata = fields.get("page_metadata")
    if isinstance(page_metadata, Mapping):
        fields["page_metadata"] = canonicalize_page_metadata(page_metadata)
    return fields


def get_result(search_id: int) -> dict | None:
    init_db()
    with _conn() as c:
        meta = c.execute(
            "SELECT target, type, timestamp, cloudflare_fronted FROM searches WHERE id = %s",
            (search_id,),
        ).fetchone()
        if not meta:
            return None
        return _hydrate_result(meta, _load_result_from_fields(c, search_id), search_id)


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


# ── Correlation layer: batched writers ──────────────────────────────────────
#
# The single-row upserts above are one network round trip each, and projecting
# one search fires two or three per observation — so a scan with 200
# observations pays ~500 sequential waits, and a full reconcile over the whole
# corpus pays that per stored search. The batched forms below send one
# statement per table per search instead, unnesting parallel arrays into the
# same INSERT ... ON CONFLICT the single-row versions use, so the semantics
# (insert-or-widen, never clobbering `attributing`/`entity_count`) are
# unchanged and only the number of round trips differs.
#
# Callers MUST pass rows already deduplicated on the conflict target: Postgres
# rejects an ON CONFLICT DO UPDATE that would touch the same row twice in one
# statement ("cannot affect row a second time"). _merge_window does that
# folding, mirroring LEAST/GREATEST — including their treatment of NULL as
# "no opinion" rather than as a minimum, which is why it cannot just be min().


def _merge_window(
    existing: tuple[str | None, str | None] | None,
    first_seen: str | None,
    last_seen: str | None,
) -> tuple[str | None, str | None]:
    """Widen a (first_seen, last_seen) pair the way LEAST/GREATEST would.

    The columns are TEXT holding normalized ISO-8601, so lexicographic order is
    chronological order and plain string compare is correct.
    """
    if existing is None:
        return (first_seen, last_seen)
    old_first, old_last = existing
    new_first = first_seen if old_first is None else (
        old_first if first_seen is None else min(old_first, first_seen)
    )
    new_last = last_seen if old_last is None else (
        old_last if last_seen is None else max(old_last, last_seen)
    )
    return (new_first, new_last)


def _batch_upsert_entities(
    c: psycopg.Connection[Any], rows: list[tuple[str, str, str | None, str | None, str | None]]
) -> dict[tuple[str, str], int]:
    """Insert-or-widen many entities; returns {(kind, value): id} for all of them."""
    if not rows:
        return {}
    kinds, values, rds, firsts, lasts = (list(col) for col in zip(*rows))
    out = c.execute(
        """INSERT INTO entities (kind, value, registrable_domain, first_seen, last_seen)
           SELECT * FROM unnest(%s::text[], %s::text[], %s::text[], %s::text[], %s::text[])
           ON CONFLICT (kind, value) DO UPDATE SET
               registrable_domain = COALESCE(EXCLUDED.registrable_domain, entities.registrable_domain),
               first_seen = LEAST(entities.first_seen, EXCLUDED.first_seen),
               last_seen  = GREATEST(entities.last_seen, EXCLUDED.last_seen)
           RETURNING id, kind, value""",
        (kinds, values, rds, firsts, lasts),
    ).fetchall()
    return {(row["kind"], row["value"]): int(row["id"]) for row in out}


def _batch_upsert_selectors(
    c: psycopg.Connection[Any], rows: list[tuple[str, str, str | None, str | None]]
) -> dict[tuple[str, str], int]:
    """Insert-or-widen many selectors; returns {(kind, value): id} for all of them."""
    if not rows:
        return {}
    kinds, values, firsts, lasts = (list(col) for col in zip(*rows))
    out = c.execute(
        """INSERT INTO selectors (kind, value, entity_count, attributing, first_seen, last_seen)
           SELECT kind, value, 0, TRUE, first_seen, last_seen
             FROM unnest(%s::text[], %s::text[], %s::text[], %s::text[])
                    AS t(kind, value, first_seen, last_seen)
           ON CONFLICT (kind, value) DO UPDATE SET
               first_seen = LEAST(selectors.first_seen, EXCLUDED.first_seen),
               last_seen  = GREATEST(selectors.last_seen, EXCLUDED.last_seen)
           RETURNING id, kind, value""",
        (kinds, values, firsts, lasts),
    ).fetchall()
    return {(row["kind"], row["value"]): int(row["id"]) for row in out}


def _batch_record_observations(
    c: psycopg.Connection[Any],
    rows: list[tuple[int, int, str, str | None, str | None, int | None]],
) -> None:
    """Insert-or-widen many entity→selector observations."""
    if not rows:
        return
    eids, sids, sources, firsts, lasts, search_ids = (list(col) for col in zip(*rows))
    c.execute(
        """INSERT INTO observations (entity_id, selector_id, source, first_seen, last_seen, search_id)
           SELECT * FROM unnest(%s::bigint[], %s::bigint[], %s::text[],
                                %s::text[], %s::text[], %s::bigint[])
           ON CONFLICT (entity_id, selector_id, source) DO UPDATE SET
               first_seen = LEAST(observations.first_seen, EXCLUDED.first_seen),
               last_seen  = GREATEST(observations.last_seen, EXCLUDED.last_seen),
               search_id  = COALESCE(observations.search_id, EXCLUDED.search_id)""",
        (eids, sids, sources, firsts, lasts, search_ids),
    )


def _batch_record_entity_edges(
    c: psycopg.Connection[Any],
    rows: list[tuple[int, int, str, str, str | None, str | None]],
) -> None:
    """Insert-or-widen many structural entity→entity edges."""
    if not rows:
        return
    srcs, dsts, kinds, sources, firsts, lasts = (list(col) for col in zip(*rows))
    c.execute(
        """INSERT INTO entity_edges (src_entity_id, dst_entity_id, kind, source, first_seen, last_seen)
           SELECT * FROM unnest(%s::bigint[], %s::bigint[], %s::text[],
                                %s::text[], %s::text[], %s::text[])
           ON CONFLICT (src_entity_id, dst_entity_id, kind) DO UPDATE SET
               first_seen = LEAST(entity_edges.first_seen, EXCLUDED.first_seen),
               last_seen  = GREATEST(entity_edges.last_seen, EXCLUDED.last_seen)""",
        (srcs, dsts, kinds, sources, firsts, lasts),
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


def recompute_selector_degrees(c: psycopg.Connection[Any], selector_ids: Iterable[int]) -> None:
    """Batch form of recompute_selector_degree: recomputes every id in one
    round-trip instead of one UPDATE per selector. Used by persist_correlation,
    which can touch dozens of selectors per analyzed target."""
    ids = sorted({int(sel_id) for sel_id in selector_ids if sel_id is not None})
    if not ids:
        return
    c.execute(
        """UPDATE selectors s SET entity_count = COALESCE(o.cnt, 0)
           FROM (
               SELECT selector_id, count(DISTINCT entity_id) AS cnt
               FROM observations WHERE selector_id = ANY(%s) GROUP BY selector_id
           ) o
           WHERE s.id = o.selector_id AND s.id = ANY(%s)""",
        (ids, ids),
    )
    c.execute(
        "UPDATE selectors SET entity_count = 0 WHERE id = ANY(%s) AND id NOT IN "
        "(SELECT selector_id FROM observations WHERE selector_id = ANY(%s))",
        (ids, ids),
    )


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


# Platforms dropped even if present in already-stored raw_json from before a
# platform was excluded at scrape time (see sources/signal_web.py) — e.g.
# "github" was pulled from any github.com/<org> link on the page, which is
# overwhelmingly a credited OSS dependency rather than the site's own account
# (github.com/facebook shows up on any site crediting React). Filtering here
# too means a recompute retroactively drops the noise without rescanning.
_NOISY_SOCIAL_PLATFORMS = {"github"}

# Handle values that are a platform's generic/un-vanitized path, not a real
# per-account identifier — e.g. "profile.php" is Facebook's un-vanitized
# profile URL (facebook.com/profile.php?id=…); the actual id lives in the
# query string, which extraction never captures, so every site linking to any
# numeric-id profile lands on the same literal value. "pages" is the same
# problem for the legacy facebook.com/pages/<Name>/<id> Page URL — extraction
# stops at the first "/", capturing the directory segment "pages" rather than
# the name or id. Filtered here too so a recompute retroactively drops
# already-stored false positives without rescanning (see
# sources.signal_web._SOCIAL_NOISE for the scan-time filter).
_NOISY_SOCIAL_HANDLES = {"profile.php", "pages"}


def _meta_tag_site_signals(page: Mapping[str, Any]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Site-verification codes + meta-tag-only social handles (e.g. Telegram's
    `<meta name="telegram:channel">`) for one page_metadata blob.

    Falls back to deriving these from the raw `meta_tags` dict when the
    pre-computed `site_verifications`/`social_handles` keys are absent — which
    is the case for every scan stored before this extraction existed. Raw meta
    tags have always been captured, so a global recompute picks these up on
    already-scanned domains without needing to rescan them.
    """
    from sources.signal_web import SITE_VERIFICATION_META_KEYS, SOCIAL_HANDLE_META_KEYS

    meta_tags = page.get("meta_tags") if isinstance(page.get("meta_tags"), Mapping) else {}

    verifications: dict[str, list[str]] = {}
    for provider, codes in (page.get("site_verifications") or {}).items():
        for code in _normalize_text_list(codes):
            verifications.setdefault(provider, [])
            if code not in verifications[provider]:
                verifications[provider].append(code)
    if not verifications:
        for meta_key, values in meta_tags.items():
            provider = SITE_VERIFICATION_META_KEYS.get(str(meta_key).strip().lower())
            if not provider:
                continue
            for value in _normalize_text_list(values):
                verifications.setdefault(provider, [])
                if value not in verifications[provider]:
                    verifications[provider].append(value)

    handles: dict[str, list[str]] = {}
    for platform, values in (page.get("social_handles") or {}).items():
        if platform in _NOISY_SOCIAL_PLATFORMS:
            continue
        for value in _normalize_text_list(values):
            if value.lower() in _NOISY_SOCIAL_HANDLES:
                continue
            handles.setdefault(platform, [])
            if value not in handles[platform]:
                handles[platform].append(value)
    for meta_key, platform in SOCIAL_HANDLE_META_KEYS.items():
        if platform in _NOISY_SOCIAL_PLATFORMS:
            continue
        for raw_value in _normalize_text_list(meta_tags.get(meta_key) or []):
            handle = raw_value.lstrip("@").strip()
            if not handle or handle.lower() in _NOISY_SOCIAL_HANDLES:
                continue
            handles.setdefault(platform, [])
            if handle not in handles[platform]:
                handles[platform].append(handle)

    return verifications, handles


# Legal/imprint page signals, as selector kind -> the key each is published
# under. An imprint is a disclosure the operator is legally obliged to make
# about itself, so it is the densest identity source on a site: the phone and
# email feed the same selectors as their homepage equivalents, the rest are
# their own kinds. `normalized_text_hash` is per-page only (the aggregate has
# no hash of its own), which is why it is read separately below.
_LEGAL_PAGE_SELECTOR_KEYS = {
    "contact_phone": "phones",
    "contact_email": "emails",
    "legal_entity": "entity_names",
    "legal_registration": "registration_ids",
    "legal_address": "addresses",
}

# An entity name shorter than this is a parsing fragment ("Ltd", "GmbH")
# rather than a company. Kept low enough to let short real names through
# ("BMW AG").
_LEGAL_ENTITY_MIN_LENGTH = 6


def _normalize_legal_selector_value(kind: str, value: Any) -> str | None:
    if kind == "contact_phone":
        return _normalize_identifier_phone(value)
    if kind == "contact_email":
        from utils.check import _is_generic_email

        email = _normalize_identifier_email(value)
        # A registrar/privacy-proxy role address identifies the provider, not
        # the operator — the email equivalent of a shared Cloudflare IP.
        return None if not email or _is_generic_email(email) else email
    text = _normalize_generic_identifier(value)
    if not text:
        return None
    if kind in ("legal_entity", "legal_address"):
        from sources.signal_web import (
            _MAX_ADDRESS_LENGTH,
            _MAX_ADDRESS_WORDS,
            _THIRD_PARTY_ENTITY_RE,
        )

        # Backstop for payloads where provenance is already gone (the flattened
        # aggregate, and results stored before the extractor was fixed). A
        # platform or ad network named in boilerplate is never the operator,
        # and it recurs on so many unrelated sites that admitting it links them
        # all to each other.
        if _THIRD_PARTY_ENTITY_RE.search(text):
            return None
        if kind == "legal_address" and (
            len(text) > _MAX_ADDRESS_LENGTH or len(text.split()) > _MAX_ADDRESS_WORDS
        ):
            # A street word inside a sentence is not an address.
            return None
    if kind == "legal_entity" and len(text) < _LEGAL_ENTITY_MIN_LENGTH:
        return None
    if kind == "legal_address" and not any(ch.isdigit() for ch in text):
        # A real postal address carries a street number or a postcode; a bare
        # label ("Office", "Registered address") is a parsing fragment, and one
        # shared across two sites would link them on nothing.
        return None
    if kind == "legal_registration":
        from sources.signal_web import _REG_ID_TOKEN_RE, _normalize_vat

        # The extractor emits one structured token per value, so anything that
        # is not wholly an ID ("business", "site data", a clause about company
        # news) came from a result stored before that was tightened. It matters
        # more here than for the other kinds because a registration number is
        # the heaviest selector there is: a registry issues it to exactly one
        # company, so a shared one reads as an ownership statement — and a
        # prose fragment shared by ten sites reads as ten ownership statements.
        if not (_REG_ID_TOKEN_RE.fullmatch(text) or _normalize_vat(text)):
            return None
    return text


def _legal_page_signals(result: Mapping[str, Any]) -> dict[str, list[str]]:
    """Normalized selector values from a scan's legal/imprint pages.

    Handles both payload shapes: the aggregated dict written by
    core.analysis_service._compact_legal_pages and the raw list of per-page
    entries that signal_web.scrape_legal_pages returns.
    """
    legal = result.get("legal_pages")
    aggregate: Mapping[str, Any] = {}
    if isinstance(legal, Mapping):
        aggregate = legal
        entries = [e for e in (legal.get("pages") or []) if isinstance(e, Mapping)]
    elif isinstance(legal, list):
        entries = [e for e in legal if isinstance(e, Mapping)]
    else:
        entries = []

    signals: dict[str, list[str]] = {}

    def push(kind: str, value: Any) -> None:
        normalized = _normalize_legal_selector_value(kind, value)
        if not normalized:
            return
        bucket = signals.setdefault(kind, [])
        if normalized not in bucket:
            bucket.append(normalized)

    from sources.signal_web import _is_operator_identity_page

    # Which page a value came from decides whether it describes this operator.
    # A privacy policy enumerates *other* companies — every ad network,
    # analytics vendor and CDN the site embeds, with postal addresses — so its
    # entity/address/registration values are somebody else's identity.
    #
    # Filtered here as well as at extraction because the graph replays stored
    # scan JSON: observations are append-only and no scan supersedes an earlier
    # one, so results captured before the extractor was fixed would otherwise
    # keep re-projecting their boilerplate on every rebuild, and a rescan would
    # only add clean values *beside* the old dirty ones.
    identity_kinds = {"legal_entity", "legal_address", "legal_registration"}
    scoped_entries = [e for e in entries if _is_operator_identity_page(e.get("url"))]

    for kind, key in _LEGAL_PAGE_SELECTOR_KEYS.items():
        if kind in identity_kinds and entries:
            # Per-page values carry a URL, so they can be attributed. The
            # aggregate is a union across every page with that provenance
            # already thrown away, so it is skipped whenever per-page entries
            # exist to replace it.
            for entry in scoped_entries:
                for value in entry.get(key) or []:
                    push(kind, value)
            continue
        for value in aggregate.get(key) or []:
            push(kind, value)
        for entry in entries:
            for value in entry.get(key) or []:
                push(kind, value)

    for entry in entries:
        digest = _normalize_identifier_hash(entry.get("normalized_text_hash"))
        if digest:
            bucket = signals.setdefault("legal_text_hash", [])
            if digest not in bucket:
                bucket.append(digest)

    return signals


def _payment_contact_signals(page: Mapping[str, Any]) -> tuple[list[str], dict[str, list[str]]]:
    """Normalized homepage phone numbers + chain->wallet addresses for one
    page_metadata blob.

    Both are normalized here rather than at scan time so the two sides of a
    match are comparable regardless of how the page wrote them, each through
    the shared normalizer for its kind (sources.signal_web) so the identifiers
    table, the selectors, and the legacy pairwise engine all agree on one key.
    """
    from sources.signal_web import normalize_crypto_address

    phones: list[str] = []
    for value in _normalize_text_list(page.get("phone_numbers") or []):
        normalized = _normalize_identifier_phone(value)
        if normalized and normalized not in phones:
            phones.append(normalized)

    wallets: dict[str, list[str]] = {}
    for chain, addresses in (page.get("crypto_wallets") or {}).items():
        chain_key = _normalize_generic_identifier(chain)
        if not chain_key:
            continue
        for address in _normalize_text_list(addresses):
            normalized = normalize_crypto_address(chain_key, address)
            if not normalized:
                continue
            wallets.setdefault(chain_key, [])
            if normalized not in wallets[chain_key]:
                wallets[chain_key].append(normalized)

    return phones, wallets


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
        # The live pipeline (core/basic.py::get_tls_certs, run on every scan) stores
        # results as result["tls_certs"]["probes"], with the fingerprint under
        # "fingerprint_sha256". result["non_cf_tls_certs"]/["tls_cert"] and a bare
        # "sha256" key only ever come from core/ip_intel.py's separate async engine
        # (not used by live ingest) — kept here so historical raw_json in that
        # older shape still replays correctly on backfill/recompute.
        tls_list = list(res.get("non_cf_tls_certs") or [])
        if res.get("tls_cert"):
            tls_list.append(res["tls_cert"])
        tls_list.extend((res.get("tls_certs") or {}).get("probes") or [])
        for cert in tls_list:
            if not isinstance(cert, Mapping) or cert.get("error"):
                continue
            nb, na = _safe_iso(cert.get("not_before")), _safe_iso(cert.get("not_after"))
            fingerprint = cert.get("sha256") or cert.get("fingerprint_sha256")
            if owner:
                add_obs(owner, "tls_cert_sha256", _normalize_identifier_hash(fingerprint), "self_scan", nb, na)
                add_obs(owner, "tls_spki", _normalize_identifier_hash(cert.get("spki_sha256")), "self_scan", nb, na)
                for san in cert.get("sans") or []:
                    add_obs(owner, "tls_san", _normalize_tls_identity(san), "self_scan", nb, na)
            if cert.get("ip") and owner:
                add_resolves(owner, cert.get("ip"), "tls", ts, ts)

        origin = _origin_candidates(res)
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
            # Provenance was "rdap" until the RDAP leg was removed from
            # core.basic.get_ip_whois; ASN now comes from ipinfo Lite and the
            # CIDR from Censys host enrichment. The label is re-derived on every
            # rebuild_clusters rather than stored per scan, so renaming it
            # relabels history uniformly instead of splitting it in two.
            add_obs(ip, "asn", _normalize_asn(asn_info.get("asn")), "ip_enrichment", ts, ts)
            add_obs(ip, "network_cidr", asn_info.get("network_cidr") or asn_info.get("asn_cidr"), "ip_enrichment", ts, ts)
            for domain in info.get("other_domains_on_ip") or []:
                add_resolves(domain, ip, "reverse_ip", ts, ts)

        if res.get("type") == "ip" and owner:
            asn_info = res.get("asn_info") or {}
            add_obs(owner, "asn", _normalize_asn(asn_info.get("asn")), "ip_enrichment", ts, ts)
            add_obs(owner, "network_cidr", asn_info.get("network_cidr") or asn_info.get("asn_cidr"), "ip_enrichment", ts, ts)

        # ── SPF sending origins exhibited by the owner domain ──
        # Where a domain is authorised to send mail from. Most sites delegate to
        # a handful of large providers, so this is high-degree by nature and
        # leans on rarity_weight + denylist seeding to stay quiet, exactly like
        # `asn`; what it catches is the operator running their own mail host.
        if owner:
            for entry in res.get("spf_origins") or []:
                if not isinstance(entry, Mapping):
                    continue
                # Prefer the CIDR: a sender that rotates addresses inside its
                # own block still matches, where a bare IP would not.
                add_obs(owner, "spf_origin", entry.get("cidr") or entry.get("ip"), "spf", ts, ts)

        # ── Historical A/AAAA records: past co-location ──
        # Carries each record's own first/last seen rather than the scan
        # timestamp, so check.recency_weight discounts it for its real age
        # (full credit 180 days, then decaying to a 0.3 floor). That is what
        # keeps a host two domains shared in 2019 from reading as present-day
        # co-location while still surfacing an operator who moved.
        for rec in _as_dict(res.get("historical_dns")).get("records") or []:
            if not isinstance(rec, Mapping):
                continue
            if str(rec.get("rrtype") or "").strip().upper() not in ("A", "AAAA"):
                continue
            if owner:
                add_resolves(
                    owner, rec.get("rdata"), "historical_dns",
                    _safe_iso(rec.get("first_seen")), _safe_iso(rec.get("last_seen")),
                )

        # ── SSH host keys exhibited by the IP they were grabbed from ──
        for probe in _ssh_host_key_records(res):
            fp = _normalize_identifier_hash(
                probe.get("fingerprint_sha256") or probe.get("sha256")
            )
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
            # Webmaster-tools verification codes (google-site-verification, …) and
            # social handles (Telegram, VK, Instagram, …) exhibited on the page.
            site_verifications, social_handles_all = _meta_tag_site_signals(page)
            for provider, codes in site_verifications.items():
                for code in codes:
                    add_obs(owner, "site_verification", f"{provider}|{code}", "self_scan", ts, ts)
            for platform, handles in social_handles_all.items():
                for handle in handles:
                    add_obs(owner, "social_handle", f"{platform}|{handle}", "self_scan", ts, ts)
            # Contact phone numbers and payment wallets solicited on the page.
            phones, wallets = _payment_contact_signals(page)
            for phone in phones:
                add_obs(owner, "contact_phone", phone, "self_scan", ts, ts)
            for chain, addresses in wallets.items():
                for address in addresses:
                    add_obs(owner, "crypto_wallet", f"{chain}|{address}", "self_scan", ts, ts)
            # Imprint/legal-page identity: phone and email land on the same
            # selectors as their homepage equivalents (same operator, just a
            # different page); entity name, registration id, address and the
            # page-text hash are their own kinds.
            for kind, values in _legal_page_signals(res).items():
                for value in values:
                    add_obs(owner, kind, value, "self_scan", ts, ts)

        # ── Nameservers exhibited by the owner domain ──
        if owner:
            for ns in _iter_dns_host_values(dns.get("NS")):
                add_obs(owner, "nameserver", _normalize_tls_identity(ns), "dns", ts, ts)
            whois_row = res.get("whois") or {}
            if isinstance(whois_row, Mapping) and not whois_row.get("error"):
                for ns in _normalize_nameservers(whois_row.get("nameservers")):
                    add_obs(owner, "nameserver", ns, "whois", ts, ts)
                # Registrant identity lands on the same selectors as the
                # imprint-page equivalents rather than getting whois-only kinds:
                # it is the same operator, declared to the registrar instead of
                # on the page. An address that appears in both places has to be
                # one selector or the two sites would never match on it — the
                # same reasoning _legal_page_signals applies to imprint phones.
                # Provenance survives as the observation's source ("whois").
                #
                # Redacted placeholders are dropped exactly as
                # _save_child_tables drops them before registrant_emails, and
                # _normalize_legal_selector_value then discards registrar and
                # privacy-proxy mailboxes (the email equivalent of a shared CDN
                # IP) plus name fragments too short to be a real company.
                whois_emails = whois_row.get("emails") or []
                if isinstance(whois_emails, str):
                    whois_emails = [whois_emails]
                for email in whois_emails:
                    if _is_redacted_whois_value(email):
                        continue
                    add_obs(
                        owner, "contact_email",
                        _normalize_legal_selector_value("contact_email", email), "whois", ts, ts,
                    )
                for name in _normalize_text_list(whois_row.get("name")):
                    if _is_redacted_whois_value(name):
                        continue
                    add_obs(
                        owner, "legal_entity",
                        _normalize_legal_selector_value("legal_entity", name), "whois", ts, ts,
                    )

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

class CorrelationTouch(NamedTuple):
    """What one projected result invalidated in the derived graph.

    ``selector_ids`` is every selector the projection observed. The two
    ``rescore_*`` sets are the subset whose *degree change actually moves a
    score* — see _affected_registrable_domains for why that is a strictly
    smaller and, crucially, bounded set. ``registrable_domains`` is the scan's
    own domains, which always need rescoring whether or not anything else did.
    """

    selector_ids: set[int]
    rescore_selector_ids: set[int]
    rescore_ip_entity_ids: set[int]
    registrable_domains: set[str]

    @classmethod
    def empty(cls) -> "CorrelationTouch":
        return cls(set(), set(), set(), set())


def _resolves_to_degrees(c: psycopg.Connection[Any], ip_entity_ids: Iterable[int]) -> dict[int, int]:
    """How many distinct registrable domains resolve to each of these IP entities."""
    ids = sorted({int(i) for i in ip_entity_ids if i is not None})
    if not ids:
        return {}
    rows = c.execute(
        """SELECT ee.dst_entity_id AS id, count(DISTINCT e.registrable_domain) AS degree
             FROM entity_edges ee
             JOIN entities e ON e.id = ee.src_entity_id
            WHERE ee.kind = 'resolves_to'
              AND ee.dst_entity_id = ANY(%s)
              AND e.registrable_domain IS NOT NULL
            GROUP BY ee.dst_entity_id""",
        (ids,),
    ).fetchall()
    return {int(row["id"]): int(row["degree"]) for row in rows}


def _ips_table_observations(c: psycopg.Connection[Any], search_id: int) -> list[dict[str, Any]]:
    """asn / network_cidr observations read from the current `ips` rows.

    Mirrors what extract_selectors derives from result["ip_details"], but from
    the columns as they stand *now* rather than as the scan recorded them —
    see persist_correlation for why that difference matters.
    """
    rows = c.execute(
        """SELECT DISTINCT ON (ip) ip, asn, network_cidr, observed_at
             FROM ips
            WHERE search_id = %s AND ip IS NOT NULL AND ip <> ''
            ORDER BY ip, observed_at DESC NULLS LAST, id DESC""",
        (search_id,),
    ).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        ts = _safe_iso(row.get("observed_at"))
        pairs = (("asn", _normalize_asn(row.get("asn"))), ("network_cidr", row.get("network_cidr")))
        for kind, value in pairs:
            text = str(value or "").strip()
            if text:
                out.append({
                    "entity": row["ip"], "kind": kind, "value": text,
                    "source": "ip_record", "first_seen": ts, "last_seen": ts,
                })
    return out


def persist_correlation(
    c: psycopg.Connection[Any],
    result: dict[str, Any],
    *,
    search_id: int | None = None,
    recount: bool = True,
) -> CorrelationTouch:
    """Upsert the correlation projection of one result. Returns what it touched.

    When recount is True (live ingest), the degree of every touched selector is
    refreshed immediately and the returned CorrelationTouch carries everything
    the incremental rescore needs. Backfill passes recount=False and
    batch-recomputes all degrees once at the end, so it skips the extra
    before/after reads and returns only the touched selector ids.
    """
    data = extract_selectors(result)
    # The `ips` table, not the stored result JSON, is the live view of an
    # address: store_censys_enrichment gap-fills asn/network_cidr there long
    # after the scan that wrote the JSON, and nothing rewrites the JSON. Reading
    # the columns as well is what lets an out-of-band enrichment become graph
    # evidence on the next reprojection instead of staying invisible until the
    # domain happens to be rescanned. Emitted under its own source, so it
    # widens the same selector rather than competing with the rdap-sourced
    # observation — the pattern `nameserver` already uses for dns vs whois.
    if search_id is not None:
        data["observations"].extend(_ips_table_observations(c, search_id))
    own_rds: set[str] = set()
    # Classification is pure and the same raw string recurs constantly within
    # one result (every observation on a host repeats that host), so memoize it
    # rather than re-parsing the suffix list per observation.
    classified: dict[str, dict[str, Any] | None] = {}

    def _classify(raw: Any) -> dict[str, Any] | None:
        key = str(raw)
        if key not in classified:
            classified[key] = classify_entity(raw)
        return classified[key]

    # Fold every entity this result names — declared up front, plus the ones
    # only an observation mentions — into one deduplicated batch. Both sources
    # went through per-row upserts before, the second one lazily inside the
    # observation loop; collecting first is what lets a single statement cover
    # them, and it does not change which entities get created (an edge endpoint
    # still never creates one).
    entity_rows: dict[tuple[str, str], tuple[str | None, tuple[str | None, str | None]]] = {}

    def _want_entity(raw: Any, first_seen: str | None, last_seen: str | None) -> None:
        info = _classify(raw)
        if not info:
            return
        key = (info["kind"], info["value"])
        rd, window = entity_rows.get(key, (None, None))
        entity_rows[key] = (
            rd or info["registrable_domain"],
            _merge_window(window, _safe_iso(first_seen), _safe_iso(last_seen)),
        )
        if info["registrable_domain"]:
            own_rds.add(info["registrable_domain"])

    for ent in data["entities"]:
        _want_entity(ent["value"], ent.get("first_seen"), ent.get("last_seen"))
    for obs in data["observations"]:
        _want_entity(obs["entity"], obs.get("first_seen"), obs.get("last_seen"))

    ent_id_by_key = _batch_upsert_entities(
        c,
        [(kind, value, rd, window[0], window[1])
         for (kind, value), (rd, window) in entity_rows.items()],
    )
    # Rebuilt with exactly the key set the per-row version produced: a declared
    # entity is keyed by its *normalized* value, an entity that only an
    # observation names by the raw string that named it. The distinction only
    # bites when the two differ, but keying both for every entity would admit
    # edges the old code skipped — a behaviour change, and not one a batching
    # patch should be making.
    ent_ids: dict[Any, int] = {}
    for ent in data["entities"]:
        info = _classify(ent["value"])
        if info and (eid := ent_id_by_key.get((info["kind"], info["value"]))) is not None:
            ent_ids[info["value"]] = eid
    for obs in data["observations"]:
        raw = obs["entity"]
        if raw in ent_ids:
            continue
        info = _classify(raw)
        if info and (eid := ent_id_by_key.get((info["kind"], info["value"]))) is not None:
            ent_ids[raw] = eid

    selector_rows: dict[tuple[str, str], tuple[str | None, str | None]] = {}
    for obs in data["observations"]:
        if obs["entity"] not in ent_ids:
            continue
        key = (obs["kind"], obs["value"])
        selector_rows[key] = _merge_window(
            selector_rows.get(key), _safe_iso(obs.get("first_seen")), _safe_iso(obs.get("last_seen"))
        )
    sel_id_by_key = _batch_upsert_selectors(
        c, [(kind, value, window[0], window[1]) for (kind, value), window in selector_rows.items()]
    )

    observation_rows: dict[tuple[int, int, str], tuple[str | None, str | None]] = {}
    touched: set[int] = set()
    for obs in data["observations"]:
        eid = ent_ids.get(obs["entity"])
        sel_id = sel_id_by_key.get((obs["kind"], obs["value"]))
        if eid is None or sel_id is None:
            continue
        key = (eid, sel_id, str(obs["source"] or ""))
        observation_rows[key] = _merge_window(
            observation_rows.get(key), _safe_iso(obs.get("first_seen")), _safe_iso(obs.get("last_seen"))
        )
        touched.add(sel_id)
    _batch_record_observations(
        c,
        [(eid, sel_id, source, window[0], window[1], search_id)
         for (eid, sel_id, source), window in observation_rows.items()],
    )

    resolves_dst = {
        ent_ids[edge["dst"]]
        for edge in data["edges"]
        if edge["kind"] == "resolves_to" and edge["dst"] in ent_ids and edge["src"] in ent_ids
    }
    # Read before the edges land: an IP's fan-out is the other half of the
    # degree-staleness problem, and only the pre-write value distinguishes
    # "this IP was already too crowded to score" from "this write is what
    # crowded it", which is a change every domain on that IP needs to see.
    ip_degree_before = _resolves_to_degrees(c, resolves_dst) if recount else {}

    edge_rows: dict[tuple[int, int, str], tuple[str, tuple[str | None, str | None]]] = {}
    for edge in data["edges"]:
        s = ent_ids.get(edge["src"])
        d = ent_ids.get(edge["dst"])
        if s is None or d is None:
            continue
        key = (s, d, str(edge["kind"]))
        source, window = edge_rows.get(key, (str(edge["source"] or ""), None))
        edge_rows[key] = (
            source,
            _merge_window(window, _safe_iso(edge.get("first_seen")), _safe_iso(edge.get("last_seen"))),
        )
    _batch_record_entity_edges(
        c,
        [(src, dst, kind, source, window[0], window[1])
         for (src, dst, kind), (source, window) in edge_rows.items()],
    )

    if not recount:
        return CorrelationTouch(touched, set(), set(), own_rds)

    # Which of the touched nodes can actually have moved somebody else's score.
    # Both tests are "was it scoring-relevant before this write, or is it now?"
    # — a node that was noise before and is still noise after contributes 0 to
    # every link either way (link_candidates_for filters on sel.attributing;
    # check._score_ip_row zeroes an IP past its noise degree), so its degree
    # changing is unobservable and its neighbourhood does not need rescoring.
    # Reading the "before" state is what makes the *transition* visible: a
    # selector that this write pushed over CORRELATION_DEGREE_THRESHOLD reads
    # as plain noise afterwards, but it just *removed* evidence from every
    # domain that shared it, and those links are now wrong until someone
    # rescores them.
    attributing_before = {
        int(row["id"])
        for row in c.execute(
            "SELECT id FROM selectors WHERE id = ANY(%s) AND attributing", (sorted(touched),)
        ).fetchall()
    } if touched else set()

    recompute_selector_degrees(c, touched)
    apply_denylist_for_selectors(c, touched)

    attributing_after = {
        int(row["id"])
        for row in c.execute(
            "SELECT id FROM selectors WHERE id = ANY(%s) AND attributing", (sorted(touched),)
        ).fetchall()
    } if touched else set()
    ip_noise_degree = _ip_noise_degree()
    ip_degree_after = _resolves_to_degrees(c, resolves_dst)
    rescore_ips = {
        ip_id
        for ip_id in resolves_dst
        if ip_degree_before.get(ip_id, 0) <= ip_noise_degree
        or ip_degree_after.get(ip_id, 0) <= ip_noise_degree + 1
    }
    return CorrelationTouch(touched, attributing_before | attributing_after, rescore_ips, own_rds)


def _truncate_correlation(c: psycopg.Connection[Any]) -> None:
    """Empty the projection tables ahead of a full reproject.

    DELETE, not TRUNCATE, for exactly the reason spelled out above
    rebuild_clusters' own DELETEs: TRUNCATE takes an ACCESS EXCLUSIVE lock held
    until commit, and this runs at the *start* of a transaction that then
    reprojects the entire corpus — so every /api/pool, /api/domain and
    /api/graph read (they all join entities/selectors/observations) would block
    for the whole rebuild instead of just reading the previous snapshot under
    MVCC. That was survivable while a full rebuild was a deliberate operator
    action; it is not survivable now that one runs unattended on a timer.
    Deleted in FK order (children first) since DELETE has no CASCADE here.
    """
    c.execute("DELETE FROM entity_edges")
    c.execute("DELETE FROM observations")
    c.execute("DELETE FROM selectors")
    c.execute("DELETE FROM entities")


def clusters_dirty() -> bool:
    init_db()
    with _conn() as c:
        row = c.execute("SELECT dirty FROM graph_state WHERE id = TRUE").fetchone()
        return True if row is None else bool(row["dirty"])


# Censys Core plan allows 20,000 host-enrichment calls per day; past that the
# API returns 429. Overridable so a plan with unlimited enrichment can lift it.
CENSYS_ENRICHMENT_DAILY_LIMIT = int(os.environ.get("CENSYS_ENRICHMENT_DAILY_LIMIT") or 20_000)


def claim_censys_enrichment_calls(count: int = 1) -> int:
    """Reserve up to `count` host-enrichment calls against today's budget.

    Returns how many were actually granted — 0 once the day's cap is spent, so
    callers skip the request rather than spending it on a guaranteed 429. The
    day rolls over on UTC, not the server's local timezone, so the window
    matches what Censys is counting.

    The row is locked with SELECT ... FOR UPDATE before the increment, and both
    statements share one transaction. That explicit lock is what keeps
    concurrent claimers from overshooting the cap: computing the grant in a CTE
    instead would read the statement's snapshot, and under READ COMMITTED a
    claimer blocked on the row lock re-evaluates only its WHERE clause, not the
    CTE — so two workers would both derive a grant from the same stale `used`.
    Deriving it in RETURNING fails for the mirror-image reason: RETURNING sees
    the post-UPDATE row, so it would measure the count it had just written.
    """
    init_db()
    if count <= 0:
        return 0
    with _conn() as c:
        row = c.execute(
            """SELECT CASE WHEN censys_enrichment_day = (NOW() AT TIME ZONE 'utc')::date
                           THEN censys_enrichment_count ELSE 0 END AS used
                 FROM graph_state
                WHERE id
                  FOR UPDATE"""
        ).fetchone()
        if row is None:
            return 0
        used = int(row["used"] or 0)
        granted = max(0, min(int(count), CENSYS_ENRICHMENT_DAILY_LIMIT - used))
        if not granted:
            return 0
        c.execute(
            """UPDATE graph_state
                  SET censys_enrichment_day   = (NOW() AT TIME ZONE 'utc')::date,
                      censys_enrichment_count = %s,
                      updated_at              = NOW()
                WHERE id""",
            (used + granted,),
        )
    return granted


def release_censys_enrichment_calls(count: int = 1) -> None:
    """Hand back calls claimed for a request that never reached the quota.

    A 401/403/409 means the credential or the plan is wrong, not that we spent
    enrichment budget — Censys never counted it. Without this, a deployment on
    a tier that lacks host enrichment would burn the whole 20k counter on
    identical failures and look like it had simply run out for the day.
    """
    if count <= 0:
        return
    init_db()
    with _conn() as c:
        c.execute(
            """UPDATE graph_state
                  SET censys_enrichment_count = GREATEST(censys_enrichment_count - %s, 0),
                      updated_at = NOW()
                WHERE id AND censys_enrichment_day = (NOW() AT TIME ZONE 'utc')::date""",
            (int(count),),
        )


def censys_enrichment_usage() -> dict[str, int]:
    """Today's host-enrichment spend and what's left of the daily cap."""
    init_db()
    with _conn() as c:
        row = c.execute(
            """SELECT CASE WHEN censys_enrichment_day = (NOW() AT TIME ZONE 'utc')::date
                           THEN censys_enrichment_count ELSE 0 END AS used
                 FROM graph_state WHERE id"""
        ).fetchone()
    used = int((row or {}).get("used") or 0)
    return {
        "used": used,
        "limit": CENSYS_ENRICHMENT_DAILY_LIMIT,
        "remaining": max(CENSYS_ENRICHMENT_DAILY_LIMIT - used, 0),
    }


def ips_pending_censys_enrichment(limit: int = 1000, *, refresh_all: bool = False) -> list[str]:
    """Distinct pool IPs that have not been host-enriched yet.

    Ordered by how many pool rows reference the IP, so a sweep that runs out of
    daily budget has spent it on the addresses the most channels resolve to.
    `refresh_all` re-enriches already-enriched IPs too (oldest first), for when
    the stored view has gone stale rather than missing.
    """
    init_db()
    where = "" if refresh_all else "WHERE censys_enriched_at IS NULL"
    order = "MIN(censys_enriched_at) ASC NULLS FIRST, COUNT(*) DESC" if refresh_all else "COUNT(*) DESC"
    with _conn() as c:
        rows = c.execute(
            f"""SELECT ip FROM ips {where}
                 GROUP BY ip
                 ORDER BY {order}
                 LIMIT %s""",
            (int(limit),),
        ).fetchall()
    return [r["ip"] for r in rows if r.get("ip")]


def store_censys_enrichment(ip: str, enrichment: dict) -> list[int]:
    """Attach an enrichment result to every `ips` row for this address.

    Also fills the scalar columns that were left empty by RDAP/ipinfo — the
    same gap-fill precedence merge_censys_enrichment applies on the scan path,
    so a sweep and a rescan converge on the same values instead of one
    overwriting the other.

    Returns the search_ids whose rows changed. Those searches need reprojecting
    for a newly filled asn/network_cidr to reach the graph (see
    _ips_table_observations); the caller batches that, because a pool-wide
    sweep hits the same searches over and over and reprojecting per IP would
    redo the same work thousands of times.
    """
    init_db()
    observed = datetime.now(timezone.utc).isoformat()
    cidrs = enrichment.get("network_cidrs") or []
    with _conn() as c:
        result = c.execute(
            # asn/asn_desc/network_* stay gap-fills so an unlimited source
            # (ipinfo Lite) is never overwritten by the 20k/day one. `country`
            # is different: enrichment now *owns* geo (see
            # utils.censys_enrichment.merge_censys_enrichment), so it overwrites
            # rather than gap-fills — but only when it actually answered, so a
            # skipped/not_found sweep never blanks a country ipinfo already set.
            """UPDATE ips
                  SET censys_enrichment  = %(payload)s,
                      censys_enriched_at = %(observed)s,
                      asn          = COALESCE(NULLIF(asn, ''),          %(asn)s),
                      asn_desc     = COALESCE(NULLIF(asn_desc, ''),     %(asn_desc)s),
                      country      = COALESCE(NULLIF(%(country)s, ''),  country),
                      network_name = COALESCE(NULLIF(network_name, ''), %(network_name)s),
                      network_cidr = COALESCE(NULLIF(network_cidr, ''), %(network_cidr)s)
                WHERE ip = %(ip)s
               RETURNING search_id""",
            {
                "ip": ip,
                "payload": _json(enrichment),
                "observed": observed,
                "asn": _normalize_asn(enrichment.get("asn")),
                "asn_desc": enrichment.get("as_name") or enrichment.get("as_description"),
                "country": enrichment.get("as_country") or enrichment.get("country_code"),
                "network_name": enrichment.get("network_name"),
                "network_cidr": (cidrs[0] if cidrs else enrichment.get("bgp_prefix")),
            },
        )
        return [int(row["search_id"]) for row in result.fetchall() if row.get("search_id")]


def _mark_clusters_dirty_stmt(c: psycopg.Connection[Any]) -> None:
    c.execute(
        """INSERT INTO graph_state (id, dirty, dirty_at, updated_at)
           VALUES (TRUE, TRUE, NOW(), NOW())
           ON CONFLICT (id) DO UPDATE SET
               dirty = TRUE,
               dirty_at = NOW(),
               updated_at = NOW()"""
    )


def _mark_clusters_dirty() -> None:
    init_db()
    with _conn() as c:
        _mark_clusters_dirty_stmt(c)


# ── Continuous graph maintenance ────────────────────────────────────────────
#
# Three tiers, cheapest and freshest first. Together they replace what used to
# be "an O(pool) rebuild every 20s while anything is dirty, plus a full
# recompute only when a human clicks the button":
#
#  1. incremental rescore (this section) — runs seconds after a write and only
#     touches the domains that write actually invalidated. Maintains the scored
#     link layer: graph_links + graph_connection_counts.
#  2. rebuild_clusters() — still a whole-pool pass, but now rate-limited to
#     GRAPH_CLUSTER_REBUILD_INTERVAL instead of firing on every dirty tick. It
#     owns the derived structures the incremental path deliberately does NOT
#     maintain: connected components (graph_clusters/graph_cluster_links),
#     multi-hop paths (graph_paths) and the browse-by-edge groups
#     (graph_selector_groups). Those are global, order-dependent structures —
#     a component can *split* when a selector turns into noise, which no
#     bounded local patch can detect — so they are recomputed wholesale rather
#     than maintained approximately.
#  3. rebuild_all_correlation() — the periodic full reconcile, every
#     GRAPH_FULL_RECONCILE_INTERVAL. Reprojects every stored search, recomputes
#     every degree and reseeds the whole denylist, which is what corrects any
#     drift tiers 1 and 2 accumulated (and what picks up changed extraction or
#     weighting logic). Still available manually via /api/graph/recompute and
#     scripts/backfill_correlation.py.


def _incremental_batch_limit() -> int:
    """Domains rescored per maintenance tick."""
    try:
        return max(1, int(os.environ.get("GRAPH_INCREMENTAL_BATCH", "500")))
    except ValueError:
        return 500


def _incremental_queue_max() -> int:
    """Queue length past which the incremental path gives up and defers to a
    whole-pool rebuild.

    Rescoring N domains one by one stops being a saving somewhere below the
    size of the pool, and a bulk sweep (the OpenCTI channel run ingests
    thousands of domains back to back) blows past that in minutes. Dropping the
    queue there is not a loss of work: the dirty flag is raised in the same
    transaction, so tier 2's whole-pool pass still recomputes every one of
    them — and a domain that has never been through any pass reads as
    "not computed yet" rather than "no connections" (see cached_links_for), so
    the UI falls back to live scoring for it in the meantime.
    """
    try:
        return max(1, int(os.environ.get("GRAPH_INCREMENTAL_QUEUE_MAX", "5000")))
    except ValueError:
        return 5000


def _cluster_rebuild_interval() -> float:
    try:
        return max(0.0, float(os.environ.get("GRAPH_CLUSTER_REBUILD_INTERVAL", "900")))
    except ValueError:
        return 900.0


def _full_reconcile_interval() -> float:
    """Seconds between automatic full reconciles. 0 disables the schedule
    (the manual endpoint and the CLI still work)."""
    try:
        return max(0.0, float(os.environ.get("GRAPH_FULL_RECONCILE_INTERVAL", "86400")))
    except ValueError:
        return 86400.0


def _ip_noise_degree() -> int:
    """utils/check.py's cutoff past which a shared IP scores zero. Imported
    lazily (check imports this module) and read rather than duplicated, so the
    incremental path's idea of "this IP can still move a score" cannot drift
    from the scorer's."""
    from utils import check as _check

    return int(_check._IP_NOISE_DEGREE)


# Cache-invalidation fan-out. Anything that wants to hear "these domains' graph
# answers just changed" registers here — the callback fires *after* the write
# transaction commits, so a listener that reacts by re-reading the database
# sees the new state. Scope is "domains" (the tuple names exactly what changed)
# or "all" (a whole-pool rebuild landed and every cached answer is suspect).
# Hooks must not raise anything the caller has to care about: a failing cache
# must never fail or roll back a graph write, so exceptions are logged and
# swallowed here.
GraphInvalidationHook = Callable[[str, tuple[str, ...]], None]
_GRAPH_INVALIDATION_HOOKS: list[GraphInvalidationHook] = []


def register_graph_invalidation_hook(hook: GraphInvalidationHook) -> None:
    """Register a callback fired after a committed change to the derived graph."""
    if hook not in _GRAPH_INVALIDATION_HOOKS:
        _GRAPH_INVALIDATION_HOOKS.append(hook)


def _notify_graph_invalidation(scope: str, domains: Iterable[str] = ()) -> None:
    if not _GRAPH_INVALIDATION_HOOKS:
        return
    payload = tuple(domains)
    for hook in list(_GRAPH_INVALIDATION_HOOKS):
        try:
            hook(scope, payload)
        except Exception as exc:
            LOGGER.warning("graph invalidation hook %r failed: %s", hook, exc)


def _affected_registrable_domains(c: psycopg.Connection[Any], touch: CorrelationTouch) -> set[str]:
    """Every registrable domain whose materialized link scores this write made wrong.

    This is the whole difficulty of incremental correlation. A link's score is
    ``base_weight x rarity(degree) x time_overlap x recency`` and rarity is
    ``1/log2(degree)`` over the selector's *global* degree — so observing one
    more entity on a selector changes the score of every link anywhere in the
    pool that rests on it, not just the links of the domain we happened to
    scan. Rescoring only the scanned domain would leave every co-sharer holding
    a number that no longer reproduces, and a stale score is worse than a slow
    one: it is silently wrong on the pool page and in the exported evidence.
    So we rescore the full neighbourhood, and rely on the fact that the
    neighbourhood is bounded:
      * an *attributing* selector has degree <= CORRELATION_DEGREE_THRESHOLD by
        construction (seed_denylist rule 1 flips anything above it to noise),
        so it can name at most that many domains — or, for the account-bound
        kinds that rule exempts, CORRELATION_ACCOUNT_DEGREE_THRESHOLD, which is
        larger but still a constant, so the bound below holds either way;
      * a non-attributing selector contributes nothing to any score, so it is
        skipped entirely — which is precisely why the pathological high-degree
        nodes (a nameserver on 40,000 domains, a CDN ASN) cost nothing here;
      * the same argument holds for shared IPs against check._IP_NOISE_DEGREE.
    The one-write-crosses-the-threshold case is caught by taking the union of
    the before and after states (see persist_correlation), which is why a
    selector that just *became* noise still drags its ex-neighbours along.
    Cost is therefore O(touched_nodes x threshold), independent of pool size.
    """
    affected = {rd for rd in touch.registrable_domains if rd}
    if touch.rescore_selector_ids:
        rows = c.execute(
            """SELECT DISTINCT e.registrable_domain AS rd
                 FROM observations o
                 JOIN entities e ON e.id = o.entity_id
                WHERE o.selector_id = ANY(%s)
                  AND e.registrable_domain IS NOT NULL""",
            (sorted(touch.rescore_selector_ids),),
        ).fetchall()
        affected.update(row["rd"] for row in rows)
    if touch.rescore_ip_entity_ids:
        rows = c.execute(
            """SELECT DISTINCT e.registrable_domain AS rd
                 FROM entity_edges ee
                 JOIN entities e ON e.id = ee.src_entity_id
                WHERE ee.kind = 'resolves_to'
                  AND ee.dst_entity_id = ANY(%s)
                  AND e.registrable_domain IS NOT NULL""",
            (sorted(touch.rescore_ip_entity_ids),),
        ).fetchall()
        affected.update(row["rd"] for row in rows)
    return affected


def _mark_graph_dirty(domains: Iterable[str]) -> int:
    """Queue `domains` for incremental rescore and flag the graph dirty.

    Two statements on the singleton row rather than one: the upsert keeps
    working if the row somehow does not exist yet, and the merge is a plain
    UPDATE. Both take the same row lock, so concurrent ingests serialize on it
    instead of losing each other's entries — which is also why no long-running
    rebuild may hold that lock for its whole transaction (see rebuild_clusters).
    Returns the resulting queue length, 0 meaning it overflowed and a whole-pool
    rebuild will pick the work up instead.
    """
    init_db()
    values = sorted({str(d).strip() for d in domains if str(d or "").strip()})
    with _conn() as c:
        _mark_clusters_dirty_stmt(c)
        if not values:
            return 0
        row = c.execute(
            """UPDATE graph_state gs
                  SET dirty_domains = CASE
                          WHEN cardinality(m.merged) > %(cap)s THEN ARRAY[]::text[]
                          ELSE m.merged
                      END,
                      updated_at = NOW()
                 FROM (
                      SELECT COALESCE(array_agg(DISTINCT d), ARRAY[]::text[]) AS merged
                        FROM graph_state s, unnest(s.dirty_domains || %(new)s::text[]) AS d
                       WHERE s.id AND d IS NOT NULL AND d <> ''
                 ) m
                WHERE gs.id
               RETURNING cardinality(gs.dirty_domains) AS pending""",
            {"new": values, "cap": _incremental_queue_max()},
        ).fetchone()
    return int((row or {}).get("pending") or 0)


def apply_pending_graph_rescores(limit: int | None = None) -> dict[str, int]:
    """Rescore the queued domains and patch their materialized links in place.

    Scoring happens *outside* the write transaction (check.links_for opens its
    own short-lived connections, exactly as rebuild_clusters' scoring pass
    does), then one short transaction takes the shared rebuild advisory lock
    and swaps the rows. Try-lock rather than wait: if a whole-pool rebuild is
    mid-flight it is about to recompute these same domains anyway, and the
    queue is only drained on success, so nothing is lost by returning and
    retrying on the next tick.

    Only rows for the batch's own domains are deleted, never rows pointing *at*
    them: link scoring is symmetric, so whenever a pair's score moves both of
    its endpoints are in the affected set (they share the selector or IP whose
    degree changed — that is what put them in the set). A batch split across
    ticks can leave the reverse row of a *dropped* link behind for one tick,
    which is why the queue is drained oldest-first and in full.
    """
    init_db()
    batch_limit = limit or _incremental_batch_limit()
    with _conn() as c:
        row = c.execute("SELECT dirty_domains FROM graph_state WHERE id").fetchone()
    pending = sorted({d for d in ((row or {}).get("dirty_domains") or []) if d})
    if not pending:
        return {"rescored_domains": 0, "links": 0, "pending": 0}
    batch = pending[:batch_limit]

    from utils import check as _check

    started = time.monotonic()
    links_by_rd: dict[str, list[dict[str, Any]]] = {}
    with ThreadPoolExecutor(max_workers=min(_rebuild_workers(), len(batch)), thread_name_prefix="rescore") as ex:
        futures = {ex.submit(_check.links_for, rd, limit=None): rd for rd in batch}
        for fut in as_completed(futures):
            links_by_rd[futures[fut]] = fut.result()

    now = datetime.now(timezone.utc).isoformat()
    link_rows: list[tuple[Any, ...]] = []
    count_rows: list[tuple[Any, ...]] = []
    for rd in batch:
        links = links_by_rd[rd]
        # Same shape as rebuild_clusters: every scored link is stored, but the
        # pool-page count uses links_for's own default top-50 cut so the number
        # never disagrees with the domain page.
        count_rows.append((rd, len(links[:50]), now))
        for link in links:
            link_rows.append((
                rd, link["target"], link["score"], link["confidence"], link["strength"],
                link["shared_node_count"], _json(link["evidence"]), now,
            ))

    with _conn() as c:
        lock_row = c.execute(
            "SELECT pg_try_advisory_xact_lock(%s) AS locked", (_GRAPH_REBUILD_LOCK_KEY,)
        ).fetchone()
        if not lock_row or not lock_row["locked"]:
            LOGGER.info("graph rescore: deferred — a full rebuild holds the lock (%d queued)", len(pending))
            return {"rescored_domains": 0, "links": 0, "pending": len(pending), "skipped": 1}
        c.execute("DELETE FROM graph_links WHERE registrable_domain = ANY(%s)", (batch,))
        c.execute("DELETE FROM graph_connection_counts WHERE registrable_domain = ANY(%s)", (batch,))
        if link_rows:
            c.cursor().executemany(
                """INSERT INTO graph_links
                       (registrable_domain, target, score, confidence, strength,
                        shared_node_count, evidence, computed_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                link_rows,
            )
        c.cursor().executemany(
            """INSERT INTO graph_connection_counts (registrable_domain, connection_count, computed_at)
               VALUES (%s,%s,%s)""",
            count_rows,
        )
        # Subtract exactly what we scored instead of clearing the column: a scan
        # that committed while this batch was scoring has already queued itself
        # and must survive this update.
        c.execute(
            """UPDATE graph_state
                  SET dirty_domains = ARRAY(
                          SELECT unnest(dirty_domains) EXCEPT SELECT unnest(%s::text[])
                      ),
                      incremental_at = NOW(),
                      updated_at = NOW()
                WHERE id""",
            (batch,),
        )
    _notify_graph_invalidation("domains", batch)
    LOGGER.info(
        "graph rescore: %d domain(s), %d link(s) in %.2fs (%d still queued)",
        len(batch), len(link_rows), time.monotonic() - started, len(pending) - len(batch),
    )
    return {
        "rescored_domains": len(batch),
        "links": len(link_rows),
        "pending": len(pending) - len(batch),
    }


def graph_maintenance_state() -> dict[str, Any]:
    """Queue depth and age of each maintenance tier, for the scheduler and ops."""
    init_db()
    with _conn() as c:
        row = c.execute(
            """SELECT dirty,
                      cardinality(dirty_domains) AS pending,
                      EXTRACT(EPOCH FROM (NOW() - clean_at))         AS since_clean,
                      EXTRACT(EPOCH FROM (NOW() - full_reconcile_at)) AS since_full
                 FROM graph_state WHERE id"""
        ).fetchone()
    if row is None:
        return {"dirty": True, "pending": 0, "since_clean": None, "since_full": None}
    return {
        "dirty": bool(row["dirty"]),
        "pending": int(row["pending"] or 0),
        "since_clean": None if row["since_clean"] is None else float(row["since_clean"]),
        "since_full": None if row["since_full"] is None else float(row["since_full"]),
    }


def run_graph_maintenance() -> dict[str, Any]:
    """One tick of continuous graph maintenance — see the tier comment above.

    At most one heavy tier runs per tick: a due full reconcile subsumes both
    cheaper tiers, and a whole-pool cluster rebuild subsumes the incremental
    queue, so doing them in the same tick would only duplicate work.
    """
    state = graph_maintenance_state()
    full_interval = _full_reconcile_interval()
    since_full = state["since_full"]
    if full_interval and (since_full is None or since_full >= full_interval):
        LOGGER.info("graph maintenance: full reconcile due (%s s since last)", since_full)
        return {"tier": "full_reconcile", **rebuild_all_correlation()}

    cluster_interval = _cluster_rebuild_interval()
    since_clean = state["since_clean"]
    clusters_due = state["dirty"] and (since_clean is None or since_clean >= cluster_interval)
    if clusters_due:
        return {"tier": "clusters", **rebuild_clusters()}
    if state["pending"]:
        return {"tier": "incremental", **apply_pending_graph_rescores()}
    return {"tier": "idle"}


def _mark_clusters_clean(c: psycopg.Connection[Any], covered: Iterable[str] = ()) -> None:
    """Clear the dirty flag, and with it the incremental queue entries this
    whole-pool rebuild just subsumed.

    `covered` is the queue as it stood when the rebuild started, not the queue
    now: anything enqueued while the rebuild was running was written after the
    rebuild had already read (or scored) that domain, so it still needs its own
    incremental pass and must survive.
    """
    c.execute(
        """INSERT INTO graph_state (id, dirty, clean_at, rebuild_started_at, updated_at)
           VALUES (TRUE, FALSE, NOW(), NULL, NOW())
           ON CONFLICT (id) DO UPDATE SET
               dirty = FALSE,
               clean_at = NOW(),
               rebuild_started_at = NULL,
               updated_at = NOW()"""
    )
    covered_list = [str(d) for d in covered if d]
    if covered_list:
        c.execute(
            """UPDATE graph_state
                  SET dirty_domains = ARRAY(
                          SELECT unnest(dirty_domains) EXCEPT SELECT unnest(%s::text[])
                      ),
                      updated_at = NOW()
                WHERE id""",
            (covered_list,),
        )


def rebuild_all_correlation() -> dict[str, int]:
    """Global recompute: rebuild the whole correlation graph from raw intel.

    Drops the derived tables and re-projects every stored search (oldest first
    so time windows widen monotonically), then recomputes degrees and seeds the
    denylist. This is the deterministic "recompute without rescanning" path,
    and the periodic reconcile that corrects whatever the incremental path
    drifted on — see the maintenance-tier comment above _incremental_batch_limit.

    Takes the shared rebuild advisory lock for the whole reprojection, waiting
    rather than skipping: an incremental rescore is a 20-second-cadence
    background chore and can retry, but this pass is the correctness backstop
    and must not be the one that gets dropped. It empties and refills
    entities/selectors/observations in a single transaction, so a concurrent
    rescore that ran against the half-built graph would write scores computed
    from a corpus that never existed.
    """
    init_db()
    started = time.monotonic()
    with _conn() as c:
        c.execute("SELECT pg_advisory_xact_lock(%s)", (_GRAPH_REBUILD_LOCK_KEY,))
        LOGGER.info("rebuild_all_correlation: dropping derived tables")
        _truncate_correlation(c)
        # Metadata for the whole corpus in one read, rather than get_result's
        # connect-and-query per search. Four small columns per row, so this
        # stays a few MB even for a large pool, and it takes the per-search
        # cost down to the one query that actually has to be per-search (the
        # JSONB field payload). Reading it on `c` also means the projection
        # sees the same snapshot as the transaction holding the rebuild lock,
        # where a per-search connection saw a slightly newer one each time.
        metas = {
            int(row["id"]): row
            for row in c.execute(
                "SELECT id, target, type, timestamp FROM searches ORDER BY id ASC"
            ).fetchall()
        }
        ids = sorted(metas)
        total = len(ids)
        LOGGER.info("rebuild_all_correlation: projecting %d stored search(es)", total)
        # Logged every ~5% of the way through (capped at 500) instead of
        # per-search: the per-search work itself (persist_correlation) is a
        # handful of INSERTs, cheap enough that per-row logging would dominate
        # the log with noise rather than signal, but this is also the slowest
        # single phase for a large corpus, so silence here is exactly what
        # makes a rebuild look hung. The cap keeps the first line from taking
        # forever on a very large corpus; the heartbeat covers a slow patch
        # (a few unusually large stored results) that would otherwise go quiet
        # for a whole percentage-point's worth of searches.
        log_every = max(1, min(total // 20, 500))
        heartbeat_seconds = 10.0
        last_logged = started
        for i, sid in enumerate(ids, 1):
            result = _hydrate_result(metas[sid], _load_result_from_fields(c, sid), sid)
            if result is not None:
                persist_correlation(c, result, search_id=sid, recount=False)
            now_mono = time.monotonic()
            if i % log_every == 0 or i == total or now_mono - last_logged >= heartbeat_seconds:
                LOGGER.info(
                    "rebuild_all_correlation: projected %d/%d searches (%.1fs elapsed)",
                    i, total, now_mono - started,
                )
                last_logged = now_mono
        LOGGER.info("rebuild_all_correlation: recomputing selector degrees")
        recompute_all_selector_degrees(c)
        LOGGER.info("rebuild_all_correlation: seeding denylist")
        denylist_started = time.monotonic()
        denylisted = seed_denylist(c)
        LOGGER.info(
            "rebuild_all_correlation: denylisted %d selector(s) (%.1fs)",
            denylisted, time.monotonic() - denylist_started,
        )
        counts = {
            "searches": total,
            "entities": c.execute("SELECT count(*) AS n FROM entities").fetchone()["n"],
            "selectors": c.execute("SELECT count(*) AS n FROM selectors").fetchone()["n"],
            "observations": c.execute("SELECT count(*) AS n FROM observations").fetchone()["n"],
            "entity_edges": c.execute("SELECT count(*) AS n FROM entity_edges").fetchone()["n"],
            "denylisted_selectors": denylisted,
        }
    # Clusters depend on the freshly seeded denylist, so rebuild them last.
    # Outside the transaction above so the advisory lock is released first —
    # rebuild_clusters takes it itself, and would otherwise deadlock against a
    # lock this process already holds only by luck of it being the same session.
    LOGGER.info("rebuild_all_correlation: projection done in %.1fs, rebuilding clusters", time.monotonic() - started)
    counts.update(rebuild_clusters())
    # Paces the automatic schedule, and resets it when an operator runs a
    # recompute by hand — a manual reconcile is still a reconcile, so the timer
    # should start from it rather than firing again minutes later.
    with _conn() as c:
        c.execute("UPDATE graph_state SET full_reconcile_at = NOW(), updated_at = NOW() WHERE id")
    _notify_graph_invalidation("all")
    LOGGER.info("rebuild_all_correlation: done in %.1fs total", time.monotonic() - started)
    return counts


def rebuild_correlation_for_search(search_id: int) -> CorrelationTouch:
    """Incrementally (re)project a single search into the correlation graph and
    queue everything its degree changes invalidated for rescore."""
    init_db()
    result = get_result(search_id)
    if result is None:
        return CorrelationTouch.empty()
    with _conn() as c:
        touch = persist_correlation(c, result, search_id=search_id, recount=True)
        affected = _affected_registrable_domains(c, touch)
    _mark_graph_dirty(affected)
    return touch


# ── Correlation layer: denylist seeding ─────────────────────────────────────

def _degree_threshold() -> int:
    try:
        return int(os.getenv("CORRELATION_DEGREE_THRESHOLD", "50"))
    except ValueError:
        return 50


# Selectors that are issued *to an account*, not deployed on infrastructure: a
# webmaster-tools verification code proves control of a Google/Bing account, and
# an AdSense publisher or GA property id binds to one payment/analytics account.
# Nobody ends up sharing one by renting the same CDN, so high degree here means
# "this account owns a lot of domains" — the finding itself — where for a
# nameserver or an ASN it means "this is public infrastructure". They still get
# a ceiling (see _account_degree_threshold) because a verification code baked
# into a widely-redistributed CMS theme does happen.
_ACCOUNT_BOUND_TRACKING_SUBKINDS = ("adsense_publisher", "ga_property")


def _account_degree_threshold() -> int:
    try:
        return int(os.getenv("CORRELATION_ACCOUNT_DEGREE_THRESHOLD", "500"))
    except ValueError:
        return 500


def _san_bundle_threshold() -> int:
    try:
        return int(os.getenv("TLS_SAN_BUNDLE_THRESHOLD", "15"))
    except ValueError:
        return 15


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
    #    (Cloudflare universal-SSL SAN sets, big nameservers/ASNs, ...) —
    #    except the account-bound kinds, where degree is the signal rather than
    #    the noise and a state broadcaster's own verification code would
    #    otherwise be discarded precisely because it covers its whole network.
    #    Rarity weighting still discounts them: 1/log2(degree) takes a token on
    #    500 domains down to ~11% of its base weight, so a wide one degrades
    #    smoothly instead of vanishing at a cliff.
    c.execute(
        """UPDATE selectors
              SET attributing = FALSE
            WHERE entity_count > CASE
                    WHEN kind = 'site_verification'
                      OR (kind = 'tracking_id'
                          AND split_part(value, '|', 1) = ANY(%s))
                    THEN %s ELSE %s END""",
        (list(_ACCOUNT_BOUND_TRACKING_SUBKINDS), _account_degree_threshold(), threshold),
    )

    # 2) Known noise ASNs (CDN/proxy, shared-hosting, big mail).
    noise_asns = sorted(_CDN_PROXY_ASNS | _SHARED_HOSTING_ASNS | _MAIL_ASNS)
    if noise_asns:
        c.execute(
            "UPDATE selectors SET attributing = FALSE WHERE kind = 'asn' AND value = ANY(%s)",
            (noise_asns,),
        )

    # 3) Big-provider / registrar nameservers from the boring-NS list.
    # 4) Shared-host / default certificate SANs (cPanel/Apache defaults, localhost…).
    # Both decisions are made in Python (the predicates are pattern lists, not
    # SQL), so the ids are collected and written in one statement each — the
    # same shape rule 5 below already uses. Per-row UPDATEs here cost a round
    # trip per selector of that kind, which on a large pool is tens of
    # thousands of them for a few thousand actual flips.
    boring_ns = [
        row["id"]
        for row in c.execute("SELECT id, value FROM selectors WHERE kind = 'nameserver'").fetchall()
        if _is_boring_nameserver(row["value"])
    ]
    low_signal_sans = [
        row["id"]
        for row in c.execute("SELECT id, value FROM selectors WHERE kind = 'tls_san'").fetchall()
        if _is_low_signal_tls_identity(row["value"])
        or _text_contains_any(row["value"], _LOW_SIGNAL_HOSTING_PATTERNS)
    ]
    for ids in (boring_ns, low_signal_sans):
        if ids:
            c.execute("UPDATE selectors SET attributing = FALSE WHERE id = ANY(%s)", (ids,))

    # 5) Certificates with an implausibly large, heterogeneous SAN list are
    #    shared-hosting/AutoSSL bundles covering many unrelated customer
    #    domains on one server — neither the cert fingerprint match nor any of
    #    its individual SANs are an ownership signal in that case, even when
    #    none of the bundled domains match a recognized hosting-provider
    #    pattern (rule 4 only catches *known* providers by name).
    #    Heterogeneity is measured in distinct *registrable* domains, not raw
    #    SAN count: one operator legitimately putting 20 of its own subdomains
    #    on a single cert is one owner, and counting names condemned all 20 of
    #    its SAN selectors. 20 unrelated customers on an AutoSSL bundle is what
    #    the rule is for, and only that trips it now.
    # 6) A cert whose *entire* SAN set is a known low-signal hosting/platform
    #    domain is a shared placeholder regardless of how many SANs it has —
    #    e.g. Firebase Hosting serves "firebaseapp.com, *.firebaseapp.com" as
    #    its generic default cert to any customer domain pointed at its shared
    #    IPs, with only 2 SANs, so rule 5's size threshold never fires.
    # Both read each certificate's real SAN list from tls_certs/scan_hits —
    # see _cert_bundle_denylist_ids for why they no longer reconstruct it from
    # observation validity windows.
    cert_bundle_ids = _cert_bundle_denylist_ids(c)
    if cert_bundle_ids:
        c.execute("UPDATE selectors SET attributing = FALSE WHERE id = ANY(%s)", (sorted(cert_bundle_ids),))

    return c.execute("SELECT count(*) AS n FROM selectors WHERE attributing = FALSE").fetchone()["n"]


def _cert_san_sets(
    c: psycopg.Connection[Any], *, fingerprints: set[str] | None = None
) -> dict[str, set[str]]:
    """Map each certificate fingerprint to the SAN set that certificate carries.

    Read straight off ``tls_certs`` / ``scan_hits``, where a row *is* one
    observed certificate and ``sans`` is that certificate's own SAN list.

    This used to be reconstructed by joining ``observations`` to itself on
    equal ``(entity_id, first_seen, last_seen)`` — the theory being that a
    cert's fingerprint and its SANs are written together and so share a
    validity window. They are, but observation windows do not stay put:
    ``record_observation`` upserts with ``first_seen = LEAST(...)`` and
    ``last_seen = GREATEST(...)``, so re-seeing a domain widens the row. After
    the first certificate rotation a SAN carried by both the old and new cert
    spans both windows and equals neither, the join returns nothing, and the
    shared-hosting rules below silently stopped flagging anything — leaving a
    40-domain AutoSSL bundle cert attributing at full weight, which is
    780 bogus "strong" pairs from a single host.

    Keying on the fingerprint avoids the question entirely: it identifies the
    exact certificate, and never widens.

    ``fingerprints`` bounds the read to specific certificates; ``None`` reads
    the whole corpus (the full-rebuild path).
    """
    san_sets: dict[str, set[str]] = {}
    for table in ("tls_certs", "scan_hits"):
        if fingerprints is None:
            rows = c.execute(
                f"SELECT sha256, sans FROM {table} WHERE sha256 IS NOT NULL AND sans IS NOT NULL"
            ).fetchall()
        elif fingerprints:
            # Bounded read for the incremental path: only the certificates the
            # touched selectors actually belong to. Both tables index sha256.
            rows = c.execute(
                f"SELECT sha256, sans FROM {table} "
                "WHERE sans IS NOT NULL AND sha256 = ANY(%s)",
                (sorted(fingerprints),),
            ).fetchall()
        else:
            rows = []
        for row in rows:
            fingerprint = _normalize_identifier_hash(row["sha256"])
            if not fingerprint:
                continue
            raw_sans = row["sans"]
            if isinstance(raw_sans, str):
                try:
                    raw_sans = json.loads(raw_sans)
                except (ValueError, TypeError):
                    continue
            if not isinstance(raw_sans, (list, tuple)):
                continue
            bucket = san_sets.setdefault(fingerprint, set())
            for san in raw_sans:
                normalized = _normalize_tls_identity(san)
                if normalized:
                    bucket.add(normalized)
    return san_sets


def _cert_bundle_denylist_ids(
    c: psycopg.Connection[Any], *, restrict_to: set[int] | None = None
) -> set[int]:
    """Selector ids to deny under the two shared-certificate rules.

    Rule 5 — a certificate covering more distinct *registrable domains* than
    ``_san_bundle_threshold()`` is a shared-hosting/AutoSSL bundle spanning
    unrelated customers: neither its fingerprint nor any of its SANs attribute
    anything. Counting registrable domains rather than SAN names is what keeps
    a single operator's 20-subdomain cert out of the rule. Rule 6 — a certificate whose *entire* SAN set is known
    platform boilerplate (Firebase's 2-SAN default cert and friends) is a
    placeholder no matter how short it is.

    ``restrict_to`` limits this to bundles that a set of freshly touched
    selectors participates in — and bounds the *work*, not just the result: the
    incremental path runs on every ingest, so reading every certificate and
    every SAN selector in the corpus each time would make ingest cost grow with
    total corpus size rather than with what changed.
    """
    # Which certificates can possibly be implicated. For the incremental path
    # that is the touched cert selectors plus the certs carrying any touched SAN
    # — resolved in SQL so the Python side only ever sees candidates.
    fingerprints: set[str] | None = None
    if restrict_to is not None:
        if not restrict_to:
            return set()
        ids = sorted(restrict_to)
        fingerprints = set()
        for row in c.execute(
            "SELECT value FROM selectors WHERE id = ANY(%s) AND kind = 'tls_cert_sha256'",
            (ids,),
        ).fetchall():
            normalized = _normalize_identifier_hash(row["value"])
            if normalized:
                fingerprints.add(normalized)
        touched_sans = [
            _normalize_tls_identity(row["value"])
            for row in c.execute(
                "SELECT value FROM selectors WHERE id = ANY(%s) AND kind = 'tls_san'", (ids,)
            ).fetchall()
        ]
        touched_sans = [san for san in touched_sans if san]
        # `sans` holds raw certificate names while selector values are
        # normalized, so match against the spellings _normalize_tls_identity
        # collapses: the bare name, a wildcard, and a www host.
        raw_candidates = sorted(
            {
                spelling
                for san in touched_sans
                if san
                for spelling in (san, f"*.{san}", f"www.{san}", f"*.www.{san}")
            }
        )
        if raw_candidates:
            for table in ("tls_certs", "scan_hits"):
                for row in c.execute(
                    f"SELECT DISTINCT sha256 FROM {table} "
                    "WHERE sha256 IS NOT NULL AND sans IS NOT NULL "
                    "AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(sans) AS san "
                    "            WHERE lower(rtrim(san, '.')) = ANY(%s))",
                    (raw_candidates,),
                ).fetchall():
                    normalized = _normalize_identifier_hash(row["sha256"])
                    if normalized:
                        fingerprints.add(normalized)
        if not fingerprints:
            return set()

    san_sets = _cert_san_sets(c, fingerprints=fingerprints)
    if not san_sets:
        return set()

    cert_ids: dict[str, int] = {}
    for row in c.execute(
        "SELECT id, value FROM selectors WHERE kind = 'tls_cert_sha256'"
    ).fetchall():
        normalized = _normalize_identifier_hash(row["value"])
        if normalized:
            cert_ids[normalized] = row["id"]

    san_ids: dict[str, int] = {}
    for row in c.execute("SELECT id, value FROM selectors WHERE kind = 'tls_san'").fetchall():
        normalized = _normalize_tls_identity(row["value"])
        if normalized:
            san_ids[normalized] = row["id"]

    san_threshold = _san_bundle_threshold()
    denied: set[int] = set()
    for fingerprint, sans in san_sets.items():
        cert_selector_id = cert_ids.get(fingerprint)
        if cert_selector_id is None or not sans:
            continue
        member_ids = {san_ids[san] for san in sans if san in san_ids}

        # Distinct owners, not distinct names — see rule 5's comment. Falls back
        # to the name itself when registrable_domain declines (an IP SAN, or a
        # bare hostname with no public suffix), so those still count separately.
        distinct_owners = {registrable_domain(san) or san for san in sans}
        is_bundle = len(distinct_owners) > san_threshold
        is_placeholder = all(
            _is_low_signal_tls_identity(san) or _text_contains_any(san, _LOW_SIGNAL_HOSTING_PATTERNS)
            for san in sans
        )
        if not (is_bundle or is_placeholder):
            continue
        if restrict_to is not None and not ({cert_selector_id} | member_ids) & restrict_to:
            continue

        denied.add(cert_selector_id)
        # Rule 6 condemns the placeholder certificate itself; its SANs are
        # already handled by rule 4's pattern list and may legitimately belong
        # to whoever registered them. Only a size-based bundle taints its SANs.
        if is_bundle:
            denied |= member_ids
    return denied


def apply_denylist_for_selectors(c: psycopg.Connection[Any], selector_ids: Iterable[int]) -> int:
    """Apply denylist rules to selectors touched by live ingest.

    Full recompute uses ``seed_denylist`` because it can reset every selector.
    Live ingest only needs to reevaluate newly touched selectors plus any cert
    bundle they participate in.
    """
    ids = sorted({int(sel_id) for sel_id in selector_ids if sel_id is not None})
    if not ids:
        return c.execute("SELECT count(*) AS n FROM selectors WHERE attributing = FALSE").fetchone()["n"]

    c.execute("UPDATE selectors SET attributing = TRUE WHERE id = ANY(%s)", (ids,))

    # Same CASE as seed_denylist's rule 1. Applying a flat threshold here while
    # the rebuild applies a raised one for site_verification and account-bound
    # tracking subkinds made the two paths disagree: a broadcaster's
    # google-site-verification token spanning 300 domains was attributing after
    # a reconcile, non-attributing after the next ingest that touched it, and
    # back again after the following reconcile — edges appearing and vanishing
    # depending only on which path ran last.
    threshold = _degree_threshold()
    c.execute(
        """UPDATE selectors
              SET attributing = FALSE
            WHERE id = ANY(%s)
              AND entity_count > CASE
                    WHEN kind = 'site_verification'
                      OR (kind = 'tracking_id'
                          AND split_part(value, '|', 1) = ANY(%s))
                    THEN %s ELSE %s END""",
        (ids, list(_ACCOUNT_BOUND_TRACKING_SUBKINDS), _account_degree_threshold(), threshold),
    )

    noise_asns = sorted(_CDN_PROXY_ASNS | _SHARED_HOSTING_ASNS | _MAIL_ASNS)
    if noise_asns:
        c.execute(
            """UPDATE selectors
               SET attributing = FALSE
               WHERE id = ANY(%s) AND kind = 'asn' AND value = ANY(%s)""",
            (ids, noise_asns),
        )

    for row in c.execute(
        "SELECT id, value FROM selectors WHERE id = ANY(%s) AND kind = 'nameserver'",
        (ids,),
    ).fetchall():
        if _is_boring_nameserver(row["value"]):
            c.execute("UPDATE selectors SET attributing = FALSE WHERE id = %s", (row["id"],))

    for row in c.execute(
        "SELECT id, value FROM selectors WHERE id = ANY(%s) AND kind = 'tls_san'",
        (ids,),
    ).fetchall():
        value = row["value"]
        if _is_low_signal_tls_identity(value) or _text_contains_any(value, _LOW_SIGNAL_HOSTING_PATTERNS):
            c.execute("UPDATE selectors SET attributing = FALSE WHERE id = %s", (row["id"],))

    # Same two shared-certificate rules as seed_denylist, limited to bundles
    # the freshly touched selectors participate in.
    cert_bundle_ids = _cert_bundle_denylist_ids(c, restrict_to=set(ids))
    if cert_bundle_ids:
        c.execute("UPDATE selectors SET attributing = FALSE WHERE id = ANY(%s)", (sorted(cert_bundle_ids),))

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
                       array_agg(DISTINCT ob.source) AS b_sources,
                       array_agg(DISTINCT ea.value) AS a_hosts,
                       array_agg(DISTINCT eb.value) AS b_hosts
                FROM selectors sel
                JOIN observations oa ON oa.selector_id = sel.id AND oa.entity_id IN (SELECT id FROM a_ent)
                JOIN entities ea ON ea.id = oa.entity_id
                JOIN observations ob ON ob.selector_id = sel.id AND ob.entity_id IN (SELECT id FROM b_ent)
                JOIN entities eb ON eb.id = ob.entity_id
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
                     a_ip AS (SELECT ee.dst_entity_id AS ip_id, min(ee.first_seen) AS f, max(ee.last_seen) AS l,
                                     array_agg(DISTINCT ee.source) AS srcs,
                                     array_agg(DISTINCT src.value) AS hosts
                              FROM entity_edges ee JOIN entities src ON src.id = ee.src_entity_id
                              WHERE ee.kind='resolves_to' AND ee.src_entity_id IN (SELECT id FROM a_ent)
                              GROUP BY ee.dst_entity_id),
                     b_ip AS (SELECT ee.dst_entity_id AS ip_id, min(ee.first_seen) AS f, max(ee.last_seen) AS l,
                                     array_agg(DISTINCT ee.source) AS srcs,
                                     array_agg(DISTINCT src.value) AS hosts
                              FROM entity_edges ee JOIN entities src ON src.id = ee.src_entity_id
                              WHERE ee.kind='resolves_to' AND ee.src_entity_id IN (SELECT id FROM b_ent)
                              GROUP BY ee.dst_entity_id)
                SELECT ip.value,
                       a_ip.f AS a_first, a_ip.l AS a_last, a_ip.srcs AS a_sources, a_ip.hosts AS a_hosts,
                       b_ip.f AS b_first, b_ip.l AS b_last, b_ip.srcs AS b_sources, b_ip.hosts AS b_hosts,
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


def ip_network_context(ip_values: list[str]) -> dict[str, dict[str, Any]]:
    """Latest known network context per IP (ASN, network name/CIDR, reverse-proxy
    family, Cloudflare flag, country, PTR) — used to explain *what kind* of box a
    shared IP is (CDN/proxy edge vs. dedicated origin vs. shared-hosting pool)
    instead of just reporting that an overlap exists.

    Also flattens the Censys host-enrichment classification out of the
    `censys_enrichment` JSONB into scalar keys (`censys_hosting`,
    `censys_proxy`, `censys_vpn`, `censys_tor`, `censys_relay`,
    `censys_anonymous`, `censys_labels`). Those are IPinfo-derived and are the
    only source in the pipeline for Tor/VPN/relay; utils.check reads them as a
    *discount* on shared_ip evidence, never as the display label — that stays
    `proxy_family` from detect_proxy_details. Flattened here so the JSON shape
    lives in one place rather than in the scorer.
    """
    values = sorted({v for v in ip_values if v})
    if not values:
        return {}
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT ON (ip) ip, cloudflare, asn, asn_desc, asn_registry, country,
                      network_name, network_cidr, proxy_family, proxy_confidence, ptr,
                      censys_enrichment
               FROM ips
               WHERE ip = ANY(%s)
               ORDER BY ip, observed_at DESC NULLS LAST, id DESC""",
            (values,),
        ).fetchall()

    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        meta = dict(row)
        enrichment = meta.pop("censys_enrichment", None)
        if isinstance(enrichment, (str, bytes)):
            try:
                enrichment = json.loads(enrichment)
            except (json.JSONDecodeError, TypeError):
                enrichment = None
        enrichment = enrichment if isinstance(enrichment, dict) else {}
        for flag in ("hosting", "proxy", "vpn", "tor", "relay", "anonymous"):
            meta[f"censys_{flag}"] = bool(enrichment.get(flag))
        labels = enrichment.get("labels")
        meta["censys_labels"] = [str(x) for x in labels] if isinstance(labels, list) else []
        out[meta["ip"]] = meta
    return out


def tls_cert_context(sha256_values: list[str]) -> dict[str, dict[str, Any]]:
    """Latest known certificate metadata per sha256 fingerprint — CN, issuer
    CN/org, and the certificate's own cryptographic validity window
    (not_before/not_after, as issued by the CA). Distinct from an
    observation's first_seen/last_seen (when *we* last scanned it): a cert
    can be long expired while still showing a recent last_seen if a probe
    only recently re-encountered a stale record, and this is the field an
    analyst actually needs to answer "is this certificate still alive" — used
    to enrich tls_cert_sha256 evidence so investigators see the real story
    behind a match, not just that one exists."""
    values = sorted({v for v in sha256_values if v})
    if not values:
        return {}
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT DISTINCT ON (sha256) sha256, cn, issuer_cn, issuer_org, not_before, not_after
               FROM tls_certs
               WHERE sha256 = ANY(%s)
               ORDER BY sha256, observed_at DESC NULLS LAST, id DESC""",
            (values,),
        ).fetchall()
    return {row["sha256"]: dict(row) for row in rows}


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
                       array_agg(DISTINCT ob.source) AS b_sources,
                       array_agg(DISTINCT ea.value) AS a_hosts,
                       array_agg(DISTINCT e2.value) AS b_hosts
                FROM selectors sel
                JOIN observations oa ON oa.selector_id = sel.id AND oa.entity_id IN (SELECT id FROM a_ent)
                JOIN entities ea ON ea.id = oa.entity_id
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
                     a_ip AS (SELECT ee.dst_entity_id AS ip_id, min(ee.first_seen) AS f, max(ee.last_seen) AS l,
                                     array_agg(DISTINCT ee.source) AS srcs,
                                     array_agg(DISTINCT src.value) AS hosts
                              FROM entity_edges ee JOIN entities src ON src.id = ee.src_entity_id
                              WHERE ee.kind='resolves_to' AND ee.src_entity_id IN (SELECT id FROM a_ent)
                              GROUP BY ee.dst_entity_id)
                SELECT e2.registrable_domain AS rd, ip.value,
                       a_ip.f AS a_first, a_ip.l AS a_last, a_ip.srcs AS a_sources, a_ip.hosts AS a_hosts,
                       min(ee.first_seen) AS b_first, max(ee.last_seen) AS b_last,
                       array_agg(DISTINCT ee.source) AS b_sources,
                       array_agg(DISTINCT e2.value) AS b_hosts,
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
                GROUP BY e2.registrable_domain, ip.id, ip.value, a_ip.f, a_ip.l, a_ip.srcs, a_ip.hosts""",
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


# ── Multi-hop path precompute ────────────────────────────────────────────────
#
# graph_links (built below) is a scored, weighted adjacency list -- each
# domain's direct connections. _extend_paths walks it breadth-first, purely
# in memory off the adjacency this same rebuild pass just computed (no extra
# DB round-trips), and materializes every domain's multi-hop reachability
# into graph_paths. This is what makes "why is A related to C" an indexed
# SELECT everywhere it's surfaced (search, domain page, path lookups) instead
# of a traversal triggered by the act of looking.

# Cap on how many of a node's own outgoing links are followed per BFS step --
# independent of graph_links' own unlimited storage -- so a hub domain with
# hundreds of direct links can't blow up every other domain's path walk.
_PATH_FRONTIER_LIMIT = 50


def _graph_path_max_hops() -> int:
    try:
        return int(os.getenv("GRAPH_PATH_MAX_HOPS", "3"))
    except ValueError:
        return 3


def _graph_path_max_nodes() -> int:
    try:
        return int(os.getenv("GRAPH_PATH_MAX_NODES", "200"))
    except ValueError:
        return 200


def _rebuild_workers() -> int:
    """Concurrency for rebuild_clusters()'s per-domain scoring pass.

    Each check.links_for(rd) call runs read-only on its own short-lived
    connection (never the rebuild's own `c`), so the loop parallelizes safely.
    What it does *not* do is overlap latency with anything: Postgres runs on
    this same host in the compose stack, so a worker "waiting on the database"
    is waiting on the very cores its siblings need. Past the core count the
    queries stop overlapping and start queueing — the scoring pass on a 4-core
    box under the old flat default of 32 ran at a load average of ~32, roughly
    8:1 oversubscription, which turns a ~300ms query into a ~9s one and adds
    connection churn and work_mem pressure on top.

    So the default tracks the machine rather than being a fixed number. Raise
    REBUILD_WORKERS above the core count only when the database is genuinely
    remote and there is round-trip latency to hide; lower it if Postgres has a
    small max_connections.
    """
    default = max(2, min(16, os.cpu_count() or 4))
    try:
        value = int(os.environ.get("REBUILD_WORKERS", str(default)))
    except ValueError:
        return default
    return max(1, value)


def _extend_paths(c: psycopg.Connection[Any], adjacency: dict[str, list[dict]], all_rds: list[str], now: str) -> None:
    """BFS every domain out to _graph_path_max_hops() over `adjacency` (each
    domain's own top-`_PATH_FRONTIER_LIMIT`-by-score graph_links rows, already
    in memory from the loop that just rebuilt graph_links) and materialize the
    shortest reachable chain to every node found into graph_paths."""
    max_hops = _graph_path_max_hops()
    max_nodes = _graph_path_max_nodes()
    c.execute("DELETE FROM graph_paths")
    rows: list[tuple[Any, ...]] = []
    for source in all_rds:
        visited = {source}
        parent: dict[str, tuple[str, dict]] = {}
        order: list[str] = []
        queue: deque[tuple[str, int]] = deque([(source, 0)])
        while queue and len(order) < max_nodes:
            node, hops = queue.popleft()
            if hops >= max_hops:
                continue
            for edge in adjacency.get(node, [])[:_PATH_FRONTIER_LIMIT]:
                target = edge["target"]
                if target in visited:
                    continue
                visited.add(target)
                parent[target] = (node, edge)
                order.append(target)
                queue.append((target, hops + 1))
                if len(order) >= max_nodes:
                    break
        for target in order:
            chain: list[dict[str, Any]] = []
            cur = target
            while cur != source:
                prev, edge = parent[cur]
                chain.append({
                    "from": prev, "to": cur,
                    "score": edge["score"], "confidence": edge["confidence"],
                    "strength": edge["strength"], "evidence": edge["evidence"],
                })
                cur = prev
            chain.reverse()
            rows.append(
                (source, target, len(chain), min(hop["score"] for hop in chain), _json(chain), now)
            )
    if rows:
        c.cursor().executemany(
            """INSERT INTO graph_paths (registrable_domain, target, hops, min_hop_score, chain, computed_at)
               VALUES (%s,%s,%s,%s,%s,%s)""",
            rows,
        )


def rebuild_clusters() -> dict[str, int]:
    """Recompute and materialize global clusters from the attributing graph,
    plus the "browse by shared edge" groups (graph_selector_groups) — so both
    are ready to read as soon as this returns, with nothing computed live on
    request."""
    init_db()
    started = time.monotonic()
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

    # Every shared node that unioned ≥2 domains, kept so we can materialize *what*
    # ties each cluster together once the components settle.
    connectors: list[dict[str, Any]] = []

    def union_group(rds: list[str], connector: dict[str, Any] | None = None) -> None:
        members = [rd for rd in rds if rd]
        for other in members[1:]:
            union(members[0], other)
        if connector is not None and len(members) >= 2:
            connectors.append({**connector, "members": members})

    # Marked in its own short transaction, deliberately not inside the long one
    # below: an UPDATE on the graph_state singleton holds that row's lock until
    # commit, and every ingest touches the same row to queue its rescore (see
    # _mark_graph_dirty) and to claim Censys budget. Doing it inline would make
    # every concurrent scan block for the entire duration of a rebuild.
    # `covered` is read here too, so the queue entries this pass subsumes are
    # the ones it can see at the start — later arrivals keep their own pass.
    covered: list[str] = []
    with _conn() as c:
        row = c.execute(
            """UPDATE graph_state SET rebuild_started_at = NOW(), updated_at = NOW()
                WHERE id = TRUE RETURNING dirty_domains"""
        ).fetchone()
        covered = [d for d in ((row or {}).get("dirty_domains") or []) if d]

    with _conn() as c:
        lock_row = c.execute(
            "SELECT pg_try_advisory_xact_lock(%s) AS locked",
            (_GRAPH_REBUILD_LOCK_KEY,),
        ).fetchone()
        if not lock_row or not lock_row["locked"]:
            LOGGER.info("rebuild_clusters: skipped — another rebuild is already in progress")
            return {"clusters": 0, "clustered_domains": 0, "connected_domains": 0, "skipped": 1}
        LOGGER.info("rebuild_clusters: starting (fanout cap %d)", fanout)

        for row in c.execute(
            """SELECT sel.kind, sel.value, array_agg(DISTINCT e.registrable_domain) AS rds
               FROM selectors sel
               JOIN observations o ON o.selector_id = sel.id
               JOIN entities e ON e.id = o.entity_id
               WHERE sel.attributing AND e.registrable_domain IS NOT NULL
               GROUP BY sel.id
               HAVING count(DISTINCT e.registrable_domain) BETWEEN 2 AND %s""",
            (fanout,),
        ).fetchall():
            union_group(row["rds"], {"node_type": "selector", "kind": row["kind"], "value": row["value"]})

        for row in c.execute(
            """SELECT ip.value, array_agg(DISTINCT e.registrable_domain) AS rds
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
            union_group(row["rds"], {"node_type": "ip", "kind": "shared_ip", "value": row["value"]})

        components: dict[str, list[str]] = defaultdict(list)
        for rd in list(parent):
            components[find(rd)].append(rd)
        LOGGER.info(
            "rebuild_clusters: found %d connected component(s) over %d domain(s) (%.1fs elapsed)",
            len(components), len(parent), time.monotonic() - started,
        )

        now = datetime.now(timezone.utc).isoformat()
        # DELETE, not TRUNCATE, on every materialized graph table below: this
        # rebuild runs in one long transaction (the connection-scoring loop
        # further down is the slow part) and TRUNCATE takes an ACCESS EXCLUSIVE
        # lock held until commit, which blocks every concurrent /api/pool and
        # /api/graph/clusters read (they LEFT JOIN these tables) for the whole
        # rebuild — the frontend hangs with no data. DELETE takes only ROW
        # EXCLUSIVE, so readers keep seeing the previous snapshot under MVCC and
        # flip to the new one atomically on commit. Do not switch back to
        # TRUNCATE.
        c.execute("DELETE FROM graph_clusters")
        c.execute("DELETE FROM graph_cluster_links")
        cluster_count = 0
        clustered = 0
        cluster_rows: list[tuple[Any, ...]] = []
        for members in components.values():
            if len(members) < 2:
                continue
            cluster_count += 1
            cluster_id = min(members)
            size = len(members)
            for member in members:
                cluster_rows.append((member, cluster_id, size, now))
                clustered += 1
        if cluster_rows:
            c.cursor().executemany(
                """INSERT INTO graph_clusters (registrable_domain, cluster_id, component_size, computed_at)
                   VALUES (%s,%s,%s,%s)
                   ON CONFLICT (registrable_domain) DO UPDATE SET
                       cluster_id = EXCLUDED.cluster_id,
                       component_size = EXCLUDED.component_size,
                       computed_at = EXCLUDED.computed_at""",
                cluster_rows,
            )

        # Attribute each connector to its (single) cluster — all its members share a
        # union-find root — and record how many members it ties together.
        if connectors:
            c.cursor().executemany(
                """INSERT INTO graph_cluster_links
                       (cluster_id, node_type, kind, value, member_count, computed_at)
                   VALUES (%s,%s,%s,%s,%s,%s)""",
                [
                    (find(connector["members"][0]), connector["node_type"], connector["kind"],
                     connector["value"], len(connector["members"]), now)
                    for connector in connectors
                ],
            )

        # Pool-page "connections" count: the number of other registrable domains
        # this one has a *real* (scored) connection to — the same scoring engine
        # and min_score threshold as check.links_for, so this number always
        # matches what clicking into the domain shows. Deliberately NOT the raw
        # adjacency above (any shared attributing node within the clustering
        # fanout cap): that over-counts weak/common/CDN-fronted shared nodes
        # that the scorer would down-weight to nothing.
        from utils import check as _check

        all_rds = [
            row["registrable_domain"]
            for row in c.execute(
                "SELECT DISTINCT registrable_domain FROM entities WHERE registrable_domain IS NOT NULL"
            ).fetchall()
        ]
        c.execute("DELETE FROM graph_connection_counts")
        c.execute("DELETE FROM graph_links")
        connected_domains = 0
        # Each domain's own top-_PATH_FRONTIER_LIMIT-by-score links, captured
        # here (links_for already sorts by score desc) so _extend_paths below
        # can BFS entirely in memory instead of re-querying graph_links.
        adjacency: dict[str, list[dict]] = {}
        connection_count_rows: list[tuple[Any, ...]] = []
        graph_link_rows: list[tuple[Any, ...]] = []
        # check.links_for(rd) is a read-only round trip to Postgres on its own
        # short-lived connection (link_candidates_for/ip_network_context each
        # open their own via _conn() — never this function's `c`), so it never
        # touches the rebuild's own connection/transaction and is safe to fan
        # out across threads. This loop was previously sequential — one domain's
        # worth of query latency at a time — and is the slow part of a rebuild
        # on a large pool; scoring itself doesn't depend on ordering, only the
        # aggregation into adjacency/connection_count_rows/graph_link_rows below
        # does, so that part stays single-threaded and lock-free.
        total_rds = len(all_rds)
        workers = _rebuild_workers()
        LOGGER.info("rebuild_clusters: scoring connections for %d domain(s) with %d worker(s)", total_rds, workers)
        scoring_started = time.monotonic()
        # Capped at 500 (not just total // 20): on a large pool (tens of
        # thousands of domains) a pure percentage cadence means the first log
        # line can be a long wait even while work is genuinely progressing —
        # a heartbeat also fires on elapsed time so a slow patch (a few
        # unusually well-connected hub domains) still produces output instead
        # of going quiet for a whole percentage-point's worth of domains.
        log_every = max(1, min(total_rds // 20, 500))
        heartbeat_seconds = 10.0
        last_logged = scoring_started
        all_links_by_rd: dict[str, list[dict]] = {}
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="rebuild-score") as ex:
            future_to_rd = {ex.submit(_check.links_for, rd, limit=None): rd for rd in all_rds}
            completed = 0
            for fut in as_completed(future_to_rd):
                rd = future_to_rd[fut]
                all_links_by_rd[rd] = fut.result()
                completed += 1
                now_mono = time.monotonic()
                if (
                    completed % log_every == 0
                    or completed == total_rds
                    or now_mono - last_logged >= heartbeat_seconds
                ):
                    LOGGER.info(
                        "rebuild_clusters: scored %d/%d domains (%.1fs elapsed)",
                        completed, total_rds, now_mono - scoring_started,
                    )
                    last_logged = now_mono
        for rd in all_rds:
            # Unlimited so graph_links caches every scored connection this
            # domain has, not just a top page-worth — connections_among()
            # below needs the full set to answer "is member #47 of a 60-node
            # cluster linked to member #12", which a top-50 cut could miss.
            # `scored` still caps at check.links_for's own default (50) so the
            # pool-page count never drifts from what the domain's own detail
            # page (which does apply that cap) shows.
            all_links = all_links_by_rd[rd]
            scored = len(all_links[:50])
            connected_domains += 1 if scored else 0
            adjacency[rd] = all_links[:_PATH_FRONTIER_LIMIT]
            # Recorded unconditionally, even when scored is 0 — this table
            # doubles as the "rd has been through a rebuild pass" marker
            # cached_links_for() checks, not just a connection count.
            connection_count_rows.append((rd, scored, now))
            for link in all_links:
                graph_link_rows.append((
                    rd, link["target"], link["score"], link["confidence"], link["strength"],
                    link["shared_node_count"], _json(link["evidence"]), now,
                ))

        LOGGER.info(
            "rebuild_clusters: scoring done — %d connected domain(s), %d link(s) to insert (%.1fs)",
            connected_domains, len(graph_link_rows), time.monotonic() - scoring_started,
        )
        # Batched with executemany (psycopg3 pipelines these) instead of one
        # INSERT per row — this loop's row count is every domain (connection
        # counts) and every scored edge (graph_links), which for a large
        # correlation graph is thousands of individual round-trips otherwise.
        if connection_count_rows:
            c.cursor().executemany(
                """INSERT INTO graph_connection_counts (registrable_domain, connection_count, computed_at)
                   VALUES (%s,%s,%s)""",
                connection_count_rows,
            )
        if graph_link_rows:
            c.cursor().executemany(
                """INSERT INTO graph_links
                       (registrable_domain, target, score, confidence, strength,
                        shared_node_count, evidence, computed_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                graph_link_rows,
            )

        LOGGER.info("rebuild_clusters: computing multi-hop paths (up to %d hops)", _graph_path_max_hops())
        paths_started = time.monotonic()
        _extend_paths(c, adjacency, all_rds, now)
        LOGGER.info("rebuild_clusters: multi-hop paths done (%.1fs)", time.monotonic() - paths_started)

        # "Browse by shared edge" groups — same source edges as clustering above,
        # but unbounded by the clustering fanout cap: this is enumeration for
        # browsing, not graph unioning, so a wide-fanout shared IP still shows up.
        LOGGER.info("rebuild_clusters: computing shared-edge browse groups")
        c.execute("DELETE FROM graph_selector_groups")
        selector_group_rows: list[tuple[Any, ...]] = [
            (row["kind"], row["value"], row["degree"], row["domains"], now)
            for row in c.execute(
                """SELECT sel.kind, sel.value, sel.entity_count AS degree,
                          array_agg(DISTINCT e.registrable_domain) AS domains
                   FROM selectors sel
                   JOIN observations o ON o.selector_id = sel.id
                   JOIN entities e ON e.id = o.entity_id
                   WHERE sel.attributing AND e.registrable_domain IS NOT NULL
                   GROUP BY sel.id, sel.kind, sel.value, sel.entity_count
                   HAVING count(DISTINCT e.registrable_domain) >= 2"""
            ).fetchall()
        ]
        for row in c.execute(
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
               HAVING count(DISTINCT e.registrable_domain) >= 2"""
        ).fetchall():
            selector_group_rows.append((row["kind"], row["value"], row["degree"], row["domains"], now))
        if selector_group_rows:
            c.cursor().executemany(
                """INSERT INTO graph_selector_groups (kind, value, degree, domains, computed_at)
                   VALUES (%s,%s,%s,%s,%s)""",
                selector_group_rows,
            )

        _mark_clusters_clean(c, covered)
    _notify_graph_invalidation("all")
    LOGGER.info(
        "rebuild_clusters: done in %.1fs — %d cluster(s), %d clustered domain(s), %d connected domain(s)",
        time.monotonic() - started, cluster_count, clustered, connected_domains,
    )
    return {"clusters": cluster_count, "clustered_domains": clustered, "connected_domains": connected_domains}


def cached_links_for(value: str) -> list[dict[str, Any]] | None:
    """`value`'s precomputed scored connections (see rebuild_clusters), or
    None if it hasn't been through a rebuild pass yet (e.g. ingested in the
    last _CLUSTER_REBUILD_INTERVAL seconds) — the caller should fall back to
    a live check.links_for() in that case rather than reading None-as-empty
    and reporting a brand-new domain as having no connections.

    Presence of a graph_connection_counts row (rebuild_clusters inserts one
    for every domain it processes, even at connection_count=0) is what marks
    "computed"; graph_links itself is legitimately empty for a domain with no
    connections, so it can't be used as that marker on its own.
    """
    init_db()
    side = _resolve_side(value)
    if not side:
        return None
    rd = side[1]
    with _conn() as c:
        marker = c.execute(
            "SELECT 1 FROM graph_connection_counts WHERE registrable_domain = %s", (rd,)
        ).fetchone()
        if marker is None:
            return None
        rows = c.execute(
            """SELECT target, score, confidence, strength, shared_node_count, evidence
               FROM graph_links WHERE registrable_domain = %s ORDER BY score DESC""",
            (rd,),
        ).fetchall()
    return [
        {
            "target": row["target"],
            "registrable_domain": row["target"],
            "score": float(row["score"]),
            "confidence": row["confidence"],
            "strength": row["strength"],
            "shared_node_count": row["shared_node_count"],
            "evidence": row["evidence"],
        }
        for row in rows
    ]


def path_between(a_value: str, b_value: str) -> dict[str, Any] | None:
    """Precomputed multi-hop chain from a to b (see graph_paths / _extend_paths,
    populated by rebuild_clusters) — an indexed read, never a live traversal.
    None if either side isn't a domain, they're the same domain, or nothing
    reaches within _graph_path_max_hops()."""
    init_db()
    side_a = _resolve_side(a_value)
    side_b = _resolve_side(b_value)
    if not side_a or not side_b or side_a[0] != "rd" or side_b[0] != "rd":
        return None
    a_rd, b_rd = side_a[1], side_b[1]
    if a_rd == b_rd:
        return None
    with _conn() as c:
        row = c.execute(
            "SELECT hops, chain FROM graph_paths WHERE registrable_domain = %s AND target = %s",
            (a_rd, b_rd),
        ).fetchone()
        flipped = False
        if row is None:
            # _extend_paths' BFS is seeded per-source from that domain's own
            # top-_PATH_FRONTIER_LIMIT links and capped at GRAPH_PATH_MAX_NODES
            # visited nodes, so graph_paths is NOT guaranteed symmetric: b may
            # discover a within its own frontier/cap even when a's BFS never
            # reached b (or vice versa). Check the reverse row before giving up
            # — a real, precomputed path shouldn't read as "none" just because
            # of which side's BFS happened to surface it.
            row = c.execute(
                "SELECT hops, chain FROM graph_paths WHERE registrable_domain = %s AND target = %s",
                (b_rd, a_rd),
            ).fetchone()
            flipped = True
    if row is None:
        return None
    chain = row["chain"]
    if flipped:
        chain = [{**hop, "from": hop["to"], "to": hop["from"]} for hop in reversed(chain)]
    return {"a": a_rd, "b": b_rd, "hops": row["hops"], "chain": chain}


def related_through(value: str, *, max_hops: int | None = None, limit: int = 50) -> list[dict[str, Any]]:
    """A domain's precomputed multi-hop neighborhood (graph_paths), shortest
    chains first, then strongest weakest-hop. graph_paths is a strict superset
    of graph_links (direct/1-hop connections are included, not just 2+-hop
    ones), so this is a drop-in replacement for a live pool_links expansion."""
    init_db()
    side = _resolve_side(value)
    if not side or side[0] != "rd":
        return []
    rd = side[1]
    with _conn() as c:
        if max_hops is not None:
            rows = c.execute(
                """SELECT target, hops, min_hop_score, chain FROM graph_paths
                   WHERE registrable_domain = %s AND hops <= %s
                   ORDER BY hops, min_hop_score DESC LIMIT %s""",
                (rd, max_hops, limit),
            ).fetchall()
        else:
            rows = c.execute(
                """SELECT target, hops, min_hop_score, chain FROM graph_paths
                   WHERE registrable_domain = %s
                   ORDER BY hops, min_hop_score DESC LIMIT %s""",
                (rd, limit),
            ).fetchall()
    return [
        {
            "target": row["target"],
            "hops": row["hops"],
            "min_hop_score": float(row["min_hop_score"]),
            "chain": row["chain"],
        }
        for row in rows
    ]


def search_targets(query: str, *, limit: int = 20) -> dict[str, Any]:
    """Ranked domain + selector-value matches for a global search box. Reads
    only materialized tables (entities/graph_connection_counts/graph_clusters/
    graph_selector_groups) — a substring lookup, unrelated to the multi-hop
    precompute above, so it never needs a rebuild pass to be accurate."""
    init_db()
    needle = str(query or "").strip().lower()
    if not needle:
        return {"query": query, "domains": [], "selectors": []}
    like = f"%{needle}%"
    prefix = f"{needle}%"
    with _conn() as c:
        domain_rows = c.execute(
            """WITH pool AS (SELECT DISTINCT registrable_domain FROM entities WHERE registrable_domain IS NOT NULL)
               SELECT p.registrable_domain AS domain,
                      COALESCE(gcc.connection_count, 0) AS connection_count,
                      gc.cluster_id
               FROM pool p
               LEFT JOIN graph_connection_counts gcc ON gcc.registrable_domain = p.registrable_domain
               LEFT JOIN graph_clusters gc ON gc.registrable_domain = p.registrable_domain
               WHERE p.registrable_domain ILIKE %s
               ORDER BY (p.registrable_domain ILIKE %s) DESC, connection_count DESC, p.registrable_domain
               LIMIT %s""",
            (like, prefix, limit),
        ).fetchall()
        selector_rows = c.execute(
            """SELECT kind, value, degree, domains FROM graph_selector_groups
               WHERE value ILIKE %s
               ORDER BY (value ILIKE %s) DESC, degree DESC, value
               LIMIT %s""",
            (like, prefix, limit),
        ).fetchall()
    domains = [
        {"domain": row["domain"], "connection_count": row["connection_count"], "cluster_id": row["cluster_id"]}
        for row in domain_rows
    ]
    tiers = get_domain_tiers([entry["domain"] for entry in domains])
    for entry in domains:
        entry["tier"] = tiers.get(entry["domain"])
    selectors = [
        {
            "kind": row["kind"],
            "value": row["value"],
            "domain_count": row["degree"],
            "sample_domains": list(row["domains"] or [])[:5],
        }
        for row in selector_rows
    ]
    return {"query": query, "domains": domains, "selectors": selectors}


# Most connectors of interest per cluster in the list view; the detail lookup
# returns all of them.
_CLUSTER_LINKS_PREVIEW = 8


def _cluster_links(c, cluster_ids: list[str], per_cluster: int | None) -> dict[str, list[dict[str, Any]]]:
    """The shared nodes tying each of `cluster_ids` together, strongest first.

    Strength here is how many members a node connects (member_count), so the node
    holding the cluster together leads. `per_cluster` caps each cluster's list;
    None returns all.
    """
    if not cluster_ids:
        return {}
    rows = c.execute(
        """SELECT cluster_id, node_type, kind, value, member_count
           FROM graph_cluster_links
           WHERE cluster_id = ANY(%s)
           ORDER BY member_count DESC, node_type, kind, value""",
        (list(cluster_ids),),
    ).fetchall()
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        bucket = out[row["cluster_id"]]
        if per_cluster is None or len(bucket) < per_cluster:
            bucket.append({k: row[k] for k in ("node_type", "kind", "value", "member_count")})
    return out


def list_graph_clusters(*, min_size: int = 2, limit: int = 100) -> list[dict[str, Any]]:
    """Strongest clusters lake-wide (largest first), each with the shared nodes
    that tie it together (a preview of the strongest connectors)."""
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
        clusters = [dict(row) for row in rows]
        links = _cluster_links(c, [cl["cluster_id"] for cl in clusters], _CLUSTER_LINKS_PREVIEW)
        counts = {
            r["cluster_id"]: r["n"]
            for r in c.execute(
                """SELECT cluster_id, count(*) AS n FROM graph_cluster_links
                   WHERE cluster_id = ANY(%s) GROUP BY cluster_id""",
                ([cl["cluster_id"] for cl in clusters],),
            ).fetchall()
        } if clusters else {}
    for cluster in clusters:
        cluster["links"] = links.get(cluster["cluster_id"], [])
        cluster["link_count"] = counts.get(cluster["cluster_id"], len(cluster["links"]))
    return clusters


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
        links = _cluster_links(c, [row["cluster_id"]], None).get(row["cluster_id"], [])
    return {
        "cluster_id": row["cluster_id"],
        "component_size": row["component_size"],
        "members": members,
        "links": links,
        "link_count": len(links),
    }


# ── Pool + by-edge browsing ─────────────────────────────────────────────────
#
# The product is one global pool of channels (registrable domains). These power
# the pool listing and the "browse by edge type" discovery mode (filter by a
# selector kind — shared TLS cert / SSH fp / shared IP / nameserver / … — and
# see which domains carry that connection).

def list_pool_domains(
    *,
    search: str | None = None,
    limit: int = 1000,
    offset: int = 0,
    provenance: str | None = None,
    sort: str = "recent",
    min_connections: int | None = None,
    max_connections: int | None = None,
    ingested_after: str | None = None,
    ingested_before: str | None = None,
    discovered_after: str | None = None,
    discovered_before: str | None = None,
    include_total: bool = False,
) -> list[dict[str, Any]] | dict[str, Any]:
    """Every registrable domain in the pool with host count, recency, cluster,
    direct pairwise connection count, and whether it was directly submitted
    (`ingested`) vs. only ever surfaced as a scan follow-up (subdomain/sibling/
    wordlist discovery).

    `connection_count` is the pool-page "connections" number: distinct other
    domains this one directly shares an attributing selector or IP with (see
    graph_connection_counts / rebuild_clusters) — not the transitive cluster
    size, which is a separate, larger-scope concept shown on the clusters page.

    `discovered_at` is when this domain first appeared in the pool at all
    (earliest entity first_seen); `ingested_at` is when it (or a subdomain of
    it) was first directly submitted, if ever.

    `scan_count` is how many times anything under the domain has been scanned
    and `last_scanned_at` when that last happened. Both are display-only: no
    code path caps, skips or gates work on them. Scans are only startable from
    the backend, so the number is a record of what was run, not a budget.

    `discovery_kind`/`discovery_reason`/`discovered_from` explain *how* a
    never-ingested domain entered the pool (subdomain enumeration, sibling
    discovery, wordlist hit, ...) and, where known, which other channel led to
    it — taken from the apex entity's most recent search, so they're only
    meaningful when `ingested` is false.
    """
    init_db()
    like = f"%{search.strip().lower()}%" if search and search.strip() else None
    safe_limit = max(1, min(int(limit or 1000), 5000))
    safe_offset = max(0, int(offset or 0))
    provenance_key = provenance if provenance in {"ingested", "discovered"} else "all"
    sort_key = sort if sort in {"recent", "connections", "domain"} else "recent"
    order_by = {
        "connections": "connection_count DESC NULLS LAST, last_seen DESC NULLS LAST, domain",
        "domain": "domain ASC",
        "recent": "last_seen DESC NULLS LAST, domain",
    }[sort_key]

    base_sql = """
        WITH pool AS (
            SELECT e.registrable_domain AS domain,
                   count(DISTINCT e.id) AS host_count,
                   max(e.last_seen) AS last_seen,
                   min(e.first_seen) AS discovered_at,
                   gc.cluster_id,
                   gc.component_size AS cluster_size,
                   COALESCE(gcc.connection_count, 0) AS connection_count,
                   -- How many times anything under this registrable domain has
                   -- been scanned. Purely informational: it is displayed in the
                   -- frontend and gates nothing. Derived from the `searches`
                   -- join already present for `ingested`, so it needs no table
                   -- of its own and stays correct for free.
                   count(DISTINCT s.id) AS scan_count,
                   max(s.timestamp) AS last_scanned_at,
                   COALESCE(bool_or(sf.json_value = 'true'::jsonb), FALSE) AS ingested,
                   min(s.timestamp) FILTER (WHERE sf.json_value = 'true'::jsonb) AS ingested_at,
                   (SELECT sf2.json_value #>> '{}' FROM searches apex_s
                      JOIN search_fields sf2 ON sf2.search_id = apex_s.id AND sf2.key = 'discovery_kind'
                      WHERE apex_s.target = e.registrable_domain
                      ORDER BY apex_s.timestamp DESC, apex_s.id DESC LIMIT 1) AS discovery_kind,
                   (SELECT sf2.json_value #>> '{}' FROM searches apex_s
                      JOIN search_fields sf2 ON sf2.search_id = apex_s.id AND sf2.key = 'discovery_reason'
                      WHERE apex_s.target = e.registrable_domain
                      ORDER BY apex_s.timestamp DESC, apex_s.id DESC LIMIT 1) AS discovery_reason,
                   (SELECT sf2.json_value #>> '{}' FROM searches apex_s
                      JOIN search_fields sf2 ON sf2.search_id = apex_s.id AND sf2.key = 'discovered_from'
                      WHERE apex_s.target = e.registrable_domain
                      ORDER BY apex_s.timestamp DESC, apex_s.id DESC LIMIT 1) AS discovered_from,
                   dt.tier AS tier
            FROM entities e
            LEFT JOIN graph_clusters gc ON gc.registrable_domain = e.registrable_domain
            LEFT JOIN graph_connection_counts gcc ON gcc.registrable_domain = e.registrable_domain
            LEFT JOIN searches s ON s.target = e.value
            LEFT JOIN search_fields sf ON sf.search_id = s.id AND sf.key = 'is_seed'
            LEFT JOIN domain_tiers dt ON dt.registrable_domain = e.registrable_domain
            WHERE e.registrable_domain IS NOT NULL
              AND (%s::text IS NULL OR e.registrable_domain LIKE %s::text)
            GROUP BY e.registrable_domain, gc.cluster_id, gc.component_size, gcc.connection_count, dt.tier
            HAVING (%s::int IS NULL OR COALESCE(gcc.connection_count, 0) >= %s::int)
               AND (%s::int IS NULL OR COALESCE(gcc.connection_count, 0) <= %s::int)
               AND (%s::text IS NULL OR min(e.first_seen) >= %s::text)
               AND (%s::text IS NULL OR min(e.first_seen) <= %s::text)
               AND (%s::text IS NULL OR min(s.timestamp) FILTER (WHERE sf.json_value = 'true'::jsonb) >= %s::text)
               AND (%s::text IS NULL OR min(s.timestamp) FILTER (WHERE sf.json_value = 'true'::jsonb) <= %s::text)
        )
        SELECT *
        FROM pool
        WHERE (%s::text = 'all')
           OR (%s::text = 'ingested' AND ingested)
           OR (%s::text = 'discovered' AND NOT ingested)
    """
    params = (
        like, like,
        min_connections, min_connections,
        max_connections, max_connections,
        discovered_after, discovered_after,
        discovered_before, discovered_before,
        ingested_after, ingested_after,
        ingested_before, ingested_before,
        provenance_key, provenance_key, provenance_key,
    )

    with _conn() as c:
        total = c.execute(f"SELECT count(*) AS n FROM ({base_sql}) filtered", params).fetchone()["n"]
        rows = c.execute(
            f"{base_sql} ORDER BY {order_by} LIMIT %s OFFSET %s",
            (*params, safe_limit, safe_offset),
        ).fetchall()

    domains = [dict(row) for row in rows]
    if include_total:
        return {"total": int(total), "domains": domains, "offset": safe_offset, "limit": safe_limit}
    return domains


def _curate_intel(result: dict[str, Any]) -> dict[str, Any]:
    """A safe, compact view of the raw gathered intel for one search result.

    Tolerates the shape drift in historical payloads (fields that are lists where
    a dict is expected) so it never throws on legacy data.
    """
    def as_dict(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    return item
        return {}

    page = as_dict(result.get("page_metadata"))
    tracking: dict[str, Any] = {}
    for key in ("google_analytics", "ga_ids", "gtm_ids", "facebook_pixel", "tiktok_pixel",
                "yandex_metrika", "adsense_publisher_ids", "fb_app_id"):
        value = page.get(key)
        if value:
            tracking[key] = value

    certs: list[dict[str, Any]] = []
    raw_certs = list(result.get("non_cf_tls_certs") or [])
    if isinstance(result.get("tls_cert"), dict):
        raw_certs.append(result["tls_cert"])
    raw_certs.extend(as_dict(result.get("tls_certs")).get("probes") or [])
    for cert in raw_certs:
        if isinstance(cert, dict) and not cert.get("error"):
            certs.append({
                "ip": cert.get("ip"),
                "cn": cert.get("cn"),
                "sans": cert.get("sans") or [],
                "sha256": cert.get("sha256") or cert.get("fingerprint_sha256"),
                "issuer": cert.get("issuer_cn") or cert.get("issuer") or cert.get("issuer_org"),
                "not_before": cert.get("not_before"),
                "not_after": cert.get("not_after"),
            })

    site_verifications, social_handles_all = _meta_tag_site_signals(page)
    phone_numbers, crypto_wallets = _payment_contact_signals(page)
    return {
        "search_id": result.get("search_id"),
        "timestamp": result.get("timestamp"),
        "dns": as_dict(result.get("dns")),
        "whois": as_dict(result.get("whois")),
        "subdomains": _normalize_text_list(result.get("subdomains") or []),
        "tls_certs": certs,
        "tracking": tracking,
        "favicon": page.get("favicon_mmh3") or page.get("favicon_md5"),
        "email_security": as_dict(result.get("email_security")),
        "resolved_ips": list(normalize_ip_details(result.get("ip_details")).keys()),
        "social_handles": social_handles_all,
        "social_links": as_dict(page.get("social_links")),
        "site_verifications": site_verifications,
        "phone_numbers": phone_numbers,
        "crypto_wallets": crypto_wallets,
        "opencti_labels": _normalize_text_list(result.get("opencti_labels")),
        # How this specific target's latest scan came to run: directly
        # submitted (is_seed) vs. queued as a follow-up from another target
        # (discovery_kind/discovery_reason/discovered_from) — see
        # core/analysis_service.py:analyze_target.
        "is_seed": bool(result.get("is_seed")),
        "discovery_kind": result.get("discovery_kind"),
        "discovery_reason": result.get("discovery_reason"),
        "discovered_from": result.get("discovered_from"),
    }


def domain_profile(value: str) -> dict[str, Any] | None:
    """Everything known about one channel: its hosts, the selectors we extracted,
    the IPs it resolves to, and a compact view of the raw gathered intel —
    independent of whether it has any connections."""
    init_db()
    side = _resolve_side(value)
    if not side:
        return None
    mode, key, _ = side
    with _conn() as c:
        if mode == "rd":
            host_filter = ("e.registrable_domain = %s", (key,))
            hosts = [dict(r) for r in c.execute(
                """SELECT e.value, e.kind, e.first_seen, e.last_seen,
                          COALESCE(array_agg(DISTINCT ip.value) FILTER (WHERE ip.value IS NOT NULL), '{}') AS ips,
                          COALESCE(prov.is_seed, FALSE) AS ingested,
                          prov.discovery_kind, prov.discovery_reason, prov.discovered_from
                   FROM entities e
                   LEFT JOIN entity_edges ee ON ee.src_entity_id = e.id AND ee.kind = 'resolves_to'
                   LEFT JOIN entities ip ON ip.id = ee.dst_entity_id AND ip.kind = 'ip'
                   LEFT JOIN LATERAL (
                       SELECT
                           EXISTS (
                               SELECT 1 FROM searches s2
                               JOIN search_fields sf2 ON sf2.search_id = s2.id AND sf2.key = 'is_seed'
                               WHERE s2.target = e.value AND sf2.json_value = 'true'::jsonb
                           ) AS is_seed,
                           (SELECT sf.json_value #>> '{}' FROM search_fields sf
                              WHERE sf.search_id = ls.id AND sf.key = 'discovery_kind') AS discovery_kind,
                           (SELECT sf.json_value #>> '{}' FROM search_fields sf
                              WHERE sf.search_id = ls.id AND sf.key = 'discovery_reason') AS discovery_reason,
                           (SELECT sf.json_value #>> '{}' FROM search_fields sf
                              WHERE sf.search_id = ls.id AND sf.key = 'discovered_from') AS discovered_from
                       FROM (
                           SELECT id FROM searches WHERE target = e.value
                           ORDER BY timestamp DESC, id DESC LIMIT 1
                       ) ls
                   ) prov ON TRUE
                   WHERE e.registrable_domain = %s
                   GROUP BY e.id, e.value, e.kind, e.first_seen, e.last_seen,
                            prov.is_seed, prov.discovery_kind, prov.discovery_reason, prov.discovered_from
                   ORDER BY (e.kind='domain') DESC, e.value""",
                (key,),
            ).fetchall()]
            ips = [dict(r) for r in c.execute(
                """SELECT ip.value AS ip,
                          (SELECT count(DISTINCT e2.registrable_domain)
                             FROM entity_edges x JOIN entities e2 ON e2.id = x.src_entity_id
                             WHERE x.dst_entity_id = ip.id AND x.kind = 'resolves_to') AS degree,
                          array_agg(DISTINCT src.value) AS hosts
                   FROM entity_edges ee
                   JOIN entities ip ON ip.id = ee.dst_entity_id AND ip.kind = 'ip'
                   JOIN entities src ON src.id = ee.src_entity_id
                   WHERE ee.kind = 'resolves_to' AND src.registrable_domain = %s
                   GROUP BY ip.id, ip.value ORDER BY ip.value""",
                (key,),
            ).fetchall()]
        else:
            host_filter = ("e.kind = 'ip' AND e.value = %s", (key,))
            hosts = [dict(r) for r in c.execute(
                "SELECT value, kind, first_seen, last_seen FROM entities WHERE kind = 'ip' AND value = %s",
                (key,),
            ).fetchall()]
            ips = []

        if ips:
            from utils.check import describe_ip_network

            context = ip_network_context([row["ip"] for row in ips])
            for row in ips:
                meta = context.get(row["ip"]) or {}
                row["cloudflare"] = bool(meta.get("cloudflare"))
                row["asn"] = meta.get("asn")
                row["asn_desc"] = meta.get("asn_desc")
                row["network_name"] = meta.get("network_name")
                row["network_cidr"] = meta.get("network_cidr")
                row["proxy_family"] = meta.get("proxy_family")
                row["proxy_confidence"] = meta.get("proxy_confidence")
                row["country"] = meta.get("country")
                row["ptr"] = meta.get("ptr")
                described = describe_ip_network(row["ip"], row["degree"], meta)
                row["network"] = described["network"]
                row["explanation"] = described["explanation"]

        selectors = [dict(r) for r in c.execute(
            f"""SELECT s.kind, s.value, s.entity_count AS degree, s.attributing
                FROM selectors s
                JOIN observations o ON o.selector_id = s.id
                JOIN entities e ON e.id = o.entity_id
                WHERE {host_filter[0]}
                GROUP BY s.id, s.kind, s.value, s.entity_count, s.attributing
                ORDER BY s.attributing DESC, s.kind, s.entity_count""",
            host_filter[1],
        ).fetchall()]

    intel = None
    sid = get_latest_search_id_for_target(key)
    if sid is not None:
        result = get_result(sid)
        if result:
            intel = _curate_intel(result)

    if not hosts and intel is None:
        return None
    return {
        "target": value,
        "domain": key,
        "kind": mode,
        "hosts": hosts,
        "host_count": len(hosts),
        # True when this channel (or any of its subdomains) was directly
        # submitted at some point, rather than only ever surfacing as a scan
        # follow-up (subdomain enumeration, sibling discovery, wordlist hit).
        "ingested": any(host.get("ingested") for host in hosts),
        "ips": ips,
        "selectors": selectors,
        "intel": intel,
        "tier": get_domain_tier(key) if mode == "rd" else None,
    }


def selector_kind_counts(*, min_domains: int = 2) -> list[dict[str, Any]]:
    """Edge types available for browsing: each selector kind (+ shared_ip) with
    the number of cross-domain groups it forms. Reads the materialized
    graph_selector_groups table (rebuilt alongside graph_clusters — see
    rebuild_clusters), so this is a cheap indexed lookup, not a live join over
    the whole lake."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT kind, count(*) AS groups
               FROM graph_selector_groups
               WHERE degree >= %s
               GROUP BY kind
               ORDER BY groups DESC""",
            (min_domains,),
        ).fetchall()
    return [dict(row) for row in rows]


def domains_by_selector(
    *, kind: str | None = None, min_domains: int = 2, limit: int = 200
) -> list[dict[str, Any]]:
    """Groups of registrable domains that share an attributing selector (or a
    non-noise shared IP when kind='shared_ip'), strongest fan-in first. Reads
    the materialized graph_selector_groups table — see rebuild_clusters."""
    init_db()
    with _conn() as c:
        rows = c.execute(
            """SELECT kind, value, degree, domains
               FROM graph_selector_groups
               WHERE degree >= %s AND (%s::text IS NULL OR kind = %s::text)
               ORDER BY degree DESC, kind, value
               LIMIT %s""",
            (min_domains, kind, kind, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def domains_for_selector_value(kind: str, value: str, limit: int = 10) -> list[str]:
    """Domains sharing one specific (kind, value) selector — e.g. every domain
    behind a given favicon hash — via the same materialized table as
    domains_by_selector. Used to pick candidate domains to re-fetch a favicon
    image from, since we only ever store the hash, not the icon bytes."""
    init_db()
    with _conn() as c:
        row = c.execute(
            "SELECT domains FROM graph_selector_groups WHERE kind = %s AND value = %s",
            (kind, value),
        ).fetchone()
    domains = list(row["domains"] or []) if row else []
    return domains[:limit]


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


def existing_search_targets(targets: list[str]) -> set[str]:
    """Return the subset of `targets` that already have at least one search row.

    Lets the OpenCTI sweep skip re-scanning channels already in the pool with a
    single indexed query instead of one lookup per domain. Matches on the exact
    stored ``target`` (the normalized_target each search was saved under), so
    callers should pass already-normalized values (clean_target output).
    """
    init_db()
    if not targets:
        return set()
    with _conn() as c:
        rows = c.execute(
            "SELECT DISTINCT target FROM searches WHERE target = ANY(%s)",
            (list(targets),),
        ).fetchall()
    return {row["target"] for row in rows}


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

# Every ASN below is confirmed against RIPEstat's as-overview (holder name in
# parens) — see "Where the CDN / proxy / shared-hosting reference data comes
# from" in the README for the audit that found (and fixed) three wrong
# entries here: 394161 was Tesla Motors, not Google Workspace mail; 60626 was
# LeaseWeb (real dedicated hosting), not Bunny CDN; 61493/2025 were BAEHOST
# and the University of Toledo, not Tumblr. All were silently misclassifying
# real infrastructure as noise (or noise as real) since whichever commit
# first typed them in — verify before adding, don't trust the label.
_MAIL_ASNS = {"15169", "16276", "8075", "3215"}  # Google, OVH, Microsoft, Orange
# Cross-checked against config/provider_asns.json's curated `edge_and_cdn_noise`
# focus set (13335 Cloudflare, 54113 Fastly, 16625/20940 Akamai, 199524
# Gcore/EdgeCenter, 200325 Bunny CDN) plus additional edge/anti-DDoS operators:
# DDoS-Guard (57724, "DDOS-GUARD LTD"), Voxility (3223, "Voxility LLP"),
# Limelight/Edgio LATAM (23059, "LLNW-LATAM"), Myra Security (41179,
# "MYRASEC-AS"), Path Network anti-DDoS (30644/39967/396998, "PATH-NETWORK").
_CDN_PROXY_ASNS = {
    "13335", "19551", "54113", "20940", "200325", "394536", "22822", "16625",
    "199524", "57724", "3223", "23059", "41179",
    "30644", "39967", "396998",
}
# Automattic (WordPress.com), Weebly, Tumblr (Yahoo Holdings runs two ASNs for
# it: 32345 "TUMBLR-CORP" and 33612 "TUMBLR").
_SHARED_HOSTING_ASNS = {"2635", "27647", "32345", "33612"}

_MAIL_PTR_PATTERNS = ("1e100.net", "google.com", "mail.ovh.", "smtp.", "mx.", "-mx-", "mail-", "mailout", "mxbiz")
_CDN_PROXY_PTR_PATTERNS = (
    "incapsula.com", "cloudflare.com", "cloudflare.net", "fastly.net",
    "akamai.net", "akamaiedge.net", "akamaized.net", "edgecast.net",
    "sucuri.net", "imperva.com", "cdn.", "cloudfront.net", "azurefd.net",
    "googleusercontent.com", "googlehosted.com", "b-cdn.net", "edgekey.net",
    "edgesuite.net", "trafficmanager.net", "myshopify.com", "pantheonsite.io",
    "webflow.io", "wixsite.com", "wpenginepowered.com",
    # Additional edge/CDN and anti-DDoS scrubbing providers (regional CDNs and
    # DDoS-mitigation reverse proxies that hand the same edge IP to many
    # unrelated customers, same as the majors above) — same set backing the
    # _CDN_PROXY_ASNS additions above.
    "gcore.com", "gcorelabs.com", "ddos-guard.net", "llnw.net",
    "stackpathdns.com", "stackpathcdn.com", "keycdn.com", "cdn77.org",
    "myracloud.com", "pathnetwork.net",
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
            if email in _GENERIC_EMAILS or _is_redacted_whois_value(email):
                continue
            emails.append({"email": email, "shared_with": _others_by("registrant_emails", "email", email)})

        registrant_names = []
        for row in c.execute("SELECT name FROM registrant_names WHERE search_id = %s", (current_sid,)).fetchall():
            name = row["name"]
            if _is_redacted_whois_value(name):
                continue
            registrant_names.append({"name": name, "shared_with": _others_by("registrant_names", "name", name)})

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
                "registrant_names": registrant_names,
                "nameservers": nameservers,
                "identifiers": identifiers,
                "discovered_domains": discovered_domains,
                "discovered_ips": discovered_ips,
            },
            "social": social,
        }
