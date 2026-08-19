# IP Intel

React + FastAPI application for domain and IP OSINT, origin discovery, and infrastructure correlation.

## Highlights

- Everything lives in **one global pool**: ingest a domain, an IP, or a CSV and it joins a single correlation graph — there are no cases or per-submission scoping. Correlation is always lake-wide.
- The **connections explorer** lets you select N channels to see whether they are connected to each other and to the wider pool, or browse the pool **by edge type** (shared TLS cert, SSH key, IP, nameserver, tracking ID…) to find every channel that carries a given connection.
- Jobs stream live progress (stage, percent, current target, logs) through the polling API and UI while an ingest scans.
- Raw intel storage is append-only, so multiple runs of the same target are preserved instead of overwritten.
- TLS relationships are time-aware: the app can distinguish shared certificates that are still current from ones only seen historically.
- Discovered IPs from DNS, provider hits, and scan hits all flow into the same enrichment path and connection logic.
- IP enrichment keeps richer network context: ASN registry, network name, network CIDR, reverse-proxy family, and proxy confidence. [ipinfo.io Lite](https://ipinfo.io/lite) (`utils/ipinfo_lite.py`) is the primary source for ASN/org/country — it's a single fast endpoint that rarely times out — with RDAP (`get_ip_whois`) supplementing the network name/CIDR detail ipinfo Lite's response doesn't carry, and standing in as the sole source when `IP_INFO_KEY` isn't configured or ipinfo Lite errors.
- Shared-infrastructure pivots include ASN clustering in addition to shared IPs, tracking IDs, favicons, and TLS.
- WHOIS capture keeps every field the registry exposes (registrant/admin/tech name, org, address, ... plus the full raw response), not just a summary subset — registrant name and email are both usable as cross-domain correlation signals, with privacy/proxy-service placeholder values (`REDACTED FOR PRIVACY`, `WhoisGuard`, etc.) filtered out so two unrelated domains never "connect" just because both are redacted the same way.
- OpenCTI website Channels can carry a **tier-1..tier-5** classification label. It's stored as a durable, per-domain attribute (`domain_tiers`, keyed on the registrable domain — survives rescans) and colours the node in the network graph, the pool listing, and the domain page heading.
- Provider integrations are handled conservatively for free/basic accounts instead of assuming paid certificate-history features are available.

## Project Layout

| File | Purpose |
|---|---|
| `app.py` | Entry point — re-exports the FastAPI `app` from `cases/case_app.py` |
| `cases/case_app.py` | FastAPI routes (pool, ingest, connections, jobs), static frontend serving, CORS |
| `cases/case_runtime.py` | Ingest/job orchestration and background workers (internal; no longer user-facing "cases") |
| `cases/case_store.py` | PostgreSQL schema/queries for the internal ingest jobs (legacy cases/pairs/clusters tables retained, unused by the UI) |
| `core/analysis_service.py` | Per-target analysis runner, bridges the ingest layer and `core/basic.py`'s engine |
| `core/basic.py` | Core intelligence engine (`analyze()`) — the pipeline every ingest actually runs |
| `core/ip_intel.py` | Separate CLI tool with its own async pipeline (GCP/ASN/country origin scanning via `masscan`/RIPE Stat). Not invoked by the web app's ingest path; `analysis_service.py` only reuses a handful of its standalone helper functions (subdomain/MX/wordlist origin probes, nameserver classification) |
| `db/intel_db.py` | PostgreSQL schema, persistence, and history for raw intel runs |
| `scripts/migrate_sqlite_to_postgres.py` | One-off migration of a legacy SQLite intel database into PostgreSQL |
| `scripts/backfill_correlation.py` | Rebuild the derived correlation graph (entities/selectors/observations/edges/clusters) from all stored intel |
| `scripts/ingest_opencti_channels.py` | Docker-command-triggered sweep of *every* OpenCTI website Channel through the full ingestion pipeline, tier-1..tier-5 classification included (see [OpenCTI Ingestion](#opencti-ingestion)) |
| `sources/signal_dns.py` | DNS and email-security signals (SPF, DKIM, DMARC, MX) |
| `sources/signal_transport.py` | TLS and SSH certificate parsing |
| `sources/signal_web.py` | Web page metadata extraction (favicons, tracking IDs, headers) |
| `utils/check.py` | Pairwise comparison logic + global graph linkage scoring (`link_evidence`, `links_for`) |
| `utils/cluster.py` | Legacy cluster-graph rendering helpers (global clustering is materialized in `db/intel_db.py`) |
| `utils/evidence_meta.py` | Evidence type catalog + per-selector base weights and strength tiers |
| `utils/ipinfo_lite.py` | ipinfo.io Lite client — primary ASN/geo source (free and uncapped; RDAP supplements CIDR/network-name detail and is the fallback when no key is set) and edge/reverse-proxy classification input |
| `utils/censys_enrichment.py` | Censys host-enrichment client — 0 credits but capped at 20k calls/day, so it gap-fills ASN/network fields and contributes only what nothing else has (reputation, GreyNoise, VPN/proxy/hosting flags, abuse contacts) |
| `integrations/mattermost_alerts.py` | Optional Mattermost webhook notifications |
| `integrations/opencti_ingest.py` | OpenCTI ingestion — Domain-Name observables, Channel SDOs, and website-channel tier/label extraction |
| `frontend/` | React frontend built with Vite |

## Storage Model

All storage is **PostgreSQL** (`DATABASE_URL`):

- `cases/case_store.py` — the internal ingest jobs (and legacy case/pair/cluster tables, retained but unused by the UI).
- `db/intel_db.py` — raw intel runs and the derived correlation graph. Search runs are append-only: every analysis is a new `searches` row, and all child tables (`ips`, `tls_certs`, `identifiers`, `discovered_targets`, ...) link back to it by `search_id` foreign keys. The `entities`/`selectors`/`observations`/`entity_edges`/`graph_clusters` tables are the derived, rebuildable correlation layer (see [Selector-centric attribution graph](#selector-centric-attribution-graph)).

Both modules use the same psycopg3 short-lived-connection conventions, so multiple workers can read and write concurrently. The intel tables can optionally live in a separate database by setting `INTEL_DATABASE_URL`; when unset, `DATABASE_URL` is used for everything (the docker-compose default).

### Migrating a legacy SQLite database

Earlier versions stored raw intel in SQLite (`data/ip_intel.db`). To copy an existing file into PostgreSQL with all row IDs and foreign keys preserved:

```bash
python3 scripts/migrate_sqlite_to_postgres.py data/ip_intel.db
```

The target defaults to `INTEL_DATABASE_URL`/`DATABASE_URL` (override with `--database-url`). The intel tables must be empty; pass `--force` to append anyway. Legacy JSON-text columns are converted to JSONB during the copy.

## Local Development

### Backend

```bash
uv sync
uv run uvicorn app:app --reload
```

The API runs on `http://127.0.0.1:8000`. You need a reachable PostgreSQL instance; set `DATABASE_URL` in a `.env` file or the environment.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The Vite dev server runs on `http://127.0.0.1:5173` and proxies `/api` to the FastAPI backend on `http://127.0.0.1:8000`.
Use Node `20+` locally for the frontend toolchain.

### Production-style Local Run

```bash
cd frontend
npm install
npm run build
cd ..
uv run uvicorn app:app --host 0.0.0.0 --port 9000
```

When `frontend/dist` exists, FastAPI serves the compiled React frontend directly.

## Docker

```bash
docker compose up -d --build
```

Then open:

```text
http://127.0.0.1:9000
```

The Docker setup:

- builds the React frontend with Vite in a Node stage
- runs the FastAPI backend with Uvicorn on container port `8000`, published as `9000`
- runs a PostgreSQL 16 container for all storage (jobs, legacy app tables, and raw intel)
- mounts `./data` for downloaded artifacts and any other persistent files

## VPN / Outbound Proxy

External OSINT providers (crt.sh, CIRCL pDNS, HackerTarget, urlscan.io,
plus direct probes of target sites) rate-limit per source IP. Outbound provider
HTTP traffic can be routed through the org VPN to bypass those limits.

RIPE Stat and the GCP IP-range download belong to `core/ip_intel.py`'s targeted
origin-scan feature (masscan/async-TCP scanning of provider/GCP/country IP
ranges for a matching TLS cert) — see the note in
[What is and is not proxied](#what-is-and-is-not-proxied). That feature is
**not enabled for the web app's ingest path** (`core/analysis_service.py`
passes through with `"Targeted origin scan is not enabled for web ingest"`);
it only runs when `core/ip_intel.py` is invoked directly as a CLI with
`--scan`/`--scan-europe`/`--scan-providers`/`--scan-country`/`--scan-full`/`--scan-all`.

### Environment variable

Set `OUTBOUND_PROXY_URL` to an `http://` or `socks5://` proxy URL:

```bash
OUTBOUND_PROXY_URL=http://vpn:8888
```

When the variable is unset or empty, all calls connect directly, exactly as before.
The helpers live in `utils/outbound.py` (`requests_kwargs()` / `httpx_kwargs()`)
and are read from the environment at call time.

### Compose profile

`docker-compose.yml` ships an optional `vpn` profile for the environment used by
this project: an externally managed `protonvpn-cli` container already attached
to the shared Docker network, plus a tinyproxy sidecar that joins that
container's network namespace. A plain `docker compose up` is unchanged.

To enable it:

1. Start the external ProtonVPN stack so the `protonvpn-cli` container exists on
   the `shared_net` Docker network.
2. Add proxy/rotation settings to `.env`:

   ```bash
   OUTBOUND_PROXY_URL=http://protonvpn-cli:8888
   VPN_API_BASE_URL=http://protonvpn-cli:8000
   ```

3. Start the proxy profile:

   ```bash
   docker compose --profile vpn up -d --build
   ```

The `protonvpn-proxy` service exposes tinyproxy through the VPN network
namespace, so the `ip-intel` service reaches it as
`http://protonvpn-cli:8888`. If `OUTBOUND_PROXY_URL` is unset, all outbound
provider traffic connects directly.

### What is and is not proxied

Proxied (when `OUTBOUND_PROXY_URL` is set):

- provider API calls run on every domain analysis: crt.sh, CIRCL passive DNS,
  HackerTarget, urlscan.io
- HTTP(S) probes of target sites: homepage / page metadata, well-known files,
  legal pages, mail client autoconfig, Microsoft tenant discovery, live probes
- RIPE Stat and GCP IP-range download — only when `core/ip_intel.py`'s
  opt-in origin-scan CLI flags are used (not part of the web app's ingest path)

Not proxied (always direct):

- internal/intranet services: Mattermost webhooks, OpenCTI, PostgreSQL
- raw socket probes (TLS certificate grabs, SSH host keys) and all DNS
  lookups — these do not go through an HTTP proxy and bypass the VPN
- the `masscan`/async-TCP port scanning used by the same opt-in origin-scan
  CLI feature
- Censys SDK traffic, which manages its own HTTP stack

`socks5://` proxy URLs are supported via the `requests[socks]` and `httpx[socks]`
extras already declared in `pyproject.toml`.

## API Overview

There is no case API — everything is the global pool and its connections.

### Ingestion

- `POST /api/ingest` — add a domain / IP / CSV to the pool. JSON `{"target": "...", "label": "..."}` or multipart with a CSV `file`. `label` is an optional free-text tag on the ingest; it scopes nothing. Returns a `job_id` to poll. The scanned targets join the one shared correlation graph.
- `GET /api/jobs/{job_id}` — poll live ingest progress (stage, percent, logs).

#### Ingestion pipeline tuning

- `ANALYSIS_WORKERS` (default `12`) — how many targets a single job/case analyzes concurrently in `cases/case_runtime.py`'s pool. Each target itself fans out roughly a dozen more threads internally (service calls, IP enrichment, probe fan-out — see [Concurrency inside a single domain analysis](#concurrency-inside-a-single-domain-analysis)), so real thread count is `ANALYSIS_WORKERS × ~12`. Raise it for large bulk sweeps (e.g. the OpenCTI channel sweep), lower it if a paid provider's own account-level rate limit — not the source IP — becomes the bottleneck.
- **Startup recovery is off by default.** On boot, `cases/case_app.py`'s `lifespan` no longer resumes jobs left `queued`/`running` from an unclean shutdown — it flips them to `failed` (`cases/case_store.py`'s `mark_interrupted_jobs()`) so nothing silently re-runs (a resumed OpenCTI sweep previously re-scanned its whole in-flight batch from the start). Set `RECOVER_JOBS_ON_STARTUP=1` to restore the old resume-on-boot behavior (`runtime.recover()`).
- Per-target job logs now include discovery context (depth, origin domain, discovery reason), per-target elapsed time, and a running `done/failed/pending` tally, so a long sweep's log is diagnosable without a debugger.

### The pool

- `GET /api/pool?search=&limit=` — every channel (registrable domain) in the pool, with host count, recency, and cluster membership.

### Connections (global)

- `POST /api/graph/connections` — body `{"domains": ["a.com","b.com",…], "pool_links": true}`. Returns the pairwise links **among the selected channels** (which of them connect to each other, with evidence) and, when `pool_links` is set, each one's strongest connections to the wider pool.
- `GET /api/graph/links/{value}` — ranked cross-corpus connections for one channel, each with its shared-node evidence breakdown (selector kind, value, degree, weight, time-overlap window, sources).
- `GET /api/graph/link?a=<rd>&b=<rd>` — the connecting evidence between two channels.
- `GET /api/graph/selector-kinds` — the edge types available for browsing (selector kind / `shared_ip`) and how many cross-channel groups each forms.
- `GET /api/graph/by-selector?kind=<kind>&min_domains=2` — browse **by edge type**: groups of channels that share a selector of `kind` (e.g. every set of channels sharing a TLS cert / SSH key / IP). Omit `kind` for all edge types.
- `GET /api/graph/clusters` — the strongest clusters lake-wide.
- `GET /api/graph/cluster/{value}` — the cluster a channel belongs to, with members.
- `GET /api/graph/path?a=<rd>&b=<rd>` — the precomputed shortest evidence chain connecting two channels, hop by hop (`db/intel_db.py`'s `path_between` / `graph_paths` table — see [Multi-hop path precompute](#multi-hop-path-precompute)). 404 if no path exists within the configured hop limit.
- `GET /api/graph/related/{value}` — a channel's precomputed multi-hop neighborhood (direct links plus everything reachable through an intermediary), strongest/shortest first. Query params `max_hops`, `limit`.
- `POST /api/graph/recompute` — global recompute: rebuild the whole correlation graph + clusters from stored intel (no rescanning).

### Search

- `GET /api/search?q=&limit=` — ranked domain / selector-value matches for the global search box (`db/intel_db.py`'s `search_targets`).

### Meta

- `GET /api/meta/evidence` — evidence type catalog used by the frontend
- `GET /api/health` — health check

> The analysis/job machinery still runs each ingest internally (under `cases/case_runtime.py`), but it is no longer surfaced as "cases" — there is no per-submission scope, and all correlation is global. Run `POST /api/graph/recompute` (or `uv run python -m scripts.backfill_correlation`) after changing extraction or weighting logic.

## Pipeline Conformance Checklist

Use this checklist when changing ingestion, providers, graph materialization, or
the frontend:

- Local dev still starts with `uv run uvicorn app:app --reload` and
  `npm run dev`, with Vite proxying `/api` to FastAPI.
- Docker still builds the React frontend first, serves `frontend/dist` through
  FastAPI, and exposes the app on `http://127.0.0.1:9000`.
- `POST /api/ingest` returns a job id, streams stage/percent/current-target/log
  progress through `GET /api/jobs/{job_id}`, and writes every successful scan to
  the append-only intel store.
- All scanned domains/IPs join the global pool and the rebuildable correlation
  graph; no user-facing case scope is reintroduced.
- Active provider behavior remains Censys plus free/no-paid-credit sources.
  Missing keys, provider tier failures, and source errors degrade per source
  without aborting the run.
- Censys/free-source hits that expose IPs, certificates, ASNs, or hostnames feed
  the same persistence and correlation paths as DNS/TLS/SSH observations.
- OpenCTI full sweeps process every website Channel, persist tier labels by
  registrable domain, attach source labels to the scan result, and leave graph
  materializations fresh or explicitly dirty for rebuild.
- `POST /api/graph/recompute` rebuilds the derived graph from stored intel
  without rescanning and does not delete durable OpenCTI domain tiers.

## Correlation Model

The app correlates on:

- shared IPs
- shared ASNs and network CIDRs
- shared tracking IDs
- shared favicons
- shared TLS certificate fingerprints
- shared WHOIS registrant email and registrant name
- per-target provider-origin hits

Noise handling is applied to common mail, CDN, proxy, and shared-hosting patterns so those overlaps remain visible but are easier to interpret as weaker evidence. WHOIS registrant email/name additionally go through a privacy-redaction filter (`_is_redacted_whois_value` in `db/intel_db.py`) before they're allowed to create a link — see [WHOIS capture and redaction filtering](#whois-capture-and-redaction-filtering).

### Selector-centric attribution graph

On top of the append-only raw `searches` substrate, the app builds a **derived,
rebuildable correlation graph** (`db/intel_db.py`) that models shared observables
as first-class nodes, so linkage becomes graph reachability — including the
transitive, subdomain-mediated case (if `x.a.com` and `y.b.com` present the same
leaf certificate, `a.com` and `b.com` link through the subdomains):

- **entities** — domains, subdomains, and IPs you enrich and traverse, each
  rolled up to its `registrable_domain`.
- **selectors** — lightweight observables implying shared ownership
  (`tls_cert_sha256`, `tls_spki`, `tls_san`, `favicon_mmh3`, `tracking_id`,
  `ssh_fp`, `nameserver`, `asn`, `network_cidr`, …), each with a global
  `entity_count` (degree) and an `attributing` flag.
- **observations** — provenance-bearing entity→selector edges (`source` +
  `search_id` + observed time window).
- **entity_edges** — structural `resolves_to` / `subdomain_of` edges.

Two registrable domains link when they share an **attributing** selector or a
non-noise shared IP. Each shared node is scored by **base weight × rarity ×
time-overlap**: rarity is `1/log2(degree)` (a cert shared by 2 entities is huge;
a nameserver/ASN shared by 40,000 is ~noise), and observation windows that
overlap score higher than the same selector seen years apart. Base weights and
strength tiers live in `utils/evidence_meta.py`; the linkage/scoring engine is in
`utils/check.py` (`link_evidence`, `links_for`); clustering is connected
components over the whole attributing graph (`graph_clusters`).

A configurable **denylist** marks selectors non-attributing — known CDN/cloud
ASNs, big-provider nameservers, default/shared-host cert SANs, and any selector
whose degree exceeds `CORRELATION_DEGREE_THRESHOLD` (default 50). Denylisted
nodes are kept in the graph but never create a link.

The degree rule is deliberately looser for **account-bound** selectors —
webmaster-tools verification codes and AdSense/GA ids — which use
`CORRELATION_ACCOUNT_DEGREE_THRESHOLD` (default 500) instead. These are issued
to an account rather than deployed on shared infrastructure, so two sites never
come to share one incidentally the way they share a CDN ASN. High degree there
means one account owns many domains, which is the finding itself: applying the
infrastructure cutoff would discard a broadcaster's own verification code
exactly because it covers the whole network being investigated. Rarity weighting
still applies, so a wide token degrades smoothly rather than at a cliff.

#### Multi-hop path precompute

`graph_links` (built by `rebuild_clusters()`) is a scored, weighted adjacency list of each domain's *direct* connections. On top of it, the same rebuild pass BFS-walks every domain out to a configurable hop limit and materializes the result into a `graph_paths` table (`db/intel_db.py`'s `_extend_paths`), so "why is A related to C" — including a same-cluster relationship with no direct edge — is always an indexed `SELECT` (`path_between`, `related_through`; see `GET /api/graph/path` and `GET /api/graph/related/{value}`) rather than a live traversal triggered by a search or page load.

- `GRAPH_PATH_MAX_HOPS` (default `3`) — how many hops the BFS walks per domain.
- `GRAPH_PATH_MAX_NODES` (default `200`) — cap on how many reachable domains are materialized per source domain, so a densely-connected hub doesn't blow up the table.
- Each BFS step only follows a node's own top-N direct links (frontier-limited, independent of `graph_links`' own unlimited storage), so a hub domain with hundreds of direct connections can't blow up every other domain's path walk.
- `rebuild_clusters()` runs `DELETE FROM graph_clusters` / `graph_cluster_links` rather than `TRUNCATE` before rematerializing them: `TRUNCATE` takes an `ACCESS EXCLUSIVE` lock held until commit, which would block every concurrent `/api/pool` and `/api/graph/clusters` read for the whole (potentially long) rebuild. `DELETE` only takes `ROW EXCLUSIVE`, so readers keep seeing the previous snapshot under MVCC and flip to the new one atomically on commit.

#### WHOIS capture and redaction filtering

`core/basic.py`'s `get_whois()` (and its CLI-engine twin in `core/ip_intel.py`) call `whois.whois(domain)` (the `python-whois` package) and keep **every field the TLD-specific parser extracted** — registrar, dates, status, nameservers, plus registrant/admin/tech name, org, address, city, state, postal code, and any TLD-specific extras — not just a curated subset. The full unparsed response text is also kept under `raw`, so nothing is lost even for fields the parser has no regex for. `expiry_date` and `nameservers` are kept as aliases of the parser's `expiration_date`/`name_servers` for backward compatibility with `db/intel_db.py`'s `whois_data` table and identifier extraction.

Registrant **email** and **name** both feed the correlation graph as `registrant_email` / `registrant_name` identifiers (tier_3, category `identity`) — but only after passing `_is_redacted_whois_value()` in `db/intel_db.py`, a denylist of privacy-service and registrar-boilerplate text (`REDACTED FOR PRIVACY`, `Data Protected`, `WhoisGuard`, `Domains By Proxy`, `Personal data, can not be publicly disclosed`, generic `n/a`/`none`/empty, ...). Without this filter, any two domains that both happen to use the same registrar's privacy proxy (or are both GDPR-masked) would spuriously "connect" — the filter makes sure only an actual shared name/email creates a link. The email-specific `_GENERIC_EMAILS` exact-match denylist (a handful of known registrar abuse addresses) still applies on top of it in the legacy `get_connections_for_target` path.

#### Where the CDN / proxy / shared-hosting reference data comes from

The noise lists that back the denylist above (and the equivalent shared-IP
classification used by the pairwise scorer) are plain Python sets/tuples
hardcoded in two files — there is no external feed pulled at runtime:

- `db/intel_db.py`: `_CDN_PROXY_ASNS`, `_SHARED_HOSTING_ASNS`, `_MAIL_ASNS`
  (ASN numbers) and `_CDN_PROXY_PTR_PATTERNS`, `_SHARED_HOSTING_PTR_PATTERNS`,
  `_MAIL_PTR_PATTERNS`, `_LOW_SIGNAL_HOSTING_PATTERNS` (reverse-DNS/hostname
  substrings) — used by `seed_denylist()` and `classify_ip()`.
- `utils/check.py`: `_CDN_NETWORK_PATTERNS` (RDAP network-name/ASN-description/
  PTR keywords), `_CF_IPV4`/`_CF_IPV6` (Cloudflare's published anycast ranges),
  and `_KNOWN_SHARED_INFRA_IPS` (documented shared frontend IPs, e.g. Firebase
  Hosting's `199.36.158.100/101`) — used by `describe_ip_network()`.

`config/provider_asns.json` is a separate, curated ASN registry (name, region,
category, notes per ASN) used by `core/ip_intel.py`'s ASN-range origin scanner
(`PROVIDER_ASNS`) to decide which hosting providers' IP space to probe for a
candidate origin server. It is not read by the denylist code above, but its
`edge_and_cdn_noise` focus set is a useful cross-check when adding new entries
to `_CDN_PROXY_ASNS`, since both should agree on which ASNs are edge/CDN
rather than direct-origin hosting.

**Provenance:** none of this is sourced from an authoritative feed except the
Cloudflare IP ranges, which carry their source in the code comment
(`https://www.cloudflare.com/ips/`, present since the first commit). Everything
else — every ASN number, every PTR/network-name keyword, the entries in
`config/provider_asns.json` and `config/boring_ns_providers.txt` — was typed in
by hand across several commits with no cited source, generator script, or
fetch step. Git history shows the ASN sets first appeared already as bare
numbers with only an inline "# CF, Incapsula, Fastly, Akamai, etc." style
comment naming what the author *believed* each one was — never verified
against a registry at the time. Treat every pre-existing entry as an
unverified claim until it's been checked, not as ground truth.

**Adding an ASN:** verify the number actually belongs to the provider you
think it does before adding it — an ASN registry lookup makes this a 10-second
check, and a wrong number silently denylists (or fails to denylist) some
other organization's real infrastructure. RIPEstat's public API needs no key:

```bash
curl -s "https://stat.ripe.net/data/as-overview/data.json?resource=AS<number>" | jq '.data.holder'
# reverse lookup by name if you only know the provider:
curl -s "https://stat.ripe.net/data/searchcomplete/data.json?resource=<name>"
```

**2026-07-06 audit:** ran every existing ASN in `_MAIL_ASNS`, `_CDN_PROXY_ASNS`,
and `_SHARED_HOSTING_ASNS` through the RIPEstat check above. Four were wrong —
not just miscategorized, but a different organization entirely — meaning real
evidence involving that org's actual infrastructure was being silently thrown
away as noise:

| ASN | Old label (untraced) | RIPEstat holder | Fix |
|---|---|---|---|
| AS394161 | "Google Workspace" mail | Tesla Motors, Inc. | Removed from `_MAIL_ASNS` (Google mail is already covered by AS15169) |
| AS60626 | "Bunny CDN" | LeaseWeb Network B.V. | Moved out of `_CDN_PROXY_ASNS` into hosting; real Bunny CDN is AS200325 ("BunnyCDN BUNNYWAY"), added in its place |
| AS61493 | "Tumblr" | InterBS S.R.L. (BAEHOST) | Removed from `_SHARED_HOSTING_ASNS` |
| AS2025 | "Tumblr" | University of Toledo | Removed from `_SHARED_HOSTING_ASNS`; real Tumblr ASNs are AS32345/AS33612 ("TUMBLR-CORP"/"TUMBLR", Yahoo Holdings), added in their place |

Also removed AS20473 (Vultr/"The Constant Company") from `_CDN_PROXY_ASNS` —
it's a generic VPS/cloud provider, not CDN/edge, so treating it as noise was
suppressing real dedicated-origin evidence for anyone hosted there (the
opposite failure mode from the other four: a false negative, not a false
positive). `config/provider_asns.json`'s `AS60626` entry had the same
Bunny-CDN mislabel and was corrected the same way.

After editing any of these lists, run a global recompute (`POST
/api/graph/recompute` or `scripts/backfill_correlation.py`) so existing
selectors are re-evaluated against the change — `seed_denylist()` always
resets every selector to attributing first, so a widened or shrunk list takes
full effect on old data, not just new ingests.

#### Backfill and global recompute

The correlation layer is populated inline on every analysis and is fully
rebuildable from stored intel without rescanning:

```bash
# build/rebuild the whole graph from all stored searches, compute degrees, seed
# the denylist, and materialize clusters
uv run python -m scripts.backfill_correlation
# or, in a running container
docker compose exec ip-intel python -m scripts.backfill_correlation
```

`POST /api/graph/recompute` does the same in-process. Because extraction and
scoring read only the stored substrate, changing a base weight in
`evidence_meta.py` (rescore: in-memory) or extraction logic (`POST
/api/graph/recompute`) reproduces everything deterministically — no rescan.

## Evidence Strength

Nothing in certificate or IP data is perfect proof of ownership by itself. The workflow is designed to separate stronger infrastructure evidence from softer context instead of treating every overlap as equal.

The strongest signals the app can surface today are:

- exact shared TLS certificate fingerprints, especially when the overlap is current instead of historical
- direct shared IPs that do not look like CDN, proxy, mail, or broad shared-hosting infrastructure
- repeated overlap between a direct shared IP and the same current TLS fingerprint
- smaller or dedicated-looking shared ASNs and network CIDRs as supporting context around the host-level signals

Weaker signals are still kept and shown, but intentionally scored lower:

- CDN or reverse-proxy edge IP overlap
- broad shared-hosting overlap
- mail or collaboration infrastructure overlap
- ASN overlap by itself, especially on large providers

## SANs and Workflow Limits

The workflow supports:

- exact TLS fingerprint clustering with `current`, `historical`, and `all` scopes
- shared IP clustering with network and reverse-proxy context
- ASN and network-CIDR clustering with noise labels
- per-pair connection pages that show current vs historical TLS overlap windows

SANs are preserved in stored certificate records. The graph does not currently treat SAN-only overlap as a first-class scored edge — the strongest automatic certificate connection is still exact fingerprint overlap rather than SAN overlap by itself.

## Provider Behavior

The active provider policy is **Censys plus free/no-paid-credit sources**.
Free sources and direct probes include DNS, WHOIS/RDAP, TLS and SSH probes,
crt.sh, CIRCL passive DNS, HackerTarget, urlscan.io, ViewDNS when
`VIEW_DNS_API_KEY` is configured, and ipinfo Lite when `IP_INFO_KEY` is
configured. Censys is the only paid-style certificate-search provider the web
pipeline is expected to use.

Censys runs **only for the seed/apex domain a user submits**:
`core/analysis_service.py` passes `run_providers = is_seed or is_apex`, so
auto-discovered follow-up subdomains skip Censys even when credentials are
configured. Free sources still run on follow-ups unless their own
key/configuration is missing. Shodan and Netlas helpers are retained only as
dormant compatibility for older installations and are not part of the supported
active provider set.

### Censys

- **Tier requirement:** the cert→host search uses the Censys Platform **search API**, which is **not available on the free tier** (free API is lookup-only). A **Starter** tier or higher is required for any Censys results; the **Enterprise Adversary Investigation** entitlement is additionally required for certificate history.
- **One implementation, one query.** `core/basic.py`'s `get_censys` — the entry in `SERVICES`, i.e. the one the web pipeline actually runs — delegates to `core/ip_intel.py`'s `censys_cert_search`. It previously ran its own copy of the identical query with `fields=["host.ip"]` and kept only the IP, paying the same search credits for a fraction of the response; the shared implementation keeps the ASN, country, open-service list, non-Cloudflare origin-candidate split, and pagination that come back in the same paid call.
- **The right tenant's certificate.** A search hit's `host_v1.matched_services` names the service(s) that actually matched the queried domain, so the leaf fingerprint is taken from *that* service rather than from the first cert-bearing service on the host. On shared hosting the first one is frequently a different tenant's cert, and chasing the wrong fingerprint costs 25 credits of cert history against infrastructure that was never the target's. When a response carries no `matched_services` (older API versions, or a `fields` selection that omits `host.services.port`/`transport_protocol`/`protocol`), the first-cert behaviour is used as a documented fallback.
- **Cert history is opt-in** (`CENSYS_CERT_HISTORY=1`, default off). The threat-hunting cert→host-observation pivot is up to 125 of the ~135 credits a single seed domain spends (5 certs × 5 pages × 5 credits) and needs the Enterprise Adversary Investigation entitlement most accounts lack, so by default it would burn the run's budget only to record entitlement errors. Free CIRCL passive DNS already covers much of the same "IPs that used to serve this domain" ground at no cost. `censys_cert_search(domain, include_history=True/False)` overrides the env var for a single call.
- Current-state cert-to-host hits are normalized into the same durable
  provider/origin path as free-source hits so they can enrich IP context and
  correlation.
- Missing credentials, missing package support, tier failures, or API errors
  are surfaced as skipped/error metadata without aborting the rest of the run.

#### Censys host enrichment vs the free sources

`GET /v3/global/asset/enrichment/host/{ip}` (`utils/censys_enrichment.py`) spends
no search credits but is capped at **20,000 calls/day account-wide**, shared
across every IP of every domain in a sweep — which makes it the *scarcer*
source, not the cheaper one. It therefore only **fills gaps** on
`asn`/`asn_description`/`asn_country`/`network_name`/`network_cidr`, and spends
its budget on what nothing else provides: reputation, GreyNoise, threat and
VPN/proxy/hosting classification, city-level geo, abuse contacts, and
open-service labels.

The primary for the overlapping fields stays [ipinfo Lite](https://ipinfo.io/lite),
because the Lite endpoint is genuinely free **and uncapped** — ipinfo's Lite API
docs state it "has no daily or monthly limit and provides unlimited access"
(re-verified 2026-08-12). Note this is specific to Lite; ipinfo's *legacy* free
endpoint is capped at 50k/month, which is what makes it easy to assume wrongly
that Lite is metered. RDAP stays the source for network name/CIDR and the
fallback when `IP_INFO_KEY` is unset.

### Dormant compatibility providers

Shodan and Netlas code paths remain in the codebase for older deployments that
may still have those keys configured, but they are not part of the supported
active provider policy and should not be required for local development,
Docker, tests, or README conformance.

### ViewDNS

- Optional subdomain source (`VIEW_DNS_API_KEY`); unset key means `get_viewdns_subdomains` returns `{"skipped": True}` and the rest of the pipeline behaves as if it were never called.
- Feeds `core/basic.py`'s `SERVICES` list, so it runs on every domain analysis alongside crt.sh/HackerTarget.
- Its hits flow into the same places crt.sh's subdomains do: `pick_followup_subdomains()` merges the two lists so newly discovered hosts get a full recursive follow-up scan (not just recorded), and any IP on a hit feeds `collect_non_cf_ips()`.
- Response shape from ViewDNS varies by plan/endpoint version (some return bare hostname strings, others `{"subdomain", "ip"}` objects) — `get_viewdns_subdomains` normalizes both into HackerTarget's `{"hits": [{"subdomain", "ip"}]}` shape so it composes with existing consumers without special-casing.

## Performance and Resilience Notes

- Repeated GCP, ASN, and country scan setup reuses cached range lookups (`core/ip_intel.py`'s opt-in origin-scan CLI feature — see [What is and is not proxied](#what-is-and-is-not-proxied); not part of the web app's ingest path).
- `masscan` is used when available for that same opt-in scan feature, with async TCP/TLS fallback preserved automatically.
- Source failures are isolated so a single provider or passive-source problem does not kill the whole run.
- Provider hits, scan hits, and direct TLS probes are normalized into the same enrichment and clustering pipeline.

### Concurrency inside a single domain analysis

`core/basic.py`'s `analyze()` and its per-domain helpers fan work out instead of running it sequentially, since almost every step is I/O-bound (DNS, HTTP, provider APIs):

- **External services** (`SERVICES` — crt.sh, CIRCL pDNS, HackerTarget, urlscan.io, WHOIS, ViewDNS, Censys, ...) run concurrently in a `ThreadPoolExecutor` sized to `len(SERVICES)`, each in a copied `contextvars.Context` so the per-provider log lines still reach the job log/UI from worker threads. Previously this was a sequential `for name, fn in SERVICES` loop, so total wall time was the sum of every source's latency; now it's roughly the slowest single source.
- **`sources/signal_web.py`**'s multi-path fetchers — `fetch_well_known_files`, `scrape_legal_pages`, `probe_mail_client_config` (autodiscover/autoconfig) — fan every candidate path/URL out concurrently (`_run_probes_concurrent`, capped at `_PROBE_FANOUT = 8` workers) instead of walking the path list one request at a time. A site with N well-known paths previously cost up to `N × timeout` on a slow/unreachable host; now it costs roughly one timeout for the whole fetcher. `httpx.Client` is thread-safe over its shared connection pool, so this reuses the same client.
- The **IP enrichment loop** (PTR + RDAP/WHOIS + reverse-IP per non-CF IP) stays intentionally sequential — RDAP/WHOIS providers rate-limit hard per source IP — but now logs per-IP elapsed time and flags any IP taking ≥5s, so a stalled lookup is visible in the job log instead of the whole loop looking hung.
- Parity enrichment steps (email security, zone transfer, well-known, legal pages, mail client config, Microsoft tenant, page metadata, source maps, origin candidates) are each wrapped in a timing context manager (`core/analysis_service.py`'s `_step`) that logs entry, exit, elapsed time, and flags anything ≥10s as `<== SLOW`.
- Per-target concurrency across a job (how many domains a single ingest analyzes at once) is controlled by `ANALYSIS_WORKERS` — see [Ingestion pipeline tuning](#ingestion-pipeline-tuning).

## OpenCTI Ingestion

`integrations/opencti_ingest.py` pulls targets from OpenCTI (set `OPENCTI_URL` and `OPENCTI_TOKEN`). OpenCTI website-channel ingestion is intentionally operator-triggered from Docker, not exposed in the web UI:

- **`scripts/ingest_opencti_channels.py`** (below) — every matching Channel, no cap, run as a docker command instead of from the UI, with tier classification.
- `_run()` / `restart_ingestion()` / `retry_source_errors()` in `integrations/opencti_ingest.py` — an older worker that separately pulled Domain-Name observables and Channel SDOs and ran them through `core/ip_intel.py`'s CLI engine rather than the current app ingest pipeline (`OPENCTI_INGEST_CHANNELS`, `OPENCTI_INGEST_WORKERS` control it). Nothing in the running app calls `start_background_ingestion()`/`restart_ingestion()` anymore — it's dead code, kept because `tests/test_opencti_ingest.py` still exercises it.

Channel SDOs (STIX 2.1 extension) are resolved to domains the same way in both live paths (`_channel_candidate_domains`): the channel `name` and aliases are used when they parse as a domain/URL, plus any external reference URLs, normalized to bare registrable domains (scheme, path, port, and leading `www.` stripped). Social-media platform domains (facebook.com, x.com, youtube.com, t.me, vk.com, etc.) are skipped per the "non-social media channels" goal.

### Full website-channel sweep with tier classification

```bash
docker compose exec ip-intel python -m scripts.ingest_opencti_channels
# preview the domain/tier/label list without ingesting anything:
docker compose exec ip-intel python -m scripts.ingest_opencti_channels --dry-run
```

`scripts/ingest_opencti_channels.py`:

1. Fetches **every** OpenCTI Channel SDO with `channel_types` containing `website` (`fetch_all_website_channel_data()`, server-side filtered, fully paginated — no 100-item cap).
2. Records tier classification for every channel up front (step 3 below), before any scanning, so it's captured even if a domain's analysis later fails or times out.
3. **Skips channels already in the pool** by default (`existing_search_targets()` — a set membership check against every already-scanned normalized target): the analysis pipeline is the expensive part, so a re-run of the sweep only scans channels new since the last run. Skipped channels still get their tier and OpenCTI labels refreshed. Pass `--rescan-existing` to force a full re-run of every channel regardless.
4. Splits the remaining new domains into **sequential batches** (`--batch-size`, default `250`; `0` = one batch for everything) submitted as separate cases, one after another. Each batch completes and persists (scans, tiers, labels) before the next starts, so a crash or restart only loses the in-flight batch, not the whole sweep — and progress (attached labels, graph state) is durable incrementally rather than only at the very end. A failed batch doesn't abort the sweep; remaining batches still run, and the script exits non-zero at the end if any batch failed.
5. Runs every domain in a batch through the same full app ingest pipeline (`CaseRuntime.submit_case` → `analyze_target` → `core/basic.py`'s `analyze()` with parity enrichments, subdomain/sibling follow-ups, and `db/intel_db.py` correlation), blocking and printing job progress until each batch finishes — safe to run as a one-shot container command, unlike the fire-and-forget frontend button. Progress lines are only printed when the job's stage/percent/done/failed/total counters actually change (`_progress_signature`), so a concurrent analysis pool (`ANALYSIS_WORKERS`) doesn't flood the log with identical polling snapshots.
6. Extracts a **tier-1..tier-5** classification from each channel's OpenCTI labels: `_extract_tier()` matches `tier` + a digit 1-5, case/space/dash/underscore-insensitive (`Tier 1`, `tier-2`, `TIER_3`, ... all match) — a channel's other labels (campaign names, platform tags, ...) are not tiers and are ignored. If a channel somehow carries more than one tier label, the lower number (higher priority) wins.
7. Writes the tier to `db/intel_db.py`'s `domain_tiers` table (`set_domain_tier`) — keyed on the **registrable domain**, not a search_id, so it's a durable, curated attribute that survives rescans instead of living and dying with one scan result. Not part of the append-only raw substrate and explicitly excluded from `rebuild_clusters`/`rebuild_all_correlation`, so a correlation-graph rebuild never touches it.
8. Attaches the full label list (not just the tier) to that ingestion's own scan result as `opencti_labels` (`save_search_fields`), informational only.
9. Rebuilds graph materializations (`rebuild_clusters()`) once at the end, after all batches finish (or immediately, if every channel was already scanned).

Since this script runs detached (stdout redirected to a logfile, no terminal attached), it attaches its own stdout handler to the `ip_intel` logger family (`_configure_logging()`) — the web app's handler setup in `cases/case_app.py` never runs here, so without this, per-domain scan progress (crt.sh hit counts, slow-step warnings, etc.) would silently never reach the log. Level honors `IP_INTEL_LOG_LEVEL` (default `INFO`).

The tier shows up wherever the domain does: a colored badge next to the name on the pool listing and the domain detail page, and node fill color (with a legend) on the network graph (`ClusterGraph.jsx`) — tier 1 (highest priority) is deep red, fading through orange/amber/blue to tier 5 (slate). `GET /api/pool`, `GET /api/domain/{value}`, and `POST /api/graph/connections` all include tier data (`list_pool_domains`, `domain_profile`, `check.connections_among` respectively).

## Configuration

Everything is configured through environment variables, read from `.env` (which
Docker Compose passes to the `ip-intel` service via `env_file`). Only
`DATABASE_URL` is required; every other variable has a working default or
degrades gracefully when unset.

A minimal `.env` to get started:

```env
DATABASE_URL=postgresql://ip_intel:ip_intel@localhost:5432/ip_intel
CENSYS_API_KEY=<personal-access-token>
CENSYS_ORG_ID=<organization-id>
IP_INFO_KEY=<your-ipinfo-lite-token>
URLSCAN_KEY=<your-urlscan-api-key>
```

### Database

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | — | **Required.** App/job tables. The Compose default points at the bundled `postgres` service. |
| `INTEL_DATABASE_URL` | `DATABASE_URL` | Only needed to put the raw intel tables in a *different* database from the app/job tables. |
| `TEST_INTEL_DATABASE_URL` | `postgresql://intel_test:intel_test@127.0.0.1:5433/intel_test` | Scratch database for the DB-backed tests. They **skip silently** when it is unreachable, so set this before trusting a green run. |

### Provider keys

All optional — a missing key disables that source and is reported as a
`skipped` marker rather than an error.

| Variable | Default | Purpose |
| --- | --- | --- |
| `CENSYS_API_KEY` | unset | Censys Platform personal access token. |
| `CENSYS_ORG_ID` | unset | Censys organization id. Required alongside the key — the Platform API rejects requests without one. |
| `CENSYS_CERT_HISTORY` | `0` | Set `1` to opt in to the cert→host-observation pivot. Off by default; it costs up to 125 of the ~135 credits per seed domain. |
| `CENSYS_ENRICHMENT_DAILY_LIMIT` | `20000` | Daily cap on host-enrichment calls, enforced *before* the request goes out. Set `0` to disable enrichment entirely. |
| `IP_INFO_KEY` | unset | ipinfo.io Lite token — the primary ASN/org/country source. |
| `URLSCAN_KEY` | unset | Authenticates urlscan.io, lifting the anonymous per-IP rate limit. |
| `SHODAN_API_KEY` | unset | Shodan origin-IP search. |
| `NETLAS_KEY` | unset | Netlas cert→host search. `NETLAS_API_KEY` is accepted as a fallback name. |
| `CERTSPOTTER_API_KEY` | unset | CertSpotter CT source. |
| `VIEW_DNS_API_KEY` | unset | ViewDNS reverse-IP lookups. |

### Correlation graph

| Variable | Default | Purpose |
| --- | --- | --- |
| `CORRELATION_DEGREE_THRESHOLD` | `50` | Selector degree past which a selector is denylisted as too common to attribute. |
| `CORRELATION_ACCOUNT_DEGREE_THRESHOLD` | `500` | The same ceiling for account-bound selectors (`site_verification`, AdSense/GA tracking ids), which are issued per account rather than deployed on shared infrastructure. |
| `CORRELATION_CLUSTER_MAX_FANOUT` | `25` | Caps how many neighbours one node contributes during clustering. |
| `GRAPH_CLUSTER_REBUILD_INTERVAL` | `900` | Seconds between whole-pool cluster passes. |
| `GRAPH_FULL_RECONCILE_INTERVAL` | `86400` | Seconds between full reconciles. `0` disables the automatic schedule. |
| `GRAPH_INCREMENTAL_BATCH` | `500` | Domains rescored per maintenance tick. |
| `GRAPH_INCREMENTAL_QUEUE_MAX` | `5000` | Queue ceiling; past it the queue is dropped and a whole-pool rebuild picks the work up instead. |
| `GRAPH_PATH_MAX_HOPS` | `3` | Multi-hop reachability precompute depth. |
| `GRAPH_PATH_MAX_NODES` | `200` | Node ceiling for that precompute. |
| `REBUILD_WORKERS` | CPU count (clamped 2–16) | Parallelism for a full rebuild's per-domain scoring pass. Postgres runs on the same host, so workers past the core count queue rather than overlap; raise this only for a genuinely remote database. |
| `TLS_SAN_BUNDLE_THRESHOLD` | `15` | SAN count past which a certificate is treated as a shared bundle rather than one operator's. |

### Response cache

| Variable | Default | Purpose |
| --- | --- | --- |
| `REDIS_URL` | `redis://redis:6379/0` | Server-side cache for the read endpoints. Unset or unreachable means every endpoint computes live — the app runs unchanged without the `redis` service. |
| `CACHE_REWARM_DEBOUNCE_SECONDS` | `5` | Quiet period before the cache re-warms itself after an invalidation. Invalidations fire once per projected search, so this coalesces a reconcile's burst into a single warm. |

### Ingestion pipeline

| Variable | Default | Purpose |
| --- | --- | --- |
| `ANALYSIS_WORKERS` | `12` | Per-job target concurrency; see [Ingestion pipeline tuning](#ingestion-pipeline-tuning). |
| `URLSCAN_MAX_PARALLEL` | `1` | Concurrent urlscan.io calls. Raising it without `URLSCAN_KEY` will trip the anonymous rate limit. |
| `RECOVER_JOBS_ON_STARTUP` | `0` | Set `1` to resume jobs left `queued`/`running` after an unclean shutdown instead of marking them `failed`. |
| `OPENCTI_URL` | unset | OpenCTI instance URL. |
| `OPENCTI_TOKEN` | unset | OpenCTI API token. |
| `OPENCTI_INGEST_CHANNELS` | `true` | Whether the website-channel sweep is enabled. |
| `OPENCTI_INGEST_WORKERS` | `3` | Concurrency for that sweep. |

### Outbound / VPN

See [VPN / Outbound Proxy](#vpn--outbound-proxy) for how these fit together.

| Variable | Default | Purpose |
| --- | --- | --- |
| `OUTBOUND_PROXY_URL` | unset | `http://` or `socks5://` proxy for provider traffic. Unset means direct connections. |
| `VPN_API_BASE_URL` | unset | ProtonVPN rotation control API. |
| `VPN_ROTATE_DISABLE` | unset | Set `1` to disable rotation even when the VPN is up. |
| `COUNTRY_CODES` | `NL, DE, LT` | Comma-separated rotation pool. |
| `DEFAULT_COUNTRY_CODE` | unset | Preferred exit country. |

### Alerts and diagnostics

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_BASE_URL` | `""` | Base URL used in alert links. |
| `MATTERMOST_WEBHOOK_URL` | unset | Non-blocking alerts on analysis completion and failure. |
| `SMTP_HOST` | unset | Email alerts are enabled only when both this and `ALERT_EMAIL_TO` are set. |
| `SMTP_PORT` | `587` | |
| `SMTP_STARTTLS` | `true` | |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | unset | Optional; authentication is skipped when unset. |
| `ALERT_EMAIL_FROM` | unset | Sender address. |
| `ALERT_EMAIL_TO` | unset | Comma-separated recipients. Delivery runs in a background thread and never blocks the caller. |
| `IP_INTEL_LOG_LEVEL` | `INFO` | Backend log level. |
| `IP_INTEL_DNS_RESOLVERS` | `1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4` | Resolvers used for direct DNS probes (never proxied). |

### Notes on the ones with real trade-offs
- `CENSYS_API_KEY` requires a **Starter tier or higher** Censys Platform account — the free tier's API is lookup-only and cannot run the cert→host search. Certificate history additionally needs the Enterprise Adversary Investigation entitlement. `CENSYS_ORG_ID` is required too: the Platform API rejects requests not associated with an organization.
- `CENSYS_CERT_HISTORY` — set to `1` to opt in to the cert→host-observation pivot. **Default off**, because it is up to 125 of the ~135 credits per seed domain and requires the Enterprise Adversary Investigation entitlement; see [Censys](#censys).
- `IP_INFO_KEY` enables [ipinfo.io Lite](https://ipinfo.io/lite) lookups (`utils/ipinfo_lite.py`), the **primary** ASN/org/country source for every associated IP — its values win over RDAP's whenever it succeeds, since RDAP errors/times out per-RIR fairly often and ipinfo Lite rarely does. The Lite endpoint is free with no daily or monthly request cap, so nothing metered is ever used in its place for those fields. RDAP (`get_ip_whois`) still always runs too, since ipinfo Lite's response doesn't include network name/CIDR, and both feed `detect_proxy_details` for edge-server/reverse-proxy classification. Missing key degrades gracefully to RDAP-only lookups.
- `URLSCAN_KEY` authenticates urlscan.io calls (`core/basic.py`'s `_urlscan_headers`), lifting the anonymous per-source-IP rate limit that otherwise forces a VPN rotation (and the batch-wide stall that comes with it) on nearly every domain during a bulk sweep. Missing key falls back to an unauthenticated UA-only request, same as before.
- `CENSYS_ENRICHMENT_DAILY_LIMIT` — host enrichment is a *separate* quota from the credit-consuming search/view APIs: 20,000 calls/day account-wide on the Core plan, spending no credits. The cap is claimed in the database before each request rather than by reacting to a 429, because on a pool-wide sweep the difference is thousands of wasted round trips. Host enrichment is Core-tier only; on a lower plan every call returns 409 and is skipped without consuming budget. See [Censys host enrichment vs the free sources](#censys-host-enrichment-vs-the-free-sources).
- `REDIS_URL` / `CACHE_REWARM_DEBOUNCE_SECONDS` — the cache re-warms itself. Any graph invalidation bumps the cache generation and signals a background worker, which waits for the debounce window to go quiet and then refills the hot keys once. Invalidating without re-warming would leave every page cold until someone happened to open it and pay the full query cost, and warming per invalidation would bury Postgres during a reconcile — the debounce is what makes both correct.
- `GRAPH_INCREMENTAL_QUEUE_MAX` — when the rescore queue overflows, it is discarded rather than truncated, and the next full reconcile picks the work up. Correctness is preserved either way; the trade is a slower path to consistency in exchange for never letting the queue grow without bound.
- `TEST_INTEL_DATABASE_URL` — the DB-backed tests **skip** rather than fail when this is unreachable, so a run reporting "29 skipped" has verified none of the SQL. Point it at a scratch database before relying on a green suite.
