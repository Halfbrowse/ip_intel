# IP Intel

React + FastAPI application for domain and IP OSINT, origin discovery, and infrastructure correlation.

## Highlights

- Analysis is organised around **cases**: submit one target or a CSV of many, and all jobs, results, and pair comparisons are grouped under a single case.
- Jobs stream live progress (stage, percent, current target, logs) through the polling API and UI.
- Raw intel storage is append-only, so multiple runs of the same target are preserved instead of overwritten.
- TLS relationships are time-aware: the app can distinguish shared certificates that are still current from ones only seen historically.
- Discovered IPs from DNS, provider hits, and scan hits all flow into the same enrichment path and connection logic.
- IP enrichment keeps richer network context: ASN registry, network name, network CIDR, reverse-proxy family, and proxy confidence.
- Shared-infrastructure pivots include ASN clustering in addition to shared IPs, tracking IDs, favicons, and TLS.
- Provider integrations are handled conservatively for free/basic accounts instead of assuming paid certificate-history features are available.

## Project Layout

| File | Purpose |
|---|---|
| `app.py` | Entry point — re-exports the FastAPI `app` from `cases/case_app.py` |
| `cases/case_app.py` | FastAPI routes, static frontend serving, CORS |
| `cases/case_runtime.py` | Case and job orchestration, background workers |
| `cases/case_store.py` | PostgreSQL schema and queries for cases, jobs, pairs, clusters |
| `core/analysis_service.py` | Per-target analysis runner, bridges case layer and core engine |
| `core/ip_intel.py` | Core intelligence engine and scanning/origin-discovery pipeline |
| `core/basic.py` | Legacy OSINT helpers used by the analysis pipeline |
| `db/intel_db.py` | PostgreSQL schema, persistence, and history for raw intel runs |
| `scripts/migrate_sqlite_to_postgres.py` | One-off migration of a legacy SQLite intel database into PostgreSQL |
| `sources/signal_dns.py` | DNS and email-security signals (SPF, DKIM, DMARC, MX) |
| `sources/signal_transport.py` | TLS and SSH certificate parsing |
| `sources/signal_web.py` | Web page metadata extraction (favicons, tracking IDs, headers) |
| `utils/check.py` | Pairwise comparison logic |
| `utils/cluster.py` | Clustering algorithm |
| `utils/evidence_meta.py` | Evidence type definitions and catalog |
| `integrations/mattermost_alerts.py` | Optional Mattermost webhook notifications |
| `integrations/opencti_ingest.py` | OpenCTI ingestion worker (Domain-Name observables and Channel SDOs) |
| `frontend/` | React frontend built with Vite |

## Storage Model

All storage is **PostgreSQL** (`DATABASE_URL`):

- `cases/case_store.py` — cases, jobs, pair comparisons, and cluster results.
- `db/intel_db.py` — raw intel runs, enriched IPs, identifiers, and per-target history. Search runs are append-only: every analysis is a new `searches` row, and all child tables (`ips`, `tls_certs`, `identifiers`, `discovered_targets`, ...) link back to it by `search_id` foreign keys so downstream analysis can join the raw intel directly.

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
- runs a PostgreSQL 16 container for all storage (cases, jobs, and raw intel)
- mounts `./data` for downloaded artifacts and any other persistent files

## VPN / Outbound Proxy

External OSINT providers (crt.sh, CIRCL pDNS, HackerTarget, urlscan.io, RIPE Stat,
plus direct probes of target sites) rate-limit per source IP. Outbound provider
HTTP traffic can be routed through the org VPN to bypass those limits.

### Environment variable

Set `OUTBOUND_PROXY_URL` to an `http://` or `socks5://` proxy URL:

```bash
OUTBOUND_PROXY_URL=http://vpn:8888
```

When the variable is unset or empty, all calls connect directly, exactly as before.
The helpers live in `utils/outbound.py` (`requests_kwargs()` / `httpx_kwargs()`)
and are read from the environment at call time.

### Compose profile

`docker-compose.yml` ships an optional `vpn` service ([gluetun](https://github.com/qdm12/gluetun))
behind the `vpn` compose profile, so a plain `docker compose up` is unchanged.
To enable it:

1. Add your VPN credentials to `.env` (passed through to gluetun), e.g.:

   ```bash
   VPN_SERVICE_PROVIDER=...
   VPN_TYPE=wireguard
   WIREGUARD_PRIVATE_KEY=...
   WIREGUARD_ADDRESSES=...
   SERVER_COUNTRIES=...
   OUTBOUND_PROXY_URL=http://vpn:8888
   ```

2. Start with the profile active:

   ```bash
   docker compose --profile vpn up -d --build
   ```

Gluetun's built-in HTTP proxy (`HTTPPROXY=on`) listens on port `8888` on the
compose network, so the `ip-intel` service reaches it as `http://vpn:8888`.

### What is and is not proxied

Proxied (when `OUTBOUND_PROXY_URL` is set):

- provider API calls: crt.sh, CIRCL passive DNS, HackerTarget, urlscan.io,
  RIPE Stat, GCP IP-range download
- HTTP(S) probes of target sites: homepage / page metadata, well-known files,
  legal pages, mail client autoconfig, Microsoft tenant discovery, live probes

Not proxied (always direct):

- internal/intranet services: Mattermost webhooks, OpenCTI, PostgreSQL
- raw socket probes (TLS certificate grabs, SSH host keys, port scans) and all
  DNS lookups — these do not go through an HTTP proxy and bypass the VPN
- Censys / Shodan / Netlas SDK clients, which manage their own HTTP stacks

`socks5://` proxy URLs are supported via the `requests[socks]` and `httpx[socks]`
extras already declared in `pyproject.toml`.

## API Overview

### Cases

- `POST /api/cases` — create a case (JSON `{"target": "..."}` or multipart with a CSV `file`)
- `GET /api/cases` — list all cases
- `GET /api/cases/{case_id}` — get a case and its status

### Jobs

- `GET /api/jobs/{job_id}` — poll live job progress, stage, logs, and result

### Pairs and Clusters

- `GET /api/cases/{case_id}/pairs` — pairwise comparison results for all targets in a case
- `GET /api/cases/{case_id}/pairs/{pair_id}` — detailed evidence for a single pair
- `GET /api/cases/{case_id}/clusters` — cluster graph for a case

### Meta

- `GET /api/meta/evidence` — evidence type catalog used by the frontend
- `GET /api/health` — health check

## Correlation Model

The app correlates on:

- shared IPs
- shared ASNs and network CIDRs
- shared tracking IDs
- shared favicons
- shared TLS certificate fingerprints
- per-target provider-origin hits

Noise handling is applied to common mail, CDN, proxy, and shared-hosting patterns so those overlaps remain visible but are easier to interpret as weaker evidence.

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

### Censys

- **Tier requirement:** the cert→host search uses the Censys Platform **search API**, which is **not available on the free tier** (free API is lookup-only). A **Starter** tier or higher is required for any Censys results; the **Enterprise Adversary Investigation** entitlement is additionally required for certificate history.
- Paginates the current-state host search up to `_CENSYS_SEARCH_MAX_PAGES` (10 × 100 hosts) instead of a single page.
- When the entitlement is present, pivots each distinct leaf certificate through the threat-hunting host-observation endpoint to recover **historical origins** — IPs that served the cert in the past but no longer appear in the current snapshot (e.g. rotated infrastructure). Non-Cloudflare historical IPs not already in the current hits are folded into `origin_candidates` tagged `source: censys_history`.
- Credit cost at Enterprise: ~1 credit per search call, +1 per extra results page, 5 per cert-history page.
- Paid-only or entitlement failures are surfaced explicitly in results (per-cert history errors are recorded without aborting the run).

### Shodan

- Checks `api.info()` first.
- Uses result-returning searches only when the account is unlocked and query-credit access is available.
- Falls back to count/facets-only mode when full result queries are not available.
- Degraded mode is shown explicitly in the API/UI.

### Netlas

- Optional provider integration for current certificate-search style hits.
- Results are normalized into the same downstream IP and connection flow.

## Performance and Resilience Notes

- Repeated GCP, ASN, and country scan setup reuses cached range lookups.
- `masscan` is used when available, with async TCP/TLS fallback preserved automatically.
- Source failures are isolated so a single provider or passive-source problem does not kill the whole run.
- Provider hits, scan hits, and direct TLS probes are normalized into the same enrichment and clustering pipeline.

## OpenCTI Ingestion

`integrations/opencti_ingest.py` is a manually triggered worker that pulls targets from OpenCTI (set `OPENCTI_URL` and `OPENCTI_TOKEN`) and runs each through the standard analysis pipeline:

- **Domain-Name observables** are ingested as-is.
- **Channel SDOs** (STIX 2.1 extension) are resolved to domains: the channel `name` and aliases are used when they parse as a domain/URL, plus any external reference URLs. Candidates are normalized to bare registrable domains (scheme, path, port, and leading `www.` stripped), social-media platform domains (facebook.com, x.com, youtube.com, t.me, vk.com, etc.) are skipped per the "non-social media channels" goal, and anything already covered by a Domain-Name observable is deduped.

Set `OPENCTI_INGEST_CHANNELS=false` to ingest domain observables only (default `true`). If the installed pycti build does not expose the channel API, the worker logs a warning and continues with domain observables. Logs and completion notifications (Mattermost/email) report per-source counts (`domain-observable` vs `channel`). `OPENCTI_INGEST_WORKERS` controls analysis concurrency (default `3`).

## Optional Configuration

Create a `.env` file and add any provider keys you have:

```env
DATABASE_URL=postgresql://ip_intel:ip_intel@localhost:5432/ip_intel
CENSYS_API_KEY=<personal-access-token>
SHODAN_API_KEY=<your-api-key>
NETLAS_API_KEY=<your-api-key>
MATTERMOST_WEBHOOK_URL=<incoming-webhook-url>
SMTP_HOST=<smtp-server-hostname>
SMTP_PORT=587
SMTP_USERNAME=<smtp-username>
SMTP_PASSWORD=<smtp-password>
SMTP_STARTTLS=true
ALERT_EMAIL_FROM=<sender-address>
ALERT_EMAIL_TO=<recipient-address>,<recipient-address>
```

Notes:

- `DATABASE_URL` is required. The default points to the Docker Compose Postgres service.
- `INTEL_DATABASE_URL` is optional and only needed if the raw intel tables should live in a different PostgreSQL database than case storage.
- All provider keys are optional. Missing keys degrade gracefully.
- `CENSYS_API_KEY` requires a **Starter tier or higher** Censys Platform account — the free tier's API is lookup-only and cannot run the cert→host search. Certificate history additionally needs the Enterprise Adversary Investigation entitlement.
- `MATTERMOST_WEBHOOK_URL` is optional. When set, the backend sends non-blocking alerts for analysis completion and failure.
- Email alerts are optional and mirror the Mattermost notifications. They are enabled only when both `SMTP_HOST` and `ALERT_EMAIL_TO` are set; otherwise sends are silent no-ops.
- `SMTP_PORT` defaults to `587` and `SMTP_STARTTLS` defaults to `true`. `SMTP_USERNAME`/`SMTP_PASSWORD` are optional (authentication is skipped when unset).
- `ALERT_EMAIL_TO` accepts a comma-separated list of recipients. `ALERT_EMAIL_FROM` sets the sender address. Email delivery runs in a background thread and never blocks or fails the caller.
