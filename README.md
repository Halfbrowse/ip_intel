# IP Intel

React + FastAPI application for domain and IP OSINT, origin discovery, and infrastructure correlation.

## Highlights

- Analysis jobs run asynchronously and stream live progress, logs, partial results, and final results through the API and UI.
- OpenCTI ingestion is manual-only and now has its own progress card with queue counts, current target, skipped count, mode, and live logs.
- SQLite storage is append-only for searches, so multiple runs of the same target are preserved instead of overwritten.
- TLS relationships are time-aware: the app can distinguish shared certificates that are still current from ones only seen historically.
- Discovered IPs from DNS, provider hits, and scan hits all flow into the same enrichment path and connection logic.
- IP enrichment now keeps richer network context such as ASN registry, network name, network CIDR, reverse-proxy family, and proxy confidence.
- Shared-infrastructure pivots now include ASN clustering in addition to shared IPs, tracking IDs, favicons, TLS, and per-target overlap views.
- Provider integrations are handled conservatively for free/basic accounts instead of assuming paid certificate-history features are available.

## Project Layout

| File | Purpose |
|---|---|
| `app.py` | FastAPI backend, job API, static frontend serving |
| `frontend/` | React frontend built with Vite |
| `ip_intel.py` | Core intelligence engine and scanning/origin-discovery pipeline |
| `intel_db.py` | SQLite schema, persistence, history, clustering, and connection queries |
| `opencti_ingest.py` | Manual OpenCTI ingestion worker and progress status feed |
| `data/ip_intel.db` / `IP_INTEL_DB_PATH` | SQLite database with saved runs and derived observations |

## Storage Model

- `searches` is append-only. Re-running a target creates a new saved run instead of replacing the previous one.
- Time-aware comparisons become meaningful from the first run created after this upgrade.
- Older rows remain useful as seed data, but they cannot reconstruct overwritten historical state from earlier latest-only versions of the app.

## Local Development

### Backend

```bash
uv sync
uv run uvicorn app:app --reload
```

The API runs on `http://127.0.0.1:8000`.

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
- stores SQLite under `./data/ip_intel.db` via `IP_INTEL_DB_PATH=/app/data/ip_intel.db`
- mounts the whole `./data` directory so SQLite `-wal` and `-shm` sidecar files persist safely across rebuilds

## API Overview

- `POST /api/analyze` starts a domain or IP analysis job
- `GET /api/jobs/{job_id}` polls live analysis progress, logs, partial results, and the final result
- `GET /api/history/recent` returns saved searches
- `GET /api/history/{id}` loads a saved result
- `GET /api/history/target/{target}` returns all saved runs for a target
- `GET /api/history/source-errors` returns domains with recorded source failures
- `GET /api/clusters/ip` returns shared-IP clusters from latest runs
- `GET /api/clusters/tracking` returns shared tracking/ad-tech identifiers
- `GET /api/clusters/favicon` returns shared favicon hashes
- `GET /api/clusters/tls?scope=current|historical|all` returns time-aware TLS overlaps
- `GET /api/clusters/asn?scope=current|historical|all` returns ASN/network overlaps
- `GET /api/connections/{target}` returns per-target overlap details, including run history, ASN overlap, provider hits, and TLS history
- `GET /api/opencti/status` returns OpenCTI ingestion status
- `POST /api/opencti/run?force_reanalyse=false|true` starts manual OpenCTI ingestion
- `POST /api/opencti/retry-failures` retries saved source-error domains in the background
- `GET /api/meta` returns certificate/server/source explainer metadata used by the frontend
- `GET /api/health` returns a health check and surfaces SQLite corruption as a real error

## OpenCTI Ingestion

OpenCTI ingestion does not start automatically on backend startup.

Use the Investigate page:

- `Run` performs an incremental ingest and skips domains already present in the database
- `Re-run all` re-analyzes every OpenCTI domain

The Investigate page now shows OpenCTI ingestion as a dedicated progress job with:

- percent complete
- processed domain count
- skipped-existing count
- current domain
- incremental vs re-run-all mode
- rolling ingestion logs

If you want the new time-aware correlation fields to show up on OpenCTI-backed data, you need to rerun ingestion or rerun the specific targets you care about.

To see "shared now" vs "shared in the past" for a given target, you need at least two post-upgrade runs of that target.

## Correlation Model

The app now correlates on:

- shared IPs
- shared ASNs and network CIDRs
- shared tracking IDs
- shared favicons
- shared TLS certificate fingerprints
- per-target provider-origin hits

Noise handling is applied to common mail, CDN, proxy, and shared-hosting patterns so those overlaps remain visible but are easier to interpret as weaker evidence.

## Evidence Strength

Nothing in certificate or IP data is perfect proof of ownership by itself. The workflow is designed to separate stronger infrastructure evidence from softer context instead of treating every overlap as equal.

The strongest cert and IP signals the app can make today are:

- exact shared TLS certificate fingerprints, especially when the overlap is current instead of historical
- direct shared IPs that do not look like CDN, proxy, mail, or broad shared-hosting infrastructure
- repeated overlap between a direct shared IP and the same current TLS fingerprint
- smaller or dedicated-looking shared ASNs and network CIDRs as supporting context around the host-level signals

Weaker signals are still kept and shown, but intentionally scored lower:

- CDN or reverse-proxy edge IP overlap
- broad shared-hosting overlap
- mail or collaboration infrastructure overlap
- ASN overlap by itself, especially on large providers

In practical terms, the graph and connection views weight evidence roughly like this:

- current exact TLS fingerprint overlap: strongest
- historical exact TLS fingerprint overlap: still strong, but below a current match
- direct shared IP overlap: strong
- shared ASN or network overlap: useful context, but below host-level evidence
- shared-hosting, mail, and CDN overlap: supporting context only

## SANs and Workflow Limits

The workflow already supports the main cert and IP links discussed above:

- exact TLS fingerprint clustering with `current`, `historical`, and `all` scopes
- shared IP clustering with network and reverse-proxy context
- ASN and network-CIDR clustering with noise labels
- per-target connection pages that show current vs historical TLS overlap windows

SANs are preserved in stored certificate records, and certificate-transparency cross-domain SANs are stored for lookup context. The graph does not currently treat SAN-only overlap as a first-class scored edge. In other words, the workflow lets you inspect SAN evidence, but the strongest automatic certificate connection is still exact fingerprint overlap rather than SAN overlap by itself.

## Provider Behavior

### Censys

- Uses a free-safe/basic host search path.
- Does not assume certificate-history or advanced paid-only pivots are available.
- Paid-only or entitlement failures are surfaced explicitly in results.

### Shodan

- Checks `api.info()` first.
- Uses result-returning searches only when the account is unlocked and query-credit access is available.
- Falls back to count/facets-only mode when full result queries are not available.
- Degraded mode is shown explicitly in the API/UI.

### Netlas

- Optional provider integration for current certificate-search style hits.
- Results are normalized into the same downstream IP and connection flow.

## Performance and Resilience Notes

- Repeated GCP, ASN, and country scan setup now reuses cached range lookups.
- `masscan` is still used when available, with async TCP/TLS fallback preserved automatically.
- Source failures are isolated so a single provider or passive-source problem does not kill the whole run.
- Provider hits, scan hits, and direct TLS probes are normalized into the same enrichment and clustering pipeline.

## Optional Configuration

Create a `.env` file and add any provider keys you have:

```env
CENSYS_API_KEY=<personal-access-token>
SHODAN_API_KEY=<your-api-key>
NETLAS_API_KEY=<your-api-key>
OPENCTI_URL=<https://opencti.example.com>
OPENCTI_TOKEN=<opencti-api-token>
MATTERMOST_WEBHOOK_URL=<incoming-webhook-url>
```

Notes:

- All provider keys are optional.
- OpenCTI credentials are only needed if you want to use manual OpenCTI ingestion.
- `MATTERMOST_WEBHOOK_URL` is optional. When set, the backend sends non-blocking Mattermost alerts for analysis completion/failure, OpenCTI ingestion completion/failure, and retry runs.
- Missing provider keys degrade gracefully; the pipeline does not fail just because a provider is unavailable.
