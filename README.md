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
| `utils/ipinfo_lite.py` | ipinfo.io Lite client — primary ASN/geo source (RDAP supplements CIDR/network-name detail and is the fallback when no key is set) and edge/reverse-proxy classification input |
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
- `POST /api/graph/recompute` — global recompute: rebuild the whole correlation graph + clusters from stored intel (no rescanning).

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
- Current-state cert-to-host hits are normalized into the same durable
  provider/origin path as free-source hits so they can enrich IP context and
  correlation.
- Missing credentials, missing package support, tier failures, or API errors
  are surfaced as skipped/error metadata without aborting the rest of the run.

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
2. Runs every resolved domain through the same full app ingest pipeline (`CaseRuntime.submit_case` → `analyze_target` → `core/basic.py`'s `analyze()` with parity enrichments, subdomain/sibling follow-ups, and `db/intel_db.py` correlation), blocking and printing job progress until it finishes — safe to run as a one-shot container command, unlike the fire-and-forget frontend button.
3. Extracts a **tier-1..tier-5** classification from each channel's OpenCTI labels: `_extract_tier()` matches `tier` + a digit 1-5, case/space/dash/underscore-insensitive (`Tier 1`, `tier-2`, `TIER_3`, ... all match) — a channel's other labels (campaign names, platform tags, ...) are not tiers and are ignored. If a channel somehow carries more than one tier label, the lower number (higher priority) wins.
4. Writes the tier to `db/intel_db.py`'s `domain_tiers` table (`set_domain_tier`) — keyed on the **registrable domain**, not a search_id, so it's a durable, curated attribute that survives rescans instead of living and dying with one scan result. Not part of the append-only raw substrate and explicitly excluded from `rebuild_clusters`/`rebuild_all_correlation`, so a correlation-graph rebuild never touches it.
5. Attaches the full label list (not just the tier) to that ingestion's own scan result as `opencti_labels` (`save_search_fields`), informational only.

The tier shows up wherever the domain does: a colored badge next to the name on the pool listing and the domain detail page, and node fill color (with a legend) on the network graph (`ClusterGraph.jsx`) — tier 1 (highest priority) is deep red, fading through orange/amber/blue to tier 5 (slate). `GET /api/pool`, `GET /api/domain/{value}`, and `POST /api/graph/connections` all include tier data (`list_pool_domains`, `domain_profile`, `check.connections_among` respectively).

## Optional Configuration

Create a `.env` file and add any provider keys you have:

```env
DATABASE_URL=postgresql://ip_intel:ip_intel@localhost:5432/ip_intel
CENSYS_API_KEY=<personal-access-token>
VIEW_DNS_API_KEY=<your-api-key>
IP_INFO_KEY=<your-ipinfo-lite-token>
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
- `INTEL_DATABASE_URL` is optional and only needed if the raw intel tables should live in a different PostgreSQL database than the app/job tables.
- All provider/source keys are optional. Missing keys degrade gracefully.
- `CENSYS_API_KEY` requires a **Starter tier or higher** Censys Platform account — the free tier's API is lookup-only and cannot run the cert→host search. Certificate history additionally needs the Enterprise Adversary Investigation entitlement.
- `IP_INFO_KEY` enables [ipinfo.io Lite](https://ipinfo.io/lite) lookups (`utils/ipinfo_lite.py`), the **primary** ASN/org/country source for every associated IP — its values win over RDAP's whenever it succeeds, since RDAP errors/times out per-RIR fairly often and ipinfo Lite rarely does. RDAP (`get_ip_whois`) still always runs too, since ipinfo Lite's response doesn't include network name/CIDR, and both feed `detect_proxy_details` for edge-server/reverse-proxy classification. Missing key degrades gracefully to RDAP-only lookups.
- `MATTERMOST_WEBHOOK_URL` is optional. When set, the backend sends non-blocking alerts for analysis completion and failure.
- Email alerts are optional and mirror the Mattermost notifications. They are enabled only when both `SMTP_HOST` and `ALERT_EMAIL_TO` are set; otherwise sends are silent no-ops.
- `SMTP_PORT` defaults to `587` and `SMTP_STARTTLS` defaults to `true`. `SMTP_USERNAME`/`SMTP_PASSWORD` are optional (authentication is skipped when unset).
- `ALERT_EMAIL_TO` accepts a comma-separated list of recipients. `ALERT_EMAIL_FROM` sets the sender address. Email delivery runs in a background thread and never blocks or fails the caller.
