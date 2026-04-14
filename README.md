# IP Intel

Domain and IP OSINT tool for infrastructure reconnaissance and FIMI (Foreign Information Manipulation and Interference) analysis. Given a domain or IP, it queries multiple free and optional paid sources to map hosting infrastructure, discover origin IPs hidden behind Cloudflare, and surface attribution signals.

---

## Files

| File | Purpose |
|---|---|
| `ip_intel.py` | Core intelligence engine — all data collection, scanning, and analysis logic |
| `app.py` | Streamlit web UI frontend |
| `intel_db.py` | SQLite persistence layer — stores and cross-references every search |

For a detailed breakdown of every data source, what it returns, and what it cannot tell you, see [`PROVIDERS.md`](PROVIDERS.md).

---

## Setup

### 1. Install dependencies

```bash
uv sync
```

### 2. Configure API keys (optional)

```bash
cp .env.example .env
```

Edit `.env` and fill in keys for enhanced coverage:

```
CENSYS_API_KEY=<personal-access-token>
SHODAN_API_KEY=<your-api-key>
NETLAS_API_KEY=<your-api-key>
```

All three are optional. Without them the tool runs all free-tier sources.

### 3. Run

**Streamlit web UI:**

```bash
uv run streamlit run app.py
```

**CLI:**

```bash
uv run ip_intel.py example.com
uv run ip_intel.py 1.2.3.4
```

---

## How it works

Every analysis runs in two concurrent groups followed by optional active scans:

**Group 1** — all concurrent:
WHOIS · DNS (A/AAAA/MX/NS/TXT/SOA/CNAME) · crt.sh · CIRCL Passive DNS · page metadata · DMARC/DKIM

**Post-processing** (fast, no I/O):
SPF `ip4:`/`ip6:` extraction · CT subdomain split

**Group 2** — all concurrent:
Zone transfer · subdomain origin probe · MX origin probe · wordlist probe · HackerTarget hostsearch · urlscan.io · Censys · Shodan · Netlas

**Active scans** (opt-in, sequential):
Each runs a two-phase sweep — Phase 1 port scan via `masscan` (or async TCP fallback), Phase 2 TLS cert match on responsive hosts.

**IP enrichment + TLS probe** — all concurrent:
Every non-Cloudflare IP gets PTR · ASN/RDAP · HackerTarget reverse-IP · live TLS cert grab.

Results are persisted to `ip_intel.db` (SQLite).

---

## Data sources

### Always free (no key required)

| Source | What it provides |
|---|---|
| DNS (`dnspython`) | A, AAAA, MX, NS, TXT, SOA, CNAME records; PTR lookups; zone transfer attempts |
| WHOIS (`python-whois`) | Registrar, creation/expiry dates, registrant org/country/email |
| IP WHOIS / RDAP (`ipwhois`) | ASN, network org, country for every discovered IP |
| crt.sh | Certificate transparency — all subdomains via SANs, issuer history, cross-domain SANs |
| CIRCL Passive DNS | Historical A/AAAA records with first-seen / last-seen timestamps |
| HackerTarget | Subdomain + IP pairs (hostsearch); other domains on same server (reverse-IP) |
| urlscan.io | Historical scan snapshots — IPs that served the domain in the past |
| SPF parsing | `ip4:`/`ip6:` directives extracted as origin candidates (no extra DNS call) |
| DMARC / DKIM | Email auth policy; DKIM selector names reveal mail provider (Yandex, Google, M365) |
| Page metadata | GA/GTM IDs, Facebook/TikTok/Yandex Metrika pixels, social handles (Telegram, VK, OK, Twitter, TikTok, Instagram, Facebook, YouTube), CMS generator, favicon MD5 |
| RIPE Stat | Full IPv4 allocations per ASN or country — feeds active scans |
| GCP IP ranges | Live GCP CIDR list filtered by region |

### Optional (API key required)

| Source | Env var | What it adds |
|---|---|---|
| Censys | `CENSYS_API_KEY` | IPs currently presenting the domain's TLS cert (indexed scan data) |
| Shodan | `SHODAN_API_KEY` | Hosts matching `ssl:"domain"` in Shodan's banner database |
| Netlas | `NETLAS_API_KEY` | IPs serving matching TLS cert CN — free tier ~50 queries/day |

### Active scans (opt-in)

| Mode | Scope |
|---|---|
| Eastern-EU GCP | 7 GCP regions near Russia/Ukraine |
| All-EU GCP + Turkey | 14 GCP regions (13 European + me-west1 / Tel Aviv) |
| Global GCP | Every GCP region worldwide |
| Known RU/EU hosters | Hetzner, OVH, M247, Aeza, Selectel, TimeWeb, Beget, Serverius, Frantech, and more — IP ranges fetched live from RIPE Stat |
| All EU member states | IPv4 allocations for all 27 EU states via RIPE Stat |
| Custom countries | Any ISO-3166 country codes — full national IPv4 allocation |
| Full scan | EU countries + known providers + EU GCP combined |

Uses `masscan` if installed (`sudo apt install masscan`), falls back to async TCP otherwise.

---

## Output

**SQLite database** — `ip_intel.db`

Every search is persisted with normalised pivot tables so you can cross-reference across targets:

| Table | Contents |
|---|---|
| `searches` | One row per scan with full raw JSON |
| `ips` | Every IP seen, with source, ASN, country, PTR |
| `tls_certs` | Live-grabbed TLS certs with SHA-256 fingerprint |
| `ct_certs` | Certificate transparency records from crt.sh |
| `subdomains` | Subdomains from crt.sh and zone transfers |
| `dns_records` | Live DNS records |
| `historical_dns` | CIRCL pDNS records |
| `tracking_ids` | GA/GTM/FB pixel/TikTok/Yandex Metrika IDs |
| `social_accounts` | Social handles and URLs found on the page |

The Streamlit UI also exposes clustering views — find all scans sharing the same IP, TLS cert fingerprint, tracking ID, or favicon hash.

**JSON results** — `results/<domain>_<timestamp>.json`

Full structured output for every module, written alongside the database entry.

---

## masscan setup (optional, recommended for large scans)

```bash
sudo apt install masscan
sudo setcap cap_net_raw+ep $(which masscan)
```

The `setcap` command grants raw socket access without requiring `sudo` on every run. Without it the tool falls back to async TCP, which is slower but works without any extra permissions.
