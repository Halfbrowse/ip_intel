# IP Intel

Domain and IP OSINT tool for infrastructure reconnaissance and FIMI (Foreign Information Manipulation and Interference) analysis. Given a domain or IP, it aggregates data from multiple free and optional paid sources to map hosting infrastructure, discover origin IPs hidden behind CDNs like Cloudflare, and surface risk indicators.

---

## Tools

| File | Purpose |
|---|---|
| `ip_intel.py` | Core intelligence engine — DNS, WHOIS, crt.sh, passive DNS, Censys/Shodan/Netlas, origin IP scanning |
| `app.py` | Streamlit web UI frontend for `ip_intel.py` |
| `fimi_intel.py` | Standalone FIMI-focused scanner — lighter-weight, no API keys required, generates abuse report targets |

---

## Workflow

### 1. Install dependencies

```bash
uv sync
```

### 2. Configure API keys (optional but recommended)

Copy `.env.example` to `.env` and fill in keys for enhanced coverage:

```
CENSYS_API_KEY=<personal-access-token>
SHODAN_API_KEY=<your-api-key>
NETLAS_API_KEY=<your-api-key>
```

All three are optional. Without them the tool still runs all free-tier sources.

### 3. Run

**CLI — full analysis:**

```bash
uv run ip_intel.py example.com
```

**Streamlit web UI:**

```bash
uv run streamlit run app.py
```

**FIMI-only scan (no API keys needed):**

```bash
uv run fimi_intel.py example.com
uv run fimi_intel.py example.com --output report.json
```

---

## Data Sources

### Always free (no key required)

| Source | What it provides |
|---|---|
| `dnspython` | A, AAAA, MX, NS, TXT, SOA, CNAME, PTR records |
| `python-whois` | Domain registration, registrar, nameservers, age |
| `ipwhois` / RDAP | ASN, network org, country for an IP |
| crt.sh | Certificate transparency — subdomains via SANs, linked domains, CA history |
| HackerTarget | Reverse IP lookup — other domains on the same host |
| CIRCL Passive DNS | Historical DNS records |
| SPF record parsing | ip4: entries that leak origin IPs |
| urlscan.io | Historical scan IPs and page metadata |
| Wayback CDX | Snapshot history from Internet Archive |
| Common Crawl | Index presence check |
| Subdomain probing | ~20 common subdomains (mail, staging, api, …) resolved and checked against Cloudflare ranges |

### Optional (API key required)

| Source | Env var | What it adds |
|---|---|---|
| Censys | `CENSYS_API_KEY` | Search indexed TLS certs for IPs currently serving the domain's certificate |
| Shodan | `SHODAN_API_KEY` | Search indexed banners for `ssl:"domain"` hits |
| Netlas | `NETLAS_API_KEY` | Search TLS banners by cert CN — free tier available |

### Active scanning (opt-in in UI)

The Streamlit UI exposes scan modes that do targeted TCP+TLS sweeps of IP ranges to find the cert CN directly:

| Mode | Scope |
|---|---|
| Eastern-EU GCP | GCP regions closest to Russia/Ukraine (requires a GTS CA cert in history) |
| All-EU GCP + Turkey | All 14 European GCP regions + me-west1 |
| Known RU/EU hosters | Hetzner, OVH, M247, Aeza, Selectel, TimeWeb, Beget, Serverius, Frantech, etc. via RIPE Stat |
| All EU member states | IPv4 allocations for all 27 EU states via RIPE Stat |
| Full scan | EU countries + known providers + GCP Europe combined |
| Global GCP | Every GCP region worldwide |
| Custom countries | Any ISO-3166 country codes — fetches full national allocations from RIPE Stat |

Uses `masscan` if installed for speed, falls back to async TCP otherwise.

---

## Output

Results are saved to `results/<domain>_<date>.json`. The file contains structured output for every module: WHOIS, DNS, IP/ASN, certificate data, origin candidates with verification status, Wayback history, urlscan history, and a FIMI risk indicator summary.

---

## FIMI Risk Indicators

`fimi_intel.py` and `ip_intel.py` both flag:

- Domain registered less than 1 year ago
- Hosting in elevated-risk jurisdictions (RU, CN, BY, IR, KP)
- Exclusively Let's Encrypt certificates
- Other domains sharing the same certificate (infrastructure overlap)
- Confirmed live origin IPs (port 80/443 responds)
- Absent from Common Crawl index (possible crawler blocking)

The scan output also lists abuse report contacts for the detected hosting provider (AWS, Cloudflare, Hetzner, OVH, etc.) and links to ICANN, Google Safe Browsing, EUvsDisinfo, and EDMO.
