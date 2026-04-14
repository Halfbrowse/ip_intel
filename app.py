#!/usr/bin/env python3
"""
Streamlit frontend for ip-intel.
Run with:  uv run streamlit run app.py
"""
import queue
import sys
import threading
import time
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent))
import ip_intel  # noqa: E402  (local import after path fix)

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IP Intel",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .hit-box   { background:#1a3a1a; border-left:4px solid #4caf50; padding:10px 14px; border-radius:4px; margin:4px 0; font-family:monospace; font-size:0.85rem; }
    .warn-box  { background:#3a2a1a; border-left:4px solid #ff9800; padding:10px 14px; border-radius:4px; margin:4px 0; font-family:monospace; font-size:0.85rem; }
    .bad-box   { background:#3a1a1a; border-left:4px solid #f44336; padding:10px 14px; border-radius:4px; margin:4px 0; font-family:monospace; font-size:0.85rem; }
    .info-box  { background:#1a2a3a; border-left:4px solid #2196f3; padding:10px 14px; border-radius:4px; margin:4px 0; font-family:monospace; font-size:0.85rem; }
    .log-line  { font-family:monospace; font-size:0.82rem; color:#aaa; padding:1px 0; }
    .explainer { color:#888; font-size:0.85rem; margin-bottom:8px; }
</style>
""", unsafe_allow_html=True)

# ── Session state init ────────────────────────────────────────────────────────
_DEFAULTS = {
    "running":         False,
    "results":         None,
    "partial_results": {},
    "log_messages":    [],
    "error":           None,
    "log_q":           queue.Queue(),
}
for k, v in _DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("🔍 IP Intel")
    st.caption("Domain / IP OSINT & origin discovery")
    st.divider()

    target_input = st.text_input(
        "Target domain or IP",
        placeholder="news-pravda.com",
        disabled=st.session_state.running,
    )

    st.divider()
    st.subheader("Origin Discovery")
    st.caption("All scan modes use masscan (fast) if available, otherwise async TCP fallback.")

    scan          = st.checkbox("Eastern-EU GCP",   help="Scan GCP regions closest to Russia/Ukraine. Only runs if a GTS CA cert was found in crt.sh history.")
    scan_europe   = st.checkbox("All-EU GCP + Turkey", help="All 14 European GCP regions + me-west1 (Tel Aviv) for Turkey. Bypasses the GTS cert requirement.")
    scan_providers= st.checkbox("Known RU/EU hosters", help="Scans Hetzner, OVH, M247, Aeza, Selectel, TimeWeb, Beget, Serverius, Frantech and more via RIPE Stat. Good first pass for non-GCP Russian-adjacent infra.")
    scan_eu_countries = st.checkbox("All EU member states", help="Fetches IPv4 allocations for all 27 EU member states from RIPE Stat and scans for the cert.")
    scan_full     = st.checkbox("Full scan (everything)", help="Combines EU countries + known providers + GCP Europe in a single run. Longest but most thorough.")
    scan_all      = st.checkbox("Global GCP (very slow)", help="Scans every GCP region worldwide. Only useful if you have evidence the site was on GCP globally.")

    country_raw   = st.text_input(
        "Custom countries (ISO codes)",
        placeholder="RU UA BY",
        help="Space-separated ISO-3166 codes. Fetches full national IP allocations from RIPE Stat.",
    )

    st.divider()
    st.subheader("Performance")
    concurrency = st.number_input(
        "Async concurrency",
        min_value=100, max_value=50_000, value=5_000, step=500,
        help="Max simultaneous TCP/TLS connections used by the asyncio fallback (not masscan). Reduce if you see connection errors.",
    )
    rate = st.number_input(
        "masscan rate (pps)",
        min_value=100, max_value=500_000, value=100_000, step=1_000,
        help="Packets per second for masscan phase 1. Lower = kinder to your network. 100k is safe for most home/VPS connections.",
    )

    st.divider()
    run_btn = st.button(
        "🚀 Analyse" if not st.session_state.running else "⏳ Running…",
        type="primary",
        use_container_width=True,
        disabled=st.session_state.running,
    )
    providers_btn = st.button(
        "🏢 Providers only" if not st.session_state.running else "⏳ Running…",
        use_container_width=True,
        disabled=st.session_state.running,
        help="Skip DNS/WHOIS/CT lookup — jump straight to scanning Hetzner, OVH, M247, Aeza, Selectel, TimeWeb, Beget etc. for the cert.",
    )


# ── Background worker ─────────────────────────────────────────────────────────
def _run_analysis(target, kwargs, log_q):
    """Runs in a daemon thread. Puts ('log', msg), ('partial', key, val), ('done', result), or ('error', msg)."""
    original_log = ip_intel.log

    def _patched_log(msg):
        log_q.put(("log", msg))
        original_log(msg)

    def _on_partial(key, value):
        log_q.put(("partial", key, value))

    ip_intel.log = _patched_log
    try:
        if ip_intel.is_ip(target):
            result = ip_intel.analyze_ip(target)
        else:
            full_kwargs = dict(kwargs)
            full_kwargs["on_partial"] = _on_partial
            result = ip_intel.analyze_domain(target, **full_kwargs)
        log_q.put(("done", result))
    except Exception as exc:  # noqa: BLE001
        log_q.put(("error", str(exc)))
    finally:
        ip_intel.log = original_log


# ── Trigger analysis ──────────────────────────────────────────────────────────
def _start(target, kwargs):
    st.session_state.running         = True
    st.session_state.results         = None
    st.session_state.partial_results = {"input": target, "type": "domain", "origin_candidates": {}}
    st.session_state.log_messages    = []
    st.session_state.error           = None
    while not st.session_state.log_q.empty():
        st.session_state.log_q.get_nowait()
    t = threading.Thread(target=_run_analysis, args=(target, kwargs, st.session_state.log_q), daemon=True)
    t.start()
    st.session_state._thread = t

if run_btn and target_input and not st.session_state.running:
    scan_countries = [c.upper() for c in country_raw.split() if c] or None
    _start(target_input, dict(
        scan=scan,
        scan_europe=scan_europe,
        scan_all=scan_all,
        scan_providers=scan_providers,
        scan_eu_countries=scan_eu_countries,
        scan_full=scan_full,
        scan_countries=scan_countries,
        concurrency=int(concurrency),
        rate=rate,
    ))

if providers_btn and target_input and not st.session_state.running:
    _start(target_input, dict(
        scan=False,
        scan_europe=False,
        scan_all=False,
        scan_providers=True,
        scan_eu_countries=False,
        scan_full=False,
        scan_countries=None,
        concurrency=int(concurrency),
        rate=rate,
    ))


# ── Poll queue while running ──────────────────────────────────────────────────
if st.session_state.running:
    while not st.session_state.log_q.empty():
        item = st.session_state.log_q.get_nowait()
        kind = item[0]
        if kind == "log":
            st.session_state.log_messages.append(item[1])
        elif kind == "partial":
            _, key, value = item
            p = st.session_state.partial_results
            if "." in key:
                top, sub = key.split(".", 1)
                p.setdefault(top, {})[sub] = value
            else:
                p[key] = value
        elif kind == "done":
            st.session_state.results = item[1]
            st.session_state.running = False
        elif kind == "error":
            st.session_state.error   = item[1]
            st.session_state.running = False


# ── Helper render functions ───────────────────────────────────────────────────
def _cf_badge(is_cf):
    return "🟠 Cloudflare" if is_cf else "🟢 Non-Cloudflare"


def _explainer(text):
    st.markdown(f'<div class="explainer">{text}</div>', unsafe_allow_html=True)


def _hit_box(html, level="hit"):
    cls = {"hit": "hit-box", "warn": "warn-box", "bad": "bad-box", "info": "info-box"}.get(level, "info-box")
    st.markdown(f'<div class="{cls}">{html}</div>', unsafe_allow_html=True)


def render_live_overview(d: dict):
    """Render key findings from partial results as they stream in during a scan."""
    st.subheader(f"⚡ Live findings — {d.get('input', '')}")

    oc  = d.get("origin_candidates", {})
    dns = d.get("dns", {})
    w   = d.get("whois", {})
    ct  = d.get("cert_transparency", {})

    col1, col2, col3 = st.columns(3)

    # Registration
    with col1:
        if w and not w.get("error"):
            reg    = (w.get("registrar") or "?")
            if isinstance(reg, list): reg = reg[0]
            created = str(w.get("creation_date") or "?")[:10].strip("['")
            col1.metric("Registrar", str(reg)[:30])
            col1.metric("Created",   created)

    # Cloudflare / hosting
    with col2:
        a_records = dns.get("A", [])
        if a_records:
            all_cf = all(ip_intel.is_cloudflare_ip(ip) for ip in a_records)
            col2.metric("Cloudflare front", "Yes 🟠" if all_cf else "No 🟢")
        ct_count = ct.get("total_certs", 0)
        if ct_count:
            col2.metric("CT certs", ct_count)

    # Origin hits so far
    with col3:
        passive_leaks = (
            oc.get("subdomain_leaks", [])
            + oc.get("mx_leaks", [])
            + oc.get("wordlist_leaks", [])
        )
        scan_hits = sum(
            len(v.get("hits", [])) for v in (oc.get("scan"), oc.get("provider_scan"), oc.get("country_scan"))
            if isinstance(v, dict) and not v.get("skipped")
        )
        col3.metric("Origin leaks", len(passive_leaks))
        col3.metric("Scan hits",    scan_hits)

    # Cert issuers
    issuers = ct.get("issuers", [])
    if issuers:
        st.markdown("**Certificate issuers seen:**")
        for issuer in issuers:
            if "WE1" in issuer:
                st.markdown(f"  🟠 `{issuer}` — Cloudflare edge")
            elif "GTS" in issuer:
                _hit_box(f"🔵 <b>{issuer}</b> — Google Trust Services → was on GCP", "info")
            elif "Sectigo" in issuer or "Comodo" in issuer:
                _hit_box(f"🟢 <b>{issuer}</b> — Commercial CA, likely origin server", "hit")
            else:
                st.markdown(f"  ⚪ `{issuer}`")

    # Passive origin leaks (come in fast)
    for leak_key, icon, label in [
        ("subdomain_leaks", "🔓", "Subdomain leak"),
        ("mx_leaks",        "📧", "MX origin leak"),
        ("wordlist_leaks",  "🔍", "Wordlist hit"),
    ]:
        for l in oc.get(leak_key, []):
            _hit_box(f"{icon} <b>{label}:</b> {l.get('subdomain', l.get('ip'))} → <b>{l['ip']}</b>", "hit")

    # SPF origins
    for o in d.get("spf_origins", []):
        _hit_box(f"📬 <b>SPF ip4:</b> {o['ip']}  (cidr: <code>{o['cidr']}</code>)", "warn")

    # urlscan / hackertarget non-CF hits
    for h in oc.get("urlscan", []):
        if not h.get("cf"):
            _hit_box(f"🟢 <b>urlscan:</b> {h['ip']}  ({h.get('date', '?')})", "hit")
    for h in oc.get("hackertarget", []):
        if not h.get("cf"):
            _hit_box(f"🟢 <b>HackerTarget:</b> {h.get('subdomain')} → {h['ip']}", "hit")

    # Scan results as they arrive
    for key, label in [("scan", "GCP"), ("provider_scan", "Providers"), ("country_scan", "Country")]:
        r = oc.get(key)
        if isinstance(r, dict) and not r.get("skipped"):
            hits = r.get("hits", [])
            real = [h for h in hits if not h.get("cloudflare") and h.get("issuer") != "WE1"]
            if real:
                st.markdown(f"**{label} scan — {len(real)} origin candidate(s):**")
            for h in real:
                _hit_box(f"🟢 <b>{h.get('ip')}</b>:{h.get('port')}  CN=<b>{h.get('cn') or '?'}</b>  issuer=<i>{h.get('issuer','')}</i>", "hit")

    # Historical non-CF IPs from CIRCL
    hist_ips = [r for r in d.get("historical_dns", {}).get("records", []) if r.get("rrtype") in ("A", "AAAA") and not ip_intel.is_cloudflare_ip(r.get("rdata", ""))]
    for r in hist_ips:
        _hit_box(f"🕰 <b>Historical IP:</b> {r['rdata']}  last seen {r.get('last_seen', '?')}", "warn")


# ── Live progress view ────────────────────────────────────────────────────────
PHASES = [
    "WHOIS",
    "DNS",
    "crt.sh",
    "CIRCL pDNS",
    "Page metadata",
    "Subdomain probe",
    "MX probe",
    "Wordlist probe",
    "HackerTarget",
    "urlscan",
    "Censys",
    "Shodan",
    "Netlas",
    "Origin scan",
    "IP enrichment",
]
PHASE_KEYWORDS = {
    "WHOIS":           ["whois"],
    "DNS":             ["dns records"],
    "crt.sh":          ["certificate transparency", "crt.sh"],
    "CIRCL pDNS":      ["circl", "passive dns"],
    "Page metadata":   ["page metadata", "whois / dns / crt.sh / circl pdns / page metadata"],
    "Subdomain probe": ["subdomain probe"],
    "MX probe":        ["mx probe"],
    "Wordlist probe":  ["wordlist"],
    "HackerTarget":    ["hackertarget"],
    "urlscan":         ["urlscan"],
    "Censys":          ["censys"],
    "Shodan":          ["shodan"],
    "Netlas":          ["netlas"],
    "Origin scan":     ["origin scan", "masscan", "phase 1", "phase 2", "fetching gcp", "fetching ip ranges"],
    "IP enrichment":   ["ip enrichment", "ptr record", "asn"],
}

if st.session_state.running or (st.session_state.log_messages and not st.session_state.results):
    st.subheader("⏳ Analysis in progress…")

    # Determine current phase from log messages
    completed_phases = set()
    for msg in st.session_state.log_messages:
        ml = msg.lower()
        for phase, kws in PHASE_KEYWORDS.items():
            if any(kw in ml for kw in kws):
                completed_phases.add(phase)

    # Progress bar
    progress = len(completed_phases) / len(PHASES)
    st.progress(progress, text=f"Phase {len(completed_phases)}/{len(PHASES)}")

    # Log output
    log_container = st.container()
    with log_container:
        for msg in st.session_state.log_messages[-40:]:  # last 40 lines
            st.markdown(f'<div class="log-line">  [*] {msg}</div>', unsafe_allow_html=True)

    # ── Live overview while running ───────────────────────────────────────────
    partial = st.session_state.partial_results
    if partial and len(partial) > 3:   # more than just the stub keys
        st.divider()
        render_live_overview(partial)

    if st.session_state.running:
        time.sleep(0.4)
        st.rerun()


# ── Error state ───────────────────────────────────────────────────────────────
if st.session_state.error:
    st.error(f"Analysis failed: {st.session_state.error}")


# ── Results ───────────────────────────────────────────────────────────────────
def render_results(d: dict):
    target    = d.get("input", "")
    is_domain = d.get("type") == "domain"

    # ── Summary row ──────────────────────────────────────────────────────────
    st.header(f"Results: {target}")

    dns = d.get("dns", {})
    a_records = dns.get("A", [])
    all_cf = all(ip_intel.is_cloudflare_ip(ip) for ip in a_records) if a_records else False

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Type",      d.get("type", "").upper())
    c2.metric("Cloudflare front", "Yes" if all_cf else "No")

    oc = d.get("origin_candidates", {})
    total_hits = sum(
        len(oc.get(k, {}).get("hits", []))
        for k in ("scan", "provider_scan", "country_scan")
        if isinstance(oc.get(k), dict)
    ) + sum(
        len(oc.get(k, []))
        for k in ("subdomain_leaks", "mx_leaks", "wordlist_leaks")
    ) + len([h for h in oc.get("hackertarget", []) if not h.get("cf")]) + len([h for h in oc.get("urlscan", []) if not h.get("cf")])
    c3.metric("Origin hits found", total_hits)

    ct = d.get("cert_transparency", {})
    c4.metric("CT certs", ct.get("total_certs", 0))

    st.divider()

    tabs = st.tabs(["⚡ Overview", "🌐 WHOIS & DNS", "📜 Certificates", "🕰 Historical DNS", "🎯 Origin Discovery", "🖥 IP Details"])

    # ── Tab 0: Overview ───────────────────────────────────────────────────────
    with tabs[0]:
        st.subheader("Key Findings")

        w  = d.get("whois", {})
        oc = d.get("origin_candidates", {})
        ct = d.get("cert_transparency", {})

        # ── Registration ──────────────────────────────────────────────────────
        st.markdown("#### Registration")
        reg_c1, reg_c2, reg_c3 = st.columns(3)
        reg_c1.metric("Registrar",   (w.get("registrar") or "Unknown")[:40])
        reg_c2.metric("Created",     str(w.get("creation_date") or "?")[:10].replace("[", "").replace("'", ""))
        reg_c3.metric("Country",     w.get("country") or "?")

        emails = w.get("emails")
        if emails:
            if isinstance(emails, list):
                emails = ", ".join(emails)
            st.markdown(f"**Registrant emails:** `{emails}`")

        # ── Hosting / Cloudflare ──────────────────────────────────────────────
        st.markdown("#### Hosting")
        dns = d.get("dns", {})
        a_records = dns.get("A") or []
        all_cf = all(ip_intel.is_cloudflare_ip(ip) for ip in a_records) if a_records else False

        if all_cf:
            _hit_box("🟠 <b>Behind Cloudflare</b> — all A records are Cloudflare anycast IPs. The real origin IP is hidden.", "info")
        else:
            for ip in a_records:
                if not ip_intel.is_cloudflare_ip(ip):
                    _hit_box(f"🟢 <b>Direct IP exposed:</b> {ip} — not behind Cloudflare", "hit")

        ns = dns.get("NS") or []
        if any("cloudflare" in n.lower() for n in ns):
            st.caption("✅ DNS managed by Cloudflare nameservers")

        # ── TXT record intel ──────────────────────────────────────────────────
        txt_records = dns.get("TXT") or []
        interesting_txt = []
        for txt in txt_records:
            t = str(txt)
            if "google-site-verification" in t:
                interesting_txt.append(("Google Search Console", t, "Links to a specific Google account. Search for this token to find other domains owned by the same operator."))
            elif "ms=" in t.lower() or "ms=" in t:
                interesting_txt.append(("Microsoft 365", t, "Microsoft tenant verification token."))
            elif "tiktok-developers" in t:
                interesting_txt.append(("TikTok Developer", t, "TikTok API/developer account linked to this domain."))
            elif "apple-domain" in t:
                interesting_txt.append(("Apple", t, "Apple domain association token."))
            elif "loaderio=" in t:
                interesting_txt.append(("Loader.io", t, "Load testing service verification — operator uses loader.io."))
            elif "spf1" in t:
                interesting_txt.append(("SPF / Mail", t, "Mail sender policy — reveals which mail providers are used."))

        if interesting_txt:
            st.markdown("#### Attribution Tokens (TXT records)")
            _explainer("These tokens tie the domain to specific external accounts. The Google token in particular can be searched across other domains to map operator infrastructure.")
            for label, val, note in interesting_txt:
                _hit_box(f"<b>{label}:</b> <code>{val[:120]}</code><br><small>{note}</small>", "warn")

        # ── Certificate issuers ───────────────────────────────────────────────
        issuers = ct.get("issuers", [])
        if issuers:
            st.markdown("#### Certificate History")
            for issuer in issuers:
                if "WE1" in issuer:
                    st.markdown(f"- 🟠 `{issuer}` — Cloudflare edge cert (expected)")
                elif "GTS" in issuer:
                    _hit_box(f"🔵 <b>{issuer}</b> — Google Trust Services → site was or is hosted on GCP", "info")
                elif "Sectigo" in issuer or "Comodo" in issuer:
                    _hit_box(f"🟢 <b>{issuer}</b> — Commercial CA, typically issued directly to origin server", "hit")
                elif "Let's Encrypt" in issuer:
                    st.markdown(f"- 🔵 `{issuer}` — Let's Encrypt")
                else:
                    st.markdown(f"- ⚪ `{issuer}`")

        # ── Origin hits ───────────────────────────────────────────────────────
        all_hits = []
        for key in ("scan", "provider_scan", "country_scan"):
            r = oc.get(key, {})
            if isinstance(r, dict) and not r.get("skipped"):
                all_hits.extend(r.get("hits", []))
        all_hits.extend(
            {"ip": l["ip"], "cn": target, "issuer": "leak", "port": 443, "cloudflare": False, "sans": [], "not_before": "", "not_after": ""}
            for l in oc.get("subdomain_leaks", [])
        )

        if all_hits:
            st.markdown("#### Origin Server Candidates")
            # Separate real candidates from CF edge noise
            real = [h for h in all_hits if not h.get("cloudflare") and h.get("issuer") != "WE1"]
            edge = [h for h in all_hits if h.get("cloudflare") or h.get("issuer") == "WE1"]

            for h in real:
                issuer = h.get("issuer", "")
                is_mitm  = "mitmproxy" in issuer.lower()
                is_caddy = "caddy" in issuer.lower()
                level = "bad" if is_mitm else ("warn" if is_caddy else "hit")
                icon  = "🚨 MITMPROXY" if is_mitm else ("⚠️ Caddy local CA" if is_caddy else "🟢 ORIGIN CANDIDATE")
                _hit_box(
                    f"{icon} &nbsp; <b>{h.get('ip')}</b>:{h.get('port')}  &nbsp; "
                    f"CN=<b>{h.get('cn') or '(none)'}</b>  &nbsp; "
                    f"issuer=<i>{issuer}</i>",
                    level,
                )
            if edge:
                st.caption(f"+ {len(edge)} Cloudflare edge node(s) matched (expected false positives, see Origin Discovery tab)")
        elif any(
            isinstance(oc.get(k), dict) and not oc.get(k, {}).get("skipped")
            for k in ("scan", "provider_scan", "country_scan")
        ):
            st.info("Scans ran but found no cert matches. The origin may be on a provider not yet scanned, behind another proxy layer, or using SNI-based routing.")
        else:
            st.info("No origin scans run yet. Use the sidebar options to scan for the origin server.")

        # ── FIMI signals ──────────────────────────────────────────────────────
        meta  = d.get("page_metadata", {})
        email = d.get("email_security", {})

        fimi_section = (
            meta.get("yandex_metrika")
            or meta.get("html_lang")
            or meta.get("social_links")
            or meta.get("google_analytics")
            or meta.get("gtm_ids")
            or meta.get("facebook_pixel")
            or meta.get("cms_generator")
            or meta.get("favicon_md5")
            or email.get("dmarc")
            or email.get("dkim")
        )
        if fimi_section:
            st.markdown("#### FIMI Signals")
            _explainer(
                "Signals extracted from the domain's homepage and DNS that can reveal operator identity, "
                "infrastructure links, or Russian attribution."
            )

            # Yandex.Metrika — strong RU signal
            ym_ids = meta.get("yandex_metrika", [])
            if ym_ids:
                for ym in ym_ids:
                    _hit_box(
                        f"🇷🇺 <b>Yandex.Metrika</b> counter <code>{ym}</code> — "
                        "Russian analytics product. Operators in Russia/CIS use this instead of Google Analytics. "
                        "Cross-reference counter ID across other domains to map infrastructure.",
                        "bad",
                    )

            # HTML lang mismatch check
            html_lang = meta.get("html_lang")
            if html_lang:
                ru_langs = {"ru", "ru-ru", "ru-ua", "be", "uk"}
                if any(html_lang.startswith(l) for l in ru_langs):
                    _hit_box(
                        f"🇷🇺 <b>HTML lang=<code>{html_lang}</code></b> — "
                        "Page declares a Russian/Slavic language even if the domain appears Western.",
                        "bad",
                    )
                else:
                    # Check for mismatch if domain appears to target a specific country
                    st.caption(f"Page language: `{html_lang}`")

            # Social media handles
            handles  = meta.get("social_handles", {})
            links    = meta.get("social_links", {})
            _PLATFORM_META = {
                "telegram":       ("📢", "Telegram",       True),
                "vkontakte":      ("🔵", "VKontakte",      True),
                "odnoklassniki":  ("🟠", "Odnoklassniki",  True),
                "twitter_x":      ("🐦", "Twitter / X",    False),
                "tiktok":         ("🎵", "TikTok",         False),
                "instagram":      ("📸", "Instagram",      False),
                "facebook":       ("📘", "Facebook",       False),
                "youtube":        ("▶️",  "YouTube",        False),
                "linkedin":       ("💼", "LinkedIn",       False),
                "pinterest":      ("📌", "Pinterest",      False),
            }

            all_platforms = sorted(
                set(handles) | set(links),
                key=lambda k: (0 if _PLATFORM_META.get(k, ("","",False))[2] else 1, k),
            )

            if all_platforms:
                st.markdown("**Social Media Accounts**")
                _explainer("Account handles are useful for cross-domain attribution — the same handle appearing on multiple sites links them to a single operator.")
                for plat in all_platforms:
                    icon, label, is_ru = _PLATFORM_META.get(plat, ("🔗", plat.title(), False))
                    level = "warn" if is_ru else "info"
                    plat_handles = handles.get(plat, [])
                    plat_links   = links.get(plat, [])
                    display_handles = plat_handles[:5] or [l.split("/")[-1] for l in plat_links[:5]]
                    if display_handles:
                        handle_str = "  ".join(f"<code>@{h}</code>" for h in display_handles)
                        ru_note = " — <small>Russian platform</small>" if is_ru else ""
                        _hit_box(f"{icon} <b>{label}:</b> {handle_str}{ru_note}", level)

            # Tracking IDs — cross-domain pivot keys
            ga_ids  = meta.get("google_analytics", [])
            gtm_ids = meta.get("gtm_ids", [])
            fb_ids  = meta.get("facebook_pixel", [])
            tt_ids  = meta.get("tiktok_pixel", [])
            if ga_ids or gtm_ids or fb_ids or tt_ids:
                st.markdown("**Tracking IDs** *(search these to find other sites run by the same operator)*")
            for gid in ga_ids:
                _hit_box(f"📊 <b>Google Analytics:</b> <code>{gid}</code>", "info")
            for gid in gtm_ids:
                _hit_box(f"📦 <b>Google Tag Manager:</b> <code>{gid}</code>", "info")
            for fid in fb_ids:
                _hit_box(f"📘 <b>Facebook Pixel:</b> <code>{fid}</code>", "info")
            for tid in tt_ids:
                _hit_box(f"🎵 <b>TikTok Pixel:</b> <code>{tid}</code>", "info")

            # CMS / generator
            cms = meta.get("cms_generator")
            if cms:
                st.caption(f"CMS: `{cms}`")

            # Favicon hash — infrastructure fingerprinting
            fav_md5 = meta.get("favicon_md5")
            fav_saved = meta.get("favicon_saved")
            if fav_md5:
                _hit_box(
                    f"🖼 <b>Favicon MD5:</b> <code>{fav_md5}</code> — "
                    "Identical hash on another domain = strong shared-infrastructure signal.",
                    "info",
                )
                if fav_saved:
                    st.caption(f"Favicon saved locally: `{fav_saved}`")

            # DMARC
            dmarc = email.get("dmarc")
            if dmarc:
                _hit_box(f"📧 <b>DMARC:</b> <code>{dmarc[:200]}</code>", "info")
            else:
                _hit_box("⚠️ <b>No DMARC record</b> — domain can be spoofed in phishing emails", "warn")

            # DKIM — flag Yandex mail infrastructure
            dkim = email.get("dkim", {})
            for sel, val in dkim.items():
                level = "bad" if sel == "yandex" else "info"
                icon  = "🇷🇺" if sel == "yandex" else "📧"
                _hit_box(f"{icon} <b>DKIM ({sel}):</b> <code>{val[:120]}</code>", level)

        # ── Historical IPs ────────────────────────────────────────────────────
        hist_ips = [
            r for r in d.get("historical_dns", {}).get("records", [])
            if r.get("rrtype") in ("A", "AAAA") and not ip_intel.is_cloudflare_ip(r.get("rdata", ""))
        ]
        if hist_ips:
            st.markdown("#### Historical Non-Cloudflare IPs (CIRCL pDNS)")
            _explainer("These IPs predate Cloudflare and may be the real origin server.")
            for r in hist_ips:
                _hit_box(f"🕰 <b>{r['rdata']}</b> — last seen: {r.get('last_seen', '?')}", "warn")

    # ── Tab 1: WHOIS & DNS ────────────────────────────────────────────────────
    with tabs[1]:
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("WHOIS")

            _explainer("Registration data for the domain. Key FIMI indicators: registrar jurisdiction, creation date, privacy protection, registrant emails.")
            w = d.get("whois", {})
            if w.get("error"):
                st.warning(f"WHOIS error: {w['error']}")
            else:
                fields = {
                    "Registrar":      w.get("registrar"),
                    "Created":        w.get("creation_date"),
                    "Expires":        w.get("expiry_date"),
                    "Updated":        w.get("updated_date"),
                    "Org":            w.get("org"),
                    "Country":        w.get("country"),
                    "Nameservers":    w.get("nameservers"),
                    "Status":         w.get("status"),
                    "Emails":         w.get("emails"),
                }
                for label, val in fields.items():
                    if val:
                        if isinstance(val, list):
                            val = ", ".join(str(v) for v in val[:5])
                        st.markdown(f"**{label}:** {val}")

        with col2:
            st.subheader("DNS Records")
            _explainer("Live DNS records. A/AAAA pointing to Cloudflare IPs confirms the site is proxied. TXT records often leak service verifications (Google, Microsoft, TikTok) which can be used to attribute the operator across domains.")

            for rtype in ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA"):
                val = dns.get(rtype)
                if not val:
                    continue
                with st.expander(f"{rtype} records"):
                    if isinstance(val, list):
                        for item in val:
                            if rtype == "A" and ip_intel.is_cloudflare_ip(str(item)):
                                st.markdown(f"`{item}` 🟠 Cloudflare")
                            elif rtype == "TXT":
                                st.code(str(item), language=None)
                            else:
                                st.markdown(f"`{item}`" if not isinstance(item, dict) else str(item))
                    elif isinstance(val, dict):
                        for k, v in val.items():
                            st.markdown(f"**{k}:** `{v}`")

            zt = d.get("zone_transfer", [])
            if zt:
                _hit_box(f"⚠️ Zone transfer succeeded! {len(zt)} records exposed: {', '.join(zt[:10])}", "warn")
            else:
                st.caption("Zone transfer: refused (normal)")

    # ── Tab 2: Certificates ───────────────────────────────────────────────────
    with tabs[2]:
        st.subheader("Certificate Transparency (crt.sh)")
        _explainer(
            "crt.sh logs every TLS certificate issued for a domain via public CT logs. "
            "Key indicators: <b>WE1</b> = Cloudflare edge cert (not origin). "
            "<b>GTS CA</b> = Google Cloud hosting. "
            "<b>Sectigo</b> = commercial CA, often origin server. "
            "<b>Cross-domain SANs</b> = other domains sharing infrastructure with this one."
        )

        issuers = ct.get("issuers", [])
        if issuers:
            st.markdown("**Certificate Authorities seen:**")
            for issuer in issuers:
                if "WE1" in issuer:
                    _hit_box(f"🟠 {issuer} — Cloudflare edge cert (terminates at CF, not origin)", "info")
                elif "GTS" in issuer:
                    _hit_box(f"🔵 {issuer} — Google Trust Services → likely hosted on GCP", "info")
                elif "Sectigo" in issuer or "Comodo" in issuer:
                    _hit_box(f"🟢 {issuer} — Commercial CA, often used by origin server directly", "hit")
                elif "Let's Encrypt" in issuer:
                    _hit_box(f"🔵 {issuer} — Let's Encrypt (free, auto-renewing)", "info")
                else:
                    _hit_box(f"⚪ {issuer}", "info")

        cross_sans = ct.get("cross_domain_sans", [])
        if cross_sans:
            st.markdown("**Cross-domain SANs** (other domains on the same cert — strong infrastructure link):")
            for san in cross_sans[:20]:
                _hit_box(f"🔗 {san}", "warn")

        subs = d.get("subdomains", ct.get("subdomains", []))
        if subs:
            st.markdown(f"**Subdomains found ({len(subs)}):**")
            st.code("\n".join(subs))

        certs = ct.get("certs", [])
        if certs:
            with st.expander(f"All {len(certs)} certificates (newest first)"):
                for c in certs:
                    issuer = c.get("issuer", "")
                    colour = "🟠" if "WE1" in issuer else ("🔵" if "GTS" in issuer else "🟢")
                    st.markdown(
                        f"{colour} `{(c.get('not_before') or '')[:10]}` → `{(c.get('not_after') or '')[:10]}`  "
                        f"**{issuer}**  SANs: `{', '.join(c.get('sans', []))}`"
                    )

    # ── Tab 3: Historical DNS ─────────────────────────────────────────────────
    with tabs[3]:
        st.subheader("Historical / Passive DNS (CIRCL pDNS)")
        _explainer(
            "CIRCL pdns.circl.lu records historical DNS resolutions. "
            "IPs that predate the current Cloudflare records may be the true origin server — "
            "the operator may have moved behind Cloudflare after setting up."
        )
        hist = d.get("historical_dns", {})
        records = [r for r in hist.get("records", []) if r.get("rrtype") in ("A", "AAAA")]
        if records:
            for r in records:
                ip = r.get("rdata", "")
                cf = ip_intel.is_cloudflare_ip(ip)
                badge = "🟠 CF" if cf else "🟢 Non-CF"
                st.markdown(
                    f"`{ip}` {badge} — first: `{r.get('first_seen', '?')}` last: `{r.get('last_seen', '?')}`"
                )
        else:
            st.info("No historical A/AAAA records found in CIRCL pDNS. The domain may have been behind Cloudflare its entire life.")

    # ── Tab 4: Origin Discovery ───────────────────────────────────────────────
    with tabs[4]:
        st.subheader("Origin Server Discovery")
        _explainer(
            "Multiple methods attempt to find the real server IP behind Cloudflare. "
            "A <b>cert match</b> means a host answered TLS with a cert CN/SAN matching your target domain — "
            "strong evidence it is the origin server or a mirror. "
            "WE1-issued hits are Cloudflare edge nodes (false positives). "
            "Sectigo / Let's Encrypt hits on non-Cloudflare IPs are genuine candidates."
        )

        # Subdomain leaks (crt.sh)
        leaks = oc.get("subdomain_leaks", [])
        st.markdown("#### Subdomain leaks (crt.sh)")
        _explainer("Subdomains from crt.sh that resolve to non-Cloudflare IPs. The operator forgot to proxy these through CF, exposing the real hosting IP.")
        if leaks:
            for l in leaks:
                _hit_box(f"🔓 <b>{l['subdomain']}</b> → {l['ip']}", "hit")
        else:
            st.caption("No leaks found.")

        # MX record origin leaks
        mx_leaks = oc.get("mx_leaks", [])
        st.markdown("#### MX record origin leaks")
        _explainer("MX hostnames that resolve to non-Cloudflare IPs. Mail servers are often co-hosted with the web server but left unproxied.")
        if mx_leaks:
            for l in mx_leaks:
                _hit_box(f"📧 <b>{l['subdomain']}</b> → {l['ip']}", "hit")
        else:
            st.caption("No MX leaks found.")

        # Wordlist subdomain probe
        wlist_leaks = oc.get("wordlist_leaks", [])
        st.markdown("#### Wordlist subdomain probe")
        _explainer("Probes common subdomains (direct, origin, mail, smtp, staging, dev…) not necessarily in CT logs. Catches origins that were never cert-logged.")
        if wlist_leaks:
            for l in wlist_leaks:
                _hit_box(f"🔍 <b>{l['subdomain']}</b> → {l['ip']}", "hit")
        else:
            st.caption("No wordlist leaks found.")

        # SPF origins
        spf_origins = d.get("spf_origins", [])
        st.markdown("#### SPF record ip4/ip6 directives")
        _explainer("IP addresses explicitly listed in the SPF record. These are authorised mail senders and often reveal the real hosting IP or mail relay.")
        if spf_origins:
            for o in spf_origins:
                _hit_box(f"📬 <b>{o['ip']}</b> (cidr: <code>{o['cidr']}</code>)", "warn")
        else:
            st.caption("No SPF ip4/ip6 directives found.")

        # HackerTarget hostsearch
        ht_results = oc.get("hackertarget", [])
        non_cf_ht  = [r for r in ht_results if not r.get("cf")]
        st.markdown(f"#### HackerTarget hostsearch — {len(ht_results)} subdomains, {len(non_cf_ht)} non-Cloudflare")
        _explainer("HackerTarget hostsearch returns subdomains and their current IPs. Non-Cloudflare results are direct origin candidates.")
        if ht_results:
            for r in ht_results:
                badge = "🟠" if r.get("cf") else "🟢"
                level = "info" if r.get("cf") else "hit"
                _hit_box(f"{badge} <b>{r['subdomain']}</b> → {r['ip']}", level)
        else:
            st.caption("No results (rate limit or no subdomains found).")

        # urlscan historical IPs
        us_results = oc.get("urlscan", [])
        non_cf_us  = [r for r in us_results if not r.get("cf")]
        st.markdown(f"#### urlscan.io historical IPs — {len(us_results)} snapshots, {len(non_cf_us)} non-Cloudflare")
        _explainer("IPs seen serving the domain in historical urlscan scans. Pre-Cloudflare snapshots often show the real origin IP.")
        if us_results:
            for r in us_results:
                badge = "🟠" if r.get("cf") else "🟢"
                level = "info" if r.get("cf") else "hit"
                _hit_box(
                    f"{badge} <b>{r['ip']}</b>  ({r.get('date', '?')})  "
                    f"<small>{r.get('url', '')[:80]}</small>",
                    level,
                )
        else:
            st.caption("No urlscan results found.")

        # API results
        for svc, label, note in [
            ("censys", "Censys", "Searches Censys Platform for hosts with a cert CN matching the domain. Requires paid plan."),
            ("shodan",  "Shodan",  "Searches Shodan's ssl: filter. Requires paid plan."),
            ("netlas",  "Netlas",  "Searches Netlas for cert CN matches. Free tier available but often restricted."),
        ]:
            r = oc.get(svc, {})
            with st.expander(f"{label} — {len(r.get('hits', []))} hits"):
                _explainer(note)
                if r.get("skipped"):
                    st.caption(f"Skipped: {r.get('reason')}")
                elif r.get("error"):
                    st.warning(f"Error: {r['error']}")
                else:
                    for h in r.get("hits", []):
                        _hit_box(
                            f"{'🟠' if h.get('cloudflare') else '🟢'} {h.get('ip')}  "
                            f"ASN: {h.get('asn') or h.get('asn_name','?')}  "
                            f"Country: {h.get('country','?')}",
                            "info" if h.get("cloudflare") else "hit",
                        )

        # Scan results (GCP, providers, countries)
        for key, label, note in [
            ("scan",          "GCP scan",      "Two-phase TCP+TLS scan of Google Cloud IP ranges. Uses masscan for phase 1 if available."),
            ("provider_scan", "Provider scan", "Two-phase scan of Hetzner, OVH, M247, Aeza, Selectel, TimeWeb, Beget, Serverius, Frantech and more."),
            ("country_scan",  "Country scan",  "Two-phase scan of national IPv4 allocations fetched live from RIPE Stat."),
        ]:
            r = oc.get(key, {})
            if not r or r.get("skipped"):
                continue

            hits = r.get("hits", [])
            st.markdown(f"#### {label}")
            _explainer(note)

            mc1, mc2, mc3, mc4 = st.columns(4)
            mc1.metric("CIDRs scanned",   f"{r.get('cidrs_scanned', 0):,}")
            mc2.metric("IPs attempted",   f"{r.get('hosts_attempted', 0):,}")
            mc3.metric("Port 443 open",   f"{r.get('open_port_count', 0):,}")
            mc4.metric("Cert matches",    len(hits))

            if hits:
                for h in hits:
                    issuer = h.get("issuer", "")
                    is_cf  = h.get("cloudflare", False)
                    is_mitm = "mitmproxy" in issuer.lower() or "mitm" in issuer.lower()
                    is_caddy = "caddy" in issuer.lower()
                    is_we1   = issuer == "WE1"

                    if is_mitm:
                        level, icon = "bad", "🚨 MITMPROXY"
                    elif is_we1 or is_cf:
                        level, icon = "info", "🟠 CF edge"
                    elif is_caddy:
                        level, icon = "warn", "⚠️ Caddy local CA"
                    else:
                        level, icon = "hit", "🟢 ORIGIN CANDIDATE"

                    _hit_box(
                        f"{icon}  <b>{h.get('ip')}</b>:{h.get('port')}  "
                        f"CN=<b>{h.get('cn') or '(none)'}</b>  "
                        f"issuer=<i>{issuer}</i>  "
                        f"valid {(h.get('not_before') or '')[:10]} → {(h.get('not_after') or '')[:10]}",
                        level,
                    )
            else:
                st.caption("No cert matches found.")

    # ── Tab 5: IP Details ─────────────────────────────────────────────────────
    _SOURCE_LABELS = {
        "dns":             "DNS record",
        "hackertarget":    "HackerTarget",
        "wordlist_probe":  "Wordlist probe",
        "mx_record":       "MX record",
        "subdomain_probe": "Subdomain probe",
        "urlscan":         "urlscan.io",
    }

    with tabs[5]:
        st.subheader("IP Details — All Discovered IPs")
        _explainer(
            "PTR, ASN/network info, and co-hosted domains for every IP surfaced during analysis — "
            "direct DNS records <i>and</i> IPs found via HackerTarget, wordlist probes, MX records, "
            "subdomain probes, and urlscan history. "
            "The <b>Source</b> field shows which method(s) found each IP. "
            "For Cloudflare anycast IPs, reverse-IP and RDAP are skipped — "
            "millions of sites share the same IP so results would be meaningless."
        )
        ip_details = d.get("ip_details", {})
        if not ip_details:
            if not is_domain:
                # IP target — show top-level fields
                cf = d.get("cloudflare", False)
                st.markdown(f"**Cloudflare:** {'Yes 🟠' if cf else 'No 🟢'}")
                st.markdown(f"**PTR:** `{d.get('ptr') or '(none)'}`")
                asn = d.get("asn_info", {})
                for k, v in asn.items():
                    if v: st.markdown(f"**{k}:** `{v}`")
                others = d.get("other_domains_on_ip", [])
                if others:
                    st.markdown(f"**Co-hosted domains ({len(others)}):**")
                    st.code("\n".join(others[:50]))
            else:
                st.info("No IP details recorded.")
        else:
            # Split into DNS-only IPs vs discovered IPs for clearer layout
            dns_ips        = {ip: info for ip, info in ip_details.items() if info.get("sources") == ["dns"] or info.get("sources") is None}
            discovered_ips = {ip: info for ip, info in ip_details.items() if ip not in dns_ips}

            def _render_ip_entry(ip: str, info: dict) -> None:
                cf  = info.get("cloudflare", False)
                asn = info.get("asn_info", {})
                sources = info.get("sources", [])
                source_str = ", ".join(_SOURCE_LABELS.get(s, s) for s in sources)
                label = f"{ip}  {'🟠 Cloudflare' if cf else '🟢 ' + (asn.get('asn_description') or 'Unknown')}"
                with st.expander(label):
                    if source_str:
                        st.markdown(f"**Source:** `{source_str}`")
                    st.markdown(f"**PTR:** `{info.get('ptr') or '(none)'}`")
                    st.markdown(f"**Cloudflare:** {'Yes' if cf else 'No'}")
                    for k, v in asn.items():
                        if v:
                            st.markdown(f"**{k}:** `{v}`")
                    others = info.get("other_domains_on_ip", [])
                    if others:
                        st.markdown(f"**Co-hosted domains ({len(others)}):**")
                        _explainer("Other domains resolving to the same IP via HackerTarget reverse-IP. Useful for finding related infrastructure or attributing shared hosting.")
                        st.code("\n".join(others[:50]))

            if dns_ips:
                st.markdown(f"#### DNS-resolved IPs ({len(dns_ips)})")
                for ip, info in dns_ips.items():
                    _render_ip_entry(ip, info)

            if discovered_ips:
                non_cf_count = sum(1 for info in discovered_ips.values() if not info.get("cloudflare"))
                st.markdown(f"#### Discovered IPs ({len(discovered_ips)} total, {non_cf_count} non-Cloudflare)")
                _explainer("IPs found through origin discovery methods — HackerTarget hostsearch, wordlist subdomain probes, MX resolution, subdomain probes, and urlscan history.")
                for ip, info in discovered_ips.items():
                    _render_ip_entry(ip, info)

    # ── Raw JSON download ─────────────────────────────────────────────────────
    st.divider()
    st.download_button(
        "⬇️ Download full JSON",
        data=__import__("json").dumps(d, indent=2, default=str),
        file_name=f"{target}_{d.get('timestamp', '')[:10]}.json",
        mime="application/json",
    )


# ── Render results or welcome screen ─────────────────────────────────────────
if st.session_state.results:
    render_results(st.session_state.results)
elif not st.session_state.running:
    st.markdown("## Enter a domain or IP in the sidebar and click **Analyse**")
    st.markdown("""
| What it checks | Why it matters |
|---|---|
| **WHOIS** | Registrar jurisdiction, creation date, privacy protection, registrant emails |
| **DNS records** | Current hosting, mail provider, service verification tokens (Google, TikTok, MS) |
| **Certificate Transparency** | All certs ever issued — reveals hosting history, CA choice, co-hosted domains |
| **Historical DNS (CIRCL pDNS)** | Past IPs before Cloudflare was added — may expose the real origin |
| **Subdomain leak check** | Subdomains that bypass Cloudflare proxy and expose the origin directly |
| **Provider scan** | Scans Hetzner, OVH, M247, Aeza, Selectel, TimeWeb etc. for the cert |
| **Country scan** | Scans all national IPv4 allocations (e.g. RU, UA, BY) for the cert |
| **GCP scan** | Scans Google Cloud IP ranges — useful when GTS CA certs appear in history |

**Cert issuer cheat-sheet:**
- 🟠 `WE1` — Cloudflare's own CA, issued to Cloudflare edge nodes. Not the origin.
- 🔵 `GTS CA` — Google Trust Services → the origin is (or was) on GCP.
- 🟢 `Sectigo` / `Let's Encrypt` — issued directly to the origin server. Real hit.
- 🚨 `mitmproxy` — someone is running a man-in-the-middle proxy for this domain.
- ⚠️ `Caddy Local Authority` — an internal/self-signed Caddy cert. Usually a dev box or internal proxy.
""")
