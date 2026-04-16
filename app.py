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
import streamlit.components.v1 as _st_components

sys.path.insert(0, str(Path(__file__).parent))
import ip_intel  # noqa: E402  (local import after path fix)
from intel_db import (  # noqa: E402
    get_recent,
    get_by_id,
    cluster_by_ip,
    cluster_by_tracking_id,
    cluster_by_favicon,
    cluster_by_tls_cert,
    get_domains_with_source_errors,
    get_connections_for_target,
)

# ── OpenCTI ingestion ─────────────────────────────────────────────────────────
# Starts once per process (daemon thread). Safe to import even if pycti /
# OPENCTI_URL are not configured — it exits silently in that case.
try:
    import opencti_ingest as _oci
    _oci.start_background_ingestion()
except Exception as e:
    import logging
    logging.getLogger("app").warning("OpenCTI ingestion failed to start: %s", e)

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
    "last_db_id":      None,
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

    # ── OpenCTI ingestion controls ────────────────────────────────────────────
    st.divider()
    st.subheader("OpenCTI Ingestion")
    try:
        import opencti_ingest as _oci_ctrl
        _oci_status = _oci_ctrl.get_ingestion_status()
        if _oci_status["running"]:
            _done  = _oci_status["done"]
            _total = _oci_status["total"]
            _cur   = _oci_status["current"] or "…"
            st.progress(_done / max(_total, 1), text=f"{_done}/{_total}")
            st.caption(f"⏳ {_cur}")
        else:
            if _oci_status["completed_at"]:
                st.caption(
                    f"Last run: {_oci_status['completed_at']}  "
                    f"({_oci_status['done']} analysed, {_oci_status['skipped']} skipped)"
                )
                if _oci_status["last_error"]:
                    st.caption(f"⚠ Last error: {_oci_status['last_error'][:60]}")
            else:
                st.caption("Not yet run this session.")

        _ingest_disabled = _oci_status["running"]
        _col_a, _col_b = st.columns(2)
        if _col_a.button("▶ Run", use_container_width=True, disabled=_ingest_disabled,
                         help="Fetch domains from OpenCTI and analyse any not already in the DB."):
            if _oci_ctrl.restart_ingestion(force_reanalyse=False):
                st.toast("OpenCTI ingestion started.")
            else:
                st.toast("Already running.")
        if _col_b.button("🔄 Re-run all", use_container_width=True, disabled=_ingest_disabled,
                         help="Re-analyse every domain from OpenCTI, even those already in the DB."):
            if _oci_ctrl.restart_ingestion(force_reanalyse=True):
                st.toast("Full re-ingestion started.")
            else:
                st.toast("Already running.")
    except ImportError:
        st.caption("opencti_ingest not available.")


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
    "TLS probe",
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
    "TLS probe":       ["tls probe"],
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
def _hosting_label(ip: str, ip_details: dict) -> str:
    """Return a short hosting/ASN description for a non-CF IP, or empty string."""
    info = ip_details.get(ip, {})
    asn  = info.get("asn_info", {})
    return asn.get("asn_description") or asn.get("network_name") or ""


def _tls_line(ip: str, tls_by_ip: dict) -> str:
    """Return an inline TLS cert summary for an IP, or empty string if none."""
    cert = tls_by_ip.get(ip)
    if not cert:
        return ""
    issuer = cert.get("issuer_cn") or cert.get("issuer_org") or "Unknown CA"
    cn     = cert.get("cn") or "(no CN)"
    expiry = (cert.get("not_after") or "")[:10]
    return f"🔐 CN=<b>{cn}</b> issuer=<i>{issuer}</i> expires={expiry}"


def render_results(d: dict):
    target     = d.get("input", "")
    is_domain  = d.get("type") == "domain"
    ip_details = d.get("ip_details", {})
    tls_by_ip  = {c["ip"]: c for c in (d.get("non_cf_tls_certs") or []) if c.get("ip")}

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
                    _host = _hosting_label(ip, ip_details)
                    _host_str = f" — {_host}" if _host else " — not behind Cloudflare"
                    _tls = _tls_line(ip, tls_by_ip)
                    _tls_str = f"<br>{_tls}" if _tls else ""
                    _hit_box(f"🟢 <b>Direct IP exposed:</b> {ip}{_host_str}{_tls_str}", "hit")

        # ── Non-CF TLS certs (live-grabbed) ───────────────────────────────────
        tls_list = d.get("non_cf_tls_certs") or (
            [d["tls_cert"]] if d.get("tls_cert") else []
        )
        if tls_list:
            st.markdown("#### Live TLS Certificates")
            for cert in tls_list:
                if not cert:
                    continue
                issuer = cert.get("issuer_cn") or cert.get("issuer_org") or "Unknown CA"
                cn     = cert.get("cn") or "(no CN)"
                sans   = cert.get("sans") or []
                sha    = cert.get("sha256", "")
                nb     = (cert.get("not_before") or "")[:10]
                na     = (cert.get("not_after")  or "")[:10]
                _hit_box(
                    f"🔐 <b>{cert['ip']}:{cert.get('port',443)}</b> &nbsp; "
                    f"CN=<b>{cn}</b><br>"
                    f"SANs: <code>{', '.join(sans[:8])}</code><br>"
                    f"Issuer: <i>{issuer}</i> &nbsp; valid {nb} → {na}<br>"
                    f"SHA-256: <code>{sha}</code>",
                    "hit",
                )

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
            for label, val, note in interesting_txt:
                _hit_box(f"<b>{label}:</b> <code>{val[:120]}</code><br><small>{note}</small>", "warn")

        # ── Certificate issuers ───────────────────────────────────────────────
        issuers = ct.get("issuers", [])
        if issuers:
            st.markdown("#### Certificate History")
            st.caption(
                "WE1 = Cloudflare edge (noise)  |  GTS = Google Trust Services → was on GCP  |  "
                "Sectigo/Comodo/DigiCert = commercial CA → origin server  |  "
                "Let's Encrypt R-series = free auto-renewing cert → likely origin  |  "
                "mitmproxy/Burp = interception proxy (red flag)"
            )
            for issuer in issuers:
                if "WE1" in issuer:
                    st.markdown(f"- 🟠 `{issuer}` — Cloudflare edge cert (expected if CF-fronted, not the origin)")
                elif "GTS" in issuer:
                    _hit_box(f"🔵 <b>{issuer}</b> — Google Trust Services: site was or is hosted on GCP / Google infrastructure", "info")
                elif "Sectigo" in issuer or "Comodo" in issuer:
                    _hit_box(f"🟢 <b>{issuer}</b> — Commercial CA, typically issued directly to origin server (strong signal)", "hit")
                elif "DigiCert" in issuer:
                    _hit_box(f"🟢 <b>{issuer}</b> — DigiCert commercial CA, typically on origin server or enterprise hosting", "hit")
                elif "Let's Encrypt" in issuer:
                    _hit_box(f"🔵 <b>{issuer}</b> — Let's Encrypt free cert (auto-renewing) — often the real origin server; R10-R14 are current CA intermediates", "info")
                elif "mitmproxy" in issuer.lower() or "burp" in issuer.lower():
                    _hit_box(f"🚨 <b>{issuer}</b> — INTERCEPTION PROXY cert — traffic was being inspected by a proxy tool", "bad")
                elif "ZeroSSL" in issuer:
                    _hit_box(f"🔵 <b>{issuer}</b> — ZeroSSL free cert (similar to Let's Encrypt, often origin server)", "info")
                elif "Amazon" in issuer or "ARCA" in issuer:
                    st.markdown(f"- 🟠 `{issuer}` — Amazon CA → hosted on AWS (CloudFront or EC2/ELB)")
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
            st.markdown("#### Historical Non-Cloudflare IPs")
            for r in hist_ips:
                _ip   = r['rdata']
                _host = _hosting_label(_ip, ip_details)
                _host_str = f" — {_host}" if _host else ""
                _tls = _tls_line(_ip, tls_by_ip)
                _tls_str = f"<br>{_tls}" if _tls else ""
                _hit_box(f"🕰 <b>{_ip}</b>{_host_str} — last seen: {r.get('last_seen', '?')}{_tls_str}", "warn")

    # ── Tab 1: WHOIS & DNS ────────────────────────────────────────────────────
    with tabs[1]:
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("WHOIS")
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

    # ── Tab 2: Certificates ───────────────────────────────────────────────────
    with tabs[2]:
        st.subheader("Certificate Transparency (crt.sh)")

        issuers = ct.get("issuers", [])
        if issuers:
            st.markdown("**Certificate Authorities seen:**")
            st.caption(
                "WE1 = Cloudflare edge (noise, not origin)  |  GTS = Google Trust Services → was on GCP  |  "
                "Sectigo/Comodo/DigiCert = commercial CA → origin server  |  "
                "Let's Encrypt R-series = free auto-renewing → often origin  |  "
                "Amazon = AWS (CloudFront or ELB)  |  mitmproxy/Burp = interception proxy"
            )
            for issuer in issuers:
                if "WE1" in issuer:
                    _hit_box(f"🟠 {issuer} — Cloudflare edge cert (terminates at CF, not the real origin server)", "info")
                elif "GTS" in issuer:
                    _hit_box(f"🔵 {issuer} — Google Trust Services → site was or is hosted on GCP/Google infrastructure", "info")
                elif "Sectigo" in issuer or "Comodo" in issuer:
                    _hit_box(f"🟢 {issuer} — Commercial CA, typically issued to origin server directly (strong signal)", "hit")
                elif "DigiCert" in issuer:
                    _hit_box(f"🟢 {issuer} — DigiCert commercial CA — origin server or enterprise hosting", "hit")
                elif "Let's Encrypt" in issuer:
                    _hit_box(f"🔵 {issuer} — Let's Encrypt free cert (R10-R14 = current intermediates) — likely the real origin server", "info")
                elif "mitmproxy" in issuer.lower() or "burp" in issuer.lower():
                    _hit_box(f"🚨 {issuer} — INTERCEPTION PROXY cert — traffic was being inspected", "bad")
                elif "ZeroSSL" in issuer:
                    _hit_box(f"🔵 {issuer} — ZeroSSL free cert (similar to Let's Encrypt) — often origin server", "info")
                elif "Amazon" in issuer or "ARCA" in issuer:
                    _hit_box(f"🟠 {issuer} — Amazon CA → hosted on AWS (CloudFront CDN or EC2/ELB origin)", "info")
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
        st.subheader("Historical / Passive DNS")
        hist = d.get("historical_dns", {})
        records = [r for r in hist.get("records", []) if r.get("rrtype") in ("A", "AAAA")]
        if records:
            for r in records:
                ip = r.get("rdata", "")
                cf = ip_intel.is_cloudflare_ip(ip)
                badge = "🟠 CF" if cf else "🟢 Non-CF"
                _host = "" if cf else _hosting_label(ip, ip_details)
                _host_str = f" — {_host}" if _host else ""
                _tls = "" if cf else _tls_line(ip, tls_by_ip)
                _tls_str = f"  {_tls}" if _tls else ""
                st.markdown(
                    f"`{ip}` {badge}{_host_str} — first: `{r.get('first_seen', '?')}` last: `{r.get('last_seen', '?')}`{_tls_str}",
                    unsafe_allow_html=True,
                )
        else:
            st.info("No historical A/AAAA records found in CIRCL pDNS. The domain may have been behind Cloudflare its entire life.")

    # ── Tab 4: Origin Discovery ───────────────────────────────────────────────
    with tabs[4]:
        st.subheader("Origin Server Discovery")

        # Subdomain leaks (crt.sh)
        leaks = oc.get("subdomain_leaks", [])
        if leaks:
            st.markdown("#### Subdomain leaks")
            for l in leaks:
                _host = _hosting_label(l['ip'], ip_details)
                _host_str = f" ({_host})" if _host else ""
                _tls = _tls_line(l['ip'], tls_by_ip)
                _tls_str = f"<br>{_tls}" if _tls else ""
                _hit_box(f"🔓 <b>{l['subdomain']}</b> → {l['ip']}{_host_str}{_tls_str}", "hit")

        # MX record origin leaks
        mx_leaks = oc.get("mx_leaks", [])
        if mx_leaks:
            st.markdown("#### MX origin leaks")
            for l in mx_leaks:
                _host = _hosting_label(l['ip'], ip_details)
                _host_str = f" ({_host})" if _host else ""
                _tls = _tls_line(l['ip'], tls_by_ip)
                _tls_str = f"<br>{_tls}" if _tls else ""
                _hit_box(f"📧 <b>{l['subdomain']}</b> → {l['ip']}{_host_str}{_tls_str}", "hit")

        # Wordlist subdomain probe
        wlist_leaks = oc.get("wordlist_leaks", [])
        if wlist_leaks:
            st.markdown("#### Wordlist probe hits")
            for l in wlist_leaks:
                _host = _hosting_label(l['ip'], ip_details)
                _host_str = f" ({_host})" if _host else ""
                _tls = _tls_line(l['ip'], tls_by_ip)
                _tls_str = f"<br>{_tls}" if _tls else ""
                _hit_box(f"🔍 <b>{l['subdomain']}</b> → {l['ip']}{_host_str}{_tls_str}", "hit")

        # SPF origins
        spf_origins = d.get("spf_origins", [])
        if spf_origins:
            st.markdown("#### SPF origins")
            for o in spf_origins:
                _host = _hosting_label(o['ip'], ip_details)
                _host_str = f" — {_host}" if _host else ""
                _tls = _tls_line(o['ip'], tls_by_ip)
                _tls_str = f"<br>{_tls}" if _tls else ""
                _hit_box(f"📬 <b>{o['ip']}</b> (cidr: <code>{o['cidr']}</code>){_host_str}{_tls_str}", "warn")

        # HackerTarget hostsearch
        ht_results = oc.get("hackertarget", [])
        non_cf_ht  = [r for r in ht_results if not r.get("cf")]
        if ht_results:
            st.markdown(f"#### HackerTarget — {len(ht_results)} subdomains, {len(non_cf_ht)} non-CF")
            for r in ht_results:
                badge = "🟠" if r.get("cf") else "🟢"
                level = "info" if r.get("cf") else "hit"
                _host = "" if r.get("cf") else _hosting_label(r['ip'], ip_details)
                _host_str = f" ({_host})" if _host else ""
                _tls = "" if r.get("cf") else _tls_line(r['ip'], tls_by_ip)
                _tls_str = f"<br>{_tls}" if _tls else ""
                _hit_box(f"{badge} <b>{r['subdomain']}</b> → {r['ip']}{_host_str}{_tls_str}", level)

        # urlscan historical IPs
        us_results = oc.get("urlscan", [])
        non_cf_us  = [r for r in us_results if not r.get("cf")]
        if us_results:
            st.markdown(f"#### urlscan.io — {len(us_results)} snapshots, {len(non_cf_us)} non-CF")
            for r in us_results:
                badge = "🟠" if r.get("cf") else "🟢"
                level = "info" if r.get("cf") else "hit"
                _host = "" if r.get("cf") else _hosting_label(r['ip'], ip_details)
                _host_str = f" — {_host}" if _host else ""
                _tls = "" if r.get("cf") else _tls_line(r['ip'], tls_by_ip)
                _tls_str = f"<br>{_tls}" if _tls else ""
                _hit_box(
                    f"{badge} <b>{r['ip']}</b>{_host_str}  ({r.get('date', '?')})  "
                    f"<small>{r.get('url', '')[:80]}</small>{_tls_str}",
                    level,
                )

        # API results — only show if not skipped
        for svc, label in [("censys", "Censys"), ("shodan", "Shodan"), ("netlas", "Netlas")]:
            r = oc.get(svc, {})
            if not r or r.get("skipped"):
                continue
            hits = r.get("hits", [])
            with st.expander(f"{label} — {len(hits)} hits"):
                if r.get("error"):
                    st.warning(f"Error: {r['error']}")
                else:
                    for h in hits:
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
        "historical_dns":  "Historical DNS (CIRCL)",
        "spf":             "SPF record",
    }

    with tabs[5]:
        st.subheader("IP Details")
        if not ip_details:
            if not is_domain:
                # IP target — show top-level fields
                cf = d.get("cloudflare", False)
                st.markdown(f"**Cloudflare:** {'Yes 🟠' if cf else 'No 🟢'}")
                st.markdown(f"**PTR:** `{d.get('ptr') or '(none)'}`")
                asn = d.get("asn_info", {})
                for k, v in asn.items():
                    if v: st.markdown(f"**{k}:** `{v}`")
                # TLS cert grabbed directly
                cert = d.get("tls_cert")
                if cert:
                    issuer = cert.get("issuer_cn") or cert.get("issuer_org") or "Unknown CA"
                    _hit_box(
                        f"🔐 <b>TLS cert on port {cert.get('port',443)}</b><br>"
                        f"CN=<b>{cert.get('cn') or '(none)'}</b><br>"
                        f"SANs: <code>{', '.join(cert.get('sans',[])[:8])}</code><br>"
                        f"Issuer: <i>{issuer}</i> &nbsp; "
                        f"valid {(cert.get('not_before') or '')[:10]} → {(cert.get('not_after') or '')[:10]}<br>"
                        f"SHA-256: <code>{cert.get('sha256','')}</code>",
                        "hit",
                    )
                elif not cf:
                    st.caption("No TLS cert found on port 443.")
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
                        st.code("\n".join(others[:50]))

            if dns_ips:
                st.markdown(f"#### DNS-resolved IPs ({len(dns_ips)})")
                for ip, info in dns_ips.items():
                    _render_ip_entry(ip, info)

            if discovered_ips:
                non_cf_count = sum(1 for info in discovered_ips.values() if not info.get("cloudflare"))
                st.markdown(f"#### Discovered IPs ({len(discovered_ips)} total, {non_cf_count} non-Cloudflare)")
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


# ── Domain connections breakdown ──────────────────────────────────────────────

_TRACK_ICONS_FULL = {
    "ga":             ("📊", "Google Analytics"),
    "gtm":            ("📦", "Google Tag Manager"),
    "fb_pixel":       ("📘", "Facebook Pixel"),
    "tiktok_pixel":   ("🎵", "TikTok Pixel"),
    "yandex_metrika": ("🇷🇺", "Yandex Metrika"),
}

_SIGNAL_STRENGTH = {
    "tracking_ids":      ("🔴 Strong",   "bad",  "Tracking IDs are manually embedded — same ID on two domains = same operator."),
    "tls_certs":         ("🔴 Strong",   "bad",  "Identical TLS fingerprint = same physical server handling both domains."),
    "favicons":          ("🟡 Medium",   "warn", "Same favicon = same operator or same CMS template."),
    "registrant_emails": ("🟡 Medium",   "warn", "Same registrant email = registered by the same person or organisation."),
    "ips":               ("🟠 Variable", "warn", "Shared IP may mean co-hosting, a shared CDN vendor, or embedded third-party content."),
    "nameservers":       ("⚪ Weak",     "info", "Shared nameserver is usually just the same DNS provider."),
}


def _render_domain_connections(data: dict) -> None:
    target = data["target"]
    cf     = data.get("cloudflare_fronted")
    ts     = str(data.get("timestamp", ""))[:16].replace("T", " ")
    w      = data.get("whois", {})
    social = data.get("social", [])
    conns  = data.get("connections", {})

    # ── Overview bar ─────────────────────────────────────────────────────────
    cf_badge = "🟠 Cloudflare-fronted" if cf == 1 else ("🟢 Direct (no Cloudflare)" if cf == 0 else "❓ Unknown")
    registrar = str(w.get("registrar") or "Unknown")[:40]
    created   = str(w.get("creation_date") or "?")[:10].lstrip("['")
    org       = str(w.get("org") or "")[:40]

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Cloudflare", cf_badge)
    m2.metric("Registrar",  registrar)
    m3.metric("Created",    created)
    m4.metric("Org",        org or "—")

    # ── Social handles (quick reference) ─────────────────────────────────────
    if social:
        handles = ", ".join(
            f"**{r['platform']}** @{r['handle']}" for r in social
            if r.get("handle") and r.get("platform")
        )
        if handles:
            st.caption(f"Social: {handles}")

    st.divider()

    # Count total cross-DB hits
    total_hits = sum(
        len(v) for section in conns.values()
        for v in ([section] if isinstance(section, list) else [])
        for item in (section if isinstance(section, list) else [])
        if isinstance(item, dict) and item.get("shared_with")
    )
    # Simpler count
    all_shared = [
        item
        for section_items in conns.values()
        for item in (section_items if isinstance(section_items, list) else [])
        if isinstance(item, dict) and item.get("shared_with")
    ]

    if not all_shared:
        st.info("No cross-database connections found for this domain. Analyse more targets to build the graph.")
    else:
        st.markdown(f"**{len(all_shared)} shared attribute(s) link this domain to others in the database.**")

    # ── Render each connection type ───────────────────────────────────────────
    for section_key, section_label, section_icon in [
        ("tracking_ids",      "Tracking / Analytics IDs",  "📊"),
        ("tls_certs",         "TLS Certificates",           "🔐"),
        ("favicons",          "Favicon",                    "🖼"),
        ("registrant_emails", "Registrant Emails",          "📧"),
        ("ips",               "IP Addresses",               "🌐"),
        ("nameservers",       "Nameservers",                "🗄"),
    ]:
        items = conns.get(section_key, [])
        if not items:
            continue

        strength_label, _, strength_note = _SIGNAL_STRENGTH.get(section_key, ("", "info", ""))
        connected     = [i for i in items if i.get("shared_with")]
        not_connected = [i for i in items if not i.get("shared_with")]

        st.markdown(f"#### {section_icon} {section_label}  `{strength_label}`")
        if strength_note:
            st.caption(strength_note)

        # Items WITH cross-DB matches first
        for item in connected:
            shared = item["shared_with"]
            n      = len(shared)
            tags   = "  ".join(f"`{t}`" for t in shared)

            if section_key == "tracking_ids":
                icon, name = _TRACK_ICONS_FULL.get(item["id_type"], ("📊", item["id_type"]))
                _hit_box(
                    f"{icon} <b>{name}</b> <code>{item['id_value']}</code> "
                    f"— also on <b>{n}</b> other domain{'s' if n != 1 else ''}: {tags}",
                    "bad",
                )

            elif section_key == "tls_certs":
                cn    = item.get("cn") or "?"
                issuer = item.get("issuer_cn") or "?"
                ip_str = item.get("ip") or "?"
                fp    = (item.get("sha256") or "")[:16]
                # Classify cert ownership
                own_cert = cn and (target.replace("www.", "") in cn or cn in target)
                if own_cert:
                    note = "This domain's own cert served from the same IP"
                else:
                    note = f"Third-party server cert (<b>{cn}</b>) — content loaded from this host"
                # Issuer gloss
                if "WE1" in issuer:
                    issuer_note = "Cloudflare edge — not the real origin server"
                elif "GTS" in issuer:
                    issuer_note = "Google Trust Services — hosted on GCP"
                elif "Let's Encrypt" in issuer:
                    issuer_note = "Let's Encrypt free cert — likely origin server"
                elif "Sectigo" in issuer or "Comodo" in issuer or "DigiCert" in issuer:
                    issuer_note = "Commercial CA — origin server"
                elif "Amazon" in issuer:
                    issuer_note = "Amazon CA — hosted on AWS"
                elif "mitmproxy" in issuer.lower() or "burp" in issuer.lower():
                    issuer_note = "⚠ INTERCEPTION PROXY"
                else:
                    issuer_note = ""
                issuer_display = f"{issuer} <small>({issuer_note})</small>" if issuer_note else issuer
                _hit_box(
                    f"IP <code>{ip_str}</code> — CN=<b>{cn}</b>  issuer=<i>{issuer_display}</i><br>"
                    f"SHA-256 <code>{fp}…</code><br>"
                    f"{note} — also seen on <b>{n}</b> other domain{'s' if n != 1 else ''}: {tags}",
                    "bad",
                )

            elif section_key == "favicons":
                md5 = item.get("md5", "")
                _hit_box(
                    f"Favicon MD5 <code>{md5}</code> "
                    f"— also on <b>{n}</b> other domain{'s' if n != 1 else ''}: {tags}",
                    "warn",
                )

            elif section_key == "registrant_emails":
                _hit_box(
                    f"Registrant email <code>{item['email']}</code> "
                    f"— also on <b>{n}</b> other domain{'s' if n != 1 else ''}: {tags}",
                    "warn",
                )

            elif section_key == "ips":
                ptr    = item.get("ptr") or ""
                asn    = item.get("asn_desc") or ""
                ip_label = item.get("label") or "direct"
                is_cf  = item.get("cloudflare") == 1
                if is_cf:
                    continue   # skip CF IPs — not meaningful
                meta = "  ".join(filter(None, [ptr, asn, item.get("country")]))
                _ip_notes = {
                    "direct":         "🔴 dedicated/VPS server — strong signal",
                    "shared_hosting": "🟡 shared hosting platform — weak signal alone",
                    "cdn_proxy":      "🔵 CDN/proxy edge — usually noise",
                    "mail":           "⚪ mail server — usually noise",
                }
                ip_note = _ip_notes.get(ip_label, "")
                _hit_box(
                    f"<code>{item['ip']}</code>  <i>{meta}</i>  <small>{ip_note}</small><br>"
                    f"also seen on <b>{n}</b> other domain{'s' if n != 1 else ''}: {tags}",
                    "warn",
                )

            elif section_key == "nameservers":
                _hit_box(
                    f"NS <code>{item['nameserver']}</code> "
                    f"— also used by <b>{n}</b> other domain{'s' if n != 1 else ''}: {tags}",
                    "info",
                )

        # Items unique to this domain (no cross-DB matches) — collapsed
        if not_connected:
            unique_vals: list[str] = []
            for item in not_connected:
                if section_key == "tracking_ids":
                    unique_vals.append(f"{item['id_type']}:{item['id_value']}")
                elif section_key == "tls_certs":
                    cn = item.get("cn") or item.get("sha256", "")[:16]
                    if item.get("cloudflare") != 1:
                        unique_vals.append(cn)
                elif section_key == "favicons":
                    unique_vals.append(item.get("md5", "")[:12] + "…")
                elif section_key == "registrant_emails":
                    unique_vals.append(item["email"])
                elif section_key == "ips":
                    if item.get("cloudflare") != 1:
                        unique_vals.append(item["ip"])
                elif section_key == "nameservers":
                    unique_vals.append(item["nameserver"])
            if unique_vals:
                with st.expander(f"No cross-DB match ({len(unique_vals)} unique to this domain)"):
                    for v in unique_vals:
                        st.caption(f"  • {v}")


# ── Connections graph ─────────────────────────────────────────────────────────

_TRACK_LABELS = {
    "ga": "GA", "gtm": "GTM", "fb_pixel": "FB Pixel",
    "tiktok_pixel": "TikTok", "yandex_metrika": "Yandex",
}


def _render_connections_graph() -> None:
    """
    Build an interactive network graph of overlapping infrastructure across all
    analysed targets.  Domains are blue nodes; shared attributes (IPs, tracking
    IDs, TLS certs, favicons) are coloured connector nodes.  An edge means
    'these two things co-occur on the same domain'.
    """
    try:
        from pyvis.network import Network
    except ImportError:
        st.warning("pyvis not installed — cannot render graph. Run `pip install pyvis`.")
        return

    # ── Toggle controls ───────────────────────────────────────────────────────
    st.markdown("**Show connection types:**")
    _tcol1, _tcol2, _tcol3, _tcol4 = st.columns(4)
    show_ips      = _tcol1.checkbox("🟠 Shared IPs",    value=True, key="graph_show_ips")
    show_tracking = _tcol2.checkbox("🔴 Tracking IDs",  value=True, key="graph_show_tracking")
    show_tls      = _tcol3.checkbox("🟢 TLS Certs",     value=True, key="graph_show_tls")
    show_favicons = _tcol4.checkbox("🟣 Favicons",       value=True, key="graph_show_favicons")

    ip_clusters       = cluster_by_ip()       if show_ips      else []
    tracking_clusters = cluster_by_tracking_id() if show_tracking else []
    favicon_clusters  = cluster_by_favicon()  if show_favicons else []
    tls_clusters      = cluster_by_tls_cert() if show_tls      else []

    total_edges = (
        sum(len(str(r["targets"]).split(",")) for r in ip_clusters)
        + sum(len(str(r["targets"]).split(",")) for r in tracking_clusters)
        + sum(len(str(r["targets"]).split(",")) for r in favicon_clusters)
        + sum(len(str(r["targets"]).split(",")) for r in tls_clusters)
    )

    if total_edges == 0:
        st.info("No shared connections yet — or all connection types are toggled off.")
        return

    net = Network(
        height="620px",
        width="100%",
        bgcolor="#0e1117",
        font_color="#e0e0e0",
        directed=False,
    )
    net.set_options("""{
      "nodes": { "borderWidth": 1, "shadow": true },
      "edges": { "shadow": false, "smooth": { "type": "dynamic" } },
      "physics": {
        "forceAtlas2Based": {
          "gravitationalConstant": -60,
          "centralGravity": 0.005,
          "springLength": 120,
          "springConstant": 0.08
        },
        "maxVelocity": 60,
        "solver": "forceAtlas2Based",
        "timestep": 0.4,
        "stabilization": { "enabled": true, "iterations": 200 }
      },
      "interaction": { "hover": true, "tooltipDelay": 200 }
    }""")

    _nodes: set[str] = set()
    _edges: set[tuple] = set()

    def _add_domain(domain: str) -> None:
        if domain not in _nodes:
            net.add_node(
                domain,
                label=domain,
                color={"background": "#1565c0", "border": "#42a5f5", "highlight": {"background": "#1976d2", "border": "#90caf9"}},
                size=22,
                shape="dot",
                title=f"<b>Domain:</b> {domain}",
                font={"size": 13},
            )
            _nodes.add(domain)

    def _add_connector(node_id: str, label: str, title: str, color: str, shape: str = "diamond", size: int = 16) -> None:
        if node_id not in _nodes:
            net.add_node(
                node_id,
                label=label,
                color={"background": color, "border": "#ffffff33", "highlight": {"background": color}},
                size=size,
                shape=shape,
                title=title,
                font={"size": 11},
            )
            _nodes.add(node_id)

    def _add_edge(a: str, b: str, **kwargs) -> None:
        if (a, b) not in _edges:
            net.add_edge(a, b, **kwargs)
            _edges.add((a, b))
            _edges.add((b, a))

    # Shared IPs — orange diamonds
    for row in ip_clusters:
        targets = [t.strip() for t in str(row["targets"]).split(",") if t.strip()]
        node_id = f"ip:{row['ip']}"
        _add_connector(node_id, row["ip"], f"<b>Shared IP:</b> {row['ip']}<br>{row['target_count']} domains", "#e65100", "diamond")
        for t in targets:
            _add_domain(t)
            _add_edge(t, node_id, color="#e65100", width=1.5, title=f"{t} → {row['ip']}")

    # Shared tracking IDs — red squares
    for row in tracking_clusters:
        targets  = [t.strip() for t in str(row["targets"]).split(",") if t.strip()]
        id_short = _TRACK_LABELS.get(row["id_type"], row["id_type"])
        node_id  = f"track:{row['id_type']}:{row['id_value']}"
        label    = f"{id_short}\n{str(row['id_value'])[:12]}"
        title    = f"<b>{id_short}:</b> {row['id_value']}<br>{row['target_count']} domains"
        _add_connector(node_id, label, title, "#c62828", "square", 14)
        for t in targets:
            _add_domain(t)
            _add_edge(t, node_id, color="#c62828", width=1.5, title=f"{t} → {id_short} {row['id_value']}")

    # Shared TLS certs — green triangles
    for row in tls_clusters:
        targets = [t.strip() for t in str(row["targets"]).split(",") if t.strip()]
        fp      = (row.get("sha256") or "")[:16]
        cn      = row.get("cn") or "?"
        node_id = f"tls:{fp}"
        label   = f"TLS\n{cn[:18]}"
        title   = f"<b>TLS cert:</b> CN={cn}<br>issuer={row.get('issuer_cn','?')}<br>SHA-256 {fp}…<br>{row['target_count']} domains"
        _add_connector(node_id, label, title, "#2e7d32", "triangle", 14)
        for t in targets:
            _add_domain(t)
            _add_edge(t, node_id, color="#2e7d32", width=1.5, title=f"{t} → TLS {cn}")

    # Shared favicons — purple stars
    for row in favicon_clusters:
        targets = [t.strip() for t in str(row["targets"]).split(",") if t.strip()]
        md5     = str(row.get("md5") or "")
        node_id = f"fav:{md5}"
        label   = f"Favicon\n{md5[:8]}"
        title   = f"<b>Favicon MD5:</b> {md5}<br>{row['target_count']} domains"
        _add_connector(node_id, label, title, "#6a1b9a", "star", 14)
        for t in targets:
            _add_domain(t)
            _add_edge(t, node_id, color="#6a1b9a", width=1.5, title=f"{t} → favicon {md5[:8]}")

    # Legend
    col_leg1, col_leg2, col_leg3, col_leg4, col_leg5 = st.columns(5)
    col_leg1.markdown("🔵 **Domain**")
    col_leg2.markdown("🟠 **Shared IP**")
    col_leg3.markdown("🔴 **Tracking ID**")
    col_leg4.markdown("🟢 **TLS Cert**")
    col_leg5.markdown("🟣 **Favicon**")

    html = net.generate_html()
    _st_components.html(html, height=650, scrolling=False)


# ── Search History & Cross-Reference Clusters ─────────────────────────────────
st.divider()
st.header("📚 Search History & Infrastructure Clusters")

_hist_tabs = st.tabs(["🕐 Recent Searches", "🌐 IP Clusters", "📊 Tracking ID Clusters", "🖼 Favicon Clusters", "🔐 TLS Cert Clusters", "🔗 Connections Graph", "🔎 Domain Lookup"])

with _hist_tabs[0]:
    try:
        recent = get_recent(limit=100)
        if not recent:
            st.info("No searches recorded yet. Run an analysis to start building the database.")
        else:
            st.markdown(f"**{len(recent)} searches in database**")
            for row in recent:
                cf_badge = "🟠 CF" if row.get("cloudflare_fronted") == 1 else ("🟢 Direct" if row.get("cloudflare_fronted") == 0 else "❓")
                ts = str(row.get("timestamp", ""))[:16].replace("T", " ")
                with st.expander(f"`{row['target']}` — {row['type'].upper()}  {cf_badge}  {ts}"):
                    # Show non-CF IPs and TLS certs for this search
                    ips_rows = []
                    tls_rows = []
                    try:
                        _detail = get_by_id(row["id"])
                        if _detail:
                            raw = __import__("json").loads(_detail.get("raw_json", "{}"))
                            for ip in raw.get("non_cf_ips", []):
                                ips_rows.append(ip)
                            for cert in (raw.get("non_cf_tls_certs") or []):
                                if cert:
                                    tls_rows.append(cert)
                            if raw.get("tls_cert"):
                                tls_rows.append(raw["tls_cert"])
                    except Exception:
                        pass
                    if ips_rows:
                        st.markdown(f"**Non-CF IPs found:** `{'`, `'.join(ips_rows)}`")
                    for cert in tls_rows:
                        if cert:
                            _hit_box(
                                f"🔐 {cert.get('ip')}:{cert.get('port',443)}  "
                                f"CN=<b>{cert.get('cn','?')}</b>  "
                                f"issuer=<i>{cert.get('issuer_cn','?')}</i>  "
                                f"<code>{cert.get('sha256','')[:16]}…</code>",
                                "info",
                            )
    except Exception as exc:
        st.warning(f"Could not load history: {exc}")

    # ── Retry failed source requests ──────────────────────────────────────────
    st.divider()
    st.markdown("#### Retry Failed Source Requests")
    try:
        failed = get_domains_with_source_errors()
        if not failed:
            st.success("No source errors recorded — all lookups completed successfully.")
        else:
            error_summary: dict[str, int] = {}
            for row in failed:
                for e in row["errors"]:
                    error_summary[e] = error_summary.get(e, 0) + 1
            summary_str = ", ".join(f"{src}: {n} domains" for src, n in error_summary.items())
            st.warning(f"**{len(failed)} domains** have source errors — {summary_str}")
            if st.button("Retry all failed source requests", key="retry_source_errors"):
                try:
                    import opencti_ingest as _oci
                    started = _oci.start_retry_in_background()
                    if started:
                        st.success(f"Retry started for {len(failed)} domains. Check container logs for progress.")
                    else:
                        st.info("Retry is already running.")
                except Exception as exc:
                    st.error(f"Could not start retry: {exc}")
    except Exception as exc:
        st.warning(f"Could not check source errors: {exc}")

with _hist_tabs[1]:
    st.markdown("#### Shared IPs")
    try:
        clusters = cluster_by_ip()
        if not clusters:
            st.info("No shared IPs yet — analyse more targets to build clusters.")
        else:
            _LABEL_META = {
                "direct":         ("🔴", "Direct server",    "error",
                                   "Dedicated/VPS server not matching known CDN or mail ASNs — strong signal, likely the real origin host."),
                "shared_hosting": ("🟡", "Shared hosting",   "warn",
                                   "Shared platform (e.g. cPanel/Plesk host) — hundreds of sites on one IP; meaningful only if combined with other signals."),
                "cdn_proxy":      ("🔵", "CDN / proxy",      "info",
                                   "Cloudflare, Fastly, Incapsula etc — the IP is an edge node, not the real server. Usually noise."),
                "mail":           ("⚪", "Mail server",      "info",
                                   "Mail-only host (MX / SMTP PTR pattern) — not the web origin. Usually noise."),
            }
            all_labels = ["direct", "shared_hosting", "cdn_proxy", "mail"]
            label_counts = {l: sum(1 for r in clusters if r.get("label") == l) for l in all_labels}
            summary = "  |  ".join(
                f"{_LABEL_META[l][0]} {_LABEL_META[l][1]}: **{label_counts[l]}**"
                for l in all_labels
            )
            st.markdown(summary)
            st.caption("🔴 Direct = dedicated/VPS (strong signal)  |  🟡 Shared = platform hosting (weak signal)  |  🔵 CDN = edge node (noise)  |  ⚪ Mail = mail server (noise)")

            show_labels = st.multiselect(
                "Show IP types",
                options=all_labels,
                default=["direct", "shared_hosting"],
                format_func=lambda l: f"{_LABEL_META[l][0]} {_LABEL_META[l][1]}",
                key="ip_cluster_filter",
            )

            shown = [r for r in clusters if r.get("label") in show_labels]
            st.caption(f"Showing {len(shown)} of {len(clusters)} shared IPs")
            for row in shown:
                label = row.get("label", "direct")
                icon, label_name, severity, label_note = _LABEL_META.get(label, ("🔴", label, "error", ""))
                targets = str(row.get("targets", "")).split(",")
                ptr_str = f"  PTR: <i>{row['ptr']}</i>" if row.get("ptr") else ""
                asn_str = f"  ASN: {row['asn_desc']}" if row.get("asn_desc") else ""
                _hit_box(
                    f"{icon} <b>{row['ip']}</b> [{label_name}] — "
                    f"<b>{row['target_count']}</b> targets: "
                    f"<code>{', '.join(targets[:10])}</code>"
                    f"{ptr_str}{asn_str}"
                    f"<br><small><i>{label_note}</i></small>",
                    severity,
                )
    except Exception as exc:
        st.warning(f"Could not load IP clusters: {exc}")

with _hist_tabs[2]:
    st.markdown("#### Shared Tracking IDs")
    try:
        clusters = cluster_by_tracking_id()
        if not clusters:
            st.info("No shared tracking IDs yet.")
        else:
            _TRACK_ICONS = {
                "ga":             "📊 Google Analytics",
                "gtm":            "📦 Google Tag Manager",
                "fb_pixel":       "📘 Facebook Pixel",
                "tiktok_pixel":   "🎵 TikTok Pixel",
                "yandex_metrika": "🇷🇺 Yandex Metrika",
            }
            for row in clusters:
                targets = str(row.get("targets", "")).split(",")
                label = _TRACK_ICONS.get(row.get("id_type", ""), row.get("id_type", ""))
                level = "bad" if row.get("id_type") == "yandex_metrika" else "warn"
                _hit_box(
                    f"{label} <code>{row.get('id_value')}</code> — "
                    f"<b>{row['target_count']}</b> targets: "
                    f"<code>{', '.join(targets[:10])}</code>",
                    level,
                )
    except Exception as exc:
        st.warning(f"Could not load tracking clusters: {exc}")

with _hist_tabs[3]:
    st.markdown("#### Shared Favicons")
    try:
        clusters = cluster_by_favicon()
        if not clusters:
            st.info("No shared favicons yet.")
        else:
            for row in clusters:
                targets = str(row.get("targets", "")).split(",")
                _hit_box(
                    f"🖼 MD5 <code>{row['md5']}</code> — "
                    f"<b>{row['target_count']}</b> targets: "
                    f"<code>{', '.join(targets[:10])}</code>",
                    "warn",
                )
    except Exception as exc:
        st.warning(f"Could not load favicon clusters: {exc}")

with _hist_tabs[4]:
    st.markdown("#### Shared TLS Fingerprints")
    try:
        clusters = cluster_by_tls_cert()
        if not clusters:
            st.info("No shared TLS fingerprints yet.")
        else:
            for row in clusters:
                targets = str(row.get("targets", "")).split(",")
                _hit_box(
                    f"🔐 CN=<b>{row.get('cn','?')}</b>  issuer=<i>{row.get('issuer_cn','?')}</i><br>"
                    f"SHA-256 <code>{row.get('sha256','')[:32]}…</code> — "
                    f"<b>{row['target_count']}</b> targets: "
                    f"<code>{', '.join(targets[:10])}</code>",
                    "bad",
                )
    except Exception as exc:
        st.warning(f"Could not load TLS clusters: {exc}")

with _hist_tabs[5]:
    _render_connections_graph()

with _hist_tabs[6]:
    st.markdown("#### Domain Connections Lookup")
    try:
        _recent_all = get_recent(limit=500)
        _domain_options = sorted({r["target"] for r in _recent_all})
        if not _domain_options:
            st.info("No domains in the database yet. Run an analysis first.")
        else:
            _lookup_target = st.selectbox(
                "Select domain",
                options=[""] + _domain_options,
                format_func=lambda x: x if x else "— choose a domain —",
                key="domain_lookup_select",
            )
            if _lookup_target:
                _conn_data = get_connections_for_target(_lookup_target)
                if _conn_data is None:
                    st.warning(f"No data found for `{_lookup_target}`.")
                else:
                    st.markdown(f"### {_lookup_target}")
                    _render_domain_connections(_conn_data)
    except Exception as _exc:
        st.warning(f"Could not load domain lookup: {_exc}")
