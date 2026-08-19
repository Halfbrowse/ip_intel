from __future__ import annotations

import contextvars
import csv
import io
import json
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Callable

from core import basic
from core import ip_intel
from sources import censys_discovery
from sources import signal_dns
from sources import signal_web


StageLogger = Callable[[str, str], None]


# ── Scan profiles ────────────────────────────────────────────────────────────
# One explicit record of what a given target is allowed to spend, instead of a
# provider check scattered through the pipeline. `run_providers` is the switch
# core/basic.py's SERVICES registry already understands (it gates the
# _PROVIDER_SERVICES set — Censys cert search); the other two flags gate the
# spend that lives outside that registry.


@dataclass(frozen=True)
class ScanProfile:
    name: str
    run_providers: bool
    censys_host_enrichment: bool
    reverse_lookups: bool


# Only the domain a human actually submitted spends Censys search credits. It is
# the one target whose cert search and reverse lookup were explicitly asked for;
# everything else in the case is something the pipeline found on its own.
FULL_SCAN = ScanProfile(
    name="full",
    run_providers=True,
    censys_host_enrichment=True,
    reverse_lookups=True,
)

# Everything the pipeline discovered for itself — subdomains, sibling apexes,
# wordlist hits, and the domains a reverse lookup surfaced. They get the full
# scan *minus the paid Censys query*: DNS, WHOIS, crt.sh, CIRCL passive DNS,
# HackerTarget, urlscan, page metadata, TLS/SSH probes, all the parity
# enrichments, and host enrichment.
#
# Host enrichment is on here because it costs no credits — it draws on the
# separate 20,000/day allowance, and utils/censys_enrichment.py claims against
# that budget before each request, so this profile self-limits at the cap
# instead of needing a per-target gate. Every IP in the case therefore gets
# reputation, GreyNoise, threat and VPN/proxy classification and city geo until
# the day's budget runs out.
#
# `reverse_lookups=False` is the load-bearing flag: a reverse-lookup discovery
# that ran its own reverse lookup would turn one promiscuous tracking ID into an
# unbounded crawl of the internet, each hop billing more searches. Because no
# non-seed target gets it, that recursion is structurally impossible rather than
# merely discouraged.
#
# This replaces the old SUBDOMAIN_FOLLOWUP / FREE_ONLY pair, which differed only
# in whether host enrichment ran. Now that enrichment runs for both, they were
# the same profile under two names.
NO_PAID_SEARCH = ScanProfile(
    name="no_paid_search",
    run_providers=False,
    censys_host_enrichment=True,
    reverse_lookups=False,
)

# The provenance value stamped on every domain a reverse lookup found. This is
# what makes the non-recursion guard structural rather than conventional: it
# rides on the record of how the domain entered the pool (`discovery_kind`,
# persisted to search_fields by db/intel_db.py and to the case run by
# cases/case_runtime.py), so a rescan, a resumed job, or a re-queue from any
# other code path all reach the same conclusion without remembering to.
REVERSE_LOOKUP_DISCOVERY_KIND = "censys_reverse_lookup"

# Read by utils/censys_enrichment.py. Kept as a ContextVar rather than a module
# flag because ANALYSIS_WORKERS analyses run concurrently in one process: a
# global would let one target's profile switch enrichment off underneath a scan
# running in the next thread over. Both live profiles now enable enrichment, so
# this currently never gates anything — it stays because it is the mechanism
# that makes the setting per-scan rather than per-process.
CENSYS_ENRICHMENT_ALLOWED: ContextVar[bool] = ContextVar(
    "ip_intel_censys_enrichment_allowed", default=True
)


def profile_for(domain: str, *, is_seed: bool, discovery_kind: str | None) -> ScanProfile:
    """Which profile a target scans under, decided solely from how it got here.

    Exactly one rule: the domain a human submitted pays for Censys search;
    everything the pipeline discovered does not.

    The apex test that used to sit here (`basic._apex(domain) == domain`) is
    gone. It handed every *discovered sibling apex* a FULL_SCAN, so each of the
    five a case can turn up ran its own cert search and its own eight-selector
    reverse lookup — about 83% of the Censys credits a single ingest spent, on
    infrastructure nobody asked to be billed for.

    The reverse-lookup guard is retained as defence in depth. It is redundant
    while there is only one non-seed profile and it disables reverse lookups,
    but it encodes the invariant directly: a domain that entered the pool
    *through* a reverse lookup must never run one, whatever the profile table
    says. `discovery_kind` rides on the durable record of how the domain got
    here (persisted to search_fields and to the case run), so a rescan, a
    resumed job, or a re-queue from any other path all reach the same answer.
    """
    if discovery_kind == REVERSE_LOOKUP_DISCOVERY_KIND:
        return NO_PAID_SEARCH
    if is_seed:
        return FULL_SCAN
    return NO_PAID_SEARCH


@contextmanager
def _apply_profile(profile: ScanProfile):
    token = CENSYS_ENRICHMENT_ALLOWED.set(profile.censys_host_enrichment)
    try:
        yield
    finally:
        CENSYS_ENRICHMENT_ALLOWED.reset(token)


@dataclass
class AnalysisRun:
    target: str
    normalized_target: str
    target_type: str
    depth: int
    discovered_from: str | None
    discovery_reason: str | None
    discovery_kind: str | None
    is_seed: bool
    payload: dict[str, Any]
    discovered_targets: list[dict[str, Any]] = field(default_factory=list)
    helpers: dict[str, Any] = field(default_factory=dict)
    status: str = "completed"
    error: str | None = None


def clean_target(value: str) -> str:
    return ip_intel.clean_target(value).strip().lower()


def detect_target_type(value: str) -> str:
    return "ip" if ip_intel.is_ip(value) else "domain"


def parse_csv_targets(content: bytes) -> list[str]:
    text = content.decode("utf-8-sig", errors="ignore")
    reader = csv.reader(io.StringIO(text))
    targets: list[str] = []
    for row in reader:
        if not row:
            continue
        candidate = clean_target(str(row[0] or ""))
        if candidate:
            targets.append(candidate)
    return targets


def normalize_inputs(targets: list[str]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, raw_target in enumerate(targets, start=1):
        target = clean_target(raw_target)
        if not target or target in seen:
            continue
        seen.add(target)
        normalized.append(
            {
                "input_value": raw_target,
                "normalized_target": target,
                "target_type": detect_target_type(target),
                "upload_row": index,
                "source": "csv",
            }
        )
    return normalized


@contextmanager
def _basic_runtime(logger: StageLogger | None):
    def _log(message: str, level: str = "*") -> None:
        if logger is not None:
            level_map = {"+": "success", "!": "warning", "*": "info"}
            logger(level_map.get(level, "info"), str(message))

    def _save(_results: dict[str, Any]) -> None:
        return

    with basic.runtime_hooks(log_hook=_log, save_hook=_save):
        yield


def analyze_target(
    target: str,
    *,
    depth: int,
    discovered_from: str | None,
    discovery_reason: str | None,
    discovery_kind: str | None,
    is_seed: bool,
    logger: StageLogger | None = None,
) -> AnalysisRun:
    normalized_target = clean_target(target)
    target_type = detect_target_type(normalized_target)
    profile = profile_for(
        normalized_target, is_seed=is_seed, discovery_kind=discovery_kind
    )
    with _apply_profile(profile):
        if target_type == "ip":
            payload = _analyze_ip(normalized_target, logger=logger)
        else:
            payload = _analyze_domain(normalized_target, logger=logger, profile=profile)
            if profile.reverse_lookups:
                payload["censys_reverse_lookup"] = _reverse_lookup(
                    normalized_target, payload, logger=logger
                )

    payload["scan_depth"] = depth
    payload["discovered_from"] = discovered_from
    payload["discovery_reason"] = discovery_reason
    payload["discovery_kind"] = discovery_kind
    payload["is_seed"] = is_seed
    payload["scan_profile"] = profile.name

    discovered_targets = []
    if target_type == "domain":
        discovered_targets = _extract_discovered_targets(payload, normalized_target)

    helpers = build_helper_rows(payload)

    # Persist the analysed result into the global intel store (db/intel_db.py) so
    # the pool and correlation graph populate on every ingest. The case-layer run
    # is saved separately by the caller; this is best-effort and must never break
    # the ingest, so any failure is logged and swallowed.
    try:
        from datetime import datetime, timezone

        from db import intel_db

        payload.setdefault("input", normalized_target)
        payload.setdefault("type", target_type)
        payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        search_id = intel_db.save_search(payload)
        lookup = payload.get("censys_reverse_lookup")
        if isinstance(lookup, dict) and lookup.get("selectors"):
            from db import discovery_store

            discovery_store.record_reverse_lookup(search_id, lookup)
    except Exception as exc:  # pragma: no cover - defensive; correlation is rebuildable
        # Log the originating frame (file:line), not just the message: this save
        # is swallowed so an ingest never breaks, but a bare "'list' object has
        # no attribute 'get'" is undiagnosable. tb[-1] is the deepest frame —
        # exactly where a mis-shaped payload field was accessed.
        frame = ""
        tb = traceback.extract_tb(exc.__traceback__)
        if tb:
            last = tb[-1]
            frame = f" at {last.filename.split('/')[-1]}:{last.lineno} in {last.name}()"
        _log(logger, "warning", f"Intel store save failed for {normalized_target}: {exc}{frame}")

    return AnalysisRun(
        target=target,
        normalized_target=normalized_target,
        target_type=target_type,
        depth=depth,
        discovered_from=discovered_from,
        discovery_reason=discovery_reason,
        discovery_kind=discovery_kind,
        is_seed=is_seed,
        payload=payload,
        discovered_targets=discovered_targets,
        helpers=helpers,
    )


def _analyze_domain(
    domain: str,
    *,
    logger: StageLogger | None = None,
    profile: ScanProfile = FULL_SCAN,
) -> dict[str, Any]:
    with _basic_runtime(logger), _apply_profile(profile):
        payload = basic.analyze(
            domain,
            is_followup=True,
            all_results=None,
            overall_bar=None,
            follow_siblings=False,
            run_providers=profile.run_providers,
        )

    payload["input"] = domain
    payload["type"] = "domain"
    payload.setdefault("domain", domain)

    dns_records = payload.get("dns") or {}
    txt_records = dns_records.get("TXT") or []
    mx_records = dns_records.get("MX") or []
    nameservers = dns_records.get("NS") or []

    # ── Parity enrichments ────────────────────────────────────────────────
    # Eight independent network probes, previously run one after another.
    # Measured across a 50-target run they cost 22.5s of a 51.3s median domain
    # scan — ~44% of it — and every second was spent blocking on a *different*
    # remote host, so the sequencing bought nothing.
    #
    # There is exactly one ordering constraint: source-map discovery reads
    # `payload["page_metadata"]`, which the page-metadata merge writes. That
    # pair is kept together in a single task rather than synchronised, so the
    # dependency is expressed by construction and cannot be broken by someone
    # reordering the list below. Every other step takes only `domain` plus
    # results the SERVICES fan-out already produced, and writes one disjoint
    # payload key, so there is nothing to race over.
    #
    # nameserver_analysis stays inline underneath: it is pure CPU over the
    # already-fetched NS records, so a thread would cost more than it saves.
    def _parity_email_security() -> dict[str, Any]:
        email_security = signal_dns.get_email_security_records(domain)
        spf_details = signal_dns.collect_spf_details(domain, txt_records=txt_records)
        email_security["spf_includes"] = spf_details.get("includes", [])
        email_security["spf_records"] = spf_details.get("records", [])
        # Two shapes, deliberately, because two consumers need different ones.
        #
        # signal_dns returns {"rua": [...], "ruf": [...]}. utils/pairwise.py
        # scores the path `email_security.dmarc_report_uris` and only scores
        # exact paths, so with the dict in place the sub-paths (`....rua`) are
        # unscored and the evidence never counts — hence the flattened list.
        # But db/intel_db.py's extract_search_identifiers reads the same key
        # expecting the dict, to type each address as dmarc_rua vs dmarc_ruf.
        #
        # Overwriting the key with the list served pairwise and broke that:
        # `.get()` on a list raises, save_search aborts mid-write, and
        # analyze_target swallows it as a warning — so a scan looked successful
        # while persisting a searches row with no identifiers, IPs or certs.
        # Keep both: the flat list where pairwise scores it, the structured tags
        # beside it where the identifier extractor can still read them.
        report_uris = email_security.get("dmarc_report_uris")
        email_security["dmarc_report_uris_by_tag"] = (
            report_uris if isinstance(report_uris, dict) else {}
        )
        email_security["dmarc_report_uris"] = _flatten_report_uris(report_uris)
        email_security["dkim_selectors"] = _dkim_selectors(email_security.get("dkim"))
        email_security["bimi_logos"] = _bimi_logos(email_security.get("bimi"))
        return {
            "email_security": email_security,
            "spf_origins": spf_details.get("origins", []),
            "txt_verification_tokens": [
                f"{token['provider']}:{token['token']}"
                for token in signal_dns.extract_txt_tenancy_tokens(txt_records)
                if token.get("provider") and token.get("token")
            ],
        }

    def _parity_page_metadata_and_source_maps() -> dict[str, Any]:
        # basic.get_page_metadata now *is* signal_web.fetch_page_metadata, so
        # this no longer refetches the homepage; the merge stays because it is
        # what derives the flattened `social_handle_values` /
        # `crypto_wallet_values` selector lists the identifier layer reads.
        page_meta = _merge_page_metadata(payload.get("page_metadata") or {}, {})
        # Hand over the whole page_metadata mapping, not `script_assets` alone.
        # signal_web builds `script_assets` as {url, host, type} records, and
        # `_script_urls_from_input`'s list branch stringifies whatever it gets —
        # so passing the list produced URLs like "{'url': '…', 'host': '…'}"
        # and every source-map fetch 404'd. Given the mapping it takes the
        # branch that reads `script_urls`/`script_assets[].url` properly.
        source_map_target = (
            page_meta
            if (page_meta.get("script_urls") or page_meta.get("script_assets"))
            else (page_meta.get("final_url") or domain)
        )
        page_meta["source_map_urls"] = _collect_source_map_urls(
            signal_web.fetch_source_map_disclosures(source_map_target)
        )
        return {"page_metadata": page_meta}

    def _parity_origin_candidates() -> dict[str, Any]:
        # The three probes are independent DNS sweeps and used to run in
        # sequence, which made this the parity block's long pole (11.5s even
        # after the wordlist sweep was bounded). They now overlap, so the step
        # costs its slowest probe rather than their sum.
        #
        # Safe to widen only because ip_intel._DNS_GATE bounds total in-flight
        # DNS process-wide: without it, three concurrent sweeps would just
        # rebuild the resolver saturation that bounding the wordlist fixed.
        probes = {
            "subdomain_leaks": lambda: ip_intel.probe_subdomain_origins(
                (payload.get("crt_sh") or {}).get("subdomains", [])
            ),
            "mx_leaks": lambda: ip_intel.probe_mx_origins(mx_records),
            "wordlist_leaks": lambda: ip_intel.probe_wordlist_subdomains(domain),
        }
        found: dict[str, Any] = {}
        with ThreadPoolExecutor(max_workers=len(probes), thread_name_prefix="origin") as ex:
            running = {ex.submit(contextvars.copy_context().run, fn): key
                       for key, fn in probes.items()}
            for fut in as_completed(running):
                key = running[fut]
                try:
                    found[key] = fut.result()
                except Exception as exc:
                    _log(logger, "warning", f"  parity[{domain}]: {key} failed: {exc}")
                    found[key] = []
        return {
            "origin_candidates": {
                "subdomain_leaks": found.get("subdomain_leaks", []),
                "mx_leaks": found.get("mx_leaks", []),
                "wordlist_leaks": found.get("wordlist_leaks", []),
                "hackertarget": (payload.get("hackertarget") or {}).get("hits", []),
                "urlscan": (payload.get("urlscan") or {}).get("hits", []),
                "censys": _provider_origin_candidates(payload, "censys"),
                "scan": {"skipped": True, "reason": "Targeted origin scan is not enabled for case mode."},
                "provider_scan": {"skipped": True, "reason": "Provider scan is not enabled for case mode."},
                "country_scan": {"skipped": True, "reason": "Country scan is not enabled for case mode."},
            }
        }

    parity_steps: list[tuple[str, Callable[[], dict[str, Any]]]] = [
        ("origin candidates (subdomain/MX/wordlist probes)", _parity_origin_candidates),
        ("legal pages", lambda: {"legal_pages": _compact_legal_pages(signal_web.scrape_legal_pages(domain))}),
        ("page metadata + source map disclosures", _parity_page_metadata_and_source_maps),
        ("well-known files", lambda: {"well_known": _compact_well_known(signal_web.fetch_well_known_files(domain))}),
        ("mail client config (autodiscover/autoconfig)",
         lambda: {"mail_client_config": _compact_mail_client_config(signal_web.probe_mail_client_config(domain))}),
        ("Microsoft tenant probe", lambda: {"microsoft_tenant": signal_dns.probe_microsoft_tenant_sync(domain)}),
        ("email security + SPF/DKIM/DMARC", _parity_email_security),
        ("zone transfer (AXFR)", lambda: {"zone_transfer": ip_intel.attempt_zone_transfer(domain, nameservers)}),
    ]

    _log(
        logger, "info",
        f"Running parity enrichments for {domain} ({len(parity_steps)} steps, concurrent)",
    )
    with ThreadPoolExecutor(
        max_workers=len(parity_steps), thread_name_prefix="parity"
    ) as parity_pool:
        parity_futures = {}
        for label, step in parity_steps:
            # Same reason core/basic.py copies the context into its SERVICES
            # fan-out: the worker inherits the ContextVar log/save hooks and the
            # scan profile, so provider-level log lines emitted *inside* a step
            # still reach the job log. A fresh copy per submit is required — one
            # Context cannot be entered by two threads at once.
            ctx = contextvars.copy_context()
            parity_futures[parity_pool.submit(ctx.run, _run_parity_step, logger, domain, label, step)] = label
        for fut in as_completed(parity_futures):
            label = parity_futures[fut]
            try:
                payload.update(fut.result())
            except Exception as exc:
                # One flaky probe must not lose the other seven, or the scan.
                # The SERVICES fan-out already treats a failed source this way,
                # and the egress proxy drops connections often enough that a
                # hard failure here would throw away a complete scan over a
                # single unreachable legal-pages URL. Logged at warning so it
                # stays visible rather than silently degrading.
                _log(logger, "warning", f"  parity[{domain}]: {label} failed: {exc}")

    # Pure CPU over the NS records the SERVICES fan-out already fetched, so it
    # stays on this thread rather than costing a worker.
    payload["nameserver_analysis"] = ip_intel._classify_nameservers(nameservers)
    payload["nameserver_analysis"]["vanity_apexes"] = sorted(
        {
            str(item.get("apex") or "").lower()
            for item in payload["nameserver_analysis"].get("vanity_candidates", [])
            if str(item.get("apex") or "").strip()
        }
    )
    payload["nameserver_analysis"].update(
        _nameserver_delegation_check(nameservers, (payload.get("whois") or {}).get("nameservers"))
    )
    payload["non_cf_ips"] = sorted({*payload.get("non_cf_ips", []), *dns_records.get("A", [])})
    payload["comparison_labels"] = {
        "primary": domain,
        "display": domain,
    }
    return payload


def _provider_origin_candidates(payload: dict[str, Any], provider: str) -> dict[str, Any]:
    """Copy supported provider hits into the durable origin-candidate shape.

    `core.basic` writes Censys results at the top level (`payload["censys"]`).
    The persistence/correlation layer intentionally reads provider-origin hits
    from `origin_candidates`, so normalize the active provider there before
    saving. Censys is now the only provider passed here; Shodan and Netlas were
    retired as duplicate cert searches on separate paid keys.
    """
    result = payload.get(provider)
    if not isinstance(result, dict):
        return {"skipped": True, "reason": f"{provider} did not return a provider result"}
    if result.get("skipped") or result.get("error"):
        return result
    hits = [hit for hit in result.get("hits", []) or [] if isinstance(hit, dict)]
    return {
        **result,
        "hits": hits,
        "status": result.get("status") or "ok",
        "query_type": result.get("query_type") or "cert_search",
        "total": result.get("total", len(hits)),
    }


def _reverse_lookup(
    domain: str, payload: dict[str, Any], *, logger: StageLogger | None = None
) -> dict[str, Any]:
    """Invert this scan's selectors into internet-wide Censys searches.

    Runs once, on the target itself, after page metadata is merged — never on
    anything a reverse lookup discovered (see `profile_for`). The result carries
    each selector's global prevalence even when no new domain comes back, which
    is the half of the answer `utils/check.py`'s corpus-local rarity can't see.
    """
    with _step(logger, domain, "Censys reverse lookups"):
        lookup = censys_discovery.reverse_lookup(payload.get("page_metadata"))
        lookup["observed_at"] = payload.get("timestamp")
        lookup["discovered"] = censys_discovery.discovered_domains(
            lookup, domain, basic._apex
        )
    if lookup.get("skipped") or lookup.get("error"):
        _log(
            logger,
            "info",
            f"Censys reverse lookup for {domain}: "
            f"{lookup.get('reason') or lookup.get('error')}",
        )
    else:
        _log(
            logger,
            "success",
            f"Censys reverse lookup for {domain}: {len(lookup['selectors'])} selectors, "
            f"{len(lookup['discovered'])} new domains",
        )
    return lookup


def _analyze_ip(ip: str, *, logger: StageLogger | None = None) -> dict[str, Any]:
    with _basic_runtime(logger):
        payload = basic.analyze_ip(ip)

    payload["input"] = ip
    payload["domain"] = ip
    payload["type"] = "ip"
    payload["live_probe"] = {
        "current_ips": [] if ":" in ip else [ip],
        "current_ipv6": [ip] if ":" in ip else [],
        "platform": None,
    }
    payload["freshness"] = {"current": [ip], "historical": []}
    payload["non_cf_ips"] = [] if payload.get("cloudflare") else [ip]
    payload["dns"] = {"A": [] if ":" in ip else [ip], "AAAA": [ip] if ":" in ip else []}
    payload["tls_certs"] = {
        "probes": [payload["tls_cert"]]
        if isinstance(payload.get("tls_cert"), dict) and not payload["tls_cert"].get("error")
        else []
    }
    payload["ssh_host_keys"] = {
        "probes": [payload["ssh_host_key"]]
        if isinstance(payload.get("ssh_host_key"), dict) and not payload["ssh_host_key"].get("error")
        else []
    }
    payload["comparison_labels"] = {
        "primary": ip,
        "display": ip,
    }
    return payload


def build_helper_rows(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "observed_ips": _observed_ips(payload),
        "tls_fingerprints": _tls_fingerprints(payload),
        "identifiers": _identifiers(payload),
        "provider_hits": _provider_hits(payload),
        "discovered_targets": _extract_discovered_targets(
            payload,
            str(payload.get("input") or payload.get("domain") or ""),
        ),
    }


def pairing_label(payload: dict[str, Any]) -> str:
    labels = payload.get("comparison_labels") or {}
    return str(
        labels.get("display")
        or labels.get("primary")
        or payload.get("domain")
        or payload.get("input")
        or "unknown"
    )


def _extract_discovered_targets(payload: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    discovered: list[dict[str, Any]] = []
    seen: set[str] = set()

    for subdomain in basic.pick_followup_subdomains(payload):
        normalized = clean_target(subdomain)
        if normalized and normalized != domain and normalized not in seen:
            seen.add(normalized)
            discovered.append(
                {
                    "target": normalized,
                    "kind": "subdomain_followup",
                    "reason": "follow-up subdomain leak",
                }
            )

    for sibling in basic.pick_sibling_domains(payload, domain):
        normalized = clean_target(str(sibling.get("domain") or ""))
        if normalized and normalized != domain and normalized not in seen:
            seen.add(normalized)
            discovered.append(
                {
                    "target": normalized,
                    "kind": "sibling_domain",
                    "reason": str(sibling.get("reason") or "sibling discovery"),
                }
            )

    # Reverse-lookup hits are queued like any other follow-up, but stamped with
    # REVERSE_LOOKUP_DISCOVERY_KIND — the flag profile_for() reads to give them a
    # free-only scan and to refuse them reverse lookups of their own.
    for candidate in (payload.get("censys_reverse_lookup") or {}).get("discovered", []) or []:
        normalized = clean_target(str(candidate.get("target") or ""))
        if normalized and normalized != domain and normalized not in seen:
            seen.add(normalized)
            discovered.append(
                {
                    "target": normalized,
                    "kind": REVERSE_LOOKUP_DISCOVERY_KIND,
                    "reason": (
                        f"shared {candidate.get('selector_kind')} "
                        f"{candidate.get('selector_value')} "
                        f"(Censys global prevalence {candidate.get('global_hits')})"
                    ),
                }
            )

    wordlist_hits = ((payload.get("origin_candidates") or {}).get("wordlist_leaks")) or []
    for candidate in ip_intel._select_wordlist_followup_targets(wordlist_hits):
        normalized = clean_target(str(candidate.get("subdomain") or ""))
        if normalized and normalized != domain and normalized not in seen:
            seen.add(normalized)
            discovered.append(
                {
                    "target": normalized,
                    "kind": "wordlist_subdomain",
                    "reason": "wordlist origin candidate",
                }
            )

    return discovered


def _observed_ips(payload: dict[str, Any]) -> list[dict[str, str]]:
    observed: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(ip: str, source: str) -> None:
        key = (ip, source)
        if not ip or key in seen:
            return
        seen.add(key)
        observed.append({"ip": ip, "source": source})

    dns_records = payload.get("dns") or {}
    for ip in dns_records.get("A", []) or []:
        add(str(ip), "dns:A")
    for ip in dns_records.get("AAAA", []) or []:
        add(str(ip), "dns:AAAA")
    for ip in payload.get("non_cf_ips", []) or []:
        add(str(ip), "non_cf")
    # Retired collectors (viewdns/shodan/netlas) are absent from any freshly
    # built payload, which is all this sees; historical payloads carrying them
    # are read by db/intel_db.py instead.
    for path, source in (
        ("hackertarget", "hackertarget"),
        ("urlscan", "urlscan"),
        ("censys", "censys"),
    ):
        for hit in (payload.get(path) or {}).get("hits", []) or []:
            ip = str(hit.get("ip") or "").strip()
            add(ip, source)
    for record in (payload.get("circl_pdns") or {}).get("records", []) or []:
        ip = str(record.get("rdata") or "").strip()
        if ip and ":" not in ip and ip.count(".") == 3:
            add(ip, "circl_pdns")
    if payload.get("type") == "ip":
        add(str(payload.get("input") or ""), "seed_ip")
    return observed


def _tls_fingerprints(payload: dict[str, Any]) -> list[dict[str, str]]:
    probes = (payload.get("tls_certs") or {}).get("probes", []) or []
    output: list[dict[str, str]] = []
    seen: set[str] = set()
    for probe in probes:
        fingerprint = str(probe.get("fingerprint_sha256") or "").strip()
        if not fingerprint or fingerprint in seen:
            continue
        seen.add(fingerprint)
        output.append(
            {
                "fingerprint_sha256": fingerprint,
                "cn": str(probe.get("cn") or ""),
                "issuer": str(probe.get("issuer_cn") or probe.get("issuer") or ""),
            }
        )
    return output


def _identifiers(payload: dict[str, Any]) -> list[dict[str, str]]:
    identifiers: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(category: str, value: Any) -> None:
        text = str(value or "").strip()
        key = (category, text)
        if not text or key in seen:
            return
        seen.add(key)
        identifiers.append({"category": category, "value": text})

    page_metadata = payload.get("page_metadata") or {}
    for field in (
        "google_analytics",
        "gtm_ids",
        "facebook_pixel",
        "tiktok_pixel",
        "yandex_metrika",
        "adsense_publisher_ids",
        "fb_app_id",
        "twitter_site",
        "twitter_creator",
        "authors",
        "rel_me",
        "source_map_urls",
        "social_handle_values",
        "phone_numbers",
        "crypto_wallet_values",
    ):
        raw_value = page_metadata.get(field) or []
        # Belt and braces behind signal_web.canonicalize_page_metadata, which
        # already list-wraps these. A scalar reaching here would be iterated as
        # a *string*, emitting one identifier per character — every site with a
        # Twitter handle would then share the selectors "a", "e", "o"… with
        # every other. Stored payloads predating the canonicalizer still carry
        # the scalar shape, so the guard has to live at the read site too.
        values = raw_value if isinstance(raw_value, (list, tuple, set)) else [raw_value]
        for value in values:
            add(f"page_metadata:{field}", value)

    email_security = payload.get("email_security") or {}
    for field in ("dmarc_report_uris", "spf_includes", "dkim_selectors", "bimi_logos"):
        for value in email_security.get(field, []) or []:
            add(f"email_security:{field}", value)

    for token in payload.get("txt_verification_tokens", []) or []:
        add("txt_verification_tokens", token)
    for email in (payload.get("whois") or {}).get("emails", []) or []:
        add("whois:email", email)
    add("whois:registrar", (payload.get("whois") or {}).get("registrar"))
    for ns in (payload.get("dns") or {}).get("NS", []) or []:
        add("dns:NS", ns)
    for value in (payload.get("nameserver_analysis") or {}).get("vanity_apexes", []) or []:
        add("nameserver_analysis:vanity_apexes", value)
    add("microsoft_tenant:tenant_guid", (payload.get("microsoft_tenant") or {}).get("tenant_guid"))
    for value in (payload.get("mail_client_config") or {}).get("servers", []) or []:
        add("mail_client_config:servers", value)
    for value in (payload.get("mail_client_config") or {}).get("domains", []) or []:
        add("mail_client_config:domains", value)
    for value in (payload.get("legal_pages") or {}).get("entity_names", []) or []:
        add("legal_pages:entity_names", value)
    for value in (payload.get("legal_pages") or {}).get("registration_ids", []) or []:
        add("legal_pages:registration_ids", value)
    for value in (payload.get("well_known") or {}).get("security_contacts", []) or []:
        add("well_known:security_contacts", value)
    for value in (payload.get("well_known") or {}).get("assetlinks_packages", []) or []:
        add("well_known:assetlinks_packages", value)
    for value in (payload.get("well_known") or {}).get("ads_txt_publishers", []) or []:
        add("well_known:ads_txt_publishers", value)
    return identifiers


def _normalize_ns_name(value: Any) -> str:
    """A nameserver hostname reduced to a comparable form (lowercase, no dot)."""
    return str(value or "").strip().rstrip(".").lower()


def _nameserver_delegation_check(
    dns_nameservers: Any, whois_nameservers: Any
) -> dict[str, Any]:
    """Compare the live NS delegation against the registrar's recorded one.

    The two arrive from different places and were never compared: `dns.NS` is
    what the zone actually answers with and feeds nameserver_analysis, while
    `whois.nameservers` is what the registrar has on file and is the only thing
    written to the `nameservers` table. Keeping both is nearly free — one DNS
    query and one WHOIS query we already make — but until now the redundancy
    bought nothing.

    A disagreement is worth surfacing: it is the normal signature of a
    delegation change in flight (a transfer, or a migration between DNS
    providers), and an abnormal one of a hijack via registrar account takeover,
    where the zone is repointed while WHOIS still shows the old operator.

    Returns empty when either side is missing — a WHOIS lookup that failed or a
    registry that does not publish nameservers is an absence of evidence, not a
    mismatch, and must not be reported as one.
    """
    live = {_normalize_ns_name(ns) for ns in (dns_nameservers or [])}
    live.discard("")
    raw_whois = whois_nameservers
    if isinstance(raw_whois, str):
        raw_whois = [raw_whois]
    registrar = {_normalize_ns_name(ns) for ns in (raw_whois or [])}
    registrar.discard("")

    if not live or not registrar:
        return {
            "whois_ns_mismatch": False,
            "whois_ns_comparable": False,
            "whois_ns_only": [],
            "dns_ns_only": [],
        }

    return {
        "whois_ns_mismatch": live != registrar,
        "whois_ns_comparable": True,
        # Named by where each one is missing from, so the direction is readable:
        # whois_ns_only = registrar still lists it but the zone does not answer
        # with it; dns_ns_only = the zone answers with it but WHOIS has not
        # caught up (or was never updated).
        "whois_ns_only": sorted(registrar - live),
        "dns_ns_only": sorted(live - registrar),
    }


def _provider_hits(payload: dict[str, Any]) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(provider: str, value: Any) -> None:
        text = str(value or "").strip()
        key = (provider, text)
        if not text or key in seen:
            return
        seen.add(key)
        hits.append({"provider": provider, "value": text})

    add("live_probe:platform", (payload.get("live_probe") or {}).get("platform"))
    add("whois:registrar", (payload.get("whois") or {}).get("registrar"))
    add("microsoft_tenant:issuer", (payload.get("microsoft_tenant") or {}).get("issuer"))
    for ns in (payload.get("nameserver_analysis") or {}).get("boring", []) or []:
        add("nameserver_provider", ns.get("apex"))
    return hits


def _collect_source_map_urls(payload: dict[str, Any]) -> list[str]:
    entries = payload.get("entries", []) or []
    urls: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        for url in entry.get("source_map_urls", []) or []:
            text = str(url or "").strip()
            if text and text not in seen:
                seen.add(text)
                urls.append(text)
    return urls


def _merge_page_metadata(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    merged = json.loads(json.dumps(base or {}))
    for key, value in (extra or {}).items():
        if isinstance(value, list):
            existing = merged.get(key) or []
            merged[key] = _merge_json_list(existing, value)
        elif isinstance(value, dict):
            existing = merged.get(key) or {}
            merged[key] = {**existing, **value}
        elif value not in (None, "", [], {}):
            merged[key] = value

    social_values: list[str] = []
    for source in (merged.get("social_handles") or {}).values():
        if isinstance(source, list):
            social_values.extend(str(item) for item in source if str(item or "").strip())
        elif str(source or "").strip():
            social_values.append(str(source))
    merged["social_handle_values"] = sorted({item.strip().lstrip("@") for item in social_values if item.strip()})

    wallet_values: list[str] = []
    for chain, addresses in (merged.get("crypto_wallets") or {}).items():
        chain_key = str(chain or "").strip().lower()
        if isinstance(addresses, list):
            candidates = [str(item) for item in addresses if str(item or "").strip()]
        elif str(addresses or "").strip():
            candidates = [str(addresses)]
        else:
            candidates = []
        for address in candidates:
            # Case-folding a Base58Check address destroys it; only the
            # case-insensitive encodings may be lowered. Same normalizer the
            # selector layer uses, so both engines key on one spelling.
            normalized = signal_web.normalize_crypto_address(chain_key, address)
            if chain_key and normalized:
                wallet_values.append(f"{chain_key}|{normalized}")
    merged["crypto_wallet_values"] = sorted(set(wallet_values))
    return merged


def _merge_json_list(existing: Any, incoming: Any) -> list[Any]:
    merged: list[Any] = []
    seen: set[str] = set()

    def add(value: Any) -> None:
        try:
            marker = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        except TypeError:
            marker = repr(value)
        if marker in seen:
            return
        seen.add(marker)
        merged.append(value)

    for value in existing if isinstance(existing, list) else []:
        add(value)
    for value in incoming if isinstance(incoming, list) else []:
        add(value)
    return merged


def _compact_well_known(raw: dict[str, Any]) -> dict[str, Any]:
    security_txt = (raw.get("security_txt") or {}).get("parsed") or {}
    # signal_web.WELL_KNOWN_PATHS names this fetcher `assetlinks_json`; reading
    # `assetlinks` returned {} for every domain ever scanned, so the Android
    # package names (pairwise weight 20, and bound to a Play developer account)
    # were never extracted. The async engine emits `assetlinks` already
    # unwrapped, so accept the parsed dict at either nesting.
    assetlinks_raw = raw.get("assetlinks_json") or raw.get("assetlinks") or {}
    assetlinks = assetlinks_raw.get("parsed") or assetlinks_raw or {}
    ads_txt = (raw.get("ads_txt") or {}).get("parsed") or {}
    apple_app = (raw.get("apple_app_site_association") or {}).get("parsed") or {}
    # Two parsers, two vocabularies for the same thing: the sync fetcher runs
    # `parse_assetlinks_json`, which emits a flat `package_names` list, while the
    # async engine runs `parse_assetlinks`, which emits `android_apps` records.
    # Reading only the latter is why this stayed empty even after the key-name
    # fix above — the nesting was right and the field was still wrong.
    assetlinks_packages = [
        str(name) for name in assetlinks.get("package_names") or [] if name
    ]
    assetlinks_packages.extend(
        item.get("package_name")
        for item in assetlinks.get("android_apps") or []
        if isinstance(item, dict) and item.get("package_name")
    )
    return {
        "security_contacts": security_txt.get("contacts", []) or [],
        "assetlinks_packages": sorted(set(assetlinks_packages)),
        "ads_txt_publishers": ads_txt.get("publisher_ids", []) or [],
        "apple_app_ids": [
            item.get("appID")
            for item in apple_app.get("applinks", []) or []
            if isinstance(item, dict) and item.get("appID")
        ],
        "raw": raw,
    }


def _compact_legal_pages(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "pages": raw.get("pages", []) or [],
        "entity_names": raw.get("entity_names", []) or [],
        "registration_ids": raw.get("registration_ids", []) or [],
        "addresses": raw.get("addresses", []) or [],
        "phones": raw.get("phones", []) or [],
        "emails": raw.get("emails", []) or [],
    }


def _compact_mail_client_config(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "autodiscover": raw.get("autodiscover", []) or [],
        "autoconfig": raw.get("autoconfig", []) or [],
        "servers": raw.get("servers", []) or [],
        "domains": raw.get("domains", []) or [],
    }


def _flatten_report_uris(value: Any) -> list[str]:
    # parse_dmarc_report_uris returns {"rua": [...], "ruf": [...]}; iterating
    # the dict directly yielded the tag names "rua"/"ruf", which then matched
    # between every pair of DMARC-enabled domains. Flatten the URI entries.
    if isinstance(value, dict):
        items: list[Any] = [entry for uris in value.values() for entry in (uris or [])]
    else:
        items = list(value or [])

    flattened: list[str] = []
    for item in items:
        if isinstance(item, dict):
            address = item.get("address") or item.get("raw")
            if address:
                flattened.append(str(address).lower())
        elif str(item or "").strip():
            flattened.append(str(item).lower())
    return sorted({item for item in flattened if item})


def _dkim_selectors(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    selectors: list[str] = []
    for selector, entry in value.items():
        records = entry.get("records") if isinstance(entry, dict) else []
        if records:
            selectors.append(str(selector))
    return sorted({item for item in selectors if item})


def _bimi_logos(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    logos: list[str] = []
    for entry in value.values():
        records = entry.get("records") if isinstance(entry, dict) else []
        for record in records or []:
            logos.append(str(record))
    return sorted({item for item in logos if item})


# _collect_source_errors was removed with the source-error retry path: nothing
# read payload["source_errors"] except integrations.opencti_ingest's
# retry_source_errors and db.intel_db.get_domains_with_source_errors, both of
# which are gone. The nullable `searches.source_errors` column is left in place
# rather than migrated away, so rows written before this change still read back.


def _log(logger: StageLogger | None, level: str, message: str) -> None:
    if logger is not None:
        logger(level, message)


def _run_parity_step(
    logger: StageLogger | None, domain: str, label: str, step: Callable[[], dict[str, Any]]
) -> dict[str, Any]:
    """Run one parity step inside its timing log, in a worker thread.

    Module-level rather than a closure so the timing/log contract stays in one
    place next to _step, and so the fan-out submits a plain function.
    """
    with _step(logger, domain, label):
        return step()


@contextmanager
def _step(logger: StageLogger | None, domain: str, label: str):
    """Log entry+exit (with elapsed) around one parity enrichment step.

    Each parity step is a blocking network call (autodiscover/autoconfig probes,
    page + well-known + legal-page fetches, wordlist DNS sweeps) that can take
    tens of seconds, and previously the whole block ran silently between
    "Running parity enrichments" and "annotating IP freshness" — so a slow step
    looked like a hang. The entry line names the step *before* it blocks (so a
    stall is attributable in real time); the exit line always fires, even on
    error, and flags anything slow so the culprit is obvious in the log.
    """
    start = time.monotonic()
    _log(logger, "info", f"  parity[{domain}]: {label}…")
    try:
        yield
    finally:
        elapsed = time.monotonic() - start
        slow = "  <== SLOW" if elapsed >= 10 else ""
        _log(logger, "info", f"  parity[{domain}]: {label} done in {elapsed:.1f}s{slow}")
