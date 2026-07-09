from __future__ import annotations

import csv
import io
import json
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable

from core import basic
from core import ip_intel
from sources import signal_dns
from sources import signal_web


StageLogger = Callable[[str, str], None]


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
    if target_type == "ip":
        payload = _analyze_ip(normalized_target, logger=logger)
    else:
        # Paid cert-search providers (Censys/Shodan/Netlas) run once per target,
        # so only fire them on apex-level domains. A seed is always honored even
        # if entered as a subdomain; discovered subdomain follow-ups inherit
        # their apex's provider coverage and skip the calls.
        is_apex = basic._apex(normalized_target) == normalized_target
        run_providers = is_seed or is_apex
        payload = _analyze_domain(
            normalized_target, logger=logger, run_providers=run_providers
        )

    payload["scan_depth"] = depth
    payload["discovered_from"] = discovered_from
    payload["discovery_reason"] = discovery_reason
    payload["discovery_kind"] = discovery_kind
    payload["is_seed"] = is_seed

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
        intel_db.save_search(payload)
    except Exception as exc:  # pragma: no cover - defensive; correlation is rebuildable
        _log(logger, "warning", f"Intel store save failed: {exc}")

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
    run_providers: bool = True,
) -> dict[str, Any]:
    with _basic_runtime(logger):
        payload = basic.analyze(
            domain,
            is_followup=True,
            all_results=None,
            overall_bar=None,
            follow_siblings=False,
            run_providers=run_providers,
        )

    payload["input"] = domain
    payload["type"] = "domain"
    payload.setdefault("domain", domain)

    dns_records = payload.get("dns") or {}
    txt_records = dns_records.get("TXT") or []
    mx_records = dns_records.get("MX") or []
    nameservers = dns_records.get("NS") or []

    _log(logger, "info", "Running parity enrichments")
    payload["email_security"] = signal_dns.get_email_security_records(domain)
    spf_details = signal_dns.collect_spf_details(domain, txt_records=txt_records)
    payload["email_security"]["spf_includes"] = spf_details.get("includes", [])
    payload["email_security"]["spf_records"] = spf_details.get("records", [])
    payload["email_security"]["dmarc_report_uris"] = _flatten_report_uris(
        payload["email_security"].get("dmarc_report_uris")
    )
    payload["email_security"]["dkim_selectors"] = _dkim_selectors(payload["email_security"].get("dkim"))
    payload["email_security"]["bimi_logos"] = _bimi_logos(payload["email_security"].get("bimi"))
    payload["spf_origins"] = spf_details.get("origins", [])
    payload["txt_verification_tokens"] = [
        f"{token['provider']}:{token['token']}"
        for token in signal_dns.extract_txt_tenancy_tokens(txt_records)
        if token.get("provider") and token.get("token")
    ]
    payload["nameserver_analysis"] = ip_intel._classify_nameservers(nameservers)
    payload["nameserver_analysis"]["vanity_apexes"] = sorted(
        {
            str(item.get("apex") or "").lower()
            for item in payload["nameserver_analysis"].get("vanity_candidates", [])
            if str(item.get("apex") or "").strip()
        }
    )
    payload["zone_transfer"] = ip_intel.attempt_zone_transfer(domain, nameservers)
    payload["well_known"] = _compact_well_known(signal_web.fetch_well_known_files(domain))
    payload["legal_pages"] = _compact_legal_pages(signal_web.scrape_legal_pages(domain))
    payload["mail_client_config"] = _compact_mail_client_config(signal_web.probe_mail_client_config(domain))
    payload["microsoft_tenant"] = signal_dns.probe_microsoft_tenant_sync(domain)
    payload["page_metadata"] = _merge_page_metadata(
        payload.get("page_metadata") or {},
        signal_web.fetch_page_metadata(domain),
    )
    payload["page_metadata"]["source_map_urls"] = _collect_source_map_urls(
        signal_web.fetch_source_map_disclosures(
            payload["page_metadata"].get("script_assets")
            or payload["page_metadata"].get("final_url")
            or domain
        )
    )
    payload["origin_candidates"] = {
        "subdomain_leaks": ip_intel.probe_subdomain_origins(
            (payload.get("crt_sh") or {}).get("subdomains", [])
        ),
        "mx_leaks": ip_intel.probe_mx_origins(mx_records),
        "wordlist_leaks": ip_intel.probe_wordlist_subdomains(domain),
        "hackertarget": (payload.get("hackertarget") or {}).get("hits", []),
        "viewdns": (payload.get("viewdns") or {}).get("hits", []),
        "urlscan": (payload.get("urlscan") or {}).get("hits", []),
        "censys": _provider_origin_candidates(payload, "censys"),
        "scan": {"skipped": True, "reason": "Targeted origin scan is not enabled for case mode."},
        "provider_scan": {"skipped": True, "reason": "Provider scan is not enabled for case mode."},
        "country_scan": {"skipped": True, "reason": "Country scan is not enabled for case mode."},
    }
    payload["source_errors"] = _collect_source_errors(payload)
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
    saving. Shodan/Netlas remain dormant compatibility helpers and are not
    promoted by the web pipeline.
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
    for path, source in (
        ("hackertarget", "hackertarget"),
        ("viewdns", "viewdns"),
        ("urlscan", "urlscan"),
        ("censys", "censys"),
        ("shodan", "shodan"),
        ("netlas", "netlas"),
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
    ):
        for value in page_metadata.get(field, []) or []:
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
    assetlinks = (raw.get("assetlinks") or {}).get("parsed") or {}
    ads_txt = (raw.get("ads_txt") or {}).get("parsed") or {}
    apple_app = (raw.get("apple_app_site_association") or {}).get("parsed") or {}
    return {
        "security_contacts": security_txt.get("contacts", []) or [],
        "assetlinks_packages": [
            item.get("package_name")
            for item in assetlinks.get("android_apps", []) or []
            if item.get("package_name")
        ],
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


def _collect_source_errors(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key in (
        "dns",
        "whois",
        "crt_sh",
        "circl_pdns",
        "hackertarget",
        "viewdns",
        "urlscan",
        "censys",
        "shodan",
        "netlas",
        "page_metadata",
        "email_security",
        "well_known",
        "legal_pages",
        "mail_client_config",
        "microsoft_tenant",
    ):
        value = payload.get(key)
        if isinstance(value, dict) and value.get("error"):
            errors.append(f"{key}:{value['error']}")
    return errors


def _log(logger: StageLogger | None, level: str, message: str) -> None:
    if logger is not None:
        logger(level, message)
