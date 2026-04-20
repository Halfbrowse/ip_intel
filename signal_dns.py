from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from typing import Any

import httpx

try:
    import dns.asyncresolver
    import dns.exception
    import dns.resolver
except ImportError:  # pragma: no cover - project runtime ships dnspython
    dns = None  # type: ignore[assignment]


TxtFetcher = Callable[[str], Awaitable[Iterable[Any]]]
SyncTxtFetcher = Callable[[str], Iterable[Any]]

DEFAULT_BIMI_SELECTORS = ("default",)
MICROSOFT_OPENID_CONFIG_URLS = (
    "https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration",
    "https://login.microsoftonline.com/{domain}/.well-known/openid-configuration",
    "https://login.windows.net/{domain}/.well-known/openid-configuration",
)
DEFAULT_DKIM_SELECTOR_CONFIG: dict[str, tuple[str, ...]] = {
    "google_workspace": ("google",),
    "microsoft_365": ("selector1", "selector2"),
    "amazonses": ("amazonses",),
    "mailchimp": ("k1", "k2"),
    "sendgrid": ("s1", "s2"),
    "yandex": ("mail", "yandex"),
    "generic": ("default", "mail", "dkim"),
}
TENANCY_TOKEN_SPECS = (
    {
        "provider": "microsoft_365",
        "token": "MS",
        "pattern": re.compile(r"^MS=(?P<value>[A-Za-z0-9._:/+=-]+)$", re.IGNORECASE),
    },
    {
        "provider": "google_workspace",
        "token": "google-site-verification",
        "pattern": re.compile(
            r"^google-site-verification=(?P<value>.+)$",
            re.IGNORECASE,
        ),
    },
    {
        "provider": "facebook",
        "token": "facebook-domain-verification",
        "pattern": re.compile(
            r"^facebook-domain-verification=(?P<value>.+)$",
            re.IGNORECASE,
        ),
    },
    {
        "provider": "atlassian",
        "token": "atlassian-domain-verification",
        "pattern": re.compile(
            r"^atlassian-domain-verification=(?P<value>.+)$",
            re.IGNORECASE,
        ),
    },
    {
        "provider": "dropbox",
        "token": "dropbox-domain-verification",
        "pattern": re.compile(
            r"^dropbox-domain-verification=(?P<value>.+)$",
            re.IGNORECASE,
        ),
    },
    {
        "provider": "adobe",
        "token": "adobe-idp-site-verification",
        "pattern": re.compile(
            r"^adobe-idp-site-verification=(?P<value>.+)$",
            re.IGNORECASE,
        ),
    },
    {
        "provider": "apple_business_manager",
        "token": "apple-domain-verification",
        "pattern": re.compile(
            r"^apple-domain-verification=(?P<value>.+)$",
            re.IGNORECASE,
        ),
    },
    {
        "provider": "box",
        "token": "box-domain-verification",
        "pattern": re.compile(
            r"^box-domain-verification=(?P<value>.+)$",
            re.IGNORECASE,
        ),
    },
    {
        "provider": "canva",
        "token": "canva-site-verification",
        "pattern": re.compile(
            r"^canva-site-verification=(?P<value>.+)$",
            re.IGNORECASE,
        ),
    },
    {
        "provider": "knowbe4",
        "token": "knowbe4-site-verification",
        "pattern": re.compile(
            r"^knowbe4-site-verification=(?P<value>.+)$",
            re.IGNORECASE,
        ),
    },
    {
        "provider": "proofpoint",
        "token": "proofpoint-domain-verification",
        "pattern": re.compile(
            r"^proofpoint-domain-verification=(?P<value>.+)$",
            re.IGNORECASE,
        ),
    },
    {
        "provider": "servicenow",
        "token": "servicenow-domain-verification",
        "pattern": re.compile(
            r"^servicenow-domain-verification=(?P<value>.+)$",
            re.IGNORECASE,
        ),
    },
    {
        "provider": "stripe",
        "token": "stripe-verification",
        "pattern": re.compile(
            r"^stripe-verification=(?P<value>.+)$",
            re.IGNORECASE,
        ),
    },
    {
        "provider": "zoom",
        "token": "ZOOM_verify_",
        "pattern": re.compile(r"^(?P<value>ZOOM_verify_[A-Za-z0-9_-]+)$"),
    },
    {
        "provider": "zoom",
        "token": "zoom-domain-verification",
        "pattern": re.compile(
            r"^zoom-domain-verification=(?P<value>.+)$",
            re.IGNORECASE,
        ),
    },
    {
        "provider": "docusign",
        "token": "docusign",
        "pattern": re.compile(r"^docusign=(?P<value>.+)$", re.IGNORECASE),
    },
)

_DMARC_MAILTO_RE = re.compile(
    r"^\s*mailto:(?P<address>[^!\s,;]+)(?:!(?P<size_limit>[^,\s;]+))?\s*$",
    re.IGNORECASE,
)
_GUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_SPF_TERM_RE = re.compile(
    r"^(?P<qualifier>[+\-~?]?)(?P<name>[A-Za-z0-9_]+)(?::(?P<value>.+))?$"
)


def _unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _normalize_domain(domain: str) -> str:
    return str(domain or "").strip().rstrip(".").lower()


def _strip_wrapping_quotes(value: str) -> str:
    text = str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return text[1:-1]
    return text


def _coerce_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    strings = getattr(value, "strings", None)
    if strings is not None:
        parts: list[str] = []
        for part in strings:
            parts.append(_coerce_text(part))
        return "".join(parts)
    to_text = getattr(value, "to_text", None)
    if callable(to_text):
        return str(to_text())
    return str(value)


def _first_prefixed_record(records: Iterable[str], prefix: str) -> str | None:
    prefix_lower = prefix.lower()
    for record in records:
        if record.lower().startswith(prefix_lower):
            return record
    return None


def normalize_txt_records(records: Iterable[Any] | Any) -> list[str]:
    if records is None:
        return []
    if isinstance(records, (str, bytes)):
        return [_strip_wrapping_quotes(_coerce_text(records))]

    result: list[str] = []
    for record in records:
        text = _strip_wrapping_quotes(_coerce_text(record))
        if text:
            result.append(text)
    return result


def build_dmarc_name(domain: str) -> str:
    return f"_dmarc.{_normalize_domain(domain)}"


def build_dkim_name(domain: str, selector: str) -> str:
    return f"{selector.strip().rstrip('.')}._domainkey.{_normalize_domain(domain)}"


def build_bimi_name(domain: str, selector: str = "default") -> str:
    return f"{selector.strip().rstrip('.')}._bimi.{_normalize_domain(domain)}"


def build_mta_sts_name(domain: str) -> str:
    return f"_mta-sts.{_normalize_domain(domain)}"


def build_tls_rpt_name(domain: str) -> str:
    return f"_smtp._tls.{_normalize_domain(domain)}"


def extract_tenancy_tokens(
    txt_records: Iterable[Any] | Any,
    token_specs: Sequence[Mapping[str, Any]] | None = None,
) -> list[dict[str, str]]:
    specs = token_specs or TENANCY_TOKEN_SPECS
    matches: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()

    for record in normalize_txt_records(txt_records):
        for spec in specs:
            pattern = spec["pattern"]
            if isinstance(pattern, str):
                pattern = re.compile(pattern, re.IGNORECASE)
            match = pattern.match(record)
            if not match:
                continue
            group = spec.get("group", "value")
            value = match.group(group) if group in match.groupdict() else match.group(1)
            item = {
                "provider": str(spec["provider"]),
                "token": str(spec.get("token", spec["provider"])),
                "value": value,
                "record": record,
            }
            key = (item["provider"], item["token"], item["value"], item["record"])
            if key not in seen:
                seen.add(key)
                matches.append(item)
    return matches


def parse_dmarc_report_uris(dmarc_record: str) -> dict[str, list[dict[str, str | None]]]:
    tags: dict[str, str] = {}
    for chunk in str(dmarc_record or "").split(";"):
        piece = chunk.strip()
        if not piece or "=" not in piece:
            continue
        key, value = piece.split("=", 1)
        tags[key.strip().lower()] = value.strip()

    parsed: dict[str, list[dict[str, str | None]]] = {"rua": [], "ruf": []}
    for field in ("rua", "ruf"):
        for uri in tags.get(field, "").split(","):
            match = _DMARC_MAILTO_RE.match(uri)
            if not match:
                continue
            parsed[field].append(
                {
                    "scheme": "mailto",
                    "address": match.group("address"),
                    "size_limit": match.group("size_limit"),
                    "raw": uri.strip(),
                }
            )
    return parsed


def _empty_dmarc_report_uris() -> dict[str, list[dict[str, str | None]]]:
    return {"rua": [], "ruf": []}


def parse_spf_record(record: str) -> dict[str, Any]:
    text = str(record or "").strip()
    parsed: dict[str, Any] = {
        "record": text,
        "is_spf": text.lower().startswith("v=spf1"),
        "ip4": [],
        "ip6": [],
        "includes": [],
        "redirect": None,
        "mechanisms": [],
    }
    if not parsed["is_spf"]:
        return parsed

    for term in text.split()[1:]:
        if not term:
            continue
        if "=" in term and not term.startswith(("ip4:", "ip6:", "include:")):
            key, value = term.split("=", 1)
            if key.lower() == "redirect":
                parsed["redirect"] = _normalize_domain(value)
            parsed["mechanisms"].append(
                {
                    "qualifier": "",
                    "name": key.lower(),
                    "value": value,
                    "raw": term,
                }
            )
            continue

        match = _SPF_TERM_RE.match(term)
        if not match:
            continue

        name = match.group("name").lower()
        value = match.group("value")
        mechanism = {
            "qualifier": match.group("qualifier") or "",
            "name": name,
            "value": value,
            "raw": term,
        }
        parsed["mechanisms"].append(mechanism)

        if name == "ip4" and value:
            parsed["ip4"].append(value)
        elif name == "ip6" and value:
            parsed["ip6"].append(value)
        elif name == "include" and value:
            parsed["includes"].append(_normalize_domain(value))

    parsed["ip4"] = _unique(parsed["ip4"])
    parsed["ip6"] = _unique(parsed["ip6"])
    parsed["includes"] = _unique(parsed["includes"])
    return parsed


def parse_spf_txt_records(txt_records: Iterable[Any] | Any) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    ip4: list[str] = []
    ip6: list[str] = []
    includes: list[str] = []
    redirects: list[str] = []

    for record in normalize_txt_records(txt_records):
        parsed = parse_spf_record(record)
        if not parsed["is_spf"]:
            continue
        records.append(parsed)
        ip4.extend(parsed["ip4"])
        ip6.extend(parsed["ip6"])
        includes.extend(parsed["includes"])
        if parsed["redirect"]:
            redirects.append(parsed["redirect"])

    return {
        "records": records,
        "ip4": _unique(ip4),
        "ip6": _unique(ip6),
        "includes": _unique(includes),
        "redirects": _unique(redirects),
    }


def extract_spf_origins(txt_records: Iterable[Any] | Any) -> list[dict[str, str]]:
    parsed = parse_spf_txt_records(txt_records)
    origins: list[dict[str, str]] = []
    for cidr in [*parsed["ip4"], *parsed["ip6"]]:
        origins.append(
            {
                "ip": cidr.split("/", 1)[0],
                "cidr": cidr,
                "source": "SPF record",
            }
        )
    return origins


async def lookup_txt_records(name: str, resolver: Any | None = None) -> list[str]:
    if resolver is None:
        if dns is None:
            raise RuntimeError("dnspython is required for TXT lookups")
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 8

    try:
        answers = await resolver.resolve(name, "TXT")
    except Exception as exc:  # pragma: no cover - exercised with dnspython in runtime
        if dns is not None and isinstance(
            exc,
            (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.exception.Timeout,
                dns.exception.DNSException,
            ),
        ):
            return []
        raise
    return normalize_txt_records(answers)


def lookup_txt_records_sync(name: str, resolver: Any | None = None) -> list[str]:
    if resolver is None:
        if dns is None:
            raise RuntimeError("dnspython is required for TXT lookups")
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 8

    try:
        answers = resolver.resolve(name, "TXT")
    except Exception as exc:  # pragma: no cover - exercised with dnspython in runtime
        if dns is not None and isinstance(
            exc,
            (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.exception.Timeout,
                dns.exception.DNSException,
            ),
        ):
            return []
        raise
    return normalize_txt_records(answers)


async def resolve_spf_chain(
    domain: str,
    *,
    txt_records: Iterable[Any] | Any | None = None,
    txt_cache: Mapping[str, Iterable[Any]] | None = None,
    txt_fetcher: TxtFetcher | None = None,
    resolver: Any | None = None,
    max_depth: int = 5,
    max_lookups: int = 20,
) -> dict[str, Any]:
    root = _normalize_domain(domain)
    cache = {
        _normalize_domain(name): normalize_txt_records(records)
        for name, records in (txt_cache or {}).items()
    }
    visited: set[str] = set()
    lookups = 0
    results: dict[str, Any] = {
        "domain": root,
        "domains": {},
        "visited": [],
        "lookups": 0,
        "ip4": [],
        "ip6": [],
        "includes": [],
        "redirects": [],
        "errors": [],
    }

    async def _fetch(name: str) -> list[str]:
        key = _normalize_domain(name)
        if key in cache:
            return cache[key]
        if key == root and txt_records is not None:
            cache[key] = normalize_txt_records(txt_records)
            return cache[key]
        if txt_fetcher is not None:
            cache[key] = normalize_txt_records(await txt_fetcher(key))
            return cache[key]
        cache[key] = await lookup_txt_records(key, resolver=resolver)
        return cache[key]

    async def _walk(name: str, depth: int) -> None:
        nonlocal lookups
        key = _normalize_domain(name)
        if not key or key in visited:
            return
        if depth > max_depth:
            results["errors"].append({"domain": key, "error": "max_depth_exceeded"})
            return
        if lookups >= max_lookups:
            results["errors"].append({"domain": key, "error": "max_lookups_exceeded"})
            return

        visited.add(key)
        lookups += 1

        try:
            parsed = parse_spf_txt_records(await _fetch(key))
        except Exception as exc:
            results["errors"].append({"domain": key, "error": str(exc)})
            return

        results["domains"][key] = parsed
        results["ip4"] = _unique([*results["ip4"], *parsed["ip4"]])
        results["ip6"] = _unique([*results["ip6"], *parsed["ip6"]])
        results["includes"] = _unique([*results["includes"], *parsed["includes"]])
        results["redirects"] = _unique([*results["redirects"], *parsed["redirects"]])

        children = [*parsed["includes"], *parsed["redirects"]]
        for child in children:
            await _walk(child, depth + 1)

    await _walk(root, 0)
    results["visited"] = sorted(visited)
    results["lookups"] = lookups
    return results


def resolve_spf_chain_sync(
    domain: str,
    *,
    txt_records: Iterable[Any] | Any | None = None,
    txt_cache: Mapping[str, Iterable[Any]] | None = None,
    txt_fetcher: SyncTxtFetcher | None = None,
    resolver: Any | None = None,
    max_depth: int = 5,
    max_lookups: int = 20,
) -> dict[str, Any]:
    root = _normalize_domain(domain)
    cache = {
        _normalize_domain(name): normalize_txt_records(records)
        for name, records in (txt_cache or {}).items()
    }
    visited: set[str] = set()
    lookups = 0
    results: dict[str, Any] = {
        "domain": root,
        "domains": {},
        "visited": [],
        "lookups": 0,
        "ip4": [],
        "ip6": [],
        "includes": [],
        "redirects": [],
        "errors": [],
    }

    def _fetch(name: str) -> list[str]:
        key = _normalize_domain(name)
        if key in cache:
            return cache[key]
        if key == root and txt_records is not None:
            cache[key] = normalize_txt_records(txt_records)
            return cache[key]
        if txt_fetcher is not None:
            cache[key] = normalize_txt_records(txt_fetcher(key))
            return cache[key]
        cache[key] = lookup_txt_records_sync(key, resolver=resolver)
        return cache[key]

    def _walk(name: str, depth: int) -> None:
        nonlocal lookups
        key = _normalize_domain(name)
        if not key or key in visited:
            return
        if depth > max_depth:
            results["errors"].append({"domain": key, "error": "max_depth_exceeded"})
            return
        if lookups >= max_lookups:
            results["errors"].append({"domain": key, "error": "max_lookups_exceeded"})
            return

        visited.add(key)
        lookups += 1

        try:
            parsed = parse_spf_txt_records(_fetch(key))
        except Exception as exc:
            results["errors"].append({"domain": key, "error": str(exc)})
            return

        results["domains"][key] = parsed
        results["ip4"] = _unique([*results["ip4"], *parsed["ip4"]])
        results["ip6"] = _unique([*results["ip6"], *parsed["ip6"]])
        results["includes"] = _unique([*results["includes"], *parsed["includes"]])
        results["redirects"] = _unique([*results["redirects"], *parsed["redirects"]])

        for child in [*parsed["includes"], *parsed["redirects"]]:
            _walk(child, depth + 1)

    _walk(root, 0)
    results["visited"] = sorted(visited)
    results["lookups"] = lookups
    return results


def parse_caa_records(caa_records: Iterable[Any] | Any) -> list[dict[str, Any]]:
    if caa_records is None:
        return []
    if isinstance(caa_records, (str, bytes)):
        caa_records = [caa_records]

    parsed_records: list[dict[str, Any]] = []
    for record in caa_records:
        flags = getattr(record, "flags", None)
        tag = getattr(record, "tag", None)
        value = getattr(record, "value", None)

        if tag is None or value is None:
            text = _strip_wrapping_quotes(_coerce_text(record))
            match = re.match(r"^\s*(\d+)\s+([A-Za-z0-9-]+)\s+(.+?)\s*$", text)
            if not match:
                continue
            flags = int(match.group(1))
            tag = match.group(2)
            value = _strip_wrapping_quotes(match.group(3))
        else:
            flags = int(flags)
            tag = _coerce_text(tag)
            value = _strip_wrapping_quotes(_coerce_text(value))

        tag_text = str(tag).lower()
        params: dict[str, str | bool] = {}
        issuer_domain: str | None = None
        accounturi: str | None = None

        if tag_text in {"issue", "issuewild"}:
            parts = [part.strip() for part in value.split(";")]
            issuer_domain = parts[0] or None
            for part in parts[1:]:
                if not part:
                    continue
                if "=" in part:
                    key, param_value = part.split("=", 1)
                    params[key.strip().lower()] = param_value.strip()
                else:
                    params[part.lower()] = True
            accounturi = (
                str(params["accounturi"])
                if isinstance(params.get("accounturi"), str)
                else None
            )

        parsed_records.append(
            {
                "flags": flags,
                "critical": bool(flags & 128),
                "tag": tag_text,
                "value": value,
                "issuer_domain": issuer_domain,
                "parameters": params,
                "accounturi": accounturi,
            }
        )

    return parsed_records


def expand_dkim_selectors(
    domain: str,
    config: Mapping[str, Sequence[Any]] | Sequence[Any] | None = None,
) -> list[dict[str, str]]:
    target = _normalize_domain(domain)
    selector_items: list[tuple[str, Any]]
    if config is None:
        selector_items = list(DEFAULT_DKIM_SELECTOR_CONFIG.items())
    elif isinstance(config, Mapping):
        selector_items = list(config.items())
    else:
        selector_items = [("custom", config)]

    expanded: list[dict[str, str]] = []
    seen: set[str] = set()
    for provider, selectors in selector_items:
        entries = selectors if isinstance(selectors, Sequence) and not isinstance(selectors, str) else [selectors]
        for entry in entries:
            if isinstance(entry, Mapping):
                selector = str(entry.get("selector", "")).strip()
                template = str(
                    entry.get("fqdn_template", "{selector}._domainkey.{domain}")
                )
                provider_name = str(entry.get("provider", provider))
            else:
                selector = str(entry).strip()
                template = "{selector}._domainkey.{domain}"
                provider_name = str(provider)
            if not selector:
                continue
            fqdn = template.format(domain=target, selector=selector).rstrip(".")
            if fqdn in seen:
                continue
            seen.add(fqdn)
            expanded.append(
                {
                    "provider": provider_name,
                    "selector": selector,
                    "fqdn": fqdn,
                }
            )
    return expanded


async def lookup_dmarc_record(domain: str, *, resolver: Any | None = None) -> dict[str, Any]:
    name = build_dmarc_name(domain)
    records = await lookup_txt_records(name, resolver=resolver)
    record = _first_prefixed_record(records, "v=DMARC1")
    return {
        "name": name,
        "records": records,
        "record": record,
        "report_uris": parse_dmarc_report_uris(record) if record else _empty_dmarc_report_uris(),
    }


def lookup_dmarc_record_sync(domain: str, *, resolver: Any | None = None) -> dict[str, Any]:
    name = build_dmarc_name(domain)
    records = lookup_txt_records_sync(name, resolver=resolver)
    record = _first_prefixed_record(records, "v=DMARC1")
    return {
        "name": name,
        "records": records,
        "record": record,
        "report_uris": parse_dmarc_report_uris(record) if record else _empty_dmarc_report_uris(),
    }


def _build_dkim_lookup_result(
    candidates: Sequence[Mapping[str, str]],
    records_by_candidate: Sequence[list[str]],
) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for candidate, records in zip(candidates, records_by_candidate):
        if not records:
            continue
        found[str(candidate["selector"])] = {
            "provider": str(candidate["provider"]),
            "selector": str(candidate["selector"]),
            "fqdn": str(candidate["fqdn"]),
            "records": records,
        }
    return found


async def lookup_dkim_records(
    domain: str,
    *,
    config: Mapping[str, Sequence[Any]] | Sequence[Any] | None = None,
    resolver: Any | None = None,
) -> dict[str, dict[str, Any]]:
    candidates = expand_dkim_selectors(domain, config=config)
    records = await asyncio.gather(
        *(lookup_txt_records(candidate["fqdn"], resolver=resolver) for candidate in candidates)
    )
    return _build_dkim_lookup_result(candidates, records)


def lookup_dkim_records_sync(
    domain: str,
    *,
    config: Mapping[str, Sequence[Any]] | Sequence[Any] | None = None,
    resolver: Any | None = None,
) -> dict[str, dict[str, Any]]:
    candidates = expand_dkim_selectors(domain, config=config)
    records = [
        lookup_txt_records_sync(candidate["fqdn"], resolver=resolver)
        for candidate in candidates
    ]
    return _build_dkim_lookup_result(candidates, records)


async def lookup_bimi_records(
    domain: str,
    *,
    selectors: Sequence[str] = DEFAULT_BIMI_SELECTORS,
    resolver: Any | None = None,
) -> dict[str, list[str]]:
    names = [build_bimi_name(domain, selector) for selector in selectors]
    records = await asyncio.gather(*(lookup_txt_records(name, resolver) for name in names))
    return {selector: record_set for selector, record_set in zip(selectors, records)}


async def lookup_mta_sts_records(domain: str, *, resolver: Any | None = None) -> list[str]:
    return await lookup_txt_records(build_mta_sts_name(domain), resolver=resolver)


async def lookup_tls_rpt_records(domain: str, *, resolver: Any | None = None) -> list[str]:
    return await lookup_txt_records(build_tls_rpt_name(domain), resolver=resolver)


async def lookup_mail_txt_records(
    domain: str,
    *,
    bimi_selectors: Sequence[str] = DEFAULT_BIMI_SELECTORS,
    resolver: Any | None = None,
) -> dict[str, Any]:
    bimi, mta_sts, tls_rpt = await asyncio.gather(
        lookup_bimi_records(domain, selectors=bimi_selectors, resolver=resolver),
        lookup_mta_sts_records(domain, resolver=resolver),
        lookup_tls_rpt_records(domain, resolver=resolver),
    )
    return {
        "bimi": {
            selector: {
                "name": build_bimi_name(domain, selector),
                "records": records,
            }
            for selector, records in bimi.items()
        },
        "mta_sts": {
            "name": build_mta_sts_name(domain),
            "records": mta_sts,
        },
        "tls_rpt": {
            "name": build_tls_rpt_name(domain),
            "records": tls_rpt,
        },
    }


def lookup_bimi_records_sync(
    domain: str,
    *,
    selectors: Sequence[str] = DEFAULT_BIMI_SELECTORS,
    resolver: Any | None = None,
) -> dict[str, list[str]]:
    return {
        selector: lookup_txt_records_sync(build_bimi_name(domain, selector), resolver=resolver)
        for selector in selectors
    }


def lookup_mta_sts_records_sync(domain: str, *, resolver: Any | None = None) -> list[str]:
    return lookup_txt_records_sync(build_mta_sts_name(domain), resolver=resolver)


def lookup_tls_rpt_records_sync(domain: str, *, resolver: Any | None = None) -> list[str]:
    return lookup_txt_records_sync(build_tls_rpt_name(domain), resolver=resolver)


def lookup_mail_txt_records_sync(
    domain: str,
    *,
    bimi_selectors: Sequence[str] = DEFAULT_BIMI_SELECTORS,
    resolver: Any | None = None,
) -> dict[str, Any]:
    bimi = lookup_bimi_records_sync(domain, selectors=bimi_selectors, resolver=resolver)
    mta_sts = lookup_mta_sts_records_sync(domain, resolver=resolver)
    tls_rpt = lookup_tls_rpt_records_sync(domain, resolver=resolver)
    return {
        "bimi": {
            selector: {
                "name": build_bimi_name(domain, selector),
                "records": records,
            }
            for selector, records in bimi.items()
        },
        "mta_sts": {
            "name": build_mta_sts_name(domain),
            "records": mta_sts,
        },
        "tls_rpt": {
            "name": build_tls_rpt_name(domain),
            "records": tls_rpt,
        },
    }


async def lookup_email_security(
    domain: str,
    *,
    dkim_config: Mapping[str, Sequence[Any]] | Sequence[Any] | None = None,
    bimi_selectors: Sequence[str] = DEFAULT_BIMI_SELECTORS,
    resolver: Any | None = None,
) -> dict[str, Any]:
    dmarc, dkim, mail_txt = await asyncio.gather(
        lookup_dmarc_record(domain, resolver=resolver),
        lookup_dkim_records(domain, config=dkim_config, resolver=resolver),
        lookup_mail_txt_records(domain, bimi_selectors=bimi_selectors, resolver=resolver),
    )
    return {
        "dmarc": dmarc["record"],
        "dmarc_name": dmarc["name"],
        "dmarc_records": dmarc["records"],
        "dmarc_report_uris": dmarc["report_uris"],
        "dkim": dkim,
        "bimi": mail_txt["bimi"],
        "mta_sts": mail_txt["mta_sts"],
        "tls_rpt": mail_txt["tls_rpt"],
    }


def lookup_email_security_sync(
    domain: str,
    *,
    dkim_config: Mapping[str, Sequence[Any]] | Sequence[Any] | None = None,
    bimi_selectors: Sequence[str] = DEFAULT_BIMI_SELECTORS,
    resolver: Any | None = None,
) -> dict[str, Any]:
    dmarc = lookup_dmarc_record_sync(domain, resolver=resolver)
    dkim = lookup_dkim_records_sync(domain, config=dkim_config, resolver=resolver)
    mail_txt = lookup_mail_txt_records_sync(
        domain,
        bimi_selectors=bimi_selectors,
        resolver=resolver,
    )
    return {
        "dmarc": dmarc["record"],
        "dmarc_name": dmarc["name"],
        "dmarc_records": dmarc["records"],
        "dmarc_report_uris": dmarc["report_uris"],
        "dkim": dkim,
        "bimi": mail_txt["bimi"],
        "mta_sts": mail_txt["mta_sts"],
        "tls_rpt": mail_txt["tls_rpt"],
    }


def extract_microsoft_tenant_guid_from_openid(document: Mapping[str, Any]) -> str | None:
    for field in (
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "end_session_endpoint",
    ):
        value = document.get(field)
        if not value:
            continue
        match = _GUID_RE.search(str(value))
        if match:
            return match.group(0).lower()
    return None


async def probe_microsoft_tenant_guid(
    domain: str,
    *,
    client: httpx.AsyncClient | Any | None = None,
    endpoints: Sequence[str] = MICROSOFT_OPENID_CONFIG_URLS,
) -> dict[str, Any]:
    target = _normalize_domain(domain)
    created_client = client is None
    if created_client:
        client = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0, read=15.0),
            follow_redirects=True,
            headers={"User-Agent": "ip-intel/signal-dns"},
        )

    async def _probe(url: str) -> dict[str, Any]:
        try:
            response = await client.get(url)
        except Exception as exc:
            return {"url": url, "ok": False, "error": str(exc)}
        if response.status_code != 200:
            return {
                "url": url,
                "ok": False,
                "status_code": response.status_code,
                "error": "unexpected_status",
            }
        try:
            document = response.json()
        except Exception as exc:
            return {
                "url": url,
                "ok": False,
                "status_code": response.status_code,
                "error": f"invalid_json: {exc}",
            }
        tenant_id = extract_microsoft_tenant_guid_from_openid(document)
        return {
            "url": url,
            "ok": True,
            "status_code": response.status_code,
            "tenant_id": tenant_id,
            "issuer": document.get("issuer"),
        }

    urls = [template.format(domain=target) for template in endpoints]
    try:
        probes = await asyncio.gather(*(_probe(url) for url in urls))
    finally:
        if created_client:
            await client.aclose()

    tenant_ids = _unique(
        probe["tenant_id"]
        for probe in probes
        if probe.get("ok") and probe.get("tenant_id")
    )
    first_hit = next(
        (
            probe
            for probe in probes
            if probe.get("ok") and probe.get("tenant_id")
        ),
        None,
    )
    return {
        "domain": target,
        "tenant_id": tenant_ids[0] if tenant_ids else None,
        "tenant_ids": tenant_ids,
        "consistent": len(set(tenant_ids)) <= 1,
        "source": first_hit.get("url") if first_hit else None,
        "results": probes,
    }


def probe_microsoft_tenant_guid_sync(
    domain: str,
    *,
    client: httpx.Client | Any | None = None,
    endpoints: Sequence[str] = MICROSOFT_OPENID_CONFIG_URLS,
) -> dict[str, Any]:
    target = _normalize_domain(domain)
    created_client = client is None
    if created_client:
        client = httpx.Client(
            timeout=httpx.Timeout(10.0, read=15.0),
            follow_redirects=True,
            headers={"User-Agent": "ip-intel/signal-dns"},
        )

    probes: list[dict[str, Any]] = []
    try:
        for template in endpoints:
            url = template.format(domain=target)
            try:
                response = client.get(url)
            except Exception as exc:
                probes.append({"url": url, "ok": False, "error": str(exc)})
                continue
            if response.status_code != 200:
                probes.append(
                    {
                        "url": url,
                        "ok": False,
                        "status_code": response.status_code,
                        "error": "unexpected_status",
                    }
                )
                continue
            try:
                document = response.json()
            except Exception as exc:
                probes.append(
                    {
                        "url": url,
                        "ok": False,
                        "status_code": response.status_code,
                        "error": f"invalid_json: {exc}",
                    }
                )
                continue
            probes.append(
                {
                    "url": url,
                    "ok": True,
                    "status_code": response.status_code,
                    "tenant_id": extract_microsoft_tenant_guid_from_openid(document),
                    "issuer": document.get("issuer"),
                }
            )
    finally:
        if created_client:
            client.close()

    tenant_ids = _unique(
        probe["tenant_id"]
        for probe in probes
        if probe.get("ok") and probe.get("tenant_id")
    )
    first_hit = next(
        (
            probe
            for probe in probes
            if probe.get("ok") and probe.get("tenant_id")
        ),
        None,
    )
    return {
        "domain": target,
        "tenant_id": tenant_ids[0] if tenant_ids else None,
        "tenant_ids": tenant_ids,
        "consistent": len(set(tenant_ids)) <= 1,
        "source": first_hit.get("url") if first_hit else None,
        "results": probes,
    }


def extract_txt_tenancy_tokens(records: Iterable[Any] | Any) -> list[dict[str, str]]:
    provider_map = {
        "google_workspace": "google_site_verification",
        "stripe": "stripe_verification",
    }
    normalized: list[dict[str, str]] = []
    for item in extract_tenancy_tokens(records):
        provider = provider_map.get(str(item.get("provider") or ""), str(item.get("provider") or ""))
        token_name = str(item.get("token") or "")
        provider = provider_map.get(token_name.replace("-", "_"), provider)
        value = str(item.get("value") or item.get("token") or "").strip()
        if provider and value:
            normalized.append({"provider": provider, "token": value})
    return normalized


def extract_mailto_addresses(value: str) -> list[str]:
    parsed = parse_dmarc_report_uris(f"v=DMARC1; rua={value}")
    return [str(item.get("address") or "").lower() for item in parsed.get("rua", []) if item.get("address")]


def parse_dmarc_record(record: str) -> dict[str, Any]:
    parsed = parse_dmarc_report_uris(record)
    return {
        "raw": record,
        "rua": [str(item.get("address") or "").lower() for item in parsed.get("rua", []) if item.get("address")],
        "ruf": [str(item.get("address") or "").lower() for item in parsed.get("ruf", []) if item.get("address")],
    }


async def acollect_spf_details(domain: str, txt_records: Iterable[Any] | Any | None = None) -> dict[str, Any]:
    return await resolve_spf_chain(domain, txt_records=txt_records)


def collect_spf_details(domain: str, txt_records: Iterable[Any] | Any | None = None) -> dict[str, Any]:
    return resolve_spf_chain_sync(domain, txt_records=txt_records)


async def aget_email_security_records(domain: str) -> dict[str, Any]:
    return await lookup_email_security(domain)


def get_email_security_records(domain: str) -> dict[str, Any]:
    return lookup_email_security_sync(domain)


async def aprobe_microsoft_tenant(domain: str, client: httpx.AsyncClient | None = None) -> dict[str, Any]:
    result = await probe_microsoft_tenant_guid(domain, client=client)
    return {
        "tenant_guid": result.get("tenant_id"),
        "issuer": next((item.get("issuer") for item in result.get("results", []) if item.get("issuer")), None),
        "token_endpoint": None,
        "source_url": result.get("source"),
        "error": None if result.get("tenant_id") else "not_found",
    }


def probe_microsoft_tenant_sync(domain: str) -> dict[str, Any]:
    result = probe_microsoft_tenant_guid_sync(domain)
    return {
        "tenant_guid": result.get("tenant_id"),
        "issuer": next((item.get("issuer") for item in result.get("results", []) if item.get("issuer")), None),
        "token_endpoint": None,
        "source_url": result.get("source"),
        "error": None if result.get("tenant_id") else "not_found",
    }


__all__ = [
    "DEFAULT_BIMI_SELECTORS",
    "DEFAULT_DKIM_SELECTOR_CONFIG",
    "MICROSOFT_OPENID_CONFIG_URLS",
    "TENANCY_TOKEN_SPECS",
    "build_bimi_name",
    "build_dkim_name",
    "build_dmarc_name",
    "build_mta_sts_name",
    "build_tls_rpt_name",
    "expand_dkim_selectors",
    "extract_microsoft_tenant_guid_from_openid",
    "extract_spf_origins",
    "extract_tenancy_tokens",
    "lookup_dkim_records",
    "lookup_dkim_records_sync",
    "lookup_dmarc_record",
    "lookup_dmarc_record_sync",
    "lookup_email_security",
    "lookup_email_security_sync",
    "lookup_bimi_records",
    "lookup_bimi_records_sync",
    "lookup_mail_txt_records",
    "lookup_mail_txt_records_sync",
    "lookup_mta_sts_records",
    "lookup_mta_sts_records_sync",
    "lookup_tls_rpt_records",
    "lookup_tls_rpt_records_sync",
    "lookup_txt_records",
    "lookup_txt_records_sync",
    "normalize_txt_records",
    "parse_caa_records",
    "parse_dmarc_report_uris",
    "parse_spf_record",
    "parse_spf_txt_records",
    "probe_microsoft_tenant_guid",
    "probe_microsoft_tenant_guid_sync",
    "resolve_spf_chain",
    "resolve_spf_chain_sync",
]
