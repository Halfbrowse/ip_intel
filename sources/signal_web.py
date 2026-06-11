from __future__ import annotations

import base64
import hashlib
import html
import json
import re
from collections import defaultdict
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urljoin, urlparse, urlunparse
import xml.etree.ElementTree as ET

import httpx

from utils.outbound import httpx_kwargs

try:
    import mmh3  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    mmh3 = None


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
DEFAULT_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept-Language": "en-US,en;q=0.9",
}

DEFAULT_TIMEOUT = 15.0
DEFAULT_SCRIPT_MAX_BYTES = 262_144
DEFAULT_MAX_SCRIPTS = 8
DEFAULT_MAX_FAVICONS = 6

LEGAL_PAGE_PATHS = (
    "/impressum",
    "/imprint",
    "/legal",
    "/legal-notice",
    "/legal-notices",
    "/legalnotice",
    "/mentions-legales",
    "/aviso-legal",
    "/privacy",
    "/privacy-policy",
    "/terms",
    "/terms-of-service",
    "/contact",
    "/about",
    "/company",
)

WELL_KNOWN_PATHS = {
    "apple_app_site_association": (
        "/.well-known/apple-app-site-association",
        "/apple-app-site-association",
    ),
    "assetlinks_json": ("/.well-known/assetlinks.json",),
    "security_txt": (
        "/.well-known/security.txt",
        "/security.txt",
    ),
    "openid_configuration": ("/.well-known/openid-configuration",),
    "mta_sts_txt": ("/.well-known/mta-sts.txt",),
    "humans_txt": ("/humans.txt",),
    "ads_txt": ("/ads.txt",),
}

MAIL_CLIENT_CONFIG_PATHS = {
    "autodiscover": (
        ("root", "/autodiscover/autodiscover.xml"),
        ("subdomain", "autodiscover"),
    ),
    "autoconfig": (
        ("well_known", "/.well-known/autoconfig/mail/config-v1.1.xml"),
        ("root", "/autoconfig/mail/config-v1.1.xml"),
        ("subdomain", "autoconfig"),
    ),
}

_SOCIAL_NOISE = {"", "home", "login", "signup", "help", "support", "about", "contact"}
_SOCIAL_PATTERNS = (
    ("telegram", re.compile(r"https?://t\.me/([A-Za-z0-9_]{3,60})", re.I)),
    ("vkontakte", re.compile(r"https?://(?:www\.)?vk\.com/([^\s\"'<>/?]{2,80})", re.I)),
    ("odnoklassniki", re.compile(r"https?://(?:www\.)?ok\.ru/(?:profile/|group/)?([^\s\"'<>/?]{2,80})", re.I)),
    ("odnoklassniki", re.compile(r"https?://(?:www\.)?odnoklassniki\.ru/([^\s\"'<>/?]{2,80})", re.I)),
    ("twitter_x", re.compile(r"https?://(?:www\.)?(?:twitter|x)\.com/(?!search|share|intent|home)([^\s\"'<>/?]{2,60})", re.I)),
    ("tiktok", re.compile(r"https?://(?:www\.)?tiktok\.com/@([A-Za-z0-9_.]{2,60})", re.I)),
    ("instagram", re.compile(r"https?://(?:www\.)?instagram\.com/([^\s\"'<>/?]{2,60})", re.I)),
    ("facebook", re.compile(r"https?://(?:www\.)?facebook\.com/(?!sharer|share|dialog|tr\b)([^\s\"'<>/?]{2,80})", re.I)),
    ("youtube", re.compile(r"https?://(?:www\.)?youtube\.com/(?:channel/|@)([^\s\"'<>/?]{2,80})", re.I)),
    ("linkedin", re.compile(r"https?://(?:www\.)?linkedin\.com/(?:company|in)/([^\s\"'<>/?]{2,80})", re.I)),
    ("pinterest", re.compile(r"https?://(?:www\.)?pinterest\.(?:com|[a-z]{2})/([^\s\"'<>/?]{2,80})", re.I)),
    ("github", re.compile(r"https?://(?:www\.)?github\.com/([^\s\"'<>/?]{2,80})", re.I)),
    ("mastodon", re.compile(r"https?://([A-Za-z0-9.-]+)/@([A-Za-z0-9_]{2,80})", re.I)),
)

_BUNDLER_PATTERNS = {
    "webpack": (
        re.compile(r"__webpack_require__"),
        re.compile(r"webpackChunk"),
        re.compile(r"webpackJsonp"),
    ),
    "vite": (
        re.compile(r"__vite__"),
        re.compile(r"import\.meta\.hot"),
        re.compile(r"/@vite/client"),
    ),
    "parcel": (
        re.compile(r"parcelRequire"),
        re.compile(r"parcelHotUpdate"),
    ),
    "rollup": (
        re.compile(r"System\.register\("),
        re.compile(r"rollupPluginBabelHelpers"),
    ),
    "nextjs": (
        re.compile(r"/_next/"),
        re.compile(r"__NEXT_DATA__"),
        re.compile(r"self\.__next_f"),
    ),
    "nuxt": (
        re.compile(r"/_nuxt/"),
        re.compile(r"window\.__NUXT__"),
        re.compile(r"nuxtApp"),
    ),
    "browserify": (
        re.compile(r"function e\(t,n,r\)"),
        re.compile(r"require=function e\(t,n,r\)"),
    ),
    "esbuild": (
        re.compile(r"__toESM"),
        re.compile(r"__commonJS"),
    ),
}

_SOURCE_MAP_RE = re.compile(
    r"(?:\/\/[@#]\s*sourceMappingURL=|\/\*[@#]\s*sourceMappingURL=)([^\s*]+)",
    re.I,
)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_PHONE_RE = re.compile(r"(?<!\w)(?:\+\d{1,3}[\s().-]*)?(?:\(?\d{1,4}\)?[\s().-]*){2,6}\d{2,4}(?!\w)")
_ENTITY_LABEL_RE = re.compile(
    r"(?im)^(?:.*?\b(?:company|registered name|legal name|operator|owner|publisher|provided by|trading as|responsible(?: for content)?)\b[^:\n]{0,30}:\s*)([^\n]{3,140})$"
)
_ENTITY_SUFFIX_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9&.,'()/\-]*(?:\s+[A-Z][A-Za-z0-9&.,'()/\-]*){0,8}\s+"
    r"(?:LLC|L\.L\.C\.|Ltd|Limited|Inc\.?|Incorporated|Corp\.?|Corporation|Company|Co\.?|"
    r"GmbH|AG|S\.?A\.?R\.?L\.?|S\.?A\.?|SAS|BV|B\.V\.|NV|N\.V\.|AB|AS|Oy|Oyj|ApS|"
    r"Sp\.?\s*z\s*o\.?o\.?|s\.?r\.?o\.?|SRL|Srl|OÜ|UG|PLC|Pty Ltd|Pte Ltd|BVBA|CVBA|Kft|d\.?o\.?o\.?))\b"
)
_REGISTRATION_LINE_RE = re.compile(
    r"(?im)^.*\b(?:company|commercial|trade|business|merchant|enterprise|register|registration|registered|"
    r"chamber of commerce|vat|tax|gst|abn|uen|cvr|siren|siret|rcs|hrb|uid|ust-?id|cif|nif|bin|iin)\b.*$"
)
_VAT_TOKEN_RE = re.compile(r"\b[A-Z]{2}[A-Z0-9][A-Z0-9 ./-]{6,18}\b")
_STREET_WORD_RE = re.compile(
    r"(?i)\b(?:street|st\.|road|rd\.|avenue|ave\.|boulevard|blvd|lane|ln\.|drive|dr\.|way|place|"
    r"strasse|straße|allee|weg|gasse|rue|route|via|viale|rua|calle|carrera|chauss[ée]e|quay|parkway|"
    r"laan|lei|dreef|court|suite|unit|building|floor|plaza)\b"
)
_ADDRESS_LABEL_RE = re.compile(
    r"(?i)\b(?:address|registered office|registered address|office|headquarters|seat)\b"
)
_POSTAL_RE = re.compile(r"\b(?:\d{4,6}|[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2})\b")
_BLOCK_TAG_RE = re.compile(
    r"(?i)</?(?:p|div|section|article|header|footer|main|aside|nav|ul|ol|li|table|thead|tbody|tfoot|tr|td|th|address|h[1-6])\b[^>]*>"
)
_TAG_RE = re.compile(r"(?is)<[^>]+>")
_SCRIPT_STYLE_RE = re.compile(r"(?is)<(script|style|noscript|template|svg)[^>]*>.*?</\1>")
_COMMENT_RE = re.compile(r"(?is)<!--.*?-->")


def _dedupe_preserve(values: Iterable[Any]) -> list[Any]:
    seen: set[Any] = set()
    out: list[Any] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _append_unique(mapping: dict[str, list[str]], key: str, value: str) -> None:
    key = key.lower().strip()
    value = value.strip()
    if not key or not value:
        return
    mapping.setdefault(key, [])
    if value not in mapping[key]:
        mapping[key].append(value)


def _target_context(target: str, default_scheme: str = "https") -> dict[str, str]:
    raw = str(target or "").strip()
    if not raw:
        return {
            "input": "",
            "scheme": default_scheme,
            "netloc": "",
            "hostname": "",
            "root_url": "",
            "base_url": "",
        }
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        raw = f"{default_scheme}://{raw.lstrip('/')}"
    parsed = urlparse(raw)
    scheme = parsed.scheme or default_scheme
    netloc = parsed.netloc or parsed.path
    path = parsed.path if parsed.netloc else ""
    hostname = parsed.hostname or netloc.split("@")[-1].split(":")[0]
    root_url = urlunparse((scheme, netloc, "/", "", "", "")) if netloc else ""
    base_url = urlunparse((scheme, netloc, path or "/", "", "", "")) if netloc else ""
    return {
        "input": target,
        "scheme": scheme,
        "netloc": netloc,
        "hostname": hostname,
        "root_url": root_url,
        "base_url": base_url,
    }


def normalize_target_url(target: str, default_scheme: str = "https") -> str:
    return _target_context(target, default_scheme=default_scheme)["root_url"]


def normalize_text(text: str) -> str:
    cleaned = html.unescape(str(text or "")).replace("\xa0", " ")
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip().lower()


def normalized_text_hash(text: str) -> str | None:
    normalized = normalize_text(text)
    if not normalized:
        return None
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def html_to_text(html_doc: str, *, preserve_lines: bool = False) -> str:
    raw = str(html_doc or "")
    if not raw:
        return ""
    text = _COMMENT_RE.sub(" ", raw)
    text = _SCRIPT_STYLE_RE.sub(" ", text)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = _BLOCK_TAG_RE.sub("\n", text)
    text = _TAG_RE.sub(" ", text)
    text = html.unescape(text).replace("\xa0", " ")
    if preserve_lines:
        lines = [re.sub(r"\s+", " ", line).strip() for line in text.splitlines()]
        return "\n".join(line for line in lines if line)
    return re.sub(r"\s+", " ", text).strip()


def html_text_hash(html_doc: str) -> str | None:
    return normalized_text_hash(html_to_text(html_doc))


def _coerce_text(content: bytes | str | None) -> str:
    if content is None:
        return ""
    if isinstance(content, bytes):
        return content.decode("utf-8", "replace")
    return str(content)


def _json_loads(content: bytes | str | None) -> Any:
    text = _coerce_text(content).lstrip("\ufeff").strip()
    return json.loads(text) if text else {}


def _clean_candidate(value: str) -> str:
    cleaned = re.sub(r"\s+", " ", html.unescape(str(value or ""))).strip(" \t\r\n,;:|")
    return cleaned


def _line_values(text: str) -> list[str]:
    return [line.strip() for line in str(text or "").splitlines() if line.strip()]


def _local_name(tag: str) -> str:
    return str(tag or "").rsplit("}", 1)[-1]


def _first(values: Sequence[str] | None) -> str | None:
    if not values:
        return None
    return values[0]


def _header_items(headers_or_response: Any) -> list[tuple[str, str]]:
    if headers_or_response is None:
        return []
    if isinstance(headers_or_response, Sequence) and not isinstance(headers_or_response, (str, bytes)):
        if all(isinstance(item, tuple) and len(item) == 2 for item in headers_or_response):
            return [(str(name), str(value)) for name, value in headers_or_response]
    if isinstance(headers_or_response, Mapping):
        items: list[tuple[str, str]] = []
        for name, value in headers_or_response.items():
            if isinstance(value, (list, tuple)):
                items.extend((str(name), str(item)) for item in value)
            else:
                items.append((str(name), str(value)))
        return items
    headers = getattr(headers_or_response, "headers", None)
    if headers is not None and headers is not headers_or_response:
        return _header_items(headers)
    multi_items = getattr(headers_or_response, "multi_items", None)
    if callable(multi_items):
        return [(str(name), str(value)) for name, value in multi_items()]
    items = getattr(headers_or_response, "items", None)
    if callable(items):
        return [(str(name), str(value)) for name, value in items()]
    raw = getattr(headers_or_response, "raw", None)
    if raw is not None:
        try:
            return [(name.decode("latin1"), value.decode("latin1")) for name, value in raw]
        except Exception:
            pass
    return []


def _parse_set_cookie_names(cookie_values: Sequence[str]) -> list[str]:
    names: list[str] = []
    attr_names = {
        "path",
        "expires",
        "domain",
        "max-age",
        "secure",
        "httponly",
        "samesite",
        "priority",
        "partitioned",
        "version",
    }
    for value in cookie_values:
        cookie = SimpleCookie()
        try:
            cookie.load(value)
        except Exception:
            cookie = SimpleCookie()
        if cookie:
            for name in cookie.keys():
                if name not in names:
                    names.append(name)
            continue
        for match in re.finditer(r"(?:^|,\s*)([!#$%&'*+\-.^_`|~0-9A-Za-z]+)=", value):
            name = match.group(1)
            if name.lower() in attr_names:
                continue
            if name not in names:
                names.append(name)
    return names


def capture_http_fingerprint(headers_or_response: Any, *, status_code: int | None = None, url: str | None = None) -> dict[str, Any]:
    items = _header_items(headers_or_response)
    grouped: dict[str, list[str]] = defaultdict(list)
    for name, value in items:
        grouped[name.lower()].append(value)
    response_status = status_code
    response_url = url
    if response_status is None:
        response_status = getattr(headers_or_response, "status_code", None)
    if response_url is None:
        response_url = str(getattr(headers_or_response, "url", "") or "") or None
    set_cookie_values = grouped.get("set-cookie", [])
    x_drupal_headers = {
        name: values[0] if len(values) == 1 else list(values)
        for name, values in grouped.items()
        if name.startswith("x-drupal-")
    }
    return {
        "status_code": response_status,
        "url": response_url,
        "header_order": [name.lower() for name, _ in items],
        "server": _first(grouped.get("server")),
        "x_powered_by": _first(grouped.get("x-powered-by")),
        "set_cookie_names": _parse_set_cookie_names(set_cookie_values),
        "content_security_policy": _first(grouped.get("content-security-policy")),
        "x_generator": _first(grouped.get("x-generator")),
        "x_aspnet_version": _first(grouped.get("x-aspnet-version")),
        "x_drupal_headers": x_drupal_headers,
        "header_names": _dedupe_preserve(name.lower() for name, _ in items),
    }


class _HTMLSignalParser(HTMLParser):
    def __init__(self, page_url: str | None = None) -> None:
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.html_lang: str | None = None
        self.title_parts: list[str] = []
        self.in_title = False
        self.meta_tags: dict[str, list[str]] = {}
        self.rel_me_links: list[str] = []
        self.favicon_links: list[dict[str, Any]] = []
        self.script_assets: list[dict[str, Any]] = []
        self.anchor_urls: list[str] = []
        self.canonical_url: str | None = None
        self.inline_scripts: list[str] = []
        self._ignoring = 0
        self._current_inline_script: list[str] | None = None

    def _absolute_url(self, value: str | None) -> str | None:
        if not value:
            return None
        stripped = value.strip()
        if not stripped:
            return None
        if self.page_url:
            return urljoin(self.page_url, stripped)
        return stripped

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {str(name).lower(): (value if value is not None else "") for name, value in attrs if name}
        tag = tag.lower()
        if tag == "html" and attrs_dict.get("lang"):
            self.html_lang = attrs_dict["lang"].lower()
        if tag == "title":
            self.in_title = True
        if tag in {"script", "style", "noscript", "template"}:
            self._ignoring += 1
        if tag == "meta":
            content = attrs_dict.get("content", "").strip()
            for key_name in ("name", "property", "http-equiv", "itemprop"):
                key = attrs_dict.get(key_name, "").strip().lower()
                if key and content:
                    _append_unique(self.meta_tags, key, content)
        elif tag == "link":
            rel_tokens = {
                token.strip().lower()
                for token in attrs_dict.get("rel", "").replace(",", " ").split()
                if token.strip()
            }
            href = self._absolute_url(attrs_dict.get("href"))
            if href and "canonical" in rel_tokens:
                self.canonical_url = href
            if href and "me" in rel_tokens and href not in self.rel_me_links:
                self.rel_me_links.append(href)
            if href and ("icon" in rel_tokens or any(token.startswith("apple-touch-icon") for token in rel_tokens)):
                entry = {
                    "href": href,
                    "rel": sorted(rel_tokens),
                    "type": attrs_dict.get("type") or None,
                    "sizes": attrs_dict.get("sizes") or None,
                }
                if entry not in self.favicon_links:
                    self.favicon_links.append(entry)
        elif tag == "a":
            href = self._absolute_url(attrs_dict.get("href"))
            if href and href not in self.anchor_urls:
                self.anchor_urls.append(href)
            rel_tokens = {
                token.strip().lower()
                for token in attrs_dict.get("rel", "").replace(",", " ").split()
                if token.strip()
            }
            if href and "me" in rel_tokens and href not in self.rel_me_links:
                self.rel_me_links.append(href)
        elif tag == "script":
            src = self._absolute_url(attrs_dict.get("src"))
            if src:
                asset = {
                    "url": src,
                    "host": urlparse(src).netloc or None,
                    "path": urlparse(src).path or None,
                    "filename": Path(urlparse(src).path).name or None,
                    "type": attrs_dict.get("type") or None,
                    "integrity": attrs_dict.get("integrity") or None,
                    "crossorigin": attrs_dict.get("crossorigin") or None,
                    "async": "async" in attrs_dict,
                    "defer": "defer" in attrs_dict,
                }
                if asset not in self.script_assets:
                    self.script_assets.append(asset)
            else:
                self._current_inline_script = []

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self.in_title = False
        if tag in {"script", "style", "noscript", "template"} and self._ignoring:
            self._ignoring -= 1
        if tag == "script" and self._current_inline_script is not None:
            snippet = "".join(self._current_inline_script).strip()
            if snippet:
                self.inline_scripts.append(snippet[:32_768])
            self._current_inline_script = None

    def handle_data(self, data: str) -> None:
        if self.in_title and data:
            self.title_parts.append(data)
        if self._current_inline_script is not None and data:
            self._current_inline_script.append(data)


def _extract_social_profiles(*sources: str) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    social_links: dict[str, list[str]] = {}
    social_handles: dict[str, list[str]] = {}
    for source in sources:
        for platform, pattern in _SOCIAL_PATTERNS:
            for match in pattern.finditer(str(source or "")):
                if platform == "mastodon":
                    full_url = match.group(0).rstrip("/?).,;\"'")
                    handle = match.group(2).rstrip("/?).,;\"'")
                else:
                    full_url = match.group(0).rstrip("/?).,;\"'")
                    handle = match.group(1).rstrip("/?).,;\"'")
                if handle.lower() in _SOCIAL_NOISE:
                    continue
                social_links.setdefault(platform, [])
                social_handles.setdefault(platform, [])
                if full_url not in social_links[platform]:
                    social_links[platform].append(full_url)
                if handle not in social_handles[platform]:
                    social_handles[platform].append(handle)
    return social_links, social_handles


def scan_script_disclosures(script_text: str, *, script_url: str | None = None, headers_or_response: Any = None) -> dict[str, Any]:
    text = str(script_text or "")
    source_map_urls: list[str] = []
    if headers_or_response is not None:
        grouped: dict[str, list[str]] = defaultdict(list)
        for name, value in _header_items(headers_or_response):
            grouped[name.lower()].append(value)
        for header_name in ("sourcemap", "x-sourcemap"):
            for ref in grouped.get(header_name, []):
                resolved = urljoin(script_url, ref) if script_url else ref
                if resolved not in source_map_urls:
                    source_map_urls.append(resolved)
    for match in _SOURCE_MAP_RE.finditer(text):
        ref = match.group(1).strip("'\"")
        resolved = urljoin(script_url, ref) if script_url else ref
        if resolved not in source_map_urls:
            source_map_urls.append(resolved)
    bundlers: list[str] = []
    url_text = str(script_url or "")
    for bundler, patterns in _BUNDLER_PATTERNS.items():
        if any(pattern.search(text) or pattern.search(url_text) for pattern in patterns):
            bundlers.append(bundler)
    return {
        "source_map_urls": source_map_urls,
        "bundlers": bundlers,
        "has_source_map_comment": bool(source_map_urls),
    }


def parse_homepage_html(html_doc: str, *, page_url: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "title": None,
        "google_analytics": [],
        "gtm_ids": [],
        "facebook_pixel": [],
        "tiktok_pixel": [],
        "yandex_metrika": [],
        "adsense_ids": [],
        "html_lang": None,
        "cms_generator": None,
        "author": None,
        "authors": [],
        "fb_app_id": None,
        "twitter_site": None,
        "twitter_creator": None,
        "social_links": {},
        "social_handles": {},
        "social_meta": {},
        "meta_tags": {},
        "rel_me_links": [],
        "canonical_url": None,
        "favicon_links": [],
        "script_assets": [],
        "script_urls": [],
        "script_asset_hosts": [],
        "inline_source_map_urls": [],
        "inline_bundlers": [],
        "homepage_text_hash": None,
    }
    raw = str(html_doc or "")
    if not raw:
        return out

    parser = _HTMLSignalParser(page_url=page_url)
    try:
        parser.feed(raw)
        parser.close()
    except Exception:
        pass

    ga = re.findall(r"\b(UA-\d{4,12}-\d{1,3}|G-[A-Z0-9]{6,12}|AW-[0-9]{8,12})\b", raw)
    gtm = re.findall(r"\b(GTM-[A-Z0-9]{4,8})\b", raw)
    fb = re.findall(r"fbq\([\"']init[\"'],\s*[\"'](\d{8,20})[\"']", raw)
    tt = re.findall(r"ttq\.load\([\"']([A-Z0-9]{15,25})[\"']", raw)
    ym_one = re.findall(r"\bym\((\d{5,12})\s*,", raw)
    ym_two = re.findall(r"metrika\.yandex\.(?:com|ru)/watch/(\d{5,12})", raw)
    adsense = re.findall(r"\b(ca-pub-\d{10,20})\b", raw, re.I)

    meta_tags = {key: _dedupe_preserve(values) for key, values in parser.meta_tags.items()}
    author_values = _dedupe_preserve(
        (meta_tags.get("author") or [])
        + (meta_tags.get("article:author") or [])
        + (meta_tags.get("profile:username") or [])
    )

    inline_source_maps: list[str] = []
    inline_bundlers: list[str] = []
    for script_text in parser.inline_scripts:
        disclosure = scan_script_disclosures(script_text, script_url=page_url)
        inline_source_maps.extend(disclosure["source_map_urls"])
        inline_bundlers.extend(disclosure["bundlers"])

    social_links, social_handles = _extract_social_profiles(
        raw,
        *parser.anchor_urls,
        *parser.rel_me_links,
        *(value for values in meta_tags.values() for value in values),
    )
    twitter_site = _first(meta_tags.get("twitter:site"))
    twitter_creator = _first(meta_tags.get("twitter:creator"))
    for handle_value in (twitter_site, twitter_creator):
        if handle_value and handle_value.startswith("@"):
            social_handles.setdefault("twitter_x", [])
            handle = handle_value[1:]
            if handle and handle not in social_handles["twitter_x"]:
                social_handles["twitter_x"].append(handle)

    out.update(
        {
            "title": _clean_candidate("".join(parser.title_parts)) or None,
            "google_analytics": sorted(set(ga)),
            "gtm_ids": sorted(set(gtm)),
            "facebook_pixel": sorted(set(fb)),
            "tiktok_pixel": sorted(set(tt)),
            "yandex_metrika": sorted(set(ym_one + ym_two)),
            "adsense_ids": sorted({item.lower() for item in adsense}),
            "html_lang": parser.html_lang,
            "cms_generator": _first(meta_tags.get("generator")),
            "author": _first(author_values),
            "authors": author_values,
            "fb_app_id": _first(meta_tags.get("fb:app_id")),
            "twitter_site": twitter_site,
            "twitter_creator": twitter_creator,
            "social_links": social_links,
            "social_handles": social_handles,
            "social_meta": {
                key: values
                for key, values in meta_tags.items()
                if key.startswith(("og:", "twitter:", "fb:", "article:", "profile:"))
            },
            "meta_tags": meta_tags,
            "rel_me_links": parser.rel_me_links,
            "canonical_url": parser.canonical_url,
            "favicon_links": parser.favicon_links,
            "script_assets": parser.script_assets,
            "script_urls": [item["url"] for item in parser.script_assets if isinstance(item, Mapping) and item.get("url")],
            "script_asset_hosts": _dedupe_preserve(
                item["host"] for item in parser.script_assets if isinstance(item, Mapping) and item.get("host")
            ),
            "inline_source_map_urls": _dedupe_preserve(inline_source_maps),
            "inline_bundlers": _dedupe_preserve(inline_bundlers),
            "homepage_text_hash": html_text_hash(raw),
        }
    )
    return out


def _process_page_html(html_doc: str, page_url: str | None = None) -> dict[str, Any]:
    return parse_homepage_html(html_doc, page_url=page_url)


def parse_apple_app_site_association(content: bytes | str | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "app_ids": [],
        "webcredentials_apps": [],
        "activitycontinuation_apps": [],
        "details": [],
        "parse_error": None,
    }
    try:
        data = _json_loads(content)
        applinks = data.get("applinks") or {}
        details = applinks.get("details") or []
        if isinstance(details, dict):
            details = list(details.values())
        for detail in details:
            if not isinstance(detail, Mapping):
                continue
            app_ids = detail.get("appIDs") or []
            if detail.get("appID"):
                app_ids = [detail["appID"], *app_ids]
            app_ids = [str(item) for item in app_ids if item]
            entry = {
                "app_ids": _dedupe_preserve(app_ids),
                "paths": [str(item) for item in detail.get("paths") or []],
                "components": detail.get("components") or [],
            }
            result["details"].append(entry)
            result["app_ids"].extend(entry["app_ids"])
        result["webcredentials_apps"] = [
            str(item) for item in (data.get("webcredentials") or {}).get("apps") or [] if item
        ]
        result["activitycontinuation_apps"] = [
            str(item) for item in (data.get("activitycontinuation") or {}).get("apps") or [] if item
        ]
        result["app_ids"] = _dedupe_preserve(result["app_ids"])
        result["webcredentials_apps"] = _dedupe_preserve(result["webcredentials_apps"])
        result["activitycontinuation_apps"] = _dedupe_preserve(result["activitycontinuation_apps"])
    except Exception as exc:
        result["parse_error"] = str(exc)
    return result


def parse_assetlinks_json(content: bytes | str | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "statements": [],
        "package_names": [],
        "sites": [],
        "relations": [],
        "parse_error": None,
    }
    try:
        data = _json_loads(content)
        statements = data if isinstance(data, list) else [data]
        for statement in statements:
            if not isinstance(statement, Mapping):
                continue
            target = statement.get("target") or {}
            entry = {
                "relation": [str(item) for item in statement.get("relation") or [] if item],
                "namespace": target.get("namespace"),
                "package_name": target.get("package_name"),
                "site": target.get("site"),
                "sha256_cert_fingerprints": [
                    str(item) for item in target.get("sha256_cert_fingerprints") or [] if item
                ],
            }
            result["statements"].append(entry)
            if entry["package_name"]:
                result["package_names"].append(str(entry["package_name"]))
            if entry["site"]:
                result["sites"].append(str(entry["site"]))
            result["relations"].extend(entry["relation"])
        result["package_names"] = _dedupe_preserve(result["package_names"])
        result["sites"] = _dedupe_preserve(result["sites"])
        result["relations"] = _dedupe_preserve(result["relations"])
    except Exception as exc:
        result["parse_error"] = str(exc)
    return result


def parse_security_txt(content: bytes | str | None) -> dict[str, Any]:
    text = _coerce_text(content)
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        _append_unique(fields, key.strip().lower(), value.strip())
    contacts = fields.get("contact", [])
    emails = _dedupe_preserve(_EMAIL_RE.findall("\n".join(contacts)))
    urls = _dedupe_preserve(re.findall(r"https?://[^\s>]+", text, re.I))
    return {
        "fields": fields,
        "contacts": contacts,
        "expires": _first(fields.get("expires")),
        "canonical": fields.get("canonical", []),
        "preferred_languages": fields.get("preferred-languages", []),
        "policy": fields.get("policy", []),
        "emails": emails,
        "urls": urls,
        "normalized_text_hash": normalized_text_hash(text),
    }


def parse_openid_configuration(content: bytes | str | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "issuer": None,
        "authorization_endpoint": None,
        "token_endpoint": None,
        "userinfo_endpoint": None,
        "jwks_uri": None,
        "registration_endpoint": None,
        "scopes_supported": [],
        "response_types_supported": [],
        "grant_types_supported": [],
        "claims_supported": [],
        "parse_error": None,
    }
    try:
        data = _json_loads(content)
        result.update(
            {
                "issuer": data.get("issuer"),
                "authorization_endpoint": data.get("authorization_endpoint"),
                "token_endpoint": data.get("token_endpoint"),
                "userinfo_endpoint": data.get("userinfo_endpoint"),
                "jwks_uri": data.get("jwks_uri"),
                "registration_endpoint": data.get("registration_endpoint"),
                "scopes_supported": [str(item) for item in data.get("scopes_supported") or [] if item],
                "response_types_supported": [
                    str(item) for item in data.get("response_types_supported") or [] if item
                ],
                "grant_types_supported": [
                    str(item) for item in data.get("grant_types_supported") or [] if item
                ],
                "claims_supported": [str(item) for item in data.get("claims_supported") or [] if item],
            }
        )
    except Exception as exc:
        result["parse_error"] = str(exc)
    return result


def parse_mta_sts_txt(content: bytes | str | None) -> dict[str, Any]:
    text = _coerce_text(content)
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        _append_unique(fields, key.strip().lower(), value.strip())
    return {
        "fields": fields,
        "version": _first(fields.get("version")),
        "mode": _first(fields.get("mode")),
        "mx": fields.get("mx", []),
        "max_age": _first(fields.get("max_age")),
        "normalized_text_hash": normalized_text_hash(text),
    }


def parse_humans_txt(content: bytes | str | None) -> dict[str, Any]:
    text = _coerce_text(content)
    sections: dict[str, list[str]] = {"default": []}
    current = "default"
    key_values: dict[str, list[str]] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        section_match = re.match(r"/\*\s*(.*?)\s*\*/", stripped)
        if section_match:
            current = section_match.group(1).strip().lower() or "default"
            sections.setdefault(current, [])
            continue
        sections.setdefault(current, []).append(stripped)
        if ":" in stripped:
            key, value = stripped.split(":", 1)
            _append_unique(key_values, key.strip().lower(), value.strip())
    return {
        "sections": sections,
        "fields": key_values,
        "emails": _dedupe_preserve(_EMAIL_RE.findall(text)),
        "phones": _dedupe_preserve(_filter_phones(_PHONE_RE.findall(text))),
        "urls": _dedupe_preserve(re.findall(r"https?://[^\s>]+", text, re.I)),
        "normalized_text_hash": normalized_text_hash(text),
    }


def parse_ads_txt(content: bytes | str | None) -> dict[str, Any]:
    text = _coerce_text(content)
    records: list[dict[str, Any]] = []
    variables: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        body = stripped.split("#", 1)[0].strip()
        if not body:
            continue
        if "=" in body and "," not in body:
            key, value = body.split("=", 1)
            variables[key.strip().lower()] = value.strip()
            continue
        parts = [part.strip() for part in body.split(",")]
        if len(parts) < 3:
            continue
        records.append(
            {
                "seller_domain": parts[0].lower(),
                "publisher_id": parts[1],
                "relationship": parts[2].upper(),
                "cert_authority_id": parts[3] if len(parts) > 3 else None,
            }
        )
    return {
        "records": records,
        "variables": variables,
        "seller_domains": _dedupe_preserve(record["seller_domain"] for record in records),
        "publisher_ids": _dedupe_preserve(record["publisher_id"] for record in records),
        "normalized_text_hash": normalized_text_hash(text),
    }


def _parser_for_well_known(name: str):
    return {
        "apple_app_site_association": parse_apple_app_site_association,
        "assetlinks_json": parse_assetlinks_json,
        "security_txt": parse_security_txt,
        "openid_configuration": parse_openid_configuration,
        "mta_sts_txt": parse_mta_sts_txt,
        "humans_txt": parse_humans_txt,
        "ads_txt": parse_ads_txt,
    }[name]


def _extract_entity_names(text: str) -> list[str]:
    entities: list[str] = []
    for match in _ENTITY_LABEL_RE.finditer(text):
        candidate = _clean_candidate(match.group(1))
        if len(candidate) >= 4 and candidate not in entities:
            entities.append(candidate)
    for match in _ENTITY_SUFFIX_RE.finditer(text):
        candidate = _clean_candidate(match.group(1))
        if len(candidate) >= 4 and candidate not in entities:
            entities.append(candidate)
    return entities


def _extract_registration_ids(text: str) -> list[str]:
    hits: list[str] = []
    for line in _line_values(text):
        if _REGISTRATION_LINE_RE.search(line):
            value = _clean_candidate(line)
            if value not in hits:
                hits.append(value)
        for vat in _VAT_TOKEN_RE.findall(line):
            if vat not in hits:
                hits.append(vat)
    return hits


def _filter_phones(matches: Sequence[str]) -> list[str]:
    phones: list[str] = []
    for match in matches:
        cleaned = re.sub(r"\s+", " ", match).strip(" ,;")
        digits = re.sub(r"\D", "", cleaned)
        if 7 <= len(digits) <= 15 and cleaned not in phones:
            phones.append(cleaned)
    return phones


def _extract_addresses(text: str) -> list[str]:
    lines = _line_values(text)
    addresses: list[str] = []
    for index, line in enumerate(lines):
        candidate: str | None = None
        if _ADDRESS_LABEL_RE.search(line):
            after_colon = line.split(":", 1)[1].strip() if ":" in line else line
            candidate = after_colon or line
        elif _STREET_WORD_RE.search(line):
            candidate = line
        if not candidate:
            continue
        if index + 1 < len(lines) and _POSTAL_RE.search(lines[index + 1]):
            if lines[index + 1] not in candidate:
                candidate = f"{candidate}, {lines[index + 1]}"
        cleaned = _clean_candidate(candidate)
        if cleaned and cleaned not in addresses:
            addresses.append(cleaned)
    return addresses


def extract_legal_page_signals(html_doc: str, *, page_url: str | None = None) -> dict[str, Any]:
    text = html_to_text(html_doc, preserve_lines=True)
    page_meta = parse_homepage_html(html_doc, page_url=page_url)
    return {
        "url": page_url,
        "title": page_meta.get("title"),
        "normalized_text_hash": normalized_text_hash(text),
        "entity_names": _extract_entity_names(text),
        "registration_ids": _extract_registration_ids(text),
        "addresses": _extract_addresses(text),
        "phones": _filter_phones(_PHONE_RE.findall(text)),
        "emails": _dedupe_preserve(_EMAIL_RE.findall(text)),
    }


def parse_autodiscover_xml(content: bytes | str | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "format": "microsoft_autodiscover",
        "protocols": [],
        "redirects": [],
        "emails": [],
        "servers": [],
        "domains": [],
        "parse_error": None,
    }
    try:
        root = ET.fromstring(_coerce_text(content))
        for elem in root.iter():
            if _local_name(elem.tag).lower() != "protocol":
                continue
            protocol: dict[str, Any] = {}
            for child in list(elem):
                key = _local_name(child.tag).lower()
                value = (child.text or "").strip()
                if value:
                    protocol[key] = value
            if protocol:
                result["protocols"].append(protocol)
                for key in ("server", "asurl", "ewsurl", "redirecturl"):
                    if protocol.get(key):
                        result["servers"].append(protocol[key])
                for key in ("redirectaddr", "redirecturl"):
                    if protocol.get(key):
                        result["redirects"].append(protocol[key])
                if protocol.get("domainrequired"):
                    result["domains"].append(protocol["domainrequired"])
        result["emails"] = _dedupe_preserve(
            (elem.text or "").strip()
            for elem in root.iter()
            if _local_name(elem.tag).lower() in {"emailaddress", "autodiscoversmtpaddress"} and (elem.text or "").strip()
        )
        result["servers"] = _dedupe_preserve(result["servers"])
        result["redirects"] = _dedupe_preserve(result["redirects"])
        result["domains"] = _dedupe_preserve(result["domains"])
    except Exception as exc:
        result["parse_error"] = str(exc)
    return result


def parse_autoconfig_xml(content: bytes | str | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "format": "mozilla_autoconfig",
        "provider_ids": [],
        "display_names": [],
        "incoming_servers": [],
        "outgoing_servers": [],
        "domains": [],
        "parse_error": None,
    }
    try:
        root = ET.fromstring(_coerce_text(content))
        for elem in root.iter():
            local = _local_name(elem.tag).lower()
            if local == "emailprovider" and elem.attrib.get("id"):
                result["provider_ids"].append(elem.attrib["id"])
            elif local == "displayname" and (elem.text or "").strip():
                result["display_names"].append((elem.text or "").strip())
            elif local in {"incomingserver", "outgoingserver"}:
                server: dict[str, Any] = {"type": elem.attrib.get("type")}
                for child in list(elem):
                    key = _local_name(child.tag).lower()
                    value = (child.text or "").strip()
                    if value:
                        server[key] = value
                if local == "incomingserver":
                    result["incoming_servers"].append(server)
                else:
                    result["outgoing_servers"].append(server)
            elif local == "domain" and (elem.text or "").strip():
                result["domains"].append((elem.text or "").strip())
        result["provider_ids"] = _dedupe_preserve(result["provider_ids"])
        result["display_names"] = _dedupe_preserve(result["display_names"])
        result["domains"] = _dedupe_preserve(result["domains"])
    except Exception as exc:
        result["parse_error"] = str(exc)
    return result


def build_mail_client_config_urls(target: str) -> dict[str, list[dict[str, str]]]:
    context = _target_context(target)
    root_url = context["root_url"]
    hostname = context["hostname"]
    scheme = context["scheme"]
    autodiscover_host = f"autodiscover.{hostname}" if hostname else ""
    autoconfig_host = f"autoconfig.{hostname}" if hostname else ""
    return {
        "autodiscover": [
            {"label": "root", "url": urljoin(root_url, "/autodiscover/autodiscover.xml")},
            {
                "label": "subdomain",
                "url": f"{scheme}://{autodiscover_host}/autodiscover/autodiscover.xml" if autodiscover_host else "",
            },
        ],
        "autoconfig": [
            {"label": "well_known", "url": urljoin(root_url, "/.well-known/autoconfig/mail/config-v1.1.xml")},
            {"label": "root", "url": urljoin(root_url, "/autoconfig/mail/config-v1.1.xml")},
            {
                "label": "subdomain",
                "url": f"{scheme}://{autoconfig_host}/mail/config-v1.1.xml" if autoconfig_host else "",
            },
        ],
    }


def hash_favicon_bytes(content: bytes | None) -> dict[str, Any]:
    if not content:
        return {"md5": None, "murmurhash3": None, "sha256": None}
    payload = bytes(content)
    murmurhash3: int | None = None
    if mmh3 is not None:  # pragma: no branch - optional dependency
        encoded = base64.encodebytes(payload).decode("ascii")
        try:
            murmurhash3 = int(mmh3.hash(encoded))
        except Exception:
            murmurhash3 = None
    return {
        "md5": hashlib.md5(payload).hexdigest(),
        "murmurhash3": murmurhash3,
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def find_favicon_urls(page_url: str, homepage_data: Mapping[str, Any] | None = None) -> list[str]:
    base_url = page_url if re.match(r"^[a-z][a-z0-9+.-]*://", str(page_url or ""), re.I) else normalize_target_url(page_url)
    urls: list[str] = []
    for entry in (homepage_data or {}).get("favicon_links", []) or []:
        if not isinstance(entry, Mapping):
            continue
        href = entry.get("href")
        if href:
            urls.append(urljoin(base_url, str(href)) if base_url else str(href))
    if base_url:
        urls.append(urljoin(base_url, "/favicon.ico"))
    return _dedupe_preserve(url for url in urls if url)


def _homepage_candidate_urls(target: str) -> list[str]:
    raw = str(target or "").strip()
    if not raw:
        return []
    if re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        context = _target_context(raw)
        return [context["root_url"]] if context["root_url"] else []
    https_context = _target_context(raw, default_scheme="https")
    http_context = _target_context(raw, default_scheme="http")
    candidates = [https_context["root_url"], http_context["root_url"]]
    return [candidate for candidate in _dedupe_preserve(candidates) if candidate]


def _best_response_body(response: httpx.Response) -> str:
    try:
        return response.text
    except Exception:
        try:
            return response.content.decode("utf-8", "replace")
        except Exception:
            return ""


def _sync_fetch_homepage(target: str, client: httpx.Client, *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    result: dict[str, Any] = {
        "request_url": None,
        "url": None,
        "status_code": None,
        "content_type": None,
        "page_metadata": parse_homepage_html(""),
        "http_fingerprint": capture_http_fingerprint({}),
        "error": None,
    }
    last_error: str | None = None
    for candidate in _homepage_candidate_urls(target):
        try:
            response = client.get(candidate, headers=DEFAULT_HEADERS, timeout=timeout, follow_redirects=True)
            body = _best_response_body(response)
            result.update(
                {
                    "request_url": candidate,
                    "url": str(response.url),
                    "status_code": response.status_code,
                    "content_type": response.headers.get("content-type"),
                    "page_metadata": parse_homepage_html(body, page_url=str(response.url)),
                    "http_fingerprint": capture_http_fingerprint(response),
                    "error": None,
                }
            )
            return result
        except Exception as exc:
            last_error = str(exc)
    result["error"] = last_error
    return result


def fetch_homepage(target: str, client: httpx.Client | None = None, *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    if client is not None:
        return _sync_fetch_homepage(target, client, timeout=timeout)
    with httpx.Client(**httpx_kwargs()) as owned_client:
        return _sync_fetch_homepage(target, owned_client, timeout=timeout)


async def _async_fetch_homepage(target: str, client: httpx.AsyncClient, *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    result: dict[str, Any] = {
        "request_url": None,
        "url": None,
        "status_code": None,
        "content_type": None,
        "page_metadata": parse_homepage_html(""),
        "http_fingerprint": capture_http_fingerprint({}),
        "error": None,
    }
    last_error: str | None = None
    for candidate in _homepage_candidate_urls(target):
        try:
            response = await client.get(candidate, headers=DEFAULT_HEADERS, timeout=timeout, follow_redirects=True)
            body = _best_response_body(response)
            result.update(
                {
                    "request_url": candidate,
                    "url": str(response.url),
                    "status_code": response.status_code,
                    "content_type": response.headers.get("content-type"),
                    "page_metadata": parse_homepage_html(body, page_url=str(response.url)),
                    "http_fingerprint": capture_http_fingerprint(response),
                    "error": None,
                }
            )
            return result
        except Exception as exc:
            last_error = str(exc)
    result["error"] = last_error
    return result


async def async_fetch_homepage(target: str, client: httpx.AsyncClient | None = None, *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    if client is not None:
        return await _async_fetch_homepage(target, client, timeout=timeout)
    async with httpx.AsyncClient(**httpx_kwargs()) as owned_client:
        return await _async_fetch_homepage(target, owned_client, timeout=timeout)


def _well_known_attempt_sync(
    root_url: str,
    path: str,
    client: httpx.Client,
    *,
    timeout: float,
) -> dict[str, Any]:
    url = urljoin(root_url, path)
    try:
        response = client.get(url, headers=DEFAULT_HEADERS, timeout=timeout, follow_redirects=True)
        content = response.content
        return {
            "url": str(response.url),
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type"),
            "sha256": hashlib.sha256(content).hexdigest() if content else None,
            "content": content,
            "error": None,
        }
    except Exception as exc:
        return {
            "url": url,
            "status_code": None,
            "content_type": None,
            "sha256": None,
            "content": b"",
            "error": str(exc),
        }


async def _well_known_attempt_async(
    root_url: str,
    path: str,
    client: httpx.AsyncClient,
    *,
    timeout: float,
) -> dict[str, Any]:
    url = urljoin(root_url, path)
    try:
        response = await client.get(url, headers=DEFAULT_HEADERS, timeout=timeout, follow_redirects=True)
        content = response.content
        return {
            "url": str(response.url),
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type"),
            "sha256": hashlib.sha256(content).hexdigest() if content else None,
            "content": content,
            "error": None,
        }
    except Exception as exc:
        return {
            "url": url,
            "status_code": None,
            "content_type": None,
            "sha256": None,
            "content": b"",
            "error": str(exc),
        }


def _select_well_known_result(name: str, attempts: list[dict[str, Any]]) -> dict[str, Any]:
    parser = _parser_for_well_known(name)
    chosen = next(
        (
            attempt
            for attempt in attempts
            if attempt.get("status_code") == 200 and attempt.get("content")
        ),
        attempts[0] if attempts else {"url": None, "status_code": None, "content_type": None, "sha256": None, "content": b"", "error": None},
    )
    parsed = parser(chosen.get("content"))
    return {
        "found": bool(chosen.get("status_code") == 200 and chosen.get("content")),
        "url": chosen.get("url"),
        "status_code": chosen.get("status_code"),
        "content_type": chosen.get("content_type"),
        "sha256": chosen.get("sha256"),
        "parsed": parsed,
        "error": chosen.get("error"),
        "attempts": [
            {
                "url": attempt.get("url"),
                "status_code": attempt.get("status_code"),
                "content_type": attempt.get("content_type"),
                "error": attempt.get("error"),
            }
            for attempt in attempts
        ],
    }


def _sync_fetch_well_known_files(target: str, client: httpx.Client, *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    root_url = normalize_target_url(target)
    results: dict[str, Any] = {}
    for name, paths in WELL_KNOWN_PATHS.items():
        attempts = [_well_known_attempt_sync(root_url, path, client, timeout=timeout) for path in paths]
        results[name] = _select_well_known_result(name, attempts)
    return results


def fetch_well_known_files(target: str, client: httpx.Client | None = None, *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    if client is not None:
        return _sync_fetch_well_known_files(target, client, timeout=timeout)
    with httpx.Client(**httpx_kwargs()) as owned_client:
        return _sync_fetch_well_known_files(target, owned_client, timeout=timeout)


async def _async_fetch_well_known_files(target: str, client: httpx.AsyncClient, *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    root_url = normalize_target_url(target)
    results: dict[str, Any] = {}
    for name, paths in WELL_KNOWN_PATHS.items():
        attempts = [await _well_known_attempt_async(root_url, path, client, timeout=timeout) for path in paths]
        results[name] = _select_well_known_result(name, attempts)
    return results


async def async_fetch_well_known_files(target: str, client: httpx.AsyncClient | None = None, *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    if client is not None:
        return await _async_fetch_well_known_files(target, client, timeout=timeout)
    async with httpx.AsyncClient(**httpx_kwargs()) as owned_client:
        return await _async_fetch_well_known_files(target, owned_client, timeout=timeout)


def _sync_scrape_legal_pages(
    target: str,
    client: httpx.Client,
    *,
    paths: Sequence[str] = LEGAL_PAGE_PATHS,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    root_url = normalize_target_url(target)
    pages: list[dict[str, Any]] = []
    entity_names: list[str] = []
    registration_ids: list[str] = []
    addresses: list[str] = []
    phones: list[str] = []
    emails: list[str] = []
    for raw_path in _dedupe_preserve(str(path).strip() for path in paths if str(path).strip()):
        path = raw_path if raw_path.startswith("/") else f"/{raw_path}"
        url = urljoin(root_url, path)
        try:
            response = client.get(url, headers=DEFAULT_HEADERS, timeout=timeout, follow_redirects=True)
            body = _best_response_body(response)
            parsed = extract_legal_page_signals(body, page_url=str(response.url)) if body else {
                "url": str(response.url),
                "title": None,
                "normalized_text_hash": None,
                "entity_names": [],
                "registration_ids": [],
                "addresses": [],
                "phones": [],
                "emails": [],
            }
            entry = {
                "path": path,
                "requested_url": url,
                "url": str(response.url),
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type"),
                "error": None,
                **parsed,
            }
        except Exception as exc:
            entry = {
                "path": path,
                "requested_url": url,
                "url": url,
                "status_code": None,
                "content_type": None,
                "error": str(exc),
                "title": None,
                "normalized_text_hash": None,
                "entity_names": [],
                "registration_ids": [],
                "addresses": [],
                "phones": [],
                "emails": [],
            }
        pages.append(entry)
        entity_names.extend(entry["entity_names"])
        registration_ids.extend(entry["registration_ids"])
        addresses.extend(entry["addresses"])
        phones.extend(entry["phones"])
        emails.extend(entry["emails"])
    return {
        "pages": pages,
        "entity_names": _dedupe_preserve(entity_names),
        "registration_ids": _dedupe_preserve(registration_ids),
        "addresses": _dedupe_preserve(addresses),
        "phones": _dedupe_preserve(phones),
        "emails": _dedupe_preserve(emails),
    }


def scrape_legal_pages(
    target: str,
    client: httpx.Client | None = None,
    *,
    paths: Sequence[str] = LEGAL_PAGE_PATHS,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    if client is not None:
        return _sync_scrape_legal_pages(target, client, paths=paths, timeout=timeout)
    with httpx.Client(**httpx_kwargs()) as owned_client:
        return _sync_scrape_legal_pages(target, owned_client, paths=paths, timeout=timeout)


async def _async_scrape_legal_pages(
    target: str,
    client: httpx.AsyncClient,
    *,
    paths: Sequence[str] = LEGAL_PAGE_PATHS,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    root_url = normalize_target_url(target)
    pages: list[dict[str, Any]] = []
    entity_names: list[str] = []
    registration_ids: list[str] = []
    addresses: list[str] = []
    phones: list[str] = []
    emails: list[str] = []
    for raw_path in _dedupe_preserve(str(path).strip() for path in paths if str(path).strip()):
        path = raw_path if raw_path.startswith("/") else f"/{raw_path}"
        url = urljoin(root_url, path)
        try:
            response = await client.get(url, headers=DEFAULT_HEADERS, timeout=timeout, follow_redirects=True)
            body = _best_response_body(response)
            parsed = extract_legal_page_signals(body, page_url=str(response.url)) if body else {
                "url": str(response.url),
                "title": None,
                "normalized_text_hash": None,
                "entity_names": [],
                "registration_ids": [],
                "addresses": [],
                "phones": [],
                "emails": [],
            }
            entry = {
                "path": path,
                "requested_url": url,
                "url": str(response.url),
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type"),
                "error": None,
                **parsed,
            }
        except Exception as exc:
            entry = {
                "path": path,
                "requested_url": url,
                "url": url,
                "status_code": None,
                "content_type": None,
                "error": str(exc),
                "title": None,
                "normalized_text_hash": None,
                "entity_names": [],
                "registration_ids": [],
                "addresses": [],
                "phones": [],
                "emails": [],
            }
        pages.append(entry)
        entity_names.extend(entry["entity_names"])
        registration_ids.extend(entry["registration_ids"])
        addresses.extend(entry["addresses"])
        phones.extend(entry["phones"])
        emails.extend(entry["emails"])
    return {
        "pages": pages,
        "entity_names": _dedupe_preserve(entity_names),
        "registration_ids": _dedupe_preserve(registration_ids),
        "addresses": _dedupe_preserve(addresses),
        "phones": _dedupe_preserve(phones),
        "emails": _dedupe_preserve(emails),
    }


async def async_scrape_legal_pages(
    target: str,
    client: httpx.AsyncClient | None = None,
    *,
    paths: Sequence[str] = LEGAL_PAGE_PATHS,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    if client is not None:
        return await _async_scrape_legal_pages(target, client, paths=paths, timeout=timeout)
    async with httpx.AsyncClient(**httpx_kwargs()) as owned_client:
        return await _async_scrape_legal_pages(target, owned_client, paths=paths, timeout=timeout)


def _sync_fetch_script_body(
    client: httpx.Client,
    url: str,
    *,
    timeout: float,
    max_bytes: int,
) -> dict[str, Any]:
    try:
        with client.stream(
            "GET",
            url,
            headers={**DEFAULT_HEADERS, "Range": f"bytes=0-{max_bytes - 1}"},
            timeout=timeout,
            follow_redirects=True,
        ) as response:
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                if not chunk:
                    continue
                remaining = max_bytes - total
                if remaining <= 0:
                    break
                chunks.append(chunk[:remaining])
                total += len(chunks[-1])
                if total >= max_bytes:
                    break
            body = b"".join(chunks)
            return {
                "url": str(response.url),
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type"),
                "headers": response.headers,
                "body": body,
                "error": None,
            }
    except Exception as exc:
        return {
            "url": url,
            "status_code": None,
            "content_type": None,
            "headers": {},
            "body": b"",
            "error": str(exc),
        }


async def _async_fetch_script_body(
    client: httpx.AsyncClient,
    url: str,
    *,
    timeout: float,
    max_bytes: int,
) -> dict[str, Any]:
    try:
        async with client.stream(
            "GET",
            url,
            headers={**DEFAULT_HEADERS, "Range": f"bytes=0-{max_bytes - 1}"},
            timeout=timeout,
            follow_redirects=True,
        ) as response:
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes():
                if not chunk:
                    continue
                remaining = max_bytes - total
                if remaining <= 0:
                    break
                chunks.append(chunk[:remaining])
                total += len(chunks[-1])
                if total >= max_bytes:
                    break
            body = b"".join(chunks)
            return {
                "url": str(response.url),
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type"),
                "headers": response.headers,
                "body": body,
                "error": None,
            }
    except Exception as exc:
        return {
            "url": url,
            "status_code": None,
            "content_type": None,
            "headers": {},
            "body": b"",
            "error": str(exc),
        }


def _script_urls_from_input(script_urls_or_homepage: Any) -> list[str]:
    if isinstance(script_urls_or_homepage, Mapping):
        if script_urls_or_homepage.get("script_urls"):
            return [str(item) for item in script_urls_or_homepage.get("script_urls") or [] if item]
        if script_urls_or_homepage.get("script_assets"):
            return [
                str(item.get("url"))
                for item in script_urls_or_homepage.get("script_assets") or []
                if isinstance(item, Mapping) and item.get("url")
            ]
    if isinstance(script_urls_or_homepage, (list, tuple, set)):
        return [str(item) for item in script_urls_or_homepage if item]
    if isinstance(script_urls_or_homepage, str):
        return [script_urls_or_homepage]
    return []


def _decode_script_body(body: bytes) -> str:
    try:
        return body.decode("utf-8")
    except Exception:
        return body.decode("utf-8", "replace")


def _assemble_script_scan(entries: list[dict[str, Any]]) -> dict[str, Any]:
    source_maps: list[str] = []
    bundlers: list[str] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        source_maps.extend(entry.get("source_map_urls", []))
        bundlers.extend(entry.get("bundlers", []))
    return {
        "scripts": entries,
        "source_map_urls": _dedupe_preserve(source_maps),
        "bundlers": _dedupe_preserve(bundlers),
    }


def _sync_fetch_source_map_disclosures(
    script_urls_or_homepage: Any,
    client: httpx.Client,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_scripts: int = DEFAULT_MAX_SCRIPTS,
    max_bytes: int = DEFAULT_SCRIPT_MAX_BYTES,
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for url in _dedupe_preserve(_script_urls_from_input(script_urls_or_homepage))[:max_scripts]:
        fetched = _sync_fetch_script_body(client, url, timeout=timeout, max_bytes=max_bytes)
        if fetched["error"]:
            entries.append(
                {
                    "url": fetched["url"],
                    "status_code": fetched["status_code"],
                    "content_type": fetched["content_type"],
                    "source_map_urls": [],
                    "bundlers": [],
                    "error": fetched["error"],
                }
            )
            continue
        text = _decode_script_body(fetched["body"])
        disclosure = scan_script_disclosures(text, script_url=fetched["url"], headers_or_response=fetched["headers"])
        entries.append(
            {
                "url": fetched["url"],
                "status_code": fetched["status_code"],
                "content_type": fetched["content_type"],
                "source_map_urls": disclosure["source_map_urls"],
                "bundlers": disclosure["bundlers"],
                "error": None,
            }
        )
    return _assemble_script_scan(entries)


def fetch_source_map_disclosures(
    script_urls_or_homepage: Any,
    client: httpx.Client | None = None,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_scripts: int = DEFAULT_MAX_SCRIPTS,
    max_bytes: int = DEFAULT_SCRIPT_MAX_BYTES,
) -> dict[str, Any]:
    if client is not None:
        return _sync_fetch_source_map_disclosures(
            script_urls_or_homepage,
            client,
            timeout=timeout,
            max_scripts=max_scripts,
            max_bytes=max_bytes,
        )
    with httpx.Client(**httpx_kwargs()) as owned_client:
        return _sync_fetch_source_map_disclosures(
            script_urls_or_homepage,
            owned_client,
            timeout=timeout,
            max_scripts=max_scripts,
            max_bytes=max_bytes,
        )


async def _async_fetch_source_map_disclosures(
    script_urls_or_homepage: Any,
    client: httpx.AsyncClient,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_scripts: int = DEFAULT_MAX_SCRIPTS,
    max_bytes: int = DEFAULT_SCRIPT_MAX_BYTES,
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for url in _dedupe_preserve(_script_urls_from_input(script_urls_or_homepage))[:max_scripts]:
        fetched = await _async_fetch_script_body(client, url, timeout=timeout, max_bytes=max_bytes)
        if fetched["error"]:
            entries.append(
                {
                    "url": fetched["url"],
                    "status_code": fetched["status_code"],
                    "content_type": fetched["content_type"],
                    "source_map_urls": [],
                    "bundlers": [],
                    "error": fetched["error"],
                }
            )
            continue
        text = _decode_script_body(fetched["body"])
        disclosure = scan_script_disclosures(text, script_url=fetched["url"], headers_or_response=fetched["headers"])
        entries.append(
            {
                "url": fetched["url"],
                "status_code": fetched["status_code"],
                "content_type": fetched["content_type"],
                "source_map_urls": disclosure["source_map_urls"],
                "bundlers": disclosure["bundlers"],
                "error": None,
            }
        )
    return _assemble_script_scan(entries)


async def async_fetch_source_map_disclosures(
    script_urls_or_homepage: Any,
    client: httpx.AsyncClient | None = None,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_scripts: int = DEFAULT_MAX_SCRIPTS,
    max_bytes: int = DEFAULT_SCRIPT_MAX_BYTES,
) -> dict[str, Any]:
    if client is not None:
        return await _async_fetch_source_map_disclosures(
            script_urls_or_homepage,
            client,
            timeout=timeout,
            max_scripts=max_scripts,
            max_bytes=max_bytes,
        )
    async with httpx.AsyncClient(**httpx_kwargs()) as owned_client:
        return await _async_fetch_source_map_disclosures(
            script_urls_or_homepage,
            owned_client,
            timeout=timeout,
            max_scripts=max_scripts,
            max_bytes=max_bytes,
        )


def _sync_fetch_favicons(
    target: str,
    client: httpx.Client,
    *,
    homepage_data: Mapping[str, Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_icons: int = DEFAULT_MAX_FAVICONS,
    include_content: bool = False,
) -> dict[str, Any]:
    page_url = str((homepage_data or {}).get("canonical_url") or "")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", page_url, re.I):
        page_url = normalize_target_url(page_url or target)
    urls = find_favicon_urls(page_url or normalize_target_url(target), homepage_data=homepage_data)[:max_icons]
    icons: list[dict[str, Any]] = []
    for url in urls:
        try:
            response = client.get(url, headers=DEFAULT_HEADERS, timeout=timeout, follow_redirects=True)
            if response.status_code != 200 or not response.content:
                icons.append(
                    {
                        "url": str(response.url),
                        "status_code": response.status_code,
                        "content_type": response.headers.get("content-type"),
                        "error": None,
                    }
                )
                continue
            hashes = hash_favicon_bytes(response.content)
            entry = {
                "url": str(response.url),
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type"),
                "size": len(response.content),
                **hashes,
                "error": None,
            }
            if include_content:
                entry["content"] = response.content
            icons.append(entry)
        except Exception as exc:
            icons.append(
                {
                    "url": url,
                    "status_code": None,
                    "content_type": None,
                    "error": str(exc),
                }
            )
    return {"icons": icons}


def fetch_favicons(
    target: str,
    client: httpx.Client | None = None,
    *,
    homepage_data: Mapping[str, Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_icons: int = DEFAULT_MAX_FAVICONS,
    include_content: bool = False,
) -> dict[str, Any]:
    if client is not None:
        return _sync_fetch_favicons(
            target,
            client,
            homepage_data=homepage_data,
            timeout=timeout,
            max_icons=max_icons,
            include_content=include_content,
        )
    with httpx.Client(**httpx_kwargs()) as owned_client:
        return _sync_fetch_favicons(
            target,
            owned_client,
            homepage_data=homepage_data,
            timeout=timeout,
            max_icons=max_icons,
            include_content=include_content,
        )


async def _async_fetch_favicons(
    target: str,
    client: httpx.AsyncClient,
    *,
    homepage_data: Mapping[str, Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_icons: int = DEFAULT_MAX_FAVICONS,
    include_content: bool = False,
) -> dict[str, Any]:
    page_url = str((homepage_data or {}).get("canonical_url") or "")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", page_url, re.I):
        page_url = normalize_target_url(page_url or target)
    urls = find_favicon_urls(page_url or normalize_target_url(target), homepage_data=homepage_data)[:max_icons]
    icons: list[dict[str, Any]] = []
    for url in urls:
        try:
            response = await client.get(url, headers=DEFAULT_HEADERS, timeout=timeout, follow_redirects=True)
            if response.status_code != 200 or not response.content:
                icons.append(
                    {
                        "url": str(response.url),
                        "status_code": response.status_code,
                        "content_type": response.headers.get("content-type"),
                        "error": None,
                    }
                )
                continue
            hashes = hash_favicon_bytes(response.content)
            entry = {
                "url": str(response.url),
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type"),
                "size": len(response.content),
                **hashes,
                "error": None,
            }
            if include_content:
                entry["content"] = response.content
            icons.append(entry)
        except Exception as exc:
            icons.append(
                {
                    "url": url,
                    "status_code": None,
                    "content_type": None,
                    "error": str(exc),
                }
            )
    return {"icons": icons}


async def async_fetch_favicons(
    target: str,
    client: httpx.AsyncClient | None = None,
    *,
    homepage_data: Mapping[str, Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_icons: int = DEFAULT_MAX_FAVICONS,
    include_content: bool = False,
) -> dict[str, Any]:
    if client is not None:
        return await _async_fetch_favicons(
            target,
            client,
            homepage_data=homepage_data,
            timeout=timeout,
            max_icons=max_icons,
            include_content=include_content,
        )
    async with httpx.AsyncClient(**httpx_kwargs()) as owned_client:
        return await _async_fetch_favicons(
            target,
            owned_client,
            homepage_data=homepage_data,
            timeout=timeout,
            max_icons=max_icons,
            include_content=include_content,
        )


def _sync_probe_mail_client_config(target: str, client: httpx.Client, *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    probes = build_mail_client_config_urls(target)
    autodiscover: list[dict[str, Any]] = []
    autoconfig: list[dict[str, Any]] = []
    servers: list[str] = []
    domains: list[str] = []
    for kind, entries in probes.items():
        for probe in entries:
            url = probe.get("url")
            if not url:
                continue
            try:
                response = client.get(url, headers=DEFAULT_HEADERS, timeout=timeout, follow_redirects=True)
                body = response.content
                parsed = parse_autodiscover_xml(body) if kind == "autodiscover" else parse_autoconfig_xml(body)
                entry = {
                    "label": probe["label"],
                    "url": str(response.url),
                    "status_code": response.status_code,
                    "content_type": response.headers.get("content-type"),
                    "parsed": parsed,
                    "error": None,
                }
            except Exception as exc:
                entry = {
                    "label": probe["label"],
                    "url": url,
                    "status_code": None,
                    "content_type": None,
                    "parsed": {},
                    "error": str(exc),
                }
            if kind == "autodiscover":
                autodiscover.append(entry)
                parsed = entry.get("parsed") if isinstance(entry.get("parsed"), Mapping) else {}
                servers.extend(parsed.get("servers", []))
                domains.extend(parsed.get("domains", []))
            else:
                autoconfig.append(entry)
                parsed = entry.get("parsed") if isinstance(entry.get("parsed"), Mapping) else {}
                for server in parsed.get("incoming_servers", []) + parsed.get("outgoing_servers", []):
                    if not isinstance(server, Mapping):
                        continue
                    hostname = server.get("hostname")
                    if hostname:
                        servers.append(hostname)
                domains.extend(parsed.get("domains", []))
    return {
        "autodiscover": autodiscover,
        "autoconfig": autoconfig,
        "servers": _dedupe_preserve(servers),
        "domains": _dedupe_preserve(domains),
    }


def probe_mail_client_config(target: str, client: httpx.Client | None = None, *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    if client is not None:
        return _sync_probe_mail_client_config(target, client, timeout=timeout)
    with httpx.Client(**httpx_kwargs()) as owned_client:
        return _sync_probe_mail_client_config(target, owned_client, timeout=timeout)


async def _async_probe_mail_client_config(
    target: str,
    client: httpx.AsyncClient,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    probes = build_mail_client_config_urls(target)
    autodiscover: list[dict[str, Any]] = []
    autoconfig: list[dict[str, Any]] = []
    servers: list[str] = []
    domains: list[str] = []
    for kind, entries in probes.items():
        for probe in entries:
            url = probe.get("url")
            if not url:
                continue
            try:
                response = await client.get(url, headers=DEFAULT_HEADERS, timeout=timeout, follow_redirects=True)
                body = response.content
                parsed = parse_autodiscover_xml(body) if kind == "autodiscover" else parse_autoconfig_xml(body)
                entry = {
                    "label": probe["label"],
                    "url": str(response.url),
                    "status_code": response.status_code,
                    "content_type": response.headers.get("content-type"),
                    "parsed": parsed,
                    "error": None,
                }
            except Exception as exc:
                entry = {
                    "label": probe["label"],
                    "url": url,
                    "status_code": None,
                    "content_type": None,
                    "parsed": {},
                    "error": str(exc),
                }
            if kind == "autodiscover":
                autodiscover.append(entry)
                parsed = entry.get("parsed") if isinstance(entry.get("parsed"), Mapping) else {}
                servers.extend(parsed.get("servers", []))
                domains.extend(parsed.get("domains", []))
            else:
                autoconfig.append(entry)
                parsed = entry.get("parsed") if isinstance(entry.get("parsed"), Mapping) else {}
                for server in parsed.get("incoming_servers", []) + parsed.get("outgoing_servers", []):
                    if not isinstance(server, Mapping):
                        continue
                    hostname = server.get("hostname")
                    if hostname:
                        servers.append(hostname)
                domains.extend(parsed.get("domains", []))
    return {
        "autodiscover": autodiscover,
        "autoconfig": autoconfig,
        "servers": _dedupe_preserve(servers),
        "domains": _dedupe_preserve(domains),
    }


async def async_probe_mail_client_config(
    target: str,
    client: httpx.AsyncClient | None = None,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    if client is not None:
        return await _async_probe_mail_client_config(target, client, timeout=timeout)
    async with httpx.AsyncClient(**httpx_kwargs()) as owned_client:
        return await _async_probe_mail_client_config(target, owned_client, timeout=timeout)


def fetch_page_metadata(
    domain: str,
    save_favicon_as: Path | None = None,
    client: httpx.Client | None = None,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    if client is None:
        with httpx.Client(**httpx_kwargs()) as owned_client:
            return fetch_page_metadata(domain, save_favicon_as=save_favicon_as, client=owned_client, timeout=timeout)

    homepage = _sync_fetch_homepage(domain, client, timeout=timeout)
    result: dict[str, Any] = {
        "google_analytics": [],
        "gtm_ids": [],
        "facebook_pixel": [],
        "tiktok_pixel": [],
        "yandex_metrika": [],
        "adsense_ids": [],
        "html_lang": None,
        "cms_generator": None,
        "social_links": {},
        "social_handles": {},
        "favicon_md5": None,
        "favicon_murmurhash3": None,
        "favicon_saved": None,
        "error": homepage.get("error"),
        "http_fingerprint": homepage.get("http_fingerprint"),
        "final_url": homepage.get("url"),
        "status_code": homepage.get("status_code"),
    }
    result.update(homepage.get("page_metadata") or {})
    favicon_result = _sync_fetch_favicons(
        homepage.get("url") or domain,
        client,
        homepage_data=homepage.get("page_metadata") or {},
        timeout=min(timeout, 10.0),
        max_icons=1,
        include_content=save_favicon_as is not None,
    )
    icons = favicon_result.get("icons") or []
    if icons:
        first_icon = icons[0]
        result["favicon_md5"] = first_icon.get("md5")
        result["favicon_murmurhash3"] = first_icon.get("murmurhash3")
        if save_favicon_as is not None and first_icon.get("content"):
            save_favicon_as.write_bytes(first_icon["content"])
            result["favicon_saved"] = str(save_favicon_as)
    return result


def extract_page_enrichment(html_doc: str, *, base_url: str | None = None) -> dict[str, Any]:
    parsed = parse_homepage_html(html_doc, page_url=base_url)
    adsense_ids = sorted(
        {
            *[value[3:] if value.startswith("ca-") else value for value in (parsed.get("adsense_ids") or [])],
            *re.findall(r"\b(pub-\d{10,20})\b", str(html_doc or ""), re.I),
        }
    )
    return {
        "adsense_publisher_ids": _dedupe_preserve(adsense_ids),
        "fb_app_id": [parsed["fb_app_id"]] if parsed.get("fb_app_id") else [],
        "twitter_site": [parsed["twitter_site"]] if parsed.get("twitter_site") else [],
        "twitter_creator": [parsed["twitter_creator"]] if parsed.get("twitter_creator") else [],
        "authors": parsed.get("authors") or [],
        "rel_me": parsed.get("rel_me_links") or [],
        "homepage_html_hash": parsed.get("homepage_text_hash"),
        "meta_tags": parsed.get("meta_tags") or {},
        "script_assets": parsed.get("script_urls") or [],
        "bundler_hints": _dedupe_preserve(
            (parsed.get("inline_bundlers") or [])
            + [item.get("type") for item in parsed.get("script_assets") or [] if isinstance(item, Mapping) and item.get("type")]
        ),
    }


async def afetch_homepage_profile(
    domain: str,
    client: httpx.AsyncClient,
    *,
    save_favicon_as: Path | None = None,
    user_agent: str | None = None,
) -> dict[str, Any]:
    homepage = await async_fetch_homepage(domain, client=client)
    result = {
        "html": "",
        "final_url": homepage.get("url"),
        "error": homepage.get("error"),
        "http_fingerprint": homepage.get("http_fingerprint") or {},
    }
    result.update(extract_page_enrichment("", base_url=homepage.get("url")))
    page_metadata = homepage.get("page_metadata") or {}
    result.update(
        {
            "google_analytics": page_metadata.get("google_analytics") or [],
            "gtm_ids": page_metadata.get("gtm_ids") or [],
            "facebook_pixel": page_metadata.get("facebook_pixel") or [],
            "tiktok_pixel": page_metadata.get("tiktok_pixel") or [],
            "yandex_metrika": page_metadata.get("yandex_metrika") or [],
            "html_lang": page_metadata.get("html_lang"),
            "cms_generator": page_metadata.get("cms_generator"),
            "social_links": page_metadata.get("social_links") or {},
            "social_handles": page_metadata.get("social_handles") or {},
            "adsense_publisher_ids": [value[3:] if value.startswith("ca-") else value for value in (page_metadata.get("adsense_ids") or [])],
            "fb_app_id": [page_metadata["fb_app_id"]] if page_metadata.get("fb_app_id") else [],
            "twitter_site": [page_metadata["twitter_site"]] if page_metadata.get("twitter_site") else [],
            "twitter_creator": [page_metadata["twitter_creator"]] if page_metadata.get("twitter_creator") else [],
            "authors": page_metadata.get("authors") or [],
            "rel_me": page_metadata.get("rel_me_links") or [],
            "homepage_html_hash": page_metadata.get("homepage_text_hash"),
            "meta_tags": page_metadata.get("meta_tags") or {},
            "script_assets": page_metadata.get("script_urls") or [],
            "bundler_hints": _dedupe_preserve(page_metadata.get("inline_bundlers") or []),
            "source_map_leaks": [],
        }
    )
    disclosures = await async_fetch_source_map_disclosures(page_metadata, client=client)
    for entry in (disclosures.get("entries") or disclosures.get("scripts") or []):
        if not isinstance(entry, Mapping):
            continue
        result["source_map_leaks"].append(
            {
                "script_url": entry.get("script_url"),
                "source_mapping_urls": entry.get("source_map_urls") or [],
                "internal_path_leaks": entry.get("internal_paths") or [],
            }
        )
    favicons = await async_fetch_favicons(
        homepage.get("url") or domain,
        client=client,
        homepage_data=page_metadata,
        include_content=save_favicon_as is not None,
        max_icons=1,
    )
    icons = favicons.get("icons") or []
    if icons:
        first = icons[0]
        result["favicon_md5"] = first.get("md5")
        result["favicon_mmh3"] = first.get("murmurhash3")
        if save_favicon_as is not None and first.get("content"):
            save_favicon_as.write_bytes(first["content"])
            result["favicon_saved"] = str(save_favicon_as)
    else:
        result["favicon_md5"] = None
        result["favicon_mmh3"] = None
        result["favicon_saved"] = None
    return result


async def afetch_well_known_artifacts(domain: str, client: httpx.AsyncClient) -> dict[str, Any]:
    raw = await async_fetch_well_known_files(domain, client=client)
    return {
        "apple_app_site_association": raw.get("apple_app_site_association", {}).get("parsed") or {},
        "assetlinks": parse_assetlinks(raw.get("assetlinks_json", {}).get("body")) if raw.get("assetlinks_json", {}).get("body") is not None else {},
        "security_txt": raw.get("security_txt", {}).get("parsed") or {},
        "openid_configuration": raw.get("openid_configuration", {}).get("parsed") or {},
        "mta_sts_file": raw.get("mta_sts_txt", {}).get("parsed") or {},
        "humans_txt": raw.get("humans_txt", {}).get("parsed") or {},
        "ads_txt": raw.get("ads_txt", {}).get("parsed") or {},
    }


async def ascrape_legal_pages(domain: str, client: httpx.AsyncClient) -> list[dict[str, Any]]:
    raw = await async_scrape_legal_pages(domain, client=client)
    pages = []
    for page in raw.get("pages") or []:
        if not isinstance(page, Mapping):
            continue
        pages.append(
            {
                "url": page.get("url"),
                "entities": page.get("entities") or [],
                "registration_numbers": {
                    "companies_house": [value for value in page.get("registration_ids") or [] if re.fullmatch(r"\d{8}", str(value or ""))],
                    "vat_ids": [value for value in page.get("registration_ids") or [] if re.fullmatch(r"[A-Z]{2}\d{8,12}", str(value or ""))],
                    "delaware_file_numbers": [],
                    "german_hrb": [value for value in page.get("registration_ids") or [] if str(value or "").startswith("HRB")],
                    "siret": [value for value in page.get("registration_ids") or [] if re.fullmatch(r"\d{14}", str(value or ""))],
                },
                "postal_addresses": page.get("addresses") or [],
                "phone_numbers": page.get("phones") or [],
                "emails": page.get("emails") or [],
                "urls": page.get("urls") or [],
                "text_hash": page.get("text_hash"),
            }
        )
    return pages


async def afetch_mail_client_config(domain: str, client: httpx.AsyncClient) -> dict[str, Any]:
    return await async_probe_mail_client_config(domain, client=client)


def compute_favicon_hashes(content: bytes | None) -> dict[str, Any]:
    hashes = hash_favicon_bytes(content)
    return {"favicon_md5": hashes.get("md5"), "favicon_mmh3": hashes.get("murmurhash3")}


def parse_assetlinks(content: bytes | str | None) -> dict[str, Any]:
    parsed = parse_assetlinks_json(content)
    android_apps = []
    for statement in parsed.get("statements") or []:
        if not isinstance(statement, Mapping):
            continue
        if statement.get("namespace") != "android_app":
            continue
        android_apps.append(
            {
                "package_name": statement.get("package_name"),
                "sha256_cert_fingerprints": statement.get("sha256_cert_fingerprints") or [],
            }
        )
    return {"android_apps": android_apps}


__all__ = [
    "DEFAULT_HEADERS",
    "DEFAULT_TIMEOUT",
    "LEGAL_PAGE_PATHS",
    "WELL_KNOWN_PATHS",
    "MAIL_CLIENT_CONFIG_PATHS",
    "normalize_target_url",
    "normalize_text",
    "normalized_text_hash",
    "html_to_text",
    "html_text_hash",
    "parse_homepage_html",
    "_process_page_html",
    "capture_http_fingerprint",
    "parse_apple_app_site_association",
    "parse_assetlinks_json",
    "parse_security_txt",
    "parse_openid_configuration",
    "parse_mta_sts_txt",
    "parse_humans_txt",
    "parse_ads_txt",
    "extract_legal_page_signals",
    "scan_script_disclosures",
    "parse_autodiscover_xml",
    "parse_autoconfig_xml",
    "build_mail_client_config_urls",
    "hash_favicon_bytes",
    "find_favicon_urls",
    "fetch_homepage",
    "async_fetch_homepage",
    "fetch_well_known_files",
    "async_fetch_well_known_files",
    "scrape_legal_pages",
    "async_scrape_legal_pages",
    "fetch_source_map_disclosures",
    "async_fetch_source_map_disclosures",
    "probe_mail_client_config",
    "async_probe_mail_client_config",
    "fetch_favicons",
    "async_fetch_favicons",
    "fetch_page_metadata",
]
