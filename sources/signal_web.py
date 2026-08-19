from __future__ import annotations

import base64
import hashlib
import html
import json
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
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

# Per-probe fan-out for the multi-URL fetchers (well-known files, legal pages,
# mail client config). These previously walked their path lists sequentially,
# so on a slow/unreachable site every path hit the full DEFAULT_TIMEOUT one
# after another (N paths -> N x 15s). httpx.Client is thread-safe for
# concurrent requests over its shared pool, so we fan the paths out instead:
# the whole fetcher now costs ~one timeout, not N. Capped so a target with many
# paths doesn't open an unbounded number of sockets at once.
_PROBE_FANOUT = 8


def _run_probes_concurrent(fns: list, *, max_workers: int = _PROBE_FANOUT) -> list:
    """Run zero-arg callables concurrently, returning results in input order.

    Each callable must handle its own exceptions (all the probe helpers already
    return an error-shaped dict rather than raising), so results line up 1:1
    with `fns` and order is preserved for deterministic aggregation.
    """
    if not fns:
        return []
    with ThreadPoolExecutor(
        max_workers=min(len(fns), max_workers), thread_name_prefix="web-probe"
    ) as ex:
        return list(ex.map(lambda fn: fn(), fns))

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

# Case-insensitive denylist of literal path segments the patterns below can
# capture instead of a real handle. Most of these are share/embed/widget
# endpoints or content permalinks (post, reel, pin, status ids all live one
# segment further in than these patterns reach) rather than operator
# identities, so the captured literal is identical across thousands of
# unrelated sites — exactly the "reel"/"groups"/"share" bug class, just for
# every platform in _SOCIAL_PATTERNS instead of just the three reported.
_SOCIAL_NOISE = {
    "", "home", "login", "signup", "help", "support", "about", "contact", "profile.php", "pages",
    # app chrome / legal / nav segments repeated across most of these platforms
    "search", "explore", "settings", "notifications", "messages", "hashtag", "tag",
    "privacy", "terms", "tos", "legal", "cookies", "policies", "faq", "join",
    "business", "ads", "careers", "press", "developers", "apps",
    "accounts", "direct", "watch", "video", "videos", "photo", "photos", "live", "topic",
    "widgets", "widget", "plugins", "embed",
    # share / outbound-redirect endpoints — identical on every page carrying a
    # share button or an outbound link, never a real handle
    "share", "share.php", "sharer", "away.php", "l.php", "dk",
    # Telegram's own reserved deep-link namespace (core.telegram.org/api/links) —
    # Telegram never allows a real @username to collide with these
    "joinchat", "addstickers", "addtheme", "addstyle", "addemoji", "proxy", "socks",
    "iv", "confirmphone", "setlanguage", "auth", "call", "boost", "auction", "giftcode", "nft",
    # VK/OK feed & widget/embed endpoints that show up on any site embedding a
    # VK comment box, like button, or OK share button — not an operator identity
    "feed", "im", "widget_comments.php", "widget_community.php", "widget_recomm.php",
    "widget_events.php", "al_widget.php", "video_ext.php",
    # Facebook feature/content-permalink endpoints — same "captures the
    # structural prefix, not the id" problem as profile.php/pages above
    "groups", "events", "marketplace", "gaming", "login.php", "photo.php",
    "video.php", "permalink.php", "story.php",
    # Instagram content permalinks / app pages, not a profile
    "reel", "reels", "tv", "stories",
    # LinkedIn Showcase pages nest under /company/showcase/<id>, so the
    # "company" branch captures the literal "showcase" instead of the id
    "showcase",
    # Pinterest pin permalinks (pinterest.com/pin/<id>) and source-domain
    # aggregation pages (pinterest.com/source/<domain>), not a user
    "pin", "source",
}
_SOCIAL_PATTERNS = (
    ("telegram", re.compile(r"https?://t\.me/([A-Za-z0-9_]{3,60})", re.I)),
    ("vkontakte", re.compile(r"https?://(?:www\.)?vk\.com/([^\s\"'<>/?]{2,80})", re.I)),
    ("odnoklassniki", re.compile(r"https?://(?:www\.)?ok\.ru/(?:profile/|group/)?([^\s\"'<>/?]{2,80})", re.I)),
    # Mirrors the ok.ru pattern above: without stripping the optional
    # "profile/"/"group/" prefix, odnoklassniki.ru/profile/<id> would capture
    # the literal "profile" instead of the id that actually identifies the
    # account — the same structural-prefix bug as Facebook's profile.php/pages.
    ("odnoklassniki", re.compile(r"https?://(?:www\.)?odnoklassniki\.ru/(?:profile/|group/)?([^\s\"'<>/?]{2,80})", re.I)),
    ("twitter_x", re.compile(r"https?://(?:www\.)?(?:twitter|x)\.com/(?!search|share|intent|home)([^\s\"'<>/?]{2,60})", re.I)),
    ("tiktok", re.compile(r"https?://(?:www\.)?tiktok\.com/@([A-Za-z0-9_.]{2,60})", re.I)),
    ("instagram", re.compile(r"https?://(?:www\.)?instagram\.com/([^\s\"'<>/?]{2,60})", re.I)),
    # profile.php is Facebook's un-vanitized profile URL (facebook.com/profile.php?id=…);
    # the real identifier lives in the query string, which this pattern never
    # captures, so every site linking to any numeric-id profile would otherwise
    # extract the literal, identical "profile.php" — a false-positive shared
    # handle linking unrelated sites. Same problem for /pages/<Name>/<id> (the
    # legacy Facebook Page URL): the pattern stops at the first "/", so it
    # captures the literal directory segment "pages" rather than the name or
    # id that would actually distinguish one page from another.
    ("facebook", re.compile(r"https?://(?:www\.)?facebook\.com/(?!sharer|share|dialog|tr\b|profile\.php\b|pages\b)([^\s\"'<>/?]{2,80})", re.I)),
    ("youtube", re.compile(r"https?://(?:www\.)?youtube\.com/(?:channel/|@)([^\s\"'<>/?]{2,80})", re.I)),
    ("linkedin", re.compile(r"https?://(?:www\.)?linkedin\.com/(?:company|in)/([^\s\"'<>/?]{2,80})", re.I)),
    ("pinterest", re.compile(r"https?://(?:www\.)?pinterest\.(?:com|[a-z]{2})/([^\s\"'<>/?]{2,80})", re.I)),
    # No "github" entry: unlike the consumer/messaging platforms above, a
    # github.com/<org> link on a page is overwhelmingly a reference to some
    # third-party OSS project it depends on or credits (react, wordpress,
    # tailwindcss, ...) rather than the site's own account — e.g.
    # github.com/facebook shows up on hundreds of unrelated sites crediting
    # React. That makes it a reliable false-positive generator rather than an
    # ownership signal, so it's excluded instead of denylisted after the fact.
    #
    # Deliberately excludes tiktok.com/youtube.com (already covered above by
    # dedicated patterns — without this the same @handle would double-book
    # under "mastodon" too) and known npm/CDN package-registry hosts that
    # serve scoped packages straight off the root (unpkg.com/@babel/core,
    # esm.sh/@material-ui/core, cdn.skypack.dev/@popperjs/core, jspm.dev/@...).
    # Those show up in <script src> on huge numbers of unrelated sites and,
    # unlike a real fediverse handle, would extract the identical scope name
    # ("babel", "popperjs", ...) as a shared "social handle" everywhere the
    # same CDN package is loaded from — a false-positive generator worse than
    # the reported reel/groups/share bugs since it isn't social media at all.
    ("mastodon", re.compile(
        r"https?://(?!(?:www\.)?(?:tiktok\.com|youtube\.com|unpkg\.com|(?:cdn\.)?jsdelivr\.net|"
        r"cdnjs\.cloudflare\.com|esm\.(?:sh|run)|(?:cdn\.)?skypack\.dev|jspm\.(?:dev|io))\b)"
        r"([A-Za-z0-9.-]+)/@([A-Za-z0-9_]{2,80})",
        re.I,
    )),
)

# Site-ownership-proof meta tags: webmaster-tools verification codes are minted
# per account, so the same code on two domains is near-decisive shared-control
# evidence (see utils/evidence_meta.SELECTOR_BASE_WEIGHTS["site_verification"]).
SITE_VERIFICATION_META_KEYS = {
    "google-site-verification": "google",
    "msvalidate.01": "bing",
    "yandex-verification": "yandex",
    "p:domain_verify": "pinterest",
    "facebook-domain-verification": "facebook",
    "norton-safeweb-site-verification": "norton",
    "alexaverifyid": "alexa",
    "baidu-site-verification": "baidu",
    "naver-site-verification": "naver",
    "ahrefs-site-verification": "ahrefs",
    "shopify-verification": "shopify",
    "verify-v1": "yahoo",
    "wot-verification": "wot",
}

# Meta tags that carry a handle for a platform not covered by a t.me/vk.com/…
# URL pattern above — e.g. Telegram's own widget meta only exposes "@handle".
SOCIAL_HANDLE_META_KEYS = {
    "telegram:channel": "telegram",
}

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
_PHONE_HREF_SCHEMES = ("tel:", "callto:", "sms:")
_PHONE_META_KEYS = ("telephone", "phone", "contact:phone_number", "business:contact_data:phone_number", "og:phone_number")
# 555-01XX is an IANA/NANP-reserved range set aside specifically for fictional
# use in film, docs and templates (like 555-0100 example.com), so it shows up
# verbatim on unrelated placeholder/demo sites and would otherwise link them.
_PHONE_FICTIONAL_555_RE = re.compile(r"55501\d\d")
_PHONE_DATE_SHAPE_RE = re.compile(
    r"^(?:(?:19|20)\d{2}[-/.](?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01])"
    r"|(?:0[1-9]|[12]\d|3[01])[-/.](?:0[1-9]|1[0-2])[-/.](?:19|20)\d{2}"
    r"|(?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01])[-/.](?:19|20)\d{2})$"
)
# Nearby labels that mean a digit run is a structured identifier (order/VAT/
# tracking/ISBN/coordinates/...) rather than a contact number -- these ids are
# frequently formatted with phone-shaped separators (spaces, dashes) so the
# digit pattern alone can't tell them apart from a real phone number.
_PHONE_NEGATIVE_CONTEXT_RE = re.compile(
    r"(?i)\b(order\s*no|invoice|tracking|reference\s*no|ref\.?\s*no|isbn|issn|sku|part\s*no|serial\s*no|"
    r"model\s*no|case\s*no|version|coordinates?|latitude|longitude|zip\s*code|postal\s*code|postcode|"
    r"price|cost|amount\s*due|total\s*due|vat\s*(?:no|id|number)|tax\s*id|ust-?id|siret|siren|iban|swift|bic|"
    r"account\s*no|registration\s*no|company\s*no|reg\.?\s*no|company\s*number|hrb)\b"
)
_PHONE_POSITIVE_CONTEXT_RE = re.compile(r"(?i)\b(tel|telephone|phone|mobile|call|fax|whatsapp|hotline|contact)\b")
_ENTITY_LABEL_RE = re.compile(
    r"(?im)^(?:.*?\b(?:company|registered name|legal name|operator|owner|publisher|provided by|trading as|responsible(?: for content)?)\b[^:\n]{0,30}:\s*)([^\n]{3,140})$"
)
# Word separators are spaces/tabs, never "\s" — "\s" matches newlines, so a
# company name at the end of one line was glued to the company on the next
# ("Beispiel Medien GmbH\nTaboola, Inc" became a single entity), fabricating
# names that belong to nobody and that no other site could ever match except
# one carrying the identical two lines.
#
# No "/" in the name character class either: with it, a URL path immediately
# before a name was swallowed into the match ("gb/privacy/privacy-policy/
# Twitter, Inc"), producing a selector that is partly someone else's link.
_ENTITY_SUFFIX_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9&.,'()\-]*(?:[ \t]+[A-Z][A-Za-z0-9&.,'()\-]*){0,8}[ \t]+"
    r"(?:LLC|L\.L\.C\.|Ltd|Limited|Inc\.?|Incorporated|Corp\.?|Corporation|Company|Co\.?|"
    r"GmbH|AG|S\.?A\.?R\.?L\.?|S\.?A\.?|SAS|BV|B\.V\.|NV|N\.V\.|AB|AS|Oy|Oyj|ApS|"
    r"Sp\.?[ \t]*z[ \t]*o\.?o\.?|s\.?r\.?o\.?|SRL|Srl|OÜ|UG|PLC|Pty Ltd|Pte Ltd|BVBA|CVBA|Kft|d\.?o\.?o\.?))\b"
)
_REGISTRATION_LINE_RE = re.compile(
    r"(?im)^.*\b(?:company|commercial|trade|business|merchant|enterprise|register|registration|registered|"
    r"chamber of commerce|vat|tax|gst|abn|uen|cvr|siren|siret|rcs|hrb|uid|ust-?id|cif|nif|bin|iin)\b.*$"
)
_VAT_TOKEN_RE = re.compile(r"\b([A-Z]{2}[ ]?[A-Z0-9][A-Z0-9 ./-]{5,18}[A-Z0-9])\b")
# Structured company/registration identifiers. We only accept tokens that look
# like an actual ID — bare numeric IDs (Companies House 8-digit, SIREN 9-digit,
# SIRET 14-digit), German HRB/HRA, and UK regional prefixes — never whole
# sentences that merely contain the word "registration".
_REG_ID_TOKEN_RE = re.compile(
    r"(?i)\b("
    r"HR[AB]\s*\d{1,7}"              # German commercial register (HRB / HRA)
    r"|(?:SC|OC|NI|SO|NL|FC|GE|RC)\d{6}"  # UK Companies House regional prefixes
    r"|\d{14}"                       # SIRET
    r"|\d{9,12}"                     # SIREN and other long numeric IDs
    r"|\d{8}"                        # Companies House / generic 8-digit
    r")\b"
)
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
    # Full header map + redirect chain, so a caller that needs to fingerprint
    # managed hosting or trace redirects does not have to re-fetch the page.
    # core.basic.get_live_probe used to make its own HEAD/GET for exactly this;
    # it now derives both from here, leaving one homepage fetch per scan.
    headers_map = {name: value for name, value in items}
    redirect_chain = []
    for hop in getattr(headers_or_response, "history", None) or []:
        try:
            redirect_chain.append({
                "url": str(getattr(hop, "url", "") or "") or None,
                "status": getattr(hop, "status_code", None),
                "location": (getattr(hop, "headers", None) or {}).get("Location"),
            })
        except Exception:
            continue
    return {
        "status_code": response_status,
        "url": response_url,
        "headers": headers_map,
        "redirect_chain": redirect_chain,
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
        self.microdata_telephone_values: list[str] = []
        self._ignoring = 0
        self._current_inline_script: list[str] | None = None
        self._telephone_itemprop_stack: list[str] = []
        self._telephone_itemprop_buffer: list[str] = []

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
        if "telephone" in attrs_dict.get("itemprop", "").lower().split():
            declared = attrs_dict.get("content") or attrs_dict.get("href")
            if declared:
                self.microdata_telephone_values.append(declared.strip())
            else:
                self._telephone_itemprop_stack.append(tag)
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
        if self._telephone_itemprop_stack and tag == self._telephone_itemprop_stack[-1]:
            self._telephone_itemprop_stack.pop()
            value = "".join(self._telephone_itemprop_buffer).strip()
            if value:
                self.microdata_telephone_values.append(value)
            self._telephone_itemprop_buffer = []

    def handle_data(self, data: str) -> None:
        if self.in_title and data:
            self.title_parts.append(data)
        if self._current_inline_script is not None and data:
            self._current_inline_script.append(data)
        if self._telephone_itemprop_stack and data:
            self._telephone_itemprop_buffer.append(data)


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


# ── Tracking-ID patterns ─────────────────────────────────────────────────────
# These run over the *whole* HTML document, so the boundary they use decides
# how much of the page can impersonate an analytics account.
#
# `\b` was the boundary here, and `\b` is happy to sit on a hyphen: in
# `LOGO-G-ABCDEF12.png` there is a word boundary between `-` and `G`, so the
# old pattern extracted `G-ABCDEF12` from an image filename. Likewise
# `class="col-G-123456"` and `srcset="hero-G-2X4K80.webp"`. A GA property is
# weighted 170 in utils/evidence_meta.py and sits in
# db/intel_db.py's _ACCOUNT_BOUND_TRACKING_SUBKINDS (500-domain denylist
# ceiling rather than 50), so two unrelated sites built from one theme that
# ships the same hashed asset name were being reported as sharing a Google
# Analytics account at "strong" confidence.
#
# `(?<![\w-])` / `(?![\w-])` additionally refuse a hyphen on either side, so an
# ID has to stand on its own rather than be a fragment of a longer token.
# GA4 measurement IDs are `G-` plus exactly 10 alphanumerics; pinning the
# length (rather than the old 6–12 window) is what rules out the short
# `col-G-123456`-shaped hits that survive the boundary on their own.
_ID_EDGE = r"(?<![\w-])"
_ID_END = r"(?![\w-])"
GA_PROPERTY_RE = re.compile(
    rf"{_ID_EDGE}(UA-\d{{4,12}}-\d{{1,3}}|G-[A-Z0-9]{{10}}|AW-[0-9]{{8,12}}){_ID_END}"
)
GTM_CONTAINER_RE = re.compile(rf"{_ID_EDGE}(GTM-[A-Z0-9]{{4,8}}){_ID_END}")


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
        "site_verifications": {},
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
        "phone_numbers": [],
        "crypto_wallets": {},
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

    ga = GA_PROPERTY_RE.findall(raw)
    gtm = GTM_CONTAINER_RE.findall(raw)
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

    for meta_key, platform in SOCIAL_HANDLE_META_KEYS.items():
        handle_value = _first(meta_tags.get(meta_key))
        if not handle_value:
            continue
        handle = handle_value.lstrip("@").strip()
        if not handle:
            continue
        social_handles.setdefault(platform, [])
        if handle not in social_handles[platform]:
            social_handles[platform].append(handle)

    site_verifications: dict[str, list[str]] = {}
    for meta_key, values in meta_tags.items():
        provider = SITE_VERIFICATION_META_KEYS.get(meta_key)
        if not provider:
            continue
        for value in values:
            site_verifications.setdefault(provider, [])
            if value not in site_verifications[provider]:
                site_verifications[provider].append(value)

    phone_numbers = _extract_homepage_phones(
        body_text=html_to_text(raw),
        anchor_urls=parser.anchor_urls,
        inline_scripts=parser.inline_scripts,
        meta_tags=meta_tags,
        microdata_values=parser.microdata_telephone_values,
    )
    crypto_wallets = _extract_crypto_wallets(
        html_doc=raw,
        body_text=html_to_text(raw),
        anchor_urls=parser.anchor_urls,
        meta_tags=meta_tags,
    )

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
            "site_verifications": site_verifications,
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
            "phone_numbers": phone_numbers,
            "crypto_wallets": crypto_wallets,
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
        # humans.txt is plain text — no anchors, no JSON-LD, no meta tags — so
        # the text sweep *is* the structured path here. Routed through
        # _extract_text_phones rather than the raw regex so it shares the one
        # normalizer with the homepage and legal-page extractors, which is what
        # makes a number found here comparable to the same number found there.
        "phones": _dedupe_preserve(_extract_text_phones(text)),
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


# Platforms, ad networks and infrastructure vendors named in the boilerplate of
# an enormous number of sites. Even on a genuine imprint these appear as the
# hoster, the analytics provider or the consent vendor, never as the operator —
# and because the same handful recur everywhere, admitting them produces
# selectors shared by thousands of unrelated domains.
_THIRD_PARTY_ENTITY_RE = re.compile(
    r"(?i)\b(?:google|alphabet|youtube|facebook|meta platforms?|instagram|whatsapp|apple|"
    r"microsoft|linkedin|amazon|aws|twitter|x corp|snap|tiktok|bytedance|yandex|"
    r"vkontakte|mail\.ru|telegram|cloudflare|akamai|fastly|oracle|addthis|adobe|"
    r"salesforce|hubspot|mailchimp|taboola|outbrain|criteo|pubmatic|openx|rubicon|"
    r"magnite|xandr|appnexus|casale|index exchange|sovrn|sharethrough|teads|smartclip|"
    r"yieldlab|simpli\.?fi|spot\.im|disqus|zendesk|intercom|stripe|paypal|shopify|"
    r"wordpress|automattic|wix|squarespace|hetzner|ovh|digitalocean|comscore|nielsen|"
    r"quantcast|matomo|hotjar|full circle studies|sourcepoint|usercentrics|cookiebot)\b"
)

# An imprint identifies the operator — one company, occasionally two (operator
# plus parent or publisher). Past a handful the extractor has stopped reading an
# imprint and started reading prose about other people's companies, so the tail
# is dropped rather than trusted.
_MAX_IDENTITY_VALUES = 3

# A postal address fits on an envelope. These bounds are what separate one from
# a paragraph that merely contains "Street" or "Floor".
_MAX_ADDRESS_LENGTH = 120
_MAX_ADDRESS_WORDS = 18


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
    kept = [e for e in entities if not _THIRD_PARTY_ENTITY_RE.search(e)]
    # Order is document order, so the survivors nearest the top of the imprint
    # are the ones kept — that is where the operator states itself.
    return kept[:_MAX_IDENTITY_VALUES]


def _normalize_vat(token: str) -> str | None:
    """Compact a VAT-shaped token, validating it actually looks like a VAT id."""
    compact = re.sub(r"[ ./-]", "", token).upper()
    if re.fullmatch(r"[A-Z]{2}[A-Z0-9]\d{6,12}", compact):
        return compact
    return None


def _extract_registration_ids(text: str) -> list[str]:
    """Pull structured company/registration identifiers from legal-page text.

    Only lines that mention a registration concept are inspected, and only
    structured ID tokens (not the surrounding prose) are kept — so a sentence
    like "voluntary registration for the services we offer" no longer becomes a
    spurious, decisive "shared registration ID" match.
    """
    hits: list[str] = []

    def _push(value: str) -> None:
        if value and value not in hits:
            hits.append(value)

    for line in _line_values(text):
        if not _REGISTRATION_LINE_RE.search(line):
            continue
        for match in _REG_ID_TOKEN_RE.finditer(line):
            _push(re.sub(r"\s+", " ", match.group(1)).strip().upper())
        for vat in _VAT_TOKEN_RE.findall(line):
            normalized = _normalize_vat(vat)
            if normalized:
                _push(normalized)
    return hits


_PHONE_GROUPING_RE = re.compile(r"[ ().\-/]")


def _filter_phones(matches: Sequence[str]) -> list[str]:
    """Phone-shaped runs scraped from free text, minus the ones that aren't.

    Free text is full of digit runs that are not phone numbers — order numbers,
    pixel and app ids, figures quoted in prose. A bare run with no country code
    and no grouping ("6789156", "155833707900388") is far more often one of
    those than a number, because a real published number is written to be
    dialled and so carries either a leading "+" or some separator. Requiring
    that is what stops an ad-network id in shared boilerplate from becoming a
    "shared phone number" linking every site that embeds the same widget.

    Numbers the page declares explicitly (tel:/callto: hrefs, JSON-LD
    `telephone`, meta phone tags) never reach here — they go through
    _normalize_declared_phone — so this rule costs nothing where intent is
    already unambiguous.
    """
    phones: list[str] = []
    for match in matches:
        cleaned = re.sub(r"\s+", " ", match).strip(" ,;")
        digits = re.sub(r"\D", "", cleaned)
        if not 7 <= len(digits) <= 15:
            continue
        if not cleaned.startswith("+") and not _PHONE_GROUPING_RE.search(cleaned):
            continue
        if cleaned not in phones:
            phones.append(cleaned)
    return phones


def _is_placeholder_phone_digits(digits: str) -> bool:
    """True for template/demo numbers that appear verbatim on unrelated sites.

    All-same-digit runs (0000000000), ascending/descending runs
    (1234567890, 9876543210 -- wraps at 9->0 so 0123456789 is caught too),
    and the NANP fictional 555-01xx exchange are never real subscriber
    numbers, so treating them as a shared selector would fabricate a
    same-operator link between any two sites that both ship the same
    placeholder markup.
    """
    if len(set(digits)) == 1:
        return True
    if len(digits) >= 4:
        ascending = all((int(digits[i + 1]) - int(digits[i])) % 10 == 1 for i in range(len(digits) - 1))
        descending = all((int(digits[i]) - int(digits[i + 1])) % 10 == 1 for i in range(len(digits) - 1))
        if ascending or descending:
            return True
    if _PHONE_FICTIONAL_555_RE.search(digits):
        return True
    if len(digits) == 13 and digits[:3] in ("978", "979"):
        return True  # ISBN-13 prefix, not a phone country code shape
    return False


def _normalize_phone(cleaned: str) -> str | None:
    """Collapse a phone-shaped string to a comparable, roughly-E.164 form.

    No `phonenumbers` dependency is available in this environment, so this is
    a conservative regex/heuristic normalizer rather than a validated one: it
    strips formatting and keeps a leading "+" (or converts a leading "00"
    international-dialing prefix to "+") so the same number written with
    different separators on two sites still compares equal.
    """
    if cleaned.startswith("+"):
        digits = re.sub(r"\D", "", cleaned)
        return f"+{digits}" if digits else None
    digits = re.sub(r"\D", "", cleaned)
    if not digits:
        return None
    if digits.startswith("00") and 10 <= len(digits) <= 15:
        rest = digits[2:]
        if 8 <= len(rest) <= 13:
            return f"+{rest}"
    return digits


def _normalize_declared_phone(raw: str) -> str | None:
    """Normalize a phone value from an explicit field (tel: href, JSON-LD
    `telephone`, meta tag, microdata) -- these carry their own context, so
    unlike free body text they don't need a separator/keyword check, only
    the placeholder/shape guards that apply everywhere.
    """
    cleaned = str(raw or "").strip()
    if not cleaned:
        return None
    cleaned = cleaned.split("?", 1)[0].split(";", 1)[0].strip()
    digits = re.sub(r"\D", "", cleaned)
    if not (7 <= len(digits) <= 15) or _is_placeholder_phone_digits(digits):
        return None
    return _normalize_phone(cleaned)


def normalize_contact_phone(value: Any) -> str | None:
    """Canonical match key for a phone number, for every layer that stores or
    compares one (identifiers table, correlation selectors, legacy pairwise).

    Kept here, next to the extractor, so there is one spelling of a number
    rather than one per layer: a second normalizer that skipped, say, the
    00->+ international-prefix rewrite would file "0044 20 …" and "+44 20 …"
    as two different selectors and silently miss the match between them.
    """
    return _normalize_declared_phone(str(value or ""))


# Bech32 (BIP-173) and CashAddr are defined as single-case encodings and
# Ethereum is plain hex -- EIP-55 only overlays a checksum onto the *case* of
# the hex digits -- so folding those canonicalizes two spellings of one
# address into one selector. Base58Check (legacy BTC/LTC/DOGE, TRON, XRP,
# Solana) and Monero's Base58 variant encode payload bytes in the case itself:
# folding them yields a string that no longer decodes to a valid address, which
# would put a value into the evidence that an analyst cannot check against a
# block explorer or cite in a report.
_BECH32_WALLET_PREFIXES = ("bc1", "tb1", "ltc1", "tltc1", "bcrt1", "bitcoincash:")


def normalize_crypto_address(chain: Any, value: Any) -> str | None:
    """Canonical match key for a wallet address on `chain`.

    Case-folds only the encodings where case carries no data (see above);
    every other address is preserved byte-for-byte.
    """
    text = str(value or "").strip().strip("\"'`")
    if not text:
        return None
    lowered = text.lower()
    if str(chain or "").strip().lower() == "ethereum" or lowered.startswith(_BECH32_WALLET_PREFIXES):
        return lowered
    return text


def _extract_href_phones(urls: Sequence[str]) -> list[str]:
    values: list[str] = []
    for url in urls:
        lowered = str(url or "").lower()
        for scheme in _PHONE_HREF_SCHEMES:
            if lowered.startswith(scheme):
                normalized = _normalize_declared_phone(url[len(scheme):])
                if normalized:
                    values.append(normalized)
                break
    return values


def _walk_jsonld_telephones(node: Any) -> Iterable[str]:
    if isinstance(node, Mapping):
        value = node.get("telephone")
        if isinstance(value, str) and value.strip():
            yield value.strip()
        for child in node.values():
            yield from _walk_jsonld_telephones(child)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_jsonld_telephones(item)


def _extract_jsonld_phones(inline_scripts: Sequence[str]) -> list[str]:
    values: list[str] = []
    for script_text in inline_scripts:
        text = script_text.strip()
        if not text or "telephone" not in text.lower():
            continue
        try:
            data = json.loads(text)
        except Exception:
            continue
        for raw in _walk_jsonld_telephones(data):
            normalized = _normalize_declared_phone(raw)
            if normalized:
                values.append(normalized)
    return values


def _extract_text_phones(text: str) -> list[str]:
    """Pull phone numbers out of visible body text.

    Unlike the declared-field sources (tel: links, JSON-LD, meta tags), free
    text has no field label telling us "this is a phone number" -- the same
    digit shape also matches dates, prices, order/SKU numbers, ISBNs, VAT and
    registration ids, and tracking numbers. So on top of the placeholder/shape
    guards, a bare digit run (no "+", no space/dash/dot/paren separators) is
    only accepted next to an explicit phone-intent word (tel/phone/call/...),
    and any match near an id/price/date-ish label is dropped outright.
    """
    values: list[str] = []
    for match in _PHONE_RE.finditer(text):
        raw = match.group(0)
        cleaned = raw.strip(" ,;.")
        digits = re.sub(r"\D", "", cleaned)
        if not (7 <= len(digits) <= 15) or _is_placeholder_phone_digits(digits):
            continue
        if _PHONE_DATE_SHAPE_RE.match(cleaned):
            continue
        window = text[max(0, match.start() - 40) : match.start()]
        if _PHONE_NEGATIVE_CONTEXT_RE.search(window):
            continue
        has_plus = cleaned.startswith("+")
        has_separator = bool(re.search(r"[\s().-]", cleaned))
        if not has_plus and not has_separator and not _PHONE_POSITIVE_CONTEXT_RE.search(window):
            continue
        normalized = _normalize_phone(cleaned)
        if normalized:
            values.append(normalized)
    return values


def _extract_homepage_phones(
    *, body_text: str, anchor_urls: Sequence[str], inline_scripts: Sequence[str], meta_tags: Mapping[str, Sequence[str]], microdata_values: Sequence[str]
) -> list[str]:
    phones: list[str] = []
    phones.extend(_extract_href_phones(anchor_urls))
    phones.extend(_extract_jsonld_phones(inline_scripts))
    for value in microdata_values:
        normalized = _normalize_declared_phone(value)
        if normalized:
            phones.append(normalized)
    for key in _PHONE_META_KEYS:
        for value in meta_tags.get(key) or []:
            normalized = _normalize_declared_phone(value)
            if normalized:
                phones.append(normalized)
    phones.extend(_extract_text_phones(body_text))
    return sorted(set(phones))


# A wallet address is scored as a correlation selector, so a single false
# positive invents a shared-operator link between two unrelated organisations.
# Every candidate below is therefore checksum-verified -- Base58Check,
# bech32/bech32m polymod, EIP-55, Keccak -- rather than shape-matched, and the
# patterns exist only to isolate runs of alphabet-legal characters for the
# validators to confirm or drop.
_CRYPTO_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# The same 58 characters in a different order: XRP is Base58Check over this
# alphabet, so an XRP address decodes to garbage under the standard one.
_CRYPTO_RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
_CRYPTO_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
# Base58Check version byte -> chain. 0x05 is both Bitcoin P2SH and Litecoin's
# legacy P2SH ("3..."), which are byte-identical, so it is keyed as bitcoin --
# the overwhelmingly more likely issuer. Bitcoin Cash legacy addresses share
# Bitcoin's version bytes too and are likewise keyed bitcoin; only CashAddr
# ("bitcoincash:q...") is attributable to bitcoin_cash.
_CRYPTO_BASE58_VERSIONS = {
    0x00: "bitcoin",
    0x05: "bitcoin",
    0x1E: "dogecoin",
    0x30: "litecoin",
    0x32: "litecoin",
    0x41: "tron",
}
# Testnet HRPs (tb1/tltc1) are deliberately absent: test coins carry no
# operator value and their addresses are pasted verbatim out of wallet docs.
_CRYPTO_BECH32_HRPS = {"bc": "bitcoin", "ltc": "litecoin"}
_CRYPTO_URI_SCHEMES = frozenset(
    {"bitcoin", "bitcoincash", "dogecoin", "ethereum", "litecoin", "monero", "ripple", "solana", "tron"}
)
_CRYPTO_SCAN_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9])0[xX][0-9a-fA-F]{40}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])(?:bc|ltc)1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{8,87}(?![A-Za-z0-9])", re.I),
    re.compile(r"(?<![A-Za-z0-9])bitcoincash:[qp][qpzry9x8gf2tvdw0s3jn54khce6mua7l]{41}(?![A-Za-z0-9])", re.I),
    re.compile(r"(?<![A-Za-z0-9])[48][1-9A-HJ-NP-Za-km-z]{94}(?:[1-9A-HJ-NP-Za-km-z]{11})?(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])[13LMDTr][1-9A-HJ-NP-Za-km-z]{24,39}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])[1-9A-HJ-NP-Za-km-z]{43,44}(?![A-Za-z0-9])"),
)
_CRYPTO_ETH_RE = re.compile(r"0[xX][0-9a-fA-F]{40}")
_CRYPTO_CASHADDR_RE = re.compile(r"(?:bitcoincash:)?[qp][qpzry9x8gf2tvdw0s3jn54khce6mua7l]{41}", re.I)
_CRYPTO_BECH32_RE = re.compile(r"(?:bc|ltc)1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{8,87}", re.I)
_CRYPTO_MONERO_RE = re.compile(r"[48][1-9A-HJ-NP-Za-km-z]{94}(?:[1-9A-HJ-NP-Za-km-z]{11})?")
_CRYPTO_SOLANA_RE = re.compile(r"[1-9A-HJ-NP-Za-km-z]{43,44}")
_CRYPTO_BASE58CHECK_RE = re.compile(r"[13LMDTr][1-9A-HJ-NP-Za-km-z]{24,39}")
_CRYPTO_ETH_CONTEXT_RE = re.compile(
    r"(?i)(\beth\b|\bether(?:eum)?\b|\berc-?20\b|\bbep-?20\b|\bbnb\b|\busdt\b|\busdc\b|\bmetamask\b|"
    r"\bwallet\b|\bdonat|\bcrypto|etherscan|bscscan|polygonscan|blockscout)"
)
_CRYPTO_SOL_CONTEXT_RE = re.compile(r"(?i)(\bsol\b|\bsolana\b|\bphantom\b|\bspl\b|\bwallet\b|\bdonat|solscan)")
# Burn/null sinks plus the canonical spec and documentation examples. These are
# quoted verbatim on thousands of unrelated pages (wallet tutorials, BIP text
# pasted into blog posts, token-contract boilerplate), so accepting one would
# link every site that mentions it -- the same false-link bug class as the
# social "share"/"reel" literals above. Compared lowercased.
_CRYPTO_NOISE = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dead",
    "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead",
    "1a1zp1ep5qgefi2dmptftl5slmv7divfna",
    "1bvbmseystwetqtfn5au4m4gfg7xjanvn2",
    "3j98t1wpez73cnmqviecrnyiwrnqrhwnly",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
    "t9yd14nj9j7xab4dbgeix9h8unkkhxuwwb",
    "rrrrrrrrrrrrrrrrrrrrrholvtp",
    "so11111111111111111111111111111111111111112",
    "tokenkegqfezyinwajbnbgkpfxcwubvf9ss623vq5da",
}
_KECCAK_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_KECCAK_ROTATIONS = (
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
)
_KECCAK_MASK = (1 << 64) - 1
_CRYPTO_MAX_CANDIDATES = 512
# Encoded block length -> decoded byte count for Monero's block-wise Base58.
_MONERO_BLOCK_SIZES = (0, 1, 2, 3, 3, 4, 4, 5, 6, 6, 7, 8)


def _keccak_f1600(lanes: list[int]) -> None:
    for round_constant in _KECCAK_ROUND_CONSTANTS:
        parity = [lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20] for x in range(5)]
        for x in range(5):
            neighbour = parity[(x + 1) % 5]
            column = parity[(x - 1) % 5] ^ (((neighbour << 1) | (neighbour >> 63)) & _KECCAK_MASK)
            for y in range(0, 25, 5):
                lanes[x + y] ^= column
        rotated = [0] * 25
        for x in range(5):
            for y in range(5):
                shift = _KECCAK_ROTATIONS[x + 5 * y]
                lane = lanes[x + 5 * y]
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = ((lane << shift) | (lane >> (64 - shift))) & _KECCAK_MASK
        for y in range(0, 25, 5):
            row = rotated[y:y + 5]
            for x in range(5):
                lanes[x + y] = row[x] ^ (~row[(x + 1) % 5] & row[(x + 2) % 5] & _KECCAK_MASK)
        lanes[0] ^= round_constant


def _keccak256(data: bytes) -> bytes:
    """Keccak-256 (the pre-NIST padding Ethereum and Monero use, not sha3_256)."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate:
        padded.append(0x00)
    padded[-1] ^= 0x80
    lanes = [0] * 25
    for offset in range(0, len(padded), rate):
        for index in range(rate // 8):
            start = offset + index * 8
            lanes[index] ^= int.from_bytes(padded[start:start + 8], "little")
        _keccak_f1600(lanes)
    return b"".join(lane.to_bytes(8, "little") for lane in lanes[:4])


def _base58_decode(value: str, alphabet: str = _CRYPTO_BASE58_ALPHABET) -> bytes | None:
    number = 0
    for char in value:
        digit = alphabet.find(char)
        if digit < 0:
            return None
        number = number * 58 + digit
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(value) - len(value.lstrip(alphabet[0]))) + body


def _base58check_payload(value: str, alphabet: str = _CRYPTO_BASE58_ALPHABET) -> bytes | None:
    decoded = _base58_decode(value, alphabet)
    if decoded is None or len(decoded) < 5:
        return None
    payload, checksum = decoded[:-4], decoded[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        return None
    return payload


def _bech32_polymod(values: list[int]) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index in range(5):
            if (top >> index) & 1:
                checksum ^= generator[index]
    return checksum


def _bech32_decode(address: str) -> tuple[str, list[int], int] | None:
    if len(address) > 90 or (address.lower() != address and address.upper() != address):
        return None
    address = address.lower()
    split = address.rfind("1")
    if split < 1 or split + 7 > len(address):
        return None
    data: list[int] = []
    for char in address[split + 1:]:
        position = _CRYPTO_BECH32_CHARSET.find(char)
        if position < 0:
            return None
        data.append(position)
    hrp = address[:split]
    constant = _bech32_polymod([ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data)
    if constant not in (1, 0x2BC830A3):
        return None
    return hrp, data[:-6], constant


def _bech32_witness_program(data: Sequence[int]) -> bytes | None:
    accumulator = 0
    bits = 0
    out = bytearray()
    for value in data:
        accumulator = (accumulator << 5) | value
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((accumulator >> bits) & 0xFF)
    if bits >= 5 or (accumulator << (8 - bits)) & 0xFF:
        return None
    return bytes(out)


def _cashaddr_checksum_ok(prefix: str, payload: str) -> bool:
    values = [ord(char) & 0x1F for char in prefix] + [0]
    for char in payload:
        position = _CRYPTO_BECH32_CHARSET.find(char)
        if position < 0:
            return False
        values.append(position)
    checksum = 1
    for value in values:
        top = checksum >> 35
        checksum = ((checksum & 0x07FFFFFFFF) << 5) ^ value
        for index, constant in enumerate((0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470)):
            if (top >> index) & 1:
                checksum ^= constant
    return checksum ^ 1 == 0


def _monero_base58_decode(value: str) -> bytes | None:
    out = bytearray()
    for offset in range(0, len(value), 11):
        chunk = value[offset:offset + 11]
        size = _MONERO_BLOCK_SIZES[len(chunk)]
        number = 0
        for char in chunk:
            digit = _CRYPTO_BASE58_ALPHABET.find(char)
            if digit < 0:
                return None
            number = number * 58 + digit
        if not size or number >> (8 * size):
            return None
        out.extend(number.to_bytes(size, "big"))
    return bytes(out)


def _eip55_checksum_ok(body: str) -> bool:
    digest = _keccak256(body.lower().encode()).hex()
    for index, char in enumerate(body):
        if char.isalpha() and char.isupper() != (int(digest[index], 16) >= 8):
            return False
    return True


def _classify_crypto_address(value: str, *, eth_context: bool, sol_context: bool) -> tuple[str, str] | None:
    if _CRYPTO_ETH_RE.fullmatch(value):
        body = value[2:]
        if body.lower() == body or body.upper() == body:
            # A single-case 40-hex string carries no checksum at all, and is
            # shape-identical to a git SHA fragment, a webpack/asset content
            # hash or a tracking id -- all rampant in page HTML and bundled JS.
            # Only take one where the page itself says it is a wallet: a
            # payment URI, or an explicit ETH/wallet/donate label beside it.
            if not eth_context:
                return None
        elif not _eip55_checksum_ok(body):
            return None
        # Stored lowercased so the same wallet displayed checksummed on one page
        # and lowercased on another is one selector rather than two.
        return "ethereum", value.lower()
    if _CRYPTO_CASHADDR_RE.fullmatch(value):
        payload = value.split(":", 1)[-1].lower()
        return ("bitcoin_cash", payload) if _cashaddr_checksum_ok("bitcoincash", payload) else None
    if _CRYPTO_BECH32_RE.fullmatch(value):
        decoded = _bech32_decode(value)
        if decoded is None:
            return None
        hrp, data, constant = decoded
        if not data:
            return None
        version = data[0]
        if version > 16 or constant != (1 if version == 0 else 0x2BC830A3):
            return None
        program = _bech32_witness_program(data[1:])
        if program is None or not 2 <= len(program) <= 40:
            return None
        if version == 0 and len(program) not in (20, 32):
            return None
        chain = _CRYPTO_BECH32_HRPS.get(hrp)
        return (chain, value.lower()) if chain else None
    if _CRYPTO_MONERO_RE.fullmatch(value):
        decoded = _monero_base58_decode(value)
        if decoded is None or len(decoded) not in (69, 77) or decoded[0] not in (18, 19, 42):
            return None
        return ("monero", value) if _keccak256(decoded[:-4])[:4] == decoded[-4:] else None
    if _CRYPTO_SOLANA_RE.fullmatch(value):
        # Solana addresses are a bare base58 ed25519 key with no checksum
        # whatsoever, so any 43/44-char base58 run -- minified JS identifiers,
        # asset digests, session tokens -- has the same shape. The 32-byte
        # decode alone rejects far too little, so an explicit SOL/wallet label
        # or a solana: URI is required as well.
        if not sol_context:
            return None
        decoded = _base58_decode(value)
        return ("solana", value) if decoded is not None and len(decoded) == 32 else None
    if _CRYPTO_BASE58CHECK_RE.fullmatch(value):
        payload = _base58check_payload(value)
        if payload is not None and len(payload) == 21:
            chain = _CRYPTO_BASE58_VERSIONS.get(payload[0])
            if chain:
                return chain, value
        if value.startswith("r"):
            payload = _base58check_payload(value, _CRYPTO_RIPPLE_ALPHABET)
            if payload is not None and len(payload) == 21 and payload[0] == 0x00:
                return "ripple", value
    return None


def _identify_crypto_address(value: str, *, eth_context: bool = False, sol_context: bool = False) -> tuple[str, str] | None:
    identified = _classify_crypto_address(value, eth_context=eth_context, sol_context=sol_context)
    if identified is None or identified[1].lower() in _CRYPTO_NOISE:
        return None
    return identified


def _crypto_uri_address(href: str) -> str | None:
    """Pull the payee out of a BIP-21 style payment URI (bitcoin:<addr>?amount=...)."""
    scheme, separator, rest = str(href or "").partition(":")
    if not separator or scheme.lower() not in _CRYPTO_URI_SCHEMES:
        return None
    address = rest.split("?", 1)[0].split("@", 1)[0].split("/", 1)[0].strip()
    if address[:4].lower() == "pay-":
        address = address[4:]
    return address or None


def _scan_crypto_text(text: str, found: dict[str, set[str]], cache: dict[tuple[str, bool, bool], Any]) -> None:
    if not text:
        return
    for pattern in _CRYPTO_SCAN_PATTERNS:
        for match in pattern.finditer(text):
            if len(cache) >= _CRYPTO_MAX_CANDIDATES:
                return
            # Deliberately tight: a label sits right against the address it
            # names ("ETH: 0x..", "0x.. (ETH)"), so a wider window mostly buys
            # leakage from the neighbouring line -- which is how a build hash
            # printed under a donation block gets mistaken for a wallet.
            window = text[max(0, match.start() - 40) : match.start()] + " " + text[match.end() : match.end() + 20]
            key = (
                match.group(0),
                bool(_CRYPTO_ETH_CONTEXT_RE.search(window)),
                bool(_CRYPTO_SOL_CONTEXT_RE.search(window)),
            )
            if key not in cache:
                cache[key] = _identify_crypto_address(key[0], eth_context=key[1], sol_context=key[2])
            identified = cache[key]
            if identified:
                found.setdefault(identified[0], set()).add(identified[1])


def _extract_crypto_wallets(
    *, html_doc: str, body_text: str, anchor_urls: Sequence[str], meta_tags: Mapping[str, Sequence[str]]
) -> dict[str, list[str]]:
    found: dict[str, set[str]] = {}
    # Validation is pure-Python Keccak/Base58 arithmetic, so a page repeating a
    # candidate thousands of times would otherwise pay for it every occurrence.
    cache: dict[tuple[str, bool, bool], Any] = {}
    for href in anchor_urls:
        declared = _crypto_uri_address(str(href or ""))
        # A payment URI is itself the label the context gates look for.
        identified = _identify_crypto_address(declared, eth_context=True, sol_context=True) if declared else None
        if identified:
            found.setdefault(identified[0], set()).add(identified[1])
    _scan_crypto_text(body_text, found, cache)
    _scan_crypto_text(html_doc, found, cache)
    for url in anchor_urls:
        _scan_crypto_text(str(url or ""), found, cache)
    for key, values in meta_tags.items():
        for value in values:
            # Scanned with the meta name attached: on a declared field the key
            # ("eth-wallet", "donation:xmr") is the label the context gates want.
            _scan_crypto_text(f"{key} {value}", found, cache)
    return {chain: sorted(addresses) for chain, addresses in sorted(found.items())}


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
        if not cleaned or cleaned in addresses:
            continue
        # A street word inside a sentence is not an address. Consent boilerplate
        # is full of them ("...das Kommentarsystem Disqus (Disqus, Inc., 717
        # Market Street, ...) verwenden, um..."), and the whole paragraph was
        # being filed as one address. A real postal address is short.
        if len(cleaned) > _MAX_ADDRESS_LENGTH or len(cleaned.split()) > _MAX_ADDRESS_WORDS:
            continue
        if _THIRD_PARTY_ENTITY_RE.search(cleaned):
            continue
        addresses.append(cleaned)
    return addresses[:_MAX_IDENTITY_VALUES]


# Paths whose whole purpose is to say who runs the site. A privacy policy or
# terms page is deliberately NOT in this set: by construction it enumerates
# *other* companies — every ad network, analytics vendor, CDN and comment
# widget the site embeds, each with its postal address — so mining one for "the
# operator's legal entity and address" harvests Google, Meta, Apple and two
# dozen adtech firms instead of the operator. Because every site running the
# same consent boilerplate yields the same names, those landed as mid-degree
# selectors (~45 domains each) and linked whole unrelated populations together.
_IDENTITY_PATH_RE = re.compile(
    r"(?i)(impressum|imprint|legal[-_]?notices?|mentions[-_]?legales|aviso[-_]?legal|"
    r"kontakt|contact|about|ueber[-_]?uns|über[-_]?uns|company|legal)"
)
# Checked first: a path can match both (/legal/privacy-policy), and when it does
# the privacy half is what decides.
_PRIVACY_TERMS_PATH_RE = re.compile(
    r"(?i)(privacy|datenschutz|terms|tos\b|agb\b|cookie|gdpr|dsgvo)"
)


def _is_operator_identity_page(page_url: str | None) -> bool:
    """Whether this page is meant to state who operates the site.

    Applied to the URL *after* redirects, so a /legal that lands on
    /privacy-policy is judged on where it ended up.
    """
    if not page_url:
        return False
    path = urlparse(str(page_url)).path or "/"
    if _PRIVACY_TERMS_PATH_RE.search(path):
        return False
    return bool(_IDENTITY_PATH_RE.search(path))


def _extract_legal_page_phones(html_doc: str, text: str, page_meta: Mapping[str, Any]) -> list[str]:
    """Phones from a legal/contact page, structured-first.

    Same extractor the homepage uses: `tel:` hrefs, JSON-LD telephone fields,
    microdata and phone meta tags, then a plain-text regex sweep as the
    fallback. This path used to be the bare regex alone, which was weakest on
    exactly the pages most likely to mark contact details up — `/contact` and
    `/about` are both in LEGAL_PAGE_PATHS, and a `tel:` href normalizes
    reliably where rendered text ("+44 (0)20 7…") often does not.

    The three structured inputs live on the parser rather than in
    parse_homepage_html's return, so the document is re-parsed here instead of
    widening that return value: `inline_scripts` holds every inline script body,
    and parse_homepage_html's output is persisted as page_metadata, so exposing
    them there would add the full script text of every page to stored payloads.
    Falls back to the text sweep alone if the re-parse fails.
    """
    try:
        parser = _HTMLSignalParser()
        parser.feed(html_doc or "")
        parser.close()
    except Exception:
        return _filter_phones(_PHONE_RE.findall(text))
    return _extract_homepage_phones(
        body_text=text,
        anchor_urls=parser.anchor_urls,
        inline_scripts=parser.inline_scripts,
        meta_tags=page_meta.get("meta_tags") or {},
        microdata_values=parser.microdata_telephone_values,
    )


def extract_legal_page_signals(html_doc: str, *, page_url: str | None = None) -> dict[str, Any]:
    text = html_to_text(html_doc, preserve_lines=True)
    page_meta = parse_homepage_html(html_doc, page_url=page_url)
    # Phones, emails and the text hash are collected from every legal page: a
    # contact address on a privacy policy is usually still the operator's (a
    # DPO or abuse mailbox), and the hash describes the page itself. Only the
    # identity fields are restricted, because only they are corrupted by a page
    # that talks about other companies.
    identity_page = _is_operator_identity_page(page_url)
    return {
        "url": page_url,
        "title": page_meta.get("title"),
        "normalized_text_hash": normalized_text_hash(text),
        "operator_identity_page": identity_page,
        "entity_names": _extract_entity_names(text) if identity_page else [],
        "registration_ids": _extract_registration_ids(text) if identity_page else [],
        "addresses": _extract_addresses(text) if identity_page else [],
        "phones": _extract_legal_page_phones(html_doc, text, page_meta),
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
                    # Transient: lets core.basic run its CMS heuristics over the
                    # markup this fetch already downloaded, instead of
                    # get_live_probe issuing a second request for the first 32KB.
                    # Stripped before the payload is persisted — see
                    # core.basic.get_page_metadata.
                    "body_prefix": (body or "")[:32768],
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
    # Fan every (name, path) attempt out at once, then regroup by name — one
    # timeout wall for the whole fetcher instead of one per path.
    jobs = [
        (name, path)
        for name, paths in WELL_KNOWN_PATHS.items()
        for path in paths
    ]
    attempts = _run_probes_concurrent(
        [lambda name=name, path=path: _well_known_attempt_sync(root_url, path, client, timeout=timeout)
         for name, path in jobs]
    )
    grouped: dict[str, list[dict[str, Any]]] = {name: [] for name in WELL_KNOWN_PATHS}
    for (name, _path), attempt in zip(jobs, attempts):
        grouped[name].append(attempt)
    return {name: _select_well_known_result(name, grouped[name]) for name in WELL_KNOWN_PATHS}


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
    entity_names: list[str] = []
    registration_ids: list[str] = []
    addresses: list[str] = []
    phones: list[str] = []
    emails: list[str] = []

    def _fetch_one(path: str) -> dict[str, Any]:
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
            return {
                "path": path,
                "requested_url": url,
                "url": str(response.url),
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type"),
                "error": None,
                **parsed,
            }
        except Exception as exc:
            return {
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

    # Fetch all candidate paths concurrently (was sequential: N paths x timeout).
    normalized_paths = [
        raw_path if raw_path.startswith("/") else f"/{raw_path}"
        for raw_path in _dedupe_preserve(str(path).strip() for path in paths if str(path).strip())
    ]
    pages = _run_probes_concurrent([lambda p=p: _fetch_one(p) for p in normalized_paths])
    for entry in pages:
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

    # These probe autodiscover.<domain> / autoconfig.<domain> hosts that usually
    # don't exist and hang until timeout, so fetching them concurrently (rather
    # than one-after-another) is the biggest single win for the parity phase.
    jobs = [
        (kind, probe)
        for kind, entries in probes.items()
        for probe in entries
        if probe.get("url")
    ]

    def _probe_one(kind: str, probe: dict[str, Any]) -> dict[str, Any]:
        url = probe.get("url")
        try:
            response = client.get(url, headers=DEFAULT_HEADERS, timeout=timeout, follow_redirects=True)
            body = response.content
            parsed = parse_autodiscover_xml(body) if kind == "autodiscover" else parse_autoconfig_xml(body)
            return {
                "label": probe["label"],
                "url": str(response.url),
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type"),
                "parsed": parsed,
                "error": None,
            }
        except Exception as exc:
            return {
                "label": probe["label"],
                "url": url,
                "status_code": None,
                "content_type": None,
                "parsed": {},
                "error": str(exc),
            }

    entries = _run_probes_concurrent(
        [lambda kind=kind, probe=probe: _probe_one(kind, probe) for kind, probe in jobs]
    )
    for (kind, _probe), entry in zip(jobs, entries):
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


# ── The page_metadata vocabulary ─────────────────────────────────────────────
# Three collectors historically produced page metadata under three spellings of
# the same values — `parse_homepage_html` (this module), `fetch_page_metadata`
# (the sync/case pipeline) and `core.ip_intel._process_page_html` (the async
# pipeline) — while every *consumer* reads exactly one spelling each:
# db/intel_db.py wants `favicon_mmh3`, utils/pairwise.py wants
# `favicon_murmurhash3`, and both want `adsense_publisher_ids`, which the sync
# collector emitted as `adsense_ids`. The mismatch is silent: a renamed key
# reads as "this domain has no AdSense publisher ID" rather than as an error,
# so the highest-weighted tracking signal in utils/evidence_meta.py (190.0)
# simply never reached the graph on the case pipeline.
#
# Rather than teach each consumer every spelling, page metadata passes through
# here once, on the way out of every collector. Aliases are *added*, never
# renamed away, because stored payloads and both engines' historical rows use
# the older keys and must keep resolving.
_PAGE_METADATA_ALIASES: tuple[tuple[str, str], ...] = (
    # (source key as some collector emits it, canonical key consumers read)
    ("adsense_ids", "adsense_publisher_ids"),
    ("rel_me_links", "rel_me"),
    # `homepage_text_hash` is the canonical spelling: the value is a sha256 of
    # the *normalized extracted text* (scripts/styles/comments stripped,
    # whitespace collapsed — see html_text_hash), and calling it
    # `homepage_html_hash` invited exactly one dangerous misreading, that it
    # could be matched against Censys' `web.endpoints.http.body_hash_sha256`,
    # which hashes the raw HTTP body. It cannot; see the warning in
    # sources/censys_discovery.py where that selector is deliberately left
    # unfed. Mirrored in both directions rather than renamed away, because
    # `homepage_html_hash` is what stored payloads, the db identifier id_type
    # and the graph's `html_hash` observations all use — those keep their
    # spelling so graph history is not split in two.
    ("homepage_text_hash", "homepage_html_hash"),
    ("homepage_html_hash", "homepage_text_hash"),
    # Deliberately NOT aliased: `script_assets` is a list of {url, host, type}
    # records in this module and a flat list of URLs in core/ip_intel.py.
    # Aliasing them would hide which shape a payload carries — and note
    # `_script_urls_from_input` does NOT transparently accept both: given a
    # mapping it reads `script_urls` first and its `script_assets` branch
    # requires record items, so hand it the whole page_metadata mapping (which
    # carries `script_urls`) rather than a bare `script_assets` list.
    # Two live spellings of the favicon murmurhash, both actively read; mirror
    # in both directions so a payload from either collector satisfies both.
    ("favicon_murmurhash3", "favicon_mmh3"),
    ("favicon_mmh3", "favicon_murmurhash3"),
)

# Keys every consumer iterates. `parse_homepage_html` returns the meta-tag
# derived ones as scalars (there is only ever one `fb:app_id` on a page), which
# made `core.analysis_service._identifiers` iterate the *string* and emit one
# identifier per character — so any two sites carrying a Twitter handle shared
# the selectors "a", "e", "o"... Normalizing to lists here removes the whole
# class of bug rather than guarding at each of the several read sites.
_PAGE_METADATA_LIST_KEYS: tuple[str, ...] = (
    "fb_app_id",
    "twitter_site",
    "twitter_creator",
    "authors",
    "rel_me",
    "adsense_publisher_ids",
    "phone_numbers",
)


def canonicalize_page_metadata(meta: Mapping[str, Any] | None) -> dict[str, Any]:
    """Normalize one collector's page metadata into the vocabulary consumers read.

    Idempotent and non-destructive: safe to apply to a freshly scraped payload,
    to a payload already canonicalized, or to one loaded back out of storage
    (db/intel_db.py applies it on the rebuild path so historical searches gain
    the canonical keys without a rescan).
    """
    if not isinstance(meta, Mapping):
        return {}
    out: dict[str, Any] = dict(meta)

    for source_key, canonical_key in _PAGE_METADATA_ALIASES:
        value = out.get(source_key)
        if value in (None, "", [], {}):
            continue
        if out.get(canonical_key) in (None, "", [], {}):
            out[canonical_key] = value

    # AdSense publisher IDs reach us in two spellings — the `ca-pub-<digits>`
    # literal in an AdSense snippet, and the bare `pub-<digits>` used in script
    # URLs and in ads.txt. One collector stripped the prefix and one did not, so
    # the two engines stored values that could never join. The bare form wins:
    # it is what `parse_ads_txt` already yields for `ads_txt_publishers`, so
    # canonicalizing here lets a homepage AdSense tag and an ads.txt entry
    # recognise each other as the same publisher account.
    adsense = out.get("adsense_publisher_ids")
    if adsense:
        normalized: list[str] = []
        for item in adsense if isinstance(adsense, (list, tuple, set)) else [adsense]:
            text = str(item or "").strip().lower()
            if text.startswith("ca-"):
                text = text[3:]
            if text and text not in normalized:
                normalized.append(text)
        out["adsense_publisher_ids"] = normalized

    for key in _PAGE_METADATA_LIST_KEYS:
        value = out.get(key)
        if value in (None, "", [], {}):
            # Assign, don't setdefault: parse_homepage_html emits these as None,
            # and setdefault is a no-op when the key already exists, so the
            # list-guarantee this function documents was silently not held.
            out[key] = []
            continue
        if not isinstance(value, (list, tuple, set)):
            out[key] = [value]
        else:
            out[key] = list(value)

    return out


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
        "site_verifications": {},
        "phone_numbers": [],
        "crypto_wallets": {},
        "favicon_md5": None,
        "favicon_murmurhash3": None,
        "favicon_saved": None,
        "error": homepage.get("error"),
        "http_fingerprint": homepage.get("http_fingerprint"),
        "final_url": homepage.get("url"),
        "status_code": homepage.get("status_code"),
        # Underscore-prefixed to mark it transient: core.basic.get_page_metadata
        # pops it after deriving the CMS so 32KB of markup per scan never
        # reaches the stored payload.
        "_html_prefix": homepage.get("body_prefix") or "",
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
        # `hash_favicon_bytes` has always computed this; nothing surfaced it, so
        # sources/censys_discovery.py's `favicon_sha256` selector could never
        # fire. It is the exact-match favicon pivot that avoids the mmh3
        # base64 construction entirely, so it is worth the one line.
        result["favicon_sha256"] = first_icon.get("sha256")
        if save_favicon_as is not None and first_icon.get("content"):
            save_favicon_as.write_bytes(first_icon["content"])
            result["favicon_saved"] = str(save_favicon_as)
    return canonicalize_page_metadata(result)


def extract_page_enrichment(html_doc: str, *, base_url: str | None = None) -> dict[str, Any]:
    parsed = parse_homepage_html(html_doc, page_url=base_url)
    # Both spellings reach this point: the `ca-pub-…` literal from
    # parse_homepage_html and a bare `pub-…` scraped from script URLs.
    # canonicalize_page_metadata folds them to the bare form, so emit as found
    # and let the one normalizer decide — the other collector kept `ca-pub-…`,
    # which is what made the two engines' publisher IDs unjoinable.
    adsense_ids = sorted(
        {
            *(parsed.get("adsense_ids") or []),
            *re.findall(r"\b(pub-\d{10,20})\b", str(html_doc or ""), re.I),
        }
    )
    enrichment = {
        "adsense_publisher_ids": _dedupe_preserve(adsense_ids),
        "fb_app_id": [parsed["fb_app_id"]] if parsed.get("fb_app_id") else [],
        "twitter_site": [parsed["twitter_site"]] if parsed.get("twitter_site") else [],
        "twitter_creator": [parsed["twitter_creator"]] if parsed.get("twitter_creator") else [],
        "authors": parsed.get("authors") or [],
        "rel_me": parsed.get("rel_me_links") or [],
        # Emit the canonical spelling; canonicalize_page_metadata mirrors it to
        # `homepage_html_hash` for the stored-payload and graph consumers.
        "homepage_text_hash": parsed.get("homepage_text_hash"),
        "phone_numbers": parsed.get("phone_numbers") or [],
        "crypto_wallets": parsed.get("crypto_wallets") or {},
        "meta_tags": parsed.get("meta_tags") or {},
        "script_assets": parsed.get("script_urls") or [],
        "bundler_hints": _dedupe_preserve(
            (parsed.get("inline_bundlers") or [])
            + [item.get("type") for item in parsed.get("script_assets") or [] if isinstance(item, Mapping) and item.get("type")]
        ),
    }
    return canonicalize_page_metadata(enrichment)


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
            "site_verifications": page_metadata.get("site_verifications") or {},
            "phone_numbers": page_metadata.get("phone_numbers") or [],
            "crypto_wallets": page_metadata.get("crypto_wallets") or {},
            "adsense_publisher_ids": [value[3:] if value.startswith("ca-") else value for value in (page_metadata.get("adsense_ids") or [])],
            "fb_app_id": [page_metadata["fb_app_id"]] if page_metadata.get("fb_app_id") else [],
            "twitter_site": [page_metadata["twitter_site"]] if page_metadata.get("twitter_site") else [],
            "twitter_creator": [page_metadata["twitter_creator"]] if page_metadata.get("twitter_creator") else [],
            "authors": page_metadata.get("authors") or [],
            "rel_me": page_metadata.get("rel_me_links") or [],
            # Canonical spelling; mirrored to homepage_html_hash on the way out.
            "homepage_text_hash": page_metadata.get("homepage_text_hash"),
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
        result["favicon_sha256"] = first.get("sha256")
        if save_favicon_as is not None and first.get("content"):
            save_favicon_as.write_bytes(first["content"])
            result["favicon_saved"] = str(save_favicon_as)
    else:
        result["favicon_md5"] = None
        result["favicon_mmh3"] = None
        result["favicon_sha256"] = None
        result["favicon_saved"] = None
    return canonicalize_page_metadata(result)


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


async def ascrape_legal_pages(domain: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """Legal-page identity signals, in the one shape every consumer reads.

    This used to re-key each page into a private vocabulary (`entities`,
    `postal_addresses`, `phone_numbers`, `text_hash`) and return a bare list.
    Two things were wrong with that. The re-keying read fields
    `extract_legal_page_signals` does not emit — it produces `entity_names` and
    `normalized_text_hash` — so `entities` and `text_hash` were *always* empty,
    silently. And returning a list dropped the aggregates, so the
    `legal_pages.entity_names` / `.phones` / `.registration_ids` paths that
    utils/pairwise.py weights at 18/34/35 could never match on this engine.
    Both engines now return `async_scrape_legal_pages`' dict unchanged:
    `{pages, entity_names, registration_ids, addresses, phones, emails}`, which
    is what core.analysis_service._compact_legal_pages and db/intel_db.py's
    both-shapes reader already expect.
    """
    return await async_scrape_legal_pages(domain, client=client)


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
