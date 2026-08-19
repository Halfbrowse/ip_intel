#!/usr/bin/env python3
"""Global correlation-graph linkage scoring.

Scores linkage over the derived attribution graph (``db.intel_db``
entities/selectors/observations/entity_edges): two registrable domains link
when they share an attributing selector or a non-noise shared IP anywhere in
the lake — including transitively through subdomains and IPs. Each shared node
is scored ``base_weight x rarity(degree) x time_overlap`` and every link carries
its evidence breakdown (the deliverable, never a bare score).

The older pairwise scan-to-scan comparison engine (``compare_pair`` /
``find_matches`` / ``MATCH_WEIGHTS``, used only by ``core/basic.py``'s CLI
batch/dive mode) now lives in ``utils/pairwise.py`` — it imports the two shared
helpers (``confidence_from_score``, ``_is_cloudflare_ip_local``) from here.
"""

import ipaddress
import math
import re
from datetime import datetime, timezone
from functools import lru_cache

from utils.evidence_meta import selector_base_weight  # leaf module — no import cycle


# Cloudflare's anycast IP ranges. Two domains "sharing" a Cloudflare IP tells
# you only that both use Cloudflare; millions of sites do. Filter these out
# of list intersections so they never appear as shared-infrastructure matches.
_CF_IPV4 = [
    "173.245.48.0/20",  "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18",  "108.162.192.0/18","190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15",  "104.16.0.0/13",
    "104.24.0.0/14",    "172.64.0.0/13",   "131.0.72.0/22",
]
_CF_IPV6 = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]
# Parse the CIDRs once at import rather than rebuilding 22 ip_network objects on
# every call — this runs per shared IP in describe_ip_network, across the whole
# lake, during each cluster rebuild.
_CF_NETWORKS_V4 = [ipaddress.ip_network(n) for n in _CF_IPV4]
_CF_NETWORKS_V6 = [ipaddress.ip_network(n) for n in _CF_IPV6]


def _is_cloudflare_ip_local(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    nets = _CF_NETWORKS_V4 if addr.version == 4 else _CF_NETWORKS_V6
    return any(addr in net for net in nets)


# Documented default frontend IPs for platforms that assign a shared IP
# straight from an ASN/RDAP lookup, so they never fingerprint via
# _CDN_NETWORK_PATTERNS or a recognized reverse-proxy when a scan didn't
# capture PTR/ASN data. Firebase Hosting's pair is what Google tells every
# customer to point an apex/custom domain at when they skip the CNAME setup
# (firebase.google.com/docs/hosting/custom-domain) — every such site resolves
# here, so sharing it says nothing about who controls the site, same as
# Cloudflare's anycast ranges above.
_KNOWN_SHARED_INFRA_IPS = {
    "199.36.158.100",  # Firebase Hosting
    "199.36.158.101",  # Firebase Hosting
}


def _is_known_shared_infra_ip(ip: str) -> bool:
    return ip in _KNOWN_SHARED_INFRA_IPS


# Email domains belonging to registrars, hosting providers, and privacy
# proxies. A WHOIS / imprint / security.txt contact at one of these is a
# provider role address (abuse@godaddy.com, hostmaster@cloudflare.com) — it
# identifies the provider, not the site's operator. Two domains "sharing"
# abuse@godaddy.com share a registrar and nothing else, so this is the email
# equivalent of a shared Cloudflare IP and must never stand as an identity
# match.
_GENERIC_EMAIL_DOMAINS = (
    "godaddy.com", "secureserver.net", "namecheap.com", "namecheaphosting.com",
    "cloudflare.com", "domainsbyproxy.com", "whoisguard.com",
    "withheldforprivacy.com", "withheldforprivacy.email", "privacyguardian.org",
    "contactprivacy.com", "privacyprotect.org", "gandi.net", "ovh.net",
    "ionos.com", "1and1.com", "hostgator.com", "bluehost.com", "googledomains.com",
    "markmonitor.com", "cscglobal.com", "tucows.com", "enom.com", "enomdomains.com",
    "publicdomainregistry.com", "wildwestdomains.com", "porkbun.com", "dynadot.com",
    "name.com", "networksolutions.com", "register.com", "fastdomain.com",
    "key-systems.net", "1api.net", "hostinger.com", "squarespace.com",
    # ccTLD registrars and their privacy services, which the Western-centric
    # list above missed entirely — nic.ru's role address alone was attached to
    # 120 domains in one pool.
    "nic.ru", "whoisproxy.ru", "reg.ru", "r01.ru", "salenames.ru", "webnames.ru",
    "internet.bs", "openprovider.com", "hosting.ua", "ukraine.com.ua",
)

# Structural backstop for the same class of address. Enumerating registrars is
# a treadmill — there is always another national registrar or privacy service —
# but they name themselves: a mail domain advertising whois/privacy/proxy/
# protection is offering to stand in for the owner, which is precisely what
# makes the address useless as an identity signal.
_PRIVACY_PROXY_DOMAIN_RE = re.compile(
    r"(?i)(whois|privacy|privat|proxy|protect|redact|anonymous|withheld|hidden|"
    r"contactfilter|domaindiscreet)"
)


def _is_generic_email(text: str) -> bool:
    """True for registrar/provider/privacy-proxy emails (not owner identity)."""
    if "@" not in text:
        return False
    domain = text.rpartition("@")[2].strip().lower()
    if any(domain == d or domain.endswith("." + d) for d in _GENERIC_EMAIL_DOMAINS):
        return True
    return bool(_PRIVACY_PROXY_DOMAIN_RE.search(domain))


def confidence_from_score(score: int | float) -> int:
    """
    Map an open-ended evidence score onto a bounded 0–100 confidence.

    Raw scores are additive weights with no upper bound (a pair sharing a
    TLS fingerprint plus IPs plus trackers can exceed 300), so showing the
    raw number as a percentage was meaningless. The saturating curve keeps
    ordering and never reaches 100 (this is correlation, not proof). A single
    fresh, rare decisive-kind match (TLS cert / near-identity tracking ID,
    weight ~170-200 — see SELECTOR_BASE_WEIGHTS) now lands in the ~72-75%
    band on its own; corroborated multi-signal pairs climb into the 85-90%+
    band.
    """
    s = max(0, float(score or 0))
    return int(round(100 * s / (s + 65)))


# ── Global graph linkage (selector-centric attribution) ─────────────────────
#
# The legacy pairwise engine (utils/pairwise.py) compares two scan payloads
# field-by-field. The functions below instead score linkage over the *global*
# correlation graph
# (db.intel_db entities/selectors/observations/entity_edges): two registrable
# domains link when they share an attributing selector or a shared IP, anywhere
# in the lake — including transitively through subdomains and IPs. Each shared
# node is scored by base_weight × rarity(degree) × time-overlap, and every link
# carries the evidence breakdown (the deliverable, never a bare score).
#
# These read only the derived graph, so they are case-free and identical for the
# apex-to-apex and transitive-subdomain cases (the graph already resolved both).

_RARITY_FLOOR = 0.04
_OVERLAP_FLOOR = 0.25
_RECENCY_FLOOR = 0.3
# A shared node last seen within this window is still clearly live
# infrastructure and gets no age penalty at all.
_RECENCY_FULL_CREDIT_DAYS = 180
# IPs shared by more registrable domains than this are shared infrastructure
# (CDN/cloud pools) and contribute nothing even before the denylist applies.
_IP_NOISE_DEGREE = 50
# Selector kinds strong enough to call a link "strong" on their own.
_DECISIVE_SELECTOR_KINDS = {"tls_cert_sha256", "ssh_fp", "shared_ip", "tracking_id"}


def rarity_weight(degree: int | None) -> float:
    """Inverse-frequency factor keyed on a node's global degree.

    A selector/IP shared by just two entities scores 1.0; the weight decays
    toward a floor as it becomes common, so a cert shared by 2 is huge while a
    nameserver/ASN shared by 40,000 is ~noise — without any manual list.
    """
    d = int(degree or 0)
    if d < 2:
        return 1.0
    return max(_RARITY_FLOOR, 1.0 / math.log2(d))


@lru_cache(maxsize=8192)
def _parse_dt(value) -> datetime | None:
    # Cached: the same handful of ISO timestamps recur across every shared node
    # of a domain (each row parses a_first/a_last/b_first/b_last), and datetimes
    # are immutable so sharing a cached instance is safe.
    text = str(value or "").strip()
    if not text:
        return None
    text = text.replace("Z", "+00:00")
    for candidate in (text, text[:19], text[:10]):
        try:
            dt = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return None


def time_overlap_factor(a_first, a_last, b_first, b_last) -> float:
    """1.0 when the two observation windows intersect, decaying with the gap.

    Shared infra served in the same month scores full; the same selector seen
    years apart is attenuated toward a floor. Unknown windows get full credit.
    """
    af, al, bf, bl = _parse_dt(a_first), _parse_dt(a_last), _parse_dt(b_first), _parse_dt(b_last)
    if not (af and al and bf and bl):
        return 1.0
    if al < af:
        af, al = al, af
    if bl < bf:
        bf, bl = bl, bf
    latest_start, earliest_end = max(af, bf), min(al, bl)
    if latest_start <= earliest_end:
        return 1.0
    gap_days = (latest_start - earliest_end).days
    return max(_OVERLAP_FLOOR, 1.0 - gap_days / 365.0)


def recency_weight(most_recent: datetime | None) -> float:
    """Decay factor for how long ago a shared node was last seen at all —
    absolute staleness, distinct from time_overlap_factor's a-vs-b *relative*
    overlap. Two sides can agree perfectly on timing (overlap=1.0) while both
    only ever saw the match years ago — e.g. a TLS certificate that was
    current in 2019 and has since expired/rotated is much weaker evidence of
    a *present-day* shared-ownership relationship than the same exact match
    seen last month, even though the two sides' windows line up. Unknown
    timestamps get full credit (nothing to penalize).
    """
    if most_recent is None:
        return 1.0
    age_days = (datetime.now(timezone.utc) - most_recent).days
    if age_days <= _RECENCY_FULL_CREDIT_DAYS:
        return 1.0
    decayed_days = age_days - _RECENCY_FULL_CREDIT_DAYS
    return max(_RECENCY_FLOOR, 1.0 - decayed_days / 730.0)


# Per-provider plain-language explanation for a shared site-verification code:
# these are minted by the provider per webmaster-tools property/account, so an
# exact match is a near-identity signal (see SELECTOR_BASE_WEIGHTS["site_verification"]).
_SITE_VERIFICATION_EXPLANATIONS = {
    "google": "Google Search Console mints this code per verified property — an exact match usually means the same Google account added it to both sites.",
    "bing": "Bing Webmaster Tools mints this code per verified site — an exact match usually means the same account administers both.",
    "yandex": "Yandex Webmaster mints this code per verified site — an exact match usually means the same account administers both.",
    "pinterest": "Pinterest mints this code per claimed domain — an exact match usually means the same business account claims both.",
    "facebook": "Meta's domain-verification code is minted per Business Manager account — an exact match usually means the same business administers both.",
    "baidu": "Baidu Webmaster Tools mints this code per verified site — an exact match usually means the same account administers both.",
    "naver": "Naver Search Advisor mints this code per verified site — an exact match usually means the same account administers both.",
    "ahrefs": "Ahrefs mints this code per verified project — an exact match usually means the same subscriber added it to both sites.",
    "yahoo": "Yahoo mints this code per verified site — an exact match usually means the same account administers both.",
    "shopify": "Shopify mints this code per store — an exact match usually means the same merchant account runs both storefronts.",
    "norton": "Norton Safe Web mints this code per verified site — an exact match usually means the same account administers both.",
    "alexa": "Alexa mints this code per verified site — an exact match usually means the same account administers both.",
    "wot": "Web of Trust mints this code per verified site — an exact match usually means the same account administers both.",
}


def _explain_site_verification(provider: str) -> str:
    base = _SITE_VERIFICATION_EXPLANATIONS.get(
        provider,
        f"{provider.title()} mints this ownership-verification code per account — an exact match usually means "
        "the same account verified both sites.",
    )
    return f"{base} Rare exception: a shared CMS or site-builder template can bake in a platform-wide code, so weigh this alongside other evidence."


# `tracking_id` values are "<provider>|<id>" (see _TRACKING_SELECTOR_MAP in
# db.intel_db); explanations are per-provider because how tightly an ID binds
# to one operator varies a lot — an AdSense publisher ID is a payment account,
# a GTM container is routinely reused by agencies across unrelated clients.
_TRACKING_SUBKIND_EXPLANATIONS = {
    "adsense_publisher": "AdSense publisher IDs are tied to a single Google AdSense payment account — this is close to a direct ownership signal, since ad revenue from both sites flows to the same account.",
    "ga_property": "Google Analytics property IDs are normally set up per site — a shared ID usually means the same person or team configured analytics for both, though agencies occasionally reuse one property across client sites.",
    "fb_pixel": "Facebook Pixel IDs tie to a single Meta Ads/Business account — usually the same advertiser runs campaigns for both sites.",
    "yandex_metrika": "Yandex Metrika counter IDs are created per site under one Yandex account — a shared counter usually means the same account manages analytics for both.",
    "gtm_container": "Google Tag Manager containers are routinely shared and reused by agencies or vendors across unrelated clients, so this is weaker standalone evidence than the other tracking IDs — treat it as supporting, not decisive.",
    "fb_app_id": "Facebook App IDs tie to a single Meta developer account, but can ride along in a shared theme or plugin — look for corroborating evidence.",
}

_TRACKING_SUBKIND_FALLBACK = (
    "Tracking/analytics IDs are usually configured per site by whoever manages marketing — a shared ID often "
    "means the same person or team, though vendors can occasionally reuse one across clients."
)

# Static per-kind explanation for every other selector kind the correlation
# graph produces. Each names *why* a match of that kind is meaningful and the
# main way it can mislead, mirroring the shared_ip / site_verification
# explainers so no evidence type in the UI is left as a bare label + value.
_SELECTOR_KIND_EXPLANATIONS = {
    "tls_cert_sha256": (
        "Both sites served the exact same TLS certificate. A certificate's private key belongs to whoever "
        "requested it, so an exact match is one of the strongest signals of shared infrastructure — the main "
        "exception is a certificate that covers a whole shared-hosting or CDN fleet rather than one operator."
    ),
    "tls_spki": (
        "Both sites' certificates share the same public key (SPKI) even though the certificates themselves "
        "differ — the same key pair was reused when issuing certs for both, a strong operational fingerprint "
        "that survives certificate renewal or rotation."
    ),
    "tls_san": (
        "Both sites' certificates list the same alternative name (SAN), meaning they're bundled on the same "
        "multi-domain certificate. Strong when that's a small, dedicated certificate; weak-to-noise when it's a "
        "big CDN or shared-hosting bundle (those are filtered out where recognized)."
    ),
    "ssh_fp": (
        "Both sites' servers presented the identical SSH host key. Host keys are generated per machine (or per "
        "machine image), so a match usually means the literal same box, or a server image/snapshot shared "
        "between them."
    ),
    "social_handle": (
        "Both sites link to or declare the same social media account. This is usually a deliberate identity "
        "claim by the operator, though a shared marketing agency, syndication network, or copied template can "
        "occasionally repeat a handle across unrelated properties."
    ),
    "crypto_wallet": (
        "Both sites solicit payment to the same cryptocurrency address. A wallet is controlled by whoever holds "
        "its private key, so two sites collecting funds to one address are almost always the same operation — "
        "the money ends up in one place. The exception to watch for is a copycat or scraper republishing "
        "someone else's donation address, which looks identical on the page."
    ),
    "legal_registration": (
        "Both sites publish the same company registration number. A registry issues that number to exactly one "
        "legal entity, so this is a declaration by the sites themselves that one company stands behind both — "
        "about as close to an ownership statement as an imprint gets. It is read out of free-form page text, "
        "so the failure mode to rule out is a mis-parse rather than a coincidence."
    ),
    "contact_email": (
        "Both sites publish the same contact mailbox. An address is account-bound and someone has to read it, so "
        "it usually belongs to whoever runs both. Registrar and privacy-proxy role addresses are filtered out "
        "before this point, but a shared agency or outsourced support desk can still explain it."
    ),
    "legal_entity": (
        "Both sites name the same company in their legal or imprint pages. That is a direct claim of common "
        "ownership — but company names are not unique, generic ones collide across unrelated firms, and the name "
        "is parsed out of prose, so treat it as corroboration rather than proof on its own."
    ),
    "legal_address": (
        "Both sites publish the same postal address. This can be one operator's real office, but registered-agent "
        "services, accountants, and coworking suites act as the registered address for thousands of unrelated "
        "companies, so it is only meaningful alongside something that isn't a mailbox."
    ),
    "legal_text_hash": (
        "Both sites serve a byte-identical legal page. Either one operator published the same document twice or "
        "one site copied the other. The common innocent explanation is a policy generator producing identical "
        "boilerplate for unrelated customers, so it carries about as much weight as an identical homepage."
    ),
    "contact_phone": (
        "Both sites publish the same contact phone number. A working number has to be answered by someone, so "
        "it usually points at one back office — but shared call centres, franchise and reseller networks, and "
        "template placeholder numbers all repeat a number across genuinely unrelated sites, so corroborate it."
    ),
    "favicon_mmh3": (
        "Both sites serve a byte-identical favicon. This often carries over when a site is cloned, rebranded, or "
        "built from the same template — common enough on templated/CMS-default sites that it's best treated as "
        "supporting evidence, not decisive on its own."
    ),
    "favicon_md5": (
        "Both sites serve a byte-identical favicon (exact-hash match). Often carries over when a site is cloned, "
        "rebranded, or built from the same template — treat as supporting evidence rather than decisive on its "
        "own."
    ),
    "html_hash": (
        "The homepage HTML is byte-identical between both sites — a strong sign of a shared template, mirrored "
        "content, or the same deployment pipeline, though a generic templated or parked-domain page can "
        "coincidentally match too."
    ),
    "nameserver": (
        "Both domains delegate to the same nameserver hostname. Meaningful when it's a small, custom/vanity "
        "nameserver dedicated to one operator; much weaker when it's a big DNS host's shared nameserver serving "
        "thousands of unrelated customers (those are filtered out where recognized)."
    ),
    "spf_origin": (
        "Both domains authorise the same server to send email on their behalf (SPF). Meaningful when it's a "
        "self-hosted or small dedicated mail origin, which points at one operator running the mail for both; "
        "close to noise when it's a large provider like Google or SendGrid that most of the internet lists."
    ),
    "network_cidr": (
        "Both domains' IPs sit in the same network block. Supporting context on top of a direct IP or "
        "certificate match — a small, dedicated block is a real signal, while a huge cloud provider's whole "
        "range is close to noise on its own."
    ),
    "asn": (
        "Both domains' IPs are announced by the same network operator (Autonomous System). This is the weakest "
        "infrastructure signal by itself, since a single ASN can host millions of unrelated customers — only "
        "meaningful alongside stronger evidence."
    ),
}


def _explain_selector(kind: str, subkind: str | None) -> str | None:
    if kind == "site_verification" and subkind:
        return _explain_site_verification(subkind)
    if kind == "tracking_id":
        return _TRACKING_SUBKIND_EXPLANATIONS.get(subkind, _TRACKING_SUBKIND_FALLBACK) if subkind else _TRACKING_SUBKIND_FALLBACK
    return _SELECTOR_KIND_EXPLANATIONS.get(kind)


def _recency_note(recency: float, most_recent: datetime | None) -> str | None:
    """The age fragment of a degradation note ("it hasn't been seen in about
    N years"), shared by every indicator kind — selectors and shared IPs
    alike. Split out from _degradation_note so _score_ip_row can reuse just
    this half (an IP's rarity/degree story is already told by its own
    CDN/pool/origin classification in _explain_shared_ip; repeating "shared
    with N other domains" there would just duplicate what describe_ip_network
    already said in different words)."""
    if most_recent is None or recency >= 0.85:
        return None
    age_years = (datetime.now(timezone.utc) - most_recent).days / 365.0
    return f"it hasn't been seen in about {age_years:.1f} years" if age_years >= 1 else "it hasn't been seen recently"


def _degradation_note(degree: int, rarity: float, recency: float, most_recent: datetime | None) -> str | None:
    """Plain-language reason a match scored lower here specifically — e.g. a
    TLS certificate match is close to decisive in the abstract, but the exact
    same certificate reused across a shared-hosting fleet (high degree -> low
    rarity) or one that hasn't been seen in years (low recency) is much
    weaker evidence of a *current* shared-ownership relationship. An analyst
    should be told why the number is smaller, not just shown a smaller
    number. Applies uniformly to every selector kind — an already-low-weight
    match (nameserver, ASN, ...) degrading further is just as worth
    explaining as a normally-strong one.
    """
    notes: list[str] = []
    if degree >= 10 and rarity < 0.6:
        notes.append(f"it's shared with {degree} other domains in the pool")
    recency_note = _recency_note(recency, most_recent)
    if recency_note:
        notes.append(recency_note)
    if not notes:
        return None
    return (
        "Scored lower than a typical match of this kind because " + " and ".join(notes)
        + " — weaker evidence of a relationship that's still current."
    )


def _cert_validity_note(cert_info: dict | None) -> str | None:
    """Plain-language status from the certificate's own not_before/not_after
    (its real, CA-issued validity window) — distinct from the observation
    windows already shown, which only say when *our scanner* last saw it.
    An investigator needs to know whether the certificate itself is still
    alive, not just whether our last probe was recent."""
    if not cert_info:
        return None
    not_after = _parse_dt(cert_info.get("not_after"))
    if not_after is None:
        return None
    now = datetime.now(timezone.utc)
    if not_after < now:
        return f"This certificate expired on {not_after.date().isoformat()}."
    not_before = _parse_dt(cert_info.get("not_before"))
    if not_before and not_before > now:
        return f"This certificate isn't valid until {not_before.date().isoformat()}."
    return f"This certificate is currently valid through {not_after.date().isoformat()}."


def _score_selector_row(row: dict, cert_meta: dict[str, dict] | None = None) -> tuple[dict, float]:
    kind = row["kind"]
    value = row["value"]
    degree = int(row.get("entity_count") or 0)
    base = selector_base_weight(kind, value)
    rarity = rarity_weight(degree)
    overlap = time_overlap_factor(row.get("a_first"), row.get("a_last"), row.get("b_first"), row.get("b_last"))
    # Absolute staleness (distinct from `overlap`'s a-vs-b relative agreement):
    # the more recent of the two sides' last-seen dates for this exact shared
    # node, so a match still active on either side isn't penalized just
    # because the other side's own observations are older.
    most_recent = max(
        (d for d in (_parse_dt(row.get("a_last")), _parse_dt(row.get("b_last"))) if d is not None),
        default=None,
    )
    recency = recency_weight(most_recent)
    weight = base * rarity * overlap * recency
    sources = sorted({s for s in (list(row.get("a_sources") or []) + list(row.get("b_sources") or [])) if s})
    # `tracking_id`/`site_verification`/`social_handle`/`crypto_wallet` values are
    # "<provider>|<id>"; expose the provider so the UI can label e.g. an AdSense
    # account distinctly from a reused GTM container, a Google vs. Yandex
    # verification code, or a Bitcoin vs. Ethereum wallet.
    has_prefix = "|" in value and kind in ("tracking_id", "site_verification", "social_handle", "crypto_wallet")
    subkind = value.split("|", 1)[0] if has_prefix else None
    explanation = _explain_selector(kind, subkind)
    degradation = _degradation_note(degree, rarity, recency, most_recent)
    if degradation:
        explanation = f"{explanation} {degradation}" if explanation else degradation
    # Real certificate metadata (CN, issuer, actual CA-issued validity window)
    # for tls_cert_sha256 matches — the full "why" an OSINT investigator needs
    # for a cert match, not just that the fingerprint is identical. Keyed by
    # the selector's own value (the sha256) so it's a plain dict lookup, no
    # extra query per row (cert_meta is batch-fetched by the caller).
    cert_info = (cert_meta or {}).get(value) if kind == "tls_cert_sha256" else None
    if cert_info:
        validity_note = _cert_validity_note(cert_info)
        if validity_note:
            explanation = f"{explanation} {validity_note}"
    evidence = {
        "node_type": "selector",
        "kind": kind,
        "subkind": subkind,
        "explanation": explanation,
        "value": value,
        "degree": degree,
        "attributing": True,
        "base_weight": round(base, 2),
        "rarity": round(rarity, 3),
        "time_overlap": round(overlap, 3),
        "recency": round(recency, 3),
        "degraded": bool(degradation),
        "weight": round(weight, 2),
        "sources": sources,
        # Certificate identity/validity, only populated for tls_cert_sha256
        # matches — the CN/issuer an investigator would check against the
        # actual site, and the cert's own CA-issued not_before/not_after
        # (never the observation window above, which is our scan history).
        "cert_cn": cert_info.get("cn") if cert_info else None,
        "cert_issuer_cn": cert_info.get("issuer_cn") if cert_info else None,
        "cert_issuer_org": cert_info.get("issuer_org") if cert_info else None,
        "cert_not_before": cert_info.get("not_before") if cert_info else None,
        "cert_not_after": cert_info.get("not_after") if cert_info else None,
        "window_a": [row.get("a_first"), row.get("a_last")],
        "window_b": [row.get("b_first"), row.get("b_last")],
        # The specific host(s) that actually exhibited this selector on each
        # side — may be a subdomain of the apex being compared, not the apex
        # itself (transitive, subdomain-mediated linkage).
        "hosts_a": sorted({h for h in (row.get("a_hosts") or []) if h}),
        "hosts_b": sorted({h for h in (row.get("b_hosts") or []) if h}),
    }
    return evidence, weight


def classify_ip_network(*, degree: int, cdn: bool) -> str:
    """cdn / pool / origin — what kind of box a shared IP is. Used both to score
    the overlap (a CDN edge or a big hosting pool is weak evidence; a small,
    dedicated box two sites both sit on is strong evidence) and to explain the
    connection to a user in plain terms."""
    if cdn:
        return "cdn"
    if degree > _IP_NOISE_DEGREE:
        return "pool"
    return "origin"


# RDAP network name / ASN description / reverse DNS keywords that name an IP
# as CDN or edge infrastructure. Catches regional and carrier CDNs (a mobile
# operator's own "CDN" product, a national telco's edge network, ...) that
# aren't in Cloudflare's ranges, carry no cloudflare flag, and fingerprint as
# no recognized reverse-proxy — which would otherwise score as a dedicated
# origin box just because our own pool hasn't scanned many of its customers.
_CDN_NETWORK_PATTERNS = (
    "cdn",
    "content delivery",
    "edge network",
    "edge cache",
    "akamai",
    "fastly",
    "cloudfront",
    "stackpath",
    "highwinds",
    "limelight",
    "lumen cdn",
    "cachefly",
    "keycdn",
    "bunny",
    "cdn77",
    "ngenix",
    "qrator",
    "gcore",
    "g-core",
    "medianova",
    "sucuri",
    "incapsula",
    "imperva",
    "edgecast",
    "chinacache",
    "wangsu",
    "azion",
    "quantil",
    # Cloudflare by name — the IP-range/flag checks above already catch most
    # Cloudflare traffic, but an RDAP network name/ASN description of
    # "CLOUDFLARENET" on an address outside the hardcoded anycast ranges (a
    # newer block, or a scan that only captured RDAP text) would otherwise
    # fall through to "origin" with no other signal to catch it.
    "cloudflare",
    # Anti-DDoS scrubbing reverse proxies — same shared-edge effect as a CDN:
    # unrelated customers behind the same scrubbing IP look like one operator
    # unless filtered. Real ASNs verified against RIPEstat (see
    # db.intel_db._CDN_PROXY_ASNS) rather than guessed from memory.
    "ddos-guard",
    "ddosguard",
    "voxility",
    "myra security",
    "myracloud",
    "path network",
    "reblaze",
    # Google's generic reverse-DNS domain for its shared-frontend IPs (GFE,
    # Firebase Hosting, Google Cache, ...) — deliberately not a bare "google"
    # keyword, since that would also catch a dedicated GCE VM's own ASN
    # description; 1e100.net specifically only appears on Google-managed
    # shared edges, never on a customer-controlled box.
    "1e100.net",
)


def _looks_like_cdn_network(meta: dict) -> bool:
    haystack = " ".join(
        str(meta.get(field) or "") for field in ("network_name", "asn_desc", "ptr")
    ).lower()
    return bool(haystack.strip()) and any(pattern in haystack for pattern in _CDN_NETWORK_PATTERNS)


# Censys host-enrichment labels that mean "shared/transit infrastructure", not
# "someone's own server".
_CENSYS_SHARED_LABELS = ("cdn", "hosting", "proxy", "vpn", "tor")


def _censys_says_shared(meta: dict) -> bool:
    """Whether Censys host enrichment classifies this IP as shared infrastructure.

    Complements detect_proxy_details rather than replacing it: `proxy_family`
    stays the display/clustering label, and this only ever *discounts* shared_ip
    evidence. It is the pipeline's only source of Tor/VPN/relay classification —
    two sites meeting on a VPN exit or Tor relay is not shared hosting in any
    meaningful sense, and previously nothing here knew the difference.

    Note `censys_hosting` alone is deliberately included: a datacenter IP is not
    by itself proof of sharing, but combined with the degree-keyed rarity factor
    that classify_ip_network already applies, treating it as non-origin is the
    safer error — it only ever weakens a link, never invents one.
    """
    if any(
        bool(meta.get(f"censys_{flag}"))
        for flag in ("hosting", "proxy", "vpn", "tor", "relay", "anonymous")
    ):
        return True
    labels = [str(x).lower() for x in (meta.get("censys_labels") or [])]
    return any(label in _CENSYS_SHARED_LABELS for label in labels)


def _censys_shared_reason(meta: dict) -> str | None:
    """The most specific Censys classification for this IP, for the explanation.

    Ordered most- to least-specific: a Tor relay or VPN exit is a much sharper
    reason to discard a shared_ip link than "this is a datacenter".
    """
    for flag, phrase in (
        ("tor", "a Tor relay"),
        ("vpn", "a VPN exit node"),
        ("relay", "a privacy relay"),
        ("proxy", "an open proxy"),
        ("anonymous", "an anonymising service"),
    ):
        if meta.get(f"censys_{flag}"):
            return phrase
    labels = [str(x).lower() for x in (meta.get("censys_labels") or [])]
    if "cdn" in labels:
        return "a CDN edge"
    if meta.get("censys_hosting") or "hosting" in labels:
        return "shared datacenter hosting"
    return None


def _explain_shared_ip(network: str, degree: int, meta: dict) -> str:
    asn_desc = str(meta.get("asn_desc") or "").strip()
    if network == "cdn":
        censys_reason = _censys_shared_reason(meta)
        # Prefer the Censys classification when it is more specific than "some
        # edge network" — "both sites were seen on a Tor relay" is a materially
        # different finding from "both sites are behind Cloudflare", and the
        # analyst needs to be able to tell them apart.
        if censys_reason and not meta.get("proxy_family"):
            return (
                f"IP that Censys classifies as {censys_reason} — two sites meeting here "
                "is shared infrastructure, not evidence of common ownership."
            )
        label = meta.get("proxy_family") or meta.get("network_name") or asn_desc or "a CDN / reverse-proxy"
        return (
            f"Front-door IP behind {label} — both sites share the same edge network, "
            "which is common infrastructure rather than evidence of common ownership."
        )
    if network == "pool":
        return f"Shared-hosting IP with {degree} other domains on it — too crowded on its own to mean much."
    suffix = f" ({asn_desc})" if asn_desc else ""
    return f"Looks like a dedicated origin server{suffix} — few sites sit directly on this box, a stronger signal."


def describe_ip_network(value: str, degree: int, meta: dict | None = None, *, noisy_net: bool = False) -> dict:
    """Classify + plain-language-explain what kind of box a shared IP is
    (CDN/proxy edge, shared-hosting pool, or likely dedicated origin server).
    Shared by the pairwise scorer and the domain-detail IP list so both agree."""
    meta = meta or {}
    # A Cloudflare/CDN or proxy edge address (flagged by a denylisted ASN/CIDR
    # on the IP, a detected reverse-proxy family, the stored Cloudflare flag,
    # matching Cloudflare's published ranges, a known shared-platform IP, or a
    # network name/PTR that names itself as CDN/edge infrastructure) tells you
    # only that both sites front through the same CDN — never a link. A
    # dedicated origin box two domains both sit on is the strong case; a big
    # shared-hosting pool decays out through the degree-keyed rarity factor.
    cdn = (
        bool(noisy_net)
        or bool(meta.get("cloudflare"))
        or bool(meta.get("proxy_family"))
        or _is_cloudflare_ip_local(value)
        or _is_known_shared_infra_ip(value)
        or _looks_like_cdn_network(meta)
        or _censys_says_shared(meta)
    )
    network = classify_ip_network(degree=degree, cdn=cdn)
    return {"network": network, "explanation": _explain_shared_ip(network, degree, meta)}


def _score_ip_row(row: dict, meta: dict | None = None) -> tuple[dict, float]:
    value = str(row.get("value") or "")
    degree = int(row.get("degree") or 0)
    meta = meta or {}
    described = describe_ip_network(value, degree, meta, noisy_net=bool(row.get("noisy_net")))
    network = described["network"]
    noisy = network != "origin"
    base = selector_base_weight("shared_ip")
    rarity = 0.0 if noisy else rarity_weight(degree)
    overlap = time_overlap_factor(row.get("a_first"), row.get("a_last"), row.get("b_first"), row.get("b_last"))
    # Same absolute-staleness treatment as selectors (see recency_weight): an
    # "origin" IP both sides only ever shared years ago is weaker evidence of
    # a still-current relationship than one seen last month, even when the
    # two sides' own windows agree with each other (overlap=1.0). Skipped
    # when noisy/rarity is already 0 — nothing left to discount further.
    most_recent = max(
        (d for d in (_parse_dt(row.get("a_last")), _parse_dt(row.get("b_last"))) if d is not None),
        default=None,
    )
    recency = 1.0 if noisy else recency_weight(most_recent)
    weight = base * rarity * overlap * recency
    sources = sorted({s for s in (list(row.get("a_sources") or []) + list(row.get("b_sources") or [])) if s})
    explanation = described["explanation"]
    # Degree/rarity is already explained by describe_ip_network's own
    # cdn/pool/origin classification above — only the age half of
    # _degradation_note applies here, so it isn't said twice in different words.
    recency_note = _recency_note(recency, most_recent) if not noisy else None
    if recency_note:
        explanation = f"{explanation} Also, {recency_note} — weaker evidence of a relationship that's still current."
    evidence = {
        "node_type": "ip",
        "kind": "shared_ip",
        "network": network,
        "explanation": explanation,
        "value": value,
        "degree": degree,
        "attributing": not noisy,
        "asn": meta.get("asn"),
        "asn_desc": meta.get("asn_desc"),
        "network_name": meta.get("network_name"),
        "proxy_family": meta.get("proxy_family"),
        "cloudflare": bool(meta.get("cloudflare")),
        "country": meta.get("country"),
        "base_weight": round(base, 2),
        "rarity": round(rarity, 3),
        "time_overlap": round(overlap, 3),
        "recency": round(recency, 3),
        "degraded": bool(recency_note),
        "weight": round(weight, 2),
        "sources": sources or ["resolves_to"],
        "window_a": [row.get("a_first"), row.get("a_last")],
        "window_b": [row.get("b_first"), row.get("b_last")],
        # The specific host(s) on each side that actually resolve to this IP —
        # may be a subdomain of the apex being compared, not the apex itself.
        "hosts_a": sorted({h for h in (row.get("a_hosts") or []) if h}),
        "hosts_b": sorted({h for h in (row.get("b_hosts") or []) if h}),
    }
    return evidence, weight


def _graph_strength(score: float, evidence: list[dict]) -> str:
    decisive = any(
        e.get("kind") in _DECISIVE_SELECTOR_KINDS and e.get("attributing") and e.get("weight", 0) >= 50
        for e in evidence
    )
    if decisive or score >= 65:
        return "strong"
    if score >= 30:
        return "moderate"
    return "weak"


# The two graph kinds that carry the same webmaster-verification codes:
# `site_verification` is scraped from a <meta> tag, `dns_txt_token` from a DNS
# TXT record. A provider issues one code and site owners routinely publish it
# both ways, so the same secret would otherwise be counted as two independent
# selectors and inflate a link's score.
#
# Which one survives is deliberate rather than arbitrary: a token in DNS proves
# control of the *zone*, a token in HTML only proves control of the page, so the
# DNS spelling is kept when both are present. They stay separate kinds in the
# graph — provenance is worth keeping — and are collapsed only here, at scoring
# time, which is the decision the user made when this was raised.
_VERIFICATION_TOKEN_KINDS = ("dns_txt_token", "site_verification")


def _verification_token_identity(row: dict) -> str | None:
    """`provider|token` for a verification-code row, lowercased; None otherwise."""
    kind = str(row.get("kind") or "")
    if kind not in _VERIFICATION_TOKEN_KINDS:
        return None
    value = str(row.get("value") or "").strip().lower()
    return value or None


def _dedupe_verification_tokens(rows: list[dict]) -> list[dict]:
    """Drop the HTML-sourced copy of any verification code also seen in DNS.

    Order-independent: the DNS row wins whichever way round the two arrive.
    Non-verification rows pass through untouched and keep their original order.
    """
    dns_identities = {
        identity
        for row in rows
        if str(row.get("kind") or "") == "dns_txt_token"
        and (identity := _verification_token_identity(row))
    }
    if not dns_identities:
        return rows
    out: list[dict] = []
    for row in rows:
        if str(row.get("kind") or "") == "site_verification":
            identity = _verification_token_identity(row)
            if identity and identity in dns_identities:
                continue
        out.append(row)
    return out


def _assemble_link(
    shared_selectors: list[dict],
    shared_ips: list[dict],
    ip_meta: dict[str, dict] | None = None,
    cert_meta: dict[str, dict] | None = None,
) -> dict:
    """Score one link from its shared selectors + IPs.

    `ip_meta` is the IP→network-context map from ``intel_db.ip_network_context``.
    `cert_meta` is the sha256→certificate-metadata map from
    ``intel_db.tls_cert_context`` (CN, issuer, real not_before/not_after —
    what an investigator needs to judge a TLS cert match, not just that one
    exists). Pass either in when scoring many links at once (e.g.
    ``links_for``) so the context is fetched a single time for the whole
    batch instead of once per link; when omitted each is fetched here for
    this link's own selectors/IPs alone.
    """
    from db import intel_db

    if cert_meta is None:
        cert_shas = [str(row["value"]) for row in shared_selectors if row.get("kind") == "tls_cert_sha256" and row.get("value")]
        cert_meta = intel_db.tls_cert_context(cert_shas) if cert_shas else {}
    evidence: list[dict] = []
    total = 0.0
    for row in _dedupe_verification_tokens(shared_selectors):
        ev, weight = _score_selector_row(row, cert_meta)
        evidence.append(ev)
        total += weight
    if ip_meta is None:
        ip_meta = intel_db.ip_network_context([str(row.get("value") or "") for row in shared_ips])
    for row in shared_ips:
        ev, weight = _score_ip_row(row, ip_meta.get(str(row.get("value") or "")))
        # Keep non-attributing shared IPs out of the breakdown (present in the
        # graph, but they must never create a link); the noise test relies on this.
        if weight > 0:
            evidence.append(ev)
            total += weight
    evidence.sort(key=lambda e: e["weight"], reverse=True)
    return {
        "score": round(total, 2),
        "confidence": confidence_from_score(total),
        "strength": _graph_strength(total, evidence),
        "evidence": evidence,
        "shared_node_count": len(evidence),
    }


def link_evidence(a_value: str, b_value: str) -> dict:
    """Score and explain the linkage between two entities / registrable domains."""
    from db import intel_db

    # A node never links to itself: same registrable domain / IP is not evidence.
    side_a = intel_db._resolve_side(a_value)
    side_b = intel_db._resolve_side(b_value)
    if side_a and side_b and side_a[0] == side_b[0] and side_a[1] == side_b[1]:
        return {
            "a": a_value, "b": b_value, "score": 0.0, "confidence": 0,
            "strength": "weak", "evidence": [], "shared_node_count": 0, "self": True,
        }

    link = _assemble_link(
        intel_db.shared_selectors_between(a_value, b_value),
        intel_db.shared_ips_between(a_value, b_value),
    )
    link["a"] = a_value
    link["b"] = b_value
    return link


def connections_among(
    domains: list[str], *, pool_links: bool = False, max_domains: int = 30
) -> dict:
    """Score linkage within a selected set of channels.

    Returns the pairwise links among the selected domains (so you can see which
    of them are connected to each other and on what evidence), and optionally
    each one's strongest connections to the wider pool.
    """
    from db import intel_db

    resolved: list[str] = []
    seen: set[str] = set()
    for value in domains:
        side = intel_db._resolve_side(value)
        if not side or side[1] in seen:
            continue
        seen.add(side[1])
        resolved.append(side[1])
        if len(resolved) >= max_domains:
            break

    # Each member's own precomputed connection list (links_for_fast — cached
    # by rebuild_clusters, live-fallback for anything not yet rebuilt), fetched
    # once per domain and reused for both the pairwise loop below and the
    # pool_links block. This is what makes opening a large cluster fast: it
    # replaces what used to be 2 live DB queries per *pair* (O(n^2) — 435
    # queries for a 30-member cluster) with one cache read per *domain* (O(n)).
    all_candidates: dict[str, list[dict]] = {
        rd: links_for_fast(rd, limit=None, min_score=0.0) for rd in resolved
    }
    resolved_set = set(resolved)
    by_domain: dict[str, dict[str, dict]] = {
        rd: {link["target"]: link for link in candidates if link["target"] in resolved_set}
        for rd, candidates in all_candidates.items()
    }

    pairs: list[dict] = []
    for i in range(len(resolved)):
        for j in range(i + 1, len(resolved)):
            a, b = resolved[i], resolved[j]
            found = by_domain.get(a, {}).get(b) or by_domain.get(b, {}).get(a)
            if found:
                link = {
                    "score": found["score"],
                    "confidence": found["confidence"],
                    "strength": found["strength"],
                    "evidence": found["evidence"],
                    "shared_node_count": found["shared_node_count"],
                }
            else:
                link = {"score": 0.0, "confidence": 0, "strength": "weak", "evidence": [], "shared_node_count": 0}
            link["a"] = a
            link["b"] = b
            link["connected"] = link["score"] > 0
            pairs.append(link)
    pairs.sort(key=lambda link: link["score"], reverse=True)

    result: dict = {
        "domains": resolved,
        "pairs": pairs,
        "connected_pair_count": sum(1 for link in pairs if link["connected"]),
    }
    tier_domains = set(resolved)
    if pool_links:
        # Same shape as links_for's own default (limit=50, min_score=1) — reuses
        # the fetch above instead of a second cache/DB read per domain. No
        # artificial cap beyond that: the frontend already previews only the
        # top few and needs the true length to report an accurate count.
        result["pool_links"] = {
            d: [link for link in all_candidates[d] if link["score"] >= 1.0][:50] for d in resolved
        }
        for links in result["pool_links"].values():
            tier_domains.update(link.get("target") for link in links if link.get("target"))
    result["tiers"] = intel_db.get_domain_tiers(tier_domains)
    return result


def links_for(value: str, *, limit: int | None = 50, min_score: float = 1.0) -> list[dict]:
    """Ranked cross-corpus connections for one entity / registrable domain.

    Candidates whose only shared nodes are non-attributing fall out for free:
    they score 0 and are dropped by min_score. Always scores live — see
    links_for_fast() for the cached-read version used by hot paths like
    connections_among().
    """
    from db import intel_db

    candidates = intel_db.link_candidates_for(value)
    # Fetch every candidate's IP network context and TLS cert metadata in one
    # query each rather than one per candidate inside _assemble_link. On a
    # well-connected domain this collapses dozens of short-lived DB
    # connections into two lookups — the difference that makes rebuild_clusters
    # (which calls this for every domain in the pool) and the domain-detail
    # page fast.
    all_ip_values = [
        str(row.get("value") or "")
        for bundle in candidates.values()
        for row in (bundle.get("ips") or [])
    ]
    ip_meta = intel_db.ip_network_context(all_ip_values)
    all_cert_shas = [
        str(row["value"])
        for bundle in candidates.values()
        for row in (bundle.get("selectors") or [])
        if row.get("kind") == "tls_cert_sha256" and row.get("value")
    ]
    cert_meta = intel_db.tls_cert_context(all_cert_shas) if all_cert_shas else {}

    results: list[dict] = []
    for rd, bundle in candidates.items():
        link = _assemble_link(bundle.get("selectors") or [], bundle.get("ips") or [], ip_meta, cert_meta)
        if link["score"] < min_score:
            continue
        link["target"] = rd
        link["registrable_domain"] = rd
        results.append(link)
    results.sort(key=lambda link: link["score"], reverse=True)
    return results[:limit] if limit else results


def links_for_fast(value: str, *, limit: int | None = 50, min_score: float = 1.0) -> list[dict]:
    """Like `links_for`, but reads the precomputed cache (db.intel_db.graph_links,
    kept fresh by rebuild_clusters' ~20s dirty-check sweep — see
    cases.case_app._cluster_rebuild_loop) instead of scoring live.

    Falls back to a live `links_for()` call for a domain that hasn't been
    through a rebuild pass yet (e.g. ingested moments ago), so a brand-new
    domain never wrongly reads as having no connections just because the
    cache hasn't caught up.
    """
    from db import intel_db

    cached = intel_db.cached_links_for(value)
    if cached is None:
        return links_for(value, limit=limit, min_score=min_score)
    links = [link for link in cached if link["score"] >= min_score]
    links.sort(key=lambda link: link["score"], reverse=True)
    return links[:limit] if limit else links
