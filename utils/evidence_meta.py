from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EvidenceDefinition:
    path: str
    label: str
    category: str
    description: str
    why_it_matters: str
    caveat: str
    base_importance: str


EVIDENCE_DEFINITIONS: dict[str, EvidenceDefinition] = {
    "tls_certs.probes[*].fingerprint_sha256": EvidenceDefinition(
        path="tls_certs.probes[*].fingerprint_sha256",
        label="Shared TLS fingerprint",
        category="Transport",
        description="Both targets served the same TLS certificate fingerprint.",
        why_it_matters="A matching certificate fingerprint is one of the strongest shared-backend indicators.",
        caveat="It weakens if the certificate is an abandoned default vhost or belongs to a broad shared platform.",
        base_importance="decisive",
    ),
    "ssh_host_keys.probes[*].fingerprint_sha256": EvidenceDefinition(
        path="ssh_host_keys.probes[*].fingerprint_sha256",
        label="Shared SSH host key",
        category="Transport",
        description="Both targets exposed the same SSH host key fingerprint.",
        why_it_matters="A shared SSH key usually points to the same managed host or image lineage.",
        caveat="It is less definitive on managed hosting where providers reuse images or proxy access.",
        base_importance="decisive",
    ),
    "non_cf_ips": EvidenceDefinition(
        path="non_cf_ips",
        label="Shared non-proxied IP",
        category="Infrastructure",
        description="Both targets exposed the same non-Cloudflare IP.",
        why_it_matters="Shared live origin IPs often indicate the same server or hosting footprint.",
        caveat="Historical or shared-hosting IPs are weaker than current dedicated infrastructure.",
        base_importance="strong",
    ),
    "dns.A": EvidenceDefinition(
        path="dns.A",
        label="Shared A record",
        category="Infrastructure",
        description="Both targets resolved to the same IPv4 address.",
        why_it_matters="Current DNS overlap can show the same live hosting or routing destination.",
        caveat="Popular hosting providers can place unrelated sites on the same address pool.",
        base_importance="strong",
    ),
    "hackertarget.hits[*].ip": EvidenceDefinition(
        path="hackertarget.hits[*].ip",
        label="Shared reverse lookup IP",
        category="Infrastructure",
        description="Both targets appeared on the same reverse-IP or hostsearch result.",
        why_it_matters="Reverse-IP overlap adds support for shared hosting history.",
        caveat="It is often historical or provider-wide rather than operator-specific.",
        base_importance="supporting",
    ),
    "urlscan.hits[*].ip": EvidenceDefinition(
        path="urlscan.hits[*].ip",
        label="Shared urlscan IP",
        category="Infrastructure",
        description="Both targets were observed on the same IP in urlscan data.",
        why_it_matters="It can connect hosting history or shared rendered infrastructure.",
        caveat="urlscan observations can be old or reflect edge/proxy infrastructure.",
        base_importance="supporting",
    ),
    "circl_pdns.records[*].rdata": EvidenceDefinition(
        path="circl_pdns.records[*].rdata",
        label="Shared passive DNS record",
        category="Infrastructure",
        description="Both targets shared the same passive DNS answer.",
        why_it_matters="Passive DNS overlap captures infrastructure that may no longer be live.",
        caveat="Historical reuse is useful context, but weaker than current resolution.",
        base_importance="supporting",
    ),
    "page_metadata.google_analytics": EvidenceDefinition(
        path="page_metadata.google_analytics",
        label="Shared Google Analytics ID",
        category="Web identity",
        description="Both targets used the same Google Analytics property.",
        why_it_matters="Analytics identifiers are often directly controlled by the same operator or team.",
        caveat="Agencies and templates can reuse IDs, so this needs other corroboration.",
        base_importance="strong",
    ),
    "page_metadata.gtm_ids": EvidenceDefinition(
        path="page_metadata.gtm_ids",
        label="Shared Google Tag Manager container",
        category="Web identity",
        description="Both targets referenced the same GTM container.",
        why_it_matters="A shared tag container often reflects shared ownership or the same deployment pipeline.",
        caveat="Third-party implementers can reuse containers across clients.",
        base_importance="strong",
    ),
    "page_metadata.facebook_pixel": EvidenceDefinition(
        path="page_metadata.facebook_pixel",
        label="Shared Facebook pixel",
        category="Web identity",
        description="Both targets shared the same Facebook tracking pixel.",
        why_it_matters="Ad-tech IDs are often tied to the same marketing or operator account.",
        caveat="Marketing vendors can reuse pixels across a portfolio.",
        base_importance="strong",
    ),
    "page_metadata.yandex_metrika": EvidenceDefinition(
        path="page_metadata.yandex_metrika",
        label="Shared Yandex Metrika ID",
        category="Web identity",
        description="Both targets shared the same Yandex Metrika identifier.",
        why_it_matters="Shared analytics IDs can be a direct operator signal.",
        caveat="Analytics alone should not outrank transport or origin evidence.",
        base_importance="strong",
    ),
    "page_metadata.tiktok_pixel": EvidenceDefinition(
        path="page_metadata.tiktok_pixel",
        label="Shared TikTok pixel",
        category="Web identity",
        description="Both targets used the same TikTok advertising identifier.",
        why_it_matters="This can connect properties that share the same ad operations.",
        caveat="Advertisers or agencies can reuse pixels for multiple campaigns.",
        base_importance="supporting",
    ),
    "page_metadata.adsense_publisher_ids": EvidenceDefinition(
        path="page_metadata.adsense_publisher_ids",
        label="Shared AdSense publisher ID",
        category="Web identity",
        description="Both targets exposed the same AdSense publisher identifier.",
        why_it_matters="Publisher IDs tie back to the same Google AdSense payment account, a near-identity ownership signal.",
        caveat="Shared templates or publisher resellers can reduce the signal.",
        base_importance="decisive",
    ),
    "page_metadata.favicon_md5": EvidenceDefinition(
        path="page_metadata.favicon_md5",
        label="Shared favicon hash",
        category="Web content",
        description="Both targets served a favicon with the same hash.",
        why_it_matters="Favicons often survive domain churn and can connect cloned or related sites.",
        caveat="Common CMS or hosting defaults can produce the same favicon across unrelated sites.",
        base_importance="supporting",
    ),
    "page_metadata.favicon_murmurhash3": EvidenceDefinition(
        path="page_metadata.favicon_murmurhash3",
        label="Shared favicon MurmurHash3",
        category="Web content",
        description="Both targets served the same favicon fingerprint used in icon matching workflows.",
        why_it_matters="It is helpful for clustering visually or operationally related sites.",
        caveat="Common defaults reduce specificity.",
        base_importance="supporting",
    ),
    "page_metadata.source_map_urls": EvidenceDefinition(
        path="page_metadata.source_map_urls",
        label="Shared source-map disclosure",
        category="Web content",
        description="Both targets exposed the same source-map reference.",
        why_it_matters="Shared build artifacts often point to the same frontend pipeline or codebase.",
        caveat="CDN-hosted shared bundles can create false positives.",
        base_importance="supporting",
    ),
    "page_metadata.social_handle_values": EvidenceDefinition(
        path="page_metadata.social_handle_values",
        label="Shared social handle",
        category="Identity",
        description="Both targets exposed the same social handle or linked profile.",
        why_it_matters="Operator-controlled social identities can be a strong attribution clue.",
        caveat="Aggregator or mirrored social links can reduce confidence.",
        base_importance="supporting",
    ),
    "whois.emails": EvidenceDefinition(
        path="whois.emails",
        label="Shared WHOIS email",
        category="Registration",
        description="Both targets shared a WHOIS contact email.",
        why_it_matters="Registration contacts can directly link ownership or administrative control.",
        caveat="Privacy proxies and registrar aliases make this less common and sometimes noisy.",
        base_importance="strong",
    ),
    "whois.registrar": EvidenceDefinition(
        path="whois.registrar",
        label="Shared registrar",
        category="Registration",
        description="Both targets used the same registrar.",
        why_it_matters="It can support other evidence when the rest of the pattern lines up.",
        caveat="Registrars are widely shared and are weak by themselves.",
        base_importance="low-signal",
    ),
    "dns.NS": EvidenceDefinition(
        path="dns.NS",
        label="Shared nameserver",
        category="DNS",
        description="Both targets delegated to the same nameserver hostname.",
        why_it_matters="Custom or vanity nameserver overlap can reflect the same operator.",
        caveat="Commodity provider nameservers are weak and often shared across many customers.",
        base_importance="supporting",
    ),
    "nameserver_analysis.vanity_apexes": EvidenceDefinition(
        path="nameserver_analysis.vanity_apexes",
        label="Shared vanity nameserver apex",
        category="DNS",
        description="Both targets used the same non-generic nameserver apex.",
        why_it_matters="Vanity nameservers are often more distinctive than commodity DNS hosting.",
        caveat="Some resellers or white-label platforms still share these values.",
        base_importance="supporting",
    ),
    "txt_verification_tokens": EvidenceDefinition(
        path="txt_verification_tokens",
        label="Shared TXT verification token",
        category="Identity",
        description="Both targets exposed the same TXT verification token.",
        why_it_matters="Verification tokens often point to the same SaaS or account ownership.",
        caveat="Some provisioning workflows can accidentally reuse them across related properties.",
        base_importance="strong",
    ),
    "email_security.dmarc_report_uris": EvidenceDefinition(
        path="email_security.dmarc_report_uris",
        label="Shared DMARC report recipient",
        category="Email policy",
        description="Both targets sent DMARC reports to the same mailbox.",
        why_it_matters="Shared reporting inboxes often indicate the same mail administration team.",
        caveat="Managed providers or MSSPs can centralize reports for multiple clients.",
        base_importance="supporting",
    ),
    "email_security.spf_includes": EvidenceDefinition(
        path="email_security.spf_includes",
        label="Shared SPF include",
        category="Email policy",
        description="Both targets referenced the same SPF include.",
        why_it_matters="It can connect the same mail provider stack or sending setup.",
        caveat="Large mail providers are widely shared, so this is usually supporting only.",
        base_importance="supporting",
    ),
    "email_security.dkim_selectors": EvidenceDefinition(
        path="email_security.dkim_selectors",
        label="Shared DKIM selector",
        category="Email policy",
        description="Both targets exposed the same DKIM selector name.",
        why_it_matters="Matching selectors can tie domains to the same mail tooling or operator habits.",
        caveat="Common default selectors are not unique.",
        base_importance="supporting",
    ),
    "microsoft_tenant.tenant_guid": EvidenceDefinition(
        path="microsoft_tenant.tenant_guid",
        label="Shared Microsoft tenant GUID",
        category="SaaS identity",
        description="Both targets pointed to the same Microsoft Entra tenant.",
        why_it_matters="A shared tenant GUID is a very strong common-administration signal.",
        caveat="It mainly speaks to administrative linkage, not necessarily the same infrastructure.",
        base_importance="decisive",
    ),
    "mail_client_config.servers": EvidenceDefinition(
        path="mail_client_config.servers",
        label="Shared mail client server",
        category="Email operations",
        description="Both targets published the same mail client configuration server hostname.",
        why_it_matters="Shared autodiscover or autoconfig endpoints can reveal common backend operations.",
        caveat="Hosted mail providers can make this common across unrelated tenants.",
        base_importance="supporting",
    ),
    "mail_client_config.domains": EvidenceDefinition(
        path="mail_client_config.domains",
        label="Shared mail config domain",
        category="Email operations",
        description="Both targets referenced the same mail configuration domain.",
        why_it_matters="This can connect the same mail deployment or control plane.",
        caveat="Mail providers can reuse domains widely.",
        base_importance="supporting",
    ),
    "legal_pages.entity_names": EvidenceDefinition(
        path="legal_pages.entity_names",
        label="Shared legal entity",
        category="Identity",
        description="Both targets exposed the same legal entity name in a legal or contact page.",
        why_it_matters="Entity names can be a direct ownership or operating-company signal.",
        caveat="Parsing can be noisy and some names are generic or partner-related.",
        base_importance="strong",
    ),
    "legal_pages.registration_ids": EvidenceDefinition(
        path="legal_pages.registration_ids",
        label="Shared registration ID",
        category="Identity",
        description="Both targets exposed the same company or registration identifier.",
        why_it_matters="Registration IDs are usually high-confidence ownership indicators.",
        caveat="Poor extraction or copied policies can introduce errors.",
        base_importance="decisive",
    ),
    "well_known.security_contacts": EvidenceDefinition(
        path="well_known.security_contacts",
        label="Shared security.txt contact",
        category="Well-known files",
        description="Both targets published the same `security.txt` contact.",
        why_it_matters="Security contact reuse can reflect the same organization or response team.",
        caveat="Bug bounty vendors or managed service providers can centralize these contacts.",
        base_importance="supporting",
    ),
    "well_known.assetlinks_packages": EvidenceDefinition(
        path="well_known.assetlinks_packages",
        label="Shared Android asset links package",
        category="Well-known files",
        description="Both targets referenced the same Android application package.",
        why_it_matters="Shared mobile app linkage is often a direct brand or operator signal.",
        caveat="White-label app bundles can weaken uniqueness.",
        base_importance="strong",
    ),
    "well_known.ads_txt_publishers": EvidenceDefinition(
        path="well_known.ads_txt_publishers",
        label="Shared ads.txt publisher",
        category="Well-known files",
        description="Both targets exposed the same ads.txt publisher ID.",
        why_it_matters="Monetization identifiers can connect related properties.",
        caveat="Resellers and shared ad operations can introduce noise.",
        base_importance="supporting",
    ),
    "tls_certs.probes[*].cn": EvidenceDefinition(
        path="tls_certs.probes[*].cn",
        label="Shared certificate name",
        category="Transport",
        description="Both targets served TLS certificates issued for the same name.",
        why_it_matters="Certificates naming the same host suggest shared or migrated infrastructure.",
        caveat="Default or wildcard hosting certificates can repeat across unrelated customers.",
        base_importance="strong",
    ),
    "dns.AAAA": EvidenceDefinition(
        path="dns.AAAA",
        label="Shared IPv6 address",
        category="Infrastructure",
        description="Both targets resolved to the same IPv6 address.",
        why_it_matters="Current DNS overlap can show the same live hosting or routing destination.",
        caveat="Popular hosting providers can place unrelated sites on the same address pool.",
        base_importance="strong",
    ),
    "crt_sh.certs[*].id": EvidenceDefinition(
        path="crt_sh.certs[*].id",
        label="Shared certificate-transparency entry",
        category="Transport",
        description="Both targets appeared on the same logged certificate.",
        why_it_matters="Domains listed on one certificate were requested together by the same operator.",
        caveat="Hosting providers sometimes bundle many customer domains on one certificate.",
        base_importance="strong",
    ),
    "censys.hits[*].ip": EvidenceDefinition(
        path="censys.hits[*].ip",
        label="Shared Censys host",
        category="Infrastructure",
        description="Both targets were observed on the same host in Censys scan data.",
        why_it_matters="Internet-wide scan overlap supports a shared hosting footprint.",
        caveat="Scan observations can be historical or reflect shared platforms.",
        base_importance="supporting",
    ),
    "shodan.hits[*].ip": EvidenceDefinition(
        path="shodan.hits[*].ip",
        label="Shared Shodan host",
        category="Infrastructure",
        description="Both targets were observed on the same host in Shodan scan data.",
        why_it_matters="Internet-wide scan overlap supports a shared hosting footprint.",
        caveat="Scan observations can be historical or reflect shared platforms.",
        base_importance="supporting",
    ),
    "netlas.hits[*].ip": EvidenceDefinition(
        path="netlas.hits[*].ip",
        label="Shared Netlas host",
        category="Infrastructure",
        description="Both targets were observed on the same host in Netlas scan data.",
        why_it_matters="Internet-wide scan overlap supports a shared hosting footprint.",
        caveat="Scan observations can be historical or reflect shared platforms.",
        base_importance="supporting",
    ),
    "dns.MX[*].exchange": EvidenceDefinition(
        path="dns.MX[*].exchange",
        label="Shared mail server",
        category="Email operations",
        description="Both targets route mail through the same mail server hostname.",
        why_it_matters="It can support other evidence when the mail setup is distinctive.",
        caveat="Large mail providers serve millions of unrelated domains, so this is weak alone.",
        base_importance="low-signal",
    ),
    "whois.creation_date": EvidenceDefinition(
        path="whois.creation_date",
        label="Same registration date",
        category="Registration",
        description="Both domains were registered on the same date.",
        why_it_matters="Coordinated campaigns often register batches of domains together.",
        caveat="Any two domains can coincidentally share a registration date.",
        base_importance="supporting",
    ),
    "whois.country": EvidenceDefinition(
        path="whois.country",
        label="Same registration country",
        category="Registration",
        description="Both domains list the same registrant country.",
        why_it_matters="It adds light context when stronger evidence already points the same way.",
        caveat="Country alone is shared by huge numbers of unrelated domains.",
        base_importance="low-signal",
    ),
    "dns.SOA.rname": EvidenceDefinition(
        path="dns.SOA.rname",
        label="Shared DNS admin contact",
        category="DNS",
        description="Both zones list the same administrative contact in their SOA record.",
        why_it_matters="A shared zone contact can indicate the same DNS administrator.",
        caveat="DNS hosting providers set this to a provider-wide value for all customers.",
        base_importance="low-signal",
    ),
    "dns.SOA.serial": EvidenceDefinition(
        path="dns.SOA.serial",
        label="Identical DNS zone serial",
        category="DNS",
        description="Both zones report the same serial number.",
        why_it_matters="Identical serials can hint at zones managed and updated together.",
        caveat="Date-based serials collide naturally across unrelated zones.",
        base_importance="low-signal",
    ),
    "crt_sh.issuers": EvidenceDefinition(
        path="crt_sh.issuers",
        label="Same certificate authority",
        category="Transport",
        description="Both targets obtained certificates from the same authority.",
        why_it_matters="It is only meaningful alongside stronger certificate evidence.",
        caveat="A handful of free authorities issue most certificates on the internet.",
        base_importance="low-signal",
    ),
    "page_metadata.fb_app_id": EvidenceDefinition(
        path="page_metadata.fb_app_id",
        label="Shared Facebook app ID",
        category="Web identity",
        description="Both sites embed the same Facebook application ID.",
        why_it_matters="App IDs are tied to a developer account, often the same operator.",
        caveat="Shared themes or plugins can carry an app ID along.",
        base_importance="supporting",
    ),
    "page_metadata.authors": EvidenceDefinition(
        path="page_metadata.authors",
        label="Shared author name",
        category="Identity",
        description="Both sites credit the same author in page metadata.",
        why_it_matters="Recurring bylines can connect content operations.",
        caveat="Common names and syndicated content create false positives.",
        base_importance="supporting",
    ),
    "page_metadata.rel_me": EvidenceDefinition(
        path="page_metadata.rel_me",
        label="Shared linked profile",
        category="Identity",
        description="Both sites declare the same verified profile link.",
        why_it_matters="rel=me links are deliberate, operator-controlled identity claims.",
        caveat="Copied templates can carry stale profile links.",
        base_importance="supporting",
    ),
}


# ── Correlation-layer base weights ──────────────────────────────────────────
#
# Per-selector-kind base weights for the graph linkage engine (utils/check.py).
# These encode the strongest→weakest ordering the product has always had — exact
# current TLS fingerprint > dedicated shared IP > … > bare ASN — as numbers. The
# graph scorer multiplies a base weight by an inverse-frequency (rarity) factor
# and a time-overlap factor; the base weight is the per-kind ceiling, rarity and
# overlap only ever attenuate it. Edit these (then global-recompute) to retune.

# Readable strength tiers map onto the same scale `score_matches` uses, so the
# pairwise and graph paths stay comparable.
IMPORTANCE_TIER_WEIGHTS: dict[str, float] = {
    "decisive": 100.0,
    "strong": 70.0,
    "supporting": 40.0,
    "low-signal": 15.0,
}

# "shared_ip" is a pseudo-kind: a shared `ip` entity that two domains both
# resolve to is scored like a selector (a CDN-free dedicated IP is strong).
SELECTOR_BASE_WEIGHTS: dict[str, float] = {
    "tls_cert_sha256": 100.0,   # exact current leaf cert — decisive
    "ssh_fp": 95.0,             # shared SSH host key — decisive
    "shared_ip": 85.0,          # dedicated shared origin IP — strong+
    "tls_spki": 80.0,           # shared public-key (SPKI) reuse — strong
    "tracking_id": 70.0,        # GA/GTM/pixel/AdSense — strong (operator account)
    "html_hash": 45.0,          # identical homepage body — supporting+
    "favicon_mmh3": 45.0,       # favicon fingerprint — supporting
    "favicon_md5": 40.0,        # favicon md5 — supporting
    "tls_san": 40.0,            # cert names overlap (not full fp) — supporting
    "network_cidr": 30.0,       # same network block — supporting-
    "nameserver": 25.0,         # shared nameserver — supporting-
    "asn": 15.0,                # bare ASN — low-signal
}

_DEFAULT_SELECTOR_WEIGHT = 40.0


def selector_base_weight(kind: str) -> float:
    """Base (pre-rarity, pre-overlap) weight for a selector kind / shared node."""
    return SELECTOR_BASE_WEIGHTS.get(str(kind or ""), _DEFAULT_SELECTOR_WEIGHT)


def _label_from_path(path: str) -> str:
    """Derive a readable label from a dot-path, e.g.
    'page_metadata.script_urls' -> 'Shared script urls'."""
    leaf = path.split(".")[-1].replace("[*]", "").replace("_", " ").strip()
    return f"Shared {leaf}" if leaf else "Shared signal"


def evidence_definition(path: str) -> EvidenceDefinition:
    known = EVIDENCE_DEFINITIONS.get(path)
    if known is not None:
        return known
    return EvidenceDefinition(
        path=path,
        label=_label_from_path(path),
        category="Other",
        description="Both targets shared the same value for this attribute.",
        why_it_matters="Any overlap can add context when it aligns with stronger evidence.",
        caveat="This attribute is not in the curated catalog, so treat it as supporting context.",
        base_importance="supporting",
    )


def evidence_catalog() -> list[dict[str, Any]]:
    return [
        {
            "type": definition.path,
            "label": definition.label,
            "category": definition.category,
            "description": definition.description,
            "why_it_matters": definition.why_it_matters,
            "caveat": definition.caveat,
            "importance": definition.base_importance,
        }
        for definition in EVIDENCE_DEFINITIONS.values()
    ]
