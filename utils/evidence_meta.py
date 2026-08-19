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
    "page_metadata.crypto_wallet_values": EvidenceDefinition(
        path="page_metadata.crypto_wallet_values",
        label="Shared crypto wallet address",
        category="Identity",
        description="Both targets solicit payment to the same cryptocurrency address.",
        why_it_matters="A wallet is controlled by whoever holds its key, so funds from both sites land with one operator.",
        caveat="A copycat or scraper can republish someone else's donation address verbatim.",
        base_importance="decisive",
    ),
    "page_metadata.phone_numbers": EvidenceDefinition(
        path="page_metadata.phone_numbers",
        label="Shared contact phone number",
        category="Identity",
        description="Both targets publish the same contact telephone number.",
        why_it_matters="A number someone has to answer usually points back to a single back office.",
        caveat="Shared call centres, franchise networks, and template placeholder numbers repeat across unrelated sites.",
        base_importance="strong",
    ),
    "legal_pages.emails": EvidenceDefinition(
        path="legal_pages.emails",
        label="Shared imprint email",
        category="Identity",
        description="Both targets published the same contact email on a legal or imprint page.",
        why_it_matters="A contact mailbox is account-bound and read by whoever operates the site.",
        caveat="A shared agency or outsourced support desk can answer for several unrelated clients.",
        base_importance="strong",
    ),
    "legal_pages.addresses": EvidenceDefinition(
        path="legal_pages.addresses",
        label="Shared registered address",
        category="Identity",
        description="Both targets published the same postal address on a legal or imprint page.",
        why_it_matters="A shared office can place two operations under one roof.",
        caveat="Registered-agent services, accountants, and coworking suites front for thousands of unrelated companies.",
        base_importance="supporting",
    ),
    "legal_pages.phones": EvidenceDefinition(
        path="legal_pages.phones",
        label="Shared imprint phone number",
        category="Identity",
        description="Both targets published the same telephone number on a legal or imprint page.",
        why_it_matters="An imprint number is disclosed to satisfy a legal requirement, so it points at the operating entity itself.",
        caveat="Agencies and hosting resellers sometimes file their own number on behalf of every client site.",
        base_importance="strong",
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
    "whois.name": EvidenceDefinition(
        path="whois.name",
        label="Shared WHOIS registrant name",
        category="Registration",
        description="Both targets named the same registrant in WHOIS.",
        why_it_matters="A registrant name is an explicit ownership claim, and an unusual one rarely repeats by chance.",
        caveat="Redacted and privacy-service placeholders are dropped; common personal names can still collide.",
        base_importance="strong",
    ),
    "spf_origins": EvidenceDefinition(
        path="spf_origins",
        label="Shared SPF sending origin",
        category="Infrastructure",
        description="Both targets authorise the same server to send their email.",
        why_it_matters="A self-hosted or dedicated mail origin usually means one operator runs the mail for both.",
        caveat="Most domains delegate to a handful of large providers, which is close to noise on its own.",
        base_importance="supporting",
    ),
    "historical_dns.records[*].rdata": EvidenceDefinition(
        path="historical_dns.records[*].rdata",
        label="Shared historical IP",
        category="Infrastructure",
        description="Both targets resolved to the same address at some point in the past.",
        why_it_matters="Past co-location catches an operator who has since moved hosting, which current DNS misses.",
        caveat="Weighted down by age, and old shared hosting can put unrelated sites on one address.",
        base_importance="supporting",
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
    "censys.hits[*].cert_fingerprint_sha256": EvidenceDefinition(
        path="censys.hits[*].cert_fingerprint_sha256",
        label="Shared certificate (Censys-observed)",
        category="Transport",
        description="Censys observed both targets' hosts serving the same leaf TLS certificate.",
        why_it_matters=(
            "Byte-identical certificates point at one operator provisioning both, and this "
            "reaches hosts our own TLS probe cannot — ones that refuse our connection or fall "
            "outside the probe cap."
        ),
        caveat=(
            "Ranks below a directly probed fingerprint: the search returns the fingerprint "
            "without the certificate body, so the shared-default-vhost check that qualifies "
            "our own cert matches cannot run on it."
        ),
        base_importance="strong",
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
#
# tls_cert_sha256 sits above the nominal 100 "decisive" reference point
# (IMPORTANCE_TIER_WEIGHTS["decisive"]) on purpose: utils.check.rarity_weight
# decays as 1/log2(degree), so even a base of 100 falls under the graph's
# decisive-strength cutoff (weight >= 50, see utils.check._graph_strength)
# once a cert is shared by more than ~4 entities — which punishes the exact
# case this selector exists to catch, one operator's own small portfolio of
# sites reusing the same cert (10-15 domains is a completely normal size for
# that, not noise). 200 keeps a single match decisive up to ~degree 15 while
# the hard denylist (CORRELATION_DEGREE_THRESHOLD, default 50) still catches
# genuinely-shared-hosting-scale reuse regardless of this weight. Retune
# alongside TRACKING_SUBKIND_WEIGHTS's near-identity entries below if the
# survivable degree needs to move.
#
# crypto_wallet gets the same >100 headroom as tls_cert_sha256 and
# adsense_publisher, and for the same structural reason: an address is a public
# key whose funds only one keyholder can spend, so two sites collecting payment
# to it are one operation by definition — and the case that most needs to
# survive rarity decay is exactly the one where a wallet is reused across a
# fundraising/scam network's whole spread of front sites. At 185 a match stays
# above the decisive cutoff to roughly degree 13, which covers that spread,
# while genuinely promiscuous reuse still trips CORRELATION_DEGREE_THRESHOLD.
# It sits just *below* adsense_publisher because a wallet address is plain
# copyable page text — an impersonator or scraper can republish someone else's
# donation address and manufacture the match, whereas a publisher ID has to be
# minted by Google for the account that gets paid.
#
# legal_registration gets headroom for the same reason as crypto_wallet: a
# company registration number is issued by a state registry to exactly one
# legal entity, so two sites publishing the same one are declaring the same
# company — and the case that must survive rarity decay is one operating
# company standing behind a spread of trading names. It sits below
# crypto_wallet because extraction reads it out of free imprint prose (see
# signal_web._extract_registration_ids, which is why only structured ID tokens
# on registration-labelled lines are accepted) rather than off a validated
# checksum, so a parse error is the realistic failure mode here.
#
# legal_entity and legal_address are the same disclosure but far softer.
# Company names collide across unrelated firms ("Digital Media Ltd") and
# addresses are routinely a registered-agent, accountant, or coworking suite
# shared by thousands of companies — noise that scales *with* degree, so like
# contact_phone they are left below 100 to let rarity decay bite early.
# legal_address sits under legal_entity because the shared-mailbox story is
# the more common one.
#
# legal_text_hash is an exact hash of the normalized text of a legal page, so
# it only fires on a byte-identical policy — either one operator publishing
# the same document twice, or one site copying another's. Generator-produced
# policies (iubenda, Termly, ...) are the false-positive source and they are
# common, so it is pinned at html_hash's weight: the same "identical page
# body" class of evidence, and no stronger.
#
# contact_email is the strongest of the imprint set after the registration id:
# a mailbox is account-bound and someone has to read it. Provider and
# privacy-proxy role addresses are the noise source and they are filtered out
# before a selector is ever written (utils.check._is_generic_email), so what
# reaches scoring is an operator-chosen address.
#
# contact_phone is deliberately denied that headroom despite being a real
# operational tie. Its noise sources — outsourced call centres, franchise and
# reseller networks, and copy-paste template/placeholder numbers — all scale
# *with* degree rather than being independent of it, so rarity decay is the
# right correction here and we want it to bite early. At 60 a phone shared by
# two sites is strong corroboration (above social_handle: you can register a
# handle for free, a live number has to be answered) but drops out of decisive
# strength at degree 3, which is where the shared-switchboard explanation
# starts to compete with the shared-operator one.
SELECTOR_BASE_WEIGHTS: dict[str, float] = {
    "tls_cert_sha256": 200.0,   # exact current leaf cert — decisive, see note above
    "ssh_fp": 95.0,             # shared SSH host key — decisive
    "site_verification": 92.0,  # webmaster-tools verification code — near-decisive
    "shared_ip": 85.0,          # dedicated shared origin IP — strong+
    "tls_spki": 80.0,           # shared public-key (SPKI) reuse — strong
    "tracking_id": 70.0,        # GA/GTM/pixel/AdSense — see TRACKING_SUBKIND_WEIGHTS
    "crypto_wallet": 185.0,     # same payment wallet — near-identity, see note above
    "legal_registration": 165.0,  # same company registration id — near-identity, see note above
    "contact_email": 88.0,      # same operator-chosen contact mailbox — strong+
    "legal_entity": 68.0,       # same legal/company name — strong-, see note above
    "contact_phone": 60.0,      # same published phone number — strong-, see note above
    "legal_address": 46.0,      # same registered/postal address — supporting, see note above
    "legal_text_hash": 45.0,    # byte-identical legal page text — supporting+
    "social_handle": 55.0,      # same social handle (Telegram/VK/Instagram/…) — strong-
    "html_hash": 45.0,          # identical homepage body — supporting+
    "favicon_mmh3": 45.0,       # favicon fingerprint — supporting
    "favicon_md5": 40.0,        # favicon md5 — supporting
    "tls_san": 40.0,            # cert names overlap (not full fp) — supporting
    "network_cidr": 30.0,       # same network block — supporting-
    "spf_origin": 30.0,         # same authorised mail sender — supporting-, see note below
    "nameserver": 25.0,         # shared nameserver — supporting-
    "asn": 15.0,                # bare ASN — low-signal
}

# `spf_origin` sits level with network_cidr rather than higher: the overwhelming
# majority of domains authorise one of a few large providers (Google, Microsoft,
# SendGrid), so the kind is high-degree by construction and most matches carry
# almost no information. That is handled the same way it is for `asn` — degree
# denylisting plus rarity_weight collapse the common blocks automatically — and
# what survives is the case worth having: two sites authorising the same
# self-hosted mail origin, which is a real operational tie.

# `tracking_id` is a single selector kind whose value is prefixed with the
# provider (see _TRACKING_SELECTOR_MAP in db.intel_db), so we grade it per
# provider rather than with one flat weight. The split turns on how tightly the
# ID binds to a single operator account vs. how routinely it is reused across
# unrelated sites:
#   - AdSense publisher IDs bind to a Google *payment* account — near-identity.
#   - GA properties / ad pixels bind to one analytics/ad account — strong.
#   - GTM containers are routinely reused by agencies across unrelated clients,
#     and a Facebook app ID rides along with shared themes/plugins — strong.
#
# adsense_publisher and ga_property are pushed well above 100 for the same
# reason as tls_cert_sha256 above: they're the two subkinds that genuinely
# bind to one operator's account (a publisher/analytics ID isn't something
# two unrelated sites end up sharing by accident, unlike a GTM container or
# ad pixel, which is why those two stay near their original weight instead).
# Without the headroom, an operator's own handful of properties sharing one
# GA/AdSense ID would fall under the graph's decisive-strength cutoff on
# rarity alone even though that's precisely the ownership signal this
# selector is meant to catch.
TRACKING_SUBKIND_WEIGHTS: dict[str, float] = {
    "adsense_publisher": 190.0,
    "ga_property": 170.0,
    "fb_pixel": 65.0,
    "yandex_metrika": 74.0,
    "tiktok_pixel": 55.0,
    "gtm_container": 45.0,
    "fb_app_id": 75.0,
}

_DEFAULT_SELECTOR_WEIGHT = 40.0


def selector_base_weight(kind: str, value: str | None = None) -> float:
    """Base (pre-rarity, pre-overlap) weight for a selector kind / shared node.

    `tracking_id` selectors are graded by their provider prefix (the value is
    stored as ``"<provider>|<id>"``); every other kind is a flat per-kind weight.
    """
    k = str(kind or "")
    if k == "tracking_id" and value:
        prefix = str(value).split("|", 1)[0]
        if prefix in TRACKING_SUBKIND_WEIGHTS:
            return TRACKING_SUBKIND_WEIGHTS[prefix]
    return SELECTOR_BASE_WEIGHTS.get(k, _DEFAULT_SELECTOR_WEIGHT)


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
