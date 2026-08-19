import { memo, useState } from "react";
import { Badge, Card, ProgressBar, Text, View } from "reshaped";

import {
  formatDate,
  formatLabel,
  formatNumber,
  formatPercent,
} from "../api.js";
import { EmptyState } from "../components/primitives.jsx";

const STRENGTH_TIERS = {
  strong: { tier: "strong", label: "Strong link", color: "positive" },
  moderate: { tier: "moderate", label: "Moderate link", color: "warning" },
  weak: { tier: "weak", label: "Weak link", color: "neutral" },
};

const SELECTOR_KIND_LABELS = {
  tls_cert_sha256: "TLS certificate fingerprint",
  tls_spki: "TLS public key (SPKI)",
  tls_san: "Certificate SAN",
  shared_ip: "Shared IP address",
  ssh_fp: "SSH host key",
  tracking_id: "Tracking / analytics ID",
  site_verification: "Site verification code",
  social_handle: "Social media handle",
  contact_phone: "Contact phone number",
  contact_email: "Contact email",
  crypto_wallet: "Crypto wallet address",
  legal_registration: "Company registration ID",
  legal_entity: "Legal entity name",
  legal_address: "Registered address",
  legal_text_hash: "Legal page content hash",
  favicon_mmh3: "Favicon fingerprint",
  favicon_md5: "Favicon hash",
  html_hash: "Homepage content hash",
  nameserver: "Nameserver",
  network_cidr: "Network block",
  spf_origin: "Mail sending origin (SPF)",
  asn: "ASN",
};

const IP_NETWORK_BADGES = {
  cdn: { label: "CDN / proxy edge", color: "neutral" },
  pool: { label: "Shared hosting pool", color: "warning" },
  origin: { label: "Likely origin server", color: "positive" },
};

const DOMAIN_TIER_COLORS = {
  1: "#b91c1c",
  2: "#ea580c",
  3: "#ca8a04",
  4: "#2563eb",
  5: "#64748b",
};

const FAVICON_KINDS = new Set(["favicon_mmh3", "favicon_md5"]);

// Kinds whose value is encoded "<prefix>|<value>" (provider, platform, chain).
// The backend normally splits this out into `subkind`; deriving it from the
// encoding is the fallback so a wallet never reads as raw "bitcoin|bc1q...".
const PREFIXED_VALUE_KINDS = new Set(["tracking_id", "site_verification", "social_handle", "crypto_wallet"]);

export function sharedNodeLabel(kind) {
  return SELECTOR_KIND_LABELS[kind] || formatLabel(kind);
}

export function ipNetworkBadge(network) {
  return IP_NETWORK_BADGES[network] || null;
}

export function linkStrength(link) {
  if (link?.strength && STRENGTH_TIERS[link.strength]) {
    return STRENGTH_TIERS[link.strength];
  }
  const value = link?.score ?? 0;
  if (value >= 65) {
    return STRENGTH_TIERS.strong;
  }
  if (value >= 30) {
    return STRENGTH_TIERS.moderate;
  }
  return STRENGTH_TIERS.weak;
}

export function TierBadge({ tier }) {
  if (!DOMAIN_TIER_COLORS[tier]) {
    return null;
  }
  // Tier 1-5 is an OpenCTI severity scale, not a UI state -- kept on its own
  // fixed hex palette (like ClusterGraph's DOMAIN_TIER_COLORS) rather than
  // Reshaped's 5-color semantic Badge palette, which doesn't have room for a
  // 5-step severity gradient. Badge is still used for consistent shape/sizing.
  return (
    <Badge
      attributes={{
        title: `OpenCTI tier ${tier} (1 = highest priority)`,
        style: { background: DOMAIN_TIER_COLORS[tier], color: "#fff" },
      }}
      size="small"
    >
      Tier {tier}
    </Badge>
  );
}

export function ProvenanceBadge({ ingested }) {
  return (
    <Badge
      attributes={{
        title: ingested
          ? "Directly submitted, or a subdomain of it was."
          : "Surfaced by following a scan: subdomain, sibling, or wordlist discovery.",
      }}
      color={ingested ? "positive" : "primary"}
      size="small"
      variant="faded"
    >
      {ingested ? "Ingested" : "Discovered"}
    </Badge>
  );
}

export function ConnectionStat({ count }) {
  return (
    <View direction="row" gap={1} align="baseline">
      <Text variant="body-1" weight="bold">
        {formatNumber(count)}
      </Text>
      <Text color="neutral-faded" variant="body-2">
        {count === 1 ? "connection" : "connections"}
      </Text>
    </View>
  );
}

export const FaviconThumb = memo(function FaviconThumb({ kind, value }) {
  const [failed, setFailed] = useState(false);
  if (!FAVICON_KINDS.has(kind) || !value || failed) {
    return null;
  }
  return (
    <img
      alt=""
      className="favicon-thumb"
      loading="lazy"
      onError={() => setFailed(true)}
      src={`/api/favicon/${encodeURIComponent(kind)}/${encodeURIComponent(value)}`}
    />
  );
});

function sharedNodeDisplay(node) {
  const separator = String(node.value).indexOf("|");
  const subkind =
    node.subkind || (PREFIXED_VALUE_KINDS.has(node.kind) && separator > 0 ? node.value.slice(0, separator) : null);
  const label = subkind ? `${sharedNodeLabel(node.kind)} · ${formatLabel(subkind)}` : sharedNodeLabel(node.kind);
  const prefix = subkind ? `${subkind}|` : null;
  const value = prefix && node.value.startsWith(prefix) ? node.value.slice(prefix.length) : node.value;
  return { label, value };
}

function extraHosts(label, hosts) {
  return (hosts || []).filter((host) => host && host !== label);
}

function formatWindow(range) {
  const [first, last] = range || [];
  if (!first && !last) {
    return "window unknown";
  }
  if (first && last && first !== last) {
    return `${formatDate(first)} → ${formatDate(last)}`;
  }
  return formatDate(first || last);
}

// Client-side "expired/valid" read of a tls_cert_sha256 node's own
// not_after (the CA-issued expiry, not our scan history) — a quick visual
// flag next to "noise"/"aging" so an investigator doesn't have to parse the
// validity-window caption to know if the certificate is still alive.
function certExpiryBadge(node) {
  if (node.kind !== "tls_cert_sha256" || !node.certNotAfter) {
    return null;
  }
  const notAfter = new Date(node.certNotAfter);
  if (Number.isNaN(notAfter.getTime())) {
    return null;
  }
  const expired = notAfter.getTime() < Date.now();
  return (
    <Badge color={expired ? "critical" : "positive"} size="small" variant="faded">
      {expired ? "cert expired" : "cert valid"}
    </Badge>
  );
}

function InfoBadge({ title, children }) {
  return (
    <Badge attributes={{ title }} color="neutral" size="small" variant="faded">
      {children}
    </Badge>
  );
}

const SharedNodeList = memo(function SharedNodeList({ evidence, leftLabel, rightLabel }) {
  if (!evidence || evidence.length === 0) {
    return <EmptyState message="No shared attributing nodes; the connection is unsupported." />;
  }
  return (
    <View as="ul" gap={3} attributes={{ style: { listStyle: "none", padding: 0, margin: 0 } }}>
      {evidence.map((node) => {
        const badge = node.kind === "shared_ip" ? ipNetworkBadge(node.network) : null;
        const { label, value } = sharedNodeDisplay(node);
        const extraA = extraHosts(leftLabel, node.hostsA);
        const extraB = extraHosts(rightLabel, node.hostsB);
        return (
          <View as="li" key={node.id}>
            <Card padding={3}>
              <View gap={2}>
                <View align="center" direction="row" gap={2} wrap>
                  <Text weight="semibold">{label}</Text>
                  {badge ? (
                    <Badge color={badge.color} size="small" variant="faded">
                      {badge.label}
                    </Badge>
                  ) : null}
                  {node.attributing === false ? (
                    <Badge color="critical" size="small" variant="faded">
                      noise
                    </Badge>
                  ) : null}
                  {node.degraded ? (
                    <Badge attributes={{ title: "Discounted for being common and/or stale — see the note below" }} color="warning" size="small" variant="faded">
                      aging
                    </Badge>
                  ) : null}
                  {certExpiryBadge(node)}
                </View>
                <View align="center" direction="row" gap={1} wrap>
                  <FaviconThumb kind={node.kind} value={node.value} />
                  <Badge attributes={{ title: node.value }} color="primary" size="small" variant="faded">
                    {value}
                  </Badge>
                  {node.degree !== null && node.degree !== undefined ? (
                    <InfoBadge title="Entities that share this node (lower is rarer)">degree {node.degree}</InfoBadge>
                  ) : null}
                  {node.baseWeight !== null && node.baseWeight !== undefined ? (
                    <InfoBadge title="Starting weight for this evidence kind, before rarity/overlap/recency attenuate it">base {node.baseWeight}</InfoBadge>
                  ) : null}
                  {node.rarity !== null && node.rarity !== undefined ? (
                    <InfoBadge title="Inverse-frequency factor from degree — 1.0 is as rare as it gets, decays toward 0 the more entities share it">rarity {node.rarity}</InfoBadge>
                  ) : null}
                  {node.weight !== null && node.weight !== undefined ? (
                    <InfoBadge title="base x rarity x time-overlap x recency — the final contribution to the link's score">weight {Math.round(node.weight)}</InfoBadge>
                  ) : null}
                  {node.timeOverlap !== null && node.timeOverlap !== undefined ? (
                    <InfoBadge title="Time-window overlap factor — do the two sides' own sighting windows agree with each other">overlap {node.timeOverlap}</InfoBadge>
                  ) : null}
                  {node.recency !== null && node.recency !== undefined && node.recency < 1 ? (
                    <InfoBadge title="Staleness factor — how long ago this was last seen at all, regardless of overlap (lower = older)">recency {node.recency}</InfoBadge>
                  ) : null}
                  {node.asnDesc ? <InfoBadge title="Network operator">{node.asnDesc}</InfoBadge> : null}
                  {node.networkName ? <InfoBadge title="RDAP network name">{node.networkName}</InfoBadge> : null}
                  {node.proxyFamily ? (
                    <InfoBadge title="Detected reverse-proxy family">{node.proxyFamily}</InfoBadge>
                  ) : null}
                </View>
                {node.explanation ? (
                  <Text color="neutral-faded" variant="caption-1">
                    {node.explanation}
                  </Text>
                ) : null}
                {node.kind === "tls_cert_sha256" && (node.certCn || node.certIssuerCn || node.certNotAfter) ? (
                  <View gap={1}>
                    {node.certCn ? (
                      <Text color="neutral-faded" variant="caption-1">
                        Certificate CN: <Text weight="medium">{node.certCn}</Text>
                      </Text>
                    ) : null}
                    {node.certIssuerCn || node.certIssuerOrg ? (
                      <Text color="neutral-faded" variant="caption-1">
                        Issued by: <Text weight="medium">{[node.certIssuerOrg, node.certIssuerCn].filter(Boolean).join(" — ")}</Text>
                      </Text>
                    ) : null}
                    {node.certNotBefore || node.certNotAfter ? (
                      <Text color="neutral-faded" variant="caption-1">
                        Certificate validity: <Text weight="medium">{formatWindow([node.certNotBefore, node.certNotAfter])}</Text>
                        {" "}(the certificate's own issued/expiry dates — not when we last scanned it)
                      </Text>
                    ) : null}
                  </View>
                ) : null}
                {extraA.length > 0 || extraB.length > 0 ? (
                  <View gap={1}>
                    {extraA.length > 0 ? (
                      <View align="center" direction="row" gap={2} wrap>
                        <Text color="neutral-faded" variant="caption-1">
                          Actually via <Text weight="bold">{leftLabel}</Text>
                        </Text>
                        {extraA.map((host) => (
                          <Badge color="neutral" key={host} size="small" variant="faded">
                            {host}
                          </Badge>
                        ))}
                      </View>
                    ) : null}
                    {extraB.length > 0 ? (
                      <View align="center" direction="row" gap={2} wrap>
                        <Text color="neutral-faded" variant="caption-1">
                          Actually via <Text weight="bold">{rightLabel}</Text>
                        </Text>
                        {extraB.map((host) => (
                          <Badge color="neutral" key={host} size="small" variant="faded">
                            {host}
                          </Badge>
                        ))}
                      </View>
                    ) : null}
                  </View>
                ) : null}
                <Text color="neutral-faded" variant="caption-1">
                  {leftLabel || "A"}: {formatWindow(node.windowA)} · {rightLabel || "B"}: {formatWindow(node.windowB)}
                  {node.sources?.length ? ` · via ${node.sources.join(", ")}` : " · source unknown"}
                </Text>
              </View>
            </Card>
          </View>
        );
      })}
    </View>
  );
});

// `toggleKey` identifies the *pair*. Defaulting to the right-hand side alone
// collided: selecting [x, y, z] returns (x,y) (x,z) (y,z), and the last two
// share b === z — so clicking one expanded both, each showing the other's
// evidence under the wrong heading. Callers that render a full pair matrix
// pass an explicit key; the single-anchor lists can keep the old identity.
export const ConnectionCard = memo(function ConnectionCard({
  link,
  expanded,
  onToggle,
  toggleKey,
  leftLabel,
  rightLabel,
}) {
  const strength = linkStrength(link);
  const barValue = Math.max(4, Math.min(100, link.confidence ?? 0));
  const topKinds = [...new Set((link.evidence || []).map((node) => sharedNodeLabel(node.kind)))].slice(0, 3);
  const heading = rightLabel ? `${leftLabel} ↔ ${rightLabel}` : link.target;
  const key = toggleKey ?? link.b ?? link.target;

  return (
    <Card
      attributes={{ "aria-expanded": expanded }}
      onClick={(event) => {
        // These cards nest inside other clickable cards (a hop chain inside an
        // expanded connection). Without this the inner toggle also bubbles to
        // the outer one, collapsing the chain the user just opened.
        event?.stopPropagation?.();
        onToggle(key);
      }}
      padding={4}
      selected={expanded}
    >
      <View align="center" direction="row" gap={4}>
        <View align="center" attributes={{ style: { minWidth: 108 } }} gap={1}>
          <Text variant="title-3" weight="bold">
            {formatPercent(link.confidence)}
          </Text>
          <Badge color={strength.color} size="small">
            {strength.label}
          </Badge>
        </View>
        <View gap={2} grow>
          <Text weight="semibold">{heading}</Text>
          <Text color="neutral-faded" variant="body-2">
            {(link.evidence || []).length} shared node{(link.evidence || []).length === 1 ? "" : "s"} · score{" "}
            {Math.round(link.score ?? 0)}
          </Text>
          {topKinds.length > 0 ? (
            <View direction="row" gap={1} wrap>
              {topKinds.map((name) => (
                <Badge color="primary" key={name} size="small" variant="faded">
                  {name}
                </Badge>
              ))}
            </View>
          ) : null}
          <ProgressBar color={strength.color} size="small" value={barValue} />
        </View>
        <Text attributes={{ "aria-hidden": true }} color="neutral-faded">
          {expanded ? "▴" : "▾"}
        </Text>
      </View>
      {expanded ? (
        <View attributes={{ style: { marginTop: 20 } }}>
          {/* leftLabel/rightLabel are always passed explicitly by every call
              site -- normalizeGraphLink never sets link.a/link.b, so those
              were dead fallbacks (see the Reshaped-migration card audit). */}
          <SharedNodeList evidence={link.evidence} leftLabel={leftLabel || "seed"} rightLabel={rightLabel || link.target} />
        </View>
      ) : null}
    </Card>
  );
});
