import { memo, useState } from "react";

import {
  formatDate,
  formatLabel,
  formatNumber,
  formatPercent,
} from "../api.js";
import { EmptyState } from "../components/primitives.jsx";

const STRENGTH_TIERS = {
  strong: { tier: "strong", label: "Strong link", tone: "success" },
  moderate: { tier: "moderate", label: "Moderate link", tone: "warning" },
  weak: { tier: "weak", label: "Weak link", tone: "neutral" },
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
  favicon_mmh3: "Favicon fingerprint",
  favicon_md5: "Favicon hash",
  html_hash: "Homepage content hash",
  nameserver: "Nameserver",
  network_cidr: "Network block",
  asn: "ASN",
};

const IP_NETWORK_BADGES = {
  cdn: { label: "CDN / proxy edge", tone: "neutral" },
  pool: { label: "Shared hosting pool", tone: "warning" },
  origin: { label: "Likely origin server", tone: "success" },
};

const DOMAIN_TIER_COLORS = {
  1: "#b91c1c",
  2: "#ea580c",
  3: "#ca8a04",
  4: "#2563eb",
  5: "#64748b",
};

const FAVICON_KINDS = new Set(["favicon_mmh3", "favicon_md5"]);

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
  return (
    <span
      className="chip"
      style={{ background: DOMAIN_TIER_COLORS[tier], color: "#fff", borderColor: "transparent" }}
      title={`OpenCTI tier ${tier} (1 = highest priority)`}
    >
      Tier {tier}
    </span>
  );
}

export function ProvenanceBadge({ ingested }) {
  return (
    <span
      className={`status-badge compact ${ingested ? "success" : "info"}`}
      title={
        ingested
          ? "Directly submitted, or a subdomain of it was."
          : "Surfaced by following a scan: subdomain, sibling, or wordlist discovery."
      }
    >
      {ingested ? "Ingested" : "Discovered"}
    </span>
  );
}

export function ConnectionStat({ count }) {
  return (
    <div className="connection-stat">
      <strong>{formatNumber(count)}</strong>
      <span>{count === 1 ? "connection" : "connections"}</span>
    </div>
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
  const label = node.subkind
    ? `${sharedNodeLabel(node.kind)} · ${formatLabel(node.subkind)}`
    : sharedNodeLabel(node.kind);
  const prefix = node.subkind ? `${node.subkind}|` : null;
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

const SharedNodeList = memo(function SharedNodeList({ evidence, leftLabel, rightLabel }) {
  if (!evidence || evidence.length === 0) {
    return <EmptyState message="No shared attributing nodes; the connection is unsupported." />;
  }
  return (
    <ul className="digest-items">
      {evidence.map((node) => {
        const badge = node.kind === "shared_ip" ? ipNetworkBadge(node.network) : null;
        const { label, value } = sharedNodeDisplay(node);
        const extraA = extraHosts(leftLabel, node.hostsA);
        const extraB = extraHosts(rightLabel, node.hostsB);
        return (
          <li className="digest-item" key={node.id}>
            <span className="digest-item-label">
              {label}
              {badge ? (
                <span className={`status-badge compact ${badge.tone}`} style={{ marginLeft: 8 }}>
                  {badge.label}
                </span>
              ) : null}
              {node.attributing === false ? (
                <span className="chip digest-more-chip" style={{ marginLeft: 8 }}>
                  noise
                </span>
              ) : null}
            </span>
            <span className="chip-row digest-item-values">
              <FaviconThumb kind={node.kind} value={node.value} />
              <span className="chip evidence-chip" title={node.value}>
                {value}
              </span>
              {node.degree !== null && node.degree !== undefined ? (
                <span className="chip" title="Entities that share this node (lower is rarer)">
                  degree {node.degree}
                </span>
              ) : null}
              {node.weight !== null && node.weight !== undefined ? (
                <span className="chip" title="base x rarity x time-overlap">
                  weight {Math.round(node.weight)}
                </span>
              ) : null}
              {node.timeOverlap !== null && node.timeOverlap !== undefined ? (
                <span className="chip" title="Time-window overlap factor">
                  overlap {node.timeOverlap}
                </span>
              ) : null}
              {node.asnDesc ? <span className="chip" title="Network operator">{node.asnDesc}</span> : null}
              {node.networkName ? (
                <span className="chip" title="RDAP network name">
                  {node.networkName}
                </span>
              ) : null}
              {node.proxyFamily ? (
                <span className="chip" title="Detected reverse-proxy family">
                  {node.proxyFamily}
                </span>
              ) : null}
            </span>
            {node.explanation ? (
              <span className="card-copy" style={{ fontSize: "0.85em" }}>
                {node.explanation}
              </span>
            ) : null}
            {extraA.length > 0 || extraB.length > 0 ? (
              <div className="host-attribution">
                {extraA.length > 0 ? (
                  <div className="host-attribution-row">
                    <span className="host-attribution-tag">Actually via</span>
                    <strong>{leftLabel}</strong>
                    <span className="chip-row">
                      {extraA.map((host) => (
                        <span className="chip host-chip" key={host}>
                          {host}
                        </span>
                      ))}
                    </span>
                  </div>
                ) : null}
                {extraB.length > 0 ? (
                  <div className="host-attribution-row">
                    <span className="host-attribution-tag">Actually via</span>
                    <strong>{rightLabel}</strong>
                    <span className="chip-row">
                      {extraB.map((host) => (
                        <span className="chip host-chip" key={host}>
                          {host}
                        </span>
                      ))}
                    </span>
                  </div>
                ) : null}
              </div>
            ) : null}
            <span className="card-copy" style={{ fontSize: "0.85em", opacity: 0.8 }}>
              {leftLabel || "A"}: {formatWindow(node.windowA)} · {rightLabel || "B"}: {formatWindow(node.windowB)}
              {node.sources?.length ? ` · via ${node.sources.join(", ")}` : " · source unknown"}
            </span>
          </li>
        );
      })}
    </ul>
  );
});

export const ConnectionCard = memo(function ConnectionCard({ link, expanded, onToggle, leftLabel, rightLabel }) {
  const strength = linkStrength(link);
  const barWidth = Math.max(4, Math.min(100, link.confidence ?? 0));
  const topKinds = [...new Set((link.evidence || []).map((node) => sharedNodeLabel(node.kind)))].slice(0, 3);
  const heading = rightLabel ? `${leftLabel} ↔ ${rightLabel}` : link.target;
  const key = link.b ?? link.target;

  return (
    <article className={`linkage-card ${expanded ? "expanded" : ""}`}>
      <button
        aria-expanded={expanded}
        className="linkage-card-main"
        onClick={() => onToggle(key)}
        type="button"
      >
        <span className="linkage-percent">
          <strong>{formatPercent(link.confidence)}</strong>
          <span className={`status-badge compact ${strength.tone}`}>{strength.label}</span>
        </span>
        <span className="linkage-body">
          <span className="linkage-domains">
            <strong>{heading}</strong>
          </span>
          <span className="card-copy linkage-reason">
            {(link.evidence || []).length} shared node{(link.evidence || []).length === 1 ? "" : "s"} · score{" "}
            {Math.round(link.score ?? 0)}
          </span>
          {topKinds.length > 0 ? (
            <span className="chip-row linkage-signal-chips">
              {topKinds.map((name) => (
                <span className="chip evidence-chip" key={name}>
                  {name}
                </span>
              ))}
            </span>
          ) : null}
          <span className="strength-track" aria-hidden="true">
            <span className={`strength-fill ${strength.tier}`} style={{ width: `${barWidth}%` }} />
          </span>
        </span>
        <span aria-hidden="true" className="linkage-caret">
          {expanded ? "▴" : "▾"}
        </span>
      </button>
      {expanded ? (
        <div className="pair-digest">
          <SharedNodeList
            evidence={link.evidence}
            leftLabel={leftLabel || link.a || "seed"}
            rightLabel={rightLabel || link.target || link.b}
          />
        </div>
      ) : null}
    </article>
  );
});
