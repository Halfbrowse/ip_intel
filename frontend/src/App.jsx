import * as d3 from "d3";
import { useEffect, useRef, useState } from "react";

const RESULT_TABS = [
  { id: "overview", label: "Overview" },
  { id: "dns", label: "DNS & WHOIS" },
  { id: "certs", label: "Certificates" },
  { id: "origin", label: "Origin discovery" },
  { id: "ips", label: "IP details" }
];

const RESULT_PAGES = [
  { id: "overview", label: "Briefing", subtitle: "Start here for the highest-signal summary." },
  { id: "dns", label: "DNS & WHOIS", subtitle: "Registration and address-book data for the target." },
  { id: "certs", label: "Certificates", subtitle: "HTTPS certificate history and certificate overlaps." },
  { id: "origin", label: "Origin hunt", subtitle: "Possible origin IPs and supporting evidence." },
  { id: "ips", label: "IP details", subtitle: "What each discovered IP probably means." }
];

const EXPLORER_TABS = [
  { id: "network", label: "Network graph" },
  { id: "recent", label: "Recent searches" },
  { id: "ip", label: "Shared IPs" },
  { id: "asn", label: "Shared ASNs" },
  { id: "tracking", label: "Tracking IDs" },
  { id: "favicon", label: "Favicons" },
  { id: "tls", label: "TLS fingerprints" },
  { id: "connections", label: "Domain connections" }
];

const EXPLORER_PAGES = [
  { id: "graph", label: "Graph", subtitle: "Full-screen domain relationship map." },
  { id: "connections", label: "Connections", subtitle: "Why one domain overlaps with others." },
  { id: "recent", label: "Recent", subtitle: "Saved investigations you can reopen." },
  { id: "ip", label: "Shared IPs", subtitle: "Domains touching the same IP or host." },
  { id: "asn", label: "ASNs", subtitle: "Domains clustering around the same autonomous system." },
  { id: "tracking", label: "Tracking IDs", subtitle: "Analytics and ad codes reused across domains." },
  { id: "favicon", label: "Favicons", subtitle: "Sites sharing the same browser-tab icon." },
  { id: "tls", label: "TLS overlaps", subtitle: "Domains tied together by certificate identity." }
];

const CONNECTION_SECTIONS = [
  {
    key: "tracking_ids",
    title: "Tracking and analytics IDs",
    infoBody: "If two domains share the same analytics or ad code, there is a decent chance they are run by the same team, contractor, or toolkit."
  },
  {
    key: "tls_certs",
    title: "TLS certificates",
    infoBody: "These are HTTPS identity cards. Shared certificates are often one of the stronger technical links between domains."
  },
  {
    key: "favicons",
    title: "Favicons",
    infoBody: "Favicons are the little tab icons websites use. Matching ones can point to a shared template or operator."
  },
  {
    key: "registrant_emails",
    title: "Registrant emails",
    infoBody: "If the same registration email appears across domains, that is a direct ownership clue."
  },
  {
    key: "ips",
    title: "IP addresses",
    infoBody: "Shared IPs can mean the same server is involved, but this is weaker when the server belongs to a big shared host or CDN."
  },
  {
    key: "asns",
    title: "ASNs and networks",
    infoBody: "ASN overlap shows that domains lived inside the same provider network. This is useful context, but large CDN and shared-hosting ASNs should be treated as softer evidence."
  },
  {
    key: "tls_history",
    title: "TLS history",
    infoBody: "This section shows whether certificate sharing is happening now or only appeared in the past, plus the time window where the overlap existed."
  },
  {
    key: "provider_hits",
    title: "Provider hits",
    infoBody: "These are normalized hits from search providers such as Censys, Shodan, and Netlas, including whether the lookup ran in a supported or degraded mode."
  },
  {
    key: "nameservers",
    title: "Nameservers",
    infoBody: "Nameservers are where the domain’s DNS is hosted. Shared nameservers can be useful background context, but they are not always a strong ownership signal."
  },
  {
    key: "discovered_domains",
    title: "Discovered domains",
    infoBody: "These are related domains surfaced during collection, such as reverse-IP pivots, subdomains, SAN overlaps, aliases, and other infrastructure-adjacent leads."
  },
  {
    key: "discovered_ips",
    title: "Discovered IPs",
    infoBody: "These are IPs surfaced during collection from DNS, historical DNS, provider hits, scans, and certificate observations. They become useful pivot points as the database grows."
  }
];

const NETWORK_LINK_META = {
  tracking: {
    label: "Tracking ID",
    headline: "Shared tracking or ad code",
    color: "#f08b57",
    summary: "The same analytics or advertising code appeared on both domains.",
    meaning: "In plain English: the same measurement or marketing setup was copied onto both sites, which often points to the same operator, agency, or site kit.",
    caution: "This is a strong clue, but some templates and resellers can reuse the same tags across unrelated customers."
  },
  tls: {
    label: "TLS cert",
    headline: "Shared TLS certificate",
    color: "#34b67f",
    summary: "Both domains presented the same HTTPS certificate fingerprint.",
    meaning: "In plain English: the same secure-web identity card showed up on both sites. When that overlap is current, it is one of the stronger technical links in the graph.",
    caution: "Managed hosts sometimes reuse certificates for multiple customers, so the issuer, the SAN list, and the surrounding infrastructure still matter."
  },
  favicon: {
    label: "Favicon",
    headline: "Shared favicon",
    color: "#d2a14d",
    summary: "The domains use the same small browser-tab icon.",
    meaning: "In plain English: the sites may share a template, a branding pack, or the same person who built them.",
    caution: "This is useful supporting evidence, but by itself it is weaker than a shared certificate or direct-server overlap."
  },
  ip: {
    label: "Shared IP",
    headline: "Shared server address",
    color: "#63a8ff",
    summary: "The domains resolved to the same IP address or hosting endpoint.",
    meaning: "In plain English: the sites touched the same server address. That matters most when the IP looks dedicated, and less when it belongs to a big shared platform or CDN.",
    caution: "Treat shared-hosting and CDN matches as softer evidence unless other signals line up too."
  },
  asn: {
    label: "ASN/network",
    headline: "Shared provider network",
    color: "#2fb6c4",
    summary: "The domains were observed inside the same autonomous system or network range.",
    meaning: "In plain English: the domains lived in the same provider network. That is useful context, especially on smaller or dedicated-looking networks, but it is usually weaker than an exact TLS or direct-IP match.",
    caution: "Large ISPs, CDNs, and shared-hosting providers can place many unrelated domains in the same ASN, so treat this as weighted context rather than proof."
  }
};

const NETWORK_LINK_ORDER = ["tls", "tracking", "ip", "asn", "favicon"];

const IP_LINK_SCORES = {
  direct: 8,
  shared_hosting: 3,
  cdn_proxy: 1,
  mail: 2
};

const TLS_LINK_SCORES = {
  current: 12,
  historical: 8
};

const ASN_LINK_SCORES = {
  current: {
    direct: 5,
    shared_hosting: 2,
    cdn_proxy: 1,
    mail: 2
  },
  historical: {
    direct: 3,
    shared_hosting: 1,
    cdn_proxy: 1,
    mail: 1
  }
};

const GRAPH_DEFAULT_CONTROLS = {
  includeIp: true,
  includeAsn: true,
  includeTracking: true,
  includeFavicon: true,
  includeTls: true,
  minScore: 5,
  maxLinks: 30,
  focus: ""
};

const GRAPH_DEFAULT_HEIGHT = 860;
const GRAPH_MIN_HEIGHT = 640;
const GRAPH_MAX_HEIGHT = 1480;
const GRAPH_DEFAULT_SIDEBAR_WIDTH = 360;
const GRAPH_MIN_SIDEBAR_WIDTH = 300;
const GRAPH_MAX_SIDEBAR_WIDTH = 520;
const GRAPH_OVERLAP_COLOR = "rgba(244, 63, 94, 0.34)";

const GRAPH_THEME = {
  light: {
    background: "rgba(7, 16, 29, 0)",
    surface: "#07131f",
    label: "rgba(7, 19, 31, 0.82)",
    labelText: "#f7fbff",
    nodeBase: "#d7e4ff",
    nodeMuted: "#86a1c3",
    nodeText: "#f7fbff",
    nodeStroke: "rgba(247, 251, 255, 0.22)",
    edgeMuted: "rgba(122, 162, 255, 0.16)",
    edgeHighlight: "#f8fafc"
  },
  dark: {
    background: "rgba(4, 10, 17, 0)",
    surface: "#040a11",
    label: "rgba(4, 10, 17, 0.86)",
    labelText: "#eff6ff",
    nodeBase: "#9bb8ff",
    nodeMuted: "#516884",
    nodeText: "#eff6ff",
    nodeStroke: "rgba(239, 246, 255, 0.22)",
    edgeMuted: "rgba(148, 163, 184, 0.22)",
    edgeHighlight: "#f8fafc"
  }
};

const numberFormatter = new Intl.NumberFormat();

async function apiFetch(path, options) {
  const response = await fetch(path, {
    headers: {
      "Content-Type": "application/json"
    },
    ...options
  });

  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const error = await response.json();
      message = error.detail || message;
    } catch (_error) {
      // Ignore parse errors and use the HTTP status instead.
    }
    throw new Error(message);
  }

  return response.json();
}

function isDatabaseCorruptionMessage(message) {
  const text = String(message || "").toLowerCase();
  return text.includes("database is corrupted")
    || text.includes("database disk image is malformed")
    || text.includes("database or disk is full")
    || text.includes("database is malformed")
    || text.includes("sqlite");
}

function formatDate(value) {
  if (!value) {
    return "Unknown";
  }
  return String(value).slice(0, 10);
}

function formatDateTime(value) {
  if (!value) {
    return "Unknown";
  }
  return String(value).replace("T", " ").slice(0, 16);
}

function formatNumber(value) {
  if (value === null || value === undefined) {
    return "0";
  }
  return numberFormatter.format(value);
}

function clampNumber(value, minimum, maximum) {
  let nextValue = value;
  if (typeof minimum === "number") {
    nextValue = Math.max(minimum, nextValue);
  }
  if (typeof maximum === "number") {
    nextValue = Math.min(maximum, nextValue);
  }
  return nextValue;
}

function parseIntegerInput(value, fallback, minimum, maximum) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return clampNumber(parsed, minimum, maximum);
}

function downloadResult(result) {
  const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${result.input || "ip-intel"}_${formatDate(result.timestamp)}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

function cloudflareLabel(value) {
  if (value === true || value === 1) {
    return "Cloudflare fronted";
  }
  if (value === false || value === 0) {
    return "Direct";
  }
  return "Unknown";
}

function collectOriginLeadCount(result) {
  const origin = result.origin_candidates || {};
  const scanHits = ["scan", "provider_scan", "country_scan"].reduce((sum, key) => {
    const hits = origin[key] && origin[key].hits ? origin[key].hits : [];
    return sum + hits.length;
  }, 0);
  const providerHits = ["censys", "shodan", "netlas"].reduce((sum, key) => {
    const hits = origin[key] && origin[key].hits ? origin[key].hits : [];
    return sum + hits.length;
  }, 0);
  const leakHits = ["subdomain_leaks", "mx_leaks", "wordlist_leaks", "hackertarget", "urlscan"].reduce((sum, key) => {
    return sum + ((origin[key] || []).length);
  }, 0);
  return scanHits + providerHits + leakHits;
}

function collectInterestingTxt(txtRecords) {
  const output = [];
  (txtRecords || []).forEach((txt) => {
    const value = String(txt);
    const lower = value.toLowerCase();
    if (lower.includes("google-site-verification")) {
      output.push({
        label: "Google Search Console",
        value,
        note: "This verification token can link the domain back to a specific Google account."
      });
    } else if (lower.includes("ms=")) {
      output.push({
        label: "Microsoft 365",
        value,
        note: "This token usually ties the domain to a Microsoft tenant."
      });
    } else if (lower.includes("tiktok-developers")) {
      output.push({
        label: "TikTok developer",
        value,
        note: "This suggests a TikTok developer or advertising setup."
      });
    } else if (lower.includes("apple-domain")) {
      output.push({
        label: "Apple domain token",
        value,
        note: "This token is used to prove ownership inside Apple services."
      });
    } else if (lower.includes("loaderio=")) {
      output.push({
        label: "Loader.io",
        value,
        note: "This usually means the operator used Loader.io for load testing."
      });
    } else if (lower.includes("spf1")) {
      output.push({
        label: "SPF / mail",
        value,
        note: "SPF records often reveal which email services or sending IPs are trusted."
      });
    }
  });
  return output;
}

function getRegistrar(result) {
  const value = result.whois && result.whois.registrar;
  if (Array.isArray(value)) {
    return value[0];
  }
  return value || "Unknown";
}

function getDomainTargets(items) {
  const seen = new Set();
  const targets = [];
  items.forEach((item) => {
    if (item.type !== "domain") {
      return;
    }
    const target = String(item.target || "");
    const normalized = target.toLowerCase();
    if (!target || seen.has(normalized)) {
      return;
    }
    seen.add(normalized);
    targets.push(target);
  });
  return targets;
}

function parseTargetList(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function pairKey(a, b) {
  return a < b ? `${a}|||${b}` : `${b}|||${a}`;
}

function shortLabel(value, max = 22) {
  if (!value) {
    return "";
  }
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function formatListPreview(values, limit = 6) {
  const items = Array.isArray(values)
    ? values
    : String(values || "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  if (!items.length) {
    return "";
  }
  if (items.length <= limit) {
    return items.join(", ");
  }
  return `${items.slice(0, limit).join(", ")} +${items.length - limit} more`;
}

function formatConfidence(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    return "n/a";
  }
  return `${Math.round(numeric * 100)}%`;
}

function formatFacetBuckets(values) {
  if (!Array.isArray(values) || !values.length) {
    return "No facet data";
  }
  return values
    .slice(0, 5)
    .map((item) => `${item.value || item.name || "unknown"} (${formatNumber(item.count || 0)})`)
    .join(", ");
}

function buildOpenctiJob(openctiState) {
  if (!openctiState || openctiState.available === false) {
    return null;
  }
  if (!openctiState.running && !openctiState.started_at && !openctiState.completed_at) {
    return null;
  }

  const total = Number(openctiState.total || 0);
  const done = Number(openctiState.done || 0);
  const fraction = total > 0 ? Math.max(0, Math.min(1, done / total)) : (!openctiState.running && openctiState.completed_at ? 1 : 0);

  return {
    id: "opencti-ingestion",
    kind: "opencti_ingestion",
    target: openctiState.current || "OpenCTI domains",
    status: openctiState.running ? "running" : openctiState.completed_at ? "completed" : "queued",
    created_at: openctiState.started_at || null,
    updated_at: openctiState.completed_at || openctiState.started_at || null,
    error: openctiState.last_error || null,
    logs: openctiState.logs || [],
    progress: {
      fraction,
      total,
      done,
      completed_count: done,
      current: openctiState.current || null,
      skipped: Number(openctiState.skipped || 0),
      mode: openctiState.mode || "incremental"
    }
  };
}

function getConnectionItemTitle(sectionKey, item) {
  if (sectionKey === "tracking_ids") {
    return item.id_value ? `${item.id_type}: ${item.id_value}` : "Tracking ID";
  }
  if (sectionKey === "tls_certs" || sectionKey === "tls_history") {
    return item.cn || shortLabel(item.sha256 || "TLS certificate", 18);
  }
  if (sectionKey === "favicons") {
    return item.md5 || "Favicon";
  }
  if (sectionKey === "registrant_emails") {
    return item.email || "Registrant email";
  }
  if (sectionKey === "ips") {
    return item.ip || "IP address";
  }
  if (sectionKey === "asns") {
    return item.asn ? `AS${item.asn}` : "ASN";
  }
  if (sectionKey === "provider_hits") {
    if (item.provider && item.ip) {
      return `${item.provider} ${item.ip}`;
    }
    return item.provider || item.ip || "Provider hit";
  }
  if (sectionKey === "nameservers") {
    return item.nameserver || "Nameserver";
  }
  if (sectionKey === "discovered_domains" || sectionKey === "discovered_ips") {
    return item.target || "Discovered target";
  }
  return item.id_value || item.email || item.ip || item.nameserver || item.md5 || item.cn || "Link";
}

function ConnectionItemDetails({ sectionKey, item, meta }) {
  if (sectionKey === "tracking_ids") {
    return <p><strong>Type:</strong> {item.id_type || "Unknown"}</p>;
  }

  if (sectionKey === "ips") {
    return (
      <>
        {item.label ? (
          <div className="pill-row">
            <TypePill kind={item.label} definitions={meta.server_types || {}} />
          </div>
        ) : null}
        {item.asn_desc || item.asn ? <p><strong>ASN:</strong> {item.asn_desc || `AS${item.asn}`}</p> : null}
        {item.network_cidr ? <p><strong>Network:</strong> {item.network_cidr}</p> : null}
        {item.proxy_family ? <p><strong>Reverse proxy:</strong> {item.proxy_family}</p> : null}
        {item.ptr ? <p className="break-word"><strong>PTR:</strong> {item.ptr}</p> : null}
        {item.shared_network_with && item.shared_network_with.length ? (
          <p className="break-word"><strong>Shared network:</strong> {item.shared_network_with.join(", ")}</p>
        ) : null}
      </>
    );
  }

  if (sectionKey === "asns") {
    return (
      <>
        {item.label ? (
          <div className="pill-row">
            <TypePill kind={item.label} definitions={meta.server_types || {}} />
          </div>
        ) : null}
        {item.asn_desc ? <p><strong>Owner:</strong> {item.asn_desc}</p> : null}
        {item.network_cidr ? <p><strong>Network:</strong> {item.network_cidr}</p> : null}
        {item.proxy_family ? <p><strong>Proxy family:</strong> {item.proxy_family}</p> : null}
        {item.shared_network_with && item.shared_network_with.length ? (
          <p className="break-word"><strong>Same CIDR also seen on:</strong> {item.shared_network_with.join(", ")}</p>
        ) : null}
      </>
    );
  }

  if (sectionKey === "tls_certs") {
    return (
      <>
        {item.issuer_cn ? <p><strong>Issuer:</strong> {item.issuer_cn}</p> : null}
        {item.ip ? <p><strong>Observed on:</strong> {item.ip}</p> : null}
        {item.sha256 ? <p className="break-word"><strong>Fingerprint:</strong> {item.sha256}</p> : null}
        {(item.not_before || item.not_after) ? (
          <p><strong>Validity:</strong> {`${formatDate(item.not_before)} to ${formatDate(item.not_after)}`}</p>
        ) : null}
      </>
    );
  }

  if (sectionKey === "tls_history") {
    return (
      <>
        {item.issuer_cn ? <p><strong>Issuer:</strong> {item.issuer_cn}</p> : null}
        <p><strong>Status:</strong> {item.relationship_status === "current" ? "Shared now" : "Historical only"}</p>
        {item.current_shared_with && item.current_shared_with.length ? (
          <p className="break-word"><strong>Current overlap:</strong> {item.current_shared_with.join(", ")}</p>
        ) : null}
        {item.historical_shared_with && item.historical_shared_with.length ? (
          <p className="break-word"><strong>Historical overlap:</strong> {item.historical_shared_with.join(", ")}</p>
        ) : null}
        {(item.first_observed || item.last_observed) ? (
          <p><strong>Seen:</strong> {`${formatDateTime(item.first_observed)} to ${formatDateTime(item.last_observed)}`}</p>
        ) : null}
        {(item.overlap_start || item.overlap_end) ? (
          <p><strong>Overlap window:</strong> {`${formatDateTime(item.overlap_start)} to ${formatDateTime(item.overlap_end)}`}</p>
        ) : null}
      </>
    );
  }

  if (sectionKey === "provider_hits") {
    return (
      <>
        <p><strong>Status:</strong> {item.status || "unknown"} | <strong>Mode:</strong> {item.mode || "unknown"}</p>
        {item.query_type ? <p><strong>Query:</strong> {item.query_type}</p> : null}
        {item.asn_desc || item.asn ? <p><strong>ASN:</strong> {item.asn_desc || `AS${item.asn}`}</p> : null}
        {item.org ? <p><strong>Org:</strong> {item.org}</p> : null}
        {item.country ? <p><strong>Country:</strong> {item.country}</p> : null}
      </>
    );
  }

  if (sectionKey === "discovered_domains" || sectionKey === "discovered_ips") {
    return (
      <>
        <p><strong>Type:</strong> {item.target_type || "unknown"} | <strong>Score:</strong> {formatNumber(item.score || 0)}</p>
        {item.relations && item.relations.length ? (
          <p className="break-word"><strong>Relations:</strong> {item.relations.join(", ")}</p>
        ) : null}
        {item.sources && item.sources.length ? (
          <p className="break-word"><strong>Sources:</strong> {item.sources.join(", ")}</p>
        ) : null}
      </>
    );
  }

  return null;
}

function buildNetworkModel(clusters, options) {
  const edgeMap = new Map();
  const nodeMap = new Map();

  function ensureNode(id) {
    if (!nodeMap.has(id)) {
      nodeMap.set(id, { id, totalWeight: 0, degree: 0 });
    }
    return nodeMap.get(id);
  }

  function registerCluster(targets, kind, score, descriptor, color) {
    for (let i = 0; i < targets.length; i += 1) {
      for (let j = i + 1; j < targets.length; j += 1) {
        const source = targets[i];
        const target = targets[j];
        const key = pairKey(source, target);
        const sourceNode = ensureNode(source);
        const targetNode = ensureNode(target);
        sourceNode.totalWeight += score;
        sourceNode.degree += 1;
        targetNode.totalWeight += score;
        targetNode.degree += 1;

        if (!edgeMap.has(key)) {
          edgeMap.set(key, {
            key,
            source: source < target ? source : target,
            target: source < target ? target : source,
            score: 0,
            details: [],
            kinds: new Set(),
            primaryKind: kind,
            primaryColor: color,
            primaryScore: score
          });
        }

        const edge = edgeMap.get(key);
        edge.score += score;
        edge.details.push({ kind, descriptor, score });
        edge.kinds.add(kind);
        if (score >= edge.primaryScore) {
          edge.primaryKind = kind;
          edge.primaryColor = color;
          edge.primaryScore = score;
        }
      }
    }
  }

  if (options.includeTracking) {
    (clusters.tracking || []).forEach((row) => {
      registerCluster(
        parseTargetList(row.targets),
        "tracking",
        9,
        `${row.id_type}: ${row.id_value}`,
        NETWORK_LINK_META.tracking.color
      );
    });
  }

  if (options.includeTls) {
    (clusters.tls || []).forEach((row) => {
      const relationshipStatus = normalizeEvidenceStatus(row.relationship_status);
      registerCluster(
        parseTargetList(row.targets),
        "tls",
        getTlsLinkScore(relationshipStatus),
        `${row.cn || shortLabel(row.sha256, 16)} | ${row.issuer_cn || "Unknown issuer"} | ${relationshipStatus}`,
        NETWORK_LINK_META.tls.color
      );
    });
  }

  if (options.includeFavicon) {
    (clusters.favicon || []).forEach((row) => {
      registerCluster(
        parseTargetList(row.targets),
        "favicon",
        4,
        `MD5 ${shortLabel(row.md5, 14)}`,
        NETWORK_LINK_META.favicon.color
      );
    });
  }

  if (options.includeIp) {
    (clusters.ip || []).forEach((row) => {
      registerCluster(
        parseTargetList(row.targets),
        "ip",
        IP_LINK_SCORES[row.label] || 2,
        `${row.ip} | ${row.label.replace("_", " ")}`,
        NETWORK_LINK_META.ip.color
      );
    });
  }

  if (options.includeAsn) {
    (clusters.asn || []).forEach((row) => {
      const relationshipStatus = normalizeEvidenceStatus(row.relationship_status);
      const networkHint = Array.isArray(row.network_cidrs) && row.network_cidrs.length
        ? row.network_cidrs.slice(0, 2).join(", ")
        : "Unknown network";
      registerCluster(
        parseTargetList(row.targets),
        "asn",
        getAsnLinkScore(row.label, relationshipStatus),
        `AS${row.asn} | ${row.asn_desc || "Unknown owner"} | ${row.label || "direct"} | ${relationshipStatus} | ${networkHint}`,
        NETWORK_LINK_META.asn.color
      );
    });
  }

  const focusValue = (options.focus || "").trim().toLowerCase();
  const allEdges = [...edgeMap.values()]
    .filter((edge) => edge.score >= options.minScore)
    .filter((edge) => {
      if (!focusValue) {
        return true;
      }
      return edge.source.toLowerCase() === focusValue || edge.target.toLowerCase() === focusValue;
    })
    .map((edge) => ({
      ...edge,
      kinds: [...edge.kinds],
      details: edge.details.sort((a, b) => b.score - a.score || a.kind.localeCompare(b.kind))
    }))
    .sort((a, b) => b.score - a.score || b.details.length - a.details.length || a.source.localeCompare(b.source));

  const visibleEdges = allEdges.slice(0, options.maxLinks);
  const visibleNodeIds = new Set();
  visibleEdges.forEach((edge) => {
    visibleNodeIds.add(edge.source);
    visibleNodeIds.add(edge.target);
  });

  const visibleNodes = [...nodeMap.values()]
    .filter((node) => visibleNodeIds.has(node.id))
    .map((node) => {
      const displayWeight = visibleEdges.reduce((sum, edge) => {
        return edge.source === node.id || edge.target === node.id ? sum + edge.score : sum;
      }, 0);
      const visibleDegree = visibleEdges.reduce((sum, edge) => {
        return edge.source === node.id || edge.target === node.id ? sum + 1 : sum;
      }, 0);
      return {
        ...node,
        displayWeight,
        visibleDegree
      };
    })
    .sort((a, b) => b.displayWeight - a.displayWeight || a.id.localeCompare(b.id));

  return {
    nodes: visibleNodes,
    edges: visibleEdges,
    hiddenEdgeCount: Math.max(allEdges.length - visibleEdges.length, 0),
    maxScore: visibleEdges.reduce((highest, edge) => Math.max(highest, edge.score), 0)
  };
}

function describeLinkStrength(score) {
  if (score >= 20) {
    return "Very strong overlap";
  }
  if (score >= 12) {
    return "Strong overlap";
  }
  if (score >= 5) {
    return "Useful lead";
  }
  return "Weak signal";
}

function formatList(values) {
  const items = (values || []).filter(Boolean);
  if (!items.length) {
    return "";
  }
  if (items.length === 1) {
    return items[0];
  }
  if (items.length === 2) {
    return `${items[0]} and ${items[1]}`;
  }
  return `${items.slice(0, -1).join(", ")}, and ${items[items.length - 1]}`;
}

function getOrderedNetworkKinds(kinds) {
  const set = new Set(kinds || []);
  return NETWORK_LINK_ORDER.filter((kind) => set.has(kind));
}

function normalizeIpDescriptorLabel(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[ -]+/g, "_");
}

function normalizeEvidenceStatus(value) {
  return String(value || "").trim().toLowerCase() === "historical" ? "historical" : "current";
}

function getTlsLinkScore(status) {
  return TLS_LINK_SCORES[normalizeEvidenceStatus(status)] || TLS_LINK_SCORES.current;
}

function getAsnLinkScore(label, status) {
  const normalizedStatus = normalizeEvidenceStatus(status);
  const normalizedLabel = normalizeIpDescriptorLabel(label) || "direct";
  const statusScores = ASN_LINK_SCORES[normalizedStatus] || ASN_LINK_SCORES.current;
  return statusScores[normalizedLabel] || statusScores.direct;
}

function describeGraphDetail(detail) {
  const meta = NETWORK_LINK_META[detail.kind] || {
    label: detail.kind,
    summary: "This is one of the overlap signals used to link domains.",
    meaning: "It means both domains shared the same underlying clue.",
    caution: "Use it alongside the other signals in the graph."
  };

  if (detail.kind === "ip") {
    const [ip, rawLabel] = String(detail.descriptor || "")
      .split("|")
      .map((part) => part.trim())
      .filter(Boolean);
    const label = normalizeIpDescriptorLabel(rawLabel);

    if (label === "direct") {
      return {
        ...meta,
        evidence: ip ? `Observed IP: ${ip}` : detail.descriptor,
        summary: ip
          ? `Both domains pointed at ${ip}, and that address looks like a direct server rather than a shared front door.`
          : "Both domains pointed at the same IP, and it looks like a direct server.",
        meaning: "In plain English: these sites may be sitting on the same real web server, which is one of the more useful infrastructure links.",
        caution: "A direct IP is usually stronger than a CDN or shared-hosting overlap, but you should still sanity-check the rest of the evidence."
      };
    }

    if (label === "shared_hosting") {
      return {
        ...meta,
        evidence: ip ? `Observed IP: ${ip}` : detail.descriptor,
        summary: ip
          ? `Both domains touched ${ip}, but that address looks like shared hosting used by multiple customers.`
          : "Both domains touched the same shared-hosting IP.",
        meaning: "In plain English: the sites were placed on the same hosting platform, which is useful context but not strong proof of a shared owner.",
        caution: "Shared-hosting overlaps are best treated as supporting evidence unless you also see TLS, tracking, or other stronger links."
      };
    }

    if (label === "cdn_proxy") {
      return {
        ...meta,
        evidence: ip ? `Observed edge IP: ${ip}` : detail.descriptor,
        summary: ip
          ? `Both domains were seen on ${ip}, but that address looks like a CDN or reverse-proxy edge rather than the hidden origin server.`
          : "Both domains shared a CDN or proxy edge IP.",
        meaning: "In plain English: they passed through the same front-door service. That can happen for many unrelated sites, so it is a weak clue by itself.",
        caution: "Treat CDN overlaps as background context, not a strong ownership signal."
      };
    }

    if (label === "mail") {
      return {
        ...meta,
        evidence: ip ? `Observed mail IP: ${ip}` : detail.descriptor,
        summary: ip
          ? `Both domains touched ${ip}, but that address looks like mail or collaboration infrastructure rather than a dedicated web origin.`
          : "Both domains touched the same mail or collaboration IP.",
        meaning: "In plain English: the sites may share the same mail, Exchange, or hosted messaging setup. That can still be useful organizational evidence, just not as strong as a direct web-origin match.",
        caution: "Mail overlaps are best treated as supporting evidence unless the certificate, SAN list, or other infrastructure clues also line up."
      };
    }

    return {
      ...meta,
      evidence: ip ? `Observed IP: ${ip}` : detail.descriptor,
      summary: meta.summary,
      meaning: meta.meaning,
      caution: meta.caution
    };
  }

  if (detail.kind === "tls") {
    const [subject, issuer, rawStatus] = String(detail.descriptor || "")
      .split("|")
      .map((part) => part.trim())
      .filter(Boolean);
    const status = normalizeEvidenceStatus(rawStatus);
    return {
      ...meta,
      evidence: subject
        ? `${subject}${issuer ? ` issued by ${issuer}` : ""}`
        : detail.descriptor,
      summary: subject
        ? `Both domains ${status === "current" ? "currently present" : "were historically seen with"} the same HTTPS certificate identity: ${subject}.`
        : meta.summary,
      meaning: status === "current"
        ? "In plain English: the same certificate fingerprint is still live on both domains. That is one of the strongest technical links this graph can make from cert and IP data."
        : "In plain English: the same certificate fingerprint was shared in the past. That still matters because it can reveal migrations, legacy hosting, or older common control that is no longer live.",
      caution: status === "current"
        ? meta.caution
        : "Historical certificate overlap is valuable, but it can reflect an old migration or temporary shared platform instead of a current live relationship."
    };
  }

  if (detail.kind === "asn") {
    const [asn, owner, rawLabel, rawStatus, networkHint] = String(detail.descriptor || "")
      .split("|")
      .map((part) => part.trim())
      .filter(Boolean);
    const label = normalizeIpDescriptorLabel(rawLabel);
    const status = normalizeEvidenceStatus(rawStatus);
    const tense = status === "current" ? "currently sit" : "were historically seen";
    const ownerLabel = owner && owner !== "Unknown owner" ? ` (${owner})` : "";
    const networkLabel = networkHint && networkHint !== "Unknown network" ? ` on ${networkHint}` : "";

    if (label === "direct") {
      return {
        ...meta,
        evidence: `${asn || "ASN"}${networkLabel}`,
        summary: `${asn || "The domains"} ${tense} inside the same provider network${ownerLabel}${networkLabel}.`,
        meaning: status === "current"
          ? "In plain English: both domains are currently operating from the same non-noisy network neighborhood. That is useful context, but it is still weaker than a shared exact certificate or direct IP."
          : "In plain English: both domains lived in the same network in the past. That can reveal historical common infrastructure even after the hosts moved.",
        caution: "ASN overlap helps build the case, especially on smaller networks, but it should be combined with stronger host-level evidence before you treat it as near-proof."
      };
    }

    if (label === "shared_hosting") {
      return {
        ...meta,
        evidence: `${asn || "ASN"}${networkLabel}`,
        summary: `${asn || "The domains"} ${tense} inside the same shared-hosting network${ownerLabel}${networkLabel}.`,
        meaning: "In plain English: both domains were placed on the same broader hosting provider. That is useful background, but plenty of unrelated sites can land there too.",
        caution: "Shared-hosting ASN overlap is supporting context, not a strong ownership link on its own."
      };
    }

    if (label === "mail") {
      return {
        ...meta,
        evidence: `${asn || "ASN"}${networkLabel}`,
        summary: `${asn || "The domains"} ${tense} inside the same mail or collaboration network${ownerLabel}${networkLabel}.`,
        meaning: "In plain English: the domains may share the same messaging or Exchange environment, which can be useful organization-level context.",
        caution: "Mail-network overlap is worth keeping, but it is usually weaker than direct web-origin or exact TLS evidence."
      };
    }

    if (label === "cdn_proxy") {
      return {
        ...meta,
        evidence: `${asn || "ASN"}${networkLabel}`,
        summary: `${asn || "The domains"} ${tense} inside the same CDN or reverse-proxy network${ownerLabel}${networkLabel}.`,
        meaning: "In plain English: both domains used the same front-door delivery network. That can happen for many unrelated sites, so it is mainly background context.",
        caution: "CDN ASN overlap should stay low-weight unless stronger direct-host evidence also appears."
      };
    }

    return {
      ...meta,
      evidence: `${asn || "ASN"}${networkLabel}`,
      summary: meta.summary,
      meaning: meta.meaning,
      caution: meta.caution
    };
  }

  if (detail.kind === "tracking") {
    const descriptor = String(detail.descriptor || "").trim();
    const splitIndex = descriptor.indexOf(":");
    const idType = splitIndex >= 0 ? descriptor.slice(0, splitIndex).trim() : "Tracking code";
    const idValue = splitIndex >= 0 ? descriptor.slice(splitIndex + 1).trim() : descriptor;
    return {
      ...meta,
      evidence: descriptor,
      summary: idValue
        ? `Both domains contain the same ${idType}: ${shortLabel(idValue, 34)}.`
        : meta.summary,
      meaning: meta.meaning,
      caution: meta.caution
    };
  }

  if (detail.kind === "favicon") {
    return {
      ...meta,
      evidence: detail.descriptor,
      summary: "Both domains use the same small browser-tab icon or favicon hash.",
      meaning: meta.meaning,
      caution: meta.caution
    };
  }

  return {
    ...meta,
    evidence: detail.descriptor,
    summary: meta.summary,
    meaning: meta.meaning,
    caution: meta.caution
  };
}

function buildEdgeNarrative(edge) {
  const kindLabels = getOrderedNetworkKinds(edge.kinds).map((kind) => NETWORK_LINK_META[kind].headline.toLowerCase());
  if (!kindLabels.length) {
    return "These domains share at least one technical clue, so the graph is treating them as related.";
  }
  return `These domains share ${formatList(kindLabels)}. In plain English, that makes this a ${describeLinkStrength(edge.score).toLowerCase()} that the same operator, infrastructure, or deployment process touched both of them.`;
}

function collectNodeSignalCounts(edges, nodeId) {
  const counts = {
    tls: 0,
    tracking: 0,
    ip: 0,
    asn: 0,
    favicon: 0
  };

  (edges || []).forEach((edge) => {
    if (!edgeTouchesNode(edge, nodeId)) {
      return;
    }
    getOrderedNetworkKinds(edge.kinds).forEach((kind) => {
      counts[kind] += 1;
    });
  });

  return counts;
}

function getEdgeEndpointId(endpoint) {
  return typeof endpoint === "string" ? endpoint : endpoint.id;
}

function edgeTouchesNode(edge, nodeId) {
  return getEdgeEndpointId(edge.source) === nodeId || getEdgeEndpointId(edge.target) === nodeId;
}

function TabButton({ active, label, onClick }) {
  return (
    <button className={active ? "tab-button active" : "tab-button"} onClick={onClick} type="button">
      {label}
    </button>
  );
}

function InfoPopover({ title, body }) {
  const [open, setOpen] = useState(false);

  return (
    <span className="info-popover">
      <button
        className="info-button"
        onClick={(event) => {
          event.preventDefault();
          event.stopPropagation();
          setOpen(!open);
        }}
        type="button"
        aria-label={`Explain ${title}`}
      >
        i
      </button>
      {open ? (
        <span className="popover-card">
          <strong>{title}</strong>
          <span>{body}</span>
        </span>
      ) : null}
    </span>
  );
}

function SectionCard({ title, subtitle, actions, infoTitle, infoBody, children }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <div className="panel-title-row">
            <h2>{title}</h2>
            {infoTitle && infoBody ? <InfoPopover title={infoTitle} body={infoBody} /> : null}
          </div>
          {subtitle ? <p>{subtitle}</p> : null}
        </div>
        {actions ? <div className="panel-actions">{actions}</div> : null}
      </div>
      {children}
    </section>
  );
}

function Callout({ tone = "info", children }) {
  return <div className={`callout ${tone}`}>{children}</div>;
}

function Metric({ label, value, detail }) {
  return (
    <div className="metric-card">
      <span>{label}</span>
      <strong>{value}</strong>
      {detail ? <small>{detail}</small> : null}
    </div>
  );
}

function TypePill({ kind, definitions }) {
  if (!kind) {
    return null;
  }
  const definition = definitions[kind];
  if (!definition) {
    return <span className="type-pill">{kind}</span>;
  }
  return (
    <span className="type-pill">
      {definition.label}
      <InfoPopover title={definition.label} body={definition.summary} />
    </span>
  );
}

function KeyValueList({ items }) {
  return (
    <div className="key-value-grid">
      {items.filter((item) => item.value).map((item) => (
        <div className="key-value-item" key={item.label}>
          <span>{item.label}</span>
          <strong>{item.value}</strong>
        </div>
      ))}
    </div>
  );
}

function LeadCard({ title, children, footer }) {
  return (
    <article className="lead-card">
      <h4>{title}</h4>
      <div>{children}</div>
      {footer ? <small>{footer}</small> : null}
    </article>
  );
}

function PageNavButton({ active, label, subtitle, onClick }) {
  return (
    <button className={active ? "page-nav-button active" : "page-nav-button"} onClick={onClick} type="button">
      <strong>{label}</strong>
      <span>{subtitle}</span>
    </button>
  );
}

function PageFrame({ eyebrow, title, subtitle, infoTitle, infoBody, actions, metrics, children }) {
  return (
    <section className="page-frame">
      <div className="page-heading">
        <div>
          {eyebrow ? <span className="eyebrow">{eyebrow}</span> : null}
          <div className="page-title-row">
            <h2>{title}</h2>
            {infoTitle && infoBody ? <InfoPopover title={infoTitle} body={infoBody} /> : null}
          </div>
          {subtitle ? <p>{subtitle}</p> : null}
        </div>
        {actions ? <div className="panel-actions">{actions}</div> : null}
      </div>
      {metrics ? <div className="metric-grid page-metrics">{metrics}</div> : null}
      <div className="stack">{children}</div>
    </section>
  );
}

function JobProgress({ job }) {
  if (!job) {
    return null;
  }

  const isOpenctiJob = job.kind === "opencti_ingestion";
  const progress = job.progress || { fraction: 0, completed: [], completed_count: 0, total: 0 };
  const partial = job.partial_result || {};
  const dns = partial.dns || {};
  const ct = partial.cert_transparency || {};
  const origin = partial.origin_candidates || {};
  const liveLeakCount =
    (origin.subdomain_leaks || []).length +
    (origin.mx_leaks || []).length +
    (origin.wordlist_leaks || []).length;

  if (isOpenctiJob) {
    const modeLabel = progress.mode === "full_reanalyse" ? "Re-run all" : "Incremental";
    const done = Number(progress.done || progress.completed_count || 0);
    const total = Number(progress.total || 0);
    const currentTarget = progress.current || "Preparing queue";

    return (
      <SectionCard
        title={job.status === "completed" ? "Latest OpenCTI ingestion" : "OpenCTI ingestion"}
        subtitle={job.status === "completed" ? `Completed ${formatDateTime(job.updated_at)}` : `Processing ${currentTarget}`}
      >
        <div className="metric-grid">
          <Metric label="Progress" value={`${Math.round((progress.fraction || 0) * 100)}%`} detail={currentTarget} />
          <Metric label="Domains done" value={`${formatNumber(done)}/${formatNumber(total)}`} />
          <Metric label="Skipped existing" value={formatNumber(progress.skipped || 0)} />
          <Metric label="Mode" value={modeLabel} detail={job.status === "running" ? "Polling live" : "Last recorded run"} />
        </div>

        <div className="progress-wrap">
          <div className="progress-track">
            <div className="progress-fill" style={{ width: `${(progress.fraction || 0) * 100}%` }} />
          </div>
          <div className="phase-pill-row">
            <span className="phase-pill done">Fetch OpenCTI domains</span>
            <span className="phase-pill done">{modeLabel}</span>
            {total ? <span className="phase-pill done">{`Queued ${formatNumber(total)}`}</span> : null}
            {progress.skipped ? <span className="phase-pill">{`Skipped ${formatNumber(progress.skipped)}`}</span> : null}
            {progress.current ? <span className="phase-pill">{shortLabel(progress.current, 36)}</span> : null}
          </div>
        </div>

        {job.error ? <Callout tone="warning">{job.error}</Callout> : null}

        <div className="log-shell">
          {(job.logs || []).slice(-30).map((entry, index) => (
            <div className="log-line" key={`${index}-${entry}`}>
              {entry}
            </div>
          ))}
        </div>
      </SectionCard>
    );
  }

  return (
    <SectionCard
      title={job.status === "completed" ? "Latest result" : "Live scan"}
      subtitle={job.status === "completed" ? `Completed ${formatDateTime(job.updated_at)}` : `Scanning ${job.target}`}
    >
      <div className="metric-grid">
        <Metric label="Progress" value={`${Math.round((progress.fraction || 0) * 100)}%`} detail={progress.current || "Wrapping up"} />
        <Metric label="Phases done" value={`${progress.completed_count || 0}/${progress.total || 0}`} />
        <Metric label="CT certs" value={ct.total_certs || 0} />
        <Metric label="Live leads" value={liveLeakCount} detail={`${(dns.A || []).length} A records resolved`} />
      </div>

      <div className="progress-wrap">
        <div className="progress-track">
          <div className="progress-fill" style={{ width: `${(progress.fraction || 0) * 100}%` }} />
        </div>
        <div className="phase-pill-row">
          {progress.completed && progress.completed.length
            ? progress.completed.map((phase) => (
                <span className="phase-pill done" key={phase}>
                  {phase}
                </span>
              ))
            : <span className="phase-pill">Waiting for first results</span>}
        </div>
      </div>

      {job.error ? <Callout tone="danger">{job.error}</Callout> : null}

      <div className="log-shell">
        {(job.logs || []).slice(-30).map((entry, index) => (
          <div className="log-line" key={`${index}-${entry}`}>
            {entry}
          </div>
        ))}
      </div>
    </SectionCard>
  );
}

function RecursivePivotCards({ title, subtitle, items, onOpenSavedResult, actionLabel }) {
  if (!items || !items.length) {
    return null;
  }

  return (
    <SectionCard title={title} subtitle={subtitle}>
      <div className="card-grid">
        {items.map((item) => (
          <LeadCard
            key={`${title}-${item.target_type || "target"}-${item.target}-${item.search_id || item.reason || "item"}`}
            title={item.target}
            footer={`${String(item.target_type || "target").toUpperCase()} | score ${formatNumber(item.score || 0)}`}
          >
            {item.search_id && onOpenSavedResult ? (
              <button className="inline-action" onClick={() => onOpenSavedResult(item.search_id)} type="button">
                {actionLabel}
              </button>
            ) : null}
            {item.timestamp ? <p><strong>Saved:</strong> {formatDateTime(item.timestamp)}</p> : null}
            <p className="break-word"><strong>Sources:</strong> {(item.sources || []).join(", ") || "unknown"}</p>
            <p className="break-word"><strong>Relations:</strong> {(item.relations || []).join(", ") || "unknown"}</p>
            {item.reason ? <p className="break-word"><strong>Reason:</strong> {item.reason}</p> : null}
          </LeadCard>
        ))}
      </div>
    </SectionCard>
  );
}

function OverviewTab({ result, meta, onOpenSavedResult }) {
  const dns = result.dns || {};
  const page = result.page_metadata || {};
  const email = result.email_security || {};
  const currentCerts = result.non_cf_tls_certs || (result.tls_cert ? [result.tls_cert] : []);
  const relatedTargets = result.related_targets_summary || {};
  const recursiveExpansion = result.recursive_expansion || null;
  const trackingIds = [
    ...(page.google_analytics || []).map((value) => ({ label: "Google Analytics", value })),
    ...(page.gtm_ids || []).map((value) => ({ label: "Google Tag Manager", value })),
    ...(page.facebook_pixel || []).map((value) => ({ label: "Facebook Pixel", value })),
    ...(page.tiktok_pixel || []).map((value) => ({ label: "TikTok Pixel", value })),
    ...(page.yandex_metrika || []).map((value) => ({ label: "Yandex Metrika", value }))
  ];
  const historicalIps = ((result.historical_dns || {}).records || []).filter((item) => ["A", "AAAA"].includes(item.rrtype));
  const interestingTxt = collectInterestingTxt(dns.TXT || []);

  return (
    <div className="stack">
      {result.source_errors && result.source_errors.length ? (
        <Callout tone="warning">
          Some external sources failed or rate-limited during this run: {result.source_errors.join(", ")}.
        </Callout>
      ) : null}

      <div className="metric-grid">
        <Metric label="Target type" value={(result.type || "").toUpperCase()} />
        <Metric label="Cloudflare" value={cloudflareLabel(result.cloudflare_fronted ?? result.cloudflare)} />
        <Metric label="Origin leads" value={collectOriginLeadCount(result)} />
        <Metric label="Search saved" value={formatDateTime(result.timestamp)} />
      </div>

      <SectionCard
        title="Registration and hosting"
        subtitle="A plain-English summary of what the current infrastructure looks like."
        infoTitle="Registration and hosting"
        infoBody="This section answers simple questions like who registered the domain, roughly where it sits, and whether the current website seems to be hidden behind a service like Cloudflare."
      >
        <KeyValueList
          items={[
            { label: "Registrar", value: getRegistrar(result) },
            { label: "Created", value: formatDate(result.whois && result.whois.creation_date) },
            { label: "Country", value: result.whois && result.whois.country },
            { label: "Org", value: result.whois && result.whois.org }
          ]}
        />

        {result.type === "ip" ? (
          <Callout tone="info">
            This was an IP lookup. The backend pulled PTR, ASN, reverse-IP, and TLS details directly from the address.
          </Callout>
        ) : result.cloudflare_fronted ? (
          <Callout tone="info">
            All current A records look like Cloudflare edge nodes, so the public web server is hidden behind Cloudflare right now.
          </Callout>
        ) : (
          <Callout tone="success">
            At least one current A record is a direct, non-Cloudflare IP. That is usually one of the strongest origin leads.
          </Callout>
        )}
      </SectionCard>

      {relatedTargets.total ? (
        <SectionCard
          title="Recursive pivot summary"
          subtitle="What this run discovered beyond the original target, and how much of that was automatically expanded."
          infoTitle="Recursive pivot summary"
          infoBody="The backend extracts related domains and IPs from DNS, historical DNS, provider hits, scans, TLS, reverse-IP, and certificate evidence. The strongest new pivots can be analysed automatically so the stored network grows as you investigate."
        >
          <div className="metric-grid">
            <Metric label="Related targets" value={formatNumber(relatedTargets.total || 0)} />
            <Metric label="Domains" value={formatNumber(relatedTargets.domains || 0)} />
            <Metric label="IPs" value={formatNumber(relatedTargets.ips || 0)} />
            <Metric label="Expandable" value={formatNumber(relatedTargets.expandable || 0)} />
          </div>
          {recursiveExpansion ? (
            <div className="metric-grid">
              <Metric label="Auto-analysed" value={formatNumber(recursiveExpansion.analysed_count || 0)} detail="New pivots analysed during this run" />
              <Metric label="Already known" value={formatNumber(recursiveExpansion.linked_existing_count || 0)} detail="Pivots already present in the database" />
              <Metric label="Skipped" value={formatNumber(recursiveExpansion.skipped_count || 0)} detail={`Limit ${formatNumber(recursiveExpansion.limit || 0)} | depth ${recursiveExpansion.depth || 1}`} />
            </div>
          ) : null}
          {relatedTargets.items && relatedTargets.items.length ? (
            <div className="card-grid">
              {relatedTargets.items.slice(0, 12).map((item) => (
                <LeadCard key={`${item.target_type}-${item.target}`} title={item.target} footer={`${item.target_type.toUpperCase()} | score ${formatNumber(item.score || 0)}`}>
                  <p className="break-word"><strong>Sources:</strong> {(item.sources || []).join(", ") || "unknown"}</p>
                  <p className="break-word"><strong>Relations:</strong> {(item.relations || []).join(", ") || "unknown"}</p>
                  <p><strong>Auto-expand:</strong> {item.auto_expand ? "Yes" : "No"}</p>
                </LeadCard>
              ))}
            </div>
          ) : null}
          <RecursivePivotCards
            title="Auto-analysed pivots"
            subtitle="New related targets that were expanded during this run."
            items={recursiveExpansion && recursiveExpansion.analysed ? recursiveExpansion.analysed : []}
            onOpenSavedResult={onOpenSavedResult}
            actionLabel="Open child result"
          />
          <RecursivePivotCards
            title="Already-known pivots"
            subtitle="Related targets that were already in the database, so the run linked to them instead of re-analysing them."
            items={recursiveExpansion && recursiveExpansion.linked_existing ? recursiveExpansion.linked_existing : []}
            onOpenSavedResult={onOpenSavedResult}
            actionLabel="Open saved result"
          />
          <RecursivePivotCards
            title="Skipped pivots"
            subtitle="Targets that were discovered but not expanded during this run."
            items={recursiveExpansion && recursiveExpansion.skipped ? recursiveExpansion.skipped : []}
            onOpenSavedResult={onOpenSavedResult}
            actionLabel="Open saved result"
          />
        </SectionCard>
      ) : null}

      {currentCerts.length ? (
        <SectionCard
          title="Live TLS certificates"
          subtitle="Certificates pulled directly from discovered non-Cloudflare IPs."
          infoTitle="Live TLS certificates"
          infoBody="These are the HTTPS identity cards presented by servers we reached directly. Matching or unusual certificates can connect one domain to another behind the scenes."
        >
          <div className="card-grid">
            {currentCerts.map((cert) => (
              <LeadCard key={`${cert.ip}-${cert.sha256 || cert.cn}`} title={`${cert.ip}:${cert.port || 443}`} footer={`Valid ${formatDate(cert.not_before)} to ${formatDate(cert.not_after)}`}>
                <p><strong>CN:</strong> {cert.cn || "None"}</p>
                <p><strong>Issuer:</strong> {cert.issuer_cn || cert.issuer_org || "Unknown"}</p>
                <TypePill kind={cert.cert_type} definitions={meta.cert_types || {}} />
                <p className="muted break-word">{(cert.sans || []).slice(0, 8).join(", ") || "No SANs listed"}</p>
              </LeadCard>
            ))}
          </div>
        </SectionCard>
      ) : null}

      {trackingIds.length ? (
        <SectionCard
          title="Tracking and attribution IDs"
          subtitle="These IDs are useful pivot points when you want to find related domains."
          infoTitle="Tracking and attribution IDs"
          infoBody="These are analytics and advertising codes copied into a website. If the same code appears on several domains, the same team or contractor may be running them."
        >
          <div className="card-grid">
            {trackingIds.map((item) => (
              <LeadCard key={`${item.label}-${item.value}`} title={item.label}>
                <p className="break-word">{item.value}</p>
              </LeadCard>
            ))}
          </div>
        </SectionCard>
      ) : null}

      {interestingTxt.length ? (
        <SectionCard title="Interesting TXT records" subtitle="Ownership and platform tokens translated into normal English.">
          <div className="card-grid">
            {interestingTxt.map((item) => (
              <LeadCard key={`${item.label}-${item.value}`} title={item.label} footer={item.note}>
                <p className="break-word">{item.value}</p>
              </LeadCard>
            ))}
          </div>
        </SectionCard>
      ) : null}

      {(page.social_handles && Object.keys(page.social_handles).length) || (page.social_links && Object.keys(page.social_links).length) ? (
        <SectionCard title="Social accounts and content signals" subtitle="Useful for operator mapping, especially when the site links out to stable public profiles.">
          <div className="card-grid">
            {Object.entries(page.social_handles || {}).map(([platform, handles]) => (
              <LeadCard key={platform} title={platform.replace("_", " ")}>
                <p className="break-word">{handles.join(", ")}</p>
              </LeadCard>
            ))}
            {page.html_lang ? (
              <LeadCard title="Page language">
                <p>{page.html_lang}</p>
              </LeadCard>
            ) : null}
            {page.cms_generator ? (
              <LeadCard title="CMS generator">
                <p>{page.cms_generator}</p>
              </LeadCard>
            ) : null}
            {page.favicon_md5 ? (
              <LeadCard title="Favicon hash">
                <p className="break-word">{page.favicon_md5}</p>
              </LeadCard>
            ) : null}
          </div>
        </SectionCard>
      ) : null}

      {historicalIps.length ? (
        <SectionCard
          title="Historical IP history"
          subtitle="Older A and AAAA records can expose previous hosting even when the current site is proxied."
          infoTitle="Historical IP history"
          infoBody="This shows where the domain pointed in the past. Old IPs can reveal origin servers that are no longer visible in the current DNS."
        >
          <div className="card-grid">
            {historicalIps.map((item) => (
              <LeadCard
                key={`${item.rdata}-${item.last_seen}`}
                title={item.rdata}
                footer={`First seen ${item.first_seen || "unknown"} | Last seen ${item.last_seen || "unknown"}`}
              >
                <p>Record type: {item.rrtype}</p>
              </LeadCard>
            ))}
          </div>
        </SectionCard>
      ) : null}

      {email.dmarc || (email.dkim && Object.keys(email.dkim).length) ? (
        <SectionCard title="Email security" subtitle="Mail infrastructure can reveal who actually runs the domain.">
          <div className="card-grid">
            {email.dmarc ? (
              <LeadCard title="DMARC policy">
                <p className="break-word">{email.dmarc}</p>
              </LeadCard>
            ) : (
              <LeadCard title="DMARC policy">
                <p>No DMARC record was found, which makes spoofing easier.</p>
              </LeadCard>
            )}
            {Object.entries(email.dkim || {}).map(([selector, value]) => (
              <LeadCard key={selector} title={`DKIM: ${selector}`}>
                <p className="break-word">{value}</p>
              </LeadCard>
            ))}
          </div>
        </SectionCard>
      ) : null}
    </div>
  );
}

function DnsTab({ result }) {
  const dns = result.dns || {};
  const whois = result.whois || {};
  const zoneTransfer = result.zone_transfer || [];
  const dnsTypes = ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA"];

  return (
    <div className="stack">
      <SectionCard
        title="WHOIS"
        subtitle="The most useful registration fields, without the noisy registry boilerplate."
        infoTitle="WHOIS"
        infoBody="WHOIS is the public registration record for a domain name. It can show dates, registrar details, and sometimes contact or organisation clues."
      >
        <KeyValueList
          items={[
            { label: "Registrar", value: Array.isArray(whois.registrar) ? whois.registrar[0] : whois.registrar },
            { label: "Created", value: formatDate(whois.creation_date) },
            { label: "Updated", value: formatDate(whois.updated_date) },
            { label: "Expires", value: formatDate(whois.expiry_date) },
            { label: "Org", value: whois.org },
            { label: "Country", value: whois.country },
            { label: "Emails", value: Array.isArray(whois.emails) ? whois.emails.join(", ") : whois.emails }
          ]}
        />
      </SectionCard>

      {zoneTransfer.length ? (
        <Callout tone="warning">
          A zone transfer succeeded and exposed {zoneTransfer.length} additional records. That is a serious DNS configuration leak.
        </Callout>
      ) : null}

      <SectionCard
        title="DNS records"
        subtitle="Current DNS answers from live resolution."
        infoTitle="DNS records"
        infoBody="DNS records are the address book entries for a domain. They tell browsers and mail servers where to go when someone tries to use the domain."
      >
        <div className="card-grid">
          {dnsTypes.map((type) => {
            const value = dns[type];
            if (!value || (Array.isArray(value) && !value.length)) {
              return null;
            }
            return (
              <LeadCard key={type} title={type}>
                {Array.isArray(value) ? (
                  <ul className="plain-list">
                    {value.map((item, index) => (
                      <li key={`${type}-${index}`} className="break-word">
                        {typeof item === "object" ? JSON.stringify(item) : String(item)}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="break-word">{JSON.stringify(value)}</p>
                )}
              </LeadCard>
            );
          })}
        </div>
      </SectionCard>
    </div>
  );
}

function CertificatesTab({ result, meta }) {
  const certs = ((result.cert_transparency || {}).certs) || [];
  const issuers = ((result.cert_transparency || {}).issuer_details) || [];
  const crossSans = ((result.cert_transparency || {}).cross_domain_sans) || [];
  const subdomains = result.subdomains || [];

  return (
    <div className="stack">
      <SectionCard
        title="Certificate issuer types"
        subtitle="Every certificate family is explained in normal English so you can interpret it quickly."
        infoTitle="Certificate issuer types"
        infoBody="This groups certificates into easy-to-read categories so you can tell whether a certificate looks like a normal public website certificate, a hosting default, or something more specialised."
      >
        <div className="card-grid">
          {issuers.map((item) => (
            <LeadCard key={item.issuer} title={item.issuer}>
              <TypePill kind={item.cert_type} definitions={meta.cert_types || {}} />
            </LeadCard>
          ))}
        </div>
      </SectionCard>

      {crossSans.length ? (
        <SectionCard
          title="Cross-domain SANs"
          subtitle="Other domains that appeared on the same certificates. These can be strong infrastructure links."
          infoTitle="Cross-domain SANs"
          infoBody="A SAN list is the set of names covered by one certificate. If two domains appear on the same certificate, that is often a useful clue that they were managed together."
        >
          <div className="tag-grid">
            {crossSans.map((item) => (
              <span className="tag" key={item}>{item}</span>
            ))}
          </div>
        </SectionCard>
      ) : null}

      {subdomains.length ? (
        <SectionCard title="Subdomains found in certificate history" subtitle="Subdomains discovered through certificate transparency.">
          <div className="tag-grid">
            {subdomains.map((item) => (
              <span className="tag" key={item}>{item}</span>
            ))}
          </div>
        </SectionCard>
      ) : null}

      <SectionCard
        title="Certificate timeline"
        subtitle="Raw crt.sh history, sorted newest first."
        infoTitle="Certificate timeline"
        infoBody="This is the certificate history for the domain over time. It can show old providers, reused certificates, or additional names that were attached to the same setup."
      >
        <div className="card-grid">
          {certs.map((cert) => (
            <LeadCard
              key={`${cert.id}-${cert.issuer}`}
              title={cert.issuer || "Unknown issuer"}
              footer={`${formatDate(cert.not_before)} to ${formatDate(cert.not_after)}`}
            >
              <TypePill kind={cert.cert_type} definitions={meta.cert_types || {}} />
              <p className="muted break-word">{(cert.sans || []).slice(0, 12).join(", ") || "No SANs listed"}</p>
            </LeadCard>
          ))}
        </div>
      </SectionCard>
    </div>
  );
}

function renderLeadCollection(title, subtitle, items, meta, fallback) {
  if (!items || !items.length) {
    return fallback ? <Callout tone="info">{fallback}</Callout> : null;
  }

  return (
    <SectionCard title={title} subtitle={subtitle}>
      <div className="card-grid">
        {items.map((item, index) => (
          <LeadCard key={`${title}-${item.ip || item.subdomain || index}`} title={item.subdomain || item.ip || "Lead"}>
            {item.ip ? <p><strong>IP:</strong> {item.ip}</p> : null}
            {item.date ? <p><strong>Date:</strong> {item.date}</p> : null}
            {item.url ? <p className="break-word"><strong>URL:</strong> {item.url}</p> : null}
            {item.cn ? <p><strong>CN:</strong> {item.cn}</p> : null}
            {item.issuer || item.issuer_cn ? <p><strong>Issuer:</strong> {item.issuer || item.issuer_cn}</p> : null}
            <div className="pill-row">
              <TypePill kind={item.cert_type} definitions={meta.cert_types || {}} />
              <TypePill kind={item.server_type} definitions={meta.server_types || {}} />
            </div>
          </LeadCard>
        ))}
      </div>
    </SectionCard>
  );
}

function OriginTab({ result, meta }) {
  const origin = result.origin_candidates || {};
  const scanSections = [
    {
      key: "scan",
      title: "Google Cloud scan hits",
      subtitle: "Two-phase scan hits from targeted Google Cloud ranges."
    },
    {
      key: "provider_scan",
      title: "Provider scan hits",
      subtitle: "Hits from known RU/EU hosting providers."
    },
    {
      key: "country_scan",
      title: "Country scan hits",
      subtitle: "Hits from country-wide IPv4 allocations."
    }
  ];
  const providerSections = [
    {
      key: "censys",
      title: "Censys",
      subtitle: "Indexed TLS observations from Censys that matched the target certificate."
    },
    {
      key: "shodan",
      title: "Shodan",
      subtitle: "Indexed banner matches from Shodan that looked like the target infrastructure."
    },
    {
      key: "netlas",
      title: "Netlas",
      subtitle: "Netlas certificate-search hits that can reveal current or recent origin hosts."
    }
  ];

  return (
    <div className="stack">
      {renderLeadCollection(
        "Subdomain leaks",
        "Subdomains that resolved away from the main Cloudflare frontage.",
        origin.subdomain_leaks || [],
        meta,
        "No subdomain leak was found in this run."
      )}
      {renderLeadCollection(
        "MX and mail leads",
        "Mail hosts can reveal infrastructure relationships even when they are not the web origin.",
        origin.mx_leaks || [],
        meta
      )}
      {renderLeadCollection(
        "Wordlist hits",
        "Fast subdomain probing across common hostnames.",
        origin.wordlist_leaks || [],
        meta
      )}
      {renderLeadCollection(
        "HackerTarget",
        "Historical hostsearch results surfaced for the target.",
        origin.hackertarget || [],
        meta
      )}
      {renderLeadCollection(
        "urlscan.io",
        "Historical browser captures that exposed non-Cloudflare IPs.",
        origin.urlscan || [],
        meta
      )}

      {providerSections.map((section) => {
        const entry = origin[section.key] || {};
        const hits = entry.hits || [];
        const facetEntries = Object.entries(entry.summary_facets || {});

        return (
          <SectionCard key={section.key} title={section.title} subtitle={section.subtitle}>
            <div className="metric-grid">
              <Metric label="Status" value={entry.status || (entry.skipped ? "skipped" : "unknown")} />
              <Metric label="Mode" value={entry.mode || "unknown"} />
              <Metric label="Query" value={entry.query_type || "n/a"} />
              <Metric label="Hits" value={formatNumber(entry.total !== undefined ? entry.total : hits.length)} />
            </div>
            {entry.account ? (
              <Callout tone="info">
                {`Account plan: ${entry.account.plan || "unknown"} | unlocked: ${entry.account.unlocked ? "yes" : "no"} | query credits: ${formatNumber(entry.account.query_credits || 0)}`}
              </Callout>
            ) : null}
            {entry.reason ? (
              <Callout tone={entry.status === "paid_only" ? "warning" : "info"}>
                {entry.reason}
              </Callout>
            ) : null}
            {entry.error ? <Callout tone="warning">{entry.error}</Callout> : null}
            {facetEntries.length ? (
              <LeadCard title="Facet summary">
                {facetEntries.map(([facetName, values]) => (
                  <p key={facetName} className="break-word">
                    <strong>{facetName}:</strong> {formatFacetBuckets(values)}
                  </p>
                ))}
              </LeadCard>
            ) : null}
            {hits.length ? (
              <div className="card-grid">
                {hits.map((hit, index) => (
                  <LeadCard key={`${section.key}-${hit.ip || index}`} title={hit.ip || "Lead"}>
                    {hit.asn || hit.asn_name ? <p><strong>ASN:</strong> {hit.asn_name || hit.asn}</p> : null}
                    {hit.network_name || hit.network_cidr ? (
                      <p><strong>Network:</strong> {hit.network_name || hit.network_cidr}</p>
                    ) : null}
                    {hit.country ? <p><strong>Country:</strong> {hit.country}</p> : null}
                    {hit.proxy_family ? <p><strong>Reverse proxy:</strong> {hit.proxy_family} ({formatConfidence(hit.proxy_confidence)})</p> : null}
                    {hit.url ? <p className="break-word"><strong>URL:</strong> {hit.url}</p> : null}
                    <div className="pill-row">
                      <TypePill kind={hit.server_type} definitions={meta.server_types || {}} />
                    </div>
                  </LeadCard>
                ))}
              </div>
            ) : entry.skipped ? (
              <Callout tone="info">{entry.reason || `${section.title} was skipped in this run.`}</Callout>
            ) : (
              <Callout tone="info">{`No ${section.title} hits were found in this run.`}</Callout>
            )}
          </SectionCard>
        );
      })}

      {scanSections.map((section) => {
        const entry = origin[section.key];
        if (!entry || entry.skipped) {
          return (
            <Callout key={section.key} tone="info">
              {entry && entry.reason ? entry.reason : `${section.title} was not run in this analysis.`}
            </Callout>
          );
        }

        return (
          <SectionCard key={section.key} title={section.title} subtitle={section.subtitle}>
            <div className="metric-grid">
              <Metric label="CIDRs" value={formatNumber(entry.cidrs_scanned || 0)} />
              <Metric label="IPs attempted" value={formatNumber(entry.hosts_attempted || 0)} />
              <Metric label="Port 443 open" value={formatNumber(entry.open_port_count || 0)} />
              <Metric label="Hits" value={formatNumber((entry.hits || []).length)} detail={entry.phase1_method || "n/a"} />
            </div>
            <div className="card-grid">
              {(entry.hits || []).map((hit) => (
                <LeadCard key={`${section.key}-${hit.ip}-${hit.port || 443}`} title={`${hit.ip}:${hit.port || 443}`}>
                  <p><strong>CN:</strong> {hit.cn || "Unknown"}</p>
                  <p><strong>Issuer:</strong> {hit.issuer || "Unknown"}</p>
                  <div className="pill-row">
                    <TypePill kind={hit.cert_type} definitions={meta.cert_types || {}} />
                    <TypePill kind={hit.server_type} definitions={meta.server_types || {}} />
                  </div>
                </LeadCard>
              ))}
            </div>
          </SectionCard>
        );
      })}
    </div>
  );
}

function IpDetailsTab({ result, meta }) {
  if (result.type === "ip") {
    return (
      <SectionCard
        title="IP details"
        subtitle="Everything the backend learned directly from this IP."
        infoTitle="IP details"
        infoBody="This is the direct profile for one IP address: what name points back to it, what network owns it, and whether it looks like a hidden origin server or just shared infrastructure."
      >
        <div className="card-grid">
          <LeadCard title={result.input}>
            <p><strong>PTR:</strong> {result.ptr || "None"}</p>
            <div className="pill-row">
              <TypePill kind={result.server_type} definitions={meta.server_types || {}} />
            </div>
            <p><strong>Cloudflare:</strong> {result.cloudflare ? "Yes" : "No"}</p>
            {result.proxy_family ? <p><strong>Reverse proxy:</strong> {result.proxy_family} ({formatConfidence(result.proxy_confidence)})</p> : null}
          </LeadCard>
          <LeadCard title="ASN and network">
            <p><strong>ASN:</strong> {(result.asn_info || {}).asn_description || (result.asn_info || {}).asn || "Unknown"}</p>
            <p><strong>Registry:</strong> {result.asn_registry || "Unknown"}</p>
            <p><strong>Network name:</strong> {result.network_name || "Unknown"}</p>
            <p><strong>Network CIDR:</strong> {result.network_cidr || "Unknown"}</p>
            <p><strong>Country:</strong> {(result.asn_info || {}).asn_country || (result.asn_info || {}).network_country || "Unknown"}</p>
          </LeadCard>
        </div>
      </SectionCard>
    );
  }

  const ipDetails = result.ip_details || {};
  const entries = Object.entries(ipDetails);
  if (!entries.length) {
    return <Callout tone="info">No IP detail records were produced for this result.</Callout>;
  }

  return (
    <SectionCard
      title="IP details"
      subtitle="Each discovered IP is classified in plain English to help separate useful leads from infrastructure noise."
      infoTitle="IP details"
      infoBody="These are the IP addresses the app found around the target. The labels are there to help you tell the difference between a meaningful origin lead and a generic shared host."
    >
      <div className="card-grid">
        {entries.map(([ipAddress, info]) => (
          <LeadCard key={ipAddress} title={ipAddress}>
            <div className="pill-row">
              <TypePill kind={info.server_type} definitions={meta.server_types || {}} />
            </div>
            <p><strong>PTR:</strong> {info.ptr || "None"}</p>
            <p><strong>Sources:</strong> {(info.sources || []).join(", ") || "Unknown"}</p>
            {info.asn_info ? (
              <p><strong>ASN:</strong> {info.asn_info.asn_description || info.asn_info.network_name || info.asn_info.asn || "Unknown"}</p>
            ) : null}
            {info.asn_registry ? <p><strong>Registry:</strong> {info.asn_registry}</p> : null}
            {info.network_name ? <p><strong>Network name:</strong> {info.network_name}</p> : null}
            {info.network_cidr ? <p><strong>Network CIDR:</strong> {info.network_cidr}</p> : null}
            {info.proxy_family ? <p><strong>Reverse proxy:</strong> {info.proxy_family} ({formatConfidence(info.proxy_confidence)})</p> : null}
            {(info.other_domains_on_ip || []).length ? (
              <p className="break-word"><strong>Co-hosted:</strong> {(info.other_domains_on_ip || []).slice(0, 10).join(", ")}</p>
            ) : null}
          </LeadCard>
        ))}
      </div>
    </SectionCard>
  );
}

function ResultPanel({ result, meta }) {
  const [activeTab, setActiveTab] = useState("overview");

  useEffect(() => {
    setActiveTab("overview");
  }, [result]);

  return (
    <SectionCard
      title={`Results for ${result.input}`}
      subtitle="Collected evidence, grouped into the views investigators actually use."
      infoTitle="How to read the results"
      infoBody="The tabs split the evidence into plain buckets: ownership clues, DNS and registration data, certificate clues, origin leads, and IP details. You do not need to read every section to spot useful overlap."
      actions={
        <button className="secondary-button" onClick={() => downloadResult(result)} type="button">
          Download JSON
        </button>
      }
    >
      <div className="tab-row">
        {RESULT_TABS.map((tab) => (
          <TabButton key={tab.id} active={activeTab === tab.id} label={tab.label} onClick={() => setActiveTab(tab.id)} />
        ))}
      </div>

      {activeTab === "overview" ? <OverviewTab result={result} meta={meta} /> : null}
      {activeTab === "dns" ? <DnsTab result={result} /> : null}
      {activeTab === "certs" ? <CertificatesTab result={result} meta={meta} /> : null}
      {activeTab === "origin" ? <OriginTab result={result} meta={meta} /> : null}
      {activeTab === "ips" ? <IpDetailsTab result={result} meta={meta} /> : null}
    </SectionCard>
  );
}

function NetworkGraphTab({ clusters, recent, theme }) {
  const graphRef = useRef(null);
  const focusOptions = getDomainTargets(recent);
  const [controls, setControls] = useState({
    includeIp: true,
    includeAsn: true,
    includeTracking: true,
    includeFavicon: true,
    includeTls: true,
    minScore: 5,
    maxLinks: 24,
    focus: ""
  });
  const [selection, setSelection] = useState(null);
  const [hoveredId, setHoveredId] = useState("");

  const graph = buildNetworkModel(clusters, controls);
  const updateControl = (key, value) => {
    setControls((current) => ({
      ...current,
      [key]: value
    }));
  };
  const graphData = {
    nodes: graph.nodes,
    links: graph.edges
  };
  const colors = GRAPH_THEME[theme] || GRAPH_THEME.dark;
  const activeNodeId = selection && selection.type === "node" ? selection.id : "";
  const activeEdgeKey = selection && selection.type === "edge" ? selection.key : "";
  const relatedNodeIds = new Set();

  graph.edges.forEach((edge) => {
    if (activeNodeId && edgeTouchesNode(edge, activeNodeId)) {
      relatedNodeIds.add(getEdgeEndpointId(edge.source));
      relatedNodeIds.add(getEdgeEndpointId(edge.target));
    }
  });

  const selectedNode = activeNodeId
    ? graph.nodes.find((node) => node.id === activeNodeId) || null
    : null;
  const selectedEdge = activeEdgeKey
    ? graph.edges.find((edge) => edge.key === activeEdgeKey) || null
    : null;
  const linkedNeighbors = selectedNode
    ? graph.edges
      .filter((edge) => edgeTouchesNode(edge, selectedNode.id))
      .map((edge) => ({
        edge,
        peer: getEdgeEndpointId(edge.source) === selectedNode.id ? getEdgeEndpointId(edge.target) : getEdgeEndpointId(edge.source)
      }))
      .sort((a, b) => b.edge.score - a.edge.score || a.peer.localeCompare(b.peer))
    : [];

  useEffect(() => {
    if (!selection) {
      return;
    }

    if (selection.type === "node" && !graph.nodes.some((node) => node.id === selection.id)) {
      setSelection(null);
    }

    if (selection.type === "edge" && !graph.edges.some((edge) => edge.key === selection.key)) {
      setSelection(null);
    }
  }, [graph.edges, graph.nodes, selection]);

  useEffect(() => {
    if (!graphRef.current || !graph.nodes.length) {
      return undefined;
    }

    const timer = window.setTimeout(() => {
      graphRef.current.zoomToFit(650, 90);
    }, 220);

    return () => {
      window.clearTimeout(timer);
    };
  }, [
    controls.focus,
    controls.includeAsn,
    controls.includeFavicon,
    controls.includeIp,
    controls.includeTls,
    controls.includeTracking,
    controls.maxLinks,
    controls.minScore,
    graph.edges.length,
    graph.nodes.length
  ]);

  return (
    <div className="stack">
      <div className="network-intro">
        <div>
          <h3>Interactive relationship map</h3>
          <p className="muted">
            Each line connects domains that share something meaningful, like the same TLS fingerprint, tracking code, direct IP, or provider network. Current TLS and direct-IP matches are weighted highest, while ASN and CDN-style overlaps stay softer.
          </p>
        </div>
        <div className="graph-legend">
          {Object.entries(NETWORK_LINK_META).map(([key, value]) => (
            <span className="legend-chip" key={key}>
              <span className="legend-swatch" style={{ background: value.color }} />
              {value.label}
            </span>
          ))}
        </div>
      </div>

      <div className="network-grid">
        <div className="graph-wrap">
          <div className="network-controls">
            <div className="network-toggle-group">
              <label className="checkbox-chip">
                <input
                  checked={controls.includeTracking}
                  onChange={() => updateControl("includeTracking", !controls.includeTracking)}
                  type="checkbox"
                />
                <span>Tracking IDs</span>
                <InfoPopover
                  title="Tracking IDs"
                  body="These are analytics or advertising codes. If two domains share one, there is a good chance the same team, agency, or operator controls both sites."
                />
              </label>
              <label className="checkbox-chip">
                <input
                  checked={controls.includeTls}
                  onChange={() => updateControl("includeTls", !controls.includeTls)}
                  type="checkbox"
                />
                <span>TLS certs</span>
                <InfoPopover
                  title="TLS certificates"
                  body="A TLS certificate is the digital ID card a site shows when it uses HTTPS. Shared certificates often mean the same operator or hosting setup is behind multiple domains."
                />
              </label>
              <label className="checkbox-chip">
                <input
                  checked={controls.includeFavicon}
                  onChange={() => updateControl("includeFavicon", !controls.includeFavicon)}
                  type="checkbox"
                />
                <span>Favicons</span>
                <InfoPopover
                  title="Favicons"
                  body="A favicon is the small browser-tab icon for a site. Matching favicons can be a useful clue that sites were built from the same template or by the same group."
                />
              </label>
              <label className="checkbox-chip">
                <input
                  checked={controls.includeIp}
                  onChange={() => updateControl("includeIp", !controls.includeIp)}
                  type="checkbox"
                />
                <span>Shared IPs</span>
                <InfoPopover
                  title="Shared IPs"
                  body="A shared IP means two domains point to the same server address. This can be a strong lead when the IP looks dedicated, but a weaker lead when it belongs to a large shared host or CDN."
                />
              </label>
              <label className="checkbox-chip">
                <input
                  checked={controls.includeAsn}
                  onChange={() => updateControl("includeAsn", !controls.includeAsn)}
                  type="checkbox"
                />
                <span>ASNs</span>
                <InfoPopover
                  title="ASNs and networks"
                  body="ASN overlap means domains were seen in the same provider network. It is useful context, especially on smaller or dedicated-looking networks, but it is normally weaker than an exact TLS or direct-IP match."
                />
              </label>
            </div>

            <div className="network-range-row">
              <label className="range-control" htmlFor="graph-min-score">
                <span>
                  Minimum strength
                  <InfoPopover
                    title="Minimum strength"
                    body="Higher numbers hide weaker links so you can focus on the strongest evidence first."
                  />
                </span>
                <input
                  id="graph-min-score"
                  min="1"
                  max="30"
                  type="range"
                  value={controls.minScore}
                  onChange={(event) => updateControl("minScore", Number(event.target.value))}
                />
                <strong>{controls.minScore}</strong>
              </label>

              <label className="range-control" htmlFor="graph-max-links">
                <span>
                  Links shown
                  <InfoPopover
                    title="Links shown"
                    body="This controls how many domain-to-domain relationships are visible at once. The graph keeps the highest-scoring ones first."
                  />
                </span>
                <input
                  id="graph-max-links"
                  min="8"
                  max="60"
                  step="2"
                  type="range"
                  value={controls.maxLinks}
                  onChange={(event) => updateControl("maxLinks", Number(event.target.value))}
                />
                <strong>{controls.maxLinks}</strong>
              </label>

              <div className="control-inline control-inline-wide">
                <label htmlFor="graph-focus">
                  Focus on a domain
                  <InfoPopover
                    title="Focus on a domain"
                    body="This shrinks the graph down to one domain and the domains most strongly connected to it, which is useful when the full network is too busy."
                  />
                </label>
                <select
                  id="graph-focus"
                  value={controls.focus}
                  onChange={(event) => updateControl("focus", event.target.value)}
                >
                  <option value="">All domains</option>
                  {focusOptions.map((item) => (
                    <option key={item} value={item}>{item}</option>
                  ))}
                </select>
              </div>

              <div className="button-row">
                <button
                  className="secondary-button"
                  onClick={() => {
                    if (graphRef.current) {
                      graphRef.current.zoomToFit(500, 90);
                    }
                  }}
                  type="button"
                >
                  Fit graph
                </button>
                <button
                  className="secondary-button"
                  onClick={() => {
                    setSelection(null);
                    setHoveredId("");
                    setControls({
                      includeIp: true,
                      includeAsn: true,
                      includeTracking: true,
                      includeFavicon: true,
                      includeTls: true,
                      minScore: 5,
                      maxLinks: 24,
                      focus: ""
                    });
                  }}
                  type="button"
                >
                  Reset view
                </button>
              </div>
            </div>
          </div>

          {graph.edges.length ? (
            <div className="graph-canvas">
              <div className="graph-meta-bar">
                <span>{graph.nodes.length} domains in view</span>
                <span>{graph.edges.length} strongest links shown</span>
                <span>Top score {graph.maxScore || 0}</span>
                {graph.hiddenEdgeCount ? <span>{graph.hiddenEdgeCount} weaker links hidden</span> : null}
              </div>

              <ForceGraph2D
                ref={graphRef}
                graphData={graphData}
                backgroundColor={colors.background}
                cooldownTicks={120}
                d3AlphaDecay={0.035}
                d3VelocityDecay={0.25}
                enableNodeDrag
                linkColor={(edge) => {
                  if (activeEdgeKey && edge.key === activeEdgeKey) {
                    return colors.edgeHighlight;
                  }
                  if (hoveredId && edge.key === hoveredId) {
                    return colors.edgeHighlight;
                  }
                  if (activeNodeId && edgeTouchesNode(edge, activeNodeId)) {
                    return edge.primaryColor;
                  }
                  return edge.primaryColor;
                }}
                linkCurvature={0.08}
                linkDirectionalParticles={0}
                linkWidth={(edge) => {
                  if (activeEdgeKey && edge.key === activeEdgeKey) {
                    return 6;
                  }
                  return 1.2 + edge.score * 0.32;
                }}
                linkLabel={(edge) => {
                  const source = getEdgeEndpointId(edge.source);
                  const target = getEdgeEndpointId(edge.target);
                  return `${source} ↔ ${target} | ${describeLinkStrength(edge.score)} | score ${edge.score}`;
                }}
                nodeAutoColorBy="id"
                nodeCanvasObject={(node, context, globalScale) => {
                  const label = shortLabel(node.id, 30);
                  const isActive = activeNodeId === node.id;
                  const isRelated = activeNodeId && relatedNodeIds.has(node.id);
                  const isHovered = hoveredId === node.id;
                  const fontSize = Math.max(11, 15 / globalScale);
                  const paddingX = 7 / globalScale;
                  const paddingY = 5 / globalScale;
                  context.font = `600 ${fontSize}px "Space Grotesk", "Manrope", sans-serif`;
                  const textWidth = context.measureText(label).width;
                  const labelWidth = textWidth + paddingX * 2;
                  const labelHeight = fontSize + paddingY * 2;

                  context.fillStyle = colors.label;
                  context.fillRect(node.x - labelWidth / 2, node.y + 13 / globalScale, labelWidth, labelHeight);
                  context.fillStyle = colors.nodeText;
                  context.fillText(label, node.x - textWidth / 2, node.y + labelHeight + 5 / globalScale);

                  context.beginPath();
                  context.arc(node.x, node.y, 6 + Math.min(node.displayWeight, 24) * 0.34, 0, Math.PI * 2);
                  context.fillStyle = isActive
                    ? colors.edgeHighlight
                    : isHovered || isRelated || controls.focus === node.id
                      ? colors.nodeBase
                      : colors.nodeMuted;
                  context.fill();
                  context.lineWidth = 1.6 / globalScale;
                  context.strokeStyle = colors.nodeStroke;
                  context.stroke();
                }}
                nodeCanvasObjectMode={() => "after"}
                nodeColor={(node) => {
                  if (activeNodeId === node.id) {
                    return colors.edgeHighlight;
                  }
                  if (activeNodeId && relatedNodeIds.has(node.id)) {
                    return colors.nodeBase;
                  }
                  if (controls.focus === node.id) {
                    return colors.nodeBase;
                  }
                  return colors.nodeMuted;
                }}
                nodeLabel={(node) => `${node.id} | visible strength ${node.displayWeight}`}
                nodeRelSize={7}
                nodeVal={(node) => Math.max(2, node.displayWeight)}
                onLinkClick={(edge) => {
                  setSelection({ type: "edge", key: edge.key });
                }}
                onLinkHover={(edge) => {
                  setHoveredId(edge ? `${getEdgeEndpointId(edge.source)}|||${getEdgeEndpointId(edge.target)}` : "");
                }}
                onNodeClick={(node) => {
                  setSelection({ type: "node", id: node.id });
                  if (graphRef.current) {
                    graphRef.current.centerAt(node.x, node.y, 500);
                    graphRef.current.zoom(2.2, 500);
                  }
                }}
                onNodeHover={(node) => {
                  setHoveredId(node ? node.id : "");
                }}
              />
            </div>
          ) : (
            <Callout tone="info">
              No links match the current graph filters. Lower the minimum strength, raise the link limit, or clear the domain focus.
            </Callout>
          )}
        </div>

        <div className="graph-sidebar">
          <SectionCard
            title={selectedEdge ? "Selected connection" : selectedNode ? "Selected domain" : "How to read this"}
            subtitle={
              selectedEdge
                ? "This is why the two domains are connected."
                : selectedNode
                  ? "This shows the domain's strongest visible relationships."
                  : "Click a domain or a line in the graph to inspect it."
            }
            infoTitle="How domain links work"
            infoBody="A connection between domains means they share one or more signals. That does not always prove the same owner, but it does tell you they are close enough to investigate together."
          >
            {selectedEdge ? (
              <div className="stack">
                <div className="metric-grid">
                  <Metric
                    label="Domains"
                    value={`${getEdgeEndpointId(selectedEdge.source)} ↔ ${getEdgeEndpointId(selectedEdge.target)}`}
                  />
                  <Metric label="Strength" value={describeLinkStrength(selectedEdge.score)} detail={`Score ${selectedEdge.score}`} />
                  <Metric label="Signals" value={selectedEdge.kinds.map((kind) => NETWORK_LINK_META[kind].label).join(", ")} />
                </div>
                <div className="strength-list">
                  {selectedEdge.details.map((detail, index) => (
                    <div className="edge-rank" key={`${selectedEdge.key}-${detail.kind}-${index}`}>
                      <div className="edge-rank-header">
                        <strong>{NETWORK_LINK_META[detail.kind].label}</strong>
                        <span>Score {detail.score}</span>
                      </div>
                      <p className="muted">
                        {detail.kind === "ip"
                          ? "These domains touched the same server address or hosting network."
                          : detail.kind === "tls"
                            ? "These domains reused the same HTTPS certificate or certificate fingerprint."
                            : detail.kind === "tracking"
                              ? "These domains shared the same analytics or advertising identifier."
                              : "These domains used the same browser-tab icon."}
                      </p>
                      <p>{detail.descriptor}</p>
                    </div>
                  ))}
                </div>
                <div className="button-row">
                  <button className="secondary-button" onClick={() => setSelection(null)} type="button">
                    Clear selection
                  </button>
                  <button
                    className="secondary-button"
                    onClick={() => updateControl("focus", getEdgeEndpointId(selectedEdge.source))}
                    type="button"
                  >
                    Focus {shortLabel(getEdgeEndpointId(selectedEdge.source), 18)}
                  </button>
                </div>
              </div>
            ) : null}

            {selectedNode ? (
              <div className="stack">
                <div className="metric-grid">
                  <Metric label="Domain" value={selectedNode.id} />
                  <Metric label="Visible links" value={formatNumber(selectedNode.visibleDegree)} />
                  <Metric label="Combined strength" value={formatNumber(selectedNode.displayWeight)} />
                </div>
                <p className="muted">
                  In plain English: this domain shares enough infrastructure or tracking clues with the domains below that they are probably worth checking together.
                </p>
                <div className="strength-list">
                  {linkedNeighbors.slice(0, 6).map(({ edge, peer }) => (
                    <div className="edge-rank" key={edge.key}>
                      <div className="edge-rank-header">
                        <strong>{peer}</strong>
                        <span>Score {edge.score}</span>
                      </div>
                      <p className="muted">{edge.kinds.map((kind) => NETWORK_LINK_META[kind].label).join(", ")}</p>
                    </div>
                  ))}
                </div>
                <div className="button-row">
                  <button
                    className="secondary-button"
                    onClick={() => updateControl("focus", selectedNode.id)}
                    type="button"
                  >
                    Focus this domain
                  </button>
                  <button className="secondary-button" onClick={() => setSelection(null)} type="button">
                    Clear selection
                  </button>
                </div>
              </div>
            ) : null}

            {!selectedNode && !selectedEdge ? (
              <div className="stack">
                <Callout tone="info">
                  Thick, bright lines mean stronger evidence. A line with TLS or tracking overlap is usually more interesting than a weak shared-hosting IP overlap.
                </Callout>
                <div className="strength-list">
                  {graph.edges.slice(0, 8).map((edge, index) => (
                    <div className="edge-rank" key={edge.key}>
                      <div className="edge-rank-header">
                        <strong>{index + 1}. {getEdgeEndpointId(edge.source)} ↔ {getEdgeEndpointId(edge.target)}</strong>
                        <span>Score {edge.score}</span>
                      </div>
                      <p className="muted">{describeLinkStrength(edge.score)} | {edge.kinds.map((kind) => NETWORK_LINK_META[kind].label).join(", ")}</p>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </SectionCard>
        </div>
      </div>
    </div>
  );
}

function ExplorerPanel({
  meta,
  recent,
  clusters,
  connections,
  theme,
  selectedTarget,
  setSelectedTarget,
  onOpenSavedResult
}) {
  const [activeTab, setActiveTab] = useState("network");
  const domainTargets = getDomainTargets(recent);

  return (
    <SectionCard
      title="Relationship explorer"
      subtitle="Move from one domain to the next using stored overlaps, shared infrastructure, and historical results."
      infoTitle="What this explorer does"
      infoBody="This area helps you pivot from one domain to related ones. In plain English, it is the part of the app that answers 'what else looks connected to this site, and why?'"
    >
      <div className="tab-row">
        {EXPLORER_TABS.map((tab) => (
          <TabButton key={tab.id} active={activeTab === tab.id} label={tab.label} onClick={() => setActiveTab(tab.id)} />
        ))}
      </div>

      {activeTab === "recent" ? (
        <div className="stack">
          <Callout tone="info">
            These are saved investigations you can reopen. Think of this as your case history, not live traffic.
          </Callout>
          <div className="card-grid">
            {recent.map((item) => (
              <LeadCard
                key={item.id}
                title={item.target}
                footer={`${item.type.toUpperCase()} | ${cloudflareLabel(item.cloudflare_fronted)} | ${formatDateTime(item.timestamp)}`}
              >
                <button className="inline-action" onClick={() => onOpenSavedResult(item.id)} type="button">
                  Open saved result
                </button>
              </LeadCard>
            ))}
          </div>
        </div>
      ) : null}

      {activeTab === "network" ? (
        <NetworkGraphTab clusters={clusters} recent={recent} theme={theme} />
      ) : null}

      {activeTab === "ip" ? (
        <div className="stack">
          <Callout tone="info">
            A shared IP means more than one domain touched the same server address. That can suggest a real relationship, but it is weaker when the IP belongs to a big shared host or CDN.
          </Callout>
          <div className="card-grid">
            {clusters.ip.map((item) => (
              <LeadCard key={item.ip} title={item.ip} footer={`${item.target_count} linked targets`}>
                <div className="pill-row">
                  <TypePill kind={item.label} definitions={meta.server_types || {}} />
                </div>
                <p className="break-word">{item.targets}</p>
                {item.asn_desc ? <p>{item.asn_desc}</p> : null}
              </LeadCard>
            ))}
          </div>
        </div>
      ) : null}

      {activeTab === "tracking" ? (
        <div className="stack">
          <Callout tone="info">
            Tracking IDs are the analytics or ad codes copied into a site. Shared tracking IDs often mean the same people, agency, or toolkit were involved.
          </Callout>
          <div className="card-grid">
            {clusters.tracking.map((item) => (
              <LeadCard key={`${item.id_type}-${item.id_value}`} title={`${item.id_type}: ${item.id_value}`} footer={`${item.target_count} linked targets`}>
                <p className="break-word">{item.targets}</p>
              </LeadCard>
            ))}
          </div>
        </div>
      ) : null}

      {activeTab === "favicon" ? (
        <div className="stack">
          <Callout tone="info">
            Favicons are the small tab icons a website uses. Matching favicons are not proof by themselves, but they are a good clue that sites share a template or operator.
          </Callout>
          <div className="card-grid">
            {clusters.favicon.map((item) => (
              <LeadCard key={item.md5} title={item.md5} footer={`${item.target_count} linked targets`}>
                <p className="break-word">{item.targets}</p>
              </LeadCard>
            ))}
          </div>
        </div>
      ) : null}

      {activeTab === "tls" ? (
        <div className="stack">
          <Callout tone="info">
            TLS fingerprints come from HTTPS certificates. When several domains reuse the same certificate identity, that is often one of the strongest technical links in the app.
          </Callout>
          <div className="card-grid">
            {clusters.tls.map((item) => (
              <LeadCard key={item.sha256} title={item.cn || item.sha256.slice(0, 16)} footer={`${item.target_count} linked targets`}>
                <p><strong>Issuer:</strong> {item.issuer_cn || "Unknown"}</p>
                <p className="break-word"><strong>Fingerprint:</strong> {item.sha256}</p>
                <p className="break-word">{item.targets}</p>
              </LeadCard>
            ))}
          </div>
        </div>
      ) : null}

      {activeTab === "connections" ? (
        <div className="stack">
          <Callout tone="info">
            Domain connections show what a chosen domain shares with other stored domains. In plain English, this is the "why does the app think these sites belong in the same conversation?" view.
          </Callout>
          <div className="field-row">
            <label htmlFor="connections-target">Choose a stored domain</label>
            <select
              id="connections-target"
              value={selectedTarget}
              onChange={(event) => setSelectedTarget(event.target.value)}
            >
              <option value="">Select a domain</option>
              {domainTargets.map((item) => (
                <option key={item} value={item}>{item}</option>
              ))}
            </select>
          </div>

          {connections ? (
            <div className="stack">
              <div className="metric-grid">
                <Metric label="Cloudflare" value={cloudflareLabel(connections.cloudflare_fronted)} />
                <Metric label="Registrar" value={(connections.whois || {}).registrar || "Unknown"} />
                <Metric label="Created" value={formatDate((connections.whois || {}).creation_date)} />
                <Metric label="Target" value={connections.target} />
              </div>

              {CONNECTION_SECTIONS.map((section) => {
                const items = (connections.connections || {})[section.key] || [];
                if (!items.length) {
                  return null;
                }
                return (
                  <SectionCard key={section.key} title={section.title}>
                    <div className="card-grid">
                      {items.map((item, index) => (
                        <LeadCard key={`${section.key}-${index}`} title={item.id_value || item.email || item.ip || item.nameserver || item.md5 || item.cn || "Link"}>
                          {item.shared_with && item.shared_with.length ? (
                            <p className="break-word"><strong>Shared with:</strong> {item.shared_with.join(", ")}</p>
                          ) : (
                            <p>No other stored domains share this attribute yet.</p>
                          )}
                          {item.label ? (
                            <div className="pill-row">
                              <TypePill kind={item.label} definitions={meta.server_types || {}} />
                            </div>
                          ) : null}
                        </LeadCard>
                      ))}
                    </div>
                  </SectionCard>
                );
              })}
            </div>
          ) : (
            <Callout tone="info">Choose a stored domain to see cross-database connections.</Callout>
          )}
        </div>
      ) : null}
    </SectionCard>
  );
}

const GRAPH_VIEW_PADDING = 120;
const GRAPH_MIN_ZOOM = 0.04;
const GRAPH_MAX_ZOOM = 2.2;
const GRAPH_INITIAL_MIN_ZOOM = 0.74;
const GRAPH_INITIAL_MAX_ZOOM = 1.18;
const GRAPH_EDGE_HIT_STROKE_WIDTH = 14;

function hashGraphValue(value) {
  let hash = 2166136261;
  const text = String(value || "");
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function getGraphNodeRadius() {
  return 20;
}

function getGraphLinkCoordinates(source, target, index, total) {
  const dx = (target.x || 0) - (source.x || 0);
  const dy = (target.y || 0) - (source.y || 0);
  const distance = Math.sqrt(dx * dx + dy * dy) || 1;
  const unitX = dx / distance;
  const unitY = dy / distance;
  const perpendicularX = -unitY;
  const perpendicularY = unitX;
  const offsetIndex = index - (total - 1) / 2;
  const offset = total > 1 ? offsetIndex * 7 : 0;
  const sourceRadius = getGraphNodeRadius(source) + 5;
  const targetRadius = getGraphNodeRadius(target) + 5;

  return {
    x1: (source.x || 0) + unitX * sourceRadius + perpendicularX * offset,
    y1: (source.y || 0) + unitY * sourceRadius + perpendicularY * offset,
    x2: (target.x || 0) - unitX * targetRadius + perpendicularX * offset,
    y2: (target.y || 0) - unitY * targetRadius + perpendicularY * offset
  };
}

function GraphSignalLegendChip({ kind, compact = false }) {
  const meta = NETWORK_LINK_META[kind];
  if (!meta) {
    return null;
  }

  return (
    <span className={compact ? "legend-chip graph-signal-chip compact" : "legend-chip graph-signal-chip"}>
      <span className="legend-swatch" style={{ background: meta.color }} />
      <strong>{meta.label}</strong>
      <InfoPopover title={meta.headline} body={meta.meaning} />
    </span>
  );
}

function computeGraphAnchorPosition(id, index, total) {
  const angle = (index / Math.max(total, 1)) * Math.PI * 2 - Math.PI / 2;
  const wobble = (hashGraphValue(id) % 80) - 40;
  const radius = Math.max(280, total * 36) + wobble;
  return {
    x: Math.cos(angle) * radius,
    y: Math.sin(angle) * radius
  };
}

function computeGraphBounds(nodes) {
  if (!nodes.length) {
    return {
      minX: 0,
      maxX: 0,
      minY: 0,
      maxY: 0,
      width: 1,
      height: 1,
      centerX: 0,
      centerY: 0
    };
  }

  const xs = nodes.map((node) => node.x || 0);
  const ys = nodes.map((node) => node.y || 0);
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);

  return {
    minX,
    maxX,
    minY,
    maxY,
    width: Math.max(maxX - minX, 1),
    height: Math.max(maxY - minY, 1),
    centerX: (minX + maxX) / 2,
    centerY: (minY + maxY) / 2
  };
}

function computeGraphNearestDistance(nodes) {
  if (nodes.length < 2) {
    return null;
  }

  let nearest = Number.POSITIVE_INFINITY;
  for (let leftIndex = 0; leftIndex < nodes.length; leftIndex += 1) {
    const left = nodes[leftIndex];
    for (let rightIndex = leftIndex + 1; rightIndex < nodes.length; rightIndex += 1) {
      const right = nodes[rightIndex];
      const dx = (right.x || 0) - (left.x || 0);
      const dy = (right.y || 0) - (left.y || 0);
      const distance = Math.sqrt(dx * dx + dy * dy);
      if (distance < nearest) {
        nearest = distance;
      }
    }
  }

  return Number.isFinite(nearest) ? nearest : null;
}

function computeGraphInitialViewport(nodes, width, height) {
  const bounds = computeGraphBounds(nodes);
  const usableWidth = Math.max(width - GRAPH_VIEW_PADDING * 2, 1);
  const usableHeight = Math.max(height - GRAPH_VIEW_PADDING * 2, 1);
  const fitZoom = Math.min(usableWidth / bounds.width, usableHeight / bounds.height);
  const nearest = computeGraphNearestDistance(nodes);
  const spacingZoom = nearest ? 132 / Math.max(nearest, 1) : 1;
  const scale = Math.min(
    GRAPH_INITIAL_MAX_ZOOM,
    Math.max(fitZoom, spacingZoom, GRAPH_INITIAL_MIN_ZOOM)
  );

  return {
    k: scale,
    x: width / 2 - bounds.centerX * scale,
    y: height / 2 - bounds.centerY * scale
  };
}

function resolveGraphLinkNodes(link) {
  if (typeof link.source === "string" || typeof link.target === "string") {
    return null;
  }
  return {
    source: link.source,
    target: link.target
  };
}

function GraphGuideCard({ kind, dimmed = false }) {
  const meta = NETWORK_LINK_META[kind];
  if (!meta) {
    return null;
  }

  return (
    <article className={dimmed ? "graph-guide-card dimmed" : "graph-guide-card"}>
      <div className="graph-guide-card-header">
        <div className="graph-guide-card-title">
          <span className="legend-swatch graph-guide-swatch" style={{ background: meta.color }} />
          <strong>{meta.headline}</strong>
        </div>
        <InfoPopover title={meta.headline} body={meta.meaning} />
      </div>
      <p>{meta.summary}</p>
      <p className="muted">{meta.meaning}</p>
      <small>{meta.caution}</small>
    </article>
  );
}

function getPrimaryEdgeKind(edge) {
  const orderedKinds = getOrderedNetworkKinds(edge.kinds);
  return orderedKinds[0] || edge.primaryKind || "ip";
}

function CompactDomainCard({ domain, subtitle, actionLabel, onAction }) {
  return (
    <div className="graph-sidebar-domain-card">
      <div>
        <p className="graph-sidebar-domain-name">{domain}</p>
        {subtitle ? <p className="graph-sidebar-domain-subtitle">{subtitle}</p> : null}
      </div>
      {actionLabel && onAction ? (
        <button className="graph-link-button" onClick={onAction} type="button">
          {actionLabel}
        </button>
      ) : null}
    </div>
  );
}

function EmptyGraphSidebarSelection() {
  return (
    <div className="graph-sidebar-empty">
      <p className="graph-sidebar-empty-title">Select a node or link</p>
      <p className="graph-sidebar-empty-copy">
        Click a domain or a connection in the graph to inspect why it is linked and what that clue means in plain English.
      </p>
    </div>
  );
}

function GraphSidebarHeader({ title, subtitle, onClose }) {
  return (
    <div className="graph-sidebar-heading">
      <div>
        <h3>{title}</h3>
        {subtitle ? <p className="muted">{subtitle}</p> : null}
      </div>
      {onClose ? (
        <button className="secondary-button graph-sidebar-close" onClick={onClose} type="button">
          Clear
        </button>
      ) : null}
    </div>
  );
}

function DomainGraphSidebar({ graph, selection, onClose, onFocus }) {
  if (!selection) {
    return <EmptyGraphSidebarSelection />;
  }

  if (selection.type === "edge") {
    const edge = graph.edges.find((item) => item.key === selection.key);
    if (!edge) {
      return <EmptyGraphSidebarSelection />;
    }

    const details = edge.details.map((detail) => describeGraphDetail(detail));

    return (
      <div className="graph-sidebar-stack">
        <GraphSidebarHeader
          title="Selected connection"
          subtitle="Why these two domains were linked."
          onClose={onClose}
        />

        <div className="graph-sidebar-badge-row">
          <span className="graph-sidebar-badge solid">{describeLinkStrength(edge.score)}</span>
          <span className="graph-sidebar-badge">{edge.score} score</span>
          <span className="graph-sidebar-badge">{edge.kinds.length} signal{edge.kinds.length === 1 ? "" : "s"}</span>
        </div>

        <div className="graph-sidebar-section">
          <p className="graph-sidebar-section-title">Domains</p>
          <div className="graph-sidebar-list">
            <CompactDomainCard
              domain={getEdgeEndpointId(edge.source)}
              subtitle="One side of this connection"
              actionLabel="Focus"
              onAction={() => onFocus(getEdgeEndpointId(edge.source))}
            />
            <CompactDomainCard
              domain={getEdgeEndpointId(edge.target)}
              subtitle="The other side of this connection"
              actionLabel="Focus"
              onAction={() => onFocus(getEdgeEndpointId(edge.target))}
            />
          </div>
        </div>

        <div className="graph-sidebar-section">
          <p className="graph-sidebar-section-title">What this means</p>
          <div className="graph-sidebar-note">
            <p>{buildEdgeNarrative(edge)}</p>
          </div>
        </div>

        <div className="graph-sidebar-section">
          <p className="graph-sidebar-section-title">Connection clues</p>
          <div className="graph-sidebar-list">
            {details.map((detail, index) => (
              <div className="graph-sidebar-detail-card" key={`${edge.key}-${detail.label}-${index}`}>
                <div className="graph-sidebar-detail-top">
                  <div className="graph-sidebar-detail-title">
                    <span className="legend-swatch" style={{ background: detail.color }} />
                    <strong>{detail.headline}</strong>
                  </div>
                  <span className="graph-sidebar-badge">{edge.details[index].score}</span>
                </div>
                <p>{detail.summary}</p>
                <p className="muted">{detail.meaning}</p>
                <div className="graph-sidebar-evidence">
                  <strong>Observed here</strong>
                  <span>{detail.evidence || edge.details[index].descriptor}</span>
                </div>
                <small>{detail.caution}</small>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  const node = graph.nodes.find((item) => item.id === selection.id);
  if (!node) {
    return <EmptyGraphSidebarSelection />;
  }

  const linkedNeighbors = graph.edges
    .filter((edge) => edgeTouchesNode(edge, node.id))
    .map((edge) => ({
      edge,
      peer: getEdgeEndpointId(edge.source) === node.id ? getEdgeEndpointId(edge.target) : getEdgeEndpointId(edge.source)
    }))
    .sort((a, b) => b.edge.score - a.edge.score || a.peer.localeCompare(b.peer))
    .slice(0, 6);
  const signalCounts = collectNodeSignalCounts(graph.edges, node.id);

  return (
    <div className="graph-sidebar-stack">
      <GraphSidebarHeader
        title={node.id}
        subtitle="Selected domain"
        onClose={onClose}
      />

      <div className="graph-sidebar-badge-row">
        <span className="graph-sidebar-badge solid">{formatNumber(node.visibleDegree)} visible links</span>
        <span className="graph-sidebar-badge">{formatNumber(node.displayWeight)} combined strength</span>
      </div>

      <div className="graph-sidebar-section">
        <p className="graph-sidebar-section-title">What this means</p>
        <div className="graph-sidebar-note">
          <p>
            In plain English, this domain shares enough infrastructure or tracking clues with the domains below that they are worth checking together.
          </p>
        </div>
      </div>

      <div className="graph-sidebar-section">
        <p className="graph-sidebar-section-title">Signal mix</p>
        <div className="graph-sidebar-badge-row">
          {Object.entries(signalCounts)
            .filter(([, count]) => count > 0)
            .sort((left, right) => right[1] - left[1])
            .map(([kind, count]) => (
              <span className="graph-sidebar-badge" key={`${node.id}-${kind}`}>
                <span className="legend-swatch" style={{ background: NETWORK_LINK_META[kind].color }} />
                {NETWORK_LINK_META[kind].label}: {count}
              </span>
            ))}
        </div>
      </div>

      <div className="graph-sidebar-section">
        <p className="graph-sidebar-section-title">Linked domains</p>
        {linkedNeighbors.length ? (
          <div className="graph-sidebar-list">
            {linkedNeighbors.map(({ edge, peer }) => (
              <CompactDomainCard
                key={edge.key}
                domain={peer}
                subtitle={buildEdgeNarrative(edge)}
                actionLabel="Focus"
                onAction={() => onFocus(peer)}
              />
            ))}
          </div>
        ) : (
          <p className="muted">No visible linked domains match the current graph filters.</p>
        )}
      </div>
    </div>
  );
}

function GraphCanvasD3({ graph, selection, setSelection, theme, graphApiRef, height }) {
  const containerRef = useRef(null);
  const svgRef = useRef(null);
  const viewportGroupRef = useRef(null);
  const positionsRef = useRef(new Map());
  const selectionRef = useRef(selection);
  const selectionChangeRef = useRef(setSelection);
  const currentTransformRef = useRef(null);
  const zoomBehaviorRef = useRef(null);
  const simulationRef = useRef(null);
  const nodeSelectionRef = useRef(null);
  const edgeSelectionRef = useRef(null);
  const [size, setSize] = useState({ width: 0, height });

  useEffect(() => {
    selectionRef.current = selection;
  }, [selection]);

  useEffect(() => {
    selectionChangeRef.current = setSelection;
  }, [setSelection]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) {
      return undefined;
    }

    const observer = new window.ResizeObserver(() => {
      setSize({
        width: container.clientWidth,
        height: container.clientHeight
      });
    });

    observer.observe(container);
    setSize({
      width: container.clientWidth,
      height: container.clientHeight
    });

    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    setSize((current) => ({ ...current, height }));
  }, [height]);

  const applySelectionStyles = () => {
    const currentSelection = selectionRef.current;

    if (edgeSelectionRef.current) {
      edgeSelectionRef.current.each(function eachEdge(link) {
        const group = d3.select(this);
        const selected = Boolean(currentSelection && currentSelection.type === "edge" && currentSelection.key === link.key);
        group.select("line.edge-highlight").attr("opacity", selected ? 1 : 0);
        if (selected) {
          group.raise();
        }
      });
    }

    if (nodeSelectionRef.current) {
      nodeSelectionRef.current.each(function eachNode(node) {
        const group = d3.select(this);
        const selected = Boolean(currentSelection && currentSelection.type === "node" && currentSelection.id === node.id);
        group
          .select("circle.node-shape")
          .attr("stroke", selected ? "#f8fafc" : "#60a5fa")
          .attr("stroke-width", selected ? 4 : 2);
        if (selected) {
          group.raise();
        }
      });
    }
  };

  useEffect(() => {
    const svgElement = svgRef.current;
    const viewportElement = viewportGroupRef.current;
    if (!svgElement || !viewportElement || size.width <= 0 || size.height <= 0) {
      return undefined;
    }

    simulationRef.current && simulationRef.current.stop();

    const svg = d3.select(svgElement);
    const viewport = d3.select(viewportElement);

    if (!zoomBehaviorRef.current) {
      zoomBehaviorRef.current = d3.zoom()
        .scaleExtent([GRAPH_MIN_ZOOM, GRAPH_MAX_ZOOM])
        .on("zoom", (event) => {
          currentTransformRef.current = event.transform;
          viewport.attr("transform", event.transform.toString());
        });
    }

    svg.call(zoomBehaviorRef.current);
    svg.on("dblclick.zoom", null);

    viewport.selectAll("*").remove();

    const sortedNodes = [...graph.nodes].sort((left, right) => right.displayWeight - left.displayWeight || left.id.localeCompare(right.id));
    const nodes = sortedNodes.map((node, index) => {
      const previous = positionsRef.current.get(node.id);
      const anchor = computeGraphAnchorPosition(node.id, index, sortedNodes.length);
      return {
        ...node,
        x: previous ? previous.x : anchor.x,
        y: previous ? previous.y : anchor.y,
        anchorX: anchor.x,
        anchorY: anchor.y,
        radius: getGraphNodeRadius(),
        vx: 0,
        vy: 0
      };
    });

    const links = graph.edges.map((edge) => ({
      ...edge,
      source: edge.source,
      target: edge.target
    }));

    const linkLayer = viewport.append("g").attr("class", "d3-link-layer");
    const nodeLayer = viewport.append("g").attr("class", "d3-node-layer");

    const edgeSelection = linkLayer
      .selectAll("g.d3-link-wrap")
      .data(links)
      .enter()
      .append("g")
      .attr("class", "d3-link-wrap")
      .attr("data-edge-id", (link) => link.key);

    edgeSelection.each(function buildEdge(link) {
      const group = d3.select(this);
      group
        .append("line")
        .attr("class", "edge-hit d3-link-hit")
        .attr("stroke", "transparent")
        .attr("stroke-width", GRAPH_EDGE_HIT_STROKE_WIDTH)
        .attr("pointer-events", "stroke")
        .style("cursor", "pointer")
        .on("click", (event) => {
          event.stopPropagation();
          selectionChangeRef.current && selectionChangeRef.current({ type: "edge", key: link.key });
        });
      group
        .append("line")
        .attr("class", "edge-base d3-link")
        .attr("pointer-events", "none");
      group
        .append("line")
        .attr("class", "edge-highlight d3-link-backdrop")
        .attr("stroke", "#f8fafc")
        .attr("stroke-width", 7)
        .attr("opacity", 0)
        .attr("pointer-events", "none");
      group.append("title").text(`${link.source} ↔ ${link.target}`);
    });

    const nodeSelection = nodeLayer
      .selectAll("g.d3-node")
      .data(nodes)
      .enter()
      .append("g")
      .attr("class", "d3-node")
      .attr("data-node-id", (node) => node.id)
      .style("cursor", "pointer")
      .on("click", (event, node) => {
        event.stopPropagation();
        selectionChangeRef.current && selectionChangeRef.current({ type: "node", id: node.id });
      });

    nodeSelection.each(function buildNode(node) {
      const group = d3.select(this);
      group
        .append("circle")
        .attr("class", "node-shape")
        .attr("r", node.radius)
        .attr("fill", "#2563eb")
        .attr("stroke", "#60a5fa")
        .attr("stroke-width", 2);

      group
        .append("text")
        .attr("class", "d3-node-text")
        .attr("y", node.radius + 18)
        .attr("text-anchor", "middle")
        .text(shortLabel(node.id, 32));

      group.append("title").text(node.id);
    });

    const updateFrame = () => {
      nodeSelection.attr("transform", (node) => `translate(${node.x || 0}, ${node.y || 0})`);

      edgeSelection.each(function drawEdge(link) {
        const group = d3.select(this);
        const resolved = resolveGraphLinkNodes(link);
        if (!resolved) {
          return;
        }

        const drawn = {
          x1: resolved.source.x || 0,
          y1: resolved.source.y || 0,
          x2: resolved.target.x || 0,
          y2: resolved.target.y || 0
        };
        const orderedKinds = getOrderedNetworkKinds(link.kinds);
        const showOverlap = orderedKinds.length > 1;
        const primaryKind = orderedKinds[0] || "ip";
        const baseStroke = showOverlap ? GRAPH_OVERLAP_COLOR : NETWORK_LINK_META[primaryKind].color;
        const baseWidth = showOverlap ? 5 : 3;

        group.select("line.edge-hit")
          .attr("x1", drawn.x1)
          .attr("y1", drawn.y1)
          .attr("x2", drawn.x2)
          .attr("y2", drawn.y2);

        group.select("line.edge-base")
          .attr("x1", drawn.x1)
          .attr("y1", drawn.y1)
          .attr("x2", drawn.x2)
          .attr("y2", drawn.y2)
          .attr("stroke", baseStroke)
          .attr("stroke-width", baseWidth);

        group.select("line.edge-highlight")
          .attr("x1", drawn.x1)
          .attr("y1", drawn.y1)
          .attr("x2", drawn.x2)
          .attr("y2", drawn.y2);
      });

      nodes.forEach((node) => {
        positionsRef.current.set(node.id, {
          x: node.x || 0,
          y: node.y || 0
        });
      });

      applySelectionStyles();
    };

    const simulation = d3.forceSimulation(nodes)
      .force("charge", d3.forceManyBody().strength(-1400))
      .force(
        "link",
        d3.forceLink(links)
          .id((node) => node.id)
          .distance(210)
          .strength(0.35)
      )
      .force("collide", d3.forceCollide().radius((node) => node.radius + 28).iterations(2))
      .force(
        "radial",
        d3.forceRadial(
          (node) => Math.max(Math.hypot(node.anchorX, node.anchorY), 260),
          0,
          0
        ).strength(0.22)
      )
      .force("anchor-x", d3.forceX((node) => node.anchorX).strength(0.16))
      .force("anchor-y", d3.forceY((node) => node.anchorY).strength(0.16))
      .force("center", d3.forceCenter(0, 0))
      .alpha(0.9)
      .alphaDecay(0.04)
      .on("tick", updateFrame);

    simulationRef.current = simulation;

    nodeSelection.call(
      d3.drag()
        .on("start", (event, node) => {
          event.sourceEvent && event.sourceEvent.stopPropagation();
          if (!event.active) {
            simulation.alphaTarget(0.25).restart();
          }
          node.fx = node.x || 0;
          node.fy = node.y || 0;
        })
        .on("drag", (event, node) => {
          node.fx = event.x;
          node.fy = event.y;
          positionsRef.current.set(node.id, { x: event.x, y: event.y });
          updateFrame();
        })
        .on("end", (event, node) => {
          if (!event.active) {
            simulation.alphaTarget(0);
          }
          node.fx = node.x || 0;
          node.fy = node.y || 0;
          positionsRef.current.set(node.id, {
            x: node.x || 0,
            y: node.y || 0
          });
          updateFrame();
        })
    );

    for (let tick = 0; tick < 60; tick += 1) {
      simulation.tick();
    }
    updateFrame();
    simulation.alpha(0.35).restart();

    nodeSelectionRef.current = nodeSelection;
    edgeSelectionRef.current = edgeSelection;

    if (currentTransformRef.current) {
      viewport.attr("transform", currentTransformRef.current.toString());
    } else {
      const initialViewport = computeGraphInitialViewport(nodes, size.width, size.height);
      const initialTransform = d3.zoomIdentity
        .translate(initialViewport.x, initialViewport.y)
        .scale(initialViewport.k);
      currentTransformRef.current = initialTransform;
      svg.call(zoomBehaviorRef.current.transform, initialTransform);
    }

    applySelectionStyles();

    return () => {
      simulation.stop();
    };
  }, [graph, size.height, size.width]);

  useEffect(() => {
    applySelectionStyles();
  }, [selection]);

  useEffect(() => {
    return () => {
      simulationRef.current && simulationRef.current.stop();
      if (svgRef.current) {
        d3.select(svgRef.current).on(".zoom", null);
      }
    };
  }, []);

  return (
    <div
      ref={containerRef}
      className="graph-canvas graph-canvas-large"
      style={{ height: `${height}px` }}
    >
      <svg
        ref={svgRef}
        width="100%"
        height="100%"
        className="graph-svg"
      >
        <rect
          width="100%"
          height="100%"
          fill="#050b16"
          onClick={() => setSelection(null)}
        />
        <g ref={viewportGroupRef} />
      </svg>
    </div>
  );
}

function GraphPage({ clusters, recent, theme }) {
  const graphApiRef = useRef({
    fit: () => {},
    reset: () => {}
  });
  const resizeStateRef = useRef(null);
  const [controls, setControls] = useState({ ...GRAPH_DEFAULT_CONTROLS });
  const [selection, setSelection] = useState(null);
  const [graphHeight, setGraphHeight] = useState(GRAPH_DEFAULT_HEIGHT);
  const [sidebarWidth, setSidebarWidth] = useState(GRAPH_DEFAULT_SIDEBAR_WIDTH);

  const graph = buildNetworkModel(clusters, controls);
  const focusOptions = getDomainTargets(recent);
  const activeNodeId = selection && selection.type === "node" ? selection.id : "";
  const activeEdgeKey = selection && selection.type === "edge" ? selection.key : "";
  const selectedNode = activeNodeId
    ? graph.nodes.find((node) => node.id === activeNodeId) || null
    : null;
  const selectedEdge = activeEdgeKey
    ? graph.edges.find((edge) => edge.key === activeEdgeKey) || null
    : null;
  const linkedNeighbors = selectedNode
    ? graph.edges
      .filter((edge) => edgeTouchesNode(edge, selectedNode.id))
      .map((edge) => ({
        edge,
        peer: getEdgeEndpointId(edge.source) === selectedNode.id ? getEdgeEndpointId(edge.target) : getEdgeEndpointId(edge.source)
      }))
      .sort((a, b) => b.edge.score - a.edge.score || a.peer.localeCompare(b.peer))
    : [];
  const nodeSignalCounts = selectedNode ? collectNodeSignalCounts(graph.edges, selectedNode.id) : null;
  const selectedEdgeDetails = selectedEdge ? selectedEdge.details.map((detail) => describeGraphDetail(detail)) : [];
  const strongestLinks = graph.edges.slice(0, 6);

  useEffect(() => {
    if (!selection) {
      return;
    }
    if (selection.type === "node" && !graph.nodes.some((node) => node.id === selection.id)) {
      setSelection(null);
    }
    if (selection.type === "edge" && !graph.edges.some((edge) => edge.key === selection.key)) {
      setSelection(null);
    }
  }, [graph.edges, graph.nodes, selection]);

  useEffect(() => {
    const handlePointerMove = (event) => {
      const activeResize = resizeStateRef.current;
      if (!activeResize) {
        return;
      }

      if (activeResize.mode === "height" || activeResize.mode === "both") {
        const nextHeight = Math.min(
          GRAPH_MAX_HEIGHT,
          Math.max(
            GRAPH_MIN_HEIGHT,
            activeResize.startHeight + (event.clientY - activeResize.startClientY)
          )
        );
        setGraphHeight(nextHeight);
      }

      if (activeResize.mode === "width" || activeResize.mode === "both") {
        const nextSidebarWidth = Math.min(
          GRAPH_MAX_SIDEBAR_WIDTH,
          Math.max(
            GRAPH_MIN_SIDEBAR_WIDTH,
            activeResize.startSidebarWidth - (event.clientX - activeResize.startClientX)
          )
        );
        setSidebarWidth(nextSidebarWidth);
      }
    };

    const clearResizeState = () => {
      resizeStateRef.current = null;
      document.body.style.removeProperty("cursor");
      document.body.style.removeProperty("user-select");
    };

    const handlePointerUp = (event) => {
      if (resizeStateRef.current && resizeStateRef.current.pointerId !== event.pointerId) {
        return;
      }
      clearResizeState();
    };

    window.addEventListener("pointermove", handlePointerMove);
    window.addEventListener("pointerup", handlePointerUp);
    window.addEventListener("pointercancel", clearResizeState);

    return () => {
      window.removeEventListener("pointermove", handlePointerMove);
      window.removeEventListener("pointerup", handlePointerUp);
      window.removeEventListener("pointercancel", clearResizeState);
      clearResizeState();
    };
  }, []);

  const updateControl = (key, value) => {
    setControls((current) => ({
      ...current,
      [key]: value
    }));
  };

  const resetGraphFilters = () => {
    setSelection(null);
    setControls({ ...GRAPH_DEFAULT_CONTROLS });
  };

  const handleSelectionChange = (nextSelection) => {
    setSelection((current) => {
      if (!nextSelection) {
        return null;
      }
      if (!current || current.type !== nextSelection.type) {
        return nextSelection;
      }
      if (current.type === "node") {
        return current.id === nextSelection.id ? null : nextSelection;
      }
      return current.key === nextSelection.key ? null : nextSelection;
    });
  };

  const handleResizePointerDown = (mode, event) => {
    resizeStateRef.current = {
      mode,
      pointerId: event.pointerId,
      startClientX: event.clientX,
      startClientY: event.clientY,
      startHeight: graphHeight,
      startSidebarWidth: sidebarWidth
    };
    document.body.style.setProperty(
      "cursor",
      mode === "width" ? "ew-resize" : mode === "height" ? "ns-resize" : "nwse-resize"
    );
    document.body.style.setProperty("user-select", "none");
    event.preventDefault();
    event.stopPropagation();
  };

  const relatedEdgeCount = graph.edges.length;

  return (
    <PageFrame
      eyebrow="Explorer"
      title="Relationship graph"
      subtitle="Copied from the TikTok-tool graph layout and adapted to domain infrastructure links."
      infoTitle="How to use this graph"
      infoBody="Drag domains to spread the network out, click a line to inspect the connection, and use the controls above the graph to focus on the strongest relationships first."
      metrics={
        <>
          <Metric label="Domains in view" value={formatNumber(graph.nodes.length)} />
          <Metric label="Links shown" value={formatNumber(graph.edges.length)} detail="Strongest links first" />
          <Metric label="Top score" value={formatNumber(graph.maxScore || 0)} />
          <Metric label="Hidden weaker links" value={formatNumber(graph.hiddenEdgeCount || 0)} />
        </>
      }
    >
      {graph.edges.length ? (
        <div className="tt-graph-layout" style={{ "--graph-sidebar-width": `${sidebarWidth}px` }}>
          <section className="tt-graph-card">
            <div className="tt-graph-card-header">
              <div className="tt-graph-title-block">
                <h3>Link graph for stored domains</h3>
                <p className="tt-graph-subtitle">
                  Inferred from shared TLS fingerprints, tracking IDs, favicons, direct IP overlaps, and shared provider networks.
                </p>
                <p className="tt-graph-tip">
                  Drag nodes to spread the network out. Single-colour links show one matching indicator. Current TLS and direct-IP matches are weighted highest, while ASN, mail, shared-hosting, and CDN overlaps stay lower so the strongest evidence surfaces first.
                </p>
              </div>
              <div className="tt-graph-badge-group">
                <span className="tt-graph-badge tt-graph-badge-solid">{formatNumber(graph.nodes.length)} domains</span>
                <span className="tt-graph-badge">{relatedEdgeCount} inferred links</span>
                <span className="tt-graph-badge">Top score {graph.maxScore || 0}</span>
              </div>
            </div>

            <div className="tt-graph-control-row">
              <button className="tt-graph-button" onClick={() => graphApiRef.current.fit()} type="button">
                Fit graph
              </button>
              <button className="tt-graph-button" onClick={() => graphApiRef.current.reset()} type="button">
                Reset zoom
              </button>
              <button className="tt-graph-button" onClick={resetGraphFilters} type="button">
                Reset filters
              </button>

              <label className="tt-graph-toggle">
                <input checked={controls.includeTls} onChange={() => updateControl("includeTls", !controls.includeTls)} type="checkbox" />
                <span>TLS certs</span>
              </label>
              <label className="tt-graph-toggle">
                <input checked={controls.includeTracking} onChange={() => updateControl("includeTracking", !controls.includeTracking)} type="checkbox" />
                <span>Tracking IDs</span>
              </label>
              <label className="tt-graph-toggle">
                <input checked={controls.includeFavicon} onChange={() => updateControl("includeFavicon", !controls.includeFavicon)} type="checkbox" />
                <span>Favicons</span>
              </label>
              <label className="tt-graph-toggle">
                <input checked={controls.includeIp} onChange={() => updateControl("includeIp", !controls.includeIp)} type="checkbox" />
                <span>Shared IPs</span>
              </label>
              <label className="tt-graph-toggle">
                <input checked={controls.includeAsn} onChange={() => updateControl("includeAsn", !controls.includeAsn)} type="checkbox" />
                <span>ASNs</span>
              </label>
            </div>

            <div className="tt-graph-control-row secondary">
              <label className="tt-graph-inline-control" htmlFor="graph-page-min-score">
                <span>Minimum strength</span>
                <input id="graph-page-min-score" min="1" max="30" type="range" value={controls.minScore} onChange={(event) => updateControl("minScore", Number(event.target.value))} />
                <strong>{controls.minScore}</strong>
              </label>

              <label className="tt-graph-inline-control" htmlFor="graph-page-max-links">
                <span>Links shown</span>
                <input id="graph-page-max-links" min="10" max="80" step="2" type="range" value={controls.maxLinks} onChange={(event) => updateControl("maxLinks", Number(event.target.value))} />
                <strong>{controls.maxLinks}</strong>
              </label>

              <label className="tt-graph-inline-select" htmlFor="graph-page-focus">
                <span>Focus domain</span>
                <select id="graph-page-focus" value={controls.focus} onChange={(event) => updateControl("focus", event.target.value)}>
                  <option value="">All domains</option>
                  {focusOptions.map((item) => (
                    <option key={item} value={item}>{item}</option>
                  ))}
                </select>
              </label>
            </div>

            <div className="tt-graph-legend">
              <span className="tt-graph-legend-item">
                <span className="tt-graph-legend-line overlap" />
                Multiple indicators
              </span>
              {NETWORK_LINK_ORDER.map((kind) => (
                <span className="tt-graph-legend-item" key={kind}>
                  <span className="tt-graph-legend-line" style={{ backgroundColor: NETWORK_LINK_META[kind].color }} />
                  {NETWORK_LINK_META[kind].label}
                </span>
              ))}
            </div>

            <div className="tt-graph-canvas-shell">
              <GraphCanvasD3
                graph={graph}
                selection={selection}
                setSelection={handleSelectionChange}
                theme={theme}
                graphApiRef={graphApiRef}
                height={graphHeight}
              />

              <button
                className="graph-resize-handle horizontal"
                onPointerDown={(event) => handleResizePointerDown("height", event)}
                type="button"
                aria-label="Resize graph height"
                title="Drag to resize graph height"
              >
                Resize height
              </button>
              <button
                className="graph-resize-handle vertical"
                onPointerDown={(event) => handleResizePointerDown("width", event)}
                type="button"
                aria-label="Resize sidebar width"
                title="Drag to resize sidebar width"
              >
                Resize sidebar
              </button>
              <button
                className="graph-resize-handle corner"
                onPointerDown={(event) => handleResizePointerDown("both", event)}
                type="button"
                aria-label="Resize graph workspace"
                title="Drag to resize graph workspace"
              >
                Resize
              </button>
            </div>
          </section>

          <aside className="tt-graph-sidebar-card">
            <DomainGraphSidebar
              graph={graph}
              selection={selection}
              onClose={() => setSelection(null)}
              onFocus={(domain) => updateControl("focus", domain)}
            />
          </aside>
        </div>
      ) : (
        <Callout tone="info">
          No links match the current graph filters. Lower the minimum strength, raise the link limit, or clear the domain focus.
        </Callout>
      )}
    </PageFrame>
  );
}

function ConnectionsPage({ connections, meta, selectedTarget, setSelectedTarget, recent, onOpenSavedResult }) {
  const domainTargets = getDomainTargets(recent);

  return (
    <PageFrame
      eyebrow="Explorer"
      title="Domain connections"
      subtitle="Pick one stored domain and see, in plain English, why it overlaps with other domains already in the database."
      infoTitle="What domain connections mean"
      infoBody="This page answers the question 'why does the app think these domains belong in the same conversation?' by breaking the overlap into categories like certificates, TLS history, tracking IDs, IPs, ASNs, and favicons."
    >
      <div className="field-row">
        <label htmlFor="connections-page-target">Choose a stored domain</label>
        <select
          id="connections-page-target"
          value={selectedTarget}
          onChange={(event) => setSelectedTarget(event.target.value)}
        >
          <option value="">Select a domain</option>
          {domainTargets.map((item) => (
            <option key={item} value={item}>{item}</option>
          ))}
        </select>
      </div>

      {connections ? (
        <div className="stack">
          <div className="metric-grid">
            <Metric label="Target" value={connections.target} />
            <Metric label="Cloudflare" value={cloudflareLabel(connections.cloudflare_fronted)} />
            <Metric label="Registrar" value={(connections.whois || {}).registrar || "Unknown"} />
            <Metric label="Created" value={formatDate((connections.whois || {}).creation_date)} />
          </div>

          {connections.history && connections.history.length ? (
            <SectionCard
              title="Run history"
              infoTitle="Run history"
              infoBody="This is the append-only timeline for the selected target. Open an older run to compare how the domain’s IPs, certificates, and provider hits changed over time."
            >
              <div className="card-grid">
                {connections.history.map((item) => (
                  <LeadCard
                    key={item.id}
                    title={formatDateTime(item.timestamp)}
                    footer={item.is_latest ? "Latest run" : "Historical run"}
                  >
                    <p><strong>Cloudflare:</strong> {cloudflareLabel(item.cloudflare_fronted)}</p>
                    <p><strong>Type:</strong> {String(item.type || "").toUpperCase()}</p>
                    <button className="inline-action" onClick={() => onOpenSavedResult(item.id)} type="button">
                      Open run
                    </button>
                  </LeadCard>
                ))}
              </div>
            </SectionCard>
          ) : null}

          {CONNECTION_SECTIONS.map((section) => {
            const items = (connections.connections || {})[section.key] || [];
            if (!items.length) {
              return null;
            }
            return (
              <SectionCard key={section.key} title={section.title} infoTitle={section.title} infoBody={section.infoBody}>
                <div className="card-grid">
                  {items.map((item, index) => (
                    <LeadCard key={`${section.key}-${index}`} title={getConnectionItemTitle(section.key, item)}>
                      {item.shared_with && item.shared_with.length ? (
                        <p className="break-word"><strong>Shared with:</strong> {item.shared_with.join(", ")}</p>
                      ) : (
                        <p>No other stored domains share this attribute yet.</p>
                      )}
                      <ConnectionItemDetails sectionKey={section.key} item={item} meta={meta} />
                    </LeadCard>
                  ))}
                </div>
              </SectionCard>
            );
          })}
        </div>
      ) : (
        <Callout tone="info">Choose a stored domain to see its cross-domain overlaps.</Callout>
      )}
    </PageFrame>
  );
}

function SharedSignalPage({ eyebrow, title, subtitle, infoTitle, infoBody, items, renderItem, emptyMessage }) {
  return (
    <PageFrame eyebrow={eyebrow} title={title} subtitle={subtitle} infoTitle={infoTitle} infoBody={infoBody}>
      {items.length ? (
        <div className="card-grid">
          {items.map(renderItem)}
        </div>
      ) : (
        <Callout tone="info">{emptyMessage}</Callout>
      )}
    </PageFrame>
  );
}

function InvestigatePage({ form, setForm, busy, scanHelp, pivotOptions, openctiState, onAnalyze, onProvidersOnly, onOpenCtiAction, job }) {
  const openctiJob = buildOpenctiJob(openctiState);

  return (
    <PageFrame
      eyebrow="Workflow"
      title="Investigate"
      subtitle="Run new collection jobs, watch progress, and control manual OpenCTI ingestion without competing with the rest of the UI for space."
      infoTitle="What this page is for"
      infoBody="Use this page to start a fresh analysis job, widen the scan if needed, and watch the backend work. The other pages are for reading the results after the data is in."
    >
      <div className="full-page-grid">
        <ControlPanel
          form={form}
          setForm={setForm}
          busy={busy}
          scanHelp={scanHelp}
          pivotOptions={pivotOptions}
          openctiState={openctiState}
          onAnalyze={onAnalyze}
          onProvidersOnly={onProvidersOnly}
          onOpenCtiAction={onOpenCtiAction}
        />
        <div className="stack">
          <SectionCard
            title="Collection flow"
            subtitle="What happens when you run a job."
            infoTitle="Collection flow"
            infoBody="The backend collects DNS, certificates, page fingerprints, hosting clues, and origin leads. If some outside services fail, the pipeline keeps going and records what was skipped."
          >
            <div className="metric-grid">
              <Metric label="Fallbacks" value="Enabled" detail="Source errors do not stop the whole run" />
              <Metric label="OpenCTI" value={openctiState.running ? "Running" : "Manual"} detail="Only runs when you press the button" />
              <Metric label="Pivoting" value={form.expand_related ? "Enabled" : "Off"} detail={form.expand_related ? `One hop, limit ${form.expand_limit}` : "Seed target only"} />
              <Metric label="Pipeline speed" value={form.concurrency} detail="Configured async concurrency" />
            </div>
          </SectionCard>
          {job ? <JobProgress job={job} /> : null}
          {openctiJob ? <JobProgress job={openctiJob} /> : null}
          {!job && !openctiJob ? (
            <SectionCard title="Ready" subtitle="No job is running right now.">
              <p className="muted">Start a job on the left, then move to the result pages or the graph once data starts arriving.</p>
            </SectionCard>
          ) : null}
        </div>
      </div>
    </PageFrame>
  );
}

function ResultContentPage({ pageId, result, meta, onOpenSavedResult }) {
  const pageMeta = RESULT_PAGES.find((page) => page.id === pageId) || RESULT_PAGES[0];
  const pageMetrics = (
    <>
      <Metric label="Target" value={result.input} />
      <Metric label="Cloudflare" value={cloudflareLabel(result.cloudflare_fronted ?? result.cloudflare)} />
      <Metric label="Origin leads" value={collectOriginLeadCount(result)} />
      <Metric label="Saved" value={formatDateTime(result.timestamp)} />
    </>
  );

  return (
    <PageFrame
      eyebrow="Result"
      title={pageMeta.label}
      subtitle={pageMeta.subtitle}
      infoTitle={pageMeta.label}
      infoBody="These result pages use the full width of the app so each analysis section has room to breathe. Switch pages from the navigation strip above."
      actions={
        <button className="secondary-button" onClick={() => downloadResult(result)} type="button">
          Download JSON
        </button>
      }
      metrics={pageMetrics}
    >
      {pageId === "overview" ? <OverviewTab result={result} meta={meta} onOpenSavedResult={onOpenSavedResult} /> : null}
      {pageId === "dns" ? <DnsTab result={result} /> : null}
      {pageId === "certs" ? <CertificatesTab result={result} meta={meta} /> : null}
      {pageId === "origin" ? <OriginTab result={result} meta={meta} /> : null}
      {pageId === "ips" ? <IpDetailsTab result={result} meta={meta} /> : null}
    </PageFrame>
  );
}

function ControlPanel({ form, setForm, busy, scanHelp, pivotOptions, openctiState, onAnalyze, onProvidersOnly, onOpenCtiAction }) {
  const pivotLimitMin = pivotOptions.expand_limit_min || 1;
  const pivotLimitMax = pivotOptions.expand_limit_max || 50;

  const updateField = (key, value) => {
    setForm((current) => ({
      ...current,
      [key]: value
    }));
  };

  const toggle = (key) => updateField(key, !form[key]);

  const scanFields = [
    ["scan", "Eastern-EU GCP"],
    ["scan_europe", "All-EU GCP + Turkey"],
    ["scan_providers", "Known RU/EU hosters"],
    ["scan_eu_countries", "All EU member states"],
    ["scan_full", "Full scan"],
    ["scan_all", "Global GCP"]
  ];

  return (
    <SectionCard
      title="Run analysis"
      subtitle="Start a fresh collection run or trigger manual OpenCTI ingestion."
      infoTitle="How a run works"
      infoBody="A run asks the backend to collect DNS, certificate, hosting, and origin clues for a domain or IP. The extra scan options widen the search, but they can take longer."
    >
      <div className="stack">
        <div className="field-row">
          <label htmlFor="target">Target domain or IP</label>
          <input
            id="target"
            type="text"
            value={form.target}
            placeholder="news-pravda.com"
            onChange={(event) => updateField("target", event.target.value)}
            disabled={busy}
          />
        </div>

        <div className="field-group">
          <h3>Origin discovery modes</h3>
          {scanFields.map(([key, label]) => (
            <label className="checkbox-row" key={key}>
              <input checked={form[key]} disabled={busy} onChange={() => toggle(key)} type="checkbox" />
              <span>
                <strong>{label}</strong>
                <small>{scanHelp[key]}</small>
              </span>
            </label>
          ))}
        </div>

        <div className="field-row">
          <label htmlFor="countries">Custom countries</label>
          <input
            id="countries"
            type="text"
            value={form.countriesText}
            placeholder="RU UA BY"
            onChange={(event) => updateField("countriesText", event.target.value.toUpperCase())}
            disabled={busy}
          />
        </div>

        <div className="field-group">
          <h3>Recursive pivoting</h3>
          <label className="checkbox-row">
            <input checked={form.expand_related} disabled={busy} onChange={() => toggle("expand_related")} type="checkbox" />
            <span>
              <strong>Auto-analyse related targets</strong>
              <small>{scanHelp.expand_related || "Automatically analyse the strongest related domains and IPs discovered during the run."}</small>
            </span>
          </label>
        </div>

        <div className="split-fields">
          <div className="field-row">
            <label htmlFor="concurrency">Async concurrency</label>
            <input
              id="concurrency"
              min="100"
              max="50000"
              step="500"
              type="number"
              value={form.concurrency}
              onChange={(event) => updateField("concurrency", Number(event.target.value))}
              disabled={busy}
            />
          </div>
          <div className="field-row">
            <label htmlFor="expand_limit">Pivot limit</label>
            <input
              id="expand_limit"
              min={pivotLimitMin}
              max={pivotLimitMax}
              step="1"
              type="number"
              value={form.expand_limit}
              onChange={(event) => updateField(
                "expand_limit",
                parseIntegerInput(event.target.value, form.expand_limit, pivotLimitMin, pivotLimitMax)
              )}
              disabled={busy || !form.expand_related}
            />
          </div>
          <div className="field-row">
            <label htmlFor="rate">masscan rate (pps)</label>
            <input
              id="rate"
              min="100"
              max="500000"
              step="1000"
              type="number"
              value={form.rate}
              onChange={(event) => updateField("rate", Number(event.target.value))}
              disabled={busy}
            />
          </div>
        </div>

        <div className="button-row">
          <button className="primary-button" onClick={onAnalyze} type="button" disabled={busy || !form.target.trim()}>
            {busy ? "Running..." : "Analyse target"}
          </button>
          <button className="secondary-button" onClick={onProvidersOnly} type="button" disabled={busy || !form.target.trim()}>
            Providers only
          </button>
        </div>

        <div className="field-group">
          <h3>OpenCTI ingestion</h3>
          {openctiState.available === false ? (
            <p className="muted">OpenCTI ingestion is not available in this environment.</p>
          ) : (
            <>
              <p className="muted">
                {openctiState.running
                  ? `Running ${openctiState.done || 0}/${openctiState.total || 0} | ${openctiState.current || "Preparing"}`
                  : openctiState.completed_at
                    ? `Last run ${openctiState.completed_at}`
                    : "Idle. Nothing runs automatically now; press Run when you want to ingest OpenCTI domains."}
              </p>
              <div className="button-row">
                <button className="secondary-button" onClick={() => onOpenCtiAction(false)} type="button" disabled={openctiState.running}>
                  Run
                </button>
                <button className="secondary-button" onClick={() => onOpenCtiAction(true)} type="button" disabled={openctiState.running}>
                  Re-run all
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </SectionCard>
  );
}

export default function App() {
  const initialHashPage = typeof window === "undefined" ? "" : window.location.hash.replace(/^#/, "");
  const [theme, setTheme] = useState(() => {
    if (typeof window === "undefined") {
      return "light";
    }
    const savedTheme = window.localStorage.getItem("ip-intel-theme");
    if (savedTheme === "light" || savedTheme === "dark") {
      return savedTheme;
    }
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });
  const [meta, setMeta] = useState({
    cert_types: {},
    server_types: {},
    scan_options: {},
    pivot_options: {}
  });
  const [job, setJob] = useState(null);
  const [recent, setRecent] = useState([]);
  const [clusters, setClusters] = useState({
    ip: [],
    asn: [],
    tracking: [],
    favicon: [],
    tls: []
  });
  const [connections, setConnections] = useState(null);
  const [selectedTarget, setSelectedTarget] = useState("");
  const [tlsScope, setTlsScope] = useState("current");
  const [asnScope, setAsnScope] = useState("current");
  const [openctiState, setOpenctiState] = useState({ available: false });
  const [statusMessage, setStatusMessage] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const [form, setForm] = useState({
    target: "",
    scan: false,
    scan_europe: false,
    scan_all: false,
    scan_providers: false,
    scan_eu_countries: false,
    scan_full: false,
    expand_related: false,
    expand_limit: 12,
    countriesText: "",
    concurrency: 5000,
    rate: 100000
  });
  const [activePage, setActivePage] = useState(initialHashPage || "investigate");

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    window.localStorage.setItem("ip-intel-theme", theme);
  }, [theme]);

  async function loadExplorerData() {
    const [recentResponse, ipResponse, asnResponse, trackingResponse, faviconResponse, tlsResponse] = await Promise.allSettled([
      apiFetch("/api/history/recent?limit=100"),
      apiFetch("/api/clusters/ip"),
      apiFetch(`/api/clusters/asn?scope=${encodeURIComponent(asnScope)}`),
      apiFetch("/api/clusters/tracking"),
      apiFetch("/api/clusters/favicon"),
      apiFetch(`/api/clusters/tls?scope=${encodeURIComponent(tlsScope)}`)
    ]);

    setRecent(recentResponse.status === "fulfilled" ? recentResponse.value.items || [] : []);
    setClusters({
      ip: ipResponse.status === "fulfilled" ? ipResponse.value.items || [] : [],
      asn: asnResponse.status === "fulfilled" ? asnResponse.value.items || [] : [],
      tracking: trackingResponse.status === "fulfilled" ? trackingResponse.value.items || [] : [],
      favicon: faviconResponse.status === "fulfilled" ? faviconResponse.value.items || [] : [],
      tls: tlsResponse.status === "fulfilled" ? tlsResponse.value.items || [] : []
    });

    const labeledResponses = [
      ["Recent searches", recentResponse],
      ["Shared IPs", ipResponse],
      ["Shared ASNs", asnResponse],
      ["Tracking IDs", trackingResponse],
      ["Favicons", faviconResponse],
      ["TLS overlaps", tlsResponse]
    ];
    const failures = labeledResponses.filter(([, response]) => response.status === "rejected");
    if (failures.length) {
      const dbFailure = failures.find(([, response]) => isDatabaseCorruptionMessage(response.reason?.message));
      if (dbFailure) {
        setErrorMessage("The SQLite database is corrupted or unreadable. Explorer pages can look empty until the database is repaired, restored, or replaced.");
      } else {
        setErrorMessage(failures.map(([label, response]) => `${label}: ${response.reason?.message || "Request failed"}`).join(" | "));
      }
    } else {
      setErrorMessage("");
    }
  }

  async function loadOpencti() {
    try {
      const response = await apiFetch("/api/opencti/status");
      setOpenctiState(response);
    } catch (_error) {
      setOpenctiState({ available: false });
    }
  }

  useEffect(() => {
    async function bootstrap() {
      try {
        const metaResponse = await apiFetch("/api/meta");
        setMeta(metaResponse);
        setForm((current) => ({
          ...current,
          expand_related: typeof metaResponse.pivot_options?.expand_related_default === "boolean"
            ? metaResponse.pivot_options.expand_related_default
            : current.expand_related,
          expand_limit: typeof metaResponse.pivot_options?.expand_limit_default === "number"
            ? metaResponse.pivot_options.expand_limit_default
            : current.expand_limit
        }));
        await loadOpencti();
      } catch (error) {
        setErrorMessage(error.message);
      }
    }

    bootstrap();
  }, []);

  useEffect(() => {
    loadExplorerData().catch((error) => {
      setErrorMessage(error.message);
    });
  }, [asnScope, tlsScope]);

  useEffect(() => {
    if (!selectedTarget) {
      const firstDomain = getDomainTargets(recent)[0];
      if (firstDomain) {
        setSelectedTarget(firstDomain);
      }
    }
  }, [recent, selectedTarget]);

  useEffect(() => {
    if (!selectedTarget) {
      setConnections(null);
      return;
    }

    let ignore = false;
    async function loadConnections() {
      try {
        const response = await apiFetch(`/api/connections/${encodeURIComponent(selectedTarget)}`);
        if (!ignore) {
          setConnections(response);
        }
      } catch (error) {
        if (!ignore) {
          setConnections(null);
          if (isDatabaseCorruptionMessage(error.message)) {
            setErrorMessage("The SQLite database is corrupted or unreadable. Domain connections cannot be loaded until the database is repaired, restored, or replaced.");
          }
        }
      }
    }

    loadConnections();
    return () => {
      ignore = true;
    };
  }, [selectedTarget]);

  useEffect(() => {
    if (!job || (job.status !== "queued" && job.status !== "running")) {
      return undefined;
    }

    const timer = window.setInterval(async () => {
      try {
        const response = await apiFetch(`/api/jobs/${job.id}`);
        setJob(response);
        if (response.status === "completed" || response.status === "failed") {
          window.clearInterval(timer);
          await loadExplorerData();
        }
      } catch (error) {
        setErrorMessage(error.message);
        window.clearInterval(timer);
      }
    }, 1000);

    return () => {
      window.clearInterval(timer);
    };
  }, [job]);

  useEffect(() => {
    const intervalMs = openctiState.running ? 1500 : 10000;
    const timer = window.setInterval(() => {
      loadOpencti();
    }, intervalMs);

    return () => {
      window.clearInterval(timer);
    };
  }, [openctiState.running]);

  async function submitAnalysis(overrides = {}) {
    setErrorMessage("");
    setStatusMessage("");

    try {
      const pivotOptions = meta.pivot_options || {};
      const expandLimit = clampNumber(
        Number.isFinite(form.expand_limit) ? form.expand_limit : (pivotOptions.expand_limit_default || 12),
        pivotOptions.expand_limit_min || 1,
        pivotOptions.expand_limit_max || 50
      );
      const payload = {
        target: form.target,
        scan: form.scan,
        scan_europe: form.scan_europe,
        scan_all: form.scan_all,
        scan_providers: form.scan_providers,
        scan_eu_countries: form.scan_eu_countries,
        scan_full: form.scan_full,
        expand_related: form.expand_related,
        expand_limit: expandLimit,
        scan_countries: form.countriesText.split(/\s+/).filter(Boolean),
        concurrency: form.concurrency,
        rate: form.rate,
        ...overrides
      };

      const response = await apiFetch("/api/analyze", {
        method: "POST",
        body: JSON.stringify(payload)
      });

      setJob(response);
      setStatusMessage(`Started analysis for ${response.target}.`);
      setActivePage("investigate");
    } catch (error) {
      setErrorMessage(error.message);
    }
  }

  async function openSavedResult(searchId) {
    try {
      const response = await apiFetch(`/api/history/${searchId}`);
      setJob({
        id: `saved-${searchId}`,
        target: response.result.input,
        status: "completed",
        logs: [],
        partial_result: response.result,
        result: response.result,
        updated_at: response.search.timestamp,
        progress: {
          fraction: 1,
          completed: [],
          completed_count: 0,
          total: 0
        }
      });
      if (response.result.type === "domain") {
        setSelectedTarget(response.result.input);
      }
      setStatusMessage(`Loaded saved result for ${response.result.input}.`);
      setActivePage("overview");
    } catch (error) {
      setErrorMessage(error.message);
    }
  }

  async function triggerOpenCti(forceReanalyse) {
    try {
      const response = await apiFetch(`/api/opencti/run?force_reanalyse=${forceReanalyse}`, {
        method: "POST"
      });
      setStatusMessage(response.started ? "OpenCTI ingestion started." : "OpenCTI ingestion is already running.");
      await loadOpencti();
    } catch (error) {
      setErrorMessage(error.message);
    }
  }

  const result = job && job.result ? job.result : null;
  const busy = job && (job.status === "queued" || job.status === "running");
  const storedDomains = getDomainTargets(recent).length;
  const sharedSignalCount = clusters.ip.length + clusters.asn.length + clusters.tracking.length + clusters.favicon.length + clusters.tls.length;
  const openctiLabel = openctiState.available === false
    ? "Unavailable"
    : openctiState.running
      ? "Running"
      : "Manual";
  const workflowPages = [
    { id: "investigate", label: "Investigate", subtitle: "Run and monitor collection jobs." }
  ];
  const resultPages = result ? RESULT_PAGES : [];
  const explorerPages = EXPLORER_PAGES;
  const availablePageIdList = [
    ...workflowPages.map((page) => page.id),
    ...resultPages.map((page) => page.id),
    ...explorerPages.map((page) => page.id)
  ];
  const availablePageIds = new Set(availablePageIdList);
  const availablePageKey = availablePageIdList.join("|");

  useEffect(() => {
    const onHashChange = () => {
      const nextPage = window.location.hash.replace(/^#/, "");
      if (nextPage && availablePageIds.has(nextPage)) {
        setActivePage(nextPage);
      }
    };

    window.addEventListener("hashchange", onHashChange);
    return () => {
      window.removeEventListener("hashchange", onHashChange);
    };
  }, [availablePageKey]);

  useEffect(() => {
    if (availablePageIds.has(activePage)) {
      return;
    }
    setActivePage(result ? "overview" : "investigate");
  }, [activePage, availablePageKey, result]);

  useEffect(() => {
    if (result && !window.location.hash) {
      setActivePage("overview");
    }
  }, [result]);

  function navigateToPage(pageId) {
    setActivePage(pageId);
    if (typeof window !== "undefined") {
      window.history.replaceState(null, "", `#${pageId}`);
    }
  }

  let pageContent = (
    <PageFrame
      eyebrow="Workflow"
      title="Ready to investigate"
      subtitle="Run a collection job or move through the explorer pages above."
      infoTitle="Where to start"
      infoBody="If you already have stored data, start on the graph page. If not, run a new job from the investigate page first."
    >
      <p className="muted">Start with a target, then move across the result and explorer pages once the data lands.</p>
    </PageFrame>
  );

  if (activePage === "investigate") {
    pageContent = (
      <InvestigatePage
        form={form}
        setForm={setForm}
        busy={busy}
        scanHelp={meta.scan_options || {}}
        pivotOptions={meta.pivot_options || {}}
        openctiState={openctiState}
        onAnalyze={() => submitAnalysis()}
        onProvidersOnly={() =>
          submitAnalysis({
            scan: false,
            scan_europe: false,
            scan_all: false,
            scan_providers: true,
            scan_eu_countries: false,
            scan_full: false,
            scan_countries: []
          })
        }
        onOpenCtiAction={triggerOpenCti}
        job={job}
      />
    );
  }

  if (result && RESULT_PAGES.some((page) => page.id === activePage)) {
    pageContent = <ResultContentPage pageId={activePage} result={result} meta={meta} onOpenSavedResult={openSavedResult} />;
  }

  if (activePage === "graph") {
    pageContent = <GraphPage clusters={clusters} recent={recent} theme={theme} />;
  }

  if (activePage === "connections") {
    pageContent = (
      <ConnectionsPage
        connections={connections}
        meta={meta}
        selectedTarget={selectedTarget}
        setSelectedTarget={setSelectedTarget}
        recent={recent}
        onOpenSavedResult={openSavedResult}
      />
    );
  }

  if (activePage === "recent") {
    pageContent = (
      <SharedSignalPage
        eyebrow="Explorer"
        title="Recent searches"
        subtitle="Saved investigations you can reopen without running the pipeline again."
        infoTitle="Recent searches"
        infoBody="Think of this page as case history, not live traffic. Open one of these searches to push its result back into the result pages."
        items={recent}
        emptyMessage="No saved searches are available yet."
        renderItem={(item) => (
          <LeadCard
            key={item.id}
            title={item.target}
            footer={`${item.type.toUpperCase()} | ${cloudflareLabel(item.cloudflare_fronted)} | ${formatDateTime(item.timestamp)}`}
          >
            <button className="inline-action" onClick={() => openSavedResult(item.id)} type="button">
              Open saved result
            </button>
          </LeadCard>
        )}
      />
    );
  }

  if (activePage === "ip") {
    pageContent = (
      <SharedSignalPage
        eyebrow="Explorer"
        title="Shared IPs"
        subtitle="Domains that touched the same server address or hosting network."
        infoTitle="Shared IPs"
        infoBody="A shared IP can be a strong clue when the server looks dedicated, but it is weaker when the IP belongs to shared hosting, mail infrastructure, or a CDN."
        items={clusters.ip}
        emptyMessage="No shared IP clusters are stored yet."
        renderItem={(item) => (
          <LeadCard key={item.ip} title={item.ip} footer={`${item.target_count} linked targets`}>
            <div className="pill-row">
              <TypePill kind={item.label} definitions={meta.server_types || {}} />
            </div>
            <p className="break-word">{item.targets}</p>
            {item.asn_desc ? <p>{item.asn_desc}</p> : null}
            {item.network_cidr ? <p><strong>Network:</strong> {item.network_cidr}</p> : null}
            {item.proxy_family ? <p><strong>Reverse proxy:</strong> {item.proxy_family}</p> : null}
          </LeadCard>
        )}
      />
    );
  }

  if (activePage === "asn") {
    pageContent = (
      <PageFrame
        eyebrow="Explorer"
        title="Shared ASNs"
        subtitle="Domains clustering around the same provider network or autonomous system."
        infoTitle="How to read ASN overlap"
        infoBody="ASN overlap is strongest when the ASN looks dedicated and weaker when it belongs to a CDN, mail service, or broad shared-hosting platform. Use the labels as a noise guide, not a final verdict."
      >
        <div className="field-row">
          <label htmlFor="asn-scope">Scope</label>
          <select id="asn-scope" value={asnScope} onChange={(event) => setAsnScope(event.target.value)}>
            <option value="current">Current overlaps</option>
            <option value="historical">Historical only</option>
            <option value="all">All history</option>
          </select>
        </div>
        {clusters.asn.length ? (
          <div className="card-grid">
            {clusters.asn.map((item) => (
              <LeadCard
                key={item.asn}
                title={`AS${item.asn}`}
                footer={`${item.target_count} linked targets | ${item.relationship_status === "current" ? "shared now" : "historical only"}`}
              >
                <div className="pill-row">
                  <TypePill kind={item.label} definitions={meta.server_types || {}} />
                </div>
                {item.asn_desc ? <p><strong>Owner:</strong> {item.asn_desc}</p> : null}
                {item.network_cidrs && item.network_cidrs.length ? (
                  <p className="break-word"><strong>Networks:</strong> {formatListPreview(item.network_cidrs)}</p>
                ) : null}
                {item.proxy_families && item.proxy_families.length ? (
                  <p><strong>Proxy families:</strong> {item.proxy_families.join(", ")}</p>
                ) : null}
                <p className="break-word">{item.targets}</p>
              </LeadCard>
            ))}
          </div>
        ) : (
          <Callout tone="info">No ASN overlaps are stored for this scope yet.</Callout>
        )}
      </PageFrame>
    );
  }

  if (activePage === "tracking") {
    pageContent = (
      <SharedSignalPage
        eyebrow="Explorer"
        title="Tracking IDs"
        subtitle="Analytics and advertising identifiers reused across stored domains."
        infoTitle="Tracking IDs"
        infoBody="If two domains share the same tracking or advertising code, it often means the same operator, agency, or page template is behind both."
        items={clusters.tracking}
        emptyMessage="No tracking overlaps are stored yet."
        renderItem={(item) => (
          <LeadCard key={`${item.id_type}-${item.id_value}`} title={`${item.id_type}: ${item.id_value}`} footer={`${item.target_count} linked targets`}>
            <p className="break-word">{item.targets}</p>
          </LeadCard>
        )}
      />
    );
  }

  if (activePage === "favicon") {
    pageContent = (
      <SharedSignalPage
        eyebrow="Explorer"
        title="Favicons"
        subtitle="Domains sharing the same browser-tab icon hash."
        infoTitle="Favicons"
        infoBody="Matching favicons are not proof by themselves, but they are a useful sign that sites may share a template, builder, or operator."
        items={clusters.favicon}
        emptyMessage="No favicon overlaps are stored yet."
        renderItem={(item) => (
          <LeadCard key={item.md5} title={item.md5} footer={`${item.target_count} linked targets`}>
            <p className="break-word">{item.targets}</p>
          </LeadCard>
        )}
      />
    );
  }

  if (activePage === "tls") {
    pageContent = (
      <PageFrame
        eyebrow="Explorer"
        title="TLS overlaps"
        subtitle="Domains tied together by exact HTTPS certificate identity, with time-aware overlap status."
        infoTitle="TLS overlaps"
        infoBody="A TLS overlap means two domains presented the same certificate fingerprint. The scope switch lets you separate domains that share a certificate now from ones that only shared it in the past."
      >
        <div className="field-row">
          <label htmlFor="tls-scope">Scope</label>
          <select id="tls-scope" value={tlsScope} onChange={(event) => setTlsScope(event.target.value)}>
            <option value="current">Current overlaps</option>
            <option value="historical">Historical only</option>
            <option value="all">All history</option>
          </select>
        </div>
        {clusters.tls.length ? (
          <div className="card-grid">
            {clusters.tls.map((item) => (
              <LeadCard
                key={item.sha256}
                title={item.cn || item.sha256.slice(0, 16)}
                footer={`${item.target_count} linked targets | ${item.relationship_status === "current" ? "shared now" : "historical only"}`}
              >
                <p><strong>Issuer:</strong> {item.issuer_cn || "Unknown"}</p>
                <p className="break-word"><strong>Fingerprint:</strong> {item.sha256}</p>
                <p><strong>Seen:</strong> {`${formatDateTime(item.first_observed)} to ${formatDateTime(item.last_observed)}`}</p>
                <p><strong>Overlap window:</strong> {`${formatDateTime(item.overlap_start)} to ${formatDateTime(item.overlap_end)}`}</p>
                <p><strong>Current targets:</strong> {formatNumber(item.current_target_count || 0)} | <strong>Historical targets:</strong> {formatNumber(item.historical_target_count || 0)}</p>
                <p className="break-word">{item.targets}</p>
              </LeadCard>
            ))}
          </div>
        ) : (
          <Callout tone="info">No TLS overlaps are stored for this scope yet.</Callout>
        )}
      </PageFrame>
    );
  }

  return (
    <main className="app-shell">
      <header className="app-topbar">
        <div className="app-topbar-main">
          <div className="brand-block">
            <span className="brand-kicker">IP Intel</span>
            <h1 className="brand-title">Investigation console</h1>
            <p className="brand-subtitle">
              Full-width pages for collection, result review, graph analysis, and domain pivots.
            </p>
          </div>
          <div className="topbar-actions">
            <div className="status-chip-row">
              <span className="status-chip">
                <strong>{formatNumber(storedDomains)}</strong>
                Stored domains
              </span>
              <span className="status-chip">
                <strong>{formatNumber(sharedSignalCount)}</strong>
                Shared signals
              </span>
              <span className="status-chip">
                <strong>{openctiLabel}</strong>
                OpenCTI
              </span>
            </div>
            <button className="theme-toggle" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} type="button">
              {theme === "dark" ? "Light mode" : "Dark mode"}
            </button>
          </div>
        </div>

        <div className="page-nav">
          <div className="page-nav-group">
            <span className="page-nav-label">Workflow</span>
            <div className="page-nav-strip">
              {workflowPages.map((page) => (
                <PageNavButton
                  key={page.id}
                  active={activePage === page.id}
                  label={page.label}
                  subtitle={page.subtitle}
                  onClick={() => navigateToPage(page.id)}
                />
              ))}
            </div>
          </div>

          {resultPages.length ? (
            <div className="page-nav-group">
              <span className="page-nav-label">Result pages</span>
              <div className="page-nav-strip">
                {resultPages.map((page) => (
                  <PageNavButton
                    key={page.id}
                    active={activePage === page.id}
                    label={page.label}
                    subtitle={page.subtitle}
                    onClick={() => navigateToPage(page.id)}
                  />
                ))}
              </div>
            </div>
          ) : null}

          <div className="page-nav-group">
            <span className="page-nav-label">Explorer pages</span>
            <div className="page-nav-strip">
              {explorerPages.map((page) => (
                <PageNavButton
                  key={page.id}
                  active={activePage === page.id}
                  label={page.label}
                  subtitle={page.subtitle}
                  onClick={() => navigateToPage(page.id)}
                />
              ))}
            </div>
          </div>
        </div>
      </header>

      {statusMessage ? <Callout tone="success">{statusMessage}</Callout> : null}
      {errorMessage ? <Callout tone="danger">{errorMessage}</Callout> : null}

      <section className="page-stage">
        {pageContent}
      </section>
    </main>
  );
}
