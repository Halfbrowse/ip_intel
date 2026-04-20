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
  { id: "overview", label: "Snapshot", subtitle: "Start here for the seed, the strongest leads, and the next pivots." },
  { id: "dns", label: "Seed data", subtitle: "The direct DNS and registration facts pulled from the supplied target." },
  { id: "certs", label: "Certificates", subtitle: "Certificate history and overlaps around the target." },
  { id: "origin", label: "Expansion", subtitle: "How the analysis spread outward into likely matches." },
  { id: "ips", label: "Infrastructure", subtitle: "What each discovered IP or network probably means." }
];

const EXPLORER_TABS = [
  { id: "network", label: "Network graph" },
  { id: "recent", label: "Recent searches" },
  { id: "ip", label: "Shared IPs" },
  { id: "asn", label: "Shared ASNs" },
  { id: "tracking", label: "Tracking IDs" },
  { id: "favicon", label: "Favicons" },
  { id: "tls", label: "Shared certificates" },
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
  { id: "tls", label: "Shared certificates", subtitle: "Domains that reused the same HTTPS certificate." }
];

const CONNECTION_SECTIONS = [
  {
    key: "tracking_ids",
    title: "Tracking and analytics IDs",
    infoBody: "If two domains share the same analytics or ad code, there is a decent chance they are run by the same team, contractor, or toolkit."
  },
  {
    key: "tls_certs",
    title: "Shared certificates",
    infoBody: "These cards show exact HTTPS certificates that multiple domains reused. Current certificate reuse is one of the stronger technical links in the app."
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
    infoBody: "Shared IPs can mean the same server is involved. Large CDN, managed WordPress, mail, and shared-hosting overlaps are treated as background noise, so the IP links shown here aim to stay higher-signal."
  },
  {
    key: "asns",
    title: "ASNs and networks",
    infoBody: "ASN overlap shows that domains lived inside the same provider network. Broad CDN, managed WordPress, mail, and shared-hosting ASNs are filtered as low-signal noise, so the remaining overlaps are meant to be more actionable."
  },
  {
    key: "tls_history",
    title: "Certificate reuse over time",
    infoBody: "This section explains whether the certificate sharing is still live or only happened in the past, plus when that overlap was seen."
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
    summary: "Both domains presented the same HTTPS certificate.",
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
    meaning: "In plain English: the sites touched the same server address. The graph already filters broad CDN, managed WordPress, mail, and shared-hosting overlaps, so what remains should skew toward more dedicated-looking infrastructure.",
    caution: "A shared IP is still supportive evidence rather than proof, but the noisier platform overlaps are already suppressed here."
  },
  asn: {
    label: "ASN/network",
    headline: "Shared provider network",
    color: "#2fb6c4",
    summary: "The domains were observed inside the same autonomous system or network range.",
    meaning: "In plain English: the domains lived in the same provider network. That is useful context, especially on smaller or dedicated-looking networks, but it is usually weaker than an exact TLS or direct-IP match.",
    caution: "Broad CDN, managed WordPress, mail, and shared-hosting providers are filtered out of the overlap views, but ASN matches should still be treated as weighted context rather than proof."
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

function formatFriendlyDateRange(start, end) {
  if (start && end) {
    return `${formatDateTime(start)} to ${formatDateTime(end)}`;
  }
  if (start) {
    return `From ${formatDateTime(start)}`;
  }
  if (end) {
    return `Until ${formatDateTime(end)}`;
  }
  return "Unknown";
}

function getTlsOverlapTitle(item) {
  const commonName = String(item?.cn || "").trim();
  if (commonName) {
    return commonName;
  }

  const issuer = String(item?.issuer_cn || item?.issuer_org || "").trim();
  if (issuer) {
    return `Certificate from ${issuer}`;
  }

  const fingerprint = String(item?.sha256 || "").trim();
  if (!fingerprint) {
    return "Shared certificate";
  }
  return `Certificate ${fingerprint.length > 24 ? `${fingerprint.slice(0, 12)}...${fingerprint.slice(-8)}` : fingerprint}`;
}

function getTlsOverlapTargetCount(item) {
  const directCount = Number(item?.target_count || 0);
  if (Number.isFinite(directCount) && directCount > 0) {
    return directCount;
  }
  return parseTargetList(item?.targets).length;
}

function getTlsOverlapStatusLabel(value) {
  return normalizeEvidenceStatus(value) === "current" ? "Still shared now" : "Past sharing only";
}

function getTlsOverlapSummary(item) {
  const status = normalizeEvidenceStatus(item?.relationship_status);
  const domainCount = getTlsOverlapTargetCount(item);
  const domainLabel = `${formatNumber(domainCount)} stored domain${domainCount === 1 ? "" : "s"}`;
  const commonName = String(item?.cn || "").trim();

  if (status === "current") {
    return commonName
      ? `The HTTPS certificate for ${commonName} is still shared across ${domainLabel}, which makes this one of the stronger technical overlaps in the app.`
      : `This exact HTTPS certificate is still shared across ${domainLabel}, which makes it one of the stronger technical overlaps in the app.`;
  }

  return commonName
    ? `The HTTPS certificate for ${commonName} linked ${domainLabel} in the past. That can reveal older hosting, migrations, or previous common control.`
    : `This exact HTTPS certificate linked ${domainLabel} in the past. That can reveal older hosting, migrations, or previous common control.`;
}

function filterLowSignalClusterItems(items) {
  return (items || []).filter((item) => !item?.is_noise);
}

function getVisibleClusters(clusters) {
  return {
    ...clusters,
    ip: filterLowSignalClusterItems(clusters?.ip),
    asn: filterLowSignalClusterItems(clusters?.asn)
  };
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

function getProviderHitCount(result) {
  const origin = result.origin_candidates || {};
  return ["censys", "shodan", "netlas"].reduce((sum, key) => {
    const hits = origin[key] && origin[key].hits ? origin[key].hits : [];
    return sum + hits.length;
  }, 0);
}

function getTargetedSweepHitCount(result) {
  const origin = result.origin_candidates || {};
  return ["scan", "provider_scan", "country_scan"].reduce((sum, key) => {
    const hits = origin[key] && origin[key].hits ? origin[key].hits : [];
    return sum + hits.length;
  }, 0);
}

function getCurrentIps(result) {
  if (!result) {
    return [];
  }
  if (result.type === "ip" && result.input) {
    return [result.input];
  }
  const dns = result.dns || {};
  return [...(dns.A || []), ...(dns.AAAA || [])]
    .filter(Boolean)
    .map((item) => String(item));
}

function getIpEntries(result) {
  if (!result) {
    return [];
  }
  if (result.type === "ip") {
    return result.input
      ? [[result.input, result]]
      : [];
  }
  return Object.entries(result.ip_details || {});
}

function getDirectIpCount(result) {
  return getIpEntries(result).filter(([, info]) => info && info.server_type === "direct").length;
}

function getLiveTlsCount(result) {
  if (!result) {
    return 0;
  }
  if (result.type === "ip") {
    return result.tls_cert ? 1 : 0;
  }
  return (result.non_cf_tls_certs || []).length;
}

function getRelatedTargetsSummary(result) {
  return result.related_targets_summary || {
    items: [],
    total: 0,
    domains: 0,
    ips: 0,
    expandable: 0,
    hard_total: 0
  };
}

function getHardConnections(result) {
  return result.hard_connections || {
    items: [],
    total: 0,
    shown: 0,
    domains: 0,
    ips: 0
  };
}

function getPivotCandidates(result, limit = 6) {
  return (getRelatedTargetsSummary(result).items || [])
    .filter((item) => item.auto_expand && item.connection_strength !== "hard")
    .slice(0, limit);
}

function formatRelationList(values, limit = 3) {
  const items = (values || [])
    .map((value) => String(value || "").replace(/_/g, " "))
    .filter(Boolean);
  return formatListPreview(items, limit) || "No relation labels";
}

function buildExposureSummary(result) {
  if (!result) {
    return {
      tone: "info",
      title: "Waiting for a seed",
      body: "Add a domain or IP and the app will profile the seed before it branches outward."
    };
  }

  if (result.type === "ip") {
    return {
      tone: result.server_type === "direct" ? "success" : "info",
      title: result.server_type === "direct" ? "Direct IP investigation" : "Infrastructure IP investigation",
      body: result.server_type === "direct"
        ? "This seed is already a direct-looking IP, so the workflow can move straight into ASN, reverse-IP, and TLS validation."
        : "This seed is an IP address, so the workflow profiles the network first and then looks outward for domains or neighboring infrastructure."
    };
  }

  if (result.cloudflare_fronted) {
    return {
      tone: "info",
      title: "Cloudflare is in front right now",
      body: "The current DNS points at Cloudflare, so the useful work is to spread outward into subdomains, historical infrastructure, provider hits, and non-Cloudflare matches."
    };
  }

  const directIpCount = getDirectIpCount(result);
  if (directIpCount > 0) {
    return {
      tone: "success",
      title: "Direct infrastructure is already visible",
      body: `${directIpCount} discovered IP${directIpCount === 1 ? "" : "s"} look direct rather than shared or proxied, which makes origin confirmation much faster.`
    };
  }

  return {
    tone: "warning",
    title: "No direct origin is confirmed yet",
    body: "The next best path is to follow nearby pivots such as subdomains, history, provider matches, and certificate overlap until a direct host emerges."
  };
}

function looksLikeIpTarget(value) {
  const text = String(value || "").trim();
  if (!text) {
    return false;
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(text)) {
    return text.split(".").every((part) => {
      const numeric = Number(part);
      return numeric >= 0 && numeric <= 255;
    });
  }
  return text.includes(":");
}

function getCompletedAnalysisPhases(payload) {
  const result = payload || {};
  const origin = result.origin_candidates || {};
  const relatedSummary = getRelatedTargetsSummary(result);
  const providerChecksRan = ["censys", "shodan", "netlas"]
    .some((key) => Object.prototype.hasOwnProperty.call(origin, key));
  const targetedSweepsRan = ["scan", "provider_scan", "country_scan"]
    .some((key) => {
      const entry = origin[key];
      return Boolean(entry) && !entry.skipped;
    });
  const ipEnrichmentRan = Boolean(
    getIpEntries(result).length
    || (result.type === "ip" && (result.ptr || (result.asn_info && Object.keys(result.asn_info).length)))
  );
  const tlsValidationRan = Object.prototype.hasOwnProperty.call(result, "non_cf_tls_certs")
    || Object.prototype.hasOwnProperty.call(result, "tls_cert");

  const completed = new Set();
  if (result.type || result.timestamp || getCurrentIps(result).length) {
    completed.add("Seed profile");
  }
  if (result.type || relatedSummary.total || collectOriginLeadCount(result) || (result.subdomains || []).length || (((result.historical_dns || {}).records) || []).length) {
    completed.add("Expand from seed");
  }
  if (providerChecksRan) {
    completed.add("Provider checks");
  }
  if (targetedSweepsRan) {
    completed.add("Targeted sweeps");
  }
  if (ipEnrichmentRan) {
    completed.add("ASN/IP enrichment");
  }
  if (tlsValidationRan) {
    completed.add("TLS validation");
  }
  return completed;
}

function buildAnalysisStages(payload, job, targetHint = "") {
  const result = payload || {};
  const target = result.input || targetHint || job?.target || "";
  const type = result.type || (target ? (looksLikeIpTarget(target) ? "ip" : "domain") : "");
  const relatedSummary = getRelatedTargetsSummary(result);
  const currentIps = getCurrentIps(result);
  const providerHitCount = getProviderHitCount(result);
  const sweepHitCount = getTargetedSweepHitCount(result);
  const directLeadCount = collectOriginLeadCount(result);
  const liveTlsCount = getLiveTlsCount(result);
  const ipCount = getIpEntries(result).length;
  const cloudflareState = result.cloudflare_fronted ?? result.cloudflare;
  const completedPhases = getCompletedAnalysisPhases(result);
  const progress = job?.progress || null;
  const completed = new Set(progress?.completed || []);
  const current = progress?.current || "";
  const hasMaterialData = Boolean(
    result.type
    || result.timestamp
    || currentIps.length
    || directLeadCount
    || providerHitCount
    || sweepHitCount
    || ipCount
    || liveTlsCount
    || relatedSummary.total
  );

  const stages = [
    {
      phase: "Seed profile",
      title: "Profile the seed",
      description: type === "ip"
        ? "Read the supplied IP directly: PTR, ASN, Cloudflare posture, reverse-IP, and live TLS."
        : "Read the supplied domain directly: DNS, WHOIS, certificate history, page metadata, and Cloudflare posture.",
      meta: target
        ? `${target}${currentIps.length ? ` • ${formatNumber(currentIps.length)} current IPs` : ""}${cloudflareState !== undefined ? ` • ${cloudflareLabel(cloudflareState)}` : ""}`
        : "Add a domain or IP to begin."
    },
    {
      phase: "Expand from seed",
      title: "Spread outward from the seed",
      description: "Use subdomains, historical records, TXT/SPF, urlscan, and discovered pivots to find nearby infrastructure.",
      meta: target
        ? `${formatNumber(directLeadCount)} direct leads • ${formatNumber(relatedSummary.expandable || 0)} expandable pivots`
        : "Nothing to expand yet."
    },
    {
      phase: "Provider checks",
      title: "Check likely provider matches",
      description: "Use Censys, Shodan, and Netlas where the seed suggests the same infrastructure may reappear elsewhere.",
      meta: target ? `${formatNumber(providerHitCount)} provider hits so far` : "Provider checks wait for a seed."
    },
    {
      phase: "Targeted sweeps",
      title: "Fan out into Google or hoster space",
      description: "If enabled, branch into Google Cloud, known hosting ASNs, or country allocations once the seed looks promising.",
      meta: target ? `${formatNumber(sweepHitCount)} targeted sweep hits` : "Targeted sweeps are optional."
    },
    {
      phase: "ASN/IP enrichment",
      title: "Classify the infrastructure",
      description: "Attach ASN and server context to each IP so dedicated hosts stand apart from shared or noisy platforms.",
      meta: target ? `${formatNumber(ipCount)} IPs enriched` : "IP enrichment starts after collection."
    },
    {
      phase: "TLS validation",
      title: "Confirm with live TLS",
      description: "Pull live certificates from non-Cloudflare IPs to verify which matches still look real.",
      meta: target ? `${formatNumber(liveTlsCount)} live TLS cert${liveTlsCount === 1 ? "" : "s"} captured` : "TLS validation happens last."
    }
  ];

  if (!job) {
    if (hasMaterialData) {
      return stages.map((stage) => ({
        ...stage,
        state: completedPhases.has(stage.phase) ? "complete" : "pending"
      }));
    }
    return stages.map((stage, index) => ({
      ...stage,
      state: target && index === 0 ? "active" : "pending"
    }));
  }

  if (job.status === "completed") {
    return stages.map((stage) => ({
      ...stage,
      state: completedPhases.has(stage.phase) ? "complete" : "pending"
    }));
  }

  let activeAssigned = false;
  return stages.map((stage) => {
    if (completed.has(stage.phase)) {
      return { ...stage, state: "complete" };
    }
    if (!activeAssigned && (current === stage.phase || job.status === "running" || job.status === "queued")) {
      activeAssigned = true;
      return { ...stage, state: "active" };
    }
    return { ...stage, state: "pending" };
  });
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

function SearchableDomainField({
  id,
  label,
  value,
  onChange,
  options,
  placeholder = "Search stored domains",
  emptySelectionLabel = "",
  helper = "",
  className = "field-row"
}) {
  const [query, setQuery] = useState(value || "");
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!open) {
      setQuery(value || "");
    }
  }, [open, value]);

  const normalizedQuery = String(query || "").trim().toLowerCase();
  const visibleLimit = normalizedQuery ? 18 : 10;
  const filteredOptions = [];
  let matchCount = 0;

  options.forEach((item) => {
    if (normalizedQuery && !item.toLowerCase().includes(normalizedQuery)) {
      return;
    }
    matchCount += 1;
    if (filteredOptions.length < visibleLimit) {
      filteredOptions.push(item);
    }
  });

  const showResults = open && (Boolean(emptySelectionLabel) || Boolean(matchCount) || Boolean(normalizedQuery));
  const metaText = normalizedQuery && query !== value
    ? `${formatNumber(matchCount)} match${matchCount === 1 ? "" : "es"}${matchCount ? ". Press Enter to choose the first." : ""}`
    : helper || `${formatNumber(options.length)} stored domain${options.length === 1 ? "" : "s"}`;

  const handleSelect = (nextValue) => {
    setQuery(nextValue);
    onChange(nextValue);
    setOpen(false);
  };

  return (
    <div className={`${className} domain-search-field`}>
      <label htmlFor={id}>{label}</label>
      <div className="domain-search-shell">
        <input
          id={id}
          type="text"
          autoComplete="off"
          value={query}
          placeholder={placeholder}
          aria-expanded={showResults}
          onFocus={() => setOpen(true)}
          onBlur={() => {
            window.setTimeout(() => setOpen(false), 120);
          }}
          onChange={(event) => {
            const nextQuery = event.target.value;
            setQuery(nextQuery);
            setOpen(true);
            if (!nextQuery.trim()) {
              onChange("");
            }
          }}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              if (!query.trim()) {
                handleSelect("");
                return;
              }
              if (filteredOptions.length) {
                handleSelect(filteredOptions[0]);
              }
            }
            if (event.key === "Escape") {
              event.preventDefault();
              setQuery(value || "");
              setOpen(false);
            }
          }}
        />

        {showResults ? (
          <div className="domain-search-results" role="listbox" aria-label={`${label} results`}>
            {emptySelectionLabel ? (
              <button
                className={!value ? "domain-search-option active" : "domain-search-option"}
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => handleSelect("")}
                type="button"
              >
                {emptySelectionLabel}
              </button>
            ) : null}

            {filteredOptions.map((item) => (
              <button
                className={item === value ? "domain-search-option active" : "domain-search-option"}
                key={item}
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => handleSelect(item)}
                type="button"
              >
                {item}
              </button>
            ))}

            {!matchCount && normalizedQuery ? (
              <div className="domain-search-empty">No stored domains match this search.</div>
            ) : null}
          </div>
        ) : null}
      </div>
      <small className="domain-search-meta">{metaText}</small>
    </div>
  );
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
    return getTlsOverlapTitle(item);
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
        <p>{getTlsOverlapSummary(item)}</p>
        {item.issuer_cn ? <p><strong>Issued by:</strong> {item.issuer_cn}</p> : null}
        {item.ip ? <p><strong>Seen on IP:</strong> {item.ip}</p> : null}
        {(item.not_before || item.not_after) ? (
          <p><strong>Certificate valid:</strong> {`${formatDate(item.not_before)} to ${formatDate(item.not_after)}`}</p>
        ) : null}
        {item.sha256 ? (
          <details className="fold-panel">
            <summary>Raw certificate detail</summary>
            <p className="break-word"><strong>Fingerprint:</strong> {item.sha256}</p>
          </details>
        ) : null}
      </>
    );
  }

  if (sectionKey === "tls_history") {
    return (
      <>
        <p>{getTlsOverlapSummary(item)}</p>
        {item.issuer_cn ? <p><strong>Issued by:</strong> {item.issuer_cn}</p> : null}
        <p><strong>Status:</strong> {getTlsOverlapStatusLabel(item.relationship_status)}</p>
        {item.current_shared_with && item.current_shared_with.length ? (
          <p className="break-word"><strong>Still shared with:</strong> {item.current_shared_with.join(", ")}</p>
        ) : null}
        {item.historical_shared_with && item.historical_shared_with.length ? (
          <p className="break-word"><strong>Previously shared with:</strong> {item.historical_shared_with.join(", ")}</p>
        ) : null}
        {(item.first_observed || item.last_observed) ? (
          <p><strong>Seen in our data:</strong> {formatFriendlyDateRange(item.first_observed, item.last_observed)}</p>
        ) : null}
        {(item.overlap_start || item.overlap_end) ? (
          <p><strong>Shared during:</strong> {formatFriendlyDateRange(item.overlap_start, item.overlap_end)}</p>
        ) : null}
        {item.sha256 ? (
          <details className="fold-panel">
            <summary>Raw certificate detail</summary>
            <p className="break-word"><strong>Fingerprint:</strong> {item.sha256}</p>
          </details>
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
        `${getTlsOverlapTitle(row)} | ${row.issuer_cn || "Unknown issuer"} | ${relationshipStatus}`,
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
        ? `Both domains ${status === "current" ? "still use" : "used in the past"} the same HTTPS certificate: ${subject}.`
        : meta.summary,
      meaning: status === "current"
        ? "In plain English: the same HTTPS certificate is still live on both domains. That is one of the strongest technical links this graph can make from cert and IP data."
        : "In plain English: the same HTTPS certificate was shared in the past. That still matters because it can reveal migrations, legacy hosting, or older common control that is no longer live.",
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

function AnalysisFlowPanel({ payload, job, targetHint = "", compact = false }) {
  const stages = buildAnalysisStages(payload, job, targetHint);

  return (
    <section className={compact ? "analysis-flow compact" : "analysis-flow"}>
      {stages.map((stage, index) => (
        <article className={`analysis-step ${stage.state}`} key={stage.phase}>
          <div className="analysis-step-top">
            <span className="analysis-step-index">{String(index + 1).padStart(2, "0")}</span>
            <span className="analysis-step-state">
              {stage.state === "complete" ? "Done" : stage.state === "active" ? "Live" : "Waiting"}
            </span>
          </div>
          <h3>{stage.title}</h3>
          <p>{stage.description}</p>
          <small>{stage.meta}</small>
        </article>
      ))}
    </section>
  );
}

function RecommendedScansPanel({ recommendations, onRunRecommendation, busy }) {
  const items = recommendations && recommendations.items ? recommendations.items : [];
  if (!items.length) {
    return null;
  }

  return (
    <SectionCard
      title="Recommended next scans"
      subtitle="The normal pass is done. These are the deeper scans the current evidence makes worth trying next."
      infoTitle="Recommended next scans"
      infoBody="These suggestions are generated from the finished seed analysis. They stay targeted so you can widen the search deliberately instead of running every heavy scan by default."
    >
      <div className="card-grid">
        {items.map((item) => (
          <LeadCard
            key={item.id}
            title={item.label}
            footer={item.options && Array.isArray(item.options.scan_countries) && item.options.scan_countries.length
              ? `Countries: ${item.options.scan_countries.join(", ")}`
              : null}
          >
            <p>{item.reason}</p>
            {onRunRecommendation ? (
              <button className="inline-action" onClick={() => onRunRecommendation(item)} type="button" disabled={busy}>
                {busy ? "Running..." : "Run this scan"}
              </button>
            ) : null}
          </LeadCard>
        ))}
      </div>
    </SectionCard>
  );
}

function HardConnectionsPanel({ summary }) {
  const items = summary && summary.items ? summary.items : [];
  if (!items.length) {
    return null;
  }

  return (
    <SectionCard
      title="Hard connections"
      subtitle="These are the concrete IP or domain links the run can already defend with direct technical evidence."
      infoTitle="Hard connections"
      infoBody="Hard connections are the main point of the app: direct DNS links, certificate overlaps, discovered origin IPs, and other exact technical ties. They should be treated differently from softer pivots or broad similarity hints."
    >
      <div className="metric-grid">
        <Metric label="Total hard links" value={formatNumber(summary.total || 0)} />
        <Metric label="Domains" value={formatNumber(summary.domains || 0)} />
        <Metric label="IPs" value={formatNumber(summary.ips || 0)} />
        <Metric
          label="Shown now"
          value={formatNumber(summary.shown || items.length)}
          detail={summary.total > items.length ? "Top-ranked evidence only" : "All hard links shown"}
        />
      </div>

      <div className="card-grid">
        {items.map((item) => (
          <LeadCard
            key={`${item.target_type}-${item.target}`}
            title={item.target}
            footer={`${item.target_type.toUpperCase()} | ${formatNumber(item.hard_evidence_count || 0)} hard evidence signal${(item.hard_evidence_count || 0) === 1 ? "" : "s"}`}
          >
            <p>{item.evidence_rationale || "Concrete technical overlap discovered around the seed."}</p>
            <p><strong>Hard evidence:</strong> {formatRelationList(item.hard_relations && item.hard_relations.length ? item.hard_relations : item.relations, 4)}</p>
            <p><strong>Seen via:</strong> {formatListPreview(item.sources, 4)}</p>
          </LeadCard>
        ))}
      </div>
    </SectionCard>
  );
}

function DatabaseMatchesPanel({ matches, onOpenSavedResult }) {
  const items = matches && matches.items ? matches.items : [];
  if (!items.length) {
    return null;
  }

  return (
    <SectionCard
      title="Already in the database"
      subtitle="These top exposed IPs or domains already touch searches we’ve stored before."
      infoTitle="Already in the database"
      infoBody="This section answers the question: did any of the pivots uncovered in this run already appear in our own history? The cards below are a ranked shortlist, not an exhaustive export. A direct target hit is stronger than a passive discovered-target hit."
    >
      <div className="metric-grid">
        <Metric label="Top pivots shown" value={formatNumber(matches.total || 0)} />
        <Metric label="Top domains shown" value={formatNumber(matches.matched_domains || 0)} />
        <Metric label="Top IPs shown" value={formatNumber(matches.matched_ips || 0)} />
        <Metric label="Direct hits shown" value={formatNumber(matches.direct_target_hits || 0)} />
      </div>

      <div className="card-grid">
        {items.map((item) => (
          <LeadCard
            key={`${item.target_type}-${item.target}`}
            title={item.target}
            footer={item.match_count > item.matches.length
              ? `Showing ${item.matches.length} of ${item.match_count} stored matches`
              : `${item.match_count} stored match${item.match_count === 1 ? "" : "es"}`}
          >
            <p><strong>Pivot type:</strong> {item.target_type.toUpperCase()}</p>
            <p><strong>Why it surfaced:</strong> {formatRelationList(item.relations)}</p>
            <p><strong>Seen via:</strong> {formatListPreview(item.sources, 4)}</p>
            <div className="match-snippet-list">
              {item.matches.map((match) => (
                <div className="match-snippet" key={`${item.target}-${match.search_id}`}>
                  <p><strong>{match.target}</strong> | {formatDateTime(match.timestamp)} | {cloudflareLabel(match.cloudflare_fronted)}</p>
                  <p>
                    {match.matched_as_target
                      ? "Matched as a searched target."
                      : `Matched via ${formatRelationList(match.matched_relations)}.`}
                  </p>
                  {!match.matched_as_target && match.matched_sources && match.matched_sources.length ? (
                    <p><strong>Stored via:</strong> {formatListPreview(match.matched_sources, 4)}</p>
                  ) : null}
                  {onOpenSavedResult ? (
                    <button className="inline-action" onClick={() => onOpenSavedResult(match.search_id)} type="button">
                      Open match
                    </button>
                  ) : null}
                </div>
              ))}
            </div>
          </LeadCard>
        ))}
      </div>
    </SectionCard>
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
      {active && subtitle ? <span>{subtitle}</span> : null}
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
  const flowPayload = job.result || partial;
  const relatedSummary = getRelatedTargetsSummary(flowPayload);
  const phasePills = [
    ...(progress.completed || []).map((phase) => ({ label: phase, tone: "done" })),
    ...(progress.current ? [{ label: progress.current, tone: "active" }] : [])
  ];

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

        <details className="fold-panel">
          <summary>Raw ingestion log</summary>
          <div className="log-shell">
            {(job.logs || []).slice(-30).map((entry, index) => (
              <div className="log-line" key={`${index}-${entry}`}>
                {entry}
              </div>
            ))}
          </div>
        </details>
      </SectionCard>
    );
  }

  return (
    <SectionCard
      title={job.status === "completed" ? "Latest analysis" : "Live analysis"}
      subtitle={job.status === "completed" ? `Completed ${formatDateTime(job.updated_at)}` : `Following ${job.target} outward from the supplied seed`}
    >
      <div className="metric-grid">
        <Metric
          label="Current stage"
          value={progress.current || (job.status === "completed" ? "Complete" : "Queued")}
          detail={`${Math.round((progress.fraction || 0) * 100)}% of the flow tracked`}
        />
        <Metric label="Seed IPs" value={formatNumber(getCurrentIps(flowPayload).length || (dns.A || []).length)} />
        <Metric label="Origin leads" value={formatNumber(collectOriginLeadCount(flowPayload))} />
        <Metric
          label="Pivots"
          value={formatNumber(relatedSummary.expandable || 0)}
          detail={`${formatNumber(relatedSummary.total || 0)} total discovered`}
        />
      </div>

      <div className="progress-wrap">
        <div className="progress-track">
          <div className="progress-fill" style={{ width: `${(progress.fraction || 0) * 100}%` }} />
        </div>
        <div className="phase-pill-row">
          {phasePills.length
            ? phasePills.map((phase) => (
                <span className={phase.tone === "done" ? "phase-pill done" : "phase-pill active"} key={phase.label}>
                  {phase.label}
                </span>
              ))
            : <span className="phase-pill">Waiting for the first seed reads</span>}
        </div>
      </div>

      <AnalysisFlowPanel payload={flowPayload} job={job} compact />

      {job.error ? <Callout tone="danger">{job.error}</Callout> : null}

      <details className="fold-panel">
        <summary>Raw job log</summary>
        <div className="log-shell">
          {(job.logs || []).slice(-30).map((entry, index) => (
            <div className="log-line" key={`${index}-${entry}`}>
              {entry}
            </div>
          ))}
        </div>
      </details>
    </SectionCard>
  );
}

function OverviewTab({ result, meta, onRunRecommendation, onOpenSavedResult, busy }) {
  const dns = result.dns || {};
  const page = result.page_metadata || {};
  const email = result.email_security || {};
  const currentCerts = result.non_cf_tls_certs || (result.tls_cert ? [result.tls_cert] : []);
  const trackingIds = [
    ...(page.google_analytics || []).map((value) => ({ label: "Google Analytics", value })),
    ...(page.gtm_ids || []).map((value) => ({ label: "Google Tag Manager", value })),
    ...(page.facebook_pixel || []).map((value) => ({ label: "Facebook Pixel", value })),
    ...(page.tiktok_pixel || []).map((value) => ({ label: "TikTok Pixel", value })),
    ...(page.yandex_metrika || []).map((value) => ({ label: "Yandex Metrika", value }))
  ];
  const historicalIps = ((result.historical_dns || {}).records || []).filter((item) => ["A", "AAAA"].includes(item.rrtype));
  const interestingTxt = collectInterestingTxt(dns.TXT || []);
  const relatedSummary = getRelatedTargetsSummary(result);
  const hardConnections = getHardConnections(result);
  const pivots = getPivotCandidates(result);
  const exposure = buildExposureSummary(result);
  const currentIps = getCurrentIps(result);
  const hasPageContext = Boolean(
    (page.social_handles && Object.keys(page.social_handles).length)
    || (page.social_links && Object.keys(page.social_links).length)
    || page.html_lang
    || page.cms_generator
    || page.favicon_md5
  );
  const hasEmailContext = Boolean(email.dmarc || (email.dkim && Object.keys(email.dkim).length));
  const hasSupportingContext = Boolean(
    currentCerts.length
    || trackingIds.length
    || interestingTxt.length
    || hasPageContext
    || historicalIps.length
    || hasEmailContext
  );

  return (
    <div className="stack">
      {result.source_errors && result.source_errors.length ? (
        <Callout tone="warning">
          Some external sources failed or rate-limited during this run: {result.source_errors.join(", ")}.
        </Callout>
      ) : null}

      <section className="overview-hero">
        <div className="overview-hero-main">
          <div className="overview-hero-copy">
            <span className="eyebrow">At a glance</span>
            <h3>{result.input}</h3>
            <p>
              Seed first, then widen into provider, Google, Cloudflare, ASN, and TLS checks only where nearby matches look worth chasing.
            </p>
          </div>
          <div className="metric-grid overview-hero-metrics">
            <Metric label="Target type" value={(result.type || "").toUpperCase()} />
            <Metric label="Cloudflare" value={cloudflareLabel(result.cloudflare_fronted ?? result.cloudflare)} />
            <Metric label="Hard connections" value={formatNumber(hardConnections.total || 0)} detail={`${formatNumber(hardConnections.domains || 0)} domains • ${formatNumber(hardConnections.ips || 0)} IPs`} />
            <Metric label="Broader pivots" value={formatNumber(Math.max((relatedSummary.expandable || 0) - (hardConnections.total || 0), 0))} detail={`${formatNumber(relatedSummary.total || 0)} total discovered`} />
          </div>
        </div>
        <Callout tone={exposure.tone}>
          <strong>{exposure.title}.</strong> {exposure.body}
        </Callout>
      </section>

      <SectionCard
        title="Analysis path"
        subtitle="Seed first, then outward only where the evidence supports it."
      >
        <AnalysisFlowPanel payload={result} compact />
      </SectionCard>

      <HardConnectionsPanel summary={hardConnections} />

      <RecommendedScansPanel
        recommendations={result.scan_recommendations}
        onRunRecommendation={onRunRecommendation}
        busy={busy}
      />

      <SectionCard
        title="Seed snapshot"
        subtitle="The direct facts pulled from the supplied target before the workflow fans outward."
      >
        <KeyValueList
          items={[
            { label: "Registrar", value: getRegistrar(result) },
            { label: "Created", value: formatDate(result.whois && result.whois.creation_date) },
            { label: "Country", value: result.whois && result.whois.country },
            { label: "Org", value: result.whois && result.whois.org },
            { label: "Seed IPs", value: currentIps.length ? formatListPreview(currentIps, 4) : null }
          ]}
        />

        <div className="card-grid">
          <LeadCard title="Current routing">
            <p><strong>Cloudflare:</strong> {cloudflareLabel(result.cloudflare_fronted ?? result.cloudflare)}</p>
            <p className="break-word"><strong>Current IPs:</strong> {currentIps.length ? formatListPreview(currentIps, 6) : "No A/AAAA records were resolved"}</p>
            <p><strong>Direct-looking IPs:</strong> {formatNumber(getDirectIpCount(result))}</p>
          </LeadCard>
          <LeadCard title="Connection evidence">
            <p><strong>Hard connections:</strong> {formatNumber(hardConnections.total || 0)}</p>
            <p><strong>Related domains:</strong> {formatNumber(relatedSummary.domains || 0)}</p>
            <p><strong>Related IPs:</strong> {formatNumber(relatedSummary.ips || 0)}</p>
          </LeadCard>
        </div>
      </SectionCard>

      {pivots.length ? (
        <SectionCard
          title="Broader pivots"
          subtitle="Useful next leads, but weaker than the hard evidence links above."
        >
          <div className="card-grid">
            {pivots.map((item) => (
              <LeadCard key={`${item.target_type}-${item.target}`} title={item.target} footer={`${item.target_type.toUpperCase()} | score ${formatNumber(item.score || 0)}`}>
                <p><strong>Why it surfaced:</strong> {formatRelationList(item.relations)}</p>
                <p><strong>Seen via:</strong> {formatListPreview(item.sources, 4)}</p>
              </LeadCard>
            ))}
          </div>
        </SectionCard>
      ) : null}

      <DatabaseMatchesPanel matches={result.db_matches} onOpenSavedResult={onOpenSavedResult} />

      {hasSupportingContext ? (
        <details className="fold-panel">
          <summary>Supporting context and technical detail</summary>

          <div className="stack">
            {currentCerts.length ? (
              <SectionCard
                title="Live TLS certificates"
                subtitle="Certificates pulled directly from discovered non-Cloudflare IPs."
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
                subtitle="Useful pivot points when you want to find related domains."
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

            {hasPageContext ? (
              <SectionCard title="Social accounts and content signals" subtitle="Useful for operator mapping and template clues.">
                <div className="card-grid">
                  {Object.entries(page.social_handles || {}).map(([platform, handles]) => (
                    <LeadCard key={platform} title={platform.replace("_", " ")}>
                      <p className="break-word">{handles.join(", ")}</p>
                    </LeadCard>
                  ))}
                  {Object.entries(page.social_links || {}).map(([platform, links]) => (
                    <LeadCard key={`link-${platform}`} title={`${platform.replace("_", " ")} links`}>
                      <p className="break-word">{links.join(", ")}</p>
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

            {hasEmailContext ? (
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
        </details>
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
  const relatedSummary = getRelatedTargetsSummary(result);
  const providerHitCount = getProviderHitCount(result);
  const sweepHitCount = getTargetedSweepHitCount(result);
  const directLeadCount = collectOriginLeadCount(result);
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
      <SectionCard
        title="Expansion summary"
        subtitle="The workflow starts at the supplied seed, then only fans outward when the nearby evidence looks promising."
        infoTitle="Expansion summary"
        infoBody="Use this section to understand how much the run spread beyond the original domain or IP before you read the raw lead collections underneath."
      >
        <div className="metric-grid">
          <Metric label="Direct leads" value={formatNumber(directLeadCount)} />
          <Metric label="Provider hits" value={formatNumber(providerHitCount)} />
          <Metric label="Targeted sweep hits" value={formatNumber(sweepHitCount)} />
          <Metric label="Expandable pivots" value={formatNumber(relatedSummary.expandable || 0)} />
        </div>
        <AnalysisFlowPanel payload={result} compact />
      </SectionCard>

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

function ResultPanel({ result, meta, onRunRecommendation, onOpenSavedResult, busy }) {
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

      {activeTab === "overview" ? (
        <OverviewTab
          result={result}
          meta={meta}
          onRunRecommendation={onRunRecommendation}
          onOpenSavedResult={onOpenSavedResult}
          busy={busy}
        />
      ) : null}
      {activeTab === "dns" ? <DnsTab result={result} /> : null}
      {activeTab === "certs" ? <CertificatesTab result={result} meta={meta} /> : null}
      {activeTab === "origin" ? <OriginTab result={result} meta={meta} /> : null}
      {activeTab === "ips" ? <IpDetailsTab result={result} meta={meta} /> : null}
    </SectionCard>
  );
}

function NetworkGraphTab({ clusters, domainTargets, theme }) {
  const graphRef = useRef(null);
  const focusOptions = domainTargets || [];
  const visibleClusters = getVisibleClusters(clusters);
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

  const graph = buildNetworkModel(visibleClusters, controls);
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
            Each line connects domains that share something meaningful, like the same TLS fingerprint, tracking code, direct IP, or provider network. Broad CDN, managed WordPress, mail, and shared-hosting overlaps are filtered out before they reach this graph.
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
                  body="A shared IP means two domains point to the same server address. Broad CDN, managed WordPress, mail, and shared-hosting overlaps are filtered from the graph, so the remaining IP links are meant to be higher-signal."
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
                  body="ASN overlap means domains were seen in the same provider network. Broad CDN, managed WordPress, mail, and shared-hosting networks are filtered as low-signal noise before they reach the graph."
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

              <SearchableDomainField
                className="control-inline control-inline-wide"
                id="graph-focus"
                label="Focus on a domain"
                value={controls.focus}
                onChange={(nextValue) => updateControl("focus", nextValue)}
                options={focusOptions}
                placeholder="Search stored domains"
                emptySelectionLabel="All domains"
                helper={`${formatNumber(focusOptions.length)} stored domains available`}
              />

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
                            ? "These domains reused the same HTTPS certificate."
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
  domainTargets,
  clusters,
  connections,
  theme,
  selectedTarget,
  setSelectedTarget,
  onOpenSavedResult
}) {
  const [activeTab, setActiveTab] = useState("network");
  const visibleClusters = getVisibleClusters(clusters);

  return (
    <SectionCard
      title="Relationship explorer"
      subtitle="Pivot across stored domains using the strongest shared signals first."
    >
      <div className="tab-row">
        {EXPLORER_TABS.map((tab) => (
          <TabButton key={tab.id} active={activeTab === tab.id} label={tab.label} onClick={() => setActiveTab(tab.id)} />
        ))}
      </div>

      {activeTab === "recent" ? (
        <div className="stack">
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
        <NetworkGraphTab clusters={clusters} domainTargets={domainTargets} theme={theme} />
      ) : null}

      {activeTab === "ip" ? (
        <div className="stack">
          <div className="card-grid">
            {visibleClusters.ip.map((item) => (
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
          <div className="card-grid">
            {clusters.tls.map((item) => (
              <LeadCard key={item.sha256} title={getTlsOverlapTitle(item)} footer={`${formatNumber(getTlsOverlapTargetCount(item))} linked domains | ${getTlsOverlapStatusLabel(item.relationship_status)}`}>
                <p>{getTlsOverlapSummary(item)}</p>
                <p className="break-word"><strong>Domains:</strong> {formatListPreview(parseTargetList(item.targets), 6) || "No linked domains recorded"}</p>
                {item.issuer_cn ? <p><strong>Issued by:</strong> {item.issuer_cn}</p> : null}
                {item.sha256 ? (
                  <details className="fold-panel">
                    <summary>Raw certificate detail</summary>
                    <p className="break-word"><strong>Fingerprint:</strong> {item.sha256}</p>
                  </details>
                ) : null}
              </LeadCard>
            ))}
          </div>
        </div>
      ) : null}

      {activeTab === "connections" ? (
        <div className="stack">
          <SearchableDomainField
            id="connections-target"
            label="Find a stored domain"
            value={selectedTarget}
            onChange={setSelectedTarget}
            options={domainTargets}
            placeholder="Search stored domains"
            helper={`${formatNumber(domainTargets.length)} stored domains available`}
          />

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

function GraphPage({ clusters, domainTargets, theme }) {
  const graphApiRef = useRef({
    fit: () => {},
    reset: () => {}
  });
  const resizeStateRef = useRef(null);
  const [controls, setControls] = useState({ ...GRAPH_DEFAULT_CONTROLS });
  const [selection, setSelection] = useState(null);
  const [graphHeight, setGraphHeight] = useState(GRAPH_DEFAULT_HEIGHT);
  const [sidebarWidth, setSidebarWidth] = useState(GRAPH_DEFAULT_SIDEBAR_WIDTH);

  const visibleClusters = getVisibleClusters(clusters);
  const graph = buildNetworkModel(visibleClusters, controls);
  const focusOptions = domainTargets || [];
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
      subtitle="Filter stored domain links by strength, signal type, and focus domain."
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
                  Shared TLS, tracking, favicon, direct-IP, and network evidence, ranked so the strongest technical links surface first.
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

              <SearchableDomainField
                className="tt-graph-inline-select domain-search-inline"
                id="graph-page-focus"
                label="Focus domain"
                value={controls.focus}
                onChange={(nextValue) => updateControl("focus", nextValue)}
                options={focusOptions}
                placeholder="Search stored domains"
                emptySelectionLabel="All domains"
                helper={`${formatNumber(focusOptions.length)} stored domains available`}
              />
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

function ConnectionsPage({ connections, meta, selectedTarget, setSelectedTarget, domainTargets, onOpenSavedResult }) {
  return (
    <PageFrame
      eyebrow="Explorer"
      title="Domain connections"
      subtitle="Search a stored domain to inspect the strongest overlaps already in the database."
    >
      <SearchableDomainField
        id="connections-page-target"
        label="Find a stored domain"
        value={selectedTarget}
        onChange={setSelectedTarget}
        options={domainTargets}
        placeholder="Search stored domains"
        helper={`${formatNumber(domainTargets.length)} stored domains available`}
      />

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

function InvestigatePage({ form, setForm, busy, scanHelp, openctiState, onAnalyze, onProvidersOnly, onOpenCtiAction, job }) {
  const openctiJob = buildOpenctiJob(openctiState);

  return (
    <PageFrame
      eyebrow="Workflow"
      title="Analyse"
      subtitle="Start from a domain or IP, then watch the workflow spread outward only where the evidence supports it."
      infoTitle="How this page works"
      infoBody="Use this page to launch a seed-first analysis run. The app profiles the supplied domain or IP first, then fans outward into pivots, providers, Google ranges, ASNs, and TLS checks as the run develops."
    >
      <div className="full-page-grid">
        <ControlPanel
          form={form}
          setForm={setForm}
          busy={busy}
          scanHelp={scanHelp}
          openctiState={openctiState}
          onAnalyze={onAnalyze}
          onProvidersOnly={onProvidersOnly}
          onOpenCtiAction={onOpenCtiAction}
        />
        <div className="stack">
          {!job ? (
            <SectionCard
              title="Seed-first workflow"
              subtitle="What the run will do once you press Analyse target."
              infoTitle="Seed-first workflow"
              infoBody="The flow starts with the supplied target, then branches outward into pivots and deeper infrastructure checks only when the earlier evidence gives it somewhere useful to go."
            >
              <AnalysisFlowPanel targetHint={form.target} />
            </SectionCard>
          ) : <JobProgress job={job} />}
          {openctiJob ? <JobProgress job={openctiJob} /> : null}
          {!job && !openctiJob ? (
            <SectionCard title="Ready" subtitle="No job is running right now.">
              <p className="muted">Add a seed on the left, start the run, and this column will switch from the planned flow to the live analysis state.</p>
            </SectionCard>
          ) : null}
        </div>
      </div>
    </PageFrame>
  );
}

function ResultContentPage({ pageId, result, meta, onRunRecommendation, onOpenSavedResult, busy }) {
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
      {pageId === "overview" ? (
        <OverviewTab
          result={result}
          meta={meta}
          onRunRecommendation={onRunRecommendation}
          onOpenSavedResult={onOpenSavedResult}
          busy={busy}
        />
      ) : null}
      {pageId === "dns" ? <DnsTab result={result} /> : null}
      {pageId === "certs" ? <CertificatesTab result={result} meta={meta} /> : null}
      {pageId === "origin" ? <OriginTab result={result} meta={meta} /> : null}
      {pageId === "ips" ? <IpDetailsTab result={result} meta={meta} /> : null}
    </PageFrame>
  );
}

function ControlPanel({ form, setForm, busy, scanHelp, openctiState, onAnalyze, onProvidersOnly, onOpenCtiAction }) {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showOpencti, setShowOpencti] = useState(false);

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
      title="Analyse a seed"
      subtitle="Start with a domain or IP. Keep the default view tight, then widen the fan-out only if you need it."
      infoTitle="How this run starts"
      infoBody="The app profiles the supplied seed first. Google, provider, and country sweeps are available, but they stay tucked away until you explicitly open them."
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

        <div className="button-row">
          <button className="primary-button" onClick={onAnalyze} type="button" disabled={busy || !form.target.trim()}>
            {busy ? "Running..." : "Analyse target"}
          </button>
          <button className="secondary-button" onClick={onProvidersOnly} type="button" disabled={busy || !form.target.trim()}>
            Providers only
          </button>
        </div>

        <div className="fold-panel control-fold">
          <button className="fold-toggle" onClick={() => setShowAdvanced(!showAdvanced)} type="button">
            {showAdvanced ? "Hide expansion settings" : "Show expansion settings"}
          </button>
          {showAdvanced ? (
            <div className="stack">
              <div className="field-group">
                <h3>Expansion modes</h3>
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
            </div>
          ) : null}
        </div>

        <div className="fold-panel control-fold">
          <button className="fold-toggle" onClick={() => setShowOpencti(!showOpencti)} type="button">
            {showOpencti ? "Hide OpenCTI controls" : "Show OpenCTI controls"}
          </button>
          {showOpencti ? (
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
          ) : null}
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
    scan_options: {}
  });
  const [job, setJob] = useState(null);
  const [recent, setRecent] = useState([]);
  const [domainTargets, setDomainTargets] = useState([]);
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
    const [recentResponse, domainsResponse, ipResponse, asnResponse, trackingResponse, faviconResponse, tlsResponse] = await Promise.allSettled([
      apiFetch("/api/history/recent?limit=100"),
      apiFetch("/api/history/domains"),
      apiFetch("/api/clusters/ip"),
      apiFetch(`/api/clusters/asn?scope=${encodeURIComponent(asnScope)}`),
      apiFetch("/api/clusters/tracking"),
      apiFetch("/api/clusters/favicon"),
      apiFetch(`/api/clusters/tls?scope=${encodeURIComponent(tlsScope)}`)
    ]);

    setRecent(recentResponse.status === "fulfilled" ? recentResponse.value.items || [] : []);
    setDomainTargets(domainsResponse.status === "fulfilled" ? domainsResponse.value.items || [] : []);
    setClusters({
      ip: ipResponse.status === "fulfilled" ? ipResponse.value.items || [] : [],
      asn: asnResponse.status === "fulfilled" ? asnResponse.value.items || [] : [],
      tracking: trackingResponse.status === "fulfilled" ? trackingResponse.value.items || [] : [],
      favicon: faviconResponse.status === "fulfilled" ? faviconResponse.value.items || [] : [],
      tls: tlsResponse.status === "fulfilled" ? tlsResponse.value.items || [] : []
    });

    const labeledResponses = [
      ["Recent searches", recentResponse],
      ["Stored domains", domainsResponse],
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
      const firstDomain = (domainTargets.length ? domainTargets : getDomainTargets(recent))[0];
      if (firstDomain) {
        setSelectedTarget(firstDomain);
      }
    }
  }, [domainTargets, recent, selectedTarget]);

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
      const payload = {
        target: form.target,
        scan: form.scan,
        scan_europe: form.scan_europe,
        scan_all: form.scan_all,
        scan_providers: form.scan_providers,
        scan_eu_countries: form.scan_eu_countries,
        scan_full: form.scan_full,
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

  async function runRecommendedScan(recommendation) {
    if (!result || !recommendation) {
      return;
    }

    const options = recommendation.options || {};
    const countries = Array.isArray(options.scan_countries) ? options.scan_countries : [];

    setForm((current) => ({
      ...current,
      target: result.input,
      scan: Boolean(options.scan),
      scan_europe: Boolean(options.scan_europe),
      scan_all: Boolean(options.scan_all),
      scan_providers: Boolean(options.scan_providers),
      scan_eu_countries: Boolean(options.scan_eu_countries),
      scan_full: Boolean(options.scan_full),
      countriesText: countries.join(" ")
    }));

    await submitAnalysis({
      target: result.input,
      scan: false,
      scan_europe: false,
      scan_all: false,
      scan_providers: false,
      scan_eu_countries: false,
      scan_full: false,
      scan_countries: countries,
      ...options
    });
  }

  const result = job && job.result ? job.result : null;
  const busy = job && (job.status === "queued" || job.status === "running");
  const availableDomainTargets = domainTargets.length ? domainTargets : getDomainTargets(recent);
  const storedDomains = availableDomainTargets.length;
  const visibleClusters = getVisibleClusters(clusters);
  const sharedSignalCount = visibleClusters.ip.length + visibleClusters.asn.length + clusters.tracking.length + clusters.favicon.length + clusters.tls.length;
  const openctiLabel = openctiState.available === false
    ? "Unavailable"
    : openctiState.running
      ? "Running"
      : "Manual";
  const topbarChips = result
    ? [
        { label: "Current target", value: shortLabel(result.input, 28), title: result.input },
        { label: "Origin leads", value: formatNumber(collectOriginLeadCount(result)) },
        { label: "Expandable pivots", value: formatNumber(getRelatedTargetsSummary(result).expandable || 0) }
      ]
    : [
        { label: "Stored domains", value: formatNumber(storedDomains) },
        { label: "Shared signals", value: formatNumber(sharedSignalCount) },
        { label: "OpenCTI", value: openctiLabel }
      ];
  const workflowPages = [
    { id: "investigate", label: "Analyse", subtitle: "Launch and monitor seed-first collection runs." }
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
      title="Ready to analyse"
      subtitle="Run a collection job or move through the explorer pages above."
      infoTitle="Where to start"
      infoBody="If you already have stored data, start on the graph page. If not, run a new job from the Analyse page first."
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
    pageContent = (
      <ResultContentPage
        pageId={activePage}
        result={result}
        meta={meta}
        onRunRecommendation={runRecommendedScan}
        onOpenSavedResult={openSavedResult}
        busy={busy}
      />
    );
  }

  if (activePage === "graph") {
    pageContent = <GraphPage clusters={clusters} domainTargets={availableDomainTargets} theme={theme} />;
  }

  if (activePage === "connections") {
    pageContent = (
      <ConnectionsPage
        connections={connections}
        meta={meta}
        selectedTarget={selectedTarget}
        setSelectedTarget={setSelectedTarget}
        domainTargets={availableDomainTargets}
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
        infoBody="Broad CDN, managed WordPress, mail, and shared-hosting overlaps are filtered out here so the remaining shared IPs stay closer to dedicated-server leads."
        items={visibleClusters.ip}
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
        infoBody="Broad CDN, managed WordPress, mail, and shared-hosting networks are filtered out here as low-signal noise. Treat the remaining ASN overlaps as supporting context, not final proof."
      >
        <div className="field-row">
          <label htmlFor="asn-scope">Scope</label>
          <select id="asn-scope" value={asnScope} onChange={(event) => setAsnScope(event.target.value)}>
            <option value="current">Current overlaps</option>
            <option value="historical">Historical only</option>
            <option value="all">All history</option>
          </select>
        </div>
        {visibleClusters.asn.length ? (
          <div className="card-grid">
            {visibleClusters.asn.map((item) => (
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
        title="Shared certificates"
        subtitle="Domains that reused the same HTTPS certificate, with the overlap explained in plain English."
        infoTitle="Shared certificates"
        infoBody="When domains present the same HTTPS certificate, they were configured together at some point. Current sharing is usually stronger than historical sharing."
      >
        <div className="field-row">
          <label htmlFor="tls-scope">Scope</label>
          <select id="tls-scope" value={tlsScope} onChange={(event) => setTlsScope(event.target.value)}>
            <option value="current">Still shared now</option>
            <option value="historical">Past sharing only</option>
            <option value="all">Now and past</option>
          </select>
        </div>
        {clusters.tls.length ? (
          <div className="card-grid">
            {clusters.tls.map((item) => (
              <LeadCard
                key={item.sha256}
                title={getTlsOverlapTitle(item)}
                footer={`${formatNumber(getTlsOverlapTargetCount(item))} linked domains | ${getTlsOverlapStatusLabel(item.relationship_status)}`}
              >
                <p>{getTlsOverlapSummary(item)}</p>
                <p className="break-word"><strong>Domains:</strong> {formatListPreview(parseTargetList(item.targets), 6) || "No linked domains recorded"}</p>
                {item.issuer_cn ? <p><strong>Issued by:</strong> {item.issuer_cn}</p> : null}
                {(item.overlap_start || item.overlap_end) ? (
                  <p><strong>Shared during:</strong> {formatFriendlyDateRange(item.overlap_start, item.overlap_end)}</p>
                ) : null}
                {(item.first_observed || item.last_observed) ? (
                  <p><strong>Seen in our data:</strong> {formatFriendlyDateRange(item.first_observed, item.last_observed)}</p>
                ) : null}
                <details className="fold-panel">
                  <summary>Raw certificate detail</summary>
                  <div className="stack">
                    {item.sha256 ? <p className="break-word"><strong>Fingerprint:</strong> {item.sha256}</p> : null}
                    <p><strong>Current linked domains:</strong> {formatNumber(item.current_target_count || 0)}</p>
                    <p><strong>Historical linked domains:</strong> {formatNumber(item.historical_target_count || 0)}</p>
                  </div>
                </details>
              </LeadCard>
            ))}
          </div>
        ) : (
          <Callout tone="info">No shared certificates are stored for this scope yet.</Callout>
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
            <h1 className="brand-title">Seed-first investigation</h1>
            <p className="brand-subtitle">
              Profile the supplied domain or IP first, then fan outward only where the evidence creates a useful lead.
            </p>
          </div>
          <div className="topbar-actions">
            <div className="status-chip-row">
              {topbarChips.map((chip) => (
                <span className="status-chip" key={chip.label} title={chip.title || chip.value}>
                  <strong>{chip.value}</strong>
                  {chip.label}
                </span>
              ))}
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
              <span className="page-nav-label">Case</span>
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
            <span className="page-nav-label">Explorer</span>
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
