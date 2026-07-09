import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Link, NavLink, Route, Routes, useParams } from "./router.jsx";

import {
  fetchJson,
  formatDate,
  formatLabel,
  formatNumber,
  formatPercent,
  isTerminalStatus,
  normalizeConnectionPairs,
  normalizeConnectionsGraph,
  normalizeExplorerGraph,
  normalizeGraphClusters,
  normalizeGraphLinks,
  normalizeJob,
  normalizePool,
  normalizeSelectorGroups,
  normalizeSelectorKinds,
  useApi,
} from "./api.js";
import {
  EmptyState,
  ErrorState,
  InlineMetric,
  LoadingState,
  MetricCard,
  ProgressBar,
} from "./components/primitives.jsx";
import ClusterGraph from "./components/ClusterGraph.jsx";

/* ============================================================== */
/* Routing                                                         */
/* ============================================================== */

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<PoolPage />} />
      <Route path="/domain/:value" element={<DomainPage />} />
      <Route path="/connections" element={<ConnectionsPage />} />
      <Route path="/clusters" element={<ClustersPage />} />
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}

/* ============================================================== */
/* Shell + theme                                                  */
/* ============================================================== */

const THEME_STORAGE_KEY = "theme";

export function getInitialTheme() {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === "light" || stored === "dark") {
      return stored;
    }
  } catch {
    // Ignore storage errors and fall back to the system preference.
  }
  return window.matchMedia?.("(prefers-color-scheme: dark)")?.matches ? "dark" : "light";
}

function useTheme() {
  const [theme, setTheme] = useState(getInitialTheme);
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);
  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, next);
    } catch {
      // Best-effort persistence.
    }
    setTheme(next);
  };
  return { theme, toggleTheme };
}

const NAV_ITEMS = [
  { to: "/", label: "Pool" },
  { to: "/connections", label: "Connections" },
  { to: "/clusters", label: "Clusters" },
];

function AppShell({ children }) {
  const { theme, toggleTheme } = useTheme();
  return (
    <div className="app-shell">
      <header className="app-header">
        <Link className="brand-mark" to="/">
          <span>IP</span>
          <strong>Intel</strong>
        </Link>
        <nav className="case-nav" aria-label="Sections">
          {NAV_ITEMS.map((item) => (
            <NavLink
              className={({ isActive }) => (isActive ? "case-nav-link active" : "case-nav-link")}
              key={item.to}
              to={item.to}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="header-side">
          <button
            aria-pressed={theme === "dark"}
            className="secondary-button theme-toggle"
            onClick={toggleTheme}
            title={theme === "dark" ? "Switch to the light theme" : "Switch to the dark theme"}
            type="button"
          >
            <span aria-hidden="true" className="theme-toggle-indicator" />
            {theme === "dark" ? "Light mode" : "Dark mode"}
          </button>
        </div>
      </header>
      <main className="app-main">{children}</main>
    </div>
  );
}

/* ============================================================== */
/* Shared evidence rendering                                      */
/* ============================================================== */

const STRENGTH_TIERS = {
  strong: { tier: "strong", label: "Strong link", tone: "success" },
  moderate: { tier: "moderate", label: "Moderate link", tone: "warning" },
  weak: { tier: "weak", label: "Weak link", tone: "neutral" },
};

function linkStrength(link) {
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

function sharedNodeLabel(kind) {
  return SELECTOR_KIND_LABELS[kind] || formatLabel(kind);
}

// What kind of box a shared IP is — badge tone + label for the "cdn / pool /
// origin" classification the backend computes (utils/check.describe_ip_network).
const IP_NETWORK_BADGES = {
  cdn: { label: "CDN / proxy edge", tone: "neutral" },
  pool: { label: "Shared hosting pool", tone: "warning" },
  origin: { label: "Likely origin server", tone: "success" },
};

function ipNetworkBadge(network) {
  return IP_NETWORK_BADGES[network] || null;
}

// OpenCTI tier-1..tier-5 domain classification (durable, keyed on the
// registrable domain — see db.intel_db.domain_tiers). Same hot-to-cool
// palette as ClusterGraph.jsx's node colouring, so a domain reads the same
// way here and on the network map. Unrelated to STRENGTH_TIERS above (that's
// link strength, this is a per-domain attribute).
const DOMAIN_TIER_COLORS = {
  1: "#b91c1c",
  2: "#ea580c",
  3: "#ca8a04",
  4: "#2563eb",
  5: "#64748b",
};

function TierBadge({ tier }) {
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

// "<provider>|<id>"-shaped selector values (tracking_id, site_verification,
// social_handle) carry a `subkind` — fold it into the label ("Site
// verification code · Google") and strip it back off the displayed value so
// the chip shows just the code/handle, not the raw stored key.
function sharedNodeDisplay(node) {
  const label = node.subkind ? `${sharedNodeLabel(node.kind)} · ${formatLabel(node.subkind)}` : sharedNodeLabel(node.kind);
  const prefix = node.subkind ? `${node.subkind}|` : null;
  const value = prefix && node.value.startsWith(prefix) ? node.value.slice(prefix.length) : node.value;
  return { label, value };
}

// We never store favicon bytes, only the hash, so there's nothing to render
// straight from data — this hits /api/favicon/<kind>/<value>, which the
// backend serves by re-fetching the icon live from a domain that shares the
// hash (see cases/case_app.py:api_favicon_image). Silently renders nothing if
// that 404s (hash predates any live match) so the raw hash text next to it
// remains the fallback.
const FAVICON_KINDS = new Set(["favicon_mmh3", "favicon_md5"]);

const FaviconThumb = memo(function FaviconThumb({ kind, value }) {
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

// When a shared node was actually exhibited by a subdomain rather than the
// apex being compared (transitive, subdomain-mediated linkage), surface which
// host(s) — instead of silently implying the apex itself carried the evidence.
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
    return <EmptyState message="No shared attributing nodes — the connection is unsupported." />;
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
                <span className="chip" title="base × rarity × time-overlap">
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
                <span className="chip" title="RDAP network name — often reveals a CDN/hosting brand degree alone won't">
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

// A collapsible card for a single connection (a -> target, or a <-> b).
const ConnectionCard = memo(function ConnectionCard({ link, expanded, onToggle, leftLabel, rightLabel }) {
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

/* ============================================================== */
/* Ingestion                                                      */
/* ============================================================== */

async function postIngest({ file, target, label }) {
  if (file) {
    const formData = new FormData();
    formData.append("file", file);
    if (label) {
      formData.append("label", label);
    }
    const response = await fetch("/api/ingest", { method: "POST", body: formData, headers: { Accept: "application/json" } });
    return finishIngest(response);
  }
  const response = await fetch("/api/ingest", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ target, label }),
  });
  return finishIngest(response);
}

async function finishIngest(response) {
  const text = await response.text();
  let payload = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = text;
  }
  if (!response.ok) {
    const message =
      (payload && typeof payload === "object" && (payload.detail || payload.message || payload.error)) ||
      (typeof payload === "string" ? payload : null) ||
      `Ingest failed with status ${response.status}.`;
    throw new Error(message);
  }
  return payload;
}

function JobProgress({ jobId, onComplete }) {
  const jobRequest = useApi(jobId ? `/api/jobs/${jobId}` : null, { pollInterval: 4000 });
  const job = useMemo(() => normalizeJob(jobRequest.data, jobId), [jobRequest.data, jobId]);
  const done = isTerminalStatus(job.status);
  // Fires once per job: as soon as the poll sees a terminal status, pull the
  // newly-ingested channels into the pool without the user clicking Refresh.
  const notifiedRef = useRef(null);
  useEffect(() => {
    if (done && jobId && notifiedRef.current !== jobId) {
      notifiedRef.current = jobId;
      onComplete?.();
    }
  }, [done, jobId, onComplete]);

  if (!jobId) {
    return null;
  }
  return (
    <div className="callout">
      <div className="mini-progress-top">
        <span>Ingest job {jobId}</span>
        <strong>{formatPercent(job.percent ?? 0)}</strong>
      </div>
      <ProgressBar value={job.percent ?? 0} />
      <p className="card-copy">
        {done
          ? "Scan complete — the channels are in the pool."
          : job.summary || job.currentStep || "Scanning… results join the pool as they finish."}
      </p>
    </div>
  );
}

function IngestPanel({ onIngested }) {
  const [targetInput, setTargetInput] = useState("");
  const [label, setLabel] = useState("");
  const [csvFile, setCsvFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [jobId, setJobId] = useState(null);

  const run = async (args) => {
    setBusy(true);
    setError(null);
    try {
      const payload = await postIngest({ ...args, label: label.trim() || undefined });
      setJobId(payload?.job_id || payload?.job?.id || null);
      onIngested?.();
    } catch (err) {
      setError(err.message || "Ingest failed.");
    } finally {
      setBusy(false);
    }
  };

  const ingestOpenCti = async () => {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch("/api/ingest/opencti-website", { method: "POST", headers: { Accept: "application/json" } });
      const payload = await finishIngest(response);
      setJobId(payload?.job_id || payload?.job?.id || null);
      onIngested?.();
    } catch (err) {
      setError(err.message || "OpenCTI ingest failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel section-stack">
      <div className="panel-header">
        <div>
          <p className="eyebrow">Add to the pool</p>
          <h2>Ingest channels</h2>
          <p className="section-copy">
            Scan one domain or IP, or upload a CSV (first column). Everything joins one shared pool —
            there are no cases.
          </p>
        </div>
      </div>

      <div className="submission-grid">
        <div className="submission-card">
          <label className="search-field">
            <span>Single domain or IP</span>
            <input
              name="target"
              onChange={(event) => setTargetInput(event.target.value)}
              placeholder="example.com or 203.0.113.10"
              type="text"
              value={targetInput}
            />
          </label>
          <button
            className="primary-button"
            disabled={busy || !targetInput.trim()}
            onClick={() => run({ target: targetInput.trim() })}
            type="button"
          >
            {busy ? "Submitting…" : "Scan & add to pool"}
          </button>
        </div>

        <div className="submission-card">
          <label className="search-field file-field">
            <span>CSV upload</span>
            <input accept=".csv,text/csv" onChange={(event) => setCsvFile(event.target.files?.[0] || null)} type="file" />
          </label>
          <button className="primary-button" disabled={busy || !csvFile} onClick={() => run({ file: csvFile })} type="button">
            {busy ? "Submitting…" : "Upload CSV"}
          </button>
        </div>
      </div>

      {/* <label className="search-field">
        <span>Optional label (free-text tag, scopes nothing)</span>
        <input name="label" onChange={(event) => setLabel(event.target.value)} placeholder="e.g. campaign-x" type="text" value={label} />
      </label> */}

      {/* <div className="submission-card">
        <div>
          <p className="eyebrow">OpenCTI website channels</p>
          <p className="section-copy">Add the domains from the 100 most recently created website-type channels.</p>
        </div>
        <button className="secondary-button" disabled={busy} onClick={ingestOpenCti} type="button">
          {busy ? "Submitting…" : "Ingest last 100 website channels"}
        </button>
      </div> */}

      {error ? <ErrorState message={error} /> : null}
      {jobId ? <JobProgress jobId={jobId} onComplete={onIngested} /> : null}
    </section>
  );
}

/* ============================================================== */
/* Pool page                                                      */
/* ============================================================== */

// How a channel entered the pool: directly submitted by a user/OpenCTI/CSV
// ingest ("ingested"), or only ever surfaced by following a scan — subdomain
// enumeration, sibling-domain discovery, or a wordlist hit ("discovered").
const PROVENANCE_FILTERS = [
  { key: "all", label: "All" },
  { key: "ingested", label: "Ingested" },
  { key: "discovered", label: "Discovered" },
];

const POOL_SORTS = [
  { key: "recent", label: "Most recent" },
  { key: "connections", label: "Most connections" },
];

function ProvenanceBadge({ ingested }) {
  return (
    <span className={`status-badge compact ${ingested ? "success" : "info"}`} title={
      ingested
        ? "Directly submitted (or a subdomain of it was)"
        : "Never submitted directly — only surfaced by following a scan (subdomain, sibling, or wordlist discovery)"
    }>
      {ingested ? "Ingested" : "Discovered"}
    </span>
  );
}

// The date-only (YYYY-MM-DD) prefix of an ISO timestamp, so it can be compared
// against <input type="date"> values without pulling in a date library.
function dateOnly(value) {
  return value ? String(value).slice(0, 10) : null;
}

// The number of channels this one directly connects to — pair-to-pair evidence
// links only. This is deliberately not cluster size: a cluster is the wider
// transitive group those connections chain into, shown on its own page.
function ConnectionStat({ count }) {
  return (
    <div className="connection-stat">
      <strong>{formatNumber(count)}</strong>
      <span>{count === 1 ? "connection" : "connections"}</span>
    </div>
  );
}

function PoolPage() {
  const poolRequest = useApi("/api/pool");
  const [search, setSearch] = useState("");
  const [provenance, setProvenance] = useState("all");
  const [sort, setSort] = useState("recent");
  const [minConnections, setMinConnections] = useState("");
  const [maxConnections, setMaxConnections] = useState("");
  const [discoveredAfter, setDiscoveredAfter] = useState("");
  const [discoveredBefore, setDiscoveredBefore] = useState("");
  const [ingestedAfter, setIngestedAfter] = useState("");
  const [ingestedBefore, setIngestedBefore] = useState("");

  const domains = useMemo(() => normalizePool(poolRequest.data), [poolRequest.data]);
  const clustered = useMemo(() => new Set(domains.filter((d) => d.clusterId).map((d) => d.clusterId)).size, [domains]);
  const ingestedCount = useMemo(() => domains.filter((d) => d.ingested).length, [domains]);
  const connectedCount = useMemo(() => domains.filter((d) => d.connectionCount > 0).length, [domains]);

  const query = search.trim().toLowerCase();
  const minConn = minConnections === "" ? null : Number(minConnections);
  const maxConn = maxConnections === "" ? null : Number(maxConnections);

  // Whether any filter differs from its default — used to show/hide the
  // "Clear filters" action so it isn't cluttering the panel on a fresh visit.
  const filtersActive =
    Boolean(search) ||
    provenance !== "all" ||
    sort !== "recent" ||
    Boolean(minConnections) ||
    Boolean(maxConnections) ||
    Boolean(discoveredAfter) ||
    Boolean(discoveredBefore) ||
    Boolean(ingestedAfter) ||
    Boolean(ingestedBefore);

  const clearFilters = useCallback(() => {
    setSearch("");
    setProvenance("all");
    setSort("recent");
    setMinConnections("");
    setMaxConnections("");
    setDiscoveredAfter("");
    setDiscoveredBefore("");
    setIngestedAfter("");
    setIngestedBefore("");
  }, []);

  const visible = useMemo(() => {
    const filtered = domains
      .filter((d) => !query || d.domain.toLowerCase().includes(query))
      .filter((d) => provenance === "all" || (provenance === "ingested" ? d.ingested : !d.ingested))
      .filter((d) => minConn === null || d.connectionCount >= minConn)
      .filter((d) => maxConn === null || d.connectionCount <= maxConn)
      .filter((d) => !discoveredAfter || (dateOnly(d.discoveredAt) ?? "") >= discoveredAfter)
      .filter((d) => !discoveredBefore || (dateOnly(d.discoveredAt) ?? "9999-99-99") <= discoveredBefore)
      .filter((d) => !ingestedAfter || (dateOnly(d.ingestedAt) ?? "") >= ingestedAfter)
      .filter((d) => !ingestedBefore || (dateOnly(d.ingestedAt) ?? "9999-99-99") <= ingestedBefore);

    return sort === "connections"
      ? [...filtered].sort((a, b) => b.connectionCount - a.connectionCount)
      : filtered;
  }, [
    domains, query, provenance, sort, minConn, maxConn,
    discoveredAfter, discoveredBefore, ingestedAfter, ingestedBefore,
  ]);

  return (
    <AppShell>
      <section className="hero-panel">
        <div className="hero-copy">
          <h1>Channel pool</h1>
          <p>
            Everything you've scanned, in one place. Open a channel to see what it's connected to, or
            select several and compare them.
          </p>
        </div>
        <div className="hero-stats">
          <MetricCard label="Channels" value={domains.length} />
          <MetricCard label="Connected" value={connectedCount} />
          <MetricCard label="Ingested" value={ingestedCount} />
          <MetricCard label="Clusters" value={clustered} />
          <Link className="primary-button" to="/connections">
            Compare channels
          </Link>
        </div>
      </section>

      <IngestPanel onIngested={poolRequest.refresh} />

      <section className="panel section-stack">
        <div className="panel-header">
          <div>
            <h2>Channels</h2>
            <p className="section-copy">
              Led by <strong>connections</strong> — how many other channels each one directly shares
              attributing evidence with (a cert, IP, nameserver, tracking ID...). The wider transitive
              groups those connections chain into are on the{" "}
              <Link className="text-link" to="/clusters">clusters page</Link>.
            </p>
          </div>
          <div className="action-row">
            {filtersActive ? (
              <button className="text-link" onClick={clearFilters} type="button">
                Clear filters
              </button>
            ) : null}
            <button className="secondary-button" onClick={poolRequest.refresh} type="button">
              Refresh
            </button>
          </div>
        </div>

        <div className="chip-row">
          {PROVENANCE_FILTERS.map((entry) => (
            <button
              className={`chip ${provenance === entry.key ? "evidence-chip" : ""}`}
              key={entry.key}
              onClick={() => setProvenance(entry.key)}
              type="button"
            >
              {entry.label}
            </button>
          ))}
        </div>

        <label className="search-field">
          <span>Search channels</span>
          <input
            name="pool-search"
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Filter by domain"
            type="search"
            value={search}
          />
        </label>

        <div className="filter-grid">
          <label className="search-field">
            <span>Min connections</span>
            <input
              min="0"
              onChange={(event) => setMinConnections(event.target.value)}
              placeholder="0"
              type="number"
              value={minConnections}
            />
          </label>
          <label className="search-field">
            <span>Max connections</span>
            <input
              min="0"
              onChange={(event) => setMaxConnections(event.target.value)}
              placeholder="Any"
              type="number"
              value={maxConnections}
            />
          </label>
          <label className="search-field">
            <span>Discovered after</span>
            <input onChange={(event) => setDiscoveredAfter(event.target.value)} type="date" value={discoveredAfter} />
          </label>
          <label className="search-field">
            <span>Discovered before</span>
            <input onChange={(event) => setDiscoveredBefore(event.target.value)} type="date" value={discoveredBefore} />
          </label>
          <label className="search-field">
            <span>Ingested after</span>
            <input onChange={(event) => setIngestedAfter(event.target.value)} type="date" value={ingestedAfter} />
          </label>
          <label className="search-field">
            <span>Ingested before</span>
            <input onChange={(event) => setIngestedBefore(event.target.value)} type="date" value={ingestedBefore} />
          </label>
          <label className="search-field">
            <span>Sort</span>
            <select onChange={(event) => setSort(event.target.value)} value={sort}>
              {POOL_SORTS.map((entry) => (
                <option key={entry.key} value={entry.key}>
                  {entry.label}
                </option>
              ))}
            </select>
          </label>
        </div>

        {poolRequest.loading && !poolRequest.data ? <LoadingState message="Loading the pool…" /> : null}
        {poolRequest.error ? <ErrorState message={poolRequest.error} /> : null}
        {!poolRequest.loading && visible.length === 0 ? (
          <EmptyState message={domains.length === 0 ? "The pool is empty — ingest a domain to begin." : "No channels match the filters."} />
        ) : null}

        {visible.length > 0 ? (
          <div className="case-grid">
            {visible.slice(0, 300).map((entry) => (
              <article className="case-card" key={entry.domain}>
                <div className="case-card-header">
                  <ConnectionStat count={entry.connectionCount} />
                  <span className="chip-row" style={{ justifyContent: "flex-end" }}>
                    {entry.clusterId ? <span className="chip">cluster · {entry.clusterSize}</span> : null}
                    <ProvenanceBadge ingested={entry.ingested} />
                  </span>
                </div>
                <h3>
                  <Link className="card-title-link" to={`/domain/${encodeURIComponent(entry.domain)}`}>
                    {entry.domain}
                  </Link>
                  {entry.tier ? <TierBadge tier={entry.tier} /> : null}
                </h3>
                <div className="inline-metrics">
                  <InlineMetric label="Hosts" value={entry.hostCount ?? "—"} />
                  <InlineMetric label="Discovered" value={entry.discoveredAt ? formatDate(entry.discoveredAt) : "—"} />
                  <InlineMetric label="Ingested" value={entry.ingestedAt ? formatDate(entry.ingestedAt) : "—"} />
                </div>
                {!entry.ingested && entry.discoveryKind ? (
                  <p className="card-copy discovery-note">
                    Found via {formatLabel(entry.discoveryKind)}
                    {entry.discoveredFrom ? (
                      <>
                        {" from "}
                        <Link className="text-link" to={`/domain/${encodeURIComponent(entry.discoveredFrom)}`}>
                          {entry.discoveredFrom}
                        </Link>
                      </>
                    ) : null}
                    {entry.discoveryReason ? ` (${entry.discoveryReason})` : ""}.
                  </p>
                ) : null}
                <div className="action-row">
                  <Link className="primary-button" to={`/domain/${encodeURIComponent(entry.domain)}`}>
                    Open
                  </Link>
                  <Link className="text-link" onClick={() => rememberFocus(entry.domain)} to="/connections">
                    Connections
                  </Link>
                </div>
              </article>
            ))}
          </div>
        ) : null}
      </section>
    </AppShell>
  );
}

/* ============================================================== */
/* Connections page                                               */
/* ============================================================== */

// The custom router stores the full path (incl. any ?query) as the pathname, so
// query strings break route matching. We hand a set of channels between pages
// through sessionStorage instead and navigate to the bare /connections path.
const FOCUS_KEY = "ipintel.focus";

function rememberFocus(domains) {
  const list = Array.isArray(domains) ? domains : [domains];
  try {
    window.sessionStorage.setItem(FOCUS_KEY, JSON.stringify(list.filter(Boolean)));
  } catch {
    // Best-effort; navigation still works without a pre-selected channel.
  }
}

function takeFocus() {
  try {
    const raw = window.sessionStorage.getItem(FOCUS_KEY);
    if (raw) {
      window.sessionStorage.removeItem(FOCUS_KEY);
    }
    if (!raw) {
      return [];
    }
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter(Boolean) : [String(parsed)];
  } catch {
    return [];
  }
}

function ConnectionsPage() {
  const [mode, setMode] = useState("domains");
  // Selection is owned here so the by-edge view can add a channel and hand off
  // to the by-domain view without a route change (same-path navigation is a
  // no-op in this router). The cross-page selection arrives via sessionStorage.
  const [selected, setSelected] = useState(() => takeFocus());

  const pickDomain = useCallback((domain) => {
    setSelected((current) => (current.includes(domain) ? current : [...current, domain]));
    setMode("domains");
  }, []);

  const pickDomains = useCallback((domains) => {
    setSelected((current) => {
      const merged = [...current];
      domains.forEach((domain) => {
        if (domain && !merged.includes(domain)) {
          merged.push(domain);
        }
      });
      return merged;
    });
    setMode("domains");
  }, []);

  return (
    <AppShell>
      <div className="breadcrumb-row">
        <Link className="text-link" to="/">
          Pool
        </Link>
        <span>/</span>
        <span>Connections</span>
      </div>

      <div className="page-heading">
        <h1>Connections</h1>
        <p>Compare a set of channels, or browse by the evidence that links them.</p>
      </div>

      <nav className="segmented" aria-label="Connection modes">
        <button
          className={mode === "domains" ? "segmented-item active" : "segmented-item"}
          onClick={() => setMode("domains")}
          type="button"
        >
          Compare channels
        </button>
        <button
          className={mode === "edges" ? "segmented-item active" : "segmented-item"}
          onClick={() => setMode("edges")}
          type="button"
        >
          Browse by shared edge
        </button>
      </nav>

      {mode === "domains" ? (
        <ByDomainExplorer selected={selected} setSelected={setSelected} />
      ) : (
        <ByEdgeExplorer onPickAll={pickDomains} onPickDomain={pickDomain} />
      )}
    </AppShell>
  );
}

// Cap on how many domains the one-hop expansion (see run() below) will send
// back to /api/graph/connections in its second round-trip — matches the
// server's own connections_among(max_domains=30) so the cap is never a
// surprise, just applied earlier so the user's own picks are never the ones
// dropped when a pick has a lot of pool links.
const EXPANSION_MAX_DOMAINS = 30;

function ByDomainExplorer({ selected, setSelected }) {
  const poolRequest = useApi("/api/pool");
  const pool = useMemo(() => normalizePool(poolRequest.data).map((entry) => entry.domain), [poolRequest.data]);

  const [filter, setFilter] = useState("");
  const [result, setResult] = useState(null);
  // The user's own picks, resolved to registrable-domain form by the first
  // round-trip — kept separate from `result.domains` because that list grows
  // to include whatever the expansion round pulled in, and ClusterGraph
  // needs to know which nodes are actual seeds vs. discovered along the way.
  const [seedDomains, setSeedDomains] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState(null);
  const autoRanRef = useRef(false);

  const toggleDomain = useCallback((domain) => {
    setSelected((current) =>
      current.includes(domain) ? current.filter((d) => d !== domain) : [...current, domain],
    );
  }, [setSelected]);

  // Type-to-add: only show matches while typing, capped — never a wall of domains.
  const suggestions = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) {
      return [];
    }
    return pool.filter((d) => d.toLowerCase().includes(needle) && !selected.includes(d)).slice(0, 10);
  }, [pool, filter, selected]);

  const fetchConnections = useCallback(async (domains) => {
    const response = await fetch("/api/graph/connections", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ domains, pool_links: true }),
    });
    return finishIngest(response);
  }, []);

  const run = useCallback(async () => {
    if (selected.length < 1) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const first = await fetchConnections(selected);
      const seedList = first.domains || [];
      setSeedDomains(seedList);

      // One-hop expansion: rescoring just the picks only ever shows "pick ->
      // pool link", never whether those pool links relate to each other or
      // pull in yet more domains. Re-run the same scoring over picks + every
      // domain any of them linked to, so the map and the pair/pool-link lists
      // below all show that fuller picture in one go.
      const seedSet = new Set(seedList);
      const relatedTargets = new Set();
      Object.values(first.pool_links || {}).forEach((rawLinks) => {
        normalizeGraphLinks({ links: rawLinks }).forEach((link) => {
          if (link.target && !seedSet.has(link.target)) {
            relatedTargets.add(link.target);
          }
        });
      });

      let finalResult = first;
      if (relatedTargets.size > 0) {
        const expandedDomains = [...seedList, ...relatedTargets].slice(0, EXPANSION_MAX_DOMAINS);
        finalResult = await fetchConnections(expandedDomains);
      }

      setResult(finalResult);
      setExpanded(null);
    } catch (err) {
      setError(err.message || "Couldn't load connections.");
    } finally {
      setBusy(false);
    }
  }, [selected, fetchConnections]);

  // Arriving with channels already chosen (from the Pool or a cluster) shows
  // their connections straight away — no extra click.
  useEffect(() => {
    if (!autoRanRef.current && selected.length >= 1 && !result && !busy) {
      autoRanRef.current = true;
      run();
    }
  }, [selected, result, busy, run]);

  const pairs = useMemo(() => normalizeConnectionPairs(result), [result]);
  const toggleExpanded = useCallback((key) => {
    setExpanded((current) => (current === key ? null : key));
  }, []);
  const scoredCount = (result?.domains || []).length;
  const explorerGraph = useMemo(() => normalizeExplorerGraph(result), [result]);
  const explorerSeeds = useMemo(() => new Set(seedDomains), [seedDomains]);

  return (
    <>
      <section className="panel selection-bar">
        <div className="selection-row">
          <div className="selection-chips">
            {selected.length === 0 ? (
              <span className="muted">Add channels to compare, or open one from the Pool.</span>
            ) : (
              selected.map((domain) => (
                <button className="token" key={domain} onClick={() => toggleDomain(domain)} title="Remove" type="button">
                  {domain}
                  <span aria-hidden="true" className="token-x">×</span>
                </button>
              ))
            )}
          </div>
          <button className="primary-button" disabled={busy || selected.length < 1} onClick={run} type="button">
            {busy ? "Working…" : "Show connections"}
          </button>
        </div>

        <div className="autocomplete">
          <input
            className="autocomplete-input"
            onChange={(event) => setFilter(event.target.value)}
            placeholder="Type a domain to add…"
            type="search"
            value={filter}
          />
          {suggestions.length > 0 ? (
            <div className="autocomplete-menu">
              {suggestions.map((domain) => (
                <button
                  className="autocomplete-option"
                  key={domain}
                  onClick={() => {
                    toggleDomain(domain);
                    setFilter("");
                  }}
                  type="button"
                >
                  {domain}
                </button>
              ))}
            </div>
          ) : null}
        </div>
        {error ? <ErrorState message={error} /> : null}
      </section>

      {busy && !result ? <LoadingState message="Scoring connections…" /> : null}

      {result ? (
        <>
          {explorerGraph.nodes.length > 0 ? (
            <ClusterGraph
              description={
                "A shareable map of how your selected domains connect — to each other and to other " +
                "domains that share hosting or registration evidence. Drag to rearrange, scroll to " +
                "zoom, click a domain or line for details. \"Download image\" saves a static picture; " +
                "\"Download interactive report\" saves a clickable version anyone can open in a " +
                "browser, no account needed; \"Email graph\" sends both to the configured recipients."
              }
              exportFileName="domain-network"
              graph={explorerGraph}
              otherRoleColor="#64748b"
              otherRoleLabel="Other domain (not selected)"
              seedRoleLabel="Selected domain"
              seedTargets={explorerSeeds}
              title="Network map"
            />
          ) : null}

          {scoredCount >= 2 ? (
            <section className="panel section-stack">
              <div className="panel-header">
                <div>
                  <h2>
                    {result.connected_pair_count ?? pairs.filter((p) => p.connected).length} of {pairs.length}{" "}
                    pair{pairs.length === 1 ? "" : "s"} connected
                  </h2>
                  <p className="section-copy">
                    Among your picks and the domains they're linked to elsewhere in the pool — so you can
                    see whether those domains are related to each other too, not just back to your picks.
                    Click a pair to see the shared certificates, IPs and other evidence.
                  </p>
                </div>
              </div>
              {pairs.length === 0 ? (
                <EmptyState message="These channels share no attributing evidence with each other." />
              ) : (
                <div className="linkage-list">
                  {pairs.map((pair) => (
                    <ConnectionCard
                      expanded={expanded === (pair.b ?? pair.target)}
                      key={`${pair.a}|${pair.b}`}
                      leftLabel={pair.a}
                      link={pair}
                      onToggle={toggleExpanded}
                      rightLabel={pair.b}
                    />
                  ))}
                </div>
              )}
            </section>
          ) : null}

          {result.pool_links ? (
            <section className="panel section-stack">
              <div className="panel-header">
                <div>
                  <h2>Connections to the rest of the pool</h2>
                  <p className="section-copy">
                    The strongest links each channel above has across everything you've scanned — your
                    own picks and the domains pulled in because they linked to one of your picks, so this
                    also surfaces a further ring of domains beyond your original selection.
                  </p>
                </div>
              </div>
              <PoolLinksPanel poolLinks={result.pool_links} />
            </section>
          ) : null}
        </>
      ) : null}
    </>
  );
}

function PoolLinksPanel({ poolLinks }) {
  const entries = useMemo(() => Object.entries(poolLinks || {}), [poolLinks]);
  const [expanded, setExpanded] = useState(null);
  const toggle = useCallback((key) => setExpanded((c) => (c === key ? null : key)), []);
  if (entries.length === 0) {
    return null;
  }
  return (
    <div className="section-stack">
      {entries.map(([domain, rawLinks]) => {
        const links = normalizeGraphLinks({ links: rawLinks });
        return (
          <div className="section-stack tight" key={domain}>
            <div className="group-heading">
              <h4>{domain}</h4>
              <span>{links.length} pool link{links.length === 1 ? "" : "s"}</span>
            </div>
            {links.length === 0 ? (
              <EmptyState message="No attributing connections to the wider pool." />
            ) : (
              <div className="linkage-list">
                {links.slice(0, 8).map((link) => (
                  <ConnectionCard
                    expanded={expanded === `${domain}|${link.target}`}
                    key={`${domain}|${link.target}`}
                    leftLabel={domain}
                    link={link}
                    onToggle={() => toggle(`${domain}|${link.target}`)}
                    rightLabel={link.target}
                  />
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function ByEdgeExplorer({ onPickAll, onPickDomain }) {
  const kindsRequest = useApi("/api/graph/selector-kinds");
  const kinds = useMemo(() => normalizeSelectorKinds(kindsRequest.data), [kindsRequest.data]);
  const [kind, setKind] = useState("");

  const path = kind ? `/api/graph/by-selector?kind=${encodeURIComponent(kind)}` : "/api/graph/by-selector";
  const groupsRequest = useApi(path);
  const groups = useMemo(() => normalizeSelectorGroups(groupsRequest.data), [groupsRequest.data]);

  return (
    <section className="panel section-stack">
      <div className="panel-header">
        <div>
          <h2>Channels that share an edge</h2>
          <p className="section-copy">
            Pick a kind of evidence — TLS certificate, SSH key, IP, nameserver, tracking ID — to see the
            groups of channels connected by it.
          </p>
        </div>
        <button className="secondary-button" onClick={groupsRequest.refresh} type="button">
          Refresh
        </button>
      </div>

      <div className="chip-row">
        <button className={`chip ${kind === "" ? "evidence-chip" : ""}`} onClick={() => setKind("")} type="button">
          All edges
        </button>
        {kinds.map((entry) => (
          <button
            className={`chip ${kind === entry.kind ? "evidence-chip" : ""}`}
            key={entry.kind}
            onClick={() => setKind(entry.kind)}
            type="button"
          >
            {sharedNodeLabel(entry.kind)}
            {entry.groups !== null ? ` · ${entry.groups}` : ""}
          </button>
        ))}
      </div>

      {groupsRequest.loading && !groupsRequest.data ? <LoadingState message="Loading shared-edge groups…" /> : null}
      {groupsRequest.error ? <ErrorState message={groupsRequest.error} /> : null}
      {!groupsRequest.loading && groups.length === 0 ? (
        <EmptyState message="No cross-channel groups for this edge type yet." />
      ) : null}

      {groups.length > 0 ? (
        <div className="cluster-grid">
          {groups.map((group) => (
            <article className="cluster-card" key={group.id}>
              <div className="cluster-card-top">
                <div>
                  <span className="muted">{sharedNodeLabel(group.kind)}</span>
                  <div className="card-heading-row">
                    <FaviconThumb kind={group.kind} value={group.value} />
                    <h4 title={group.value}>{group.value}</h4>
                  </div>
                </div>
                <strong title="Channels sharing this edge">{group.degree ?? group.domains.length}</strong>
              </div>
              <div className="chip-row">
                {group.domains.slice(0, 12).map((domain) => (
                  <button
                    className="chip"
                    key={`${group.id}-${domain}`}
                    onClick={() => onPickDomain(domain)}
                    title="Add to the comparison"
                    type="button"
                  >
                    {domain}
                  </button>
                ))}
                {group.domains.length > 12 ? (
                  <span className="chip digest-more-chip">+{group.domains.length - 12} more</span>
                ) : null}
              </div>
              <div className="action-row">
                <button
                  className="text-link"
                  onClick={() => onPickAll(group.domains)}
                  type="button"
                >
                  Compare all {group.domains.length} →
                </button>
              </div>
            </article>
          ))}
        </div>
      ) : null}
    </section>
  );
}

/* ============================================================== */
/* Clusters page                                                  */
/* ============================================================== */

function ClustersPage() {
  const clustersRequest = useApi("/api/graph/clusters");
  const clusters = useMemo(() => normalizeGraphClusters(clustersRequest.data), [clustersRequest.data]);
  const [recomputing, setRecomputing] = useState(false);
  const [recomputeMsg, setRecomputeMsg] = useState(null);

  const recompute = async () => {
    setRecomputing(true);
    setRecomputeMsg(null);
    try {
      const payload = await fetchJson("/api/graph/recompute").catch(async () => {
        const response = await fetch("/api/graph/recompute", { method: "POST", headers: { Accept: "application/json" } });
        return finishIngest(response);
      });
      setRecomputeMsg(`Rebuilt: ${payload?.clusters ?? 0} clusters, ${payload?.entities ?? "?"} entities.`);
      clustersRequest.refresh();
    } catch (err) {
      setRecomputeMsg(err.message || "Recompute failed.");
    } finally {
      setRecomputing(false);
    }
  };

  return (
    <AppShell>
      <div className="breadcrumb-row">
        <Link className="text-link" to="/">
          Pool
        </Link>
        <span>/</span>
        <span>Clusters</span>
      </div>

      <div className="page-heading">
        <div className="page-heading-row">
          <div>
            <h1>Clusters</h1>
            <p>Groups of channels that connect to each other through shared infrastructure.</p>
          </div>
          <div className="action-row">
            <button className="secondary-button" onClick={clustersRequest.refresh} type="button">
              Refresh
            </button>
            <button className="secondary-button" disabled={recomputing} onClick={recompute} type="button">
              {recomputing ? "Recomputing…" : "Recompute graph"}
            </button>
          </div>
        </div>
        {recomputeMsg ? <div className="callout"><p>{recomputeMsg}</p></div> : null}
      </div>

      {clustersRequest.loading && !clustersRequest.data ? <LoadingState message="Loading clusters…" /> : null}
      {clustersRequest.error ? <ErrorState message={clustersRequest.error} /> : null}
      {!clustersRequest.loading && clusters.length === 0 ? (
        <EmptyState message="No clusters yet. Ingest channels — clusters build up automatically in the background." />
      ) : null}

      {clusters.length > 0 ? (
        <div className="cluster-grid">
          {clusters.map((cluster) => (
            <ClusterCard cluster={cluster} key={cluster.id} />
          ))}
        </div>
      ) : null}
    </AppShell>
  );
}

function ClusterCard({ cluster }) {
  const [modalOpen, setModalOpen] = useState(false);
  const [graphState, setGraphState] = useState({ loading: false, error: null, data: null });

  const loadGraph = useCallback(async () => {
    setGraphState({ loading: true, error: null, data: null });
    try {
      const response = await fetch("/api/graph/connections", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ domains: cluster.members, pool_links: false }),
      });
      const payload = await finishIngest(response);
      setGraphState({ loading: false, error: null, data: payload });
    } catch (err) {
      setGraphState({ loading: false, error: err.message || "Couldn't load the network graph.", data: null });
    }
  }, [cluster.members]);

  const openGraph = useCallback(() => {
    setModalOpen(true);
    if (!graphState.data && !graphState.loading) {
      loadGraph();
    }
  }, [graphState.data, graphState.loading, loadGraph]);

  const closeGraph = useCallback(() => setModalOpen(false), []);

  const scoredDomains = graphState.data?.domains;
  const graph = useMemo(
    () => (graphState.data ? normalizeConnectionsGraph(graphState.data, scoredDomains || cluster.members) : null),
    [graphState.data, scoredDomains, cluster.members],
  );
  const seedTargets = useMemo(() => new Set(cluster.members), [cluster.members]);
  const truncated = Array.isArray(scoredDomains) && scoredDomains.length < cluster.members.length;

  return (
    <article className="cluster-card">
      <div className="cluster-card-top">
        <div>
          <span className="muted">Cluster</span>
          <h4>{cluster.id}</h4>
        </div>
        <strong title="Channels in this cluster">{cluster.size}</strong>
      </div>
      <div className="chip-row">
        {cluster.members.slice(0, 12).map((member) => (
          <span className="chip" key={`${cluster.id}-${member}`}>
            {member}
          </span>
        ))}
        {cluster.members.length > 12 ? (
          <span className="chip digest-more-chip">+{cluster.members.length - 12} more</span>
        ) : null}
      </div>
      {cluster.links.length > 0 ? (
        <div className="cluster-links">
          <span className="muted">Connected by</span>
          <div className="chip-row">
            {cluster.links.map((link) => (
              <span
                className="chip connector-chip"
                key={`${cluster.id}-${link.kind}-${link.value}`}
                title={`${sharedNodeLabel(link.kind)}: ${link.value}`}
              >
                <FaviconThumb kind={link.kind} value={link.value} />
                {sharedNodeLabel(link.kind)}
                <span className="connector-value">{link.value}</span>
                {link.memberCount ? <span className="connector-count">×{link.memberCount}</span> : null}
              </span>
            ))}
            {cluster.linkCount > cluster.links.length ? (
              <span className="chip digest-more-chip">
                +{cluster.linkCount - cluster.links.length} more
              </span>
            ) : null}
          </div>
        </div>
      ) : null}
      <div className="action-row">
        <button className="secondary-button" onClick={openGraph} type="button">
          View network graph
        </button>
        <Link className="primary-button" onClick={() => rememberFocus(cluster.members)} to="/connections">
          Show connections
        </Link>
      </div>
      {modalOpen ? (
        <GraphModal onClose={closeGraph} title={`Cluster ${cluster.id}`}>
          {graphState.loading ? <LoadingState message="Scoring connections…" /> : null}
          {graphState.error ? <ErrorState message={graphState.error} /> : null}
          {truncated ? (
            <p className="muted">
              Showing the first {scoredDomains.length} of {cluster.members.length} channels.
            </p>
          ) : null}
          {graph ? <ClusterGraph graph={graph} seedTargets={seedTargets} /> : null}
        </GraphModal>
      ) : null}
    </article>
  );
}

// Rendered via a portal straight onto <body> — a cluster card can sit inside
// a backdrop-filter'd panel, which (like a CSS filter/transform) creates its
// own containing block for `position: fixed` descendants. Left in place, a
// fixed-position modal would anchor to that card instead of the viewport and
// show up clipped to whichever card happened to be clicked, not centered on
// screen. The portal renders outside that subtree so it's never at the mercy
// of an ancestor's layout, and always opens the same way regardless of which
// cluster card (or where in the grid) triggered it.
function GraphModal({ title, onClose, children }) {
  useEffect(() => {
    const onKeyDown = (event) => {
      if (event.key === "Escape") {
        onClose();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  return createPortal(
    <div className="graph-modal-backdrop" onClick={onClose}>
      <div
        aria-label={title}
        aria-modal="true"
        className="graph-modal"
        onClick={(event) => event.stopPropagation()}
        role="dialog"
      >
        <div className="graph-modal-head">
          <strong>{title}</strong>
          <button className="secondary-button small" onClick={onClose} type="button">
            Close
          </button>
        </div>
        <div className="graph-modal-body">{children}</div>
      </div>
    </div>,
    document.body,
  );
}

/* ============================================================== */
/* Domain detail page                                             */
/* ============================================================== */

function asText(value) {
  if (value === null || value === undefined || value === "") {
    return "—";
  }
  if (Array.isArray(value)) {
    return value.map(asText).join(", ");
  }
  if (typeof value === "object") {
    return value.value || value.exchange || value.name || JSON.stringify(value);
  }
  return String(value);
}

function DefRow({ label, children }) {
  return (
    <div className="def-row">
      <span className="def-label">{label}</span>
      <span className="def-value">{children}</span>
    </div>
  );
}

function DomainPage() {
  const { value } = useParams();
  const profileRequest = useApi(`/api/domain/${encodeURIComponent(value)}`);
  const linksRequest = useApi(`/api/graph/links/${encodeURIComponent(value)}`);
  const profile = profileRequest.data;
  const links = useMemo(() => normalizeGraphLinks(linksRequest.data), [linksRequest.data]);
  const [expanded, setExpanded] = useState(null);
  const toggle = useCallback((key) => setExpanded((c) => (c === key ? null : key)), []);

  const selectorsByKind = useMemo(() => {
    const map = new Map();
    for (const sel of profile?.selectors || []) {
      if (!map.has(sel.kind)) {
        map.set(sel.kind, []);
      }
      map.get(sel.kind).push(sel);
    }
    return [...map.entries()];
  }, [profile]);

  const intel = profile?.intel || null;
  const dnsEntries = Object.entries(intel?.dns || {}).filter(([, v]) => v && (!Array.isArray(v) || v.length));
  const whoisEntries = Object.entries(intel?.whois || {}).filter(([k, v]) => v && k !== "error" && k !== "raw");
  const trackingEntries = Object.entries(intel?.tracking || {});
  const socialHandleEntries = Object.entries(intel?.social_handles || {}).filter(([, v]) => v && v.length);
  const socialLinkEntries = Object.entries(intel?.social_links || {}).filter(([, v]) => v && v.length);
  const siteVerificationEntries = Object.entries(intel?.site_verifications || {}).filter(([, v]) => v && v.length);
  const otherHosts = (profile?.hosts || []).filter((host) => host.value !== profile?.domain);

  return (
    <AppShell>
      <div className="breadcrumb-row">
        <Link className="text-link" to="/">
          Pool
        </Link>
        <span>/</span>
        <span>{value}</span>
      </div>

      <div className="page-heading">
        <div className="page-heading-row">
          <div>
            <h1>
              {value}
              {profile ? (
                <span style={{ marginLeft: 10, verticalAlign: "middle" }}>
                  <ProvenanceBadge ingested={profile.ingested} />
                  {profile.tier ? <TierBadge tier={profile.tier} /> : null}
                </span>
              ) : null}
            </h1>
            <p>
              {profile
                ? `${profile.host_count || 0} host${profile.host_count === 1 ? "" : "s"} · ${(profile.ips || []).length} IP${(profile.ips || []).length === 1 ? "" : "s"} · ${links.length} connection${links.length === 1 ? "" : "s"}`
                : "Everything gathered on this channel."}
            </p>
            {profile && !profile.ingested && intel?.discovery_kind ? (
              <p className="card-copy" style={{ fontSize: "0.85em" }}>
                Never submitted directly — found via {formatLabel(intel.discovery_kind)}
                {intel.discovered_from ? ` from ${intel.discovered_from}` : ""}
                {intel.discovery_reason ? ` (${intel.discovery_reason})` : ""}.
              </p>
            ) : null}
            {(intel?.opencti_labels || []).length > 0 ? (
              <span className="chip-row" style={{ marginTop: 6 }}>
                {intel.opencti_labels.map((label) => (
                  <span className="chip evidence-chip" key={label} title="OpenCTI label">
                    {label}
                  </span>
                ))}
              </span>
            ) : null}
          </div>
          <Link className="primary-button" onClick={() => rememberFocus(value)} to="/connections">
            Compare with others
          </Link>
        </div>
      </div>

      {profileRequest.loading && !profile ? <LoadingState message="Loading channel…" /> : null}
      {profileRequest.error ? <ErrorState message={profileRequest.error} /> : null}

      {profile ? (
        <>
          {/* Connections (may be empty — the page still shows everything below) */}
          <section className="panel section-stack">
            <div className="panel-header">
              <div>
                <h2>Connections</h2>
                <p className="section-copy">
                  {links.length === 0 ? "No connections to other channels yet." : "Other channels this one is linked to."}
                </p>
              </div>
            </div>
            {links.length === 0 ? (
              <EmptyState message="Nothing in the pool shares attributing evidence with this channel." />
            ) : (
              <div className="linkage-list">
                {links.slice(0, 25).map((link) => (
                  <ConnectionCard
                    expanded={expanded === link.target}
                    key={link.target}
                    leftLabel={value}
                    link={link}
                    onToggle={() => toggle(link.target)}
                    rightLabel={link.target}
                  />
                ))}
              </div>
            )}
          </section>

          {/* What we extracted (the observables) */}
          <section className="panel section-stack">
            <div className="panel-header">
              <div>
                <h2>What we found</h2>
                <p className="section-copy">The observables extracted from this channel. A degree above 1 means it's shared.</p>
              </div>
            </div>
            {selectorsByKind.length === 0 ? (
              <EmptyState message="No selectors extracted yet." />
            ) : (
              selectorsByKind.map(([kind, items]) => (
                <div className="section-stack tight" key={kind}>
                  <div className="group-heading">
                    <h4>{sharedNodeLabel(kind)}</h4>
                    <span>{items.length}</span>
                  </div>
                  <div className="chip-row">
                    {items.slice(0, 30).map((sel) => (
                      <span className={`chip ${sel.degree > 1 ? "evidence-chip" : ""}`} key={sel.value} title={`shared by ${sel.degree}`}>
                        <FaviconThumb kind={kind} value={sel.value} />
                        {sel.value}
                        {sel.degree > 1 ? ` · ${sel.degree}` : ""}
                      </span>
                    ))}
                  </div>
                </div>
              ))
            )}
          </section>

          {/* Raw gathered intel */}
          <section className="panel section-stack">
            <div className="panel-header">
              <div>
                <h2>Gathered intel</h2>
                <p className="section-copy">
                  {intel?.timestamp ? `From the latest scan (${formatDate(intel.timestamp)}).` : "From the latest scan."}
                </p>
              </div>
            </div>

            {(profile.ips || []).length > 0 ? (
              <div className="section-stack tight">
                <h4>IPs ({profile.ips.length})</h4>
                {profile.ips.map((entry) => {
                  const badge = ipNetworkBadge(entry.network);
                  const context = [entry.asn_desc, entry.network_name, entry.proxy_family, entry.country]
                    .filter(Boolean)
                    .join(" · ");
                  return (
                    <DefRow key={entry.ip} label={entry.ip}>
                      <span className="chip-row" style={{ marginBottom: context ? 4 : 0 }}>
                        {badge ? <span className={`status-badge compact ${badge.tone}`}>{badge.label}</span> : null}
                        {entry.degree > 1 ? (
                          <span className="chip" title="Other domains on this IP">
                            {entry.degree} domains
                          </span>
                        ) : null}
                      </span>
                      {context ? (
                        <span className="card-copy" style={{ fontSize: "0.85em", opacity: 0.85, display: "block" }}>
                          {context}
                        </span>
                      ) : null}
                    </DefRow>
                  );
                })}
              </div>
            ) : null}

            {dnsEntries.length > 0 ? (
              <div className="section-stack tight">
                <h4>DNS</h4>
                {dnsEntries.map(([rtype, values]) => (
                  <DefRow key={rtype} label={rtype}>
                    {asText(values)}
                  </DefRow>
                ))}
              </div>
            ) : null}

            {whoisEntries.length > 0 ? (
              <div className="section-stack tight">
                <h4>WHOIS</h4>
                {whoisEntries.map(([k, v]) => (
                  <DefRow key={k} label={formatLabel(k)}>
                    {asText(v)}
                  </DefRow>
                ))}
              </div>
            ) : null}

            {(intel?.tls_certs || []).length > 0 ? (
              <div className="section-stack tight">
                <h4>TLS certificates</h4>
                {intel.tls_certs.map((cert, index) => (
                  <DefRow key={`${cert.sha256}-${index}`} label={cert.cn || cert.ip || `cert ${index + 1}`}>
                    {[cert.issuer, cert.sha256 ? `sha256 ${String(cert.sha256).slice(0, 16)}…` : null, (cert.sans || []).join(", ")]
                      .filter(Boolean)
                      .join(" · ")}
                  </DefRow>
                ))}
              </div>
            ) : null}

            {trackingEntries.length > 0 ? (
              <div className="section-stack tight">
                <h4>Tracking & analytics</h4>
                {trackingEntries.map(([k, v]) => (
                  <DefRow key={k} label={formatLabel(k)}>
                    {asText(v)}
                  </DefRow>
                ))}
              </div>
            ) : null}

            {siteVerificationEntries.length > 0 || socialHandleEntries.length > 0 || socialLinkEntries.length > 0 ? (
              <div className="section-stack tight">
                <h4>Social & verification</h4>
                {siteVerificationEntries.map(([provider, codes]) => (
                  <DefRow key={`verify-${provider}`} label={`${formatLabel(provider)} verification`}>
                    {asText(codes)}
                  </DefRow>
                ))}
                {socialHandleEntries.map(([platform, handles]) => (
                  <DefRow key={`handle-${platform}`} label={formatLabel(platform)}>
                    {asText(handles)}
                  </DefRow>
                ))}
                {socialLinkEntries.map(([platform, urls]) => (
                  <DefRow key={`link-${platform}`} label={`${formatLabel(platform)} link`}>
                    {asText(urls)}
                  </DefRow>
                ))}
              </div>
            ) : null}

            {!intel ? <EmptyState message="No raw scan stored for this channel yet." /> : null}
          </section>

          {/* Hosts under this apex — subdomains, each with what it resolves to */}
          <section className="panel section-stack">
            <div className="panel-header">
              <div>
                <h2>Hosts</h2>
                <p className="section-copy">
                  {otherHosts.length === 0
                    ? "No subdomains discovered for this channel yet."
                    : `${otherHosts.length} subdomain${otherHosts.length === 1 ? "" : "s"} discovered, each linking to its own detail page.`}
                </p>
              </div>
            </div>
            {otherHosts.length === 0 ? (
              <EmptyState message="Nothing beyond the apex domain on record." />
            ) : (
              <div className="linkage-list">
                {otherHosts.slice(0, 60).map((host) => (
                  <div className="def-row" key={host.value}>
                    <span className="def-label">
                      <Link className="text-link" to={`/domain/${encodeURIComponent(host.value)}`}>
                        {host.value}
                      </Link>
                    </span>
                    <span className="def-value">
                      <span className="chip-row">
                        <span
                          className="status-badge compact info"
                          title="A subdomain discovered while investigating this channel — not a separate direct submission"
                        >
                          Found subdomain
                        </span>
                        {(host.ips || []).length > 0 ? (
                          host.ips.map((ip) => (
                            <span className="chip" key={ip}>
                              {ip}
                            </span>
                          ))
                        ) : (
                          <span className="muted">no resolved IP on record</span>
                        )}
                      </span>
                      {host.discovery_kind ? (
                        <span className="card-copy" style={{ fontSize: "0.8em", opacity: 0.8, display: "block" }}>
                          via {formatLabel(host.discovery_kind)}
                          {host.discovered_from ? ` from ${host.discovered_from}` : ""}
                        </span>
                      ) : null}
                    </span>
                  </div>
                ))}
                {otherHosts.length > 60 ? (
                  <span className="chip digest-more-chip">+{otherHosts.length - 60} more</span>
                ) : null}
              </div>
            )}
          </section>
        </>
      ) : null}
    </AppShell>
  );
}

function NotFoundPage() {
  return (
    <AppShell>
      <section className="panel section-stack">
        <div className="panel-header">
          <div>
            <p className="eyebrow">404</p>
            <h1>Page not found</h1>
          </div>
        </div>
        <p className="section-copy">This page does not exist.</p>
        <div className="action-row">
          <Link className="primary-button" to="/">
            Back to the pool
          </Link>
        </div>
      </section>
    </AppShell>
  );
}
