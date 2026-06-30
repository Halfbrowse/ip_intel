import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, NavLink, Route, Routes } from "./router.jsx";

import {
  fetchJson,
  formatDate,
  formatLabel,
  formatPercent,
  isTerminalStatus,
  normalizeConnectionPairs,
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

/* ============================================================== */
/* Routing                                                         */
/* ============================================================== */

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<PoolPage />} />
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
      {evidence.map((node) => (
        <li className="digest-item" key={node.id}>
          <span className="digest-item-label">
            {sharedNodeLabel(node.kind)}
            {node.attributing === false ? (
              <span className="chip digest-more-chip" style={{ marginLeft: 8 }}>
                noise
              </span>
            ) : null}
          </span>
          <span className="chip-row digest-item-values">
            <span className="chip evidence-chip" title={node.value}>
              {node.value}
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
          </span>
          <span className="card-copy" style={{ fontSize: "0.85em", opacity: 0.8 }}>
            {leftLabel || "A"}: {formatWindow(node.windowA)} · {rightLabel || "B"}: {formatWindow(node.windowB)}
            {node.sources?.length ? ` · via ${node.sources.join(", ")}` : " · source unknown"}
          </span>
        </li>
      ))}
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

function JobProgress({ jobId }) {
  const jobRequest = useApi(jobId ? `/api/jobs/${jobId}` : null, { pollInterval: 4000 });
  const job = useMemo(() => normalizeJob(jobRequest.data, jobId), [jobRequest.data, jobId]);
  if (!jobId) {
    return null;
  }
  const done = isTerminalStatus(job.status);
  return (
    <div className="callout">
      <div className="mini-progress-top">
        <span>Ingest job {jobId}</span>
        <strong>{formatPercent(job.percent ?? 0)}</strong>
      </div>
      <ProgressBar value={job.percent ?? 0} />
      <p className="card-copy">
        {done
          ? "Scan complete — the channels are in the pool. Refresh to see them and their connections."
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

      <label className="search-field">
        <span>Optional label (free-text tag, scopes nothing)</span>
        <input name="label" onChange={(event) => setLabel(event.target.value)} placeholder="e.g. campaign-x" type="text" value={label} />
      </label>

      <div className="submission-card">
        <div>
          <p className="eyebrow">OpenCTI website channels</p>
          <p className="section-copy">Add the domains from the 100 most recently created website-type channels.</p>
        </div>
        <button className="secondary-button" disabled={busy} onClick={ingestOpenCti} type="button">
          {busy ? "Submitting…" : "Ingest last 100 website channels"}
        </button>
      </div>

      {error ? <ErrorState message={error} /> : null}
      {jobId ? <JobProgress jobId={jobId} /> : null}
    </section>
  );
}

/* ============================================================== */
/* Pool page                                                      */
/* ============================================================== */

function PoolPage() {
  const poolRequest = useApi("/api/pool");
  const [search, setSearch] = useState("");
  const domains = useMemo(() => normalizePool(poolRequest.data), [poolRequest.data]);
  const clustered = useMemo(() => new Set(domains.filter((d) => d.clusterId).map((d) => d.clusterId)).size, [domains]);

  const query = search.trim().toLowerCase();
  const visible = useMemo(
    () => (query ? domains.filter((d) => d.domain.toLowerCase().includes(query)) : domains),
    [domains, query],
  );

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
            <p className="section-copy">Most recently scanned first.</p>
          </div>
          <button className="secondary-button" onClick={poolRequest.refresh} type="button">
            Refresh
          </button>
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

        {poolRequest.loading && !poolRequest.data ? <LoadingState message="Loading the pool…" /> : null}
        {poolRequest.error ? <ErrorState message={poolRequest.error} /> : null}
        {!poolRequest.loading && visible.length === 0 ? (
          <EmptyState message={domains.length === 0 ? "The pool is empty — ingest a domain to begin." : "No channels match the search."} />
        ) : null}

        {visible.length > 0 ? (
          <div className="case-grid">
            {visible.slice(0, 300).map((entry) => (
              <article className="case-card" key={entry.domain}>
                <div className="case-card-header">
                  <div>
                    <p className="eyebrow">Channel</p>
                    <h3>{entry.domain}</h3>
                  </div>
                  {entry.clusterId ? <span className="chip">cluster · {entry.clusterSize}</span> : null}
                </div>
                <div className="inline-metrics">
                  <InlineMetric label="Hosts" value={entry.hostCount ?? "—"} />
                  <InlineMetric label="Last seen" value={entry.lastSeen ? formatDate(entry.lastSeen) : "—"} />
                </div>
                <div className="action-row">
                  <Link className="primary-button" onClick={() => rememberFocus(entry.domain)} to="/connections">
                    View connections
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
        <ByEdgeExplorer onPickDomain={pickDomain} />
      )}
    </AppShell>
  );
}

function ByDomainExplorer({ selected, setSelected }) {
  const poolRequest = useApi("/api/pool");
  const pool = useMemo(() => normalizePool(poolRequest.data).map((entry) => entry.domain), [poolRequest.data]);

  const [filter, setFilter] = useState("");
  const [result, setResult] = useState(null);
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

  const run = useCallback(async () => {
    if (selected.length < 1) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const response = await fetch("/api/graph/connections", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ domains: selected, pool_links: true }),
      });
      const payload = await finishIngest(response);
      setResult(payload);
      setExpanded(null);
    } catch (err) {
      setError(err.message || "Couldn't load connections.");
    } finally {
      setBusy(false);
    }
  }, [selected]);

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
          {scoredCount >= 2 ? (
            <section className="panel section-stack">
              <div className="panel-header">
                <div>
                  <h2>
                    {result.connected_pair_count ?? pairs.filter((p) => p.connected).length} of {pairs.length}{" "}
                    pair{pairs.length === 1 ? "" : "s"} connected
                  </h2>
                  <p className="section-copy">Within your selection. Click a pair to see the shared certificates, IPs and other evidence.</p>
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
                  <p className="section-copy">The strongest links each selected channel has across everything you've scanned.</p>
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

function ByEdgeExplorer({ onPickDomain }) {
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
                  <h4 title={group.value}>{group.value}</h4>
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
                <Link
                  className="text-link"
                  onClick={() => rememberFocus(group.domains)}
                  to="/connections"
                >
                  Compare all {group.domains.length} →
                </Link>
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
        <EmptyState message="No clusters yet. Ingest channels, then recompute the graph." />
      ) : null}

      {clusters.length > 0 ? (
        <div className="cluster-grid">
          {clusters.map((cluster) => (
            <article className="cluster-card" key={cluster.id}>
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
              <div className="action-row">
                <Link
                  className="primary-button"
                  onClick={() => rememberFocus(cluster.members)}
                  to="/connections"
                >
                  Show connections
                </Link>
              </div>
            </article>
          ))}
        </div>
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
