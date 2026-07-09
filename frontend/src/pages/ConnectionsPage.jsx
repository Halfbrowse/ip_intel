import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  normalizeConnectionPairs,
  normalizeConnectionsGraph,
  normalizeExplorerGraph,
  normalizeGraphLinks,
  normalizePool,
  normalizeSelectorGroups,
  normalizeSelectorKinds,
  useApi,
} from "../api.js";
import LazyClusterGraph from "../components/LazyClusterGraph.jsx";
import { EmptyState, ErrorState, LoadingState } from "../components/primitives.jsx";
import { ConnectionCard, FaviconThumb, sharedNodeLabel } from "../features/evidence.jsx";
import { takeFocus } from "../features/focus.js";
import { finishIngest } from "../features/ingest.jsx";
import { Link } from "../router.jsx";
import AppShell from "../shell/AppShell.jsx";

const EXPANSION_MAX_DOMAINS = 30;

export default function ConnectionsPage() {
  const [mode, setMode] = useState("domains");
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

function ByDomainExplorer({ selected, setSelected }) {
  const poolRequest = useApi("/api/pool?limit=5000&sort=domain");
  const pool = useMemo(() => normalizePool(poolRequest.data).map((entry) => entry.domain), [poolRequest.data]);
  const [filter, setFilter] = useState("");
  const [result, setResult] = useState(null);
  const [seedDomains, setSeedDomains] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState(null);
  const autoRanRef = useRef(false);

  const toggleDomain = useCallback((domain) => {
    setSelected((current) =>
      current.includes(domain) ? current.filter((entry) => entry !== domain) : [...current, domain],
    );
  }, [setSelected]);

  const suggestions = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) {
      return [];
    }
    return pool.filter((domain) => domain.toLowerCase().includes(needle) && !selected.includes(domain)).slice(0, 10);
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
      setError(err.message || "Could not load connections.");
    } finally {
      setBusy(false);
    }
  }, [selected, fetchConnections]);

  useEffect(() => {
    if (!autoRanRef.current && selected.length >= 1 && !result && !busy) {
      autoRanRef.current = true;
      run();
    }
  }, [selected, result, busy, run]);

  const pairs = useMemo(() => normalizeConnectionPairs(result), [result]);
  const explorerGraph = useMemo(() => normalizeExplorerGraph(result), [result]);
  const explorerSeeds = useMemo(() => new Set(seedDomains), [seedDomains]);
  const scoredCount = (result?.domains || []).length;
  const toggleExpanded = useCallback((key) => {
    setExpanded((current) => (current === key ? null : key));
  }, []);

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
                  <span aria-hidden="true" className="token-x">x</span>
                </button>
              ))
            )}
          </div>
          <button className="primary-button" disabled={busy || selected.length < 1} onClick={run} type="button">
            {busy ? "Working..." : "Show connections"}
          </button>
        </div>

        <div className="autocomplete">
          <input
            className="autocomplete-input"
            onChange={(event) => setFilter(event.target.value)}
            placeholder="Type a domain to add..."
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
        {poolRequest.error ? <ErrorState message={poolRequest.error} /> : null}
        {error ? <ErrorState message={error} /> : null}
      </section>

      {busy && !result ? <LoadingState message="Scoring connections..." /> : null}

      {result ? (
        <>
          {explorerGraph.nodes.length > 0 ? (
            <LazyClusterGraph
              description="A map of selected channels and the related channels surfaced by shared infrastructure or registration evidence."
              exportFileName="domain-network"
              graph={explorerGraph}
              otherRoleColor="#64748b"
              otherRoleLabel="Other domain"
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
                    {result.connected_pair_count ?? pairs.filter((pair) => pair.connected).length} of {pairs.length} pair
                    {pairs.length === 1 ? "" : "s"} connected
                  </h2>
                  <p className="section-copy">Click a pair to inspect the shared selectors, IPs, and supporting context.</p>
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
                  <p className="section-copy">The strongest links each channel has across the shared corpus.</p>
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
  const toggle = useCallback((key) => setExpanded((current) => (current === key ? null : key)), []);

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
          <p className="section-copy">Pick a kind of evidence to see connected channel groups.</p>
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
            {entry.groups !== null ? ` - ${entry.groups}` : ""}
          </button>
        ))}
      </div>

      {kindsRequest.error ? <ErrorState message={kindsRequest.error} /> : null}
      {groupsRequest.loading && !groupsRequest.data ? <LoadingState message="Loading shared-edge groups..." /> : null}
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
                <button className="text-link" onClick={() => onPickAll(group.domains)} type="button">
                  Compare all {group.domains.length}
                </button>
              </div>
            </article>
          ))}
        </div>
      ) : null}
    </section>
  );
}
