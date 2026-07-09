import { useCallback, useMemo, useState } from "react";

import { formatDate, formatLabel, normalizePool, useApi } from "../api.js";
import { InlineMetric, EmptyState, ErrorState, LoadingState, MetricCard } from "../components/primitives.jsx";
import { ConnectionStat, ProvenanceBadge, TierBadge } from "../features/evidence.jsx";
import { rememberFocus } from "../features/focus.js";
import IngestPanel from "../features/ingest.jsx";
import { Link } from "../router.jsx";
import AppShell from "../shell/AppShell.jsx";
import {
  DEFAULT_PAGE_SIZE,
  DEFAULT_POOL_FILTERS,
  buildPoolQuery,
  getPoolPageMeta,
  poolFiltersActive,
} from "../utils/poolQuery.js";

const PROVENANCE_FILTERS = [
  { key: "all", label: "All channels" },
  { key: "ingested", label: "Ingested" },
  { key: "discovered", label: "Discovered" },
];

const POOL_SORTS = [
  { key: "recent", label: "Most recent" },
  { key: "connections", label: "Most connections" },
  { key: "domain", label: "Domain A-Z" },
];

export default function PoolPage() {
  const [filters, setFilters] = useState(DEFAULT_POOL_FILTERS);
  const [page, setPage] = useState(1);
  const pageSize = DEFAULT_PAGE_SIZE;
  const poolPath = useMemo(() => buildPoolQuery(filters, page, pageSize), [filters, page, pageSize]);
  const poolRequest = useApi(poolPath);
  const domains = useMemo(() => normalizePool(poolRequest.data), [poolRequest.data]);
  const pageMeta = useMemo(
    () => getPoolPageMeta(poolRequest.data, domains.length, page, pageSize),
    [poolRequest.data, domains.length, page, pageSize],
  );
  const filtersActive = poolFiltersActive(filters);

  const setFilter = useCallback((key, value) => {
    setPage(1);
    setFilters((current) => ({ ...current, [key]: value }));
  }, []);

  const clearFilters = useCallback(() => {
    setPage(1);
    setFilters(DEFAULT_POOL_FILTERS);
  }, []);

  const pageConnected = domains.filter((entry) => entry.connectionCount > 0).length;
  const pageIngested = domains.filter((entry) => entry.ingested).length;
  const pageClusters = new Set(domains.filter((entry) => entry.clusterId).map((entry) => entry.clusterId)).size;

  return (
    <AppShell>
      <section className="hero-panel">
        <div className="hero-copy">
          <h1>Channel pool</h1>
          <p>
            Every submitted or discovered channel, backed by append-only intel and the shared correlation graph.
          </p>
        </div>
        <div className="hero-stats">
          <MetricCard label="Matching channels" value={pageMeta.total} />
          <MetricCard label="Connected on page" value={pageConnected} />
          <MetricCard label="Ingested on page" value={pageIngested} />
          <MetricCard label="Clusters on page" value={pageClusters} />
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
              Sort and filter the shared pool without loading the whole corpus into the browser.
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

        <div className="chip-row" role="group" aria-label="Provenance filter">
          {PROVENANCE_FILTERS.map((entry) => (
            <button
              className={`chip ${filters.provenance === entry.key ? "evidence-chip" : ""}`}
              key={entry.key}
              onClick={() => setFilter("provenance", entry.key)}
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
            onChange={(event) => setFilter("search", event.target.value)}
            placeholder="Filter by domain"
            type="search"
            value={filters.search}
          />
        </label>

        <div className="filter-grid">
          <label className="search-field">
            <span>Min connections</span>
            <input
              min="0"
              onChange={(event) => setFilter("minConnections", event.target.value)}
              placeholder="0"
              type="number"
              value={filters.minConnections}
            />
          </label>
          <label className="search-field">
            <span>Max connections</span>
            <input
              min="0"
              onChange={(event) => setFilter("maxConnections", event.target.value)}
              placeholder="Any"
              type="number"
              value={filters.maxConnections}
            />
          </label>
          <label className="search-field">
            <span>Discovered after</span>
            <input
              onChange={(event) => setFilter("discoveredAfter", event.target.value)}
              type="date"
              value={filters.discoveredAfter}
            />
          </label>
          <label className="search-field">
            <span>Discovered before</span>
            <input
              onChange={(event) => setFilter("discoveredBefore", event.target.value)}
              type="date"
              value={filters.discoveredBefore}
            />
          </label>
          <label className="search-field">
            <span>Ingested after</span>
            <input
              onChange={(event) => setFilter("ingestedAfter", event.target.value)}
              type="date"
              value={filters.ingestedAfter}
            />
          </label>
          <label className="search-field">
            <span>Ingested before</span>
            <input
              onChange={(event) => setFilter("ingestedBefore", event.target.value)}
              type="date"
              value={filters.ingestedBefore}
            />
          </label>
          <label className="search-field">
            <span>Sort</span>
            <select onChange={(event) => setFilter("sort", event.target.value)} value={filters.sort}>
              {POOL_SORTS.map((entry) => (
                <option key={entry.key} value={entry.key}>
                  {entry.label}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="pager-row">
          <span className="muted">
            Showing {pageMeta.start}-{pageMeta.end} of {pageMeta.total}
          </span>
          <div className="action-row">
            <button
              className="secondary-button small"
              disabled={page <= 1}
              onClick={() => setPage((current) => Math.max(1, current - 1))}
              type="button"
            >
              Previous
            </button>
            <span className="chip">Page {pageMeta.page} / {pageMeta.pageCount}</span>
            <button
              className="secondary-button small"
              disabled={page >= pageMeta.pageCount}
              onClick={() => setPage((current) => Math.min(pageMeta.pageCount, current + 1))}
              type="button"
            >
              Next
            </button>
          </div>
        </div>

        {poolRequest.loading && !poolRequest.data ? <LoadingState message="Loading the pool..." /> : null}
        {poolRequest.error ? <ErrorState message={poolRequest.error} /> : null}
        {!poolRequest.loading && domains.length === 0 ? (
          <EmptyState
            message={pageMeta.total === 0 ? "The pool is empty. Ingest a domain to begin." : "No channels on this page."}
          />
        ) : null}

        {domains.length > 0 ? (
          <div className="pool-grid">
            {domains.map((entry) => (
              <article className="pool-card" key={entry.domain}>
                <div className="pool-card-header">
                  <ConnectionStat count={entry.connectionCount} />
                  <span className="chip-row" style={{ justifyContent: "flex-end" }}>
                    {entry.clusterId ? <span className="chip">cluster {entry.clusterSize}</span> : null}
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
                  <InlineMetric label="Hosts" value={entry.hostCount ?? "-"} />
                  <InlineMetric label="Discovered" value={entry.discoveredAt ? formatDate(entry.discoveredAt) : "-"} />
                  <InlineMetric label="Ingested" value={entry.ingestedAt ? formatDate(entry.ingestedAt) : "-"} />
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
