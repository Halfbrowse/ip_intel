import { useCallback, useEffect, useMemo, useState } from "react";
import { Badge, Button, Card, Text, TextField, ToggleButton, ToggleButtonGroup, View } from "reshaped";

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

// Long enough to collapse a burst of typing into one request, short enough
// that the grid still feels live. Matches the global search box.
const FILTER_DEBOUNCE_MS = 250;

export default function PoolPage() {
  const [filters, setFilters] = useState(DEFAULT_POOL_FILTERS);
  // The fields stay controlled by `filters` so typing is never laggy, but the
  // request is built from a debounced copy. Without this every keystroke in a
  // filter field issued its own /api/pool query — seven DB round trips to type
  // "example", each one evicting entries from the 50-slot response cache.
  const [queryFilters, setQueryFilters] = useState(DEFAULT_POOL_FILTERS);
  const [page, setPage] = useState(1);
  const pageSize = DEFAULT_PAGE_SIZE;

  useEffect(() => {
    const handle = window.setTimeout(() => setQueryFilters(filters), FILTER_DEBOUNCE_MS);
    return () => window.clearTimeout(handle);
  }, [filters]);

  const poolPath = useMemo(
    () => buildPoolQuery(queryFilters, page, pageSize),
    [queryFilters, page, pageSize],
  );
  // The only place a path change means "same resource, narrowed differently".
  // Everything else must blank on a path change; see useApi's keepPreviousData.
  const poolRequest = useApi(poolPath, { keepPreviousData: true });
  const domains = useMemo(() => normalizePool(poolRequest.data), [poolRequest.data]);
  const pageMeta = useMemo(
    () => getPoolPageMeta(poolRequest.data, domains.length, page, pageSize),
    [poolRequest.data, domains.length, page, pageSize],
  );
  const filtersActive = poolFiltersActive(filters);

  // Filters debounce but setPage(1) is immediate, so between the two the Next
  // button is enabled against the *previous* result's page count. Clicking it
  // inside that window requested a page the new filter set does not have, and
  // landed on a permanently empty grid. Snap back whenever the page overruns.
  useEffect(() => {
    if (pageMeta.pageCount && page > pageMeta.pageCount) {
      setPage(pageMeta.pageCount);
    }
  }, [page, pageMeta.pageCount]);

  const setFilter = useCallback((key, value) => {
    setPage(1);
    setFilters((current) => ({ ...current, [key]: value }));
  }, []);

  const clearFilters = useCallback(() => {
    setPage(1);
    setFilters(DEFAULT_POOL_FILTERS);
    // Explicit action, so skip the debounce and requery at once.
    setQueryFilters(DEFAULT_POOL_FILTERS);
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
          <View direction="row" gap={2}>
            {filtersActive ? (
              <Button onClick={clearFilters} variant="ghost">
                Clear filters
              </Button>
            ) : null}
            <Button onClick={poolRequest.refresh} variant="outline">
              Refresh
            </Button>
          </View>
        </div>

        {/* selectedColor defaults to "neutral", which this dark theme's
            navy-tinted neutral background renders as low-contrast
            navy-on-navy when selected -- champagne is the theme's one
            accent color and reads clearly as "this one's active". */}
        <ToggleButtonGroup
          onChange={({ value }) => setFilter("provenance", value[0] || "all")}
          selectedColor="primary"
          selectionMode="single"
          value={[filters.provenance]}
        >
          {PROVENANCE_FILTERS.map((entry) => (
            <ToggleButton key={entry.key} value={entry.key}>
              {entry.label}
            </ToggleButton>
          ))}
        </ToggleButtonGroup>

        <TextField
          inputAttributes={{ type: "search" }}
          name="pool-search"
          onChange={({ value }) => setFilter("search", value)}
          placeholder="Filter by domain"
          value={filters.search}
        />

        {/* direction is a plain "row" (not Reshaped's { s, m } breakpoint
            object) because that responsive form depends on Reshaped's
            "@media (--rs-viewport-m)" custom-media rules, which this
            project's build never resolves to real media queries (no
            postcss-custom-media in the pipeline) -- so the "m" breakpoint
            silently never applied and the row was permanently stuck in its
            "s" (column) fallback, full-width one field per line. Wrapping
            plain "row" plus the width caps in .pool-filter-field below gets
            the same "wrap into a grid" result without relying on a
            breakpoint that never fires. */}
        <View className="pool-filter-row" direction="row" gap={3} wrap>
          <TextField
            className="pool-filter-field"
            inputAttributes={{ type: "number", min: 0 }}
            name="min-connections"
            onChange={({ value }) => setFilter("minConnections", value)}
            placeholder="Min connections"
            value={filters.minConnections}
          />
          <TextField
            className="pool-filter-field"
            inputAttributes={{ type: "number", min: 0 }}
            name="max-connections"
            onChange={({ value }) => setFilter("maxConnections", value)}
            placeholder="Max connections"
            value={filters.maxConnections}
          />
          <TextField
            className="pool-filter-field"
            inputAttributes={{ type: "date" }}
            name="discovered-after"
            onChange={({ value }) => setFilter("discoveredAfter", value)}
            placeholder="Discovered after"
            value={filters.discoveredAfter}
          />
          <TextField
            className="pool-filter-field"
            inputAttributes={{ type: "date" }}
            name="discovered-before"
            onChange={({ value }) => setFilter("discoveredBefore", value)}
            placeholder="Discovered before"
            value={filters.discoveredBefore}
          />
          <TextField
            className="pool-filter-field"
            inputAttributes={{ type: "date" }}
            name="ingested-after"
            onChange={({ value }) => setFilter("ingestedAfter", value)}
            placeholder="Ingested after"
            value={filters.ingestedAfter}
          />
          <TextField
            className="pool-filter-field"
            inputAttributes={{ type: "date" }}
            name="ingested-before"
            onChange={({ value }) => setFilter("ingestedBefore", value)}
            placeholder="Ingested before"
            value={filters.ingestedBefore}
          />
          <label className="search-field pool-filter-field">
            <span>Sort</span>
            <select onChange={(event) => setFilter("sort", event.target.value)} value={filters.sort}>
              {POOL_SORTS.map((entry) => (
                <option key={entry.key} value={entry.key}>
                  {entry.label}
                </option>
              ))}
            </select>
          </label>
        </View>

        <View align="center" direction="row" gap={3} justify="space-between" wrap>
          <Text color="neutral-faded">
            Showing {pageMeta.start}-{pageMeta.end} of {pageMeta.total}
          </Text>
          <View align="center" direction="row" gap={2}>
            <Button
              disabled={page <= 1}
              onClick={() => setPage((current) => Math.max(1, current - 1))}
              size="small"
              variant="outline"
            >
              Previous
            </Button>
            <Badge color="neutral" variant="faded">
              Page {pageMeta.page} / {pageMeta.pageCount}
            </Badge>
            <Button
              disabled={page >= pageMeta.pageCount}
              onClick={() => setPage((current) => Math.min(pageMeta.pageCount, current + 1))}
              size="small"
              variant="outline"
            >
              Next
            </Button>
          </View>
        </View>

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
              <Card key={entry.domain} padding={4}>
                <View gap={3}>
                  <View align="center" direction="row" justify="space-between">
                    <ConnectionStat count={entry.connectionCount} />
                    <View align="center" direction="row" gap={1}>
                      {entry.clusterId ? (
                        <Badge color="neutral" variant="faded">
                          cluster {entry.clusterSize}
                        </Badge>
                      ) : null}
                      <ProvenanceBadge ingested={entry.ingested} />
                    </View>
                  </View>
                  <View align="center" direction="row" gap={2}>
                    <Text variant="body-1" weight="bold">
                      <Link className="card-title-link" to={`/domain/${encodeURIComponent(entry.domain)}`}>
                        {entry.domain}
                      </Link>
                    </Text>
                    {entry.tier ? <TierBadge tier={entry.tier} /> : null}
                  </View>
                  <div className="inline-metrics">
                    <InlineMetric label="Hosts" value={entry.hostCount ?? "-"} />
                    {/* Record of how often this channel has been scanned. Shown
                        because a domain on its fifth scan and one on its first
                        carry very different amounts of evidence, and nothing
                        else on this card distinguishes them. Informational
                        only -- scans are started from the backend. */}
                    <InlineMetric
                      label="Scans"
                      value={entry.scanCount ? `${entry.scanCount}` : "-"}
                    />
                    <InlineMetric label="Discovered" value={entry.discoveredAt ? formatDate(entry.discoveredAt) : "-"} />
                    <InlineMetric label="Ingested" value={entry.ingestedAt ? formatDate(entry.ingestedAt) : "-"} />
                    <InlineMetric label="Last scan" value={entry.lastScannedAt ? formatDate(entry.lastScannedAt) : "-"} />
                  </div>
                  {!entry.ingested && entry.discoveryKind ? (
                    <Text color="neutral-faded" variant="caption-1">
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
                    </Text>
                  ) : null}
                  <View direction="row" gap={3}>
                    {/* Link (not Button) -- these need the router's client-side
                        SPA navigation, which an <a href> rendered by Button
                        would bypass with a full page reload. */}
                    <Link className="primary-button" to={`/domain/${encodeURIComponent(entry.domain)}`}>
                      Open
                    </Link>
                    <Link className="text-link" onClick={() => rememberFocus(entry.domain)} to="/connections">
                      Connections
                    </Link>
                  </View>
                </View>
              </Card>
            ))}
          </div>
        ) : null}
      </section>
    </AppShell>
  );
}
