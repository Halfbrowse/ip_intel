import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Autocomplete, Badge, Button, Card, Tabs, Text, View } from "reshaped";

import {
  fetchJson,
  normalizeConnectionPairs,
  normalizeExplorerGraph,
  normalizeGraphLinks,
  normalizePool,
  normalizeRelatedThrough,
  normalizeSelectorGroups,
  normalizeSelectorKinds,
  useApi,
} from "../api.js";
import LazyClusterGraph from "../components/LazyClusterGraph.jsx";
import { EmptyState, ErrorState, LoadingState } from "../components/primitives.jsx";
import { ConnectionCard, FaviconThumb, sharedNodeLabel } from "../features/evidence.jsx";
import { downloadReportCsv, downloadReportJson, printReport } from "../features/exportReport.js";
import { subscribeFocus, takeFocus } from "../features/focus.js";
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

  // Picks made while this page is already mounted (the global search box
  // selecting a selector from /connections itself) never remount it, so the
  // takeFocus() above would not see them. Subscribing keeps the initial read
  // and the live case on one path.
  useEffect(
    () =>
      subscribeFocus((domains) => {
        takeFocus();
        pickDomains(domains);
      }),
    [pickDomains],
  );

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

      {/* Tabs has no color prop -- the "pills" variant's selected-pill fill is
          hardcoded to the neutral token, which we've retinted to a navy that
          reads as low-contrast navy-on-navy in dark mode (see .pills-accent
          override in styles.css, which repaints it champagne instead). */}
      <Tabs onChange={({ value }) => setMode(value)} value={mode} variant="pills">
        <Tabs.List className="pills-accent">
          <Tabs.Item value="domains">Compare channels</Tabs.Item>
          <Tabs.Item value="edges">Browse by shared edge</Tabs.Item>
        </Tabs.List>
      </Tabs>

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
  // Map<seedDomain, relatedThroughEntries[]> from the precomputed multi-hop
  // lookup below -- kept around (not just used to pick expansion targets) so
  // the graph can draw a dashed "inferred" edge for a pair the scorer found
  // no direct evidence for, instead of silently dropping it.
  const [relatedChains, setRelatedChains] = useState(new Map());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  // Non-fatal: the run produced a result, but part of the expansion is missing.
  const [partialWarning, setPartialWarning] = useState(null);
  const [expanded, setExpanded] = useState(null);
  // See DomainPage: a blocked popup must not fail silently.
  const [printBlocked, setPrintBlocked] = useState(false);
  const autoRanRef = useRef(false);
  const runAbortRef = useRef(null);

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

  const fetchConnections = useCallback(async (domains, signal) => {
    // Scoring runs live server-side, so it gets the shared timeout and is
    // abortable — navigating away previously left the run holding a worker.
    return fetchJson("/api/graph/connections", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domains, pool_links: true }),
      signal,
    });
  }, []);

  // Each selected domain's precomputed multi-hop neighborhood (graph_paths,
  // via /api/graph/related/{value}) -- an instant indexed read, not a live
  // scoring pass -- used to pull in everything reachable through an
  // intermediary before scoring the expanded set as a whole.
  const fetchRelated = useCallback(async (domain, signal) => {
    try {
      return {
        entries: normalizeRelatedThrough(
          await fetchJson(`/api/graph/related/${encodeURIComponent(domain)}`, { signal }),
        ),
        failed: false,
      };
    } catch (err) {
      // A domain with no precomputed neighbourhood is the common case and not
      // worth failing the run over — but a 500 or a timeout is a *failure to
      // answer*, and swallowing both alike silently drops that domain's
      // multi-hop expansion from the graph and the exported report with
      // nothing on screen to say so. Report the second kind.
      return { entries: [], failed: err?.status !== 404 };
    }
  }, []);

  const run = useCallback(async () => {
    if (selected.length < 1) {
      return;
    }
    // One controller for the whole run, aborted on unmount (see the effect
    // below) so an abandoned scoring pass stops instead of finishing into a
    // component that no longer exists.
    runAbortRef.current?.abort();
    const controller = new AbortController();
    runAbortRef.current = controller;
    const { signal } = controller;

    setBusy(true);
    setError(null);
    setPartialWarning(null);
    try {
      const seedSet = new Set(selected);
      const relatedLists = await Promise.all(selected.map((domain) => fetchRelated(domain, signal)));
      const relatedTargets = new Set();
      const chainMap = new Map();
      const expansionFailures = [];
      selected.forEach((domain, index) => {
        const { entries, failed } = relatedLists[index];
        if (failed) {
          expansionFailures.push(domain);
        }
        chainMap.set(domain, entries);
        entries.forEach((entry) => {
          if (entry.target && !seedSet.has(entry.target)) {
            relatedTargets.add(entry.target);
          }
        });
      });
      setRelatedChains(chainMap);
      setPartialWarning(
        expansionFailures.length > 0
          ? `Could not load the multi-hop neighbourhood for ${expansionFailures.join(", ")}. ` +
            `Channels reachable only through those are missing from this view.`
          : null,
      );

      const expandedDomains =
        relatedTargets.size > 0
          ? [...selected, ...relatedTargets].slice(0, EXPANSION_MAX_DOMAINS)
          : selected;
      const finalResult = await fetchConnections(expandedDomains, signal);
      // seedDomains marks the true anchors (what the user picked) vs. domains
      // only pulled in via the multi-hop expansion above -- intersect against
      // the canonical resolved names finalResult returns, since the raw
      // `selected` values may not exactly match (case, resolution) what the
      // backend resolved them to.
      const resolvedSeeds = (finalResult.domains || []).filter((domain) => seedSet.has(domain));
      setSeedDomains(resolvedSeeds.length > 0 ? resolvedSeeds : selected);
      setResult(finalResult);
      setExpanded(null);
    } catch (err) {
      if (signal.aborted) {
        return;
      }
      setError(err.message || "Could not load connections.");
    } finally {
      if (runAbortRef.current === controller) {
        runAbortRef.current = null;
        setBusy(false);
      }
    }
  }, [selected, fetchConnections, fetchRelated]);

  useEffect(() => () => runAbortRef.current?.abort(), []);

  useEffect(() => {
    if (!autoRanRef.current && selected.length >= 1 && !result && !busy) {
      autoRanRef.current = true;
      run();
    }
  }, [selected, result, busy, run]);

  const pairs = useMemo(() => normalizeConnectionPairs(result), [result]);
  const explorerGraph = useMemo(() => normalizeExplorerGraph(result, relatedChains), [result, relatedChains]);
  const explorerSeeds = useMemo(() => new Set(seedDomains), [seedDomains]);
  const scoredCount = (result?.domains || []).length;
  const toggleExpanded = useCallback((key) => {
    setExpanded((current) => (current === key ? null : key));
  }, []);

  // Not a graph artifact, not a persisted/shared link -- a point-in-time
  // report/data dump of exactly what's on screen (direct pairs + any
  // multi-hop chains), for handing to someone who doesn't need to open the
  // tool or for loading into another analysis pipeline.
  const exportScope = useMemo(() => {
    const chains = [];
    relatedChains.forEach((entries, seed) => {
      (entries || [])
        .filter((entry) => entry.hops > 1)
        .forEach((entry) => chains.push({ a: seed, b: entry.target, hops: entry.hops, chain: entry.chain }));
    });
    return {
      title: "Channel connection report",
      domains: result?.domains || selected,
      pairs,
      chains,
    };
  }, [result, selected, pairs, relatedChains]);

  return (
    <>
      <section className="panel selection-bar">
        <View align="center" direction="row" gap={3} justify="space-between" wrap>
          <View direction="row" gap={2} wrap>
            {selected.length === 0 ? (
              <Text color="neutral-faded">Add channels to compare, or open one from the Pool.</Text>
            ) : (
              selected.map((domain) => (
                <Badge
                  color="primary"
                  dismissAriaLabel={`Remove ${domain}`}
                  key={domain}
                  onDismiss={() => toggleDomain(domain)}
                  variant="faded"
                >
                  {domain}
                </Badge>
              ))
            )}
          </View>
          <Button color="primary" disabled={busy || selected.length < 1} loading={busy} onClick={run}>
            {busy ? "Working..." : "Show connections"}
          </Button>
        </View>

        <Autocomplete
          className="global-search"
          name="connections-domain-picker"
          onChange={({ value }) => setFilter(value)}
          onItemSelect={({ value }) => {
            toggleDomain(value);
            setFilter("");
          }}
          placeholder="Type a domain to add..."
          value={filter}
        >
          {suggestions.map((domain) => (
            <Autocomplete.Item key={domain} value={domain}>
              {domain}
            </Autocomplete.Item>
          ))}
        </Autocomplete>
        {poolRequest.error ? <ErrorState message={poolRequest.error} /> : null}
        {error ? <ErrorState message={error} /> : null}
        {partialWarning ? (
          <Text color="warning" variant="body-2">
            {partialWarning}
          </Text>
        ) : null}
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

          <Card padding={4}>
            <View align="center" direction="row" gap={3} wrap>
              <Text color="neutral-faded">Share these findings without the graph:</Text>
              <Button onClick={() => setPrintBlocked(!printReport(exportScope))} size="small" title="Open a printable plain-language report (use your browser's Save as PDF)" variant="outline">
                Export report
              </Button>
              <Button onClick={() => downloadReportCsv(exportScope)} size="small" title="Download every connection and its evidence as a CSV" variant="outline">
                Export CSV
              </Button>
              <Button onClick={() => downloadReportJson(exportScope)} size="small" title="Download the raw connection data as JSON" variant="outline">
                Export JSON
              </Button>
              {printBlocked ? (
                <Text color="critical" variant="body-2">
                  Allow pop-ups for this site to open the printable report.
                </Text>
              ) : null}
            </View>
          </Card>

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
                      expanded={expanded === `${pair.a}|${pair.b}`}
                      key={`${pair.a}|${pair.b}`}
                      leftLabel={pair.a}
                      link={pair}
                      onToggle={toggleExpanded}
                      rightLabel={pair.b}
                      toggleKey={`${pair.a}|${pair.b}`}
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
                    onToggle={toggle}
                    rightLabel={link.target}
                    toggleKey={`${domain}|${link.target}`}
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
        <Button onClick={groupsRequest.refresh} variant="outline">
          Refresh
        </Button>
      </div>

      {/* color="primary" only on the selected chip -- left at the Button
          default ("neutral") these solid chips render navy-on-navy against
          the dark theme's midnight background, with no visible distinction
          between "selected" and "just dark text on a dark pill". Champagne
          is the theme's one accent color, so it's the right signal for
          "this one's active" here. */}
      <View direction="row" gap={2} wrap>
        <Button
          color={kind === "" ? "primary" : "neutral"}
          highlighted={kind === ""}
          onClick={() => setKind("")}
          size="small"
          variant={kind === "" ? "solid" : "outline"}
        >
          All edges
        </Button>
        {kinds.map((entry) => (
          <Button
            color={kind === entry.kind ? "primary" : "neutral"}
            key={entry.kind}
            onClick={() => setKind(entry.kind)}
            size="small"
            variant={kind === entry.kind ? "solid" : "outline"}
          >
            {sharedNodeLabel(entry.kind)}
            {entry.groups !== null ? ` - ${entry.groups}` : ""}
          </Button>
        ))}
      </View>

      {kindsRequest.error ? <ErrorState message={kindsRequest.error} /> : null}
      {groupsRequest.loading && !groupsRequest.data ? <LoadingState message="Loading shared-edge groups..." /> : null}
      {groupsRequest.error ? <ErrorState message={groupsRequest.error} /> : null}
      {!groupsRequest.loading && groups.length === 0 ? (
        <EmptyState message="No cross-channel groups for this edge type yet." />
      ) : null}

      {groups.length > 0 ? (
        <div className="cluster-grid">
          {groups.map((group) => (
            <Card key={group.id} padding={4}>
              <View gap={3}>
                <View align="center" direction="row" justify="space-between">
                  <View gap={1}>
                    <Text color="neutral-faded" variant="caption-1">
                      {sharedNodeLabel(group.kind)}
                    </Text>
                    <View align="center" direction="row" gap={2}>
                      <FaviconThumb kind={group.kind} value={group.value} />
                      <Text attributes={{ title: group.value }} weight="semibold">
                        {group.value}
                      </Text>
                    </View>
                  </View>
                  <Badge attributes={{ title: "Channels sharing this edge" }} color="primary" variant="faded">
                    {group.degree ?? group.domains.length}
                  </Badge>
                </View>
                <View direction="row" gap={1} wrap>
                  {group.domains.slice(0, 12).map((domain) => (
                    <Badge
                      attributes={{ title: "Add to the comparison", role: "button", tabIndex: 0 }}
                      color="neutral"
                      key={`${group.id}-${domain}`}
                      onClick={() => onPickDomain(domain)}
                      variant="faded"
                    >
                      {domain}
                    </Badge>
                  ))}
                  {group.domains.length > 12 ? (
                    <Badge color="neutral">+{group.domains.length - 12} more</Badge>
                  ) : null}
                </View>
                <Button onClick={() => onPickAll(group.domains)} variant="ghost">
                  Compare all {group.domains.length}
                </Button>
              </View>
            </Card>
          ))}
        </div>
      ) : null}
    </section>
  );
}
