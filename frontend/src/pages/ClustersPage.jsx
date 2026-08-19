import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Badge, Button, Card, Modal, Text, View } from "reshaped";

import { fetchJson, normalizeConnectionsGraph, normalizeGraphClusters, useApi } from "../api.js";
import LazyClusterGraph from "../components/LazyClusterGraph.jsx";
import { EmptyState, ErrorState, LoadingState } from "../components/primitives.jsx";
import { FaviconThumb, sharedNodeLabel } from "../features/evidence.jsx";
import { rememberFocus } from "../features/focus.js";
import { Link } from "../router.jsx";
import AppShell from "../shell/AppShell.jsx";

export default function ClustersPage() {
  const clustersRequest = useApi("/api/graph/clusters");
  const clusters = useMemo(() => normalizeGraphClusters(clustersRequest.data), [clustersRequest.data]);
  const [recomputing, setRecomputing] = useState(false);
  const [recomputeMsg, setRecomputeMsg] = useState(null);

  const recompute = async () => {
    setRecomputing(true);
    setRecomputeMsg(null);
    try {
      // A full graph recompute is long-running, so it gets a longer ceiling
      // than the default request timeout rather than being cut off mid-rebuild.
      const payload = await fetchJson("/api/graph/recompute", {
        method: "POST",
        timeoutMs: 10 * 60 * 1000,
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
            <p>Groups of channels connected through shared infrastructure or identifiers.</p>
          </div>
          <View direction="row" gap={2}>
            <Button onClick={clustersRequest.refresh} variant="outline">
              Refresh
            </Button>
            <Button disabled={recomputing} loading={recomputing} onClick={recompute} variant="outline">
              {recomputing ? "Recomputing..." : "Recompute graph"}
            </Button>
          </View>
        </div>
        {recomputeMsg ? (
          <div className="callout">
            <p>{recomputeMsg}</p>
          </div>
        ) : null}
      </div>

      {clustersRequest.loading && !clustersRequest.data ? <LoadingState message="Loading clusters..." /> : null}
      {clustersRequest.error ? <ErrorState message={clustersRequest.error} /> : null}
      {!clustersRequest.loading && clusters.length === 0 ? (
        <EmptyState message="No clusters yet. Ingest channels; clusters build automatically in the background." />
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

  const graphAbortRef = useRef(null);
  const loadGraph = useCallback(async () => {
    // Abortable and unmount-safe: this is a live scoring call, and closing the
    // card previously left it running and then set state on a dead component.
    graphAbortRef.current?.abort();
    const controller = new AbortController();
    graphAbortRef.current = controller;

    setGraphState({ loading: true, error: null, data: null });
    try {
      const payload = await fetchJson("/api/graph/connections", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domains: cluster.members, pool_links: false }),
        signal: controller.signal,
      });
      setGraphState({ loading: false, error: null, data: payload });
    } catch (err) {
      if (controller.signal.aborted) {
        return;
      }
      setGraphState({ loading: false, error: err.message || "Could not load the network graph.", data: null });
    }
  }, [cluster.members]);

  useEffect(() => () => graphAbortRef.current?.abort(), []);

  const openGraph = useCallback(() => {
    setModalOpen(true);
    if (!graphState.data && !graphState.loading) {
      loadGraph();
    }
  }, [graphState.data, graphState.loading, loadGraph]);

  const graph = useMemo(
    () => (graphState.data ? normalizeConnectionsGraph(graphState.data, graphState.data?.domains || cluster.members) : null),
    [graphState.data, cluster.members],
  );
  const seedTargets = useMemo(() => new Set(cluster.members), [cluster.members]);
  const scoredDomains = graphState.data?.domains;
  const truncated = Array.isArray(scoredDomains) && scoredDomains.length < cluster.members.length;

  return (
    <Card padding={4}>
      <View gap={3}>
        <View align="center" direction="row" justify="space-between">
          <View gap={1}>
            <Text color="neutral-faded" variant="caption-1">
              Cluster
            </Text>
            <Text variant="body-1" weight="bold">
              {cluster.id}
            </Text>
          </View>
          <Badge attributes={{ title: "Channels in this cluster" }} color="primary" variant="faded">
            {cluster.size}
          </Badge>
        </View>
        <View direction="row" gap={1} wrap>
          {cluster.members.slice(0, 12).map((member) => (
            <Badge color="neutral" key={`${cluster.id}-${member}`} variant="faded">
              {member}
            </Badge>
          ))}
          {cluster.members.length > 12 ? (
            <Badge color="neutral">+{cluster.members.length - 12} more</Badge>
          ) : null}
        </View>
        {cluster.links.length > 0 ? (
          <View gap={1}>
            <Text color="neutral-faded" variant="caption-1">
              Connected by
            </Text>
            <View direction="row" gap={1} wrap>
              {cluster.links.map((link) => (
                <Badge
                  attributes={{ title: `${sharedNodeLabel(link.kind)}: ${link.value}` }}
                  color="primary"
                  key={`${cluster.id}-${link.kind}-${link.value}`}
                  variant="faded"
                >
                  <FaviconThumb kind={link.kind} value={link.value} />
                  {sharedNodeLabel(link.kind)}: {link.value}
                  {link.memberCount ? ` x${link.memberCount}` : ""}
                </Badge>
              ))}
              {cluster.linkCount > cluster.links.length ? (
                <Badge color="neutral">+{cluster.linkCount - cluster.links.length} more</Badge>
              ) : null}
            </View>
          </View>
        ) : null}
        <View direction="row" gap={3}>
          <Button onClick={openGraph} variant="outline">
            View network graph
          </Button>
          {/* Link (not Button) -- needs the router's client-side navigation. */}
          <Link className="primary-button" onClick={() => rememberFocus(cluster.members)} to="/connections">
            Show connections
          </Link>
        </View>
      </View>
      <Modal active={modalOpen} onClose={() => setModalOpen(false)} size="90vw">
        <View gap={4}>
          <View align="center" direction="row" justify="space-between">
            <Text variant="title-3" weight="bold">
              Cluster {cluster.id}
            </Text>
            <Button onClick={() => setModalOpen(false)} size="small" variant="ghost">
              Close
            </Button>
          </View>
          {graphState.loading ? <LoadingState message="Scoring connections..." /> : null}
          {graphState.error ? <ErrorState message={graphState.error} /> : null}
          {truncated ? (
            <Text color="neutral-faded">
              Showing the first {scoredDomains.length} of {cluster.members.length} channels.
            </Text>
          ) : null}
          {graph ? <LazyClusterGraph graph={graph} seedTargets={seedTargets} /> : null}
        </View>
      </Modal>
    </Card>
  );
}
