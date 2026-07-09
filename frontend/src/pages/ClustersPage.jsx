import { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";

import { normalizeConnectionsGraph, normalizeGraphClusters, useApi } from "../api.js";
import LazyClusterGraph from "../components/LazyClusterGraph.jsx";
import { EmptyState, ErrorState, LoadingState } from "../components/primitives.jsx";
import { FaviconThumb, sharedNodeLabel } from "../features/evidence.jsx";
import { rememberFocus } from "../features/focus.js";
import { finishIngest } from "../features/ingest.jsx";
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
      const response = await fetch("/api/graph/recompute", {
        method: "POST",
        headers: { Accept: "application/json" },
      });
      const payload = await finishIngest(response);
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
          <div className="action-row">
            <button className="secondary-button" onClick={clustersRequest.refresh} type="button">
              Refresh
            </button>
            <button className="secondary-button" disabled={recomputing} onClick={recompute} type="button">
              {recomputing ? "Recomputing..." : "Recompute graph"}
            </button>
          </div>
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
      setGraphState({ loading: false, error: err.message || "Could not load the network graph.", data: null });
    }
  }, [cluster.members]);

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
                {link.memberCount ? <span className="connector-count">x{link.memberCount}</span> : null}
              </span>
            ))}
            {cluster.linkCount > cluster.links.length ? (
              <span className="chip digest-more-chip">+{cluster.linkCount - cluster.links.length} more</span>
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
        <GraphModal onClose={() => setModalOpen(false)} title={`Cluster ${cluster.id}`}>
          {graphState.loading ? <LoadingState message="Scoring connections..." /> : null}
          {graphState.error ? <ErrorState message={graphState.error} /> : null}
          {truncated ? (
            <p className="muted">
              Showing the first {scoredDomains.length} of {cluster.members.length} channels.
            </p>
          ) : null}
          {graph ? <LazyClusterGraph graph={graph} seedTargets={seedTargets} /> : null}
        </GraphModal>
      ) : null}
    </article>
  );
}

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
