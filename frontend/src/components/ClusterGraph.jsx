import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { drag as d3Drag } from "d3-drag";
import { zoom as d3Zoom, zoomIdentity } from "d3-zoom";
import { select as d3Select } from "d3-selection";
import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  forceX,
  forceY,
} from "d3-force";

// Evidence-edge tiers — how strong the link between two domains is.
const EDGE_TIERS = {
  strong: { color: "#dc2626", label: "Certificate or SSH key match" },
  infra: { color: "#f97316", label: "Shared hosting or IP address" },
  weak: { color: "#94a3b8", label: "Weaker shared signals" },
};
const TIER_ORDER = ["strong", "infra", "weak"];

// Node roles. The graph now only ever contains two kinds of node:
//   submitted — a domain the user asked about (the anchors of the map)
//   bridge    — a subdomain that links one submitted domain to another
const SUBMITTED_COLOR = "#2752d6";
const BRIDGE_COLOR = "#0ea5e9";
// Faint tie connecting a bridge subdomain back to the domain it belongs to.
const MEMBERSHIP_COLOR = "#cbd5e1";

const LABEL_MODES = {
  all: { label: "All" },
  hubs: { label: "Hubs only" },
  none: { label: "None" },
};

function edgeKind(edge) {
  return edge.kind || "evidence";
}

function edgeTier(edge) {
  return EDGE_TIERS[edge.visual] ? edge.visual : "weak";
}

function isSubmitted(node, seeds) {
  return node.role === "submitted" || seeds.has(node.id);
}

function truncateLabel(text, max = 28) {
  const value = String(text || "");
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

const ClusterGraph = memo(function ClusterGraph({
  graph,
  seedTargets = new Set(),
  renderPairEvidence = null,
}) {
  const containerRef = useRef(null);
  const svgRef = useRef(null);
  const gRef = useRef(null);
  const simulationRef = useRef(null);
  const zoomRef = useRef(null);
  // Live references to the rendered D3 selections so the styling effect can
  // restyle without tearing down and restarting the force simulation.
  const selectionsRef = useRef({ node: null, link: null });

  const [width, setWidth] = useState(960);
  const height = Math.max(460, Math.min(680, Math.round(width * 0.58)));

  // Presentation controls — deliberately lean. The map only shows submitted
  // domains and their bridges, so there's no node-colour/size lens to pick.
  const [labelMode, setLabelMode] = useState("all");
  const [tierFilter, setTierFilter] = useState({ strong: true, infra: true, weak: true });
  const [minScore, setMinScore] = useState(0);
  const [spread, setSpread] = useState(1);

  // Selection drives the detail panels below the map.
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);

  // Track the rendered width so the layout adapts to the panel size.
  useEffect(() => {
    if (!containerRef.current || typeof ResizeObserver === "undefined") {
      return undefined;
    }
    let frame = 0;
    const observer = new ResizeObserver((entries) => {
      const next = Math.round(entries[0]?.contentRect?.width || 0);
      if (next <= 0) {
        return;
      }
      // Coalesce resize bursts to one update per frame, and skip same-width
      // updates: width is a rebuild dependency of the simulation effect, so an
      // undebounced observer rebuilds the force layout on every intermediate
      // pixel while the window (or a flex reflow) is dragging.
      if (frame) {
        cancelAnimationFrame(frame);
      }
      frame = requestAnimationFrame(() => {
        frame = 0;
        setWidth((current) => (current === next ? current : next));
      });
    });
    observer.observe(containerRef.current);
    return () => {
      if (frame) {
        cancelAnimationFrame(frame);
      }
      observer.disconnect();
    };
  }, []);

  const allNodes = useMemo(
    () => (Array.isArray(graph?.nodes) ? graph.nodes : []),
    [graph],
  );
  const allEdges = useMemo(
    () => (Array.isArray(graph?.edges) ? graph.edges : []),
    [graph],
  );
  const maxScore = useMemo(
    () =>
      allEdges.reduce(
        (max, edge) => (edgeKind(edge) === "evidence" ? Math.max(max, edge.score || 0) : max),
        0,
      ),
    [allEdges],
  );

  // Evidence edges that survive the tier + minimum-strength filters. These are
  // the actual links between domains; membership ties are handled separately.
  const visibleEvidence = useMemo(() => {
    const ids = new Set(allNodes.map((node) => node.id));
    return allEdges.filter(
      (edge) =>
        edgeKind(edge) === "evidence" &&
        ids.has(edge.from) &&
        ids.has(edge.to) &&
        tierFilter[edgeTier(edge)] &&
        (edge.score || 0) >= minScore,
    );
  }, [allNodes, allEdges, tierFilter, minScore]);

  // A node earns its place on the map only if it takes part in a surviving
  // link — directly, or (for a submitted domain) through one of its bridges.
  // That's what "submitted domains that match the strength" means in practice.
  const liveIds = useMemo(() => {
    const ids = new Set();
    visibleEvidence.forEach((edge) => {
      ids.add(edge.from);
      ids.add(edge.to);
    });
    allEdges.forEach((edge) => {
      if (edgeKind(edge) !== "membership") return;
      // edge.from = apex (submitted domain), edge.to = bridge subdomain.
      if (ids.has(edge.to)) ids.add(edge.from);
    });
    return ids;
  }, [visibleEvidence, allEdges]);

  const visibleNodes = useMemo(
    () => allNodes.filter((node) => liveIds.has(node.id)),
    [allNodes, liveIds],
  );

  const visibleMembership = useMemo(
    () =>
      allEdges.filter(
        (edge) =>
          edgeKind(edge) === "membership" &&
          liveIds.has(edge.from) &&
          liveIds.has(edge.to),
      ),
    [allEdges, liveIds],
  );

  const visibleEdges = useMemo(
    () => [...visibleEvidence, ...visibleMembership],
    [visibleEvidence, visibleMembership],
  );

  // Per-node connection count, from evidence links only (membership ties don't
  // count toward how "connected" a domain is).
  const metrics = useMemo(() => {
    const degree = new Map();
    visibleEvidence.forEach((edge) => {
      degree.set(edge.from, (degree.get(edge.from) || 0) + 1);
      degree.set(edge.to, (degree.get(edge.to) || 0) + 1);
    });
    let maxDegree = 0;
    degree.forEach((value) => {
      maxDegree = Math.max(maxDegree, value);
    });
    return { degree, maxDegree };
  }, [visibleEvidence]);

  // Submitted domains are the larger anchors; bridges sit smaller alongside.
  const radiusFor = useCallback(
    (node) => {
      if (isSubmitted(node, seedTargets)) {
        const degree = metrics.degree.get(node.id) || 0;
        return Math.min(26, 13 + degree * 1.1);
      }
      return 8;
    },
    [metrics, seedTargets],
  );

  const colorFor = useCallback(
    (node) => (isSubmitted(node, seedTargets) ? SUBMITTED_COLOR : BRIDGE_COLOR),
    [seedTargets],
  );

  const handleNodeClick = useCallback((nodeId) => {
    setSelectedEdge(null);
    setSelectedNode((current) => (current === nodeId ? null : nodeId));
  }, []);

  const handleEdgeClick = useCallback((edge) => {
    setSelectedNode(null);
    setSelectedEdge((current) => {
      const key = `${edge.from}|${edge.to}`;
      return current === key ? null : key;
    });
  }, []);

  // The set of nodes adjacent to the current selection (used to dim the rest).
  const neighborIds = useMemo(() => {
    if (!selectedNode) {
      return null;
    }
    const ids = new Set([selectedNode]);
    visibleEdges.forEach((edge) => {
      if (edge.from === selectedNode) ids.add(edge.to);
      if (edge.to === selectedNode) ids.add(edge.from);
    });
    return ids;
  }, [selectedNode, visibleEdges]);

  // Latest presentation state, read by applyStyles at call-time. Keeping this in
  // a ref lets applyStyles stay referentially stable (empty deps) so the build
  // effect can call it without rebuilding the simulation on every recolour.
  const styleRef = useRef({});
  styleRef.current = { colorFor, labelMode, selectedNode, selectedEdge, neighborIds, metrics, seedTargets };

  // Apply colour / label / highlight to the existing selections in place.
  const applyStyles = useCallback(() => {
    const { node, link } = selectionsRef.current;
    if (!node || !link) {
      return;
    }
    const {
      colorFor: color,
      labelMode: labels,
      selectedNode: selNode,
      selectedEdge: selEdge,
      neighborIds: neighbors,
      metrics: nodeMetrics,
      seedTargets: seeds,
    } = styleRef.current;

    const labelThreshold = Math.max(2, Math.ceil(nodeMetrics.maxDegree * 0.4));
    node
      .select("circle.graph-marker")
      .attr("fill", (d) => color(d))
      .attr("stroke", (d) => (selNode === d.id ? "var(--text)" : "transparent"));
    node.attr("opacity", (d) => (neighbors && !neighbors.has(d.id) ? 0.2 : 1));
    node
      .select("text.graph-node-label")
      .attr("font-weight", (d) => (isSubmitted(d, seeds) ? 700 : 400))
      .style("display", (d) => {
        if (labels === "none") return "none";
        if (labels === "hubs") {
          const degree = nodeMetrics.degree.get(d.id) || 0;
          return degree >= labelThreshold || isSubmitted(d, seeds) ? null : "none";
        }
        return null;
      });

    link.each(function each(d) {
      const key = `${d.from}|${d.to}`;
      const isSelected = selEdge === key;
      const membership = edgeKind(d) === "membership";
      const dimmed =
        (neighbors && d.from !== selNode && d.to !== selNode) ||
        (selEdge && !isSelected);
      const base = membership ? 0.4 : 0.55;
      d3Select(this)
        .select(".graph-edge-stroke")
        .attr("stroke-opacity", dimmed ? 0.08 : isSelected ? 0.95 : base)
        .attr("stroke-width", isSelected ? (d.width || 1.5) + 1.5 : d.width || 1.5);
    });
  }, []);

  // --- Build / rebuild the simulation and DOM ---------------------------------
  // Runs when the data, viewport, or any layout-affecting control changes.
  useEffect(() => {
    if (!svgRef.current || !gRef.current || visibleNodes.length === 0) {
      return undefined;
    }

    const simNodes = visibleNodes.map((node) => ({
      ...node,
      radius: radiusFor(node),
    }));
    const byId = new Map(simNodes.map((node) => [node.id, node]));
    const simLinks = visibleEdges
      .filter((edge) => byId.has(edge.from) && byId.has(edge.to))
      .map((edge) => ({ ...edge, source: edge.from, target: edge.to }));

    const g = d3Select(gRef.current);
    g.selectAll("*").remove();

    const linkSel = g
      .append("g")
      .attr("class", "graph-links")
      .selectAll("g")
      .data(simLinks, (d) => `${d.from}|${d.to}`)
      .join("g");

    // Wide transparent hit-line for easy clicking (evidence edges only), plus
    // the visible stroke.
    linkSel
      .filter((d) => edgeKind(d) === "evidence")
      .append("line")
      .attr("class", "graph-edge-hit")
      .attr("stroke", "transparent")
      .attr("stroke-width", 14)
      .style("cursor", "pointer")
      .on("click", (event, d) => {
        event.stopPropagation();
        handleEdgeClick(d);
      });
    linkSel
      .append("line")
      .attr("class", "graph-edge-stroke")
      .attr("pointer-events", "none")
      .attr("stroke", (d) =>
        edgeKind(d) === "membership" ? MEMBERSHIP_COLOR : EDGE_TIERS[edgeTier(d)].color,
      )
      .attr("stroke-dasharray", (d) => (edgeKind(d) === "membership" ? "3 4" : null))
      .attr("stroke-width", (d) => d.width || 1.5);

    const nodeSel = g
      .append("g")
      .attr("class", "graph-nodes")
      .selectAll("g")
      .data(simNodes, (d) => d.id)
      .join("g")
      .attr("class", "cluster-node")
      .style("cursor", "grab")
      .on("click", (event, d) => {
        event.stopPropagation();
        handleNodeClick(d.id);
      });

    // Halo behind each submitted domain to set the anchors apart.
    nodeSel
      .filter((d) => isSubmitted(d, seedTargets))
      .append("circle")
      .attr("class", "graph-seed-halo")
      .attr("fill", "rgba(39, 82, 214, 0.16)")
      .attr("r", (d) => d.radius + 7);

    nodeSel
      .append("circle")
      .attr("class", "graph-marker")
      .attr("r", (d) => d.radius)
      .attr("stroke-width", 2);

    nodeSel
      .append("text")
      .attr("class", "graph-node-label")
      .attr("text-anchor", "middle")
      .attr("y", (d) => d.radius + 14)
      .text((d) => truncateLabel(d.label));

    selectionsRef.current = { node: nodeSel, link: linkSel };
    // Apply the current colour / label / highlight to the freshly-built DOM.
    applyStyles();

    // Link distance / charge scale with the "spread" control so the user can
    // pull dense clusters apart or pack them tight. Membership ties stay short
    // so a bridge hugs the domain it belongs to.
    const simulation = forceSimulation(simNodes)
      .force(
        "link",
        forceLink(simLinks)
          .id((node) => node.id)
          .distance((edge) => {
            if (edgeKind(edge) === "membership") return 48 * spread;
            return (
              (edgeTier(edge) === "strong" ? 80 : edgeTier(edge) === "infra" ? 120 : 160) *
              spread
            );
          })
          .strength((edge) =>
            edgeKind(edge) === "membership" ? 0.9 : edgeTier(edge) === "weak" ? 0.25 : 0.6,
          ),
      )
      .force("charge", forceManyBody().strength(-260 * spread))
      .force("center", forceCenter(width / 2, height / 2))
      .force("collide", forceCollide().radius((node) => node.radius + 16))
      .force("x", forceX(width / 2).strength(0.06))
      .force("y", forceY(height / 2).strength(0.08));

    simulationRef.current = simulation;

    const margin = 30;
    simulation.on("tick", () => {
      simNodes.forEach((node) => {
        node.x = Math.max(margin, Math.min(width - margin, node.x));
        node.y = Math.max(margin, Math.min(height - margin, node.y));
      });
      linkSel
        .selectAll("line")
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y);
      nodeSel.attr("transform", (d) => `translate(${d.x}, ${d.y})`);
    });

    // Drag: pin a node while held, then release it back to the simulation.
    const dragger = d3Drag()
      .on("start", function start(event, d) {
        if (!event.active) {
          simulation.alphaTarget(0.3).restart();
        }
        d.fx = d.x;
        d.fy = d.y;
        d3Select(this).style("cursor", "grabbing");
      })
      .on("drag", (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on("end", function end(event, d) {
        if (!event.active) {
          simulation.alphaTarget(0);
        }
        d.fx = null;
        d.fy = null;
        d3Select(this).style("cursor", "grab");
      });
    nodeSel.call(dragger);

    return () => {
      simulation.stop();
      simulationRef.current = null;
      selectionsRef.current = { node: null, link: null };
    };
  }, [
    visibleNodes,
    visibleEdges,
    width,
    height,
    spread,
    radiusFor,
    seedTargets,
    handleNodeClick,
    handleEdgeClick,
    applyStyles,
  ]);

  // --- Zoom / pan (set up once) ----------------------------------------------
  useEffect(() => {
    if (!svgRef.current || !gRef.current) {
      return undefined;
    }
    const svg = d3Select(svgRef.current);
    const g = d3Select(gRef.current);
    const zoomer = d3Zoom()
      .scaleExtent([0.3, 5])
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
      });
    zoomRef.current = { svg, zoomer };
    svg.call(zoomer);
    // Clear selection when clicking empty canvas.
    svg.on("click", () => {
      setSelectedNode(null);
      setSelectedEdge(null);
    });
    return () => {
      svg.on(".zoom", null);
      svg.on("click", null);
    };
  }, []);

  const resetView = useCallback(() => {
    const handle = zoomRef.current;
    if (handle) {
      handle.svg.transition().duration(300).call(handle.zoomer.transform, zoomIdentity);
    }
  }, []);

  // Restyle in place whenever a presentation control changes — colour, labels
  // and highlight are pure presentation, so they never restart the simulation.
  useEffect(() => {
    applyStyles();
  }, [applyStyles, colorFor, labelMode, selectedNode, selectedEdge, neighborIds, metrics, seedTargets]);

  const selectedEdgeData = useMemo(() => {
    if (!selectedEdge) {
      return null;
    }
    return visibleEvidence.find((edge) => `${edge.from}|${edge.to}` === selectedEdge) || null;
  }, [selectedEdge, visibleEvidence]);

  const selectedNodeEdges = useMemo(() => {
    if (!selectedNode) {
      return [];
    }
    return visibleEvidence
      .filter((edge) => edge.from === selectedNode || edge.to === selectedNode)
      .sort((a, b) => (b.score || 0) - (a.score || 0));
  }, [selectedNode, visibleEvidence]);

  if (allNodes.length === 0) {
    return null;
  }

  const submittedCount = visibleNodes.filter((node) => isSubmitted(node, seedTargets)).length;
  const bridgeCount = visibleNodes.length - submittedCount;

  return (
    <section className="cluster-graph-card" ref={containerRef}>
      <div className="panel-header">
        <div>
          <p className="eyebrow">Connection map</p>
          <h3>How your submitted domains link together</h3>
          <p className="section-copy">
            Big circles are the domains you submitted. A small circle only appears when one
            domain&apos;s subdomain is the thing that bridges it to another submitted domain —
            everything else is left off to keep the picture clean. Lines show shared evidence;
            faint dashed lines tie a bridge back to the domain it belongs to. Click a line to
            see what two domains share, click a domain to highlight its connections, drag to
            rearrange, scroll to zoom.
          </p>
        </div>
      </div>

      <div className="graph-controls" aria-label="Map customisation">
        <label className="graph-control">
          <span>Labels</span>
          <select value={labelMode} onChange={(e) => setLabelMode(e.target.value)}>
            {Object.entries(LABEL_MODES).map(([key, mode]) => (
              <option key={key} value={key}>
                {mode.label}
              </option>
            ))}
          </select>
        </label>

        <label className="graph-control">
          <span>Spread</span>
          <input
            max="2"
            min="0.5"
            onChange={(e) => setSpread(Number(e.target.value))}
            step="0.1"
            type="range"
            value={spread}
          />
        </label>

        {maxScore > 0 ? (
          <label className="graph-control">
            <span>Min. strength {minScore > 0 ? `(${minScore})` : ""}</span>
            <input
              max={maxScore}
              min="0"
              onChange={(e) => setMinScore(Number(e.target.value))}
              step="1"
              type="range"
              value={minScore}
            />
          </label>
        ) : null}

        <div className="graph-control tiers">
          <span>Show links</span>
          <div className="graph-tier-toggles">
            {TIER_ORDER.map((tier) => (
              <label className="graph-tier-toggle" key={tier}>
                <input
                  checked={tierFilter[tier]}
                  onChange={(e) =>
                    setTierFilter((prev) => ({ ...prev, [tier]: e.target.checked }))
                  }
                  type="checkbox"
                />
                <span
                  className="graph-legend-swatch"
                  style={{ background: EDGE_TIERS[tier].color }}
                />
                {tier}
              </label>
            ))}
          </div>
        </div>

        <button className="secondary-button small" onClick={resetView} type="button">
          Reset view
        </button>
      </div>

      <div className="graph-legend" aria-label="Map legend">
        <span className="graph-legend-item">
          <span className="graph-legend-swatch round" style={{ background: SUBMITTED_COLOR }} />
          Domain you submitted ({submittedCount})
        </span>
        <span className="graph-legend-item">
          <span className="graph-legend-swatch round" style={{ background: BRIDGE_COLOR }} />
          Bridging subdomain ({bridgeCount})
        </span>
        {TIER_ORDER.map((tier) => (
          <span className="graph-legend-item" key={tier}>
            <span className="graph-legend-swatch" style={{ background: EDGE_TIERS[tier].color }} />
            {EDGE_TIERS[tier].label}
          </span>
        ))}
      </div>

      <svg
        ref={svgRef}
        className="cluster-graph"
        viewBox={`0 0 ${width} ${height}`}
        style={{ cursor: "grab", height }}
        role="img"
        aria-label="Network map of connected domains"
      >
        <g ref={gRef} />
      </svg>

      {selectedEdgeData ? (
        <div className="graph-detail-panel">
          <strong>
            {selectedEdgeData.from} ↔ {selectedEdgeData.to}
          </strong>
          <p className="card-copy">What these two have in common:</p>
          {/* Render the exact same evidence packet the summary page shows for
              these two entities, sourced from the shared pair endpoint. Falls
              back to the edge's own labels for links with no backing pair. */}
          {renderPairEvidence && selectedEdgeData.pairing_id ? (
            renderPairEvidence(selectedEdgeData.pairing_id)
          ) : (
            <ul className="simple-list">
              {(selectedEdgeData.labels && selectedEdgeData.labels.length > 0
                ? selectedEdgeData.labels
                : (selectedEdgeData.paths || []).map(formatPathFallback)
              ).map((label) => (
                <li key={label}>{label}</li>
              ))}
            </ul>
          )}
        </div>
      ) : null}

      {selectedNode && selectedNodeEdges.length > 0 ? (
        <div className="graph-detail-panel">
          <strong>{selectedNode}</strong>
          <p className="card-copy">
            Connected to {selectedNodeEdges.length} other
            {selectedNodeEdges.length === 1 ? " node" : " nodes"}:
          </p>
          <ul className="simple-list">
            {selectedNodeEdges.slice(0, 8).map((edge) => {
              const other = edge.from === selectedNode ? edge.to : edge.from;
              const labels =
                edge.labels && edge.labels.length > 0
                  ? edge.labels
                  : (edge.paths || []).map(formatPathFallback);
              return (
                <li key={`${edge.from}|${edge.to}`}>
                  <strong>{other}</strong>
                  {labels.length > 0 ? ` — ${labels.slice(0, 3).join(", ")}` : ""}
                </li>
              );
            })}
            {selectedNodeEdges.length > 8 ? (
              <li>…and {selectedNodeEdges.length - 8} more connections.</li>
            ) : null}
          </ul>
        </div>
      ) : null}
    </section>
  );
});

function formatPathFallback(path) {
  const text = String(path || "");
  if (text.startsWith("observed_ip:")) {
    return "Observed IP address";
  }
  const leaf = text.split(".").pop().replace("[*]", "").replace(/_/g, " ");
  return `Shared ${leaf}`;
}

export default ClusterGraph;
