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

const EDGE_TIERS = {
  strong: { color: "#dc2626", label: "Certificate or SSH key match" },
  infra: { color: "#f97316", label: "Shared hosting or IP address" },
  weak: { color: "#94a3b8", label: "Weaker shared signals" },
};

const TIER_ORDER = ["strong", "infra", "weak"];
const SEED_COLOR = "#2752d6";

// Palette used when colouring nodes by their connection count ("degree").
// Low connectivity → cool/faint, high connectivity → warm/strong accent.
const DEGREE_RAMP = ["#cbd5e1", "#60a5fa", "#2752d6", "#7c3aed", "#db2777"];

// Colours for the "node type" insight.
const KIND_COLORS = {
  domain: "#2752d6",
  apex: "#2752d6",
  subdomain: "#0ea5e9",
  ip: "#f97316",
};
const KIND_FALLBACK = "#64748b";

// The different lenses the user can put the graph under. Each one answers a
// different question about the same cluster data.
const COLOR_MODES = {
  cluster: { label: "Cluster grouping" },
  evidence: { label: "Evidence strength" },
  degree: { label: "Connection count" },
  kind: { label: "Node type" },
};

const SIZE_MODES = {
  degree: { label: "Connection count" },
  weight: { label: "Connection strength" },
  uniform: { label: "Uniform" },
};

const LABEL_MODES = {
  all: { label: "All" },
  hubs: { label: "Hubs only" },
  none: { label: "None" },
};

function edgeTier(edge) {
  return EDGE_TIERS[edge.visual] ? edge.visual : "weak";
}

function truncateLabel(text, max = 28) {
  const value = String(text || "");
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function looksLikeIp(value) {
  return /^[\d.]+$/.test(String(value || "")) || String(value || "").includes(":");
}

function isIpNode(node) {
  return node.kind === "ip" || looksLikeIp(node.id);
}

// Linear interpolation across a list of hex stops, t in [0, 1].
function rampColor(stops, t) {
  if (t <= 0) return stops[0];
  if (t >= 1) return stops[stops.length - 1];
  const scaled = t * (stops.length - 1);
  const i = Math.floor(scaled);
  return lerpHex(stops[i], stops[i + 1], scaled - i);
}

function lerpHex(a, b, t) {
  const pa = parseHex(a);
  const pb = parseHex(b);
  const ch = (k) => Math.round(pa[k] + (pb[k] - pa[k]) * t);
  return `rgb(${ch(0)}, ${ch(1)}, ${ch(2)})`;
}

function parseHex(hex) {
  const h = hex.replace("#", "");
  return [
    parseInt(h.slice(0, 2), 16),
    parseInt(h.slice(2, 4), 16),
    parseInt(h.slice(4, 6), 16),
  ];
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

  // Customisation controls — each one changes what the map reveals.
  const [showIps, setShowIps] = useState(false);
  const [colorMode, setColorMode] = useState("cluster");
  const [sizeMode, setSizeMode] = useState("degree");
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
    const observer = new ResizeObserver((entries) => {
      const next = Math.round(entries[0]?.contentRect?.width || 0);
      if (next > 0) {
        setWidth(next);
      }
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  const allNodes = useMemo(
    () => (Array.isArray(graph?.nodes) ? graph.nodes : []),
    [graph],
  );
  const allEdges = useMemo(
    () => (Array.isArray(graph?.edges) ? graph.edges : []),
    [graph],
  );
  const ipCount = useMemo(
    () => allNodes.filter((node) => isIpNode(node)).length,
    [allNodes],
  );
  const maxScore = useMemo(
    () => allEdges.reduce((max, edge) => Math.max(max, edge.score || 0), 0),
    [allEdges],
  );

  const visibleNodes = useMemo(() => {
    if (showIps) {
      return allNodes;
    }
    return allNodes.filter((node) => !isIpNode(node));
  }, [allNodes, showIps]);

  // Edges survive only if both endpoints are visible, the tier is enabled, and
  // the connection score clears the user's minimum-strength threshold.
  const visibleEdges = useMemo(() => {
    const ids = new Set(visibleNodes.map((node) => node.id));
    return allEdges.filter(
      (edge) =>
        ids.has(edge.from) &&
        ids.has(edge.to) &&
        tierFilter[edgeTier(edge)] &&
        (edge.score || 0) >= minScore,
    );
  }, [visibleNodes, allEdges, tierFilter, minScore]);

  // Per-node metrics derived from the currently-visible edges: connection
  // count (degree) and summed connection strength.
  const metrics = useMemo(() => {
    const degree = new Map();
    const weight = new Map();
    const strongestTier = new Map();
    visibleEdges.forEach((edge) => {
      degree.set(edge.from, (degree.get(edge.from) || 0) + 1);
      degree.set(edge.to, (degree.get(edge.to) || 0) + 1);
      weight.set(edge.from, (weight.get(edge.from) || 0) + (edge.score || 0));
      weight.set(edge.to, (weight.get(edge.to) || 0) + (edge.score || 0));
      const tier = edgeTier(edge);
      [edge.from, edge.to].forEach((id) => {
        const current = strongestTier.get(id);
        if (current === undefined || TIER_ORDER.indexOf(tier) < TIER_ORDER.indexOf(current)) {
          strongestTier.set(id, tier);
        }
      });
    });
    let maxDegree = 0;
    let maxWeight = 0;
    degree.forEach((value) => {
      maxDegree = Math.max(maxDegree, value);
    });
    weight.forEach((value) => {
      maxWeight = Math.max(maxWeight, value);
    });
    return { degree, weight, strongestTier, maxDegree, maxWeight };
  }, [visibleEdges]);

  // Resolve a node's radius for the active size lens.
  const radiusFor = useCallback(
    (node) => {
      if (isIpNode(node)) {
        return 5;
      }
      if (sizeMode === "uniform") {
        return 12;
      }
      if (sizeMode === "weight") {
        const value = metrics.weight.get(node.id) || 0;
        return 9 + (metrics.maxWeight ? (value / metrics.maxWeight) * 16 : 0);
      }
      const degree = metrics.degree.get(node.id) || 0;
      return Math.min(26, 9 + degree * 1.4);
    },
    [sizeMode, metrics],
  );

  // Resolve a node's fill for the active colour lens.
  const colorFor = useCallback(
    (node) => {
      if (colorMode === "kind") {
        return KIND_COLORS[node.kind] || KIND_FALLBACK;
      }
      if (colorMode === "evidence") {
        const tier = metrics.strongestTier.get(node.id);
        return tier ? EDGE_TIERS[tier].color : "#cbd5e1";
      }
      if (colorMode === "degree") {
        const degree = metrics.degree.get(node.id) || 0;
        return rampColor(DEGREE_RAMP, metrics.maxDegree ? degree / metrics.maxDegree : 0);
      }
      return node.color || KIND_FALLBACK;
    },
    [colorMode, metrics],
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
      .select("circle.graph-marker, rect.graph-marker")
      .attr("fill", (d) => color(d))
      .attr("stroke", (d) => (selNode === d.id ? "var(--text)" : "transparent"));
    node.attr("opacity", (d) => (neighbors && !neighbors.has(d.id) ? 0.2 : 1));
    node
      .select("text.graph-node-label")
      .attr("font-weight", (d) => (seeds.has(d.id) ? 700 : 400))
      .style("display", (d) => {
        if (labels === "none") return "none";
        if (labels === "hubs") {
          const degree = nodeMetrics.degree.get(d.id) || 0;
          return degree >= labelThreshold || seeds.has(d.id) ? null : "none";
        }
        return null;
      });

    link.each(function each(d) {
      const key = `${d.from}|${d.to}`;
      const isSelected = selEdge === key;
      const dimmed =
        (neighbors && d.from !== selNode && d.to !== selNode) ||
        (selEdge && !isSelected);
      d3Select(this)
        .select(".graph-edge-stroke")
        .attr("stroke-opacity", dimmed ? 0.1 : isSelected ? 0.95 : 0.55)
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

    // Wide transparent hit-line for easy clicking, plus the visible stroke.
    linkSel
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
      .attr("stroke", (d) => EDGE_TIERS[edgeTier(d)].color)
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

    // Seed halo behind the marker.
    nodeSel
      .filter((d) => seedTargets.has(d.id))
      .append("circle")
      .attr("class", "graph-seed-halo")
      .attr("fill", "rgba(39, 82, 214, 0.16)")
      .attr("r", (d) => d.radius + 7);

    // IPs render as squares, domains as circles.
    nodeSel
      .filter((d) => isIpNode(d))
      .append("rect")
      .attr("class", "graph-marker")
      .attr("rx", 2)
      .attr("width", (d) => d.radius * 2)
      .attr("height", (d) => d.radius * 2)
      .attr("x", (d) => -d.radius)
      .attr("y", (d) => -d.radius);
    nodeSel
      .filter((d) => !isIpNode(d))
      .append("circle")
      .attr("class", "graph-marker")
      .attr("r", (d) => d.radius)
      .attr("stroke-width", 2);

    nodeSel
      .append("text")
      .attr("class", (d) => `graph-node-label ${isIpNode(d) ? "ip" : ""}`)
      .attr("text-anchor", "middle")
      .attr("y", (d) => d.radius + 14)
      .text((d) => truncateLabel(d.label));

    selectionsRef.current = { node: nodeSel, link: linkSel };
    // Apply the current colour / label / highlight to the freshly-built DOM.
    applyStyles();

    // Link distance / charge scale with the "spread" control so the user can
    // pull dense clusters apart or pack them tight.
    const simulation = forceSimulation(simNodes)
      .force(
        "link",
        forceLink(simLinks)
          .id((node) => node.id)
          .distance(
            (edge) =>
              (edgeTier(edge) === "strong" ? 70 : edgeTier(edge) === "infra" ? 110 : 150) *
              spread,
          )
          .strength((edge) => (edgeTier(edge) === "weak" ? 0.25 : 0.6)),
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
    return visibleEdges.find((edge) => `${edge.from}|${edge.to}` === selectedEdge) || null;
  }, [selectedEdge, visibleEdges]);

  const selectedNodeEdges = useMemo(() => {
    if (!selectedNode) {
      return [];
    }
    return visibleEdges
      .filter((edge) => edge.from === selectedNode || edge.to === selectedNode)
      .sort((a, b) => (b.score || 0) - (a.score || 0));
  }, [selectedNode, visibleEdges]);

  if (allNodes.length === 0) {
    return null;
  }

  const legend = legendForMode(colorMode);

  return (
    <section className="cluster-graph-card" ref={containerRef}>
      <div className="panel-header">
        <div>
          <p className="eyebrow">Connection map</p>
          <h3>How the domains link together</h3>
          <p className="section-copy">
            Each circle is a domain; lines show shared evidence. Use the controls to
            recolour, resize and filter the map for different insights. Click a line to
            see what two domains share, click a domain to highlight its connections, drag
            to rearrange, scroll to zoom.
          </p>
        </div>
      </div>

      <div className="graph-controls" aria-label="Map customisation">
        <label className="graph-control">
          <span>Colour by</span>
          <select value={colorMode} onChange={(e) => setColorMode(e.target.value)}>
            {Object.entries(COLOR_MODES).map(([key, mode]) => (
              <option key={key} value={key}>
                {mode.label}
              </option>
            ))}
          </select>
        </label>

        <label className="graph-control">
          <span>Size by</span>
          <select value={sizeMode} onChange={(e) => setSizeMode(e.target.value)}>
            {Object.entries(SIZE_MODES).map(([key, mode]) => (
              <option key={key} value={key}>
                {mode.label}
              </option>
            ))}
          </select>
        </label>

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

        {ipCount > 0 ? (
          <label className="graph-toggle">
            <input
              checked={showIps}
              onChange={(e) => setShowIps(e.target.checked)}
              type="checkbox"
            />
            Show {ipCount} shared IP{ipCount === 1 ? "" : "s"}
          </label>
        ) : null}

        <button className="secondary-button small" onClick={resetView} type="button">
          Reset view
        </button>
      </div>

      <div className="graph-legend" aria-label="Map legend">
        {legend.map((item) => (
          <span className="graph-legend-item" key={item.label}>
            <span
              className={`graph-legend-swatch ${item.round ? "round" : ""}`}
              style={{ background: item.color }}
            />
            {item.label}
          </span>
        ))}
        <span className="graph-legend-item">
          <span className="graph-legend-swatch round" style={{ background: SEED_COLOR }} />
          Domain you submitted
        </span>
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
              back to the edge's own labels for links with no backing pair
              (e.g. shared-IP observation edges). */}
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
          {subdomainContributors(selectedEdgeData).length > 0 ? (
            <>
              <p className="card-copy">Linked through subdomains:</p>
              <ul className="simple-list">
                {subdomainContributors(selectedEdgeData).map((contributor) => {
                  const labels =
                    contributor.labels && contributor.labels.length > 0
                      ? ` — ${contributor.labels.slice(0, 3).join(", ")}`
                      : "";
                  return (
                    <li key={`${contributor.from}|${contributor.to}`}>
                      <strong>
                        {contributor.from} ↔ {contributor.to}
                      </strong>
                      {labels}
                    </li>
                  );
                })}
              </ul>
            </>
          ) : null}
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

// Legend entries that match the active colour lens.
function legendForMode(mode) {
  if (mode === "evidence") {
    return TIER_ORDER.map((tier) => ({
      label: EDGE_TIERS[tier].label,
      color: EDGE_TIERS[tier].color,
      round: true,
    }));
  }
  if (mode === "degree") {
    return [
      { label: "Few connections", color: DEGREE_RAMP[0], round: true },
      { label: "Many connections", color: DEGREE_RAMP[DEGREE_RAMP.length - 1], round: true },
    ];
  }
  if (mode === "kind") {
    return [
      { label: "Domain", color: KIND_COLORS.domain, round: true },
      { label: "Subdomain", color: KIND_COLORS.subdomain, round: true },
      { label: "IP address", color: KIND_COLORS.ip, round: true },
    ];
  }
  return [{ label: "Coloured by cluster", color: "#94a3b8", round: true }];
}

// Edge contributors whose link came from a subdomain (rather than a direct
// apex↔apex match) — these are what we surface when a connection is expanded.
function subdomainContributors(edge) {
  return (edge?.contributors || []).filter((contributor) => contributor.via_subdomain);
}

function formatPathFallback(path) {
  const text = String(path || "");
  if (text.startsWith("observed_ip:")) {
    return "Observed IP address";
  }
  const leaf = text.split(".").pop().replace("[*]", "").replace(/_/g, " ");
  return `Shared ${leaf}`;
}

export default ClusterGraph;
