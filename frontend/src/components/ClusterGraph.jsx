import { memo, useEffect, useMemo, useRef, useState } from "react";
import { drag as d3Drag } from "d3-drag";
import { zoom as d3Zoom } from "d3-zoom";
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

const SEED_COLOR = "#2752d6";

function edgeTier(edge) {
  return EDGE_TIERS[edge.visual] ? edge.visual : "weak";
}

function truncateLabel(text, max = 28) {
  const value = String(text || "");
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

// Runs the force simulation to completion synchronously so the graph renders
// settled, instead of animating every tick through React state.
function computeLayout(nodes, edges, width, height) {
  const simNodes = nodes.map((node) => ({ ...node }));
  const ids = new Set(simNodes.map((node) => node.id));
  const simEdges = edges
    .filter((edge) => ids.has(edge.from) && ids.has(edge.to))
    .map((edge) => ({ ...edge, source: edge.from, target: edge.to }));

  const degree = new Map();
  simEdges.forEach((edge) => {
    degree.set(edge.from, (degree.get(edge.from) || 0) + 1);
    degree.set(edge.to, (degree.get(edge.to) || 0) + 1);
  });
  simNodes.forEach((node) => {
    node.degree = degree.get(node.id) || 0;
    node.radius = node.kind === "ip" ? 5 : Math.min(22, 11 + node.degree * 1.2);
  });

  const simulation = forceSimulation(simNodes)
    .force(
      "link",
      forceLink(simEdges)
        .id((node) => node.id)
        .distance((edge) => (edgeTier(edge) === "strong" ? 70 : edgeTier(edge) === "infra" ? 110 : 150))
        .strength((edge) => (edgeTier(edge) === "weak" ? 0.25 : 0.6)),
    )
    .force("charge", forceManyBody().strength(-260))
    .force("center", forceCenter(width / 2, height / 2))
    .force("collide", forceCollide().radius((node) => node.radius + 16))
    .force("x", forceX(width / 2).strength(0.06))
    .force("y", forceY(height / 2).strength(0.08))
    .stop();

  const ticks = Math.min(300, Math.max(120, simNodes.length * 4));
  for (let i = 0; i < ticks; i += 1) {
    simulation.tick();
  }

  // Keep every node inside the viewport with a margin for labels.
  const margin = 40;
  simNodes.forEach((node) => {
    node.x = Math.max(margin, Math.min(width - margin, node.x));
    node.y = Math.max(margin, Math.min(height - margin, node.y));
  });

  return { nodes: simNodes, edges: simEdges };
}

const ClusterGraph = memo(function ClusterGraph({ graph, seedTargets = new Set() }) {
  const containerRef = useRef(null);
  const svgRef = useRef(null);
  const gRef = useRef(null);
  const [width, setWidth] = useState(960);
  const [showIps, setShowIps] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);
  const height = Math.max(420, Math.min(640, Math.round(width * 0.55)));

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
    () => allNodes.filter((node) => node.kind === "ip" || looksLikeIp(node.id)).length,
    [allNodes],
  );

  const visibleNodes = useMemo(() => {
    if (showIps) {
      return allNodes;
    }
    return allNodes.filter((node) => node.kind !== "ip" && !looksLikeIp(node.id));
  }, [allNodes, showIps]);

  const layout = useMemo(
    () => computeLayout(visibleNodes, allEdges, width, height),
    [visibleNodes, allEdges, width, height],
  );

  // Node positions live outside React state during drag for responsiveness;
  // this state only holds overrides created by dragging.
  const [dragPositions, setDragPositions] = useState({});
  useEffect(() => {
    setDragPositions({});
    setSelectedNode(null);
    setSelectedEdge(null);
  }, [layout]);

  const positions = useMemo(() => {
    const map = {};
    layout.nodes.forEach((node) => {
      map[node.id] = dragPositions[node.id] || { x: node.x, y: node.y };
    });
    return map;
  }, [layout.nodes, dragPositions]);

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
    svg.call(zoomer);
    return () => {
      svg.on(".zoom", null);
    };
  }, [layout]);

  useEffect(() => {
    if (!gRef.current) {
      return undefined;
    }
    const g = d3Select(gRef.current);
    const dragger = d3Drag()
      .on("start", function start(event) {
        event.sourceEvent.stopPropagation();
        d3Select(this).style("cursor", "grabbing");
      })
      .on("drag", function move(event) {
        const nodeId = this.dataset.id;
        setDragPositions((previous) => {
          const base = previous[nodeId] ||
            layout.nodes.find((node) => node.id === nodeId) || { x: 0, y: 0 };
          return { ...previous, [nodeId]: { x: base.x + event.dx, y: base.y + event.dy } };
        });
      })
      .on("end", function end() {
        d3Select(this).style("cursor", "grab");
      });
    g.selectAll(".cluster-node").call(dragger);
    return () => {
      g.selectAll(".cluster-node").on(".drag", null);
    };
  }, [layout]);

  const neighborIds = useMemo(() => {
    if (!selectedNode) {
      return null;
    }
    const ids = new Set([selectedNode]);
    layout.edges.forEach((edge) => {
      if (edge.from === selectedNode) {
        ids.add(edge.to);
      }
      if (edge.to === selectedNode) {
        ids.add(edge.from);
      }
    });
    return ids;
  }, [selectedNode, layout.edges]);

  const selectedEdgeData = useMemo(() => {
    if (!selectedEdge) {
      return null;
    }
    return (
      layout.edges.find((edge) => `${edge.from}|${edge.to}` === selectedEdge) || null
    );
  }, [selectedEdge, layout.edges]);

  const selectedNodeEdges = useMemo(() => {
    if (!selectedNode) {
      return [];
    }
    return layout.edges
      .filter((edge) => edge.from === selectedNode || edge.to === selectedNode)
      .sort((a, b) => (b.score || 0) - (a.score || 0));
  }, [selectedNode, layout.edges]);

  const handleNodeClick = (nodeId) => {
    setSelectedEdge(null);
    setSelectedNode((current) => (current === nodeId ? null : nodeId));
  };

  const handleEdgeClick = (edge) => {
    setSelectedNode(null);
    setSelectedEdge((current) => {
      const key = `${edge.from}|${edge.to}`;
      return current === key ? null : key;
    });
  };

  if (allNodes.length === 0) {
    return null;
  }

  return (
    <section className="cluster-graph-card" ref={containerRef}>
      <div className="panel-header">
        <div>
          <p className="eyebrow">Connection map</p>
          <h3>How the domains link together</h3>
          <p className="section-copy">
            Each circle is a domain; lines show shared evidence. Click a line to see
            exactly what two domains have in common, or click a domain to highlight its
            connections. Drag to rearrange, scroll to zoom.
          </p>
        </div>
        {ipCount > 0 ? (
          <label className="graph-toggle">
            <input
              checked={showIps}
              onChange={(event) => setShowIps(event.target.checked)}
              type="checkbox"
            />
            Show the {ipCount} shared IP address{ipCount === 1 ? "" : "es"}
          </label>
        ) : null}
      </div>

      <div className="graph-legend" aria-label="Map legend">
        {Object.entries(EDGE_TIERS).map(([key, tier]) => (
          <span className="graph-legend-item" key={key}>
            <span className="graph-legend-swatch" style={{ background: tier.color }} />
            {tier.label}
          </span>
        ))}
        <span className="graph-legend-item">
          <span
            className="graph-legend-swatch round"
            style={{ background: SEED_COLOR }}
          />
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
        <g ref={gRef}>
          {layout.edges.map((edge) => {
            const from = positions[edge.from];
            const to = positions[edge.to];
            if (!from || !to) {
              return null;
            }
            const key = `${edge.from}|${edge.to}`;
            const tier = edgeTier(edge);
            const isSelected = selectedEdge === key;
            const dimmed =
              (neighborIds && edge.from !== selectedNode && edge.to !== selectedNode) ||
              (selectedEdge && !isSelected);
            return (
              <g key={key}>
                <line
                  className="graph-edge-hit"
                  onClick={() => handleEdgeClick(edge)}
                  stroke="transparent"
                  strokeWidth={14}
                  x1={from.x}
                  x2={to.x}
                  y1={from.y}
                  y2={to.y}
                />
                <line
                  pointerEvents="none"
                  stroke={EDGE_TIERS[tier].color}
                  strokeOpacity={dimmed ? 0.12 : isSelected ? 0.95 : 0.55}
                  strokeWidth={isSelected ? (edge.width || 1.5) + 1.5 : edge.width || 1.5}
                  x1={from.x}
                  x2={to.x}
                  y1={from.y}
                  y2={to.y}
                />
              </g>
            );
          })}
          {layout.nodes.map((node) => {
            const pos = positions[node.id];
            const isSeed = seedTargets.has(node.id);
            const isIp = node.kind === "ip" || looksLikeIp(node.id);
            const dimmed = neighborIds && !neighborIds.has(node.id);
            const fill = isSeed ? SEED_COLOR : node.color || "#64748b";
            return (
              <g
                className="cluster-node"
                data-id={node.id}
                key={node.id}
                onClick={() => handleNodeClick(node.id)}
                opacity={dimmed ? 0.25 : 1}
                style={{ cursor: "grab" }}
                transform={`translate(${pos.x}, ${pos.y})`}
              >
                {isSeed ? (
                  <circle fill="rgba(39, 82, 214, 0.16)" r={node.radius + 7} />
                ) : null}
                {isIp ? (
                  <rect
                    fill={fill}
                    height={node.radius * 2}
                    rx={2}
                    width={node.radius * 2}
                    x={-node.radius}
                    y={-node.radius}
                  />
                ) : (
                  <circle
                    fill={fill}
                    r={node.radius}
                    stroke={selectedNode === node.id ? "var(--text)" : "transparent"}
                    strokeWidth={2}
                  />
                )}
                <text
                  className={`graph-node-label ${isIp ? "ip" : ""}`}
                  fontWeight={isSeed ? 700 : 400}
                  textAnchor="middle"
                  y={node.radius + 14}
                >
                  {truncateLabel(node.label)}
                </text>
              </g>
            );
          })}
        </g>
      </svg>

      {selectedEdgeData ? (
        <div className="graph-detail-panel">
          <strong>
            {selectedEdgeData.from} ↔ {selectedEdgeData.to}
          </strong>
          <p className="card-copy">What these two have in common:</p>
          <ul className="simple-list">
            {(selectedEdgeData.labels && selectedEdgeData.labels.length > 0
              ? selectedEdgeData.labels
              : (selectedEdgeData.paths || []).map(formatPathFallback)
            ).map((label) => (
              <li key={label}>{label}</li>
            ))}
          </ul>
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

function looksLikeIp(value) {
  return /^[\d.]+$/.test(String(value || "")) || String(value || "").includes(":");
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
