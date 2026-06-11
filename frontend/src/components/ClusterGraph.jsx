import { memo, useEffect, useMemo, useRef, useState } from "react";
import { drag as d3Drag } from "d3-drag";
import { zoom as d3Zoom, zoomIdentity } from "d3-zoom";
import { select as d3Select } from "d3-selection";

const ClusterGraph = memo(function ClusterGraph({ graph, seedTargets = new Set() }) {
  const initialLayout = useMemo(
    () => buildClusterLayout(graph, seedTargets),
    [graph, seedTargets],
  );
  const [nodePositions, setNodePositions] = useState(() => {
    const map = {};
    for (const n of initialLayout.nodes) {
      map[n.id] = { x: n.x, y: n.y };
    }
    return map;
  });

  useEffect(() => {
    const map = {};
    for (const n of initialLayout.nodes) {
      map[n.id] = { x: n.x, y: n.y };
    }
    setNodePositions(map);
  }, [initialLayout]);

  const svgRef = useRef(null);
  const gRef = useRef(null);

  useEffect(() => {
    if (!svgRef.current || !gRef.current) return;
    const svg = d3Select(svgRef.current);
    const g = d3Select(gRef.current);
    const zoomer = d3Zoom()
      .scaleExtent([0.2, 4])
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
      });
    svg.call(zoomer);
    svg.call(zoomer.transform, zoomIdentity);
    return () => {
      svg.on(".zoom", null);
    };
  }, [initialLayout]);

  useEffect(() => {
    if (!gRef.current) return;
    const g = d3Select(gRef.current);
    const dragger = d3Drag()
      .on("start", function (event) {
        event.sourceEvent.stopPropagation();
        d3Select(this).style("cursor", "grabbing");
      })
      .on("drag", function (event) {
        const nodeId = this.dataset.id;
        setNodePositions((prev) => {
          const cur = prev[nodeId];
          if (!cur) return prev;
          return { ...prev, [nodeId]: { x: cur.x + event.dx, y: cur.y + event.dy } };
        });
      })
      .on("end", function () {
        d3Select(this).style("cursor", "grab");
      });
    g.selectAll(".cluster-node").call(dragger);
    return () => {
      g.selectAll(".cluster-node").on(".drag", null);
    };
  }, [initialLayout]);

  const edges = useMemo(() => {
    return initialLayout.edges.map((edge) => {
      const from = nodePositions[edge.from] ?? { x: edge.x1, y: edge.y1 };
      const to = nodePositions[edge.to] ?? { x: edge.x2, y: edge.y2 };
      return { ...edge, x1: from.x, y1: from.y, x2: to.x, y2: to.y };
    });
  }, [initialLayout.edges, nodePositions]);

  // Render seed edges on top by splitting into two layers
  const normalEdges = edges.filter((e) => !e.isSeedEdge);
  const seedEdges = edges.filter((e) => e.isSeedEdge);

  return (
    <section className="cluster-graph-card">
      <div className="panel-header">
        <div>
          <p className="eyebrow">Diagram</p>
          <h3>Cluster map</h3>
        </div>
        {seedTargets.size > 0 ? (
          <div className="chip-row">
            {[...seedTargets].map((t) => (
              <span className="chip" key={t} style={{ background: "var(--info-soft)", color: "var(--link)" }}>
                {t}
              </span>
            ))}
          </div>
        ) : null}
      </div>
      <svg
        ref={svgRef}
        className="cluster-graph"
        viewBox={`0 0 ${initialLayout.width} ${initialLayout.height}`}
        style={{ cursor: "grab" }}
      >
        <defs>
          <filter id="seed-glow">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <g ref={gRef}>
          {normalEdges.map((edge) => (
            <line
              key={`${edge.from}-${edge.to}`}
              stroke={edge.color || "#94a3b8"}
              strokeWidth={edge.width || 1}
              strokeOpacity={0.45}
              x1={edge.x1}
              x2={edge.x2}
              y1={edge.y1}
              y2={edge.y2}
            />
          ))}
          {seedEdges.map((edge) => (
            <g key={`seed-${edge.from}-${edge.to}`}>
              <line
                stroke="#2752d6"
                strokeWidth={4}
                strokeOpacity={0.18}
                x1={edge.x1}
                x2={edge.x2}
                y1={edge.y1}
                y2={edge.y2}
              />
              <line
                stroke="#2752d6"
                strokeWidth={2.5}
                strokeDasharray="6 3"
                x1={edge.x1}
                x2={edge.x2}
                y1={edge.y1}
                y2={edge.y2}
              />
            </g>
          ))}
          {initialLayout.nodes.map((node) => {
            const pos = nodePositions[node.id] ?? { x: node.x, y: node.y };
            const isSeed = node.isSeed;
            const r = isSeed ? 26 : 18;
            const fill = isSeed ? "#2752d6" : (node.color || "#2752d6");
            return (
              <g
                key={node.id}
                className="cluster-node"
                transform={`translate(${pos.x}, ${pos.y})`}
                style={{ cursor: "grab" }}
                data-id={node.id}
                filter={isSeed ? "url(#seed-glow)" : undefined}
              >
                {isSeed ? (
                  <circle fill="rgba(39,82,214,0.15)" r={r + 8} />
                ) : null}
                <circle fill={fill} r={r} />
                <text
                  className="graph-node-label"
                  textAnchor="middle"
                  y={r + 16}
                  fontWeight={isSeed ? "700" : "400"}
                >
                  {node.label}
                </text>
              </g>
            );
          })}
        </g>
      </svg>
    </section>
  );
});

export default ClusterGraph;

function buildClusterLayout(graph, seedTargets = new Set()) {
  const width = 1080;
  const height = 600;
  const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph?.edges) ? graph.edges : [];

  // Separate seed nodes and place them prominently at the top-centre
  const seedNodes = nodes.filter((n) => seedTargets.has(n.id));
  const nonSeedNodes = nodes.filter((n) => !seedTargets.has(n.id));

  const grouped = new Map();
  nonSeedNodes.forEach((node) => {
    const key = node.cluster ?? node.group ?? "isolate";
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(node);
  });

  const groups = Array.from(grouped.values());
  const layoutNodes = [];
  const byId = new Map();

  // Place seed nodes along the top edge, centered
  const seedSpacing = Math.min(200, width / Math.max(seedNodes.length, 1));
  const seedY = 80;
  seedNodes.forEach((node, i) => {
    const totalWidth = (seedNodes.length - 1) * seedSpacing;
    const x = width / 2 - totalWidth / 2 + i * seedSpacing;
    const laidOutNode = { ...node, x, y: seedY, isSeed: true };
    layoutNodes.push(laidOutNode);
    byId.set(node.id, laidOutNode);
  });

  // Place non-seed groups in the lower area
  const lowerCenterX = width / 2;
  const lowerCenterY = height / 2 + 60;
  const outerRadius = Math.max(100, Math.min(220, 52 * groups.length));

  groups.forEach((groupNodes, groupIndex) => {
    const groupAngle = (Math.PI * 2 * groupIndex) / Math.max(groups.length, 1);
    const groupCenterX =
      groups.length === 1 ? lowerCenterX : lowerCenterX + Math.cos(groupAngle) * outerRadius;
    const groupCenterY =
      groups.length === 1 ? lowerCenterY : lowerCenterY + Math.sin(groupAngle) * Math.min(outerRadius * 0.55, 140);
    const innerRadius = Math.max(24, 18 * groupNodes.length);

    groupNodes.forEach((node, nodeIndex) => {
      const nodeAngle = (Math.PI * 2 * nodeIndex) / Math.max(groupNodes.length, 1);
      const x = groupCenterX + Math.cos(nodeAngle) * (groupNodes.length === 1 ? 0 : innerRadius);
      const y = groupCenterY + Math.sin(nodeAngle) * (groupNodes.length === 1 ? 0 : innerRadius);
      const laidOutNode = { ...node, x, y, isSeed: false };
      layoutNodes.push(laidOutNode);
      byId.set(node.id, laidOutNode);
    });
  });

  const layoutEdges = edges
    .map((edge) => {
      const fromNode = byId.get(edge.from);
      const toNode = byId.get(edge.to);
      if (!fromNode || !toNode) return null;
      const isSeedEdge = seedTargets.has(edge.from) && seedTargets.has(edge.to);
      return {
        ...edge,
        x1: fromNode.x,
        y1: fromNode.y,
        x2: toNode.x,
        y2: toNode.y,
        isSeedEdge,
      };
    })
    .filter(Boolean);

  return { width, height, nodes: layoutNodes, edges: layoutEdges };
}
