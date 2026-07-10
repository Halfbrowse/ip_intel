import { memo, useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
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

// Evidence-edge tiers — colour encodes connection STRENGTH only (the score),
// never the kind of evidence behind it (a strong link can be a cert match, a
// shared IP, or several weaker signals stacked together). What actually ties
// two nodes together is shown in the detail panel on click, not by colour.
const EDGE_TIERS = {
  strong: { color: "#dc2626", label: "Strong (score 65+)" },
  moderate: { color: "#f97316", label: "Moderate (score 30–64)" },
  weak: { color: "#94a3b8", label: "Weak (score below 30)" },
};
const TIER_ORDER = ["strong", "moderate", "weak"];

// Domain classification tiers (1-5, from OpenCTI channel labels — see
// integrations/opencti_ingest.py). Unrelated to EDGE_TIERS above (that's
// link strength; this is a per-domain attribute) — kept as a hot-to-cool
// severity scale so tier 1 (highest confidence/priority) reads as the most
// alarming colour and tier 5 the least, same convention as SIEM severity.
const DOMAIN_TIER_COLORS = {
  1: "#b91c1c",
  2: "#ea580c",
  3: "#ca8a04",
  4: "#2563eb",
  5: "#64748b",
};
const DOMAIN_TIER_LABELS = {
  1: "Tier 1",
  2: "Tier 2",
  3: "Tier 3",
  4: "Tier 4",
  5: "Tier 5",
};
const DOMAIN_TIER_ORDER = [1, 2, 3, 4, 5];

function domainTierColor(node) {
  return DOMAIN_TIER_COLORS[node?.tier] || null;
}

// Node roles. The graph now only ever contains two kinds of node:
//   submitted — a domain the user asked about (the anchors of the map)
//   bridge    — a subdomain that links one submitted domain to another
const SUBMITTED_COLOR = "#2752d6";
const BRIDGE_COLOR = "#0ea5e9";
// Faint tie connecting a bridge subdomain back to the domain it belongs to.
const MEMBERSHIP_COLOR = "#cbd5e1";
// Selection ring — deliberately outside both role colours (blue/slate) so
// "this is the node you clicked" never gets mistaken for its role colour.
const SELECTION_RING_COLOR = "#f59e0b";

const LABEL_MODES = {
  auto: { label: "Auto" },
  hubs: { label: "Hubs only" },
  all: { label: "All" },
  none: { label: "None" },
};
const UNCLASSIFIED_TIER = "unclassified";
const ROLE_FILTERS = {
  submitted: "Anchors",
  related: "Related",
};

function allTrue(items) {
  return Object.fromEntries(items.map((item) => [item, true]));
}

function edgeKey(edge) {
  return `${edge.from}|${edge.to}`;
}

function isActivationKey(event) {
  return event.key === "Enter" || event.key === " ";
}

function edgeKind(edge) {
  return edge.kind || "evidence";
}

function edgeTier(edge) {
  return EDGE_TIERS[edge.visual] ? edge.visual : "weak";
}

function isSubmitted(node, seeds) {
  return node.role === "submitted" || seeds.has(node.id);
}

function nodeRole(node, seeds) {
  return isSubmitted(node, seeds) ? "submitted" : "related";
}

function nodeTierKey(node) {
  return DOMAIN_TIER_COLORS[node?.tier] ? String(node.tier) : UNCLASSIFIED_TIER;
}

function evidenceType(edge) {
  const first = evidenceLabels(edge)[0] || "Relationship";
  const separator = String(first).indexOf(": ");
  return separator === -1 ? String(first) : String(first).slice(0, separator);
}

function includesNeedle(value, needle) {
  return String(value || "").toLowerCase().includes(needle);
}

function todayLabel() {
  return new Date().toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" });
}

function truncateLabel(text, max = 28) {
  const value = String(text || "");
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

// The line label only ever names the strongest/first piece of evidence
// (e.g. "TLS certificate: sha256:8f2c..." -> "TLS certificate") — a domain
// pair can share several selectors at once, but naming all of them on the
// line the way OpenCTI names a single STIX relationship type would just
// turn into a wall of text; the full list is still one click away.
function shortEvidenceLabel(label) {
  const text = String(label || "");
  const separator = text.indexOf(": ");
  return separator === -1 ? truncateLabel(text, 22) : truncateLabel(text.slice(0, separator), 22);
}

function evidenceLabels(edge) {
  return edge.labels && edge.labels.length > 0 ? edge.labels : (edge.paths || []).map(formatPathFallback);
}

function edgeAccessibleLabel(edge) {
  const labels = evidenceLabels(edge);
  const score = Number.isFinite(edge.score) ? `, score ${edge.score}` : "";
  return `${edge.from} to ${edge.to}${score}${labels.length > 0 ? `. ${labels.slice(0, 2).join(", ")}` : ""}`;
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Vanilla-JS renderer embedded verbatim into the exported interactive report
// (buildInteractiveHtml below) — no external dependencies, so the file still
// works when a recipient just double-clicks it, offline, with no server and
// no build step. Every piece of graph data (labels, evidence text) is written
// to the DOM via textContent/createElement, never innerHTML, so a hostile
// domain name or evidence value in the underlying data can't inject markup
// into a report someone else opens later.
const INTERACTIVE_RENDERER_JS = `
(function () {
  var DATA = window.__GRAPH_DATA__;
  var ns = "http://www.w3.org/2000/svg";
  var svg = document.getElementById("stage");
  var detail = document.getElementById("detail");

  document.getElementById("doc-title").textContent = DATA.title;
  document.getElementById("doc-generated").textContent =
    "Generated " + DATA.generated + " \\u00b7 lines show shared hosting/registration evidence between domains, not guesses";
  var captionEl = document.getElementById("doc-caption");
  captionEl.textContent = DATA.caption;
  if (DATA.filtered) captionEl.classList.add("warn");

  var legend = document.getElementById("legend");
  function legendItem(swatchClass, color, label) {
    var item = document.createElement("span");
    item.className = "item";
    var sw = document.createElement("span");
    sw.className = "swatch " + swatchClass;
    sw.style.background = color;
    var text = document.createElement("span");
    text.textContent = label;
    item.appendChild(sw);
    item.appendChild(text);
    legend.appendChild(item);
  }
  var seedCount = DATA.nodes.filter(function (n) { return n.seed; }).length;
  var otherCount = DATA.nodes.length - seedCount;
  legendItem("", DATA.seedColor, DATA.seedLabel + " (" + seedCount + ")");
  if (otherCount > 0) legendItem("", DATA.otherColor, DATA.otherLabel + " (" + otherCount + ")");
  ["strong", "moderate", "weak"].forEach(function (tier) {
    legendItem("bar", DATA.tierColors[tier], DATA.tierLabels[tier]);
  });
  var presentDomainTiers = [];
  DATA.nodes.forEach(function (n) {
    if (n.tier && presentDomainTiers.indexOf(n.tier) === -1) presentDomainTiers.push(n.tier);
  });
  presentDomainTiers.sort();
  presentDomainTiers.forEach(function (tier) {
    legendItem("", DATA.domainTierColors[tier], DATA.domainTierLabels[tier]);
  });

  svg.setAttribute("viewBox", "0 0 " + DATA.width + " " + DATA.height);

  var view = document.createElementNS(ns, "g");
  svg.appendChild(view);

  var byId = {};
  DATA.nodes.forEach(function (n) { byId[n.id] = n; });

  function midpoint(from, to) {
    return { x: (from.x + to.x) / 2, y: (from.y + to.y) / 2 };
  }

  function shortEvidenceLabel(label) {
    var text = String(label || "");
    var sep = text.indexOf(": ");
    var name = sep === -1 ? text : text.slice(0, sep);
    return name.length > 22 ? name.slice(0, 21) + "\\u2026" : name;
  }

  // Matches the live app: past this many edges, inline labels would just
  // pile up unreadably on a busy hub, so skip them and lean on click-for-
  // detail (still available either way) instead.
  var showInlineEdgeLabels = DATA.edges.length <= 10;

  var edgeLines = [];
  DATA.edges.forEach(function (e) {
    var from = byId[e.from], to = byId[e.to];
    if (!from || !to) return;
    var group = document.createElementNS(ns, "g");
    var stroke = document.createElementNS(ns, "line");
    stroke.setAttribute("stroke", DATA.tierColors[e.tier] || "#94a3b8");
    stroke.setAttribute("stroke-width", String(e.width || 1.5));
    stroke.setAttribute("stroke-opacity", "0.55");
    var hit = document.createElementNS(ns, "line");
    hit.setAttribute("class", "edge-hit");
    hit.setAttribute("stroke", "transparent");
    hit.setAttribute("stroke-width", "14");
    [stroke, hit].forEach(function (line) {
      line.setAttribute("x1", from.x); line.setAttribute("y1", from.y);
      line.setAttribute("x2", to.x); line.setAttribute("y2", to.y);
    });
    group.appendChild(stroke);
    group.appendChild(hit);

    // Names the strongest piece of evidence right on the line (e.g. "TLS
    // certificate"), same idea as a labelled relationship in a knowledge
    // graph, so the kind of link is visible without clicking.
    var labelGroup = null;
    var labelBg = null;
    if (showInlineEdgeLabels && e.labels && e.labels.length > 0) {
      labelGroup = document.createElementNS(ns, "g");
      labelBg = document.createElementNS(ns, "rect");
      labelBg.setAttribute("rx", "3");
      labelBg.setAttribute("fill", "#f8fafc");
      var labelText = document.createElementNS(ns, "text");
      labelText.setAttribute("text-anchor", "middle");
      labelText.setAttribute("dy", "0.32em");
      labelText.setAttribute("font-size", "10");
      labelText.setAttribute("fill", "#475569");
      labelText.textContent = shortEvidenceLabel(e.labels[0]);
      labelGroup.appendChild(labelBg);
      labelGroup.appendChild(labelText);
      view.appendChild(labelGroup);
      var mid = midpoint(from, to);
      labelGroup.setAttribute("transform", "translate(" + mid.x + "," + mid.y + ")");
      var box = labelText.getBBox();
      labelBg.setAttribute("x", box.x - 4);
      labelBg.setAttribute("y", box.y - 1.5);
      labelBg.setAttribute("width", box.width + 8);
      labelBg.setAttribute("height", box.height + 3);
    }

    hit.addEventListener("click", function (ev) { ev.stopPropagation(); showEdge(e); });
    view.appendChild(group);
    edgeLines.push({ edge: e, from: from, to: to, hit: hit, stroke: stroke, labelGroup: labelGroup });
  });

  function makeDraggable(g, n) {
    var dragging = false, startX = 0, startY = 0;
    g.addEventListener("mousedown", function (ev) {
      dragging = true; startX = ev.clientX; startY = ev.clientY;
      ev.stopPropagation(); ev.preventDefault();
    });
    window.addEventListener("mousemove", function (ev) {
      if (!dragging) return;
      var dx = (ev.clientX - startX) / scale, dy = (ev.clientY - startY) / scale;
      startX = ev.clientX; startY = ev.clientY;
      n.x += dx; n.y += dy;
      g.setAttribute("transform", "translate(" + n.x + "," + n.y + ")");
      edgeLines.forEach(function (el) {
        if (el.from === n || el.to === n) {
          el.hit.setAttribute("x1", el.from.x); el.hit.setAttribute("y1", el.from.y);
          el.hit.setAttribute("x2", el.to.x); el.hit.setAttribute("y2", el.to.y);
          el.stroke.setAttribute("x1", el.from.x); el.stroke.setAttribute("y1", el.from.y);
          el.stroke.setAttribute("x2", el.to.x); el.stroke.setAttribute("y2", el.to.y);
          if (el.labelGroup) {
            var mid = midpoint(el.from, el.to);
            el.labelGroup.setAttribute("transform", "translate(" + mid.x + "," + mid.y + ")");
          }
        }
      });
    });
    window.addEventListener("mouseup", function () { dragging = false; });
  }

  DATA.nodes.forEach(function (n) {
    var g = document.createElementNS(ns, "g");
    g.setAttribute("class", "node");
    g.setAttribute("transform", "translate(" + n.x + "," + n.y + ")");
    if (n.seed) {
      var ring = document.createElementNS(ns, "circle");
      ring.setAttribute("r", n.radius + 5);
      ring.setAttribute("fill", "none");
      ring.setAttribute("stroke", DATA.seedColor);
      ring.setAttribute("stroke-opacity", "0.45");
      ring.setAttribute("stroke-width", "2");
      g.appendChild(ring);
    }
    var circle = document.createElementNS(ns, "circle");
    circle.setAttribute("r", n.radius);
    circle.setAttribute(
      "fill",
      (n.tier && DATA.domainTierColors[n.tier]) || (n.seed ? DATA.seedColor : DATA.otherColor),
    );
    circle.setAttribute("stroke", "#fff");
    circle.setAttribute("stroke-width", "1.5");
    g.appendChild(circle);

    // Every node is a domain, so every node gets the same minimal "globe"
    // glyph rather than a flat dot -- an icon-in-a-circle reads as a
    // knowledge-graph entity, not a bubble-chart point.
    var iconR = Math.max(3, n.radius * 0.52);
    var iconStroke = Math.max(0.75, iconR * 0.12);
    var meridian = document.createElementNS(ns, "circle");
    meridian.setAttribute("r", iconR);
    meridian.setAttribute("fill", "none");
    meridian.setAttribute("stroke", "rgba(255,255,255,0.85)");
    meridian.setAttribute("stroke-width", String(iconStroke));
    g.appendChild(meridian);
    var equator = document.createElementNS(ns, "ellipse");
    equator.setAttribute("rx", iconR);
    equator.setAttribute("ry", iconR * 0.42);
    equator.setAttribute("fill", "none");
    equator.setAttribute("stroke", "rgba(255,255,255,0.85)");
    equator.setAttribute("stroke-width", String(iconStroke));
    g.appendChild(equator);
    var axis = document.createElementNS(ns, "line");
    axis.setAttribute("y1", String(-iconR));
    axis.setAttribute("y2", String(iconR));
    axis.setAttribute("stroke", "rgba(255,255,255,0.85)");
    axis.setAttribute("stroke-width", String(iconStroke));
    g.appendChild(axis);

    var text = document.createElementNS(ns, "text");
    text.setAttribute("text-anchor", "middle");
    text.setAttribute("y", n.radius + 14);
    text.setAttribute("font-weight", n.seed ? "700" : "400");
    text.textContent = n.label;
    g.appendChild(text);
    g.addEventListener("click", function (ev) { ev.stopPropagation(); showNode(n); });
    makeDraggable(g, n);
    view.appendChild(g);
  });

  var scale = 1, panX = 0, panY = 0;
  function applyView() {
    view.setAttribute("transform", "translate(" + panX + "," + panY + ") scale(" + scale + ")");
  }
  svg.addEventListener("wheel", function (ev) {
    ev.preventDefault();
    var factor = ev.deltaY < 0 ? 1.1 : 0.9;
    scale = Math.min(4, Math.max(0.3, scale * factor));
    applyView();
  }, { passive: false });

  var panning = false, panStartX = 0, panStartY = 0;
  svg.addEventListener("mousedown", function (ev) {
    if (ev.target !== svg) return;
    panning = true; panStartX = ev.clientX - panX; panStartY = ev.clientY - panY;
    svg.classList.add("grabbing");
  });
  window.addEventListener("mousemove", function (ev) {
    if (!panning) return;
    panX = ev.clientX - panStartX; panY = ev.clientY - panStartY;
    applyView();
  });
  window.addEventListener("mouseup", function () { panning = false; svg.classList.remove("grabbing"); });

  function clearDetail() { detail.style.display = "none"; detail.textContent = ""; }
  svg.addEventListener("click", clearDetail);

  function detailHeader(titleText) {
    detail.textContent = "";
    var close = document.createElement("button");
    close.className = "close";
    close.type = "button";
    close.textContent = "Close";
    close.addEventListener("click", clearDetail);
    detail.appendChild(close);
    var h3 = document.createElement("h3");
    h3.textContent = titleText;
    detail.appendChild(h3);
    detail.style.display = "block";
  }

  function showEdge(e) {
    detailHeader(e.from + " \\u2194 " + e.to);
    var selected = document.createElement("p");
    selected.textContent = "Selected link: " + e.from + " to " + e.to;
    detail.appendChild(selected);
    var p = document.createElement("p");
    p.textContent = "What these two have in common:";
    detail.appendChild(p);
    var ul = document.createElement("ul");
    (e.labels.length ? e.labels : ["No evidence details recorded."]).forEach(function (label) {
      var li = document.createElement("li");
      li.textContent = label;
      ul.appendChild(li);
    });
    detail.appendChild(ul);
  }

  function showNode(n) {
    var related = DATA.edges
      .filter(function (e) { return e.from === n.id || e.to === n.id; })
      .sort(function (a, b) { return (b.score || 0) - (a.score || 0); });
    detailHeader(n.label);
    var p = document.createElement("p");
    p.textContent = "Selected domain: " + n.label;
    detail.appendChild(p);
    var summary = document.createElement("p");
    summary.textContent = "Visible relationships: " + related.length;
    detail.appendChild(summary);
  }
})();
`;

const ClusterGraph = memo(function ClusterGraph({
  graph,
  seedTargets = new Set(),
  renderPairEvidence = null,
  otherRoleColor = BRIDGE_COLOR,
  otherRoleLabel = "Bridging subdomain",
  seedRoleLabel = "Channel in this cluster",
  title = "How this cluster's channels link together",
  description = "Shared infrastructure and registration evidence, with warmer links carrying stronger scores.",
  exportFileName = "network-graph",
}) {
  const statusId = useId();
  const containerRef = useRef(null);
  const svgRef = useRef(null);
  const gRef = useRef(null);
  const simulationRef = useRef(null);
  // Latest simulation node array (with live x/y) so export can bake in the
  // exact on-screen layout rather than recomputing/guessing positions.
  const simNodesRef = useRef([]);
  const zoomRef = useRef(null);
  // Live references to the rendered D3 selections so the styling effect can
  // restyle without tearing down and restarting the force simulation.
  const selectionsRef = useRef({ node: null, link: null, edgeLabel: null });

  const [width, setWidth] = useState(960);
  const height = Math.max(460, Math.min(680, Math.round(width * 0.58)));

  // Presentation controls — deliberately lean. The map only shows submitted
  // domains and their bridges, so there's no node-colour/size lens to pick.
  const [labelMode, setLabelMode] = useState("auto");
  const [tierFilter, setTierFilter] = useState({ strong: true, moderate: true, weak: true });
  const [minScore, setMinScore] = useState(0);
  const [spread, setSpread] = useState(1);
  const [narrowSelection, setNarrowSelection] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState({ submitted: true, related: true });
  const [domainTierFilter, setDomainTierFilter] = useState({
    1: true,
    2: true,
    3: true,
    4: true,
    5: true,
    [UNCLASSIFIED_TIER]: true,
  });
  const [evidenceTypeFilter, setEvidenceTypeFilter] = useState({});

  // Selection drives the detail panels below the map.
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [hoveredEdge, setHoveredEdge] = useState(null);
  const selectedRef = useRef({ node: null, edge: null });
  selectedRef.current = { node: selectedNode, edge: selectedEdge };

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
  const nodeById = useMemo(
    () => new Map(allNodes.map((node) => [node.id, node])),
    [allNodes],
  );
  const searchNeedle = searchQuery.trim().toLowerCase();
  const evidenceTypes = useMemo(() => {
    const labels = new Set();
    allEdges.forEach((edge) => {
      if (edgeKind(edge) === "evidence") {
        labels.add(evidenceType(edge));
      }
    });
    return [...labels].sort((a, b) => a.localeCompare(b));
  }, [allEdges]);
  const maxScore = useMemo(
    () =>
      allEdges.reduce(
        (max, edge) => (edgeKind(edge) === "evidence" ? Math.max(max, edge.score || 0) : max),
        0,
      ),
    [allEdges],
  );

  const nodeCriteriaIds = useMemo(() => {
    const ids = new Set();
    allNodes.forEach((node) => {
      const role = nodeRole(node, seedTargets);
      if (!roleFilter[role]) {
        return;
      }
      if (!domainTierFilter[nodeTierKey(node)]) {
        return;
      }
      ids.add(node.id);
    });
    return ids;
  }, [allNodes, seedTargets, roleFilter, domainTierFilter]);

  const edgeMatchesSearch = useCallback(
    (edge) => {
      if (!searchNeedle) {
        return true;
      }
      const from = nodeById.get(edge.from);
      const to = nodeById.get(edge.to);
      return (
        includesNeedle(edge.from, searchNeedle) ||
        includesNeedle(edge.to, searchNeedle) ||
        includesNeedle(from?.label, searchNeedle) ||
        includesNeedle(to?.label, searchNeedle) ||
        evidenceLabels(edge).some((label) => includesNeedle(label, searchNeedle))
      );
    },
    [nodeById, searchNeedle],
  );

  // Evidence edges that survive the knowledge filters. These are the actual
  // relationships between domains; membership ties are handled separately.
  const visibleEvidence = useMemo(() => {
    return allEdges.filter(
      (edge) =>
        edgeKind(edge) === "evidence" &&
        nodeCriteriaIds.has(edge.from) &&
        nodeCriteriaIds.has(edge.to) &&
        tierFilter[edgeTier(edge)] &&
        (edge.score || 0) >= minScore &&
        evidenceTypeFilter[evidenceType(edge)] !== false &&
        edgeMatchesSearch(edge),
    );
  }, [allEdges, nodeCriteriaIds, tierFilter, minScore, evidenceTypeFilter, edgeMatchesSearch]);

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
      if (ids.has(edge.to) && nodeCriteriaIds.has(edge.from)) ids.add(edge.from);
    });
    return ids;
  }, [visibleEvidence, allEdges, nodeCriteriaIds]);

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

  const selectedScope = useMemo(() => {
    if (selectedNode) {
      const ids = new Set([selectedNode]);
      const edgeKeys = new Set();
      visibleEdges.forEach((edge) => {
        if (edge.from === selectedNode || edge.to === selectedNode) {
          ids.add(edge.from);
          ids.add(edge.to);
          edgeKeys.add(edgeKey(edge));
        }
      });
      return { ids, edgeKeys };
    }
    if (selectedEdge) {
      const edge = visibleEvidence.find((candidate) => edgeKey(candidate) === selectedEdge);
      return edge ? { ids: new Set([edge.from, edge.to]), edgeKeys: new Set([selectedEdge]) } : null;
    }
    return null;
  }, [selectedNode, selectedEdge, visibleEdges, visibleEvidence]);

  const hoverScope = useMemo(() => {
    if (hoveredNode) {
      const ids = new Set([hoveredNode]);
      const edgeKeys = new Set();
      visibleEdges.forEach((edge) => {
        if (edge.from === hoveredNode || edge.to === hoveredNode) {
          ids.add(edge.from);
          ids.add(edge.to);
          edgeKeys.add(edgeKey(edge));
        }
      });
      return { ids, edgeKeys };
    }
    if (hoveredEdge) {
      const edge = visibleEvidence.find((candidate) => edgeKey(candidate) === hoveredEdge);
      return edge ? { ids: new Set([edge.from, edge.to]), edgeKeys: new Set([hoveredEdge]) } : null;
    }
    return null;
  }, [hoveredNode, hoveredEdge, visibleEdges, visibleEvidence]);

  const activeScope = useMemo(() => {
    if (!hoverScope) return selectedScope;
    if (!selectedScope) return hoverScope;
    return {
      ids: new Set([...selectedScope.ids, ...hoverScope.ids]),
      edgeKeys: new Set([...selectedScope.edgeKeys, ...hoverScope.edgeKeys]),
    };
  }, [hoverScope, selectedScope]);

  const displayNodes = useMemo(
    () =>
      narrowSelection && selectedScope
        ? visibleNodes.filter((node) => selectedScope.ids.has(node.id))
        : visibleNodes,
    [visibleNodes, selectedScope, narrowSelection],
  );
  const displayEdges = useMemo(
    () =>
      narrowSelection && selectedScope
        ? visibleEdges.filter((edge) => selectedScope.ids.has(edge.from) && selectedScope.ids.has(edge.to))
        : visibleEdges,
    [visibleEdges, selectedScope, narrowSelection],
  );

  const clearFocus = useCallback(() => {
    setSelectedNode(null);
    setSelectedEdge(null);
    setHoveredNode(null);
    setHoveredEdge(null);
    setNarrowSelection(false);
  }, []);

  const resetKnowledgeFilters = useCallback(() => {
    setSearchQuery("");
    setRoleFilter({ submitted: true, related: true });
    setDomainTierFilter({
      1: true,
      2: true,
      3: true,
      4: true,
      5: true,
      [UNCLASSIFIED_TIER]: true,
    });
    setEvidenceTypeFilter(allTrue(evidenceTypes));
    setTierFilter({ strong: true, moderate: true, weak: true });
    setMinScore(0);
    clearFocus();
  }, [clearFocus, evidenceTypes]);

  useEffect(() => {
    const selectedNodeHidden = selectedNode && !visibleNodes.some((node) => node.id === selectedNode);
    const selectedEdgeHidden = selectedEdge && !visibleEvidence.some((edge) => edgeKey(edge) === selectedEdge);
    if (selectedNodeHidden || selectedEdgeHidden) {
      clearFocus();
    }
  }, [clearFocus, selectedEdge, selectedNode, visibleEvidence, visibleNodes]);

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
    (node) => domainTierColor(node) || (isSubmitted(node, seedTargets) ? SUBMITTED_COLOR : otherRoleColor),
    [seedTargets, otherRoleColor],
  );

  const handleNodeClick = useCallback((nodeId) => {
    const isSameSelection = selectedRef.current.node === nodeId;
    setSelectedEdge(null);
    setSelectedNode(isSameSelection ? null : nodeId);
    if (isSameSelection) {
      setNarrowSelection(false);
    }
  }, []);

  const handleEdgeClick = useCallback((edge) => {
    const key = edgeKey(edge);
    const isSameSelection = selectedRef.current.edge === key;
    setSelectedNode(null);
    setSelectedEdge(isSameSelection ? null : key);
    if (isSameSelection) {
      setNarrowSelection(false);
    }
  }, []);

  // Latest presentation state, read by applyStyles at call-time. Keeping this in
  // a ref lets applyStyles stay referentially stable (empty deps) so the build
  // effect can call it without rebuilding the simulation on every recolour.
  const styleRef = useRef({});
  styleRef.current = {
    activeScope,
    colorFor,
    displayEdgeCount: displayEdges.filter((edge) => edgeKind(edge) === "evidence").length,
    displayNodeCount: displayNodes.length,
    hoveredNode,
    hoveredEdge,
    labelMode,
    metrics,
    seedTargets,
    selectedNode,
    selectedEdge,
  };

  // Apply colour / label / highlight to the existing selections in place.
  // Selection and hover are pure presentation now: the full filtered graph
  // stays on screen unless the user explicitly narrows it, while unrelated
  // nodes/edges dim out of the way.
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
      hoveredNode: hoverNode,
      hoveredEdge: hoverEdge,
      metrics: nodeMetrics,
      seedTargets: seeds,
      activeScope: scope,
      displayNodeCount,
      displayEdgeCount,
    } = styleRef.current;

    const labelThreshold = Math.max(2, Math.ceil(nodeMetrics.maxDegree * 0.4));
    const showAllAutoLabels = displayNodeCount <= 18 && displayEdgeCount <= 24;
    const hasActiveScope = Boolean(scope);
    node
      .classed("is-dimmed", (d) => hasActiveScope && !scope.ids.has(d.id))
      .classed("is-selected", (d) => selNode === d.id)
      .classed("is-hovered", (d) => hoverNode === d.id)
      .style("opacity", (d) => (hasActiveScope && !scope.ids.has(d.id) ? 0.22 : 1));
    node
      .select("circle.graph-marker")
      .attr("fill", (d) => color(d))
      .attr("stroke", (d) => {
        if (selNode === d.id) return SELECTION_RING_COLOR;
        if (hoverNode === d.id) return "var(--accent, #0a7ea4)";
        return "var(--graph-node-ring, #fff)";
      })
      .attr("stroke-width", (d) => (selNode === d.id || hoverNode === d.id ? 3.25 : 1.75));
    node
      .select("text.graph-node-label")
      .attr("font-weight", (d) => (isSubmitted(d, seeds) ? 700 : 400))
      .style("display", (d) => {
        if (labels === "none") return "none";
        if (hasActiveScope) return scope.ids.has(d.id) ? null : "none";
        if (labels === "auto" && showAllAutoLabels) return null;
        if (labels === "hubs") {
          const degree = nodeMetrics.degree.get(d.id) || 0;
          return degree >= labelThreshold || isSubmitted(d, seeds) ? null : "none";
        }
        if (labels === "auto") {
          const degree = nodeMetrics.degree.get(d.id) || 0;
          return degree >= labelThreshold || isSubmitted(d, seeds) ? null : "none";
        }
        return null;
      });

    link.each(function each(d) {
      const key = edgeKey(d);
      const isSelected = selEdge === key;
      const isHovered = hoverEdge === key;
      const membership = edgeKind(d) === "membership";
      const isActive = !hasActiveScope || scope.edgeKeys.has(key);
      const dimmed = hasActiveScope && !isActive;
      const base = membership ? 0.32 : 0.58;
      const activeOpacity = membership ? 0.52 : 0.82;
      const widthBoost = isSelected || isHovered ? 2 : hasActiveScope && isActive ? 0.8 : 0;
      const self = d3Select(this);
      self.classed("is-dimmed", dimmed).classed("is-selected", isSelected).classed("is-hovered", isHovered);
      self
        .select(".graph-edge-stroke")
        .attr("stroke-opacity", dimmed ? 0.08 : isSelected || isHovered ? 0.98 : hasActiveScope ? activeOpacity : base)
        .attr("stroke-width", (d.width || 1.5) + widthBoost);
      self.select(".graph-edge-label").attr("opacity", dimmed ? 0 : hasActiveScope && !isActive ? 0 : 1);
    });
  }, []);

  // Frames the current layout (from simNodesRef's live x/y) so the map fills
  // the card instead of sitting as a small clump inside a lot of empty
  // canvas. Shared by the initial auto-fit below and the "Reset view" button,
  // so resetting never throws the user back into the un-fitted raw layout.
  const fitToView = useCallback(
    (duration = 450, ids = null) => {
      const nodes = ids
        ? simNodesRef.current.filter((node) => ids.has(node.id))
        : simNodesRef.current;
      const handle = zoomRef.current;
      if (!handle || !nodes || nodes.length === 0) {
        return;
      }
      const pad = ids ? 96 : 60;
      const xs = nodes.map((node) => node.x);
      const ys = nodes.map((node) => node.y);
      const minX = Math.min(...xs) - pad;
      const maxX = Math.max(...xs) + pad;
      const minY = Math.min(...ys) - pad;
      const maxY = Math.max(...ys) + pad;
      const boxWidth = Math.max(1, maxX - minX);
      const boxHeight = Math.max(1, maxY - minY);
      const scale = Math.min(1.8, Math.max(0.4, Math.min(width / boxWidth, height / boxHeight)));
      const translateX = width / 2 - (scale * (minX + maxX)) / 2;
      const translateY = height / 2 - (scale * (minY + maxY)) / 2;
      handle.svg
        .transition()
        .duration(duration)
        .call(handle.zoomer.transform, zoomIdentity.translate(translateX, translateY).scale(scale));
    },
    [width, height],
  );

  // --- Build / rebuild the simulation and DOM ---------------------------------
  // Runs when the data, viewport, or any layout-affecting control changes.
  useEffect(() => {
    if (!svgRef.current || !gRef.current) {
      return undefined;
    }

    const g = d3Select(gRef.current);
    if (displayNodes.length === 0) {
      if (simulationRef.current) {
        simulationRef.current.stop();
        simulationRef.current = null;
      }
      g.selectAll("*").remove();
      simNodesRef.current = [];
      selectionsRef.current = { node: null, link: null, edgeLabel: null };
      return undefined;
    }

    const simNodes = displayNodes.map((node) => ({
      ...node,
      radius: radiusFor(node),
    }));
    const byId = new Map(simNodes.map((node) => [node.id, node]));
    const simLinks = displayEdges
      .filter((edge) => byId.has(edge.from) && byId.has(edge.to))
      .map((edge) => ({ ...edge, source: edge.from, target: edge.to }));

    g.selectAll("*").remove();

    const linkSel = g
      .append("g")
      .attr("class", "graph-links")
      .selectAll("g")
      .data(simLinks, edgeKey)
      .join("g")
      .attr("class", (d) => `graph-edge ${edgeKind(d) === "membership" ? "membership" : "evidence"}`);

    linkSel
      .append("title")
      .text((d) => (edgeKind(d) === "membership" ? `${d.from} contains ${d.to}` : edgeAccessibleLabel(d)));

    // Wide transparent hit-line for easy clicking (evidence edges only), plus
    // the visible stroke. Straight lines, not curves — a technical knowledge
    // graph (this is deliberately modelled on OpenCTI's investigation graph)
    // reads as schematic/precise, not a decorative "bubble map".
    linkSel
      .filter((d) => edgeKind(d) === "evidence")
      .append("line")
      .attr("class", "graph-edge-hit")
      .attr("role", "button")
      .attr("tabindex", 0)
      .attr("aria-label", (d) => `Inspect evidence: ${edgeAccessibleLabel(d)}`)
      .attr("stroke", "transparent")
      .attr("stroke-width", 14)
      .style("cursor", "pointer")
      .on("mouseenter", (_event, d) => setHoveredEdge(edgeKey(d)))
      .on("mouseleave", () => setHoveredEdge(null))
      .on("focus", (_event, d) => setHoveredEdge(edgeKey(d)))
      .on("blur", () => setHoveredEdge(null))
      .on("click", (event, d) => {
        event.stopPropagation();
        handleEdgeClick(d);
      })
      .on("keydown", (event, d) => {
        if (!isActivationKey(event)) {
          return;
        }
        event.preventDefault();
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

    // Relationship-type label sat directly on the line (e.g. "TLS
    // certificate", "Shared IP") — same idea as OpenCTI showing the STIX
    // relationship name on its edges, so the kind of evidence is visible
    // without a click. Only the strongest/first piece of evidence is named
    // here; the full breakdown is still one click away. A background chip
    // behind the text (sized from the rendered text's own bounding box)
    // breaks the line behind it instead of the text sitting on top of it.
    //
    // Labels aren't collision-checked against each other (unlike nodes), so
    // dense maps only label the strongest few evidence links and leave the
    // full list one click away.
    const evidenceLinks = simLinks.filter((edge) => edgeKind(edge) === "evidence");
    const evidenceLinkCount = evidenceLinks.length;
    const showInlineEdgeLabels = evidenceLinkCount <= 12;
    const labelledEdgeKeys = new Set(
      (showInlineEdgeLabels
        ? evidenceLinks
        : [...evidenceLinks]
            .sort((a, b) => (b.score || 0) - (a.score || 0))
            .slice(0, Math.min(8, Math.max(3, Math.ceil(evidenceLinkCount * 0.12)))))
        .map(edgeKey),
    );
    const edgeLabelSel = linkSel
      .filter((d) => labelledEdgeKeys.has(edgeKey(d)) && evidenceLabels(d).length > 0)
      .append("g")
      .attr("class", "graph-edge-label");
    edgeLabelSel.append("rect").attr("class", "graph-edge-label-bg").attr("rx", 3);
    edgeLabelSel
      .append("text")
      .attr("class", "graph-edge-label-text")
      .attr("text-anchor", "middle")
      .attr("dy", "0.32em")
      .text((d) => shortEvidenceLabel(evidenceLabels(d)[0]));
    edgeLabelSel.each(function attachBackground() {
      const group = d3Select(this);
      const box = group.select("text").node().getBBox();
      group
        .select("rect")
        .attr("x", box.x - 4)
        .attr("y", box.y - 1.5)
        .attr("width", box.width + 8)
        .attr("height", box.height + 3);
    });

    const nodeSel = g
      .append("g")
      .attr("class", "graph-nodes")
      .selectAll("g")
      .data(simNodes, (d) => d.id)
      .join("g")
      .attr("class", "cluster-node")
      .attr("role", "button")
      .attr("tabindex", 0)
      .attr("aria-label", (d) => {
        const degree = metrics.degree.get(d.id) || 0;
        return `Inspect ${d.label}. ${degree} evidence ${degree === 1 ? "link" : "links"}.`;
      })
      .style("cursor", "grab")
      .on("mouseenter", (_event, d) => setHoveredNode(d.id))
      .on("mouseleave", () => setHoveredNode(null))
      .on("focus", (_event, d) => setHoveredNode(d.id))
      .on("blur", () => setHoveredNode(null))
      .on("click", (event, d) => {
        event.stopPropagation();
        handleNodeClick(d.id);
      })
      .on("keydown", (event, d) => {
        if (!isActivationKey(event)) {
          return;
        }
        event.preventDefault();
        event.stopPropagation();
        handleNodeClick(d.id);
      });

    nodeSel
      .append("title")
      .text((d) => {
        const degree = metrics.degree.get(d.id) || 0;
        const tier = d.tier ? `, ${DOMAIN_TIER_LABELS[d.tier]}` : "";
        return `${d.label}${tier}. ${degree} evidence ${degree === 1 ? "link" : "links"}.`;
      });

    // A second, wider ring (not a soft blurred halo) marks the domains the
    // user actually picked — flatter and crisper than a glow, in keeping
    // with a technical/schematic graph rather than a glossy consumer one.
    nodeSel
      .filter((d) => isSubmitted(d, seedTargets))
      .append("circle")
      .attr("class", "graph-seed-ring")
      .attr("fill", "none")
      .attr("stroke", SUBMITTED_COLOR)
      .attr("stroke-opacity", 0.45)
      .attr("stroke-width", 2)
      .attr("r", (d) => d.radius + 5);

    nodeSel
      .append("circle")
      .attr("class", "graph-marker")
      .attr("r", (d) => d.radius)
      .attr("stroke", "var(--graph-node-ring, #fff)")
      .attr("stroke-width", 1.5);

    // Every node is a domain, so every node gets the same minimal "globe"
    // glyph (three arcs over a circle) rather than a flat dot — the
    // icon-in-a-circle look is the other half of what reads as a knowledge
    // graph instead of a bubble chart. Scales down gracefully for the
    // smaller "related" nodes.
    const iconGroup = nodeSel.append("g").attr("class", "graph-node-icon").style("pointer-events", "none");
    iconGroup.each(function drawGlobe(d) {
      const iconR = Math.max(3, d.radius * 0.52);
      const group = d3Select(this);
      group
        .append("circle")
        .attr("r", iconR)
        .attr("fill", "none")
        .attr("stroke", "var(--graph-node-icon, rgba(255,255,255,0.85))")
        .attr("stroke-width", Math.max(0.75, iconR * 0.12));
      group
        .append("ellipse")
        .attr("rx", iconR)
        .attr("ry", iconR * 0.42)
        .attr("fill", "none")
        .attr("stroke", "var(--graph-node-icon, rgba(255,255,255,0.85))")
        .attr("stroke-width", Math.max(0.75, iconR * 0.12));
      group
        .append("line")
        .attr("y1", -iconR)
        .attr("y2", iconR)
        .attr("stroke", "var(--graph-node-icon, rgba(255,255,255,0.85))")
        .attr("stroke-width", Math.max(0.75, iconR * 0.12));
    });

    nodeSel
      .append("text")
      .attr("class", "graph-node-label")
      .attr("text-anchor", "middle")
      .attr("y", (d) => d.radius + 15)
      // A stroke behind the fill in the background colour acts as a soft
      // halo/cutout, so a label stays legible where it crosses a link or
      // sits close to a neighbour instead of turning into visual noise.
      .attr("paint-order", "stroke")
      .attr("stroke", "var(--graph-label-halo, #fff)")
      .attr("stroke-width", 3)
      .attr("stroke-linejoin", "round")
      .text((d) => truncateLabel(d.label));

    selectionsRef.current = { node: nodeSel, link: linkSel, edgeLabel: edgeLabelSel };
    // Apply the current colour / label / highlight to the freshly-built DOM.
    applyStyles();

    // Link distance / charge scale with the "spread" control so the user can
    // pull dense clusters apart or pack them tight. Membership ties stay short
    // so a bridge hugs the domain it belongs to. Distances and charge are
    // deliberately generous — a tight, overlapping clump reads as clutter,
    // and the auto-fit-to-view pass below means going wider never leaves the
    // map looking empty either.
    const simulation = forceSimulation(simNodes)
      .force(
        "link",
        forceLink(simLinks)
          .id((node) => node.id)
          .distance((edge) => {
            if (edgeKind(edge) === "membership") return 48 * spread;
            return (
              (edgeTier(edge) === "strong" ? 100 : edgeTier(edge) === "moderate" ? 150 : 195) *
              spread
            );
          })
          .strength((edge) =>
            edgeKind(edge) === "membership" ? 0.9 : edgeTier(edge) === "weak" ? 0.25 : 0.6,
          ),
      )
      .force("charge", forceManyBody().strength(-420 * spread))
      .force("center", forceCenter(width / 2, height / 2))
      .force(
        "collide",
        forceCollide().radius((node) => node.radius + 22 + Math.min(46, truncateLabel(node.label).length * 1.8)),
      )
      .force("x", forceX(width / 2).strength(0.05))
      .force("y", forceY(height / 2).strength(0.07));

    simulationRef.current = simulation;
    // Same array objects the simulation mutates in place, so reading this
    // ref later (e.g. on export) always sees the latest x/y without needing
    // a per-tick copy.
    simNodesRef.current = simNodes;

    const margin = 30;
    let tickFrame = 0;
    const renderTick = () => {
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
      edgeLabelSel.attr(
        "transform",
        (d) => `translate(${(d.source.x + d.target.x) / 2}, ${(d.source.y + d.target.y) / 2})`,
      );
      nodeSel.attr("transform", (d) => `translate(${d.x}, ${d.y})`);
    };
    simulation.on("tick", () => {
      if (tickFrame) {
        return;
      }
      tickFrame = requestAnimationFrame(() => {
        tickFrame = 0;
        renderTick();
      });
    });

    // Once the layout settles, frame it so the map fills the card instead of
    // sitting as a small clump inside a lot of empty canvas (or, for a large
    // graph, spilling past the edges). Only on the *first* settle after a
    // fresh build — dragging a node re-heats/cools the same simulation and
    // firing this again on every drag release would yank the view out from
    // under whoever's mid-drag.
    let hasFitToView = false;
    simulation.on("end", () => {
      if (hasFitToView) {
        return;
      }
      hasFitToView = true;
      fitToView();
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
      if (tickFrame) {
        cancelAnimationFrame(tickFrame);
      }
      simulation.stop();
      simulationRef.current = null;
      selectionsRef.current = { node: null, link: null, edgeLabel: null };
    };
  }, [
    displayNodes,
    displayEdges,
    width,
    height,
    spread,
    radiusFor,
    metrics,
    seedTargets,
    otherRoleColor,
    handleNodeClick,
    handleEdgeClick,
    applyStyles,
    fitToView,
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
    // Clicking empty canvas drops the focus and shows the whole cluster again.
    svg.on("click", clearFocus);
    return () => {
      svg.on(".zoom", null);
      svg.on("click", null);
    };
  }, [clearFocus]);

  const resetView = useCallback(() => {
    fitToView(300);
  }, [fitToView]);

  const fitSelection = useCallback(() => {
    if (selectedScope) {
      fitToView(300, selectedScope.ids);
    }
  }, [fitToView, selectedScope]);

  // Builds a standalone, presentation-ready copy of the current map — title,
  // generated date, and a full legend baked in as real SVG content — as a
  // detached XML document rather than relying on the page's stylesheet: an
  // <img> loaded from a serialised SVG blob is its own document and can't see
  // var(--text)/var(--graph-bg) or any other page CSS, so every colour that
  // matters is written out explicitly here. Shared by both the download and
  // email actions so the picture they produce is always identical.
  const buildPresentationSvg = useCallback(() => {
    const liveG = gRef.current;
    if (!liveG || displayNodes.length === 0) {
      return null;
    }

    const headerH = 76;
    const footerH = 96;
    const pad = 24;
    const totalW = Math.max(width, 480);
    const totalH = height + headerH + footerH;

    const ns = "http://www.w3.org/2000/svg";
    const doc = document.implementation.createDocument(ns, "svg", null);
    const out = doc.documentElement;
    out.setAttribute("width", totalW);
    out.setAttribute("height", totalH);
    out.setAttribute("viewBox", `0 0 ${totalW} ${totalH}`);
    out.setAttribute("font-family", "-apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif");

    const style = doc.createElementNS(ns, "style");
    style.textContent = `
      :root { --text: #111827; }
      text { font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
      .graph-node-label { fill: #111827; }
    `;
    out.appendChild(style);

    const bg = doc.createElementNS(ns, "rect");
    bg.setAttribute("width", totalW);
    bg.setAttribute("height", totalH);
    bg.setAttribute("fill", "#ffffff");
    out.appendChild(bg);

    // Header: title derived from the domains actually anchoring this map, so
    // it can never drift from what the picture shows.
    const seedNames = displayNodes.filter((node) => isSubmitted(node, seedTargets)).map((node) => node.label);
    const preview = seedNames.slice(0, 3).join(", ") + (seedNames.length > 3 ? ` +${seedNames.length - 3} more` : "");
    const header = doc.createElementNS(ns, "g");
    const headTitle = doc.createElementNS(ns, "text");
    headTitle.setAttribute("x", pad);
    headTitle.setAttribute("y", 30);
    headTitle.setAttribute("font-size", "19");
    headTitle.setAttribute("font-weight", "700");
    headTitle.setAttribute("fill", "#0f172a");
    headTitle.textContent = `Network map — ${preview || "no domains"}`;
    header.appendChild(headTitle);

    const headSub = doc.createElementNS(ns, "text");
    headSub.setAttribute("x", pad);
    headSub.setAttribute("y", 52);
    headSub.setAttribute("font-size", "12.5");
    headSub.setAttribute("fill", "#64748b");
    headSub.textContent = `Generated ${todayLabel()} · lines show shared hosting/registration evidence between domains, not guesses`;
    header.appendChild(headSub);

    // Disclosure line — if any tier/strength filter or a click-to-focus is
    // hiding part of the underlying data, say so on the image itself. The
    // exported picture should never imply completeness it doesn't have.
    const totalEvidence = allEdges.filter((edge) => edgeKind(edge) === "evidence").length;
    const shownEvidence = displayEdges.filter((edge) => edgeKind(edge) === "evidence").length;
    const filtered = displayNodes.length < allNodes.length || shownEvidence < totalEvidence;
    const headCaption = doc.createElementNS(ns, "text");
    headCaption.setAttribute("x", pad);
    headCaption.setAttribute("y", 70);
    headCaption.setAttribute("font-size", "12");
    headCaption.setAttribute("fill", filtered ? "#b45309" : "#64748b");
    headCaption.textContent = filtered
      ? `Filtered view: showing ${displayNodes.length} of ${allNodes.length} domains and ${shownEvidence} of ${totalEvidence} links — clear the filters above to export everything.`
      : `Showing all ${displayNodes.length} domains and ${shownEvidence} evidence-backed links currently loaded.`;
    header.appendChild(headCaption);
    out.appendChild(header);

    // The graph itself, re-fit to the export canvas rather than carrying over
    // whatever the live view happens to be panned/zoomed to (a mid-pan export
    // would otherwise crop content, and a never-touched view would reproduce
    // the same "small clump in a big empty canvas" look the on-screen
    // auto-fit exists to avoid). Uses the same settled simulation coordinates
    // (simNodesRef) the on-screen fit-to-view reads, just recomputed against
    // the export canvas's own dimensions.
    const boundsSource = simNodesRef.current.length > 0 ? simNodesRef.current : displayNodes;
    const fitPad = 44;
    const xs = boundsSource.map((node) => node.x ?? width / 2);
    const ys = boundsSource.map((node) => node.y ?? height / 2);
    const minX = Math.min(...xs) - fitPad;
    const maxX = Math.max(...xs) + fitPad;
    const minY = Math.min(...ys) - fitPad;
    const maxY = Math.max(...ys) + fitPad;
    const boxWidth = Math.max(1, maxX - minX);
    const boxHeight = Math.max(1, maxY - minY);
    const fitScale = Math.min(1.6, Math.max(0.3, Math.min(totalW / boxWidth, height / boxHeight)));
    const fitTx = totalW / 2 - (fitScale * (minX + maxX)) / 2;
    const fitTy = height / 2 - (fitScale * (minY + maxY)) / 2;

    const graphClone = liveG.cloneNode(true);
    graphClone.removeAttribute("transform");
    const graphGroup = doc.createElementNS(ns, "g");
    graphGroup.setAttribute(
      "transform",
      `translate(0, ${headerH}) translate(${fitTx}, ${fitTy}) scale(${fitScale})`,
    );
    Array.from(graphClone.childNodes).forEach((child) => graphGroup.appendChild(doc.importNode(child, true)));
    out.appendChild(graphGroup);

    // Footer legend — the same roles/tiers shown on-page, restated as real
    // SVG so the exported image is self-explanatory outside the app.
    const legend = doc.createElementNS(ns, "g");
    legend.setAttribute("transform", `translate(${pad}, ${headerH + height + 30})`);
    const svgPresentTiers = DOMAIN_TIER_ORDER.filter((tier) => displayNodes.some((node) => node.tier === tier));
    const legendItems = [
      { swatch: "circle", color: SUBMITTED_COLOR, label: `${seedRoleLabel} (${seedNames.length})` },
      { swatch: "circle", color: otherRoleColor, label: otherRoleLabel },
      ...TIER_ORDER.map((tier) => ({ swatch: "line", color: EDGE_TIERS[tier].color, label: EDGE_TIERS[tier].label })),
      ...svgPresentTiers.map((tier) => ({ swatch: "circle", color: DOMAIN_TIER_COLORS[tier], label: DOMAIN_TIER_LABELS[tier] })),
    ];
    let lx = 0;
    let ly = 0;
    const maxLegendW = totalW - pad * 2;
    legendItems.forEach((item) => {
      const itemW = item.label.length * 6.6 + 34;
      if (lx + itemW > maxLegendW) {
        lx = 0;
        ly += 24;
      }
      const g = doc.createElementNS(ns, "g");
      g.setAttribute("transform", `translate(${lx}, ${ly})`);
      if (item.swatch === "circle") {
        const c = doc.createElementNS(ns, "circle");
        c.setAttribute("cx", 6);
        c.setAttribute("cy", -4);
        c.setAttribute("r", 6);
        c.setAttribute("fill", item.color);
        g.appendChild(c);
      } else {
        const l = doc.createElementNS(ns, "rect");
        l.setAttribute("x", 0);
        l.setAttribute("y", -8);
        l.setAttribute("width", 16);
        l.setAttribute("height", 4);
        l.setAttribute("rx", 2);
        l.setAttribute("fill", item.color);
        g.appendChild(l);
      }
      const t = doc.createElementNS(ns, "text");
      t.setAttribute("x", 22);
      t.setAttribute("y", 0);
      t.setAttribute("font-size", "12.5");
      t.setAttribute("fill", "#1e293b");
      t.textContent = item.label;
      g.appendChild(t);
      legend.appendChild(g);
      lx += itemW;
    });
    out.appendChild(legend);

    return { svgElement: out, totalW, totalH, seedNames };
  }, [
    allEdges,
    allNodes,
    displayEdges,
    displayNodes,
    height,
    otherRoleColor,
    otherRoleLabel,
    seedRoleLabel,
    seedTargets,
    width,
  ]);

  // Builds a self-contained, clickable HTML report — inline SVG plus vanilla
  // JS (INTERACTIVE_RENDERER_JS above), no external scripts or fonts — so a
  // non-technical recipient can open the file straight from their downloads
  // folder or an email attachment and get the same click-a-line-for-evidence
  // interaction as the live app, without needing an account or network access
  // to this tool. Node positions are baked in from the live simulation
  // (simNodesRef) so the exported layout matches what's on screen.
  const buildInteractiveHtml = useCallback(() => {
    if (displayNodes.length === 0) {
      return null;
    }
    const simById = new Map((simNodesRef.current || []).map((node) => [node.id, node]));
    const seedNames = displayNodes.filter((node) => isSubmitted(node, seedTargets)).map((node) => node.label);
    const preview = seedNames.slice(0, 3).join(", ") + (seedNames.length > 3 ? ` +${seedNames.length - 3} more` : "");

    const totalEvidence = allEdges.filter((edge) => edgeKind(edge) === "evidence").length;
    const shownEvidence = displayEdges.filter((edge) => edgeKind(edge) === "evidence").length;
    const filtered = displayNodes.length < allNodes.length || shownEvidence < totalEvidence;

    const nodes = displayNodes.map((node) => {
      const sim = simById.get(node.id);
      const seed = isSubmitted(node, seedTargets);
      return {
        id: node.id,
        label: node.label,
        seed,
        tier: DOMAIN_TIER_COLORS[node.tier] ? node.tier : null,
        radius: sim ? sim.radius : seed ? 16 : 8,
        x: sim ? Math.round(sim.x) : width / 2,
        y: sim ? Math.round(sim.y) : height / 2,
      };
    });

    const edges = displayEdges
      .filter((edge) => edgeKind(edge) === "evidence")
      .map((edge) => ({
        from: edge.from,
        to: edge.to,
        score: edge.score || 0,
        tier: edgeTier(edge),
        width: edge.width || 1.5,
        labels:
          edge.labels && edge.labels.length > 0 ? edge.labels : (edge.paths || []).map(formatPathFallback),
      }));

    const data = {
      title: `Network map — ${preview || "no domains"}`,
      generated: todayLabel(),
      caption: filtered
        ? `Filtered view: showing ${displayNodes.length} of ${allNodes.length} domains and ${shownEvidence} of ${totalEvidence} links.`
        : `Showing all ${displayNodes.length} domains and ${shownEvidence} evidence-backed links currently loaded.`,
      filtered,
      width: Math.max(width, 480),
      height,
      seedColor: SUBMITTED_COLOR,
      otherColor: otherRoleColor,
      seedLabel: seedRoleLabel,
      otherLabel: otherRoleLabel,
      tierColors: { strong: EDGE_TIERS.strong.color, moderate: EDGE_TIERS.moderate.color, weak: EDGE_TIERS.weak.color },
      tierLabels: { strong: EDGE_TIERS.strong.label, moderate: EDGE_TIERS.moderate.label, weak: EDGE_TIERS.weak.label },
      domainTierColors: DOMAIN_TIER_COLORS,
      domainTierLabels: DOMAIN_TIER_LABELS,
      nodes,
      edges,
    };

    // Escape `<` so the JSON blob can't prematurely close the <script> tag
    // it's embedded in (or smuggle a `<!--`) if a domain/evidence value ever
    // contains one — JSON.stringify already handles quoting/escaping.
    const dataJson = JSON.stringify(data).replace(/</g, "\\u003c");

    const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>${escapeHtml(data.title)}</title>
<style>
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #f8fafc; color: #111827; }
  header { padding: 20px 24px 4px; }
  h1 { font-size: 19px; margin: 0 0 4px; color: #0f172a; }
  .meta { font-size: 12.5px; color: #64748b; margin: 2px 0; }
  .meta.warn { color: #b45309; }
  .legend { display: flex; flex-wrap: wrap; gap: 14px; padding: 10px 24px; font-size: 12.5px; color: #334155; }
  .legend .item { display: inline-flex; align-items: center; gap: 6px; }
  .swatch { width: 11px; height: 11px; border-radius: 50%; display: inline-block; }
  .swatch.bar { width: 16px; height: 4px; border-radius: 2px; }
  #stage-wrap { margin: 0 24px; border: 1px solid #e2e8f0; border-radius: 16px; overflow: hidden; background: #fff; }
  #stage { width: 100%; height: 640px; display: block; cursor: grab; }
  #stage.grabbing { cursor: grabbing; }
  .node { cursor: pointer; }
  .node text { font-family: "IBM Plex Mono", "SFMono-Regular", monospace; font-size: 11px; fill: #111827; user-select: none; }
  .edge-hit { cursor: pointer; }
  .hint { padding: 10px 24px 4px; font-size: 12px; color: #94a3b8; }
  #detail { margin: 12px 24px 24px; padding: 14px 16px; border: 1px solid #e2e8f0; border-radius: 12px; background: #fff; display: none; font-size: 13px; }
  #detail h3 { margin: 0 0 8px; font-size: 14px; }
  #detail ul { margin: 8px 0 0; padding-left: 18px; }
  #detail .close { float: right; border: 1px solid #e2e8f0; background: #f8fafc; border-radius: 999px; padding: 4px 10px; font-size: 12px; cursor: pointer; }
</style>
</head>
<body>
<header>
  <h1 id="doc-title"></h1>
  <p class="meta" id="doc-generated"></p>
  <p class="meta" id="doc-caption"></p>
</header>
<div class="legend" id="legend"></div>
<div id="stage-wrap"><svg id="stage"></svg></div>
<p class="hint">Click a domain or a line to see the evidence behind it. Drag a domain to move it, scroll to zoom, drag empty space to pan.</p>
<div id="detail"></div>
<script>window.__GRAPH_DATA__ = ${dataJson};</script>
<script>${INTERACTIVE_RENDERER_JS}</script>
</body>
</html>`;

    return new Blob([html], { type: "text/html;charset=utf-8" });
  }, [
    allEdges,
    allNodes,
    displayEdges,
    displayNodes,
    height,
    otherRoleColor,
    otherRoleLabel,
    seedRoleLabel,
    seedTargets,
    width,
  ]);

  // Rasterises a built presentation SVG to a PNG Blob at 2x scale (crisp when
  // dropped into a slide or email). Returns null if there's nothing to draw.
  const renderPresentationPng = useCallback(() => {
    const built = buildPresentationSvg();
    if (!built) {
      return Promise.resolve(null);
    }
    const { svgElement, totalW, totalH, seedNames } = built;
    const svgString = new XMLSerializer().serializeToString(svgElement);
    const svgBlob = new Blob([svgString], { type: "image/svg+xml;charset=utf-8" });
    const svgUrl = URL.createObjectURL(svgBlob);

    return new Promise((resolve) => {
      const img = new Image();
      img.onload = () => {
        const scale = 2;
        const canvas = document.createElement("canvas");
        canvas.width = totalW * scale;
        canvas.height = totalH * scale;
        const ctx = canvas.getContext("2d");
        ctx.scale(scale, scale);
        ctx.fillStyle = "#ffffff";
        ctx.fillRect(0, 0, totalW, totalH);
        ctx.drawImage(img, 0, 0, totalW, totalH);
        URL.revokeObjectURL(svgUrl);
        canvas.toBlob((blob) => resolve(blob ? { blob, seedNames } : null), "image/png");
      };
      img.onerror = () => {
        URL.revokeObjectURL(svgUrl);
        resolve(null);
      };
      img.src = svgUrl;
    });
  }, [buildPresentationSvg]);

  const downloadImage = useCallback(() => {
    renderPresentationPng().then((result) => {
      if (!result) return;
      const link = document.createElement("a");
      link.href = URL.createObjectURL(result.blob);
      link.download = `${exportFileName}-${Date.now()}.png`;
      link.click();
      URL.revokeObjectURL(link.href);
    });
  }, [renderPresentationPng, exportFileName]);

  const downloadInteractive = useCallback(() => {
    const blob = buildInteractiveHtml();
    if (!blob) return;
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `${exportFileName}-${Date.now()}.html`;
    link.click();
    URL.revokeObjectURL(link.href);
  }, [buildInteractiveHtml, exportFileName]);

  const [emailState, setEmailState] = useState({ status: "idle", message: "" });

  // Sends both the static PNG (a safe preview that renders in any mail
  // client) and the clickable HTML report (the actual "dynamic" artifact) as
  // two attachments on one message, so recipients get real interactivity
  // even though a raw image attachment never could be.
  const emailGraph = useCallback(async () => {
    setEmailState({ status: "sending", message: "" });
    try {
      const result = await renderPresentationPng();
      if (!result) {
        setEmailState({ status: "error", message: "Nothing to export yet." });
        return;
      }
      const htmlBlob = buildInteractiveHtml();
      const form = new FormData();
      form.append("image", result.blob, "network-graph.png");
      if (htmlBlob) {
        form.append("report", htmlBlob, "network-graph-interactive.html");
      }
      form.append("domains", JSON.stringify(result.seedNames));
      const response = await fetch("/api/graph/email", { method: "POST", body: form });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || "Couldn't send the email.");
      }
      setEmailState({ status: "sent", message: "Emailed to the configured recipients." });
    } catch (err) {
      setEmailState({ status: "error", message: err.message || "Couldn't send the email." });
    }
  }, [renderPresentationPng, buildInteractiveHtml]);

  // Restyle in place whenever a presentation control changes — colour, labels
  // and highlight are pure presentation, so they never restart the simulation.
  useEffect(() => {
    applyStyles();
  }, [
    activeScope,
    applyStyles,
    colorFor,
    displayEdges,
    displayNodes.length,
    hoveredEdge,
    hoveredNode,
    labelMode,
    metrics,
    seedTargets,
    selectedEdge,
    selectedNode,
  ]);

  const selectedEdgeData = useMemo(() => {
    if (!selectedEdge) {
      return null;
    }
    return visibleEvidence.find((edge) => edgeKey(edge) === selectedEdge) || null;
  }, [selectedEdge, visibleEvidence]);

  const selectedNodeEdges = useMemo(() => {
    if (!selectedNode) {
      return [];
    }
    return visibleEvidence
      .filter((edge) => edge.from === selectedNode || edge.to === selectedNode)
      .sort((a, b) => (b.score || 0) - (a.score || 0));
  }, [selectedNode, visibleEvidence]);
  const selectedNodeData = useMemo(
    () => (selectedNode ? allNodes.find((node) => node.id === selectedNode) || null : null),
    [allNodes, selectedNode],
  );

  if (allNodes.length === 0) {
    return null;
  }

  const submittedCount = displayNodes.filter((node) => isSubmitted(node, seedTargets)).length;
  const bridgeCount = displayNodes.length - submittedCount;
  const hasSelection = Boolean(selectedNode || selectedEdge);
  const focusViewActive = Boolean(narrowSelection && selectedScope);
  const presentTiers = DOMAIN_TIER_ORDER.filter((tier) => displayNodes.some((node) => node.tier === tier));
  const filterTierKeys = DOMAIN_TIER_ORDER.filter((tier) => allNodes.some((node) => node.tier === tier));
  const hasUnclassifiedTier = allNodes.some((node) => !DOMAIN_TIER_COLORS[node.tier]);
  const hiddenRoleCount = Object.keys(ROLE_FILTERS).filter((role) => !roleFilter[role]).length;
  const hiddenTierCount =
    filterTierKeys.filter((tier) => !domainTierFilter[String(tier)]).length +
    (hasUnclassifiedTier && !domainTierFilter[UNCLASSIFIED_TIER] ? 1 : 0);
  const hiddenEvidenceTypeCount = evidenceTypes.filter((type) => evidenceTypeFilter[type] === false).length;
  const hiddenStrengthCount = TIER_ORDER.filter((tier) => !tierFilter[tier]).length;
  const activeCriteriaCount =
    (searchNeedle ? 1 : 0) +
    hiddenRoleCount +
    hiddenTierCount +
    hiddenEvidenceTypeCount +
    hiddenStrengthCount +
    (minScore > 0 ? 1 : 0);
  const totalEvidenceCount = allEdges.filter((edge) => edgeKind(edge) === "evidence").length;
  const shownEvidenceCount = displayEdges.filter((edge) => edgeKind(edge) === "evidence").length;
  const visibleFiltered = visibleNodes.length < allNodes.length || visibleEvidence.length < totalEvidenceCount;
  const denseMap = displayNodes.length > 32 || shownEvidenceCount > 48;
  const selectedLabel = selectedNode || (selectedEdgeData ? `${selectedEdgeData.from} to ${selectedEdgeData.to}` : null);
  const graphStatus =
    displayNodes.length === 0
      ? "No links match the current strength filters."
      : hasSelection && focusViewActive
        ? `Focused on ${displayNodes.length} domains and ${shownEvidenceCount} evidence links.`
          : hasSelection
            ? `Highlighting ${selectedLabel || "selection"}; ${displayNodes.length} domains remain in context.`
          : visibleFiltered && activeCriteriaCount > 0
            ? `Showing ${displayNodes.length} of ${allNodes.length} domains and ${shownEvidenceCount} of ${totalEvidenceCount} evidence links across ${activeCriteriaCount} active filter${activeCriteriaCount === 1 ? "" : "s"}.`
            : visibleFiltered
              ? `Showing ${displayNodes.length} of ${allNodes.length} domains and ${shownEvidenceCount} of ${totalEvidenceCount} evidence links.`
            : `Showing ${displayNodes.length} domains and ${shownEvidenceCount} evidence links.`;

  return (
    <section className="cluster-graph-card" ref={containerRef}>
      <div className="panel-header">
        <div>
          <p className="eyebrow">Connection map</p>
          <h3>{title}</h3>
          <p className="section-copy">{description}</p>
        </div>
      </div>

      <div className="graph-controls" aria-label="Knowledge graph controls">
        <label className="graph-control graph-search-control">
          <span>Search knowledge</span>
          <input
            aria-label="Search visible domains and evidence"
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="domain, IP, cert, ASN..."
            type="search"
            value={searchQuery}
          />
        </label>

        <label className="graph-control compact">
          <span>Labels</span>
          <select
            aria-label="Node label density"
            title="Node label density"
            value={labelMode}
            onChange={(e) => setLabelMode(e.target.value)}
          >
            {Object.entries(LABEL_MODES).map(([key, mode]) => (
              <option key={key} value={key}>
                {mode.label}
              </option>
            ))}
          </select>
        </label>

        <label className="graph-control compact">
          <span>Spread</span>
          <input
            aria-label="Graph spread"
            aria-valuetext={`${spread.toFixed(1)}x`}
            max="2"
            min="0.5"
            onChange={(e) => setSpread(Number(e.target.value))}
            step="0.1"
            type="range"
            value={spread}
          />
        </label>

        {maxScore > 0 ? (
          <label className="graph-control compact">
            <span>Min. strength {minScore > 0 ? `(${minScore})` : ""}</span>
            <input
              aria-label="Minimum link strength"
              aria-valuetext={minScore > 0 ? `${minScore}` : "Any strength"}
              max={maxScore}
              min="0"
              onChange={(e) => setMinScore(Number(e.target.value))}
              step="1"
              type="range"
              value={minScore}
            />
          </label>
        ) : null}

        <div className="graph-control graph-filter-block">
          <span>Objects</span>
          <div className="graph-tier-toggles">
            {Object.entries(ROLE_FILTERS).map(([role, label]) => (
              <label className="graph-tier-toggle" key={role}>
                <input
                  aria-label={`Show ${label.toLowerCase()} objects`}
                  checked={roleFilter[role]}
                  onChange={(e) => setRoleFilter((prev) => ({ ...prev, [role]: e.target.checked }))}
                  type="checkbox"
                />
                <span
                  className="graph-legend-swatch round"
                  style={{ background: role === "submitted" ? SUBMITTED_COLOR : otherRoleColor }}
                />
                {label}
              </label>
            ))}
          </div>
        </div>

        {(filterTierKeys.length > 0 || hasUnclassifiedTier) ? (
          <div className="graph-control graph-filter-block">
            <span>OpenCTI tier</span>
            <div className="graph-tier-toggles">
              {filterTierKeys.map((tier) => (
                <label className="graph-tier-toggle" key={`filter-tier-${tier}`}>
                  <input
                    aria-label={`Show ${DOMAIN_TIER_LABELS[tier]} domains`}
                    checked={domainTierFilter[String(tier)]}
                    onChange={(e) =>
                      setDomainTierFilter((prev) => ({ ...prev, [String(tier)]: e.target.checked }))
                    }
                    type="checkbox"
                  />
                  <span className="graph-legend-swatch round" style={{ background: DOMAIN_TIER_COLORS[tier] }} />
                  {DOMAIN_TIER_LABELS[tier].replace("Tier ", "T")}
                </label>
              ))}
              {hasUnclassifiedTier ? (
                <label className="graph-tier-toggle">
                  <input
                    aria-label="Show unclassified domains"
                    checked={domainTierFilter[UNCLASSIFIED_TIER]}
                    onChange={(e) =>
                      setDomainTierFilter((prev) => ({ ...prev, [UNCLASSIFIED_TIER]: e.target.checked }))
                    }
                    type="checkbox"
                  />
                  <span className="graph-legend-swatch round muted-swatch" />
                  Unclassified
                </label>
              ) : null}
            </div>
          </div>
        ) : null}

        {evidenceTypes.length > 0 ? (
          <div className="graph-control graph-filter-block wide">
            <span>Relationship type</span>
            <div className="graph-tier-toggles scrollable">
              {evidenceTypes.map((type) => (
                <label className="graph-tier-toggle" key={type} title={type}>
                  <input
                    aria-label={`Show ${type} relationships`}
                    checked={evidenceTypeFilter[type] !== false}
                    onChange={(e) =>
                      setEvidenceTypeFilter((prev) => ({ ...prev, [type]: e.target.checked }))
                    }
                    type="checkbox"
                  />
                  {truncateLabel(type, 18)}
                </label>
              ))}
            </div>
          </div>
        ) : null}

        <div className="graph-control graph-filter-block">
          <span>Strength</span>
          <div className="graph-tier-toggles">
            {TIER_ORDER.map((tier) => (
              <label className="graph-tier-toggle" key={tier}>
                <input
                  aria-label={`Show ${tier} links`}
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

        {activeCriteriaCount > 0 ? (
          <button className="secondary-button small" onClick={resetKnowledgeFilters} title="Reset all graph filters" type="button">
            Reset filters
          </button>
        ) : null}

        {hasSelection ? (
          <button
            aria-label={focusViewActive ? "Keep the selected neighborhood in context" : "Focus the graph on the selected neighborhood"}
            className="secondary-button small"
            onClick={() => setNarrowSelection((current) => !current)}
            title={focusViewActive ? "Keep the selected neighborhood in context" : "Focus the graph on the selected neighborhood"}
            type="button"
          >
            {focusViewActive ? "Keep context" : "Focus selection"}
          </button>
        ) : null}

        {hasSelection ? (
          <button
            aria-label="Fit the selected neighborhood"
            className="secondary-button small"
            onClick={fitSelection}
            title="Fit the selected neighborhood"
            type="button"
          >
            Fit selection
          </button>
        ) : null}

        {hasSelection ? (
          <button className="secondary-button small" onClick={clearFocus} title="Clear graph selection" type="button">
            Clear selection
          </button>
        ) : null}

        <button aria-label="Fit the whole graph" className="secondary-button small" onClick={resetView} title="Fit the whole graph" type="button">
          Fit graph
        </button>

        <div className="graph-actions" aria-label="Graph export actions">
          <button className="secondary-button small" onClick={downloadImage} title="Download PNG image" type="button">
            PNG
          </button>

          <button
            className="secondary-button small"
            onClick={downloadInteractive}
            title="Download offline interactive HTML report"
            type="button"
          >
            HTML report
          </button>

          <button
            className="primary-button small"
            disabled={emailState.status === "sending"}
            onClick={emailGraph}
            title="Email the graph attachments"
            type="button"
          >
            {emailState.status === "sending" ? "Sending..." : "Email"}
          </button>
        </div>
      </div>

      <p className="graph-status" id={statusId} aria-live="polite">
        <span>{graphStatus}</span>
        {denseMap && labelMode === "auto" && displayNodes.length > 0 ? (
          <span>Dense map: labels are limited to anchors and hubs.</span>
        ) : null}
      </p>

      {emailState.status === "sent" || emailState.status === "error" ? (
        <p
          className={emailState.status === "error" ? undefined : "muted"}
          style={emailState.status === "error" ? { color: "var(--danger)" } : undefined}
        >
          {emailState.message}
        </p>
      ) : null}

      <div className="graph-legend" aria-label="Map legend">
        <span className="graph-legend-item">
          <span className="graph-legend-swatch round" style={{ background: SUBMITTED_COLOR }} />
          {seedRoleLabel} ({submittedCount})
        </span>
        {bridgeCount > 0 ? (
          <span className="graph-legend-item">
            <span className="graph-legend-swatch round" style={{ background: otherRoleColor }} />
            {otherRoleLabel} ({bridgeCount})
          </span>
        ) : null}
        {TIER_ORDER.map((tier) => (
          <span className="graph-legend-item" key={tier}>
            <span className="graph-legend-swatch" style={{ background: EDGE_TIERS[tier].color }} />
            {EDGE_TIERS[tier].label}
          </span>
        ))}
        {presentTiers.length > 0
          ? presentTiers.map((tier) => (
              <span className="graph-legend-item" key={`domain-tier-${tier}`}>
                <span className="graph-legend-swatch round" style={{ background: DOMAIN_TIER_COLORS[tier] }} />
                {DOMAIN_TIER_LABELS[tier]}
              </span>
            ))
          : null}
      </div>

      <div className="graph-workbench">
        <div className="graph-stage">
          <svg
            ref={svgRef}
            className="cluster-graph"
            viewBox={`0 0 ${width} ${height}`}
            style={{ cursor: "grab", height }}
            role="img"
            aria-label="Network map of connected domains"
            aria-describedby={statusId}
          >
            <g ref={gRef} />
          </svg>
          {displayNodes.length === 0 ? (
            <div className="graph-empty-state" role="status">
              <strong>No visible links</strong>
              <span>Relax the knowledge filters to bring relationships back into view.</span>
            </div>
          ) : null}
        </div>

        <aside className="graph-inspector" aria-label="Knowledge selection details">
          {selectedEdgeData ? (
            <>
              <div className="graph-inspector-head">
                <div>
                  <span className="muted">Selected link</span>
                  <strong>{evidenceType(selectedEdgeData)}</strong>
                </div>
                <button className="secondary-button small" onClick={clearFocus} type="button">
                  Clear
                </button>
              </div>
              <p className="card-copy graph-selection-summary">
                <strong>{selectedEdgeData.from}</strong> to <strong>{selectedEdgeData.to}</strong>
              </p>
              <dl className="graph-inspector-meta">
                <div>
                  <dt>Source</dt>
                  <dd>{selectedEdgeData.from}</dd>
                </div>
                <div>
                  <dt>Target</dt>
                  <dd>{selectedEdgeData.to}</dd>
                </div>
                <div>
                  <dt>Strength</dt>
                  <dd>{EDGE_TIERS[edgeTier(selectedEdgeData)].label}</dd>
                </div>
                <div>
                  <dt>Score</dt>
                  <dd>{selectedEdgeData.score ?? "-"}</dd>
                </div>
              </dl>
              <p className="card-copy">Evidence:</p>
              {renderPairEvidence && selectedEdgeData.pairing_id ? (
                renderPairEvidence(selectedEdgeData.pairing_id)
              ) : (
                <ul className="simple-list">
                  {evidenceLabels(selectedEdgeData).map((label) => (
                    <li key={label}>{label}</li>
                  ))}
                </ul>
              )}
            </>
          ) : selectedNodeData ? (
            <>
              <div className="graph-inspector-head">
                <div>
                  <span className="muted">Selected domain</span>
                  <strong>{selectedNodeData.label || selectedNode}</strong>
                </div>
                <button className="secondary-button small" onClick={clearFocus} type="button">
                  Clear
                </button>
              </div>
              <p className="card-copy graph-selection-summary">
                <strong>{selectedNodeData.label || selectedNode}</strong>
              </p>
              <dl className="graph-inspector-meta">
                <div>
                  <dt>Type</dt>
                  <dd>{nodeRole(selectedNodeData, seedTargets) === "submitted" ? "Anchor channel" : "Related channel"}</dd>
                </div>
                <div>
                  <dt>Tier</dt>
                  <dd>{selectedNodeData.tier ? DOMAIN_TIER_LABELS[selectedNodeData.tier] : "Unclassified"}</dd>
                </div>
                <div>
                  <dt>Relationships</dt>
                  <dd>{selectedNodeEdges.length}</dd>
                </div>
              </dl>
            </>
          ) : (
            <div className="graph-inspector-empty">
              <span className="muted">Inspector</span>
              <strong>Select a node or relationship</strong>
              <p className="card-copy">Details, evidence, score, and tier appear here.</p>
            </div>
          )}
        </aside>
      </div>
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
