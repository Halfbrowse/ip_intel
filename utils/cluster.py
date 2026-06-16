#!/usr/bin/env python3
"""
Build clusters from json_match pair output.

Two domains are in the same cluster if they are connected — directly or
transitively — by pair relationships whose score meets the threshold. The
output records the specific evidence types that held each cluster together
so you can see *why* the cluster exists, not just who's in it.

Usage:
    python cluster.py <overlaps_dir> <out_file.json> [--threshold N]

The <overlaps_dir> is the directory json_match.py wrote in --dir mode, which
must contain summary.json and one pair file per overlap.

Examples:
    # Strict clustering — only crypto-strength evidence (TLS or SSH fingerprint):
    python cluster.py ./investigation_01/overlaps clusters.json --threshold 90

    # Loose clustering — include shared trackers / registrars:
    python cluster.py ./investigation_01/overlaps clusters.json --threshold 30

    # Default: medium confidence — shared IP / analytics ID / similar strength:
    python cluster.py ./investigation_01/overlaps clusters.json
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path


# Match paths that identify forensically strong ("smoking gun") evidence.
# If any of these are in a pair's matches, the cluster membership is
# near-certain, regardless of the numerical score.
STRONG_PATHS = {
    "tls_certs.probes[*].fingerprint_sha256",
    "ssh_host_keys.probes[*].fingerprint_sha256",
}


# ── Union-find ────────────────────────────────────────────────────────────────
# Disjoint-set structure for connected-component grouping. Fast and trivial
# to implement; keeps the script dependency-free.

class UnionFind:
    def __init__(self) -> None:
        self._parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        if x not in self._parent:
            self._parent[x] = x
            return x
        # Path compression so find() stays O(α(n)) amortized.
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[x] != root:
            self._parent[x], x = root, self._parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[ra] = rb

    def groups(self) -> dict[str, list[str]]:
        """Return {root: [members...]} for every cluster."""
        out: dict[str, list[str]] = defaultdict(list)
        for node in self._parent:
            out[self.find(node)].append(node)
        return out


# ── Loading ───────────────────────────────────────────────────────────────────

def load_pair(overlap_dir: Path, filename: str) -> dict | None:
    try:
        return json.loads((overlap_dir / filename).read_text())
    except Exception as exc:
        print(f"  [!] couldn't read {filename}: {exc}")
        return None


# ── Cluster analysis ──────────────────────────────────────────────────────────

def cluster(overlap_dir: Path, threshold: int) -> dict:
    """
    Build clusters from pair files in overlap_dir whose score ≥ threshold.

    Returns a dict with:
      - threshold:    the score cutoff that was used
      - clusters:     list of cluster dicts, each with members + evidence
      - isolates:     domains that appeared in summary.json but matched no one
                      strongly enough to cluster
      - edge_count:   number of pair relationships used to form the clusters
    """
    summary_file = overlap_dir / "summary.json"
    if not summary_file.exists():
        raise SystemExit(f"  [!] {summary_file} not found — run json_match.py --dir first")
    summary = json.loads(summary_file.read_text())

    all_domains = sorted(summary.get("per_domain", {}).keys())
    pairs       = summary.get("pairs", [])

    uf = UnionFind()
    # Seed the union-find with every domain so isolates are detectable.
    for d in all_domains:
        uf.find(d)

    # Track the evidence that caused each union. When we later summarize a
    # cluster, we want to say "these six domains are linked by a shared TLS
    # fingerprint and two shared SSH host keys" — so we keep every crossed
    # edge with its matched paths and score.
    edges_used: list[dict] = []

    for pair in pairs:
        score = pair.get("score", 0)
        if score < threshold:
            continue

        pair_data = load_pair(overlap_dir, pair["file"])
        if pair_data is None:
            continue

        matches  = pair_data.get("matches", {}) or {}
        a_domain = pair_data.get("a_domain") or pair["a_domain"]
        b_domain = pair_data.get("b_domain") or pair["b_domain"]

        uf.union(a_domain, b_domain)
        edges_used.append({
            "a":             a_domain,
            "b":             b_domain,
            "score":         score,
            "paths":         list(matches.keys()),
            "has_strong":    bool(STRONG_PATHS & set(matches.keys())),
        })

    groups = uf.groups()

    # Split real clusters (≥ 2 members) from isolates (singleton domains).
    clusters:  list[dict] = []
    isolates:  list[str]  = []
    for _root, members in groups.items():
        if len(members) < 2:
            isolates.append(members[0])
            continue
        clusters.append(_summarize_cluster(sorted(members), edges_used))

    # Rank clusters: strongest evidence first, then by member count.
    clusters.sort(key=lambda c: (-c["max_edge_score"], -len(c["members"])))
    isolates.sort()

    return {
        "threshold":   threshold,
        "domain_count": len(all_domains),
        "cluster_count": len(clusters),
        "edge_count":  len(edges_used),
        "clusters":    clusters,
        "isolates":    isolates,
    }


def _summarize_cluster(members: list[str], edges_used: list[dict]) -> dict:
    """
    Collect the evidence that ties a cluster together.

    An edge "belongs" to this cluster if both endpoints are members. Counting
    which paths appear across those edges answers "why is this a cluster" —
    e.g., "five of the six internal edges share a TLS fingerprint; three
    share an SSH host key" tells you the backbone of the group.
    """
    member_set = set(members)
    internal_edges = [e for e in edges_used
                      if e["a"] in member_set and e["b"] in member_set]

    path_counts: dict[str, int] = defaultdict(int)
    strong_edges = 0
    max_score = 0
    for edge in internal_edges:
        if edge["has_strong"]:
            strong_edges += 1
        max_score = max(max_score, edge["score"])
        for path in edge["paths"]:
            path_counts[path] += 1

    # Top-5 evidence types across the cluster, ranked by how many internal
    # edges exhibit them.
    top_evidence = sorted(path_counts.items(), key=lambda kv: -kv[1])[:5]

    return {
        "members":        members,
        "member_count":   len(members),
        "edge_count":     len(internal_edges),
        "strong_edges":   strong_edges,
        "max_edge_score": max_score,
        "top_evidence":   [
            {"path": p, "label": _edge_labels([p])[0], "edges": n}
            for p, n in top_evidence
        ],
        "edges":          internal_edges,
    }


# ── Graph export ──────────────────────────────────────────────────────────────

# Tailwind-adjacent palette, picked for contrast on both light and dark UI.
_CLUSTER_COLORS = [
    "#ef4444", "#3b82f6", "#10b981", "#f59e0b", "#8b5cf6",
    "#ec4899", "#06b6d4", "#84cc16", "#f97316", "#6366f1",
    "#14b8a6", "#d946ef", "#eab308", "#22c55e", "#a855f7",
]
_ISOLATE_COLOR = "#9ca3af"  # grey

# Edge colors by evidence strength.
_EDGE_COLOR_STRONG = "#dc2626"  # red — crypto-strength (TLS/SSH fingerprint)
_EDGE_COLOR_INFRA  = "#f97316"  # orange — shared IP/NS/cert CN
_EDGE_COLOR_WEAK   = "#94a3b8"  # slate — shared registrar/country/etc.


def _edge_visual_class(paths: list[str]) -> str:
    """Pick an edge-color tier from the match paths on this edge."""
    paths_set = set(paths)
    if paths_set & STRONG_PATHS:
        return "strong"
    if any(str(path).startswith("observed_ip:") for path in paths_set):
        return "infra"
    infra_markers = {
        "non_cf_ips", "dns.A", "hackertarget.hits[*].ip",
        "urlscan.hits[*].ip", "tls_certs.probes[*].cn",
        "circl_pdns.records[*].rdata",
    }
    if paths_set & infra_markers:
        return "infra"
    return "weak"


def _node_cluster_lookup(clusters: list[dict]) -> dict[str, int]:
    """Map each domain to the index of its cluster (for color assignment)."""
    lookup: dict[str, int] = {}
    for i, c in enumerate(clusters):
        for m in c["members"]:
            lookup[m] = i
    return lookup


def _node_kind(node_id: str) -> str:
    import ipaddress
    try:
        ipaddress.ip_address(node_id)
        return "ip"
    except ValueError:
        return "domain"


def _edge_labels(paths: list[str]) -> list[str]:
    """Plain-English labels for an edge's matched paths (deduped, in order)."""
    from utils.evidence_meta import evidence_definition
    labels: list[str] = []
    for path in paths:
        if str(path).startswith("observed_ip:"):
            label = "Observed IP address"
        else:
            label = evidence_definition(str(path)).label
        if label not in labels:
            labels.append(label)
    return labels


def build_graph_payload(result: dict) -> dict:
    """
    Produce a serializable {nodes, edges} payload suitable for vis-network
    or for export to GEXF. Pulls everything from the cluster() result.
    """
    clusters = result["clusters"]
    isolates = result["isolates"]
    threshold = result["threshold"]

    cluster_of = _node_cluster_lookup(clusters)

    nodes: list[dict] = []
    for domain, idx in cluster_of.items():
        nodes.append({
            "id":      domain,
            "label":   domain,
            "group":   f"cluster-{idx}",
            "color":   _CLUSTER_COLORS[idx % len(_CLUSTER_COLORS)],
            "cluster": idx,
            "kind":    _node_kind(domain),
        })
    for iso in isolates:
        nodes.append({
            "id":      iso,
            "label":   iso,
            "group":   "isolate",
            "color":   _ISOLATE_COLOR,
            "cluster": None,
            "kind":    _node_kind(iso),
        })

    edges: list[dict] = []
    seen_edges: set[tuple[str, str]] = set()
    for c in clusters:
        for edge in c.get("edges", []):
            a, b = edge["a"], edge["b"]
            key = tuple(sorted((a, b)))
            if key in seen_edges:
                continue
            seen_edges.add(key)
            paths = edge.get("paths") or []
            visual = _edge_visual_class(paths)
            edges.append({
                "from":   a,
                "to":     b,
                "score":  edge["score"],
                "paths":  paths,
                "labels": _edge_labels(paths),
                # The pair this edge came from; lets the UI render the same
                # evidence packet the summary page shows for the same entities.
                "pairing_id": edge.get("pairing_id"),
                "visual": visual,
                # Edge thickness scaled by score. Cap so one high-score edge
                # doesn't dominate the rendering.
                "width":  min(8, max(1, edge["score"] // 30)),
                "color":  {
                    "strong": _EDGE_COLOR_STRONG,
                    "infra":  _EDGE_COLOR_INFRA,
                    "weak":   _EDGE_COLOR_WEAK,
                }[visual],
                "title":  (f"score {edge['score']}\n"
                           + "\n".join(f"· {p}" for p in paths)),
            })

    return {
        "nodes":     nodes,
        "edges":     edges,
        "threshold": threshold,
        "stats": {
            "node_count":    len(nodes),
            "edge_count":    len(edges),
            "cluster_count": len(clusters),
            "isolate_count": len(isolates),
        },
    }


def collapse_graph_to_apex(payload: dict, apex_of) -> dict:
    """
    Fold a {nodes, edges} graph so each *domain* node becomes its registrable
    apex ("main domain"); IP nodes are left as-is. Subdomain nodes merge into
    their apex, same-site edges (a subdomain to its own apex) disappear, and
    parallel edges between the same collapsed pair are merged.

    The merged edge keeps the strongest score and the union of evidence, plus a
    ``contributors`` list recording the original subdomain-level links that fed
    it — so the UI can show "linked via vpn.a.com ↔ b.com" when an apex↔apex
    connection is expanded. ``apex_of`` is injected (e.g. ``basic._apex``) to
    keep this module dependency-free.
    """
    def collapse_id(node_id: str) -> str:
        if _node_kind(node_id) == "ip":
            return node_id
        return apex_of(node_id) or node_id

    nodes: list[dict] = []
    seen_nodes: set[str] = set()
    for node in payload.get("nodes") or []:
        cid = collapse_id(node["id"])
        if cid in seen_nodes:
            continue
        seen_nodes.add(cid)
        nodes.append({**node, "id": cid, "label": cid})

    merged: dict[tuple[str, str], dict] = {}
    for edge in payload.get("edges") or []:
        a, b = collapse_id(edge["from"]), collapse_id(edge["to"])
        if a == b:
            continue  # same-site (subdomain ↔ its own apex) — nothing to show
        key = tuple(sorted((a, b)))
        contributor = {
            "from": edge["from"],
            "to": edge["to"],
            "score": edge.get("score", 0),
            "labels": edge.get("labels") or [],
            "pairing_id": edge.get("pairing_id"),
            "via_subdomain": edge["from"] != a or edge["to"] != b,
        }
        existing = merged.get(key)
        if existing is None:
            paths = list(edge.get("paths") or [])
            merged[key] = {
                "from": key[0],
                "to": key[1],
                "score": edge.get("score", 0),
                "paths": paths,
                "labels": list(edge.get("labels") or []),
                # Apex pairing id is assigned authoritatively after collapse;
                # seed it from a direct apex↔apex edge when one is present.
                "pairing_id": edge.get("pairing_id") if not contributor["via_subdomain"] else None,
                "visual": edge.get("visual", "weak"),
                "width": edge.get("width", 1),
                "color": edge.get("color"),
                "contributors": [contributor],
            }
        else:
            existing["contributors"].append(contributor)
            if not contributor["via_subdomain"] and edge.get("pairing_id"):
                existing["pairing_id"] = edge.get("pairing_id")
            for path in edge.get("paths") or []:
                if path not in existing["paths"]:
                    existing["paths"].append(path)
            for label in edge.get("labels") or []:
                if label not in existing["labels"]:
                    existing["labels"].append(label)
            if edge.get("score", 0) > existing["score"]:
                existing["score"] = edge["score"]
                existing["width"] = edge.get("width", existing["width"])
            # Promote the strongest visual tier present on any contributing edge.
            if _visual_rank(edge.get("visual", "weak")) > _visual_rank(existing["visual"]):
                existing["visual"] = edge.get("visual", "weak")
                existing["color"] = edge.get("color")

    edges: list[dict] = []
    for item in merged.values():
        item["contributors"].sort(key=lambda c: -(c.get("score") or 0))
        item["title"] = f"score {item['score']}\n" + "\n".join(f"· {p}" for p in item["paths"])
        edges.append(item)

    return {
        **payload,
        "nodes": nodes,
        "edges": edges,
        "stats": {
            **(payload.get("stats") or {}),
            "node_count": len(nodes),
            "edge_count": len(edges),
        },
    }


def submitted_bridge_graph(payload: dict, apex_of, submitted) -> dict:
    """
    Reduce a full {nodes, edges} graph to just the *submitted* domains and the
    subdomains that *bridge* one submitted domain to another.

    Rendering rules (see the connection-map UI):
      * Each submitted domain is drawn once, as a single apex node.
      * A subdomain is drawn **iff** it carries a cross-domain link to a
        *different* submitted domain — i.e. it is a genuine bridge. Non-bridging
        subdomains, non-submitted domains, and IP nodes are dropped entirely.
      * "Evidence" edges connect the real endpoints of each link (a submitted
        apex, or one of its bridge subdomains).
      * A light "membership" edge ties every bridge subdomain back to the apex
        it belongs to, so the reader can see which submitted domain it sits under.

    ``apex_of`` is injected (e.g. ``basic._apex``) to keep this module
    dependency-free; ``submitted`` is the set of submitted domain labels.
    """
    submitted_apex = {apex_of(s) for s in submitted}
    # Original node metadata, so rebuilt nodes keep their colour / cluster group.
    meta = {node["id"]: node for node in (payload.get("nodes") or [])}

    nodes: dict[str, dict] = {}
    membership: set[tuple[str, str]] = set()
    evidence: list[dict] = []

    def add_apex(apex: str) -> None:
        if apex not in nodes:
            nodes[apex] = {
                **meta.get(apex, {}),
                "id": apex,
                "label": apex,
                "kind": "apex",
                "role": "submitted",
            }

    def add_bridge(node_id: str, apex: str) -> None:
        if node_id not in nodes:
            nodes[node_id] = {
                **meta.get(node_id, {}),
                "id": node_id,
                "label": node_id,
                "kind": "subdomain",
                "role": "bridge",
                "apex": apex,
            }
        membership.add((apex, node_id))

    for edge in payload.get("edges") or []:
        u, v = edge["from"], edge["to"]
        au, av = apex_of(u), apex_of(v)
        if au == av:
            continue  # same-site link — nothing to bridge
        if au not in submitted_apex or av not in submitted_apex:
            continue  # at least one side isn't a submitted domain — drop it
        add_apex(au)
        add_apex(av)
        # An endpoint is either the apex itself (direct link) or a bridge subdomain.
        nu = au if u == au else u
        nv = av if v == av else v
        if nu != au:
            add_bridge(nu, au)
        if nv != av:
            add_bridge(nv, av)
        evidence.append({**edge, "from": nu, "to": nv, "kind": "evidence"})

    edges: list[dict] = list(evidence)
    for apex, sub in sorted(membership):
        edges.append({
            "from": apex,
            "to": sub,
            "kind": "membership",
            "visual": "owns",
            "score": 0,
            "width": 1,
            "labels": [],
            "paths": [],
            "contributors": [],
        })

    return {
        **payload,
        "nodes": list(nodes.values()),
        "edges": edges,
        "stats": {
            **(payload.get("stats") or {}),
            "node_count": len(nodes),
            "edge_count": len(edges),
            "submitted_count": len(submitted_apex),
            "bridge_count": sum(1 for n in nodes.values() if n.get("role") == "bridge"),
        },
    }


_VISUAL_ORDER = {"weak": 0, "infra": 1, "strong": 2}


def _visual_rank(visual: str) -> int:
    return _VISUAL_ORDER.get(str(visual), 0)


def write_html_graph(payload: dict, out_file: Path) -> None:
    """
    Write a self-contained interactive HTML page with a vis-network graph.
    No server required — open the file in a browser.
    """
    # Embed the payload as JSON inside a <script> tag so the page works
    # offline and can be emailed / saved without breaking.
    payload_json = json.dumps(payload, default=str)

    # The vis-network CDN URL is pinned to a specific version so the graph
    # doesn't break if vis-network ships a breaking change later.
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ip-intel clusters</title>
<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
<style>
  html, body {{
    margin: 0; padding: 0;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    background: #0f172a; color: #e2e8f0;
    height: 100%;
  }}
  #header {{
    padding: 12px 16px; background: #1e293b; border-bottom: 1px solid #334155;
    display: flex; justify-content: space-between; align-items: center;
    flex-wrap: wrap; gap: 12px;
  }}
  #header h1 {{ margin: 0; font-size: 14px; font-weight: 600; }}
  #header .stats {{ font-size: 12px; color: #94a3b8; }}
  #legend {{ font-size: 11px; color: #cbd5e1; }}
  #legend span.swatch {{
    display: inline-block; width: 14px; height: 3px;
    vertical-align: middle; margin: 0 4px;
  }}
  #net {{ height: calc(100vh - 56px); background: #0f172a; }}
  .vis-tooltip {{
    background: #1e293b !important; color: #e2e8f0 !important;
    border: 1px solid #334155 !important; padding: 8px !important;
    font-family: inherit !important; font-size: 11px !important;
    white-space: pre !important;
  }}
</style>
</head>
<body>
<div id="header">
  <h1>ip-intel clusters</h1>
  <div class="stats"></div>
  <div id="legend">
    <span class="swatch" style="background:{_EDGE_COLOR_STRONG};"></span>crypto-strength
    <span class="swatch" style="background:{_EDGE_COLOR_INFRA};"></span>infrastructure
    <span class="swatch" style="background:{_EDGE_COLOR_WEAK};"></span>weak
  </div>
</div>
<div id="net"></div>
<script>
  const payload = {payload_json};
  document.querySelector('.stats').textContent =
    `threshold ${{payload.threshold}} · ${{payload.stats.node_count}} nodes · `
    + `${{payload.stats.edge_count}} edges · ${{payload.stats.cluster_count}} clusters `
    + `· ${{payload.stats.isolate_count}} isolates`;

  const nodes = new vis.DataSet(payload.nodes.map(n => ({{
    id: n.id, label: n.label,
    color: {{ background: n.color, border: n.color,
             highlight: {{ background: n.color, border: '#fff' }} }},
    font: {{ color: '#f8fafc', face: 'monospace', size: 11 }},
    shape: 'dot', size: n.cluster === null ? 8 : 14,
  }})));

  const edges = new vis.DataSet(payload.edges.map(e => ({{
    from: e.from, to: e.to, width: e.width,
    color: {{ color: e.color, highlight: '#fff' }},
    title: e.title, smooth: false,
  }})));

  const network = new vis.Network(
    document.getElementById('net'),
    {{ nodes, edges }},
    {{
      physics: {{
        enabled: true,
        barnesHut: {{ gravitationalConstant: -8000, springLength: 120 }},
        stabilization: {{ iterations: 150 }},
      }},
      interaction: {{ hover: true, tooltipDelay: 120 }},
      edges: {{ font: {{ size: 9 }} }},
    }}
  );

  // Click a node to print its neighborhood to the console — useful for
  // quickly seeing which domains cluster with a specific one.
  network.on('click', params => {{
    if (!params.nodes.length) return;
    const node = params.nodes[0];
    const connected = network.getConnectedNodes(node);
    console.log(node, '→', connected);
  }});
</script>
</body>
</html>
"""
    out_file.write_text(html, encoding="utf-8")


def write_gexf_graph(payload: dict, out_file: Path) -> None:
    """
    Write a GEXF 1.2 file for Gephi/Cytoscape. No XML library required;
    GEXF is small enough to string-build safely.
    """
    from xml.sax.saxutils import escape as xe

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<gexf xmlns="http://www.gexf.net/1.2draft" version="1.2">',
        '  <graph mode="static" defaultedgetype="undirected">',
        '    <attributes class="node">',
        '      <attribute id="0" title="cluster" type="integer"/>',
        '    </attributes>',
        '    <attributes class="edge">',
        '      <attribute id="0" title="score"  type="integer"/>',
        '      <attribute id="1" title="paths"  type="string"/>',
        '      <attribute id="2" title="visual" type="string"/>',
        '    </attributes>',
        '    <nodes>',
    ]

    for n in payload["nodes"]:
        color = n["color"].lstrip("#")
        r, g, b = int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)
        lines.append(f'      <node id="{xe(n["id"])}" label="{xe(n["label"])}">')
        lines.append(f'        <viz:color r="{r}" g="{g}" b="{b}" xmlns:viz="http://www.gexf.net/1.2draft/viz"/>')
        if n["cluster"] is not None:
            lines.append( '        <attvalues>')
            lines.append(f'          <attvalue for="0" value="{n["cluster"]}"/>')
            lines.append( '        </attvalues>')
        lines.append( '      </node>')

    lines.append('    </nodes>')
    lines.append('    <edges>')
    for i, e in enumerate(payload["edges"]):
        paths_str = "; ".join(e.get("paths") or [])
        lines.append(
            f'      <edge id="{i}" source="{xe(e["from"])}" '
            f'target="{xe(e["to"])}" weight="{e["score"]}">'
        )
        lines.append( '        <attvalues>')
        lines.append(f'          <attvalue for="0" value="{e["score"]}"/>')
        lines.append(f'          <attvalue for="1" value="{xe(paths_str)}"/>')
        lines.append(f'          <attvalue for="2" value="{e["visual"]}"/>')
        lines.append( '        </attvalues>')
        lines.append( '      </edge>')
    lines.append('    </edges>')
    lines.append('  </graph>')
    lines.append('</gexf>')
    out_file.write_text("\n".join(lines), encoding="utf-8")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Build clusters from json_match output.")
    parser.add_argument("overlap_dir", type=Path,
                        help="Directory produced by json_match.py --dir")
    parser.add_argument("out_file", type=Path,
                        help="Where to write the clusters JSON")
    parser.add_argument("--threshold", type=int, default=60,
                        help="Minimum pair score to form an edge (default: 60)")
    parser.add_argument("--no-graph", action="store_true",
                        help="Skip graph export (HTML + GEXF) — JSON only.")
    args = parser.parse_args()

    result = cluster(args.overlap_dir, args.threshold)

    args.out_file.write_text(json.dumps(result, indent=2, default=str))

    print(f"\n  [+] {result['cluster_count']} cluster(s), "
          f"{len(result['isolates'])} isolate(s), "
          f"{result['edge_count']} edge(s) above threshold {result['threshold']}")
    print(f"      → {args.out_file}")

    if not args.no_graph:
        payload   = build_graph_payload(result)
        html_path = args.out_file.with_suffix(".html")
        gexf_path = args.out_file.with_suffix(".gexf")
        write_html_graph(payload, html_path)
        write_gexf_graph(payload, gexf_path)
        print(f"      → {html_path}  (open in browser)")
        print(f"      → {gexf_path}  (open in Gephi/Cytoscape)")

    print()

    # Human-readable summary.
    for i, c in enumerate(result["clusters"], 1):
        strong_note = f", {c['strong_edges']} crypto-strength" if c["strong_edges"] else ""
        print(f"  Cluster {i}  ({c['member_count']} members, "
              f"{c['edge_count']} edges{strong_note}, max score {c['max_edge_score']}):")
        for m in c["members"]:
            print(f"      · {m}")
        if c["top_evidence"]:
            print(f"    linked by:")
            for ev in c["top_evidence"]:
                print(f"      · {ev['path']}  ({ev['edges']} edge(s))")
        print()

    if result["isolates"]:
        print(f"  Isolates ({len(result['isolates'])}):")
        for m in result["isolates"][:20]:
            print(f"      · {m}")
        if len(result["isolates"]) > 20:
            print(f"      ... and {len(result['isolates']) - 20} more")


if __name__ == "__main__":
    main()
