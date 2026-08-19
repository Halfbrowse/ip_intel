import { useState } from "react";

import { ConnectionCard } from "./evidence.jsx";

// Renders a multi-hop chain (from /api/graph/path or /api/graph/related/*,
// both precomputed -- see db.intel_db.graph_paths) as a sequence of per-hop
// ConnectionCards, one for each link in the chain -- same expand-for-evidence
// interaction as a direct connection, applied hop by hop.
export function PathChain({ chain }) {
  const [expandedHop, setExpandedHop] = useState(null);
  if (!chain || chain.length === 0) {
    return null;
  }
  return (
    <ol className="linkage-list path-chain">
      {chain.map((hop, index) => (
        <li className="path-chain-hop" key={`${hop.from}|${hop.to}`}>
          <span className="path-chain-step">Step {index + 1}</span>
          <ConnectionCard
            expanded={expandedHop === index}
            leftLabel={hop.from}
            link={{ ...hop, a: hop.from, b: hop.to, target: hop.to }}
            onToggle={() => setExpandedHop((current) => (current === index ? null : index))}
            rightLabel={hop.to}
          />
        </li>
      ))}
    </ol>
  );
}
