import { useCallback, useEffect, useRef, useState } from "react";

// Upper bound on any single request. Without it a stalled intel lookup — the
// VPN sidecar down, a provider hanging — leaves the UI spinning indefinitely
// with no way for the user to tell a slow answer from a dead one.
const REQUEST_TIMEOUT_MS = 45000;

// One AbortController per request, aborted on unmount/path change or timeout.
// `timedOut()` separates the two: an unmount abort must stay silent, but a
// timeout is the user's answer and has to reach the screen — reporting neither
// is how a request that gave up still leaves a spinner turning forever.
function requestSignal(timeoutMs = REQUEST_TIMEOUT_MS) {
  const controller = new AbortController();
  const state = { timedOut: false };
  const timerId = window.setTimeout(() => {
    state.timedOut = true;
    controller.abort(new Error("timeout"));
  }, timeoutMs);
  return {
    signal: controller.signal,
    timedOut: () => state.timedOut,
    abort: () => controller.abort(),
    done: () => window.clearTimeout(timerId),
  };
}

const TIMEOUT_MESSAGE = "The server did not respond in time. It may still be working — try again.";

function isAbort(error) {
  return error?.name === "AbortError" || error?.message === "timeout";
}

// Last successful response per request path, kept across mounts. Without it,
// clicking Pool -> Domain -> Pool tore down the hook and started from nothing:
// a spinner, a full refetch, and a full re-parse of a payload the browser
// already had. Now a revisit renders the previous payload immediately and
// revalidates in the background with If-None-Match, so the common navigation
// (back to a page whose data has not changed) costs one 304 and no re-render.
// Bounded because /api/search paths are per-keystroke and unbounded.
const RESPONSE_CACHE_LIMIT = 50;
const responseCache = new Map();

function readCache(path) {
  return path ? responseCache.get(path) : undefined;
}

function writeCache(path, entry) {
  if (!path) {
    return;
  }
  // Re-insert so iteration order stays least-recently-used first.
  responseCache.delete(path);
  responseCache.set(path, entry);
  if (responseCache.size > RESPONSE_CACHE_LIMIT) {
    responseCache.delete(responseCache.keys().next().value);
  }
}

// `keepPreviousData` opts a caller into showing the *previous path's* payload
// while a new one loads. Only correct where consecutive paths describe the same
// resource narrowed differently — the pool's filter/sort/page query, where
// blanking made the whole card grid unmount and reappear on every keystroke.
// It is wrong anywhere the path identifies a different subject: a domain page
// would render one channel's heading over another channel's intel.
export function useApi(path, options = {}) {
  const { enabled = true, pollInterval = 0, keepPreviousData = false } = options;
  const [state, setState] = useState(() => {
    const cached = enabled ? readCache(path) : undefined;
    return {
      data: cached ? cached.data : null,
      error: null,
      status: null,
      loading: Boolean(path && enabled) && !cached,
    };
  });
  const [requestVersion, setRequestVersion] = useState(0);
  const loadRef = useRef(null);

  useEffect(() => {
    if (!path || !enabled) {
      setState({ data: null, error: null, status: null, loading: false });
      loadRef.current = null;
      return undefined;
    }

    let active = true;
    let requestSequence = 0;
    let inFlight = false;
    // Every in-flight request, so unmount/path-change aborts them rather than
    // just ignoring the reply. An ignored reply still holds a server worker
    // open — on /api/graph/connections that is a live scoring run — and still
    // lands a setState after unmount.
    const pending = new Set();
    // Cheap change detection: keep the raw response text and the ETag from
    // the last successful fetch. Polls send If-None-Match (a 304 costs almost
    // nothing on the wire) and the body is only parsed when it changed. Seeded
    // from the cross-mount cache so a revisit revalidates instead of reloading.
    const seed = readCache(path);
    let lastBodyText = seed ? seed.text : null;
    let lastEtag = seed ? seed.etag : null;

    const keepCurrent = (previous) => {
      if (previous.error === null && previous.loading === false) {
        return previous;
      }
      return { data: previous.data, error: null, status: null, loading: false };
    };

    const load = async (reset = false) => {
      if (inFlight && !reset) {
        // A previous poll is still running; skip this tick instead of piling
        // up overlapping requests.
        return;
      }
      const currentRequest = ++requestSequence;
      inFlight = true;
      if (reset) {
        lastBodyText = null;
        lastEtag = null;
      }

      // Avoid a redundant re-render on every poll tick: when a load is already
      // in a clean loading state we return the same state ref so React bails
      // out — the 304 and byte-identical paths below do the same.
      //
      // Data is carried through here, which is safe because every load reached
      // from this closure is for the *same* path (a poll, a refresh, a
      // revalidation). Crossing to a new path goes through the effect body
      // below, which decides there whether the old payload may stay.
      setState((previous) =>
        previous.loading && previous.error === null
          ? previous
          : { data: previous.data, error: null, status: null, loading: true },
      );

      const request = requestSignal();
      pending.add(request);
      try {
        const headers = { Accept: "application/json" };
        if (lastEtag) {
          headers["If-None-Match"] = lastEtag;
        }
        const response = await fetch(path, { headers, signal: request.signal });

        if (!active || currentRequest !== requestSequence) {
          return;
        }

        if (response.status === 304) {
          // Unchanged since the last poll; keep the data we already have.
          setState(keepCurrent);
          return;
        }

        const text = response.status === 204 ? "" : await response.text();

        if (!active || currentRequest !== requestSequence) {
          return;
        }

        if (!response.ok) {
          const payload = parseTextPayload(text);
          const message =
            (payload &&
              typeof payload === "object" &&
              (payload.detail || payload.message || payload.error)) ||
            `Request failed with status ${response.status}`;
          const failure = new Error(String(message));
          // Carried through to state so a caller can tell "the server says
          // there is nothing" (404) from "the request failed" — rendering the
          // second as the first turns an outage into a confident analytic
          // negative, which is the worst answer an intel tool can give.
          failure.status = response.status;
          throw failure;
        }

        if (lastBodyText !== null && text === lastBodyText) {
          lastEtag = response.headers.get("etag");
          setState(keepCurrent);
          return;
        }

        const data = parseTextPayload(text);
        // A 200 carrying something that is not JSON is not data. A reverse
        // proxy error page, or the SPA index.html served for an /api/* path,
        // used to be stored verbatim: `profile` became a string, every
        // `profile?.selectors` read yielded undefined, and the page rendered
        // as fully loaded and completely empty. For an intel tool that reads
        // as the finding "nothing here", so it has to be an error instead.
        if (text && (data === null || typeof data !== "object")) {
          throw new Error("Unexpected response from the server (expected JSON).");
        }

        // Only remember the validator *after* the body passed validation.
        // Recording it above meant the next poll sent If-None-Match, got a 304,
        // and `keepCurrent` cleared the error — so a proxy error page surfaced
        // for one tick and then silently became "loaded, empty".
        lastEtag = response.headers.get("etag");
        lastBodyText = text;
        writeCache(path, { text, etag: lastEtag, data });
        setState({ data, error: null, status: null, loading: false });
      } catch (error) {
        if (!active || currentRequest !== requestSequence) {
          return;
        }
        // An unmount/supersede abort is silent; a timeout is not. Returning for
        // both left `loading: true` set forever, which is the exact symptom the
        // timeout was added to remove.
        if (isAbort(error) && !request.timedOut()) {
          return;
        }

        setState((previous) => ({
          data: previous.data,
          error: request.timedOut() ? TIMEOUT_MESSAGE : error.message || "Request failed.",
          status: error.status ?? null,
          loading: false,
        }));
      } finally {
        request.done();
        pending.delete(request);
        if (currentRequest === requestSequence) {
          inFlight = false;
        }
      }
    };

    loadRef.current = load;
    if (seed) {
      // Paint the known-good payload first, then revalidate in the background.
      setState({ data: seed.data, error: null, status: null, loading: false });
      load(false);
    } else {
      // Nothing cached for this path, so whatever is in state right now belongs
      // to the path we just left. Drop it unless the caller opted in: carrying
      // it over rendered one channel's intel under another channel's heading,
      // and made a just-started ingest job inherit the previous job's
      // "complete" status and fire its completion callback immediately.
      if (!keepPreviousData) {
        setState({ data: null, error: null, status: null, loading: true });
      }
      load(true);
    }

    return () => {
      active = false;
      pending.forEach((request) => {
        request.done();
        request.abort();
      });
      pending.clear();
      if (loadRef.current === load) {
        loadRef.current = null;
      }
    };
  }, [enabled, path, requestVersion, keepPreviousData]);

  // Polling lives in its own effect so that turning it on or off (for example
  // when a job finishes) does not reset the data that is already loaded.
  useEffect(() => {
    if (!path || !enabled || !(pollInterval > 0)) {
      return undefined;
    }

    const timerId = window.setInterval(() => {
      // Skip background work while the tab is hidden.
      if (document.hidden) {
        return;
      }
      loadRef.current?.(false);
    }, pollInterval);

    const handleVisibility = () => {
      // Refresh immediately when the tab becomes visible again.
      if (!document.hidden) {
        loadRef.current?.(false);
      }
    };
    document.addEventListener("visibilitychange", handleVisibility);

    return () => {
      window.clearInterval(timerId);
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, [enabled, path, pollInterval, requestVersion]);

  // Stable identity: `refresh` is passed as `onIngested`/`onComplete`, and a
  // fresh function every render re-ran those completion effects on every
  // parent render (harmless only because of a notified-once ref guard).
  const refresh = useCallback(() => {
    // An explicit refresh (or a finished ingest) must not be answered from
    // the remembered payload, so drop it before re-running the effect.
    responseCache.delete(path);
    setRequestVersion((version) => version + 1);
  }, [path]);

  return { ...state, refresh };
}

function parseTextPayload(text) {
  if (!text) {
    return null;
  }

  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

// The one-shot fetch used by everything outside useApi (cluster graph loads,
// the connections scoring POST, ingest submission). There used to be two of
// these — this one, unused, and `finishIngest` in features/ingest.jsx, which
// the pages imported instead. Pages taking their generic response parser from
// a module named "ingest" was the wrong shape, so the behaviour lives here and
// features/ingest.jsx re-exports it.
export async function fetchJson(path, init = {}) {
  const { timeoutMs = REQUEST_TIMEOUT_MS, signal: callerSignal, ...rest } = init;
  const request = requestSignal(timeoutMs);
  // Honour a caller's own signal alongside the timeout.
  const onCallerAbort = () => request.abort();
  callerSignal?.addEventListener("abort", onCallerAbort, { once: true });
  try {
    const response = await fetch(path, {
      ...rest,
      signal: request.signal,
      headers: { Accept: "application/json", ...(rest.headers || {}) },
    });
    return await readJsonResponse(response);
  } catch (error) {
    // The abort reason is the literal string "timeout"; surfacing that raw put
    // the word "timeout" on screen as the entire error message.
    throw request.timedOut() ? new Error(TIMEOUT_MESSAGE) : error;
  } finally {
    request.done();
    callerSignal?.removeEventListener("abort", onCallerAbort);
  }
}

// Shared response handling: surfaces the server's error text when it sent one,
// and refuses a non-JSON 2xx body rather than passing an HTML error page
// downstream as though it were data.
export async function readJsonResponse(response) {
  if (response.status === 204) {
    return null;
  }

  const text = await response.text();
  const payload = parseTextPayload(text);

  if (!response.ok) {
    const message =
      (payload && typeof payload === "object" && (payload.detail || payload.message || payload.error)) ||
      (typeof payload === "string" && payload.trim() && payload.length < 200 ? payload : null) ||
      `Request failed with status ${response.status}`;
    const failure = new Error(String(message));
    // Same contract as useApi's error: callers branch on 404 vs everything
    // else, and without this every fetchJson caller is structurally unable to.
    failure.status = response.status;
    throw failure;
  }

  if (text && (payload === null || typeof payload !== "object")) {
    throw new Error("Unexpected response from the server (expected JSON).");
  }

  return payload;
}

export function normalizeJob(payload, fallbackId = null) {
  const raw = unwrapEntity(payload, ["job", "data", "item", "result"]);
  const steps = coerceArray(
    pickFirst(raw, ["steps", "timeline", "milestones", "stages"], []),
  ).map((step, index) => normalizeStep(step, index));

  return {
    raw,
    id: pickFirst(raw, ["id", "job_id", "jobId"], fallbackId),
    status: normalizeStatus(pickFirst(raw, ["status", "state", "phase"], "unknown")),
    percent:
      resolvePercent(
        pickFirst(raw, [
          "percent_complete",
          "progress_percent",
          "progress",
          "percent",
          "completion",
        ]),
      ) ?? deriveStepPercent(raw),
    summary: summarizeText(
      pickFirst(raw, ["summary", "description", "message", "detail", "current_step"]),
    ),
    stage: pickFirst(raw, ["stage", "job_stage", "phase"], null),
    currentTarget: pickFirst(raw, ["current_target", "currentTarget"], null),
    currentStep: pickFirst(raw, ["current_step", "currentStep", "phase_name", "stage_name"]),
    completedSteps:
      pickFirst(raw, ["completed_steps", "completedSteps", "counts.completed"], null) ?? null,
    totalSteps: pickFirst(raw, ["total_steps", "totalSteps", "counts.total"], null) ?? null,
    failedTargets: pickFirst(raw, ["failed_targets", "failedTargets", "counts.failed"], null) ?? null,
    updatedAt: pickFirst(raw, ["updated_at", "updatedAt", "last_seen_at", "lastSeenAt"]),
    logs: normalizeLogLines(pickFirst(raw, ["logs", "events", "messages"], [])),
    steps,
  };
}

// Mirrors the backend's saturating score→confidence curve so pairs stored
// before the confidence field existed still display a bounded percentage
// instead of a raw additive score clamped at 100.
export function confidenceFromScore(score) {
  const value = Number(score);
  if (!Number.isFinite(value) || value <= 0) {
    return 0;
  }
  return Math.round((100 * value) / (value + 65));
}

// ── Global correlation graph ────────────────────────────────────────────────
// Shapes the /api/graph/links response into ranked connections, each carrying
// its shared-node evidence breakdown (the deliverable — never a bare score).

export function normalizeGraphLinks(payload) {
  return coerceArray(payload?.links ?? payload).map((item, index) => normalizeGraphLink(item, index));
}

export function normalizeGraphLink(item, index = 0) {
  const raw = item || {};
  const target = readableValue(pickFirst(raw, ["target", "registrable_domain", "rd", "b"], `link-${index}`));
  return {
    raw,
    target,
    score: typeof raw.score === "number" ? raw.score : Number(raw.score) || 0,
    confidence: resolvePercent(pickFirst(raw, ["confidence"])) ?? confidenceFromScore(raw.score),
    strength: pickFirst(raw, ["strength"]) || null,
    sharedNodeCount: pickFirst(raw, ["shared_node_count", "sharedNodeCount"], null),
    evidence: coerceArray(raw.evidence).map((node, nodeIndex) => normalizeSharedNode(node, nodeIndex)),
  };
}

function normalizeSharedNode(node, index) {
  const raw = node || {};
  const window = (value) => {
    const range = coerceArray(value);
    return range.length ? range.map((entry) => (entry ? String(entry) : null)) : [null, null];
  };
  return {
    id: `${raw.kind || "node"}-${raw.value || index}`,
    nodeType: pickFirst(raw, ["node_type", "nodeType"], "selector"),
    kind: pickFirst(raw, ["kind"], "unknown"),
    // Provider prefix for "<provider>|<id>"-shaped values (tracking_id,
    // site_verification, social_handle, crypto_wallet) — e.g. "google" out of
    // "google|abc123", or "bitcoin" out of "bitcoin|bc1q...". Kept in sync with
    // PREFIXED_VALUE_KINDS in features/evidence.jsx, which strips the prefix
    // from the displayed value.
    subkind: pickFirst(raw, ["subkind"], null),
    value: readableValue(pickFirst(raw, ["value"])) || "—",
    degree: pickFirst(raw, ["degree"], null),
    attributing: raw.attributing !== false,
    baseWeight: pickFirst(raw, ["base_weight", "baseWeight"], null),
    rarity: pickFirst(raw, ["rarity"], null),
    timeOverlap: pickFirst(raw, ["time_overlap", "timeOverlap"], null),
    // How much the match's weight was discounted for staleness (1 = seen
    // recently, lower = the exact same node hasn't been seen in a while) —
    // distinct from timeOverlap, which only measures whether the two sides'
    // own windows agree with each other. See utils/check.recency_weight.
    recency: pickFirst(raw, ["recency"], null),
    // True when the backend attached a plain-language reason (in
    // `explanation`) for why this match scored below what its kind normally
    // gets — e.g. a TLS cert shared by hundreds of domains, or one not seen
    // in years. Lets the UI flag it distinctly instead of just a smaller number.
    degraded: raw.degraded === true,
    weight: pickFirst(raw, ["weight"], null),
    sources: coerceArray(raw.sources).map((entry) => readableValue(entry)).filter(Boolean),
    windowA: window(pickFirst(raw, ["window_a", "windowA"])),
    windowB: window(pickFirst(raw, ["window_b", "windowB"])),
    // The specific host(s) that exhibited this node on each side — may be a
    // subdomain of the compared apex, not the apex itself (transitive,
    // subdomain-mediated linkage). Empty when the backend didn't supply it.
    hostsA: coerceArray(raw.hosts_a ?? raw.hostsA).map((entry) => readableValue(entry)).filter(Boolean),
    hostsB: coerceArray(raw.hosts_b ?? raw.hostsB).map((entry) => readableValue(entry)).filter(Boolean),
    // Only populated on `shared_ip` nodes — what kind of box the IP is
    // (CDN/proxy edge, shared-hosting pool, or likely dedicated origin) and a
    // plain-language explanation, so a shared IP reads as more than a bare hit.
    network: pickFirst(raw, ["network"], null),
    explanation: pickFirst(raw, ["explanation"], null),
    // Only populated on `tls_cert_sha256` nodes — the certificate's own
    // identity (CN, issuer) and its real CA-issued validity window, not just
    // our scan history (windowA/windowB above). See db.intel_db.tls_cert_context.
    certCn: pickFirst(raw, ["cert_cn", "certCn"], null),
    certIssuerCn: pickFirst(raw, ["cert_issuer_cn", "certIssuerCn"], null),
    certIssuerOrg: pickFirst(raw, ["cert_issuer_org", "certIssuerOrg"], null),
    certNotBefore: pickFirst(raw, ["cert_not_before", "certNotBefore"], null),
    certNotAfter: pickFirst(raw, ["cert_not_after", "certNotAfter"], null),
    asnDesc: pickFirst(raw, ["asn_desc", "asnDesc"], null),
    networkName: pickFirst(raw, ["network_name", "networkName"], null),
    proxyFamily: pickFirst(raw, ["proxy_family", "proxyFamily"], null),
    cloudflare: raw.cloudflare === true,
    country: pickFirst(raw, ["country"], null),
  };
}

export function normalizeGraphClusters(payload) {
  return coerceArray(payload?.clusters ?? payload).map((item, index) => {
    const raw = item || {};
    const members = coerceArray(pickFirst(raw, ["members"], []))
      .map((entry) => readableValue(entry))
      .filter(Boolean);
    const links = normalizeClusterLinks(raw);
    return {
      raw,
      id: pickFirst(raw, ["cluster_id", "clusterId", "id"], `cluster-${index}`),
      size: pickFirst(raw, ["component_size", "componentSize", "size"], members.length),
      members,
      links,
      linkCount: pickFirst(raw, ["link_count", "linkCount"], links.length),
    };
  });
}

// The shared nodes that tie a cluster together ("what connects it"), strongest
// (most members) first.
export function normalizeClusterLinks(payload) {
  return coerceArray(payload?.links ?? payload)
    .map((item) => {
      const raw = item || {};
      return {
        nodeType: pickFirst(raw, ["node_type", "nodeType"], "selector"),
        kind: pickFirst(raw, ["kind"], "unknown"),
        value: readableValue(pickFirst(raw, ["value"])) || "—",
        memberCount: pickFirst(raw, ["member_count", "memberCount"], null),
      };
    })
    .filter((link) => link.value && link.value !== "—");
}

export function normalizePool(payload) {
  return coerceArray(payload?.domains ?? payload)
    .map((item) => {
      const raw = item || {};
      return {
        domain: readableValue(pickFirst(raw, ["domain"])),
        hostCount: pickFirst(raw, ["host_count", "hostCount"], null),
        lastSeen: pickFirst(raw, ["last_seen", "lastSeen"], null),
        // Direct pairwise connections — distinct other domains this one shares
        // attributing evidence with. Not the same as cluster size, which is a
        // transitive component shown only on the clusters page.
        connectionCount: pickFirst(raw, ["connection_count", "connectionCount"], 0) ?? 0,
        clusterId: pickFirst(raw, ["cluster_id", "clusterId"], null),
        clusterSize: pickFirst(raw, ["cluster_size", "clusterSize"], null),
        // How many times anything under this channel has been scanned, and
        // when it last was. Display-only — scans are startable only from the
        // backend, so this records what ran rather than budgeting what may.
        scanCount: pickFirst(raw, ["scan_count", "scanCount"], 0) ?? 0,
        lastScannedAt: pickFirst(raw, ["last_scanned_at", "lastScannedAt"], null),
        // True if this channel (or a subdomain of it) was directly submitted
        // at some point; false if it only ever surfaced as a scan follow-up
        // (subdomain enumeration, sibling discovery, wordlist hit).
        ingested: raw.ingested === true,
        ingestedAt: pickFirst(raw, ["ingested_at", "ingestedAt"], null),
        discoveredAt: pickFirst(raw, ["discovered_at", "discoveredAt"], null),
        // How/where a never-ingested channel was found — only meaningful when
        // ingested is false (an ingested channel was directly submitted).
        discoveryKind: pickFirst(raw, ["discovery_kind", "discoveryKind"], null),
        discoveryReason: pickFirst(raw, ["discovery_reason", "discoveryReason"], null),
        discoveredFrom: pickFirst(raw, ["discovered_from", "discoveredFrom"], null),
        // OpenCTI tier-1..tier-5 classification (see domain_tiers /
        // integrations/opencti_ingest.py) — null when unclassified.
        tier: pickFirst(raw, ["tier"], null),
      };
    })
    .filter((entry) => entry.domain);
}

export function normalizeConnectionPairs(payload) {
  return coerceArray(payload?.pairs).map((pair, index) => {
    const link = normalizeGraphLink(pair, index);
    return {
      ...link,
      a: readableValue(pair?.a),
      b: readableValue(pair?.b),
      connected: Boolean(pair?.connected),
    };
  });
}

// Shapes /api/graph/connections (pairwise scored links among a domain set)
// into the {nodes, edges} structure ClusterGraph.jsx renders. Every domain is
// treated as a "submitted" anchor node — there's no bridge/membership concept
// here, just the direct evidence-backed links between cluster members.
//
// `visual` carries the tier ClusterGraph colours the edge by — strength only
// (matches backend strength labels "strong"/"moderate"/"weak" one-to-one).
// The evidence *type* behind a link (cert, IP, nameserver, ...) is never
// color-coded — it only shows up in `labels`, in the click-through detail
// panel — so strength and type never fight over the same colour.
export function normalizeConnectionsGraph(payload, members) {
  const pairs = normalizeConnectionPairs(payload);
  const tiers = payload?.tiers || {};
  const nodes = coerceArray(members)
    .map((domain) => readableValue(domain))
    .filter(Boolean)
    .map((domain) => ({ id: domain, label: domain, role: "submitted", tier: tiers[domain] ?? null }));
  const edges = pairs
    .filter((pair) => pair.connected && pair.a && pair.b)
    .map((pair) => ({
      from: pair.a,
      to: pair.b,
      kind: "evidence",
      direct: true,
      score: pair.score,
      visual: pair.strength || "weak",
      width: Math.min(8, Math.max(1, Math.round((pair.score || 0) / 15))),
      labels: pair.evidence.map((node) => `${formatLabel(node.kind)}: ${node.value}`),
      paths: [],
    }));
  return { nodes, edges };
}

// Shapes /api/graph/connections (called with pool_links:true) into a combined
// {nodes, edges} graph for the domain-comparison page. `payload.domains` may
// itself already be an expanded set (see ByDomainExplorer.run(), which does
// an extra round-trip to pull in whatever the initial pick's pool links
// surfaced) -- this function doesn't care which domains were the user's own
// picks vs. discovered along the way, it just draws every evidence-backed
// link in the payload: pairwise links among all of `payload.domains` (so two
// domains that both showed up via pool links can turn out to be linked to
// each other too), plus each domain's own pool links, which is how a domain
// that's neither an original pick nor already in `payload.domains` still
// earns a node on the map. Every node defaults to role:"related" -- the
// caller marks true seeds via ClusterGraph's `seedTargets` prop, not via
// anything computed in here.
// `relatedChains` (optional): Map<seedDomain, relatedThroughEntries[]> from
// normalizeRelatedThrough -- each entry with hops > 1 and no direct pairwise
// edge above becomes a dashed "inferred" edge instead of being left off the
// map entirely, sourced from the precomputed graph_paths chain (never a live
// traversal). This is what lets a multi-hop-only relationship ("A relates to
// C only through B") actually show up on the graph, distinguished from a
// direct link by ClusterGraph's dasharray (see edge.direct below).
export function normalizeExplorerGraph(payload, relatedChains) {
  const tiers = payload?.tiers || {};
  const known = coerceArray(payload?.domains).map((domain) => readableValue(domain)).filter(Boolean);
  const nodes = new Map(
    known.map((domain) => [domain, { id: domain, label: domain, role: "related", tier: tiers[domain] ?? null }]),
  );
  const edges = [];
  const seenPairs = new Set();
  const pairKey = (a, b) => (a < b ? `${a}|${b}` : `${b}|${a}`);

  const addEdge = (from, to, score, strength, evidence, extra = {}) => {
    const key = pairKey(from, to);
    if (seenPairs.has(key)) {
      return;
    }
    seenPairs.add(key);
    edges.push({
      from,
      to,
      kind: "evidence",
      direct: true,
      score,
      visual: strength || "weak",
      width: Math.min(8, Math.max(1, Math.round((score || 0) / 15))),
      labels: (evidence || []).map((node) => `${formatLabel(node.kind)}: ${node.value}`),
      paths: [],
      ...extra,
    });
  };

  normalizeConnectionPairs(payload)
    .filter((pair) => pair.connected && pair.a && pair.b)
    .forEach((pair) => addEdge(pair.a, pair.b, pair.score, pair.strength, pair.evidence));

  const poolLinks = payload?.pool_links || {};
  Object.entries(poolLinks).forEach(([domain, rawLinks]) => {
    normalizeGraphLinks({ links: rawLinks }).forEach((link) => {
      const target = link.target;
      if (!target || target === domain) {
        return;
      }
      if (!nodes.has(target)) {
        nodes.set(target, { id: target, label: target, role: "related", tier: tiers[target] ?? null });
      }
      addEdge(domain, target, link.score, link.strength, link.evidence);
    });
  });

  if (relatedChains) {
    for (const [seed, entries] of relatedChains) {
      (entries || []).forEach((entry) => {
        if (!entry.target || entry.hops <= 1 || seenPairs.has(pairKey(seed, entry.target))) {
          return;
        }
        if (!nodes.has(entry.target)) {
          nodes.set(entry.target, { id: entry.target, label: entry.target, role: "related", tier: tiers[entry.target] ?? null });
        }
        const hopSummary = entry.chain
          .slice(0, -1)
          .map((hop) => hop.to)
          .join(" -> ");
        addEdge(seed, entry.target, entry.minHopScore, "weak", [], {
          direct: false,
          hops: entry.hops,
          labels: [`${entry.hops}-hop chain${hopSummary ? ` via ${hopSummary}` : ""}`],
        });
      });
    }
  }

  return { nodes: Array.from(nodes.values()), edges };
}

export function normalizeSelectorGroups(payload) {
  return coerceArray(payload?.groups ?? payload).map((item, index) => {
    const raw = item || {};
    return {
      id: `${raw.kind || "group"}-${raw.value || index}`,
      kind: pickFirst(raw, ["kind"], "unknown"),
      value: readableValue(pickFirst(raw, ["value"])) || "—",
      degree: pickFirst(raw, ["degree"], null),
      domains: coerceArray(raw.domains).map((entry) => readableValue(entry)).filter(Boolean),
    };
  });
}

// ── Search + multi-hop paths (all precomputed reads, never scored live) ────

export function normalizeSearchResults(payload) {
  const raw = payload || {};
  return {
    query: pickFirst(raw, ["query"], "") || "",
    domains: coerceArray(raw.domains).map((item) => {
      const entry = item || {};
      return {
        domain: readableValue(pickFirst(entry, ["domain"])),
        connectionCount: pickFirst(entry, ["connection_count", "connectionCount"], 0) ?? 0,
        clusterId: pickFirst(entry, ["cluster_id", "clusterId"], null),
        tier: pickFirst(entry, ["tier"], null),
      };
    }).filter((entry) => entry.domain),
    selectors: coerceArray(raw.selectors).map((item, index) => {
      const entry = item || {};
      return {
        id: `${entry.kind || "selector"}-${entry.value || index}`,
        kind: pickFirst(entry, ["kind"], "unknown"),
        value: readableValue(pickFirst(entry, ["value"])) || "—",
        domainCount: pickFirst(entry, ["domain_count", "domainCount"], null),
        sampleDomains: coerceArray(entry.sample_domains ?? entry.sampleDomains)
          .map((d) => readableValue(d))
          .filter(Boolean),
      };
    }),
  };
}

// A hop chain (from graph_paths, via /api/graph/path or /api/graph/related/*)
// shaped the same way normalizeGraphLink shapes a direct pair, so per-hop UI
// (ConnectionCard, sharedNodeLabel) can be reused unmodified.
function normalizeChain(chain) {
  return coerceArray(chain).map((hop, index) => {
    const raw = hop || {};
    return {
      from: readableValue(pickFirst(raw, ["from"])),
      to: readableValue(pickFirst(raw, ["to"])),
      score: typeof raw.score === "number" ? raw.score : Number(raw.score) || 0,
      confidence: resolvePercent(pickFirst(raw, ["confidence"])) ?? confidenceFromScore(raw.score),
      strength: pickFirst(raw, ["strength"]) || null,
      evidence: coerceArray(raw.evidence).map((node, nodeIndex) => normalizeSharedNode(node, nodeIndex)),
    };
  }).filter((hop) => hop.from && hop.to);
}

export function normalizeGraphPath(payload) {
  const raw = payload?.path ?? payload ?? {};
  return {
    a: readableValue(pickFirst(raw, ["a"])),
    b: readableValue(pickFirst(raw, ["b"])),
    hops: pickFirst(raw, ["hops"], null),
    chain: normalizeChain(raw.chain),
  };
}

export function normalizeRelatedThrough(payload) {
  const raw = payload || {};
  return coerceArray(raw.related).map((item) => {
    const entry = item || {};
    return {
      target: readableValue(pickFirst(entry, ["target"])),
      hops: pickFirst(entry, ["hops"], null),
      minHopScore: pickFirst(entry, ["min_hop_score", "minHopScore"], null),
      chain: normalizeChain(entry.chain),
    };
  }).filter((entry) => entry.target);
}

export function normalizeSelectorKinds(payload) {
  return coerceArray(payload?.kinds ?? payload)
    .map((item) => ({
      kind: pickFirst(item || {}, ["kind"], "unknown"),
      groups: pickFirst(item || {}, ["groups"], null),
    }))
    .filter((entry) => entry.kind && entry.kind !== "unknown");
}

function normalizeLogLines(payload) {
  return coerceArray(payload).map((item, index) => {
    if (typeof item === "string") {
      return {
        id: `log-${index}`,
        level: "info",
        message: item,
      };
    }

    const raw = item || {};
    return {
      id: pickFirst(raw, ["id", "timestamp", "time"], `log-${index}`),
      level: normalizeStatus(pickFirst(raw, ["level", "severity", "type"], "info")),
      message:
        pickFirst(raw, ["message", "summary", "detail", "description"]) || JSON.stringify(raw),
    };
  });
}

function normalizeStep(item, index) {
  if (typeof item === "string") {
    return {
      id: `step-${index}`,
      label: item,
      status: "pending",
      detail: null,
    };
  }

  const raw = item || {};
  return {
    id: pickFirst(raw, ["id", "key"], `step-${index}`),
    label: pickFirst(raw, ["label", "name", "title", "step"], `Step ${index + 1}`),
    status: normalizeStatus(pickFirst(raw, ["status", "state"], "pending")),
    detail: summarizeText(pickFirst(raw, ["detail", "summary", "description"])),
  };
}

function deriveStepPercent(raw) {
  const completed = pickFirst(raw, ["completed_steps", "completedSteps", "counts.completed"]);
  const total = pickFirst(raw, ["total_steps", "totalSteps", "counts.total"]);

  if (typeof completed === "number" && typeof total === "number" && total > 0) {
    return Math.round((completed / total) * 100);
  }

  return null;
}

function summarizeText(value) {
  if (!value) {
    return null;
  }

  if (typeof value === "string") {
    return value;
  }

  if (typeof value !== "object") {
    return String(value);
  }

  return (
    pickFirst(value, ["text", "summary", "headline", "description", "message", "detail"]) || null
  );
}

function readableValue(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  if (typeof value === "string" || typeof value === "number") {
    return String(value);
  }

  if (typeof value === "object") {
    return (
      pickFirst(value, ["label", "name", "title", "target", "domain", "ip", "value", "id"]) ||
      JSON.stringify(value)
    );
  }

  return String(value);
}

function resolvePercent(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const numeric = typeof value === "number" ? value : Number.parseFloat(String(value).replace("%", ""));

  if (!Number.isFinite(numeric)) {
    return null;
  }

  const normalized = numeric <= 1 ? numeric * 100 : numeric;
  return Math.max(0, Math.min(100, Math.round(normalized)));
}

function unwrapEntity(payload, keys) {
  if (!payload || typeof payload !== "object") {
    return payload || {};
  }

  for (const key of keys) {
    if (payload[key] && typeof payload[key] === "object") {
      return payload[key];
    }
  }

  return payload;
}

function coerceArray(value) {
  if (Array.isArray(value)) {
    return value;
  }

  if (!value) {
    return [];
  }

  if (Array.isArray(value.items)) {
    return value.items;
  }

  if (Array.isArray(value.results)) {
    return value.results;
  }

  return [];
}

function pickFirst(source, keys, fallback = null) {
  for (const key of keys) {
    const value = getPath(source, key);
    if (value !== null && value !== undefined && value !== "") {
      return value;
    }
  }

  return fallback;
}

function getPath(source, path) {
  if (!source || typeof source !== "object") {
    return undefined;
  }

  return path.split(".").reduce((current, key) => {
    if (current && typeof current === "object" && key in current) {
      return current[key];
    }

    return undefined;
  }, source);
}

function normalizeStatus(value) {
  if (!value) {
    return "unknown";
  }

  return String(value).trim().toLowerCase().replace(/[\s_]+/g, "-");
}

export function isTerminalStatus(status) {
  const normalized = normalizeStatus(status);
  return (
    normalized.includes("done") ||
    normalized.includes("complete") ||
    normalized.includes("success") ||
    normalized.includes("failed") ||
    normalized.includes("error") ||
    normalized.includes("cancel")
  );
}

export function formatLabel(value) {
  return String(value || "")
    .replace(/[_-]+/g, " ")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/\b\w/g, (character) => character.toUpperCase())
    .trim();
}

export function formatDate(value) {
  const timestamp = Date.parse(value);

  if (!Number.isFinite(timestamp)) {
    // Never hand the caller back a non-primitive: `pickFirst` can legitimately
    // return an object (a {value, last_seen} wrapper), and returning it
    // unchanged put it straight into JSX — "Objects are not valid as a React
    // child", which with no error boundary blanks the whole tool.
    if (value === null || value === undefined) {
      return "—";
    }
    return typeof value === "object" ? "—" : String(value);
  }

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(timestamp);
}

export function formatNumber(value) {
  const numeric = typeof value === "number" ? value : Number(value);

  if (!Number.isFinite(numeric)) {
    return String(value);
  }

  return new Intl.NumberFormat().format(numeric);
}

export function formatPercent(value) {
  if (value === null || value === undefined || value === "") {
    return "—";
  }

  return `${formatNumber(value)}%`;
}
