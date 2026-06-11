import {
  Suspense,
  lazy,
  memo,
  useCallback,
  useDeferredValue,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  Link,
  NavLink,
  Navigate,
  Outlet,
  Route,
  Routes,
  useOutletContext,
  useParams,
} from "./router.jsx";

import {
  fetchJson,
  formatLabel,
  formatPercent,
  isTerminalStatus,
  normalizeCaseDetail,
  normalizeCases,
  normalizeClusterGroups,
  normalizeJob,
  normalizePairDetail,
  normalizePairs,
  useApi,
} from "./api.js";
import {
  DescriptionGrid,
  EmptyState,
  ErrorState,
  InlineMetric,
  LoadingState,
  MetricCard,
  ProgressBar,
  RawDataDisclosure,
  StatusBadge,
  SubjectCard,
  formatDisplayValue,
  formatMaybeDate,
  formatMaybeNumber,
  formatStatusLabel,
} from "./components/primitives.jsx";

// Heavy views load on demand so the initial route ships less JavaScript:
// the cluster graph pulls in the d3 modules, and the progress/log view is
// only needed while a job is running.
const ClusterGraph = lazy(() => import("./components/ClusterGraph.jsx"));
const CaseProgressPage = lazy(() => import("./components/CaseProgressPage.jsx"));

const RAW_CASE_EXCLUDES = new Set([
  "id",
  "case_id",
  "caseId",
  "uuid",
  "title",
  "name",
  "label",
  "summary",
  "overview",
  "description",
  "job",
  "latest_job",
  "latestJob",
  "current_job",
  "currentJob",
  "metrics",
  "counts",
  "pairs",
  "pair_count",
  "pairCount",
  "clusters",
  "cluster_count",
  "clusterCount",
  "targets",
  "subjects",
  "entities",
  "members",
  "highlights",
  "findings",
  "notes",
  "evidence",
  "evidence_items",
  "evidenceItems",
]);

const RAW_PAIR_EXCLUDES = new Set([
  "id",
  "pair_id",
  "pairId",
  "left",
  "right",
  "lhs",
  "rhs",
  "domain_a",
  "domain_b",
  "score",
  "confidence",
  "strength",
  "status",
  "classification",
  "verdict",
  "summary",
  "description",
  "explanation",
  "entities",
  "subjects",
  "members",
  "evidence",
  "evidence_items",
  "evidenceItems",
]);

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<HomePage />} />
      <Route path="/cases/:caseId" element={<CaseLayout />}>
        <Route index element={<Navigate replace to="summary" />} />
        <Route
          path="progress"
          element={
            <Suspense fallback={<LoadingState message="Loading the progress view..." />}>
              <CaseProgressPage />
            </Suspense>
          }
        />
        <Route path="summary" element={<CaseSummaryPage />} />
        <Route path="pairs/:pairId" element={<CasePairPage />} />
        <Route path="clusters" element={<CaseClustersPage />} />
      </Route>
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}

function HomePage() {
  const casesRequest = useApi("/api/cases");
  const [search, setSearch] = useState("");
  const [targetInput, setTargetInput] = useState("");
  const [csvFile, setCsvFile] = useState(null);
  const [submitState, setSubmitState] = useState({
    busy: false,
    error: null,
  });
  const deferredSearch = useDeferredValue(search);
  const cases = useMemo(
    () => normalizeCases(casesRequest.data).sort(sortCases),
    [casesRequest.data],
  );
  const query = deferredSearch.trim().toLowerCase();
  const filteredCases = useMemo(
    () =>
      query
        ? cases.filter((caseItem) => {
            const haystack = [
              caseItem.id,
              caseItem.title,
              caseItem.summaryText,
              caseItem.status,
              caseItem.jobId,
              caseItem.targets.join(" "),
            ]
              .filter(Boolean)
              .join(" ")
              .toLowerCase();
            return haystack.includes(query);
          })
        : cases,
    [cases, query],
  );

  const runningCases = useMemo(
    () => cases.filter((caseItem) => !isTerminalStatus(caseItem.status)).length,
    [cases],
  );
  const readySummaries = useMemo(
    () => cases.filter((caseItem) => caseItem.summaryText).length,
    [cases],
  );

  const LIST_CAP = 200;
  const visibleCases = filteredCases.slice(0, LIST_CAP);

  return (
    <AppShell>
      <section className="hero-panel">
        <div className="hero-copy">
          <p className="eyebrow">Submission workspace</p>
          <h1>Submit domains or IPs and follow the overlap case as it runs.</h1>
          <p>
            Start with one target or a CSV, then explore which domains are linked, how
            strongly, and why — in plain English.
          </p>
        </div>
        <div className="hero-stats">
          <MetricCard label="Cases available" value={cases.length} />
          <MetricCard label="Jobs in flight" value={runningCases} />
          <MetricCard label="Cases with summaries" value={readySummaries} />
        </div>
      </section>

      <section className="panel section-stack">
        <div className="panel-header">
          <div>
            <p className="eyebrow">New case</p>
            <h2>Submit targets</h2>
            <p className="section-copy">
              Add one domain or IP directly, or upload a CSV and we will process the first
              column only.
            </p>
          </div>
        </div>

        <div className="submission-grid">
          <div className="submission-card">
            <label className="search-field">
              <span>Single domain or IP</span>
              <input
                name="target"
                onChange={(event) => setTargetInput(event.target.value)}
                placeholder="example.com or 203.0.113.10"
                type="text"
                value={targetInput}
              />
            </label>
            <button
              className="primary-button"
              disabled={submitState.busy || !targetInput.trim()}
              onClick={() => submitCase({ target: targetInput.trim() })}
              type="button"
            >
              {submitState.busy ? "Submitting..." : "Start single-target case"}
            </button>
          </div>

          <div className="submission-card">
            <label className="search-field file-field">
              <span>CSV upload</span>
              <input
                accept=".csv,text/csv"
                onChange={(event) => setCsvFile(event.target.files?.[0] || null)}
                type="file"
              />
            </label>
            <button
              className="primary-button"
              disabled={submitState.busy || !csvFile}
              onClick={() => submitCase({ file: csvFile })}
              type="button"
            >
              {submitState.busy ? "Submitting..." : "Upload CSV case"}
            </button>
          </div>
        </div>

        <div className="callout subtle">
          <p>
            Accepted input: one domain or IP in the text field, or a CSV where the first
            column contains domains or IPs. Duplicate rows are deduplicated server-side.
          </p>
        </div>

        {submitState.error ? <ErrorState message={submitState.error} /> : null}
      </section>

      <section className="panel section-stack">
        <div className="panel-header">
          <div>
            <p className="eyebrow">API</p>
            <h2>Cases</h2>
            <p className="section-copy">Loaded from `/api/cases` and ready to drill into.</p>
          </div>
          <button className="secondary-button" onClick={casesRequest.refresh} type="button">
            Refresh
          </button>
        </div>

        <label className="search-field">
          <span>Search cases</span>
          <input
            name="case-search"
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Filter by title, case ID, target, or status"
            type="search"
            value={search}
          />
        </label>

        {casesRequest.loading && !casesRequest.data ? (
          <LoadingState message="Loading cases..." />
        ) : null}

        {casesRequest.error ? <ErrorState message={casesRequest.error} /> : null}

        {!casesRequest.loading && !casesRequest.error && filteredCases.length === 0 ? (
          <EmptyState
            message={
              cases.length === 0
                ? "No cases were returned by the backend yet."
                : "No cases match the current search."
            }
          />
        ) : null}

        {filteredCases.length > LIST_CAP ? (
          <p className="section-copy">
            Showing {LIST_CAP} of {filteredCases.length} cases. Refine the search to see more.
          </p>
        ) : null}

        {filteredCases.length > 0 ? (
          <div className="case-grid">
            {visibleCases.map((caseItem) => (
              <CaseCard caseItem={caseItem} key={caseItem.id} />
            ))}
          </div>
        ) : null}
      </section>
    </AppShell>
  );

  async function submitCase({ file, target }) {
    setSubmitState({ busy: true, error: null });
    try {
      let response;
      if (file) {
        const formData = new FormData();
        formData.append("file", file);
        response = await fetch("/api/cases", {
          method: "POST",
          body: formData,
          headers: {
            Accept: "application/json",
          },
        });
      } else {
        response = await fetch("/api/cases", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify({ target }),
        });
      }

      const payload = await parseSubmitPayload(response);
      if (!response.ok) {
        const message =
          (payload && typeof payload === "object" && (payload.detail || payload.message || payload.error)) ||
          (typeof payload === "string" ? payload : null) ||
          `Case submission failed with status ${response.status}.`;
        throw new Error(message);
      }

      const caseId = payload?.case_id || payload?.case?.id;
      if (!caseId) {
        throw new Error("The backend did not return a case ID.");
      }
      window.location.assign(`/cases/${caseId}/progress`);
    } catch (error) {
      setSubmitState({
        busy: false,
        error: error.message || "Case submission failed.",
      });
      return;
    }
    setSubmitState({ busy: false, error: null });
  }

  async function parseSubmitPayload(response) {
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      return response.json();
    }

    const text = await response.text();
    if (!text) {
      return null;
    }

    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }
}

const CaseCard = memo(function CaseCard({ caseItem }) {
  const caseRunning = !isTerminalStatus(caseItem.status);
  return (
    <article className="case-card">
      <div className="case-card-header">
        <div>
          <p className="eyebrow">Case {caseItem.id}</p>
          <h3>{caseItem.title}</h3>
          <p className="card-copy">
            {caseItem.summaryText || "Open the summary page to inspect the case detail."}
          </p>
        </div>
        <StatusBadge status={caseItem.status} />
      </div>

      {caseItem.targets.length > 0 ? (
        <div className="chip-row">
          {caseItem.targets.slice(0, 4).map((target) => (
            <span className="chip" key={target}>
              {target}
            </span>
          ))}
        </div>
      ) : null}

      <div className="inline-metrics">
        <InlineMetric label="Pairs" value={formatMaybeNumber(caseItem.pairCount)} />
        <InlineMetric label="Clusters" value={formatMaybeNumber(caseItem.clusterCount)} />
        <InlineMetric label="Updated" value={formatMaybeDate(caseItem.updatedAt)} />
      </div>

      {caseRunning && caseItem.progress !== null ? (
        <div className="mini-progress">
          <div className="mini-progress-top">
            <span>Progress</span>
            <strong>{formatPercent(caseItem.progress)}</strong>
          </div>
          <ProgressBar value={caseItem.progress} />
        </div>
      ) : null}

      <div className="action-row">
        <Link className="primary-button" to={`/cases/${caseItem.id}/summary`}>
          Open summary
        </Link>
        {caseRunning ? (
          <Link className="text-link" to={`/cases/${caseItem.id}/progress`}>
            Progress
          </Link>
        ) : null}
        <Link className="text-link" to={`/cases/${caseItem.id}/clusters`}>
          Clusters
        </Link>
      </div>
    </article>
  );
});

function isCaseActive(caseDetail) {
  const status = String(caseDetail?.status || "").toLowerCase();
  return status === "running" || status === "queued" || status === "pending";
}

function CaseLayout() {
  const { caseId } = useParams();
  const [livePolling, setLivePolling] = useState(false);
  const caseRequest = useApi(`/api/cases/${caseId}`, {
    pollInterval: livePolling ? 4000 : 0,
  });
  const caseDetail = useMemo(
    () => normalizeCaseDetail(caseRequest.data, caseId),
    [caseRequest.data, caseId],
  );
  const caseActive = Boolean(caseRequest.data) && isCaseActive(caseDetail);

  useEffect(() => {
    setLivePolling(caseActive);
  }, [caseActive]);

  const navItems = useMemo(() => {
    const items = [{ to: "summary", label: "Summary" }];
    if (caseActive) {
      items.push({ to: "progress", label: "Progress" });
    }
    items.push({ to: "clusters", label: "Clusters" });
    return items;
  }, [caseActive]);

  return (
    <AppShell>
      <div className="breadcrumb-row">
        <Link className="text-link" to="/">
          All cases
        </Link>
        <span>/</span>
        <span>{caseDetail.title}</span>
      </div>

      <section className="hero-panel compact">
        <div className="hero-copy">
          <p className="eyebrow">Case {caseDetail.id || caseId}</p>
          <h1>{caseDetail.title}</h1>
          <p>
            {caseDetail.summaryText ||
              "This case answers one question: are these domains controlled by the same entity, and with what confidence?"}
          </p>
        </div>
        <div className="hero-side-stack">
          <StatusBadge status={caseDetail.status} />
          <div className="inline-metrics">
            <InlineMetric label="Pairs" value={formatMaybeNumber(caseDetail.pairCount)} />
            <InlineMetric label="Clusters" value={formatMaybeNumber(caseDetail.clusterCount)} />
            <InlineMetric label="Targets" value={caseDetail.targets.length || "—"} />
          </div>
        </div>
      </section>

      <nav className="case-nav" aria-label="Case sections">
        {navItems.map((item) => (
          <NavLink
            className={({ isActive }) =>
              isActive ? "case-nav-link active" : "case-nav-link"
            }
            key={item.to}
            to={item.to}
          >
            {item.label}
          </NavLink>
        ))}
      </nav>

      {caseRequest.error && !caseRequest.data ? (
        <ErrorState message={caseRequest.error} />
      ) : null}

      <Outlet context={{ caseId, caseDetail, caseRequest, caseActive }} />
    </AppShell>
  );
}

/* ------------------------------------------------------------------ */
/* Evidence vocabulary: plain-English framing for the backend signals. */
/* ------------------------------------------------------------------ */

const IMPORTANCE_RANK = {
  decisive: 0,
  key: 0,
  anchoring: 0,
  strong: 1,
  supporting: 2,
  "low-signal": 3,
  low_signal: 3,
};

function importanceRank(importance) {
  const rank = IMPORTANCE_RANK[String(importance || "").toLowerCase()];
  return rank === undefined ? 2 : rank;
}

function importanceTone(importance) {
  switch (importanceRank(importance)) {
    case 0:
      return "success";
    case 1:
      return "warning";
    case 3:
      return "neutral";
    default:
      return "info";
  }
}

const CATEGORY_INFO = {
  Transport: {
    title: "TLS certificates & SSH keys",
    blurb: "Cryptographic fingerprints served by the live servers.",
  },
  Infrastructure: {
    title: "Shared IP addresses",
    blurb: "Current and historical hosting overlap.",
  },
  "Web identity": {
    title: "Tracking & analytics IDs",
    blurb: "Analytics, tag-manager, and advertising accounts embedded in the pages.",
  },
  "Web content": {
    title: "Page content & favicons",
    blurb: "Visual and build artifacts served by the sites.",
  },
  Identity: {
    title: "Ownership identity",
    blurb: "Legal entities, social handles, and verification tokens.",
  },
  Registration: {
    title: "Domain registration",
    blurb: "WHOIS contacts and registrar records.",
  },
  DNS: {
    title: "DNS & nameservers",
    blurb: "Delegation and resolution overlap.",
  },
  "Email policy": {
    title: "Email configuration",
    blurb: "SPF, DKIM, and DMARC policy overlap.",
  },
  "Email operations": {
    title: "Mail infrastructure",
    blurb: "Mail servers and autodiscover endpoints.",
  },
  "SaaS identity": {
    title: "SaaS tenants",
    blurb: "Shared cloud-service accounts such as Microsoft 365.",
  },
  "Well-known files": {
    title: "Site metadata files",
    blurb: "security.txt, ads.txt, and app-link files.",
  },
  Other: {
    title: "Other shared signals",
    blurb: "Additional overlap captured during the scan.",
  },
};

const CATEGORY_PHRASES = {
  Transport: "shared TLS certificates or SSH keys",
  Infrastructure: "shared hosting IPs",
  "Web identity": "shared tracking and analytics IDs",
  "Web content": "matching page content",
  Identity: "shared ownership identity details",
  Registration: "shared registration records",
  DNS: "shared DNS infrastructure",
  "Email policy": "shared email configuration",
  "Email operations": "shared mail infrastructure",
  "SaaS identity": "a shared SaaS tenant",
  "Well-known files": "shared site metadata files",
  Other: "shared low-level signals",
};

function sortEvidence(evidence) {
  return [...(evidence || [])].sort(
    (a, b) => importanceRank(a.importance) - importanceRank(b.importance),
  );
}

function lowerFirst(text) {
  if (!text) {
    return text;
  }
  return text.charAt(0).toLowerCase() + text.slice(1);
}

function evidenceNoun(item) {
  const label = item.title || formatLabel(item.type);
  if (/^shared\s+/i.test(label)) {
    return `the same ${label.replace(/^shared\s+/i, "")}`;
  }
  return lowerFirst(label);
}

function linkStrength(score) {
  const value = score === null || score === undefined ? 0 : score;
  if (value >= 70) {
    return { tier: "strong", label: "Strong link", tone: "success" };
  }
  if (value >= 30) {
    return { tier: "moderate", label: "Moderate link", tone: "warning" };
  }
  return { tier: "weak", label: "Weak link", tone: "neutral" };
}

function connectionReason(pair) {
  const sorted = sortEvidence(pair.evidence);
  if (sorted.length === 0) {
    return "No shared evidence was recorded for this pair, so the connection is unsupported.";
  }
  const best = sorted[0];
  const noun = evidenceNoun(best);
  const { tier } = linkStrength(pair.score);

  if (tier === "strong") {
    return `These domains share ${noun} — ${
      lowerFirst(best.whyItMatters) || "a strong sign that they are run by the same entity."
    }`;
  }
  if (tier === "moderate") {
    const why = best.whyItMatters ? `${best.whyItMatters} ` : "";
    return `These domains overlap on ${noun}. ${why}Treat this as a moderate signal that needs corroboration.`;
  }
  const nouns = [...new Set(sorted.slice(0, 2).map((item) => evidenceNoun(item)))];
  return `The only overlap is ${nouns.join(" and ")} — ${
    lowerFirst(best.caveat) ||
    "signals that many unrelated sites share, so this is weak evidence of common control."
  }`;
}

function categorySummaryLine(items) {
  const best = items[0];
  const noun = evidenceNoun(best);
  const extraCount = items.length - 1;
  const extra =
    extraCount > 0 ? ` plus ${extraCount} related signal${extraCount === 1 ? "" : "s"}` : "";
  switch (importanceRank(best.importance)) {
    case 0:
      return `Both sites present ${noun}${extra}. ${best.whyItMatters || ""}`.trim();
    case 1:
      return `Both sites share ${noun}${extra}. ${best.whyItMatters || ""}`.trim();
    case 3:
      return `They match on ${noun}${extra}, but ${
        lowerFirst(best.caveat) || "this is common across unrelated sites, so it counts for little."
      }`;
    default:
      return `They also share ${noun}${extra} — supporting context rather than proof on its own.`;
  }
}

function groupEvidence(evidence) {
  const sorted = sortEvidence(evidence);
  const byCategory = new Map();
  sorted.forEach((item) => {
    const category = item.category || "Other";
    if (!byCategory.has(category)) {
      byCategory.set(category, []);
    }
    byCategory.get(category).push(item);
  });

  return [...byCategory.entries()]
    .map(([category, items]) => {
      const info = CATEGORY_INFO[category] || { title: category, blurb: "" };
      return {
        category,
        title: info.title,
        blurb: info.blurb,
        items,
        bestImportance: items[0].importance,
        bestRank: importanceRank(items[0].importance),
        summary: categorySummaryLine(items),
      };
    })
    .sort((a, b) => a.bestRank - b.bestRank || b.items.length - a.items.length);
}

function dominantCategoryPhrase(pairs) {
  const counts = new Map();
  pairs.forEach((pair) => {
    const best = sortEvidence(pair.evidence)[0];
    if (!best) {
      return;
    }
    const category = best.category || "Other";
    counts.set(category, (counts.get(category) || 0) + 1);
  });
  let topCategory = null;
  let topCount = 0;
  counts.forEach((count, category) => {
    if (count > topCount) {
      topCount = count;
      topCategory = category;
    }
  });
  return topCategory ? CATEGORY_PHRASES[topCategory] || CATEGORY_PHRASES.Other : null;
}

function buildCaseExplanation(seedTargets, pairs) {
  const seeds = [...new Set(seedTargets)].filter(Boolean);
  const seedPairs = pairs.filter((pair) => pair.isSeedPair);
  const historicalPairs = pairs.filter((pair) => pair.scope === "historical");
  const sentences = [];

  if (seeds.length >= 2) {
    const bestByDomain = new Map(seeds.map((domain) => [domain, 0]));
    seedPairs.forEach((pair) => {
      const score = pair.score ?? 0;
      [pair.left, pair.right].forEach((domain) => {
        if (bestByDomain.has(domain) && score > bestByDomain.get(domain)) {
          bestByDomain.set(domain, score);
        }
      });
    });

    let strong = 0;
    let moderate = 0;
    let weak = 0;
    bestByDomain.forEach((score) => {
      if (score >= 70) {
        strong += 1;
      } else if (score >= 30) {
        moderate += 1;
      } else {
        weak += 1;
      }
    });

    if (strong >= 2) {
      const phrase = dominantCategoryPhrase(
        seedPairs.filter((pair) => (pair.score ?? 0) >= 70),
      );
      sentences.push(
        `${strong} of the ${seeds.length} submitted domains appear tightly linked${
          phrase ? `, mainly through ${phrase}` : ""
        }.`,
      );
      if (moderate > 0) {
        sentences.push(
          `${moderate} more show${moderate === 1 ? "s" : ""} only a moderate connection.`,
        );
      }
    } else if (moderate >= 2) {
      const phrase = dominantCategoryPhrase(
        seedPairs.filter((pair) => (pair.score ?? 0) >= 30),
      );
      sentences.push(
        `${moderate} of the ${seeds.length} submitted domains show a moderate connection${
          phrase ? ` through ${phrase}` : ""
        } — suggestive, but not conclusive on its own.`,
      );
    } else {
      sentences.push(
        `No strong connections were found between the ${seeds.length} submitted domains.`,
      );
    }

    if (weak > 0 && (strong >= 2 || moderate >= 2)) {
      sentences.push(
        `${weak} show${weak === 1 ? "s" : ""} only weak or no overlap with the rest.`,
      );
    }
  } else if (seeds.length === 1) {
    sentences.push(
      `One domain was submitted, so it is compared against its discovered subdomains and against domains from earlier cases.`,
    );
  }

  if (historicalPairs.length > 0) {
    const top = historicalPairs.reduce((bestSoFar, pair) =>
      (pair.score ?? 0) > (bestSoFar.score ?? 0) ? pair : bestSoFar,
    );
    sentences.push(
      `Earlier cases surfaced ${historicalPairs.length} historical match${
        historicalPairs.length === 1 ? "" : "es"
      }; the strongest is ${top.left} and ${top.right} at ${formatPercent(top.score)}.`,
    );
  }

  if (sentences.length === 0) {
    return pairs.length === 0
      ? "No overlap between the analyzed domains has been recorded yet."
      : null;
  }
  return sentences.join(" ");
}

/* ----------------------------------------------------- */
/* Domain-centric linkage explorer and the pair digest.   */
/* ----------------------------------------------------- */

function DomainLinkageExplorer({ caseId, pairs, seedTargets, request }) {
  const domainLists = useMemo(() => {
    const seeds = [...new Set(seedTargets)].filter(Boolean);
    const seedSet = new Set(seeds);
    const others = new Set();
    pairs.forEach((pair) => {
      [pair.left, pair.right].forEach((domain) => {
        if (domain && !seedSet.has(domain)) {
          others.add(domain);
        }
      });
    });
    return { seeds, others: [...others].sort() };
  }, [pairs, seedTargets]);

  const allDomains = useMemo(
    () => [...domainLists.seeds, ...domainLists.others],
    [domainLists],
  );

  const [selected, setSelected] = useState(null);
  const [expandedPairId, setExpandedPairId] = useState(null);
  const togglePair = useCallback((pairId) => {
    setExpandedPairId((current) => (current === pairId ? null : pairId));
  }, []);
  const activeDomain =
    selected && allDomains.includes(selected) ? selected : allDomains[0] ?? null;

  const rows = useMemo(() => {
    if (!activeDomain) {
      return [];
    }
    return pairs
      .filter((pair) => pair.left === activeDomain || pair.right === activeDomain)
      .map((pair) => ({
        pair,
        other: pair.left === activeDomain ? pair.right : pair.left,
      }))
      .sort((a, b) => (b.pair.score ?? 0) - (a.pair.score ?? 0));
  }, [pairs, activeDomain]);

  const selectDomain = (domain) => {
    setSelected(domain);
    setExpandedPairId(null);
  };

  return (
    <section className="panel section-stack">
      <div className="panel-header">
        <div>
          <p className="eyebrow">Domain linkage</p>
          <h2>Who is linked to whom?</h2>
          <p className="section-copy">
            Pick a domain to see every other domain ranked by linkage confidence, strongest
            first. Click a connection to see what the two sites have in common.
          </p>
        </div>
        {request ? (
          <button className="secondary-button" onClick={request.refresh} type="button">
            Refresh
          </button>
        ) : null}
      </div>

      {request?.loading && !request?.data ? (
        <LoadingState message="Loading connections..." />
      ) : null}
      {request?.error ? <ErrorState message={request.error} /> : null}

      {allDomains.length === 0 && !request?.loading ? (
        <EmptyState message="No comparison results are available for this case yet." />
      ) : null}

      {domainLists.seeds.length > 0 ? (
        <div className="domain-selector" role="group" aria-label="Select a domain">
          {domainLists.seeds.map((domain) => (
            <button
              className={`domain-chip ${domain === activeDomain ? "active" : ""}`}
              key={domain}
              onClick={() => selectDomain(domain)}
              type="button"
            >
              {domain}
            </button>
          ))}
        </div>
      ) : null}

      {domainLists.others.length > 0 ? (
        <details
          className="domain-extra"
          open={domainLists.others.includes(activeDomain) || undefined}
        >
          <summary>
            Discovered and historical domains ({domainLists.others.length})
          </summary>
          <div className="domain-selector">
            {domainLists.others.map((domain) => (
              <button
                className={`domain-chip secondary ${domain === activeDomain ? "active" : ""}`}
                key={domain}
                onClick={() => selectDomain(domain)}
                type="button"
              >
                {domain}
              </button>
            ))}
          </div>
        </details>
      ) : null}

      {activeDomain && rows.length === 0 && !request?.loading ? (
        <EmptyState
          message={`No recorded overlap between ${activeDomain} and any other domain in this case.`}
        />
      ) : null}

      {rows.length > 0 ? (
        <div className="linkage-list">
          {rows.map(({ pair, other }) => (
            <LinkageCard
              caseId={caseId}
              expanded={expandedPairId === pair.id}
              key={pair.id}
              onToggle={togglePair}
              other={other}
              pair={pair}
            />
          ))}
        </div>
      ) : null}
    </section>
  );
}

const LinkageCard = memo(function LinkageCard({ caseId, expanded, onToggle, other, pair }) {
  const strength = linkStrength(pair.score);
  const reason = connectionReason(pair);
  const barWidth = Math.max(4, Math.min(100, pair.score ?? 0));
  const signalCount = pair.evidenceCount ?? pair.evidence.length;

  return (
    <article className={`linkage-card ${expanded ? "expanded" : ""}`}>
      <button
        aria-expanded={expanded}
        className="linkage-card-main"
        onClick={() => onToggle(pair.id)}
        type="button"
      >
        <span className="linkage-percent">
          <strong>{pair.score === null ? "—" : formatPercent(pair.score)}</strong>
          <span className={`status-badge compact ${strength.tone}`}>{strength.label}</span>
        </span>
        <span className="linkage-body">
          <span className="linkage-domains">
            <strong>{other || "Unknown domain"}</strong>
            {pair.scope === "historical" ? (
              <span className="chip linkage-scope-chip">From an earlier case</span>
            ) : null}
            <span className="linkage-signal-count">
              {signalCount} signal{signalCount === 1 ? "" : "s"}
            </span>
          </span>
          <span className="card-copy linkage-reason">{reason}</span>
          <span className="strength-track" aria-hidden="true">
            <span
              className={`strength-fill ${strength.tier}`}
              style={{ width: `${barWidth}%` }}
            />
          </span>
        </span>
        <span aria-hidden="true" className="linkage-caret">
          {expanded ? "▴" : "▾"}
        </span>
      </button>
      {expanded ? <PairDigest caseId={caseId} pair={pair} /> : null}
    </article>
  );
});

// The pairs list ships only the top few evidence items per pair, so the
// digest fetches the full evidence lazily on first expand. Resolved details
// are cached in memory so re-expanding a card is instant.
const pairEvidenceCache = new Map();

function usePairEvidence(caseId, pairId) {
  const cacheKey = caseId && pairId ? `${caseId}/${pairId}` : null;
  const [state, setState] = useState(() => {
    if (!cacheKey) {
      return { evidence: null, loading: false, error: null };
    }
    const cached = pairEvidenceCache.get(cacheKey);
    return cached
      ? { evidence: cached, loading: false, error: null }
      : { evidence: null, loading: true, error: null };
  });

  useEffect(() => {
    if (!cacheKey) {
      return undefined;
    }
    const cached = pairEvidenceCache.get(cacheKey);
    if (cached) {
      setState({ evidence: cached, loading: false, error: null });
      return undefined;
    }

    let active = true;
    setState({ evidence: null, loading: true, error: null });
    fetchJson(`/api/cases/${caseId}/pairs/${pairId}`)
      .then((payload) => {
        const detail = normalizePairDetail(payload, pairId);
        pairEvidenceCache.set(cacheKey, detail.evidence);
        if (active) {
          setState({ evidence: detail.evidence, loading: false, error: null });
        }
      })
      .catch((error) => {
        if (active) {
          setState({
            evidence: null,
            loading: false,
            error: error.message || "Failed to load the shared evidence.",
          });
        }
      });
    return () => {
      active = false;
    };
  }, [cacheKey, caseId, pairId]);

  return state;
}

const PairDigest = memo(function PairDigest({ caseId = null, pair }) {
  const lazyDetail = usePairEvidence(caseId, caseId ? pair.id : null);
  const evidence = caseId ? lazyDetail.evidence : pair.evidence;
  const groups = useMemo(() => groupEvidence(evidence || []), [evidence]);

  if (caseId && lazyDetail.loading) {
    return (
      <div className="pair-digest">
        <DigestShimmer />
      </div>
    );
  }

  return (
    <div className="pair-digest">
      {caseId && lazyDetail.error ? <ErrorState message={lazyDetail.error} /> : null}
      {!(caseId && lazyDetail.error) && groups.length === 0 ? (
        <EmptyState message="No shared evidence was recorded for this pair." />
      ) : null}
      {groups.map((group) => (
        <EvidenceCategoryGroup group={group} key={group.category} />
      ))}
      {caseId && pair.id ? (
        <div className="action-row">
          <Link className="text-link" to={`/cases/${caseId}/pairs/${pair.id}`}>
            Open full pair detail
          </Link>
        </div>
      ) : null}
    </div>
  );
});

function DigestShimmer() {
  return (
    <div aria-label="Loading shared evidence" className="digest-shimmer" role="status">
      <span className="shimmer-line wide" />
      <span className="shimmer-line" />
      <span className="shimmer-line narrow" />
    </div>
  );
}

const DIGEST_PREVIEW_COUNT = 3;

const EvidenceCategoryGroup = memo(function EvidenceCategoryGroup({ group }) {
  const [showAll, setShowAll] = useState(false);
  const visibleItems = showAll ? group.items : group.items.slice(0, DIGEST_PREVIEW_COUNT);
  const hiddenCount = group.items.length - DIGEST_PREVIEW_COUNT;

  return (
    <section className="digest-group">
      <div className="digest-group-head">
        <div className="digest-group-title">
          <strong>{group.title}</strong>
          <span className="digest-count">
            {group.items.length} signal{group.items.length === 1 ? "" : "s"}
          </span>
        </div>
        <span className={`status-badge compact ${importanceTone(group.bestImportance)}`}>
          {formatLabel(group.bestImportance || "supporting")}
        </span>
      </div>
      <p className="card-copy digest-summary">{group.summary}</p>
      <ul className="digest-items">
        {visibleItems.map((item) => (
          <li className="digest-item" key={item.id}>
            <span className="digest-item-label">{item.title || formatLabel(item.type)}</span>
            <span className="chip-row digest-item-values">
              {evidenceValues(item)
                .slice(0, 2)
                .map((value) => (
                  <span className="chip evidence-chip" key={`${item.id}-${value}`} title={value}>
                    {value}
                  </span>
                ))}
              {evidenceValues(item).length > 2 ? (
                <span className="chip digest-more-chip">
                  +{evidenceValues(item).length - 2} more
                </span>
              ) : null}
            </span>
          </li>
        ))}
      </ul>
      {hiddenCount > 0 ? (
        <button
          className="show-all-button"
          onClick={() => setShowAll((current) => !current)}
          type="button"
        >
          {showAll
            ? `Show top ${DIGEST_PREVIEW_COUNT}`
            : `Show all ${group.items.length} signals`}
        </button>
      ) : null}
    </section>
  );
});

function evidenceValues(item) {
  if (item.matchedValues?.length) {
    return item.matchedValues;
  }
  return item.value ? [item.value] : [];
}

/* ----------------- */
/* Case detail pages */
/* ----------------- */

function CaseSummaryPage() {
  const { caseId, caseDetail, caseRequest, caseActive } = useCaseContext();
  const pairsRequest = useApi(`/api/cases/${caseId}/pairs`, {
    pollInterval: caseActive ? 6000 : 0,
  });
  const pairs = useMemo(() => normalizePairs(pairsRequest.data), [pairsRequest.data]);
  const seedTargets = useMemo(() => {
    const fromPairs = pairsRequest.data?.seed_targets;
    if (Array.isArray(fromPairs) && fromPairs.length > 0) {
      return fromPairs;
    }
    return caseDetail.targets;
  }, [pairsRequest.data, caseDetail.targets]);
  const explanation = useMemo(
    () => buildCaseExplanation(seedTargets, pairs),
    [seedTargets, pairs],
  );
  const highlightLines = useMemo(
    () =>
      collectStringList(
        caseDetail.raw?.highlights ?? caseDetail.raw?.findings ?? caseDetail.raw?.notes,
      ),
    [caseDetail.raw],
  );
  const metricEntries = useMemo(() => buildMetricEntries(caseDetail), [caseDetail]);
  const scalarEntries = useMemo(
    () => collectScalarEntries(caseDetail.raw, RAW_CASE_EXCLUDES).slice(0, 8),
    [caseDetail.raw],
  );

  return (
    <div className="page-stack">
      {caseRequest.loading && !caseRequest.data ? (
        <LoadingState message="Loading case detail..." />
      ) : null}

      {caseActive ? <ActiveJobNotice caseDetail={caseDetail} caseId={caseId} /> : null}

      <div className="page-grid two-column">
        <section className="panel section-stack">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Overview</p>
              <h2>What this case found</h2>
              {caseDetail.summaryText ? (
                <p className="section-copy">{caseDetail.summaryText}</p>
              ) : null}
            </div>
            <button className="secondary-button" onClick={caseRequest.refresh} type="button">
              Refresh
            </button>
          </div>

          {explanation ? (
            <div className="callout">
              <p>{explanation}</p>
            </div>
          ) : null}

          {metricEntries.length > 0 ? (
            <div className="metric-grid">
              {metricEntries.map((metric) => (
                <MetricCard key={metric.label} label={metric.label} value={metric.value} />
              ))}
            </div>
          ) : null}

          {caseDetail.targets.length > 0 ? (
            <div className="section-stack tight">
              <h3>Targets</h3>
              <div className="chip-row">
                {caseDetail.targets.map((target) => (
                  <span className="chip" key={target}>
                    {target}
                  </span>
                ))}
              </div>
            </div>
          ) : null}

          {highlightLines.length > 0 ? (
            <div className="section-stack tight">
              <h3>Highlights</h3>
              <ul className="simple-list">
                {highlightLines.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </section>

        <aside className="panel section-stack">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Metadata</p>
              <h2>Case details</h2>
            </div>
          </div>

          {scalarEntries.length > 0 ? (
            <DescriptionGrid entries={scalarEntries} />
          ) : (
            <EmptyState message="No scalar summary fields were exposed for this case." />
          )}
        </aside>
      </div>

      <DomainLinkageExplorer
        caseId={caseId}
        pairs={pairs}
        request={pairsRequest}
        seedTargets={seedTargets}
      />

      <RawDataDisclosure label="Raw case payload" value={caseDetail.raw} />
    </div>
  );
}

function ActiveJobNotice({ caseDetail, caseId }) {
  const job = normalizeJob(caseDetail.raw?.job ?? caseDetail.raw?.latest_job, caseDetail.jobId);
  const percent = job.percent ?? caseDetail.progress ?? 0;

  return (
    <section className="panel section-stack active-job-strip">
      <div className="panel-header">
        <div>
          <p className="eyebrow">Job running</p>
          <h2>{formatStatusLabel(caseDetail.status)}</h2>
          <p className="section-copy">
            {job.summary || "The case is still being processed. Results update automatically."}
          </p>
        </div>
        <div className="progress-figure">
          <strong>{formatPercent(percent)}</strong>
          <span>{job.currentStep || "Working..."}</span>
        </div>
      </div>
      <ProgressBar value={percent} />
      <div className="action-row">
        <Link className="text-link" to={`/cases/${caseId}/progress`}>
          View detailed progress and logs
        </Link>
      </div>
    </section>
  );
}

function CasePairPage() {
  const { caseId } = useCaseContext();
  const { pairId } = useParams();
  const pairRequest = useApi(`/api/cases/${caseId}/pairs/${pairId}`);
  const pair = useMemo(
    () => normalizePairDetail(pairRequest.data, pairId),
    [pairRequest.data, pairId],
  );
  const strength = linkStrength(pair.score);
  const reason = connectionReason(pair);
  const barWidth = Math.max(4, Math.min(100, pair.score ?? 0));
  const scalarEntries = useMemo(
    () => collectScalarEntries(pair.raw, RAW_PAIR_EXCLUDES).slice(0, 8),
    [pair.raw],
  );

  return (
    <div className="page-stack">
      <div className="breadcrumb-row">
        <Link className="text-link" to={`/cases/${caseId}/summary`}>
          Back to summary
        </Link>
      </div>

      <section className="panel section-stack">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Pair {pair.id || pairId}</p>
            <h2>{pair.left && pair.right ? `${pair.left} and ${pair.right}` : "Pair detail"}</h2>
          </div>
          <button className="secondary-button" onClick={pairRequest.refresh} type="button">
            Refresh
          </button>
        </div>

        {pairRequest.loading && !pairRequest.data ? (
          <LoadingState message="Loading pair detail..." />
        ) : null}
        {pairRequest.error ? <ErrorState message={pairRequest.error} /> : null}

        <div className="linkage-headline">
          <div className="linkage-percent">
            <strong>{pair.score === null ? "—" : formatPercent(pair.score)}</strong>
            <span className={`status-badge compact ${strength.tone}`}>{strength.label}</span>
          </div>
          <div className="linkage-body">
            <p className="card-copy linkage-reason">{reason}</p>
            <div className="strength-track" aria-hidden="true">
              <div
                className={`strength-fill ${strength.tier}`}
                style={{ width: `${barWidth}%` }}
              />
            </div>
          </div>
        </div>

        <div className="subject-grid">
          <SubjectCard label="Left entity" value={pair.left || "Unavailable"} />
          <SubjectCard label="Right entity" value={pair.right || "Unavailable"} />
        </div>

        {pair.summary ? (
          <div className="callout">
            <p>{pair.summary}</p>
          </div>
        ) : null}
      </section>

      <section className="panel section-stack">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Evidence digest</p>
            <h2>What these domains have in common</h2>
            <p className="section-copy">
              Grouped by what the overlap means, strongest first. Expand a group to see every
              matched value.
            </p>
          </div>
        </div>

        <PairDigest pair={pair} />
      </section>

      {scalarEntries.length > 0 ? (
        <section className="panel section-stack">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Metadata</p>
              <h2>Pair details</h2>
            </div>
          </div>
          <DescriptionGrid entries={scalarEntries} />
        </section>
      ) : null}

      <RawDataDisclosure label="Raw pair payload" value={pair.raw} />
    </div>
  );
}

function CaseClustersPage() {
  const { caseId } = useCaseContext();
  const clustersRequest = useApi(`/api/cases/${caseId}/clusters`);
  const clusterGroups = useMemo(
    () => normalizeClusterGroups(clustersRequest.data),
    [clustersRequest.data],
  );
  const graph = clustersRequest.data?.graph ?? clustersRequest.data?.graph_payload ?? null;
  const seedTargets = useMemo(
    () => new Set(clustersRequest.data?.seed_targets ?? []),
    [clustersRequest.data],
  );

  return (
    <div className="page-stack">
      <section className="panel section-stack">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Clusters</p>
            <h2>Cluster review</h2>
            <p className="section-copy">Loaded from `/api/cases/:caseId/clusters`.</p>
          </div>
          <button className="secondary-button" onClick={clustersRequest.refresh} type="button">
            Refresh
          </button>
        </div>

        {clustersRequest.loading && !clustersRequest.data ? (
          <LoadingState message="Loading clusters..." />
        ) : null}
        {clustersRequest.error ? <ErrorState message={clustersRequest.error} /> : null}
        {!clustersRequest.loading && !clustersRequest.error && clusterGroups.length === 0 ? (
          <EmptyState message="No clusters were returned for this case." />
        ) : null}
        {graph?.nodes?.length > 0 ? (
          <Suspense fallback={<LoadingState message="Loading the cluster map..." />}>
            <ClusterGraph graph={graph} seedTargets={seedTargets} />
          </Suspense>
        ) : null}

        {clusterGroups.length > 0 ? (
          <div className="section-stack">
            {clusterGroups.map((group) => (
              <section className="section-stack tight" key={group.key}>
                <div className="group-heading">
                  <h3>{group.label}</h3>
                  <span>{group.clusters.length} clusters</span>
                </div>

                <div className="cluster-grid">
                  {group.clusters.map((cluster) => (
                    <article className="cluster-card" key={cluster.id}>
                      <div className="cluster-card-top">
                        <div>
                          <p className="eyebrow">{cluster.type ? formatLabel(cluster.type) : "Cluster"}</p>
                          <h4>{cluster.label}</h4>
                        </div>
                        {cluster.score !== null ? <strong>{formatPercent(cluster.score)}</strong> : null}
                      </div>

                      <div className="inline-metrics">
                        <InlineMetric
                          label="Members"
                          value={formatMaybeNumber(cluster.memberCount || cluster.members.length)}
                        />
                        <InlineMetric label="Cluster ID" value={cluster.id} />
                      </div>

                      {cluster.summary ? <p className="card-copy">{cluster.summary}</p> : null}

                      {cluster.members.length > 0 ? (
                        <div className="chip-row">
                          {cluster.members.slice(0, 6).map((member) => (
                            <span className="chip" key={`${cluster.id}-${member}`}>
                              {member}
                            </span>
                          ))}
                        </div>
                      ) : null}
                    </article>
                  ))}
                </div>
              </section>
            ))}
          </div>
        ) : null}
      </section>

      <RawDataDisclosure label="Raw cluster payload" value={clustersRequest.data} />
    </div>
  );
}

function NotFoundPage() {
  return (
    <AppShell>
      <section className="panel section-stack">
        <div className="panel-header">
          <div>
            <p className="eyebrow">404</p>
            <h1>Page not found</h1>
          </div>
        </div>
        <p className="section-copy">
          The requested route is not part of this small routed frontend rewrite.
        </p>
        <div className="action-row">
          <Link className="primary-button" to="/">
            Return to cases
          </Link>
        </div>
      </section>
    </AppShell>
  );
}

const THEME_STORAGE_KEY = "theme";

export function getInitialTheme() {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === "light" || stored === "dark") {
      return stored;
    }
  } catch {
    // Ignore storage access errors and fall back to the system preference.
  }

  return window.matchMedia?.("(prefers-color-scheme: dark)")?.matches ? "dark" : "light";
}

function useTheme() {
  const [theme, setTheme] = useState(getInitialTheme);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, next);
    } catch {
      // Persisting the preference is best-effort.
    }
    setTheme(next);
  };

  return { theme, toggleTheme };
}

function AppShell({ children }) {
  const { theme, toggleTheme } = useTheme();

  return (
    <div className="app-shell">
      <header className="app-header">
        <Link className="brand-mark" to="/">
          <span>IP</span>
          <strong>Intel</strong>
        </Link>
        <div className="header-side">
          <p className="header-copy">Frontend routes for cases, jobs, pairs, and clusters.</p>
          <button
            aria-pressed={theme === "dark"}
            className="secondary-button theme-toggle"
            onClick={toggleTheme}
            title={theme === "dark" ? "Switch to the light theme" : "Switch to the dark theme"}
            type="button"
          >
            <span aria-hidden="true" className="theme-toggle-indicator" />
            {theme === "dark" ? "Light mode" : "Dark mode"}
          </button>
        </div>
      </header>
      <main className="app-main">{children}</main>
    </div>
  );
}

function useCaseContext() {
  return useOutletContext();
}

function collectScalarEntries(source, excludes) {
  if (!source || typeof source !== "object") {
    return [];
  }

  return Object.entries(source)
    .filter(([key, value]) => {
      if (excludes.has(key)) {
        return false;
      }

      if (value === null || value === undefined || value === "") {
        return false;
      }

      if (Array.isArray(value)) {
        return false;
      }

      return typeof value !== "object";
    })
    .map(([key, value]) => ({
      label: formatLabel(key),
      value: formatDisplayValue(value, key),
    }));
}

function collectStringList(value) {
  if (!value) {
    return [];
  }

  if (Array.isArray(value)) {
    return value
      .map((item) => {
        if (typeof item === "string") {
          return item;
        }

        if (item && typeof item === "object") {
          return item.label ?? item.title ?? item.summary ?? item.description ?? null;
        }

        return null;
      })
      .filter(Boolean);
  }

  if (typeof value === "string") {
    return [value];
  }

  return [];
}

function buildMetricEntries(caseDetail) {
  const metrics = [];
  const pushMetric = (label, value) => {
    if (value === null || value === undefined || value === "") {
      return;
    }

    metrics.push({ label, value });
  };

  pushMetric("Status", formatStatusLabel(caseDetail.status));
  pushMetric("Pairs", formatMaybeNumber(caseDetail.pairCount));
  pushMetric("Clusters", formatMaybeNumber(caseDetail.clusterCount));

  Object.entries(caseDetail.metrics || {})
    .slice(0, 4)
    .forEach(([key, value]) => {
      pushMetric(formatLabel(key), formatDisplayValue(value, key));
    });

  return metrics.slice(0, 6);
}

function sortCases(left, right) {
  const leftDate = left.updatedAt ? Date.parse(left.updatedAt) : 0;
  const rightDate = right.updatedAt ? Date.parse(right.updatedAt) : 0;

  if (leftDate !== rightDate) {
    return rightDate - leftDate;
  }

  return String(left.title).localeCompare(String(right.title));
}
