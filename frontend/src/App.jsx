import { useDeferredValue, useState } from "react";
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
  formatDate,
  formatLabel,
  formatNumber,
  formatPercent,
  isTerminalStatus,
  normalizeCaseDetail,
  normalizeCases,
  normalizeClusterGroups,
  normalizeEvidenceMeta,
  normalizeJob,
  normalizePairDetail,
  normalizePairs,
  useApi,
} from "./api.js";

const CASE_NAV_ITEMS = [
  { to: "summary", label: "Summary" },
  { to: "progress", label: "Progress" },
  { to: "clusters", label: "Clusters" },
];

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
        <Route path="progress" element={<CaseProgressPage />} />
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
  const cases = normalizeCases(casesRequest.data).sort(sortCases);
  const query = deferredSearch.trim().toLowerCase();
  const filteredCases = query
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
    : cases;

  const runningCases = cases.filter((caseItem) => !isTerminalStatus(caseItem.status)).length;
  const readySummaries = cases.filter((caseItem) => caseItem.summaryText).length;

  return (
    <AppShell>
      <section className="hero-panel">
        <div className="hero-copy">
          <p className="eyebrow">Submission workspace</p>
          <h1>Submit domains or IPs and follow the overlap case as it runs.</h1>
          <p>
            Start with one target or a CSV, then move through progress, overlap summary,
            pair evidence, and cluster review without the old monolithic explorer.
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

        {filteredCases.length > 0 ? (
          <div className="case-grid">
            {filteredCases.map((caseItem) => (
              <article className="case-card" key={caseItem.id}>
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

                {caseItem.progress !== null ? (
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
                  <Link className="text-link" to={`/cases/${caseItem.id}/progress`}>
                    Progress
                  </Link>
                  <Link className="text-link" to={`/cases/${caseItem.id}/clusters`}>
                    Clusters
                  </Link>
                </div>
              </article>
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

function CaseLayout() {
  const { caseId } = useParams();
  const caseRequest = useApi(`/api/cases/${caseId}`);
  const caseDetail = normalizeCaseDetail(caseRequest.data, caseId);

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
              "This case page is wired to the new API and will surface whatever summary data the backend provides."}
          </p>
        </div>
        <div className="hero-side-stack">
          <StatusBadge status={caseDetail.status} />
          <div className="inline-metrics">
            <InlineMetric label="Pairs" value={formatMaybeNumber(caseDetail.pairCount)} />
            <InlineMetric label="Clusters" value={formatMaybeNumber(caseDetail.clusterCount)} />
            <InlineMetric label="Job" value={caseDetail.jobId || "None"} />
          </div>
        </div>
      </section>

      <nav className="case-nav" aria-label="Case sections">
        {CASE_NAV_ITEMS.map((item) => (
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

      <Outlet context={{ caseId, caseDetail, caseRequest }} />
    </AppShell>
  );
}

function CaseSummaryPage() {
  const { caseId, caseDetail, caseRequest } = useCaseContext();
  const pairsRequest = useApi(`/api/cases/${caseId}/pairs`);
  const evidenceMetaRequest = useApi("/api/meta/evidence");
  const pairs = normalizePairs(pairsRequest.data);
  const withinCasePairs = normalizePairs(pairsRequest.data?.within_case ?? []);
  const historicalPairs = normalizePairs(pairsRequest.data?.historical ?? []);
  const evidenceMeta = normalizeEvidenceMeta(evidenceMetaRequest.data);
  const highlightLines = collectStringList(
    caseDetail.raw?.highlights ?? caseDetail.raw?.findings ?? caseDetail.raw?.notes,
  );
  const metricEntries = buildMetricEntries(caseDetail);
  const scalarEntries = collectScalarEntries(caseDetail.raw, RAW_CASE_EXCLUDES).slice(0, 8);

  return (
    <div className="page-stack">
      {caseRequest.loading && !caseRequest.data ? <LoadingState message="Loading case detail..." /> : null}

      <div className="page-grid two-column">
        <section className="panel section-stack">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Summary</p>
              <h2>Case overview</h2>
            </div>
            <button className="secondary-button" onClick={caseRequest.refresh} type="button">
              Refresh
            </button>
          </div>

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

          {caseDetail.summaryText ? (
            <div className="callout">
              <p>{caseDetail.summaryText}</p>
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

      <section className="panel section-stack">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Pairs</p>
            <h2>Related case pairs</h2>
            <p className="section-copy">Loaded from `/api/cases/:caseId/pairs`.</p>
          </div>
          <button className="secondary-button" onClick={pairsRequest.refresh} type="button">
            Refresh
          </button>
        </div>

        {pairsRequest.loading && !pairsRequest.data ? <LoadingState message="Loading pairs..." /> : null}
        {pairsRequest.error ? <ErrorState message={pairsRequest.error} /> : null}
        {!pairsRequest.loading && !pairsRequest.error && pairs.length === 0 ? (
          <EmptyState message="This case does not have any pairs yet." />
        ) : null}
        {withinCasePairs.length > 0 ? (
          <div className="section-stack tight">
            <h3>Within this submission</h3>
            <PairList caseId={caseId} pairs={withinCasePairs} />
          </div>
        ) : null}
        {historicalPairs.length > 0 ? (
          <div className="section-stack tight">
            <h3>Against previous history</h3>
            <PairList caseId={caseId} pairs={historicalPairs} />
          </div>
        ) : null}
      </section>

      <section className="panel section-stack">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Evidence guide</p>
            <h2>Evidence metadata</h2>
            <p className="section-copy">Loaded from `/api/meta/evidence`.</p>
          </div>
          <button
            className="secondary-button"
            onClick={evidenceMetaRequest.refresh}
            type="button"
          >
            Refresh
          </button>
        </div>

        {evidenceMetaRequest.loading && !evidenceMetaRequest.data ? (
          <LoadingState message="Loading evidence metadata..." />
        ) : null}
        {evidenceMetaRequest.error ? <ErrorState message={evidenceMetaRequest.error} /> : null}
        {!evidenceMetaRequest.loading && !evidenceMetaRequest.error && evidenceMeta.length === 0 ? (
          <EmptyState message="The evidence metadata endpoint returned no definitions." />
        ) : null}
        {evidenceMeta.length > 0 ? <EvidenceMetaGrid items={evidenceMeta} /> : null}
      </section>

      <RawDataDisclosure label="Raw case payload" value={caseDetail.raw} />
    </div>
  );
}

function CaseProgressPage() {
  const { caseDetail } = useCaseContext();
  const jobId = caseDetail.jobId;
  const jobRequest = useApi(jobId ? `/api/jobs/${jobId}` : null, {
    enabled: Boolean(jobId),
    pollInterval: jobId ? 3000 : 0,
  });
  const job = normalizeJob(jobRequest.data ?? caseDetail.raw?.job ?? caseDetail.raw?.latest_job, jobId);
  const progressValue =
    job.percent ?? caseDetail.progress ?? (isTerminalStatus(job.status) ? 100 : null);

  return (
    <div className="page-stack">
      <section className="panel section-stack">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Job tracking</p>
            <h2>Progress</h2>
            <p className="section-copy">Polling `/api/jobs/:jobId` for live status.</p>
          </div>
          {jobId ? (
            <button className="secondary-button" onClick={jobRequest.refresh} type="button">
              Refresh
            </button>
          ) : null}
        </div>

        {!jobId ? (
          <EmptyState message="This case does not currently expose a job ID, so there is nothing to poll yet." />
        ) : null}

        {jobRequest.loading && !jobRequest.data && jobId ? (
          <LoadingState message="Loading job progress..." />
        ) : null}

        {jobRequest.error ? <ErrorState message={jobRequest.error} /> : null}

        {jobId ? (
          <div className="progress-card">
            <div className="progress-header">
              <div>
                <p className="eyebrow">Job {job.id || jobId}</p>
                <h3>{formatStatusLabel(job.status)}</h3>
                <p className="card-copy">
                  {job.summary ||
                    "The progress page keeps polling the backend so the loading bar stays current while the case is running."}
                </p>
              </div>
              <div className="progress-figure">
                <strong>{progressValue === null ? "—" : formatPercent(progressValue)}</strong>
                <span>{job.currentStep || "Waiting for the next backend update"}</span>
              </div>
            </div>

            <ProgressBar large value={progressValue ?? 0} />

            <div className="metric-grid">
              <MetricCard label="Status" value={formatStatusLabel(job.status)} />
              <MetricCard label="Completed steps" value={formatMaybeNumber(job.completedSteps)} />
              <MetricCard label="Total steps" value={formatMaybeNumber(job.totalSteps)} />
              <MetricCard
                label="Failed targets"
                value={formatMaybeNumber(job.raw?.failed_targets ?? job.failedTargets)}
              />
              <MetricCard label="Updated" value={formatMaybeDate(job.updatedAt)} />
            </div>
          </div>
        ) : null}

        {job.steps.length > 0 ? (
          <div className="section-stack tight">
            <h3>Milestones</h3>
            <div className="timeline">
              {job.steps.map((step) => (
                <div className="timeline-item" key={step.id}>
                  <div className={`timeline-dot ${toneClass(step.status)}`} />
                  <div>
                    <div className="timeline-title-row">
                      <strong>{step.label}</strong>
                      <span>{formatStatusLabel(step.status)}</span>
                    </div>
                    {step.detail ? <p className="card-copy">{step.detail}</p> : null}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : null}
      </section>

      <section className="panel section-stack">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Logs</p>
            <h2>Job output</h2>
          </div>
        </div>

        {job.logs.length === 0 ? (
          <EmptyState message="No job logs were returned yet." />
        ) : (
          <div className="log-shell">
            {job.logs.map((line) => (
              <div className="log-line" key={line.id}>
                <span className="log-level">{line.level.toUpperCase()}</span>
                <span>{line.message}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      <RawDataDisclosure label="Raw job payload" value={job.raw} />
    </div>
  );
}

function CasePairPage() {
  const { caseId } = useCaseContext();
  const { pairId } = useParams();
  const pairRequest = useApi(`/api/cases/${caseId}/pairs/${pairId}`);
  const evidenceMetaRequest = useApi("/api/meta/evidence");
  const pair = normalizePairDetail(pairRequest.data, pairId);
  const evidenceMeta = normalizeEvidenceMeta(evidenceMetaRequest.data);
  const scalarEntries = collectScalarEntries(pair.raw, RAW_PAIR_EXCLUDES).slice(0, 8);

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
            <p className="section-copy">
              Loaded from `/api/cases/:caseId/pairs/:pairId`.
            </p>
          </div>
          <button className="secondary-button" onClick={pairRequest.refresh} type="button">
            Refresh
          </button>
        </div>

        {pairRequest.loading && !pairRequest.data ? <LoadingState message="Loading pair detail..." /> : null}
        {pairRequest.error ? <ErrorState message={pairRequest.error} /> : null}

        <div className="metric-grid">
          <MetricCard label="Score" value={pair.score === null ? "-" : formatPercent(pair.score)} />
          <MetricCard label="Status" value={formatStatusLabel(pair.status)} />
          <MetricCard label="Evidence items" value={pair.evidence.length} />
          <MetricCard label="Updated" value={formatMaybeDate(pair.updatedAt)} />
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
            <p className="eyebrow">Evidence</p>
            <h2>Signals behind this pair</h2>
          </div>
        </div>

        {pair.evidence.length === 0 ? (
          <EmptyState message="No evidence items were returned for this pair." />
        ) : (
          <div className="evidence-grid">
            {pair.evidence.map((item) => {
              const meta = findEvidenceMeta(evidenceMeta, item.type);
              const values = item.matchedValues?.length ? item.matchedValues : item.value ? [item.value] : [];
              return (
                <article className="evidence-card" key={item.id}>
                  <div className="evidence-card-top">
                    <strong>{meta?.label || item.title || formatLabel(item.type)}</strong>
                    <span>{formatLabel(item.importance || meta?.importance || "supporting")}</span>
                  </div>
                  {values.length > 0 ? (
                    <div className="chip-row">
                      {values.slice(0, 6).map((value) => (
                        <span className="chip" key={`${item.id}-${value}`}>
                          {value}
                        </span>
                      ))}
                    </div>
                  ) : null}
                  <p className="card-copy">
                    {item.summary || meta?.description || "This signal was returned without an explanation."}
                  </p>
                  <div className="evidence-notes">
                    <p>
                      <strong>Why it matters:</strong>{" "}
                      {item.whyItMatters || meta?.whyItMatters || "This overlap adds context to the pair."}
                    </p>
                    <p>
                      <strong>Why it may be weak:</strong>{" "}
                      {item.caveat || meta?.caveat || "This signal should be weighed with the rest of the evidence."}
                    </p>
                  </div>
                </article>
              );
            })}
          </div>
        )}
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
  const clusterGroups = normalizeClusterGroups(clustersRequest.data);
  const graph = clustersRequest.data?.graph ?? clustersRequest.data?.graph_payload ?? null;

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
        {graph?.nodes?.length > 0 ? <ClusterGraph graph={graph} /> : null}

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

function ClusterGraph({ graph }) {
  const layout = buildClusterLayout(graph);

  return (
    <section className="cluster-graph-card">
      <div className="panel-header">
        <div>
          <p className="eyebrow">Diagram</p>
          <h3>Cluster map</h3>
        </div>
      </div>
      <svg className="cluster-graph" viewBox={`0 0 ${layout.width} ${layout.height}`}>
        {layout.edges.map((edge) => (
          <line
            key={`${edge.from}-${edge.to}`}
            stroke={edge.color || "#94a3b8"}
            strokeWidth={edge.width || 1}
            x1={edge.x1}
            x2={edge.x2}
            y1={edge.y1}
            y2={edge.y2}
          />
        ))}
        {layout.nodes.map((node) => (
          <g key={node.id} transform={`translate(${node.x}, ${node.y})`}>
            <circle fill={node.color || "#2752d6"} r="18" />
            <text className="graph-node-label" textAnchor="middle" y="34">
              {node.label}
            </text>
          </g>
        ))}
      </svg>
    </section>
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

function AppShell({ children }) {
  return (
    <div className="app-shell">
      <header className="app-header">
        <Link className="brand-mark" to="/">
          <span>IP</span>
          <strong>Intel</strong>
        </Link>
        <p className="header-copy">Frontend routes for cases, jobs, pairs, and clusters.</p>
      </header>
      <main className="app-main">{children}</main>
    </div>
  );
}

function PairList({ caseId, pairs }) {
  return (
    <div className="pair-list">
      {pairs.map((pair) => (
        <article className="pair-row" key={pair.id}>
          <div className="pair-row-copy">
            <h3>{pair.left && pair.right ? `${pair.left} vs ${pair.right}` : `Pair ${pair.id}`}</h3>
            <p className="card-copy">
              {pair.summary ||
                `${pair.evidence.length} evidence item${pair.evidence.length === 1 ? "" : "s"} returned.`}
            </p>
          </div>
          <div className="pair-row-meta">
            {pair.score !== null ? <strong>{formatPercent(pair.score)}</strong> : null}
            <StatusBadge compact status={pair.status} />
            <Link className="text-link" to={`/cases/${caseId}/pairs/${pair.id}`}>
              Open pair
            </Link>
          </div>
        </article>
      ))}
    </div>
  );
}

function EvidenceMetaGrid({ items }) {
  return (
    <div className="evidence-grid">
      {items.map((item) => (
        <article className="evidence-card" key={item.type}>
          <div className="evidence-card-top">
            <strong>{item.label}</strong>
            <span>{item.type}</span>
          </div>
          <p className="card-copy">
            {item.description || "This evidence type did not include a description."}
          </p>
        </article>
      ))}
    </div>
  );
}

function DescriptionGrid({ entries }) {
  return (
    <dl className="description-grid">
      {entries.map((entry) => (
        <div className="description-item" key={entry.label}>
          <dt>{entry.label}</dt>
          <dd>{entry.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function MetricCard({ label, value }) {
  return (
    <article className="metric-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

function SubjectCard({ label, value }) {
  return (
    <article className="subject-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

function InlineMetric({ label, value }) {
  return (
    <div className="inline-metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ProgressBar({ large = false, value }) {
  const safeValue = Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : 0;
  return (
    <div className={`progress-track ${large ? "large" : ""}`}>
      <div className="progress-fill" style={{ width: `${safeValue}%` }} />
    </div>
  );
}

function StatusBadge({ compact = false, status }) {
  return (
    <span className={`status-badge ${toneClass(status)} ${compact ? "compact" : ""}`}>
      {formatStatusLabel(status)}
    </span>
  );
}

function LoadingState({ message }) {
  return <div className="state-card">{message}</div>;
}

function ErrorState({ message }) {
  return <div className="state-card error">{message}</div>;
}

function EmptyState({ message }) {
  return <div className="state-card muted">{message}</div>;
}

function RawDataDisclosure({ label, value }) {
  if (!value) {
    return null;
  }

  return (
    <details className="raw-disclosure">
      <summary>{label}</summary>
      <pre>{JSON.stringify(value, null, 2)}</pre>
    </details>
  );
}

function useCaseContext() {
  return useOutletContext();
}

function buildClusterLayout(graph) {
  const width = 1080;
  const height = 540;
  const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph?.edges) ? graph.edges : [];
  const grouped = new Map();

  nodes.forEach((node) => {
    const key = node.cluster ?? node.group ?? "isolate";
    if (!grouped.has(key)) {
      grouped.set(key, []);
    }
    grouped.get(key).push(node);
  });

  const groups = Array.from(grouped.values());
  const centerX = width / 2;
  const centerY = height / 2 - 10;
  const outerRadius = Math.max(120, Math.min(240, 56 * groups.length));
  const layoutNodes = [];
  const byId = new Map();

  groups.forEach((groupNodes, groupIndex) => {
    const groupAngle = (Math.PI * 2 * groupIndex) / Math.max(groups.length, 1);
    const groupCenterX =
      groups.length === 1 ? centerX : centerX + Math.cos(groupAngle) * outerRadius;
    const groupCenterY =
      groups.length === 1 ? centerY : centerY + Math.sin(groupAngle) * Math.min(outerRadius * 0.55, 150);
    const innerRadius = Math.max(24, 18 * groupNodes.length);

    groupNodes.forEach((node, nodeIndex) => {
      const nodeAngle = (Math.PI * 2 * nodeIndex) / Math.max(groupNodes.length, 1);
      const x = groupCenterX + Math.cos(nodeAngle) * (groupNodes.length === 1 ? 0 : innerRadius);
      const y = groupCenterY + Math.sin(nodeAngle) * (groupNodes.length === 1 ? 0 : innerRadius);
      const laidOutNode = { ...node, x, y };
      layoutNodes.push(laidOutNode);
      byId.set(node.id, laidOutNode);
    });
  });

  const layoutEdges = edges
    .map((edge) => {
      const fromNode = byId.get(edge.from);
      const toNode = byId.get(edge.to);
      if (!fromNode || !toNode) {
        return null;
      }
      return {
        ...edge,
        x1: fromNode.x,
        y1: fromNode.y,
        x2: toNode.x,
        y2: toNode.y,
      };
    })
    .filter(Boolean);

  return {
    width,
    height,
    nodes: layoutNodes,
    edges: layoutEdges,
  };
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
  pushMetric("Progress", caseDetail.progress === null ? null : formatPercent(caseDetail.progress));

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

function formatDisplayValue(value, key = "") {
  if (value === null || value === undefined || value === "") {
    return "—";
  }

  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }

  if (typeof value === "number") {
    return formatNumber(value);
  }

  if (typeof value === "string") {
    if (/(_at|_on|date|time)$/i.test(key)) {
      return formatDate(value);
    }

    return value;
  }

  return String(value);
}

function formatMaybeDate(value) {
  return value ? formatDate(value) : "—";
}

function formatMaybeNumber(value) {
  return value === null || value === undefined || value === "" ? "—" : formatNumber(value);
}

function toneClass(status) {
  const normalized = String(status || "unknown").toLowerCase();

  if (normalized.includes("fail") || normalized.includes("error") || normalized.includes("cancel")) {
    return "danger";
  }

  if (
    normalized.includes("done") ||
    normalized.includes("complete") ||
    normalized.includes("success") ||
    normalized.includes("ready")
  ) {
    return "success";
  }

  if (normalized.includes("warn") || normalized.includes("review") || normalized.includes("hold")) {
    return "warning";
  }

  return "info";
}

function formatStatusLabel(status) {
  if (!status) {
    return "Unknown";
  }

  return formatLabel(status);
}

function findEvidenceMeta(items, type) {
  return items.find((item) => item.type === type) ?? null;
}
