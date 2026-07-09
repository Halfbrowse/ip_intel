import { useEffect, useMemo, useRef, useState } from "react";

import {
  formatDate,
  formatLabel,
  formatPercent,
  isTerminalStatus,
  normalizeJob,
  useApi,
} from "../api.js";
import {
  ErrorState,
  ProgressBar,
} from "../components/primitives.jsx";

export async function postIngest({ file, target, label }) {
  if (file) {
    const formData = new FormData();
    formData.append("file", file);
    if (label) {
      formData.append("label", label);
    }
    const response = await fetch("/api/ingest", {
      method: "POST",
      body: formData,
      headers: { Accept: "application/json" },
    });
    return finishIngest(response);
  }
  const response = await fetch("/api/ingest", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ target, label }),
  });
  return finishIngest(response);
}

export async function finishIngest(response) {
  const text = await response.text();
  let payload = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = text;
  }
  if (!response.ok) {
    const message =
      (payload && typeof payload === "object" && (payload.detail || payload.message || payload.error)) ||
      (typeof payload === "string" ? payload : null) ||
      `Request failed with status ${response.status}.`;
    throw new Error(message);
  }
  return payload;
}

function JobProgress({ jobId, onComplete }) {
  const jobRequest = useApi(jobId ? `/api/jobs/${jobId}` : null, { pollInterval: 4000 });
  const job = useMemo(() => normalizeJob(jobRequest.data, jobId), [jobRequest.data, jobId]);
  const done = isTerminalStatus(job.status);
  const visibleSteps = job.steps.slice(0, 6);
  const recentLogs = job.logs.slice(-5);
  const notifiedRef = useRef(null);

  useEffect(() => {
    if (done && jobId && notifiedRef.current !== jobId) {
      notifiedRef.current = jobId;
      onComplete?.();
    }
  }, [done, jobId, onComplete]);

  if (!jobId) {
    return null;
  }

  return (
    <div className="callout active-job-strip">
      <div className="mini-progress-top">
        <span>Ingest job {jobId}</span>
        <strong>{formatPercent(job.percent ?? 0)}</strong>
      </div>
      <ProgressBar value={job.percent ?? 0} />

      <div className="job-status-grid">
        <div>
          <span>Stage</span>
          <strong>{job.stage || job.currentStep || formatLabel(job.status)}</strong>
        </div>
        <div>
          <span>Current target</span>
          <strong>{job.currentTarget || "Waiting for target"}</strong>
        </div>
        <div>
          <span>Steps</span>
          <strong>
            {job.completedSteps ?? visibleSteps.filter((step) => isTerminalStatus(step.status)).length}
            {job.totalSteps || visibleSteps.length ? ` / ${job.totalSteps || visibleSteps.length}` : ""}
          </strong>
        </div>
      </div>

      <p className="card-copy">
        {done
          ? "Scan complete. New channels are now available in the pool."
          : job.summary || job.currentStep || "Scanning; results join the pool as they finish."}
        {job.updatedAt ? ` Updated ${formatDate(job.updatedAt)}.` : ""}
      </p>

      {visibleSteps.length > 0 ? (
        <ol className="job-steps">
          {visibleSteps.map((step) => (
            <li className={`job-step ${step.status}`} key={step.id}>
              <span className={`timeline-dot ${step.status}`} aria-hidden="true" />
              <span>
                <strong>{step.label}</strong>
                {step.detail ? <small>{step.detail}</small> : null}
              </span>
            </li>
          ))}
        </ol>
      ) : null}

      {recentLogs.length > 0 ? (
        <div className="log-shell compact" aria-label="Recent ingest logs">
          {recentLogs.map((line) => (
            <div className="log-line" key={line.id}>
              <span className="log-level">{line.level}</span>
              <span>{line.message}</span>
            </div>
          ))}
        </div>
      ) : null}

      {job.failedTargets ? (
        <p className="card-copy danger-copy">{job.failedTargets} target(s) failed during this ingest.</p>
      ) : null}
      {jobRequest.error ? <ErrorState message={jobRequest.error} /> : null}
    </div>
  );
}

export default function IngestPanel({ onIngested }) {
  const [targetInput, setTargetInput] = useState("");
  const [label, setLabel] = useState("");
  const [csvFile, setCsvFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [jobId, setJobId] = useState(null);

  const run = async (args) => {
    setBusy(true);
    setError(null);
    try {
      const payload = await postIngest({ ...args, label: label.trim() || undefined });
      setJobId(payload?.job_id || payload?.job?.id || null);
      onIngested?.();
    } catch (err) {
      setError(err.message || "Ingest failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel section-stack">
      <div className="panel-header">
        <div>
          <p className="eyebrow">Add to pool</p>
          <h2>Ingest channels</h2>
          <p className="section-copy">
            Scan one domain or IP, or upload a CSV first column. Results join the shared channel pool.
          </p>
        </div>
      </div>

      <label className="search-field">
        <span>Label (optional)</span>
        <input
          name="label"
          onChange={(event) => setLabel(event.target.value)}
          placeholder="campaign, source, or analyst note"
          type="text"
          value={label}
        />
      </label>

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
            disabled={busy || !targetInput.trim()}
            onClick={() => run({ target: targetInput.trim() })}
            type="button"
          >
            {busy ? "Submitting..." : "Scan and add"}
          </button>
        </div>

        <div className="submission-card">
          <label className="search-field file-field">
            <span>CSV upload</span>
            <input accept=".csv,text/csv" onChange={(event) => setCsvFile(event.target.files?.[0] || null)} type="file" />
          </label>
          <button className="primary-button" disabled={busy || !csvFile} onClick={() => run({ file: csvFile })} type="button">
            {busy ? "Submitting..." : "Upload CSV"}
          </button>
        </div>

      </div>

      {error ? <ErrorState message={error} /> : null}
      {jobId ? <JobProgress jobId={jobId} onComplete={onIngested} /> : null}
    </section>
  );
}
