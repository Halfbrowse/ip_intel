import { useEffect, useMemo, useRef, useState } from "react";
import { Button, Card, FileUpload, Text, TextField, View } from "reshaped";

import {
  formatDate,
  formatLabel,
  formatPercent,
  isTerminalStatus,
  normalizeJob,
  readJsonResponse,
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
    return readJsonResponse(response);
  }
  const response = await fetch("/api/ingest", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ target, label }),
  });
  return readJsonResponse(response);
}

// Kept as a named re-export: this was the de-facto shared response parser and
// other modules import it from here. The behaviour now lives in api.js.
export { readJsonResponse as finishIngest };

function JobProgress({ jobId, onComplete }) {
  // `done` gates the interval: a finished job is a terminal resource, and
  // polling it every 4s for as long as the pool page stays open is pure waste.
  // The hook reads pollInterval on each render, so flipping it to 0 tears the
  // timer down without disturbing the data already loaded.
  const [done, setDone] = useState(false);
  const jobRequest = useApi(jobId ? `/api/jobs/${jobId}` : null, {
    pollInterval: done ? 0 : 4000,
  });
  const job = useMemo(() => normalizeJob(jobRequest.data, jobId), [jobRequest.data, jobId]);
  const terminal = isTerminalStatus(job.status);

  useEffect(() => {
    setDone(terminal);
  }, [terminal]);
  const visibleSteps = job.steps.slice(0, 6);
  const recentLogs = job.logs.slice(-5);
  const notifiedRef = useRef(null);

  useEffect(() => {
    if (terminal && jobId && notifiedRef.current !== jobId) {
      notifiedRef.current = jobId;
      onComplete?.();
    }
  }, [terminal, jobId, onComplete]);

  if (!jobId) {
    return null;
  }

  return (
    <Card padding={4}>
      <View align="center" direction="row" justify="space-between">
        <Text color="neutral-faded">Ingest job {jobId}</Text>
        <Text weight="bold">{formatPercent(job.percent ?? 0)}</Text>
      </View>
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
        <Text color="critical">{job.failedTargets} target(s) failed during this ingest.</Text>
      ) : null}
      {jobRequest.error ? <ErrorState message={jobRequest.error} /> : null}
    </Card>
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

      <View gap={1}>
        <Text variant="body-2" weight="medium">
          Label (optional)
        </Text>
        <TextField
          name="label"
          onChange={({ value }) => setLabel(value)}
          placeholder="campaign, source, or analyst note"
          value={label}
        />
      </View>

      <div className="submission-grid">
        <Card padding={4}>
          <View gap={3}>
            <View gap={1}>
              <Text variant="body-2" weight="medium">
                Single domain or IP
              </Text>
              <TextField
                name="target"
                onChange={({ value }) => setTargetInput(value)}
                placeholder="example.com or 203.0.113.10"
                value={targetInput}
              />
            </View>
            <Button
              color="primary"
              disabled={busy || !targetInput.trim()}
              loading={busy}
              onClick={() => run({ target: targetInput.trim() })}
            >
              {busy ? "Submitting..." : "Scan and add"}
            </Button>
          </View>
        </Card>

        <Card padding={4}>
          <View gap={3}>
            <View gap={1}>
              <Text variant="body-2" weight="medium">
                CSV upload
              </Text>
              <FileUpload
                inputAttributes={{ accept: ".csv,text/csv" }}
                name="csv-upload"
                onChange={({ value }) => setCsvFile(value?.[0] || null)}
              >
                {csvFile ? csvFile.name : "Choose a CSV file or drag it here"}
              </FileUpload>
            </View>
            <Button color="primary" disabled={busy || !csvFile} loading={busy} onClick={() => run({ file: csvFile })}>
              {busy ? "Submitting..." : "Upload CSV"}
            </Button>
          </View>
        </Card>
      </div>

      {error ? <ErrorState message={error} /> : null}
      {jobId ? <JobProgress jobId={jobId} onComplete={onIngested} /> : null}
    </section>
  );
}
