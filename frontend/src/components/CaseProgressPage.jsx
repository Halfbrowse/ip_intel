import { memo, useEffect, useMemo, useState } from "react";

import { Link, useOutletContext } from "../router.jsx";
import { formatPercent, isTerminalStatus, normalizeJob, useApi } from "../api.js";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  MetricCard,
  ProgressBar,
  RawDataDisclosure,
  StatusBadge,
  formatMaybeDate,
  formatMaybeNumber,
  formatStatusLabel,
  toneClass,
} from "./primitives.jsx";

export default function CaseProgressPage() {
  const { caseId, caseDetail } = useOutletContext();
  const jobId = caseDetail.jobId;
  const [polling, setPolling] = useState(true);
  const jobRequest = useApi(jobId ? `/api/jobs/${jobId}` : null, {
    enabled: Boolean(jobId),
    pollInterval: jobId && polling ? 3000 : 0,
  });
  const job = useMemo(
    () => normalizeJob(jobRequest.data ?? caseDetail.raw?.job ?? caseDetail.raw?.latest_job, jobId),
    [jobRequest.data, caseDetail.raw, jobId],
  );
  const hasJobData = Boolean(jobRequest.data || caseDetail.raw?.job || caseDetail.raw?.latest_job);
  const jobFinished = hasJobData && isTerminalStatus(job.status);

  useEffect(() => {
    setPolling(!jobFinished);
  }, [jobFinished]);

  if (!jobId) {
    return (
      <div className="page-stack">
        <section className="panel section-stack">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Job tracking</p>
              <h2>Progress</h2>
            </div>
          </div>
          <EmptyState message="This case does not currently expose a job ID, so there is nothing to poll yet." />
        </section>
      </div>
    );
  }

  if (jobFinished) {
    return (
      <div className="page-stack">
        <section className="panel section-stack">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Job tracking</p>
              <h2>This run has finished</h2>
              <p className="section-copy">
                Progress is only shown while a job is actively running. The results are ready
                on the summary page.
              </p>
            </div>
            <StatusBadge status={job.status} />
          </div>

          {job.summary ? (
            <div className="callout">
              <p>{job.summary}</p>
            </div>
          ) : null}

          <div className="metric-grid">
            <MetricCard label="Targets scanned" value={formatMaybeNumber(job.completedSteps)} />
            <MetricCard
              label="Failed targets"
              value={formatMaybeNumber(job.raw?.failed_targets ?? job.failedTargets)}
            />
            <MetricCard label="Finished" value={formatMaybeDate(job.updatedAt)} />
          </div>

          <div className="action-row">
            <Link className="primary-button" to={`/cases/${caseId}/summary`}>
              View results
            </Link>
            <Link className="text-link" to={`/cases/${caseId}/clusters`}>
              Clusters
            </Link>
          </div>
        </section>
      </div>
    );
  }

  const progressValue = job.percent ?? caseDetail.progress ?? 0;

  return (
    <div className="page-stack">
      <section className="panel section-stack">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Job tracking</p>
            <h2>Progress</h2>
            <p className="section-copy">Polling `/api/jobs/:jobId` for live status.</p>
          </div>
          <button className="secondary-button" onClick={jobRequest.refresh} type="button">
            Refresh
          </button>
        </div>

        {jobRequest.loading && !jobRequest.data ? (
          <LoadingState message="Loading job progress..." />
        ) : null}

        {jobRequest.error ? <ErrorState message={jobRequest.error} /> : null}

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
              <strong>{formatPercent(progressValue)}</strong>
              <span>{job.currentStep || "Waiting for the next backend update"}</span>
            </div>
          </div>

          <ProgressBar large value={progressValue} />

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

        {job.steps.length > 0 ? <JobMilestones steps={job.steps} /> : null}
      </section>

      <section className="panel section-stack">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Logs</p>
            <h2>Job output</h2>
          </div>
        </div>

        <JobLogs logs={job.logs} />
      </section>

      <RawDataDisclosure label="Raw job payload" value={job.raw} />
    </div>
  );
}

const JobMilestones = memo(function JobMilestones({ steps }) {
  return (
    <div className="section-stack tight">
      <h3>Milestones</h3>
      <div className="timeline">
        {steps.map((step) => (
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
  );
});

const JobLogs = memo(function JobLogs({ logs }) {
  if (logs.length === 0) {
    return <EmptyState message="No job logs were returned yet." />;
  }

  return (
    <div className="log-shell">
      {logs.map((line) => (
        <div className="log-line" key={line.id}>
          <span className="log-level">{line.level.toUpperCase()}</span>
          <span>{line.message}</span>
        </div>
      ))}
    </div>
  );
});
