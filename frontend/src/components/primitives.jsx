export function MetricCard({ label, value }) {
  return (
    <article className="metric-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

export function InlineMetric({ label, value }) {
  return (
    <div className="inline-metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function ProgressBar({ large = false, value }) {
  const safeValue = Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : 0;
  return (
    <div className={`progress-track ${large ? "large" : ""}`}>
      <div className="progress-fill" style={{ width: `${safeValue}%` }} />
    </div>
  );
}

export function LoadingState({ message }) {
  return <div className="state-card">{message}</div>;
}

export function ErrorState({ message }) {
  return <div className="state-card error">{message}</div>;
}

export function EmptyState({ message }) {
  return <div className="state-card muted">{message}</div>;
}
