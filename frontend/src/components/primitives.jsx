import { formatDate, formatLabel, formatNumber } from "../api.js";

export function DescriptionGrid({ entries }) {
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

export function MetricCard({ label, value }) {
  return (
    <article className="metric-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

export function SubjectCard({ label, value }) {
  return (
    <article className="subject-card">
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

export function StatusBadge({ compact = false, status }) {
  return (
    <span className={`status-badge ${toneClass(status)} ${compact ? "compact" : ""}`}>
      {formatStatusLabel(status)}
    </span>
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

export function RawDataDisclosure({ label, value }) {
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

export function formatDisplayValue(value, key = "") {
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

export function formatMaybeDate(value) {
  return value ? formatDate(value) : "—";
}

export function formatMaybeNumber(value) {
  return value === null || value === undefined || value === "" ? "—" : formatNumber(value);
}

export function toneClass(status) {
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

export function formatStatusLabel(status) {
  if (!status) {
    return "Unknown";
  }

  return formatLabel(status);
}
