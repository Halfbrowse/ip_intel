import { useEffect, useState } from "react";

export function useApi(path, options = {}) {
  const { enabled = true, pollInterval = 0 } = options;
  const [state, setState] = useState({
    data: null,
    error: null,
    loading: Boolean(path && enabled),
  });
  const [requestVersion, setRequestVersion] = useState(0);

  useEffect(() => {
    if (!path || !enabled) {
      setState({ data: null, error: null, loading: false });
      return undefined;
    }

    let active = true;
    let timerId = null;
    let requestSequence = 0;

    const load = async (reset = false) => {
      const currentRequest = requestSequence + 1;
      requestSequence = currentRequest;

      setState((previous) => ({
        data: reset ? null : previous.data,
        error: null,
        loading: reset || previous.data === null,
      }));

      try {
        const data = await fetchJson(path);

        if (!active || currentRequest !== requestSequence) {
          return;
        }

        setState({ data, error: null, loading: false });
      } catch (error) {
        if (!active || currentRequest !== requestSequence) {
          return;
        }

        setState((previous) => ({
          data: previous.data,
          error: error.message || "Request failed.",
          loading: false,
        }));
      }
    };

    load(true);

    if (pollInterval > 0) {
      timerId = window.setInterval(() => {
        load(false);
      }, pollInterval);
    }

    return () => {
      active = false;
      if (timerId) {
        window.clearInterval(timerId);
      }
    };
  }, [enabled, path, pollInterval, requestVersion]);

  return {
    ...state,
    refresh() {
      setRequestVersion((version) => version + 1);
    },
  };
}

export async function fetchJson(path) {
  const response = await fetch(path, {
    headers: {
      Accept: "application/json",
    },
  });

  const payload = await parsePayload(response);

  if (!response.ok) {
    const message =
      (payload && typeof payload === "object" && (payload.detail || payload.message || payload.error)) ||
      `Request failed with status ${response.status}`;
    throw new Error(String(message));
  }

  return payload;
}

async function parsePayload(response) {
  if (response.status === 204) {
    return null;
  }

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

export function normalizeCases(payload) {
  return coerceArray(payload?.cases ?? payload?.items ?? payload?.results ?? payload).map(
    (item, index) => normalizeCaseItem(item, index),
  );
}

export function normalizeCaseDetail(payload, fallbackId = null) {
  const raw = unwrapEntity(payload, ["case", "data", "item", "result"]);
  const title =
    pickFirst(raw, ["title", "name", "label", "target", "subject"]) ||
    (fallbackId ? `Case ${fallbackId}` : "Untitled case");
  const targets = coerceArray(
    pickFirst(raw, ["targets", "subjects", "entities", "members", "domains"]) || [],
  )
    .map((item) => readableValue(item))
    .filter(Boolean);

  return {
    raw,
    id: pickFirst(raw, ["id", "case_id", "caseId", "uuid"], fallbackId),
    title,
    summaryText: summarizeText(
      pickFirst(raw, ["summary", "overview", "description", "case_summary", "synopsis"]),
    ),
    status: normalizeStatus(
      pickFirst(raw, ["status", "state", "job_status", "job.state"], "unknown"),
    ),
    progress: resolvePercent(
      pickFirst(raw, [
        "progress",
        "percent_complete",
        "progress_percent",
        "completion",
        "job.progress",
        "job.percent_complete",
      ]),
    ),
    jobId: pickFirst(raw, [
      "job_id",
      "jobId",
      "current_job_id",
      "currentJobId",
      "latest_job.id",
      "latestJob.id",
      "job.id",
    ]),
    pairCount:
      pickFirst(raw, ["pair_count", "pairCount", "counts.pairs", "metrics.pairs"], null) ?? null,
    clusterCount:
      pickFirst(raw, ["cluster_count", "clusterCount", "counts.clusters", "metrics.clusters"], null) ??
      null,
    updatedAt: pickFirst(raw, ["updated_at", "updatedAt", "modified_at", "modifiedAt"]),
    metrics: raw?.metrics || raw?.counts || {},
    targets,
  };
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

export function normalizePairs(payload) {
  return coerceArray(payload?.pairs ?? payload?.items ?? payload?.results ?? payload).map(
    (item, index) => normalizePairItem(item, index),
  );
}

export function normalizePairDetail(payload, fallbackId = null) {
  const pair = normalizePairItem(
    unwrapEntity(payload, ["pair", "data", "item", "result"]),
    fallbackId ?? 0,
  );

  return {
    ...pair,
    id: pair.id || fallbackId,
  };
}

export function normalizeClusterGroups(payload) {
  const clustersValue = payload?.clusters ?? payload;

  if (Array.isArray(clustersValue)) {
    return [
      {
        key: "clusters",
        label: "Clusters",
        clusters: clustersValue.map((item, index) => normalizeClusterItem(item, index, "clusters")),
      },
    ];
  }

  if (!clustersValue || typeof clustersValue !== "object") {
    return [];
  }

  return Object.entries(clustersValue)
    .filter(([, value]) => Array.isArray(value))
    .map(([key, value]) => ({
      key,
      label: formatLabel(key),
      clusters: value.map((item, index) => normalizeClusterItem(item, index, key)),
    }));
}

export function normalizeEvidenceMeta(payload) {
  const collection = payload?.evidence ?? payload?.evidence_types ?? payload?.items ?? payload;

  if (Array.isArray(collection)) {
    return collection.map((item, index) => normalizeEvidenceMetaItem(item, index));
  }

  if (!collection || typeof collection !== "object") {
    return [];
  }

  return Object.entries(collection).map(([key, value], index) =>
    normalizeEvidenceMetaItem(
      value && typeof value === "object" ? { ...value, type: value.type || key } : { type: key, description: value },
      index,
    ),
  );
}

export function normalizeEvidenceItems(payload) {
  return coerceArray(payload).map((item, index) => {
    if (typeof item === "string") {
      return {
        id: `evidence-${index}`,
        level: "info",
        message: item,
      };
    }

    const raw = item || {};
    return {
      id: pickFirst(raw, ["id", "timestamp", "time"], `evidence-${index}`),
      level: normalizeStatus(pickFirst(raw, ["level", "severity", "type"], "info")),
      message: pickFirst(raw, ["message", "summary", "detail", "description"], JSON.stringify(raw)),
    };
  });
}

function normalizeCaseItem(item, index) {
  const raw = item || {};
  return {
    raw,
    id: pickFirst(raw, ["id", "case_id", "caseId", "uuid"], index + 1),
    title:
      pickFirst(raw, ["title", "name", "label", "target", "subject"]) || `Case ${index + 1}`,
    summaryText: summarizeText(
      pickFirst(raw, ["summary", "overview", "description", "case_summary"]),
    ),
    status: normalizeStatus(pickFirst(raw, ["status", "state", "job_status"], "unknown")),
    progress: resolvePercent(
      pickFirst(raw, ["progress", "percent_complete", "progress_percent", "completion"]),
    ),
    pairCount:
      pickFirst(raw, ["pair_count", "pairCount", "counts.pairs", "metrics.pairs"], null) ?? null,
    clusterCount:
      pickFirst(raw, ["cluster_count", "clusterCount", "counts.clusters", "metrics.clusters"], null) ??
      null,
    updatedAt: pickFirst(raw, ["updated_at", "updatedAt", "modified_at", "modifiedAt"]),
    jobId: pickFirst(raw, [
      "job_id",
      "jobId",
      "current_job_id",
      "currentJobId",
      "latest_job.id",
      "latestJob.id",
    ]),
    targets: coerceArray(
      pickFirst(raw, ["targets", "subjects", "entities", "members", "domains"]) || [],
    )
      .map((entry) => readableValue(entry))
      .filter(Boolean),
  };
}

function normalizePairItem(item, index) {
  const raw = item || {};
  const entities = coerceArray(pickFirst(raw, ["entities", "subjects", "members"], []));
  const evidence = normalizePairEvidence(
    pickFirst(raw, ["evidence", "evidence_items", "evidenceItems", "signals", "matches"], []),
  );

  let left = readableValue(pickFirst(raw, ["left", "lhs", "source", "domain_a", "a"]));
  let right = readableValue(pickFirst(raw, ["right", "rhs", "target", "domain_b", "b"]));

  if ((!left || !right) && entities.length >= 2) {
    left ||= readableValue(entities[0]);
    right ||= readableValue(entities[1]);
  }

  return {
    raw,
    id: pickFirst(raw, ["id", "pair_id", "pairId", "uuid"], index + 1),
    scope: pickFirst(raw, ["scope", "group", "type"], "pair"),
    left,
    right,
    score: resolvePercent(pickFirst(raw, ["score", "confidence", "strength"])),
    status: normalizeStatus(pickFirst(raw, ["status", "classification", "verdict"], "unknown")),
    summary: summarizeText(
      pickFirst(raw, ["summary", "description", "explanation", "rationale"]),
    ),
    updatedAt: pickFirst(raw, ["updated_at", "updatedAt", "modified_at", "modifiedAt"]),
    evidence,
  };
}

function normalizeClusterItem(item, index, fallbackType) {
  const raw = item || {};
  const members = coerceArray(
    pickFirst(raw, ["members", "entities", "subjects", "domains", "items", "nodes"], []),
  )
    .map((entry) => readableValue(entry))
    .filter(Boolean);

  return {
    raw,
    id: pickFirst(raw, ["id", "cluster_id", "clusterId", "key"], `${fallbackType}-${index + 1}`),
    label:
      pickFirst(raw, ["label", "name", "title", "summary_key", "key"]) ||
      `${formatLabel(fallbackType)} ${index + 1}`,
    type: pickFirst(raw, ["type", "cluster_type", "kind", "signal"], fallbackType),
    score: resolvePercent(pickFirst(raw, ["score", "confidence", "strength"])),
    summary: summarizeText(pickFirst(raw, ["summary", "description", "note"])),
    memberCount:
      pickFirst(raw, ["member_count", "memberCount", "count", "size"], null) ?? members.length,
    members,
  };
}

function normalizeEvidenceMetaItem(item, index) {
  const raw = item || {};
  const type = pickFirst(raw, ["type", "id", "key"], `type_${index + 1}`);
  return {
    raw,
    type,
    label: pickFirst(raw, ["label", "name", "title"], formatLabel(type)),
    category: pickFirst(raw, ["category", "group"], "Other"),
    importance: pickFirst(raw, ["importance", "severity"], "supporting"),
    description: summarizeText(
      pickFirst(raw, ["description", "summary", "detail", "help_text", "helpText"]),
    ),
    whyItMatters: summarizeText(
      pickFirst(raw, ["why_it_matters", "whyItMatters", "reason"]),
    ),
    caveat: summarizeText(
      pickFirst(raw, ["caveat", "why_it_may_not_matter", "whyItMayNotMatter"]),
    ),
  };
}

function normalizePairEvidence(payload) {
  return coerceArray(payload).map((item, index) => {
    if (typeof item === "string") {
      return {
        id: `signal-${index}`,
        type: item,
        title: formatLabel(item),
        value: item,
        summary: null,
        score: null,
      };
    }

    const raw = item || {};
    const type = pickFirst(raw, ["type", "kind", "signal", "category"], `signal_${index + 1}`);
    return {
      raw,
      id: pickFirst(raw, ["id", "key", "value"], `signal-${index}`),
      type,
      title: pickFirst(raw, ["title", "label", "name"], formatLabel(type)),
      importance: pickFirst(raw, ["importance", "severity"], "supporting"),
      category: pickFirst(raw, ["category", "group"], "Other"),
      value: readableValue(
        pickFirst(raw, ["value", "match", "shared_value", "identifier", "matched_values"]),
      ),
      matchedValues: coerceArray(
        pickFirst(raw, ["matched_values", "matchedValues", "values"], []),
      ).map((entry) => readableValue(entry)).filter(Boolean),
      summary: summarizeText(
        pickFirst(raw, ["summary", "description", "reason", "explanation"]),
      ),
      whyItMatters: summarizeText(pickFirst(raw, ["why_it_matters", "whyItMatters"])),
      caveat: summarizeText(
        pickFirst(raw, ["caveat", "why_it_may_not_matter", "whyItMayNotMatter"]),
      ),
      score: resolvePercent(pickFirst(raw, ["score", "confidence", "strength"])),
    };
  });
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
      pickFirst(value, ["label", "name", "title", "target", "domain", "value", "id"]) ||
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
    return value;
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
