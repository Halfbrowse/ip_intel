export const DEFAULT_POOL_FILTERS = {
  search: "",
  provenance: "all",
  sort: "recent",
  minConnections: "",
  maxConnections: "",
  discoveredAfter: "",
  discoveredBefore: "",
  ingestedAfter: "",
  ingestedBefore: "",
};

export const DEFAULT_PAGE_SIZE = 24;

export function buildPoolQuery(filters = DEFAULT_POOL_FILTERS, page = 1, pageSize = DEFAULT_PAGE_SIZE) {
  const params = new URLSearchParams();
  const offset = Math.max(0, (Number(page) || 1) - 1) * pageSize;

  appendParam(params, "search", filters.search);
  appendParam(params, "provenance", filters.provenance !== "all" ? filters.provenance : "");
  appendParam(params, "sort", filters.sort !== "recent" ? filters.sort : "");
  appendParam(params, "min_connections", filters.minConnections);
  appendParam(params, "max_connections", filters.maxConnections);
  appendParam(params, "discovered_after", filters.discoveredAfter);
  appendParam(params, "discovered_before", filters.discoveredBefore);
  appendParam(params, "ingested_after", filters.ingestedAfter);
  appendParam(params, "ingested_before", filters.ingestedBefore);
  appendParam(params, "limit", pageSize);
  appendParam(params, "offset", offset);

  const query = params.toString();
  return query ? `/api/pool?${query}` : "/api/pool";
}

export function poolFiltersActive(filters = DEFAULT_POOL_FILTERS) {
  return Object.entries(DEFAULT_POOL_FILTERS).some(([key, value]) => filters[key] !== value);
}

export function getPoolPageMeta(payload, fallbackCount, page = 1, pageSize = DEFAULT_PAGE_SIZE) {
  const total = Number.isFinite(Number(payload?.total)) ? Number(payload.total) : fallbackCount;
  const offset = Number.isFinite(Number(payload?.offset)) ? Number(payload.offset) : Math.max(0, page - 1) * pageSize;
  const limit = Number.isFinite(Number(payload?.limit)) ? Number(payload.limit) : pageSize;
  const pageCount = Math.max(1, Math.ceil(total / Math.max(1, limit)));

  return {
    total,
    offset,
    limit,
    page,
    pageCount,
    start: total === 0 ? 0 : offset + 1,
    end: Math.min(total, offset + fallbackCount),
  };
}

function appendParam(params, key, value) {
  if (value === null || value === undefined || value === "") {
    return;
  }
  params.set(key, String(value));
}
