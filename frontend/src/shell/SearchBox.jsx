import { useEffect, useState } from "react";
import { Autocomplete } from "reshaped";

import { normalizeSearchResults, useApi } from "../api.js";
import { sharedNodeLabel } from "../features/evidence.jsx";
import { rememberFocus } from "../features/focus.js";
import { useNavigate } from "../router.jsx";

const DEBOUNCE_MS = 200;
const MIN_QUERY_LENGTH = 2;

// Global "find anything" box — a channel, a subdomain, or an evidence value
// (cert hash, tracking ID, ...) — hits the precomputed /api/search index, not
// a live scan or scoring pass, so it's always instant.
export default function SearchBox() {
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const handle = setTimeout(() => setDebounced(query.trim()), DEBOUNCE_MS);
    return () => clearTimeout(handle);
  }, [query]);

  const path =
    debounced.length >= MIN_QUERY_LENGTH ? `/api/search?q=${encodeURIComponent(debounced)}&limit=8` : null;
  const searchRequest = useApi(path);
  const results = normalizeSearchResults(searchRequest.data);
  const hasResults = results.domains.length > 0 || results.selectors.length > 0;
  const showMenu = debounced.length >= MIN_QUERY_LENGTH;
  // The hook holds the previous query's payload for one render after `path`
  // changes, so without this the menu briefly lists matches for what the user
  // typed a moment ago. The normalizer already carries the query the server
  // answered, so compare against it rather than guessing from timing.
  const isStale = Boolean(results.query) && results.query !== debounced;

  const handleItemSelect = ({ data }) => {
    setQuery("");
    setDebounced("");
    if (!data) {
      return;
    }
    if (data.type === "domain") {
      navigate(`/domain/${encodeURIComponent(data.domain)}`);
    } else {
      rememberFocus(data.sampleDomains);
      navigate("/connections");
    }
  };

  return (
    <Autocomplete
      className="global-search"
      inputAttributes={{ "aria-label": "Search channels and evidence" }}
      name="global-search"
      onChange={({ value }) => setQuery(value)}
      onItemSelect={handleItemSelect}
      placeholder="Search domains, certs, IPs..."
      value={query}
    >
      {showMenu ? (
        <>
          {searchRequest.error ? (
            <Autocomplete.Item disabled value="">
              Search unavailable — {searchRequest.error}
            </Autocomplete.Item>
          ) : null}
          {(isStale ? [] : results.domains).map((entry) => (
            <Autocomplete.Item data={{ type: "domain", domain: entry.domain }} key={entry.domain} value={entry.domain}>
              {entry.domain} — {entry.connectionCount} connection{entry.connectionCount === 1 ? "" : "s"}
            </Autocomplete.Item>
          ))}
          {(isStale ? [] : results.selectors).map((entry) => (
            <Autocomplete.Item
              data={{ type: "selector", sampleDomains: entry.sampleDomains }}
              key={entry.id}
              value={entry.value}
            >
              {sharedNodeLabel(entry.kind)}: {entry.value} — {entry.domainCount} channels
            </Autocomplete.Item>
          ))}
          {/* "No matches" is an answer about the corpus, so it must not stand
              in for a failed or still-running request. */}
          {!searchRequest.loading && !searchRequest.error && !isStale && !hasResults ? (
            <Autocomplete.Item disabled value="">
              No matches.
            </Autocomplete.Item>
          ) : null}
        </>
      ) : null}
    </Autocomplete>
  );
}
