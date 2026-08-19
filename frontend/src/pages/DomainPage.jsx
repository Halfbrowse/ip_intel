import { useCallback, useMemo, useState } from "react";
import { Badge, Button, Card, Text, TextField, View } from "reshaped";

import {
  formatDate,
  formatLabel,
  normalizeGraphLinks,
  normalizeGraphPath,
  normalizeRelatedThrough,
  useApi,
} from "../api.js";
import { EmptyState, ErrorState, LoadingState } from "../components/primitives.jsx";
import {
  ConnectionCard,
  FaviconThumb,
  ProvenanceBadge,
  TierBadge,
  ipNetworkBadge,
  sharedNodeLabel,
} from "../features/evidence.jsx";
import { downloadReportCsv, downloadReportJson, printReport } from "../features/exportReport.js";
import { rememberFocus } from "../features/focus.js";
import { PathChain } from "../features/pathExplain.jsx";
import { Link, useParams } from "../router.jsx";
import AppShell from "../shell/AppShell.jsx";

export default function DomainPage() {
  const { value } = useParams();
  const profileRequest = useApi(`/api/domain/${encodeURIComponent(value)}`);
  const linksRequest = useApi(`/api/graph/links/${encodeURIComponent(value)}`);
  const profile = profileRequest.data;
  const links = useMemo(() => normalizeGraphLinks(linksRequest.data), [linksRequest.data]);
  const [expanded, setExpanded] = useState(null);
  // printReport returns false when the browser blocked the popup; without
  // surfacing it, "Export report" simply did nothing with no explanation.
  const [printBlocked, setPrintBlocked] = useState(false);
  const toggle = useCallback((key) => setExpanded((current) => (current === key ? null : key)), []);
  const directTargets = useMemo(() => new Set(links.map((link) => link.target)), [links]);
  const exportScope = useMemo(
    () => ({
      title: `${value} — connection report`,
      domains: [value],
      pairs: links.map((link) => ({ ...link, a: value, b: link.target, connected: true })),
      chains: [],
    }),
    [value, links],
  );

  const selectorsByKind = useMemo(() => {
    const map = new Map();
    for (const selector of profile?.selectors || []) {
      if (!map.has(selector.kind)) {
        map.set(selector.kind, []);
      }
      map.get(selector.kind).push(selector);
    }
    return [...map.entries()];
  }, [profile]);

  const intel = profile?.intel || null;
  const dnsEntries = Object.entries(intel?.dns || {}).filter(([, item]) => item && (!Array.isArray(item) || item.length));
  const whoisEntries = Object.entries(intel?.whois || {}).filter(([key, item]) => item && key !== "error" && key !== "raw");
  const trackingEntries = Object.entries(intel?.tracking || {});
  const socialHandleEntries = Object.entries(intel?.social_handles || {}).filter(([, item]) => item && item.length);
  const socialLinkEntries = Object.entries(intel?.social_links || {}).filter(([, item]) => item && item.length);
  const siteVerificationEntries = Object.entries(intel?.site_verifications || {}).filter(([, item]) => item && item.length);
  const cryptoWalletEntries = Object.entries(intel?.crypto_wallets || {}).filter(([, item]) => item && item.length);
  const phoneNumbers = (intel?.phone_numbers || []).filter(Boolean);
  const otherHosts = (profile?.hosts || []).filter((host) => host.value !== profile?.domain);

  return (
    <AppShell>
      <div className="breadcrumb-row">
        <Link className="text-link" to="/">
          Pool
        </Link>
        <span>/</span>
        <span>{value}</span>
      </div>

      <div className="page-heading">
        <div className="page-heading-row">
          <div>
            <h1>
              {value}
              {profile ? (
                <span className="heading-badges">
                  <ProvenanceBadge ingested={profile.ingested} />
                  {profile.tier ? <TierBadge tier={profile.tier} /> : null}
                </span>
              ) : null}
            </h1>
            <p>
              {profile
                ? `${profile.host_count || 0} host${profile.host_count === 1 ? "" : "s"} | ${(profile.ips || []).length} IP${(profile.ips || []).length === 1 ? "" : "s"} | ${links.length} connection${links.length === 1 ? "" : "s"}`
                : "Everything gathered on this channel."}
            </p>
            {profile && !profile.ingested && intel?.discovery_kind ? (
              <p className="card-copy discovery-note">
                Found via {formatLabel(intel.discovery_kind)}
                {intel.discovered_from ? ` from ${intel.discovered_from}` : ""}
                {intel.discovery_reason ? ` (${intel.discovery_reason})` : ""}.
              </p>
            ) : null}
            {(intel?.opencti_labels || []).length > 0 ? (
              <View direction="row" gap={1} wrap>
                {intel.opencti_labels.map((label) => (
                  <Badge attributes={{ title: "OpenCTI label" }} color="primary" key={label} variant="faded">
                    {label}
                  </Badge>
                ))}
              </View>
            ) : null}
          </div>
          <Link className="primary-button" onClick={() => rememberFocus(value)} to="/connections">
            Compare with others
          </Link>
        </div>
      </div>

      {profileRequest.loading && !profile ? <LoadingState message="Loading channel..." /> : null}
      {profileRequest.error ? <ErrorState message={profileRequest.error} /> : null}

      {profile ? (
        <>
          <section className="panel section-stack">
            <div className="panel-header">
              <div>
                <h2>Connections</h2>
                <p className="section-copy">
                  {links.length === 0 ? "No connections to other channels yet." : "Other channels this one is linked to."}
                </p>
              </div>
            </div>
            {links.length === 0 ? (
              <EmptyState message="Nothing in the pool shares attributing evidence with this channel." />
            ) : (
              <div className="linkage-list">
                {links.slice(0, 25).map((link) => (
                  <ConnectionCard
                    expanded={expanded === link.target}
                    key={link.target}
                    leftLabel={value}
                    link={link}
                    onToggle={toggle}
                    rightLabel={link.target}
                    toggleKey={link.target}
                  />
                ))}
                {/* Silent truncation is a lie of omission on an intel page:
                    the analyst had no way to tell 25 connections from 250. */}
                {links.length > 25 ? (
                  <Text color="neutral-faded" variant="body-2">
                    Showing the 25 strongest of {links.length} connections. Use Compare channels to
                    work through the rest.
                  </Text>
                ) : null}
              </div>
            )}
          </section>

          {links.length > 0 ? (
            <Card padding={4}>
              <View align="center" direction="row" gap={3} wrap>
                <Text color="neutral-faded">Share these findings without the graph:</Text>
                <Button onClick={() => setPrintBlocked(!printReport(exportScope))} size="small" title="Open a printable plain-language report (use your browser's Save as PDF)" variant="outline">
                  Export report
                </Button>
                <Button onClick={() => downloadReportCsv(exportScope)} size="small" title="Download every connection and its evidence as a CSV" variant="outline">
                  Export CSV
                </Button>
                <Button onClick={() => downloadReportJson(exportScope)} size="small" title="Download the raw connection data as JSON" variant="outline">
                  Export JSON
                </Button>
              </View>
              {printBlocked ? (
                <Text color="critical" variant="body-2">
                  Allow pop-ups for this site to open the printable report.
                </Text>
              ) : null}
            </Card>
          ) : null}

          <RelatedThroughSection value={value} directTargets={directTargets} />
          <FindPathSection value={value} />

          <section className="panel section-stack">
            <div className="panel-header">
              <div>
                <h2>What we found</h2>
                <p className="section-copy">Extracted observables. A degree above 1 means the value is shared.</p>
              </div>
            </div>
            {selectorsByKind.length === 0 ? (
              <EmptyState message="No selectors extracted yet." />
            ) : (
              selectorsByKind.map(([kind, items]) => (
                <div className="section-stack tight" key={kind}>
                  <div className="group-heading">
                    <h4>{sharedNodeLabel(kind)}</h4>
                    <span>{items.length}</span>
                  </div>
                  <View direction="row" gap={1} wrap>
                    {items.slice(0, 30).map((selector) => (
                      <Badge
                        attributes={{ title: `shared by ${selector.degree}` }}
                        color={selector.degree > 1 ? "primary" : "neutral"}
                        key={selector.value}
                        variant="faded"
                      >
                        <FaviconThumb kind={kind} value={selector.value} />
                        {selector.value}
                        {selector.degree > 1 ? ` - ${selector.degree}` : ""}
                      </Badge>
                    ))}
                    {items.length > 30 ? (
                      <Text color="neutral-faded" variant="body-2">
                        +{items.length - 30} more
                      </Text>
                    ) : null}
                  </View>
                </div>
              ))
            )}
          </section>

          <section className="panel section-stack">
            <div className="panel-header">
              <div>
                <h2>Gathered intel</h2>
                <p className="section-copy">
                  {intel?.timestamp ? `From the latest scan (${formatDate(intel.timestamp)}).` : "From the latest scan."}
                </p>
              </div>
            </div>

            {(profile.ips || []).length > 0 ? (
              <div className="section-stack tight">
                <h4>IPs ({profile.ips.length})</h4>
                {profile.ips.map((entry) => {
                  const badge = ipNetworkBadge(entry.network);
                  const context = [entry.asn_desc, entry.network_name, entry.proxy_family, entry.country]
                    .filter(Boolean)
                    .join(" | ");
                  return (
                    <DefRow key={entry.ip} label={entry.ip}>
                      <View align="center" direction="row" gap={1} wrap>
                        {badge ? (
                          <Badge color={badge.color} variant="faded">
                            {badge.label}
                          </Badge>
                        ) : null}
                        {entry.degree > 1 ? (
                          <Badge attributes={{ title: "Other domains on this IP" }} color="neutral" variant="faded">
                            {entry.degree} domains
                          </Badge>
                        ) : null}
                      </View>
                      {context ? (
                        <Text color="neutral-faded" variant="caption-1">
                          {context}
                        </Text>
                      ) : null}
                    </DefRow>
                  );
                })}
              </div>
            ) : null}

            {dnsEntries.length > 0 ? (
              <DetailGroup title="DNS" entries={dnsEntries} />
            ) : null}
            {whoisEntries.length > 0 ? (
              <DetailGroup title="WHOIS" entries={whoisEntries.map(([key, item]) => [formatLabel(key), item])} />
            ) : null}

            {(intel?.tls_certs || []).length > 0 ? (
              <div className="section-stack tight">
                <h4>TLS certificates</h4>
                {intel.tls_certs.map((cert, index) => (
                  <DefRow key={`${cert.sha256}-${index}`} label={cert.cn || cert.ip || `cert ${index + 1}`}>
                    {[cert.issuer, cert.sha256 ? `sha256 ${String(cert.sha256).slice(0, 16)}...` : null, (cert.sans || []).join(", ")]
                      .filter(Boolean)
                      .join(" | ")}
                  </DefRow>
                ))}
              </div>
            ) : null}

            {trackingEntries.length > 0 ? (
              <DetailGroup title="Tracking and analytics" entries={trackingEntries.map(([key, item]) => [formatLabel(key), item])} />
            ) : null}

            {siteVerificationEntries.length > 0 || socialHandleEntries.length > 0 || socialLinkEntries.length > 0 ? (
              <div className="section-stack tight">
                <h4>Social and verification</h4>
                {siteVerificationEntries.map(([provider, codes]) => (
                  <DefRow key={`verify-${provider}`} label={`${formatLabel(provider)} verification`}>
                    {asText(codes)}
                  </DefRow>
                ))}
                {socialHandleEntries.map(([platform, handles]) => (
                  <DefRow key={`handle-${platform}`} label={formatLabel(platform)}>
                    {asText(handles)}
                  </DefRow>
                ))}
                {socialLinkEntries.map(([platform, urls]) => (
                  <DefRow key={`link-${platform}`} label={`${formatLabel(platform)} link`}>
                    {asText(urls)}
                  </DefRow>
                ))}
              </div>
            ) : null}

            {/* Wallet addresses and phone numbers are deliberately inert text --
                no block-explorer or tel: links, since an outbound request would
                disclose the analyst's interest in this target to a third party. */}
            {phoneNumbers.length > 0 || cryptoWalletEntries.length > 0 ? (
              <div className="section-stack tight">
                <h4>Contact and wallets</h4>
                {phoneNumbers.length > 0 ? <DefRow label="Phone numbers">{asText(phoneNumbers)}</DefRow> : null}
                {cryptoWalletEntries.map(([chain, addresses]) => (
                  <DefRow key={`wallet-${chain}`} label={`${formatLabel(chain)} wallet`}>
                    <View direction="row" gap={1} wrap>
                      {addresses.map((address) => (
                        <Badge attributes={{ title: address }} color="neutral" key={address} variant="faded">
                          {truncateAddress(address)}
                        </Badge>
                      ))}
                    </View>
                  </DefRow>
                ))}
              </div>
            ) : null}

            {!intel ? <EmptyState message="No raw scan stored for this channel yet." /> : null}
          </section>

          <section className="panel section-stack">
            <div className="panel-header">
              <div>
                <h2>Hosts</h2>
                <p className="section-copy">
                  {otherHosts.length === 0
                    ? "No subdomains discovered for this channel yet."
                    : `${otherHosts.length} subdomain${otherHosts.length === 1 ? "" : "s"} discovered.`}
                </p>
              </div>
            </div>
            {otherHosts.length === 0 ? (
              <EmptyState message="Nothing beyond the apex domain on record." />
            ) : (
              <div className="linkage-list">
                {otherHosts.slice(0, 60).map((host) => (
                  <div className="def-row" key={host.value}>
                    <span className="def-label">
                      <Link className="text-link" to={`/domain/${encodeURIComponent(host.value)}`}>
                        {host.value}
                      </Link>
                    </span>
                    <span className="def-value">
                      <View align="center" direction="row" gap={1} wrap>
                        <Badge color="primary" variant="faded">
                          Found subdomain
                        </Badge>
                        {(host.ips || []).length > 0 ? (
                          host.ips.map((ip) => (
                            <Badge color="neutral" key={ip} variant="faded">
                              {ip}
                            </Badge>
                          ))
                        ) : (
                          <Text color="neutral-faded">no resolved IP on record</Text>
                        )}
                      </View>
                      {host.discovery_kind ? (
                        <Text color="neutral-faded" variant="caption-1">
                          via {formatLabel(host.discovery_kind)}
                          {host.discovered_from ? ` from ${host.discovered_from}` : ""}
                        </Text>
                      ) : null}
                    </span>
                  </div>
                ))}
                {otherHosts.length > 60 ? (
                  <Badge color="neutral">+{otherHosts.length - 60} more</Badge>
                ) : null}
              </div>
            )}
          </section>
        </>
      ) : null}
    </AppShell>
  );
}

// A channel's precomputed multi-hop neighborhood (db.intel_db.graph_paths) --
// domains reachable only through an intermediary, not shared directly.
// Always an instant indexed read (see /api/graph/related/{value}), never a
// traversal triggered by opening this page.
function RelatedThroughSection({ value, directTargets }) {
  const relatedRequest = useApi(`/api/graph/related/${encodeURIComponent(value)}`);
  const related = useMemo(
    () => normalizeRelatedThrough(relatedRequest.data).filter((entry) => entry.hops > 1 && !directTargets.has(entry.target)),
    [relatedRequest.data, directTargets],
  );
  const [expandedTarget, setExpandedTarget] = useState(null);

  if (relatedRequest.loading && !relatedRequest.data) {
    return null;
  }
  if (related.length === 0) {
    return null;
  }

  return (
    <section className="panel section-stack">
      <div className="panel-header">
        <div>
          <h2>Related through other channels</h2>
          <p className="section-copy">
            No direct evidence with this channel, but reachable through an intermediary — precomputed, not a guess.
          </p>
        </div>
      </div>
      <View gap={3}>
        {/* The toggle is a header button rather than an onClick on the Card.
            Reshaped turns a Card with onClick into a <button>, and the
            expanded body renders PathChain — which is itself made of clickable
            ConnectionCards (more buttons) and lists. Nesting those inside a
            button is invalid, and the inner clicks bubbled out to collapse the
            chain the user had just opened. */}
        {related.slice(0, 20).map((entry) => (
          <Card key={entry.target} padding={4}>
            <button
              aria-expanded={expandedTarget === entry.target}
              className="disclosure-button"
              onClick={() => setExpandedTarget((current) => (current === entry.target ? null : entry.target))}
              type="button"
            >
              <View align="center" direction="row" justify="space-between">
                <View gap={1}>
                  <Text weight="semibold">
                    {value} ↔ {entry.target}
                  </Text>
                  <Text color="neutral-faded" variant="body-2">
                    {entry.hops} hop{entry.hops === 1 ? "" : "s"} away
                  </Text>
                </View>
                <Text attributes={{ "aria-hidden": true }} color="neutral-faded">
                  {expandedTarget === entry.target ? "▴" : "▾"}
                </Text>
              </View>
            </button>
            {expandedTarget === entry.target ? (
              <View attributes={{ style: { marginTop: 16 } }}>
                <PathChain chain={entry.chain} />
              </View>
            ) : null}
          </Card>
        ))}
      </View>
    </section>
  );
}

// Precomputed lookup (db.intel_db.path_between / graph_paths) for a specific
// second channel, rather than browsing everything related -- an indexed
// read, not a live search-triggered traversal.
function FindPathSection({ value }) {
  const [input, setInput] = useState("");
  const [target, setTarget] = useState(null);
  const pathRequest = useApi(
    target ? `/api/graph/path?a=${encodeURIComponent(value)}&b=${encodeURIComponent(target)}` : null,
  );
  const path = useMemo(() => normalizeGraphPath(pathRequest.data), [pathRequest.data]);

  const submit = (event) => {
    event.preventDefault();
    const trimmed = input.trim();
    if (trimmed) {
      setTarget(trimmed);
    }
  };

  return (
    <section className="panel section-stack">
      <div className="panel-header">
        <div>
          <h2>Find a path to another channel</h2>
          <p className="section-copy">See how this channel connects to a specific one, hop by hop.</p>
        </div>
      </div>
      <View as="form" attributes={{ onSubmit: submit }} direction="row" gap={2}>
        <View grow>
          <TextField
            inputAttributes={{ type: "search" }}
            name="find-path-target"
            onChange={({ value }) => setInput(value)}
            placeholder="Type a domain to check..."
            value={input}
          />
        </View>
        <Button disabled={!input.trim()} type="submit" variant="outline">
          Find path
        </Button>
      </View>
      {target && pathRequest.loading && !pathRequest.data ? <LoadingState message="Looking up the precomputed path..." /> : null}
      {/* Only a 404 — or a successful lookup that came back empty — means
          "these two are not connected". A 500 or a dropped connection is a
          failure to answer, and reporting it as an analytic negative tells the
          analyst something false. */}
      {target && pathRequest.error && pathRequest.status === 404 ? (
        <EmptyState message={`No precomputed path between ${value} and ${target} within the configured hop limit.`} />
      ) : null}
      {target && pathRequest.error && pathRequest.status !== 404 ? (
        <ErrorState message={`Could not look up the path: ${pathRequest.error}`} />
      ) : null}
      {target && !pathRequest.error && !pathRequest.loading && path.chain.length === 0 ? (
        <EmptyState message={`No precomputed path between ${value} and ${target} within the configured hop limit.`} />
      ) : null}
      {path.chain.length > 0 ? <PathChain chain={path.chain} /> : null}
    </section>
  );
}

function DetailGroup({ title, entries }) {
  return (
    <div className="section-stack tight">
      <h4>{title}</h4>
      {entries.map(([key, value]) => (
        <DefRow key={key} label={key}>
          {asText(value)}
        </DefRow>
      ))}
    </div>
  );
}

function DefRow({ label, children }) {
  return (
    <div className="def-row">
      <span className="def-label">{label}</span>
      <span className="def-value">{children}</span>
    </div>
  );
}

// Same head-truncation the TLS sha256 rows use; the full address stays
// available on the badge's title attribute for copying.
function truncateAddress(value) {
  const text = String(value ?? "");
  return text.length > 20 ? `${text.slice(0, 16)}...` : text;
}

function asText(value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  if (Array.isArray(value)) {
    return value.map(asText).join(", ");
  }
  if (typeof value === "object") {
    return value.value || value.exchange || value.name || JSON.stringify(value);
  }
  return String(value);
}
