import { useCallback, useMemo, useState } from "react";

import { formatDate, formatLabel, normalizeGraphLinks, useApi } from "../api.js";
import { EmptyState, ErrorState, LoadingState } from "../components/primitives.jsx";
import {
  ConnectionCard,
  FaviconThumb,
  ProvenanceBadge,
  TierBadge,
  ipNetworkBadge,
  sharedNodeLabel,
} from "../features/evidence.jsx";
import { rememberFocus } from "../features/focus.js";
import { Link, useParams } from "../router.jsx";
import AppShell from "../shell/AppShell.jsx";

export default function DomainPage() {
  const { value } = useParams();
  const profileRequest = useApi(`/api/domain/${encodeURIComponent(value)}`);
  const linksRequest = useApi(`/api/graph/links/${encodeURIComponent(value)}`);
  const profile = profileRequest.data;
  const links = useMemo(() => normalizeGraphLinks(linksRequest.data), [linksRequest.data]);
  const [expanded, setExpanded] = useState(null);
  const toggle = useCallback((key) => setExpanded((current) => (current === key ? null : key)), []);

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
              <span className="chip-row opencti-labels">
                {intel.opencti_labels.map((label) => (
                  <span className="chip evidence-chip" key={label} title="OpenCTI label">
                    {label}
                  </span>
                ))}
              </span>
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
                    onToggle={() => toggle(link.target)}
                    rightLabel={link.target}
                  />
                ))}
              </div>
            )}
          </section>

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
                  <div className="chip-row">
                    {items.slice(0, 30).map((selector) => (
                      <span
                        className={`chip ${selector.degree > 1 ? "evidence-chip" : ""}`}
                        key={selector.value}
                        title={`shared by ${selector.degree}`}
                      >
                        <FaviconThumb kind={kind} value={selector.value} />
                        {selector.value}
                        {selector.degree > 1 ? ` - ${selector.degree}` : ""}
                      </span>
                    ))}
                  </div>
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
                      <span className="chip-row">
                        {badge ? <span className={`status-badge compact ${badge.tone}`}>{badge.label}</span> : null}
                        {entry.degree > 1 ? (
                          <span className="chip" title="Other domains on this IP">
                            {entry.degree} domains
                          </span>
                        ) : null}
                      </span>
                      {context ? <span className="card-copy small-copy">{context}</span> : null}
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
                      <span className="chip-row">
                        <span className="status-badge compact info">Found subdomain</span>
                        {(host.ips || []).length > 0 ? (
                          host.ips.map((ip) => (
                            <span className="chip" key={ip}>
                              {ip}
                            </span>
                          ))
                        ) : (
                          <span className="muted">no resolved IP on record</span>
                        )}
                      </span>
                      {host.discovery_kind ? (
                        <span className="card-copy small-copy">
                          via {formatLabel(host.discovery_kind)}
                          {host.discovered_from ? ` from ${host.discovered_from}` : ""}
                        </span>
                      ) : null}
                    </span>
                  </div>
                ))}
                {otherHosts.length > 60 ? (
                  <span className="chip digest-more-chip">+{otherHosts.length - 60} more</span>
                ) : null}
              </div>
            )}
          </section>
        </>
      ) : null}
    </AppShell>
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
