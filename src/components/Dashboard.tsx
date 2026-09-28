"use client";

import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  Check,
  CircleHelp,
  Clock3,
  Fingerprint,
  LayoutDashboard,
  LockKeyhole,
  MapPin,
  Radio,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Signal,
  Wifi,
  X,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { RiskBadge } from "@/components/RiskBadge";
import { RiskScore } from "@/components/RiskScore";
import { getNetworks, getTrustedNetworks, isBackendConnected, isBackendConfigured, scanNetworks, trustNetwork } from "@/lib/api";
import type { Network, RiskFilter } from "@/types/network";

const filters: { label: string; value: RiskFilter }[] = [
  { label: "All networks", value: "ALL" },
  { label: "Trusted", value: "TRUSTED" },
  { label: "Suspicious", value: "SUSPICIOUS" },
  { label: "High risk", value: "HIGH_RISK" },
];

function formatTime(date: Date | null) {
  return date?.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) ?? "No scans yet";
}

function StatCard({
  label,
  value,
  icon: Icon,
  tone,
  note,
}: {
  label: string;
  value: number;
  icon: typeof Wifi;
  tone: string;
  note: string;
}) {
  return (
    <article className={`stat-card stat-${tone}`}>
      <div className="stat-top">
        <span className="stat-icon"><Icon size={17} strokeWidth={1.8} /></span>
        <span className="stat-note">{note}</span>
      </div>
      <div className="stat-value">{value.toString().padStart(2, "0")}</div>
      <div className="stat-label">{label}</div>
    </article>
  );
}

function NetworkTable({
  networks,
  selectedBssid,
  onSelect,
}: {
  networks: Network[];
  selectedBssid: string;
  onSelect: (network: Network) => void;
}) {
  return (
    <div className="table-scroll">
      <table className="network-table">
        <thead>
          <tr><th>Network</th><th>Signal</th><th>Channel</th><th>Security</th><th>Risk</th><th>Status</th></tr>
        </thead>
        <tbody>
          {networks.map((network) => (
            <tr
              key={network.bssid}
              className={selectedBssid === network.bssid ? "selected-row" : ""}
              onClick={() => onSelect(network)}
              tabIndex={0}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") onSelect(network);
              }}
              aria-label={`${network.ssid}, ${network.classification.replace("_", " ")}, risk ${network.risk_score} of 100`}
            >
              <td>
                <div className="network-name"><Wifi size={15} /><span>{network.ssid}</span></div>
                <span className="network-bssid">{network.bssid}</span>
              </td>
              <td><span className="signal-cell"><Signal size={14} />{network.signal} dBm</span></td>
              <td><span className="channel-cell">{network.channel}<small> ch</small></span></td>
              <td><span className={`security-cell ${network.security === "OPEN" ? "security-open" : ""}`}><LockKeyhole size={13} />{network.security}</span></td>
              <td><strong className={`table-risk risk-text-${network.classification.toLowerCase()}`}>{network.risk_score}<small>/100</small></strong></td>
              <td><RiskBadge classification={network.classification} /></td>
            </tr>
          ))}
          {networks.length === 0 && (
            <tr><td colSpan={6} className="empty-state"><div className="empty-state-content"><span className="empty-state-icon"><Radio size={19} /></span><strong>No scan results</strong><span>Connect the wireless security backend, then run a scan to populate this inventory.</span></div></td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

export default function Dashboard() {
  const [networks, setNetworks] = useState<Network[]>([]);
  const [selectedBssid, setSelectedBssid] = useState("");
  const [filter, setFilter] = useState<RiskFilter>("ALL");
  const [search, setSearch] = useState("");
  const [scanning, setScanning] = useState(false);
  const [lastScan, setLastScan] = useState<Date | null>(null);
  const [backendOnline, setBackendOnline] = useState(false);
  const [trustedBssids, setTrustedBssids] = useState<string[]>([]);
  const [detailOpen, setDetailOpen] = useState(false);
  const [scanMessage, setScanMessage] = useState("");
  const [trustMessage, setTrustMessage] = useState("");
  const [trusting, setTrusting] = useState(false);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const backendConfigured = isBackendConfigured();

  useEffect(() => {
    let active = true;
    Promise.all([getNetworks(), getTrustedNetworks()]).then(([result, trusted]) => {
      if (!active) return;
      setNetworks(result);
      setSelectedBssid(result[0]?.bssid ?? "");
      setTrustedBssids(trusted.map((network) => network.bssid));
      setBackendOnline(isBackendConnected());
    });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    function focusSearch(event: KeyboardEvent) {
      if (event.key === "/" && !(event.target instanceof HTMLInputElement) && !(event.target instanceof HTMLTextAreaElement)) {
        event.preventDefault();
        searchInputRef.current?.focus();
      }
    }
    window.addEventListener("keydown", focusSearch);
    return () => window.removeEventListener("keydown", focusSearch);
  }, []);

  const selected = networks.find((network) => network.bssid === selectedBssid) ?? networks[0];
  const trustedReference = networks.find((network) => network.ssid === selected?.ssid && (trustedBssids.includes(network.bssid) || network.classification === "TRUSTED"));
  const alertNetwork = networks.find((network) => network.classification === "HIGH_RISK") ?? networks.find((network) => network.risk_score >= 61);
  const alertBaseline = alertNetwork && networks.find((network) => network.ssid === alertNetwork.ssid && network.bssid !== alertNetwork.bssid && (trustedBssids.includes(network.bssid) || network.classification === "TRUSTED"));
  const baselineProfile = networks.find((network) => trustedBssids.includes(network.bssid)) ?? networks.find((network) => network.classification === "TRUSTED");
  const expectedChannels = baselineProfile ? [...new Set(networks.filter((network) => network.ssid === baselineProfile.ssid && network.classification === "TRUSTED").map((network) => network.channel))].join(", ") : "Not reported";
  const counts = useMemo(() => ({
    total: networks.length,
    trusted: networks.filter((network) => network.classification === "TRUSTED").length,
    suspicious: networks.filter((network) => network.classification === "SUSPICIOUS").length,
    highRisk: networks.filter((network) => network.classification === "HIGH_RISK").length,
  }), [networks]);
  const visibleNetworks = useMemo(() => networks.filter((network) => {
    const matchesFilter = filter === "ALL" || network.classification === filter;
    const term = search.trim().toLowerCase();
    const matchesSearch = !term || network.ssid.toLowerCase().includes(term) || network.bssid.toLowerCase().includes(term);
    return matchesFilter && matchesSearch;
  }), [networks, filter, search]);

  async function handleScan() {
    if (scanning) return;
    setScanning(true);
    setScanMessage("");
    const result = await scanNetworks();
    setNetworks(result);
    setSelectedBssid((current) => result.some((network) => network.bssid === current) ? current : result[0]?.bssid ?? "");
    setTrustedBssids(result.filter((network) => network.classification === "TRUSTED").map((network) => network.bssid));
    setBackendOnline(isBackendConnected());
    if (isBackendConnected()) {
      setLastScan(new Date());
    } else {
      setScanMessage(backendConfigured ? "Could not reach the backend. Check the API connection and try again." : "Set NEXT_PUBLIC_API_URL to connect a backend before scanning.");
    }
    setScanning(false);
  }

  async function handleTrust() {
    if (!selected) return;
    setTrusting(true);
    setTrustMessage("");
    try {
      const updated = await trustNetwork(selected);
      if (updated) {
        setNetworks((current) => current.map((network) => network.bssid === updated.bssid ? updated : network));
      } else {
        const refreshed = await getNetworks();
        setNetworks(refreshed);
      }
      const trusted = await getTrustedNetworks();
      setTrustedBssids(trusted.map((network) => network.bssid));
      setBackendOnline(isBackendConnected());
    } catch {
      setBackendOnline(false);
      setTrustMessage("Could not update the trusted profile. Check the backend connection.");
    } finally {
      setTrusting(false);
    }
  }

  function selectNetwork(network: Network) {
    setSelectedBssid(network.bssid);
    setDetailOpen(true);
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#top" aria-label="WiFiSentinel home">
          <span className="brand-mark"><Shield size={20} /></span>
          <span className="brand-name">wifi<span>sentinel</span><small>WIRELESS SECURITY</small></span>
        </a>
        <div className="side-label">Workspace</div>
        <nav className="side-nav" aria-label="Main navigation">
          <a className="nav-item active" href="#overview"><LayoutDashboard size={17} />Overview<span className="nav-active-mark" /></a>
          <a className="nav-item" href="#networks"><Radio size={17} />Networks<span className="nav-count">{counts.total}</span></a>
          <a className="nav-item" href="#trusted"><ShieldCheck size={17} />Trusted profile</a>
        </nav>
        <div className="sidebar-bottom">
          <div className="sensor-card">
            <span className={`sensor-status ${backendOnline ? "" : "sensor-offline"}`}><span className="live-dot" />{backendOnline ? "SENSOR CONNECTED" : "SENSOR OFFLINE"}</span>
            <div className="sensor-title">Wireless sensor</div>
            <div className="sensor-location"><MapPin size={13} />Backend sensor</div>
            <div className="sensor-footer"><span>Last scan</span><strong>{formatTime(lastScan)}</strong></div>
          </div>
          <a className="help-link" href="mailto:support@wifisentinel.local"><CircleHelp size={16} />Help &amp; support</a>
          <div className="sidebar-version">WIFI SENTINEL <span>v0.8.2</span></div>
        </div>
      </aside>

      <main className="main-content" id="top">
        <header className="topbar">
          <div className="breadcrumb"><span>Workspace</span><span className="crumb-slash">/</span><strong>Overview</strong></div>
          <div className="topbar-actions">
            <div className={`backend-status ${backendOnline ? "is-online" : "is-unavailable"}`}>
              <span className="live-dot" />{backendOnline ? "Backend connected" : backendConfigured ? "Backend offline" : "Backend not configured"}
            </div>
            <span className="topbar-divider" />
            <span className="topbar-time"><Clock3 size={14} />{formatTime(lastScan)}</span>
            <button className={`scan-button ${scanning ? "is-scanning" : ""}`} onClick={handleScan} disabled={scanning}>
              <RefreshCw size={15} className={scanning ? "spin" : ""} />{scanning ? "Scanning" : "Scan now"}
            </button>
          </div>
        </header>

        <div className="page-content" id="overview">
          <section className="page-heading">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" />WIRELESS THREAT MONITOR</div>
              <h1>Security overview</h1>
              <p>Monitor nearby access points and investigate unusual network behavior.</p>
            </div>
            <div className="scan-meta"><span className={`scan-pulse ${backendOnline ? "" : "offline-pulse"}`} /><span>{backendOnline ? "Backend connected" : "Awaiting backend"}</span><span className="scan-meta-divider" />Last scan <strong>{formatTime(lastScan)}</strong></div>
          </section>

          {scanMessage && <div className="scan-message" role="status"><CircleHelp size={14} />{scanMessage}</div>}

          <section className="stats-grid" aria-label="Network statistics">
            <StatCard label="Networks detected" value={counts.total} icon={Wifi} tone="blue" note="CURRENT SCAN" />
            <StatCard label="Trusted" value={counts.trusted} icon={ShieldCheck} tone="green" note="KNOWN PROFILES" />
            <StatCard label="Suspicious" value={counts.suspicious} icon={AlertTriangle} tone="amber" note="NEEDS REVIEW" />
            <StatCard label="High risk" value={counts.highRisk} icon={ShieldAlert} tone="red" note="PRIORITY ALERT" />
          </section>

          {alertNetwork && <section className="alert-banner" aria-label="Potentially suspicious network alert">
            <div className="alert-symbol"><AlertTriangle size={18} /></div>
            <div className="alert-copy">
              <div className="alert-title">{alertBaseline ? "Same SSID detected from an unrecognized access point" : "Potentially suspicious network detected"}</div>
              <p><strong>{alertNetwork.ssid}</strong>{alertBaseline ? " is broadcasting from a second BSSID with a different network profile." : ` has a risk score of ${alertNetwork.risk_score}/100 and should be reviewed.`}</p>
            </div>
            <div className="alert-score"><span>RISK SCORE</span><strong>{alertNetwork.risk_score}<small>/100</small></strong></div>
            <button className="alert-action" onClick={() => selectNetwork(alertNetwork)} aria-label="Review suspicious network"><ArrowDownRight size={18} /></button>
          </section>}

          {alertNetwork && alertBaseline && <section className="comparison-section" aria-label="Same SSID comparison">
            <div className="section-heading comparison-heading">
              <div><div className="section-kicker">IDENTITY CHECK</div><h2>Same SSID, different identity</h2></div>
              <span className="comparison-label"><Fingerprint size={14} />SSID: {alertNetwork.ssid}</span>
            </div>
            <div className="comparison-grid">
              <div className="comparison-node trusted-node">
                <div className="node-heading"><span className="node-icon"><ShieldCheck size={16} /></span><div><strong>Known access point</strong><small>Trusted network profile</small></div><RiskBadge classification={alertBaseline.classification} /></div>
                <div className="node-data"><span>BSSID</span><strong>{alertBaseline.bssid}</strong></div>
                <div className="node-facts"><span><LockKeyhole size={13} />{alertBaseline.security}</span><span><Radio size={13} />Channel {alertBaseline.channel}</span><span><Activity size={13} />Risk {alertBaseline.risk_score}</span></div>
              </div>
              <div className="comparison-connector"><span><ArrowUpRight size={15} /></span><small>SSID<br />match</small></div>
              <button className="comparison-node suspicious-node" onClick={() => selectNetwork(alertNetwork)}>
                <div className="node-heading"><span className="node-icon"><ShieldAlert size={16} /></span><div><strong>Unrecognized access point</strong><small>Potentially suspicious</small></div><RiskBadge classification={alertNetwork.classification} /></div>
                <div className="node-data"><span>BSSID</span><strong>{alertNetwork.bssid}</strong></div>
                <div className="node-facts"><span><LockKeyhole size={13} />{alertNetwork.security}</span><span><Radio size={13} />Channel {alertNetwork.channel}</span><span><Activity size={13} />Risk {alertNetwork.risk_score}</span></div>
              </button>
            </div>
            <div className="comparison-note"><CircleHelp size={14} /><span>Matching network names do not confirm device identity. Verify the BSSID and security profile.</span></div>
          </section>}

          <section className="work-grid" id="networks">
            <div className="inventory-panel panel">
              <div className="panel-heading inventory-heading">
                <div><div className="section-kicker">WIRELESS ENVIRONMENT</div><h2>Detected networks <span className="count-pill">{visibleNetworks.length}</span></h2></div>
              </div>
              <div className="inventory-toolbar">
                <label className="search-box"><Search size={16} /><input ref={searchInputRef} aria-label="Search networks" placeholder="Search SSID or BSSID..." value={search} onChange={(event) => setSearch(event.target.value)} />{search && <button onClick={() => setSearch("")} aria-label="Clear search"><X size={14} /></button>}<kbd>/</kbd></label>
                <div className="filter-tabs" aria-label="Filter networks">
                  {filters.map((item) => <button key={item.value} className={filter === item.value ? "filter-tab active" : "filter-tab"} onClick={() => setFilter(item.value)}>{item.label}{item.value === "ALL" && <span>{counts.total}</span>}</button>)}
                </div>
              </div>
              <NetworkTable networks={visibleNetworks} selectedBssid={selectedBssid} onSelect={selectNetwork} />
              <div className="table-footer"><span><span className={`live-dot ${backendOnline ? "" : "offline-dot"}`} />{backendOnline ? "Backend data connected" : "Waiting for backend"}</span><span>Data refreshes on scan</span></div>
            </div>

            <aside className={`detail-panel panel ${detailOpen ? "detail-open" : ""}`} aria-label="Selected network details">
              {selected ? <>
              <div className="detail-heading">
                <div><div className="section-kicker">NETWORK PROFILE</div><h2>Network details</h2></div>
                <button className="icon-button detail-close" onClick={() => setDetailOpen(false)} aria-label="Close network details"><X size={16} /></button>
              </div>
              <div className="detail-network-head">
                <span className={`detail-network-icon ${selected.classification.toLowerCase()}`}><Wifi size={19} /></span>
                <div><strong>{selected.ssid}</strong><span>{selected.bssid}</span></div>
                <RiskBadge classification={selected.classification} />
              </div>
              <RiskScore score={selected.risk_score} />

              {trustedReference && selected.bssid !== trustedReference.bssid && (
                <div className="baseline-callout"><div className="baseline-icon"><Fingerprint size={15} /></div><div><strong>Same SSID as trusted profile</strong><span>Compared against {trustedReference.bssid}</span></div></div>
              )}

              <div className="detail-section">
                <div className="detail-section-title"><span>Network attributes</span><span className="section-count">04</span></div>
                <div className="attribute-grid">
                  <div><span>Signal strength</span><strong><Signal size={13} />{selected.signal} dBm</strong></div>
                  <div><span>Channel</span><strong><Radio size={13} />{selected.channel}</strong></div>
                  <div><span>Frequency</span><strong><Activity size={13} />{(selected.frequency / 1000).toFixed(3)} GHz</strong></div>
                  <div><span>Security</span><strong className={selected.security === "OPEN" ? "open-value" : ""}><LockKeyhole size={13} />{selected.security}</strong></div>
                </div>
              </div>

              <div className="detail-section reasons-section">
                <div className="detail-section-title"><span>Potential indicators</span><span className="section-count">{selected.reasons.length.toString().padStart(2, "0")}</span></div>
                {selected.reasons.length > 0 ? (
                  <ul className="reason-list">{selected.reasons.map((reason) => <li key={reason}><span><AlertTriangle size={13} /></span>{reason}</li>)}</ul>
                ) : (
                  <div className="no-indicators"><Check size={14} />No indicators reported for this network.</div>
                )}
              </div>

              <div className="detail-disclaimer"><CircleHelp size={14} /><span>Risk scores indicate observed anomalies. They do not confirm malicious activity.</span></div>
              {trustMessage && <div className="trust-message" role="status">{trustMessage}</div>}
              <button className={`trust-button ${trustedBssids.includes(selected.bssid) ? "already-trusted" : ""}`} onClick={handleTrust} disabled={!backendOnline || trusting || trustedBssids.includes(selected.bssid)}>
                {trustedBssids.includes(selected.bssid) ? <><Check size={15} />In trusted profile</> : trusting ? <><RefreshCw size={15} className="spin" />Updating profile</> : !backendOnline ? <><ShieldCheck size={15} />Backend required to trust</> : <><ShieldCheck size={15} />Trust this network</>}
              </button>
              </> : <div className="empty-detail"><Radio size={21} /><strong>No network selected</strong><span>Connect the backend and run a scan to load network details.</span></div>}
            </aside>
          </section>

          <section className="trusted-section panel" id="trusted">
            <div className="trusted-section-heading">
              <div className="trusted-title-icon"><ShieldCheck size={17} /></div>
              <div><div className="section-kicker">KNOWN BASELINE</div><h2>Trusted network profile</h2></div>
              <span className="profile-state">{baselineProfile && <span className="live-dot" />}{baselineProfile ? "PROFILE ACTIVE" : "NO PROFILE"}</span>
            </div>
            <div className="trusted-profile-grid">
              <div className="profile-value"><span>SSID</span><strong>{baselineProfile?.ssid ?? "No profile"}</strong></div>
              <div className="profile-value"><span>Known BSSID</span><strong className="mono">{baselineProfile?.bssid ?? "Not reported"}</strong></div>
              <div className="profile-value"><span>Security</span><strong><LockKeyhole size={13} />{baselineProfile?.security ?? "Not reported"}</strong></div>
              <div className="profile-value"><span>Expected channels</span><strong>{expectedChannels}</strong></div>
              <div className="profile-value profile-trust"><span>Status</span><strong>{baselineProfile ? <><Check size={14} />Trusted</> : "No profile"}</strong></div>
            </div>
          </section>

          <footer className="page-footer"><span><Shield size={13} />WiFiSentinel AI <span className="footer-separator">/</span> AI-powered wireless security monitor</span><span><span className="footer-safe-dot" />Defensive monitoring only</span></footer>
        </div>
      </main>
    </div>
  );
}