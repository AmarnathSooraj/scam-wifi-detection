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
  HelpCircle,
  LayoutDashboard,
  Loader2,
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
import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { RiskBadge } from "@/components/RiskBadge";
import { RiskScore } from "@/components/RiskScore";
import {
  ApiError,
  getProfiles,
  getVerdicts,
  isBackendConfigured,
  networksFromReport,
  runScan,
  trustNetwork,
  untrustNetwork,
} from "@/lib/api";
import {
  ATTENTION_VERDICTS,
  BENIGN_VERDICTS,
  toneFor,
  type Network,
  type RiskFilter,
  type ScanReport,
  type Verdict,
  type VerdictVocabulary,
} from "@/types/network";

const filters: { label: string; value: RiskFilter }[] = [
  { label: "All access points", value: "ALL" },
  { label: "Vouched for", value: "TRUSTED" },
  { label: "Consistent", value: "LEGITIMATE" },
  { label: "Suspicious", value: "SUSPICIOUS" },
  { label: "Possible impersonation", value: "POTENTIAL_FAKE" },
  { label: "Unverified", value: "UNVERIFIED" },
];

/**
 * Seconds the radio is given to settle a scan. The scanner treats anything
 * under ~7s as stale or half-populated (see `scanner/config.py`), so this sits
 * above that floor while still leaving room in a 15s cadence.
 */
const SCAN_SETTLE_SECONDS = 12;

/**
 * Auto-scan cadence, measured from the *end* of the previous scan.
 *
 * Measured from the end rather than the start on purpose. A scan already takes
 * 7-20s of real radio time, so a 15s timer started at the beginning of a scan
 * would fire while the previous one was still running. Overlapping scans keep
 * the adapter permanently busy, which degrades normal connectivity on the
 * machine and produces partial readings. A 15s gap after completion is both
 * achievable and leaves the radio idle in between.
 */
const AUTO_SCAN_SECONDS = 15;

const AUTO_SCAN_KEY = "wifisentinel:auto-scan";
const AUTO_SCAN_EVENT = "wifisentinel:auto-scan-change";

/**
 * The operator's auto-scan preference, read from localStorage.
 *
 * Uses `useSyncExternalStore` rather than reading in a `useEffect`, because a
 * `useState` initialiser cannot touch `localStorage` during SSR without
 * desynchronising the client's first render from the server's HTML. This hook
 * is built for exactly that: `getServerSnapshot` supplies the default, the
 * client supplies the stored value, and React hydrates without a mismatch.
 */
function useAutoScanPreference(): [boolean, () => void] {
  const subscribe = useCallback((onChange: () => void) => {
    window.addEventListener(AUTO_SCAN_EVENT, onChange);
    // `storage` fires for changes made in *other* tabs, which is how a second
    // dashboard window stays consistent with this one.
    window.addEventListener("storage", onChange);
    return () => {
      window.removeEventListener(AUTO_SCAN_EVENT, onChange);
      window.removeEventListener("storage", onChange);
    };
  }, []);

  const getSnapshot = useCallback(() => {
    try {
      return window.localStorage.getItem(AUTO_SCAN_KEY) !== "off";
    } catch {
      return true;
    }
  }, []);

  // The server has no localStorage, so it renders the default.
  const getServerSnapshot = useCallback(() => true, []);

  const enabled = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  const toggle = useCallback(() => {
    try {
      window.localStorage.setItem(AUTO_SCAN_KEY, enabled ? "off" : "on");
    } catch {
      // Private browsing can block storage. The session still works; the
      // preference simply will not survive a reload.
    }
    window.dispatchEvent(new Event(AUTO_SCAN_EVENT));
  }, [enabled]);

  return [enabled, toggle];
}

/**
 * Relative age of the last reading.
 *
 * On a 15-second auto-refresh an absolute "14:32" is close to useless - it
 * tells you when it happened today, not whether what you are reading is
 * current. "14s ago" answers the question actually being asked. The absolute
 * time is still available as a tooltip for cross-referencing a log.
 */
function formatRelative(date: Date | null, now: number): string {
  if (!date) return "never";
  const seconds = Math.max(0, Math.floor((now - date.getTime()) / 1000));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

/** Absolute time, for the `title` tooltip. */
function formatAbsolute(date: Date | null): string {
  return date ? date.toLocaleString() : "No scan has completed yet";
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
        <span className="stat-icon">
          <Icon size={17} strokeWidth={1.8} />
        </span>
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
  hasScanned,
  refreshing,
}: {
  networks: Network[];
  selectedBssid: string;
  onSelect: (network: Network) => void;
  /** Distinguishes "filtered to nothing" from "never scanned". */
  hasScanned: boolean;
  /** A scan is in flight; existing rows are stale until it lands. */
  refreshing: boolean;
}) {
  return (
    <div className={`table-scroll ${refreshing ? "is-refreshing" : ""}`}>
      <table className="network-table">
        <thead>
          <tr>
            <th>Access point</th>
            <th>Signal</th>
            <th>Channel</th>
            <th>Security</th>
            <th>Risk</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {/* First scan, nothing to show yet. A skeleton is honest here: the
              radio is genuinely working and rows are genuinely coming. */}
          {!hasScanned &&
            [0, 1, 2, 3].map((row) => (
              <tr key={`skeleton-${row}`} className="skeleton-row" aria-hidden="true">
                <td>
                  <span className="skeleton skeleton-name" />
                  <span className="skeleton skeleton-sub" />
                </td>
                <td><span className="skeleton skeleton-cell" /></td>
                <td><span className="skeleton skeleton-cell" /></td>
                <td><span className="skeleton skeleton-cell" /></td>
                <td><span className="skeleton skeleton-cell" /></td>
                <td><span className="skeleton skeleton-cell" /></td>
              </tr>
            ))}
          {hasScanned &&
            networks.map((network) => (
            <tr
              key={network.bssid}
              className={selectedBssid === network.bssid ? "selected-row" : ""}
              onClick={() => onSelect(network)}
              tabIndex={0}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onSelect(network);
                }
              }}
              aria-label={`${network.ssid || "hidden network"}, ${network.verdict.replace(/_/g, " ").toLowerCase()}, risk ${network.risk_score} of 100`}
            >
              <td>
                <div className="network-name">
                  <Wifi size={15} />
                  <span>{network.ssid || <em className="hidden-ssid">hidden SSID</em>}</span>
                </div>
                <span className="network-bssid">{network.bssid}</span>
              </td>
              <td>
                <span className="signal-cell">
                  <Signal size={14} />
                  {network.observed.signal ?? "—"} dBm
                </span>
              </td>
              <td>
                <span className="channel-cell">
                  {network.observed.channel ?? "—"}
                  <small> ch</small>
                </span>
              </td>
              <td>
                <span
                  className={`security-cell ${network.observed.security === "OPEN" ? "security-open" : ""}`}
                >
                  <LockKeyhole size={13} />
                  {network.observed.security}
                </span>
              </td>
              <td>
                <strong className={`table-risk risk-text-${toneFor(network.verdict)}`}>
                  {network.risk_score}
                  <small>/100</small>
                </strong>
              </td>
              <td>
                <RiskBadge verdict={network.verdict} />
              </td>
            </tr>
            ))}
          {hasScanned && networks.length === 0 && (
            <tr>
              <td colSpan={6} className="empty-state">
                <div className="empty-state-content">
                  <span className="empty-state-icon">
                    <Radio size={19} />
                  </span>
                  <strong>No access points to show</strong>
                  <span>No access point matched the current filter and search.</span>
                </div>
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

export default function Dashboard() {
  const [report, setReport] = useState<ScanReport | null>(null);
  const [networks, setNetworks] = useState<Network[]>([]);
  const [selectedBssid, setSelectedBssid] = useState("");
  const [filter, setFilter] = useState<RiskFilter>("ALL");
  const [search, setSearch] = useState("");
  const [scanning, setScanning] = useState(false);
  const [lastScan, setLastScan] = useState<Date | null>(null);
  const [backendOnline, setBackendOnline] = useState(false);
  const [profileSsids, setProfileSsids] = useState<string[]>([]);
  const [vocabulary, setVocabulary] = useState<VerdictVocabulary | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [error, setError] = useState<string>("");
  const [notice, setNotice] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [autoScan, toggleAutoScan] = useAutoScanPreference();
  /**
   * Wall-clock time, refreshed once a second only while auto-scan is running.
   * The countdown is *derived* from it and `nextScanAt` rather than stored as
   * its own ticking counter, so no effect has to reset it synchronously.
   */
  const [tick, setTick] = useState(() => Date.now());
  const [nextScanAt, setNextScanAt] = useState<number | null>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const backendConfigured = isBackendConfigured();
  const hasScanned = report !== null;
  const autoScanActive = autoScan && backendOnline && hasScanned;
  const secondsToNext =
    autoScanActive && nextScanAt !== null
      ? Math.max(0, Math.ceil((nextScanAt - tick) / 1000))
      : null;

  /**
   * Guards against overlapping scans.
   *
   * A ref rather than the `scanning` state, because the auto-schedule and a
   * manual click can both reach the scanner within the same tick - at which
   * point `scanning` still holds the previous render's value and both would
   * run. Two concurrent scans of one radio is the failure mode worth
   * engineering against here.
   */
  const inFlight = useRef(false);

  // Reachability check on mount. Deliberately does NOT scan: a scan costs
  // seconds and occupies the radio, and the user asked for a dashboard, not
  // for the machine to start probing the air on page load.
  useEffect(() => {
    if (!backendConfigured) return;
    let active = true;
    Promise.all([getVerdicts(), getProfiles()])
      .then(([verdicts, profiles]) => {
        if (!active) return;
        setVocabulary(verdicts);
        setProfileSsids(profiles.ssids);
        setBackendOnline(true);
        setError("");
      })
      .catch((cause: unknown) => {
        if (!active) return;
        setBackendOnline(false);
        setError(
          cause instanceof ApiError
            ? cause.message
            : "Could not reach the backend. Check that it is running and that NEXT_PUBLIC_API_URL is correct.",
        );
      });
    return () => {
      active = false;
    };
  }, [backendConfigured]);

  useEffect(() => {
    function focusSearch(event: KeyboardEvent) {
      if (
        event.key === "/" &&
        !(event.target instanceof HTMLInputElement) &&
        !(event.target instanceof HTMLTextAreaElement)
      ) {
        event.preventDefault();
        searchInputRef.current?.focus();
      }
    }
    window.addEventListener("keydown", focusSearch);
    return () => window.removeEventListener("keydown", focusSearch);
  }, []);

  const selected = useMemo(
    () => networks.find((network) => network.bssid === selectedBssid) ?? networks[0],
    [networks, selectedBssid],
  );

  // The same-SSID comparison the dashboard is built around: one network name
  // spanning several BSSIDs is normal, but a *contradicting* fingerprint under
  // a trusted name is the impersonation pattern.
  const vouchedBssids = useMemo(
    () =>
      new Set(
        networks
          .filter((network) => network.profile_match || network.verdict === "TRUSTED")
          .map((network) => network.bssid),
      ),
    [networks],
  );

  const baselineProfile = useMemo(
    () => networks.find((network) => vouchedBssids.has(network.bssid)),
    [networks, vouchedBssids],
  );

  /**
   * Everything needing a human, worst first.
   *
   * The previous implementation took a single `find()`, so three flagged
   * access points were rendered as one. The stat tile said "3 need review" and
   * the page showed one - which reads as "handled" when it is not. A triage
   * tool has to show its whole queue.
   */
  const flaggedNetworks = useMemo(
    () =>
      networks
        .filter((network) => ATTENTION_VERDICTS.includes(network.verdict))
        .sort((a, b) => b.risk_score - a.risk_score),
    [networks],
  );

  /** The worst offender - the one the comparison view and banner describe. */
  const alertNetwork = flaggedNetworks[0];

  const alertBaseline = useMemo(() => {
    if (!alertNetwork) return undefined;
    return networks.find(
      (network) =>
        network.ssid === alertNetwork.ssid &&
        network.bssid !== alertNetwork.bssid &&
        vouchedBssids.has(network.bssid),
    );
  }, [networks, alertNetwork, vouchedBssids]);

  const expectedChannels = useMemo(() => {
    if (!baselineProfile) return "Not reported";
    const channels = [
      ...new Set(
        networks
          .filter((network) => network.ssid === baselineProfile.ssid && vouchedBssids.has(network.bssid))
          .map((network) => network.observed.channel)
          .filter((channel): channel is number => channel !== null),
      ),
    ];
    return channels.length ? channels.join(", ") : "Not reported";
  }, [networks, baselineProfile, vouchedBssids]);

  const counts = useMemo(
    () => ({
      total: networks.length,
      trusted: networks.filter((network) => BENIGN_VERDICTS.includes(network.verdict)).length,
      attention: networks.filter((network) => ATTENTION_VERDICTS.includes(network.verdict)).length,
      unverified: networks.filter((network) => network.verdict === "UNVERIFIED").length,
    }),
    [networks],
  );

  const visibleNetworks = useMemo(
    () =>
      networks.filter((network) => {
        const matchesFilter = filter === "ALL" || network.verdict === filter;
        const term = search.trim().toLowerCase();
        const matchesSearch =
          !term ||
          (network.ssid ?? "").toLowerCase().includes(term) ||
          network.bssid.toLowerCase().includes(term);
        return matchesFilter && matchesSearch;
      }),
    [networks, filter, search],
  );

  /**
   * Performs one scan. Shared by the manual button, the auto-schedule and the
   * post-trust refresh, so all three share one in-flight guard and one error
   * path.
   *
   * `silent` is set by the auto-schedule: a background poll that fails should
   * not blow away a good reading the user is looking at, it should just stop
   * the schedule and surface the reason.
   */
  const performScan = useCallback(async (silent = false) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setScanning(true);
    if (!silent) {
      setError("");
      setNotice("");
    }
    try {
      const result = await runScan(SCAN_SETTLE_SECONDS);
      const list = networksFromReport(result);
      setReport(result);
      setNetworks(list);
      setSelectedBssid((current) =>
        list.some((n) => n.bssid === current) ? current : list[0]?.bssid ?? "",
      );
      setBackendOnline(true);
      setLastScan(new Date());
      // Schedule the next automatic scan 15s from completion - not from the
      // start - so the radio is never asked to scan twice at once.
      setNextScanAt(Date.now() + AUTO_SCAN_SECONDS * 1000);
      if (!silent) {
        if (list.length === 0) {
          setNotice("The scan completed but heard no access points. That is a real result, not a failure.");
        } else if (result.flagged_count > 0) {
          setNotice(`${result.flagged_count} access point(s) need review.`);
        }
      }
    } catch (cause) {
      setBackendOnline(false);
      setError(
        cause instanceof ApiError
          ? cause.message
          : "The scan failed for an unknown reason. Check the backend logs.",
      );
    } finally {
      inFlight.current = false;
      setScanning(false);
    }
  }, []);

  /**
   * The very first scan.
   *
   * The schedule above deliberately waits for `hasScanned`, so something has
   * to start the loop. With auto-scan on (the default) that is this effect:
   * as soon as the backend proves reachable, scan once, which then hands over
   * to the 15-second schedule. Guarded on `!hasScanned` so it can never fire
   * a second time, and `inFlight` covers the case where the operator is
   * already clicking "Scan now".
   */
  useEffect(() => {
    if (!autoScan || !backendOnline || hasScanned) return;
    // Deferred by a tick so this does not synchronously cascade a render on
    // mount, and so the reachability check has settled before we touch the
    // radio. `inFlight` still guarantees a manual click cannot double-scan.
    const id = setTimeout(() => void performScan(true), 0);
    return () => clearTimeout(id);
  }, [autoScan, backendOnline, hasScanned, performScan]);

  /**
   * Auto-scan schedule.
   *
   * Fires `AUTO_SCAN_SECONDS` after the *previous scan finished*, never during
   * one. Three guards matter here:
   *
   * - `backendOnline` - polling a backend that is down just generates errors.
   * - `hasScanned` - the first scan is triggered explicitly, so a page load
   *   never races the reachability check.
   * - `document.hidden` - a background tab has no use for radio activity, and
   *   browsers throttle its timers anyway, which would make the cadence
   *   meaningless. Resuming triggers an immediate scan so the numbers on
   *   screen are never stale.
   */
  useEffect(() => {
    if (!autoScan || !backendOnline || !hasScanned) return;

    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;

    const tick = () => {
      if (cancelled) return;
      if (document.hidden) {
        // Wait for the tab to come back rather than firing blind.
        timer = setTimeout(tick, 1000);
        return;
      }
      performScan(true).finally(() => {
        if (!cancelled) timer = setTimeout(tick, AUTO_SCAN_SECONDS * 1000);
      });
    };

    timer = setTimeout(tick, AUTO_SCAN_SECONDS * 1000);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [autoScan, backendOnline, hasScanned, performScan]);

  useEffect(() => {
    // Ticks unconditionally, not only while auto-scanning: the "last reading"
    // label is relative, and a frozen "3s ago" would read as a stale dashboard.
    const id = setInterval(() => setTick(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  // Scan as soon as the tab is brought back into view, so a stale reading is
  // never what the user comes back to.
  useEffect(() => {
    if (!autoScan) return;
    const onVisible = () => {
      if (document.visibilityState === "visible" && backendOnline && hasScanned) {
        void performScan(true);
      }
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [autoScan, backendOnline, hasScanned, performScan]);

  // The manual button restarts the cadence rather than firing in isolation.
  const handleScan = useCallback(async () => {
    await performScan(false);
  }, [performScan]);

  // After any change to the trust store, re-read it rather than guessing what
  // the server wrote. The profile is a server-side concern; the client does
  // not model it.
  const refreshProfiles = useCallback(async () => {
    const profiles = await getProfiles();
    setProfileSsids(profiles.ssids);
    setBackendOnline(true);
  }, []);

  const handleTrust = useCallback(async () => {
    if (!selected?.ssid || busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await trustNetwork(selected.ssid);
      await refreshProfiles();
      setNotice(`${selected.ssid} recorded as trusted. Future observations of it will be scored against this profile.`);
      // Re-scan so the new profile is applied to the numbers on screen. The
      // verdict genuinely changes after approval, so showing the old value
      // would be misleading.
      await performScan(false);
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : "Could not update the trusted profile.");
    } finally {
      setBusy(false);
    }
  }, [selected, busy, refreshProfiles, performScan]);

  const handleUntrust = useCallback(async () => {
    if (!selected?.ssid || busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await untrustNetwork(selected.ssid);
      await refreshProfiles();
      setNotice(`${selected.ssid} removed from the trusted profile.`);
      await performScan(false);
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : "Could not remove the trusted profile.");
    } finally {
      setBusy(false);
    }
  }, [selected, busy, refreshProfiles, performScan]);

  function selectNetwork(network: Network) {
    setSelectedBssid(network.bssid);
    setDetailOpen(true);
  }

  const selectedSsidTrusted = selected?.ssid ? profileSsids.includes(selected.ssid) : false;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#top" aria-label="WiFiSentinel home">
          <span className="brand-mark">
            <Shield size={20} />
          </span>
          <span className="brand-name">
            wifi<span>sentinel</span>
            <small>WIRELESS SECURITY</small>
          </span>
        </a>
        <div className="side-label">Workspace</div>
        <nav className="side-nav" aria-label="Main navigation">
          <a className="nav-item active" href="#overview">
            <LayoutDashboard size={17} />
            Overview
            <span className="nav-active-mark" />
          </a>
          <a className="nav-item" href="#networks">
            <Radio size={17} />
            Access points
            <span className="nav-count">{counts.total}</span>
          </a>
          <a className="nav-item" href="#trusted">
            <ShieldCheck size={17} />
            Trusted profile
          </a>
        </nav>
        <div className="sidebar-bottom">
          <div className="sensor-card">
            <span className={`sensor-status ${backendOnline ? "" : "sensor-offline"}`}>
              <span className="live-dot" />
              {backendOnline ? "SENSOR CONNECTED" : "SENSOR OFFLINE"}
            </span>
            <div className="sensor-title">Wireless sensor</div>
            <div className="sensor-location">
              <MapPin size={13} />
              {report?.interface ?? "No adapter read yet"}
            </div>
            <div className="sensor-footer">
              <span>Last reading</span>
              <strong title={formatAbsolute(lastScan)}>{formatRelative(lastScan, tick)}</strong>
            </div>
          </div>
          <div className="sidebar-version">
            WIFI SENTINEL <span>v1.0</span>
          </div>
        </div>
      </aside>

      <main className="main-content" id="top">
        <header className="topbar">
          <div className="breadcrumb">
            <span>Workspace</span>
            <span className="crumb-slash">/</span>
            <strong>Overview</strong>
          </div>
          <div className="topbar-actions">
            <div className={`backend-status ${backendOnline ? "is-online" : "is-unavailable"}`}>
              <span className="live-dot" />
              {backendOnline
                ? "Backend connected"
                : backendConfigured
                  ? "Backend offline"
                  : "Backend not configured"}
            </div>
            <span className="topbar-divider" />
            <span
              className={`topbar-time ${scanning ? "is-scanning" : ""}`}
              title={formatAbsolute(lastScan)}
            >
              {scanning ? <Loader2 size={14} className="spin" /> : <Clock3 size={14} />}
              {scanning ? "Scanning…" : formatRelative(lastScan, tick)}
            </span>
            <button
              className={`auto-toggle ${autoScan ? "is-on" : ""}`}
              onClick={toggleAutoScan}
              role="switch"
              aria-checked={autoScan}
              title={
                autoScan
                  ? "Continuous monitoring on. Pauses while this tab is in the background."
                  : "Continuous monitoring off. Scans only when you ask."
              }
            >
              <span className="auto-track" aria-hidden="true">
                <span className="auto-thumb" />
              </span>
              <span className="auto-label">Auto</span>
              {autoScan && secondsToNext !== null && (
                <span className="auto-countdown">{secondsToNext}s</span>
              )}
            </button>
            <button
              className={`scan-button ${scanning ? "is-scanning" : ""}`}
              onClick={handleScan}
              disabled={scanning || !backendConfigured}
              title={backendConfigured ? "Perform a real passive scan now" : "Set NEXT_PUBLIC_API_URL to enable scanning"}
            >
              {scanning ? <Loader2 size={15} className="spin" /> : <RefreshCw size={15} />}
              {scanning ? "Scanning" : "Scan now"}
            </button>
          </div>
        </header>

        <div className="page-content" id="overview">
          <section className="page-heading">
            <div>
              <div className="eyebrow">
                <span className="eyebrow-line" />
                WIRELESS THREAT MONITOR
              </div>
              <h1>Security overview</h1>
              <p>Monitor nearby access points and investigate unusual network behavior.</p>
            </div>
            <div className="scan-meta">
              <span className={`scan-pulse ${backendOnline ? "" : "offline-pulse"}`} />
              <span>{backendOnline ? "Backend connected" : "Awaiting backend"}</span>
              <span className="scan-meta-divider" />
              Updated <strong>{formatRelative(lastScan, tick)}</strong>
            </div>
          </section>

          {error && (
            <div className="scan-message scan-error" role="alert">
              <AlertTriangle size={14} />
              <span>{error}</span>
            </div>
          )}
          {notice && !error && (
            <div className="scan-message" role="status">
              <CircleHelp size={14} />
              <span>{notice}</span>
            </div>
          )}
          {!backendConfigured && (
            <div className="scan-message" role="status">
              <CircleHelp size={14} />
              <span>
                No backend configured. Copy <code>.env.example</code> to <code>.env.local</code>, set{" "}
                <code>NEXT_PUBLIC_API_URL</code>, and restart the dev server.
              </span>
            </div>
          )}

          <section className="stats-grid" aria-label="Access point statistics">
            <StatCard label="Access points heard" value={counts.total} icon={Wifi} tone="blue" note="CURRENT SCAN" />
            <StatCard label="Recognised" value={counts.trusted} icon={ShieldCheck} tone="green" note="VOUCHED / CONSISTENT" />
            <StatCard label="Needs review" value={counts.attention} icon={AlertTriangle} tone="amber" note="FLAGGED" />
            <StatCard label="Unverified" value={counts.unverified} icon={HelpCircle} tone="slate" note="NO REFERENCE" />
          </section>

          {alertNetwork && (
            <section
              className={`alert-banner ${alertNetwork.verdict === "POTENTIAL_FAKE" ? "is-critical" : ""}`}
              aria-label="Access points needing review"
            >
              <div className="alert-symbol">
                {alertNetwork.verdict === "POTENTIAL_FAKE" ? <ShieldAlert size={18} /> : <AlertTriangle size={18} />}
              </div>
              <div className="alert-copy">
                <div className="alert-title">
                  {alertNetwork.verdict === "POTENTIAL_FAKE"
                    ? "Possible impersonation of a network this site vouches for"
                    : "Access point deviates from the expected profile"}
                </div>
                <p>
                  <strong>{alertNetwork.ssid || "hidden SSID"}</strong>
                  {alertBaseline
                    ? ` is broadcasting from ${alertNetwork.bssid} as well as from ${alertBaseline.bssid}, which the trusted profile vouches for. Two access points, one name, and a contradicting fingerprint.`
                    : ` scored ${alertNetwork.risk_score}/100 against the trusted profile.`}
                </p>
                {flaggedNetworks.length > 1 && (
                  <p className="alert-more">
                    <strong>{flaggedNetworks.length - 1}</strong> further access point
                    {flaggedNetworks.length - 1 === 1 ? "" : "s"} also flagged &mdash; see the Needs review list below.
                  </p>
                )}
              </div>
              <div className="alert-score">
                <span>RISK SCORE</span>
                <strong>
                  {alertNetwork.risk_score}
                  <small>/100</small>
                </strong>
              </div>
              <button
                className="alert-action"
                onClick={() => selectNetwork(alertNetwork)}
                aria-label={`Review ${alertNetwork.ssid || "hidden network"}`}
              >
                <ArrowDownRight size={18} />
              </button>
            </section>
          )}

          {alertNetwork && alertBaseline && (
            <section className="comparison-section" aria-label="Same network name comparison">
              <div className="section-heading comparison-heading">
                <div>
                  <div className="section-kicker">IDENTITY CHECK</div>
                  <h2>Same name, different hardware</h2>
                </div>
                <span className="comparison-label">
                  <Fingerprint size={14} />
                  SSID: {alertNetwork.ssid}
                </span>
              </div>
              <div className="comparison-grid">
                <div className="comparison-node trusted-node">
                  <div className="node-heading">
                    <span className="node-icon">
                      <ShieldCheck size={16} />
                    </span>
                    <div>
                      <strong>Known access point</strong>
                      <small>Vouched for by the trusted profile</small>
                    </div>
                    <RiskBadge verdict={alertBaseline.verdict} />
                  </div>
                  <div className="node-data">
                    <span>BSSID</span>
                    <strong>{alertBaseline.bssid}</strong>
                  </div>
                  <div className="node-facts">
                    <span>
                      <LockKeyhole size={13} />
                      {alertBaseline.observed.security}
                    </span>
                    <span>
                      <Radio size={13} />
                      Channel {alertBaseline.observed.channel ?? "?"}
                    </span>
                    <span>
                      <Activity size={13} />
                      Risk {alertBaseline.risk_score}
                    </span>
                  </div>
                </div>
                <div className="comparison-connector">
                  <span>
                    <ArrowUpRight size={15} />
                  </span>
                  <small>
                    SSID
                    <br />
                    match
                  </small>
                </div>
                <button className="comparison-node suspicious-node" onClick={() => selectNetwork(alertNetwork)}>
                  <div className="node-heading">
                    <span className="node-icon">
                      <ShieldAlert size={16} />
                    </span>
                    <div>
                      <strong>Unrecognised access point</strong>
                      <small>Contradicts the trusted profile</small>
                    </div>
                    <RiskBadge verdict={alertNetwork.verdict} />
                  </div>
                  <div className="node-data">
                    <span>BSSID</span>
                    <strong>{alertNetwork.bssid}</strong>
                  </div>
                  <div className="node-facts">
                    <span>
                      <LockKeyhole size={13} />
                      {alertNetwork.observed.security}
                    </span>
                    <span>
                      <Radio size={13} />
                      Channel {alertNetwork.observed.channel ?? "?"}
                    </span>
                    <span>
                      <Activity size={13} />
                      Risk {alertNetwork.risk_score}
                    </span>
                  </div>
                </button>
              </div>
              <div className="comparison-note">
                <CircleHelp size={14} />
                <span>
                  Matching network names do not confirm device identity. Verify the BSSID and security profile.
                </span>
              </div>
            </section>
          )}

          {flaggedNetworks.length > 0 && (
            <section className="triage-section panel" aria-label="Access points needing review">
              <div className="triage-heading">
                <div>
                  <div className="section-kicker">TRIAGE QUEUE</div>
                  <h2>
                    Needs review <span className="count-pill">{flaggedNetworks.length}</span>
                  </h2>
                </div>
                <p className="triage-note">
                  Ranked by risk score. Evidence is passive observation, not proof of compromise.
                </p>
              </div>
              <ul className="triage-list">
                {flaggedNetworks.map((network, index) => {
                  const reasons = network.indicator_details.filter((i) => i.points > 0);
                  return (
                    <li key={network.bssid}>
                      <button
                        className={`triage-row ${selectedBssid === network.bssid ? "is-selected" : ""}`}
                        onClick={() => selectNetwork(network)}
                        aria-label={`Review ${network.ssid || "hidden network"}, risk ${network.risk_score}`}
                      >
                        <span className="triage-rank">{index + 1}</span>
                        <span className="triage-id">
                          <strong>{network.ssid || "hidden SSID"}</strong>
                          <small>{network.bssid}</small>
                        </span>
                        <span className="triage-reasons">
                          {reasons.length > 0 ? (
                            reasons.slice(0, 2).map((indicator) => (
                              <span key={indicator.code} className="triage-chip">
                                {indicator.code.replace(/_/g, " ").toLowerCase()}
                              </span>
                            ))
                          ) : (
                            <span className="triage-chip is-muted">deviation from profile</span>
                          )}
                          {reasons.length > 2 && (
                            <span className="triage-more">+{reasons.length - 2}</span>
                          )}
                        </span>
                        <span className="triage-score">
                          <strong className={`risk-text-${toneFor(network.verdict)}`}>{network.risk_score}</strong>
                          <small>/100</small>
                        </span>
                        <RiskBadge verdict={network.verdict} />
                      </button>
                    </li>
                  );
                })}
              </ul>
            </section>
          )}

          <section className="work-grid" id="networks">
            <div className="inventory-panel panel">
              <div className="panel-heading inventory-heading">
                <div>
                  <div className="section-kicker">WIRELESS ENVIRONMENT</div>
                  <h2>
                    Detected access points <span className="count-pill">{visibleNetworks.length}</span>
                  </h2>
                </div>
              </div>
              <div className="inventory-toolbar">
                <label className="search-box">
                  <Search size={16} />
                  <input
                    ref={searchInputRef}
                    aria-label="Search access points"
                    placeholder="Search SSID or BSSID..."
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                  />
                  {search && (
                    <button onClick={() => setSearch("")} aria-label="Clear search">
                      <X size={14} />
                    </button>
                  )}
                  <kbd>/</kbd>
                </label>
                <div className="filter-tabs" aria-label="Filter access points">
                  {filters.map((item) => (
                    <button
                      key={item.value}
                      className={filter === item.value ? "filter-tab active" : "filter-tab"}
                      onClick={() => setFilter(item.value)}
                    >
                      {item.label}
                      {item.value === "ALL" && <span>{counts.total}</span>}
                    </button>
                  ))}
                </div>
              </div>
              <NetworkTable
                networks={visibleNetworks}
                selectedBssid={selectedBssid}
                onSelect={selectNetwork}
                hasScanned={hasScanned}
                refreshing={scanning && hasScanned}
              />
              <div className="table-footer">
                <span>
                  <span className={`live-dot ${backendOnline ? "" : "offline-dot"}`} />
                  {scanning
                    ? "Scanning…"
                    : backendOnline
                      ? "Backend connected"
                      : "Waiting for backend"}
                </span>
                <span>One row per access point, not per network name</span>
              </div>
            </div>

            <aside className={`detail-panel panel ${detailOpen ? "detail-open" : ""}`} aria-label="Selected access point details">
              {selected ? (
                <>
                  <div className="detail-heading">
                    <div>
                      <div className="section-kicker">ACCESS POINT PROFILE</div>
                      <h2>Details</h2>
                    </div>
                    <button className="icon-button detail-close" onClick={() => setDetailOpen(false)} aria-label="Close details">
                      <X size={16} />
                    </button>
                  </div>
                  <div className="detail-network-head">
                    <span className={`detail-network-icon ${toneFor(selected.verdict)}`}>
                      <Wifi size={19} />
                    </span>
                    <div>
                      <strong>{selected.ssid || "hidden SSID"}</strong>
                      <span>{selected.bssid}</span>
                    </div>
                    <RiskBadge verdict={selected.verdict} />
                  </div>
                  <RiskScore score={selected.risk_score} verdict={selected.verdict} />

                  {selected.verdict_summary && (
                    <div className="baseline-callout">
                      <div className="baseline-icon">
                        <Fingerprint size={15} />
                      </div>
                      <div>
                        <strong>{selected.verdict_summary}</strong>
                        {selected.verdict_guidance && <span>{selected.verdict_guidance}</span>}
                      </div>
                    </div>
                  )}

                  <div className="detail-section">
                    <div className="detail-section-title">
                      <span>Observed attributes</span>
                      <span className="section-count">04</span>
                    </div>
                    <div className="attribute-grid">
                      <div>
                        <span>Signal strength</span>
                        <strong>
                          <Signal size={13} />
                          {selected.observed.signal ?? "—"} dBm
                        </strong>
                      </div>
                      <div>
                        <span>Channel</span>
                        <strong>
                          <Radio size={13} />
                          {selected.observed.channel ?? "—"}
                        </strong>
                      </div>
                      <div>
                        <span>Frequency</span>
                        <strong>
                          <Activity size={13} />
                          {selected.observed.frequency
                            ? `${(selected.observed.frequency / 1000).toFixed(3)} GHz`
                            : "—"}
                        </strong>
                      </div>
                      <div>
                        <span>Security</span>
                        <strong className={selected.observed.security === "OPEN" ? "open-value" : ""}>
                          <LockKeyhole size={13} />
                          {selected.observed.security}
                        </strong>
                      </div>
                    </div>
                  </div>

                  <div className="detail-section reasons-section">
                    <div className="detail-section-title">
                      <span>Indicators</span>
                      <span className="section-count">
                        {selected.indicator_details.length.toString().padStart(2, "0")}
                      </span>
                    </div>
                    {selected.indicator_details.length > 0 ? (
                      <ul className="reason-list">
                        {selected.indicator_details.map((indicator) => (
                          <li key={indicator.code}>
                            <span>
                              <AlertTriangle size={13} />
                            </span>
                            <div>
                              {indicator.message}
                              {indicator.points > 0 && <em className="reason-points">+{indicator.points} risk</em>}
                            </div>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <div className="no-indicators">
                        <Check size={14} />
                        No indicators reported for this access point.
                      </div>
                    )}
                    {selected.mitigating.length > 0 && (
                      <ul className="reason-list reason-list-mitigating">
                        {selected.mitigating.map((note) => (
                          <li key={note}>
                            <span>
                              <Check size={13} />
                            </span>
                            <div>{note}</div>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>

                  {Object.keys(selected.score_breakdown).length > 0 && (
                    <div className="detail-section">
                      <div className="detail-section-title">
                        <span>Score breakdown</span>
                      </div>
                      <ul className="breakdown-list">
                        {Object.entries(selected.score_breakdown).map(([code, points]) => (
                          <li key={code}>
                            <span>{code}</span>
                            <strong>+{points}</strong>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="detail-disclaimer">
                    <CircleHelp size={14} />
                    <span>
                      {selected.accuracy_note ||
                        vocabulary?.accuracy_note ||
                        "Risk scores indicate observed anomalies. They do not confirm malicious activity."}
                    </span>
                  </div>

                  <div className="trust-actions">
                    <button
                      className={`trust-button ${selectedSsidTrusted ? "already-trusted" : ""}`}
                      onClick={handleTrust}
                      disabled={!backendOnline || busy || selectedSsidTrusted}
                    >
                      {selectedSsidTrusted ? (
                        <>
                          <Check size={15} />
                          In trusted profile
                        </>
                      ) : busy ? (
                        <>
                          <Loader2 size={15} className="spin" />
                          Updating profile
                        </>
                      ) : (
                        <>
                          <ShieldCheck size={15} />
                          Trust this network
                        </>
                      )}
                    </button>
                    {selectedSsidTrusted && (
                      <button className="untrust-button" onClick={handleUntrust} disabled={busy}>
                        Remove from profile
                      </button>
                    )}
                  </div>
                  <p className="trust-hint">
                    Records the access points currently broadcasting this name, as seen in a real scan. It cannot
                    hand-write a trusted BSSID.
                  </p>
                </>
              ) : (
                <div className="empty-detail">
                  <Radio size={21} />
                  <strong>No access point selected</strong>
                  <span>Run a scan to load access point details.</span>
                </div>
              )}
            </aside>
          </section>

          <section className="trusted-section panel" id="trusted">
            <div className="trusted-section-heading">
              <div className="trusted-title-icon">
                <ShieldCheck size={17} />
              </div>
              <div>
                <div className="section-kicker">KNOWN BASELINE</div>
                <h2>Trusted network profile</h2>
              </div>
              <span className="profile-state">
                {profileSsids.length > 0 && <span className="live-dot" />}
                {profileSsids.length > 0 ? `${profileSsids.length} PROFILE(S)` : "NO PROFILE"}
              </span>
            </div>
            {profileSsids.length === 0 ? (
              <div className="trusted-empty">
                <p>
                  This site has not vouched for any network yet. Every access point is reported <code>UNVERIFIED</code>,
                  which is the honest answer rather than a failure &mdash; the engine has nothing to compare against
                  and says so instead of guessing.
                </p>
                <p>
                  Select an access point and choose <strong>Trust</strong> to record the hardware it is actually
                  broadcasting from, or use <code>python run_scan.py --trust &quot;&lt;SSID&gt;&quot;</code>.
                </p>
              </div>
            ) : (
              <>
                <div className="trusted-profile-grid">
                  <div className="profile-value">
                    <span>Networks vouched for</span>
                    <strong>{profileSsids.join(", ")}</strong>
                  </div>
                  <div className="profile-value">
                    <span>Access points in this scan</span>
                    <strong className="mono">{vouchedBssids.size}</strong>
                  </div>
                  <div className="profile-value">
                    <span>Baseline example</span>
                    <strong className="mono">{baselineProfile?.bssid ?? "None in this scan"}</strong>
                  </div>
                  <div className="profile-value">
                    <span>Expected channels</span>
                    <strong>{expectedChannels}</strong>
                  </div>
                </div>
                {vocabulary && (
                  <div className="verdict-legend">
                    {Object.entries(vocabulary.verdicts).map(([name, meaning]) => (
                      <div key={name} className="legend-item">
                        <RiskBadge verdict={name as Verdict} />
                        <span>{meaning}</span>
                      </div>
                    ))}
                  </div>
                )}
              </>
            )}
          </section>

          <footer className="page-footer">
            <span>
              <Shield size={13} />
              WiFiSentinel AI <span className="footer-separator">/</span> Passive wireless risk analysis
            </span>
            <span>
              <span className="footer-safe-dot" />
              Defensive monitoring only &mdash; nothing is transmitted or associated
            </span>
          </footer>
        </div>
      </main>
    </div>
  );
}
