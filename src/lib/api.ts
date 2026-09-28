/**
 * Backend client.
 *
 * The endpoints here are the ones `backend/main.py` actually serves:
 *
 *   POST   /scan            real scan + analysis (the only source of data)
 *   GET    /profiles        SSIDs this site has vouched for
 *   GET    /verdicts        the verdict vocabulary
 *   POST   /trust           record an observed SSID as trusted (writes)
 *   DELETE /trust/{ssid}    remove a trusted profile (writes)
 *
 * Two behaviours here are deliberate and worth not "simplifying" away:
 *
 * 1. **Errors are thrown, not swallowed.** An earlier version caught every
 *    failure and returned `[]`, which is indistinguishable from "the scan
 *    genuinely found nothing". The dashboard then showed a healthy empty
 *    state while the backend was down - the worst possible failure for a
 *    security tool, since it reads as "all clear".
 * 2. **A scan is expensive and real.** It takes seconds and occupies the
 *    radio, so it is never called automatically on page load without the user
 *    asking.
 */

import type {
  Network,
  ProfileSummary,
  ScanReport,
  VerdictVocabulary,
} from "@/types/network";

const apiUrl = (process.env.NEXT_PUBLIC_API_URL ?? "").replace(/\/$/, "");

export function isBackendConfigured(): boolean {
  return apiUrl.length > 0;
}

/**
 * An API failure with the server's own diagnosis attached.
 *
 * The backend returns a structured `detail` on 503 (`NoWifiAdapterError` and
 * friends); surfacing that text is far more useful to an operator than
 * "request failed", so it is preserved here.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly detail: Record<string, unknown> | null;

  constructor(message: string, status: number, detail: Record<string, unknown> | null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = typeof detail?.error === "string" ? detail.error : "RequestFailed";
    this.detail = detail;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  if (!apiUrl) {
    throw new ApiError(
      "NEXT_PUBLIC_API_URL is not set, so no backend is configured.",
      0,
      null,
    );
  }

  let response: Response;
  try {
    response = await fetch(`${apiUrl}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...init?.headers },
      cache: "no-store",
    });
  } catch {
    // A network-level failure: server down, wrong port, CORS preflight
    // rejected. There is no status to report, so say what actually happened
    // rather than echoing an opaque platform error at the user.
    throw new ApiError(
      `Could not reach the backend at ${apiUrl}. Is it running, and is NEXT_PUBLIC_API_URL correct?`,
      0,
      null,
    );
  }

  if (response.status === 204) return undefined as T;

  let body: unknown = null;
  const text = await response.text();
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      // A non-JSON error body (a proxy's HTML 502, say). Keep it as text so
      // the message is still actionable.
      if (!response.ok) throw new ApiError(text.slice(0, 300), response.status, null);
    }
  }

  if (!response.ok) {
    const detail =
      body && typeof body === "object" && "detail" in body
        ? ((body as { detail: unknown }).detail as Record<string, unknown>)
        : null;
    const message =
      (typeof detail?.message === "string" && detail.message) ||
      (typeof detail?.hint === "string" && detail.hint) ||
      `Backend request failed with status ${response.status}.`;
    throw new ApiError(message, response.status, detail);
  }

  return body as T;
}

/**
 * Perform a real scan and return the full report.
 *
 * The only way to obtain data: the backend is stateless and holds no history,
 * so a scan *is* the fetch. Returns the report so callers can use
 * `verdict_counts` and `flagged`, not just the flat result list.
 */
export async function runScan(settle = 20): Promise<ScanReport> {
  return request<ScanReport>(`/scan?settle=${settle}`, { method: "POST" });
}

/** Flat list from a report, worst first. */
export function networksFromReport(report: ScanReport): Network[] {
  return [...report.results].sort((a, b) => b.risk_score - a.risk_score);
}

export async function getVerdicts(): Promise<VerdictVocabulary> {
  return request<VerdictVocabulary>("/verdicts");
}

export async function getProfiles(): Promise<ProfileSummary> {
  return request<ProfileSummary>("/profiles");
}

/**
 * Record an SSID as operator-approved.
 *
 * The backend builds the profile from its own scan, so the request body
 * carries only the *intent* - which SSID, and an optional human label. It
 * cannot be used to hand-write a trusted BSSID, which is deliberate: that
 * would be a way to silence detection for any network.
 */
export async function trustNetwork(ssid: string, location?: string): Promise<void> {
  await request("/trust", {
    method: "POST",
    body: JSON.stringify({ ssid, settle: 20, ...(location ? { location } : {}) }),
  });
}

export async function untrustNetwork(ssid: string): Promise<void> {
  await request(`/trust/${encodeURIComponent(ssid)}`, { method: "DELETE" });
}
