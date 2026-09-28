/**
 * Types mirroring the WiFiSentinel engine's actual output.
 *
 * These are transcribed from `ai/models.py` (`Classification`, `Verdict`) and
 * `DetectionResult.to_dict()`. The engine publishes both vocabularies and the
 * distinction is meaningful, so both are carried:
 *
 * - `classification` is the numeric risk band (TRUSTED / LOW_RISK /
 *   UNVERIFIED / SUSPICIOUS / HIGH_RISK).
 * - `verdict` is the semantic reading (TRUSTED / LEGITIMATE / UNVERIFIED /
 *   SUSPICIOUS / POTENTIAL_FAKE).
 *
 * The dashboard bands on `verdict` and shows `classification` as detail,
 * because "POTENTIAL_FAKE" answers "is this ok or might it be fake?" - which
 * is the question a judge is actually asking - while the risk band alone does
 * not.
 *
 * `POTENTIAL_FAKE` means *may be impersonating*, never *proven malicious*.
 * Passive metadata cannot establish intent, and the engine is explicit about
 * this. The UI must not imply otherwise.
 */

/** Risk band, from `Classification` in `ai/models.py`. */
export type Classification =
  | "TRUSTED"
  | "LOW_RISK"
  | "UNVERIFIED"
  | "SUSPICIOUS"
  | "HIGH_RISK";

/** Semantic verdict, from `Verdict` in `ai/verdict.py`. */
export type Verdict =
  | "TRUSTED"
  | "LEGITIMATE"
  | "UNVERIFIED"
  | "SUSPICIOUS"
  | "POTENTIAL_FAKE";

/** Raw radio attributes of one access point, as the scanner observed them. */
export type Observed = {
  ssid: string | null;
  bssid: string;
  signal: number | null;
  channel: number | null;
  frequency: number | null;
  security: string;
  timestamp: string;
  signal_quality?: number | null;
  hidden?: boolean;
  mode?: string | null;
};

/** One indicator code with its human-readable message. */
export type Indicator = {
  code: string;
  message: string;
  /** What the code means in general, independent of what was seen here. */
  meaning: string;
  family: string;
  points: number;
};

/** One analysed access point - one BSSID, never merged by SSID. */
export type Network = {
  ssid: string;
  bssid: string;
  risk_score: number;
  classification: Classification;
  verdict: Verdict;
  evidence_level: string;
  reasons: string[];
  indicators: string[];
  mitigating: string[];
  indicator_details: Indicator[];
  score_breakdown: Record<string, number>;
  anomaly_score: number;
  anomaly_available: boolean;
  profile_match: boolean;
  impersonation_pattern: boolean;
  impersonating: string | null;
  families_deviating: string[];
  verdict_summary: string;
  verdict_guidance: string;
  accuracy_note: string;
  observed: Observed;
  timestamp: string;
};

/** The dashboard-ready payload `POST /scan` and `POST /analyze` return. */
export type ScanReport = {
  timestamp: string | null;
  interface?: string | null;
  source?: string;
  network_count: number;
  ssid_count: number;
  classification_counts: Record<Classification, number>;
  verdict_counts: Record<Verdict, number>;
  flagged_count: number;
  flagged: Network[];
  results: Network[];
  /** Access points grouped by SSID - one network, many access points. */
  networks: Record<string, Network[]>;
  thresholds: Record<string, string>;
  verdict_definitions: Record<string, string>;
};

/** `GET /profiles` - the SSIDs this site has vouched for. */
export type ProfileSummary = {
  count: number;
  ssids: string[];
  store_path: string;
};

/** `GET /verdicts` - the vocabulary, so the UI never hardcodes the wording. */
export type VerdictVocabulary = {
  verdicts: Record<string, string>;
  accuracy_note: string;
};

export type RiskFilter = "ALL" | Verdict;

/** Verdicts that mean "something a human should look at". */
export const ATTENTION_VERDICTS: Verdict[] = ["SUSPICIOUS", "POTENTIAL_FAKE"];

/** Verdicts that affirm legitimacy. */
export const BENIGN_VERDICTS: Verdict[] = ["TRUSTED", "LEGITIMATE"];

/**
 * The CSS tone to render a verdict with. Kept here so the mapping is defined
 * once rather than re-derived from a string in every component.
 */
export type Tone = "trusted" | "suspicious" | "high_risk" | "unknown";

export function toneFor(verdict: Verdict): Tone {
  switch (verdict) {
    case "TRUSTED":
    case "LEGITIMATE":
      return "trusted";
    case "SUSPICIOUS":
      return "suspicious";
    case "POTENTIAL_FAKE":
      return "high_risk";
    // UNVERIFIED is deliberately neutral, not green. A network we cannot
    // vouch for is not the same as one we have confirmed.
    default:
      return "unknown";
  }
}
