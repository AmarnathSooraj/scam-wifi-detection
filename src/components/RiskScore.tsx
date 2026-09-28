import { toneFor, type Verdict } from "@/types/network";

/**
 * Risk meter.
 *
 * The band boundaries match the engine's own thresholds in `ai/risk_engine.py`
 * (`trusted_max=24`, `low_risk_max=49`, `suspicious_max=74`) so the colour the
 * user sees always agrees with the band the server assigned. The previous
 * version used its own 30/60/60 cut-offs, which put a score of 28 in one
 * bucket and a 26 in another relative to the server's classification.
 */
const BANDS: { max: number; label: string; tone: ReturnType<typeof toneFor> }[] = [
  { max: 24, label: "TRUSTED BAND", tone: "trusted" },
  { max: 49, label: "LOW RISK", tone: "trusted" },
  { max: 74, label: "SUSPICIOUS", tone: "suspicious" },
  { max: 100, label: "HIGH RISK", tone: "high_risk" },
];

export function RiskScore({ score, verdict }: { score: number; verdict: Verdict }) {
  const value = Math.max(0, Math.min(100, Math.round(score)));
  const band = BANDS.find((b) => value <= b.max) ?? BANDS[BANDS.length - 1];
  // The verdict, not the score, decides colour: a score of 30 on an AP the
  // engine could not vouch for is not the same claim as a verified one.
  const tone = toneFor(verdict);
  const color =
    tone === "trusted"
      ? "var(--green)"
      : tone === "suspicious"
        ? "var(--amber)"
        : tone === "high_risk"
          ? "var(--red)"
          : "var(--slate, #7c8b94)";

  return (
    <div className="risk-score">
      <div className="risk-score-head">
        <span>Risk score</span>
        <span className="risk-value" style={{ color }}>
          {value}
          <small> / 100</small>
        </span>
      </div>
      <div
        className="risk-track"
        role="meter"
        aria-label="Risk score"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={value}
        aria-valuetext={`${value} of 100, ${band.label}`}
      >
        <span style={{ width: `${value}%`, backgroundColor: color }} />
      </div>
      <div className="risk-score-foot">
        <span>0</span>
        <strong style={{ color }}>{band.label}</strong>
        <span>100</span>
      </div>
    </div>
  );
}
