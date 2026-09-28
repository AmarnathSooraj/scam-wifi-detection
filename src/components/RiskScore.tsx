export function RiskScore({ score }: { score: number }) {
  const value = Math.max(0, Math.min(100, score));
  const tone = value <= 30 ? "trusted" : value <= 60 ? "suspicious" : "high_risk";
  const color = tone === "trusted" ? "var(--green)" : tone === "suspicious" ? "var(--amber)" : "var(--red)";
  const label = tone === "trusted" ? "LOW RISK" : tone === "suspicious" ? "ELEVATED" : "HIGH RISK";
  return (
    <div className="risk-score">
      <div className="risk-score-head">
        <span>Risk score</span>
        <span className="risk-value">{value}<small> / 100</small></span>
      </div>
      <div
        className="risk-track"
        role="meter"
        aria-label="Risk score"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={value}
      >
        <span style={{ width: `${value}%`, backgroundColor: color }} />
      </div>
      <div className="risk-score-foot">
        <span>0</span><strong style={{ color }}>{label}</strong><span>100</span>
      </div>
    </div>
  );
}