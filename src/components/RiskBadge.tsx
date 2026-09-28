import type { Classification } from "@/types/network";

const labels: Record<Classification, string> = {
  TRUSTED: "Trusted",
  SUSPICIOUS: "Potentially suspicious",
  HIGH_RISK: "Potentially suspicious",
};

export function RiskBadge({ classification }: { classification: Classification }) {
  return (
    <span className={`risk-badge risk-${classification.toLowerCase()}`}>
      <span className="badge-dot" />
      {labels[classification]}
    </span>
  );
}