import { toneFor, type Verdict } from "@/types/network";

/**
 * Verdict wording.
 *
 * `POTENTIAL_FAKE` is written as "possibly impersonating", never as an
 * accusation. Passive metadata cannot establish intent - the engine says so
 * itself in its accuracy note - and a badge that reads "fake" would overstate
 * what the evidence supports.
 */
const labels: Record<Verdict, string> = {
  TRUSTED: "Trusted",
  LEGITIMATE: "Consistent",
  UNVERIFIED: "Unverified",
  SUSPICIOUS: "Suspicious",
  POTENTIAL_FAKE: "Possibly impersonating",
};

export function RiskBadge({ verdict }: { verdict: Verdict }) {
  return (
    <span className={`risk-badge risk-${toneFor(verdict)}`}>
      <span className="badge-dot" />
      {labels[verdict]}
    </span>
  );
}
