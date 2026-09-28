"""Risk scoring and classification.

Three inputs, one number:

    rule indicators + profile comparison + anomaly result  ->  risk score

The arithmetic is deliberately transparent. Judges ask "why 87?" and the
answer is a sum of named, individually documented weights - not a black box.
Everything here is a **heuristic triage aid**, not a probability of compromise
and not a security verdict.

Design rules:

* No single fact is sufficient. The highest single weight
  (:attr:`ScoringConfig.security_downgrade`) still leaves an AP well below
  ``HIGH_RISK`` on its own, so a lone channel change never condemns an AP.
* An unknown BSSID is cheap. At a new location *every* BSSID is unknown; if
  unknown cost a lot, every AP in every new airport would alarm.
* A profile that expresses no opinion contributes nothing. Absence of
  configuration is not evidence.
* A provisional (self-learned) profile can never produce ``TRUSTED``.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    AnomalyResult,
    Classification,
    ProfileComparison,
    RuleResult,
)

__all__ = [
    "ScoringConfig",
    "DEFAULT_CONFIG",
    "RiskBreakdown",
    "score_risk",
    "classify",
]


#: Minimum anomaly score that counts as a strong ML signal. sklearn's own
#: ``predict`` uses ``decision_function < 0``; the risk engine only pays out
#: well past that boundary so a marginal outlier cannot by itself push an AP
#: into ``SUSPICIOUS``.
STRONG_ANOMALY_SCORE = 0.70

#: Anomaly score above which the ML model is treated as a corroborating
#: signal even if it did not clear ``STRONG_ANOMALY_SCORE``.
WEAK_ANOMALY_SCORE = 0.55


@dataclass
class ScoringConfig:
    """Configurable weights and thresholds.

    Weights are chosen so that the brief's demo rogue AP (unknown BSSID + OPEN
    + 2.4 GHz channel on a 5 GHz WPA2 network) lands in the high 80s from rule
    evidence alone, rather than saturating at 100 and telling the reviewer
    nothing. A clean in-profile AP scores 0; a merely unknown but otherwise
    consistent AP scores in the low 20s.

    Two anti-double-counting choices are worth calling out, because three
    indicators can all fire from what is really one observation:

    * ``security_mismatch`` and ``security_downgrade`` describe the same fact.
      The downgrade is treated as a *qualifier*: it adds a small bonus on top
      of the mismatch rather than a second full weight, so "OPEN on a WPA2
      network" costs ~30, not ~50.
    * ``channel_mismatch``, ``frequency_mismatch`` and ``band_mismatch`` all
      follow from an AP sitting on the wrong part of the radio plan. Channel
      is the primary observation, so it carries the full weight and the other
      two contribute less.
    """

    # --- indicator weights -------------------------------------------------
    unknown_bssid: int = 20
    no_trusted_profile: int = 0
    provisional_profile: int = 0
    security_mismatch: int = 25
    #: Added on top of ``security_mismatch`` when the observed encryption is
    #: strictly weaker than the profile expects. Kept small on purpose - see
    #: the class docstring.
    security_downgrade: int = 5
    channel_mismatch: int = 10
    frequency_mismatch: int = 5
    band_mismatch: int = 5
    vendor_mismatch: int = 10
    #: Deliberately small. A BSSID is bytes in a beacon frame - an
    #: impersonator can put any vendor prefix in it - and a legitimate
    #: organisation can buy hardware from a new vendor at any time. It is
    #: corroborating colour, never a load-bearing claim. The
    #: multi-family corroboration rule in :mod:`ai.verdict` is what carries
    #: an impersonation verdict, not this number.
    oui_mismatch: int = 5
    profile_deviation: int = 5
    strong_anomaly: int = 20
    weak_anomaly: int = 8
    missing_fields: int = 0
    hidden_ssid: int = 0

    # --- anomaly gating ---------------------------------------------------
    strong_anomaly_score: float = STRONG_ANOMALY_SCORE
    weak_anomaly_score: float = WEAK_ANOMALY_SCORE
    #: An ML anomaly only counts when the engine has something to compare
    #: against, or when the deviation is far past the baseline. An
    #: unfamiliar-but-coherent environment should not be punished twice (once
    #: for being unknown, once for being "anomalous" relative to a baseline
    #: built for a different site).
    anomaly_requires_profile: bool = True

    # --- classification thresholds ----------------------------------------
    #: Inclusive upper bound of the TRUSTED band.
    trusted_max: int = 24
    #: Inclusive upper bound of the LOW_RISK band.
    low_risk_max: int = 49
    #: Inclusive upper bound of the SUSPICIOUS band. Above this is HIGH_RISK.
    suspicious_max: int = 74

    #: A provisional profile may reach at most this classification unless the
    #: score crosses ``suspicious_max``.
    provisional_ceiling: str = Classification.LOW_RISK

    def threshold(self, indicator: str) -> int:
        """Weight for a rule indicator code (0 for non-scoring indicators)."""
        return int(getattr(self, indicator.lower(), 0))

    def with_overrides(self, **kwargs: Any) -> "ScoringConfig":
        """Return a copy with specific weights/thresholds replaced."""
        return replace(self, **kwargs)


#: The configuration used when a caller does not supply one.
DEFAULT_CONFIG = ScoringConfig()


@dataclass
class RiskBreakdown:
    """The arithmetic behind a risk score, kept for explainability.

    ``contributions`` preserves indicator order so the dashboard can show
    "what added what".
    """

    total: int = 0
    contributions: List[Tuple[str, int]] = field(default_factory=list)
    anomaly_applied: bool = False
    anomaly_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "contributions": [{"indicator": name, "points": points} for name, points in self.contributions],
            "anomaly_applied": self.anomaly_applied,
            "anomaly_score": self.anomaly_score,
        }


def _anomaly_allowed(
    anomaly: AnomalyResult,
    cmp_: ProfileComparison,
    config: ScoringConfig,
) -> bool:
    """Whether the ML result may contribute to the score.

    Three gates, in order of strictness:

    1. **Profile match vetoes the model.** If a real (non-provisional) trusted
       profile vouches for this exact BSSID and every characteristic it checks
       agrees, that is authoritative evidence. The anomaly score must not be
       able to overturn it, because Isolation Forest's tail ranking is known
       to be coarse (a weak but genuine AP can score as high as a rogue one).
       This is what keeps a legitimate distant AP in the ``TRUSTED`` band.
    2. **Availability.** An unfitted or under-sized detector contributes
       nothing, rather than a fabricated number.
    3. **No-profile restraint.** Without a profile the only acceptable case is
       an observation far past even the usual threshold, because "unfamiliar
       environment" and "anomalous" overlap heavily and would otherwise be
       charged twice.
    """
    if not anomaly.available:
        return False
    if cmp_.profile_match:
        return False
    if not config.anomaly_requires_profile:
        return True
    if cmp_.has_profile:
        return True
    # No profile: only a far-outlying observation is worth acting on, because
    # "unfamiliar environment" and "anomalous" overlap heavily here.
    return anomaly.anomaly_score >= max(config.strong_anomaly_score, 0.85)


def score_risk(
    rules: RuleResult,
    comparison: ProfileComparison,
    anomaly: Optional[AnomalyResult] = None,
    config: Optional[ScoringConfig] = None,
) -> RiskBreakdown:
    """Combine the evidence into a 0-100 risk score.

    The sum is clamped to ``[0, 100]``: several deviations on a bad AP can
    exceed 100, and a score above 100 is not more informative than 100.
    """
    config = config or DEFAULT_CONFIG
    breakdown = RiskBreakdown()

    for indicator in rules.indicators:
        points = config.threshold(indicator)
        if points:
            breakdown.contributions.append((indicator, points))

    if anomaly is not None:
        breakdown.anomaly_score = anomaly.anomaly_score
        if _anomaly_allowed(anomaly, comparison, config):
            if anomaly.anomaly_score >= config.strong_anomaly_score:
                breakdown.anomaly_applied = True
                breakdown.contributions.append(("ML_ANOMALY", config.strong_anomaly))
            elif anomaly.anomaly_score >= config.weak_anomaly_score:
                breakdown.contributions.append(("ML_ANOMALY_WEAK", config.weak_anomaly))

    breakdown.total = max(0, min(100, sum(points for _, points in breakdown.contributions)))
    return breakdown


def classify(
    breakdown: RiskBreakdown,
    comparison: ProfileComparison,
    config: Optional[ScoringConfig] = None,
) -> str:
    """Map a risk score plus verification state to a classification.

    ``UNVERIFIED`` is a first-class outcome, not an apology for missing data.
    It means: the engine has no trusted basis to call this AP safe, and also
    no evidence strong enough to call it hostile. That is exactly the state of
    every AP at a location we have never visited.
    """
    config = config or DEFAULT_CONFIG
    score = breakdown.total

    # Bands, highest first: [0, trusted_max] / (trusted_max, low_risk_max] /
    # (low_risk_max, suspicious_max] / (suspicious_max, 100].
    if score > config.suspicious_max:
        return Classification.HIGH_RISK
    if score > config.low_risk_max:
        return Classification.SUSPICIOUS
    if score > config.trusted_max:
        return Classification.LOW_RISK

    # Score is in the TRUSTED band. Only an actually verified AP gets TRUSTED.
    if comparison.profile_match:
        return Classification.TRUSTED
    return Classification.UNVERIFIED


def apply_provisional_ceiling(
    classification: str,
    comparison: ProfileComparison,
    config: Optional[ScoringConfig] = None,
) -> str:
    """Cap a self-learned profile below ``TRUSTED``.

    A provisional baseline was built from the observations it is now judging,
    so it cannot confirm anything. ``SUSPICIOUS`` and above are unaffected -
    real deviations still escalate.
    """
    config = config or DEFAULT_CONFIG
    if not comparison.provisional:
        return classification
    ceiling = config.provisional_ceiling
    order = {
        Classification.TRUSTED: 0,
        Classification.UNVERIFIED: 1,
        Classification.LOW_RISK: 2,
        Classification.SUSPICIOUS: 3,
        Classification.HIGH_RISK: 4,
    }
    if order.get(classification, 0) < order.get(ceiling, 2):
        return ceiling
    return classification


def thresholds_doc() -> Dict[str, str]:
    """Machine-readable threshold description for the dashboard / README."""
    return {
        "TRUSTED": f"0-{DEFAULT_CONFIG.trusted_max}, requires a matching trusted profile",
        "UNVERIFIED": f"0-{DEFAULT_CONFIG.trusted_max} but not verifiable against any trusted profile",
        "LOW_RISK": f"{DEFAULT_CONFIG.trusted_max + 1}-{DEFAULT_CONFIG.low_risk_max}",
        "SUSPICIOUS": f"{DEFAULT_CONFIG.low_risk_max + 1}-{DEFAULT_CONFIG.suspicious_max}",
        "HIGH_RISK": f"{DEFAULT_CONFIG.suspicious_max + 1}-100",
        "note": "heuristic triage bands, not calibrated probabilities of compromise",
    }
