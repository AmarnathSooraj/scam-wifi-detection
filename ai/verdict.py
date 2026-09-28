"""Semantic verdict layer: what the evidence actually means.

The risk engine answers "how much concern?". This module answers the question
the dashboard and the user actually ask:

    Does this Wi-Fi *appear* legitimate, or does its fingerprint contain enough
    evidence that it may be an impersonating access point?

It is deliberately a **second layer on top of** the existing risk engine, not
a replacement. The tested 0-100 risk score and its five bands stay exactly as
they are; this interprets them.

The rule that matters
---------------------
A verdict is never reached from one weak signal. ``unknown_bssid`` alone, or
``anomaly_score`` above some number, can never produce ``POTENTIAL_FAKE``.

Instead every indicator is assigned to an independent **signal family**, and a
``POTENTIAL_FAKE`` verdict requires:

1. a risk score in the high band, **and**
2. deviations in at least :data:`MIN_FAMILIES_FOR_FAKE` *distinct* families,
   **and**
3. no authoritative profile match.

This is what makes a single anomaly behave the way the brief demands: a weak
signal raises concern, corroboration raises the verdict. The three independent
facts an impersonator must get wrong simultaneously (its hardware identity,
its encryption, its radio plan) are exactly what the family count measures.

Language
--------
The strongest available word is ``POTENTIAL_FAKE``, and the accompanying text
always says *may be* / *consistent with impersonation*. Passive metadata
cannot establish intent: a misconfigured controller, a visiting contractor's
rogue-range extender and a deliberate impersonator all look identical on the
air. :data:`ACCURACY_NOTE` is attached to every such result, and a test
asserts the strong phrasing never appears.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set

from .models import AnomalyResult, Classification, DetectionResult, ProfileComparison, RuleResult

__all__ = [
    "Verdict",
    "EvidenceLevel",
    "SignalFamily",
    "INDICATOR_FAMILY",
    "INDICATOR_MEANING",
    "FAMILY_LABEL",
    "ACCURACY_NOTE",
    "MIN_FAMILIES_FOR_FAKE",
    "FraudAssessment",
    "assess_fraud",
    "indicator_details",
    "verdict_definitions",
]


#: Attached to any result that is not cleanly trusted. Keeps the system from
#: ever asserting intent it cannot observe.
ACCURACY_NOTE = (
    "Passive Wi-Fi metadata cannot establish malicious intent. This assessment "
    "reports fingerprint deviation, which is consistent with impersonation but "
    "also with misconfiguration or an unapproved device. Verify with the "
    "network operator before acting."
)


class Verdict:
    """Semantic outcome, independent of the raw risk band."""

    TRUSTED = "TRUSTED"             # a real profile vouches for this exact BSSID
    LEGITIMATE = "LEGITIMATE"       # consistent with the expected network, not explicitly trusted
    UNVERIFIED = "UNVERIFIED"       # not enough information either way
    SUSPICIOUS = "SUSPICIOUS"       # meaningful deviation from the expected fingerprint
    POTENTIAL_FAKE = "POTENTIAL_FAKE"  # strong evidence of an impersonation pattern

    ALL = (TRUSTED, LEGITIMATE, UNVERIFIED, SUSPICIOUS, POTENTIAL_FAKE)

    #: Verdicts that are affirmative statements about legitimacy.
    BENIGN = (TRUSTED, LEGITIMATE)


class EvidenceLevel:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    ALL = (LOW, MEDIUM, HIGH)


class SignalFamily:
    """Groups of evidence that fail independently of one another.

    Independence is the whole point. A rogue access point has to get several
    things wrong at once, and each family here corresponds to a different
    decision an impersonator had to make independently.
    """

    IDENTITY = "IDENTITY"      # is this BSSID hardware we know? (BSSID, OUI)
    SECURITY = "SECURITY"      # is it encrypted the way the network is?
    RADIO_PLAN = "RADIO_PLAN"  # is it on a plausible channel/band/frequency?
    VENDOR = "VENDOR"          # vendor string, when both sides know one
    BEHAVIOR = "BEHAVIOR"      # aggregate fingerprint drift
    ML = "ML"                  # statistical deviation from the site baseline
    CONTEXT = "CONTEXT"        # missing data, no profile: explains, never accuses

    ALL = (IDENTITY, SECURITY, RADIO_PLAN, VENDOR, BEHAVIOR, ML, CONTEXT)


#: Every indicator code, mapped to the family whose failure it represents.
#: An indicator absent from this map is treated as CONTEXT and can never
#: contribute toward a ``POTENTIAL_FAKE`` verdict.
INDICATOR_FAMILY: Dict[str, str] = {
    "UNKNOWN_BSSID": SignalFamily.IDENTITY,
    "SECURITY_MISMATCH": SignalFamily.SECURITY,
    "SECURITY_DOWNGRADE": SignalFamily.SECURITY,
    "CHANNEL_MISMATCH": SignalFamily.RADIO_PLAN,
    "FREQUENCY_MISMATCH": SignalFamily.RADIO_PLAN,
    "BAND_MISMATCH": SignalFamily.RADIO_PLAN,
    "VENDOR_MISMATCH": SignalFamily.VENDOR,
    "OUI_MISMATCH": SignalFamily.IDENTITY,
    "PROFILE_DEVIATION": SignalFamily.BEHAVIOR,
    "ML_ANOMALY": SignalFamily.ML,
    "NO_TRUSTED_PROFILE": SignalFamily.CONTEXT,
    "PROVISIONAL_PROFILE": SignalFamily.CONTEXT,
    "MISSING_FIELDS": SignalFamily.CONTEXT,
    "HIDDEN_SSID": SignalFamily.CONTEXT,
}

FAMILY_LABEL: Dict[str, str] = {
    SignalFamily.IDENTITY: "Access point identity (BSSID / hardware)",
    SignalFamily.SECURITY: "Encryption",
    SignalFamily.RADIO_PLAN: "Radio plan (channel / band / frequency)",
    SignalFamily.VENDOR: "Vendor",
    SignalFamily.BEHAVIOR: "Overall fingerprint drift",
    SignalFamily.ML: "Statistical deviation from site baseline",
    SignalFamily.CONTEXT: "Data completeness",
}

def family_of(code: str) -> str:
    """Return the signal family for an indicator code."""
    return INDICATOR_FAMILY.get(code, SignalFamily.CONTEXT)


@dataclass
class FraudAssessment:
    """The semantic reading of one detection result."""

    verdict: str
    evidence_level: str
    risk_score: int
    risk_band: str
    #: SSID whose infrastructure this AP appears to be riding on, when the
    #: engine can tell. This is the "what is being impersonated" field.
    impersonating: Optional[str] = None
    #: True only for POTENTIAL_FAKE.
    impersonation_pattern: bool = False
    families_deviating: List[str] = field(default_factory=list)
    families_corroborating: List[str] = field(default_factory=list)
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    guidance: str = ""
    accuracy_note: str = ACCURACY_NOTE

    @property
    def is_benign(self) -> bool:
        return self.verdict in Verdict.BENIGN

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "evidence_level": self.evidence_level,
            "risk_score": self.risk_score,
            "risk_band": self.risk_band,
            "impersonating": self.impersonating,
            "impersonation_pattern": self.impersonation_pattern,
            "families_deviating": list(self.families_deviating),
            "families_corroborating": list(self.families_corroborating),
            "indicators": [dict(item) for item in self.indicators],
            "summary": self.summary,
            "guidance": self.guidance,
            "accuracy_note": self.accuracy_note,
        }


# ---------------------------------------------------------------------------
# Indicator descriptions
# ---------------------------------------------------------------------------

#: Human-readable meaning for every indicator, so the dashboard can show a
#: sentence without having to know the code. Kept here rather than in the rule
#: messages because these describe *what the code means*, not what was seen.
INDICATOR_MEANING: Dict[str, str] = {
    "UNKNOWN_BSSID": "BSSID is not present in the trusted network profile",
    "SECURITY_MISMATCH": "Observed security differs from the expected network security",
    "SECURITY_DOWNGRADE": "Encryption is weaker than the trusted profile expects",
    "CHANNEL_MISMATCH": "Channel is outside the trusted profile's channel plan",
    "FREQUENCY_MISMATCH": "Centre frequency is outside the trusted profile",
    "BAND_MISMATCH": "AP is on a different band than the trusted network uses",
    "VENDOR_MISMATCH": "Hardware vendor differs from the trusted profile",
    "OUI_MISMATCH": "BSSID's hardware vendor block is foreign to this network",
    "OUI_MATCH": "BSSID's hardware vendor block matches known infrastructure",
    "PROFILE_DEVIATION": "Several independent characteristics deviate together",
    "ML_ANOMALY": "Deviation detected by the anomaly model",
    "NO_TRUSTED_PROFILE": "No trusted profile exists for this network",
    "PROVISIONAL_PROFILE": "Only a self-learned baseline exists for this network",
    "MISSING_FIELDS": "Some wireless attributes were not reported",
    "HIDDEN_SSID": "AP is not broadcasting its SSID",
}

#: Families whose deviation means the AP *behaves differently* from the
#: expected network, as opposed to merely not being individually recognised.
#:
#: This distinction is the crux of the whole layer. "Is this BSSID on our
#: list?" is a **verification** question - its honest answer is
#: ``LEGITIMATE``/``UNVERIFIED``, because organisations add access points
#: constantly and that is not impersonation. "Does this AP encrypt, transmit
#: and position itself like the real network?" is a **fingerprint consistency**
#: question, and a "no" is genuine evidence.
#:
#: So IDENTITY alone never escalates a verdict on its own; it becomes evidence
#: only when something behavioural corroborates it.
FINGERPRINT_FAMILIES = frozenset(
    {SignalFamily.SECURITY, SignalFamily.RADIO_PLAN, SignalFamily.VENDOR,
     SignalFamily.BEHAVIOR, SignalFamily.ML}
)

#: Families that contribute to the corroboration count. IDENTITY is included
#: here: an unknown BSSID does become meaningful once something else also
#: contradicts the profile.
_COUNTED_FAMILIES = frozenset(
    {
        SignalFamily.IDENTITY,
        SignalFamily.SECURITY,
        SignalFamily.RADIO_PLAN,
        SignalFamily.VENDOR,
        SignalFamily.BEHAVIOR,
        SignalFamily.ML,
    }
)

#: How many *independent* fingerprint families must contradict the profile
#: before an impersonation verdict is allowed. Two is the minimum that is
#: still meaningful: a single family can deviate innocently (an org buys a new
#: AP from another vendor; a controller moves a channel). Two unrelated
#: families failing at once is what a copied SSID backed by different real
#: hardware actually looks like.
MIN_FAMILIES_FOR_FAKE = 2



def indicator_details(
    rules: RuleResult,
    points_by_code: Optional[Dict[str, int]] = None,
) -> List[Dict[str, Any]]:
    """Return the structured indicator list the API contract calls for.

    Each entry carries the stable ``code``, a dashboard-ready ``message``,
    the independent ``family`` it belongs to, and the risk ``points`` it
    actually contributed (0 when it is contextual).
    """
    points_by_code = points_by_code or {}
    details: List[Dict[str, Any]] = []
    for index, reason in enumerate(rules.reasons):
        code = rules.indicators[index] if index < len(rules.indicators) else "UNCLASSIFIED"
        details.append(
            {
                "code": code,
                "message": reason,
                "meaning": INDICATOR_MEANING.get(code, "Additional observation"),
                "family": family_of(code),
                "points": int(points_by_code.get(code, 0)),
            }
        )
    return details


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------


def _evidence_level(
    risk_score: int,
    families: Set[str],
    has_profile: bool,
) -> str:
    """Grade the *strength* of what we know, not just how worried we are.

    Deliberately not a function of the risk score alone: a high score built
    from one family is weaker evidence than a moderate score corroborated
    across three, and saying so is the point of the layer.
    """
    if not has_profile:
        # No reference at all. Whatever the score, our confidence about
        # legitimacy is low by construction.
        return EvidenceLevel.LOW
    corroborated = len(families) >= MIN_FAMILIES_FOR_FAKE
    if risk_score >= 75 and corroborated:
        return EvidenceLevel.HIGH
    if risk_score >= 50 or corroborated:
        return EvidenceLevel.MEDIUM
    if families:
        return EvidenceLevel.LOW
    return EvidenceLevel.MEDIUM


def assess_fraud(
    rules: RuleResult,
    comparison: ProfileComparison,
    anomaly: Optional[AnomalyResult] = None,
    classification: str = Classification.UNVERIFIED,
    risk_score: int = 0,
    points_by_code: Optional[Dict[str, int]] = None,
    ssid: str = "",
) -> FraudAssessment:
    """Turn rule evidence into a semantic verdict.

    The decision order is fixed and every branch is reachable from evidence
    alone - there is no path where a single indicator short-circuits to
    ``POTENTIAL_FAKE``.
    """
    codes = list(rules.indicators)
    families: Set[str] = {family_of(code) for code in codes} & _COUNTED_FAMILIES
    details = indicator_details(rules, points_by_code)

    has_profile = comparison.has_profile and not comparison.provisional
    verified = comparison.profile_match

    # --- 1. Authoritative match wins outright -----------------------------
    if verified:
        return FraudAssessment(
            verdict=Verdict.TRUSTED,
            evidence_level=EvidenceLevel.HIGH,
            risk_score=risk_score,
            risk_band=classification,
            families_deviating=sorted(families),
            indicators=details,
            summary=(
                f"This BSSID is listed in the trusted profile for {ssid or 'its network'} "
                f"and every characteristic the profile checks matches."
            ),
            guidance="No action needed. Verified infrastructure.",
            accuracy_note="",
        )

    # --- 2. No reference at all -> insufficient information ---------------
    if not comparison.has_profile:
        return FraudAssessment(
            verdict=Verdict.UNVERIFIED,
            evidence_level=EvidenceLevel.LOW,
            risk_score=risk_score,
            risk_band=classification,
            families_deviating=sorted(families),
            indicators=details,
            summary=(
                "No trusted network profile is available for this SSID, so there is "
                "nothing to compare against. Insufficient evidence to determine legitimacy."
            ),
            guidance=(
                "Treat as an ordinary unknown network. To build a reference, have an "
                "administrator verify it and record it with: "
                "python run_scan.py trust \"" + (ssid or "<SSID>") + "\""
            ),
        )

    # --- 3. Provisional (self-learned) baseline can confirm nothing -------
    if comparison.provisional:
        return FraudAssessment(
            verdict=Verdict.UNVERIFIED,
            evidence_level=EvidenceLevel.LOW,
            risk_score=risk_score,
            risk_band=classification,
            families_deviating=sorted(families),
            indicators=details,
            summary=(
                "Only a provisional baseline learned on site exists for this network. "
                "It was built from the observations it is now judging, so it cannot "
                "confirm a device as legitimate."
            ),
            guidance=(
                "Have an administrator verify this network and record it explicitly; "
                "self-learned state can never confirm a trusted device."
            ),
        )

    # From here on there is a real, operator-approved profile, and this AP is
    # not a confirmed match for it.
    # Only behavioural families count toward escalation. An unknown BSSID
    # alone is a verification gap, not a behavioural contradiction.
    fingerprint = families & FINGERPRINT_FAMILIES
    corroborated = len(fingerprint) >= MIN_FAMILIES_FOR_FAKE
    high_risk = risk_score >= 75

    # --- 4. Strong evidence of an impersonation pattern -------------------
    if corroborated and high_risk:
        return FraudAssessment(
            verdict=Verdict.POTENTIAL_FAKE,
            evidence_level=_evidence_level(risk_score, families, has_profile),
            risk_score=risk_score,
            risk_band=classification,
            impersonating=ssid or None,
            impersonation_pattern=True,
            families_deviating=sorted(families),
            families_corroborating=sorted(fingerprint),
            indicators=details,
            summary=(
                f"High-risk impersonation pattern: {len(fingerprint)} independent parts of "
                f"this AP's fingerprint ({', '.join(FAMILY_LABEL.get(f, f) for f in sorted(fingerprint))}) "
                f"contradict the trusted profile for {ssid or 'its network'}. An access point "
                f"broadcasting this SSID does not look like the infrastructure behind it."
            ),
            guidance=(
                "Do not connect or enter credentials. Confirm with the network operator "
                "whether this BSSID belongs to them."
            ),
        )

    # --- 5. Meaningful but uncorroborated deviation -----------------------
    # Keyed on fingerprint families, not on the raw score: a score of 25 from
    # an unknown BSSID alone means "consistent, not verified", not "suspicious".
    if fingerprint:
        return FraudAssessment(
            verdict=Verdict.SUSPICIOUS,
            evidence_level=_evidence_level(risk_score, families, has_profile),
            risk_score=risk_score,
            risk_band=classification,
            impersonating=ssid or None,
            impersonation_pattern=False,
            families_deviating=sorted(families),
            families_corroborating=[],
            indicators=details,
            summary=(
                f"{len(fingerprint)} characteristic(s) deviate from the trusted profile for "
                f"{ssid or 'its network'}, but the evidence is not yet corroborated across "
                f"independent parts of the fingerprint."
                if families
                else f"Some deviation from the trusted profile for {ssid or 'its network'} was observed."
            ),
            guidance=(
                "Watch this BSSID. If an operator confirms it was added, record it with "
                "python run_scan.py trust \"" + (ssid or "<SSID>") + "\"."
            ),
        )

    # --- 6. Consistent with the expected network, just not verified ------
    return FraudAssessment(
        verdict=Verdict.LEGITIMATE,
        evidence_level=EvidenceLevel.MEDIUM,
        risk_score=risk_score,
        risk_band=classification,
        # Still reported: the dashboard must be able to say *why* this is not
        # TRUSTED ("BSSID is not on the list"), not just that it isn't.
        families_deviating=sorted(families),
        indicators=details,
        summary=(
            f"This AP matches the expected fingerprint for {ssid or 'its network'} on every "
            f"attribute that could be checked, but its BSSID is not on the trusted list, so it "
            f"is not explicitly verified."
        ),
        guidance=(
            "Probably an access point added since the profile was written. An operator can "
            "confirm it with: python run_scan.py trust \"" + (ssid or "<SSID>") + "\""
        ),
    )


#: Plain-language definitions, published in the scan report so a dashboard
#: never has to hardcode them or guess at the difference between SUSPICIOUS
#: and POTENTIAL_FAKE.
VERDICT_DEFINITIONS: Dict[str, str] = {
    Verdict.TRUSTED: (
        "A trusted network profile lists this exact BSSID and every attribute the "
        "profile checks matches. Verified legitimate infrastructure."
    ),
    Verdict.LEGITIMATE: (
        "Consistent with the expected network on every attribute that could be "
        "checked, but this BSSID is not on the trusted list - most likely an "
        "access point added since the profile was written."
    ),
    Verdict.UNVERIFIED: (
        "Insufficient information to determine legitimacy. Either no trusted "
        "profile exists for this SSID, or only a self-learned baseline does. "
        "Not an accusation."
    ),
    Verdict.SUSPICIOUS: (
        "One or more meaningful deviations from the expected fingerprint, not yet "
        "corroborated across independent parts of it. Worth watching; not a "
        "conclusion."
    ),
    Verdict.POTENTIAL_FAKE: (
        "Strong evidence of an impersonation pattern: several independent parts "
        "of this AP's fingerprint contradict the trusted profile at once. Means "
        "'may be impersonating', never 'proven malicious' - passive metadata "
        "cannot establish intent."
    ),
}


def verdict_definitions() -> Dict[str, str]:
    """Return the verdict vocabulary for API consumers and the dashboard."""
    return dict(VERDICT_DEFINITIONS)
