"""Top-level analysis pipeline.

    analyze_network(network, trusted_profile) -> DetectionResult

This is the only function the FastAPI backend (Person 3) needs. It takes one
scanner observation plus an optional trusted profile and returns a
JSON-serialisable :class:`~ai.models.DetectionResult` whose ``reasons`` explain
the verdict in plain language.

Stages, in order:

1. **Validation / coercion** - dicts and scanner objects become
   :class:`~ai.models.WiFiNetwork`; missing optional fields are ``None``, never
   guessed. A malformed observation degrades to a low-confidence result
   instead of raising.
2. **Feature extraction** - numeric vector, missingness flagged.
3. **Trusted profile comparison** - facts about known BSSIDs, security,
   channel, frequency, vendor.
4. **Security rules** - explainable indicators.
5. **Isolation Forest** - anomaly score against the learned baseline.
6. **Risk engine** - weighted, clamped 0-100 score and classification.
7. **Explainability** - reasons, score breakdown and evidence for the UI.

Nothing here performs active probing or deauthentication; the engine reads
passive metadata only.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from .anomaly import AnomalyDetector, baseline_from_profiles, get_default_detector
from .features import extract_features
from .models import (
    AnomalyResult,
    Classification,
    DetectionResult,
    ProfileComparison,
    RuleResult,
    TrustedProfile,
    WiFiNetwork,
)
from .risk_engine import (
    DEFAULT_CONFIG,
    ScoringConfig,
    apply_provisional_ceiling,
    classify,
    score_risk,
    thresholds_doc,
)
from .rules import evaluate_rules
from .verdict import Verdict, assess_fraud, verdict_definitions
from .trusted_profile import (
    ProvisionalBaseline,
    compare_to_profile,
    load_profiles,
    profile_for_ssid,
)

__all__ = [
    "analyze_network",
    "analyze_networks",
    "analyze_scan",
    "detector_for_profile",
    "clear_detector_cache",
]


# ---------------------------------------------------------------------------
# Detector cache
# ---------------------------------------------------------------------------

#: Fitted detectors are cached per profile so a scan of 40 APs fits one forest,
#: not 40. Keyed by a stable fingerprint of the profile, so editing a profile
#: (adding a BSSID) produces a new key and therefore a refit.
_DETECTOR_CACHE: Dict[str, AnomalyDetector] = {}

#: Upper bound on cached detectors, so a long-running backend that sees many
#: distinct SSIDs cannot grow this without limit. Overflow evicts the oldest
#: insertion (FIFO), which is acceptable: refitting is cheap.
_DETECTOR_CACHE_MAX = 32


def _profile_fingerprint(profile: TrustedProfile) -> str:
    """Stable cache key for a profile's baseline-defining content."""
    return json.dumps(
        {
            "ssid": profile.ssid,
            "bssids": profile.known_bssids,
            "security": profile.security,
            "channels": profile.expected_channels,
            "frequencies": profile.expected_frequencies,
            "provisional": profile.provisional,
        },
        sort_keys=True,
    )


def detector_for_profile(profile: Optional[TrustedProfile]) -> AnomalyDetector:
    """Return a detector whose baseline matches ``profile``.

    A profile already states what normal looks like at this site, so the
    baseline is synthesised from it. This is what gives the model enough
    resolution to flag an AP that breaks the site's pattern, instead of
    comparing a corporate 5 GHz AP against a generic multi-band reference set.

    Falls back to the shared reference detector when the profile yields too few
    baseline rows.
    """
    if profile is None:
        return get_default_detector()

    key = _profile_fingerprint(profile)
    cached = _DETECTOR_CACHE.get(key)
    if cached is not None:
        return cached

    rows = baseline_from_profiles([profile])
    detector = (
        AnomalyDetector().fit(rows)
        if len(rows) >= AnomalyDetector().min_rows
        else get_default_detector()
    )
    if len(_DETECTOR_CACHE) >= _DETECTOR_CACHE_MAX:
        _DETECTOR_CACHE.pop(next(iter(_DETECTOR_CACHE)))
    _DETECTOR_CACHE[key] = detector
    return detector


def clear_detector_cache() -> None:
    """Drop all cached detectors. Useful in tests and after a config reload."""
    _DETECTOR_CACHE.clear()


# ---------------------------------------------------------------------------
# Single-network analysis
# ---------------------------------------------------------------------------

def analyze_network(
    network: Any,
    trusted_profile: Optional[Any] = None,
    detector: Optional[AnomalyDetector] = None,
    config: Optional[ScoringConfig] = None,
) -> DetectionResult:
    """Assess one observed access point.

    Args:
        network: scanner observation - a dict (``{ssid, bssid, signal, ...}``)
            or any object with those attributes.
        trusted_profile: the matching :class:`~ai.models.TrustedProfile`, a
            dict in the same shape, or ``None`` for a network we have no
            configuration for.
        detector: an :class:`~ai.anomaly.AnomalyDetector`. Defaults to the
            process-wide reference-baseline detector, fitted on first use.
        config: optional :class:`~ai.risk_engine.ScoringConfig` override.

    Returns:
        A :class:`~ai.models.DetectionResult`. Always has non-empty ``reasons``.
    """
    config = config or DEFAULT_CONFIG
    net = WiFiNetwork.from_dict(network)

    # An empty container is not a profile. Without this, `analyze_network(net, [])`
    # would build a phantom blank profile and report "has a trusted profile"
    # rather than "nothing is known about this network" - the exact opposite
    # of the truth, and it would suppress the NO_TRUSTED_PROFILE reason.
    if trusted_profile is not None and not trusted_profile:
        trusted_profile = None

    profile = TrustedProfile.from_dict(trusted_profile) if trusted_profile is not None else None
    comparison = compare_to_profile(net, profile)

    features = extract_features(net, comparison)
    rules: RuleResult = evaluate_rules(net, comparison, expected_security=profile.security if profile else None)

    if detector is not None:
        active_detector = detector
    else:
        active_detector = detector_for_profile(profile)
    anomaly: AnomalyResult = active_detector.score(net, comparison)

    breakdown = score_risk(rules, comparison, anomaly, config)

    # The ML reason is appended here rather than inside evaluate_rules so the
    # rules module stays free of any model dependency.
    #
    # It keys off ``breakdown.contributions`` rather than re-testing the
    # threshold, so the stated reason and the awarded points can never
    # disagree - and so the profile-match veto in the risk engine is honoured
    # here too. An AP that a trusted profile vouches for never gets an
    # anomaly reason, because no points were taken.
    applied = dict(breakdown.contributions)
    if applied.get("ML_ANOMALY"):
        rules.add(
            "ML_ANOMALY",
            "Significant deviation detected by the Isolation Forest anomaly model "
            f"(anomaly score {anomaly.anomaly_score:.2f} against the learned baseline)",
        )
    elif applied.get("ML_ANOMALY_WEAK"):
        rules.add(
            "ML_ANOMALY",
            f"Mild deviation from the learned wireless baseline (anomaly score {anomaly.anomaly_score:.2f})",
        )
    elif not anomaly.available:
        rules.add_mitigating(
            "No anomaly baseline for this network (it needs a trusted or "
            "on-site-learned profile to compare against), so the score is based "
            "on profile and rule evidence only"
        )

    classification = apply_provisional_ceiling(classify(breakdown, comparison, config), comparison, config)

    # Semantic layer: interpret the risk band against *what kind* of evidence
    # produced it. Kept separate from classify() so the tested risk behaviour is
    # untouched and the verdict can be reasoned about on its own.
    assessment = assess_fraud(
        rules,
        comparison,
        anomaly,
        classification=classification,
        risk_score=breakdown.total,
        points_by_code={name: points for name, points in breakdown.contributions},
        ssid=net.ssid,
    )

    reasons = _build_reasons(net, comparison, rules, anomaly, classification, config)

    return DetectionResult(
        ssid=net.ssid,
        bssid=net.bssid,
        risk_score=breakdown.total,
        classification=classification,
        anomaly_score=anomaly.anomaly_score,
        anomaly_available=anomaly.available,
        profile_match=comparison.profile_match,
        verdict=assessment.verdict,
        evidence_level=assessment.evidence_level,
        impersonation_pattern=assessment.impersonation_pattern,
        impersonating=assessment.impersonating,
        indicator_details=assessment.indicators,
        families_deviating=assessment.families_deviating,
        verdict_summary=assessment.summary,
        verdict_guidance=assessment.guidance,
        accuracy_note=assessment.accuracy_note,
        reasons=reasons,
        indicators=list(rules.indicators),
        mitigating=list(rules.mitigating),
        score_breakdown={
            name: points for name, points in breakdown.contributions
        },
        profile_comparison=comparison.to_dict(),
        features=features,
        observed=net.to_dict(),
        timestamp=net.timestamp,
    )


# ---------------------------------------------------------------------------
# Reason assembly
# ---------------------------------------------------------------------------

def _build_reasons(
    net: WiFiNetwork,
    comparison: ProfileComparison,
    rules: RuleResult,
    anomaly: AnomalyResult,
    classification: str,
    config: ScoringConfig,
) -> List[str]:
    """Assemble the ordered, human-readable explanation.

    Order: evidence that raised risk, then verification status, then caveats,
    then mitigating notes. The list is never empty - a result with no reasons
    would be unusable for a human reviewer.
    """
    reasons: List[str] = list(rules.reasons)

    if classification == Classification.TRUSTED:
        reasons.insert(0, "BSSID belongs to trusted infrastructure and matches its expected profile")
    elif classification == Classification.UNVERIFIED and not comparison.has_profile:
        reasons.append(
            "Classified UNVERIFIED: unknown infrastructure is not treated as malicious, "
            "but this AP cannot be confirmed as legitimate either"
        )
    elif classification == Classification.UNVERIFIED:
        reasons.append(
            "Classified UNVERIFIED: the observed characteristics are consistent, "
            "but this BSSID is not on the trusted list"
        )
    elif classification == Classification.LOW_RISK:
        reasons.append(
            "Minor deviations from the trusted profile; consistent with legitimate infrastructure "
            "but worth a second look"
        )
    elif classification == Classification.SUSPICIOUS:
        reasons.append(
            "Multiple independent characteristics deviate from the trusted profile; "
            "this AP warrants manual verification"
        )
    elif classification == Classification.HIGH_RISK:
        reasons.append(
            "Strong, corroborated evidence of deviation from the expected wireless infrastructure; "
            "avoid connecting and verify with the network operator"
        )

    for note in rules.mitigating:
        reasons.append(note)
    for warning in net.parse_warnings:
        reasons.append(f"Input warning: {warning}")

    if not reasons:
        reasons = [f"No anomalies identified (classified {classification})"]
    return reasons


# ---------------------------------------------------------------------------
# Batch helpers
# ---------------------------------------------------------------------------

def analyze_networks(
    networks: Iterable[Any],
    profiles: Optional[Iterable[Any]] = None,
    detector: Optional[AnomalyDetector] = None,
    config: Optional[ScoringConfig] = None,
    baseline: Optional[ProvisionalBaseline] = None,
) -> List[DetectionResult]:
    """Assess a whole scan.

    Args:
        networks: the scan's observations.
        profiles: trusted profiles as dicts/objects.
        detector: shared anomaly detector, so the baseline is fitted once.
        config: scoring overrides.
        baseline: optional :class:`~ai.trusted_profile.ProvisionalBaseline`
            holding repeated observations from this location.

    The three ways to call this mean three different things, and the
    difference matters:

    * ``profiles=[...]`` - "here is the configured infrastructure". SSIDs with
      no match are reported ``UNVERIFIED`` and are **never** absorbed into a
      self-learned baseline. This is the mode a production deployment should
      use.
    * ``profiles=[]`` - the same statement, said explicitly: infrastructure is
      configured and none of it covers these SSIDs. Still ``UNVERIFIED``; the
      difference from ``None`` is that nothing is learned on the fly.
    * ``profiles=None`` (default) - "I have no configuration; learn a
      provisional baseline from this scan". Appropriate for a first visit to
      an unknown location, where a provisional profile is the only reference
      available. Provisional profiles can never yield ``TRUSTED``.

    In short: pass a list once you have configuration, and leave it ``None``
    only while you are still discovering a location.
    """

    nets = [WiFiNetwork.from_dict(item) for item in networks or ()]
    if not nets:
        return []

    resolved_profiles: Dict[str, Optional[TrustedProfile]] = {}
    provisional_used = False
    if profiles is not None:
        loaded = load_profiles(profiles) if not isinstance(profiles, (list, tuple)) else [
            TrustedProfile.from_dict(p) for p in profiles
        ]
        for net in nets:
            resolved_profiles[net.ssid] = profile_for_ssid(loaded, net.ssid)
    else:
        if baseline is None:
            baseline = ProvisionalBaseline()
        learned = baseline.update(nets)
        provisional_used = True
        for net in nets:
            resolved_profiles[net.ssid] = learned.get(net.ssid)

    # One detector per distinct profile, chosen so each network is scored
    # against *its own* site's baseline rather than a single shared one.
    # ``detector_for_profile`` caches by profile content, so a scan of 40
    # access points spanning 6 networks still fits at most 6 forests.
    if detector is not None:
        detectors: Dict[str, Optional[AnomalyDetector]] = {}
    elif provisional_used:
        # Nothing is configured. Where the provisional baseline produced
        # enough observations, learn a local detector from it; otherwise there
        # is no baseline and the results say so honestly.
        usable = [p for p in resolved_profiles.values() if p is not None and p.provisional]
        shared = AnomalyDetector().fit_from_profiles(usable) if usable else None
        detectors = {ssid: shared for ssid in resolved_profiles}
    else:
        detectors = {}

    results: List[DetectionResult] = []
    for net in nets:
        profile = resolved_profiles.get(net.ssid)
        if detector is not None:
            active = detector
        elif provisional_used:
            active = detectors.get(net.ssid)
        else:
            # Cached per profile; returns an unfitted detector when there is
            # no profile, which is reported as anomaly_available=False.
            active = detector_for_profile(profile)
        results.append(analyze_network(net, profile, detector=active, config=config))
    return results


def analyze_scan(
    scan: Any,
    profiles: Optional[Iterable[Any]] = None,
    detector: Optional[AnomalyDetector] = None,
    config: Optional[ScoringConfig] = None,
) -> Dict[str, Any]:
    """Assess a full scanner payload and return a dashboard-ready dict.

    Accepts the scanner's ``ScanResult``/``{"networks": [...]}`` shape. The
    returned dict groups results by SSID so the dashboard can render one
    network with its APs, which is also what makes the "many APs, one SSID"
    case obvious to a viewer.
    """
    if isinstance(scan, Mapping):
        raw_networks = scan.get("networks")
        scan_timestamp = scan.get("timestamp")
    else:
        raw_networks = getattr(scan, "networks", None)
        scan_timestamp = getattr(scan, "timestamp", None)
        if raw_networks is None and isinstance(scan, Sequence) and not isinstance(scan, (str, bytes)):
            raw_networks = scan

    baseline = ProvisionalBaseline()
    results = analyze_networks(
        raw_networks or (), profiles=profiles, detector=detector, config=config, baseline=baseline
    )

    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for result in results:
        grouped.setdefault(result.ssid, []).append(result.to_dict())

    counts = {label: 0 for label in Classification.ALL}
    for result in results:
        counts[result.classification] = counts.get(result.classification, 0) + 1

    # Verdict counts are what a dashboard should lead with: they answer "is
    # this network ok or might it be fake", which the raw risk band does not.
    verdict_counts: Dict[str, int] = {label: 0 for label in Verdict.ALL}
    for result in results:
        verdict_counts[result.verdict] = verdict_counts.get(result.verdict, 0) + 1

    # Highest concern first, so a summary can be rendered without sorting.
    order = {name: rank for rank, name in enumerate(reversed(Verdict.ALL))}
    flagged = sorted(
        (r for r in results if r.verdict in (Verdict.SUSPICIOUS, Verdict.POTENTIAL_FAKE)),
        key=lambda r: (-r.risk_score, r.bssid),
    )

    return {
        "timestamp": scan_timestamp,
        "network_count": len(results),
        "classification_counts": counts,
        "verdict_counts": verdict_counts,
        "flagged_count": len(flagged),
        "flagged": [r.to_dict() for r in flagged],
        "ssid_count": len(grouped),
        "results": [result.to_dict() for result in results],
        "networks": grouped,
        "thresholds": thresholds_doc(),
        "verdict_definitions": verdict_definitions(),
    }
