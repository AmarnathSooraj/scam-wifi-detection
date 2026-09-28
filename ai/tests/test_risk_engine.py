"""Tests for risk scoring, classification and the ML gating logic.

The behaviour under test is the engine's central safety property: evidence
accumulates, but no single fact - and especially not an unknown BSSID - is
enough on its own to call an access point hostile.
"""

from __future__ import annotations

import pytest

from ai.models import AnomalyResult, Classification, ProfileComparison, RuleResult
from ai.risk_engine import (
    DEFAULT_CONFIG,
    ScoringConfig,
    apply_provisional_ceiling,
    classify,
    score_risk,
    thresholds_doc,
)
from ai.trusted_profile import compare_to_profile

from .conftest import AIRPORT_PROFILE, ap

STRONG = AnomalyResult(anomaly_score=0.95, available=True)
WEAK = AnomalyResult(anomaly_score=0.60, available=True)
NIL = AnomalyResult(anomaly_score=0.0, available=True)
UNAVAILABLE = AnomalyResult(anomaly_score=0.0, available=False)

#: A comparison representing an AP a real trusted profile vouches for.
VERIFIED = ProfileComparison(has_profile=True, known_bssid=True, deviation_count=0)


def result_for(*indicators, points=None):
    rules = RuleResult(indicators=list(indicators))
    if points:
        for code, value in points.items():
            rules.add(code, "")
    return rules


# --- arithmetic ----------------------------------------------------------

def test_no_indicators_means_no_risk():
    breakdown = score_risk(RuleResult(), ProfileComparison(has_profile=True), NIL)
    assert breakdown.total == 0


def test_weights_are_summed_from_named_indicators():
    breakdown = score_risk(
        result_for("UNKNOWN_BSSID", "CHANNEL_MISMATCH"),
        ProfileComparison(has_profile=True),
        NIL,
    )
    expected = DEFAULT_CONFIG.unknown_bssid + DEFAULT_CONFIG.channel_mismatch
    assert breakdown.total == expected


def test_breakdown_explains_every_point_awarded():
    breakdown = score_risk(
        result_for("UNKNOWN_BSSID", "SECURITY_MISMATCH"),
        ProfileComparison(has_profile=True),
        STRONG,
    )
    awarded = sum(points for _, points in breakdown.contributions)
    assert awarded == breakdown.total
    names = {name for name, _ in breakdown.contributions}
    assert {"UNKNOWN_BSSID", "SECURITY_MISMATCH", "ML_ANOMALY"} <= names


def test_unknown_indicator_codes_score_nothing():
    breakdown = score_risk(
        result_for("SOMETHING_NEW"), ProfileComparison(has_profile=True), NIL
    )
    assert breakdown.total == 0


# --- clamping ------------------------------------------------------------

def test_score_is_clamped_to_one_hundred():
    breakdown = score_risk(
        result_for("UNKNOWN_BSSID", "SECURITY_MISMATCH", "SECURITY_DOWNGRADE",
                   "CHANNEL_MISMATCH", "FREQUENCY_MISMATCH", "BAND_MISMATCH",
                   "VENDOR_MISMATCH", "PROFILE_DEVIATION"),
        ProfileComparison(has_profile=True), STRONG,
    )
    assert breakdown.total == 100


def test_score_is_never_negative():
    breakdown = score_risk(RuleResult(), ProfileComparison(), AnomalyResult(-5.0, available=True))
    assert breakdown.total >= 0


def test_the_demo_rogue_does_not_saturate_at_one_hundred():
    """A clamped score tells the reviewer nothing; the common case must not clamp."""
    breakdown = score_risk(
        result_for("UNKNOWN_BSSID", "SECURITY_MISMATCH", "SECURITY_DOWNGRADE",
                   "CHANNEL_MISMATCH", "FREQUENCY_MISMATCH", "BAND_MISMATCH",
                   "PROFILE_DEVIATION"),
        ProfileComparison(has_profile=True), NIL,
    )
    assert 60 <= breakdown.total < 100


# --- the ML gates --------------------------------------------------------

def test_profile_match_vetoes_the_anomaly_score():
    """A vouched-for AP is never penalised by a model with a coarse tail ranking."""
    comparison = ProfileComparison(
        has_profile=True, known_bssid=True, deviation_count=0
    )
    breakdown = score_risk(RuleResult(), comparison, STRONG)
    assert breakdown.total == 0
    assert breakdown.anomaly_applied is False


def test_provisional_profile_does_not_get_the_veto():
    comparison = ProfileComparison(
        has_profile=True, provisional=True, known_bssid=True, deviation_count=0
    )
    breakdown = score_risk(RuleResult(), comparison, STRONG)
    assert breakdown.total > 0


def test_unavailable_model_contributes_nothing():
    breakdown = score_risk(RuleResult(), ProfileComparison(has_profile=True), UNAVAILABLE)
    assert breakdown.total == 0


def test_strong_and_weak_anomalies_are_weighted_differently():
    strong = score_risk(RuleResult(), ProfileComparison(has_profile=True), STRONG)
    weak = score_risk(RuleResult(), ProfileComparison(has_profile=True), WEAK)
    assert strong.total > weak.total > 0


def test_without_a_profile_only_a_far_outlier_counts():
    """Otherwise a new location is charged twice: unknown *and* anomalous."""
    mild = score_risk(RuleResult(), ProfileComparison(has_profile=False), WEAK)
    assert mild.total == 0
    far = score_risk(RuleResult(), ProfileComparison(has_profile=False), STRONG)
    assert far.total > 0


def test_anomaly_gating_can_be_disabled():
    config = DEFAULT_CONFIG.with_overrides(anomaly_requires_profile=False)
    breakdown = score_risk(RuleResult(), ProfileComparison(has_profile=False), WEAK, config)
    assert breakdown.total > 0


# --- classification ------------------------------------------------------

@pytest.mark.parametrize(
    "score, expected",
    [
        (0, Classification.TRUSTED),
        (24, Classification.TRUSTED),
        (25, Classification.LOW_RISK),
        (49, Classification.LOW_RISK),
        (50, Classification.SUSPICIOUS),
        (74, Classification.SUSPICIOUS),
        (75, Classification.HIGH_RISK),
        (100, Classification.HIGH_RISK),
    ],
)
def test_threshold_bands(score, expected):
    """Bands are score-driven; TRUSTED additionally requires a real match."""
    breakdown = score_risk(RuleResult(), VERIFIED, NIL)
    breakdown.total = score
    assert classify(breakdown, VERIFIED) == expected


def test_low_score_without_a_profile_is_unverified_not_trusted():
    breakdown = score_risk(RuleResult(), ProfileComparison(has_profile=False), NIL)
    assert classify(breakdown, ProfileComparison(has_profile=False)) == Classification.UNVERIFIED


def test_unknown_bssid_alone_stays_below_high_risk():
    """At a new location every BSSID is unknown; this must not cry wolf."""
    breakdown = score_risk(
        result_for("UNKNOWN_BSSID"), ProfileComparison(has_profile=True), NIL
    )
    classification = classify(breakdown, ProfileComparison(has_profile=True))
    assert classification in (Classification.UNVERIFIED, Classification.LOW_RISK)
    assert breakdown.total < DEFAULT_CONFIG.suspicious_max


def test_provisional_profile_is_capped_below_trusted():
    comparison = ProfileComparison(has_profile=True, provisional=True, known_bssid=True)
    breakdown = score_risk(RuleResult(), comparison, NIL)
    assert classify(breakdown, comparison) == Classification.UNVERIFIED
    assert apply_provisional_ceiling(
        Classification.UNVERIFIED, comparison
    ) == Classification.LOW_RISK


def test_provisional_cap_does_not_suppress_real_escalation():
    comparison = ProfileComparison(has_profile=True, provisional=True)
    assert apply_provisional_ceiling(Classification.SUSPICIOUS, comparison) == Classification.SUSPICIOUS
    assert apply_provisional_ceiling(Classification.HIGH_RISK, comparison) == Classification.HIGH_RISK


def test_ceiling_is_inert_without_a_provisional_profile():
    comparison = ProfileComparison(has_profile=True)
    assert apply_provisional_ceiling(Classification.UNVERIFIED, comparison) == Classification.UNVERIFIED


# --- configurability -----------------------------------------------------

def test_weights_are_configurable():
    config = ScoringConfig(unknown_bssid=0, channel_mismatch=0)
    breakdown = score_risk(
        result_for("UNKNOWN_BSSID", "CHANNEL_MISMATCH"),
        ProfileComparison(has_profile=True), NIL, config,
    )
    assert breakdown.total == 0


def test_thresholds_are_configurable():
    """Moving the bands moves the verdicts; the defaults are not hard-coded."""
    breakdown = score_risk(RuleResult(), VERIFIED, NIL)
    breakdown.total = 30
    assert classify(breakdown, VERIFIED) == Classification.LOW_RISK

    stricter = ScoringConfig(low_risk_max=10, suspicious_max=20)
    assert classify(breakdown, VERIFIED, stricter) == Classification.HIGH_RISK

    laxer = ScoringConfig(trusted_max=60, low_risk_max=90, suspicious_max=100)
    assert classify(breakdown, VERIFIED, laxer) == Classification.TRUSTED


def test_override_returns_a_copy_and_leaves_the_default_untouched():
    config = DEFAULT_CONFIG.with_overrides(unknown_bssid=99)
    assert config.unknown_bssid == 99
    assert DEFAULT_CONFIG.unknown_bssid != 99


def test_thresholds_doc_is_published_for_the_dashboard():
    doc = thresholds_doc()
    assert set(Classification.ALL) <= set(doc)
    assert "not calibrated probabilities" in doc["note"]


# --- end-to-end weighting sanity ----------------------------------------

def test_real_observations_score_as_expected():
    """Spot-check the weights against the brief's demo network."""
    trusted = compare_to_profile(ap(), AIRPORT_PROFILE)
    unknown = compare_to_profile(ap(bssid="BB:CC:DD:44:55:66"), AIRPORT_PROFILE)
    rogue = compare_to_profile(
        ap(bssid="BB:CC:DD:44:55:66", security="OPEN", channel=6, frequency=2437), AIRPORT_PROFILE
    )

    assert score_risk(RuleResult(), trusted, NIL).total == 0

    unknown_rules = result_for("UNKNOWN_BSSID")
    unknown_score = score_risk(unknown_rules, unknown, NIL).total
    assert 0 < unknown_score < DEFAULT_CONFIG.suspicious_max

    rogue_rules = result_for("UNKNOWN_BSSID", "SECURITY_MISMATCH", "SECURITY_DOWNGRADE",
                             "CHANNEL_MISMATCH", "FREQUENCY_MISMATCH", "BAND_MISMATCH",
                             "PROFILE_DEVIATION")
    rogue_breakdown = score_risk(rogue_rules, rogue, NIL)
    assert rogue_breakdown.total > unknown_score * 2
