"""Tests for Isolation Forest anomaly detection.

These assert the properties the engine actually guarantees: a bounded,
deterministic, always-available-when-fitted score that never fabricates a
number, plus honest reporting when there is no baseline to judge against.

They deliberately do **not** assert that the model separates a rogue AP from a
weak-signal legitimate AP. That separation was measured (see the README) and
does not hold: Isolation Forest's path-length score saturates for both, because
a point outside the training support and a point in the tail of one feature are
both isolated in O(1) splits. Asserting a separation that does not exist would
make this suite lie, and the engine is explicitly designed so the rules - not
the model - carry the classification.
"""

from __future__ import annotations

import math

import pytest

from ai.anomaly import (
    BASELINE_SAMPLES,
    MIN_BASELINE_ROWS,
    AnomalyDetector,
    baseline_from_profiles,
    get_default_detector,
    set_default_detector,
)
from ai.features import FEATURE_NAMES
from ai.models import Classification
from ai.trusted_profile import compare_to_profile

from .conftest import AIRPORT_PROFILE, ap, three_legit_aps


@pytest.fixture
def detector():
    return AnomalyDetector().fit_from_profiles([AIRPORT_PROFILE])


# --- contract ------------------------------------------------------------

def test_unfitted_detector_reports_unavailable_not_zero(detector):
    """A missing model must not masquerade as a confident 'normal'."""
    empty = AnomalyDetector()
    assert empty.is_fitted is False
    result = empty.score(ap())
    assert result.available is False
    assert result.anomaly_score == 0.0


def test_score_is_always_within_unit_interval(detector):
    cases = [
        ap(),
        ap(bssid="BB:CC:DD:44:55:66", security="OPEN", channel=6, frequency=2437),
        ap(signal=-95, channel=165, frequency=5825, security="WEP"),
        {},
        ap(bssid="not-a-mac", security=None, channel=None, frequency=None),
    ]
    for network in cases:
        result = detector.score(network)
        assert result.available
        assert 0.0 <= result.anomaly_score <= 1.0, network
        assert math.isfinite(result.anomaly_score)


def test_score_is_deterministic_across_fits():
    """The demo must not re-roll its own numbers between runs."""
    scores = []
    for _ in range(3):
        det = AnomalyDetector().fit_from_profiles([AIRPORT_PROFILE])
        result = det.score(ap(bssid="BB:CC:DD:44:55:66", security="OPEN", channel=6, frequency=2437))
        scores.append(result.anomaly_score)
    assert len(set(scores)) == 1


def test_baseline_synthesis_is_deterministic():
    first = baseline_from_profiles([AIRPORT_PROFILE])
    second = baseline_from_profiles([AIRPORT_PROFILE])
    assert first == second


def test_raw_decision_value_is_reported_alongside_the_score(detector):
    """The underlying model output stays visible for explainability."""
    result = detector.score(ap())
    assert isinstance(result.raw_score, float)
    assert math.isfinite(result.raw_score)
    assert result.baseline_size == detector.baseline_size


def test_anomaly_flag_follows_the_models_own_boundary(detector):
    """``is_anomaly`` is the model's verdict; the score is our rescaling."""
    result = detector.score(ap(bssid="BB:CC:DD:44:55:66", security="OPEN", channel=6, frequency=2437))
    assert result.is_anomaly == (result.raw_score < 0.0)


# --- baseline construction ----------------------------------------------

def test_baseline_rows_have_the_right_width():
    rows = baseline_from_profiles([AIRPORT_PROFILE])
    assert rows
    assert all(len(row) == len(FEATURE_NAMES) for row in rows)


def test_baseline_is_large_enough_to_be_a_distribution():
    """A handful of points is a grid, not a distribution."""
    rows = baseline_from_profiles([AIRPORT_PROFILE])
    assert len(rows) >= BASELINE_SAMPLES
    assert len(rows) >= MIN_BASELINE_ROWS


def test_no_built_in_baseline_exists():
    """There is no built-in set of invented access points.

    Scoring real networks against a fictional baseline would produce a
    confident-looking number that means nothing.
    """
    assert not hasattr(AnomalyDetector, "REFERENCE_BASELINE")
    assert not hasattr(__import__("ai.anomaly", fromlist=["x"]), "REFERENCE_BASELINE")


def test_detector_without_a_baseline_reports_unavailable_not_a_number():
    """The honest state at a site with no configuration and no history."""
    detector = AnomalyDetector()
    assert detector.is_fitted is False
    result = detector.score(ap())
    assert result.available is False
    assert result.anomaly_score == 0.0


def test_empty_profile_list_leaves_the_detector_unfitted():
    detector = AnomalyDetector().fit_from_profiles([])
    assert detector.is_fitted is False
    assert detector.score(ap()).available is False


def test_default_detector_is_unfitted():
    """`default()` must not silently invent a baseline."""
    assert AnomalyDetector.default().is_fitted is False


def test_baseline_spans_a_realistic_signal_range():
    """Signal varies with distance, not with legitimacy."""
    signals = {row[FEATURE_NAMES.index("signal")] for row in baseline_from_profiles([AIRPORT_PROFILE])}
    assert len(signals) > 20, "baseline signal should not be a handful of fixed values"


def test_baseline_rows_are_fully_in_profile():
    """Every synthesised row must agree with the profile it came from."""
    for row in baseline_from_profiles([AIRPORT_PROFILE]):
        values = dict(zip(FEATURE_NAMES, row))
        assert values["known_bssid"] == 1.0
        assert values["security_match"] == 1.0
        assert values["deviation_count"] == 0.0
        assert values["channel_deviation"] == 0.0


def test_empty_baseline_is_rejected_loudly():
    with pytest.raises(ValueError):
        AnomalyDetector().fit([])


def test_wrong_feature_width_is_rejected():
    with pytest.raises(ValueError):
        AnomalyDetector().fit([[0.0, 1.0, 2.0]])


def test_non_finite_baseline_is_rejected():
    rows = baseline_from_profiles([AIRPORT_PROFILE])
    rows[0] = [float("nan")] * len(FEATURE_NAMES)
    with pytest.raises(ValueError):
        AnomalyDetector().fit(rows)


def test_too_small_baseline_is_rejected():
    rows = baseline_from_profiles([AIRPORT_PROFILE])[:2]
    with pytest.raises(ValueError):
        AnomalyDetector().fit(rows)


# --- fallback ------------------------------------------------------------

def test_pipeline_reports_a_missing_baseline_honestly():
    """With no profile there is no baseline, and the result must say so."""
    from ai.pipeline import analyze_network

    result = analyze_network(ap(ssid="Never_Configured_Network"), None)
    assert result.anomaly_available is False
    assert result.classification == Classification.UNVERIFIED
    assert any("baseline" in reason for reason in result.reasons)


def test_pipeline_reports_a_present_baseline_honestly():
    """A configured profile gives a real measurement, flagged as available."""
    from ai.pipeline import analyze_network

    result = analyze_network(ap(), AIRPORT_PROFILE)
    assert result.anomaly_available is True
    assert 0.0 <= result.anomaly_score <= 1.0


def test_default_detector_is_cached():
    set_default_detector(None)
    first = get_default_detector()
    assert get_default_detector() is first
    set_default_detector(None)


def test_fit_networks_accepts_raw_observations():
    networks = [ap(bssid=b, channel=c, frequency=f) for b, c, f in [
        ("AA:BB:CC:11:22:33", 36, 5180), ("AA:BB:CC:11:22:34", 40, 5200),
        ("AA:BB:CC:11:22:35", 44, 5220), ("AA:BB:CC:11:22:36", 48, 5240),
    ]]
    det = AnomalyDetector().fit_networks(networks)
    assert det.is_fitted
    assert det.score(networks[0]).available


def test_fit_networks_rejects_a_baseline_below_the_minimum():
    with pytest.raises(ValueError):
        AnomalyDetector().fit_networks(three_legit_aps()[:2])


def test_score_matrix_matches_individual_scoring(detector):
    networks = three_legit_aps()
    comparisons = [compare_to_profile(n, AIRPORT_PROFILE) for n in networks]
    from ai.features import build_feature_matrix

    matrix_results = detector.score_matrix(build_feature_matrix(networks, comparisons))
    for network, comparison, matrix_result in zip(networks, comparisons, matrix_results):
        assert matrix_result.anomaly_score == detector.score(network, comparison).anomaly_score


def test_no_profile_comparison_still_scores(detector):
    """A brand-new location must still get a number, not a crash."""
    result = detector.score(ap(ssid="Never_Seen_Network", bssid="AA:BB:CC:DD:EE:01"))
    assert result.available
    assert 0.0 <= result.anomaly_score <= 1.0
