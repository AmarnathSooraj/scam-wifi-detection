"""Tests for feature extraction.

Two properties matter most and are asserted throughout:

* the vector is always the same length, in the same order, and always finite;
* categorical security is one-hot encoded, so the model cannot invent an
  ordering such as "WPA2 is 1 away from OPEN".
"""

from __future__ import annotations

import math

import pytest

from ai.features import (
    FEATURE_NAMES,
    IMPUTE_BAND,
    IMPUTE_FREQUENCY,
    IMPUTE_SIGNAL,
    MAX_SCALED_DEVIATION,
    build_feature_matrix,
    extract_features,
    feature_row,
)
from ai.models import ProfileComparison
from ai.trusted_profile import compare_to_profile

from .conftest import AIRPORT_PROFILE, ap


def test_feature_vector_has_exact_documented_layout():
    features = extract_features(ap())
    assert list(features) == list(FEATURE_NAMES)
    assert len(features) == len(FEATURE_NAMES)
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES), "feature names must be unique"


def test_all_features_are_finite_floats():
    features = extract_features(ap())
    for name, value in features.items():
        assert isinstance(value, float), name
        assert math.isfinite(value), f"{name} was {value}"


def test_fully_populated_observation_sets_no_missing_flags():
    features = extract_features(ap())
    assert features["signal_missing"] == 0.0
    assert features["band_missing"] == 0.0
    assert features["security_missing"] == 0.0
    assert features["signal"] == -45.0
    assert features["band_ghz"] == 5.0


def test_missing_core_fields_are_imputed_and_flagged():
    """A missing field must be distinguishable from a measured one."""
    features = extract_features({"ssid": "X", "bssid": "AA:BB:CC:DD:EE:FF"})
    assert features["signal"] == IMPUTE_SIGNAL
    assert features["signal_missing"] == 1.0
    assert features["frequency"] == IMPUTE_FREQUENCY
    assert features["band_ghz"] == IMPUTE_BAND
    assert features["band_missing"] == 1.0
    assert math.isfinite(features["signal"])


def test_optional_fields_absent_does_not_change_the_vector_shape():
    minimal = extract_features({"ssid": "X", "bssid": "AA:BB:CC:DD:EE:FF", "signal": -50,
                                "channel": 36, "frequency": 5180, "security": "WPA2"})
    rich = extract_features(ap(vendor="Cisco", channel_width=80, wifi_standard="802.11ac"))
    assert list(minimal) == list(rich) == list(FEATURE_NAMES)


# --- security encoding ---------------------------------------------------

@pytest.mark.parametrize(
    "label, expected_column",
    [
        ("OPEN", "sec_open"),
        ("WEP", "sec_wep"),
        ("WPA2", "sec_wpa2"),
        ("WPA3", "sec_wpa3"),
        ("SAE", "sec_wpa3"),
    ],
)
def test_security_is_one_hot(label, expected_column):
    features = extract_features(ap(security=label))
    for column in ("sec_open", "sec_wep", "sec_wpa1", "sec_wpa2", "sec_wpa3", "sec_owe"):
        assert features[column] == (1.0 if column == expected_column else 0.0)


def test_security_one_hot_is_exclusive_not_ordinal():
    """OPEN and WPA2 must not be adjacent points on a numeric line."""
    open_features = extract_features(ap(security="OPEN"))
    wpa2_features = extract_features(ap(security="WPA2"))
    differing = [
        name for name in FEATURE_NAMES
        if open_features[name] != wpa2_features[name]
    ]
    # The only numeric difference is the documented strength rank; identity is
    # carried by disjoint one-hot columns.
    assert "sec_open" in differing and "sec_wpa2" in differing
    numeric_differences = [
        name for name in differing
        if not name.startswith("sec_") and name != "security_rank"
    ]
    assert numeric_differences == []


def test_unknown_security_is_flagged_not_assumed_open():
    """Missing security must not silently become "the AP is unencrypted"."""
    features = extract_features(ap(security=None))
    assert features["security_missing"] == 1.0
    assert features["sec_open"] == 0.0
    assert features["sec_wpa2"] == 0.0
    assert features["sec_other"] == 1.0


def test_composite_security_takes_the_strongest_category():
    features = extract_features(ap(security="WPA2/WPA3"))
    assert features["sec_wpa3"] == 1.0
    assert features["security_missing"] == 0.0


# --- profile agreement columns ------------------------------------------

def test_agreement_columns_reflect_a_matching_profile():
    comparison = compare_to_profile(ap(), AIRPORT_PROFILE)
    features = extract_features(ap(), comparison)
    assert features["known_bssid"] == 1.0
    assert features["security_match"] == 1.0
    assert features["channel_expected"] == 1.0
    assert features["frequency_expected"] == 1.0
    assert features["vendor_known"] == 1.0
    assert features["profile_available"] == 1.0
    assert features["deviation_count"] == 0.0


def test_absent_profile_is_distinct_from_agreeing_profile():
    """'no opinion' must not read as 'agrees'."""
    no_profile = extract_features(ap(), ProfileComparison())
    assert no_profile["profile_available"] == 0.0
    assert no_profile["has_profile_data"] == 0.0
    assert no_profile["known_bssid"] == 0.0
    assert no_profile["vendor_missing"] == 1.0


def test_deviation_magnitude_is_reported_and_clipped():
    comparison = compare_to_profile(ap(channel=6, frequency=2437), AIRPORT_PROFILE)
    features = extract_features(ap(channel=6, frequency=2437), comparison)
    assert features["channel_deviation"] > 0
    assert features["frequency_deviation"] > 0
    assert features["channel_deviation_scaled"] <= MAX_SCALED_DEVIATION
    assert features["frequency_deviation_scaled"] <= MAX_SCALED_DEVIATION
    assert features["deviation_count"] >= 1


def test_deviation_ratio_is_bounded():
    comparison = compare_to_profile(ap(security="OPEN", channel=6), AIRPORT_PROFILE)
    features = extract_features(ap(security="OPEN", channel=6), comparison)
    assert 0.0 <= features["deviation_ratio"] <= 1.0 + 1e-9


# --- batching ------------------------------------------------------------

def test_build_feature_matrix_is_rectangular_and_aligned():
    networks = [ap(), ap(bssid="AA:BB:CC:11:22:34", channel=40, frequency=5200), ap(security="OPEN")]
    rows = build_feature_matrix(networks)
    assert len(rows) == 3
    assert all(len(row) == len(FEATURE_NAMES) for row in rows)
    assert rows[0] == feature_row(extract_features(networks[0]))


def test_build_feature_matrix_accepts_comparisons_positionally():
    networks = [ap(), ap(bssid="BB:CC:DD:44:55:66")]
    comparisons = [
        compare_to_profile(networks[0], AIRPORT_PROFILE),
        compare_to_profile(networks[1], AIRPORT_PROFILE),
    ]
    rows = build_feature_matrix(networks, comparisons)
    assert rows[0][FEATURE_NAMES.index("known_bssid")] == 1.0
    assert rows[1][FEATURE_NAMES.index("known_bssid")] == 0.0


def test_empty_input_yields_empty_matrix():
    assert build_feature_matrix([]) == []


def test_garbage_input_never_produces_nan():
    """Hostile input must degrade, not poison the model matrix."""
    rows = build_feature_matrix([
        {},
        {"ssid": None, "bssid": "not-a-mac", "signal": "abc", "channel": None},
        {"ssid": "X", "bssid": "AA:BB:CC:DD:EE:FF", "signal": -9999, "channel": 99999},
    ])
    assert len(rows) == 3
    for row in rows:
        assert all(math.isfinite(v) for v in row)
