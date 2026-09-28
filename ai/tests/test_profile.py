"""Tests for trusted-profile comparison and the provisional baseline."""

from __future__ import annotations

import pytest

from ai.models import TrustedProfile, WiFiNetwork
from ai.trusted_profile import (
    MIN_PROVISIONAL_OBSERVATIONS,
    ProvisionalBaseline,
    band_of_channel,
    band_of_frequency,
    build_provisional_profile,
    compare_to_profile,
    load_profiles,
    nearest_value,
    profile_for_ssid,
)

from .conftest import AIRPORT_PROFILE, ap, three_legit_aps


# --- normalisation -------------------------------------------------------

def test_bssid_notation_is_normalised():
    """Profiles and scans will not agree on MAC notation; they must still match."""
    for spelling in ("AA:BB:CC:11:22:33", "aa-bb-cc-11-22-33", "aabbcc112233", "AA:BB:CC:11:22:33 "):
        assert compare_to_profile(ap(bssid=spelling), AIRPORT_PROFILE).known_bssid is True


def test_invalid_bssid_is_rejected_not_guessed():
    assert compare_to_profile(ap(bssid="not-a-mac"), AIRPORT_PROFILE).known_bssid is None
    assert WiFiNetwork.from_dict({"bssid": "zz"}).bssid == ""


# --- tri-state comparison ------------------------------------------------

def test_full_match_reports_profile_match():
    comparison = compare_to_profile(ap(), AIRPORT_PROFILE)
    assert comparison.has_profile
    assert comparison.known_bssid is True
    assert comparison.security_match is True
    assert comparison.channel_expected is True
    assert comparison.frequency_expected is True
    assert comparison.vendor_known is True
    assert comparison.deviation_count == 0
    assert comparison.profile_match is True


def test_unknown_bssid_is_false_not_absent():
    comparison = compare_to_profile(ap(bssid="BB:CC:DD:44:55:66"), AIRPORT_PROFILE)
    assert comparison.known_bssid is False
    assert comparison.deviation_count == 1
    assert comparison.profile_match is False


def test_profile_for_a_different_ssid_does_not_apply():
    comparison = compare_to_profile(ap(), dict(AIRPORT_PROFILE, ssid="Some_Other_Network"))
    assert comparison.has_profile is False
    assert comparison.known_bssid is None


def test_no_profile_leaves_everything_unknown():
    comparison = compare_to_profile(ap(), None)
    assert comparison.has_profile is False
    assert comparison.known_bssid is None
    assert comparison.security_match is None
    assert comparison.channel_expected is None
    assert comparison.deviation_count == 0


def test_empty_expectation_is_no_opinion_not_mismatch():
    """A sparse profile must not flag every AP."""
    sparse = {"ssid": "Airport_Free_WiFi", "known_bssids": ["AA:BB:CC:11:22:33"]}
    comparison = compare_to_profile(ap(vendor="Whatever", security="OPEN", channel=6), sparse)
    assert comparison.security_match is None
    assert comparison.channel_expected is None
    assert comparison.vendor_known is None
    assert comparison.deviation_count == 0


# --- security matching semantics ----------------------------------------

@pytest.mark.parametrize(
    "observed, expected, result",
    [
        ("WPA2", ["WPA2"], True),
        ("WPA2/WPA3", ["WPA2"], True),          # a superset is consistent
        ("WPA3", ["WPA2"], False),              # different protocol
        ("OPEN", ["WPA2"], False),
        ("OPEN", ["OPEN"], True),
        ("WPA2", ["WPA2", "WPA3"], True),
        (None, ["WPA2"], None),                 # unknown, not mismatch
        ("WPA2", [], None),                     # no expectation
    ],
)
def test_security_matching_matrix(observed, expected, result):
    comparison = compare_to_profile(ap(security=observed), dict(AIRPORT_PROFILE, security=expected))
    assert comparison.security_match is result


# --- deviation bookkeeping ----------------------------------------------

def test_deviation_counts_only_disagreements_with_an_expectation():
    comparison = compare_to_profile(
        ap(bssid="BB:CC:DD:44:55:66", security="OPEN", channel=6, vendor="Other"), AIRPORT_PROFILE
    )
    # unknown bssid + security + channel + vendor; frequency was still 5180.
    assert comparison.deviation_count == 4
    assert comparison.expectation_count == 5


def test_deviation_distance_is_reported_for_explanations():
    comparison = compare_to_profile(ap(channel=6), AIRPORT_PROFILE)
    assert comparison.channel_deviation == 30      # nearest expected is 36
    assert comparison.channel_expected is False
    # Only the channel was changed, so the frequency must NOT be implicated.
    assert comparison.frequency_expected is True
    assert comparison.deviation_count == 1


# --- band helpers --------------------------------------------------------

@pytest.mark.parametrize(
    "freq, band", [(2412, 2.4), (2437, 2.4), (5180, 5.0), (5745, 5.0), (6115, 6.0)]
)
def test_band_of_frequency(freq, band):
    assert band_of_frequency(freq) == band


@pytest.mark.parametrize("channel, band", [(1, 2.4), (6, 2.4), (11, 2.4), (36, 5.0), (149, 5.0)])
def test_band_of_channel(channel, band):
    assert band_of_channel(channel) == band


def test_band_helpers_return_none_for_missing_values():
    assert band_of_frequency(None) is None
    assert band_of_channel(None) is None


def test_nearest_value_reports_distance():
    assert nearest_value(6, [36, 40, 44, 48]) == (36, 30)
    assert nearest_value(None, [36]) == (None, None)
    assert nearest_value(36, []) == (None, None)


# --- provisional baseline ------------------------------------------------

def test_single_observation_is_not_a_baseline():
    assert build_provisional_profile("Net", [ap()]) is None


def test_minimum_observations_required():
    observations = three_legit_aps()
    assert len(observations) < MIN_PROVISIONAL_OBSERVATIONS + 1
    assert build_provisional_profile("Airport_Free_WiFi", observations, min_observations=3) is not None


def test_provisional_profile_is_flagged_and_never_trusted():
    profile = build_provisional_profile("Airport_Free_WiFi", three_legit_aps())
    assert profile.provisional is True
    assert compare_to_profile(three_legit_aps()[0], profile).profile_match is False


def test_provisional_baseline_learns_the_dominant_security():
    """A single OPEN AP among WPA2 peers must not become 'expected'."""
    observations = three_legit_aps() + [ap(bssid="BB:CC:DD:44:55:66", security="OPEN")]
    profile = build_provisional_profile("Airport_Free_WiFi", observations)
    assert profile.security == ["WPA2"]
    comparison = compare_to_profile(observations[3], profile)
    assert comparison.security_match is False
    assert comparison.known_bssid is True, "the rogue BSSID was seen in the baseline"


def test_provisional_baseline_accepts_unanimous_security():
    observations = three_legit_aps()
    profile = build_provisional_profile("Airport_Free_WiFi", observations)
    assert profile.security == ["WPA2"]
    assert compare_to_profile(observations[0], profile).security_match is True


def test_provisional_baseline_keeps_many_channels():
    """A network legitimately spans channels; each is seen once."""
    profile = build_provisional_profile("Airport_Free_WiFi", three_legit_aps())
    assert profile.expected_channels == [36, 40, 44]


def test_provisional_baseline_ignores_other_ssids():
    observations = three_legit_aps() + [ap(ssid="Other_Net", bssid="BB:CC:DD:44:55:66")]
    profile = build_provisional_profile("Airport_Free_WiFi", observations)
    assert profile is not None
    assert "BB:CC:DD:44:55:66" not in profile.known_bssids


def test_provisional_baseline_accumulates_across_scans():
    baseline = ProvisionalBaseline()
    # Two observations are below the minimum of three: not a baseline yet.
    assert baseline.update(three_legit_aps()[:2]).get("Airport_Free_WiFi") is None
    profiles = baseline.update(three_legit_aps())
    assert "Airport_Free_WiFi" in profiles
    assert baseline.observations("Airport_Free_WiFi") == 5


def test_provisional_baseline_resets():
    baseline = ProvisionalBaseline()
    baseline.update(three_legit_aps())
    baseline.update(three_legit_aps())
    baseline.reset()
    assert baseline.observations("Airport_Free_WiFi") == 0


# --- loading -------------------------------------------------------------

def test_load_profiles_accepts_several_shapes():
    one = {"ssid": "A", "known_bssids": ["AA:BB:CC:DD:EE:FF"]}
    assert len(load_profiles(one)) == 1
    assert len(load_profiles([one, dict(one, ssid="B")])) == 2
    assert len(load_profiles({"profiles": [one]})) == 1
    assert load_profiles(None) == []


def test_profile_for_ssid_selects_the_right_one():
    profiles = [dict(AIRPORT_PROFILE, ssid="A"), dict(AIRPORT_PROFILE, ssid="B")]
    assert profile_for_ssid(profiles, "B").ssid == "B"
    assert profile_for_ssid(profiles, "C") is None


def test_profile_round_trips_through_dict():
    original = TrustedProfile.from_dict(AIRPORT_PROFILE)
    assert TrustedProfile.from_dict(original.to_dict()).to_dict() == original.to_dict()
