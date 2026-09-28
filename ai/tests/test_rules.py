"""Tests for the explainable cybersecurity rules.

The central claim under test: rules produce *evidence*, and no single piece of
evidence - notably an unknown BSSID - is treated as proof of malice.
"""

from __future__ import annotations

import pytest

from ai.models import ProfileComparison
from ai.rules import INDICATORS, evaluate_rules, summarize
from ai.trusted_profile import compare_to_profile

from .conftest import AIRPORT_PROFILE, ap, three_legit_aps


def rules_for(network, profile=AIRPORT_PROFILE, expected_security=None):
    if profile is None:
        comparison = ProfileComparison()
    else:
        comparison = compare_to_profile(network, profile)
    security = expected_security
    if security is None and profile is not None:
        security = profile.get("security", [])
    return evaluate_rules(network, comparison, expected_security=security)


# --- unknown BSSID -------------------------------------------------------

def test_unknown_bssid_is_evidence_not_a_verdict():
    """An unknown BSSID raises suspicion; it must not by itself be damning.

    A foreign OUI is also reported here, but it is *implied* by the unknown
    BSSID rather than independent of it, so it does not trip the
    multi-deviation aggregator on its own.
    """
    result = rules_for(ap(bssid="BB:CC:DD:44:55:66"))
    assert result.has("UNKNOWN_BSSID")
    # Nothing from the security or radio-plan families may appear.
    assert not result.has("SECURITY_MISMATCH")
    assert not result.has("CHANNEL_MISMATCH")
    assert not result.has("BAND_MISMATCH")
    # And it must not aggregate into the "several things are wrong" signal.
    assert not result.has("PROFILE_DEVIATION")


def test_known_bssid_produces_no_unknown_indicator():
    assert not rules_for(ap()).has("UNKNOWN_BSSID")


def test_profile_without_bssid_list_expresses_no_opinion():
    sparse = {"ssid": "Airport_Free_WiFi", "security": ["WPA2"], "expected_channels": [36]}
    result = rules_for(ap(), profile=sparse)
    assert not result.has("UNKNOWN_BSSID")
    assert any("does not enumerate BSSIDs" in note for note in result.mitigating)


# --- security ------------------------------------------------------------

def test_security_mismatch_is_reported_with_both_values():
    result = rules_for(ap(security="OPEN"))
    assert result.has("SECURITY_MISMATCH")
    assert any("OPEN" in reason and "WPA2" in reason for reason in result.reasons)


def test_open_under_protected_ssid_is_a_downgrade():
    result = rules_for(ap(security="OPEN"))
    assert result.has("SECURITY_DOWNGRADE")
    assert any("OPEN" in reason for reason in result.reasons)


def test_upgrade_is_a_mismatch_but_not_a_downgrade():
    """WPA3 where WPA2 was expected is unexpected, but not an attack."""
    result = rules_for(ap(security="WPA3"))
    assert result.has("SECURITY_MISMATCH")
    assert not result.has("SECURITY_DOWNGRADE")


def test_wep_where_wpa2_expected_is_a_downgrade():
    result = rules_for(ap(security="WEP"))
    assert result.has("SECURITY_DOWNGRADE")


def test_matching_security_is_silent():
    result = rules_for(ap(security="WPA2"))
    assert not result.has("SECURITY_MISMATCH")
    assert not result.has("SECURITY_DOWNGRADE")


def test_unknown_security_is_not_called_a_mismatch():
    """We cannot assert a mismatch from a field we never received."""
    result = rules_for(ap(security=None))
    assert not result.has("SECURITY_MISMATCH")
    assert not result.has("SECURITY_DOWNGRADE")


# --- channel / frequency / band -----------------------------------------

def test_channel_outside_expectation_is_reported():
    result = rules_for(ap(channel=6, frequency=2437))
    assert result.has("CHANNEL_MISMATCH")
    assert result.has("FREQUENCY_MISMATCH")
    assert result.has("BAND_MISMATCH")


def test_expected_channel_is_silent():
    assert not rules_for(ap(channel=44, frequency=5220)).has("CHANNEL_MISMATCH")


def test_missing_channel_is_not_a_channel_mismatch():
    result = rules_for(ap(channel=None, frequency=None))
    assert not result.has("CHANNEL_MISMATCH")
    assert not result.has("FREQUENCY_MISMATCH")
    assert result.has("MISSING_FIELDS")


# --- vendor --------------------------------------------------------------

def test_vendor_mismatch_is_reported_when_both_sides_know_the_vendor():
    result = rules_for(ap(vendor="Raspberry Pi Trading Ltd"))
    assert result.has("VENDOR_MISMATCH")


def test_vendor_check_is_skipped_when_observation_lacks_vendor():
    result = rules_for(ap(vendor=None))
    assert not result.has("VENDOR_MISMATCH")
    assert any("Vendor information unavailable" in note for note in result.mitigating)


def test_vendor_check_is_skipped_when_profile_lacks_vendors():
    no_vendors = dict(AIRPORT_PROFILE)
    no_vendors.pop("known_vendors")
    result = rules_for(ap(), profile=no_vendors)
    assert not result.has("VENDOR_MISMATCH")


# --- aggregation ---------------------------------------------------------

def test_multiple_deviations_aggregate():
    result = rules_for(ap(bssid="BB:CC:DD:44:55:66", security="OPEN", channel=6, frequency=2437))
    assert result.has("PROFILE_DEVIATION")
    assert any("deviate" in reason for reason in result.reasons)


def test_single_deviation_does_not_aggregate():
    """One disagreement is an observation, not a pattern."""
    result = rules_for(ap(bssid="BB:CC:DD:44:55:66"))
    assert not result.has("PROFILE_DEVIATION")


def test_clean_observation_is_fully_silent_and_mitigating():
    result = rules_for(ap())
    assert result.indicators == []
    assert result.mitigating, "a clean result must still explain itself"


# --- no profile ----------------------------------------------------------

def test_missing_profile_says_so_plainly():
    result = rules_for(ap(), profile=None)
    assert result.has("NO_TRUSTED_PROFILE")
    assert any("no established trusted profile" in reason for reason in result.reasons)


def test_missing_profile_never_claims_unknown_bssid():
    """With no profile, every BSSID is unknown - flagging them is noise."""
    result = rules_for(ap(), profile=None)
    assert not result.has("UNKNOWN_BSSID")


def test_provisional_profile_is_labelled_as_such():
    provisional = dict(AIRPORT_PROFILE, provisional=True)
    result = rules_for(ap(), profile=provisional)
    assert result.has("PROVISIONAL_PROFILE")
    assert not result.has("NO_TRUSTED_PROFILE")


# --- the headline requirement -------------------------------------------

def test_many_aps_sharing_one_ssid_raise_nothing():
    """The core anti-pattern: duplicate SSID must never be an indicator."""
    for index, network in enumerate(three_legit_aps()):
        result = rules_for(network)
        assert result.indicators == [], f"AP {index} raised {result.indicators}"


def test_five_aps_one_ssid_all_verified():
    seen = []
    for octet in range(0x33, 0x38):
        network = ap(bssid=f"AA:BB:CC:11:22:{octet:02X}")
        comparison = compare_to_profile(network, AIRPORT_PROFILE)
        seen.append(comparison.profile_match)
    assert seen == [True] * 5


# --- misc ----------------------------------------------------------------

def test_every_emitted_indicator_is_declared():
    network = ap(bssid="BB:CC:DD:44:55:66", security="OPEN", channel=6, frequency=2437, vendor="Other")
    result = rules_for(network)
    assert set(result.indicators) <= set(INDICATORS)


def test_summarize_never_returns_empty():
    """A score with no justification is unusable for a human reviewer."""
    for profile in (AIRPORT_PROFILE, None):
        result = rules_for(ap(), profile=profile)
        assert summarize(result, "TRUSTED")


def test_empty_rule_result_still_summarizes():
    from ai.models import RuleResult

    assert summarize(RuleResult(), "TRUSTED")
