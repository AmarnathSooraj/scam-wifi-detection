"""Tests for network identity and OUI (hardware vendor block) handling.

The claim under test: **an SSID is an advertised claim, not an identity.** The
BSSID is the per-device identifier, and its OUI is the only hardware signal
available when the scanner reports no vendor (nmcli does not).
"""

from __future__ import annotations

import pytest

from ai.identity import NetworkIdentity, OuiRegistry, identity_of, load_oui_registry, oui_of
from ai.models import TrustedProfile, normalise_oui
from ai.trusted_profile import compare_to_profile

from .conftest import ap, three_legit_aps
from .fixtures_scenarios import OFFICE_PROFILE


# --- OUI extraction ------------------------------------------------------

@pytest.mark.parametrize(
    "bssid, expected",
    [
        ("BC:07:1D:66:C2:E6", "BC:07:1D"),
        ("bc:07:1d:66:c2:e6", "BC:07:1D"),
        ("bc-07-1d-66-c2-e6", "BC:07:1D"),
        ("b c : 0 7 - 1 d : 6 6 : c 2 : e 6", "BC:07:1D"),
    ],
)
def test_oui_extracted_from_any_mac_notation(bssid, expected):
    assert oui_of(bssid) == expected


@pytest.mark.parametrize("bad", [None, "", "nope", "AA:BB", "ZZ:ZZ:ZZ:11:22:33"])
def test_invalid_bssid_yields_no_oui_rather_than_guessing(bad):
    """No OUI means 'no opinion', never a fabricated value."""
    assert oui_of(bad) == ""


@pytest.mark.parametrize(
    "value, expected",
    [("BC:07:1D", "BC:07:1D"), ("bc-07-1d", "BC:07:1D"), ("bc071d", "BC:07:1D"), ("nope", "")],
)
def test_oui_normalisation(value, expected):
    assert normalise_oui(value) == expected


# --- identity ------------------------------------------------------------

def test_identity_key_is_the_bssid_not_the_ssid():
    a = identity_of({"ssid": "Office_Net", "bssid": "10:27:F5:F3:9B:B1"})
    b = identity_of({"ssid": "Office_Net", "bssid": "BC:07:1D:66:C2:E1"})
    assert a.key != b.key, "two APs on one SSID are two identities"
    assert a.oui == "10:27:F5"
    assert b.oui == "BC:07:1D"


def test_identity_accepts_scanner_objects():
    from scanner.models import WiFiNetwork

    net = WiFiNetwork(ssid="CE-WIFI", bssid="10:27:F5:F3:9B:B3", channel=1, security="WPA1/WPA2")
    identity = identity_of(net)
    assert identity.bssid == "10:27:F5:F3:9B:B3"
    assert identity.oui == "10:27:F5"
    assert identity.to_dict()["ssid"] == "CE-WIFI"


def test_identity_degrades_on_garbage():
    identity = identity_of({"ssid": "X", "bssid": "garbage"})
    assert identity.bssid == ""
    assert identity.oui == ""
    assert identity.has_hardware_identity is False


# --- profile-side OUI expectations --------------------------------------

def test_expected_ouis_derive_automatically_from_known_bssids():
    """Operators must not maintain OUI lists by hand."""
    profile = TrustedProfile.from_dict(OFFICE_PROFILE)
    assert profile.known_ouis == ["10:27:F5", "BC:07:1D"]


def test_explicit_ouis_are_merged_with_derived_ones():
    profile = TrustedProfile.from_dict(dict(OFFICE_PROFILE, known_ouis=["aa:bb:cc"]))
    assert "AA:BB:CC" in profile.known_ouis
    assert "10:27:F5" in profile.known_ouis


def test_oui_comparison_is_tri_state():
    profile = TrustedProfile.from_dict(OFFICE_PROFILE)
    match = compare_to_profile({"ssid": "Office_Net", "bssid": "10:27:F5:00:00:01"}, profile)
    foreign = compare_to_profile({"ssid": "Office_Net", "bssid": "DE:AD:BE:00:00:01"}, profile)
    absent = compare_to_profile({"ssid": "Office_Net"}, profile)
    assert match.oui_known is True
    assert foreign.oui_known is False
    assert absent.oui_known is None, "no BSSID means no OUI opinion"


def test_oui_mismatch_is_not_counted_as_independent_when_bssid_already_unknown():
    """Regression guard for the independence principle.

    An unknown BSSID whose OUI is foreign is ONE fact ("this is a different
    device"), not two. Counting both let a single deviation trip the
    multi-deviation aggregator on its own.
    """
    profile = TrustedProfile.from_dict(OFFICE_PROFILE)
    comparison = compare_to_profile(
        {"ssid": "Office_Net", "bssid": "DE:AD:BE:00:00:01", "channel": 36,
         "frequency": 5180, "security": "WPA2"},
        profile,
    )
    assert comparison.known_bssid is False
    assert comparison.oui_known is False
    assert comparison.deviation_count == 1, "must not double-count one fact"


def test_oui_match_is_recorded_as_supporting_evidence():
    profile = TrustedProfile.from_dict(OFFICE_PROFILE)
    comparison = compare_to_profile(
        {"ssid": "Office_Net", "bssid": "10:27:F5:00:00:01", "channel": 36,
         "frequency": 5180, "security": "WPA2"},
        profile,
    )
    assert comparison.oui_known is True
    assert comparison.observed_oui == "10:27:F5"
    assert comparison.expected_ouis == ["10:27:F5", "BC:07:1D"]


# --- optional OUI registry ----------------------------------------------

def test_registry_ships_empty_and_is_optional():
    registry = load_oui_registry()
    assert len(registry) >= 0, "a missing registry must not raise"
    assert registry.vendor_of("10:27:F5") in (None, registry.vendor_of("10:27:F5"))


def test_registry_normalises_keys_on_lookup():
    registry = OuiRegistry({"10-27-f5": "Example Vendor"})
    assert registry.vendor_of("10:27:F5") == "Example Vendor"
    assert registry.vendor_of("1027f5") == "Example Vendor"
    assert registry.vendor_of("AA:BB:CC") is None
    assert registry.vendor_of(None) is None


def test_registry_ignores_malformed_entries():
    registry = OuiRegistry({"nope": "X", "10:27:F5": "Good", "AA:BB:CC": ""})
    assert len(registry) == 1
    assert registry.vendor_of("10:27:F5") == "Good"


def test_corrupt_registry_file_degrades_to_empty(tmp_path):
    bad = tmp_path / "oui.json"
    bad.write_text("{ not json", encoding="utf-8")
    assert len(load_oui_registry(bad)) == 0, "enrichment must never break a scan"


def test_missing_registry_file_degrades_to_empty(tmp_path):
    assert len(load_oui_registry(tmp_path / "absent.json")) == 0
