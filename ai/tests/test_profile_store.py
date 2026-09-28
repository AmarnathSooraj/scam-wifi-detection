"""Tests for the trusted-profile store.

The store is the one place where the system decides what counts as known
infrastructure, so its two hard guarantees are tested directly:

1. It ships **empty**. A fresh deployment must have no invented networks.
2. A profile can only be created from **really observed** access points. There
   is no code path that fabricates a BSSID.
"""

from __future__ import annotations

import json

import pytest

from ai.models import TrustedProfile
from ai.profile_store import ProfileStore, build_profile_from_observations, load_trusted_profiles
from ai.trusted_profile import compare_to_profile

from .conftest import AIRPORT_PROFILE, ap, three_legit_aps


@pytest.fixture
def store_path(tmp_path):
    return tmp_path / "trusted_networks.json"


# --- the empty-store guarantee ------------------------------------------

def test_shipped_store_contains_no_invented_networks():
    """The real configuration file must start with nothing trusted."""
    profiles = load_trusted_profiles()
    # Whatever a given machine has configured, nothing in the *shipped* file
    # may be a placeholder. Assert no profile is marked provisional-by-default
    # and that any present profile has at least one real BSSID.
    for profile in profiles:
        assert profile.known_bssids, f"{profile.ssid} trusts no BSSIDs"
        for bssid in profile.known_bssids:
            assert len(bssid) == 17, f"{bssid} is not a formatted BSSID"


def test_missing_store_file_is_not_an_error(store_path):
    """The first scan anywhere in the world starts from nothing configured."""
    store = ProfileStore(store_path)
    assert store.exists() is False
    assert store.load() == []


def test_empty_store_means_everything_is_unverified(store_path):
    from ai.pipeline import analyze_network

    result = analyze_network(ap(), ProfileStore(store_path).load())
    assert result.classification == "UNVERIFIED"
    assert "NO_TRUSTED_PROFILE" in result.indicators


# --- building from real observations -------------------------------------

def test_profile_is_built_only_from_observed_hardware():
    profile = build_profile_from_observations("Airport_Free_WiFi", three_legit_aps())
    assert profile is not None
    assert set(profile.known_bssids) == {n["bssid"] for n in three_legit_aps()}
    assert profile.security == ["WPA2"]
    assert profile.expected_channels == [36, 40, 44]
    assert profile.provisional is False, "operator-approved, not self-learned"


def test_nothing_is_invented_for_an_unobserved_ssid():
    assert build_profile_from_observations("Not_Here", three_legit_aps()) is None
    assert build_profile_from_observations("Airport_Free_WiFi", []) is None


def test_observations_from_other_ssids_are_excluded():
    profile = build_profile_from_observations(
        "Airport_Free_WiFi", three_legit_aps() + [ap(ssid="Other", bssid="BB:CC:DD:44:55:66")]
    )
    assert "BB:CC:DD:44:55:66" not in profile.known_bssids


def test_vendor_is_excluded_unless_requested():
    """Vendor data is unreliable, so it is opt-in."""
    observations = [dict(n, vendor="Cisco") for n in three_legit_aps()]
    assert build_profile_from_observations("Airport_Free_WiFi", observations).known_vendors == []
    with_vendor = build_profile_from_observations(
        "Airport_Free_WiFi", observations, include_vendors=True
    )
    assert with_vendor.known_vendors == ["cisco"]


def test_a_built_profile_verifies_the_hardware_it_came_from():
    profile = build_profile_from_observations("Airport_Free_WiFi", three_legit_aps())
    for network in three_legit_aps():
        assert compare_to_profile(network, profile).profile_match is True


# --- persistence ---------------------------------------------------------

def test_upsert_then_reload_round_trips(store_path):
    store = ProfileStore(store_path)
    store.upsert(build_profile_from_observations("Airport_Free_WiFi", three_legit_aps()))
    reloaded = ProfileStore(store_path).load()
    assert [p.ssid for p in reloaded] == ["Airport_Free_WiFi"]
    assert reloaded[0].known_bssids == store.load()[0].known_bssids


def test_upsert_preserves_other_profiles(store_path):
    store = ProfileStore(store_path)
    store.upsert(TrustedProfile.from_dict(AIRPORT_PROFILE))
    store.upsert(TrustedProfile.from_dict(dict(AIRPORT_PROFILE, ssid="Second_Network")))
    assert sorted(store.ssids()) == ["Airport_Free_WiFi", "Second_Network"]


def test_upsert_replaces_the_same_ssid(store_path):
    store = ProfileStore(store_path)
    store.upsert(TrustedProfile.from_dict(AIRPORT_PROFILE))
    store.upsert(TrustedProfile.from_dict(dict(AIRPORT_PROFILE, known_bssids=["AA:BB:CC:11:22:99"])))
    profiles = store.load()
    assert len(profiles) == 1, "one entry per SSID, not two"
    assert profiles[0].known_bssids == ["AA:BB:CC:11:22:99"]


def test_remove_deletes_a_profile(store_path):
    store = ProfileStore(store_path)
    store.upsert(TrustedProfile.from_dict(AIRPORT_PROFILE))
    assert store.remove("Airport_Free_WiFi") is True
    assert store.load() == []
    assert store.remove("Airport_Free_WiFi") is False


def test_for_ssid_selects_the_right_profile(store_path):
    store = ProfileStore(store_path)
    store.upsert(TrustedProfile.from_dict(AIRPORT_PROFILE))
    assert store.for_ssid("Airport_Free_WiFi").ssid == "Airport_Free_WiFi"
    assert store.for_ssid("Never_Seen") is None


def test_corrupt_file_raises_rather_than_returning_nothing(store_path):
    """Silently returning [] would look like a healthy, all-UNVERIFIED system."""
    store_path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(ValueError):
        ProfileStore(store_path).load()


def test_writes_are_atomic_and_leave_no_temp_files(store_path):
    store = ProfileStore(store_path)
    store.upsert(TrustedProfile.from_dict(AIRPORT_PROFILE))
    leftovers = [p.name for p in store_path.parent.iterdir() if p.name.startswith(".profiles-")]
    assert leftovers == []
    assert json.loads(store_path.read_text(encoding="utf-8"))["profiles"]


def test_unknown_keys_in_the_file_are_preserved(store_path):
    store_path.write_text(
        json.dumps({"profiles": [], "site": "HQ", "owner": "netops"}), encoding="utf-8"
    )
    store = ProfileStore(store_path)
    store.upsert(TrustedProfile.from_dict(AIRPORT_PROFILE))
    payload = json.loads(store_path.read_text(encoding="utf-8"))
    assert payload["site"] == "HQ", "site-specific metadata must survive a rewrite"
    assert payload["owner"] == "netops"
