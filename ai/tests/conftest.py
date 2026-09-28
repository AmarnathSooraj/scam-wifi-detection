"""Shared fixtures and helpers for the AI engine test suite.

The tests deliberately assert on *behaviour the brief requires* (unknown
BSSID is not malicious, duplicate SSIDs are normal, a new location yields
UNVERIFIED) rather than on incidental numbers, so they stay meaningful when
weights are retuned.

**On the synthetic data in this directory.** Unit tests need deterministic
input, and you cannot wait on live Wi-Fi hardware to assert that an
access point scoring 75 is classified ``HIGH_RISK``. The BSSIDs, SSIDs and
expected channels here are therefore invented - but they exist *only* inside
``ai/tests/`` and are never reachable from the application. Production data
comes from the real adapter via ``scanner.scan_wifi()``; the runtime loads no
fixture file of any kind.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

# Make the repository root importable so `import ai` works from any cwd.
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

#: Invented test inputs. Deliberately under tests/ and nowhere else.
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def load_fixture(name: str) -> Dict[str, Any]:
    """Load a synthetic scenario from ``ai/tests/fixtures/<name>.json``."""
    with (FIXTURES_DIR / f"{name}.json").open(encoding="utf-8") as handle:
        return json.load(handle)


def load_fixture_profiles() -> list:
    """Load the invented trusted profiles used by the unit tests."""
    from ai.trusted_profile import load_profiles

    return load_profiles(load_fixture("trusted_profiles"))


def resolve_fixture_scenario(name: str) -> Dict[str, Any]:
    """Load a synthetic scenario with its invented profile resolved.

    Mirrors what the application does with *real* data, but against test
    fixtures so the assertions stay deterministic.
    """
    from ai.models import TrustedProfile
    from ai.trusted_profile import profile_for_ssid

    data = load_fixture(name)
    ssid = data.get("trusted_profile")
    profiles = []
    if ssid:
        match = profile_for_ssid(load_fixture_profiles(), ssid)
        profiles = [match] if match else []
    return {
        "scenario": data.get("scenario", name),
        "description": data.get("description", ""),
        "profiles": profiles,
        "networks": data.get("networks", []),
    }


#: The demo profile: a WPA2 5 GHz network with five legitimate BSSIDs.
#: Multiple BSSIDs is the normal case, not a duplicate-SSID alert.
AIRPORT_PROFILE: Dict[str, Any] = {
    "ssid": "Airport_Free_WiFi",
    "location": "Terminal 2, Gates A-D",
    "known_bssids": [
        "AA:BB:CC:11:22:33",
        "AA:BB:CC:11:22:34",
        "AA:BB:CC:11:22:35",
        "AA:BB:CC:11:22:36",
        "AA:BB:CC:11:22:37",
    ],
    "security": ["WPA2"],
    "expected_channels": [36, 40, 44, 48],
    "expected_frequencies": [5180, 5200, 5220, 5240],
    "known_vendors": ["Cisco"],
}


def ap(**overrides: Any) -> Dict[str, Any]:
    """Build a scanner observation, overriding any field."""
    record: Dict[str, Any] = {
        "ssid": "Airport_Free_WiFi",
        "bssid": "AA:BB:CC:11:22:33",
        "signal": -45,
        "channel": 36,
        "frequency": 5180,
        "security": "WPA2",
        "vendor": "Cisco",
        "timestamp": "2026-09-28T19:30:00+00:00",
    }
    record.update(overrides)
    return record


def three_legit_aps() -> List[Dict[str, Any]]:
    """Three legitimate APs sharing one SSID - the brief's demo network."""
    return [
        ap(bssid="AA:BB:CC:11:22:33", channel=36, frequency=5180, signal=-45),
        ap(bssid="AA:BB:CC:11:22:34", channel=40, frequency=5200, signal=-48),
        ap(bssid="AA:BB:CC:11:22:35", channel=44, frequency=5220, signal=-51),
    ]


@pytest.fixture
def profile() -> Dict[str, Any]:
    return dict(AIRPORT_PROFILE)


@pytest.fixture(autouse=True)
def _clear_detector_cache():
    """Keep the per-profile detector cache from leaking between tests."""
    from ai.pipeline import clear_detector_cache

    clear_detector_cache()
    yield
    clear_detector_cache()
