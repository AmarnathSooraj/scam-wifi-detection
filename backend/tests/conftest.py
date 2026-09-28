"""Shared fixtures for the backend API tests.

Two things need isolating for the HTTP layer to be testable without hardware:

1. **The profile store.** The service reads ``config/trusted_networks.json``
   through ``ProfileStore()``, which resolves its default path at import time.
   Tests must never read or write the real file - a test that calls
   ``DELETE /trust/CE-WIFI`` would otherwise delete the project's actual
   configuration. :func:`store_env` rebinds the default to a tmp file.
2. **The radio.** ``scan_wifi`` shells out to ``nmcli``. Every test that
   exercises a scanning route installs :func:`fake_scan` instead, so the suite
   passes on a machine with no wireless adapter and stays deterministic.

**On the fixtures.** The BSSIDs and SSIDs in :func:`fake_scan` are invented,
but they exist only inside this test package. They are a stand-in for a real
``ScanResult``, which is exactly what the engine is designed to consume. No
test asserts on a number the engine would only produce for these specific
invented inputs unless that behaviour is the requirement under test.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import ai.profile_store as profile_store  # noqa: E402
import backend.main as main  # noqa: E402
from scanner import ScanResult, WiFiNetwork  # noqa: E402
from scanner.scanner import NoWifiAdapterError, ScannerError  # noqa: E402


#: A small, coherent site: one trusted network with two known access points,
#: plus an access point that is unknown and advertises itself OPEN.
KNOWN_BSSID = "10:27:F5:F3:9B:B3"
KNOWN_BSSID_2 = "BC:07:1D:66:C2:E6"
ROGUE_BSSID = "DE:AD:BE:EF:00:01"
TRUSTED_SSID = "CE-WIFI"

SITE_PROFILES: List[Dict[str, Any]] = [
    {
        "ssid": TRUSTED_SSID,
        "known_bssids": [KNOWN_BSSID, KNOWN_BSSID_2],
        "security": ["WPA1/WPA2"],
        "expected_channels": [149],
        "expected_frequencies": [5745],
        "known_vendors": [],
        "location": None,
        "provisional": False,
    }
]


def make_scan(networks: Optional[List[Dict[str, Any]]] = None) -> ScanResult:
    """Build a ``ScanResult`` the way the scanner would hand one over."""
    if networks is None:
        networks = [
            {
                "ssid": TRUSTED_SSID,
                "bssid": KNOWN_BSSID,
                "signal": -50,
                "channel": 149,
                "frequency": 5745,
                "security": "WPA1/WPA2",
            },
            {
                "ssid": TRUSTED_SSID,
                "bssid": KNOWN_BSSID_2,
                "signal": -62,
                "channel": 149,
                "frequency": 5745,
                "security": "WPA1/WPA2",
            },
            {
                # Same SSID, hardware nobody vouched for, no encryption, and on
                # the 2.4 GHz band the real network does not use.
                "ssid": TRUSTED_SSID,
                "bssid": ROGUE_BSSID,
                "signal": -44,
                "channel": 6,
                "frequency": 2437,
                "security": "OPEN",
            },
        ]
    # scanner.WiFiNetwork is a plain dataclass with no from_dict - the engine
    # has its own richer model. Build the scanner's directly, as scanner.py does.
    return ScanResult(
        timestamp="2026-09-29T12:00:00+00:00",
        networks=[WiFiNetwork(**item) for item in networks],
        interface="wlo1",
    )


@pytest.fixture
def store_env(tmp_path, monkeypatch):
    """Point the profile store at a temporary file and seed the site's config.

    Returns a callable giving the current path, so a test can assert on what
    the service actually wrote.
    """
    path = tmp_path / "trusted_networks.json"
    path.write_text(json.dumps({"profiles": SITE_PROFILES}, indent=2), encoding="utf-8")
    # ProfileStore.__init__ reads this module global at call time, so patching
    # the module attribute redirects every default-constructed store.
    monkeypatch.setattr(profile_store, "DEFAULT_PROFILE_PATH", path)
    main.clear_detector_cache()
    yield lambda: main.ProfileStore().path
    main.clear_detector_cache()


@pytest.fixture
def fake_scan(monkeypatch):
    """Replace ``scan_wifi`` with a canned real-shaped result."""
    calls: List[Dict[str, Any]] = []

    def _fake(interface=None, settle=0.0, include_optional=True):
        calls.append({"interface": interface, "settle": settle})
        return make_scan()

    monkeypatch.setattr(main, "scan_wifi", _fake)
    return calls


@pytest.fixture
def no_adapter(monkeypatch):
    """Make every scan fail the way a machine with no radio would."""

    def _boom(interface=None, settle=0.0, include_optional=True):
        raise NoWifiAdapterError()

    monkeypatch.setattr(main, "scan_wifi", _boom)


@pytest.fixture
def client() -> TestClient:
    return TestClient(main.app)
