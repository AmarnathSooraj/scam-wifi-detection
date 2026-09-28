"""Tests for the mutating ``/trust`` routes.

The contract these enforce: a profile can only ever be built from a **real
scan**. The caller names an SSID; the adapter supplies the BSSIDs, security
and channels. That is what stops a caller from hand-writing a profile that
vouches for hardware the machine never heard - which would be a way to silence
detection for any network.
"""

from __future__ import annotations

import json

import pytest

from .conftest import KNOWN_BSSID, KNOWN_BSSID_2, ROGUE_BSSID, TRUSTED_SSID, make_scan

pytestmark = pytest.mark.usefixtures("store_env")


def _read(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


# --- POST /trust ---------------------------------------------------------


def test_trust_records_a_profile_built_from_the_scan(client, fake_scan, store_env):
    response = client.post("/trust", json={"ssid": TRUSTED_SSID, "settle": 0.0})
    assert response.status_code == 201

    payload = response.json()
    assert payload["trusted"] == TRUSTED_SSID
    assert payload["security"]

    # The profile is whatever the radio is advertising right now, including any
    # access point the operator has not actually verified. The endpoint records
    # reality; it does not adjudicate. An operator approving an SSID while an
    # impostor is beaconing it therefore also approves the impostor - which is
    # why this route is the one that must sit behind authentication.
    assert set(payload["known_bssids"]) == {KNOWN_BSSID, KNOWN_BSSID_2, ROGUE_BSSID}

    stored = _read(store_env())["profiles"]
    assert [p["ssid"] for p in stored] == [TRUSTED_SSID]


def test_trust_derives_ouis_from_the_recorded_bssids(client, fake_scan):
    """Vendor blocks are derived, never hand-maintained."""
    payload = client.post("/trust", json={"ssid": TRUSTED_SSID, "settle": 0.0}).json()
    assert payload["known_ouis"]


def test_trust_preserves_an_existing_location_label(client, fake_scan, store_env):
    """Re-approving a network with a label must not drop unrelated profiles."""
    client.post("/trust", json={"ssid": TRUSTED_SSID, "settle": 0.0, "location": "Terminal 2"})
    profiles = _read(store_env())["profiles"]
    terminal = next(p for p in profiles if p["ssid"] == TRUSTED_SSID)
    assert terminal["location"] == "Terminal 2"


def test_trust_rejects_an_ssid_that_is_not_broadcasting(client, fake_scan):
    """Approving a network we cannot hear would be a fiction."""
    response = client.post("/trust", json={"ssid": "Never-Seen", "settle": 0.0})
    assert response.status_code == 404
    detail = response.json()["detail"]
    assert detail["error"] == "SSIDNotObserved"
    assert TRUSTED_SSID in detail["observed_ssids"]


def test_trust_refuses_to_write_without_a_scan(client, no_adapter, store_env):
    """No adapter means no observations, so nothing may be written."""
    before = store_env().read_text(encoding="utf-8")
    response = client.post("/trust", json={"ssid": TRUSTED_SSID, "settle": 0.0})
    assert response.status_code == 503
    assert store_env().read_text(encoding="utf-8") == before


def test_trust_requires_a_non_empty_ssid(client, fake_scan):
    assert client.post("/trust", json={"ssid": "", "settle": 0.0}).status_code == 422


def test_trust_succeeds_against_a_sparse_observation(client, monkeypatch, store_env):
    """A beacon with only a BSSID is still enough to record."""
    import backend.main as main

    sparse = [{"ssid": "Bare-Bones", "bssid": "AA:BB:CC:DD:EE:FF"}]
    monkeypatch.setattr(main, "scan_wifi", lambda **kw: make_scan(sparse))

    payload = client.post("/trust", json={"ssid": "Bare-Bones", "settle": 0.0}).json()
    assert payload["known_bssids"] == ["AA:BB:CC:DD:EE:FF"]
    assert payload["expected_channels"] == []


# --- DELETE /trust/{ssid} ----------------------------------------------


def test_untrust_removes_the_profile(client, store_env):
    assert client.delete(f"/trust/{TRUSTED_SSID}").status_code == 200
    assert [p["ssid"] for p in _read(store_env())["profiles"]] == []


def test_untrusted_networks_drop_back_to_unverified(client, fake_scan, store_env):
    """Removing the profile must visibly change the verdict, not just the file."""
    client.delete(f"/trust/{TRUSTED_SSID}")
    payload = client.post("/scan", params={"settle": 0.0}).json()
    by_bssid = {r["bssid"]: r for r in payload["results"]}
    assert by_bssid[KNOWN_BSSID]["verdict"] == "UNVERIFIED"
    assert by_bssid[ROGUE_BSSID]["verdict"] == "UNVERIFIED"


def test_untrust_of_an_unknown_ssid_is_404(client, store_env):
    assert client.delete("/trust/Never-Trusted").status_code == 404


def test_untrust_needs_no_adapter(client, no_adapter, store_env):
    """Deleting configuration is not a scan and must stay available."""
    assert client.delete(f"/trust/{TRUSTED_SSID}").status_code == 200


# --- interaction with the analysis routes --------------------------------


def test_trusted_network_becomes_trusted_after_approval(client, monkeypatch, store_env):
    """The end-to-end point of the endpoint: approval changes the verdict."""
    import backend.main as main

    new_site = [
        {
            "ssid": "Newly-Approved",
            "bssid": "11:22:33:44:55:66",
            "signal": -55,
            "channel": 36,
            "frequency": 5180,
            "security": "WPA2",
        }
    ]
    monkeypatch.setattr(main, "scan_wifi", lambda **kw: make_scan(new_site))

    before = client.post("/scan", params={"settle": 0.0}).json()
    assert before["results"][0]["verdict"] == "UNVERIFIED"

    assert client.post("/trust", json={"ssid": "Newly-Approved", "settle": 0.0}).status_code == 201

    after = client.post("/scan", params={"settle": 0.0}).json()
    assert after["results"][0]["verdict"] == "TRUSTED"
    assert after["results"][0]["risk_score"] == 0


def test_a_corrupt_store_blocks_trusting_rather_than_overwriting(client, fake_scan, store_env):
    """Never clobber a config we could not read."""
    store_env().write_text("{ not json", encoding="utf-8")
    response = client.post("/trust", json={"ssid": TRUSTED_SSID, "settle": 0.0})
    assert response.status_code == 500
    assert store_env().read_text(encoding="utf-8") == "{ not json"
