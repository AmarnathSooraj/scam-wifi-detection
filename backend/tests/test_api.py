"""API tests for the read-only and analysis routes.

These assert on the service's *contract* - which endpoints exist, what they
report, and what they refuse to do - rather than on specific risk numbers, so
they survive a retune of the scoring weights.
"""

from __future__ import annotations

import pytest

from .conftest import KNOWN_BSSID, ROGUE_BSSID, TRUSTED_SSID

pytestmark = pytest.mark.usefixtures("store_env")


# --- /health -------------------------------------------------------------


def test_health_is_static_and_never_touches_the_radio(client, no_adapter):
    """A health check must not depend on Wi-Fi hardware being present."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# --- /verdicts -----------------------------------------------------------


def test_verdicts_publishes_the_vocabulary_and_the_accuracy_caveat(client):
    """A dashboard must learn the wording from the server, not hardcode it."""
    payload = client.get("/verdicts").json()
    assert payload["verdicts"], "the verdict vocabulary must not be empty"
    assert payload["accuracy_note"]
    # POTENTIAL_FAKE means "may be impersonating", not "proven malicious".
    assert "POTENTIAL_FAKE" in payload["verdicts"]


# --- /profiles -----------------------------------------------------------


def test_profiles_lists_configured_ssids(client):
    payload = client.get("/profiles").json()
    assert payload["count"] == 1
    assert payload["ssids"] == [TRUSTED_SSID]
    assert payload["store_path"]


def test_profiles_reports_an_empty_store_honestly(client, store_env):
    """A site that has vouched for nothing is a valid, non-error state."""
    import json

    path = store_env()
    path.write_text(json.dumps({"profiles": []}), encoding="utf-8")
    assert client.get("/profiles").json() == {"count": 0, "ssids": [], "store_path": str(path)}


def test_corrupt_profile_file_is_loud_not_silently_empty(client, store_env):
    """A broken config must surface as 500, not as a quietly healthy system."""
    store_env().write_text("{ not json", encoding="utf-8")
    response = client.get("/profiles")
    assert response.status_code == 500
    assert response.json()["detail"]["error"] == "ProfileStoreError"


# --- /scan ---------------------------------------------------------------


def test_scan_analyses_a_real_scan_result(client, fake_scan):
    payload = client.post("/scan", params={"settle": 0.0}).json()
    assert payload["source"] == "live-scan"
    assert payload["interface"] == "wlo1"
    assert payload["network_count"] == 3
    assert set(payload["verdict_counts"]) >= {"TRUSTED", "POTENTIAL_FAKE"}
    # Every result carries an explanation; a bare score is not acceptable.
    for result in payload["results"]:
        assert result["reasons"]


def test_scan_flags_the_rogue_and_trusts_the_known_bssids(client, fake_scan):
    payload = client.post("/scan", params={"settle": 0.0}).json()
    by_bssid = {r["bssid"]: r for r in payload["results"]}
    assert by_bssid[KNOWN_BSSID]["classification"] == "TRUSTED"
    assert by_bssid[ROGUE_BSSID]["verdict"] == "POTENTIAL_FAKE"
    assert payload["flagged_count"] == 1
    assert payload["flagged"][0]["bssid"] == ROGUE_BSSID


def test_scan_returns_503_with_a_reason_when_the_radio_is_absent(client, no_adapter):
    """No adapter must produce a clear 503, never an empty or invented scan."""
    response = client.post("/scan", params={"settle": 0.0})
    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["error"] == "NoWifiAdapterError"
    assert detail["hint"]


def test_scan_rejects_an_out_of_range_settle(client, fake_scan):
    assert client.post("/scan", params={"settle": 9999.0}).status_code == 422


# --- /flagged ------------------------------------------------------------


def test_flagged_returns_only_the_worst_offenders(client, fake_scan):
    payload = client.get("/flagged", params={"settle": 0.0}).json()
    assert payload["flagged_count"] == 1
    assert [f["bssid"] for f in payload["flagged"]] == [ROGUE_BSSID]
    assert payload["verdict_counts"]["TRUSTED"] == 2


def test_flagged_also_fails_loudly_without_an_adapter(client, no_adapter):
    assert client.get("/flagged").status_code == 503


# --- /analyze ------------------------------------------------------------


def test_analyze_scores_supplied_observations_without_a_scan(client, fake_scan):
    """``/analyze`` must not occupy the radio: the fake scan records no calls."""
    response = client.post(
        "/analyze",
        json={
            "networks": [
                {
                    "ssid": TRUSTED_SSID,
                    "bssid": KNOWN_BSSID,
                    "signal": -50,
                    "channel": 149,
                    "frequency": 5745,
                    "security": "WPA1/WPA2",
                }
            ]
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["source"] == "supplied-observations"
    assert payload["results"][0]["classification"] == "TRUSTED"
    assert fake_scan == [], "/analyze must not perform a scan"


def test_analyze_with_no_profiles_reports_unverified_not_suspicious(client, fake_scan):
    """Without configuration the honest answer is UNVERIFIED, not an alarm."""
    payload = client.post(
        "/analyze",
        json={
            "use_profiles": False,
            "networks": [
                {"ssid": "Somewhere-New", "bssid": ROGUE_BSSID, "signal": -40, "channel": 6}
            ],
        },
    ).json()
    result = payload["results"][0]
    assert result["verdict"] == "UNVERIFIED"
    assert "NO_TRUSTED_PROFILE" in result["indicators"]


def test_analyze_accepts_an_empty_payload(client, fake_scan):
    payload = client.post("/analyze", json={}).json()
    assert payload["network_count"] == 0
    assert payload["results"] == []
