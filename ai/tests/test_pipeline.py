"""End-to-end pipeline tests - the seven scenarios named in the brief.

Each test maps to one numbered requirement and states the expected outcome in
its name, so a failure reads as a failed requirement rather than a failed
assertion.
"""

from __future__ import annotations

import json

import pytest

from ai.models import Classification, TrustedProfile
from ai.pipeline import (
    analyze_network,
    analyze_networks,
    analyze_scan,
)
from ai.risk_engine import DEFAULT_CONFIG

from .conftest import AIRPORT_PROFILE, ap, resolve_fixture_scenario, three_legit_aps

ACCEPTABLE_LOW = {Classification.TRUSTED, Classification.LOW_RISK}


# --- Test 1: known BSSID, matching security, expected channel ------------

def test_1_known_bssid_matching_everything_is_low_risk():
    result = analyze_network(
        ap(bssid="AA:BB:CC:11:22:33", channel=36, frequency=5180, security="WPA2"),
        AIRPORT_PROFILE,
    )
    assert result.classification in ACCEPTABLE_LOW
    assert result.classification == Classification.TRUSTED
    assert result.risk_score == 0
    assert result.profile_match is True
    assert result.reasons


# --- Test 2: a different known BSSID on the same SSID --------------------

def test_2_duplicate_ssid_with_another_known_bssid_is_not_an_alert():
    """The headline requirement: one SSID, many BSSIDs, all legitimate."""
    for network in three_legit_aps():
        result = analyze_network(network, AIRPORT_PROFILE)
        assert result.classification in ACCEPTABLE_LOW, (network["bssid"], result.reasons)
        assert "UNKNOWN_BSSID" not in result.indicators


def test_2b_all_five_known_bssids_are_verified():
    results = analyze_networks(three_legit_aps(), profiles=[AIRPORT_PROFILE])
    assert all(r.classification == Classification.TRUSTED for r in results)
    assert len({r.bssid for r in results}) == 3


# --- Test 3: unknown BSSID only ------------------------------------------

def test_3_unknown_bssid_alone_is_unverified_not_high_risk():
    result = analyze_network(
        ap(bssid="BB:CC:DD:44:55:66", channel=36, frequency=5180, security="WPA2"),
        AIRPORT_PROFILE,
    )
    assert result.classification in (Classification.UNVERIFIED, Classification.LOW_RISK)
    assert result.classification != Classification.HIGH_RISK
    assert "UNKNOWN_BSSID" in result.indicators


def test_3b_unknown_bssid_is_elevated_but_bounded():
    result = analyze_network(ap(bssid="BB:CC:DD:44:55:66"), AIRPORT_PROFILE)
    assert 0 < result.risk_score < DEFAULT_CONFIG.suspicious_max
    assert any("not present in trusted infrastructure" in reason for reason in result.reasons)


# --- Test 4: unknown BSSID + security mismatch ---------------------------

def test_4_unknown_bssid_with_open_security_escalates():
    result = analyze_network(
        ap(bssid="BB:CC:DD:44:55:66", security="OPEN"), AIRPORT_PROFILE
    )
    assert result.classification in (Classification.SUSPICIOUS, Classification.HIGH_RISK)
    assert "SECURITY_MISMATCH" in result.indicators
    assert result.risk_score > DEFAULT_CONFIG.low_risk_max


# --- Test 5: the full rogue combination ----------------------------------

def test_5_full_rogue_profile_is_high_risk():
    result = analyze_network(
        ap(bssid="BB:CC:DD:44:55:66", signal=-55, channel=6, frequency=2437, security="OPEN"),
        AIRPORT_PROFILE,
    )
    assert result.classification == Classification.HIGH_RISK
    assert result.profile_match is False
    assert 75 <= result.risk_score <= 100


def test_5b_full_rogue_lists_every_piece_of_evidence():
    result = analyze_network(
        ap(bssid="BB:CC:DD:44:55:66", signal=-55, channel=6, frequency=2437, security="OPEN"),
        AIRPORT_PROFILE,
    )
    for indicator in ("UNKNOWN_BSSID", "SECURITY_MISMATCH", "CHANNEL_MISMATCH", "PROFILE_DEVIATION"):
        assert indicator in result.indicators, indicator
    assert len(result.reasons) >= 4
    # Each reason is a sentence a judge can read, not a code.
    assert all(isinstance(reason, str) and reason.strip() for reason in result.reasons)


def test_5c_demonstration_scenario_end_to_end():
    """The exact demo from the brief: 3 green APs and 1 red one."""
    networks = three_legit_aps() + [
        ap(bssid="BB:CC:DD:44:55:66", signal=-55, channel=6, frequency=2437, security="OPEN")
    ]
    report = analyze_scan(networks, profiles=[AIRPORT_PROFILE])
    by_bssid = {r["bssid"]: r for r in report["results"]}

    for bssid in ("AA:BB:CC:11:22:33", "AA:BB:CC:11:22:34", "AA:BB:CC:11:22:35"):
        assert by_bssid[bssid]["classification"] == Classification.TRUSTED
    assert by_bssid["BB:CC:DD:44:55:66"]["classification"] == Classification.HIGH_RISK

    # One SSID, four APs, grouped together for the dashboard.
    assert report["ssid_count"] == 1
    assert len(report["networks"]["Airport_Free_WiFi"]) == 4


# --- Test 6: no trusted profile at all ----------------------------------

def test_6_no_profile_yields_unverified():
    result = analyze_network(
        ap(ssid="ZRH_Guest_WiFi", bssid="11:22:33:44:55:01"), None
    )
    assert result.classification == Classification.UNVERIFIED
    assert "NO_TRUSTED_PROFILE" in result.indicators
    assert any("no established trusted profile" in reason for reason in result.reasons)


def test_6b_every_ap_at_an_unknown_location_is_not_summoned():
    """A new airport must not light up entirely red."""
    networks = [
        ap(ssid="ZRH_Guest_WiFi", bssid="11:22:33:44:55:%02d" % i, channel=c, frequency=f)
        for i, c, f in [(1, 36, 5180), (2, 40, 5200), (3, 44, 5220)]
    ]
    results = analyze_networks(networks, profiles=[])
    assert all(r.classification != Classification.HIGH_RISK for r in results)
    assert all(r.classification in (Classification.UNVERIFIED, Classification.LOW_RISK) for r in results)


def test_6c_engine_distinguishes_unknown_consistent_from_unknown_anomalous():
    """The three states the brief asks the engine to separate."""
    consistent = [ap(ssid="New_Net", bssid="11:22:33:44:55:0%d" % i, channel=c, frequency=f)
                  for i, c, f in [(1, 36, 5180), (2, 40, 5200), (3, 44, 5220)]]
    anomalous = consistent + [ap(ssid="New_Net", bssid="99:88:77:66:55:0A",
                                  channel=11, frequency=2462, security="OPEN")]
    # profiles=None enables the on-site provisional baseline; a new location is
    # exactly the case it exists for.
    results = analyze_networks(anomalous, profiles=None)
    scores = {r.bssid: r.risk_score for r in results}
    rogue = "99:88:77:66:55:0A"
    assert scores[rogue] > max(v for k, v in scores.items() if k != rogue)
    rogue_result = next(r for r in results if r.bssid == rogue)
    assert "SECURITY_MISMATCH" in rogue_result.indicators


def test_6d_empty_profile_list_means_configured_but_nothing_matches():
    """`profiles=[]` is a deliberate statement, not a request to self-learn.

    An operator who has configured infrastructure must not have unknown SSIDs
    silently absorbed into a self-learned baseline, so an explicit empty list
    yields UNVERIFIED with no provisional profile.
    """
    networks = three_legit_aps()
    results = analyze_networks(networks, profiles=[])
    assert all(r.classification == Classification.UNVERIFIED for r in results)
    assert all("PROVISIONAL_PROFILE" not in r.indicators for r in results)


# --- Test 7: missing optional fields must not crash ----------------------

def test_7_observation_with_only_the_minimal_contract():
    result = analyze_network(
        {"ssid": "Airport_Free_WiFi", "bssid": "AA:BB:CC:11:22:33", "signal": -45,
         "channel": 36, "frequency": 5180, "security": "WPA2", "timestamp": "2026-09-28T19:30:00"},
        AIRPORT_PROFILE,
    )
    assert result.classification in ACCEPTABLE_LOW


def test_7b_completely_empty_observation_survives():
    result = analyze_network({}, AIRPORT_PROFILE)
    assert 0 <= result.risk_score <= 100
    assert result.classification in Classification.ALL
    assert result.reasons


@pytest.mark.parametrize(
    "network",
    [
        {},
        {"ssid": "", "bssid": ""},
        {"ssid": None, "bssid": None, "signal": "abc", "channel": None},
        {"ssid": "X", "bssid": "not-a-mac", "security": None},
        {"ssid": "X", "bssid": "AA:BB:CC:DD:EE:FF", "signal": 99999, "channel": -5, "frequency": 0},
    ],
)
def test_7c_malformed_observations_degrade_instead_of_raising(network):
    result = analyze_network(network, AIRPORT_PROFILE)
    assert 0 <= result.risk_score <= 100
    assert result.reasons


def test_7d_missing_optional_fields_do_not_manufacture_a_security_mismatch():
    """A scanner that omitted `security` must not make every AP look rogue."""
    result = analyze_network({"ssid": "Airport_Free_WiFi", "bssid": "AA:BB:CC:11:22:33",
                              "channel": 36, "frequency": 5180}, AIRPORT_PROFILE)
    assert "SECURITY_MISMATCH" not in result.indicators
    assert result.classification in ACCEPTABLE_LOW


def test_7e_garbage_profile_does_not_crash_the_pipeline():
    result = analyze_network(ap(), {"ssid": None, "known_bssids": "nonsense"})
    assert 0 <= result.risk_score <= 100


# --- upstream schema compatibility ---------------------------------------

SCANNER_HANDOFF_ROW = {
    # Exactly the shape documented in scanner/integration_example.py.
    "bssid": "AA:BB:CC:11:22:33", "ssid": "Airport_Free_WiFi", "is_hidden": False,
    "signal_dbm": -45, "signal_quality": 92, "channel": 36, "frequency_mhz": 5180,
    "bandwidth_mhz": 80, "security": "WPA2", "is_open": False,
    "observed_at": "2026-09-28T19:30:00+00:00",
}


def test_scanner_handoff_field_names_are_understood():
    """The scanner and the engine use different names in different places.

    A silently dropped `signal` would quietly disable a real check rather than
    raise, so every renamed field has to survive the trip.
    """
    from ai.models import WiFiNetwork

    parsed = WiFiNetwork.from_dict(SCANNER_HANDOFF_ROW)
    assert parsed.signal == -45
    assert parsed.frequency == 5180
    assert parsed.channel == 36
    assert parsed.channel_width == 80
    assert parsed.timestamp == "2026-09-28T19:30:00+00:00"
    assert parsed.hidden is False


def test_both_upstream_schemas_produce_the_same_verdict():
    canonical = {
        "ssid": "Airport_Free_WiFi", "bssid": "AA:BB:CC:11:22:33", "signal": -45,
        "channel": 36, "frequency": 5180, "security": "WPA2",
        "timestamp": "2026-09-28T19:30:00+00:00",
    }
    a = analyze_network(SCANNER_HANDOFF_ROW, AIRPORT_PROFILE)
    b = analyze_network(canonical, AIRPORT_PROFILE)
    assert a.classification == b.classification
    assert a.risk_score == b.risk_score
    assert "MISSING_FIELDS" not in a.indicators, "no field should be lost in translation"


def test_extra_unknown_fields_are_harmless():
    row = dict(SCANNER_HANDOFF_ROW, signal_quality=92, is_open=False, some_future_field="x")
    result = analyze_network(row, AIRPORT_PROFILE)
    assert result.classification in ACCEPTABLE_LOW


# --- handoff to the backend ---------------------------------------------

def test_backend_snippet_is_valid_python():
    """Guards the backend skeleton, without importing FastAPI.

    Checked with ``ast.parse`` rather than executed, so the test suite keeps
    working on a machine with no FastAPI installed. The engine must not gain
    a web-framework dependency.
    """
    import ast

    from ai.integration_example import fastapi_example

    code = fastapi_example()
    ast.parse(code)  # raises SyntaxError if the snippet has rotted
    assert "from ai.pipeline import analyze_scan" in code
    assert "@app.post" in code


def test_empty_profile_container_behaves_like_no_profile():
    """A blank profile must not masquerade as real configuration.

    `[]` or `{}` used to build a phantom empty profile that claimed a trusted
    profile existed, suppressing the NO_TRUSTED_PROFILE explanation.
    """
    for empty in (None, [], {}, TrustedProfile(ssid="")):
        result = analyze_network(ap(), empty)
        assert result.classification == Classification.UNVERIFIED
        assert "NO_TRUSTED_PROFILE" in result.indicators
        assert "PROFILE_DEVIATION" not in result.indicators


def test_batch_mode_uses_each_profiles_own_baseline():
    """Regression: a batch scan must not share one detector across sites.

    Batch analysis previously handed every network the same detector, so a
    network with a configured profile was scored against a baseline unrelated
    to its site and reported `anomaly_available=False` even though a correct
    baseline existed.
    """
    configured = [ap(bssid="AA:BB:CC:11:22:33", channel=36, frequency=5180)]
    unconfigured = [{"ssid": "Elsewhere", "bssid": "AA:BB:CC:99:99:99",
                     "signal": -50, "channel": 6, "frequency": 2437, "security": "OPEN"}]

    results = analyze_scan(
        {"networks": configured + unconfigured}, profiles=[AIRPORT_PROFILE]
    )
    by_ssid = {r["observed"]["ssid"]: r for r in results["results"]}

    assert by_ssid["Airport_Free_WiFi"]["anomaly_available"] is True
    assert by_ssid["Elsewhere"]["anomaly_available"] is False, "no profile, so no baseline"


def test_anomaly_score_is_never_presented_as_measured_when_unavailable():
    """`anomaly_available=False` must accompany a placeholder score of 0.0."""
    result = analyze_network({"ssid": "Unconfigured", "bssid": "AA:BB:CC:99:99:99"}, None)
    assert result.anomaly_available is False
    assert result.anomaly_score == 0.0
    assert any("baseline" in reason for reason in result.reasons)


# --- output contract -----------------------------------------------------

def test_output_contract_fields_are_present_and_serialisable():
    result = analyze_network(ap(), AIRPORT_PROFILE)
    payload = result.to_dict()
    for key in ("ssid", "bssid", "risk_score", "classification", "anomaly_score",
                "profile_match", "reasons"):
        assert key in payload
    assert isinstance(payload["risk_score"], int)
    assert 0 <= payload["anomaly_score"] <= 1.0
    assert payload["classification"] in Classification.ALL
    assert isinstance(result.to_json(), str)
    json.loads(result.to_json())  # must be valid JSON for the FastAPI layer


def test_every_result_always_has_reasons():
    for network in [ap(), ap(bssid="BB:CC:DD:44:55:66", security="OPEN"), {}, ap(ssid="Other")]:
        for profile in (AIRPORT_PROFILE, None):
            assert analyze_network(network, profile).reasons


def test_anomaly_score_is_never_described_as_a_probability():
    """The field name and wording must not imply attack likelihood."""
    result = analyze_network(ap(bssid="BB:CC:DD:44:55:66", security="OPEN"), AIRPORT_PROFILE)
    blob = json.dumps(result.to_dict()).lower()
    for forbidden in ("probability", "chance of attack", "% attack", "p(attack"):
        assert forbidden not in blob


def test_scan_report_is_dashboard_ready():
    report = analyze_scan({"networks": three_legit_aps(), "timestamp": "2026-09-28T19:30:00"},
                          profiles=[AIRPORT_PROFILE])
    assert report["network_count"] == 3
    assert report["ssid_count"] == 1
    assert report["timestamp"] == "2026-09-28T19:30:00"
    assert report["classification_counts"][Classification.TRUSTED] == 3
    assert "thresholds" in report
    json.dumps(report)  # the API layer returns this directly


# --- synthetic test fixtures (test-only, never reachable at runtime) -----

@pytest.mark.parametrize("scenario", ["normal", "suspicious", "new_location"])
def test_sample_scenarios_load_and_analyse(scenario):
    resolved = resolve_fixture_scenario(scenario)
    report = analyze_scan(resolved["networks"], profiles=resolved["profiles"] or None)
    assert report["network_count"] == len(resolved["networks"])
    assert all(r["reasons"] for r in report["results"])


def test_normal_sample_is_entirely_trusted():
    resolved = resolve_fixture_scenario("normal")
    report = analyze_scan(resolved["networks"], profiles=resolved["profiles"])
    assert report["classification_counts"][Classification.TRUSTED] == 5


def test_suspicious_sample_flags_the_rogue_but_not_the_legitimate_aps():
    resolved = resolve_fixture_scenario("suspicious")
    report = analyze_scan(resolved["networks"], profiles=resolved["profiles"])
    counts = report["classification_counts"]
    assert counts[Classification.HIGH_RISK] >= 1
    assert counts[Classification.TRUSTED] >= 2, "legitimate APs must stay green"
