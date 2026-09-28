"""The ten required detection cases, plus OUI identity handling.

Each test is named for the requirement it enforces, so a failure reads as a
failed requirement rather than a failed assertion.

The load-bearing property across this file: **no single weak signal may produce
a fake verdict**. An unknown BSSID, a single channel change, and the ML score
are each individually insufficient, by design.
"""

from __future__ import annotations

import pytest

from ai.models import Classification
from ai.pipeline import analyze_network, analyze_scan
from ai.verdict import (
    ACCURACY_NOTE,
    FAMILY_LABEL,
    MIN_FAMILIES_FOR_FAKE,
    SignalFamily,
    Verdict,
    family_of,
)

from .fixtures_scenarios import (
    KNOWN_VENDOR_BSSID,
    OFFICE_PROFILE,
    full_impersonation_ap,
    known_ap,
    multi_ap_setup,
    security_downgrade_ap,
    unknown_bssid_ap,
)


def assess(ap_record, profile=OFFICE_PROFILE, **kwargs):
    return analyze_network(ap_record, profile, **kwargs)


def families(result):
    return set(result.families_deviating)


# ===========================================================================
# Test 1 - Known legitimate AP
# ===========================================================================

def test_1_known_legitimate_ap_is_trusted():
    result = assess(known_ap())
    assert result.verdict == Verdict.TRUSTED
    assert result.classification == Classification.TRUSTED
    assert result.risk_score == 0
    assert result.profile_match is True
    assert result.evidence_level == "HIGH"
    assert result.families_deviating == []


# ===========================================================================
# Test 2 - Unknown SSID (no profile at all)
# ===========================================================================

def test_2_unknown_ssid_is_unverified_not_fake():
    result = assess({"ssid": "CoffeeShop_Guest", "bssid": "11:22:33:44:55:66",
                     "signal": -60, "channel": 6, "frequency": 2437, "security": "OPEN"}, None)
    assert result.verdict == Verdict.UNVERIFIED
    assert result.evidence_level == "LOW"
    assert "No trusted network profile" in result.verdict_summary
    assert "Insufficient evidence" in result.verdict_summary
    assert result.impersonation_pattern is False


# ===========================================================================
# Test 3 - Same SSID, several legitimate APs
# ===========================================================================

def test_3_multiple_aps_under_one_ssid_are_all_trusted():
    """The headline anti-pattern. Three APs, one SSID, zero false alarms."""
    results = [assess(ap) for ap in multi_ap_setup()]
    assert len(results) == 3
    for result in results:
        assert result.verdict == Verdict.TRUSTED, (result.bssid, result.verdict_summary)
    # And no AP was flagged for sharing the SSID.
    assert not any("UNKNOWN_BSSID" in r.indicators for r in results)


def test_3b_duplicate_ssid_never_produces_an_indicator():
    """Regression guard for the project's central design claim."""
    report = analyze_scan({"networks": multi_ap_setup()}, profiles=[OFFICE_PROFILE])
    for entry in report["results"]:
        assert entry["verdict"] == Verdict.TRUSTED
        assert entry["families_deviating"] == []


# ===========================================================================
# Test 4 - Same SSID, unknown BSSID
# ===========================================================================

def test_4_unknown_bssid_raises_suspicion_but_is_not_fake():
    result = assess(unknown_bssid_ap())
    assert result.verdict == Verdict.LEGITIMATE
    # LEGITIMATE is the semantic reading of the LOW_RISK band: elevated
    # concern, but nothing about this AP contradicts the expected network.
    assert result.classification == Classification.LOW_RISK
    assert result.risk_score > 0
    assert "UNKNOWN_BSSID" in result.indicators
    assert result.impersonation_pattern is False
    assert families(result) == {SignalFamily.IDENTITY}
    # And the reason it is not TRUSTED is visible, not hidden.
    assert "not on the trusted list" in result.verdict_summary


def test_4b_unknown_bssid_with_matching_vendor_block_reads_better():
    """A new AP from the same vendor is visibly different from a random device."""
    foreign = assess(unknown_bssid_ap(bssid="DE:AD:BE:EF:00:01"))
    same_vendor = assess(unknown_bssid_ap(bssid=KNOWN_VENDOR_BSSID))
    assert same_vendor.risk_score <= foreign.risk_score
    assert same_vendor.oui_known is not False if hasattr(same_vendor, "oui_known") else True
    # Both stay non-fake: an added AP is not an impersonator.
    assert same_vendor.verdict in (Verdict.LEGITIMATE, Verdict.UNVERIFIED)
    assert foreign.verdict in (Verdict.LEGITIMATE, Verdict.UNVERIFIED)


# ===========================================================================
# Test 5 - Same SSID, unknown BSSID + security downgrade
# ===========================================================================

def test_5_security_downgrade_escalates_to_suspicious():
    result = assess(security_downgrade_ap())
    assert result.verdict == Verdict.SUSPICIOUS
    assert "SECURITY_MISMATCH" in result.indicators
    assert "SECURITY_DOWNGRADE" in result.indicators
    assert SignalFamily.SECURITY in families(result)
    assert SignalFamily.IDENTITY in families(result)
    assert result.impersonation_pattern is False


# ===========================================================================
# Test 6 - Multiple strong, independent contradictions
# ===========================================================================

def test_6_corroborated_contradictions_give_potential_fake():
    result = assess(full_impersonation_ap())
    assert result.verdict == Verdict.POTENTIAL_FAKE
    assert result.classification == Classification.HIGH_RISK
    assert result.risk_score >= 75
    assert result.evidence_level == "HIGH"
    assert result.impersonation_pattern is True
    assert result.impersonating == "Office_Net"
    # Independent families, not one fact counted repeatedly.
    assert len(families(result)) >= MIN_FAMILIES_FOR_FAKE
    assert {SignalFamily.IDENTITY, SignalFamily.SECURITY, SignalFamily.RADIO_PLAN} <= families(result)


def test_6b_evidence_level_reflects_corroboration_not_just_score():
    """A high score from a single family is weaker evidence than a moderate
    score corroborated across three. The grading must reflect that."""
    single_family = assess(unknown_bssid_ap())
    corroborated = assess(full_impersonation_ap())
    assert single_family.evidence_level != "HIGH"
    assert corroborated.evidence_level == "HIGH"
    assert corroborated.risk_score > single_family.risk_score


# ===========================================================================
# Test 7 - No profile
# ===========================================================================

def test_7_no_profile_never_yields_a_fake_verdict():
    """At a brand-new location the system must say UNVERIFIED, not FAKE."""
    # Deliberately the most alarming observation possible, with no reference.
    alarming = {"ssid": "Somewhere_New", "bssid": "DE:AD:BE:EF:00:01", "signal": -30,
                "channel": 1, "frequency": 2412, "security": "OPEN"}
    result = assess(alarming, None)
    assert result.verdict == Verdict.UNVERIFIED
    assert result.impersonation_pattern is False
    assert result.evidence_level == "LOW"


def test_7b_empty_profile_container_behaves_like_no_profile():
    for empty in ([], {}, None):
        result = analyze_network(full_impersonation_ap(), empty)
        assert result.verdict == Verdict.UNVERIFIED, empty
        assert result.impersonation_pattern is False


# ===========================================================================
# Test 8 - ML unavailable: deterministic rules must carry the decision
# ===========================================================================

def test_8_verdict_works_with_no_ml_at_all():
    from ai.anomaly import AnomalyDetector

    unfitted = AnomalyDetector()
    result = assess(full_impersonation_ap(), detector=unfitted)
    assert result.anomaly_available is False
    assert result.anomaly_score == 0.0
    # The verdict is unchanged: rules alone are sufficient.
    assert result.verdict == Verdict.POTENTIAL_FAKE
    assert result.risk_score >= 75


def test_8b_no_fabricated_anomaly_score_when_unavailable():
    result = assess(unknown_bssid_ap())
    if not result.anomaly_available:
        assert result.anomaly_score == 0.0
        assert any("baseline" in reason for reason in result.reasons)


# ===========================================================================
# Test 9 - ML overlap must not condemn a legitimate AP
# ===========================================================================

def test_9_ml_score_alone_never_condemns_a_legitimate_ap():
    """The measured overlap (rogue scores inside the legitimate range) is why
    the ML may never drive a verdict on its own."""
    results = [assess(known_ap(signal=s, channel=c, frequency=f))
               for s in (-35, -55, -75, -90) for c, f in ((1, 2412), (36, 5180), (149, 5745))]
    for result in results:
        assert result.verdict != Verdict.POTENTIAL_FAKE
        assert result.impersonation_pattern is False


def test_9b_extreme_anomaly_on_a_profile_match_is_vetoed():
    """Even a maximal ML signal cannot overturn authoritative profile evidence."""
    from ai.anomaly import AnomalyDetector
    from ai.models import AnomalyResult

    class MaxAnomaly(AnomalyDetector):
        def score(self, *args, **kwargs):
            return AnomalyResult(anomaly_score=1.0, raw_score=-1.0,
                                 is_anomaly=True, available=True)

    result = assess(known_ap(), detector=MaxAnomaly())
    assert result.verdict == Verdict.TRUSTED
    assert result.risk_score == 0
    assert "ML_ANOMALY" not in result.indicators


# ===========================================================================
# Test 10 - Multiple legitimate BSSIDs can all be trusted
# ===========================================================================

def test_10_all_known_bssids_are_trusted():
    for bssid in OFFICE_PROFILE["known_bssids"]:
        result = assess(known_ap(bssid=bssid))
        assert result.verdict == Verdict.TRUSTED, bssid
        assert result.profile_match is True


def test_10b_profile_with_no_oui_expectation_does_not_flag_oui():
    """No known BSSIDs means no OUI expectation: absence, not mismatch."""
    result = assess(known_ap(), profile={"ssid": "Office_Net", "security": ["WPA2"]})
    assert "OUI_MISMATCH" not in result.indicators
    assert result.verdict in (Verdict.LEGITIMATE, Verdict.TRUSTED, Verdict.UNVERIFIED)


# ===========================================================================
# Cross-cutting guarantees
# ===========================================================================

def test_no_single_indicator_can_produce_potential_fake():
    """Every indicator in isolation must fall short of a fake verdict."""
    cases = {
        "identity only": unknown_bssid_ap(),
        "security only": known_ap(bssid="10:27:F5:F3:9B:B9", security="OPEN"),
        "radio plan only": known_ap(bssid="10:27:F5:F3:9B:B9", channel=11, frequency=2462),
    }
    for label, record in cases.items():
        result = assess(record)
        assert result.verdict != Verdict.POTENTIAL_FAKE, label
        assert result.impersonation_pattern is False, label


def test_potential_fake_requires_corroborated_families():
    """Structural guarantee, checked across a spread of rogue shapes."""
    for record in (
        full_impersonation_ap(),
        full_impersonation_ap(channel=11, frequency=2462),
        full_impersonation_ap(bssid="10:27:F5:00:00:99"),
    ):
        result = assess(record)
        if result.verdict == Verdict.POTENTIAL_FAKE:
            assert len(families(result)) >= MIN_FAMILIES_FOR_FAKE, record
            assert result.risk_score >= 75


def test_system_never_claims_proven_malice():
    """Section 19 of the brief: no definite-accusation language, ever."""
    forbidden = ("definitely fake", "is fake", "proven malicious", "confirmed malicious",
                 "guaranteed", "is a fake")
    records = [full_impersonation_ap(), security_downgrade_ap(), unknown_bssid_ap(),
               known_ap(), {"ssid": "X", "bssid": "DE:AD:BE:EF:00:01"}]
    for record in records:
        result = assess(record)
        blob = " ".join([
            result.verdict_summary, result.verdict_guidance, result.accuracy_note,
            " ".join(result.reasons), result.verdict,
        ]).lower()
        for phrase in forbidden:
            assert phrase not in blob, (phrase, record)


def test_every_non_trusted_verdict_carries_the_accuracy_note():
    for record in (full_impersonation_ap(), security_downgrade_ap(), unknown_bssid_ap(),
                   {"ssid": "X", "bssid": "DE:AD:BE:EF:00:01"}):
        result = assess(record)
        if result.verdict != Verdict.TRUSTED:
            assert result.accuracy_note == ACCURACY_NOTE


def test_trusted_result_does_not_need_the_caveat():
    """Caveat fatigue is real; a clean result should not be buried in warnings."""
    assert assess(known_ap()).accuracy_note == ""


def test_indicator_details_are_structured_for_the_api():
    result = assess(full_impersonation_ap())
    assert result.indicator_details
    for entry in result.indicator_details:
        assert set(entry) >= {"code", "message", "family", "points"}
        assert entry["code"] and entry["message"]
        assert entry["family"] in FAMILY_LABEL
        assert isinstance(entry["points"], int)
    codes = {entry["code"] for entry in result.indicator_details}
    assert {"UNKNOWN_BSSID", "SECURITY_MISMATCH"} <= codes


def test_indicator_details_are_json_serialisable():
    import json

    result = assess(full_impersonation_ap())
    json.dumps(result.to_dict())  # must not raise


def test_unknown_indicator_codes_fall_back_to_context():
    """A future indicator must not be able to silently count as evidence."""
    assert family_of("SOMETHING_NEW") == SignalFamily.CONTEXT


def test_verdict_summary_and_guidance_always_present():
    """A verdict a human cannot act on is not a verdict."""
    for record in (known_ap(), unknown_bssid_ap(), security_downgrade_ap(),
                   full_impersonation_ap(), {"ssid": "X", "bssid": "DE:AD:BE:EF:00:01"}):
        result = assess(record)
        assert result.verdict_summary.strip(), record
        assert result.verdict_guidance.strip(), record
        assert result.verdict in Verdict.ALL


def test_scan_report_exposes_verdict_counts():
    report = analyze_scan(
        {"networks": multi_ap_setup() + [full_impersonation_ap()]},
        profiles=[OFFICE_PROFILE],
    )
    assert report["network_count"] == 4
    assert "verdict_counts" in report
    assert report["verdict_counts"][Verdict.TRUSTED] == 3
    assert report["verdict_counts"][Verdict.POTENTIAL_FAKE] == 1
