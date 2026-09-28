"""Explainable cybersecurity rules.

Each rule is a small, independently testable function that returns a stable
indicator code plus the sentence a judge will read on the dashboard. The rules
themselves assign **no** risk: the weights live in :mod:`ai.risk_engine`, so
the same rules can be re-weighted without touching this module.

Every rule is written to be evidence, not proof. The strongest single signal
here is a *security downgrade* (a network that should be WPA2 advertising
itself as OPEN) combined with an unknown BSSID. Unknown BSSID on its own is
deliberately weak evidence, because at a new location every BSSID is unknown.
"""

from __future__ import annotations

from typing import List, Optional

from .models import (
    Classification,
    ProfileComparison,
    RuleResult,
    WiFiNetwork,
    classify_security,
    security_rank,
)

__all__ = [
    "INDICATORS",
    "evaluate_rules",
    "rule_unknown_bssid",
    "rule_security_mismatch",
    "rule_security_downgrade",
    "rule_channel_mismatch",
    "rule_frequency_mismatch",
    "rule_vendor_mismatch",
    "rule_oui_mismatch",
    "rule_oui_match",
    "rule_band_mismatch",
    "rule_profile_deviation",
    "rule_missing_fields",
    "rule_ssid_hidden",
]


#: Every indicator code the engine can emit. Tests and the dashboard use these
#: as stable identifiers; the human text may be reworded, the codes may not.
INDICATORS = (
    "UNKNOWN_BSSID",
    "NO_TRUSTED_PROFILE",
    "PROVISIONAL_PROFILE",
    "SECURITY_MISMATCH",
    "SECURITY_DOWNGRADE",
    "CHANNEL_MISMATCH",
    "FREQUENCY_MISMATCH",
    "BAND_MISMATCH",
    "VENDOR_MISMATCH",
    "OUI_MISMATCH",
    "OUI_MATCH",
    "PROFILE_DEVIATION",
    "ML_ANOMALY",
    "MISSING_FIELDS",
    "HIDDEN_SSID",
)


# ---------------------------------------------------------------------------
# Individual rules
# ---------------------------------------------------------------------------

def rule_unknown_bssid(net: WiFiNetwork, cmp_: ProfileComparison, out: RuleResult) -> None:
    """The BSSID is not listed in the trusted profile.

    This means "not yet verified", not "hostile". A new airport, a roaming
    guest network or a legitimately added AP all look like this.
    """
    if not cmp_.has_profile:
        return
    if cmp_.known_bssid is None:
        # Profile has no BSSID list at all: no opinion, no evidence.
        out.add_mitigating("Trusted profile does not enumerate BSSIDs, so the BSSID could not be checked")
        return
    if not cmp_.known_bssid:
        out.add(
            "UNKNOWN_BSSID",
            "BSSID is not present in trusted infrastructure (unverified, not automatically malicious)",
        )


def rule_security_mismatch(net: WiFiNetwork, cmp_: ProfileComparison, out: RuleResult) -> None:
    """Observed security is outside the set the profile expects."""
    if cmp_.security_match is False:
        out.add(
            "SECURITY_MISMATCH",
            "Security configuration differs from trusted profile "
            f"(observed {net.security}, expected {'/'.join(sorted(_expected(cmp_)))})",
        )


def rule_security_downgrade(net: WiFiNetwork, cmp_: ProfileComparison, out: RuleResult) -> None:
    """Observed encryption is strictly weaker than the profile expects.

    This is the highest-value rule in the set: a WPA2 network appearing as
    OPEN is the classic rogue-AP pattern, and unlike a channel change it does
    not have an innocent explanation on a managed network. It is kept separate
    from the generic mismatch so it can carry a larger weight.
    """
    if cmp_.security_match is not False:
        return
    observed_rank = security_rank(net.security)
    if observed_rank is None:
        return
    expected_ranks = [
        rank for rank in (security_rank(name) for name in _expected(cmp_)) if rank is not None
    ]
    if expected_ranks and observed_rank < max(expected_ranks):
        out.add(
            "SECURITY_DOWNGRADE",
            f"Encryption is weaker than the trusted profile ({net.security} vs "
            f"{'/'.join(sorted(_expected(cmp_)))})",
        )
    if net.is_open:
        out.add(
            "SECURITY_DOWNGRADE",
            "AP is advertising an OPEN (unencrypted) network under a protected SSID",
        )


def rule_channel_mismatch(net: WiFiNetwork, cmp_: ProfileComparison, out: RuleResult) -> None:
    """The channel is not one the profile expects."""
    if cmp_.channel_expected is False:
        detail = f", nearest expected channel differs by {cmp_.channel_deviation}" if cmp_.channel_deviation else ""
        out.add(
            "CHANNEL_MISMATCH",
            f"Channel is outside expected profile (observed {net.channel}{detail})",
        )


def rule_frequency_mismatch(net: WiFiNetwork, cmp_: ProfileComparison, out: RuleResult) -> None:
    """The centre frequency is not one the profile expects."""
    if cmp_.frequency_expected is False:
        detail = (
            f", nearest expected frequency differs by {cmp_.frequency_deviation} MHz"
            if cmp_.frequency_deviation
            else ""
        )
        out.add(
            "FREQUENCY_MISMATCH",
            f"Frequency is outside expected profile (observed {net.frequency} MHz{detail})",
        )


def rule_band_mismatch(net: WiFiNetwork, cmp_: ProfileComparison, out: RuleResult) -> None:
    """The AP is on a different band than the profile covers (2.4 vs 5 GHz)."""
    if cmp_.band_mismatch:
        out.add(
            "BAND_MISMATCH",
            f"AP is on the {net.band_ghz} GHz band, outside the profile's expected band",
        )


def rule_vendor_mismatch(net: WiFiNetwork, cmp_: ProfileComparison, out: RuleResult) -> None:
    """Vendor OUIs differ from the profile's known hardware.

    Skipped entirely when vendor data is absent - vendor information is
    optional and unreliable, so a missing value must not become evidence.
    """
    if cmp_.vendor_known is None:
        if not net.vendor:
            out.add_mitigating("Vendor information unavailable; vendor check skipped")
        return
    if not cmp_.vendor_known:
        out.add("VENDOR_MISMATCH", f"Hardware vendor differs from trusted profile (observed {net.vendor})")


def rule_oui_mismatch(net: WiFiNetwork, cmp_: ProfileComparison, out: RuleResult) -> None:
    """The BSSID's hardware vendor block is foreign to the trusted network.

    This is *weak* evidence, and deliberately so. A BSSID is just bytes in a
    beacon frame: an impersonator can put any prefix it likes in there, and a
    legitimate organisation can buy a different vendor at any time. So this
    never contributes risk on its own - it exists to be **corroborated** with
    an independent contradiction such as a security downgrade. That
    corroboration requirement lives in :mod:`ai.verdict`.
    """
    if cmp_.oui_known is None:
        return
    if not cmp_.oui_known:
        out.add(
            "OUI_MISMATCH",
            f"Hardware vendor block {cmp_.observed_oui} is not one this network "
            f"is known to use (expected {'/'.join(cmp_.expected_ouis) or 'none recorded'})",
        )


def rule_oui_match(net: WiFiNetwork, cmp_: ProfileComparison, out: RuleResult) -> None:
    """The BSSID's vendor block matches known infrastructure.

    Recorded as supporting evidence, not as proof: a cloned BSSID reproduces
    a plausible prefix trivially. It exists so the dashboard can show the one
    signal that argues *for* legitimacy, and so a real AP added by the same
    vendor is visibly distinguishable from an unknown device.
    """
    if cmp_.oui_known:
        out.add_mitigating(
            f"Hardware vendor block {cmp_.observed_oui} matches this network's known hardware"
        )


def rule_profile_deviation(net: WiFiNetwork, cmp_: ProfileComparison, out: RuleResult) -> None:
    """Aggregate signal: several independent characteristics disagree at once.

    This is the "evidence accumulates" rule. It is what stops the engine from
    concluding anything from a single deviation, and it is the reason a rogue
    AP carrying a copied SSID, channel *and* security still stands out: the
    deviations are correlated across independent attributes.
    """
    if cmp_.deviation_count >= 2:
        out.add(
            "PROFILE_DEVIATION",
            f"{cmp_.deviation_count} independent characteristics deviate from the trusted profile",
        )
    elif cmp_.deviation_count == 0 and cmp_.expectation_count > 0:
        out.add_mitigating("All profile characteristics that could be checked matched")


def rule_missing_fields(net: WiFiNetwork, cmp_: ProfileComparison, out: RuleResult) -> None:
    """Note missing core metadata so a low score is not over-trusted.

    Missing data is not evidence of anything, but it does reduce how much the
    engine can vouch for the AP, so it is surfaced as an explicit caveat.
    """
    missing = [name for name in ("signal", "channel", "frequency") if getattr(net, name) is None]
    if not net.bssid:
        missing.append("bssid")
    if missing:
        out.add(
            "MISSING_FIELDS",
            "Incomplete observation (" + ", ".join(missing) + " missing), reducing the checks that could be run",
        )
    else:
        out.add_mitigating("Observation contained the full set of core wireless attributes")


def rule_ssid_hidden(net: WiFiNetwork, cmp_: ProfileComparison, out: RuleResult) -> None:
    """A non-empty SSID profile seen on a beacon that hides its SSID.

    Minor context, kept as a note rather than a weighted indicator.
    """
    if net.hidden and cmp_.has_profile:
        out.add_mitigating("SSID is being broadcast as hidden despite matching a known profile")


def rule_no_trusted_profile(net: WiFiNetwork, cmp_: ProfileComparison, out: RuleResult) -> None:
    """There is no configured profile for this SSID (new location).

    This is the reason an unfamiliar airport does not light up red: the engine
    states plainly that it has nothing to compare against and downgrades its
    own confidence rather than the AP's reputation.
    """
    if cmp_.has_profile:
        if cmp_.provisional:
            out.add(
                "PROVISIONAL_PROFILE",
                "Only a provisional baseline learned on site exists for this network; "
                "it cannot confirm a trusted device",
            )
        return
    out.add(
        "NO_TRUSTED_PROFILE",
        "This network has no established trusted profile; its infrastructure is unknown to the engine",
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _expected(cmp_: ProfileComparison) -> List[str]:
    """Expected security labels, kept on the comparison for message building."""
    return list(getattr(cmp_, "expected_security", []) or [])


#: Rule order defines reason order in the output, strongest evidence first.
_RULE_ORDER = (
    rule_no_trusted_profile,
    rule_unknown_bssid,
    rule_security_downgrade,
    rule_security_mismatch,
    rule_channel_mismatch,
    rule_frequency_mismatch,
    rule_band_mismatch,
    rule_vendor_mismatch,
    rule_oui_mismatch,
    rule_oui_match,
    rule_profile_deviation,
    rule_missing_fields,
    rule_ssid_hidden,
)


def evaluate_rules(
    network: object,
    comparison: Optional[ProfileComparison] = None,
    expected_security: Optional[List[str]] = None,
) -> RuleResult:
    """Run every rule against one observation and collect the evidence.

    ``expected_security`` is passed separately (rather than stored on the
    comparison) so the rules stay free of profile objects; the pipeline
    supplies it from the profile it already resolved.
    """
    net = WiFiNetwork.from_dict(network)
    cmp_ = comparison if comparison is not None else ProfileComparison()
    # Messages need the profile's expected security labels; attach them for
    # the duration of the rule run only.
    setattr(cmp_, "expected_security", list(expected_security or []))

    result = RuleResult()
    for rule in _RULE_ORDER:
        rule(net, cmp_, result)
    return result


def summarize(result: RuleResult, classification: str) -> List[str]:
    """Return the final, ordered reason list for the dashboard.

    Positive indicators come first, then caveats, then any mitigating notes.
    Always non-empty: a result with no reasons is a bug, not a clean AP.
    """
    reasons = list(result.reasons)
    if not reasons:
        if result.mitigating:
            reasons = list(result.mitigating)
        else:
            reasons = [f"No anomalies identified (classified {classification})"]
    return reasons
