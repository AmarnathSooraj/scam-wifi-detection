"""Trusted wireless profiles and the comparison of observations against them.

A profile answers "does this AP belong to infrastructure we expect here?".
It is deliberately *permissive*: it may list many legitimate BSSIDs, and each
expected field is optional. An empty expectation means "no opinion", never
"mismatch" - otherwise a sparse profile would flag every AP in a new airport.

Two hard rules, both load-bearing for the demo:

1. Multiple APs sharing an SSID is the normal case. A profile with five
   BSSIDs is a healthy network, not a duplicate-SSID alert.
2. No single mismatch means malicious. The comparison only produces facts;
   :mod:`ai.rules` and :mod:`ai.risk_engine` decide what they are worth.
"""

from __future__ import annotations

import math
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .models import (
    ProfileComparison,
    TrustedProfile,
    WiFiNetwork,
    classify_security,
    format_bssid,
    normalize_security,
    oui_of,
)

__all__ = [
    "band_of_frequency",
    "band_of_channel",
    "compare_to_profile",
    "nearest_value",
    "build_provisional_profile",
    "ProvisionalBaseline",
    "load_profiles",
    "profile_for_ssid",
]


# ---------------------------------------------------------------------------
# Band helpers
# ---------------------------------------------------------------------------

def band_of_frequency(frequency: Optional[int]) -> Optional[float]:
    """Coarse band in GHz for a centre frequency in MHz."""
    if not frequency:
        return None
    if frequency < 3000:
        return 2.4
    if frequency < 5900:
        return 5.0
    return 6.0


def band_of_channel(channel: Optional[int]) -> Optional[float]:
    """Coarse band in GHz for an IEEE 802.11 channel number."""
    if not channel:
        return None
    if 1 <= channel <= 14:
        return 2.4
    if 32 <= channel <= 177:
        return 5.0
    if 177 < channel <= 233:
        return 6.0
    return None


def nearest_value(value: Optional[int], candidates: Sequence[int]) -> Tuple[Optional[int], Optional[int]]:
    """Return ``(nearest_candidate, absolute_distance)`` for ``value``.

    Both are ``None`` when there is nothing to compare - the caller then
    records "no expectation" instead of a deviation.
    """
    if value is None or not candidates:
        return None, None
    nearest = min(candidates, key=lambda c: abs(c - value))
    return nearest, abs(nearest - value)


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def _security_matches(observed: str, expected: Sequence[str]) -> Optional[bool]:
    """Compare observed security against the profile's allowed labels.

    Matching is by *category* and set overlap, not string equality: a trusted
    ``WPA2/WPA3`` profile should accept an AP advertising ``WPA2``, and a
    trusted ``WPA2`` profile should not accept ``OPEN``.

    Returns ``None`` - "no opinion", not "mismatch" - when either side has no
    usable information. This matters: a scanner that failed to report the
    security field would otherwise make *every* AP on a WPA2 network look like
    a security mismatch, and missing data would be scored as evidence.
    """
    if not expected:
        return None
    observed_label = normalize_security(observed)
    observed_category = classify_security(observed_label)
    if observed_category == "UNKNOWN":
        return None
    expected_labels = {normalize_security(e) for e in expected}
    if observed_label in expected_labels:
        return True
    # Overlap on *any* component protocol counts. An AP advertising
    # "WPA2/WPA3" still supports WPA2, so a WPA2 profile should accept it -
    # networks mid-transition to WPA3 are extremely common and must not be
    # flagged as deviations. The reverse (profile WPA2/WPA3, observed WPA2) is
    # accepted by the same rule.
    observed_parts = {part for part in observed_label.split("/") if part}
    if observed_parts & expected_labels:
        return True
    return classify_security(observed_label) in {classify_security(e) for e in expected_labels}


def compare_to_profile(
    network: Any,
    profile: Optional[Any] = None,
) -> ProfileComparison:
    """Compare one observation against a trusted profile.

    Returns a :class:`~ai.models.ProfileComparison` holding only facts. A
    ``None`` field means the profile expressed no opinion about that attribute.
    """
    net = WiFiNetwork.from_dict(network)
    prof = TrustedProfile.from_dict(profile) if profile is not None else None

    if prof is not None and prof.is_empty:
        # A blank profile carries no expectations at all. Reporting
        # ``has_profile=True`` for it would claim an operator vouched for this
        # network when they did not, and would hide the NO_TRUSTED_PROFILE
        # explanation from the user.
        prof = None

    if prof is None or (prof.ssid and net.ssid and prof.ssid != net.ssid):
        # No profile covers this SSID. Everything stays unknown on purpose.
        return ProfileComparison(has_profile=False, provisional=bool(prof and prof.provisional))

    comparison = ProfileComparison(
        has_profile=True,
        provisional=prof.provisional,
        ssid_match=bool(net.ssid) and net.ssid == prof.ssid,
    )

    # --- BSSID ------------------------------------------------------------
    if prof.known_bssids:
        comparison.expectation_count += 1
        if net.bssid:
            # ``net.bssid`` is already normalised to AA:BB:.. form by
            # WiFiNetwork; normalise both sides anyway so hand-built
            # TrustedProfile objects in any MAC notation still match.
            comparison.known_bssid = format_bssid(net.bssid) in prof.bssid_set

    # --- security ---------------------------------------------------------
    comparison.security_match = _security_matches(net.security, prof.security)
    if comparison.security_match is not None:
        comparison.expectation_count += 1

    # --- channel ----------------------------------------------------------
    if prof.expected_channels:
        comparison.expectation_count += 1
        if net.channel is not None:
            nearest, distance = nearest_value(net.channel, prof.expected_channels)
            comparison.channel_expected = nearest == net.channel
            comparison.channel_deviation = distance

    # --- frequency --------------------------------------------------------
    if prof.expected_frequencies:
        comparison.expectation_count += 1
        if net.frequency is not None:
            nearest, distance = nearest_value(net.frequency, prof.expected_frequencies)
            comparison.frequency_expected = nearest == net.frequency
            comparison.frequency_deviation = distance

    # --- vendor -----------------------------------------------------------
    if prof.known_vendors:
        if net.vendor:
            comparison.expectation_count += 1
            comparison.vendor_known = net.vendor.strip().lower() in prof.known_vendors

    # --- OUI / hardware vendor block ---------------------------------------
    # Reported always, because it is visible information. It is only *counted*
    # as a deviation when the BSSID is already known-good-but-different, which
    # cannot happen: a BSSID on the trusted list necessarily carries an expected
    # OUI. So in practice an OUI mismatch accompanies an unknown BSSID, and in
    # that case it is **implied** rather than independent - counting it twice
    # would let one fact masquerade as two contradictions and trip the
    # multi-deviation aggregator on its own.
    #
    # Its value is the opposite direction: a matching OUI is supporting
    # evidence that an otherwise-unknown BSSID is the same vendor's hardware.
    comparison.observed_oui = oui_of(net.bssid)
    comparison.expected_ouis = list(prof.known_ouis)
    if comparison.observed_oui and comparison.expected_ouis:
        comparison.oui_known = comparison.observed_oui in comparison.expected_ouis
        # Only an independent OUI observation counts, i.e. when the BSSID
        # itself was not already flagged.
        if comparison.known_bssid is not False:
            comparison.expectation_count += 1

    # --- band coherence ---------------------------------------------------
    # A 2.4 GHz AP on a 5 GHz-only profile is a meaningful deviation even
    # before the exact channel is compared. Only recorded when both bands are
    # actually known.
    if net.frequency is not None or net.channel is not None:
        observed_band = net.band_ghz
        expected_bands = {
            b
            for b in (band_of_frequency(f) for f in prof.expected_frequencies)
            if b is not None
        } or {b for b in (band_of_channel(c) for c in prof.expected_channels) if b is not None}
        if observed_band is not None and expected_bands:
            comparison.band_mismatch = observed_band not in expected_bands

    # --- deviation tally --------------------------------------------------
    # Only disagreements count. ``band_mismatch`` is inverted by construction
    # (False means the bands agree), so it contributes on True; the other
    # fields are tri-state and contribute on False.
    comparison.deviation_count = sum(
        1
        for value in (
            comparison.known_bssid,
            comparison.security_match,
            comparison.channel_expected,
            comparison.frequency_expected,
            comparison.vendor_known,
            # Only counted when it is an independent observation; see the OUI
            # block above for why it usually is not.
            comparison.oui_known if comparison.known_bssid is not False else None,
        )
        if value is False
    )
    if comparison.band_mismatch:
        comparison.deviation_count += 1

    return comparison


# ---------------------------------------------------------------------------
# Provisional baseline for unknown locations
# ---------------------------------------------------------------------------

#: A provisional profile is only built from at least this many observations of
#: the same SSID. One beacon is not a baseline.
MIN_PROVISIONAL_OBSERVATIONS = 3

#: Share of observations that must agree before a *security* label is accepted
#: into a provisional profile.
#:
#: Security is treated differently from the channel plan on purpose. A new
#: network legitimately spans many channels and BSSIDs, each seen once, so a
#: support threshold there would throw away the whole baseline. Security is
#: different: an SSID is normally served with one encryption policy, so a lone
#: AP advertising something else is the exact thing worth noticing. Without
#: this threshold a rogue is absorbed into the baseline on the very first scan
#: (3 WPA2 + 1 OPEN became "expected: WPA2 or OPEN") and the engine could never
#: notice it.
PROVISIONAL_SECURITY_SUPPORT = 0.6

#: ...but never on fewer than this many observations in absolute terms, so a
#: two-observation sample does not demand unanimity.
PROVISIONAL_SECURITY_MIN_VOTES = 2

#: A provisional profile never yields TRUSTED, only LOW_RISK at most.
#: Enforced in :mod:`ai.risk_engine` via ``TrustedProfile.provisional``.


def build_provisional_profile(
    ssid: str,
    observations: Iterable[Any],
    min_observations: int = MIN_PROVISIONAL_OBSERVATIONS,
    max_bssids: int = 32,
) -> Optional[TrustedProfile]:
    """Infer a provisional profile from repeated observations of one SSID.

    Used when arriving at a location with no configured profile. It captures
    the *consensus* characteristics of the SSID (the security the APs agree
    on, the channel/BSSID set observed) so that a single odd AP can be
    recognised as a deviation from its peers.

    Deliberate limitations, documented in the README:

    * The first observations are **not** trusted permanently - the profile is
      flagged ``provisional`` and can never produce ``TRUSTED``.
    * Channel/frequency sets are capped so one odd observation does not widen
      the baseline; only the most frequently seen values are kept.
    * A rogue present from the very first scan can still be absorbed, because
      the baseline is built from the very observations it later judges. The
      security support threshold narrows this considerably, but does not
      remove it - a location where the rogue is the *majority* of the APs on
      an SSID will learn the rogue's fingerprint as normal.
    """
    nets = [WiFiNetwork.from_dict(item) for item in observations]
    nets = [n for n in nets if n.ssid == ssid and n.bssid]
    if len(nets) < min_observations:
        return None

    def ranked_consensus(values: List[Any]) -> List[Any]:
        """Most frequently observed values, tie-broken deterministically."""
        counts: Dict[Any, int] = {}
        for value in values:
            counts[value] = counts.get(value, 0) + 1
        return sorted(counts.items(), key=lambda kv: (-kv[1], str(kv[0])))

    security_votes = [n.security for n in nets if n.security]
    security_support = max(
        PROVISIONAL_SECURITY_MIN_VOTES,
        int(math.ceil(PROVISIONAL_SECURITY_SUPPORT * len(security_votes))),
    )
    # A tie at the threshold is kept: 2 WPA2 vs 2 OPEN should not silently
    # discard the legitimate half.
    security = [value for value, count in ranked_consensus(security_votes) if count >= security_support]

    channels = [value for value, _ in ranked_consensus([n.channel for n in nets if n.channel is not None])[:8]]
    frequencies = [
        value for value, _ in ranked_consensus([n.frequency for n in nets if n.frequency is not None])[:8]
    ]
    vendors = [value for value, _ in ranked_consensus([n.vendor for n in nets if n.vendor])[:5]]
    bssids = [n.bssid for n in nets][:max_bssids]

    return TrustedProfile(
        ssid=ssid,
        known_bssids=bssids,
        security=security,
        expected_channels=channels,
        expected_frequencies=frequencies,
        known_vendors=[v.lower() for v in vendors],
        location="provisional (learned on site)",
        provisional=True,
    )


class ProvisionalBaseline:
    """Stateful helper that turns a batch of observations into profiles.

    Usage in a FastAPI process::

        baseline = ProvisionalBaseline()
        profiles = baseline.update(networks)          # learned so far
        results = [analyze_network(n, profiles.get(n.ssid)) for n in networks]

    The learned profiles are held in memory only. Persisting them is a
    decision for the backend team; until then the baseline resets when the
    process restarts, which is the safe failure mode (a fresh start reverts to
    ``UNVERIFIED`` rather than to blind trust).
    """

    def __init__(self, min_observations: int = MIN_PROVISIONAL_OBSERVATIONS) -> None:
        self.min_observations = min_observations
        self._history: Dict[str, List[Dict[str, Any]]] = {}
        self._profiles: Dict[str, TrustedProfile] = {}

    def observe(self, networks: Iterable[Any]) -> None:
        """Record one scan's worth of observations."""
        for net in networks:
            record = WiFiNetwork.from_dict(net)
            if not record.ssid or not record.bssid:
                continue
            self._history.setdefault(record.ssid, []).append(record.to_dict())

    def update(self, networks: Optional[Iterable[Any]] = None) -> Dict[str, TrustedProfile]:
        """Observe ``networks`` (optional) and rebuild the provisional profiles."""
        if networks is not None:
            self.observe(networks)
        self._profiles = {}
        for ssid, history in self._history.items():
            profile = build_provisional_profile(ssid, history, self.min_observations)
            if profile is not None:
                self._profiles[ssid] = profile
        return dict(self._profiles)

    def profile_for(self, ssid: str) -> Optional[TrustedProfile]:
        return self._profiles.get(ssid)

    def observations(self, ssid: str) -> int:
        return len(self._history.get(ssid, ()))

    def reset(self) -> None:
        self._history.clear()
        self._profiles.clear()


# ---------------------------------------------------------------------------
# Loading configured profiles
# ---------------------------------------------------------------------------

def profile_for_ssid(profiles: Optional[Iterable[Any]], ssid: str) -> Optional[TrustedProfile]:
    """Return the configured profile covering ``ssid``, if any."""
    for raw in profiles or ():
        profile = TrustedProfile.from_dict(raw)
        if profile.ssid == ssid:
            return profile
    return None


def load_profiles(payload: Any) -> List[TrustedProfile]:
    """Load profiles from a dict, a list, or the ``{"profiles": [...]}`` form.

    Accepts the JSON shipped in ``sample_data/trusted_profiles.json`` so the
    backend can load configuration from a file with no extra code. A bare
    single-profile dict (one that has an ``ssid``) is also accepted, because
    the single-profile case is the common one and requiring the caller to wrap
    it in a list is a needless foot-gun at the HTTP boundary.
    """
    if payload is None:
        return []
    if isinstance(payload, (list, tuple)):
        raw_profiles: List[Any] = list(payload)
    elif isinstance(payload, dict):
        if payload.get("profiles") or payload.get("trusted_profiles"):
            raw_profiles = list(payload.get("profiles") or payload.get("trusted_profiles"))
        elif payload.get("ssid"):
            raw_profiles = [payload]
        else:
            raw_profiles = []
    else:
        raw_profiles = [payload]
    return [TrustedProfile.from_dict(item) for item in raw_profiles]
