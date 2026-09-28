"""Feature extraction for the anomaly model.

Converts one observation plus its profile comparison into a fixed-length,
numeric feature vector. Two principles drive the design:

**No meaningless ordering between categorical values.** ``security`` is not
"0 = WPA2, 1 = OPEN". It is emitted as one-hot columns over an explicit
category vocabulary, so the model cannot learn a false "distance" between
protocols. The one ordinal number (``security_rank``) is a hand-assigned
encryption-strength table, documented below, and it is accompanied by a
``security_missing`` flag so imputed values are never mistaken for observed
ones.

**Absence of data is itself a feature.** Missing fields are imputed to a fixed
constant *and* flagged, so the Isolation Forest can tell "signal was -45" from
"signal was not reported" instead of silently treating both as -70.

Feature vector layout
---------------------
See :data:`FEATURE_NAMES` for the authoritative ordered list. Groups:

===========================  ================================================
Group                        Features
===========================  ================================================
Radio physics                ``signal``, ``signal_missing``
Plan / band                  ``channel``, ``frequency``, ``band_ghz``,
                              ``band_missing``
Security (one-hot)           ``sec_open``, ``sec_wep``, ``sec_wpa1``,
                              ``sec_wpa2``, ``sec_wpa3``, ``sec_owe``,
                              ``sec_other``, ``security_rank``,
                              ``security_missing``
Trusted-profile agreement    ``known_bssid``, ``security_match``,
                              ``channel_expected``, ``frequency_expected``,
                              ``vendor_known``, ``vendor_missing``,
                              ``profile_available``, ``has_profile_data``
Deviation magnitude          ``channel_deviation``, ``channel_deviation_scaled``,
                              ``frequency_deviation``,
                              ``frequency_deviation_scaled``,
                              ``deviation_count``, ``deviation_ratio``
Observability                ``hidden``
===========================  ================================================

``known_*`` and ``*_match`` columns are ``0.0`` when the profile expressed no
opinion, and ``has_profile_data`` / ``profile_available`` distinguish "profile
agrees" from "no profile to agree with".

Deviation scaling: raw channel/frequency deviations are divided by
:data:`CHANNEL_DEVIATION_SCALE` (5 channel slots = 20 MHz) and
:data:`FREQUENCY_DEVIATION_SCALE` (20 MHz) and clipped to
:data:`MAX_SCALED_DEVIATION`. A missing deviation becomes ``0.0`` with the
``has_profile_data`` flag already low, so an absent expectation is not read as
"no deviation, therefore normal".
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .models import (
    ProfileComparison,
    WiFiNetwork,
    classify_security,
    security_rank,
)

__all__ = [
    "FEATURE_NAMES",
    "FEATURE_GROUPS",
    "SECURITY_CATEGORIES",
    "IMPUTE_SIGNAL",
    "CHANNEL_DEVIATION_SCALE",
    "FREQUENCY_DEVIATION_SCALE",
    "MAX_SCALED_DEVIATION",
    "extract_features",
    "build_feature_matrix",
    "feature_row",
]


#: Imputation constants. Chosen to sit outside the plausible range of a real
#: reading so an imputed value is still separable in the tree ensemble.
IMPUTE_SIGNAL = -100.0
IMPUTE_CHANNEL = 0.0
IMPUTE_FREQUENCY = 0.0
IMPUTE_BAND = 0.0
IMPUTE_RANK = 2.0

#: 5 channel slots at 5 MHz spacing = 25 MHz, rounded to 20 MHz. A deviation
#: of one "typical" channel spacing saturates the scaled feature.
CHANNEL_DEVIATION_SCALE = 20.0
FREQUENCY_DEVIATION_SCALE = 20.0
MAX_SCALED_DEVIATION = 10.0

#: One-hot vocabulary for security. Fixed order so the matrix layout is stable
#: across runs and the fitted model stays compatible with new observations.
SECURITY_CATEGORIES = ("OPEN", "WEP", "WPA1", "WPA2", "WPA3", "OWE")

#: Encryption-strength ranks (see :func:`ai.models.security_rank`). Only the
#: difference between the observed and expected strength matters, so the
#: absolute value is only weakly informative; the one-hot columns above carry
#: the actual identity.
_SECURITY_RANK_BY_CATEGORY = {
    "OPEN": 0.0,
    "WEP": 1.0,
    "WPA1": 2.0,
    "WPA2": 3.0,
    "WPA3": 3.5,
    "OWE": 3.5,
}

FEATURE_GROUPS: Dict[str, Sequence[str]] = {
    "radio": ("signal", "signal_missing"),
    "plan": ("channel", "frequency", "band_ghz", "band_missing"),
    "security": (
        "sec_open",
        "sec_wep",
        "sec_wpa1",
        "sec_wpa2",
        "sec_wpa3",
        "sec_owe",
        "sec_other",
        "security_rank",
        "security_missing",
    ),
    "profile_agreement": (
        "known_bssid",
        "security_match",
        "channel_expected",
        "frequency_expected",
        "vendor_known",
        "vendor_missing",
        "profile_available",
        "has_profile_data",
    ),
    "deviation": (
        "channel_deviation",
        "channel_deviation_scaled",
        "frequency_deviation",
        "frequency_deviation_scaled",
        "deviation_count",
        "deviation_ratio",
    ),
    "observability": ("hidden",),
}

#: Authoritative, ordered feature layout. Any change here invalidates a fitted
#: model - bump :data:`MODEL_VERSION` and refit.
FEATURE_NAMES: tuple = tuple(
    name for group in ("radio", "plan", "security", "profile_agreement", "deviation", "observability")
    for name in FEATURE_GROUPS[group]
)

#: Bump when :data:`FEATURE_NAMES` changes, so a stale model is rejected
#: instead of silently scored against the wrong columns.
MODEL_VERSION = 1


def _tri(value: Optional[bool]) -> float:
    """Map a tri-state bool to 1.0 / 0.0 / 0.0 (unknown reads as neutral)."""
    if value is None:
        return 0.0
    return 1.0 if value else 0.0


def _scaled(value: Optional[int], scale: float) -> float:
    """Scale a raw deviation, clipping and mapping absence to 0.0."""
    if not value:
        return 0.0
    return min(abs(value) / scale, MAX_SCALED_DEVIATION)


def extract_features(
    network: Any,
    comparison: Optional[ProfileComparison] = None,
) -> Dict[str, float]:
    """Return the feature dict for one observation.

    ``comparison`` is the profile comparison from
    :func:`ai.trusted_profile.compare_to_profile`; passing ``None`` yields the
    no-profile variant of the vector.
    """
    net = WiFiNetwork.from_dict(network)
    cmp_ = comparison or ProfileComparison()

    signal = float(net.signal) if net.signal is not None else IMPUTE_SIGNAL
    channel = float(net.channel) if net.channel is not None else IMPUTE_CHANNEL
    frequency = float(net.frequency) if net.frequency is not None else IMPUTE_FREQUENCY
    band = net.band_ghz if net.band_ghz is not None else IMPUTE_BAND

    category = classify_security(net.security)
    rank = security_rank(net.security)

    features: Dict[str, float] = {
        # --- radio physics ------------------------------------------------
        "signal": signal,
        "signal_missing": 1.0 if net.signal is None else 0.0,
        # --- channel plan -------------------------------------------------
        "channel": channel,
        "frequency": frequency,
        "band_ghz": float(band),
        "band_missing": 1.0 if band == IMPUTE_BAND else 0.0,
        # --- security (one-hot + documented ordinal) -----------------------
        "security_rank": IMPUTE_RANK if rank is None else rank,
        "security_missing": 1.0 if rank is None else 0.0,
        # --- trusted-profile agreement ------------------------------------
        "known_bssid": _tri(cmp_.known_bssid),
        "security_match": _tri(cmp_.security_match),
        "channel_expected": _tri(cmp_.channel_expected),
        "frequency_expected": _tri(cmp_.frequency_expected),
        "vendor_known": _tri(cmp_.vendor_known),
        "vendor_missing": 0.0 if cmp_.vendor_known is not None else 1.0,
        "profile_available": 1.0 if cmp_.has_profile else 0.0,
        "has_profile_data": min(1.0, cmp_.expectation_count / 5.0),
        # --- deviation magnitude ------------------------------------------
        "channel_deviation": float(cmp_.channel_deviation or 0),
        "channel_deviation_scaled": _scaled(cmp_.channel_deviation, CHANNEL_DEVIATION_SCALE),
        "frequency_deviation": float(cmp_.frequency_deviation or 0),
        "frequency_deviation_scaled": _scaled(cmp_.frequency_deviation, FREQUENCY_DEVIATION_SCALE),
        "deviation_count": float(cmp_.deviation_count),
        "deviation_ratio": (
            cmp_.deviation_count / cmp_.expectation_count if cmp_.expectation_count else 0.0
        ),
        # --- observability ------------------------------------------------
        "hidden": 1.0 if net.hidden else 0.0,
    }

    for name in SECURITY_CATEGORIES:
        features[f"sec_{name.lower()}"] = 1.0 if category == name else 0.0
    features["sec_other"] = 0.0 if category in SECURITY_CATEGORIES else 1.0

    # Guard against key ordering mistakes: emit exactly FEATURE_NAMES, in order.
    return {name: float(features.get(name, 0.0)) for name in FEATURE_NAMES}


def feature_row(features: Mapping[str, float]) -> List[float]:
    """Convert a feature dict into a row ordered by :data:`FEATURE_NAMES`."""
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]


def build_feature_matrix(
    networks: Sequence[Any],
    comparisons: Optional[Sequence[Optional[ProfileComparison]]] = None,
) -> List[List[float]]:
    """Build a feature matrix for a batch of observations.

    Used to fit the Isolation Forest baseline. Returns a plain list of lists so
    it serialises cleanly and stays inspectable in a notebook during the
    hackathon; numpy conversion happens at the model boundary.
    """
    rows: List[List[float]] = []
    for index, net in enumerate(networks or ()):
        comparison = comparisons[index] if comparisons and index < len(comparisons) else None
        rows.append(feature_row(extract_features(net, comparison)))
    return rows
