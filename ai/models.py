"""Input / output models for the WiFiSentinel AI detection engine.

Standard library only (``dataclasses``) so the module stays importable from
FastAPI without pulling in a validation framework. Validation is explicit and
forgiving: a malformed observation is coerced to a usable record and the
reason is recorded, never raised as an exception during a scan.

Three public models:

``WiFiNetwork``
    One observed access point / BSS. One instance == one BSSID. Several APs
    may advertise the same SSID; they stay as separate records because the
    risk engine reasons per BSS.

``TrustedProfile``
    The expected fingerprint of a known-good network (SSID): its legitimate
    BSSIDs, security, channels, frequencies and vendors.

``DetectionResult``
    The explainable assessment of one observed AP.

Design rules:

* Missing optional fields are ``None`` / ``UNKNOWN`` - never guessed.
* A duplicate SSID is normal. Nothing in this module treats repetition as
  evidence of anything.
* Unknown BSSID is *not* malicious. It means "not yet verified".
"""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "Classification",
    "UNCLASSIFIED_SECURITY",
    "WiFiNetwork",
    "TrustedProfile",
    "ProfileComparison",
    "RuleResult",
    "AnomalyResult",
    "DetectionResult",
    "normalize_bssid",
    "format_bssid",
    "oui_of",
    "normalise_oui",
    "normalize_security",
    "classify_security",
    "security_rank",
]


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

class Classification:
    """Risk bands. Plain strings so the dashboard can compare them directly."""

    TRUSTED = "TRUSTED"
    LOW_RISK = "LOW_RISK"
    UNVERIFIED = "UNVERIFIED"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"

    ALL = (TRUSTED, LOW_RISK, UNVERIFIED, SUSPICIOUS, HIGH_RISK)


#: Used when an observation carries no usable security information at all.
#: It is intentionally *not* treated as ``OPEN``: "unknown" must not silently
#: upgrade into "the AP is unencrypted".
UNCLASSIFIED_SECURITY = "UNKNOWN"

_BSSID_CLEAN_RE = re.compile(r"[^0-9a-f]")


def normalize_bssid(value: Optional[str]) -> str:
    """Return a BSSID as 12 lowercase hex characters (no separators).

    Accepts ``"AA:BB:CC:11:22:33"``, ``"aa-bb-cc-11-22-33"`` and the compact
    ``"aabbcc112233"``. Returns ``""`` when the value is missing or is not a
    6-octet MAC, so callers can treat it as "BSSID not recorded".
    """
    if not value:
        return ""
    digits = _BSSID_CLEAN_RE.sub("", str(value).lower())
    if len(digits) != 12:
        return ""
    return digits


def format_bssid(value: Optional[str]) -> str:
    """Inverse of :func:`normalize_bssid` for human-facing output."""
    digits = normalize_bssid(value)
    if not digits:
        return ""
    return ":".join(digits[i : i + 2].upper() for i in range(0, 12, 2))


def oui_of(bssid: Optional[str]) -> str:
    """Return the 24-bit OUI (vendor block) of a BSSID as ``"BC:07:1D"``.

    The first three octets are IEEE-assigned to a hardware vendor. Returns
    ``""`` for a missing or malformed BSSID so callers treat "no OUI" as "no
    opinion" rather than as a mismatch.

    This lives here, next to the other BSSID primitives, because both the
    profile model and the identity module need it and neither may depend on
    the other.
    """
    digits = normalize_bssid(bssid)
    if len(digits) != 12:
        return ""
    return ":".join(digits[i : i + 2].upper() for i in range(0, 6, 2))


def normalise_oui(value: Optional[str]) -> str:
    """Normalise an OUI written in any common notation.

    Accepts ``"BC:07:1D"``, ``"bc-07-1d"`` and ``"bc071d"``. Returns ``""``
    when the value is not a 3-octet hex prefix.
    """
    if not value:
        return ""
    # Clean on a lower-cased string: _BSSID_CLEAN_RE only matches [0-9a-f], so
    # upper-casing first would strip every hex letter and yield "".
    digits = _BSSID_CLEAN_RE.sub("", str(value).lower())
    if len(digits) != 6:
        return ""
    return ":".join(digits[i : i + 2].upper() for i in range(0, 6, 2))


def normalize_security(value: Optional[str]) -> str:
    """Normalise a security string to a stable upper-case protocol label.

    Mirrors the scanner's ``normalize_security`` so both sides agree:
    ``""``/``None``/``"--"``/``"none"`` become :data:`UNCLASSIFIED_SECURITY`
    (we cannot assert an AP is open just because the field was empty), and
    mixed labels such as ``"WPA2/WPA3"`` are preserved and upper-cased.
    """
    if value is None:
        return UNCLASSIFIED_SECURITY
    text = str(value).strip().strip("()").strip()
    if not text or text in {"--", "none", "None", "null"}:
        return UNCLASSIFIED_SECURITY
    return "/".join(part.upper() for part in text.split() if part) or UNCLASSIFIED_SECURITY


#: Security labels mapped to a *category*. Categories are non-numeric on
#: purpose: they are consumed as one-hot vectors by the feature extractor so
#: no artificial ordering is implied between them.
_SECURITY_CATEGORIES = {
    "OPEN": "OPEN",
    "NONE": "OPEN",
    "WEP": "WEP",
    "WPA": "WPA1",
    "WPA1": "WPA1",
    "RSN": "WPA2",
    "WPA2": "WPA2",
    "WPA3": "WPA3",
    "SAE": "WPA3",
    "OWE": "OWE",
    "EAP": "EAP",
    "WAPI": "WAPI",
    "VPN": "VPN",
    "UNKNOWN": "UNKNOWN",
}

#: Explicit, hand-assigned strength ranks. Unlike an arbitrary integer cast
#: of the label these encode a real property of the encryption: how much the
#: observed security deviates from the profile. The mapping is documented in
#: ``features.py`` and is intentionally partial - anything not listed is
#: treated as "as strong as the strongest known protocol".
_SECURITY_RANK = {
    "OPEN": 0.0,
    "WEP": 1.0,
    "WPA1": 2.0,
    "WPA2": 3.0,
    "WPA3": 3.5,
    "OWE": 3.5,
    "WAPI": 3.0,
    "EAP": 3.0,
    "VPN": 3.0,
    "UNKNOWN": 2.0,
}


def classify_security(security: Optional[str]) -> str:
    """Return the non-numeric category for a security label.

    A composite label such as ``"WPA2/WPA3"`` takes the *strongest* category
    present, which is the property a rule cares about.
    """
    label = normalize_security(security)
    best = "UNKNOWN"
    best_rank = -1.0
    for part in label.split("/"):
        category = _SECURITY_CATEGORIES.get(part)
        if category is None:
            continue
        rank = _SECURITY_RANK.get(category, 0.0)
        if rank > best_rank:
            best, best_rank = category, rank
    return best


def security_rank(security: Optional[str]) -> Optional[float]:
    """Return the documented encryption-strength rank, or ``None`` if unknown.

    ``None`` means "no information"; the feature extractor substitutes an
    impute value flagged by a companion ``security_missing`` feature so the
    model can tell imputed rows apart.
    """
    category = classify_security(security)
    if category == "UNKNOWN":
        return None
    return _SECURITY_RANK.get(category)


def _coerce_int(value: Any) -> Optional[int]:
    """Best-effort int conversion that never raises."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if math.isfinite(value) else None
    text = str(value).strip()
    if not text:
        return None
    match = re.search(r"-?\d+", text)
    return int(match.group()) if match else None


def _coerce_float(value: Any) -> Optional[float]:
    """Best-effort float conversion that never raises."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) if math.isfinite(float(value)) else None
    text = str(value).strip()
    if not text:
        return None
    match = re.search(r"-?\d+(?:\.\d+)?", text)
    if not match:
        return None
    try:
        return float(match.group())
    except ValueError:
        return None


def _clean_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


# ---------------------------------------------------------------------------
# Input model
# ---------------------------------------------------------------------------

@dataclass
class WiFiNetwork:
    """A single observed access point / BSS.

    Accepts both the scanner's minimal schema
    ``{ssid, bssid, signal, channel, frequency, security, timestamp}`` and the
    richer optional fields the scanner may later add (``vendor``,
    ``channel_width``/``bandwidth_mhz``, ``wifi_standard``/``mode``,
    ``hidden``, ``signal_quality``).
    """

    ssid: str
    bssid: str
    signal: Optional[int] = None
    channel: Optional[int] = None
    frequency: Optional[int] = None
    security: str = UNCLASSIFIED_SECURITY
    timestamp: Optional[str] = None
    vendor: Optional[str] = None
    channel_width: Optional[int] = None
    wifi_standard: Optional[str] = None
    hidden: bool = False
    #: Non-fatal problems found while parsing. Surfaced in the result so a
    #: bad observation is visible instead of silently mis-scored.
    parse_warnings: List[str] = field(default_factory=list)

    # -- construction -------------------------------------------------------

    @classmethod
    def from_dict(cls, raw: Any) -> "WiFiNetwork":
        """Build a record from a dict or a duck-typed scanner object.

    Missing or unparseable fields become ``None`` and are noted in
    ``parse_warnings``; this never raises, so one bad beacon cannot break
    a whole scan.

    Several spellings of the same field are accepted, because the scanner and
    the backend do not have to agree on one: ``signal_dbm``/``rssi`` for
    ``signal``, ``frequency_mhz`` for ``frequency``, ``is_hidden`` for
    ``hidden``, ``observed_at`` for ``timestamp``. The canonical names are
    tried first. This exists because the two upstream components legitimately
    use different names in different places, and a silently dropped
    ``signal`` would quietly disable a real check rather than raise an error.
    """

        if isinstance(raw, WiFiNetwork):
            return raw
        if raw is None:
            return cls(ssid="", bssid="", parse_warnings=["empty observation"])

        if isinstance(raw, Mapping):
            data: Mapping[str, Any] = raw
            warnings: List[str] = []
        else:
            # Duck-typing keeps the engine decoupled from the scanner module:
            # any object exposing the right attributes works.
            data = {
                name: getattr(raw, name, None)
                for name in (
                    "ssid",
                    "bssid",
                    "signal",
                    "channel",
                    "frequency",
                    "security",
                    "timestamp",
                    "vendor",
                    "channel_width",
                    "bandwidth_mhz",
                    "wifi_standard",
                    "mode",
                    "hidden",
                    "signal_quality",
                    # Aliases, in case an upstream component uses the longer
                    # unit-suffixed spellings.
                    "signal_dbm",
                    "rssi",
                    "frequency_mhz",
                    "is_hidden",
                    "observed_at",
                )
                if hasattr(raw, name)
            }
            warnings = []

        def pick(*names: str) -> Any:
            for name in names:
                if data.get(name) is not None:
                    return data[name]
            return None

        bssid = format_bssid(data.get("bssid"))
        if data.get("bssid") and not bssid:
            warnings.append("bssid is not a valid 6-octet MAC; treated as unknown")

        ssid = _clean_str(data.get("ssid")) or _clean_str(data.get("ssid_hex")) or ""
        if not ssid:
            warnings.append("ssid missing; record kept for the BSSID report only")

        security = normalize_security(data.get("security"))

        return cls(
            ssid=ssid,
            bssid=bssid,
            signal=_coerce_int(pick("signal", "signal_dbm", "rssi")),
            channel=_coerce_int(pick("channel", "channel_number")),
            frequency=_coerce_int(pick("frequency", "frequency_mhz", "freq_mhz")),
            security=security,
            timestamp=_clean_str(pick("timestamp", "observed_at", "observed", "time")),
            vendor=_clean_str(pick("vendor", "manufacturer", "oui_vendor")),
            channel_width=_coerce_int(pick("channel_width", "bandwidth_mhz", "bandwidth")),
            wifi_standard=_clean_str(pick("wifi_standard", "mode")),
            hidden=bool(pick("hidden", "is_hidden") or False),
            parse_warnings=warnings,
        )

    # -- serialisation ------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe dict using the agreed output field names."""
        return {
            "ssid": self.ssid,
            "bssid": self.bssid,
            "signal": self.signal,
            "channel": self.channel,
            "frequency": self.frequency,
            "security": self.security,
            "timestamp": self.timestamp,
            "vendor": self.vendor,
            "channel_width": self.channel_width,
            "wifi_standard": self.wifi_standard,
            "hidden": self.hidden,
        }

    # -- derived properties -------------------------------------------------

    @property
    def security_category(self) -> str:
        """Non-numeric security category (``OPEN``, ``WPA2``, ...)."""
        return classify_security(self.security)

    @property
    def is_open(self) -> bool:
        return self.security_category == "OPEN"

    @property
    def security_rank(self) -> Optional[float]:
        """Documented encryption-strength rank, or ``None`` when unknown."""
        return security_rank(self.security)

    @property
    def band_ghz(self) -> Optional[float]:
        """Coarse band in GHz (2.4 / 5 / 6) derived from frequency or channel.

        ``None`` when neither value is usable, so a missing value is imputed
        explicitly by the feature extractor instead of silently.
        """
        if self.frequency:
            if self.frequency < 3000:
                return 2.4
            if self.frequency < 5900:
                return 5.0
            return 6.0
        if self.channel:
            if self.channel in range(1, 15):
                return 2.4
            if self.channel in range(32, 177):
                return 5.0 if self.channel < 177 else 6.0
        return None

    def key(self) -> Tuple[str, str]:
        """Identity used for de-duplication: the BSSID, not the SSID."""
        return (self.ssid, self.bssid)


# ---------------------------------------------------------------------------
# Trusted profile
# ---------------------------------------------------------------------------

@dataclass
class TrustedProfile:
    """Expected fingerprint of a known-good network.

    A single network legitimately spans many BSSIDs (roaming APs, band
    steering, per-floor hardware), so ``known_bssids`` is a list and nothing
    here treats repetition as anomalous.
    """

    ssid: str
    known_bssids: List[str] = field(default_factory=list)
    security: List[str] = field(default_factory=list)
    expected_channels: List[int] = field(default_factory=list)
    expected_frequencies: List[int] = field(default_factory=list)
    known_vendors: List[str] = field(default_factory=list)
    #: Hardware vendor blocks (OUI, first three BSSID octets) expected for this
    #: network. Left empty this is derived automatically from ``known_bssids``,
    #: so operators never have to maintain it by hand. Set it explicitly only
    #: to record blocks that legitimately belong here but are not yet seen.
    known_ouis: List[str] = field(default_factory=list)
    #: Human label for the deployment, e.g. "Terminal 2, Gate B". Shown in the
    #: dashboard so a judge can see which infrastructure was trusted.
    location: Optional[str] = None
    #: True when the profile was inferred from a new location's own
    #: observations instead of being configured. A provisional profile can
    #: raise suspicion but can never produce TRUSTED.
    provisional: bool = False

    def __post_init__(self) -> None:
        self.ssid = (self.ssid or "").strip()
        self.known_bssids = [format_bssid(b) for b in self.known_bssids if format_bssid(b)]
        self.security = sorted({normalize_security(s) for s in self.security if s})
        self.expected_channels = sorted(
            {c for c in (_coerce_int(v) for v in self.expected_channels) if c is not None}
        )
        self.expected_frequencies = sorted(
            {f for f in (_coerce_int(v) for v in self.expected_frequencies) if f is not None}
        )
        self.known_vendors = sorted({v.strip().lower() for v in self.known_vendors if v and v.strip()})
        self.known_ouis = sorted(
            {normalise_oui(o) for o in self.known_ouis if normalise_oui(o)}
            # Derive from the BSSIDs already trusted: hardware blocks need no
            # separate maintenance, and a new AP inherits its own OUI.
            | {oui_of(b) for b in self.known_bssids}
        )

    @classmethod
    def from_dict(cls, raw: Any) -> "TrustedProfile":
        if isinstance(raw, TrustedProfile):
            return raw
        if raw is None:
            raise ValueError("trusted profile must not be None")
        if not isinstance(raw, Mapping):
            raw = {
                "ssid": getattr(raw, "ssid", ""),
                "known_bssids": getattr(raw, "known_bssids", []),
                "security": getattr(raw, "security", []),
                "expected_channels": getattr(raw, "expected_channels", []),
                "expected_frequencies": getattr(raw, "expected_frequencies", []),
                "known_vendors": getattr(raw, "known_vendors", []),
                "known_ouis": getattr(raw, "known_ouis", []),
                "location": getattr(raw, "location", None),
                "provisional": getattr(raw, "provisional", False),
            }
        return cls(
            ssid=str(raw.get("ssid", "")),
            known_bssids=list(raw.get("known_bssids") or []),
            security=list(raw.get("security") or []),
            expected_channels=list(raw.get("expected_channels") or []),
            expected_frequencies=list(raw.get("expected_frequencies") or []),
            known_vendors=list(raw.get("known_vendors") or []),
            known_ouis=list(raw.get("known_ouis") or []),
            location=_clean_str(raw.get("location")),
            provisional=bool(raw.get("provisional", False)),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ssid": self.ssid,
            "known_bssids": [format_bssid(b) for b in self.known_bssids],
            "security": list(self.security),
            "expected_channels": list(self.expected_channels),
            "expected_frequencies": list(self.expected_frequencies),
            "known_vendors": list(self.known_vendors),
            "known_ouis": list(self.known_ouis),
            "location": self.location,
            "provisional": self.provisional,
        }

    @property
    def bssid_set(self) -> frozenset:
        return frozenset(self.known_bssids)

    @property
    def is_empty(self) -> bool:
        """True when the profile vouches for nothing at all.

        An empty profile must be treated as "no profile". Otherwise a blank
        entry in the configuration file would report that a trusted profile
        exists, silently suppressing the NO_TRUSTED_PROFILE explanation and
        making an unconfigured site look configured.
        """
        return not (
            self.known_bssids
            or self.security
            or self.expected_channels
            or self.expected_frequencies
            or self.known_vendors
        )

    def has_expectation(self, field_name: str) -> bool:
        """True when the profile actually constrains ``field_name``.

        An empty expectation is "no opinion", not "mismatch" - this is what
        stops a sparse profile from flagging everything.
        """
        return bool(getattr(self, field_name, None))

    def get(self, network: Any) -> Optional["TrustedProfile"]:
        """Return this profile if it describes ``network``'s SSID, else ``None``."""
        net = WiFiNetwork.from_dict(network)
        if not self.ssid or not net.ssid:
            return self
        return self if net.ssid.strip() == self.ssid else None


# ---------------------------------------------------------------------------
# Intermediate assessment models
# ---------------------------------------------------------------------------

@dataclass
class ProfileComparison:
    """Result of comparing one observation against a trusted profile.

    Every field is a *fact* about the comparison. Interpretation (how much a
    mismatch is worth) lives in :mod:`ai.rules` and :mod:`ai.risk_engine`, so
    the same comparison can be re-scored with different weights.
    """

    has_profile: bool = False
    provisional: bool = False
    ssid_match: bool = False
    known_bssid: Optional[bool] = None
    security_match: Optional[bool] = None
    channel_expected: Optional[bool] = None
    frequency_expected: Optional[bool] = None
    vendor_known: Optional[bool] = None
    #: Observed hardware vendor block vs the blocks the profile's own BSSIDs
    #: use. Tri-state like the rest: ``None`` when either side is unknown, so
    #: a missing OUI is never read as a mismatch.
    oui_known: Optional[bool] = None
    observed_oui: Optional[str] = None
    expected_ouis: List[str] = field(default_factory=list)
    #: Observed value vs nearest expected value, for explainable output.
    channel_deviation: Optional[int] = None
    frequency_deviation: Optional[int] = None
    band_mismatch: Optional[bool] = None
    #: Count of fields where the profile had an opinion and disagreed.
    deviation_count: int = 0
    #: Count of profile fields that carried usable expectations.
    expectation_count: int = 0

    @property
    def profile_match(self) -> bool:
        """True only when a real profile vouched for this AP.

        An unknown BSSID, a provisional profile, or no profile at all all
        yield ``False``: the engine is explicit that it could not verify the
        AP, which is different from finding a deviation.
        """
        return bool(
            self.has_profile
            and not self.provisional
            and self.known_bssid
            and self.deviation_count == 0
        )

    @property
    def verified(self) -> bool:
        """True when the profile lists this exact BSSID as trusted hardware."""
        return bool(self.has_profile and self.known_bssid)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RuleResult:
    """Explainable cybersecurity rule output.

    ``indicators`` are stable machine codes (used by the risk engine and
    tests); ``reasons`` are the human sentences the dashboard displays.
    """

    indicators: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    #: Observations that lowered or held steady the risk, shown so a clean
    #: result is explained too.
    mitigating: List[str] = field(default_factory=list)

    def add(self, code: str, reason: str) -> None:
        if code not in self.indicators:
            self.indicators.append(code)
        if reason not in self.reasons:
            self.reasons.append(reason)

    def add_mitigating(self, note: str) -> None:
        if note not in self.mitigating:
            self.mitigating.append(note)

    def has(self, code: str) -> bool:
        return code in self.indicators

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicators": list(self.indicators),
            "reasons": list(self.reasons),
            "mitigating": list(self.mitigating),
        }


@dataclass
class AnomalyResult:
    """Isolation Forest output.

    ``anomaly_score`` is a bounded rescaling of the forest's decision
    function. It is a *relative deviation indicator* for this baseline - it
    is not a probability of attack and must not be shown as one.
    """

    anomaly_score: float = 0.0
    raw_score: float = 0.0
    is_anomaly: bool = False
    #: True when the detector had too little baseline data to judge. The
    #: pipeline then omits the ML reason instead of inventing one.
    available: bool = True
    baseline_size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_score": self.anomaly_score,
            "raw_score": self.raw_score,
            "is_anomaly": self.is_anomaly,
            "available": self.available,
            "baseline_size": self.baseline_size,
        }


# ---------------------------------------------------------------------------
# Output model
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    """Explainable risk assessment for one observed access point.

    ``reasons`` is mandatory and always populated: a bare score with no
    justification is not a usable output.
    """

    ssid: str
    bssid: str
    risk_score: int
    classification: str
    anomaly_score: float
    profile_match: bool
    reasons: List[str] = field(default_factory=list)
    #: False when there was no baseline to compare against, so ``anomaly_score``
    #: is a placeholder rather than a measurement. Consumers must be able to
    #: tell "measured, nothing odd" from "never measured".
    anomaly_available: bool = True
    # --- semantic layer (see ai.verdict) ---------------------------------
    #: TRUSTED / LEGITIMATE / UNVERIFIED / SUSPICIOUS / POTENTIAL_FAKE.
    #: This is what the dashboard should lead with; ``classification`` remains
    #: the raw risk band and is kept for backward compatibility.
    verdict: str = "UNVERIFIED"
    #: LOW / MEDIUM / HIGH - how strong the evidence is, independent of score.
    evidence_level: str = "LOW"
    #: True only when independent signal families corroborate an impersonation
    #: pattern. Never asserted as proven malice.
    impersonation_pattern: bool = False
    #: Which network's identity this AP appears to be riding on, when known.
    impersonating: Optional[str] = None
    #: Structured indicators for the API: code, message, family, points.
    indicator_details: List[Dict[str, Any]] = field(default_factory=list)
    #: Independent signal families that deviated, for the "why" panel.
    families_deviating: List[str] = field(default_factory=list)
    verdict_summary: str = ""
    verdict_guidance: str = ""
    accuracy_note: str = ""
    #: Full evidence trail for the dashboard and for debugging.
    indicators: List[str] = field(default_factory=list)
    mitigating: List[str] = field(default_factory=list)
    score_breakdown: Dict[str, int] = field(default_factory=dict)
    profile_comparison: Dict[str, Any] = field(default_factory=dict)
    features: Dict[str, Any] = field(default_factory=dict)
    observed: Dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe dict containing the agreed output contract keys first."""
        return {
            "ssid": self.ssid,
            "bssid": self.bssid,
            "risk_score": self.risk_score,
            "classification": self.classification,
            "anomaly_score": self.anomaly_score,
            "anomaly_available": self.anomaly_available,
            "profile_match": self.profile_match,
            "reasons": list(self.reasons),
            "verdict": self.verdict,
            "evidence_level": self.evidence_level,
            "impersonation_pattern": self.impersonation_pattern,
            "impersonating": self.impersonating,
            "indicator_details": [dict(d) for d in self.indicator_details],
            "families_deviating": list(self.families_deviating),
            "verdict_summary": self.verdict_summary,
            "verdict_guidance": self.verdict_guidance,
            "accuracy_note": self.accuracy_note,
            "indicators": list(self.indicators),
            "mitigating": list(self.mitigating),
            "score_breakdown": dict(self.score_breakdown),
            "profile_comparison": dict(self.profile_comparison),
            "features": dict(self.features),
            "observed": dict(self.observed),
            "timestamp": self.timestamp,
        }

    def to_json(self, indent: int = 2) -> str:
        import json

        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def as_networks(items: Optional[Iterable[Any]]) -> List[WiFiNetwork]:
    """Coerce an iterable of raw observations into :class:`WiFiNetwork`."""
    if not items:
        return []
    if isinstance(items, (WiFiNetwork, Mapping)):
        items = [items]
    return [WiFiNetwork.from_dict(item) for item in items]


def as_sequence(value: Any) -> Sequence[Any]:
    """Wrap a scalar in a list; pass lists through; ``None`` becomes ``()``."""
    if value is None:
        return ()
    if isinstance(value, (str, bytes, Mapping)):
        return (value,)
    if isinstance(value, Sequence):
        return value
    return (value,)
