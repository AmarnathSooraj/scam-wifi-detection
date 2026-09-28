"""Data model for observed Wi-Fi access points.

Deliberately stdlib-only (dataclasses). The JSON produced by
:meth:`ScanResult.to_dict` is the contract that the backend and AI components
depend on, so field names and types are treated as a public API.

Design rules:

* One record per **BSSID**, never per SSID. Several APs may advertise the
  same SSID; merging them would destroy information the risk engine needs.
* Never invent data. A value that could not be read is ``None``, not a
  guess. The single exception is ``frequency``, which is derived from
  ``channel`` via the IEEE 802.11 channel plan when nmcli omits it.
* An unknown BSSID is *not* suspicious. This module records observations and
  makes no judgement about them.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

__all__ = [
    "WiFiNetwork",
    "ScanResult",
    "iso_timestamp",
    "channel_to_frequency",
]

# IEEE 802.11 channel -> centre frequency (MHz).
#
# 2.4 GHz: channels 1-13 are 2412 + 5 * (n - 1); channel 14 is 2484.
#          (Channel 8 -> 2447 matches what nmcli reports in practice.)
# 5 GHz:   every 5 GHz channel is 5000 + 5 * channel
#          (36 -> 5180, 149 -> 5745, 165 -> 5825).
# 6 GHz:   channels are 5950 + 5 * channel, covered below.
_FIRST_FIVE_GHZ_CHANNEL = 32


def channel_to_frequency(channel: Optional[int]) -> Optional[int]:
    """Return the centre frequency in MHz for a Wi-Fi channel.

    Used only as a fallback when nmcli does not report a frequency. Returns
    ``None`` for unknown or out-of-plan channels rather than guessing.
    """
    if channel is None:
        return None
    if 1 <= channel <= 13:
        return 2412 + (5 * (channel - 1))
    if channel == 14:
        return 2484
    if channel >= _FIRST_FIVE_GHZ_CHANNEL:
        return 5000 + (5 * channel)
    return None


def iso_timestamp(moment: Optional[datetime] = None) -> str:
    """Return a stable, timezone-aware ISO-8601 timestamp.

    The example schema shows a naive local timestamp. We emit an explicit
    UTC offset instead so records from multiple machines are unambiguous and
    sortable.
    """
    moment = moment or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


@dataclass
class WiFiNetwork:
    """A single observed access point / BSS.

    One instance == one BSSID. Two APs broadcasting ``"CEV_WIFI"`` produce
    two instances with different ``bssid`` values.
    """

    ssid: str
    bssid: str
    signal: Optional[int] = None
    channel: Optional[int] = None
    frequency: Optional[int] = None
    security: str = "OPEN"
    timestamp: str = field(default_factory=iso_timestamp)

    # --- Optional / supplementary fields ---------------------------------
    # Present only when nmcli reported them reliably. They are additive and
    # never replace the core fields above.
    #
    # `signal` is dBm (negative). `signal_quality` is nmcli's native 0-100
    # figure, kept because `signal` is a derived estimate - see config.py.
    signal_quality: Optional[int] = None
    ssid_hex: Optional[str] = None
    hidden: bool = False
    bandwidth_mhz: Optional[int] = None
    mode: Optional[str] = None

    def to_dict(self, include_optional: bool = True) -> Dict[str, Any]:
        """Serialise to a JSON-safe dict.

        ``include_optional=False`` yields exactly the minimal schema that the
        agreed output example specifies.
        """
        payload: Dict[str, Any] = {
            "ssid": self.ssid,
            "bssid": self.bssid,
            "signal": self.signal,
            "channel": self.channel,
            "frequency": self.frequency,
            "security": self.security,
            "timestamp": self.timestamp,
        }
        if include_optional:
            payload["signal_quality"] = self.signal_quality
            payload["ssid_hex"] = self.ssid_hex
            payload["hidden"] = self.hidden
            payload["bandwidth_mhz"] = self.bandwidth_mhz
            payload["mode"] = self.mode
        return payload

    @property
    def is_open(self) -> bool:
        return self.security.upper() == "OPEN"

    def merge(self, other: "WiFiNetwork") -> "WiFiNetwork":
        """Merge a duplicate observation of the same BSSID.

        nmcli normally de-duplicates within one scan, but a BSS observed
        without its SSID in one beacon and with the SSID in a later probe
        response can appear twice. Keep the most informative value for each
        field and the strongest signal reading.
        """
        def pick_str(new: str, old: str) -> str:
            return new if new else old

        def pick_opt(new: Any, old: Any) -> Any:
            return new if new is not None else old

        strongest = self
        if other.signal is not None and (self.signal is None or other.signal > self.signal):
            strongest = other

        return WiFiNetwork(
            ssid=pick_str(other.ssid, self.ssid),
            bssid=self.bssid,
            signal=strongest.signal,
            channel=pick_opt(other.channel, self.channel),
            frequency=pick_opt(other.frequency, self.frequency),
            security=pick_str(other.security, self.security),
            timestamp=self.timestamp,
            signal_quality=pick_opt(strongest.signal_quality, self.signal_quality),
            ssid_hex=pick_str(other.ssid_hex, self.ssid_hex or ""),
            hidden=self.hidden and other.hidden,
            bandwidth_mhz=pick_opt(other.bandwidth_mhz, self.bandwidth_mhz),
            mode=pick_str(other.mode, self.mode or ""),
        )


@dataclass
class ScanResult:
    """The complete result of one scan: a timestamp plus every AP seen."""

    timestamp: str
    networks: List[WiFiNetwork] = field(default_factory=list)
    interface: Optional[str] = None
    schema_version: str = "1.0"

    def to_dict(self, include_optional: bool = True) -> Dict[str, Any]:
        """Serialise to the agreed top-level schema."""
        payload: Dict[str, Any] = {
            "timestamp": self.timestamp,
            "networks": [n.to_dict(include_optional) for n in self.networks],
        }
        if include_optional:
            payload["interface"] = self.interface
            payload["schema_version"] = self.schema_version
            payload["network_count"] = len(self.networks)
        return payload

    def to_json(self, indent: int = 2, include_optional: bool = True) -> str:
        import json

        return json.dumps(self.to_dict(include_optional), indent=indent, ensure_ascii=False)

    def __len__(self) -> int:
        return len(self.networks)

    def __iter__(self):
        return iter(self.networks)
