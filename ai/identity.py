"""Network identity: what exactly are we looking at?

The central distinction this module exists to enforce::

    SSID  !=  access point identity

``SSID`` is an *advertised claim* - any device can broadcast any string it
likes, and a legitimate organisation routinely runs dozens of access points
under one name. The only stable per-device identifier in passive Wi-Fi
metadata is the **BSSID**, and the only thing that makes it evidence rather
than a label is the rest of the fingerprint around it.

So identity here is a compound::

    identity = (SSID, BSSID, OUI, channel, frequency, security, signal)

OUI / hardware prefix
---------------------
The first three octets of a BSSID identify the hardware vendor's block
(IEEE-assigned). We extract it and compare it against the OUIs already present
in the trusted profile's BSSIDs.

Two honest caveats, both load-bearing:

1. **nmcli does not report a vendor**, so in practice the ``vendor`` field is
   usually absent and OUI is the *only* hardware signal available. That is why
   this module works from the BSSID rather than depending on vendor strings.
2. **A spoofed BSSID can carry any OUI an attacker likes.** An OUI match is
   therefore weak *supporting* evidence of legitimacy, never proof. An OUI
   mismatch is weak negative evidence. Neither may on its own drive a
   "fake" verdict - which is exactly why :mod:`ai.verdict` requires
   corroboration across independent signal families.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from .models import WiFiNetwork, normalize_bssid, normalise_oui, oui_of

__all__ = [
    "oui_of",
    "normalise_oui",
    "NetworkIdentity",
    "identity_of",
    "OuiRegistry",
    "load_oui_registry",
    "DEFAULT_OUI_REGISTRY_PATH",
]

def ouis_of(bssids: Iterable[Optional[str]]) -> List[str]:
    """Return the sorted, de-duplicated OUIs of several BSSIDs."""
    return sorted({oui for oui in (oui_of(b) for b in bssids) if oui})


class NetworkIdentity:
    """A single observed access point, with its identity facts separated out.

    Distinguishing *claimed* attributes (SSID) from *observed* ones (BSSID,
    OUI, channel, security) is what stops the engine from ever reasoning from
    an SSID match alone.
    """

    __slots__ = ("ssid", "bssid", "oui", "channel", "frequency", "security", "signal", "vendor")

    def __init__(
        self,
        ssid: str,
        bssid: str,
        oui: str,
        channel: Optional[int],
        frequency: Optional[int],
        security: str,
        signal: Optional[int],
        vendor: Optional[str] = None,
    ) -> None:
        self.ssid = ssid
        self.bssid = bssid
        self.oui = oui
        self.channel = channel
        self.frequency = frequency
        self.security = security
        self.signal = signal
        self.vendor = vendor

    @property
    def key(self) -> str:
        """Stable per-access-point identity. Never the SSID."""
        return self.bssid or f"ssid:{self.ssid}"

    @property
    def has_hardware_identity(self) -> bool:
        """True when we know which vendor block this BSSID claims to be."""
        return bool(self.oui)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ssid": self.ssid,
            "bssid": self.bssid,
            "oui": self.oui,
            "channel": self.channel,
            "frequency": self.frequency,
            "security": self.security,
            "signal": self.signal,
            "vendor": self.vendor,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"NetworkIdentity(ssid={self.ssid!r}, bssid={self.bssid!r}, oui={self.oui!r})"


def identity_of(observation: Any) -> NetworkIdentity:
    """Build a :class:`NetworkIdentity` from a dict or scanner object."""
    net = WiFiNetwork.from_dict(observation)
    return NetworkIdentity(
        ssid=net.ssid,
        bssid=net.bssid,
        oui=oui_of(net.bssid),
        channel=net.channel,
        frequency=net.frequency,
        security=net.security,
        signal=net.signal,
        vendor=net.vendor,
    )


# ---------------------------------------------------------------------------
# Optional OUI -> vendor registry
# ---------------------------------------------------------------------------

DEFAULT_OUI_REGISTRY_PATH = Path(__file__).resolve().parent.parent / "config" / "oui_vendors.json"


class OuiRegistry:
    """Optional mapping of OUI prefix -> vendor name.

    Ships **empty** and is expected to stay small. It exists for display
    ("this BSSID claims to be a Cisco block") and for profiles that record
    vendor names; it is never required, because the scanner does not report a
    vendor and a fabricated one would be worse than none.

    A missing or unreadable file yields an empty registry rather than an
    error: this is enrichment, not a dependency.
    """

    def __init__(self, mapping: Optional[Mapping[str, str]] = None) -> None:
        self._mapping: Dict[str, str] = {}
        for oui, vendor in (mapping or {}).items():
            key = normalise_oui(oui)
            if key and vendor:
                self._mapping[key] = str(vendor).strip()

    def vendor_of(self, oui: Optional[str]) -> Optional[str]:
        """Return the vendor for ``oui``, or ``None`` if unknown."""
        key = normalise_oui(oui)
        return self._mapping.get(key) if key else None

    def known_ouis(self) -> List[str]:
        return sorted(self._mapping)

    def __len__(self) -> int:
        return len(self._mapping)


def load_oui_registry(path: Optional[Path] = None) -> OuiRegistry:
    """Load the optional OUI registry, tolerating absence or corruption."""
    target = Path(path) if path is not None else DEFAULT_OUI_REGISTRY_PATH
    if not target.is_file():
        return OuiRegistry()
    try:
        with target.open(encoding="utf-8") as handle:
            payload = json.load(handle)
    except (json.JSONDecodeError, OSError):
        return OuiRegistry()
    entries: Sequence[Any]
    if isinstance(payload, Mapping):
        entries = payload.get("ouis") or []
    elif isinstance(payload, list):
        entries = payload
    else:
        entries = []
    mapping = {
        str(item.get("oui")): item.get("vendor")
        for item in entries
        if isinstance(item, Mapping)
    }
    return OuiRegistry(mapping)
