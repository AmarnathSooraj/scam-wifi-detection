"""WiFiSentinel AI - networking and Wi-Fi scanner component.

Passive observation of nearby Wi-Fi access points via NetworkManager's
``nmcli``. This package is independent of the AI, risk-engine and dashboard
components; it only produces a stable JSON schema for them to consume.
"""

from __future__ import annotations

from .models import ScanResult, WiFiNetwork, channel_to_frequency, iso_timestamp
from .scanner import (
    InterfaceNotFoundError,
    NetworkManagerUnavailableError,
    NoWifiAdapterError,
    PermissionDeniedError,
    ScanFailedError,
    ScannerError,
    WifiDisabledError,
    scan_wifi,
)
from .parser import normalize_security, parse_nmcli_terse, split_unescaped

__version__ = "1.0.0"

__all__ = [
    "scan_wifi",
    "ScanResult",
    "WiFiNetwork",
    "iso_timestamp",
    "channel_to_frequency",
    "parse_nmcli_terse",
    "split_unescaped",
    "normalize_security",
    "ScannerError",
    "NoWifiAdapterError",
    "WifiDisabledError",
    "NetworkManagerUnavailableError",
    "PermissionDeniedError",
    "InterfaceNotFoundError",
    "ScanFailedError",
    "__version__",
]
