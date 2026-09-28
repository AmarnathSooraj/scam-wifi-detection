"""Central configuration for the Wi-Fi scanner.

Everything tunable lives here so the rest of the package stays free of
magic values. All values can be overridden through environment variables,
which keeps the module free of external dependencies.
"""

from __future__ import annotations

import os

# --- External tools -------------------------------------------------------

NMCLI_BIN = os.environ.get("WIFISENTINEL_NMCLI", "nmcli")

# --- Timeouts (seconds) ---------------------------------------------------

# `nmcli device wifi rescan` returns immediately: NetworkManager performs the
# scan asynchronously in the background, and (measured on nmcli 1.56) the
# cache keeps showing the PREVIOUS scan's results for ~5 s before the new ones
# arrive. SCAN_SETTLE_SECONDS is therefore a hard ceiling, not a fixed sleep.
SCAN_SETTLE_SECONDS = float(os.environ.get("WIFISENTINEL_SETTLE", "20.0"))

# Hard time floor before the cache may be trusted. Measured on this machine:
# the previous scan's results stay cached and unchanged for ~5.5 s, and a
# rescan issued while another is in flight leaves the cache PARTIALLY
# populated (7 of 14 APs) that looks perfectly stable. Anything under ~6 s
# therefore returns stale or half-populated data, so the floor sits at 7 s.
SCAN_MIN_WAIT_SECONDS = float(os.environ.get("WIFISENTINEL_MIN_WAIT", "7.0"))

# Consecutive identical reads required after the floor, so that late 5 GHz
# arrivals are included.
SCAN_STABLE_ROUNDS = int(os.environ.get("WIFISENTINEL_STABLE_ROUNDS", "2"))

SCAN_POLL_INTERVAL = float(os.environ.get("WIFISENTINEL_POLL", "0.4"))
NMCLI_TIMEOUT = float(os.environ.get("WIFISENTINEL_TIMEOUT", "30"))

# --- nmcli field selection ------------------------------------------------

# Only request fields verified against `nmcli device wifi list --help` on
# NetworkManager >= 1.36. `IN-USE` and `ACTIVE` are intentionally excluded:
#   * IN-USE prefixes the SSID with '*', which corrupts the value.
#   * ACTIVE is only "yes" for the single associated AP and "no" for every
#     other AP we just successfully heard, so it cannot be used to filter.
# SSID-HEX is requested as a lossless fallback for SSIDs that terse mode
# cannot round-trip (e.g. embedded newlines).
WIFI_FIELDS = (
    "BSSID",
    "SSID",
    "SSID-HEX",
    "MODE",
    "CHAN",
    "FREQ",
    "SIGNAL",
    "SECURITY",
    "BANDWIDTH",
)

# The order above must match WIFI_FIELDS; parsing is positional.
FIELD_ORDER = WIFI_FIELDS

# Device listing fields used to find a usable Wi-Fi interface.
DEVICE_FIELDS = ("DEVICE", "TYPE", "STATE")

# Device types that are real scan-capable Wi-Fi radios. `wifi-p2p` (the
# p2p-dev-* devices) is deliberately excluded: it cannot perform a scan.
SCANNABLE_DEVICE_TYPES = frozenset({"wifi"})

# --- Security normalisation ----------------------------------------------

# nmcli reports an open network as an empty SECURITY field. The published
# schema requires an explicit value, so map empty to this.
OPEN_SECURITY = "OPEN"

# --- Signal units ---------------------------------------------------------
#
# IMPORTANT: nmcli's SIGNAL field is a 0-100 quality percentage, NOT dBm,
# even though the nmcli table header and the team's agreed schema example
# both suggest otherwise. NetworkManager derives it from RSSI with:
#
#     percent = clamp((rssi_dbm + 100) * 2, 0, 100)
#
# so the inverse is rssi_dbm = percent / 2 - 100.
#
# The agreed JSON schema shows "signal": -45 (dBm), so we publish the
# converted dBm in `signal` and keep the raw 0-100 value in `signal_quality`
# so no information is lost. Consumers needing true RSSI must use `iw`
# (not installed by default); see the README's limitations section.

SIGNAL_QUALITY_MIN = 0
SIGNAL_QUALITY_MAX = 100


def quality_to_dbm(quality: int) -> int:
    """Convert nmcli's 0-100 SIGNAL percentage to a dBm estimate."""
    clamped = max(SIGNAL_QUALITY_MIN, min(SIGNAL_QUALITY_MAX, quality))
    return int(round(clamped / 2.0 - 100))

# nmcli reports pairwise ciphers (e.g. "RSN pairwise-CCMP TKIP") in some
# versions. Drop them so SECURITY stays a protocol description.
_CIPHER_TOKENS = frozenset(
    {
        "tkip",
        "ccmp",
        "pair_ccmp",
        "pair_tkip",
        "group_ccmp",
        "group_tkip",
        "sae",
        "psk",
        "802.1x",
        "wpa",
    }
)

# --- Output ---------------------------------------------------------------

SCHEMA_VERSION = "1.0"
DEFAULT_OUTPUT_DIR = os.environ.get("WIFISENTINEL_OUTDIR", "scans")
