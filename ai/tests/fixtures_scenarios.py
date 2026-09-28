"""Fixtures for the impersonation-detection tests.

Every value here is invented and exists only under ``ai/tests/``. Nothing in
this module is reachable from the application: the production path reads real
observations from the Wi-Fi adapter and real profiles from
``config/trusted_networks.json``.

The shape mirrors a real managed network so the assertions are about
behaviour, not about magic numbers.
"""

from __future__ import annotations

#: A plausible managed network: three access points from two hardware vendors
#: (one shared OUI), spread over 2.4 and 5 GHz, all WPA2.
OFFICE_PROFILE = {
    "ssid": "Office_Net",
    "location": "Building A, floors 1-3",
    "known_bssids": [
        "10:27:F5:F3:9B:B1",  # OUI 10:27:F5
        "10:27:F5:F3:9B:B2",  # OUI 10:27:F5  (same vendor block)
        "BC:07:1D:66:C2:E1",  # OUI BC:07:1D
    ],
    "security": ["WPA2"],
    # Channel plan covers the three access points in ``multi_ap_setup()``
    # (1, 11, 149) plus 36. Channel 6 / 2437 MHz is deliberately NOT in the
    # plan so the rogue fixture lands on a genuinely foreign channel.
    "expected_channels": [1, 11, 36, 149],
    "expected_frequencies": [2412, 2462, 5180, 5745],
}

#: An expected-OUI block that is legitimate here but has not been seen yet.
#: Used to prove a new AP from a known vendor is recognised, not suspected.
KNOWN_VENDOR_BSSID = "10:27:F5:AA:BB:C1"


def known_ap(**overrides):
    """A verified access point: known BSSID, expected channel and security."""
    record = {
        "ssid": "Office_Net",
        "bssid": "10:27:F5:F3:9B:B1",
        "signal": -55,
        "channel": 36,
        "frequency": 5180,
        "security": "WPA2",
        "timestamp": "2026-09-29T10:00:00+00:00",
    }
    record.update(overrides)
    return record


def multi_ap_setup():
    """The legitimate case from the brief: three APs, one SSID, three channels.

    None of these may be called fake simply for sharing an SSID.
    """
    return [
        known_ap(bssid="10:27:F5:F3:9B:B1", security="WPA2", channel=1, frequency=2412),
        known_ap(bssid="10:27:F5:F3:9B:B2", security="WPA2", channel=11, frequency=2462),
        known_ap(bssid="BC:07:1D:66:C2:E1", security="WPA2", channel=149, frequency=5745),
    ]


def unknown_bssid_ap(**overrides):
    """Same SSID, unknown BSSID, but everything else exactly as expected."""
    record = {
        "ssid": "Office_Net",
        "bssid": "DE:AD:BE:EF:00:01",
        "signal": -50,
        "channel": 36,
        "frequency": 5180,
        "security": "WPA2",
        "timestamp": "2026-09-29T10:00:00+00:00",
    }
    record.update(overrides)
    return record


def security_downgrade_ap(**overrides):
    """Unknown BSSID plus an encryption downgrade - the classic pattern."""
    record = {"security": "OPEN"}
    record.update(overrides)
    return unknown_bssid_ap(**record)


def full_impersonation_ap(**overrides):
    """Every independent part of the fingerprint wrong at once.

    Overrides are merged over the defaults rather than splatted as keyword
    arguments, so a caller may replace any field (``channel=11``) without
    colliding with the defaults.
    """
    record = {
        "signal": -35,
        "channel": 6,
        "frequency": 2437,
        "security": "OPEN",
    }
    record.update(overrides)
    return unknown_bssid_ap(**record)
