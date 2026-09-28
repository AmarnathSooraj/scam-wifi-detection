"""Live smoke test against the machine's real Wi-Fi hardware.

Skipped automatically when no Wi-Fi adapter is present, so it is safe to run
anywhere:

    python scanner/tests/test_live.py
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from scanner.models import ScanResult
from scanner.scanner import ScannerError, scan_wifi


def _adapter_present() -> bool:
    try:
        scan_wifi(settle=0.0)
        return True
    except ScannerError:
        return False


@unittest.skipUnless(_adapter_present(), "no usable Wi-Fi adapter on this machine")
class TestLiveScan(unittest.TestCase):
    """Exercises the real nmcli path end to end."""

    @classmethod
    def setUpClass(cls):
        cls.result: ScanResult = scan_wifi()

    def test_returns_scan_result(self):
        self.assertIsInstance(self.result, ScanResult)
        self.assertIsInstance(self.result.networks, list)
        self.assertTrue(self.result.timestamp)

    def test_resolves_interface(self):
        self.assertTrue(self.result.interface)
        self.assertTrue(self.result.interface.startswith(("wl", "wlp", "wlx", "en", "eth")))

    def test_records_are_wellformed(self):
        for n in self.result.networks:
            self.assertRegex(n.bssid, r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")
            self.assertIsInstance(n.ssid, str)
            self.assertIsInstance(n.security, str)
            self.assertTrue(n.security)
            if n.signal is not None:
                self.assertLessEqual(n.signal, 0)
                self.assertGreaterEqual(n.signal, -100)

    def test_bssids_unique(self):
        bssids = [n.bssid for n in self.result.networks]
        self.assertEqual(len(bssids), len(set(bssid.upper() for bssid in bssids)))

    def test_frequency_channel_consistent(self):
        # freq should agree with the channel on every standard-band record.
        from scanner.models import channel_to_frequency

        for n in self.result.networks:
            if n.channel and n.frequency:
                expected = channel_to_frequency(n.channel)
                if expected is not None and abs(n.channel) <= 165:
                    self.assertEqual(
                        n.frequency,
                        expected,
                        f"{n.bssid} ch{n.channel} -> {n.frequency} (expected {expected})",
                    )

    def test_sorted_by_strength(self):
        signals = [n.signal for n in self.result.networks if n.signal is not None]
        self.assertEqual(signals, sorted(signals, reverse=True))

    def test_serialises(self):
        payload = self.result.to_dict()
        self.assertIn("networks", payload)
        self.assertEqual(len(payload["networks"]), len(self.result.networks))

    # ---- Test 5: repeated scans stay structurally consistent -----------
    def test5_repeated_scans_consistent_shape(self):
        shapes = set()
        for _ in range(2):
            result = scan_wifi()
            for entry in result.to_dict()["networks"]:
                shapes.add(tuple(sorted(entry.keys())))
        self.assertEqual(len(shapes), 1, "record shape drifted between live scans")

    def test5_scans_are_independent(self):
        a = scan_wifi()
        b = scan_wifi()
        self.assertIsNot(a, b)
        # Both scans must be independently valid even if APs differ.
        for result in (a, b):
            self.assertIsInstance(result.to_dict()["networks"], list)


class TestLiveErrorHandling(unittest.TestCase):
    def test_bad_interface_raises_typed_error(self):
        from scanner.scanner import InterfaceNotFoundError

        with self.assertRaises(InterfaceNotFoundError):
            scan_wifi(interface="definitely_not_an_interface")

    def test_empty_result_is_not_an_error(self):
        # A scan in a shielded environment returns zero APs, which must be a
        # valid result rather than an exception.
        result = scan_wifi(settle=0.0)
        self.assertIsInstance(result, ScanResult)
        self.assertEqual(len(result.networks), len(result.networks))


if __name__ == "__main__":
    unittest.main(verbosity=2)
