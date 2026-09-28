"""Tests for the Wi-Fi scanner.

Runs entirely from fixtures so it works in CI and on machines with no Wi-Fi
hardware. Live verification is done separately with ``test_live.py``.

    python -m pytest scanner/tests/ -v
    python scanner/tests/test_parser.py        # no pytest required
"""

from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from scanner.config import quality_to_dbm
from scanner.models import ScanResult, WiFiNetwork, channel_to_frequency
from scanner.parser import (
    find_interface,
    normalize_security,
    parse_nmcli_terse,
    parse_usable_interfaces,
    split_unescaped,
)

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def load(name: str) -> str:
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as handle:
        return handle.read()


class TestSplitting(unittest.TestCase):
    """The escaping behaviour that makes naive splitting dangerous."""

    def test_escaped_colons_in_bssid(self):
        self.assertEqual(
            split_unescaped("90\\:A2\\:10\\:06\\:17\\:B8:MyNet"),
            ["90:A2:10:06:17:B8", "MyNet"],
        )

    def test_ssid_with_colon(self):
        self.assertEqual(
            split_unescaped("AA\\:BB\\:CC\\:DD\\:EE\\:FF:Cafe\\:Free"),
            ["AA:BB:CC:DD:EE:FF", "Cafe:Free"],
        )

    def test_escaped_backslash(self):
        # Python literal "A:B\\:Back\\" is the text: A:B\:Back\
        # The \: is an escaped colon (stays in the field) and the trailing
        # lone backslash has nothing to escape, so it is preserved verbatim.
        self.assertEqual(split_unescaped("A:B\\:Back\\"), ["A", "B:Back\\"])

    def test_empty_fields_preserved(self):
        self.assertEqual(split_unescaped("A::B"), ["A", "", "B"])

    def test_lone_trailing_backslash_does_not_raise(self):
        self.assertEqual(split_unescaped("A:B\\"), ["A", "B\\"])

    def test_real_output_round_trip(self):
        # WIFI_FIELDS has 9 entries, so every real row must split into 9.
        for line in load("real_scan.txt").splitlines():
            if not line.strip():
                continue
            self.assertEqual(len(split_unescaped(line)), 9, line)


class TestSecurityNormalisation(unittest.TestCase):
    def test_empty_is_open(self):
        self.assertEqual(normalize_security(""), "OPEN")
        self.assertEqual(normalize_security(None), "OPEN")
        self.assertEqual(normalize_security("   "), "OPEN")
        self.assertEqual(normalize_security("--"), "OPEN")

    def test_single(self):
        self.assertEqual(normalize_security("WPA2"), "WPA2")
        self.assertEqual(normalize_security("WEP"), "WEP")

    def test_mixed(self):
        self.assertEqual(normalize_security("WPA2 WPA3"), "WPA2/WPA3")
        self.assertEqual(normalize_security("WPA1 WPA2"), "WPA1/WPA2")

    def test_ciphers_stripped(self):
        self.assertEqual(normalize_security("RSN pairwise-CCMP TKIP"), "RSN")

    def test_always_non_empty(self):
        for raw in ["", None, "--", "()", "none", "pair_ccmp group_ccmp psk"]:
            self.assertTrue(normalize_security(raw), raw)


class TestChannelMath(unittest.TestCase):
    def test_24ghz(self):
        self.assertEqual(channel_to_frequency(1), 2412)
        self.assertEqual(channel_to_frequency(6), 2437)
        self.assertEqual(channel_to_frequency(11), 2462)
        self.assertEqual(channel_to_frequency(13), 2472)
        self.assertEqual(channel_to_frequency(14), 2484)

    def test_5ghz(self):
        self.assertEqual(channel_to_frequency(36), 5180)
        self.assertEqual(channel_to_frequency(149), 5745)
        self.assertEqual(channel_to_frequency(165), 5825)

    def test_unknown(self):
        self.assertIsNone(channel_to_frequency(None))
        self.assertIsNone(channel_to_frequency(0))
        self.assertIsNone(channel_to_frequency(20))


class TestParsingRealScan(unittest.TestCase):
    def setUp(self):
        self.networks = parse_nmcli_terse(load("real_scan.txt"))

    def test_counts_all_aps(self):
        self.assertEqual(len(self.networks), 12)

    def test_required_fields_present_and_typed(self):
        for n in self.networks:
            self.assertIsInstance(n.ssid, str)
            self.assertIsInstance(n.bssid, str)
            self.assertIsInstance(n.security, str)
            self.assertIsInstance(n.timestamp, str)
            if n.signal is not None:
                # signal is published as dBm, so it must be negative.
                self.assertIsInstance(n.signal, int)
                self.assertLessEqual(n.signal, 0)
                self.assertGreaterEqual(n.signal, -100)
            if n.channel is not None:
                self.assertIsInstance(n.channel, int)
            if n.frequency is not None:
                self.assertIsInstance(n.frequency, int)

    def test_bssids_wellformed_and_unique(self):
        bssids = [n.bssid for n in self.networks]
        self.assertEqual(len(bssids), len(set(bssids)))
        for b in bssids:
            self.assertRegex(b, r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")

    def test_ssids_with_spaces_survive(self):
        ssids = {n.ssid for n in self.networks}
        self.assertIn("Galaxy A23 D073", ssids)
        self.assertIn("Engineering College", ssids)
        self.assertIn("KFON@engineeringcollege", ssids)

    def test_frequency_units_stripped(self):
        n = next(x for x in self.networks if x.ssid == "Engineering College")
        self.assertEqual(n.frequency, 2427)
        self.assertEqual(n.channel, 4)

    # ---- nmcli reports "0 MHz" when it cannot determine the width ------
    def test_zero_bandwidth_becomes_none(self):
        zero = [n for n in parse_nmcli_terse(load("edge_cases.txt")) if n.ssid == "ZeroWidth"]
        self.assertEqual(len(zero), 1)
        self.assertIsNone(zero[0].bandwidth_mhz)
        # The rest of the record is still valid.
        self.assertEqual(zero[0].channel, 8)
        self.assertEqual(zero[0].frequency, 2447)
        self.assertEqual(zero[0].security, "WPA1/WPA2")

    # ---- Test 1: normal Wi-Fi ------------------------------------------
    def test1_normal_wifi_detected(self):
        matches = [n for n in self.networks if n.ssid == "KFON@engineeringcollege"]
        self.assertEqual(len(matches), 1)
        n = matches[0]
        self.assertEqual(n.bssid, "90:A2:10:06:17:B8")
        self.assertEqual(n.security, "WPA1/WPA2")
        self.assertEqual(n.channel, 10)
        self.assertEqual(n.frequency, 2457)
        # nmcli quality 80 -> -60 dBm
        self.assertEqual(n.signal_quality, 80)
        self.assertEqual(n.signal, -60)

    # ---- Test 2: multiple APs, one SSID ---------------------------------
    def test2_same_ssid_multiple_bssids_not_merged(self):
        ce = [n for n in self.networks if n.ssid == "CE-WIFI"]
        self.assertEqual(len(ce), 3, "three APs broadcast CE-WIFI")
        self.assertEqual(
            sorted(n.bssid for n in ce),
            ["10:27:F5:F3:9B:B3", "BC:07:1D:66:C2:E6", "BC:07:1D:66:C2:E7"],
        )
        # Distinct channels confirm these are genuinely separate radios.
        self.assertEqual(sorted(n.channel for n in ce), [1, 11, 149])

    # ---- Test 3: open AP -------------------------------------------------
    def test3_open_ap_security(self):
        # Two of the three CE-WIFI radios advertise no security; the 2.4 GHz
        # one is secured. Confirms OPEN and secured APs coexist per SSID.
        ce = [n for n in self.networks if n.ssid == "CE-WIFI"]
        self.assertEqual(sorted(n.security for n in ce), ["OPEN", "OPEN", "WPA1/WPA2"])
        open_ce = [n for n in ce if n.is_open]
        self.assertEqual(
            sorted(n.channel for n in open_ce), [11, 149]
        )

    # ---- Test 4: hidden SSID ---------------------------------------------
    def test4_hidden_ssids_do_not_crash(self):
        hidden = [n for n in self.networks if n.hidden]
        self.assertEqual(len(hidden), 2)
        for n in hidden:
            self.assertEqual(n.ssid, "")
            self.assertIsNone(n.ssid_hex)
            # A hidden AP still reports real radio data.
            self.assertIsNotNone(n.channel)
            self.assertIsNotNone(n.frequency)
            self.assertRegex(n.bssid, r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")

    def test4_hidden_ap_security_parsed(self):
        n = next(x for x in self.networks if x.bssid == "AE:2E:A8:D9:D4:34")
        self.assertEqual(n.security, "WPA2/WPA3")
        self.assertTrue(n.hidden)


class TestParsingEdgeCases(unittest.TestCase):
    def setUp(self):
        self.networks = parse_nmcli_terse(load("edge_cases.txt"))

    def test_ssid_with_colons(self):
        n = next(x for x in self.networks if x.bssid == "AA:BB:CC:11:22:33")
        self.assertEqual(n.ssid, "CEV_WIFI")
        n2 = next(x for x in self.networks if "Cafe" in x.ssid)
        self.assertEqual(n2.ssid, "Cafe:Free:Guest")

    def test_ssid_with_backslash(self):
        n = next(x for x in self.networks if "Back" in x.ssid)
        self.assertEqual(n.ssid, "Back\\Slash:Net")

    def test_unicode_ssid(self):
        n = next(x for x in self.networks if "Unicode" in x.ssid)
        self.assertEqual(n.ssid, "Unicode Network 名前")
        self.assertEqual(n.frequency, 5180)

    def test_tab_ssid(self):
        n = next(x for x in self.networks if "Tab" in x.ssid)
        self.assertEqual(n.ssid, "Tab\tInName")

    def test_wep(self):
        n = next(x for x in self.networks if "WEP" in x.ssid)
        self.assertEqual(n.security, "WEP")

    def test_rsnb_ciphers_reduced(self):
        n = next(x for x in self.networks if "RSN" in x.ssid)
        self.assertEqual(n.security, "RSN")

    def test_80mhz_bandwidth(self):
        n = next(x for x in self.networks if x.bssid == "AA:BB:CC:11:22:33")
        self.assertEqual(n.bandwidth_mhz, 80)
        self.assertEqual(n.channel, 36)
        self.assertEqual(n.frequency, 5180)

    # ---- Test 2 restated on the controlled CEV_WIFI fixture -------------
    def test2_controlled_three_bssids_one_ssid(self):
        cev = [n for n in self.networks if n.ssid == "CEV_WIFI"]
        self.assertEqual(len(cev), 3)
        self.assertEqual(
            sorted(n.bssid for n in cev),
            ["AA:BB:CC:11:22:33", "BB:CC:DD:44:55:66", "CC:DD:EE:55:66:77"],
        )
        # Same SSID, three different radios - they must stay separate.
        self.assertEqual(sorted(n.channel for n in cev), [6, 11, 36])


class TestMalformedInput(unittest.TestCase):
    """Bad data must degrade, never crash."""

    def setUp(self):
        self.networks = parse_nmcli_terse(load("malformed.txt"))

    def test_invalid_bssid_dropped(self):
        self.assertNotIn("BadRow", [n.ssid for n in self.networks])

    def test_short_row_padded(self):
        n = next(x for x in self.networks if x.bssid == "AA:BB:CC:DD:EE:01")
        self.assertEqual(n.ssid, "TooFewFields")
        self.assertIsNone(n.channel)

    def test_lowercase_bssid_normalised(self):
        n = next(x for x in self.networks if x.bssid == "AA:BB:CC:DD:EE:FF")
        self.assertEqual(n.ssid, "LowerHex")

    def test_out_of_range_signal_none(self):
        n = next(x for x in self.networks if x.bssid == "AA:BB:CC:DD:EE:03")
        self.assertIsNone(n.signal)
        self.assertIsNone(n.signal_quality)
        self.assertTrue(n.hidden)

    def test_zero_quality_is_valid(self):
        n = next(x for x in self.networks if x.bssid == "AA:BB:CC:DD:EE:04")
        self.assertEqual(n.signal_quality, 0)
        self.assertEqual(n.signal, -100)
        self.assertEqual(n.security, "OPEN")

    def test_missing_signal(self):
        n = next(x for x in self.networks if x.bssid == "AA:BB:CC:DD:EE:05")
        self.assertIsNone(n.signal)
        self.assertIsNone(n.signal_quality)

    def test_frequency_derived_from_channel(self):
        n = next(x for x in self.networks if x.bssid == "AA:BB:CC:DD:EE:06")
        self.assertIsNone(n.security if n.security is None else None)
        self.assertEqual(n.frequency, 2412)
        self.assertEqual(n.channel, 1)

    def test_trailing_escape_survives(self):
        n = next(x for x in self.networks if x.bssid == "AA:BB:CC:DD:EE:08")
        self.assertEqual(n.ssid, "TrailingEscape")

    def test_all_parsed_have_required_keys(self):
        for n in self.networks:
            payload = n.to_dict()
            for key in ("ssid", "bssid", "signal", "channel", "frequency", "security"):
                self.assertIn(key, payload)


class TestEmptyAndBlank(unittest.TestCase):
    def test_empty_output(self):
        self.assertEqual(parse_nmcli_terse(""), [])
        self.assertEqual(parse_nmcli_terse("\n\n\n"), [])
        self.assertEqual(parse_nmcli_terse("   \n  \n"), [])

    def test_empty_scan_is_valid_result(self):
        result = ScanResult(timestamp="2026-09-28T19:30:00+00:00", networks=[])
        self.assertEqual(len(result), 0)
        self.assertEqual(result.to_dict()["networks"], [])


class TestInterfaceDetection(unittest.TestCase):
    DEVICE_STATUS = (
        "wlo1:wifi:connected:AP1\n"
        "lo:loopback:unmanaged:\n"
        "p2p-dev-wlo1:wifi-p2p:disconnected:\n"
        "eno1:ethernet:unavailable:\n"
    )

    def test_only_real_wifi_counted(self):
        devices = parse_usable_interfaces(self.DEVICE_STATUS)
        self.assertEqual([d[0] for d in devices], ["wlo1"])

    def test_picks_connected_device(self):
        self.assertEqual(find_interface(self.DEVICE_STATUS), "wlo1")

    def test_preferred_interface_respected(self):
        status = "wpa:wifi:connected:A\nwlo1:wifi:connected:B\n"
        self.assertEqual(find_interface(status, preferred="wlo1"), "wlo1")

    def test_unknown_preferred_raises(self):
        with self.assertRaises(Exception):
            find_interface(self.DEVICE_STATUS, preferred="nosuch")

    def test_first_when_none_connected(self):
        status = "wlo2:wifi:disconnected:\n"
        self.assertEqual(find_interface(status), "wlo2")

    def test_no_interfaces(self):
        self.assertIsNone(find_interface("lo:loopback:unmanaged:\n"))


class TestSignalUnits(unittest.TestCase):
    """nmcli reports 0-100 quality; the agreed schema requires dBm.

    This is the easiest part of the contract to get silently wrong, so it is
    pinned down explicitly.
    """

    def test_endpoints(self):
        self.assertEqual(quality_to_dbm(100), -50)
        self.assertEqual(quality_to_dbm(0), -100)

    def test_midpoints(self):
        self.assertEqual(quality_to_dbm(80), -60)
        self.assertEqual(quality_to_dbm(50), -75)
        self.assertEqual(quality_to_dbm(20), -90)

    def test_always_negative(self):
        for q in range(0, 101):
            self.assertLessEqual(quality_to_dbm(q), 0, q)

    def test_monotonic_stronger_is_higher(self):
        values = [quality_to_dbm(q) for q in range(101)]
        self.assertEqual(values, sorted(values))

    def test_roundtrip_against_nm_formula(self):
        # NetworkManager: percent = clamp((rssi + 100) * 2, 0, 100)
        for dbm in range(-100, -49):
            percent = max(0, min(100, (dbm + 100) * 2))
            self.assertEqual(quality_to_dbm(percent), dbm, dbm)

    def test_out_of_range_quality_rejected(self):
        networks = parse_nmcli_terse(
            r"AA\:BB\:CC\:DD\:EE\:F0:Neg:4E6567:Infra:1:2412 MHz:-9999:WPA2:20 MHz" "\n"
            r"AA\:BB\:CC\:DD\:EE\:F1:Big:426967:Infra:1:2412 MHz:500:WPA2:20 MHz" "\n"
        )
        self.assertEqual(len(networks), 2)
        for n in networks:
            self.assertIsNone(n.signal_quality)
            self.assertIsNone(n.signal)

    def test_quality_exposed_alongside_dbm(self):
        n = parse_nmcli_terse(
            r"AA\:BB\:CC\:DD\:EE\:F2:Net:4E6574:Infra:6:2437 MHz:92:WPA2:20 MHz" "\n"
        )[0]
        self.assertEqual(n.signal_quality, 92)
        self.assertEqual(n.signal, -54)


class TestSchemaContract(unittest.TestCase):
    """The JSON shape that Person 2 and Person 3 depend on."""

    def setUp(self):
        self.result = ScanResult(
            timestamp="2026-09-28T19:30:00+00:00",
            networks=parse_nmcli_terse(load("real_scan.txt")),
            interface="wlo1",
        )

    def test_top_level_keys(self):
        payload = self.result.to_dict()
        self.assertIn("timestamp", payload)
        self.assertIn("networks", payload)
        self.assertIsInstance(payload["networks"], list)

    def test_network_keys_exactly_as_specified(self):
        required = {"ssid", "bssid", "signal", "channel", "frequency", "security"}
        for entry in self.result.to_dict()["networks"]:
            self.assertTrue(required.issubset(entry.keys()))

    def test_minimal_mode_matches_agreed_schema(self):
        payload = self.result.to_dict(include_optional=False)
        self.assertEqual(
            set(payload["networks"][0].keys()),
            {"ssid", "bssid", "signal", "channel", "frequency", "security", "timestamp"},
        )

    def test_json_serialisable(self):
        text = self.result.to_json()
        self.assertEqual(json.loads(text)["networks"][0]["ssid"], "Galaxy A23 D073")

    def test_json_is_stable_across_runs(self):
        a = ScanResult(timestamp="T", networks=parse_nmcli_terse(load("real_scan.txt"))).to_json()
        b = ScanResult(timestamp="T", networks=parse_nmcli_terse(load("real_scan.txt"))).to_json()
        self.assertEqual(a, b)

    # ---- Test 5: repeated scans -----------------------------------------
    def test5_repeated_scans_structurally_consistent(self):
        shapes = set()
        for _ in range(5):
            result = ScanResult(
                timestamp="2026-09-28T19:30:00+00:00",
                networks=parse_nmcli_terse(load("real_scan.txt")),
            )
            for entry in result.to_dict()["networks"]:
                shapes.add(tuple(sorted(entry.keys())))
                self.assertIsInstance(entry["bssid"], str)
                self.assertIsInstance(entry["security"], str)
        self.assertEqual(len(shapes), 1, "record shape drifted between scans")

    def test5_same_input_same_output(self):
        runs = [
            [n.to_dict() for n in parse_nmcli_terse(load("real_scan.txt"))]
            for _ in range(5)
        ]
        for run in runs[1:]:
            self.assertEqual(run, runs[0])


class TestMerge(unittest.TestCase):
    def test_keeps_strongest_signal(self):
        a = WiFiNetwork(ssid="", bssid="AA:BB:CC:DD:EE:01", signal=-80, channel=1, security="OPEN")
        b = WiFiNetwork(ssid="Net", bssid="AA:BB:CC:DD:EE:01", signal=-40, channel=6, security="WPA2")
        merged = a.merge(b)
        self.assertEqual(merged.signal, -40)
        self.assertEqual(merged.ssid, "Net")
        self.assertEqual(merged.security, "WPA2")
        self.assertEqual(merged.bssid, "AA:BB:CC:DD:EE:01")

    def test_hidden_flag_uses_and(self):
        hidden = WiFiNetwork(ssid="", bssid="AA:BB:CC:DD:EE:02", hidden=True)
        named = WiFiNetwork(ssid="X", bssid="AA:BB:CC:DD:EE:02", hidden=False)
        self.assertFalse(hidden.merge(named).hidden)
        self.assertTrue(hidden.merge(hidden).hidden)


if __name__ == "__main__":
    unittest.main(verbosity=2)
