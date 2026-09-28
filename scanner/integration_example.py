"""Integration example: how the backend team consumes scanner output.

Run it directly to see every consumption pattern working end to end:

    python scanner/integration_example.py

Import ``scan_wifi`` from the ``scanner`` package and do nothing else. The
package has no third-party dependencies and does not import anything from the
AI, risk-engine or dashboard layers.
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Make the project root importable so this file runs from anywhere.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import ScanResult, ScannerError, scan_wifi


# ---------------------------------------------------------------------------
# 1. Simplest possible use: scan and iterate.
# ---------------------------------------------------------------------------


def basic_usage() -> ScanResult:
    """One scan, iterate the access points."""
    result = scan_wifi()

    print(f"Scanned on {result.interface}: {len(result.networks)} access points\n")

    for network in result.networks:
        print(f"  {network}")

    return result


# ---------------------------------------------------------------------------
# 2. Consuming the raw JSON payload (what an HTTP handler would return).
# ---------------------------------------------------------------------------


def json_payload() -> dict:
    """The exact dict the scanner hands to the backend.

    Passing this straight into a FastAPI response gives the dashboard the
    agreed schema with no extra code.
    """
    result = scan_wifi()
    return result.to_dict()


# ---------------------------------------------------------------------------
# 3. Handing data to the AI / risk engine.
# ---------------------------------------------------------------------------


def features_for_risk_engine(result: ScanResult) -> list[dict]:
    """Flatten observations into per-BSSID records for the AI component.

    One row per BSSID, never per SSID: three APs broadcasting "CE-WIFI" are
    three separate observations and must be scored separately.
    """
    rows = []
    for network in result.networks:
        rows.append(
            {
                "bssid": network.bssid,
                "ssid": network.ssid or None,  # None marks a hidden SSID
                "is_hidden": network.hidden,
                "signal_dbm": network.signal,
                "signal_quality": network.signal_quality,
                "channel": network.channel,
                "frequency_mhz": network.frequency,
                "bandwidth_mhz": network.bandwidth_mhz,
                "security": network.security,
                "is_open": network.is_open,
                "observed_at": network.timestamp,
            }
        )
    return rows


# ---------------------------------------------------------------------------
# 4. Grouping by SSID (for display in a dashboard).
# ---------------------------------------------------------------------------


def group_by_ssid(result: ScanResult) -> dict[str, list]:
    """Group the per-BSSID records under their SSID for UI purposes.

    The scanner never merges records; this is purely a view for humans. The
    duplicate-BSSID count is often interesting to the risk engine, since a
    single SSID on several channels is a normal mesh, but also something an
    attacker can imitate.
    """
    grouped = defaultdict(list)
    for network in result.networks:
        grouped[network.ssid or "<hidden>"].append(network)
    return dict(grouped)


# ---------------------------------------------------------------------------
# 5. Minimal FastAPI integration.
# ---------------------------------------------------------------------------


def fastapi_example() -> str:
    """A drop-in FastAPI endpoint returning the agreed schema."""
    return '''
# backend/main.py  (Person 3)
from fastapi import FastAPI, HTTPException
from scanner import scan_wifi, ScannerError

app = FastAPI()

@app.get("/scan")
def scan():
    try:
        return scan_wifi().to_dict()
    except ScannerError as exc:
        # No adapter / Wi-Fi off / NetworkManager down -> a clear 503,
        # never a 500 with a stack trace.
        raise HTTPException(status_code=503, detail=str(exc)) from exc

# Person 3 can then simply:
#     curl http://localhost:8000/scan
#
# The AI component receives `networks`, a list of per-BSSID records, and
# decides what (if anything) is suspicious. An unknown BSSID is NOT
# suspicious on its own - a first-time AP in a new location is normal.
'''.strip()


# ---------------------------------------------------------------------------


def main() -> int:
    try:
        result = basic_usage()
    except ScannerError as exc:
        print(f"scan failed: {exc}", file=sys.stderr)
        return 1

    print("\n" + "=" * 70)
    print("JSON payload (this is the agreed schema):")
    print("=" * 70)
    print(json.dumps(json_payload(), indent=2)[:1200] + "\n...")

    print("=" * 70)
    print("Per-BSSID rows for the risk engine:")
    print("=" * 70)
    for row in features_for_risk_engine(result)[:5]:
        print(f"  {row}")

    print("\n" + "=" * 70)
    print("Grouped by SSID:")
    print("=" * 70)
    for ssid, members in sorted(group_by_ssid(result).items()):
        channels = ", ".join(str(m.channel) for m in members)
        print(f"  {ssid:<26} {len(members)} AP(s) on channel(s) {channels}")

    print("\n" + "=" * 70)
    print("Security summary:")
    print("=" * 70)
    for security, count in Counter(n.security for n in result.networks).most_common():
        print(f"  {security:<14} {count} AP(s)")

    open_aps = [n for n in result.networks if n.is_open]
    hidden_aps = [n for n in result.networks if n.hidden]
    print(f"\n  Open APs    : {len(open_aps)}")
    print(f"  Hidden APs  : {len(hidden_aps)}")

    print("\n" + "=" * 70)
    print("FastAPI endpoint for Person 3:")
    print("=" * 70)
    print(fastapi_example())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
