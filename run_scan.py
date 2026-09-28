#!/usr/bin/env python3
"""WiFiSentinel AI - production command-line entry point.

Performs a real passive Wi-Fi scan on the local adapter, analyses every
access point that was actually observed, and reports a risk score and
classification for each one.

    python run_scan.py

No invented networks, no sample data, no mock profiles. Every BSSID, SSID,
channel and signal printed below came from the Wi-Fi hardware a few seconds
earlier. If the scan cannot be performed the command says why and exits
non-zero rather than printing something fabricated.

Commands
--------
    python run_scan.py                    scan, analyse, print a table
    python run_scan.py --json             same, as JSON (for piping/scripting)
    python run_scan.py --interface wlo1   force a specific adapter
    python run_scan.py --verbose          include reasons and score breakdowns
    python run_scan.py profiles           list this site's trusted networks
    python run_scan.py --trust "SSID"     record a real SSID as trusted
    python run_scan.py --untrust "SSID"   remove a trusted network

Trust model
-----------
An access point is TRUSTED only when this site has an operator-approved profile
listing its BSSID. The store starts empty, so a first run anywhere reports
every network as UNVERIFIED - which is the honest answer, not a failure. Use
``--trust`` to record a network you have verified is legitimate.

    python run_scan.py --trust "My_Home_WiFi"

That records the BSSIDs currently observed for that SSID. It is a deliberate
operator action, not something the tool does on its own.

Security boundary: passive observation and analysis only. This tool never
transmits, deauthenticates, injects, or associates with any network.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Make the repo root importable regardless of the caller's working directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ai.pipeline import analyze_scan
from ai.profile_store import ProfileStore, build_profile_from_observations
from ai.risk_engine import thresholds_doc
from scanner import ScannerError, scan_wifi


# ---------------------------------------------------------------------------
# Terminal formatting
# ---------------------------------------------------------------------------

#: Colour only when stdout is a terminal, so piped/redirected output stays clean.
_COLOURS = {
    "TRUSTED": "\033[32m",       # green
    "LEGITIMATE": "\033[32m",    # green - consistent, just not on the list
    "UNVERIFIED": "\033[37m",    # grey - not enough information
    "LOW_RISK": "\033[33m",
    "SUSPICIOUS": "\033[33m",    # yellow - meaningful deviation
    "POTENTIAL_FAKE": "\033[31m",  # red - corroborated impersonation pattern
    "HIGH_RISK": "\033[31m",
}
_RESET = "\033[0m"

_SSID_WIDTH = 26
_BSSID_WIDTH = 17


def _supports_colour() -> bool:
    return sys.stdout.isatty() and not sys.stdout.isatty.__self__ is None


def colour(text: str, classification: str) -> str:
    if not sys.stdout.isatty():
        return text
    code = _COLOURS.get(classification)
    return f"{code}{text}{_RESET}" if code else text


def print_table(report: Dict[str, Any], verbose: bool = False) -> None:
    results = report["results"]

    print()
    print(f"Interface      : {report.get('interface')}")
    print(f"Networks found : {report['network_count']} access point(s) across {report['ssid_count']} network(s)")
    trusted = report.get("trusted_profiles") or []
    print(f"Trusted here   : {', '.join(trusted) if trusted else '(none configured)'}")
    if not trusted:
        print("                  every network below is UNVERIFIED until an operator")
        print("                  approves it with:  python run_scan.py --trust \"<SSID>\"")

    counts = {k: v for k, v in report.get("verdict_counts", {}).items() if v}
    if counts:
        print(f"Verdicts       : " + "  ".join(f"{k}={v}" for k, v in counts.items()))
    if report.get("flagged_count"):
        print(f"Flagged        : {report['flagged_count']} access point(s) need a closer look")
    print()

    header = (f"{'BSSID':<{_BSSID_WIDTH}}  {'SSID':<{_SSID_WIDTH}}  {'CH':>4}  "
              f"{'SIGNAL':>6}  {'SECURITY':<12}  {'RISK':>4}  {'EVIDENCE':<8}  VERDICT")
    print(header)
    print("-" * len(header))

    if not results:
        print("  (no access points were observed)")
        return

    for result in sorted(results, key=lambda r: (-r["risk_score"], r["bssid"])):
        observed = result["observed"]
        bssid = result["bssid"] or "<unknown>"
        ssid = (observed["ssid"] or "<hidden>")[:_SSID_WIDTH]
        channel = str(observed["channel"] if observed["channel"] is not None else "-")
        signal = f"{observed['signal']}dBm" if observed["signal"] is not None else "-"
        verdict = result.get("verdict", result["classification"])
        print(f"{bssid:<{_BSSID_WIDTH}}  {ssid:<{_SSID_WIDTH}}  {channel:>4}  "
              f"{signal:>6}  {str(observed['security']):<12}  {result['risk_score']:>4}  "
              f"{result.get('evidence_level', '-'):<8}  {colour(verdict, verdict)}")

        if verbose:
            if result.get("verdict_summary"):
                print(f"{'':<{_BSSID_WIDTH}}      {result['verdict_summary']}")
            for entry in result.get("indicator_details", []):
                print(f"{'':<{_BSSID_WIDTH}}      [{entry['code']}] {entry['message']}"
                      f"  ({entry.get('family', '')})")
            if result.get("verdict_guidance"):
                print(f"{'':<{_BSSID_WIDTH}}      -> {result['verdict_guidance']}")
            if result.get("score_breakdown"):
                breakdown = ", ".join(f"{k}={v}" for k, v in result["score_breakdown"].items())
                print(f"{'':<{_BSSID_WIDTH}}      score breakdown: {breakdown}")
            print()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def do_scan(args: argparse.Namespace) -> int:
    """Perform a real scan and analyse it."""
    try:
        scan = scan_wifi(interface=args.interface, settle=args.settle)
    except ScannerError as exc:
        print(f"error: cannot scan: {type(exc).__name__}: {exc}", file=sys.stderr)
        print(
            "\nThis command needs a real wireless adapter. Check that:\n"
            "  - a Wi-Fi interface exists and is up   (nmcli device status)\n"
            "  - NetworkManager is running            (systemctl status NetworkManager)\n"
            "  - you may query it without root       (nmcli device wifi list)\n"
            "\nNo data is fabricated when a scan is unavailable.",
            file=sys.stderr,
        )
        return 2

    store = ProfileStore(args.profile_store)
    profiles = store.load()

    report = analyze_scan(scan, profiles=profiles)
    report["interface"] = scan.interface
    report["trusted_profiles"] = [p.ssid for p in profiles]

    if args.json:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print("Scanning Wi-Fi networks...")
        print_table(report, verbose=args.verbose)
        if not args.json:
            _print_thresholds()
    return 0


def _print_thresholds() -> None:
    print()
    print("Classification thresholds (heuristic triage bands, not probabilities):")
    for label, description in thresholds_doc().items():
        print(f"  {label:<12} {description}")


def do_profiles(args: argparse.Namespace) -> int:
    store = ProfileStore(args.profile_store)
    profiles = store.load()
    if args.json:
        json.dump(
            {"path": str(store.path), "count": len(profiles),
             "profiles": [p.to_dict() for p in profiles]},
            sys.stdout, indent=2,
        )
        sys.stdout.write("\n")
        return 0

    print(f"Profile store: {store.path}")
    if not profiles:
        print("\n  No networks are trusted at this site yet.")
        print("  Everything a real scan observes will be reported UNVERIFIED.")
        print("\n  To approve a network you have verified is legitimate:")
        print('      python run_scan.py --trust "Your_SSID"')
        return 0

    print(f"\n  {len(profiles)} trusted network(s):\n")
    for profile in profiles:
        where = f"  [{profile.location}]" if profile.location else ""
        print(f"    {profile.ssid}{where}")
        print(f"      BSSIDs   : {len(profile.known_bssids)}")
        for bssid in profile.known_bssids:
            print(f"        {bssid}")
        print(f"      security : {', '.join(profile.security) or '(any)'}")
        print(f"      channels : {profile.expected_channels or '(any)'}")
        print(f"      freqs    : {profile.expected_frequencies or '(any)'}")
        print(f"      vendors  : {', '.join(profile.known_vendors) or '(any)'}")
    return 0


def do_trust(args: argparse.Namespace) -> int:
    """Record a real, currently-observed SSID as trusted for this site."""
    store = ProfileStore(args.profile_store)

    try:
        scan = scan_wifi(interface=args.interface, settle=args.settle)
    except ScannerError as exc:
        print(f"error: cannot scan, so nothing can be trusted: {exc}", file=sys.stderr)
        return 2

    observed: List[Dict[str, Any]] = [n.to_dict() for n in scan.networks]
    matches = [n for n in observed if (n.get("ssid") or "") == args.ssid]
    if not matches:
        available = sorted({n.get("ssid") for n in observed if n.get("ssid")})
        print(f"error: {args.ssid!r} was not observed in this scan.", file=sys.stderr)
        if available:
            print("SSIDs actually seen right now:", file=sys.stderr)
            for ssid in available:
                print(f"  - {ssid}", file=sys.stderr)
        return 1

    profile = build_profile_from_observations(
        args.ssid, observed, location=args.location, include_vendors=args.include_vendors
    )
    if profile is None:  # pragma: no cover - matches is non-empty, so this cannot happen
        print("error: no usable observations for that SSID.", file=sys.stderr)
        return 1

    store.upsert(profile)
    print(f"Trusted {args.ssid!r} at this site.")
    print(f"  recorded {len(profile.known_bssids)} BSSID(s):")
    for bssid in profile.known_bssids:
        print(f"    {bssid}")
    print(f"  security : {', '.join(profile.security)}")
    print(f"  channels : {profile.expected_channels}")
    print(f"\nSaved to {store.path}")
    return 0


def do_untrust(args: argparse.Namespace) -> int:
    store = ProfileStore(args.profile_store)
    if store.remove(args.ssid):
        print(f"Removed {args.ssid!r} from {store.path}. Future observations are UNVERIFIED again.")
        return 0
    print(f"error: {args.ssid!r} was not in the profile store.", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_scan.py",
        description="Real passive Wi-Fi scan and rogue-AP risk analysis.",
        epilog="Passive observation only: nothing is transmitted, injected or associated.",
    )
    parser.add_argument(
        "--interface", metavar="IFACE",
        help="force a Wi-Fi interface (default: auto-detect)",
    )
    parser.add_argument(
        "--settle", type=float, default=20.0, metavar="SECONDS",
        help="max seconds to wait for the scan to settle (default: 20)",
    )
    parser.add_argument(
        "--profile-store", metavar="PATH", default=None,
        help="trusted-profile store file (default: config/trusted_networks.json)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    parser.add_argument("--verbose", "-v", action="store_true", help="show reasons and score breakdowns")

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("scan", help="scan and analyse (the default)")
    sub.add_parser("profiles", help="list trusted networks for this site")

    trust = sub.add_parser("trust", help="record a real SSID as trusted for this site")
    trust.add_argument("ssid", help="the SSID to trust, exactly as scanned")

    untrust = sub.add_parser("untrust", help="remove a trusted network")
    untrust.add_argument("ssid", help="the SSID to remove")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Extra flags shared by the subcommands that perform a scan.
    for name in ("location", "include_vendors"):
        if not hasattr(args, name):
            setattr(args, name, None)

    command = args.command or "scan"
    handlers = {
        "scan": do_scan,
        "profiles": do_profiles,
        "trust": do_trust,
        "untrust": do_untrust,
    }
    return handlers[command](args)


if __name__ == "__main__":
    raise SystemExit(main())
