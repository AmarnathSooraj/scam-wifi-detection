"""Wi-Fi scanning orchestration.

Public entry point for the rest of the project::

    from scanner import scan_wifi

    result = scan_wifi()
    for network in result.networks:
        print(network.ssid, network.bssid, network.signal)

This module only *observes*. It never associates with a network, sends
authentication frames, or otherwise interacts with neighbouring devices
beyond the passive scan beacon collection that every Wi-Fi client performs
to discover which networks exist.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from typing import List, Optional

if __package__ in (None, ""):  # pragma: no cover - direct `python scanner.py`
    # Support being run as a script from inside the package directory.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    __package__ = "scanner"

from . import config
from .models import ScanResult, WiFiNetwork, iso_timestamp
from .parser import (
    ParseError,
    find_interface,
    normalize_security,
    parse_nmcli_terse,
    parse_usable_interfaces,
    split_unescaped,
)

__all__ = [
    "scan_wifi",
    "ScanResult",
    "WiFiNetwork",
    "ScannerError",
    "NoWifiAdapterError",
    "WifiDisabledError",
    "NetworkManagerUnavailableError",
    "PermissionDeniedError",
    "ScanFailedError",
    "InterfaceNotFoundError",
    "main",
]


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


class ScannerError(Exception):
    """Base class for all scanner failures.

    Carries a ``hint`` so the CLI can print actionable remediation advice
    instead of a bare traceback.
    """

    def __init__(self, message: str, hint: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message if not self.hint else f"{self.message}\n  hint: {self.hint}"


class NoWifiAdapterError(ScannerError):
    def __init__(self, message: str = "No Wi-Fi adapter found."):
        super().__init__(
            message,
            "Plug in a USB Wi-Fi adapter, or check `lsusb` / `ip link`.",
        )


class InterfaceNotFoundError(ScannerError):
    def __init__(
        self,
        message: str = "The requested Wi-Fi interface was not found.",
        hint: str = "Run `nmcli device status` to list valid interface names.",
    ):
        super().__init__(message, hint)


class WifiDisabledError(ScannerError):
    def __init__(self, message: str = "Wi-Fi is disabled (rfkill)."):
        super().__init__(
            message,
            "Turn the radio on with `nmcli radio wifi on`, or unblock with "
            "`rfkill unblock wifi`.",
        )


class NetworkManagerUnavailableError(ScannerError):
    def __init__(self, message: Optional[str] = None):
        super().__init__(
            message or "NetworkManager is not available or not responding.",
            "Check `systemctl status NetworkManager`. Without NetworkManager "
            "this scanner cannot enumerate APs; consider a direct `iw scan` "
            "backend as a future improvement.",
        )


class PermissionDeniedError(ScannerError):
    def __init__(self, message: str = "Permission denied while scanning."):
        super().__init__(
            message,
            "Scanning usually works as a normal user via polkit. If denied, "
            "add the user to the `network` group or run with elevated rights.",
        )


class ScanFailedError(ScannerError):
    pass


# --------------------------------------------------------------------------
# nmcli plumbing
# --------------------------------------------------------------------------


class _NmcliResult:
    __slots__ = ("returncode", "stdout", "stderr")

    def __init__(self, returncode: int, stdout: str, stderr: str):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _run(args: List[str], timeout: Optional[float] = None) -> _NmcliResult:
    """Run an nmcli command, capturing output and never raising on non-zero."""
    try:
        proc = subprocess.run(
            [config.NMCLI_BIN, "--terse", "--wait", str(int(config.NMCLI_TIMEOUT))] + args,
            capture_output=True,
            text=True,
            timeout=timeout or config.NMCLI_TIMEOUT,
            check=False,
        )
    except FileNotFoundError as exc:
        raise NetworkManagerUnavailableError(
            f"`{config.NMCLI_BIN}` not found on PATH."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanFailedError(
            f"`{' '.join(args)}` timed out after {exc.timeout}s."
        ) from exc
    except PermissionError as exc:
        raise PermissionDeniedError(str(exc)) from exc

    return _NmcliResult(proc.returncode, proc.stdout, proc.stderr)


def _raise_for_nmcli_error(result: _NmcliResult, action: str) -> None:
    """Translate nmcli's exit codes and stderr into typed exceptions."""
    if result.returncode == 0:
        return

    message = (result.stderr or result.stdout or "").strip()
    lowered = message.lower()

    if "not found" in lowered and "device" in lowered:
        raise InterfaceNotFoundError(
            f"nmcli could not find the requested device while {action}: {message}",
            "Run `nmcli device status` to list valid interface names.",
        )
    if "no suitable device" in lowered or "no wifi" in lowered:
        raise NoWifiAdapterError(
            f"nmcli reports no suitable Wi-Fi device while {action}: {message}"
        )
    if "permission" in lowered or "not authorized" in lowered or "denied" in lowered:
        raise PermissionDeniedError(
            f"nmcli denied permission while {action}: {message}"
        )
    if "disabled" in lowered and "wifi" in lowered:
        raise WifiDisabledError(
            f"Wi-Fi appears disabled while {action}: {message}"
        )
    if "not running" in lowered or "connection refused" in lowered:
        raise NetworkManagerUnavailableError(
            f"Cannot reach NetworkManager's D-Bus service while {action}: {message}"
        )

    raise ScanFailedError(f"nmcli failed while {action}: {message or 'unknown error'}")


def _ensure_nmcli_present() -> None:
    if shutil.which(config.NMCLI_BIN) is None:
        raise NetworkManagerUnavailableError(
            f"`{config.NMCLI_BIN}` is not installed or not on PATH."
        )


def _radio_enabled() -> bool:
    """Return True unless nmcli explicitly reports the Wi-Fi radio as off."""
    result = _run(["radio", "wifi"])
    if result.returncode != 0:
        return True  # cannot tell; let the scan itself surface the problem
    return "enabled" in result.stdout.lower()


def _detect_interface(preferred: Optional[str]) -> str:
    """Pick the interface to scan on, or raise a typed error."""
    result = _run(["-f", ",".join(config.DEVICE_FIELDS), "device", "status"])
    _raise_for_nmcli_error(result, "listing devices")

    interfaces = parse_usable_interfaces(result.stdout)
    if not interfaces:
        # Distinguish "no adapter at all" from "adapter present but NM can't use it".
        if result.stdout.strip():
            raise NoWifiAdapterError(
                "Devices exist but none is a scan-capable Wi-Fi radio "
                f"(found: {result.stdout.strip()!r})."
            )
        raise NoWifiAdapterError()

    try:
        return find_interface(result.stdout, preferred=preferred) or interfaces[0][0]
    except ParseError as exc:
        # Translate the parser's error into the scanner's typed hierarchy so
        # callers only ever need to catch ScannerError.
        raise InterfaceNotFoundError(str(exc)) from exc


def _trigger_rescan(interface: str) -> None:
    """Ask NetworkManager to refresh the scan cache.

    ``nmcli device wifi rescan`` is asynchronous: it queues a scan and returns
    immediately, so this function returning does *not* mean results are
    ready. :func:`_await_scan` handles that.
    """
    result = _run(["device", "wifi", "rescan", "ifname", interface])
    if result.returncode != 0:
        # A refused rescan should not abort the scan: NetworkManager may
        # still hold a usable recent cache. Record nothing and continue.
        if "disabled" in (result.stderr or "").lower():
            raise WifiDisabledError()
        return


def _fetch_results(interface: str) -> str:
    result = _run(
        [
            "-f",
            ",".join(config.WIFI_FIELDS),
            "device",
            "wifi",
            "list",
            "ifname",
            interface,
            "--rescan",
            "no",
        ]
    )
    _raise_for_nmcli_error(result, "listing Wi-Fi networks")
    return result.stdout


def _await_scan(interface: str, settle: float, baseline: Optional[str] = None) -> str:
    """Wait for the asynchronous scan to land, then return the cache.

    Measured behaviour of NetworkManager (nmcli 1.56) that shapes this logic:

    1. ``device wifi rescan`` returns immediately and never reports an error,
       even when a scan is already running.
    2. The cache keeps showing the PREVIOUS scan's results unchanged for
       ~5 s before new results arrive. A "wait until the output stops
       changing" loop therefore returns the STALE cache almost immediately.
    3. If a rescan is issued while another is in flight, the cache is left in
       a PARTIALLY populated state (measured: 7 of 14 APs) and only becomes
       complete ~6 s later.

    So a stability check alone is not enough - the cache looks stable right
    after the scan starts. We require a hard time floor first, then wait for
    the cache to stop changing so that late arrivals (5 GHz results in
    particular) are included, with ``settle`` as the final ceiling.
    """
    started = time.monotonic()
    deadline = started + settle
    not_before = started + min(config.SCAN_MIN_WAIT_SECONDS, settle)

    previous: Optional[str] = None
    stable_rounds = 0

    while True:
        current = _fetch_results(interface)

        if current == previous:
            stable_rounds += 1
        else:
            stable_rounds = 0
        previous = current

        # The scan must have had time to start and deliver before the cache
        # can be trusted, and must then have stopped changing.
        if time.monotonic() >= not_before and stable_rounds >= config.SCAN_STABLE_ROUNDS:
            return current

        if time.monotonic() >= deadline:
            return current

        time.sleep(config.SCAN_POLL_INTERVAL)

    return previous or ""  # pragma: no cover - unreachable


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def scan_wifi(
    interface: Optional[str] = None,
    settle: float = config.SCAN_SETTLE_SECONDS,
    include_optional: bool = True,
) -> ScanResult:
    """Perform one passive scan and return the standardised result.

    Args:
        interface: force a specific interface; auto-detected when omitted.
        settle: seconds to wait for the asynchronous scan to complete.
        include_optional: keep supplementary fields in the serialised output.

    Returns:
        A :class:`~scanner.models.ScanResult`. An empty ``networks`` list is a
        valid result meaning "no APs were heard" - it is not an error.

    Raises:
        NoWifiAdapterError, WifiDisabledError, NetworkManagerUnavailableError,
        PermissionDeniedError, InterfaceNotFoundError, ScanFailedError.
    """
    _ensure_nmcli_present()

    if not _radio_enabled():
        raise WifiDisabledError()

    resolved_interface = _detect_interface(interface)

    started = iso_timestamp()

    # Snapshot the cache before rescanning. Used as a fallback if NetworkManager
    # leaves the cache empty or half-populated while a new scan is starting.
    try:
        baseline: Optional[str] = _fetch_results(resolved_interface)
    except ScannerError:
        baseline = None

    _trigger_rescan(resolved_interface)
    raw_output = _await_scan(resolved_interface, settle, baseline)

    networks = parse_nmcli_terse(raw_output, timestamp=started)

    # An empty result right after a rescan is a known NetworkManager artefact:
    # the cache is briefly cleared or rebuilt when a scan is (re)started, and
    # issuing rescans faster than the driver's ~11 s cycle makes this likely.
    # Reporting "0 access points" then would be a false negative, so fall back
    # to the pre-rescan cache. A genuinely empty environment has an empty
    # baseline too, and is still reported as an empty result.
    if not networks and baseline:
        fallback = parse_nmcli_terse(baseline, timestamp=started)
        if fallback:
            networks = fallback

    # Strongest signal first: easier to read and a stable, deterministic
    # order for downstream consumers and diffing.
    networks.sort(key=lambda n: (-(n.signal if n.signal is not None else -999), n.bssid))

    return ScanResult(
        timestamp=started,
        networks=networks,
        interface=resolved_interface,
        schema_version=config.SCHEMA_VERSION,
    )


def scan_to_file(result: ScanResult, directory: str, filename: Optional[str] = None) -> str:
    """Write a scan result to ``directory`` as JSON and return the path."""
    os.makedirs(directory, exist_ok=True)
    if filename is None:
        stamp = result.timestamp.replace(":", "").replace("-", "").replace("+0000", "Z")
        filename = f"scan-{stamp}.json"
    path = os.path.join(directory, filename)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result.to_dict(), handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return path


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _print_summary(result: ScanResult) -> None:
    print(f"Scan timestamp : {result.timestamp}")
    print(f"Interface      : {result.interface}")
    print(f"Networks found : {len(result.networks)}")
    print("-" * 78)
    if not result.networks:
        print("No access points observed. This is a valid (empty) result.")
        return
    print(f"{'SSID':<24} {'BSSID':<18} {'SIG':>5} {'CH':>5} {'FREQ':>6} {'SECURITY'}")
    for network in result.networks:
        ssid_display = (network.ssid or "<hidden>")[:23]
        signal = network.signal if network.signal is not None else "--"
        channel = network.channel if network.channel is not None else "--"
        frequency = network.frequency if network.frequency is not None else "--"
        print(
            f"{ssid_display:<24} {network.bssid:<18} {signal:>5} "
            f"{channel:>5} {frequency:>6} {network.security}"
        )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Passive Wi-Fi access point scanner (WiFiSentinel AI).",
    )
    parser.add_argument("-i", "--interface", help="force a specific Wi-Fi interface")
    parser.add_argument(
        "-s",
        "--settle",
        type=float,
        default=config.SCAN_SETTLE_SECONDS,
        help=f"seconds to wait for scan completion (default {config.SCAN_SETTLE_SECONDS})",
    )
    parser.add_argument("--json", action="store_true", help="print JSON only (no summary)")
    parser.add_argument(
        "--minimal",
        action="store_true",
        help="omit optional fields from the JSON",
    )
    parser.add_argument("--save", metavar="DIR", help="also write the JSON result to DIR")
    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="run N scans in a row (for repeatability checks)",
    )
    args = parser.parse_args(argv)

    if args.count < 1:
        parser.error("--count must be >= 1")

    try:
        results = [
            scan_wifi(interface=args.interface, settle=args.settle)
            for _ in range(args.count)
        ]
    except ScannerError as exc:
        print(f"scanner: {exc}", file=sys.stderr)
        return 1
    except ParseError as exc:
        print(f"scanner: could not interpret nmcli output: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:  # pragma: no cover
        print("\nscanner: interrupted", file=sys.stderr)
        return 130

    for index, result in enumerate(results):
        if args.count > 1:
            print(f"--- scan {index + 1}/{args.count} ---")
        if args.json:
            print(result.to_json(include_optional=not args.minimal))
        else:
            _print_summary(result)
        if args.save and index == len(results) - 1:
            path = scan_to_file(result, args.save)
            if not args.json:
                print(f"\nSaved JSON to {path}")

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
