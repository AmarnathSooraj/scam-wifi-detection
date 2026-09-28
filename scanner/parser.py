"""Convert raw ``nmcli`` output into :class:`~scanner.models.WiFiNetwork`.

The single most important detail in this module is :func:`split_unescaped`.
``nmcli --terse`` escapes ``:`` as ``\\:``, so a BSSID like ``AA:BB:CC:11:22:33``
and an SSID like ``Cafe:Wifi`` both survive a naive ``line.split(":")`` only
by accident. Splitting first and unescaping afterwards corrupts every record,
so we must scan the line and split only on *unescaped* separators.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import config
from .models import WiFiNetwork, channel_to_frequency, iso_timestamp

__all__ = [
    "split_unescaped",
    "parse_nmcli_terse",
    "parse_networks",
    "normalize_security",
    "ParseError",
]

_BSSID_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")
# nmcli renders signal as an integer, frequency as "2457 MHz", width as
# "80 MHz". Anything unparsable becomes None rather than a guess.
_INT_RE = re.compile(r"-?\d+")

# Ciphers nmcli may mix into the SECURITY column in some releases.
_CIPHER_TOKENS = config._CIPHER_TOKENS


class ParseError(ValueError):
    """Raised when nmcli output cannot be interpreted at all."""


def _is_cipher_token(token: str) -> bool:
    """True if a SECURITY token names a cipher rather than a protocol.

    NetworkManager renders ciphers as ``pairwise-CCMP``, ``TKIP``, ``CCMP``,
    ``PSK``, ``SAE`` and similar depending on version. Match by suffix and
    prefix so new cipher names are handled without a code change, while
    protocol names (``WPA2``, ``RSN``, ``SAE`` as a protocol, ``OWE``,
    ``WEP``, ``EAP``) are preserved.
    """
    lowered = token.lower()
    if lowered in _CIPHER_TOKENS:
        return True
    if lowered.startswith(("pairwise-", "group-", "pair-", "rsn-")):
        return True
    return lowered.endswith(("-ccmp", "-tkip", "-gcmp", "-wpa"))


def split_unescaped(line: str, separator: str = ":") -> List[str]:
    r"""Split ``line`` on unescaped ``separator`` and unescape each field.

    ``nmcli -t`` escapes the separator and the escape character itself with a
    backslash. For example::

        BSSID  SSID
        90\\:A2\\:10  Cafe\\:Free

    A plain ``str.split(":")`` would produce 8 junk fields for the first row.
    This function returns ``["90:A2:10", "Cafe:Free"]``.

    A trailing lone backslash (nmcli emits this for some values) is preserved
    verbatim rather than raising.
    """
    fields: List[str] = []
    current: List[str] = []
    index = 0
    length = len(line)

    while index < length:
        char = line[index]
        if char == "\\" and index + 1 < length:
            current.append(line[index + 1])
            index += 2
            continue
        if char == separator:
            fields.append("".join(current))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1

    fields.append("".join(current))
    return fields


def _to_int(value: Optional[str]) -> Optional[int]:
    """Best-effort integer extraction. Returns None if no number is present."""
    if value is None:
        return None
    match = _INT_RE.search(value)
    if not match:
        return None
    try:
        return int(match.group())
    except ValueError:
        return None


def normalize_security(raw: Optional[str]) -> str:
    """Normalise nmcli's SECURITY field to a short protocol label.

    * empty / ``--`` -> ``OPEN`` (an AP with no advertised security)
    * ``WPA1 WPA2``   -> ``WPA1/WPA2``
    * ``WPA2 WPA3``   -> ``WPA2/WPA3``
    * ``(none)``      -> ``OPEN``
    * cipher listings (e.g. ``RSN pairwise-CCMP``) are reduced to protocol
      names only.
    """
    if raw is None:
        return config.OPEN_SECURITY

    text = raw.strip().strip("()").strip()
    if not text or text in {"--", "none", "None"}:
        return config.OPEN_SECURITY

    # Drop known cipher words but keep tokens such as "WPA2", "RSN", "SAE",
    # "WEP", "OWE", "WPA3".
    tokens = [t for t in text.split() if not _is_cipher_token(t)]
    if not tokens:
        return config.OPEN_SECURITY

    ordered: List[str] = []
    for token in tokens:
        if token not in ordered:
            ordered.append(token)
    return "/".join(ordered)


def _is_hidden(fields: Dict[str, str]) -> bool:
    """A hidden SSID shows as empty in both SSID and SSID-HEX."""
    return not fields.get("SSID", "").strip()


def _ssid_from_hex(hex_value: Optional[str]) -> Optional[str]:
    """Decode SSID-HEX, used when the human-readable SSID is unusable.

    This protects against SSIDs containing control characters or newlines,
    which cannot survive a line-oriented text format.
    """
    if not hex_value:
        return None
    candidate = hex_value.strip()
    if not candidate or len(candidate) % 2 != 0:
        return None
    try:
        decoded = bytes.fromhex(candidate).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        try:
            decoded = bytes.fromhex(candidate).decode("latin-1")
        except ValueError:
            return None
    # Reject values containing control characters we cannot safely emit.
    if any(ord(ch) < 0x20 and ch not in "\t" for ch in decoded):
        return None
    return decoded


def _build_network(
    fields: Dict[str, str], timestamp: str
) -> Optional[WiFiNetwork]:
    """Build one WiFiNetwork, or None if the row has no usable BSSID."""
    bssid = fields.get("BSSID", "").strip().upper()
    if not _BSSID_RE.match(bssid):
        # Without a BSSID the record cannot be de-duplicated or compared, so
        # it is worthless downstream. Drop it rather than emit a fake one.
        return None

    ssid = fields.get("SSID", "").strip()
    if not ssid:
        # Fall back to the hex form before declaring the AP hidden.
        decoded = _ssid_from_hex(fields.get("SSID-HEX"))
        if decoded:
            ssid = decoded

    # nmcli reports SIGNAL as a 0-100 quality percentage, not dBm. Validate
    # that range, then convert to dBm for the agreed schema.
    quality = _to_int(fields.get("SIGNAL"))
    if quality is not None and not (
        config.SIGNAL_QUALITY_MIN <= quality <= config.SIGNAL_QUALITY_MAX
    ):
        quality = None
    signal = config.quality_to_dbm(quality) if quality is not None else None

    channel = _to_int(fields.get("CHAN"))
    frequency = _to_int(fields.get("FREQ"))
    if frequency is not None and not (2400 <= frequency <= 7200):
        frequency = None
    if frequency is None:
        # Standards-based derivation, only when nmcli gave us nothing.
        frequency = channel_to_frequency(channel)

    bandwidth = _to_int(fields.get("BANDWIDTH"))
    if bandwidth is not None and bandwidth <= 0:
        # nmcli reports "0 MHz" when it cannot determine the width.
        bandwidth = None

    return WiFiNetwork(
        ssid=ssid,
        bssid=bssid,
        signal=signal,
        channel=channel,
        frequency=frequency,
        security=normalize_security(fields.get("SECURITY")),
        timestamp=timestamp,
        signal_quality=quality,
        ssid_hex=fields.get("SSID-HEX", "").strip() or None,
        hidden=_is_hidden(fields),
        bandwidth_mhz=bandwidth,
        mode=fields.get("MODE", "").strip() or None,
    )


def parse_nmcli_terse(
    output: str,
    field_order: Sequence[str] = config.FIELD_ORDER,
    timestamp: Optional[str] = None,
    dedupe: bool = True,
) -> List[WiFiNetwork]:
    """Parse terse ``nmcli`` output into de-duplicated WiFiNetwork records.

    Robustness notes:

    * Rows are matched to field names *positionally*, so a missing trailing
      value (nmcli prints nothing after a final separator) is tolerated.
    * Rows with the wrong field count are skipped, not raised on: one bad
      line must not abort a scan.
    * SSIDs containing spaces, colons, backslashes and non-ASCII text all
      round-trip correctly.
    * Duplicate BSSIDs are merged (:meth:`WiFiNetwork.merge`) keeping the
      strongest signal and the most complete metadata. Different BSSIDs
      that happen to share an SSID are **never** merged.
    """
    stamp = timestamp or iso_timestamp()
    expected = len(field_order)
    records: Dict[str, WiFiNetwork] = {}
    order: List[str] = []

    for raw_line in output.splitlines():
        if not raw_line.strip():
            continue

        values = split_unescaped(raw_line)

        # An SSID containing a newline produces extra lines. If this row is
        # too long, salvage the leading fields rather than discarding the AP.
        if len(values) > expected:
            values = values[:expected]
        elif len(values) < expected:
            values = values + [""] * (expected - len(values))

        fields = dict(zip(field_order, values))
        network = _build_network(fields, stamp)
        if network is None:
            continue

        if not dedupe:
            order.append(network.bssid)
            records[network.bssid] = network
            continue

        if network.bssid in records:
            records[network.bssid] = records[network.bssid].merge(network)
        else:
            order.append(network.bssid)
            records[network.bssid] = network

    return [records[bssid] for bssid in order]


def parse_networks(
    output: str,
    field_order: Sequence[str] = config.FIELD_ORDER,
    timestamp: Optional[str] = None,
) -> List[WiFiNetwork]:
    """Alias for :func:`parse_nmcli_terse` (reads better at call sites)."""
    return parse_nmcli_terse(output, field_order=field_order, timestamp=timestamp)


def parse_usable_interfaces(device_output: str) -> List[Tuple[str, str, str]]:
    """Parse ``nmcli -t -f DEVICE,TYPE,STATE device status``.

    Returns ``(device, type, state)`` triples for scan-capable Wi-Fi radios
    only. ``wifi-p2p`` devices are excluded: they advertise TYPE ``wifi-p2p``
    and cannot perform a scan.
    """
    results: List[Tuple[str, str, str]] = []
    for raw_line in device_output.splitlines():
        if not raw_line.strip():
            continue
        values = split_unescaped(raw_line)
        if len(values) < 3:
            continue
        device, device_type, state = values[0], values[1], values[2]
        if device_type in config.SCANNABLE_DEVICE_TYPES:
            results.append((device, device_type, state))
    return results


def find_interface(
    device_output: str, preferred: Optional[str] = None
) -> Optional[str]:
    """Choose which interface to scan on.

    Preference order: an explicitly requested interface, then a connected
    Wi-Fi device, then any available Wi-Fi device.
    """
    interfaces = parse_usable_interfaces(device_output)
    if not interfaces:
        return None

    names = [name for name, _, _ in interfaces]

    if preferred:
        if preferred in names:
            return preferred
        raise ParseError(
            f"Interface '{preferred}' is not a usable Wi-Fi device. "
            f"Available: {', '.join(names) or 'none'}"
        )

    for name, _, state in interfaces:
        if state == "connected":
            return name
    return names[0]
