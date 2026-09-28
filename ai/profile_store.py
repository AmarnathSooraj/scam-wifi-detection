"""Persistent store for operator-approved trusted network profiles.

This is the bridge between "networks this site legitimately runs" and the
comparison logic in :mod:`ai.trusted_profile`. It exists so the engine never
has to ship, invent, or guess its own baseline: a profile only exists once an
operator has put a real access point in this file, via a real scan.

Separation of concerns
----------------------
* :mod:`ai.trusted_profile` compares an observation against a profile. It has
  no idea where profiles come from.
* This module owns the on-disk format, the read/write cycle, and the rule that
  a profile must be *earned* from observed hardware.

The store ships empty. There is no built-in example network, because a
hardcoded BSSID in production code would be indistinguishable from a mock.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .models import TrustedProfile, WiFiNetwork, oui_of
from .trusted_profile import load_profiles

__all__ = [
    "DEFAULT_PROFILE_PATH",
    "ProfileStore",
    "load_trusted_profiles",
    "build_profile_from_observations",
]

#: Repository-relative default. Overridable per deployment with the
#: ``WIFISENTINEL_PROFILES`` environment variable, so a service can point at
#: its own configuration without code changes.
DEFAULT_PROFILE_PATH = Path(
    os.environ.get(
        "WIFISENTINEL_PROFILES",
        Path(__file__).resolve().parent.parent / "config" / "trusted_networks.json",
    )
)


class ProfileStore:
    """Read/write access to the trusted-profile configuration file.

    The file is treated as source-of-truth configuration, so writes are
    atomic (write to a temporary file in the same directory, then rename).
    A crash mid-write must not leave a truncated, unparseable profile file
    behind - that would silently turn every network into UNVERIFIED.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path is not None else DEFAULT_PROFILE_PATH

    # -- reading ------------------------------------------------------------

    def exists(self) -> bool:
        return self.path.is_file()

    def load(self) -> List[TrustedProfile]:
        """Return the configured profiles.

        A missing file is not an error: it means "this deployment has vouched
        for nothing yet", which is a valid and common state - the first scan
        anywhere in the world starts here.
        """
        if not self.exists():
            return []
        try:
            with self.path.open(encoding="utf-8") as handle:
                payload = json.load(handle)
        except (json.JSONDecodeError, OSError) as exc:
            raise ValueError(f"cannot read trusted profiles from {self.path}: {exc}") from exc
        return load_profiles(payload)

    def load_raw(self) -> Dict[str, Any]:
        """Return the whole file as a dict, preserving any extra keys/comments."""
        if not self.exists():
            return {"profiles": []}
        with self.path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload if isinstance(payload, dict) else {"profiles": []}

    def for_ssid(self, ssid: str) -> Optional[TrustedProfile]:
        """Return the profile covering ``ssid``, if one is configured."""
        from .trusted_profile import profile_for_ssid

        return profile_for_ssid(self.load(), ssid)

    def ssids(self) -> List[str]:
        return [profile.ssid for profile in self.load()]

    # -- writing ------------------------------------------------------------

    def save(self, profiles: Iterable[Any]) -> None:
        """Atomically replace the stored profiles, preserving unknown keys."""
        payload = self.load_raw()
        payload["profiles"] = [
            profile.to_dict() if isinstance(profile, TrustedProfile) else profile
            for profile in profiles
        ]
        payload.pop("_comment", None)  # a rewritten file gets a fresh header
        self._write_atomic(payload)

    def upsert(self, profile: Any, replace_ssid: bool = True) -> TrustedProfile:
        """Add or update one profile, keeping every other profile intact."""
        new = TrustedProfile.from_dict(profile)
        existing = self.load()
        if replace_ssid:
            remaining = [p for p in existing if p.ssid != new.ssid]
        else:
            merged = set(new.known_bssids)
            for profile in existing:
                if profile.ssid == new.ssid:
                    merged |= set(profile.known_bssids)
            new.known_bssids = sorted(merged)
            remaining = [p for p in existing if p.ssid != new.ssid]
        self.save([*remaining, new])
        return new

    def remove(self, ssid: str) -> bool:
        """Delete a profile. Returns False if it was not there."""
        existing = self.load()
        remaining = [p for p in existing if p.ssid != ssid]
        if len(remaining) == len(existing):
            return False
        self.save(remaining)
        return True

    def _write_atomic(self, payload: Dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Same directory, so the final rename is atomic on one filesystem.
        handle = tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=self.path.parent, prefix=".profiles-", suffix=".tmp", delete=False
        )
        try:
            with handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False)
                handle.write("\n")
            os.replace(handle.name, self.path)
        except BaseException:
            Path(handle.name).unlink(missing_ok=True)
            raise


def load_trusted_profiles(path: Optional[Path] = None) -> List[TrustedProfile]:
    """Convenience wrapper: load profiles from ``path`` (or the default)."""
    return ProfileStore(path).load()


def build_profile_from_observations(
    ssid: str,
    observations: Sequence[Any],
    location: Optional[str] = None,
    include_vendors: bool = False,
) -> Optional[TrustedProfile]:
    """Build a trusted profile from access points actually observed for ``ssid``.

    This is the "operator says yes" path: the caller has looked at a real scan,
    decided this SSID is legitimate infrastructure, and is recording what the
    hardware actually looks like. Nothing is invented - every BSSID, channel
    and frequency comes from a real beacon.

    Vendor is included only when the hardware actually advertised one and the
    caller opted in. Vendor data is the least reliable attribute available
    (it is frequently absent or wrong), so it is off by default and carries a
    small weight even when present.

    Returns ``None`` when nothing usable was observed, so a caller cannot
    accidentally persist an empty profile and make an SSID "known" while
    vouching for none of its access points.
    """
    nets = [WiFiNetwork.from_dict(item) for item in observations]
    nets = [n for n in nets if n.ssid == ssid and n.bssid]
    if not nets:
        return None

    security: List[str] = []
    for net in nets:
        if net.security and net.security not in security:
            security.append(net.security)

    return TrustedProfile(
        ssid=ssid,
        known_bssids=sorted({n.bssid for n in nets}),
        security=security,
        expected_channels=sorted({n.channel for n in nets if n.channel is not None}),
        expected_frequencies=sorted({n.frequency for n in nets if n.frequency is not None}),
        known_vendors=sorted({n.vendor.lower() for n in nets if n.vendor and include_vendors}),
        # Derived from the BSSIDs just recorded, so a later access point from
        # the same hardware vendor is recognised rather than treated as
        # foreign. Never has to be maintained by hand.
        known_ouis=sorted({oui_of(n.bssid) for n in nets if oui_of(n.bssid)}),
        location=location,
        provisional=False,  # operator-approved, not self-learned
    )
