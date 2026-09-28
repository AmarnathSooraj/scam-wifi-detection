"""WiFiSentinel AI - HTTP API.

    pip install -r requirements.txt
    python -m uvicorn backend.main:app --reload --port 8000

Every network in a ``/scan`` response came from the local Wi-Fi adapter during
that request. Nothing is hardcoded, replayed, or seeded. If the adapter is
unavailable the endpoint returns 503 with the reason - it never invents data.

Endpoints
---------
``GET  /health``        liveness, static by design
``GET  /verdicts``      the verdict vocabulary and the accuracy caveat
``GET  /flagged``       only the access points worth a human's attention
``GET  /profiles``      which SSIDs this site has vouched for
``POST /scan``          REAL scan_wifi() -> real analysis -> JSON
``POST /analyze``       analyse observations the caller supplies (no scan)
``POST /trust``         record an observed SSID as operator-approved (writes)
``DELETE /trust/{ssid}`` remove a trusted profile (writes)

``/scan`` is the endpoint a dashboard should poll. ``/analyze`` exists so the
engine can be exercised against stored or replayed observations without
occupying the radio; it is explicitly not a scan.

Security boundary: passive observation and analysis only. This service never
transmits, injects, deauthenticates, or associates with any network.

Authentication: none of the routes are authenticated here, which is fine for a
single-operator tool but not for a shared deployment. The ``/trust`` routes
are the ones that matter - a caller who can write the profile store can silence
detection for any network by trusting it. Put the service behind authz before
exposing it.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from ai.pipeline import analyze_scan, clear_detector_cache
from ai.profile_store import ProfileStore, build_profile_from_observations
from scanner import ScannerError, scan_wifi


#: Trusted-network configuration, loaded from disk. Re-read per request rather
#: than cached, so an operator running ``run_scan.py trust ...`` sees the
#: change immediately without restarting the service. The file is tiny and
#: parsed in microseconds; correctness is worth more than the saving.
def _load_profiles() -> List[Any]:
    try:
        return ProfileStore().load()
    except ValueError as exc:
        # A corrupt profile file must be loud, not silently downgrade every
        # network to UNVERIFIED and look like a quiet, healthy system.
        raise HTTPException(
            status_code=500,
            detail={
                "error": "ProfileStoreError",
                "message": str(exc),
                "hint": f"Fix or delete {ProfileStore().path}.",
            },
        ) from exc


app = FastAPI(
    title="WiFiSentinel AI",
    version="1.0.0",
    description="Passive Wi-Fi rogue-AP detection. Real scans, explainable risk scores.",
)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class TrustIn(BaseModel):
    """Request body for recording a network as trusted.

    ``ssid`` is required because it names the network being approved. The
    BSSIDs, security and channels are **not** supplied by the caller: they are
    always read from a real scan, so a caller cannot hand-write a profile that
    vouches for hardware it never observed.
    """

    ssid: str = Field(..., min_length=1, description="Exact SSID as broadcast.")
    interface: Optional[str] = Field(None, description="Force a Wi-Fi interface.")
    settle: float = Field(20.0, ge=0.0, le=120.0, description="Seconds to wait for the scan.")
    location: Optional[str] = Field(None, description="Human label, e.g. 'Terminal 2, Gate B'.")
    include_vendors: bool = Field(
        False, description="Record vendor strings (least reliable attribute; off by default)."
    )


class AnalyzeIn(BaseModel):
    """Observations supplied by the caller. No radio access is performed."""

    networks: List[Dict[str, Any]] = Field(default_factory=list)
    timestamp: Optional[str] = None
    use_profiles: bool = Field(
        True, description="Set false to analyse with no trusted profiles at all."
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> Dict[str, Any]:
    """Liveness. Intentionally static - a health check must not touch the radio."""
    return {"status": "ok"}


@app.get("/flagged")
def flagged(interface: Optional[str] = Query(None)) -> Dict[str, Any]:
    """Access points that need a human's attention, worst first.

    Convenience view over ``POST /scan`` for a dashboard that only wants the
    handful of results worth surfacing. Performs a real scan.
    """
    try:
        result = scan_wifi(interface=interface)
    except ScannerError as exc:
        raise HTTPException(
            status_code=503,
            detail={"error": type(exc).__name__, "message": str(exc)},
        ) from exc

    report = analyze_scan(result, profiles=_load_profiles())
    return {
        "interface": result.interface,
        "scan_timestamp": result.timestamp,
        "flagged_count": report.get("flagged_count", 0),
        "verdict_counts": report.get("verdict_counts", {}),
        "flagged": report.get("flagged", []),
    }


@app.get("/verdicts")
def verdicts() -> Dict[str, Any]:
    """The verdict vocabulary, so a dashboard never hardcodes the wording.

    In particular this is where a client learns that ``POTENTIAL_FAKE`` means
    "may be impersonating", not "proven malicious" - passive metadata cannot
    establish intent.
    """
    from ai.verdict import ACCURACY_NOTE, verdict_definitions

    return {"verdicts": verdict_definitions(), "accuracy_note": ACCURACY_NOTE}


@app.get("/profiles")
def profiles() -> Dict[str, Any]:
    """Trusted networks configured for this site."""
    loaded = _load_profiles()
    return {
        "count": len(loaded),
        "ssids": [profile.ssid for profile in loaded],
        "store_path": str(ProfileStore().path),
    }


@app.post("/trust", status_code=201)
def trust(payload: TrustIn) -> Dict[str, Any]:
    """Record a currently-observed SSID as operator-approved infrastructure.

    This is the HTTP equivalent of ``python run_scan.py --trust "SSID"``, and
    carries the same guarantee: a profile can only be **earned from a real
    scan**. The caller names the SSID, the adapter supplies the BSSIDs,
    security and channels. Nothing is hand-written, so a profile cannot vouch
    for hardware this machine never heard.

    This endpoint writes to the profile store. It is deliberately the only
    mutating route in the service, and it should sit behind authentication in
    any real deployment - an unauthenticated caller who can write the store can
    silence detection for any network by trusting it.
    """
    try:
        result = scan_wifi(interface=payload.interface, settle=payload.settle)
    except ScannerError as exc:
        # A profile built without a scan would be fiction, so refuse rather
        # than store something unverifiable.
        raise HTTPException(
            status_code=503,
            detail={
                "error": type(exc).__name__,
                "message": str(exc),
                "hint": "Recording a trusted network requires a real scan of the local adapter.",
            },
        ) from exc

    observed: List[Dict[str, Any]] = [n.to_dict() for n in result.networks]
    matches = [n for n in observed if (n.get("ssid") or "") == payload.ssid]
    if not matches:
        available = sorted({n.get("ssid") for n in observed if n.get("ssid")})
        raise HTTPException(
            status_code=404,
            detail={
                "error": "SSIDNotObserved",
                "message": f"{payload.ssid!r} was not observed in this scan.",
                "observed_ssids": available,
                "hint": "The SSID must match exactly, including case and spacing.",
            },
        )

    profile = build_profile_from_observations(
        payload.ssid, observed, location=payload.location, include_vendors=payload.include_vendors
    )
    if profile is None:  # pragma: no cover - matches is non-empty, so unreachable
        raise HTTPException(
            status_code=422,
            detail={"error": "NoUsableObservations", "message": "No usable beacons for that SSID."},
        )

    store = ProfileStore()
    try:
        store.upsert(profile)
    except ValueError as exc:
        # ``upsert`` reads the current file first. If that file is corrupt we
        # must NOT write over it: the operator's configuration would be lost,
        # and every network would silently fall back to UNVERIFIED. Refuse and
        # tell them to fix the file, same as the read path does.
        raise HTTPException(
            status_code=500,
            detail={
                "error": "ProfileStoreError",
                "message": str(exc),
                "hint": f"Refusing to overwrite an unreadable profile file. Fix or delete {store.path}.",
            },
        ) from exc
    # The per-profile detector cache is keyed on profile content, so a changed
    # profile naturally gets a fresh baseline on its next scan. Clearing is
    # still correct hygiene: it releases the forests built for the old profile.
    clear_detector_cache()
    return {
        "trusted": profile.ssid,
        "known_bssids": profile.known_bssids,
        "security": profile.security,
        "expected_channels": profile.expected_channels,
        "expected_frequencies": profile.expected_frequencies,
        "known_ouis": profile.known_ouis,
        "location": profile.location,
        "store_path": str(store.path),
        "scan_timestamp": result.timestamp,
    }


@app.delete("/trust/{ssid}")
def untrust(ssid: str) -> Dict[str, Any]:
    """Remove a trusted profile. Future observations are UNVERIFIED again.

    Deliberately not a scan: the store is source-of-truth configuration, so
    deleting from it needs no radio access and stays fast and available.
    """
    store = ProfileStore()
    if not store.remove(ssid):
        raise HTTPException(
            status_code=404,
            detail={"error": "NotTrusted", "message": f"{ssid!r} is not in the profile store."},
        )
    clear_detector_cache()
    return {"untrusted": ssid, "store_path": str(store.path)}


@app.post("/scan")
def scan(
    interface: Optional[str] = Query(None, description="Force a Wi-Fi interface."),
    settle: float = Query(20.0, ge=0.0, le=120.0, description="Seconds to wait for the scan."),
) -> Dict[str, Any]:
    """Perform a REAL passive Wi-Fi scan and analyse every access point found.

    This is the primary endpoint. The ``networks`` array in the response is the
    literal output of ``scan_wifi()`` on the machine serving the request.
    """
    try:
        result = scan_wifi(interface=interface, settle=settle)
    except ScannerError as exc:
        # No adapter, Wi-Fi off, NetworkManager down, or insufficient
        # permission. A clear 503 beats a 500 with a stack trace, and beats
        # silently returning an empty or invented result.
        raise HTTPException(
            status_code=503,
            detail={
                "error": type(exc).__name__,
                "message": str(exc),
                "hint": "A real scan needs a wireless adapter, NetworkManager, and permission to query it.",
            },
        ) from exc

    report = analyze_scan(result, profiles=_load_profiles())
    report["interface"] = result.interface
    report["source"] = "live-scan"
    report["scan_timestamp"] = result.timestamp
    return report


@app.post("/analyze")
def analyze(payload: AnalyzeIn) -> Dict[str, Any]:
    """Analyse caller-supplied observations. Does NOT perform a scan.

    Useful for testing the engine, replaying a stored scan, or analysing
    observations gathered on another machine.
    """
    if payload.use_profiles:
        profiles_payload = _load_profiles()
    else:
        profiles_payload = []

    report = analyze_scan(
        {"networks": payload.networks, "timestamp": payload.timestamp},
        profiles=profiles_payload,
    )
    report["source"] = "supplied-observations"
    return report
