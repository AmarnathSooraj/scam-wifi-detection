"""WiFiSentinel AI - HTTP API.

    pip install -r requirements.txt
    python -m uvicorn backend.main:app --reload --port 8000

Every network in a ``/scan`` response came from the local Wi-Fi adapter during
that request. Nothing is hardcoded, replayed, or seeded. If the adapter is
unavailable the endpoint returns 503 with the reason - it never invents data.

Endpoints
---------
``GET  /health``    liveness, static by design
``GET  /profiles``  which SSIDs this site has vouched for
``POST /scan``      REAL scan_wifi() -> real analysis -> JSON
``POST /analyze``   analyse observations the caller supplies (no scan)

``/scan`` is the endpoint a dashboard should poll. ``/analyze`` exists so the
engine can be exercised against stored or replayed observations without
occupying the radio; it is explicitly not a scan.

Security boundary: passive observation and analysis only. This service never
transmits, injects, deauthenticates, or associates with any network.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from ai.pipeline import analyze_scan
from ai.profile_store import ProfileStore
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.profile_store = ProfileStore()
    yield


app = FastAPI(
    title="WiFiSentinel AI",
    version="1.0.0",
    description="Passive Wi-Fi rogue-AP detection. Real scans, explainable risk scores.",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ObservationIn(BaseModel):
    """One observed access point.

    Only ``bssid`` is required in practice; everything else is optional
    because a beacon may be partially observed and the engine degrades
    gracefully rather than rejecting it. Field aliases (``signal_dbm``,
    ``frequency_mhz``, ``is_hidden``, ``observed_at``) are also accepted.
    """

    ssid: Optional[str] = None
    bssid: Optional[str] = None
    signal: Optional[int] = Field(None, description="RSSI in dBm")
    channel: Optional[int] = None
    frequency: Optional[int] = Field(None, description="Centre frequency in MHz")
    security: Optional[str] = None
    timestamp: Optional[str] = None
    vendor: Optional[str] = None


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
