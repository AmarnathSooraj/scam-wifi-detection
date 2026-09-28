"""Backend integration reference: how the API layer wraps the engine.

Run it to see the real request/response shapes:

    python ai/integration_example.py

Everything here is production-shaped. There is no invented network data: the
demonstration performs a **real passive scan** of the local adapter and feeds
the result straight into the analysis engine. If no adapter is available it
reports that plainly instead of falling back to fake data.

The API itself lives in ``backend/main.py``. :func:`fastapi_example` is kept so
the reference implementation has a test guarding it, but the real file is the
authoritative one.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make the project root importable so this file runs from anywhere.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ai.pipeline import analyze_scan
from ai.profile_store import ProfileStore
from ai.risk_engine import thresholds_doc


# ---------------------------------------------------------------------------
# 1. The production data flow.
# ---------------------------------------------------------------------------


def scan_and_analyze(interface: str | None = None) -> dict:
    """One real scan, analysed against the site's configured profiles.

    This is the entire application: acquire real observations, compare them
    against real configuration, report. No step invents a network.
    """
    from scanner import ScannerError, scan_wifi

    try:
        scan = scan_wifi(interface=interface)
    except ScannerError as exc:
        return {
            "error": type(exc).__name__,
            "detail": str(exc),
            "hint": "This needs a wireless adapter, NetworkManager, and permission to query it.",
        }

    profiles = ProfileStore().load()
    report = analyze_scan(scan, profiles=profiles)
    report["interface"] = scan.interface
    report["trusted_profiles"] = [p.ssid for p in profiles]
    return report


# ---------------------------------------------------------------------------
# 2. Reference API implementation (mirrors backend/main.py).
# ---------------------------------------------------------------------------


def fastapi_example() -> str:
    """The FastAPI layer as a source string, guarded by a test.

    Kept here rather than only in ``backend/main.py`` so the test suite can
    parse it with ``ast`` on a machine with no FastAPI installed. The real
    file is the one to run; this is a copy for reference.
    """
    return '''
# backend/main.py
#
#   pip install -r requirements.txt
#   python -m uvicorn backend.main:app --reload --port 8000
#
# /health  -> static liveness
# /scan    -> REAL scan_wifi() -> real analysis -> JSON
#
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ai.pipeline import analyze_scan
from ai.profile_store import ProfileStore
from scanner import ScannerError, scan_wifi

store = ProfileStore()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="WiFiSentinel AI", lifespan=lifespan)


class AnalyzeIn(BaseModel):
    """Analyse observations the client already holds.

    This endpoint does NOT scan. It exists so the engine can be exercised
    against a stored or replayed observation. /scan is the real one.
    """
    networks: list[dict] = []
    timestamp: str | None = None
    use_profiles: bool = True


@app.get("/health")
def health():
    """Liveness only. Intentionally static."""
    return {"status": "ok"}


@app.get("/profiles")
def profiles():
    """Which SSIDs this site has vouched for."""
    loaded = store.load()
    return {"count": len(loaded), "ssids": [p.ssid for p in loaded], "path": str(store.path)}


@app.post("/scan")
def scan(interface: str | None = None, settle: float = 20.0):
    """Perform a REAL passive scan and analyse it.

    Every network in the response came from the local Wi-Fi adapter.
    """
    try:
        result = scan_wifi(interface=interface, settle=settle)
    except ScannerError as exc:
        # No adapter / Wi-Fi off / no permission -> a clear 503, never a 500.
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    report = analyze_scan(result, profiles=store.load())
    report["interface"] = result.interface
    return report


@app.post("/analyze")
def analyze(payload: AnalyzeIn):
    """Analyse observations supplied by the caller (no scan performed)."""
    report = analyze_scan(
        {"networks": payload.networks, "timestamp": payload.timestamp},
        profiles=store.load() if payload.use_profiles else [],
    )
    return report
'''.strip()


# ---------------------------------------------------------------------------


def _print_report(report: dict) -> None:
    if "error" in report:
        print(f"  scan failed: {report['error']}: {report['detail']}")
        return

    print(f"  interface : {report.get('interface')}")
    print(f"  observed  : {report['network_count']} access points "
          f"across {report['ssid_count']} network(s)")
    print(f"  trusted   : {report['trusted_profiles'] or '(none configured - everything is UNVERIFIED)'}")
    counts = {k: v for k, v in report["classification_counts"].items() if v}
    print(f"  verdicts  : {counts}\n")

    width = max((len(r["bssid"]) for r in report["results"]), default=17)
    print(f"  {'BSSID':<{width}}  {'SSID':<24}  {'CH':>4}  {'SECURITY':<12}  {'RISK':>4}  CLASSIFICATION")
    for result in sorted(report["results"], key=lambda r: -r["risk_score"]):
        observed = result["observed"]
        ssid = (observed["ssid"] or "<hidden>")[:24]
        print(f"  {result['bssid'] or '<unknown>':<{width}}  {ssid:<24}  "
              f"{str(observed['channel'] or '-'):>4}  {observed['security']:<12}  "
              f"{result['risk_score']:>4}  {result['classification']}")


def main() -> int:
    print("=" * 78)
    print("REAL SCAN -> AI ANALYSIS")
    print("=" * 78)
    report = scan_and_analyze()
    _print_report(report)

    if "error" not in report:
        print("\n" + "=" * 78)
        print("Classification thresholds")
        print("=" * 78)
        for label, description in thresholds_doc().items():
            print(f"  {label:<14} {description}")

    print("\n" + "=" * 78)
    print("Reference API (the real one is backend/main.py)")
    print("=" * 78)
    print(fastapi_example())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
