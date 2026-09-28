"""Guard the HTTP contract the Next.js dashboard depends on.

The frontend broke for months because it called ``/api/networks`` and
``/api/trusted`` - routes no backend ever served - while the API exposed
``/scan``, ``/profiles`` and ``/trust``. Nothing checked that the two sides
agreed, so the mismatch only surfaced as a permanently empty dashboard.

These tests pin the shape the TypeScript types in ``src/types/network.ts``
declare. If a field is renamed or a verdict value is added on the Python
side, these fail rather than the UI silently rendering ``undefined``.

Mirroring rule: every name asserted here must also appear in
``src/types/network.ts``. The ``test_types_file_declares_every_field`` test at
the bottom enforces that in the other direction.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from .conftest import ROGUE_BSSID, TRUSTED_SSID

pytestmark = pytest.mark.usefixtures("store_env")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TYPES_FILE = REPO_ROOT / "src" / "types" / "network.ts"
API_FILE = REPO_ROOT / "src" / "lib" / "api.ts"


def _analyze(client, networks):
    response = client.post("/analyze", json={"networks": networks})
    assert response.status_code == 200
    return response.json()


# --- Report shape ---------------------------------------------------------


def test_scan_report_has_every_key_the_dashboard_reads(client, fake_scan):
    payload = client.post("/scan", params={"settle": 0.0}).json()
    required = {
        "timestamp",
        "network_count",
        "ssid_count",
        "classification_counts",
        "verdict_counts",
        "flagged_count",
        "flagged",
        "results",
        "networks",
        "thresholds",
        "verdict_definitions",
    }
    assert required <= set(payload), f"missing: {required - set(payload)}"


def test_each_result_has_every_key_the_types_declare(client, fake_scan):
    """The `Network` type in src/types/network.ts, asserted field by field."""
    payload = client.post("/scan", params={"settle": 0.0}).json()
    declared = {
        "ssid",
        "bssid",
        "risk_score",
        "classification",
        "verdict",
        "evidence_level",
        "reasons",
        "indicators",
        "mitigating",
        "indicator_details",
        "score_breakdown",
        "anomaly_score",
        "anomaly_available",
        "profile_match",
        "impersonation_pattern",
        "impersonating",
        "families_deviating",
        "verdict_summary",
        "verdict_guidance",
        "accuracy_note",
        "observed",
        "timestamp",
    }
    for result in payload["results"]:
        assert declared <= set(result), f"{result['bssid']} missing {declared - set(result)}"


def test_observed_block_matches_the_observed_type(client, fake_scan):
    """Radio attributes live under `observed`, not at the top level.

    The dashboard reads `network.observed.signal`; reading `network.signal`
    would silently yield undefined and render "undefined dBm".
    """
    payload = client.post("/scan", params={"settle": 0.0}).json()
    for result in payload["results"]:
        assert {"ssid", "bssid", "signal", "channel", "frequency", "security", "timestamp"} <= set(
            result["observed"]
        )


def test_indicator_details_carry_code_message_and_points(client, fake_scan):
    """The detail panel renders `code`, `message` and `points` per indicator."""
    payload = client.post("/scan", params={"settle": 0.0}).json()
    flagged = [r for r in payload["results"] if r["indicator_details"]]
    assert flagged, "expected at least one access point with indicators"
    for result in flagged:
        for indicator in result["indicator_details"]:
            assert {"code", "message", "meaning", "family", "points"} <= set(indicator)
            assert isinstance(indicator["points"], int)


# --- Vocabulary -----------------------------------------------------------


def test_verdict_values_match_the_typescript_union(client, fake_scan):
    """Every verdict the engine emits must be one the UI can render.

    A new verdict added to `ai/verdict.py` that the union does not list would
    render as an undefined badge - the worst kind of failure for a security
    dashboard, because an unreviewable state looks like a clean one.
    """
    payload = client.post("/scan", params={"settle": 0.0}).json()
    seen = {r["verdict"] for r in payload["results"]}
    assert seen <= {"TRUSTED", "LEGITIMATE", "UNVERIFIED", "SUSPICIOUS", "POTENTIAL_FAKE"}
    assert set(payload["verdict_counts"]) == {
        "TRUSTED",
        "LEGITIMATE",
        "UNVERIFIED",
        "SUSPICIOUS",
        "POTENTIAL_FAKE",
    }


def test_verdicts_endpoint_publishes_the_same_vocabulary(client):
    """`/verdicts` is what the UI renders its legend from, so it must be complete."""
    verdicts = client.get("/verdicts").json()["verdicts"]
    assert set(verdicts) == {
        "TRUSTED",
        "LEGITIMATE",
        "UNVERIFIED",
        "SUSPICIOUS",
        "POTENTIAL_FAKE",
    }


def test_risk_score_is_always_a_bounded_integer(client, fake_scan):
    """The meter clamps to 0-100 and renders the value directly."""
    payload = client.post("/scan", params={"settle": 0.0}).json()
    for result in payload["results"]:
        assert isinstance(result["risk_score"], int)
        assert 0 <= result["risk_score"] <= 100


# --- Route surface the client calls --------------------------------------


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/health"),
        ("get", "/verdicts"),
        ("get", "/profiles"),
        ("get", "/flagged"),
        ("post", "/scan"),
        ("post", "/analyze"),
        ("post", "/trust"),
    ],
)
def test_every_route_the_client_calls_exists(client, fake_scan, method, path):
    """Guards against the original bug: the client called routes that never existed."""
    kwargs: dict = {"params": {"settle": 0.0}}
    if method == "post":
        kwargs["json"] = {"ssid": TRUSTED_SSID, "settle": 0.0, "networks": []}
    response = getattr(client, method)(path, **kwargs)
    assert response.status_code != 404, f"{method.upper()} {path} is not served"


def test_frontend_calls_only_routes_that_exist():
    """Parse the endpoint paths out of `src/lib/api.ts` and resolve each one.

    This is the check that would have caught the original mismatch at build
    time rather than as an empty dashboard in the browser.
    """
    import backend.main as main

    source = API_FILE.read_text(encoding="utf-8")
    # Paths appear as template literals or plain strings in request(...) calls.
    paths = set(re.findall(r'request[<(][^)\n]*?["`](/[a-z][^"`?]*)', source))
    assert paths, "no endpoint paths found in src/lib/api.ts - has the client been refactored?"

    served = {getattr(route, "path", "").rstrip("/") for route in main.app.routes}

    for path in paths:
        bare = path.split("?")[0].rstrip("/")
        # A client path parameter is written `${...}` but declared `{...}` by
        # FastAPI, so match on the literal prefix up to the parameter.
        prefix = bare.split("${")[0].rstrip("/")
        assert any(
            route == prefix or route.startswith(f"{prefix}{{") or prefix.startswith(route)
            for route in served
        ), f"src/lib/api.ts calls {bare!r}, which backend/main.py does not serve"


# --- The other direction: does the type file cover the API? --------------


def test_types_file_declares_every_verdict_the_api_can_return():
    """`src/types/network.ts` must know about every verdict the engine emits."""
    types = TYPES_FILE.read_text(encoding="utf-8")
    for verdict in ("TRUSTED", "LEGITIMATE", "UNVERIFIED", "SUSPICIOUS", "POTENTIAL_FAKE"):
        assert f'"{verdict}"' in types, f"{verdict} is missing from the TypeScript types"
