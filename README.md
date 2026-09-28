# WiFiSentinel AI

A wireless security dashboard. It performs **real passive Wi-Fi scans** through
NetworkManager, scores every access point it hears against a trusted-profile
baseline, and shows the evidence behind each verdict.

Passive observation only: nothing is ever transmitted, injected,
deauthenticated, or associated with a network.

## Architecture

```
Wi-Fi adapter
     ↓  nmcli (scanner/)
  observations
     ↓  ai/  — profile comparison, rules, weighted scoring, Isolation Forest
  risk report
     ↓  backend/  — FastAPI
  JSON
     ↓  src/  — Next.js dashboard
```

| Path | Role |
|---|---|
| `scanner/` | Real passive observation via `nmcli`, one record per BSSID |
| `ai/` | The detection engine: rules, risk scoring, anomaly model |
| `backend/` | FastAPI service wrapping the engine |
| `src/` | Next.js dashboard |
| `run_scan.py` | Command-line entry point |

## Setup

Two processes: the API and the dashboard.

### 1. Backend

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn backend.main:app --port 8000
```

The scanner shells out to `nmcli`, which must be installed separately
(`apt install network-manager`). Without a usable adapter the API returns
**503 with a reason** — it never invents data.

### 2. Dashboard

```bash
npm install
cp .env.example .env.local     # sets NEXT_PUBLIC_API_URL=http://localhost:8000
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). `NEXT_PUBLIC_*` values
are inlined at build time, so restart the dev server after changing one.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness. Never touches the radio. |
| `GET` | `/verdicts` | The verdict vocabulary and accuracy caveat |
| `GET` | `/flagged` | Only the access points worth reviewing |
| `GET` | `/profiles` | SSIDs this site has vouched for |
| `POST` | `/scan` | **Real** scan + analysis. The dashboard's data source. |
| `POST` | `/analyze` | Score caller-supplied observations. No scan. |
| `POST` | `/trust` | Record an observed SSID as trusted (writes) |
| `DELETE` | `/trust/{ssid}` | Remove a trusted profile (writes) |

The service is **stateless**: it keeps no scan history, so `POST /scan` *is*
the data fetch. A scan takes several seconds and occupies the radio, which is
why the dashboard never calls it on page load without the user asking.

### Trusting a network

An access point is `TRUSTED` only when an operator has recorded it. A profile
is always built from a real scan, so it cannot vouch for hardware the machine
never heard:

```bash
curl -X POST localhost:8000/trust -H 'Content-Type: application/json' \
  -d '{"ssid": "CE-WIFI"}'
```

or from the CLI:

```bash
python run_scan.py --trust "CE-WIFI"
```

Until a site has vouched for something, every access point is `UNVERIFIED`.
That is the honest answer, not a failure.

## Verdicts

`classification` is the numeric risk band; `verdict` is the semantic reading.
The dashboard bands on `verdict`.

| Verdict | Meaning |
|---|---|
| `TRUSTED` | A trusted profile vouches for this exact BSSID |
| `LEGITIMATE` | Consistent with the expected network, not explicitly on the list |
| `UNVERIFIED` | Not enough information either way |
| `SUSPICIOUS` | Meaningful deviation from the expected fingerprint |
| `POTENTIAL_FAKE` | Two or more independent parts of the fingerprint contradict the profile |

`POTENTIAL_FAKE` means *may be impersonating*, never *proven malicious*.
Passive metadata cannot establish intent. One network name spanning many
access points is normal; a *contradicting* fingerprint under a trusted name is
the impersonation pattern.

The Isolation Forest learns only what **normal** looks like at your site. It
never sees an attack, and a high anomaly score is not a probability of
compromise. The rules carry the verdict; the model corroborates.

## Security notes

- **The `/trust` routes are unauthenticated.** A caller who can reach
  `POST /trust` can silence detection for any network by trusting it. Put the
  service behind authz before exposing it beyond the operator's machine.
- CORS is restricted to `localhost:3000` by default. Override with
  `WIFISENTINEL_CORS_ORIGINS`.
- A profile built from a scan records whatever is beaconing under that name. If
  an impostor is broadcasting an SSID you approve, the impostor's BSSID is
  recorded too. Verify the BSSID list after trusting a network.

## Tests

```bash
.venv/bin/python -m pytest ai/tests scanner/tests backend/tests -q   # 344
npm run lint && npm run build
```

`backend/tests/test_frontend_contract.py` pins the JSON contract the dashboard
depends on, and parses the endpoint paths out of `src/lib/api.ts` to assert
each one is actually served — the check that would have caught the original
frontend/backend mismatch at build time.
