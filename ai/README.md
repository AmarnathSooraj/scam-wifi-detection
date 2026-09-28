# WiFiSentinel AI — Detection Engine

Person 2's module. It sits between the Wi-Fi scanner (Person 1) and the FastAPI
backend (Person 3):

```
Wi-Fi metadata JSON
        ↓
   THIS MODULE
        ↓
Risk Assessment JSON  →  FastAPI (Person 3)  →  Dashboard (Person 4)
```

The question it answers is **not** "is this SSID duplicated?". A single
legitimate network routinely spans many access points:

```
Airport_Free_WiFi
  AP1 → BSSID AA:BB:CC:11:22:33  → legitimate
  AP2 → BSSID AA:BB:CC:11:22:34  → legitimate
  AP3 → BSSID AA:BB:CC:11:22:35  → legitimate
  AP4 → BSSID AA:BB:CC:11:22:36  → legitimate
```

The question it actually answers is:

> **Does this access point belong to the expected wireless infrastructure, and
> does its fingerprint deviate from the normal profile?**

**Security boundary.** This module performs passive analysis of wireless
metadata only. It contains no active probing, packet injection,
deauthentication, interception, credential handling, or AP creation. The one
documented requirement on the backend is that the scanner it consumes is
itself passive.

---
## What this component is

The analysis engine. It takes **real observations of nearby Wi-Fi access
points** and produces an explainable risk score and classification for each
one. It never invents, simulates, or replays network data.

```
Wi-Fi adapter  →  scanner.scan_wifi()  →  this engine  →  CLI / HTTP API
                     (real hardware)      (ai/)
```

The complementary components are:

| Path | Role |
|---|---|
| `scanner/` | Person 1 — passive Wi-Fi observation via `nmcli` |
| `ai/` | Person 2 — **this component** — risk analysis engine |
| `backend/` | Person 3 — HTTP API wrapping the engine |
| `run_scan.py` | Production command-line entry point |

---

## Production usage

These are the commands you run to *use* the system. All of them operate on a
real Wi-Fi adapter. Run from the repository root.

### Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The engine on its own needs only `numpy` and `scikit-learn`
(`pip install -r ai/requirements.txt`); the API layer adds `fastapi` and
`uvicorn`. The scanner has **no** Python dependencies but does require the
system `nmcli` binary (NetworkManager) and a wireless adapter.

### Scan and analyse

```bash
python run_scan.py
```

Performs a real passive scan, analyses every access point found, and prints
BSSID, SSID, channel, signal, security, risk score and classification for each:

```
Scanning Wi-Fi networks...

Interface      : wlo1
Networks found : 15 access point(s) across 13 network(s)
Trusted here   : CE-WIFI
Verdicts       : TRUSTED=3  UNVERIFIED=12

BSSID              SSID                          CH  SIGNAL  SECURITY      RISK  EVIDENCE  VERDICT
--------------------------------------------------------------------------------------------------
BC:07:1D:66:C2:E6  CE-WIFI                       11  -55dBm  OPEN             0  HIGH      TRUSTED
E6:C4:C8:2D:90:C3  Nishani's F55                  1  -62dBm  WPA2             0  LOW       UNVERIFIED
04:38:55:3C:2E:10  Engineering College            4  -68dBm  WPA1/WPA2        0  LOW       UNVERIFIED
...
```

Add `-v` to see why each verdict was reached:

```
BC:07:1D:66:C2:E6  CE-WIFI                       11  -55dBm  OPEN             0  HIGH      TRUSTED
                       This BSSID is listed in the trusted profile for CE-WIFI and every
                       characteristic the profile checks matches.
                       -> No action needed. Verified infrastructure.
```

Every value above came from the radio seconds earlier. If the scan cannot run,
the command explains why and exits non-zero — it never prints placeholder
data.

| Command | Effect |
|---|---|
| `python run_scan.py` | scan and print the table |
| `python run_scan.py --json` | same, as JSON for scripting |
| `python run_scan.py -v` | add reasons and score breakdowns |
| `python run_scan.py --interface wlo1` | force a specific adapter |
| `python run_scan.py profiles` | list this site's trusted networks |
| `python run_scan.py trust "SSID"` | record a real SSID as trusted |
| `python run_scan.py untrust "SSID"` | remove a trusted network |

### Trusted networks

The store starts **empty**. There are no built-in example networks, because a
hardcoded BSSID in production code would be indistinguishable from a mock.

An access point is `TRUSTED` only when this site has an operator-approved
profile listing its BSSID. To approve a network you have verified is
legitimate:

```bash
python run_scan.py trust "My_Home_WiFi"
```

This performs a real scan and records the BSSIDs currently observed for that
SSID into `config/trusted_networks.json`. It is a deliberate operator action —
the tool will never trust anything on its own.

Until then, every network is `UNVERIFIED`, which is the honest answer at an
unconfigured site rather than a failure.

### HTTP API

```bash
python -m uvicorn backend.main:app --reload --port 8000
```

| Endpoint | Behaviour |
|---|---|
| `GET /health` | static liveness — never touches the radio |
| `GET /profiles` | which SSIDs this site has vouched for |
| `POST /scan` | **real** `scan_wifi()` → real analysis → JSON |
| `POST /analyze` | analyse caller-supplied observations, no scan |
| `GET /verdicts` | the verdict vocabulary, so a dashboard never hardcodes the wording |
| `GET /flagged` | only the access points needing attention (real scan) |

```bash
curl localhost:8000/health
# {"status":"ok"}

curl -X POST localhost:8000/scan
# every network below was heard by the adapter serving this request
```

`/scan` returns HTTP 503 with the reason when no adapter is available, rather
than an empty or invented result. Each response carries `"source": "live-scan"`
to make that explicit.

---

## Testing

Fixtures under `ai/tests/fixtures/` are **invented on purpose and used only by
the unit tests**. Unit tests need deterministic input — you cannot wait on live
Wi-Fi hardware to assert that an access point scoring 75 classifies as
`HIGH_RISK`. Those files are unreachable from the application: no runtime module
references them, and there is no loader for them outside `ai/tests/`.

```bash
pip install pytest
python -m pytest ai/tests -q
# 251 passed
```

| File | Covers |
|---|---|
| `test_features.py` | vector layout, one-hot encoding, imputation, no NaN/inf |
| `test_rules.py` | every indicator, and the anti-duplicate-SSID guarantee |
| `test_profile.py` | tri-state comparison, MAC normalisation, provisional baseline |
| `test_profile_store.py` | the store ships empty; profiles come only from real scans |
| `test_anomaly.py` | boundedness, determinism, honest unavailability |
| `test_risk_engine.py` | weighting, clamping, bands, ML gating, configurability |
| `test_identity.py` | OUI extraction, per-AP identity, tri-state comparison |
| `test_detection.py` | the ten required detection cases + cross-cutting guarantees |
| `test_pipeline.py` | the seven required scenarios, end to end |

The seven scenarios from the specification:

| # | Scenario | Expected | Result |
|---|---|---|---|
| 1 | Known BSSID, matching everything | `TRUSTED` / `LOW_RISK` | `TRUSTED`, risk 0 |
| 2 | Different known BSSID, same SSID | `TRUSTED` / `LOW_RISK` | `TRUSTED` ×3 |
| 3 | Unknown BSSID only | `UNVERIFIED`, not high risk | `UNVERIFIED`, risk 20 |
| 4 | Unknown BSSID + security mismatch | `SUSPICIOUS` / `HIGH_RISK` | `SUSPICIOUS`, risk 55 |
| 5 | + channel + frequency + band | `HIGH_RISK` | `HIGH_RISK`, risk 75 |
| 6 | No trusted profile | `UNVERIFIED` or cautious | `UNVERIFIED`, risk 0 |
| 7 | Missing optional fields | must not crash | passes on 5 malformed shapes |

---

## Library use

```python
from scanner import scan_wifi
from ai.pipeline import analyze_scan
from ai.profile_store import ProfileStore

scan = scan_wifi()                                  # real observation
report = analyze_scan(scan, profiles=ProfileStore().load())

for result in report["results"]:
    print(result["bssid"], result["risk_score"], result["classification"])
    for reason in result["reasons"]:
        print("   -", reason)
```

`analyze_network(observation, profile)` scores a single access point and is the
whole integration surface for anything that does not need a scan.

---

## Output contract

```json
{
  "ssid": "CE-WIFI",
  "bssid": "BC:07:1D:66:C2:E6",
  "risk_score": 0,
  "classification": "TRUSTED",
  "anomaly_score": 0.5,
  "profile_match": true,
  "reasons": [
    "BSSID belongs to trusted infrastructure and matches its expected profile"
  ],
  "indicators": [],
  "mitigating": ["All profile characteristics that could be checked matched"],
  "score_breakdown": {},
  "profile_comparison": { "known_bssid": true, "deviation_count": 0 },
  "features": {},
  "observed": { "ssid": "CE-WIFI", "bssid": "BC:07:1D:66:C2:E6", "channel": 11 },
  "timestamp": "2026-09-28T19:00:51+00:00"
}
```

`reasons` is **always** non-empty — a score with no justification is not usable
output, and a test asserts it.

**`anomaly_score` is not a probability.** `0.84` does not mean "84% chance of
attack". It means *this observation sits far into the tail of the learned
baseline*. The field is deliberately named `anomaly_score`; a test asserts the
word "probability" never appears in the serialised result.

---

## How the score is built

```
feature extraction → profile comparison → security rules → Isolation Forest
                                                                 ↓
                                            risk score (0-100) → classification
```

### 1. Feature representation (`features.py`)

30 numeric features in a fixed, documented order. Two design rules:

- **Categoricals are one-hot, never integers.** `security` becomes `sec_open`,
  `sec_wpa2`, `sec_wpa3`, … so the model cannot learn a false distance such as
  "WPA2 is one step away from OPEN". The single ordinal (`security_rank`) is a
  hand-assigned encryption-strength table, accompanied by a
  `security_missing` flag.
- **Absence of data is itself a feature.** Missing fields are imputed to a
  fixed constant *and* flagged, so "signal was −45" is distinguishable from
  "signal was never reported".

### 2. Trusted profile comparison (`trusted_profile.py`)

Every field is tri-state: `True` (agrees), `False` (disagrees), `None` (the
profile had no opinion). **An empty expectation is "no opinion", never
"mismatch"** — otherwise a sparse profile would flag every access point at a
new site.

### 3. Rules (`rules.py`)

Rules produce named indicator codes and human sentences. They assign **no** risk
themselves; the weights live in the risk engine, so rules can be re-weighted
without touching that module.

| Indicator | Weight | Rationale |
|---|---:|---|
| `UNKNOWN_BSSID` | 20 | Cheap on purpose. At a new site *every* BSSID is unknown. |
| `SECURITY_MISMATCH` | 25 | The strongest single signal. |
| `SECURITY_DOWNGRADE` | 5 | A **qualifier** on the mismatch, not a second full weight. |
| `CHANNEL_MISMATCH` | 10 | Primary observation of a wrong radio plan. |
| `FREQUENCY_MISMATCH` | 5 | Same fact as the channel, counted once. |
| `BAND_MISMATCH` | 5 | Same fact again, counted once. |
| `VENDOR_MISMATCH` | 10 | Only when both sides actually know the vendor. |
| `PROFILE_DEVIATION` | 5 | Fires only at **≥2 independent** deviations. |
| `ML_ANOMALY` | 20 / 8 | Strong / weak, subject to the gates below. |
| `NO_TRUSTED_PROFILE`, `MISSING_FIELDS`, `HIDDEN_SSID` | 0 | Context, not risk. |

The last rows matter: `SECURITY_MISMATCH` + `SECURITY_DOWNGRADE` and
`CHANNEL` + `FREQUENCY` + `BAND` each describe *one* observation. Counting them
at full weight made a known rogue clamp to 100, which tells a reviewer nothing.

### 4. Anomaly detection (`anomaly.py`)

`sklearn.ensemble.IsolationForest`, `random_state=42`, baseline synthesised from
the trusted profile across a realistic signal range. The raw decision function
is rescaled against the baseline's own observed decision range:

```
score = clamp((max_decision - decision) / (2 · span), 0, 1)
```

so `0` = the most normal baseline observation, `0.5` = the least normal one,
`1` = further out than any of them. The transform is strictly monotone, so the
model's ordering is preserved.

### 5. Two-layer classification

There are **two** classifications, and they answer different questions. The
risk band is the tested arithmetic; the verdict is what a human acts on.

**Layer 1 — risk band** (`classification`, unchanged, still 0-100 weighted):

| Score | Band |
|---|---|
| 0–24 | `TRUSTED` — only if a real profile vouches for the BSSID |
| 0–24 | `UNVERIFIED` — consistent, but nothing verifies it |
| 25–49 | `LOW_RISK` |
| 50–74 | `SUSPICIOUS` |
| 75–100 | `HIGH_RISK` |

**Layer 2 — verdict** (`verdict`, semantic, in `ai/verdict.py`):

| Verdict | Meaning |
|---|---|
| `TRUSTED` | The profile lists this exact BSSID and every checked attribute matches |
| `LEGITIMATE` | Consistent with the expected network on every checked attribute, but the BSSID is not on the trusted list — most likely an AP added since the profile was written |
| `UNVERIFIED` | Insufficient information: no profile, or only a self-learned one. **Not an accusation.** |
| `SUSPICIOUS` | Real deviation(s) from the expected fingerprint, not yet corroborated |
| `POTENTIAL_FAKE` | Independent parts of the fingerprint contradict the profile **at once** |

`POTENTIAL_FAKE` means *strong evidence of an impersonation pattern*, never
proven malice. Every non-`TRUSTED` result carries `accuracy_note`, and a test
asserts the system never emits definite-accusation language.

#### The corroboration rule

This is the part that makes the system defensible. Every indicator is assigned
to an **independent signal family**:

| Family | Covers | Examples |
|---|---|---|
| `IDENTITY` | Is this BSSID hardware we know? | `UNKNOWN_BSSID`, `OUI_MISMATCH` |
| `SECURITY` | Is it encrypted like the real network? | `SECURITY_MISMATCH`, `SECURITY_DOWNGRADE` |
| `RADIO_PLAN` | Is it positioned like the real network? | `CHANNEL_MISMATCH`, `BAND_MISMATCH` |
| `VENDOR` | Vendor string, when both sides know one | `VENDOR_MISMATCH` |
| `BEHAVIOR` | Aggregate fingerprint drift | `PROFILE_DEVIATION` |
| `ML` | Statistical deviation from the site baseline | `ML_ANOMALY` |
| `CONTEXT` | Missing data, no profile — explains, never accuses | `MISSING_FIELDS` |

A `POTENTIAL_FAKE` verdict requires **all three** of:

1. a risk score ≥ 75, **and**
2. deviations in ≥ 2 **independent** fingerprint families, **and**
3. no authoritative profile match.

So no single weak signal can produce it — not an unknown BSSID, not a channel
change, and not the ML score. An impersonator has to get its hardware
identity, its encryption and its radio plan wrong simultaneously; the family
count measures exactly that.

A second, subtler rule: **`IDENTITY` alone never escalates a verdict.** "Is
this BSSID on our list?" is a *verification* question, and its honest answer is
`LEGITIMATE` — organisations add access points constantly, which is not
impersonation. Only once something *behavioural* contradicts the profile does
the identity gap become evidence.

`MIN_FAMILIES_FOR_FAKE = 2` in `ai/verdict.py`. Changing it is a one-line,
explicit decision.

#### Evidence level

`evidence_level` grades the *strength* of the evidence, not just the score:

- `HIGH` — corroborated across families at high risk, or an authoritative match
- `MEDIUM` — a real profile exists and something partially fits
- `LOW` — no reference at all, or only one weak family

A high score from one family is deliberately *not* `HIGH` evidence.

### 6. Network identity and OUI

`SSID` is an advertised claim. The per-device identity is the BSSID, and the
only hardware signal available when the scanner reports no vendor (nmcli does
not) is the **OUI** — the IEEE-assigned vendor block in the first three octets.

Expected OUIs are derived **automatically** from the profile's own BSSIDs, so
operators never maintain them by hand. A new AP from a known vendor is
recognised; a random device is not. The OUI signal is deliberately weak (5
points) and never load-bearing, because a cloned BSSID can carry any prefix an
attacker likes.

---

## Design decisions that were measured, not assumed

### 1. Missing data is not disagreement

A scanner that failed to report the `security` field originally produced
"observed UNKNOWN, expected WPA2" — a security mismatch. Every access point on a
WPA2 network would have been penalised for a reporting gap. Unknown information
now yields *no opinion* (`None`), and a test guards it.

### 2. The provisional baseline used to absorb rogues

At an unconfigured site the engine can learn a provisional profile from what it
sees. The first implementation kept the top-3 most common security labels — so
`3 × WPA2 + 1 × OPEN` became "expected: WPA2 **or** OPEN", and the rogue was
absorbed into the baseline on the very first scan.

Security is now subject to a **support threshold** (60% of observations,
minimum 2 votes); the channel plan deliberately is not, because a legitimate
network spans many channels each seen once. The rogue now scores 30 while its
peers score 0. Residual limitation: a rogue that is the *majority* of the
access points on an SSID will still teach the baseline its own fingerprint.

### 3. Isolation Forest does not separate rogue from weak-signal legitimate APs

This is the most important honest caveat, and it was worth the experiment.

Isolation Forest scores a point by how quickly random axis-aligned splits
isolate it. A point **outside the training support** and a point in the **tail
of a single feature** are both isolated in O(1) splits, so their decisions
saturate into the same narrow band. Measured over 704 verified in-profile
access points spanning −30…−96 dBm:

| | anomaly score range |
|---|---|
| 704 verified in-profile APs | 0.000 – 0.556 |
| 192 unknown-BSSID APs | 0.075 – 0.358 |
| rogue APs (out-of-band OPEN, etc.) | 0.187 – 0.338 |

**The rogue scores sit entirely inside the legitimate range.** This survived
every configuration tried: `max_samples`, `contamination`, baselines from 32 to
1000 rows, injected jitter, dropping constant columns, excluding `signal`, and
four different score calibrations. It is a structural property of the algorithm
on this problem, not a tuning failure.

Consequences, all deliberate:

1. The **rules carry the classification**; the forest is a second, independent
   opinion.
2. A **profile match vetoes the anomaly score**
   (`risk_engine._anomaly_allowed`). Authoritative profile evidence outranks a
   model whose tail ranking is known to be coarse, and this removes the only
   realistic false-positive path — a genuine AP with a faint signal. All 704
   verified APs score 0 and classify `TRUSTED`.
3. The anomaly thresholds stay conservative (0.70 strong / 0.55 weak) because
   **no threshold exists that fires for the rogues without firing for the
   legitimate ones.** Lowering them until the demo looked good would have
   manufactured a signal that is not in the data.

The fix, for whoever picks this up next: the baseline needs to be *real observed
data from the site*, not a synthesis from the profile. A model calibrated on
several weeks of genuine observations has real variation to measure against,
and this analysis should be repeated on it.

---

## New locations

Arriving somewhere the engine has never seen means every BSSID is unknown. It
says so plainly and **downgrades its own confidence, not the network's
reputation**:

```json
{
  "classification": "UNVERIFIED",
  "reasons": [
    "This network has no established trusted profile; its infrastructure is unknown to the engine",
    "Classified UNVERIFIED: unknown infrastructure is not treated as malicious, but this AP cannot be confirmed as legitimate either"
  ]
}
```

The engine separates three states:

| State | Result |
|---|---|
| Known and consistent | `TRUSTED`, risk 0 |
| Unknown but consistent | `UNVERIFIED` / `LOW_RISK`, risk ≈ 0 |
| Unknown **and** anomalous | `SUSPICIOUS` / `HIGH_RISK` |

A **provisional** profile can never produce `TRUSTED`: it was built from the
observations it is now judging. It is capped at `LOW_RISK`.

---

## Detection scenarios

All figures below are produced by the engine, not written by hand. Run them
with `python -m pytest ai/tests/test_detection.py -v`.

| Observation (SSID `Office_Net`, profile trusts 3 BSSIDs) | Verdict | Risk | Evidence |
|---|---|---:|---|
| Known BSSID, expected channel + `WPA2` | `TRUSTED` | 0 | HIGH |
| 3 APs, one SSID, channels 1/11/149 | `TRUSTED` ×3 | 0 | HIGH |
| No profile at all | `UNVERIFIED` | 0 | LOW |
| Unknown BSSID, everything else exact | `LEGITIMATE` | 25 | MEDIUM |
| Unknown BSSID, same vendor OUI | `LEGITIMATE` | 20 | MEDIUM |
| Unknown BSSID + `OPEN` downgrade | `SUSPICIOUS` | 60 | MEDIUM |
| Unknown BSSID + `OPEN` + foreign OUI + wrong channel | `POTENTIAL_FAKE` | 75 | HIGH |

Note row 4 vs 5: an unrecognised BSSID that belongs to a **known vendor block**
scores lower than a random one. That is the OUI signal earning its keep without
ever being load-bearing.

Note also that `POTENTIAL_FAKE` needs a network with real encryption. On an
open network like `CE-WIFI`, an unknown BSSID on an odd channel reaches only
`SUSPICIOUS` (45) — there is no security downgrade to corroborate it, and the
engine will not invent one. That restraint is intentional.

---

## Limitations

1. **Passive metadata cannot prove an AP is malicious.** It can show that an AP
   deviates from what we expect. That is a triage signal, not a verdict.
2. **Unknown BSSID does not mean malicious.** It means *not yet verified*. At a
   new site every BSSID is unknown; treating that as an attack would mark
   every building as hostile.
3. **Duplicate SSIDs are normal.** Nothing in this engine treats repetition as
   evidence. One network legitimately spans many BSSIDs.
4. **An unconfigured site can only say "consistent" or "anomalous among its
   peers".** Nothing is `TRUSTED` until an operator approves it.
5. **A capable attacker can imitate the profile.** A rogue that copies the
   SSID, channel, *and* encryption leaves few radio-visible traces. This engine
   detects inconsistency, not deception. Distinguishing the two requires
   association-level or 802.11 authentication analysis, outside a passive
   scanner's reach.
6. **The ML component is currently the weakest link.** As measured above,
   Isolation Forest on a synthetic baseline does not separate rogues from
   weak-signal legitimate APs. The rules carry the decision; the anomaly score
   is reported but gated so it cannot do harm. Real site data is the fix.
7. **The risk score is a heuristic, not a probability of compromise.** Weights
   were chosen against the test suite, not fitted to labelled attack data,
   which we do not have.
8. **The provisional baseline is in-memory only.** It resets when the process
   restarts, which is the safe failure direction (a fresh start reverts to
   `UNVERIFIED` rather than to blind trust).
9. **Vendor data is optional and unreliable**, so it is excluded from recorded
   profiles by default and carries a small weight even when present.

---

## Layout

```
.
├── run_scan.py              production CLI entry point
├── requirements.txt         full application dependencies
├── config/
│   └── trusted_networks.json  operator-approved profiles (ships empty)
├── backend/
│   └── main.py              HTTP API; /scan performs a real scan
├── scanner/                 Person 1 - real Wi-Fi observation (nmcli)
├── ai/                      this component
│   ├── models.py            input/output dataclasses, validation, normalisation
│   ├── features.py          30-feature vector, one-hot encoding, imputation
│   ├── trusted_profile.py   profile comparison + provisional baseline
│   ├── identity.py          BSSID / OUI extraction, per-AP identity
│   ├── verdict.py           semantic verdict + cross-family corroboration
│   ├── profile_store.py     on-disk trusted-profile store (read/write)
│   ├── rules.py             explainable indicators (assign no risk themselves)
│   ├── anomaly.py           Isolation Forest wrapper + score calibration
│   ├── risk_engine.py       weights, clamping, thresholds, ML gating
│   ├── pipeline.py          analyze_network / analyze_networks / analyze_scan
│   ├── integration_example.py  runnable reference for the API layer
│   ├── tests/               251 tests
│   │   ├── fixtures/        invented data — TEST-ONLY, never loaded at runtime
│   │   └── fixtures_scenarios.py  test network profiles — TEST-ONLY
│   ├── requirements.txt     engine-only dependencies
│   └── README.md
```

**Security boundary.** This project performs passive observation and analysis
of wireless metadata only. It contains no active probing, packet injection,
deauthentication, interception, credential handling, handshake capture, or
access-point creation. The scanner it consumes is itself passive.
