# WiFiSentinel AI — Wi-Fi Scanner (Person 1)

Passive Wi-Fi access point scanner for Linux, built on NetworkManager's
`nmcli`. It produces a **stable, documented JSON schema** for the AI and
backend components to consume.

**Scope:** this component only observes and reports. It makes no judgement
about whether an AP is malicious — that decision belongs to the AI/risk
engine. An unknown BSSID is **not** evidence of anything; a legitimate AP in
a new location has never been seen before, and that is normal.

---

## 1. Requirements

| Requirement | Version tested | Notes |
|---|---|---|
| Linux | Arch Linux | any distro with NetworkManager works |
| Python | 3.14.6 (3.9+ supported) | standard library only |
| NetworkManager | 1.56.1 | provides `nmcli` |
| `iw` | not required | see [Limitations](#8-known-limitations) |

**No third-party Python packages are needed.** `requirements.txt` is
intentionally dependency-free.

### Install / verify

```bash
# Arch
sudo pacman -S networkmanager

# Debian/Ubuntu
sudo apt install networkmanager

# Verify
nmcli --version
nmcli device status
nmcli device wifi list
```

Scanning normally works as a **regular user** (polkit). If your setup denies
it, add yourself to the `network` group or run with elevated rights.

---

## 2. Quick start

```bash
cd scanner
python scanner.py
```

Sample real output:

```text
Scan timestamp : 2026-09-28T16:44:57+00:00
Interface      : wlo1
Networks found : 14
------------------------------------------------------------------------------
SSID                     BSSID                SIG    CH   FREQ SECURITY
KFON@engineeringcollege  90:A2:10:06:17:B8    -50    10   2457 WPA1/WPA2
Galaxy A23 D073          5A:75:D6:E9:7A:7D    -52     6   2437 WPA2
CE-WIFI                  BC:07:1D:66:C2:E6    -56    11   2462 OPEN
CE-WIFI                  BC:07:1D:66:C2:E7    -62   149   5745 OPEN
<hidden>                 AE:2E:A8:D9:D4:34    -72     6   2437 WPA2/WPA3
...
```

### CLI options

```bash
python scanner.py                    # human-readable summary
python scanner.py --json             # JSON only (includes optional fields)
python scanner.py --json --minimal   # JSON with only the agreed core fields
python scanner.py -i wlo1            # force a specific interface
python scanner.py -s 20              # ceiling for the scan (default 20s)
python scanner.py --count 5          # 5 consecutive scans (repeatability check)
python scanner.py --save scans/      # also write the JSON to disk
python -m scanner --json             # equivalent package invocation
```

### Tuning knobs

| Env var | Default | Meaning |
|---|---|---|
| `WIFISENTINEL_SETTLE` | `20.0` | Hard ceiling on how long to wait for a scan. |
| `WIFISENTINEL_MIN_WAIT` | `7.0` | Time floor before the cache is trusted. Lowering this returns stale or half-populated data — see limitations. |
| `WIFISENTINEL_POLL` | `0.4` | Poll interval while waiting. |
| `WIFISENTINEL_TIMEOUT` | `30` | Per-command nmcli timeout. |
| `WIFISENTINEL_NMCLI` | `nmcli` | Path to the nmcli binary. |

---

## 3. Output format (the agreed schema)

`--minimal` produces exactly the agreed contract:

```json
{
  "timestamp": "2026-09-28T16:45:12+00:00",
  "networks": [
    {
      "ssid": "CE-WIFI",
      "bssid": "AA:BB:CC:11:22:33",
      "signal": -45,
      "channel": 36,
      "frequency": 5180,
      "security": "WPA2",
      "timestamp": "2026-09-28T16:45:12+00:00"
    }
  ]
}
```

Default output adds these **additive** fields plus top-level metadata:

```json
{
  "timestamp": "...",
  "networks": [ ... ],
  "interface": "wlo1",
  "schema_version": "1.0",
  "network_count": 14
}
```

### Per-network fields

| Field | Type | Always present | Meaning |
|---|---|---|---|
| `ssid` | `string` | yes | Network name. `""` when hidden. |
| `bssid` | `string` | yes | AP MAC address, uppercase. Unique per record. |
| `signal` | `int` or `null` | yes | Signal in **dBm** (negative). See note below. |
| `channel` | `int` or `null` | yes | Wi-Fi channel number. |
| `frequency` | `int` or `null` | yes | Centre frequency in MHz. |
| `security` | `string` | yes | `OPEN`, `WPA2`, `WPA1/WPA2`, `WPA2/WPA3`, `WEP`, … |
| `timestamp` | `string` | yes | ISO-8601 UTC, when the record was captured. |
| `signal_quality` | `int` or `null` | no | Raw `nmcli` value, 0–100. |
| `ssid_hex` | `string` or `null` | no | SSID as hex; `null` when hidden. |
| `hidden` | `bool` | no | `true` when no SSID is advertised. |
| `bandwidth_mhz` | `int` or `null` | no | 20 / 40 / 80. `null` if unknown. |
| `mode` | `string` or `null` | no | e.g. `Infra`. |

`null` always means *"not reported by the radio"*. The scanner never invents
a value to fill a gap.

### Three contract rules the AI/backend team can rely on

1. **One record per BSSID, never per SSID.** Three APs broadcasting
   `CE-WIFI` produce three records with three different BSSIDs. They are
   never merged.
2. **`signal` is dBm and always ≤ 0** when present. `null` if unreported.
3. **`security` is never an empty string.** An AP with no advertised
   security is reported as `"OPEN"`.

> **Important signal note.** `nmcli`'s `SIGNAL` field is a **0–100 quality
> percentage, not dBm** — despite the column header. NetworkManager derives
> it from RSSI as `percent = clamp((rssi + 100) * 2, 0, 100)`, so the
> scanner inverts this and publishes `signal` in dBm to match the agreed
> schema. The unmodified `0–100` value remains available as
> `signal_quality`. Ordering and comparisons in dBm are correct; the value
> is an **estimate**, since exact RSSI needs `iw`. See limitations.

---

## 4. Project layout

```text
scanner/
├── scanner.py               # orchestration, error handling, CLI
├── parser.py                # nmcli output -> WiFiNetwork
├── models.py                # WiFiNetwork / ScanResult dataclasses
├── config.py                # timeouts, field list, signal conversion
├── requirements.txt         # no runtime dependencies
├── integration_example.py   # how Person 3 consumes this
├── README.md
└── tests/
    ├── test_parser.py       # 66 offline tests (fixtures, no hardware needed)
    ├── test_live.py         # 11 live tests against real hardware
    └── fixtures/
        ├── real_scan.txt    # captured verbatim from nmcli 1.56.1
        ├── edge_cases.txt   # colons, backslashes, unicode, tabs, hidden, 0 MHz
        └── malformed.txt    # bad BSSIDs, short rows, out-of-range values
```

---

## 5. How it works

```text
nmcli device wifi rescan   →  trigger (asynchronous, returns immediately)
   ↓ poll
nmcli --terse -f … list    →  machine-readable rows
   ↓ parser.split_unescaped
parser                     →  WiFiNetwork objects (deduped by BSSID)
   ↓
ScanResult.to_dict()       →  the agreed JSON schema
```

### The three things that are easy to get wrong

**1. Never split terse output on `:`.** `nmcli --terse` escapes the
separator, so a BSSID arrives as `90\:A2\:10\:06\:17\:B8`. A naive
`line.split(":")` turns one 9-field record into 14 junk fields. The parser
walks each line and splits only on *unescaped* colons, then unescapes
(`parser.split_unescaped`).

**2. `rescan` is asynchronous, and the stale cache looks "stable".**
Measured on nmcli 1.56: the cache keeps showing the **previous** scan's
results unchanged for ~5.5 s before new results land. A "wait until the
output stops changing" loop therefore returns the *stale* cache in under a
second. The scanner instead imposes a hard time floor (default 7 s) before
trusting the cache, then waits for it to stop changing.

**3. Rescanning too fast yields a *partial* cache.** Issuing `rescan` while a
scan is still running always reports success, but leaves the cache half
populated (measured: 7 of 14 APs) and sometimes empty. The scanner falls
back to the pre-rescan cache if a scan yields nothing, so a false "0 access
points" is never reported.

### Robustness handled

| Case | Behaviour |
|---|---|
| SSID with spaces / colons / backslashes / unicode / tabs | preserved exactly |
| Hidden SSID | `ssid: ""`, `hidden: true`, rest of record valid |
| Missing security | `"OPEN"` |
| Missing signal / channel / bandwidth | `null` |
| Malformed BSSID | row dropped (no usable identity) |
| Duplicate BSSID | merged, keeping the strongest signal and best metadata |
| Same SSID, different BSSID | **kept separate** |
| Short / long rows | padded or truncated, never fatal |
| Empty scan | valid result with `"networks": []`, not an error |
| No adapter / Wi-Fi off / NM down | typed exception with a remediation hint |

---

## 6. Errors

All failures raise a subclass of `ScannerError`, each with a `hint`:

```python
from scanner import scan_wifi, ScannerError, NoWifiAdapterError, WifiDisabledError

try:
    result = scan_wifi()
except NoWifiAdapterError as exc:
    print(exc.hint)   # "Plug in a USB Wi-Fi adapter..."
except ScannerError as exc:
    print(exc)        # never a raw traceback
```

| Exception | Cause |
|---|---|
| `NoWifiAdapterError` | no scan-capable Wi-Fi radio |
| `WifiDisabledError` | radio is off / rfkill blocked |
| `NetworkManagerUnavailableError` | `nmcli` missing or D-Bus unreachable |
| `PermissionDeniedError` | polkit denied the scan |
| `InterfaceNotFoundError` | requested interface does not exist |
| `ScanFailedError` | nmcli failed or timed out |

CLI behaviour: message plus hint on stderr, exit code `1`, no traceback.

---

## 7. Testing

```bash
# Offline: no hardware required, 66 tests
python scanner/tests/test_parser.py

# Live: 11 tests against a real adapter
python scanner/tests/test_live.py

# Both via pytest, if installed
python -m pytest scanner/tests/ -v
```

### Coverage of the five required cases

| # | Test | Where | Result |
|---|---|---|---|
| 1 | Normal Wi-Fi detected | `test1_normal_wifi_detected` | pass |
| 2 | Same SSID, 3 BSSIDs → 3 records | `test2_same_ssid_multiple_bssids_not_merged`, `test2_controlled_three_bssids_one_ssid` | pass |
| 3 | Open AP → `OPEN` | `test3_open_ap_security` | pass |
| 4 | Hidden SSID, no crash | `test4_hidden_ssids_do_not_crash` | pass |
| 5 | Repeated scans consistent | `test5_repeated_scans_structurally_consistent`, `test5_repeated_scans_consistent_shape` | pass |

Tests 1–4 run against fixtures captured verbatim from real hardware, plus
synthetic rows for cases that are hard to reproduce on demand (colons in
SSIDs, `0 MHz` bandwidth, out-of-range values).

---

## 8. Known limitations

1. **`signal` is an estimate.** nmcli gives 0–100 quality, not RSSI. The
   scanner inverts NetworkManager's own mapping to get dBm. It is correct for
   ordering and comparison, but is not a true RSSI reading. `signal_quality`
   keeps the raw value. If exact RSSI is needed, install `iw` and read
   `signal` from `iw dev <iface> link`.
2. **No vendor/OUI field.** Deriving a vendor from the BSSID needs a local
   OUI database. It was deliberately left out rather than shipping a stale
   lookup table — the spec says not to sacrifice reliability for optional
   fields. A small `oui.csv` lookup is a clean follow-up if Person 2 wants it.
3. **No Wi-Fi standard / PHY field** (`iw phy`). Requires `iw`, which is not
   installed by default. Same reasoning as above.
4. **No 6 GHz / Wi-Fi 6E channel plan.** Channels ≥ 32 map to
   `5000 + 5 × channel`, which is correct for 6 GHz too, but the 2.4 GHz
   range is limited to channels 1–14.
5. **A scan takes ~7 s.** NetworkManager scans asynchronously and some
   drivers refuse repeated scans, so a scan cannot be made instant. `--settle`
   tunes the ceiling. If you need a faster cadence, raise the driver's scan
   rate rather than lowering `--min-wait` (below), and accept partial data.
6. **Very rapid rescans degrade completeness.** Issuing rescans faster than
   the driver's ~11 s cycle makes NetworkManager leave the cache briefly
   empty or half-populated. The scanner defends against this two ways: a hard
   time floor (`--min-wait`, default 7 s) before the cache is trusted, and a
   fallback to the pre-rescan cache if a scan returns nothing. Even so,
   space scans out by ~10 s for best results.
7. **Hidden SSIDs cannot be named.** A beacon that omits the SSID carries no
   name; the scanner reports `""` and `hidden: true`. That is a limit of the
   protocol, not the scanner.
8. **Requires NetworkManager.** With `wpa_supplicant` alone there is no
   equivalent machine-readable listing. A future `iw`-based backend could
   cover that case.

---

## 9. How the backend consumes this

Full runnable version: `scanner/integration_example.py`.

```python
from scanner import scan_wifi

result = scan_wifi()

for network in result.networks:
    print(network.ssid, network.bssid, network.signal, network.security)
```

Or as a ready-to-use payload:

```python
payload = scan_wifi().to_dict()      # exactly the agreed schema
```

### FastAPI endpoint

```python
from fastapi import FastAPI, HTTPException
from scanner import scan_wifi, ScannerError

app = FastAPI()

@app.get("/scan")
def scan():
    try:
        return scan_wifi().to_dict()
    except ScannerError as exc:
        # No adapter / Wi-Fi off / NetworkManager down -> a clear 503,
        # never a 500 with a stack trace.
        raise HTTPException(status_code=503, detail=str(exc)) from exc
```

```bash
curl http://localhost:8000/scan
```

### Handoff notes for Person 2 (AI) and Person 3 (backend)

- Consume `networks`: a list of **per-BSSID** records.
- Do **not** treat an unknown BSSID as suspicious on its own. A legitimate AP
  in a new location is unknown by definition. `security == "OPEN"`,
  `hidden == true`, or a locally-administered BSSID are *features for the
  risk engine*, not verdicts.
- `ssid == ""` means hidden; check the `hidden` flag rather than testing for
  an empty string.
- Every `signal` is ≤ 0 dBm. Sort ascending to get strongest first.
- The schema is versioned via `schema_version` (`"1.0"`). Additive optional
  fields may appear; the six core fields will not change meaning.

---

## 10. Security scope

This component performs **passive observation only**: the same scan a phone
does automatically to show available networks. It does not associate with
networks, send authentication or deauthentication frames, capture traffic,
read keys, or touch any neighbouring device beyond beacon collection.

There is no attack, interception, credential-handling, or traffic-analysis
code in this package, and none should be added to it.
