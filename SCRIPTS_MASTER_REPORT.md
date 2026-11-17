# BLE LAB — MASTER SCRIPTS REPORT

Full technical analysis of every script in `scripts/`, the attack strategies they
implement, the tools they depend on, and the reliability plan.

```
ble-lab/
├── scripts/          21 Python scripts + check.sh + ble_scripts_report.txt (legacy digest)
├── tools/            Sniffle, sweyntooth_..., BlueToolkit-upstream, SbleedyGonzales, whadbro, ZEPHYR
├── venv/             Python env (whad, scapy, bleak, pyserial) — all scripts run from here
└── SCRIPTS_MASTER_REPORT.md   (this file)
```

Run any script with: `~/ble-lab/venv/bin/python scripts/<name>.py --help`

---

## 1. ECOSYSTEM

| Item | What it is |
|---|---|
| **WHAD ButteRFly** | nRF52840 USB dongle (VID:PID `c0ff:eeee`, bootloader `1915:521f`), appears as `/dev/ttyACM*`, addressed as `uart0`/`uart1` in WHAD. Runs custom firmware that can scan, trigger, and transmit Link Layer PDUs. |
| **Sniffle** (`tools/Sniffle/`) | TI CC1352 BLE sniffer — firmware in `fw/`, host CLI + Wireshark extcap in `python_cli/`. Independent capture path to verify our packets on-air. |
| **sweyntooth_...** (`tools/`) | Upstream SweynTooth PoC suite (ASSET Research) — 18 BLE SoC CVEs (CC2540 length overflow, LLID deadlock, ATT deadlock, etc.). Source of the length-field crash methodology used by `sweyntooth_crash.py` / `oooooooooooo.py`. |
| **BlueToolkit-upstream** (`tools/`) | Upstream BlueToolkit — automated BLE exploit-testing framework (bluekit engine, exploits/, evaluation/). |
| **SbleedyGonzales** (`tools/`) | CLI runner for multiple BLE/BR-EDR exploits concurrently, with JSON reports and hardware flashing helpers. |
| **whadbro** (`tools/`) | The prototype/ancestor working directory of this lab's own framework (`sooooooooo.py` 773-line draft of `own_packet_full.py`, `dos.py`). |
| **ZEPHYR** (`tools/`) | Alternative USB-HCI firmware image (zephyr.bin + mcuboot bundle) for the nRF52840 dongle, so it can act as a standard HCI adapter instead of WHAD serial protocol. |
| **check.sh** | "BLE LAB DOCTOR" — 12 environment checks, exit code = number of failures. |

### Two hardware tiers (scripts never mix them)

| Tier | Hardware | Library | Scripts | Default target |
|---|---|---|---|---|
| **A — Link Layer** | ButteRFly / WHAD | `whad` + `scapy` | 1, 2, 4–8, 10–15, oooooooooooo, own_packet_full, sweyntooth_crash | `C0:00:00:41:73:AC` (random static, "MDT2410161") |
| **B — Host stack** | plain BT adapter (BlueZ) | `bleak` | ble_busy, pairing_req_multiple, ble_connection_time_checker, getting-all-details, read_descriptors, thor | `00:1F:FF:C1:63:9F`, `80:E1:27:4D:A8:3F` |

---

## 2. SHARED ATTACK DNA ("our packet")

The same 36-byte CONNECT_IND template is embedded in scripts 1, 4–8, 10–15,
`oooooooooooo.py`, `own_packet_full.py`, `sweyntooth_crash.py`:

```
8522 AABBCCDDEEFF AC73410000C0 A1B2C3D4 123456 02 0000 1800 0000 C800 FFFFFFFF1F 2D
│  │  └─ InitA    └─ AdvA      └─ AA     └CRCInit WinSz WinOf Intv Lat T/o ChM  Hop/SCA
│  └─ Length=0x22 (34)
└─ HDR: CONNECT_IND(0x05) | TxAdd=0 (InitA FF:EE:DD:CC:BB:AA public) | RxAdd=1 (AdvA random)
```

- Access Address `0xD4C3B2A1`, CRCInit `0x563412`
- WinSize 2 (2.5 ms), Interval 24 (30 ms), Latency 0, Timeout 200 (**2000 ms**)
- Channel map `FFFFFFFF1F` (37 channels), Hop 13, SCA 1
- AdvA `C0:00:00:41:73:AC` in wire order = `AC 73 41 00 00 C0` (LSB octet first)
- Wrapped on-air as `BTLE("D6BE898E" + RAW)` (advertising access address)

### The central technical narrative (what the numbered pipeline proved)

1. **Scripts 4–8:** reactive *literal* CONNECT_IND injection via `ReceptionTrigger`
   on stock ButteRFly firmware — needs exact AdvA pattern byte offset (calibrated
   by `8_trigger_sweep.py`, offsets 0–30).
2. **Script 10:** root cause — `prepare()` only accepts literal PDUs when wrapped
   as `BTLE(advAA)/BTLE_DATA(raw)`; even then reactive literal TX is unreliable
   on stock firmware.
3. **Pivot:** use WHAD's `Central.connect()` with custom LLData (AA, CRCInit,
   interval, hop) — the firmware builds a *correct* CONNECT_IND from parameters
   instead of transmitting our bytes.
4. **Scripts 12–13:** A/B diagnosis — the peripheral kills links that never
   answer `ATT_EXCHANGE_MTU_REQ` within ~200 ms (`LL_TERMINATE_IND 0x13`);
   idle links with custom params survive.
5. **Scripts 14–15:** the fix — intercept MTU_REQ on `on_data_pdu`, reply with
   a raw ATT MTU Response (247) within milliseconds; then drive ATT discovery
   manually over raw L2CAP data PDUs.
6. **`own_packet_full.py`:** all of the above productized into one 8-step
   rogue-central framework with a 3 ms MTU-response pump.

---

## 3. PER-SCRIPT DEEP DIVES

### Tier A — WHAD / Link Layer

#### `1_build_packet.py` — offline packet builder (73 lines, no hardware)
- **Does:** builds the 36-byte CONNECT_IND byte-exactly: 13 LLData "knobs" →
  payload → header (Length auto) → BLE CRC-24 → pretty field table → spec checks
  (AA legality per Core Spec Vol 6 B 2.3, hop 5–16, timeout > 2(1+latency)×interval,
  WinOffset ≤ Interval, AdvA top-bits decode).
- **Key functions:** `ble_crc24(d, init=0x555555)` LSB-first poly `0x100065B`;
  `mac()` LSB-first wire order; `aa_bad()` Access Address legality.
- **CLI:** `[mac]` (target AdvA), `--inita`.
- **Reliability:** solid, pure stdlib. Note: on-air CRC seed in the packet is
  `0x563412`, while the helper's default init `0x555555` is only a function default.

#### `2_send_packet.py` — first live custom-param connect (46 lines)
- **Does:** `central.connect(TARGET, random, access_address, crc_init,
  channel_map, hop_interval, hop_increment)` then `conn.discover()` to prove the
  rogue-parameter link carries GATT.
- **Key detail:** `ChannelMap.from_int(0x1FFFFFFFFF)` must be an object, not an int.
- **CLI:** `[mac]`, `--public`, `--port`.
- **Reliability:** exit 1 on `PeripheralNotFound`; defensive `conn.services`
  callable-or-property shim (WHAD API drift).

#### `4_inject_raw.py` — first reactive injection attempt (57 lines)
- **Does:** introspects `ReceptionTrigger` source, then tries 4 trigger-construction
  strategies (packet=ADV_IND, AdvA@off2, @off0, bare pattern) until one arms;
  watches 120 s telling the operator to watch "MDT2410161" vanish on the phone.
- **CLI:** `[mac]`, `--window`, `--port`.
- **Reliability:** survives WHAD API drift via the 4-strategy ladder; Ctrl+C-safe watch loop.

#### `5_scan_then_inject.py` — scan → confirm → arm → watch (135 lines)
- **Flow:** Phase 1 scan via `ScanningEmulator` (handles dict *and* list device
  API shapes) ≤30 s, exit 1 if absent → release dongle → Phase 2 reopen as
  `Injector` with 5 retries, arm 4 triggers (AdvA@off2/0/6, auto ADV_IND),
  monkey-patch `trig.trigger` + `inj.on_triggered` with FIRED hooks → Phase 3 90 s
  watch distinguishing "sent" vs "never fired (phone grabbed it)".
- **CLI:** `[mac]`, `--scan-time`, `--window`, `--port`.

#### `6_scan_inject_final.py` — single-instance continuous RX (115 lines)
- **Does:** opens the Injector once (no close/reopen race), hooks `on_adv_pdu`
  to count target ADVs by raw AdvA byte match, enters RX via a 4-way API
  fallback (`enable_scan_mode` ×2, `sniff_advertisements` ×2), arms triggers
  while scan stays on, watches 90 s, 3-way verdict.
- **CLI:** `[mac]`, `--scan-time`, `--window`, `--port`.

#### `7_connect_lifecycle.py` — acceptance oracle (143 lines)
- **Does:** everything in 6, plus measures the target's ADV interval, then after
  FIRE watches for the ADV stream to **stop** (device accepted the CONNECT_IND)
  and **resume** (supervision timeout elapsed) — validating that the peripheral
  obeyed the packet's 2.000 s `LLConnectionTimeout` field (±0.8 s tolerance).
- **Output:** timestamped event log + timeline replay + 4-way verdict.
- **CLI:** `[mac]`, `--scan-time`, `--window`, `--port`.

#### `8_trigger_sweep.py` — hardware calibration (162 lines)
- **Phases:** ① confirm advertising (25 s) → ② sanity: mask-0 pattern must match
  *any* packet (retry in sniff mode; exit 3 if machinery never fires) → ③ sweep
  AdvA pattern byte offsets (default 0–30, 3.5 s each, dongle reopened per
  offset) → ④ acceptance watch on the best offset with gap detection.
- **CLI:** `[mac]`, `--scan-time`, `--offsets 0-30`, `--port`.

#### `10_prepare_rootcause.py` — prepare() root cause (76 lines)
- **Does:** THE TRICK — wrap our 36 bytes as `BTLE("D6BE898E")/BTLE_DATA(RAW)` so
  `prepare()` accepts them (byte-exact round-trip asserted, exit 1 on mismatch).
  TEST 1: `ManualTrigger` immediate literal TX ×4 (plumbing proof).
  TEST 2: `ReceptionTrigger(AdvA@off0)` + 25 s silence-gap oracle using
  `statistics.median` of ADV intervals to compute threshold → verdict on whether
  reactive literal injection works on stock firmware.
- **Exit codes:** 1 = round-trip mismatch, 2 = not advertising, 3 = prepare refuses.

#### `11_max_fidelity.py` — identity spoofing (53 lines)
- **Does:** claims InitA `FF:EE:DD:CC:BB:AA` via `set_bd_address` (1-arg/2-arg
  signature fallback) → Phase A: 5× `raw_inject` of the literal packet
  (sniffer-verifiable artifact) → Phase B: full custom-LLData connect + GATT
  discovery + 5 s link-liveness loop.
- **CLI:** `[mac]`, `--port`.

#### `12_ab_diagnose.py` — A/B differential diagnosis (108 lines)
- **Does:** `scan_present()` advertising check (4 retries) → attempt A (default
  params) vs attempt B (custom AA/CRCInit/chanmap/hop) → probe discovery up to
  5×0.8 s → decision tree: both dead ⇒ device wants pairing/LL procedure;
  only custom dead ⇒ interval sweep (80/160/320 → 100/200/400 ms) at hop 13 →
  post-mortem scan.
- **CLI:** `[mac]`, `--port`.

#### `13_death_autopsy.py` — post-mortem capture (98 lines)
- **Does:** ONE WhadDevice for the whole run (no fd errors). Hooks
  `on_disconnected` (dumps all event attributes, decodes HCI termination reason
  via a hardcoded map: 0x08 timeout, 0x13 remote terminated, 0x16 local
  terminated, 0x3B unreasonable interval, 0x3E LL response timeout, 0x06 failed
  to establish), `on_ctl_pdu` (LL control hex), `on_data_pdu`. Attempt A
  (default, idle 6 s) vs B (custom, idle 6 s) → verdict matrix that pointed the
  investigation at ATT/MTU as the actual killer.
- **CLI:** `[mac]`, `--port`.

#### `14_mtu_responder.py` — the MTU fix (89 lines)
- **Does:** intercepts `ATT_EXCHANGE_MTU_REQ` (L2CAP CID 0x0004, ATT opcode
  `0x02`) inside `on_data_pdu`, and within the 14×0.2 s pump loop answers with
  a raw ATT MTU Response (247) — trying scapy `BTLE_DATA/L2CAP_Hdr/ATT_Exchange_MTU_Response`
  and the bare L2CAP frame `03 00 04 00 03 <mtu le16>` — then attempts
  `conn.discover()` at t+1.2 s. Verdict: "LINK SURVIVED THE MTU EXCHANGE".
- **Fixed:** `send_data_pdu(pkt, conn_handle=handle)` argument order (was
  reversed — see §5).
- **CLI:** `[mac]`, `--mtu`, `--port`.

#### `15_manual_att.py` — manual ATT stack (155 lines)
- **Does:** bypasses WHAD's host stack entirely: hand-builds L2CAP frames
  (`len_le16 + CID 0x0004 + ATT`) inside LL data PDUs (`LLID=2` header),
  tests 4 candidate TX formats (bare L2CAP, full PDU w/ LL header, scapy object,
  raw+our-AA) — first format that isn't terminated wins → Phase 2 runs
  ATT By-Group-Type-Discovery (`0x10`, UUID 0x2800) for services (≤12) and
  By-Type-Discovery (`0x08`, UUID 0x2803) for characteristics.
- **Hooks:** `on_ctl_pdu` detects `LL_TERMINATE_IND` (`0b 02`), `on_data_pdu`
  decodes ATT opcodes 0x02/0x11/0x09/0x01.
- **Side effect:** writes `send_src.txt` (dump of `Central.send_data_pdu` source).
- **CLI:** `[mac]`, `--mtu`, `--port`.

#### `own_packet_full.py` — the full rogue-central framework (531 lines)
- **8 steps:** ① env audit (Python ≥3.8, whad/scapy importable, `/dev/ttyACM*`,
  pyserial open, uucp group, ModemManager off, `lsusb c0ff:eeee`) with exact
  fix hints → ② scan + address-type auto-detect from `BTLE_ADV.TxAdd` →
  ③ build/verify our CONNECT_IND (template bytes `TPL[14:36]` are the single
  source of truth) → ④ literal raw_inject attempt → ⑤ reopen as Central +
  claim InitA → ⑥ connect with our LLData (6× dongle retries, 3× connect
  retries, `timeout=10`) → ⑦ **3 ms MTU-response pump** (optimistic + reactive)
  watching for `LL_TERMINATE_IND` → ⑧ manual GATT discovery (By-Group-Type
  0x10 + By-Type 0x08, reads device name from char 0x2A00 in service 0x1800).
- **Artifacts:** `packet.txt`, `report_<MAC>_<ts>.txt`.
- **Exit codes:** 0 = alive, 1 = dead, 2 = environment, 3 = not advertising, 130 = SIGINT.
- **CLI:** `mac`, `--addr-type {auto,public,random}`, `--scan-time`, `--mtu`, `--watch`.

#### `oooooooooooo.py` — connect framework + length fuzzer (541 lines)
- **Same as `own_packet_full.py`** (fork; header now correctly names this file)
  plus the **SweynTooth-style length-field fuzzer** (`-l`): `build_pdu_len()`
  declares N payload bytes in the header while physically truncating the buffer
  to match — "legal shape, missing fields" (CC2540 CVE-2019-19194 methodology;
  N > 34 keeps the full buffer with an over-declared Length).
- **Oracle:** rhythm-sync TX right after each detected ADV_IND (min 0.4 s apart,
  30 s deadline) → short ~2 s gap ≈ accepted; silence > max(crash_window,
  4×median ADV interval) + recovery window = CRASH-LIKELY → wait up to 20 s for
  reboot → results table + `fuzz_len_<ts>.txt`.
- **CLI:** `mac`, `-l/--fuzz-length`, `--lens`, `--shots`, `--crash-window`,
  `--recovery-window`, `--addr-type`, `--scan-time`, `--mtu`, `--watch`.
- **Warning:** DoS-class tool — authorized targets only.

#### `sweyntooth_crash.py` — named-vector crasher (161 lines)
- **9 pre-built vectors** via scapy `BTLE_CONNECT_REQ`: `trunc0/12/18/26`
  (physically truncated), `iv0` (interval=0), `to0` (timeout=0), `hop0` (hop=0,
  spec-illegal), `over247` (Length byte=247 over 34 B), `valid34` (control).
- **Oracle:** 5 s baseline → median ADV interval → thresholds
  `acc=max(1.2, 2×med)`, `crash=max(window, 4×med)` → per-vector shots synced
  to <0.6 s after last ADV → results table + `crash_<ts>.txt`.
- **CLI:** `mac`, `--vectors`, `--shots`, `--window`, `--list`.
- **Fixed:** variable shadowing that prevented results from ever being saved (§5).

### Tier B — bleak / host stack

#### `ble_busy.py` — saturation / DoS (82 lines)
- **Does:** infinite loop of `BleakClient(mac, timeout=0.5)` connect → immediate
  disconnect → 0.05 s gap, holding the target's Link Layer busy so legitimate
  centrals can't connect.
- **CLI:** `[mac]`, `--timeout`, `--delay`. Ctrl+C clean exit.
- **Warning:** DoS-class tool — authorized targets only.

#### `ble_connection_time_checker.py` — uptime/crash monitor (75 lines)
- **Does:** connect, hold the link, log exact connect/disconnect timestamps and
  session duration, reconnect after 2 s — observes watchdog reboots or
  instability under test.
- **CLI:** `[mac]` (required), `--timeout`, `--retry`.

#### `getting-all-details-of-ble.py` — GATT recon (60 lines)
- **Does:** connects and dumps every service, characteristic (UUID, handle,
  properties), readable values (bytes + UTF-8/hex fallback), descriptors in a
  tree layout. Pre-attack attack-surface mapping.
- **CLI:** `[mac]`.

#### `read_descriptors.py` — targeted descriptor read (24 lines)
- **Does:** reads GATT descriptors at fixed handles (default 19, 22), prints
  raw repr + ASCII. Verifies improper access controls on specific handles.
- **CLI:** `[mac]`, `--handles 19,22`.

#### `thor.py` — GATT explorer + byte-length prober (714 lines, largest)
- **Part 1:** GATT explorer (same as getting-all-details).
- **Part 2:** sweeps write payload lengths 1..min(244, MTU−3) over every
  writable characteristic with:
  - `ConnectionTracker` — sessions, errors, reconnects, drop timestamps
  - `BLESession.ensure()` — instant reconnect on drop (measures drop→ready ms)
  - `ProbeState` — JSON checkpoint (`probe_checkpoint.json`) resuming each
    handle at `last_sent + 1` after reconnects or restarts
  - hang detection (`MAX_CONSECUTIVE_HANGS=8`) with remediation hints
  - `classify_write_error()` — bleak exception → ATT error codes (0x0C length
    mismatch, 0x03 not permitted, 0x0D unlikely…)
  - notification capture, CCCD subscribe on every connect, read-back after writes
  - verdicts: FIXED-LENGTH / variable / patchy / all-rejected / dead-path
- **~20 module-level tunables** (PROBE_MIN/MAX_LEN, PROBE_FILL_BYTE 0x41,
  PROBE_DELAY, WRITE_TIMEOUT, CONNECT_RETRIES, CHECKPOINT_FILE, …).
- **CLI:** `[mac]`, `--address-type {public,random}`, `--reset-checkpoint`,
  `--explore-only`.
- **Note:** writes real payloads to the device — intrusive by design.

### Tooling

#### `check.sh` — BLE LAB DOCTOR (22 lines)
- 12 checks: ButteRFly USB (`c0ff:eeee`), `/dev/ttyACM0`, pyserial open,
  ModemManager off, `uucp` group, `import whad`, sniffle package
  (`tools/Sniffle/python_cli` — **updated** after the folder reorg), sniffle
  extcap, `arm-none-eabi-gcc`, wireshark, nrfutil, `wble-central`.
- Exit code = number of failures. Uses `$HOME/ble-lab/venv/bin/python`.

#### `ble_scripts_report.txt` (in `scripts/`)
- Legacy one-line-per-script digest (Functionality / BLE Attack Use). Superseded
  by this document but kept for cross-checking.

---

## 4. STRATEGY MAP (what each script is for)

```
PACKET FOUNDATION
  1_build_packet .......... build + spec-verify the 36-byte CONNECT_IND (offline)
  2_send_packet ........... fire it via Central.connect() custom LLData

REACTIVE INJECTION LINE (literal bytes on-air)
  4_inject_raw ............ first arm attempt (4 trigger strategies)
  5_scan_then_inject ...... scan first, then arm + FIRED hooks
  6_scan_inject_final ..... single-instance continuous RX + arming
  7_connect_lifecycle ..... + acceptance oracle (ADV silence gap ≈ your 2s timeout)
  8_trigger_sweep ......... calibrate hardware pattern offsets 0..30

ROOT-CAUSE / DIAGNOSIS LINE
  10_prepare_rootcause .... does prepare() accept literal PDUs? Manual vs Reception
  12_ab_diagnose .......... default vs custom params; interval tolerance sweep
  13_death_autopsy ........ capture LL_CTRL / HCI termination codes while idle

THE FIX
  14_mtu_responder ........ answer ATT_EXCHANGE_MTU_REQ to stop the ~200ms kill
  15_manual_att ........... full manual ATT over raw L2CAP (bypass host GATT)
  11_max_fidelity ......... spoof InitA + raw_inject proof + custom connect

PRODUCTIZED FRAMEWORK
  own_packet_full ......... 8-step rogue central: audit→scan→inject→connect→MTU→GATT
  oooooooooooo ............ same + SweynTooth length-field fuzzer (CVE-2019-19194 style)
  sweyntooth_crash ........ 9 named malformed CONNECT_IND crash vectors

HOST-STACK / RECON (no dongle)
  getting-all-details ..... full GATT enumeration
  read_descriptors ........ raw descriptor reads at fixed handles
  thor .................... GATT explorer + writable-length fuzzer w/ checkpoints
  ble_connection_time..... uptime / crash monitor
  ble_busy ................ link saturation DoS (authorized targets only)

ENVIRONMENT
  check.sh ................ 12-point lab doctor
```

---

## 5. BUGS & RELIABILITY

### Fixed in this pass

| # | File | Bug | Fix |
|---|---|---|---|
| 1 | `thor.py:651` | `RECONNECT_ON_DROP` referenced but never defined → `NameError` as soon as any handle lost its connection | defined as module constant `RECONNECT_ON_DROP = True` |
| 2 | `sweyntooth_crash.py:153` | `with open(...) as f:` then `for n,f,v in results:` rebinds `f` to an int → results file **never written**, script died after summary | renamed to `fh` / `shots` |
| 3 | `14_mtu_responder.py:34` | `send_data_pdu(handle, pkt)` — args reversed (correct signature is `send_data_pdu(payload, conn_handle=...)` as proven by script 15) | corrected call |
| 4 | `oooooooooooo.py` header | header comment still said `own_packet_full.py` | corrected |
| 5 | `getting-all-details`, `read_descriptors`, `thor` | missing shebangs | `#!/usr/bin/env python3` added |
| 6 | 17 scripts | no CLI — MAC/params were edit-in-place constants; `ble_connection_time_checker` treated `--help` as a MAC and hung | full `argparse` added to all 21 scripts (`[mac]`, `--port`, `--scan-time`, `--window`, `--mtu`, `--handles`, `--address-type`, …); `--help` verified on every script |
| 7 | `4_inject_raw` | 120 s watch loop with no Ctrl+C guard | KeyboardInterrupt handled |
| 8 | `check.sh` | stale `~/ble-lab/Sniffle` paths after folder reorg | updated to `~/ble-lab/tools/Sniffle` |

### Remaining known fragilities (documented, by design or deferred)

1. **WHAD callback monkey-patching** (`on_adv_pdu`, `on_data_pdu`, `on_ctl_pdu`,
   `on_triggered`, `trig.trigger`) is the single largest version-drift surface.
   Scripts survive it with multi-signature fallbacks, but a WHAD upgrade can
   still break them. *Mitigation: keep the WHAD version pinned in `venv`.*
2. **No shared module** — the packet template, MAC wire conversion, CRC24, and
   4-candidate trigger ladder are copy-pasted across ~13 scripts (drift risk).
   Extracting `ble_common.py` is the next reliability phase (not done here —
   deliberately excluded to avoid a risky mass refactor).
3. **Path assumptions** — `check.sh` and several hint strings assume
   `$HOME/ble-lab/venv`. Scripts themselves use no relative paths, so they run
   from any CWD.
4. **Hardware assumptions** — tier A assumes ButteRFly on `uart0` (now
   overridable with `--port`, but `uart1` fallback only exists in
   own_packet_full / oooooooooooo).
5. **`thor.py` private API** — `client._backend._acquire_mtu()` is BlueZ-only
   and private (guarded by try/except); checkpoint file is keyed by char UUID
   only (device MAC stored but not checked on load).
6. **`15_manual_att.py`** char-discovery parser assumes 2-byte UUID items —
   breaks on 16-bit UUID characteristics.
7. **Infinite loops** in tier B (`ble_busy`, `ble_connection_time_checker`,
   thor's watchdog) run until Ctrl+C by design; `ble_busy` has no attempt cap.

---

## 6. RELIABILITY PLAN — "reliable every time, anywhere"

### Phase 1 — done (this pass)
- 8 concrete bugs fixed (table above)
- argparse + `--help` on all 21 scripts; shebangs everywhere
- Ctrl+C guards, connect timeouts/retry flags
- all 21 scripts compile-verified (`py_compile`) and `--help` smoke-tested

### Phase 2 — shared core (recommended next)
- Extract `scripts/ble_common.py`: `PACKET_TEMPLATE`, `mac_wire()`,
  `ble_crc24()`, `arm_trigger_ladder()` (the 4-strategy pattern), `open_dongle()`
  (uart0/uart1 + retries), `wait_for_advertising()`, `advance_oracle()` (gap
  detection), common `log()`/exit-code scheme.
- Migrate scripts incrementally (start with `own_packet_full` → `oooooooooooo`
  → `sweyntooth_crash`, then the 4–8 series). One unit test file against the
  packet builder (byte-exact golden vectors from `1_build_packet.py`).

### Phase 3 — portability ("anywhere")
- `check.sh` → derive `ROOT` from the script's own location instead of
  `$HOME/ble-lab`; same for hint strings.
- Single `config.toml`/env-var layer: default MAC, port, windows, MTU —
  so target changes happen in one place, not 13 files.
- Pin `whad`/`scapy`/`bleak` versions in a `requirements.txt` + `pip check`
  in `check.sh`; add `python --version` gate.
- Optional: `--dry-run` mode for tier-A scripts (print the packet/plan without
  touching the dongle) — makes them testable on machines with no hardware.

### Phase 4 — operational hardening
- Structured exit codes standardized across all scripts (already good in the
  own_packet_full family: 0/1/2/3/130 — extend to scripts 1–15).
- JSON result artifacts (like `thor`'s checkpoint and own_packet_full's
  report) for every run instead of ad-hoc stdout.
- Retry/deadline budgets on every hardware open (scripts 5–8 already do 5–6
  retries; make it universal with `--retries`).
- A single `run_all.sh` smoke suite: `--help` + `--dry-run` + compile check
  for every script (the exact verification performed for this report).

### Verification performed for this report
- `py_compile` passed on all 21 scripts
- `--help` executed successfully on all 21 scripts
- `1_build_packet.py` executes end-to-end offline and reproduces the golden
  packet header `85 22` / Length 0x22
- `check.sh`: 9/12 PASS (3 failures are hardware-not-connected only;
  Sniffle paths after the reorg verified PASS)
