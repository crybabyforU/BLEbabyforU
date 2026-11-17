# BLE Lab Runner

`scripts/run_all_ble.py` runs the BLE attack/assessment scripts from
`ALL_SCRIPTS_ATTACKS.txt` **in order**, with:

- live verbose output for every child script,
- a preflight hardware/dongle check,
- automatic skipping of tests whose dongle is not plugged in,
- a run log + JSON/Markdown summary,
- and, when a script fails, the **exact failing function and line**.

`./run-all-ble.sh` is the same thing through the lab venv.

`./run-all-ble-no-whad.sh` runs the same manifest **without the WHAD
framework**: it skips every `whad`-stage script (and the `whadbro`
prototypes), so no WHAD package or ButteRFly dongle is required.

> **WARNING**: most steps are DoS / exploit tooling. Only run them against a
> device you own or have explicit written authorization to test. Destructive
> steps require `--yes` (or typing `I OWN THE TARGET` at a TTY).

---

## Quick start

```bash
cd ~/ble-lab/crybabyforu

# What does the runner know about this machine?
./run-all-ble.sh --hw-check

# What will run, in what order? (no hardware touched)
./run-all-ble.sh --list

# Catalogue: every script, 2-word function, hardware YES/NO
./run-all-ble.sh -l

# Run exactly one script from that catalogue (example: 2 = packet builder)
./run-all-ble.sh -N 2 --yes

# Safe first pass: environment + offline packet build + GATT recon
./run-all-ble.sh --profile safe --target C0:00:00:41:73:AC

# Full BLE IoT assessment (destructive; requires --yes)
./run-all-ble.sh --profile iot-ble --target C0:00:00:41:73:AC --yes

# Everything except WHAD (no WHAD package / ButteRFly dongle needed)
./run-all-ble-no-whad.sh --target C0:00:00:41:73:AC --yes
```

Set your device's MAC with `--target`. The lab default is
`C0:00:00:41:73:AC` (`MDT2410161`).

---

## Profiles (ordered stages)

| Profile | Stages that run | Use it for |
|---|---|---|
| `safe` | doctor -> offline -> recon | first contact, no DoS |
| `recon` | doctor -> offline -> recon -> sniffle | passive recon + capture |
| `whad` | doctor -> offline -> whad | WHAD/ButteRFly link-layer suite |
| `no-whad` | doctor -> offline -> recon -> sniffle -> host -> sweyntooth -> zephyr | everything that does **not** use WHAD |
| `sweyntooth` | doctor -> offline -> sweyntooth | nRF52840 + SweynTooth PoCs |
| `iot-ble` | doctor -> offline -> recon -> sniffle -> whad -> host -> sweyntooth | full BLE assessment |
| `all` | iot-ble + zephyr | full assessment + ZEPHYR HCI tests |

Within a stage, scripts run in the manifest order (roughly the numbering used
in the lab: `1_build_packet`, `2_send_packet`, `4_inject_raw`, ...).

## List every script and run one by number

`./run-all-ble.sh -l` prints the full catalogue: number, script, a two-word
function, and the exact hardware the script needs.

```text
  #  SCRIPT                              FUNCTION              HARDWARE NEEDED
  1  doctor/check                        environment check     none
  2  offline/1_build_packet              packet builder        none
  3  recon/getting-all-details-of-ble    GATT enumeration      HOST,TARGET
 15  whad/2_send_packet                  rogue central         DONGLE,TARGET
 37  sweyntooth/CC2640R2_public_key_crash CC2640R2 key         NRF52-ST,TARGET
  6  sniffle/version_check               firmware probe        SNIFFLE
 63  zephyr/nrf-api-check                HCI probe             ZEPHYR-HCI
```

A hardware legend below the table explains each tag, for example
`DONGLE` = WHAD ButteRFly nRF52840 USB dongle, `NRF52-ST` = nRF52840 +
SweynTooth firmware, `SNIFFLE` = TI Launchpad + Sniffle firmware.

Run exactly one catalogue entry with `-N`:

```bash
./run-all-ble.sh -N 2 --yes                 # offline packet builder
./run-all-ble.sh -N 3 --yes                 # GATT enumeration (needs target)
./run-all-ble.sh -N 15 --yes --force        # one WHAD script, even if dongle missing
```

The numbers are stable for a given invocation because `-l` and `-N` use the
same list. The normal runner shows all 67 manifest scripts (including WHAD,
optional and duplicate entries). `run-all-ble-no-whad.sh` adds
`--skip-stage whad`, so its `-l` shows only **49 non-WHAD scripts** and its
`-N` numbers refer to that 49-entry list. A chosen script still skips itself
when its hardware is missing unless you add `--force`.

**67 entries = 65 unique files.** Two scripts are launched in two different
modes, so each mode has its own `-N` number. `-l` marks those rows with `†`
and prints the footnote automatically:

| # | File | Mode |
|---:|---|---|
| 5 | `scripts/thor.py` | GATT explore only |
| 36 | `scripts/thor.py` | write fuzzer |
| 27 | `scripts/oooooooooooo.py` | packet connector |
| 28 | `scripts/oooooooooooo.py` | length fuzzer (`-l`) |

`SCRIPTS_GUIDE.md` explains every entry in detail.

### Stage meaning

| Stage | What runs | Dongle |
|---|---|---|
| `doctor` | `scripts/check.py` (cross-platform environment checks) | none (checks what is present) |
| `offline` | `1_build_packet.py` | none |
| `recon` | GATT enumeration, descriptor reads, `thor --explore-only` | host BLE adapter |
| `sniffle` | Sniffle version/scanner/capture | TI Launchpad |
| `whad` | WHAD rogue-central, injector, MTU, manual ATT, SweynTooth-style crash vectors | WHAD ButteRFly nRF52840 |
| `host` | uptime monitor, connect/disconnect DoS, `thor` write fuzzer | host BLE adapter |
| `sweyntooth` | 13 main + 12 extra SweynTooth PoCs | nRF52840 + SweynTooth firmware |
| `zephyr` | ZEPHYR HCI adapter tests | nRF52840 + ZEPHYR firmware |

---

## Hardware / dongles

The runner detects hardware from USB IDs and `/dev/ttyACM*` / `/dev/ttyUSB*`
before running anything. The full reference is in `HARDWARE_REQUIRED.txt`.

| Tag | Hardware | Detected by |
|---|---|---|
| `HOST` | built-in / USB BLE adapter | `hci*` + importable `bleak` |
| `DONGLE` | WHAD ButteRFly nRF52840 | USB `c0ff:eeee` or Nordic `1915:*`, serial port, `whad` import |
| `NRF52-ST` | nRF52840 + **SweynTooth driver firmware** | nRF52840 USB + serial port |
| `SNIFFLE` | TI CC1352/CC26x2 Launchpad | TI USB `0451:*` or explicit `--sniffle-port`, `sniffle` import |
| `ZEPHYR-HCI` | nRF52840 + ZEPHYR USB-HCI firmware | `hci1` or nRF52840 USB |
| `ESP32` | ESP32 + Braktooth | USB-serial adapter (`10c4`, `1a86`, `0403`) |
| `NEXUS5` | rooted Nexus 5 / CYW20735 | `adb devices` |
| `MICROBIT` | micro:bit / nRF52 + Btlejack | USB `0d28:*` |
| `BLUING` | CSR8510 + Bluing | USB `0a12:0001` |
| `TARGET` | the device under test | `--target` MAC |

### Important dongle rules

1. **One nRF52840 cannot run two firmwares at once.**
   - `whad` stage needs **ButteRFly** firmware.
   - `sweyntooth` stage needs **SweynTooth driver** firmware.
   - `zephyr` stage needs **ZEPHYR USB-HCI** firmware.
   If you only own one dongle, re-flash between stages, or use two dongles and
   point `--nrf-port` at the SweynTooth one. The runner prints a warning at the
   start of those stages.
2. **Sniffle is a separate radio.** It is a TI Launchpad, not the nRF52840.
   It is optional; the `sniffle` stage auto-skips when it is absent.
3. **ModemManager must be stopped** or it will grab `/dev/ttyACM*` from under
   the dongle. `check.py`/`--hw-check` report this.
4. If a step's hardware is missing it is **skipped** with the reason in the
   plan. `--force` runs it anyway (useful when detection is wrong, e.g. a
   custom USB ID).

Typical full lab:

- 1x host Bluetooth adapter (built-in is fine) for `recon`/`host`,
- 1x WHAD ButteRFly nRF52840 for the `whad` stage,
- 1x second nRF52840 (or re-flash the first) for `sweyntooth`,
- 1x TI Launchpad for `sniffle` (optional but recommended to prove packets
  actually went on-air),
- the BLE device under test.

---

## Verbose mode and failure diagnosis

Verbose is the default. Every child line is streamed with a `│` prefix:

```text
[ 10/53] whad/2_send_packet
       hardware: DONGLE, TARGET   timeout: 90s
       rogue central with custom AA / CRCInit / interval / hop
  $ /home/.../venv/bin/python /home/.../scripts/2_send_packet.py C0:00:00:41:73:AC --port uart0
  cwd: /home/.../ble-runs/.../work
    │ [*] Sending custom CONNECT_IND -> C0:00:00:41:73:AC (random/static)
    │ ...
  => PASS  (1.2s)
```

When a script dies, the runner prints:

```text
 FAILURE: whad/4_inject_raw
 exit code: 1
 reason   : exit code 1: KeyError: 'missing'

 FAILING FUNCTION
   /home/.../scripts/4_inject_raw.py:58  in arm_trigger
      58 |     return strategies["missing"]()

 CALL STACK (outer -> inner)
     .../4_inject_raw.py:120  in <module>
     .../4_inject_raw.py:58   in arm_trigger

 LAST OUTPUT
    ...last 15 lines...
```

This is the fastest way to see whether the problem is in the target script, the
Whad library, the dongle firmware, or a missing dependency.

Useful flags:

```bash
--quiet              # don't stream child output, still show failures
--stop-on-fail       # stop after the first FAIL/TIMEOUT
--only 'whad/*'      # run only matching step ids/script names
--skip 'sweyntooth*' # skip matching steps
--stage whad         # run one stage (repeatable)
--include duplicates # also run bundled/older copies (whadbro, knob_tester)
--include optional   # also run sniffle reset/advertiser/relay utilities
--include long       # allow long-running steps in safe/recon profiles
--no-target-check    # skip the 8 s preflight scan for the target
--target-scan-time N # preflight scan length
--timeout N          # default timeout for scripts without an override
--python PATH        # use a different interpreter for the target scripts
```

### Common selections

```bash
# Just the WHAD link-layer suite
./run-all-ble.sh --stage whad --yes

# Just one script, without executing it
./run-all-ble.sh --only whad/2_send_packet --dry-run --yes

# SweynTooth only, using a second dongle
./run-all-ble.sh --profile sweyntooth --nrf-port /dev/ttyACM1 --yes

# Use an explicit Sniffle port
./run-all-ble.sh --profile recon --sniffle-port /dev/ttyACM1

# Force steps past the hardware check (use with care)
./run-all-ble.sh --stage whad --force --yes
```

---

## Artifacts

Every real run creates `ble-runs/<timestamp>/`:

| File | Contents |
|---|---|
| `runner.log` | complete multiplexed console log |
| `summary.json` | machine-readable result, hardware state, failing frames |
| `summary.md` | human-readable result table |
| `logs/<step>.log` | full output of one child script |
| `work/` | cwd for the core lab scripts (packet dumps, reports, checkpoints) |
| `sniffle_capture.pcap` | capture from the sniffle stage, when enabled |

Timeouts are not always failures:

- `TIMEOUT-OK` means a deliberately long-running tool (monitor, scanner,
  SweynTooth PoC that waits for a connection) was stopped on purpose.
- `TIMEOUT` is a real failure.
- `WARN` is used for the doctor (`check.py`), because a missing optional tool should not
  fail the whole assessment.

Exit codes: `0` all good, `1` at least one FAIL/TIMEOUT, `2` bad arguments,
`3` authorization refused, `130` interrupted.

---

## What is covered, and what is not

**Covered automatically:** 23 core lab scripts (`scripts/`), the 13 main + 12
extra SweynTooth PoCs, the 2 whadbro prototypes (as `--include duplicates`),
the Sniffle CLI tools, and optional ZEPHYR HCI tests.

**Not launched by this runner:**

- BlueToolkit / Sbleedy **YAML** exploits. These are configuration files for
  their own engines (`bluekit`, `sbleedyCLI`), not standalone scripts. They
  also mostly target classic BR/EDR (BleedingTooth, BlueBorne, Braktooth,
  InternalBlue) and need an ESP32, rooted Nexus 5, or a classic adapter.
- Vendored libraries and firmware images (they are support files, not tests).
- Firmware flashing. The runner never flashes a dongle; it only tells you
  which firmware the next stage needs.

For the classic BR/EDR suite, use the BlueToolkit/Sbleedy CLIs directly. See
`CLASSIC_BR_EDR_SCRIPTS.txt` and `HARDWARE_REQUIRED.txt`.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `DONGLE MISSING` even though it is plugged in | Check `lsusb` for `c0ff:eeee` / `1915:*`; run `./run-all-ble.sh --hw-check`; ensure ModemManager is stopped. |
| `Device or resource busy` / serial permission error | `sudo systemctl stop ModemManager`; add your user to `uucp`; log out/in. |
| WHAD steps fail at `WhadDevice.create()` | Wrong firmware or port. Use `--whad-port uart0` (or `uart1`). |
| SweynTooth steps all fail immediately | The dongle is still on WHAD firmware. Re-flash the SweynTooth driver firmware, or use a second dongle via `--nrf-port`. |
| SweynTooth import fails with `FileNotFoundError: ... liblibc.a` | Old bundled Scapy plus Python 3.10 and new binutils. The runner already loads `scripts/pycompat/sitecustomize.py`; if you launch a PoC by hand, set `PYTHONPATH=$HOME/ble-lab/crybabyforu/scripts/pycompat`. `./scripts/check.py` tests this. |
| Target not found in the preflight scan | It may use a private/random address or not be advertising. The run continues; check the MAC with `bluetoothctl` / `wble-central`. |
| `check.py` (doctor) says `ButteRFly USB FAIL` | Only means the WHAD dongle is not plugged in; `WARN` is normal for a host-only run. |
| `sniffle` steps skipped | No TI Launchpad detected. Pass `--sniffle-port` if the board uses a non-TI USB-serial chip. |

---

## Files

```text
crybabyforu/
├── run-all-ble.sh              # convenience wrapper (local/parent venv)
├── run-all-ble-no-whad.sh      # wrapper: all stages except WHAD
├── run.bat                     # Windows launcher
├── setup-venv.sh               # create a local Python venv
├── README.md                   # copy overview and what is included
├── docs/                       # every guide and catalog
│   ├── README.md               # documentation index
│   ├── RUNNER_README.md        # this file
│   ├── SCRIPTS_GUIDE.md        # what every BLE script does
│   ├── SCRIPTS_BY_FUNCTION.md  # number -> function -> script -> hardware
│   ├── ALL_SCRIPTS_ATTACKS.txt # source inventory
│   └── HARDWARE_REQUIRED.txt   # full hardware reference
├── scripts/run_all_ble.py      # the runner
├── scripts/pycompat/           # startup shim for old Scapy on Python 3.10
├── tools/                      # Sniffle, SweynTooth, ZEPHYR, whadbro + libs
└── ble-runs/                   # per-run logs and summaries
```
