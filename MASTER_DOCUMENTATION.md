# 📘 crybabyforu — Master Documentation

**A cross-platform (Windows · Ubuntu · Arch) BLE security-testing framework.**

One folder. One runner. Every script ordered, hardware-aware, logged, and
failure-diagnosed — on your OS of choice.

> ⚠️ **LEGAL NOTICE**
> This framework contains DoS, crash, and fuzzing tooling for Bluetooth Low
> Energy. Use it **only** on devices you own or have explicit **written
> authorization** to test. Destructive steps are gated behind `--yes`.
> You are responsible for complying with your local laws.

---

## Table of contents

1. [What is this?](#1-what-is-this)
2. [OS support matrix](#2-os-support-matrix)
3. [Folder map](#3-folder-map)
4. [Installation — Windows](#4-installation--windows)
5. [Installation — Ubuntu](#5-installation--ubuntu)
6. [Installation — Arch](#6-installation--arch)
7. [Hardware guide (dongles & firmware)](#7-hardware-guide)
8. [Quick start](#8-quick-start)
9. [Command reference](#9-command-reference)
10. [Profiles & stages](#10-profiles--stages)
11. [Artifacts of a run](#11-artifacts-of-a-run)
12. [Troubleshooting by OS](#12-troubleshooting-by-os)
13. [FAQ](#13-faq)

---

## 1. What is this?

`crybabyforu` is a portable, self-contained copy of a BLE security lab:

- **Ordered execution** — 67 scripts run in a sensible assessment order
  (doctor → offline → recon → sniffle → whad → host → sweyntooth → zephyr).
- **Hardware-aware** — every script declares which dongle it needs; the
  runner detects dongles from USB IDs and serial ports and **auto-skips**
  what is missing (with the reason printed).
- **Verbose & diagnosable** — all child output is streamed live; when a
  script dies you get the exact failing function and line.
- **Artifacts everywhere** — every run produces logs, JSON + Markdown
  summaries, and per-script log files in `ble-runs/<timestamp>/`.
- **Cross-platform** — Windows (COM ports, WinRT BLE), Ubuntu/Debian,
  Arch Linux, and macOS for host-based stages.

The runner core is `scripts/run_all_ble.py` — pure Python stdlib, zero
external dependencies for the runner itself.

---

## 2. OS support matrix

| Capability | Windows 10/11 | Ubuntu 22.04+ | Arch Linux | macOS |
|---|---|---|---|---|
| Doctor / environment check | ✅ | ✅ | ✅ | ✅ |
| Offline packet build | ✅ | ✅ | ✅ | ✅ |
| Recon (GATT enumeration, bleak) | ✅ WinRT | ✅ BlueZ | ✅ BlueZ | ✅ CoreBluetooth |
| Host DoS / fuzz stages | ✅ | ✅ | ✅ | ✅ |
| SweynTooth PoCs (nRF52840) | ✅ COMx | ✅ ttyACM | ✅ ttyACM | ✅ |
| Sniffle capture (TI Launchpad) | ✅ COMx | ✅ | ✅ | ✅ |
| WHAD / ButteRFly link-layer suite | ⚠️ experimental | ✅ | ✅ | ⚠️ |
| Classic BR/EDR (BlueZ only tools) | ❌ | ✅ | ✅ | ❌ |
| Zephyr BlueZ D-Bus scripts | ❌ | ✅ | ✅ | ❌ |

`✅` fully supported · `⚠️` works but less tested · `❌` needs Linux.

---

## 3. Folder map

```text
crybabyforu/
├── run-all-ble.sh               # Linux/macOS launcher
├── run.bat                      # Windows launcher (cmd / PowerShell)
├── run-all-ble-no-whad.sh       # Linux launcher without the WHAD stage
├── setup-venv.sh                # Linux/macOS venv bootstrap
├── setup-venv.bat               # Windows venv bootstrap
├── setup-linux.sh               # Ubuntu/Arch system packages + groups (sudo)
├── requirements.txt             # Linux Python packages
├── requirements-windows.txt     # Windows Python packages (no D-Bus deps)
├── requirements-freeze.txt      # exact original lab package list
│
├── MASTER_DOCUMENTATION.md      # ← this file
├── RUNNER_README.md             # deep runner docs (flags, internals)
├── SCRIPTS_BY_FUNCTION.md       # script number → function → hardware map
├── SCRIPTS_GUIDE.md             # detailed what-every-script-does guide
├── HOW_TO_USE_SCRIPTS.txt       # long-form usage examples for every script
├── README.md                    # short overview
│
├── scripts/                     # the lab scripts + runner + doctor
│   ├── run_all_ble.py           # THE RUNNER (cross-platform, stdlib only)
│   ├── check.py                 # cross-platform environment doctor
│   ├── check.sh                 # legacy bash doctor (Linux deep checks)
│   ├── pycompat/sitecustomize.py# fix for old bundled Scapy on py3.10
│   ├── 1_build_packet.py … 15_manual_att.py   # core WHAD lab scripts
│   ├── ble_busy.py, thor.py, sweyntooth_crash.py, …
│   └── by_function/             # optional symlinks named by function
│
├── tools/
│   ├── sweyntooth_bluetooth_low_energy_attacks/  # 13 main + 12 extra PoCs
│   │   └── libs/                # bundled old Scapy, colorama, SMP server
│   ├── Sniffle/                 # Sniffle CLI + package + TI firmware
│   ├── BlueToolkit-upstream/    # classic BR/EDR YAML exploits + bluekit
│   ├── SbleedyGonzales/         # BLE + classic exploit modules + sbleedyCLI
│   ├── ZEPHYR/pylol/            # Zephyr HCI adapter tests
│   └── whadbro/                 # older WHAD prototypes (optional)
│
└── ble-runs/<timestamp>/        # artifacts of every real run
    ├── runner.log, summary.json, summary.md
    ├── logs/<step>.log
    ├── work/                    # packet dumps, reports, checkpoints
    └── sniffle_capture.pcap     # when the sniffle stage runs
```

---

## 4. Installation — Windows

### Requirements

- Windows 10 or 11 (ANSI-capable console: Terminal, PowerShell, cmd all work)
- Python **3.10 or newer** — <https://python.org> (tick **"Add python.exe to PATH"**)
- A USB port for the dongles (see [§7](#7-hardware-guide))

### Steps

```bat
cd path\to\crybabyforu

:: 1. create the Python venv + install packages
setup-venv.bat --windows

:: 2. health check (works with zero hardware)
run.bat --hw-check

:: 3. script catalogue
run.bat -l

:: 4. safe first pass against your device
run.bat --profile safe --target C0:00:00:41:73:AC
```

Notes for Windows:

- Host BLE goes through **Bleak/WinRT** — make sure your PC's Bluetooth radio
  is enabled in Device Manager.
- Dongles appear as **`COMx`** ports, not `/dev/ttyACM0`. Check Device
  Manager → *Ports (COM & LPT)*, or run `run.bat --hw-check` which lists every
  COM port with its USB VID:PID.
- If `run.bat` cannot find Python, install it from python.org **with
  "Add to PATH"** ticked, or set it explicitly:
  `set PYTHON=C:\Python310\python.exe && setup-venv.bat --windows`
- **Do not install dbus-fast/dbus-python on Windows** — they are Linux-only.
  That is why `requirements-windows.txt` exists.
- The WHAD/ButteRFly stage is **experimental** on Windows (serial transport
  works; the full host stack assumes Linux). Prefer the `no-whad` profile:
  `run.bat --skip-stage whad --yes`

### Destructive runs (Windows)

```bat
run.bat --profile iot-ble --target C0:00:00:41:73:AC --yes
run.bat --profile sweyntooth --nrf-port COM3 --yes
```

---

## 5. Installation — Ubuntu

### Requirements

- Ubuntu 22.04 / 24.04 (or any Debian derivative)
- Python 3.10+ (Ubuntu ships one)
- `sudo` rights for the one-time system setup

### One-command setup (recommended)

```bash
cd ~/ble-lab/crybabyforu
sudo ./setup-linux.sh          # packages + ModemManager off + groups + venv
```

### Manual setup

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip bluez bluez-tools \
                    usbutils adb wireshark-common

# ModemManager steals /dev/ttyACM* from under the dongle — stop it for good:
sudo systemctl stop ModemManager
sudo systemctl disable ModemManager

# serial permission (log out/in afterwards!)
sudo usermod -aG dialout $USER

# Python environment
./setup-venv.sh                # add --full for the exact original package list

# health check
./run-all-ble.sh --hw-check
```

> **Python version note.** The lab was validated with Python 3.10.18.
> Newer Ubuntus ship 3.11/3.12 — those work; the bundled-Scapy fix
> (`scripts/pycompat/sitecustomize.py`) is loaded automatically. If your
> default is *very* new and a SweynTooth import complains, pin an older
> interpreter: `PYTHON=python3.10 ./setup-venv.sh`.

---

## 6. Installation — Arch

### Requirements

- Arch (or any pacman-based distro; Omarchy works the same way)
- Python 3.10+ (`python` package)
- `sudo` rights

### One-command setup (recommended)

```bash
cd ~/ble-lab/crybabyforu
sudo ./setup-linux.sh
```

### Manual setup

```bash
sudo pacman -Sy --needed python python-pip bluez bluez-tools bluez-utils \
                         usbutils android-tools wireshark-cli

# ModemManager does not usually run on Arch, but if installed, stop it:
sudo systemctl stop ModemManager 2>/dev/null || true

# serial permission — Arch uses the 'uucp' group (log out/in afterwards!)
sudo usermod -aG uucp $USER

# Python environment
./setup-venv.sh

# health check
./run-all-ble.sh --hw-check
```

> **Arch Python note.** Arch tracks the newest Python (3.13+). The runner,
> recon, host, and SweynTooth stages handle that. If the *old bundled
> Scapy* import ever fails, create the venv with Python 3.10/3.11 (via
> `pyenv`, `python310` from AUR, or `pacman -U` an older python) and run:
> `PYTHON=python3.10 ./setup-venv.sh`

---

## 7. Hardware guide

The runner never flashes firmware — it tells you which firmware the next
stage needs. Detection is based on USB VID/PID and serial ports.

| Tag | Hardware | Detected by | Firmware needed |
|---|---|---|---|
| `HOST` | your PC's built-in / USB BLE adapter | hciX (Linux) / bleak import | — (BlueZ or WinRT) |
| `DONGLE` | WHAD ButteRFly nRF52840 USB dongle | USB `c0ff:eeee` or Nordic `1915:*` | **ButteRFly** |
| `NRF52-ST` | nRF52840 + SweynTooth driver | Nordic USB + serial port | **SweynTooth driver** |
| `SNIFFLE` | TI CC1352/CC26x2 Launchpad | TI USB `0451:*` or `--sniffle-port` | **Sniffle** |
| `ZEPHYR-HCI` | nRF52840 + Zephyr USB-HCI | nRF52840 USB / `hci1` | **ZEPHYR USB-HCI** |
| `ESP32` | ESP32 + Braktooth | USB-serial `10c4`/`1a86`/`0403` | Braktooth |
| `NEXUS5` | rooted Nexus 5 / CYW20735 | `adb devices` | InternalBlue |
| `MICROBIT` | BBC micro:bit / nRF52 | USB `0d28:*` | Btlejack |
| `BLUING` | CSR8510 USB dongle | USB `0a12:0001` | Bluing |
| `TARGET` | the device under test | `--target` MAC | — |

### The one rule that matters: one dongle, one firmware

A single nRF52840 cannot run two firmwares at once:

- the **`whad`** stage needs ButteRFly firmware,
- the **`sweyntooth`** stage needs the SweynTooth driver firmware,
- the **`zephyr`** stage needs the Zephyr USB-HCI firmware.

If you own one dongle → re-flash between stages.
If you own two → keep the SweynTooth one separate and point the runner at it:

```bash
./run-all-ble.sh --profile sweyntooth --nrf-port /dev/ttyACM1 --yes     # Linux
run.bat --profile sweyntooth --nrf-port COM3 --yes                      # Windows
```

Missing hardware is **skipped automatically** with the reason in the plan.
Add `--force` to run a step anyway (e.g. a custom USB ID the detector
doesn't know).

### Typical full lab shopping list

1. Your PC's Bluetooth adapter (built-in is fine) — recon & host stages
2. 1× WHAD ButteRFly nRF52840 — whad stage
3. 1× second nRF52840 (or re-flash the first) — sweyntooth stage
4. 1× TI Launchpad — sniffle stage *(optional, but proves packets went on-air)*
5. The BLE device under test

---

## 8. Quick start

All examples work identically on Linux (`./run-all-ble.sh`) and Windows
(`run.bat`). Set your device's MAC with `--target`; the lab default is
`C0:00:00:41:73:AC`.

```bash
# 0. what does the runner know about this machine?  (no hardware touched)
run-all-ble.sh --hw-check

# 1. what will run, in what order?  (no hardware touched)
run-all-ble.sh --list

# 2. full catalogue: every script, 2-word function, hardware YES/NO
run-all-ble.sh -l

# 3. run exactly ONE script from that catalogue
run-all-ble.sh -N 2 --yes          # offline packet builder

# 4. safe first pass — doctor + offline build + GATT recon, NO DoS
run-all-ble.sh --profile safe --target C0:00:00:41:73:AC

# 5. full BLE IoT assessment (destructive; --yes required)
run-all-ble.sh --profile iot-ble --target C0:00:00:41:73:AC --yes

# 6. everything except WHAD (no WHAD package / ButteRFly dongle needed)
run-all-ble-no-whad.sh --target C0:00:00:41:73:AC --yes
```

Every destructive command asks for `--yes` (or, in an interactive TTY, the
literal phrase `I OWN THE TARGET`).

---

## 9. Command reference

```text
--profile NAME        ordered stage set (see §10)          default: iot-ble
--target MAC          the BLE device under test            default: C0:00:00:41:73:AC
--stage NAME          run only this stage (repeatable)
--skip-stage NAME     remove a stage from the plan (repeatable)

--list                show the execution plan, then exit
-l / --list-scripts   full catalogue: number → script → function → hardware
-N NUMBER             run exactly catalogue entry #NUMBER (same list as -l)
--hw-check            hardware/dongle report only, then exit

--only  PATTERN       run only matching step ids/names (fnmatch)
--skip  PATTERN       skip matching step ids/names
--include SET         also run: duplicates | optional | long

--yes                 authorize destructive steps
--force               run steps even when their hardware looks missing
--no-target-check     skip the 8 s preflight scan for the target
--target-scan-time N  preflight scan length in seconds      default: 8

--timeout N           default per-script timeout           default: 120
--stop-on-fail        stop after the first FAIL/TIMEOUT
--quiet               don't stream child output (failures still shown)
--dry-run             print commands without executing

--python PATH         interpreter for the target scripts
--nrf-port PORT       nRF52840 serial port  (/dev/ttyACM1 | COM3)
--whad-port NAME      WHAD transport        (uart0, uart1, …)
--sniffle-port PORT   Sniffle serial port   (/dev/ttyACM1 | COM3)
--log-dir DIR         where run artifacts go                default: ble-runs/
--no-color            disable ANSI colours
```

Exit codes: `0` all good · `1` at least one FAIL/TIMEOUT · `2` bad arguments ·
`3` authorization refused · `130` interrupted.

Timeouts are not always failures:

- `TIMEOUT-OK` — a deliberately long-running tool (monitor, scanner, PoC
  that waits for a connection) was stopped on purpose. Not a failure.
- `TIMEOUT` — a real failure.
- `WARN` — used for the doctor; a missing optional thing should not fail the
  whole assessment.

---

## 10. Profiles & stages

| Profile | Stages that run | Use it for |
|---|---|---|
| `safe` | doctor → offline → recon | first contact, no DoS |
| `recon` | doctor → offline → recon → sniffle | passive recon + capture |
| `whad` | doctor → offline → whad | WHAD/ButteRFly link-layer suite |
| `no-whad` | doctor → offline → recon → sniffle → host → sweyntooth → zephyr | everything **not** using WHAD |
| `sweyntooth` | doctor → offline → sweyntooth | nRF52840 + SweynTooth PoCs |
| `iot-ble` | doctor → offline → recon → sniffle → whad → host → sweyntooth | full BLE assessment |
| `all` | `iot-ble` + zephyr | full assessment + ZEPHYR HCI tests |

### Stage meaning

| Stage | What runs | Hardware |
|---|---|---|
| `doctor` | `scripts/check.py` (cross-platform environment checks) | none |
| `offline` | `1_build_packet.py` — CONNECT_IND builder + legality checks | none |
| `recon` | GATT enumeration, descriptor reads, `thor --explore-only` | host adapter |
| `sniffle` | Sniffle version/scanner/capture → `sniffle_capture.pcap` | TI Launchpad |
| `whad` | rogue-central, injector, MTU, manual ATT, crash vectors | ButteRFly nRF52840 |
| `host` | uptime monitor, connect/disconnect DoS, `thor` write fuzzer | host adapter |
| `sweyntooth` | 13 main + 12 extra SweynTooth PoCs | nRF52840 (ST firmware) |
| `zephyr` | ZEPHYR HCI adapter tests | nRF52840 (Zephyr firmware) |

### What is *not* launched by this runner

- **BlueToolkit / Sbleedy YAML exploits** — the YAMLs, modules and CLIs are
  shipped in `tools/`, but they are **not** launched by the BLE runner: they
  are configuration files for their own engines (`bluekit`, `sbleedyCLI`) and
  mostly target classic BR/EDR (BleedingTooth, BlueBorne, Braktooth,
  InternalBlue), needing an ESP32, a rooted Nexus 5, or a classic adapter.
  Run them directly; see `CLASSIC_BR_EDR_SCRIPTS.txt` and
  `HARDWARE_REQUIRED.txt`.
- **Firmware flashing** — the runner only *reports* which firmware the next
  stage needs; it never flashes.

---

## 11. Artifacts of a run

Every real run creates `ble-runs/<timestamp>/`:

| File | Contents |
|---|---|
| `runner.log` | complete multiplexed console log |
| `summary.json` | machine-readable results, hardware state, failing frames |
| `summary.md` | human-readable result table |
| `logs/<step>.log` | full output of each child script |
| `work/` | cwd for the core scripts (packet dumps, reports, checkpoints) |
| `sniffle_capture.pcap` | capture from the sniffle stage (when enabled) |

### When a script dies you see

```text
 FAILURE: whad/4_inject_raw
 exit code: 1
 reason   : exit code 1: KeyError: 'missing'

 FAILING FUNCTION
   .../4_inject_raw.py:58  in arm_trigger
      58 |     return strategies["missing"]()

 CALL STACK (outer -> inner)
     .../4_inject_raw.py:120  in <module>
     .../4_inject_raw.py:58   in arm_trigger

 LAST OUTPUT
    ...last 15 lines...
```

This is the fastest way to see whether the problem is in the target script,
the WHAD library, the dongle firmware, or a missing dependency.

---

## 12. Troubleshooting by OS

### All platforms

| Symptom | Fix |
|---|---|
| `TARGET` not found in the preflight scan | The device may use a private/random address or may not be advertising. Confirm the MAC with `bluetoothctl` (Linux) or `run.bat -l` + a scanner app. The run continues. |
| A step is skipped as MISSING but the dongle is plugged in | Run `--hw-check`; if the VID is custom, add `--force`. |
| SweynTooth steps all fail instantly | The dongle is still on WHAD/other firmware. Re-flash the SweynTooth driver, or use a second dongle with `--nrf-port`. |
| WHAD steps fail at `WhadDevice.create()` | Wrong firmware or transport. Try `--whad-port uart0` / `uart1`. |
| `SweynTooth py: FAILED` in the doctor | Old bundled Scapy + a very new Python. Recreate the venv with Python 3.10/3.11: `PYTHON=python3.10 ./setup-venv.sh`. The pycompat shim (`scripts/pycompat/`) is loaded automatically by the runner. |

### Windows

| Symptom | Fix |
|---|---|
| `run.bat` says "No Python found" | Install Python from python.org with **"Add to PATH"** ticked, or `set PYTHON=path\to\python.exe` first. |
| Dongle not detected | Device Manager → Ports (COM & LPT). If Windows shows it under "Other devices", install the **Nordic nRF52840 USB CDC** driver. Use `run.bat --hw-check` to list COM ports + USB IDs. |
| Wrong COM port picked automatically | Pass it explicitly: `--nrf-port COM7`, `--sniffle-port COM5`. |
| Host (recon) stages can't see the radio | Check that Bluetooth is enabled; Bleak uses WinRT. Virtual machines need a *passed-through* Bluetooth adapter, not just USB. |
| Garbled colors in an old console | Use Windows Terminal, or add `--no-color`. |
| `whad` stage misbehaves | Serial transport is supported, but the WHAD host stack is Linux-first. Prefer `run.bat --skip-stage whad --yes`. |

### Ubuntu / Debian

| Symptom | Fix |
|---|---|
| `DONGLE MISSING` though plugged in | `lsusb` should show `c0ff:eeee` or `1915:*`; run `--hw-check`; make sure ModemManager is stopped: `sudo systemctl stop ModemManager`. |
| `Device or resource busy` on `/dev/ttyACM0` | ModemManager grabbed it (see above) — also stop `brltty`. |
| `Permission denied` on serial | `sudo usermod -aG dialout $USER`, then log out/in. |
| Bleak can't scan | `sudo systemctl start bluetooth` and ensure `bluez` is installed. |
| `dbus` errors in recon | The venv includes `dbus-fast`; recreate it with `./setup-venv.sh`. |

### Arch

| Symptom | Fix |
|---|---|
| `Permission denied` on serial | Arch uses **uucp** (not dialout): `sudo usermod -aG uucp $USER`, then log out/in. |
| Old bundled Scapy fails to import | See the "SweynTooth py" row in the all-platforms table; recreate the venv with Python 3.10/3.11. |
| `python: module whad not found` | Create the venv first (`./setup-venv.sh`), then use `./run-all-ble.sh` which picks it up. |
| bluez missing tools | `sudo pacman -S bluez-utils` (provides `hcitool`, `bluetoothctl`). |

---

## 13. FAQ

**Q: Can I run this without any dongle?**
Yes — the `safe` profile (doctor → offline → recon) works with just your
PC's Bluetooth radio. Everything needing a dongle auto-skips.

**Q: Does it work on a VM?**
Host stages need a *Bluetooth adapter passed through to the VM* (USB
passthrough). Serial dongles (COM/ttyACM) pass through fine.

**Q: How do I make the folder fully self-contained?**
Run `./setup-venv.sh` (Linux) or `setup-venv.bat --windows` (Windows). The
folder then carries its own interpreter environment — nothing outside is
needed.

**Q: Where do results go?**
`ble-runs/<timestamp>/` — see [§11](#11-artifacts-of-a-run). The
`summary.md` is the report you share; `summary.json` is what you parse.

**Q: Where are the individual scripts documented?**
`SCRIPTS_GUIDE.md` explains what every BLE script does (with hardware,
flags and a run command), `SCRIPTS_BY_FUNCTION.md` is the numbered
one-line map, and `ble_scripts_report.txt` has the attack-use notes.
`./run-all-ble.sh -l` prints the same catalogue live.

**Q: Is firmware flashing included?**
No — by design. The runner only reports which firmware the next stage needs.
Use `nrfutil dfu` / the vendor tools yourself.

**Q: How do I update the package list?**
`requirements.txt` = minimal working set (Linux);
`requirements-windows.txt` = same for Windows; `requirements-freeze.txt` =
the exact original lab venv. Install with `--full` only if you need the
historical exactness.
