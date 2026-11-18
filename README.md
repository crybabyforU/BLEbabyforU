# crybabyforu — BLE Security Testing Lab

A portable, **cross-platform** Bluetooth Low Energy security-testing framework —
runner, attack scripts and the libraries they need. Works on Windows,
Ubuntu/Debian and Arch.

It bundles **67 runnable catalogue entries (65 unique files)** covering
reconnaissance, sniffing, connection hijacking, DoS/crash PoCs, GATT fuzzing,
SweynTooth protocol-compliance attacks and Zephyr/BlueZ HCI tests, plus the
classic BR/EDR suites **BlueToolkit** and **SbleedyGonzales**.

---

## ⚠️ AUTHORIZED TESTING ONLY

> **This project is for education, research and authorized security testing
> only.** Several scripts are deliberately destructive: they can crash, hang,
> brick or permanently deny service to the device under test. You are
> responsible for how you use them.

### Rules of engagement

1. **Only test hardware you own**, or devices for which you hold **explicit
   written permission** from the owner (a signed scope/authorization letter).
2. **Never** point these scripts at public infrastructure, strangers' phones,
   wearables, medical devices, vehicles, locks or any device you do not control.
3. **Work in an isolated lab.** Use a shielded/benched setup, keep transmit
   power low, and keep the target and your test hardware physically close.
4. **Accept the risk of damage.** DoS and crash PoCs can corrupt firmware,
   clear pairing bonds or leave a device unusable. Back up the target and know
   how to recover/reflash it *before* you start.
5. **Obey the law.** Unauthorized access to computer systems and radio
   equipment is a criminal offence in most countries (e.g. CFAA, UK Computer
   Misuse Act, India IT Act, EU NIS2/national laws). Radio transmission is also
   regulated — check your local spectrum rules.
6. **Handle captured data responsibly.** PCAPs and GATT dumps can contain
   identifiers, keys or personal data. Do not publish or share them without
   consent.
7. **Do not redistribute this toolkit as an attack service.** If you fork it,
   keep this notice and the upstream licenses intact.

### Pre-flight checklist

- [ ] Written authorization / ownership confirmed
- [ ] Target list and MAC addresses documented
- [ ] Target firmware backup and recovery method ready
- [ ] Lab is isolated; no production or third-party devices in range
- [ ] Stop conditions agreed (e.g. stop on first crash)
- [ ] Runner used with `--dry-run` first, and `--yes` only when intended

The authors and contributors accept **no liability** for misuse or damage.
If you do not agree with these terms, do not use this repository.

---

## Quick start

```bash
# Linux / macOS
./run-all-ble.sh -l                 # catalogue: 67 entries (65 unique files)
./run-all-ble.sh -N 2 --yes         # run entry #2 (offline packet builder)
./run-all-ble-no-whad.sh -l         # catalogue without the WHAD stage: 49 entries
./run-all-ble.sh --hw-check         # dongle / board report
./run-all-ble.sh --profile safe --target C0:00:00:41:73:AC

# Windows (cmd or PowerShell)
run.bat --hw-check
run.bat -l
run.bat --profile safe --target C0:00:00:41:73:AC
```

Useful runner options:

```bash
./run-all-ble.sh -N 15 --target <MAC> --dry-run     # show the command, run nothing
./run-all-ble.sh -N 15 --target <MAC> --yes         # allow destructive steps
./run-all-ble.sh --profile safe --target <MAC>      # recon + non-destructive only
./run-all-ble.sh --include optional                 # also run optional/setup steps
./run-all-ble.sh --include duplicates               # also run older prototype copies
./run-all-ble.sh --force                            # run even if hardware is missing
```

`thor.py` and `oooooooooooo.py` each appear twice because they run in two
modes. `-l` marks those rows with `†` and prints both `-N` numbers.

Every real run creates `ble-runs/<timestamp>/` containing `runner.log`,
`summary.json`, `summary.md` and one log per step under `logs/`.

---

## Attack coverage at a glance

| Category | Entries | What it covers |
|---|---|---|
| Environment / offline | 1–2 | Doctor, byte-exact CONNECT_IND builder with spec checks |
| Reconnaissance | 3–5 | GATT tree enumeration, descriptor reads, safe explore |
| Sniffing (Sniffle) | 6–14 | Firmware check, passive scan, PCAP capture, fake advertiser/central, relay |
| WHAD rogue central / injection | 15–32 | CONNECT_IND injection, connection takeover, MTU tricks, low-level ATT, length fuzzer, crash vectors |
| Host-side DoS / fuzzing | 33–36 | Uptime monitor, connection flood, pairing flood, GATT write fuzzer |
| SweynTooth core PoCs | 37–49 | 13 device-specific Link-Layer/pairing crashes and overflows |
| SweynTooth extra PoCs | 50–62 | 12 specification-violation and overflow variants + PoC selector |
| Zephyr / BlueZ HCI | 63–67 | HCI probe, advertisement and GATT registration, GATT dump, bleak end-to-end test |
| Classic BR/EDR (bundled) | — | BlueToolkit + SbleedyGonzales: BlueBorne, BleedingTooth, Braktooth, KNOB, etc. |

---

## Complete script catalogue

Run any entry with `./run-all-ble.sh -N <number>`. Hardware tags are explained
in [Hardware required](#hardware-required).

### 1–2 · Setup and offline tooling

| # | Script | What it does | Hardware |
|---:|---|---|---|
| 1 | `check.py` | Cross-platform environment doctor: Python version, packages (bleak, whad, pyserial, scapy), BlueZ/WinRT/CoreBluetooth, USB VID:PIDs, serial ports, ModemManager, serial group, Wireshark, nrfutil, adb, ARM GCC. Warnings do not fail the run. | none |
| 2 | `1_build_packet.py` | Builds a byte-exact 36-byte `CONNECT_IND` with chosen Access Address, CRCInit, interval, hop, SCA, timeout and channel map, then validates it against the Bluetooth spec (AA rules, hop 5–16, timeout rule, WinOffset ≤ interval). No radio needed. | none |

### 3–5 · Reconnaissance (host adapter)

| # | Script | What it does | Hardware |
|---:|---|---|---|
| 3 | `getting-all-details-of-ble.py` | Walks the full GATT tree with Bleak: services, characteristics, handles, properties and descriptors, printing values as bytes, hex and UTF-8. The main attack-surface map. | HOST, TARGET |
| 4 | `read_descriptors.py` | Reads raw GATT descriptor bytes at fixed handles (default 19 and 22) and prints repr + ASCII. Checks for data leaks or unauthenticated reads. | HOST, TARGET |
| 5† | `thor.py` (explore mode) | Enumerates services, characteristics and properties only — no writes. Safe first look at what the device exposes. | HOST, TARGET |

### 6–14 · Sniffing and link control with Sniffle (TI Launchpad)

| # | Script | What it does | Hardware |
|---:|---|---|---|
| 6 | `version_check.py` | Asks the Sniffle firmware for its API version and reports host/firmware compatibility. | SNIFFLE |
| 7 | `uart_test.py` | Exercises the serial/UART link to the Launchpad (echo and latency). | SNIFFLE |
| 8 | `scanner.py` | Passive BLE scan through the sniffer; prints advertising and scan-response packets, including traffic the host stack filters. | SNIFFLE |
| 9 | `sniff_receiver.py` | Captures BLE traffic for the target to `sniffle_capture.pcap` for Wireshark analysis. Proof of what actually went on-air. | SNIFFLE, TARGET |
| 10 | `reset.py` | Resets the Sniffle firmware state after a failed or interrupted capture. | SNIFFLE |
| 11 | `advertiser.py` | Makes the Sniffle board advertise as a fake peripheral to test scanners, whitelists and central behaviour. | SNIFFLE |
| 12 | `initiator.py` | Makes the Sniffle board act as a central and connect to the target, bypassing the host stack. | SNIFFLE, TARGET |
| 13 | `relay_master.py` | Master half of a BLE relay between two links (man-in-the-middle style setup). | SNIFFLE, TARGET |
| 14 | `relay_slave.py` | Slave half of the relay; pairs with `relay_master.py`. | SNIFFLE, TARGET |

### 15–32 · WHAD rogue central, injection and takeover (nRF52840 dongle)

| # | Script | What it does | Hardware |
|---:|---|---|---|
| 15 | `2_send_packet.py` | Rogue central: connects while choosing Access Address, CRCInit, interval, hop and channel map, then proves GATT still works over attacker-chosen link parameters. | DONGLE, TARGET |
| 16 | `4_inject_raw.py` | Arms the injector with four trigger strategies and fires a raw `CONNECT_IND` inside the advertising inter-frame space; watches 30 s for takeover. | DONGLE, TARGET |
| 17 | `5_scan_then_inject.py` | Confirms the target is advertising, reopens the dongle as an injector, arms AdvA triggers and watches for connection takeover. | DONGLE, TARGET |
| 18 | `6_scan_inject_final.py` | Low-latency injection race: continuous RX counts advertisements and arms triggers without reopening the dongle, removing reopen delay. | DONGLE, TARGET |
| 19 | `7_connect_lifecycle.py` | Injects `CONNECT_IND` on sight and measures advertisement silence — a long gap suggests the peripheral accepted the link. | DONGLE, TARGET |
| 20 | `8_trigger_sweep.py` | Injector calibration: sweeps AdvA pattern byte offsets 0–30 to find where reactive injection fires reliably. | DONGLE, TARGET |
| 21 | `10_prepare_rootcause.py` | Root-cause probe for failed injection: wraps packets as BTLE/BTLE_DATA and compares manual TX vs ReceptionTrigger. | DONGLE, TARGET |
| 22 | `11_max_fidelity.py` | Maximum-fidelity rogue link: claims `InitA FF:EE:DD:CC:BB:AA`, injects `CONNECT_IND` five times, connects with custom LLData and enumerates GATT. | DONGLE, TARGET |
| 23 | `12_ab_diagnose.py` | A/B diagnosis: default vs custom LLData and 80/160/320 ms interval sweep to find which combination kills or keeps the link. | DONGLE, TARGET |
| 24 | `13_death_autopsy.py` | Post-mortem: dumps Link-Layer control PDUs and decodes HCI termination reasons while the link idles. | DONGLE, TARGET |
| 25 | `14_mtu_responder.py` | Intercepts `ATT_EXCHANGE_MTU_REQ` and answers with MTU 247 to stop the peripheral's `LL_TERMINATE_IND` and keep a rogue link alive. | DONGLE, TARGET |
| 26 | `15_manual_att.py` | Builds L2CAP and ATT frames by hand inside LL data PDUs and performs service/characteristic discovery below the host GATT stack — low-level ATT fuzzing. | DONGLE, TARGET |
| 27† | `oooooooooooo.py` (connect mode) | Connects using the project's own crafted packet, without the fuzz loop. | DONGLE, TARGET |
| 28† | `oooooooooooo.py` (fuzz mode) | Length-field truncation fuzzer: declares N payload bytes while truncating the buffer (CC2540 CVE-2019-19194 style), using advertisement gaps as crash oracle. | DONGLE, TARGET |
| 29 | `own_packet_full.py` | Eight-step rogue-central pipeline: dongle audit, scan, packet build/verify, raw inject, InitA spoof, custom connect, MTU pump and manual GATT discovery. | DONGLE, TARGET |
| 30 | `sweyntooth_crash.py` | Fires nine named malformed `CONNECT_IND` vectors (truncated lengths, iv0, to0, hop0, over-247, valid-34) with an advertisement-gap crash oracle. | DONGLE, TARGET |
| 31 | `dos.py` | Early WHAD prototype connection-flood/saturation attack; kept for reference (ancestor of `ble_busy.py`). | DONGLE, TARGET |
| 32 | `sooooooooo.py` | 773-line WHAD prototype and ancestor of `own_packet_full.py`: packet build, inject, custom connect, MTU handling. | DONGLE, TARGET |

### 33–36 · Host-side monitoring, DoS and GATT fuzzing

| # | Script | What it does | Hardware |
|---:|---|---|---|
| 33 | `ble_connection_time_checker.py` | Uptime/crash monitor: holds a link, logs exact connect/disconnect times and reconnects every 2 s so watchdog reboots become visible. | HOST, TARGET |
| 34 | `ble_busy.py` | Connection-flood DoS: infinite fast connect/disconnect loop (0.5 s timeout, 0.05 s gap) to keep the Link Layer busy and block legitimate centrals. | HOST, TARGET |
| 35 | `pairing_req_multiple.py` | Pairing/connection flood: rapid connect/pair requests until the first success, then holds the link and silently reconnects if dropped. | HOST, TARGET |
| 36† | `thor.py` (write-fuzz mode) | GATT write fuzzer: explores the device, then sweeps write lengths 1 → MTU-3 on every writable characteristic with resume, reconnect, hang detection, notification capture and ATT error classification. | HOST, TARGET |

### 37–49 · SweynTooth core PoCs (nRF52840 SweynTooth firmware)

| # | Script | What it does | Hardware |
|---:|---|---|---|
| 37 | `CC2640R2_public_key_crash.py` | Sends an invalid public key during LE pairing to crash the TI CC2640R2 stack. | NRF52-ST, TARGET |
| 38 | `CC_connection_req_crash.py` | Malformed `CONNECT_REQ` length crashes TI CC2540/CC2541 controllers (CVE-2019-19194 family). | NRF52-ST, TARGET |
| 39 | `DA14580_exploit_att_crash.py` | Malformed ATT requests / ATT exchange crash the Dialog DA14580 stack. | NRF52-ST, TARGET |
| 40 | `DA14680_exploit_silent_overflow.py` | Crafted L2CAP/SMP traffic triggers a silent memory overflow in the Dialog DA14680. | NRF52-ST, TARGET |
| 41 | `esp32_hci_desync.py` | Desynchronizes the ESP32 HCI/Link-Layer state machine to hang or crash the controller. | NRF52-ST, TARGET |
| 42 | `invalid_channel_map.py` | Sends `LL_CHANNEL_MAP_IND` with an illegal channel map to crash or wedge the link layer. | NRF52-ST, TARGET |
| 43 | `link_layer_length_overflow.py` | Oversized Link-Layer payload length triggers buffer overflow / memory corruption. | NRF52-ST, TARGET |
| 44 | `llid_dealock.py` | Mismatched LLID values deadlock the Link-Layer state machine. | NRF52-ST, TARGET |
| 45 | `Microchip_invalid_lcap_fragment.py` | Invalid L2CAP fragment crashes Microchip BLE controllers. | NRF52-ST, TARGET |
| 46 | `sequential_att_deadlock.py` | Sequential ATT requests deadlock the ATT server and freeze the connection. | NRF52-ST, TARGET |
| 47 | `Telink_key_size_overflow.py` | Oversized encryption key size during SMP overflows the Telink stack. | NRF52-ST, TARGET |
| 48 | `Telink_zero_ltk_installation.py` | Installs a zero-length LTK during pairing, breaking encryption on Telink devices. | NRF52-ST, TARGET |
| 49 | `zephyr_invalid_sequence.py` | Out-of-sequence Link-Layer PDUs crash or hang Zephyr-based controllers. | NRF52-ST, TARGET |

### 50–62 · SweynTooth extra PoCs, compliance violations and selector

| # | Script | What it does | Hardware |
|---:|---|---|---|
| 50 | `anomaly_unexpected_encryption_start.py` | Starts encryption at an unexpected point in the pairing sequence to test state-machine handling. | NRF52-ST, TARGET |
| 51 | `CC2540_connection_req_crash_truncated.py` | Sends a physically truncated `CONNECT_REQ` to crash the TI CC2540. | NRF52-ST, TARGET |
| 52 | `CC2540_truncated_connection_success.py` | Sends a truncated `CONNECT_IND` that the CC2540 wrongly accepts — a spec violation. | NRF52-ST, TARGET |
| 53 | `DA14680_att_mtu_length_114_silent_overflow_accepted.py` | ATT MTU length 114 is accepted and silently overflows the DA14680 buffer. | NRF52-ST, TARGET |
| 54 | `DA14680_att_mtu_length_5_malformed_accepted.py` | Malformed ATT MTU length-5 request is wrongly accepted by the DA14680. | NRF52-ST, TARGET |
| 55 | `DA14680_att_read_100_silent_overflow_crash.py` | ATT read of 100 bytes triggers a silent overflow and crash on the DA14680. | NRF52-ST, TARGET |
| 56 | `DA14680_truncated_l2cap_crash.py` | Truncated L2CAP frame crashes the DA14680 stack. | NRF52-ST, TARGET |
| 57 | `Microchip_and_others_non_compliant_connection.py` | Sends a non-compliant connection request that Microchip and other controllers wrongly accept. | NRF52-ST, TARGET |
| 58 | `non_compliance_data_during_encryption_setup.py` | Sends data PDUs during encryption setup to test whether ordering is enforced. | NRF52-ST, TARGET |
| 59 | `non_compliance_dhcheck_skip.py` | Skips the Diffie-Hellman check during LE Secure Connections pairing — MitM / information-leak testing. | NRF52-ST, TARGET |
| 60 | `non_compliance_multiple_version.py` | Sends multiple Link-Layer version exchanges to test state handling. | NRF52-ST, TARGET |
| 61 | `non_compliance_nonzero_ediv_rand.py` | Sends non-zero EDIV/RAND where the spec expects zero. | NRF52-ST, TARGET |
| 62 | `knob_tester_ble.py` | Selector that reruns a chosen subset of the SweynTooth BLE pairing/Link-Layer variants. | NRF52-ST, TARGET |

### 63–67 · Zephyr HCI, BlueZ D-Bus and end-to-end tests

| # | Script | What it does | Hardware |
|---:|---|---|---|
| 63 | `nrf-api-check.py` | Probes the nRF HCI adapter and host commands needed by the Zephyr scripts. Defaults to `hci1`; override with `--hci`. | ZEPHYR-HCI |
| 64 | `adv-checker.py` | Registers a BlueZ D-Bus advertisement on the Zephyr HCI adapter and verifies it is accepted. | ZEPHYR-HCI |
| 65 | `adv-connect-wireshark.py` | Advertises, waits for a central to connect, then dumps GATT services, characteristics and handles. | ZEPHYR-HCI |
| 66 | `connect-gatt-char.py` | Registers a GATT service and characteristic on the Zephyr HCI adapter through BlueZ D-Bus. | ZEPHYR-HCI |
| 67 | `ble_connect.py` | Connects with bleak and writes a UTF-8 payload to a fixed characteristic UUID — end-to-end host BLE sanity test. | HOST, TARGET |

### Multi-mode files (†)

| # | File | Mode |
|---:|---|---|
| 5 | `scripts/thor.py` | GATT explore only (no writes) |
| 36 | `scripts/thor.py` | GATT write fuzzer |
| 27 | `scripts/oooooooooooo.py` | Packet connector |
| 28 | `scripts/oooooooooooo.py` | Length-field fuzzer (`-l`) |

**67 catalogue entries = 65 unique files.** Everything else appears once.

---

## Harnessed but not launched: classic BR/EDR suites

These are copied with their own engines and are **not** wired into the BLE
runner. Run them through their own CLIs. Full catalogue:
`docs/CLASSIC_BR_EDR_SCRIPTS.txt`.

| Toolkit | Focus | Example attacks | Needs |
|---|---|---|---|
| `tools/BlueToolkit-upstream/` | Classic BR/EDR YAML exploits | BlueBorne (CVE-2017-0785/1000250/1000251), BleedingTooth (CVE-2020-12351/12352/24490), Braktooth baseband/LMP DoS and SDP/LMP overflows, KNOB, BIAS and more | HOST-BR adapter, ESP32 (Braktooth), rooted Nexus 5 or CYW20735 (InternalBlue) |
| `tools/SbleedyGonzales/` | BLE + classic exploit modules | BLE pairing/SMP and GATT abuse modules, classic discovery/exploit helpers, `sbleedyCLI` engine | Host BLE/BR adapter, optional ESP32/InternalBlue |

---

## Hardware required

| Tag | Hardware | Used by |
|---|---|---|
| `HOST` | Your PC's built-in/USB BLE adapter (BlueZ on Linux, WinRT on Windows, CoreBluetooth on macOS) | 3–5, 33–36, 67 |
| `DONGLE` | WHAD ButteRFly nRF52840 USB dongle | 15–32 |
| `NRF52-ST` | nRF52840 flashed with the SweynTooth driver firmware | 37–62 |
| `SNIFFLE` | TI CC1352/CC26x2 Launchpad with Sniffle firmware | 6–14 |
| `ZEPHYR-HCI` | nRF52840 flashed with Zephyr USB-HCI firmware | 63–66 |
| `TARGET` | The BLE peripheral under test | most entries |

Missing hardware is skipped automatically; add `--force` to run anyway.
Firmware flashing, udev rules and dongle setup are covered in
`docs/HARDWARE_REQUIRED.txt` and `docs/MASTER_DOCUMENTATION.md`.

---

## Folder structure

```text
crybabyforu/
├── README.md                    # you are here
├── run-all-ble.sh               # normal runner (Linux / macOS)
├── run-all-ble-no-whad.sh       # runner without the WHAD stage
├── run.bat                      # normal runner (Windows)
├── setup-venv.sh                # create a local Python venv (Linux / macOS)
├── setup-venv.bat               # create a local Python venv (Windows)
├── setup-linux.sh               # Ubuntu/Arch system packages + groups (sudo)
├── requirements.txt             # Python packages (Linux)
├── requirements-windows.txt     # Python packages (Windows)
├── requirements-freeze.txt      # exact package list from the original lab venv
│
├── docs/                        # every guide and catalog (start with docs/README.md)
│   ├── README.md                # documentation index
│   ├── MASTER_DOCUMENTATION.md  # install, hardware, full command reference
│   ├── RUNNER_README.md         # runner internals, profiles, troubleshooting
│   ├── SCRIPTS_GUIDE.md         # what every BLE script does
│   ├── SCRIPTS_BY_FUNCTION.md   # number → function → script → hardware
│   ├── HOW_TO_USE_SCRIPTS.txt   # long-form usage examples
│   ├── ALL_SCRIPTS_ATTACKS.txt  # master attack inventory
│   ├── BLE_SCRIPTS.txt          # BLE-only inventory
│   ├── BLE_ATTACK_SCRIPTS_LIST.txt
│   ├── CLASSIC_BR_EDR_SCRIPTS.txt
│   ├── HARDWARE_REQUIRED.txt    # dongles, boards and firmware
│   ├── SCRIPTS_FULL_DETAILS.txt # per-script PATH/WHAT/USE/DEPS/OUTPUT
│   ├── SCRIPTS_REPORT.txt       # per-script attack-use notes
│   └── SCRIPTS_MASTER_REPORT.md # earlier overall report
│
├── scripts/                     # runner + core lab scripts
│   ├── README.md                # scripts folder guide
│   ├── run_all_ble.py           # THE RUNNER (stdlib only)
│   ├── check.py                 # cross-platform environment doctor
│   ├── check.sh                 # legacy bash doctor (Linux deep checks)
│   ├── 1_build_packet.py … 15_manual_att.py
│   ├── ble_busy.py, pairing_req_multiple.py, thor.py, …
│   ├── pycompat/                # old bundled-Scapy fix
│   └── by_function/             # optional functional-name symlinks
│
├── tools/                       # bundled tools (see tools/README.md)
│   ├── Sniffle/
│   ├── sweyntooth_bluetooth_low_energy_attacks/
│   ├── ZEPHYR/pylol/
│   ├── whadbro/
│   ├── BlueToolkit-upstream/    # classic BR/EDR (not launched by runner)
│   └── SbleedyGonzales/         # BLE + classic modules (not launched by runner)
│
└── ble-runs/                    # run artifacts (git-ignored)
    └── <timestamp>/             # runner.log, summary.json/md, logs/, work/
```

## Documentation

Start with **`docs/README.md`** for the full index. The most useful files:

| If you want to… | Read |
|---|---|
| Install and run it | `docs/MASTER_DOCUMENTATION.md` |
| Understand the runner internals | `docs/RUNNER_README.md` |
| Know what a script does | `docs/SCRIPTS_GUIDE.md` |
| See the numbered map | `docs/SCRIPTS_BY_FUNCTION.md` |
| Check hardware / firmware | `docs/HARDWARE_REQUIRED.txt` |
| See every attack | `docs/ALL_SCRIPTS_ATTACKS.txt` |
| Read per-script attack notes | `docs/SCRIPTS_REPORT.txt` |

## Safety controls in the runner

- **`destructive` steps require `--yes`.** Nothing crash/DoS-related fires by
  accident.
- **`--profile safe`** limits a sweep to recon and non-destructive entries.
- **Timeouts** stop long-running or hanging steps (`timeout-ok` means the stop
  is expected).
- **`--dry-run`** prints every command without executing it.
- **Hardware checks** skip steps whose dongle/board is missing (override with
  `--force`).
- **Everything is logged** to `ble-runs/<timestamp>/` for later review.

## Python environment

The launchers use, in order:

1. `crybabyforu/venv/bin/python` (if present)
2. `../venv/bin/python` (the original lab venv)
3. `$PYTHON` or `python3`

To make this folder fully independent:

```bash
./setup-venv.sh
# or, if your default Python is too new:
PYTHON=python3.10 ./setup-venv.sh
```

`requirements.txt` is the minimal working set; `requirements-freeze.txt` is
the exact original package list.

## What is included, what is not

**Launched by the runner:** the 67 catalogue entries — core BLE scripts,
Sniffle tools, SweynTooth PoCs, Zephyr HCI tests and the whadbro prototypes.

**Bundled but not launched:** BlueToolkit and SbleedyGonzales exploit
YAMLs/modules/CLIs. They are driven by their own engines, mostly target
classic BR/EDR, and are documented in `docs/CLASSIC_BR_EDR_SCRIPTS.txt`.
See `tools/README.md`.

**Not copied:** per-tool virtualenvs, `.git/`, `__pycache__/`, old logs and
target-specific `results/` folders. Run artifacts live in `ble-runs/` and are
git-ignored.

## Credits and licenses

This lab builds on the work of the upstream projects it bundles:

- [Sniffle](https://github.com/nccgroup/Sniffle) — NCC Group
- [SweynTooth](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks) — Matheus Garbelini et al.
- [BlueToolkit](https://github.com/sgxgsx/BlueToolkit)
- [SbleedyGonzales](https://github.com/b0rdst31n/SbleedyGonzales)
- Zephyr project HCI samples

Each upstream directory keeps its own license and notice files; review them
before redistribution or commercial use. The lab's own glue code is provided
as-is, without warranty, for authorized testing only.
