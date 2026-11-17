# Documentation index

All guides and catalogs for `crybabyforu` live in this folder.

## Start here

| Document | What it covers |
|---|---|
| `MASTER_DOCUMENTATION.md` | Install on Windows / Ubuntu / Arch, hardware guide, full command reference, troubleshooting |
| `RUNNER_README.md` | Runner internals: profiles, stages, flags, artifacts, exit codes |
| `SCRIPTS_GUIDE.md` | What every BLE script does, with hardware, flags and a run command |

## Script reference

| Document | What it covers |
|---|---|
| `SCRIPTS_GUIDE.md` | Detailed per-script guide (67 entries) |
| `SCRIPTS_BY_FUNCTION.md` | Number → function → script → hardware table |
| `HOW_TO_USE_SCRIPTS.txt` | Long-form usage examples, direct commands and runner notes |
| `SCRIPTS_REPORT.txt` | Per-script functionality and attack-use notes |

## Catalogs and inventory

| Document | What it covers |
|---|---|
| `ALL_SCRIPTS_ATTACKS.txt` | Master one-line inventory: script, type, attack, device |
| `BLE_SCRIPTS.txt` | BLE-only inventory including bundled BLE modules |
| `BLE_ATTACK_SCRIPTS_LIST.txt` | BLE attack-oriented list |
| `CLASSIC_BR_EDR_SCRIPTS.txt` | Classic BR/EDR YAML/module inventory (not launched by the BLE runner) |
| `HARDWARE_REQUIRED.txt` | Dongles, boards, firmware and what each attack needs |
| `SCRIPTS_FULL_DETAILS.txt` | Long per-script breakdown: PATH/TYPE/WHAT/USE/DEVICE/DEPS/OUTPUT |
| `SCRIPTS_MASTER_REPORT.md` | Earlier overall lab report |

## Counting rule

`./run-all-ble.sh -l` lists **67 catalogue entries = 65 unique files**.
Two files have two modes, so each mode has its own `-N` number:

| # | File | Mode |
|---:|---|---|
| 5 | `scripts/thor.py` | GATT explore only |
| 27 | `scripts/oooooooooooo.py` | packet connector |
| 28 | `scripts/oooooooooooo.py` | length fuzzer (`-l`) |
| 36 | `scripts/thor.py` | write fuzzer |

`-l` marks those rows with `†` and prints the same footnote.
