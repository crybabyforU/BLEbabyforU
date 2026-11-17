# crybabyforu

A portable, **cross-platform** BLE security-testing framework — runner,
scripts and the libraries they need. Works on Windows, Ubuntu/Debian and Arch.

> ⚠️ Most steps are DoS / crash / fuzzing tooling. Use only on devices you own
> or have explicit written authorization to test.

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

`thor.py` and `oooooooooooo.py` each appear twice because they run in two
modes. `-l` marks those rows with `†` and prints both `-N` numbers.

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
