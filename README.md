# crybabyforu

A portable, **cross-platform** copy of the BLE lab runner, its scripts, and
the libraries those scripts actually need — Windows, Ubuntu, and Arch.

```bash
# Linux / macOS
./run-all-ble.sh -l                 # 67 entries (65 unique files), function + hardware
./run-all-ble.sh -N 2 --yes         # run script #2 (packet builder)
./run-all-ble-no-whad.sh -l         # 49 entries, no WHAD
./run-all-ble.sh --hw-check         # dongle / board report

# Windows (cmd or PowerShell)
run.bat --hw-check
run.bat -l
run.bat --profile safe --target C0:00:00:41:73:AC
```

`thor.py` and `oooooooooooo.py` each appear twice because they have two
modes (explore/fuzz and connect/fuzz). `-l` marks them with `†` and lists both
`-N` numbers.

**Start here: `MASTER_DOCUMENTATION.md`** — install guides for Windows /
Ubuntu / Arch, hardware guide, full command reference, and per-OS
troubleshooting. `RUNNER_README.md` has the deep runner internals,
`SCRIPTS_GUIDE.md` explains what every script does, and
`SCRIPTS_BY_FUNCTION.md` is the numbered one-line script map.

---

## What is in here

```text
crybabyforu/
├── run-all-ble.sh                  # normal runner (Linux/macOS)
├── run.bat                         # normal runner (Windows)
├── run-all-ble-no-whad.sh          # runner without the WHAD stage
├── setup-venv.sh                   # create a local Python venv (Linux/macOS)
├── setup-venv.bat                  # create a local Python venv (Windows)
├── setup-linux.sh                  # Ubuntu/Arch: system packages + groups
├── requirements.txt                # Python packages needed (Linux)
├── requirements-windows.txt        # Python packages needed (Windows)
├── requirements-freeze.txt         # exact package list from the lab venv
├── MASTER_DOCUMENTATION.md         # ← the master doc (start here)
├── RUNNER_README.md                # full usage / troubleshooting
├── SCRIPTS_GUIDE.md                # what every BLE script does (detailed)
├── SCRIPTS_BY_FUNCTION.md          # number -> function -> script -> hardware
├── HOW_TO_USE_SCRIPTS.txt          # per-script usage examples (long form)
├── scripts/                        # all lab scripts + runner + doctor + pycompat
│   ├── check.py                    # cross-platform environment doctor
│   └── by_function/                # optional symlinks named by function
└── tools/
    ├── Sniffle/                    # Sniffle CLI + sniffle package + firmware
    ├── sweyntooth_bluetooth_low_energy_attacks/
    │   ├── libs/                   # bundled old Scapy, colorama, SMP server
    │   ├── drivers/                # NRF52 serial driver used by the PoCs
    │   ├── extras/                 # extra SweynTooth PoCs
    │   └── *.py                    # main SweynTooth PoCs
    ├── BlueToolkit-upstream/       # classic BR/EDR YAML exploits + bluekit
    ├── SbleedyGonzales/            # BLE + classic exploit modules + sbleedyCLI
    ├── ZEPHYR/pylol/               # Zephyr HCI test scripts
    └── whadbro/                    # older WHAD prototype scripts
```

The original filenames are kept so the framework is an exact working copy.
The two-word functional names are shown by `-l` and in
`SCRIPTS_BY_FUNCTION.md`.

---

## Python environment

The wrapper uses, in order:

1. `crybabyforu/venv/bin/python` (if present)
2. `../venv/bin/python` (the original lab venv)
3. `$PYTHON` or `python3`

On this machine it currently uses the parent lab venv, so everything works
immediately. To make this folder independent:

```bash
./setup-venv.sh
# or, if your default python is too new:
PYTHON=python3.10 ./setup-venv.sh
```

`requirements.txt` is the minimal working set. `requirements-freeze.txt` is
the exact list from the original lab venv.

---

## Deliberately not copied

These are large or not used by the BLE runner:

- `venv/` and the per-tool `venv/` folders (use `setup-venv.sh` instead).
- `.git/`, `__pycache__/`, logs and capture output from old runs.
- The per-tool virtualenvs inside `tools/BlueToolkit-upstream/` and
  `tools/SbleedyGonzales/`, plus their `results/` folders. The exploit YAMLs,
  modules and CLIs themselves **are** included; see `RUNNER_README.md` for
  why the BLE runner does not launch them automatically.

The tools were copied with their own libraries included, so SweynTooth's
bundled Scapy, the Sniffle Python package, and the NRF52 serial driver do not
need to be installed separately.

---

## Safety

Most steps are DoS / crash / fuzzing tooling. Use only on devices you own or
have explicit written authorization to test. Destructive steps require
`--yes`; missing hardware steps are skipped unless you add `--force`.
