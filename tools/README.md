# Bundled tools

These are the external tool suites the lab scripts use. Only the first three
are launched by `run-all-ble.sh` / `run.bat`; the classic suites are included
for completeness and must be run through their own CLIs.

| Directory | What it is | Runner stage | Upstream |
|---|---|---|---|
| `Sniffle/` | TI CC13xx/CC26xx sniffer CLI + firmware | `sniffle` | <https://github.com/nccgroup/Sniffle> |
| `sweyntooth_bluetooth_low_energy_attacks/` | SweynTooth BLE PoCs (13 main + 12 extra) + bundled old Scapy | `sweyntooth` | <https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks> |
| `ZEPHYR/pylol/` | Zephyr HCI / BlueZ D-Bus test scripts | `zephyr` | Zephyr project samples |
| `whadbro/` | Older WHAD prototype scripts | `whad` (duplicates) | local lab prototypes |
| `BlueToolkit-upstream/` | Classic BR/EDR YAML exploit engine (`bluekit`) | **not launched** | <https://github.com/sgxgsx/BlueToolkit> |
| `SbleedyGonzales/` | BLE + classic exploit modules and `sbleedyCLI` | **not launched** | <https://github.com/b0rdst31n/SbleedyGonzales> |

## BlueToolkit / Sbleedy

The exploit YAMLs, modules, helpers and CLIs are copied so nothing is missing
from the lab, but they are deliberately **not** wired into the BLE runner:

- they are driven by their own engines (`bluekit`, `sbleedyCLI`), not by
  `run_all_ble.py`;
- most of their checks target classic BR/EDR and need an ESP32/Braktooth
  board, a rooted Nexus 5 (InternalBlue), or a classic Bluetooth adapter;
- their per-tool virtualenvs and local `results/` output were not copied
  (they are large and machine-specific).

Use them directly after installing their own requirements:

```bash
cd tools/BlueToolkit-upstream   # see install.sh and README.md
cd tools/SbleedyGonzales        # see README.md, arch-req.sh, sbleedy_installer.sh
```

The classic attack catalogue is in `../CLASSIC_BR_EDR_SCRIPTS.txt`; the full
hardware matrix is in `../HARDWARE_REQUIRED.txt`.

## Licenses

Each upstream directory keeps its own license/notice files. Check them before
redistributing or using the code commercially.
