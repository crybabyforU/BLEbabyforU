# scripts/

The runner and the core lab scripts. Filenames are kept from the original lab
so the framework behaves exactly like it.

| File / folder | What it is |
|---|---|
| `run_all_ble.py` | **The runner.** Ordered execution, hardware checks, logging, summaries, failure diagnosis. Stdlib only. |
| `check.py` | Cross-platform environment doctor (Windows / Linux / macOS). |
| `check.sh` | Legacy bash doctor with deeper Linux checks. |
| `1_build_packet.py` … `15_manual_att.py` | Core BLE lab scripts (offline builder, WHAD injectors, ATT tools). |
| `ble_busy.py` | Host BLE connect/disconnect DoS. |
| `pairing_req_multiple.py` | Host BLE pairing/connection flood. |
| `ble_connection_time_checker.py` | Uptime / reboot monitor. |
| `getting-all-details-of-ble.py` | GATT enumeration. |
| `read_descriptors.py` | Descriptor reader. |
| `thor.py` | GATT explorer **and** write fuzzer (two runner modes). |
| `oooooooooooo.py` | Own-packet connector **and** length fuzzer (two runner modes). |
| `own_packet_full.py` | Full rogue-central pipeline. |
| `sweyntooth_crash.py` | Malformed CONNECT_IND crash vectors. |
| `pycompat/sitecustomize.py` | Shim that lets the old bundled Scapy import on newer Python. |
| `by_function/` | Optional symlinks named `<number>__<function>`; see its README. |

## Run through the runner, not directly

```bash
../run-all-ble.sh -l                 # catalogue and stable numbers
../run-all-ble.sh -N 2 --yes         # run entry #2
../run-all-ble.sh -N 36 --yes        # thor write-fuzzer mode
```

The runner sets the correct working directory, timeout, Python interpreter and
hardware check for each tool. Running a tool directly can fail because some
scripts expect their own `tools/...` directory.

## Documentation

- `../docs/SCRIPTS_GUIDE.md` — what every entry does
- `../docs/SCRIPTS_BY_FUNCTION.md` — number → function → hardware
- `../docs/RUNNER_README.md` — runner internals and flags
