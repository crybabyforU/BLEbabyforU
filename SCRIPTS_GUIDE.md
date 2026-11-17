# BLE script guide — what every script does

This guide explains every script that `./run-all-ble.sh -l` can run in
`crybabyforu`. It is **BLE-only**; the bundled classic BR/EDR YAML suites
(BlueToolkit / Sbleedy) are described in `CLASSIC_BR_EDR_SCRIPTS.txt` and are
not launched by this runner.

> **67 entries = 65 unique files.** Two scripts run in two different modes and
> therefore appear twice in the catalogue: `thor.py` (#5 explore, #36 write
> fuzzer) and `oooooooooooo.py` (#27 packet connector, #28 length fuzzer).

> ⚠️ **Authorization required.** Most entries are DoS, crash, fuzzing or
> injection tooling. Use them only on devices you own or have explicit written
> permission to test. Destructive steps require `--yes`.

---

## How to run a script from this guide

Every heading has a catalogue number. Run that exact entry with:

```bash
./run-all-ble.sh -l                                  # see the live catalogue
./run-all-ble.sh -N 15 --target <MAC> --yes          # run entry #15
./run-all-ble.sh -N 15 --dry-run                     # show the command only
./run-all-ble.sh -N 15 --target <MAC> --yes --no-color
```

- `-N` uses the same numbering as `-l`, and hardware that is missing is
  skipped automatically unless you add `--force`.
- Every real run writes `ble-runs/<timestamp>/` with `runner.log`,
  `summary.json`, `summary.md` and `logs/<step>.log`.
- Prefer `-N` over running a script directly: it sets the right working
  directory, timeout, Python interpreter and hardware check.

### Hardware tags

| Tag | Meaning |
|---|---|
| `HOST` | your PC's BLE adapter (BlueZ / WinRT / CoreBluetooth) |
| `DONGLE` | WHAD ButteRFly nRF52840 USB dongle |
| `NRF52-ST` | nRF52840 flashed with the SweynTooth driver firmware |
| `SNIFFLE` | TI CC1352/CC26x2 Launchpad with Sniffle firmware |
| `ZEPHYR-HCI` | nRF52840 flashed with Zephyr USB-HCI firmware |
| `TARGET` | the BLE peripheral under test |

### Status flags

| Flag | Meaning |
|---|---|
| `destructive` | can crash, hang or deny service; `--yes` required |
| `long-running` | does not exit on its own; stopped by the timeout |
| `timeout-ok` | being stopped by the timeout is expected, not a failure |
| `optional` | utility/setup step, skipped unless `--include optional` |
| `duplicate` | older/bundled copy of another step; needs `--include duplicates` |
| `interactive` | needs a human at the keyboard |
| `not flagged` | the runner does not gate it behind `--yes`; it may still be offensive tooling |

---

## Quick picks by goal

| Goal | Start with |
|---|---|
| Is my machine ready? | #1 `check.py`, then `--hw-check` |
| Map services before attacking | #3, #4, #5 |
| Prove packets went on-air | #9 `sniff_receiver.py` |
| Take over a connection (WHAD) | #16, #17, #18, #29 |
| Crash / DoS the target | #28, #30, #34, #35, #36, then #37-#62 |
| Fuzz GATT writes | #36 `thor.py` |
| SweynTooth device-specific PoCs | #37-#62 |
| Zephyr HCI / BlueZ D-Bus tests | #63-#67 |

---

## Script reference


## Doctor & offline

### 1. `check.py` — environment check

- **Step id:** `doctor/check`
- **File:** `scripts/check.py`
- **Hardware:** `none`
- **Timeout:** 120s · **Flags:** not flagged

Cross-platform environment doctor. Checks the Python version and required packages (bleak, whad, pyserial, scapy), BlueZ/WinRT/CoreBluetooth availability, USB VID:PIDs, serial ports, ModemManager, serial group membership, and optional tools such as Wireshark, nrfutil, adb and arm-none-eabi-gcc. A non-zero exit is reported as WARN, not FAIL.

```bash
./run-all-ble.sh -N 1 --target <MAC>
```

### 2. `1_build_packet.py` — packet builder

- **Step id:** `offline/1_build_packet`
- **File:** `scripts/1_build_packet.py`
- **Hardware:** `none`
- **Timeout:** 30s · **Flags:** not flagged

Builds a byte-exact 36-byte CONNECT_IND with attacker-chosen Access Address, CRCInit, connection interval, hop increment, SCA, timeout and channel map, then runs Bluetooth-spec legality checks (AA rules, hop 5-16, timeout rule, WinOffset <= interval). Needs no radio at all.

```bash
./run-all-ble.sh -N 2 --target <MAC>
```


## Recon (host BLE adapter)

### 3. `getting-all-details-of-ble.py` — GATT enumeration

- **Step id:** `recon/getting-all-details-of-ble`
- **File:** `scripts/getting-all-details-of-ble.py`
- **Hardware:** `HOST, TARGET`
- **Timeout:** 90s · **Flags:** not flagged

Connects to the target with Bleak and walks the whole GATT tree: services, characteristics (UUID, handle, properties) and descriptors, printing readable values as bytes, hex and UTF-8. This is the main pre-attack attack-surface map.

```bash
./run-all-ble.sh -N 3 --target <MAC>
```

### 4. `read_descriptors.py` — descriptor reader

- **Step id:** `recon/read_descriptors`
- **File:** `scripts/read_descriptors.py`
- **Hardware:** `HOST, TARGET`
- **Timeout:** 60s · **Flags:** not flagged

Reads raw GATT descriptor bytes at fixed handles (default 19 and 22) and prints repr plus ASCII. Edit the handle list in the script for your device. Useful for checking whether descriptors leak data or allow unauthenticated reads.

```bash
./run-all-ble.sh -N 4 --target <MAC>
```

### 5. `thor.py` — GATT explore

- **Step id:** `recon/thor-explore`
- **File:** `scripts/thor.py`
- **Hardware:** `HOST, TARGET`
- **Timeout:** 180s · **Flags:** not flagged

Runs only the exploration half of thor.py: enumerates services, characteristics and properties without sending any writes. Safe first look at what the device exposes.

```bash
./run-all-ble.sh -N 5 --target <MAC>
```


## Sniffle (TI Launchpad sniffer)

### 6. `version_check.py` — firmware probe

- **Step id:** `sniffle/version_check`
- **File:** `tools/Sniffle/python_cli/version_check.py`
- **Hardware:** `SNIFFLE`
- **Timeout:** 30s · **Flags:** not flagged

Asks the Sniffle firmware on the TI Launchpad which API version it implements and reports host/firmware compatibility. Run this first when the sniffer misbehaves.

```bash
./run-all-ble.sh -N 6 --target <MAC>
```

### 7. `uart_test.py` — UART test

- **Step id:** `sniffle/uart_test`
- **File:** `tools/Sniffle/python_cli/uart_test.py`
- **Hardware:** `SNIFFLE`
- **Timeout:** 8s · **Flags:** long-running, timeout-ok

Exercises the serial/UART link to the Launchpad (echo and latency). It keeps running, so the runner stops it after the timeout on purpose (TIMEOUT-OK).

```bash
./run-all-ble.sh -N 7 --target <MAC>
```

### 8. `scanner.py` — passive scan

- **Step id:** `sniffle/scanner`
- **File:** `tools/Sniffle/python_cli/scanner.py`
- **Hardware:** `SNIFFLE`
- **Timeout:** 15s · **Flags:** long-running, timeout-ok

Passive BLE scan through the Sniffle sniffer. Prints advertising and scan-response packets without using the host Bluetooth adapter, so it also sees traffic the host stack would filter.

```bash
./run-all-ble.sh -N 8 --target <MAC>
```

### 9. `sniff_receiver.py` — pcap capture

- **Step id:** `sniffle/sniff_receiver`
- **File:** `tools/Sniffle/python_cli/sniff_receiver.py`
- **Hardware:** `SNIFFLE, TARGET`
- **Timeout:** 20s · **Flags:** long-running, timeout-ok

Captures BLE traffic for the target to ble-runs/<timestamp>/sniffle_capture.pcap, including advertisements. Open the pcap in Wireshark to prove what actually went on-air.

```bash
./run-all-ble.sh -N 9 --target <MAC>
```

### 10. `reset.py` — sniffer reset

- **Step id:** `sniffle/reset`
- **File:** `tools/Sniffle/python_cli/reset.py`
- **Hardware:** `SNIFFLE`
- **Timeout:** 20s · **Flags:** optional

Resets the Sniffle dongle/firmware state. Handy after a previous capture or test left the sniffer in a bad state.

```bash
./run-all-ble.sh -N 10 --target <MAC> --include optional
```

### 11. `advertiser.py` — fake advertiser

- **Step id:** `sniffle/advertiser`
- **File:** `tools/Sniffle/python_cli/advertiser.py`
- **Hardware:** `SNIFFLE`
- **Timeout:** 15s · **Flags:** long-running, timeout-ok, optional

Makes the Sniffle board act as a fake BLE peripheral and advertise. Used to test scanners, whitelists and central behaviour.

```bash
./run-all-ble.sh -N 11 --target <MAC> --include optional
```

### 12. `initiator.py` — fake initiator

- **Step id:** `sniffle/initiator`
- **File:** `tools/Sniffle/python_cli/initiator.py`
- **Hardware:** `SNIFFLE, TARGET`
- **Timeout:** 20s · **Flags:** long-running, timeout-ok, optional

Makes the Sniffle board act as a central and initiate a connection to the target. Used for controlled connection tests without the host stack.

```bash
./run-all-ble.sh -N 12 --target <MAC> --include optional
```

### 13. `relay_master.py` — relay master

- **Step id:** `sniffle/relay_master`
- **File:** `tools/Sniffle/python_cli/relay_master.py`
- **Hardware:** `SNIFFLE, TARGET`
- **Timeout:** 20s · **Flags:** long-running, timeout-ok, optional, interactive

Master side of a BLE relay between two links. Interactive/optional: needs two radios or a sniffer plus a controller.

```bash
./run-all-ble.sh -N 13 --target <MAC> --include optional --include interactive
```

### 14. `relay_slave.py` — relay slave

- **Step id:** `sniffle/relay_slave`
- **File:** `tools/Sniffle/python_cli/relay_slave.py`
- **Hardware:** `SNIFFLE, TARGET`
- **Timeout:** 20s · **Flags:** long-running, timeout-ok, optional

Slave side of a BLE relay between two links. Pairs with relay_master for a man-in-the-middle style relay setup.

```bash
./run-all-ble.sh -N 14 --target <MAC> --include optional
```


## WHAD / ButteRFly link-layer suite

### 15. `2_send_packet.py` — rogue central

- **Step id:** `whad/2_send_packet`
- **File:** `scripts/2_send_packet.py`
- **Hardware:** `DONGLE, TARGET`
- **Timeout:** 90s · **Flags:** not flagged

WHAD rogue central. Connects to the target while choosing the Access Address, CRCInit, connection interval, hop and channel map, then proves that GATT still works over the attacker-chosen link parameters.

```bash
./run-all-ble.sh -N 15 --target <MAC>
```

### 16. `4_inject_raw.py` — CONNECT_IND inject

- **Step id:** `whad/4_inject_raw`
- **File:** `scripts/4_inject_raw.py`
- **Hardware:** `DONGLE, TARGET`
- **Timeout:** 90s · **Flags:** not flagged

Arms the WHAD injector with four trigger strategies and fires a raw CONNECT_IND inside the advertising inter-frame space. Watches a 30-second window to see whether the target accepts the injected connection.

```bash
./run-all-ble.sh -N 16 --target <MAC>
```

### 17. `5_scan_then_inject.py` — scan inject

- **Step id:** `whad/5_scan_then_inject`
- **File:** `scripts/5_scan_then_inject.py`
- **Hardware:** `DONGLE, TARGET`
- **Timeout:** 120s · **Flags:** not flagged

First scans to confirm the target is advertising, then reopens the dongle as an injector, arms AdvA-based triggers and watches for the connection to be taken over.

```bash
./run-all-ble.sh -N 17 --target <MAC>
```

### 18. `6_scan_inject_final.py` — injection race

- **Step id:** `whad/6_scan_inject_final`
- **File:** `scripts/6_scan_inject_final.py`
- **Hardware:** `DONGLE, TARGET`
- **Timeout:** 120s · **Flags:** not flagged

Low-latency connection race: a single-instance continuous-RX loop counts target advertisements and arms triggers without reopening the dongle, which removes the reopen delay.

```bash
./run-all-ble.sh -N 18 --target <MAC>
```

### 19. `7_connect_lifecycle.py` — link lifecycle

- **Step id:** `whad/7_connect_lifecycle`
- **File:** `scripts/7_connect_lifecycle.py`
- **Hardware:** `DONGLE, TARGET`
- **Timeout:** 120s · **Flags:** not flagged

Injects CONNECT_IND as soon as an advertisement is seen, then measures the advertisement-silence gap. A long silence suggests the peripheral accepted the link and is obeying the supervision timeout.

```bash
./run-all-ble.sh -N 19 --target <MAC>
```

### 20. `8_trigger_sweep.py` — trigger sweep

- **Step id:** `whad/8_trigger_sweep`
- **File:** `scripts/8_trigger_sweep.py`
- **Hardware:** `DONGLE, TARGET`
- **Timeout:** 180s · **Flags:** not flagged

Injector calibration. Sweeps the AdvA pattern byte offsets 0-30 to find the offset where reactive injection fires reliably for the target's advertisement layout.

```bash
./run-all-ble.sh -N 20 --target <MAC>
```

### 21. `10_prepare_rootcause.py` — rootcause probe

- **Step id:** `whad/10_prepare_rootcause`
- **File:** `scripts/10_prepare_rootcause.py`
- **Hardware:** `DONGLE, TARGET`
- **Timeout:** 90s · **Flags:** not flagged

Root-cause probe for injection failures. Wraps the raw packet as BTLE/BTLE_DATA so WHAD prepare() accepts it, then compares manual TX against ReceptionTrigger to separate packet problems from trigger problems.

```bash
./run-all-ble.sh -N 21 --target <MAC>
```

### 22. `11_max_fidelity.py` — raw injection

- **Step id:** `whad/11_max_fidelity`
- **File:** `scripts/11_max_fidelity.py`
- **Hardware:** `DONGLE, TARGET`
- **Timeout:** 120s · **Flags:** not flagged

Maximum-fidelity rogue connection: claims InitA FF:EE:DD:CC:BB:AA, raw-injects the CONNECT_IND five times, then connects with custom LLData and enumerates GATT over the resulting link.

```bash
./run-all-ble.sh -N 22 --target <MAC>
```

### 23. `12_ab_diagnose.py` — diagnose sweep

- **Step id:** `whad/12_ab_diagnose`
- **File:** `scripts/12_ab_diagnose.py`
- **Hardware:** `DONGLE, TARGET`
- **Timeout:** 150s · **Flags:** not flagged

A/B diagnosis of link parameters. Tests default versus custom LLData and sweeps 80/160/320 ms connection intervals to find which parameter combination makes the link die or survive.

```bash
./run-all-ble.sh -N 23 --target <MAC>
```

### 24. `13_death_autopsy.py` — disconnect autopsy

- **Step id:** `whad/13_death_autopsy`
- **File:** `scripts/13_death_autopsy.py`
- **Hardware:** `DONGLE, TARGET`
- **Timeout:** 90s · **Flags:** not flagged

Post-mortem forensics: dumps Link Layer control PDUs and decodes HCI termination reasons while the link idles, so you can see why the target or controller tore the connection down.

```bash
./run-all-ble.sh -N 24 --target <MAC>
```

### 25. `14_mtu_responder.py` — MTU responder

- **Step id:** `whad/14_mtu_responder`
- **File:** `scripts/14_mtu_responder.py`
- **Hardware:** `DONGLE, TARGET`
- **Timeout:** 90s · **Flags:** not flagged

Intercepts ATT_EXCHANGE_MTU_REQ and answers with a raw ATT MTU response (247) to stop the peripheral's ~200 ms LL_TERMINATE_IND and keep a rogue link alive longer.

```bash
./run-all-ble.sh -N 25 --target <MAC>
```

### 26. `15_manual_att.py` — manual ATT

- **Step id:** `whad/15_manual_att`
- **File:** `scripts/15_manual_att.py`
- **Hardware:** `DONGLE, TARGET`
- **Timeout:** 120s · **Flags:** not flagged

Builds L2CAP and ATT frames by hand inside Link Layer data PDUs and runs service/characteristic discovery completely below the host GATT stack. Used for low-level ATT fuzzing.

```bash
./run-all-ble.sh -N 26 --target <MAC>
```

### 27. `oooooooooooo.py` — packet connector

- **Step id:** `whad/oo-connect`
- **File:** `scripts/oooooooooooo.py`
- **Hardware:** `DONGLE, TARGET`
- **Timeout:** 150s · **Flags:** not flagged

Runs oooooooooooo.py in connection mode: uses the project's own crafted packet to connect to the target, without the length-fuzz loop.

```bash
./run-all-ble.sh -N 27 --target <MAC>
```

### 28. `oooooooooooo.py` — length fuzzer

- **Step id:** `whad/oo-fuzz`
- **File:** `scripts/oooooooooooo.py`
- **Hardware:** `DONGLE, TARGET`
- **Timeout:** 180s · **Flags:** destructive

Runs oooooooooooo.py in fuzz mode (-l): declares N payload bytes while truncating the actual buffer (CC2540 CVE-2019-19194 style) and uses advertisement gaps as the crash oracle.

```bash
./run-all-ble.sh -N 28 --target <MAC> --yes
```

### 29. `own_packet_full.py` — rogue pipeline

- **Step id:** `whad/own_packet_full`
- **File:** `scripts/own_packet_full.py`
- **Hardware:** `DONGLE, TARGET`
- **Timeout:** 180s · **Flags:** not flagged

Eight-step rogue-central pipeline: dongle audit, target scan, packet build/verify, raw inject, InitA spoof, custom connect, MTU-response pump and manual GATT discovery. The most complete WHAD workflow.

```bash
./run-all-ble.sh -N 29 --target <MAC>
```

### 30. `sweyntooth_crash.py` — crash vectors

- **Step id:** `whad/sweyntooth_crash`
- **File:** `scripts/sweyntooth_crash.py`
- **Hardware:** `DONGLE, TARGET`
- **Timeout:** 180s · **Flags:** destructive

Fires nine named malformed-CONNECT_IND vectors (truncated lengths, iv0, to0, hop0, over-247, valid-34) with an advertisement-interval crash oracle to detect firmware crashes, deadlocks and resets.

```bash
./run-all-ble.sh -N 30 --target <MAC> --yes
```

### 31. `dos.py` — prototype DoS

- **Step id:** `whadbro/dos`
- **File:** `tools/whadbro/dos.py`
- **Hardware:** `DONGLE, TARGET`
- **Timeout:** 180s · **Flags:** destructive, duplicate

Older WHAD prototype: an early connection-flood / saturation attack that later became ble_busy.py and own_packet_full.py. Kept for reference.

```bash
./run-all-ble.sh -N 31 --target <MAC> --yes --include duplicates
```

### 32. `sooooooooo.py` — prototype pipeline

- **Step id:** `whadbro/sooooooooo`
- **File:** `tools/whadbro/sooooooooo.py`
- **Hardware:** `DONGLE, TARGET`
- **Timeout:** 180s · **Flags:** duplicate

Older 773-line WHAD prototype and ancestor of own_packet_full.py: packet build, inject, custom connect and MTU handling. Runs with -c in the runner.

```bash
./run-all-ble.sh -N 32 --target <MAC> --include duplicates
```


## Host BLE (BlueZ / WinRT / CoreBluetooth)

### 33. `ble_connection_time_checker.py` — uptime monitor

- **Step id:** `host/ble_connection_time_checker`
- **File:** `scripts/ble_connection_time_checker.py`
- **Hardware:** `HOST, TARGET`
- **Timeout:** 20s · **Flags:** long-running, timeout-ok

Uptime/crash monitor. Holds a connection, logs exact connect/disconnect timestamps and session duration, and reconnects every two seconds so watchdog reboots or resets are visible during an attack.

```bash
./run-all-ble.sh -N 33 --target <MAC>
```

### 34. `ble_busy.py` — connection DoS

- **Step id:** `host/ble_busy`
- **File:** `scripts/ble_busy.py`
- **Hardware:** `HOST, TARGET`
- **Timeout:** 20s · **Flags:** destructive, long-running, timeout-ok

Connection-flood DoS. Runs an infinite loop of fast BleakClient connect/disconnect (0.5 s timeout, 0.05 s gap) to keep the target's Link Layer busy so legitimate centrals cannot connect.

```bash
./run-all-ble.sh -N 34 --target <MAC> --yes
```

### 35. `pairing_req_multiple.py` — pairing flood

- **Step id:** `host/pairing_req_multiple`
- **File:** `scripts/pairing_req_multiple.py`
- **Hardware:** `HOST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, long-running, timeout-ok

Pairing/connection flood. Fires rapid connect/pairing requests (0.3 s timeout, 0.02 s gap) until the first success, then holds that one link stable forever and silently reconnects if the device drops it.

```bash
./run-all-ble.sh -N 35 --target <MAC> --yes
```

### 36. `thor.py` — write fuzzer

- **Step id:** `host/thor-fuzz`
- **File:** `scripts/thor.py`
- **Hardware:** `HOST, TARGET`
- **Timeout:** 240s · **Flags:** destructive, long-running, timeout-ok

GATT write fuzzer. Explores the device, then sweeps write lengths from 1 up to MTU-3 on every writable characteristic, with checkpoint resume, drop reconnects, hang detection, notification capture and ATT error classification.

```bash
./run-all-ble.sh -N 36 --target <MAC> --yes
```


## SweynTooth PoCs (nRF52840 + SweynTooth firmware)

### 37. `CC2640R2_public_key_crash.py` — CC2640R2 key

- **Step id:** `sweyntooth/CC2640R2_public_key_crash`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/CC2640R2_public_key_crash.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Sends an invalid public key during LE pairing to crash the TI CC2640R2 BLE stack.

```bash
./run-all-ble.sh -N 37 --target <MAC> --yes
```

### 38. `CC_connection_req_crash.py` — CC connect

- **Step id:** `sweyntooth/CC_connection_req_crash`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/CC_connection_req_crash.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Malformed CONNECT_REQ length field crashes TI CC2540/CC2541 controllers (CVE-2019-19194 family).

```bash
./run-all-ble.sh -N 38 --target <MAC> --yes
```

### 39. `DA14580_exploit_att_crash.py` — DA14580 ATT

- **Step id:** `sweyntooth/DA14580_exploit_att_crash`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/DA14580_exploit_att_crash.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Malformed ATT requests and ATT exchange crash the Dialog DA14580 stack.

```bash
./run-all-ble.sh -N 39 --target <MAC> --yes
```

### 40. `DA14680_exploit_silent_overflow.py` — DA14680 overflow

- **Step id:** `sweyntooth/DA14680_exploit_silent_overflow`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/DA14680_exploit_silent_overflow.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Crafted L2CAP/SMP traffic triggers a silent memory overflow in the Dialog DA14680.

```bash
./run-all-ble.sh -N 40 --target <MAC> --yes
```

### 41. `esp32_hci_desync.py` — ESP32 HCI

- **Step id:** `sweyntooth/esp32_hci_desync`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/esp32_hci_desync.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Desynchronizes the ESP32 HCI/Link-Layer state machine to hang or crash the controller.

```bash
./run-all-ble.sh -N 41 --target <MAC> --yes
```

### 42. `invalid_channel_map.py` — channel map

- **Step id:** `sweyntooth/invalid_channel_map`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/invalid_channel_map.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Sends LL_CHANNEL_MAP_IND with an illegal channel map to crash or wedge the link layer.

```bash
./run-all-ble.sh -N 42 --target <MAC> --yes
```

### 43. `link_layer_length_overflow.py` — LL overflow

- **Step id:** `sweyntooth/link_layer_length_overflow`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/link_layer_length_overflow.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Oversized Link Layer payload length triggers a buffer overflow / memory corruption.

```bash
./run-all-ble.sh -N 43 --target <MAC> --yes
```

### 44. `llid_dealock.py` — LLID deadlock

- **Step id:** `sweyntooth/llid_dealock`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/llid_dealock.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Mismatched LLID values deadlock the Link Layer state machine.

```bash
./run-all-ble.sh -N 44 --target <MAC> --yes
```

### 45. `Microchip_invalid_lcap_fragment.py` — Microchip fragment

- **Step id:** `sweyntooth/Microchip_invalid_lcap_fragment`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/Microchip_invalid_lcap_fragment.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Invalid L2CAP fragment crashes Microchip BLE controllers.

```bash
./run-all-ble.sh -N 45 --target <MAC> --yes
```

### 46. `sequential_att_deadlock.py` — ATT deadlock

- **Step id:** `sweyntooth/sequential_att_deadlock`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/sequential_att_deadlock.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Sequential ATT requests deadlock the ATT server and freeze the connection.

```bash
./run-all-ble.sh -N 46 --target <MAC> --yes
```

### 47. `Telink_key_size_overflow.py` — Telink key

- **Step id:** `sweyntooth/Telink_key_size_overflow`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/Telink_key_size_overflow.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Oversized encryption key size during SMP overflows the Telink stack.

```bash
./run-all-ble.sh -N 47 --target <MAC> --yes
```

### 48. `Telink_zero_ltk_installation.py` — Telink LTK

- **Step id:** `sweyntooth/Telink_zero_ltk_installation`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/Telink_zero_ltk_installation.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Installs a zero-length LTK during pairing, breaking encryption on Telink devices.

```bash
./run-all-ble.sh -N 48 --target <MAC> --yes
```

### 49. `zephyr_invalid_sequence.py` — Zephyr sequence

- **Step id:** `sweyntooth/zephyr_invalid_sequence`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/zephyr_invalid_sequence.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Out-of-sequence Link Layer PDUs crash or hang Zephyr-based controllers.

```bash
./run-all-ble.sh -N 49 --target <MAC> --yes
```

### 50. `anomaly_unexpected_encryption_start.py` — encryption anomaly

- **Step id:** `sweyntooth-extra/anomaly_unexpected_encryption_start`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/extras/anomaly_unexpected_encryption_start.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Starts encryption at an unexpected point in the pairing sequence to test state-machine handling.

```bash
./run-all-ble.sh -N 50 --target <MAC> --yes
```

### 51. `CC2540_connection_req_crash_truncated.py` — CC2540 truncated

- **Step id:** `sweyntooth-extra/CC2540_connection_req_crash_truncated`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/extras/CC2540_connection_req_crash_truncated.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Sends a physically truncated CONNECT_REQ to crash the TI CC2540.

```bash
./run-all-ble.sh -N 51 --target <MAC> --yes
```

### 52. `CC2540_truncated_connection_success.py` — CC2540 connect

- **Step id:** `sweyntooth-extra/CC2540_truncated_connection_success`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/extras/CC2540_truncated_connection_success.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Sends a truncated CONNECT_IND that the CC2540 wrongly accepts, proving a specification violation.

```bash
./run-all-ble.sh -N 52 --target <MAC> --yes
```

### 53. `DA14680_att_mtu_length_114_silent_overflow_accepted.py` — DA14680 MTU114

- **Step id:** `sweyntooth-extra/DA14680_att_mtu_length_114_silent_overflow_accepted`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/extras/DA14680_att_mtu_length_114_silent_overflow_accepted.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

ATT MTU length 114 is accepted and silently overflows the DA14680 buffer.

```bash
./run-all-ble.sh -N 53 --target <MAC> --yes
```

### 54. `DA14680_att_mtu_length_5_malformed_accepted.py` — DA14680 MTU5

- **Step id:** `sweyntooth-extra/DA14680_att_mtu_length_5_malformed_accepted`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/extras/DA14680_att_mtu_length_5_malformed_accepted.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Malformed ATT MTU length 5 request is wrongly accepted by the DA14680.

```bash
./run-all-ble.sh -N 54 --target <MAC> --yes
```

### 55. `DA14680_att_read_100_silent_overflow_crash.py` — DA14680 read

- **Step id:** `sweyntooth-extra/DA14680_att_read_100_silent_overflow_crash`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/extras/DA14680_att_read_100_silent_overflow_crash.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

ATT read of 100 bytes triggers a silent overflow and crash on the DA14680.

```bash
./run-all-ble.sh -N 55 --target <MAC> --yes
```

### 56. `DA14680_truncated_l2cap_crash.py` — DA14680 L2CAP

- **Step id:** `sweyntooth-extra/DA14680_truncated_l2cap_crash`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/extras/DA14680_truncated_l2cap_crash.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Truncated L2CAP frame crashes the DA14680 stack.

```bash
./run-all-ble.sh -N 56 --target <MAC> --yes
```

### 57. `Microchip_and_others_non_compliant_connection.py` — Microchip connect

- **Step id:** `sweyntooth-extra/Microchip_and_others_non_compliant_connection`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/extras/Microchip_and_others_non_compliant_connection.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Sends a non-compliant connection request that Microchip and other controllers wrongly accept.

```bash
./run-all-ble.sh -N 57 --target <MAC> --yes
```

### 58. `non_compliance_data_during_encryption_setup.py` — encryption setup

- **Step id:** `sweyntooth-extra/non_compliance_data_during_encryption_setup`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/extras/non_compliance_data_during_encryption_setup.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Sends data PDUs during encryption setup to test whether the controller enforces ordering.

```bash
./run-all-ble.sh -N 58 --target <MAC> --yes
```

### 59. `non_compliance_dhcheck_skip.py` — DHCheck skip

- **Step id:** `sweyntooth-extra/non_compliance_dhcheck_skip`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/extras/non_compliance_dhcheck_skip.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Skips the Diffie-Hellman check during LE Secure Connections pairing, enabling MitM / information leak testing.

```bash
./run-all-ble.sh -N 59 --target <MAC> --yes
```

### 60. `non_compliance_multiple_version.py` — version replay

- **Step id:** `sweyntooth-extra/non_compliance_multiple_version`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/extras/non_compliance_multiple_version.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Sends multiple Link Layer version exchanges to test state handling.

```bash
./run-all-ble.sh -N 60 --target <MAC> --yes
```

### 61. `non_compliance_nonzero_ediv_rand.py` — EDIV rand

- **Step id:** `sweyntooth-extra/non_compliance_nonzero_ediv_rand`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/extras/non_compliance_nonzero_ediv_rand.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok

Sends non-zero EDIV/RAND values where the specification expects zero.

```bash
./run-all-ble.sh -N 61 --target <MAC> --yes
```

### 62. `knob_tester_ble.py` — PoC selector

- **Step id:** `sweyntooth-extra/knob_tester_ble`
- **File:** `tools/sweyntooth_bluetooth_low_energy_attacks/extras/knob_tester_ble.py`
- **Hardware:** `NRF52-ST, TARGET`
- **Timeout:** 30s · **Flags:** destructive, timeout-ok, duplicate

Selector that reruns a chosen subset of the SweynTooth BLE pairing/Link-Layer variants.

```bash
./run-all-ble.sh -N 62 --target <MAC> --yes --include duplicates
```


## Zephyr HCI tests (nRF52840 + Zephyr USB-HCI)

### 63. `nrf-api-check.py` — HCI probe

- **Step id:** `zephyr/nrf-api-check`
- **File:** `tools/ZEPHYR/pylol/nrf-api-check.py`
- **Hardware:** `ZEPHYR-HCI`
- **Timeout:** 30s · **Flags:** not flagged

Probes the nRF dongle/HCI adapter and the host commands needed by the Zephyr scripts. Defaults to hci1; adjust with --hci if your adapter differs.

```bash
./run-all-ble.sh -N 63 --target <MAC>
```

### 64. `adv-checker.py` — advert register

- **Step id:** `zephyr/adv-checker`
- **File:** `tools/ZEPHYR/pylol/adv-checker.py`
- **Hardware:** `ZEPHYR-HCI`
- **Timeout:** 40s · **Flags:** long-running, timeout-ok

Registers a BlueZ D-Bus advertisement on the Zephyr HCI adapter and checks that it is accepted.

```bash
./run-all-ble.sh -N 64 --target <MAC>
```

### 65. `adv-connect-wireshark.py` — GATT dump

- **Step id:** `zephyr/adv-connect-wireshark`
- **File:** `tools/ZEPHYR/pylol/adv-connect-wireshark.py`
- **Hardware:** `ZEPHYR-HCI`
- **Timeout:** 60s · **Flags:** long-running, timeout-ok

Advertises, waits for a central to connect, then dumps GATT services/characteristics/handles for inspection.

```bash
./run-all-ble.sh -N 65 --target <MAC>
```

### 66. `connect-gatt-char.py` — GATT register

- **Step id:** `zephyr/connect-gatt-char`
- **File:** `tools/ZEPHYR/pylol/connect-gatt-char.py`
- **Hardware:** `ZEPHYR-HCI`
- **Timeout:** 20s · **Flags:** long-running, timeout-ok

Registers a GATT service and characteristic on the Zephyr HCI adapter through BlueZ D-Bus.

```bash
./run-all-ble.sh -N 66 --target <MAC>
```

### 67. `ble_connect.py` — bleak connect

- **Step id:** `zephyr/ble_connect`
- **File:** `tools/ZEPHYR/pylol/ble_connect.py`
- **Hardware:** `HOST, TARGET`
- **Timeout:** 30s · **Flags:** not flagged

Connects to the target with bleak and writes a UTF-8 payload to a fixed characteristic UUID; useful as an end-to-end host BLE sanity test.

```bash
./run-all-ble.sh -N 67 --target <MAC>
```

---

## What the runner does *not* launch

- **BlueToolkit / Sbleedy classic YAML exploits** — shipped in `tools/` but
  driven by their own `bluekit` / `sbleedyCLI` engines, mostly for classic
  BR/EDR. See `CLASSIC_BR_EDR_SCRIPTS.txt`.
- **Firmware flashing** — the runner only reports which firmware a stage
  needs; it never flashes a dongle.
- **Vendored libraries and firmware images** — support files, not tests.

## Related documents

- `SCRIPTS_BY_FUNCTION.md` — one-line number → function → hardware table
- `RUNNER_README.md` — full runner manual, profiles, troubleshooting
- `MASTER_DOCUMENTATION.md` — installation, hardware, command reference
- `BLE_SCRIPTS.txt` — BLE script inventory incl. bundled BLE modules
- `BLE_ATTACK_SCRIPTS_LIST.txt` — attack-oriented one-liners
