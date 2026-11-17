# Scripts by function

This is the human-readable map for the copy in `crybabyforu/`.
The framework keeps the original filenames so it behaves exactly like
the lab; this table gives each script a two-word functional name.

Run one with `./run-all-ble.sh -N <number>`; the number is the same as
`./run-all-ble.sh -l`.

Optional functional-name symlinks live in `scripts/by_function/` (for example
`002__packet_builder.py`). They point at the real files, but prefer `-N`:
it sets the correct working directory, timeout, hardware check, and Python
path for each tool.

| # | Function | Script | Hardware needed |
|---:|---|---|---|
| 1 | environment check | `scripts/check.py` | none |
| 2 | packet builder | `scripts/1_build_packet.py` | none |
| 3 | GATT enumeration | `scripts/getting-all-details-of-ble.py` | HOST,TARGET |
| 4 | descriptor reader | `scripts/read_descriptors.py` | HOST,TARGET |
| 5† | GATT explore (explore mode) | `scripts/thor.py` | HOST,TARGET |
| 6 | firmware probe | `tools/Sniffle/python_cli/version_check.py` | SNIFFLE |
| 7 | UART test | `tools/Sniffle/python_cli/uart_test.py` | SNIFFLE |
| 8 | passive scan | `tools/Sniffle/python_cli/scanner.py` | SNIFFLE |
| 9 | pcap capture | `tools/Sniffle/python_cli/sniff_receiver.py` | SNIFFLE,TARGET |
| 10 | sniffer reset | `tools/Sniffle/python_cli/reset.py` | SNIFFLE |
| 11 | fake advertiser | `tools/Sniffle/python_cli/advertiser.py` | SNIFFLE |
| 12 | fake initiator | `tools/Sniffle/python_cli/initiator.py` | SNIFFLE,TARGET |
| 13 | relay master | `tools/Sniffle/python_cli/relay_master.py` | SNIFFLE,TARGET |
| 14 | relay slave | `tools/Sniffle/python_cli/relay_slave.py` | SNIFFLE,TARGET |
| 15 | rogue central | `scripts/2_send_packet.py` | DONGLE,TARGET |
| 16 | CONNECT_IND inject | `scripts/4_inject_raw.py` | DONGLE,TARGET |
| 17 | scan inject | `scripts/5_scan_then_inject.py` | DONGLE,TARGET |
| 18 | injection race | `scripts/6_scan_inject_final.py` | DONGLE,TARGET |
| 19 | link lifecycle | `scripts/7_connect_lifecycle.py` | DONGLE,TARGET |
| 20 | trigger sweep | `scripts/8_trigger_sweep.py` | DONGLE,TARGET |
| 21 | rootcause probe | `scripts/10_prepare_rootcause.py` | DONGLE,TARGET |
| 22 | raw injection | `scripts/11_max_fidelity.py` | DONGLE,TARGET |
| 23 | diagnose sweep | `scripts/12_ab_diagnose.py` | DONGLE,TARGET |
| 24 | disconnect autopsy | `scripts/13_death_autopsy.py` | DONGLE,TARGET |
| 25 | MTU responder | `scripts/14_mtu_responder.py` | DONGLE,TARGET |
| 26 | manual ATT | `scripts/15_manual_att.py` | DONGLE,TARGET |
| 27† | packet connector (connect mode) | `scripts/oooooooooooo.py` | DONGLE,TARGET |
| 28† | length fuzzer (fuzz mode) | `scripts/oooooooooooo.py` | DONGLE,TARGET |
| 29 | rogue pipeline | `scripts/own_packet_full.py` | DONGLE,TARGET |
| 30 | crash vectors | `scripts/sweyntooth_crash.py` | DONGLE,TARGET |
| 31 | prototype DoS | `tools/whadbro/dos.py` | DONGLE,TARGET |
| 32 | prototype pipeline | `tools/whadbro/sooooooooo.py` | DONGLE,TARGET |
| 33 | uptime monitor | `scripts/ble_connection_time_checker.py` | HOST,TARGET |
| 34 | connection DoS | `scripts/ble_busy.py` | HOST,TARGET |
| 35 | pairing flood | `scripts/pairing_req_multiple.py` | HOST,TARGET |
| 36† | write fuzzer (fuzz mode) | `scripts/thor.py` | HOST,TARGET |
| 37 | CC2640R2 key | `tools/sweyntooth_bluetooth_low_energy_attacks/CC2640R2_public_key_crash.py` | NRF52-ST,TARGET |
| 38 | CC connect | `tools/sweyntooth_bluetooth_low_energy_attacks/CC_connection_req_crash.py` | NRF52-ST,TARGET |
| 39 | DA14580 ATT | `tools/sweyntooth_bluetooth_low_energy_attacks/DA14580_exploit_att_crash.py` | NRF52-ST,TARGET |
| 40 | DA14680 overflow | `tools/sweyntooth_bluetooth_low_energy_attacks/DA14680_exploit_silent_overflow.py` | NRF52-ST,TARGET |
| 41 | ESP32 HCI | `tools/sweyntooth_bluetooth_low_energy_attacks/esp32_hci_desync.py` | NRF52-ST,TARGET |
| 42 | channel map | `tools/sweyntooth_bluetooth_low_energy_attacks/invalid_channel_map.py` | NRF52-ST,TARGET |
| 43 | LL overflow | `tools/sweyntooth_bluetooth_low_energy_attacks/link_layer_length_overflow.py` | NRF52-ST,TARGET |
| 44 | LLID deadlock | `tools/sweyntooth_bluetooth_low_energy_attacks/llid_dealock.py` | NRF52-ST,TARGET |
| 45 | Microchip fragment | `tools/sweyntooth_bluetooth_low_energy_attacks/Microchip_invalid_lcap_fragment.py` | NRF52-ST,TARGET |
| 46 | ATT deadlock | `tools/sweyntooth_bluetooth_low_energy_attacks/sequential_att_deadlock.py` | NRF52-ST,TARGET |
| 47 | Telink key | `tools/sweyntooth_bluetooth_low_energy_attacks/Telink_key_size_overflow.py` | NRF52-ST,TARGET |
| 48 | Telink LTK | `tools/sweyntooth_bluetooth_low_energy_attacks/Telink_zero_ltk_installation.py` | NRF52-ST,TARGET |
| 49 | Zephyr sequence | `tools/sweyntooth_bluetooth_low_energy_attacks/zephyr_invalid_sequence.py` | NRF52-ST,TARGET |
| 50 | encryption anomaly | `tools/sweyntooth_bluetooth_low_energy_attacks/extras/anomaly_unexpected_encryption_start.py` | NRF52-ST,TARGET |
| 51 | CC2540 truncated | `tools/sweyntooth_bluetooth_low_energy_attacks/extras/CC2540_connection_req_crash_truncated.py` | NRF52-ST,TARGET |
| 52 | CC2540 connect | `tools/sweyntooth_bluetooth_low_energy_attacks/extras/CC2540_truncated_connection_success.py` | NRF52-ST,TARGET |
| 53 | DA14680 MTU114 | `tools/sweyntooth_bluetooth_low_energy_attacks/extras/DA14680_att_mtu_length_114_silent_overflow_accepted.py` | NRF52-ST,TARGET |
| 54 | DA14680 MTU5 | `tools/sweyntooth_bluetooth_low_energy_attacks/extras/DA14680_att_mtu_length_5_malformed_accepted.py` | NRF52-ST,TARGET |
| 55 | DA14680 read | `tools/sweyntooth_bluetooth_low_energy_attacks/extras/DA14680_att_read_100_silent_overflow_crash.py` | NRF52-ST,TARGET |
| 56 | DA14680 L2CAP | `tools/sweyntooth_bluetooth_low_energy_attacks/extras/DA14680_truncated_l2cap_crash.py` | NRF52-ST,TARGET |
| 57 | Microchip connect | `tools/sweyntooth_bluetooth_low_energy_attacks/extras/Microchip_and_others_non_compliant_connection.py` | NRF52-ST,TARGET |
| 58 | encryption setup | `tools/sweyntooth_bluetooth_low_energy_attacks/extras/non_compliance_data_during_encryption_setup.py` | NRF52-ST,TARGET |
| 59 | DHCheck skip | `tools/sweyntooth_bluetooth_low_energy_attacks/extras/non_compliance_dhcheck_skip.py` | NRF52-ST,TARGET |
| 60 | version replay | `tools/sweyntooth_bluetooth_low_energy_attacks/extras/non_compliance_multiple_version.py` | NRF52-ST,TARGET |
| 61 | EDIV rand | `tools/sweyntooth_bluetooth_low_energy_attacks/extras/non_compliance_nonzero_ediv_rand.py` | NRF52-ST,TARGET |
| 62 | PoC selector | `tools/sweyntooth_bluetooth_low_energy_attacks/extras/knob_tester_ble.py` | NRF52-ST,TARGET |
| 63 | HCI probe | `tools/ZEPHYR/pylol/nrf-api-check.py` | ZEPHYR-HCI |
| 64 | advert register | `tools/ZEPHYR/pylol/adv-checker.py` | ZEPHYR-HCI |
| 65 | GATT dump | `tools/ZEPHYR/pylol/adv-connect-wireshark.py` | ZEPHYR-HCI |
| 66 | GATT register | `tools/ZEPHYR/pylol/connect-gatt-char.py` | ZEPHYR-HCI |
| 67 | bleak connect | `tools/ZEPHYR/pylol/ble_connect.py` | HOST,TARGET |

## Multi-mode files (†)

**67 entries = 65 unique files.** These two files are launched in two
different modes, so each mode has its own `-N` number:

| # | File | Mode |
|---:|---|---|
| 5 | `scripts/thor.py` | GATT explore only |
| 36 | `scripts/thor.py` | write fuzzer |
| 27 | `scripts/oooooooooooo.py` | packet connector |
| 28 | `scripts/oooooooooooo.py` | length fuzzer (`-l`) |

Everything else appears once. `./run-all-ble.sh -l` marks these rows with `†`
and prints the same footnote.

## Hardware tags

- **HOST** - host BLE adapter (BlueZ + bleak)
- **DONGLE** - WHAD ButteRFly nRF52840 USB dongle
- **NRF52-ST** - nRF52840 + SweynTooth driver firmware
- **SNIFFLE** - TI CC1352/CC26x2 Launchpad + Sniffle firmware
- **ZEPHYR-HCI** - nRF52840 + ZEPHYR USB-HCI firmware
- **TARGET** - device under test (BLE peripheral)
