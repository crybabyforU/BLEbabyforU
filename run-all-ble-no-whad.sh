#!/usr/bin/env bash
# ============================================================================
#  run-all-ble-no-whad.sh - run every BLE lab step that does NOT use WHAD
#
#  Skips the whole "whad" stage, which is where all WHAD/ButteRFly scripts
#  live (2_send_packet, 4_inject_raw, 5_scan_then_inject, 6_scan_inject_final,
#  7_connect_lifecycle, 8_trigger_sweep, 10..15, oooooooooooo,
#  own_packet_full, sweyntooth_crash, and the whadbro prototypes).
#
#  What remains: doctor, offline, recon, sniffle, host, sweyntooth, zephyr.
#  Steps still skip themselves if their own hardware (nRF52840, Sniffle board,
#  etc.) is missing.  No WHAD package or ButteRFly dongle is required.
#
#  Examples:
#     ./run-all-ble-no-whad.sh --list
#     ./run-all-ble-no-whad.sh --hw-check
#     ./run-all-ble-no-whad.sh --yes
#     ./run-all-ble-no-whad.sh --target C0:00:00:41:73:AC --yes
# ============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --profile no-whad selects the non-WHAD stages.  --skip-stage whad is a
# second guard in case the caller overrides --profile on the command line.
exec "$HERE/run-all-ble.sh" --profile no-whad --skip-stage whad "$@"
