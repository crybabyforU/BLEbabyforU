#!/bin/bash
# Environment doctor for the crybabyforu copy.  All paths are relative to this
# folder, so it does not depend on ~/ble-lab.
G='\033[0;32m'; R='\033[0;31m'; N='\033[0m'
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

if [ -x "$ROOT/venv/bin/python" ]; then
    PY="$ROOT/venv/bin/python"
elif [ -x "$ROOT/../venv/bin/python" ]; then
    PY="$ROOT/../venv/bin/python"
else
    PY="${PYTHON:-python3}"
fi

P=0; F=0
check(){ if bash -c "$2" >/tmp/blecheck 2>&1; then printf " ${G}[PASS]${N} %s\n" "$1"; P=$((P+1)); else printf " ${R}[FAIL]${N} %s\n" "$1"; cat /tmp/blecheck | head -2; F=$((F+1)); fi; }

echo "========== BLE LAB DOCTOR (crybabyforu) =========="
echo " Root: $ROOT"
echo " Python: $PY"
check "ButteRFly USB" "lsusb | grep -qi c0ff:eeee"
check "ttyACM0" "[ -e /dev/ttyACM0 ]"
check "Serial permissions" "$PY -c 'import serial; serial.Serial(\"/dev/ttyACM0\",timeout=1).close()'"
check "ModemManager stopped" "! systemctl is-active --quiet ModemManager"
check "uucp group" "id -nG | grep -qw uucp"
check "WHAD package" "$PY -c 'import whad'"
check "Sniffle package" "PYTHONPATH=$ROOT/tools/Sniffle/python_cli $PY -c 'import sniffle'"
check "Sniffle extcap" "[ -f $ROOT/tools/Sniffle/python_cli/sniffle_extcap.py ]"
check "SweynTooth Scapy import" "cd $ROOT/tools/sweyntooth_bluetooth_low_energy_attacks && PYTHONPATH=$ROOT/scripts/pycompat $PY -c 'import sys; sys.path.insert(0, \"libs\"); import scapy.layers.bluetooth, scapy.layers.bluetooth4LE'"
check "ARM compiler" "command -v arm-none-eabi-gcc"
check "Wireshark" "command -v wireshark"
check "nrfutil" "command -v nrfutil"
check "WHAD CLI" "command -v wble-central"
echo "==================================================="
printf "RESULT: %d passed, %d failed\n" "$P" "$F"
[ "$F" -eq 0 ] && echo "ALL GREEN - BLE LAB READY"
rm -f /tmp/blecheck
exit "$F"
