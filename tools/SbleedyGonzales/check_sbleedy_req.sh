#!/usr/bin/env bash

echo "=============================================="
echo " SbleedyGonzales Requirement Scanner"
echo "=============================================="
echo

ok()   { echo "[+] $1"; }
warn() { echo "[!] $1"; }
fail() { echo "[-] $1"; }

echo "=== OS ==="
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "OS      : $PRETTY_NAME"
    echo "Kernel  : $(uname -r)"
    echo "Arch    : $(uname -m)"
else
    warn "Cannot detect OS"
fi
echo

echo "=== Python ==="

for py in python python2 python2.7 python3 python3.10; do
    if command -v "$py" >/dev/null 2>&1; then
        ok "$py -> $($py --version 2>&1)"
    else
        fail "$py -> NOT FOUND"
    fi
done
echo

echo "=== Python pip ==="

for py in python2.7 python3.10; do
    if command -v "$py" >/dev/null 2>&1; then
        if "$py" -m pip --version >/dev/null 2>&1; then
            ok "$py pip -> $($py -m pip --version)"
        else
            fail "$py pip -> NOT FOUND"
        fi
    fi
done
echo

echo "=== Build Tools ==="

for cmd in gcc g++ make cmake meson pkg-config git wget curl patchelf; do
    if command -v "$cmd" >/dev/null 2>&1; then
        ok "$cmd -> $(command -v "$cmd")"
    else
        fail "$cmd -> NOT FOUND"
    fi
done
echo

echo "=== Bluetooth Tools ==="

for cmd in bluetoothctl hciconfig hcitool rfkill btmgmt; do
    if command -v "$cmd" >/dev/null 2>&1; then
        ok "$cmd -> $(command -v "$cmd")"
    else
        warn "$cmd -> NOT FOUND"
    fi
done
echo

echo "=== Bluetooth Service ==="

if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet bluetooth; then
        ok "Bluetooth service is RUNNING"
    else
        warn "Bluetooth service is NOT running"
    fi
fi
echo

echo "=== Bluetooth Adapters ==="

if command -v hciconfig >/dev/null 2>&1; then
    hciconfig -a
else
    warn "hciconfig unavailable"
fi

echo

echo "=== RF Kill ==="

if command -v rfkill >/dev/null 2>&1; then
    rfkill list bluetooth
else
    warn "rfkill unavailable"
fi

echo

echo "=== Bluetooth Kernel Modules ==="

for mod in bluetooth btusb btrtl btintel btbcm; do
    if lsmod 2>/dev/null | grep -q "^$mod"; then
        ok "$mod -> loaded"
    else
        warn "$mod -> not loaded"
    fi
done
echo

echo "=== USB Devices ==="

if command -v lsusb >/dev/null 2>&1; then
    lsusb | grep -Ei 'bluetooth|wireless|nrf|ubertooth|hackrf|yard|bladerf' \
        || warn "No obvious Bluetooth/security-radio USB device found"
else
    warn "lsusb unavailable"
fi
echo

echo "=== Required Libraries ==="

libs=(
    libbluetooth
    libcairo
    libffi
    openssl
    zlib
    sqlite
    libgdbm
    bzip2
    xz
)

for lib in "${libs[@]}"; do
    if ldconfig -p 2>/dev/null | grep -q "$lib"; then
        ok "$lib -> available"
    else
        warn "$lib -> not detected"
    fi
done
echo

echo "=== Sbleedy Repository ==="

if [ -f README.md ]; then
    ok "README.md found"
else
    fail "README.md missing"
fi

if [ -f pyproject.toml ]; then
    ok "pyproject.toml found"
else
    warn "pyproject.toml missing"
fi

if [ -f helpers/sbleedy_installer.sh ]; then
    ok "Installer script found"
else
    fail "Installer script missing"
fi

echo

echo "=== Sbleedy Virtual Environments ==="

for venv in venv2 venv3; do
    if [ -d "$venv" ]; then
        ok "$venv exists"
    else
        warn "$venv does not exist"
    fi
done

echo

echo "=== Sbleedy Important Files ==="

files=(
    "modules/sweyntooth/requirements.txt"
    "modules/sweyntooth/libs/smp_server"
    "helpers/pybluez"
    "helpers/bluing"
)

for f in "${files[@]}"; do
    if [ -e "$f" ]; then
        ok "$f"
    else
        fail "$f -> MISSING"
    fi
done

echo
echo "=============================================="
echo " Scan Complete"
echo "=============================================="
echo
echo "[-] = Required/missing"
echo "[!] = Optional or needs investigation"
echo "[+] = Available"
