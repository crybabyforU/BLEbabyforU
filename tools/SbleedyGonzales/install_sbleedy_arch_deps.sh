#!/usr/bin/env bash

set -e

echo "=============================================="
echo " SbleedyGonzales - Arch/Omarchy Dependencies"
echo "=============================================="
echo

if ! command -v pacman >/dev/null 2>&1; then
    echo "[-] This script requires an Arch-based system."
    exit 1
fi

echo "[+] Arch-based system detected"
echo

echo "[+] Updating package database..."
sudo pacman -Sy

echo
echo "[+] Installing SbleedyGonzales dependencies..."
echo

sudo pacman -S --needed \
    base-devel \
    gcc \
    gcc-libs \
    make \
    cmake \
    meson \
    pkgconf \
    git \
    wget \
    curl \
    patchelf \
    bluez \
    bluez-utils \
    libbluetooth \
    usbutils \
    rfkill \
    openssl \
    zlib \
    ncurses \
    readline \
    sqlite \
    gdbm \
    bzip2 \
    xz \
    tk \
    libffi \
    cairo \
    go \
    dbus \
    dbus-devel \
    gobject-introspection \
    python \
    python-pip \
    python-virtualenv \
    adb

echo
echo "=============================================="
echo " Checking installed dependencies"
echo "=============================================="
echo

check_cmd() {
    if command -v "$1" >/dev/null 2>&1; then
        echo "[+] $1 -> $(command -v "$1")"
    else
        echo "[-] $1 -> MISSING"
    fi
}

for cmd in \
    gcc \
    g++ \
    make \
    cmake \
    meson \
    pkg-config \
    git \
    wget \
    curl \
    patchelf \
    bluetoothctl \
    btmgmt \
    rfkill \
    lsusb \
    go \
    adb
do
    check_cmd "$cmd"
done

echo
echo "=== Bluetooth Service ==="

if systemctl is-enabled bluetooth >/dev/null 2>&1; then
    echo "[+] Bluetooth service enabled"
else
    echo "[!] Bluetooth service not enabled"
fi

if systemctl is-active --quiet bluetooth; then
    echo "[+] Bluetooth service running"
else
    echo "[!] Bluetooth service not running"
    echo "    Start it with:"
    echo "    sudo systemctl enable --now bluetooth"
fi

echo
echo "=== Bluetooth Adapter ==="

if command -v bluetoothctl >/dev/null 2>&1; then
    bluetoothctl list || true
fi

echo
echo "=== Python ==="

python --version 2>&1 || true
python -m pip --version 2>&1 || true

echo
echo "=============================================="
echo " System dependency installation complete"
echo "=============================================="
echo
echo "[!] Python 2.7 is NOT installed by this script."
echo "[!] Sbleedy requires Python 2.7 for its legacy"
echo "    Sweyntooth components."
echo
echo "Next step: build/install Python 2.7 separately."
echo
