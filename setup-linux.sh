#!/usr/bin/env bash
# ============================================================================
#  crybabyforu - Linux system preparation (Ubuntu/Debian AND Arch)
#
#  What it does:
#    1. detects your distro (apt / pacman)
#    2. installs the system packages the lab needs
#    3. stops ModemManager (it steals /dev/ttyACM* from the dongle)
#    4. adds you to the serial group (dialout on Ubuntu, uucp on Arch)
#    5. offers to create the Python venv via setup-venv.sh
#
#  Usage:
#    sudo ./setup-linux.sh            # full: packages + groups + ModemManager
#    ./setup-linux.sh --venv-only     # only create the Python venv
#
#  Nothing here flashes firmware or touches radio hardware.
# ============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

VENV_ONLY=0
[ "${1:-}" = "--venv-only" ] && VENV_ONLY=1

if command -v lsb_release >/dev/null 2>&1 && lsb_release -i 2>/dev/null | grep -qi ubuntu; then
    DISTRO=ubuntu
elif [ -e /etc/debian_version ]; then
    DISTRO=ubuntu
elif command -v pacman >/dev/null 2>&1; then
    DISTRO=arch
else
    DISTRO=unknown
fi

echo "Distro: ${DISTRO}"

if [ "$VENV_ONLY" -eq 0 ]; then
    case "$DISTRO" in
        ubuntu)
            $SUDO apt-get update
            $SUDO apt-get install -y --no-install-recommends \
                python3 python3-venv python3-pip \
                bluez bluetooth bluez-tools \
                usbutils adb \
                wireshark-common gcc binutils
            ;;
        arch)
            $SUDO pacman -Sy --needed --noconfirm \
                python python-pip \
                bluez bluez-tools bluez-utils \
                usbutils android-tools \
                wireshark-cli gcc binutils
            ;;
        *)
            echo "Unknown distro - install these packages yourself:"
            echo "  python3 python3-venv python3-pip bluez usbutils adb wireshark"
            ;;
    esac

    # ModemManager grabs /dev/ttyACM* and breaks the dongle connection.
    if command -v systemctl >/dev/null 2>&1; then
        echo "Stopping ModemManager (it fights the BLE dongle for serial ports)..."
        $SUDO systemctl stop ModemManager 2>/dev/null || true
        $SUDO systemctl disable ModemManager 2>/dev/null || true
    fi

    # Serial group: dialout on Debian/Ubuntu, uucp on Arch.
    SERIAL_GROUP=""
    case "$DISTRO" in
        ubuntu) SERIAL_GROUP=dialout ;;
        arch)   SERIAL_GROUP=uucp ;;
    esac
    if [ -n "$SERIAL_GROUP" ] && ! id -nG | grep -qw "$SERIAL_GROUP"; then
        echo "Adding $USER to group '$SERIAL_GROUP' (log out/in to take effect)..."
        $SUDO usermod -aG "$SERIAL_GROUP" "${USER:-$(id -un)}"
        echo "  -> NOTE: log out and back in before using the dongle."
    fi
fi

echo
echo "Creating the Python venv..."
"$HERE/setup-venv.sh"

echo
echo "Setup complete. Next steps:"
echo "  $HERE/run-all-ble.sh --hw-check      # what hardware is visible?"
echo "  $HERE/run-all-ble.sh -l              # script catalogue"
echo "  $HERE/run-all-ble.sh --profile safe --target <MAC>   # safe first pass"
