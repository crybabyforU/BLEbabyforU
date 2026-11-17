#!/usr/bin/env bash
set -e

REPO="$HOME/ble-lab/SbleedyGonzales"

echo "[+] Starting SbleedyGonzales Arch/Omarchy setup..."

# ============================================================
# 1. Check Arch Linux / Omarchy
# ============================================================

if ! command -v pacman >/dev/null 2>&1; then
    echo "[-] This script requires Arch Linux / Omarchy."
    exit 1
fi

# ============================================================
# 2. Install system dependencies
# ============================================================

echo "[+] Installing Arch dependencies..."

sudo pacman -S --needed --noconfirm \
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
    bluez-libs \
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
    gobject-introspection \
    python \
    python-pip \
    python-virtualenv \
    android-tools

# ============================================================
# 3. Enable Bluetooth
# ============================================================

echo "[+] Enabling Bluetooth service..."

sudo systemctl enable --now bluetooth

# ============================================================
# 4. Check pyenv
# ============================================================

if ! command -v pyenv >/dev/null 2>&1; then
    echo "[-] pyenv is not installed."
    echo "[!] Install it first:"
    echo "    sudo pacman -S pyenv"
    exit 1
fi

export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"

eval "$(pyenv init -)"

# ============================================================
# 5. Check Python 3.10
# ============================================================

echo "[+] Checking Python 3.10..."

if ! pyenv versions --bare | grep -qx "3.10.18"; then
    echo "[+] Installing Python 3.10.18..."
    pyenv install 3.10.18
fi

# ============================================================
# 6. Check Python 2.7
# ============================================================

echo "[+] Checking Python 2.7..."

if ! pyenv versions --bare | grep -qx "2.7.18"; then
    echo "[-] Python 2.7.18 is not installed."
    echo "[!] Install it with:"
    echo "    pyenv install 2.7.18"
    exit 1
fi

PY3="$HOME/.pyenv/versions/3.10.18/bin/python"
PY2="$HOME/.pyenv/versions/2.7.18/bin/python"

# ============================================================
# 7. Clone repository if required
# ============================================================

if [ ! -d "$REPO/.git" ]; then
    echo "[+] Cloning SbleedyGonzales..."
    mkdir -p "$HOME/ble-lab"
    git clone https://github.com/b0rdst31n/SbleedyGonzales.git "$REPO"
else
    echo "[+] SbleedyGonzales repository already exists."
fi

cd "$REPO"

# ============================================================
# 8. Create Python 2 virtual environment
# ============================================================

if [ ! -d "$REPO/venv2" ]; then
    echo "[+] Creating Python 2 virtual environment..."
    "$PY2" -m virtualenv "$REPO/venv2"
fi

# ============================================================
# 9. Create Python 3 virtual environment
# ============================================================

if [ ! -d "$REPO/venv3" ]; then
    echo "[+] Creating Python 3 virtual environment..."
    "$PY3" -m virtualenv "$REPO/venv3"
fi

echo "[+] Python versions:"
"$REPO/venv2/bin/python" --version
"$REPO/venv3/bin/python" --version

# ============================================================
# 10. Sweyntooth Python 2 dependencies
# ============================================================

echo "[+] Installing Sweyntooth Python 2 dependencies..."

"$REPO/venv2/bin/pip" install \
    -r "$REPO/modules/sweyntooth/requirements.txt"

# ============================================================
# 11. Build/install BLESMPServer using Python 2
# ============================================================

echo "[+] Building BLESMPServer..."

cd "$REPO/modules/sweyntooth/libs/smp_server"

# Remove old build artifacts
rm -rf BLESMPServer.egg-info
rm -rf build
rm -rf dist

# IMPORTANT:
# Do NOT use "sudo make install".
# Build/install explicitly with Python 2.7.
"$REPO/venv2/bin/python" setup.py install

cd "$REPO"

# Verify BLESMPServer
"$REPO/venv2/bin/python" -c \
    "import BLESMPServer; print('[+] BLESMPServer OK')"

# ============================================================
# 12. Install PyBluez
# ============================================================

echo "[+] Installing PyBluez..."

cd "$REPO/helpers/pybluez"

"$REPO/venv3/bin/pip" install .

# ============================================================
# 13. Install Bluing
# ============================================================

echo "[+] Installing Bluing..."

cd "$REPO/helpers/bluing"

CFLAGS="-lm" \
LDFLAGS="-ldl -pthread -lutil" \
"$REPO/venv3/bin/pip" install --no-deps .

# ============================================================
# 14. Bluing runtime dependencies
# ============================================================

echo "[+] Installing Bluing runtime dependencies..."

"$REPO/venv3/bin/pip" install \
    docopt \
    bluepy \
    halo \
    pyserial \
    PyGObject \
    dbus-python

# ============================================================
# 15. Install SbleedyGonzales
# ============================================================

echo "[+] Installing SbleedyGonzales..."

cd "$REPO"

"$REPO/venv3/bin/pip" install -e .

# ============================================================
# 16. Compatible setuptools
# ============================================================

echo "[+] Installing compatible setuptools..."

"$REPO/venv3/bin/pip" install 'setuptools<81'

# ============================================================
# 17. Add user to Bluetooth serial group
# ============================================================

echo "[+] Adding user to uucp group..."

sudo usermod -aG uucp "$USER"

# ============================================================
# 18. Create global sbleedy command
# ============================================================

echo "[+] Creating global sbleedy command..."

mkdir -p "$HOME/.local/bin"

cat > "$HOME/.local/bin/sbleedy" <<EOF
#!/usr/bin/env bash
exec "$REPO/venv3/bin/sbleedy" "\$@"
EOF

chmod +x "$HOME/.local/bin/sbleedy"

# ============================================================
# 19. Add ~/.local/bin to Bash PATH
# ============================================================

if ! grep -qs 'HOME/.local/bin' "$HOME/.bashrc" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
fi

# ============================================================
# 20. Add ~/.local/bin to Nushell PATH
# ============================================================

if [ -d "$HOME/.config/nushell" ]; then

    if ! grep -qs 'HOME/.local/bin' \
        "$HOME/.config/nushell/env.nu" 2>/dev/null; then

        cat >> "$HOME/.config/nushell/env.nu" <<'EOF'

# Sbleedy
$env.PATH = ($env.PATH | prepend ($env.HOME | path join ".local/bin"))
EOF

    fi
fi

# ============================================================
# 21. Final verification
# ============================================================

echo
echo "=============================================="
echo " SbleedyGonzales installation completed"
echo "=============================================="

echo
echo "[+] Python 2:"
"$REPO/venv2/bin/python" --version

echo
echo "[+] Python 3:"
"$REPO/venv3/bin/python" --version

echo
echo "[+] BLESMPServer:"
"$REPO/venv2/bin/python" -c \
    "import BLESMPServer; print('BLESMPServer OK')"

echo
echo "[+] Sbleedy CLI:"

"$REPO/venv3/bin/sbleedy" --help >/dev/null

echo "Sbleedy CLI works."

echo
echo "[!] IMPORTANT:"
echo "    Log out and log back in once so the uucp group takes effect."

echo
echo "[+] After login run:"
echo
echo "    sbleedy -l"
echo
echo "    sbleedy --help"
echo
