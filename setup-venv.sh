#!/usr/bin/env bash
# Create a self-contained crybabyforu/venv and install the Python packages.
#
# Usage:
#   ./setup-venv.sh            # minimal requirements (recommended)
#   ./setup-venv.sh --full     # exact package list from the original lab venv
#   PYTHON=python3.10 ./setup-venv.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1:-}" == "--full" ]]; then
    REQ="$HERE/requirements-freeze.txt"
else
    REQ="$HERE/requirements.txt"
fi

PYTHON_BIN="${PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
    if command -v python3.10 >/dev/null 2>&1; then
        PYTHON_BIN=python3.10
    elif command -v python3.11 >/dev/null 2>&1; then
        PYTHON_BIN=python3.11
    else
        PYTHON_BIN=python3
    fi
fi

echo "Using interpreter: $PYTHON_BIN"
"$PYTHON_BIN" -m venv "$HERE/venv"
"$HERE/venv/bin/python" -m pip install --upgrade pip
"$HERE/venv/bin/python" -m pip install -r "$REQ"

echo
echo "Done. Local venv: $HERE/venv"
echo "Run: $HERE/run-all-ble.sh -l"
