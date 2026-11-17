#!/usr/bin/env bash
# Convenience wrapper for the crybabyforu BLE lab copy.
#
# It uses, in order:
#   1. this folder's own venv        (crybabyforu/venv)
#   2. the parent lab venv           (../venv)
#   3. $PYTHON or python3
#
# Run ./setup-venv.sh to create a fully self-contained local venv.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -x "$HERE/venv/bin/python" ]]; then
    PY="$HERE/venv/bin/python"
elif [[ -x "$HERE/../venv/bin/python" ]]; then
    PY="$HERE/../venv/bin/python"
else
    PY="${PYTHON:-python3}"
fi

exec "$PY" "$HERE/scripts/run_all_ble.py" "$@"
