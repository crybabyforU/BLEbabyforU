#!/usr/bin/env python3
"""Cross-platform environment doctor for the crybabyforu BLE lab.

Same 13+ checks as scripts/check.sh, but written in Python so it runs on
Windows, Ubuntu/Debian, Arch Linux and macOS.  The bash doctor (check.sh)
remains available for deep Linux checks; the runner (run_all_ble.py) invokes
THIS file so the "doctor" stage works everywhere.

Exit codes: 0 = all critical checks passed, N = number of failures.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")
IS_MACOS = sys.platform == "darwin"

LAB_ROOT = Path(__file__).resolve().parent.parent
SNIFFLE_DIR = LAB_ROOT / "tools" / "Sniffle" / "python_cli"
ST_DIR = LAB_ROOT / "tools" / "sweyntooth_bluetooth_low_energy_attacks"
PYCOMPAT_DIR = Path(__file__).resolve().parent / "pycompat"

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

G = "\033[32m"
R = "\033[31m"
Y = "\033[33m"
N = "\033[0m"
if IS_WINDOWS:
    try:
        import ctypes
        k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        h = k32.GetStdHandle(-11)
        m = ctypes.c_uint32()
        if k32.GetConsoleMode(h, ctypes.byref(m)):
            k32.SetConsoleMode(h, m.value | 0x0004)
    except Exception:
        pass
USE_COLOR = sys.stdout.isatty()


def paint(text: str, color: str) -> str:
    if not USE_COLOR:
        return text
    return f"{color}{text}{N}"


def pick_python() -> str:
    if IS_WINDOWS:
        candidates = [
            LAB_ROOT / "venv" / "Scripts" / "python.exe",
            LAB_ROOT.parent / "venv" / "Scripts" / "python.exe",
        ]
    else:
        candidates = [
            LAB_ROOT / "venv" / "bin" / "python",
            LAB_ROOT.parent / "venv" / "bin" / "python",
        ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return sys.executable


PY = pick_python()
PASSED = 0
FAILED = 0


def run(cmd: list[str] | str, timeout: float = 20, shell: bool = False,
        env_extra: dict[str, str] | None = None,
        cwd: Path | None = None) -> tuple[int, str]:
    env = os.environ.copy()
    if env_extra:
        for k, v in env_extra.items():
            env[k] = ((env.get(k, "") + os.pathsep + v) if k == "PYTHONPATH" and env.get(k)
                      else v)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, shell=shell,
                              timeout=timeout, env=env, cwd=str(cwd) if cwd else None,
                              errors="replace")
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return 127, ""


def check(name: str, ok: bool, detail: str = "", required: bool = True) -> None:
    global PASSED, FAILED
    if ok:
        print(f" {paint('[PASS]', G)} {name}")
        if detail:
            print(f"        {detail}")
        PASSED += 1
    else:
        print(f" {paint('[FAIL]', R)} {name}")
        if detail:
            print(f"        {paint(detail, Y)}")
        if not required:
            print(f"        {paint('(informational - not required for this OS)', Y)}")
        FAILED += 1


def py_ok(code: str, env_extra: dict[str, str] | None = None,
          cwd: Path | None = None) -> bool:
    rc, _ = run([PY, "-c", code], env_extra=env_extra, cwd=cwd)
    return rc == 0


def main() -> int:
    print("=" * 60)
    print("        BLE LAB DOCTOR (crybabyforu, cross-platform)")
    print("=" * 60)
    print(f" Root     : {LAB_ROOT}")
    print(f" Python   : {PY}")
    print(f" Platform : {sys.platform} / {os.name}")

    # --- interpreter and packages -----------------------------------------
    check("Python venv found", PY != sys.executable or not (LAB_ROOT / "venv").exists(),
          f"interpreter: {PY}")
    check("bleak (host BLE)", py_ok("import bleak"))
    check("pyserial", py_ok("import serial"))
    check("WHAD package", py_ok("import whad"),
          "needed only for the whad stage")
    check("Sniffle package", py_ok("import sniffle",
                                   {"PYTHONPATH": str(SNIFFLE_DIR)}),
          "needed only for the sniffle stage")
    check("Sniffle extcap", (SNIFFLE_DIR / "sniffle_extcap.py").exists())
    check("SweynTooth Scapy import",
          py_ok("import sys; sys.path.insert(0, 'libs'); "
                "import scapy.layers.bluetooth, scapy.layers.bluetooth4LE",
                {"PYTHONPATH": str(PYCOMPAT_DIR)}, cwd=ST_DIR))

    # --- hardware / OS specific -------------------------------------------
    if IS_LINUX:
        def has_usb(vid: str) -> bool:
            base = Path("/sys/bus/usb/devices")
            if not base.is_dir():
                return False
            for entry in base.iterdir():
                try:
                    if ((entry / "idVendor").read_text().strip().lower() == vid):
                        return True
                except OSError:
                    continue
            return False

        check("ButteRFly USB (c0ff:eeee) or nRF52840 (1915:*)",
              has_usb("c0ff") or has_usb("1915"), "plug the dongle in to run whad/sweyntooth stages")

        ttys = sorted(Path("/dev").glob("ttyACM*")) + sorted(Path("/dev").glob("ttyUSB*"))
        if ttys:
            first = str(ttys[0])
            check(f"Serial port readable ({first})",
                  py_ok(f"import serial; serial.Serial({first!r}, timeout=1).close()"),
                  "if this fails: sudo usermod -aG uucp,dialout $USER, then log out/in")
        else:
            check("Serial port present", False, "no /dev/ttyACM* or /dev/ttyUSB* found")

        rc, _ = run(["systemctl", "is-active", "--quiet", "ModemManager"])
        check("ModemManager stopped", rc != 0,
              "sudo systemctl stop ModemManager (it can steal the dongle)")
        rc, out = run(["id", "-nG"])
        groups = out.split()
        check("Serial group membership (uucp/dialout)",
              "uucp" in groups or "dialout" in groups,
              "Arch: sudo usermod -aG uucp $USER / Ubuntu: sudo usermod -aG dialout $USER")
    elif IS_WINDOWS:
        try:
            from serial.tools import list_ports  # noqa: F401
            ports = list(list_ports.comports())
            have = [(p.device, f"{p.vid:04x}:{p.pid:04x}" if p.vid and p.pid else "?")
                    for p in ports]
        except Exception:
            have = []
        check("Serial ports visible", bool(have),
              ", ".join(f"{d}[{v}]" for d, v in have) or "plug the dongle in")
        nordic = [d for d, v in have if v.startswith("1915") or v.startswith("c0ff")]
        check("nRF52840 / ButteRFly dongle", bool(nordic),
              f"found: {', '.join(nordic)}" if nordic else "no Nordic VID (1915/c0ff) COM port")
        check("WinRT BLE backend (bleak)", py_ok("import bleak; import sys; "
              "sys.exit(0 if sys.platform == 'win32' else 1)"),
              "Windows host BLE works through Bleak/WinRT")
    else:  # macOS
        check("macOS detected", True, "host BLE via Bleak/CoreBluetooth; serial via /dev/tty.*")

    # --- optional tools ----------------------------------------------------
    for tool in ("arm-none-eabi-gcc", "wireshark", "nrfutil", "wble-central",
                 "bluetoothctl", "adb"):
        present = shutil.which(tool) is not None
        check(f"Optional tool: {tool}", present, required=False)

    print("=" * 60)
    print(f"RESULT: {PASSED} passed, {FAILED} failed")
    if FAILED == 0:
        print(paint("ALL GREEN - BLE LAB READY", G))
    else:
        print(paint("Some checks failed - see the notes above. "
                    "Optional tools are not required.", Y))
    return FAILED


if __name__ == "__main__":
    sys.exit(main())
