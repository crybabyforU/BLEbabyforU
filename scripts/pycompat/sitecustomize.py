"""Compatibility fixes loaded automatically for the BLE lab runner.

Python 3.10's ``ctypes.util.find_library()`` parses GNU ld's ``-t`` trace.
Newer binutils adds a helpful hint when ``-llibc`` is not found::

    note to link with .../libc.a use -l:libc.a or rename it to liblibc.a

The 3.10 regex treats ``liblibc.a`` as a real file, then ``_is_elf()`` raises
``FileNotFoundError`` instead of returning False.  Scapy's old vendored copy
(used by SweynTooth) calls ``find_library("libc")`` at import time, so
``import scapy.layers.bluetooth`` dies before any BLE code runs.

Python 3.11+ and the system Python 3.14 handle this; only the lab venv's
Python 3.10 needs the shim.  It is a no-op on fixed interpreters and for
normal library names.
"""

try:
    import ctypes.util as _ctypes_util

    _orig_find_library = _ctypes_util.find_library

    def _safe_find_library(name):
        try:
            return _orig_find_library(name)
        except (OSError, ValueError):
            # Broken candidate list (e.g. the liblibc.a hint).  "libc" is the
            # odd name old Scapy uses; "c" resolves through ldconfig.
            if name == "libc":
                try:
                    return _orig_find_library("c")
                except (OSError, ValueError):
                    return None
            return None

    _ctypes_util.find_library = _safe_find_library
except Exception:
    # Never let a compatibility shim break interpreter startup.
    pass
