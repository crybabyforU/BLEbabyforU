#!/usr/bin/env python3
# ============================================================================
#  run_all_ble.py - ordered, verbose, hardware-aware BLE lab runner
#
#  Runs the BLE attack / assessment scripts from ALL_SCRIPTS_ATTACKS.txt in a
#  sane order, checks which USB dongles are required and present, streams all
#  output live, and prints the exact failing function/line when a script dies.
#
#  Stdlib only.  The target scripts use ~/ble-lab/venv.
#
#  Quick start:
#     ./scripts/run_all_ble.py --list
#     ./scripts/run_all_ble.py --hw-check
#     ./scripts/run_all_ble.py --profile iot-ble --target C0:00:00:41:73:AC --yes
#
#  WARNING: many steps are DoS / exploit tooling. Only use them on devices you
#  own or have explicit written authorization to test.
# ============================================================================
from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import fnmatch
import json
import os
import queue
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable, Iterable, Optional

# ----------------------------------------------------------------------------
# Paths / constants
# ----------------------------------------------------------------------------
IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")
IS_MACOS = sys.platform == "darwin"
IS_UNIX = not IS_WINDOWS

LAB_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = LAB_ROOT / "scripts"
ST_REPO = "tools/sweyntooth_bluetooth_low_energy_attacks"
SNIFFLE_DIR = LAB_ROOT / "tools" / "Sniffle" / "python_cli"
ZEPHYR_DIR = "tools/ZEPHYR/pylol"
WHADBRO_DIR = "tools/whadbro"
PYCOMPAT_DIR = SCRIPTS_DIR / "pycompat"

DEFAULT_TARGET = "C0:00:00:41:73:AC"
DEFAULT_RUNS_DIR = LAB_ROOT / "ble-runs"
DEFAULT_WHAD_PORT = "uart0"

HARDWARE_ORDER = [
    "OFFLINE", "HOST", "HOST-BR", "DONGLE", "NRF52-ST", "SNIFFLE",
    "ESP32", "NEXUS5", "MICROBIT", "BLUING", "ZEPHYR-HCI", "TARGET",
]

HW_LABEL = {
    "OFFLINE": "no radio (pure Python)",
    "HOST": "host BLE adapter (bleak: BlueZ / WinRT / CoreBluetooth)",
    "HOST-BR": "host BR/EDR adapter (BlueZ classic)",
    "DONGLE": "WHAD ButteRFly nRF52840 USB dongle",
    "NRF52-ST": "nRF52840 + SweynTooth driver firmware",
    "SNIFFLE": "TI CC1352/CC26x2 Launchpad + Sniffle firmware",
    "ESP32": "ESP32 + Braktooth firmware",
    "NEXUS5": "rooted Nexus 5 / CYW20735 + InternalBlue",
    "MICROBIT": "BBC micro:bit / nRF52 + Btlejack firmware",
    "BLUING": "CSR8510 USB dongle + Bluing firmware",
    "ZEPHYR-HCI": "nRF52840 + ZEPHYR USB-HCI firmware",
    "TARGET": "device under test (BLE peripheral)",
}

STAGES = ["doctor", "offline", "recon", "sniffle", "whad", "host",
          "sweyntooth", "zephyr"]

PROFILES: dict[str, list[str]] = {
    "safe":       ["doctor", "offline", "recon"],
    "recon":      ["doctor", "offline", "recon", "sniffle"],
    "whad":       ["doctor", "offline", "whad"],
    "no-whad":    ["doctor", "offline", "recon", "sniffle", "host",
                   "sweyntooth", "zephyr"],
    "sweyntooth": ["doctor", "offline", "sweyntooth"],
    "iot-ble":    ["doctor", "offline", "recon", "sniffle", "whad", "host",
                   "sweyntooth"],
    "all":        ["doctor", "offline", "recon", "sniffle", "whad", "host",
                   "sweyntooth", "zephyr"],
}

ATTACK_PROFILES = {"iot-ble", "all", "whad", "sweyntooth", "no-whad"}

# ANSI
_COLORS = {
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "dim": "\033[2m", "bold": "\033[1m", "reset": "\033[0m",
}
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
USE_COLOR = True


def enable_windows_ansi() -> None:
    """Enable ANSI escape sequences on legacy Windows consoles (Win10+)."""
    if not IS_WINDOWS:
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        # Best effort only; the runner still works without colors.
        pass


def paint(text: str, color: Optional[str] = None) -> str:
    if not USE_COLOR or not color:
        return text
    return f"{_COLORS.get(color, '')}{text}{_COLORS['reset']}"


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


# ----------------------------------------------------------------------------
# Manifest
# ----------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class Step:
    """One runnable script in the ordered plan."""
    id: str
    stage: str
    path: str
    hardware: tuple[str, ...] = ()
    args: tuple[str, ...] = ()
    argfn: Optional[Callable[["Context"], list[str]]] = None
    kind: str = "python"                  # python | bash
    timeout: Optional[int] = None         # seconds; None -> --timeout
    timeout_ok: bool = False              # long-running tool: timeout = normal
    destructive: bool = False             # DoS / crash / fuzz
    long: bool = False                    # does not exit on its own
    interactive: bool = False             # needs a human at the keyboard
    duplicate: bool = False               # older/bundled copy of another step
    optional: bool = False                # setup/utility, not a core test
    soft_fail: bool = False               # non-zero is informational (doctor)
    cwd: str = "work"                     # work | lab | path relative to lab
    note: str = ""
    summary: str = ""                     # exactly two words, used by -l

    def command(self, ctx: "Context") -> list[str]:
        raw = list(self.argfn(ctx)) if self.argfn else list(self.args)
        argv: list[str] = []
        for item in raw:
            if item is None:
                continue
            value = ctx.expand(item)
            if value == "":
                continue
            argv.append(value)
        if self.kind == "bash":
            return ["bash", str(LAB_ROOT / self.path), *argv]
        return [ctx.python, str(LAB_ROOT / self.path), *argv]

    def cwd_path(self, ctx: "Context") -> Path:
        if self.cwd == "work":
            return ctx.run_dir / "work"
        if self.cwd == "lab":
            return LAB_ROOT
        return LAB_ROOT / self.cwd


def sniffle_args(*extra: str) -> Callable[["Context"], list[str]]:
    def _build(ctx: "Context") -> list[str]:
        prefix = ["-s", ctx.sniffle_port] if ctx.sniffle_port else []
        return prefix + list(extra)
    return _build


def S(step_id: str, stage: str, path: str, hardware: Iterable[str] = (),
      args: Iterable[str] = (), **kw) -> Step:
    return Step(step_id, stage, path, tuple(hardware), tuple(args), **kw)


def _core_steps() -> list[Step]:
    return [
        S("doctor/check", "doctor", "scripts/check.py",
          timeout=120, soft_fail=True, cwd="lab",
          note="cross-platform environment doctor; non-zero is reported as WARN, not FAIL"),
        S("offline/1_build_packet", "offline", "scripts/1_build_packet.py",
          args=("{target}",), timeout=30,
          note="offline CONNECT_IND builder + spec legality checks (no radio)"),

        # ---- host / BlueZ recon -------------------------------------------
        S("recon/getting-all-details-of-ble", "recon",
          "scripts/getting-all-details-of-ble.py", ("HOST", "TARGET"),
          ("{target}",), timeout=90,
          note="full GATT service/characteristic/descriptor tree"),
        S("recon/read_descriptors", "recon", "scripts/read_descriptors.py",
          ("HOST", "TARGET"), ("{target}", "--handles", "19,22"),
          timeout=60, note="reads descriptor handles 19 and 22 (adjust in the script if needed)"),
        S("recon/thor-explore", "recon", "scripts/thor.py",
          ("HOST", "TARGET"), ("{target}", "--explore-only"), timeout=180,
          note="thor part 1 only: GATT exploration, no write fuzzing"),

        # ---- host / BlueZ attacks -----------------------------------------
        S("host/ble_connection_time_checker", "host",
          "scripts/ble_connection_time_checker.py", ("HOST", "TARGET"),
          ("{target}",), timeout=20, timeout_ok=True, long=True,
          note="uptime monitor; stopped after the timeout, that is expected"),
        S("host/ble_busy", "host", "scripts/ble_busy.py",
          ("HOST", "TARGET"), ("{target}",), timeout=20, timeout_ok=True,
          long=True, destructive=True,
          note="rapid connect/disconnect DoS; stopped after the timeout"),
        S("host/pairing_req_multiple", "host", "scripts/pairing_req_multiple.py",
          ("HOST", "TARGET"), ("{target}",), timeout=30, timeout_ok=True,
          long=True, destructive=True,
          note="rapid pairing requests until one connect, then holds that link; stopped after the timeout"),
        S("host/thor-fuzz", "host", "scripts/thor.py",
          ("HOST", "TARGET"), ("{target}", "--reset-checkpoint"),
          timeout=240, timeout_ok=True, long=True, destructive=True,
          note="write-length fuzzer; checkpoint resets on every run"),

        # ---- WHAD ButteRFly link-layer suite ------------------------------
        S("whad/2_send_packet", "whad", "scripts/2_send_packet.py",
          ("DONGLE", "TARGET"), ("{target}", "--port", "{whad_port}"),
          timeout=90, note="rogue central with custom AA / CRCInit / interval / hop"),
        S("whad/4_inject_raw", "whad", "scripts/4_inject_raw.py",
          ("DONGLE", "TARGET"),
          ("{target}", "--window", "30", "--port", "{whad_port}"),
          timeout=90, note="reactive CONNECT_IND injection, 30 s watch window"),
        S("whad/5_scan_then_inject", "whad", "scripts/5_scan_then_inject.py",
          ("DONGLE", "TARGET"),
          ("{target}", "--scan-time", "10", "--window", "30",
           "--port", "{whad_port}"),
          timeout=120, note="scan, reopen as injector, arm AdvA triggers"),
        S("whad/6_scan_inject_final", "whad", "scripts/6_scan_inject_final.py",
          ("DONGLE", "TARGET"),
          ("{target}", "--scan-time", "10", "--window", "30",
           "--port", "{whad_port}"),
          timeout=120, note="single-instance continuous-RX connection race"),
        S("whad/7_connect_lifecycle", "whad", "scripts/7_connect_lifecycle.py",
          ("DONGLE", "TARGET"),
          ("{target}", "--scan-time", "10", "--window", "30",
           "--port", "{whad_port}"),
          timeout=120, note="inject + measure ADV silence / supervision timeout"),
        S("whad/8_trigger_sweep", "whad", "scripts/8_trigger_sweep.py",
          ("DONGLE", "TARGET"),
          ("{target}", "--scan-time", "10", "--offsets", "0-30",
           "--port", "{whad_port}"),
          timeout=180, note="AdvA offset sweep to calibrate the injector"),
        S("whad/10_prepare_rootcause", "whad", "scripts/10_prepare_rootcause.py",
          ("DONGLE", "TARGET"), ("{target}", "--port", "{whad_port}"),
          timeout=90, note="manual TX vs ReceptionTrigger root-cause probe"),
        S("whad/11_max_fidelity", "whad", "scripts/11_max_fidelity.py",
          ("DONGLE", "TARGET"), ("{target}", "--port", "{whad_port}"),
          timeout=120, note="InitA spoof + raw inject + custom connect"),
        S("whad/12_ab_diagnose", "whad", "scripts/12_ab_diagnose.py",
          ("DONGLE", "TARGET"), ("{target}", "--port", "{whad_port}"),
          timeout=150, note="default vs custom LLData + interval sweep"),
        S("whad/13_death_autopsy", "whad", "scripts/13_death_autopsy.py",
          ("DONGLE", "TARGET"), ("{target}", "--port", "{whad_port}"),
          timeout=90, note="LL control PDU / HCI termination forensics"),
        S("whad/14_mtu_responder", "whad", "scripts/14_mtu_responder.py",
          ("DONGLE", "TARGET"), ("{target}", "--port", "{whad_port}"),
          timeout=90, note="answer ATT MTU request to keep the rogue link alive"),
        S("whad/15_manual_att", "whad", "scripts/15_manual_att.py",
          ("DONGLE", "TARGET"), ("{target}", "--port", "{whad_port}"),
          timeout=120, note="raw L2CAP/ATT discovery below the host stack"),
        S("whad/oo-connect", "whad", "scripts/oooooooooooo.py",
          ("DONGLE", "TARGET"), ("{target}",), timeout=150,
          note="our-packet connector (non-fuzz mode)"),
        S("whad/oo-fuzz", "whad", "scripts/oooooooooooo.py",
          ("DONGLE", "TARGET"), ("{target}", "-l"), timeout=180,
          destructive=True, note="length-field fuzzer (CC2540 CVE-2019-19194 style)"),
        S("whad/own_packet_full", "whad", "scripts/own_packet_full.py",
          ("DONGLE", "TARGET"), ("{target}",), timeout=180,
          note="8-step rogue-central pipeline"),
        S("whad/sweyntooth_crash", "whad", "scripts/sweyntooth_crash.py",
          ("DONGLE", "TARGET"), ("{target}",), timeout=180, destructive=True,
          note="9 malformed CONNECT_IND vectors + ADV-gap crash oracle"),

        # ---- older WHADBRO prototypes (duplicates of the above) -----------
        S("whadbro/dos", "whad", f"{WHADBRO_DIR}/dos.py",
          ("DONGLE", "TARGET"), ("{target}",), timeout=180,
          destructive=True, duplicate=True, cwd="work",
          note="prototype ancestor of ble_busy / own_packet_full"),
        S("whadbro/sooooooooo", "whad", f"{WHADBRO_DIR}/sooooooooo.py",
          ("DONGLE", "TARGET"), ("{target}", "-c"), timeout=180,
          duplicate=True, cwd="work",
          note="773-line prototype ancestor of own_packet_full"),
    ]


def _sweyntooth_steps() -> list[Step]:
    main = [
        "CC2640R2_public_key_crash",
        "CC_connection_req_crash",
        "DA14580_exploit_att_crash",
        "DA14680_exploit_silent_overflow",
        "esp32_hci_desync",
        "invalid_channel_map",
        "link_layer_length_overflow",
        "llid_dealock",
        "Microchip_invalid_lcap_fragment",
        "sequential_att_deadlock",
        "Telink_key_size_overflow",
        "Telink_zero_ltk_installation",
        "zephyr_invalid_sequence",
    ]
    extras = [
        "anomaly_unexpected_encryption_start",
        "CC2540_connection_req_crash_truncated",
        "CC2540_truncated_connection_success",
        "DA14680_att_mtu_length_114_silent_overflow_accepted",
        "DA14680_att_mtu_length_5_malformed_accepted",
        "DA14680_att_read_100_silent_overflow_crash",
        "DA14680_truncated_l2cap_crash",
        "Microchip_and_others_non_compliant_connection",
        "non_compliance_data_during_encryption_setup",
        "non_compliance_dhcheck_skip",
        "non_compliance_multiple_version",
        "non_compliance_nonzero_ediv_rand",
    ]
    steps: list[Step] = []
    for name in main:
        steps.append(S(f"sweyntooth/{name}", "sweyntooth",
                       f"{ST_REPO}/{name}.py", ("NRF52-ST", "TARGET"),
                       ("{nrf_port}", "{target}"), timeout=30, timeout_ok=True,
                       destructive=True, cwd=ST_REPO,
                       note="SweynTooth PoC; stopped after 30 s, that is expected"))
    for name in extras:
        steps.append(S(f"sweyntooth-extra/{name}", "sweyntooth",
                       f"{ST_REPO}/extras/{name}.py", ("NRF52-ST", "TARGET"),
                       ("{nrf_port}", "{target}"), timeout=30, timeout_ok=True,
                       destructive=True, cwd=ST_REPO,
                       note="SweynTooth extra PoC; stopped after 30 s, that is expected"))
    steps.append(S("sweyntooth-extra/knob_tester_ble", "sweyntooth",
                   f"{ST_REPO}/extras/knob_tester_ble.py",
                   ("NRF52-ST", "TARGET"), ("{nrf_port}", "{target}"),
                   timeout=30, timeout_ok=True, destructive=True, duplicate=True,
                   cwd=ST_REPO, note="selector that reruns a subset of the PoCs above"))
    return steps


def _sniffle_steps() -> list[Step]:
    return [
        S("sniffle/version_check", "sniffle", "tools/Sniffle/python_cli/version_check.py",
          ("SNIFFLE",), argfn=sniffle_args(), timeout=30,
          cwd="tools/Sniffle/python_cli",
          note="probe sniffer firmware API level"),
        S("sniffle/uart_test", "sniffle", "tools/Sniffle/python_cli/uart_test.py",
          ("SNIFFLE",), argfn=sniffle_args(), timeout=8, timeout_ok=True,
          long=True, cwd="tools/Sniffle/python_cli",
          note="UART echo/latency test; stopped after the timeout"),
        S("sniffle/scanner", "sniffle", "tools/Sniffle/python_cli/scanner.py",
          ("SNIFFLE",), argfn=sniffle_args("-d"), timeout=15, timeout_ok=True,
          long=True, cwd="tools/Sniffle/python_cli",
          note="passive BLE scan for the whole timeout window"),
        S("sniffle/sniff_receiver", "sniffle", "tools/Sniffle/python_cli/sniff_receiver.py",
          ("SNIFFLE", "TARGET"),
          argfn=sniffle_args("-m", "{target}", "-a", "-o",
                             "{run_dir}/sniffle_capture.pcap"),
          timeout=20, timeout_ok=True, long=True,
          cwd="tools/Sniffle/python_cli",
          note="capture target advertisements to pcap for the timeout window"),
        S("sniffle/reset", "sniffle", "tools/Sniffle/python_cli/reset.py",
          ("SNIFFLE",), argfn=sniffle_args(), timeout=20, optional=True,
          cwd="tools/Sniffle/python_cli"),
        S("sniffle/advertiser", "sniffle", "tools/Sniffle/python_cli/advertiser.py",
          ("SNIFFLE",), argfn=sniffle_args(), timeout=15, timeout_ok=True,
          long=True, optional=True, cwd="tools/Sniffle/python_cli"),
        S("sniffle/initiator", "sniffle", "tools/Sniffle/python_cli/initiator.py",
          ("SNIFFLE", "TARGET"),
          argfn=sniffle_args("-m", "{target}"), timeout=20, timeout_ok=True,
          long=True, optional=True, cwd="tools/Sniffle/python_cli"),
        S("sniffle/relay_master", "sniffle", "tools/Sniffle/python_cli/relay_master.py",
          ("SNIFFLE", "TARGET"),
          argfn=sniffle_args("-m", "{target}"), timeout=20, timeout_ok=True,
          long=True, interactive=True, optional=True,
          cwd="tools/Sniffle/python_cli"),
        S("sniffle/relay_slave", "sniffle", "tools/Sniffle/python_cli/relay_slave.py",
          ("SNIFFLE", "TARGET"), argfn=sniffle_args(), timeout=20,
          timeout_ok=True, long=True, optional=True,
          cwd="tools/Sniffle/python_cli"),
    ]


def _zephyr_steps() -> list[Step]:
    return [
        S("zephyr/nrf-api-check", "zephyr", f"{ZEPHYR_DIR}/nrf-api-check.py",
          ("ZEPHYR-HCI",), ("--hci", "hci1"), timeout=30,
          cwd=ZEPHYR_DIR, note="probe the ZEPHYR HCI adapter (default hci1)"),
        S("zephyr/adv-checker", "zephyr", f"{ZEPHYR_DIR}/adv-checker.py",
          ("ZEPHYR-HCI",), timeout=40, timeout_ok=True, long=True,
          cwd=ZEPHYR_DIR, note="register a BlueZ advertisement on hci1"),
        S("zephyr/adv-connect-wireshark", "zephyr",
          f"{ZEPHYR_DIR}/adv-connect-wireshark.py", ("ZEPHYR-HCI",),
          timeout=60, timeout_ok=True, long=True, cwd=ZEPHYR_DIR,
          note="advertise, accept a central, dump GATT handles"),
        S("zephyr/connect-gatt-char", "zephyr",
          f"{ZEPHYR_DIR}/connect-gatt-char.py", ("ZEPHYR-HCI",),
          timeout=20, timeout_ok=True, long=True, cwd=ZEPHYR_DIR,
          note="register a GATT service on the ZEPHYR adapter"),
        S("zephyr/ble_connect", "zephyr", f"{ZEPHYR_DIR}/ble_connect.py",
          ("HOST", "TARGET"), ("-m", "{target}"), timeout=30,
          cwd=ZEPHYR_DIR, note="bleak write test against the target"),
    ]


# Exactly two words per script, used by the `-l` catalogue.  Keep this in the
# same order of magnitude as the script: it is the quick "what does this do?"
# column, not a replacement for the full note in --list-all.
SUMMARY_2W: dict[str, str] = {
    "doctor/check": "environment check",
    "offline/1_build_packet": "packet builder",
    "recon/getting-all-details-of-ble": "GATT enumeration",
    "recon/read_descriptors": "descriptor reader",
    "recon/thor-explore": "GATT explore",
    "host/ble_connection_time_checker": "uptime monitor",
    "host/ble_busy": "connection DoS",
    "host/pairing_req_multiple": "pairing flood",
    "host/thor-fuzz": "write fuzzer",
    "whad/2_send_packet": "rogue central",
    "whad/4_inject_raw": "CONNECT_IND inject",
    "whad/5_scan_then_inject": "scan inject",
    "whad/6_scan_inject_final": "injection race",
    "whad/7_connect_lifecycle": "link lifecycle",
    "whad/8_trigger_sweep": "trigger sweep",
    "whad/10_prepare_rootcause": "rootcause probe",
    "whad/11_max_fidelity": "raw injection",
    "whad/12_ab_diagnose": "diagnose sweep",
    "whad/13_death_autopsy": "disconnect autopsy",
    "whad/14_mtu_responder": "MTU responder",
    "whad/15_manual_att": "manual ATT",
    "whad/oo-connect": "packet connector",
    "whad/oo-fuzz": "length fuzzer",
    "whad/own_packet_full": "rogue pipeline",
    "whad/sweyntooth_crash": "crash vectors",
    "whadbro/dos": "prototype DoS",
    "whadbro/sooooooooo": "prototype pipeline",
    "sweyntooth/CC2640R2_public_key_crash": "CC2640R2 key",
    "sweyntooth/CC_connection_req_crash": "CC connect",
    "sweyntooth/DA14580_exploit_att_crash": "DA14580 ATT",
    "sweyntooth/DA14680_exploit_silent_overflow": "DA14680 overflow",
    "sweyntooth/esp32_hci_desync": "ESP32 HCI",
    "sweyntooth/invalid_channel_map": "channel map",
    "sweyntooth/link_layer_length_overflow": "LL overflow",
    "sweyntooth/llid_dealock": "LLID deadlock",
    "sweyntooth/Microchip_invalid_lcap_fragment": "Microchip fragment",
    "sweyntooth/sequential_att_deadlock": "ATT deadlock",
    "sweyntooth/Telink_key_size_overflow": "Telink key",
    "sweyntooth/Telink_zero_ltk_installation": "Telink LTK",
    "sweyntooth/zephyr_invalid_sequence": "Zephyr sequence",
    "sweyntooth-extra/anomaly_unexpected_encryption_start": "encryption anomaly",
    "sweyntooth-extra/CC2540_connection_req_crash_truncated": "CC2540 truncated",
    "sweyntooth-extra/CC2540_truncated_connection_success": "CC2540 connect",
    "sweyntooth-extra/DA14680_att_mtu_length_114_silent_overflow_accepted": "DA14680 MTU114",
    "sweyntooth-extra/DA14680_att_mtu_length_5_malformed_accepted": "DA14680 MTU5",
    "sweyntooth-extra/DA14680_att_read_100_silent_overflow_crash": "DA14680 read",
    "sweyntooth-extra/DA14680_truncated_l2cap_crash": "DA14680 L2CAP",
    "sweyntooth-extra/Microchip_and_others_non_compliant_connection": "Microchip connect",
    "sweyntooth-extra/non_compliance_data_during_encryption_setup": "encryption setup",
    "sweyntooth-extra/non_compliance_dhcheck_skip": "DHCheck skip",
    "sweyntooth-extra/non_compliance_multiple_version": "version replay",
    "sweyntooth-extra/non_compliance_nonzero_ediv_rand": "EDIV rand",
    "sweyntooth-extra/knob_tester_ble": "PoC selector",
    "sniffle/version_check": "firmware probe",
    "sniffle/uart_test": "UART test",
    "sniffle/scanner": "passive scan",
    "sniffle/sniff_receiver": "pcap capture",
    "sniffle/reset": "sniffer reset",
    "sniffle/advertiser": "fake advertiser",
    "sniffle/initiator": "fake initiator",
    "sniffle/relay_master": "relay master",
    "sniffle/relay_slave": "relay slave",
    "zephyr/nrf-api-check": "HCI probe",
    "zephyr/adv-checker": "advert register",
    "zephyr/adv-connect-wireshark": "GATT dump",
    "zephyr/connect-gatt-char": "GATT register",
    "zephyr/ble_connect": "bleak connect",
}


def _with_summaries(steps: Iterable[Step]) -> list[Step]:
    return [dataclasses.replace(step, summary=SUMMARY_2W.get(step.id, "misc script"))
            for step in steps]


ALL_STEPS: list[Step] = _with_summaries(
    _core_steps() + _sweyntooth_steps() + _sniffle_steps() + _zephyr_steps()
)


# ----------------------------------------------------------------------------
# Context
# ----------------------------------------------------------------------------
@dataclasses.dataclass
class Context:
    args: argparse.Namespace
    python: str
    target: str
    whad_port: str
    nrf_port: str
    sniffle_port: Optional[str]
    run_dir: Path

    def expand(self, value: str) -> str:
        mapping = {
            "{target}": self.target,
            "{target_lower}": self.target.replace(":", "").lower(),
            "{whad_port}": self.whad_port,
            "{nrf_port}": self.nrf_port,
            "{sniffle_port}": self.sniffle_port or "",
            "{run_dir}": str(self.run_dir),
            "{lab}": str(LAB_ROOT),
        }
        for key, replacement in mapping.items():
            value = value.replace(key, replacement)
        return value


# ----------------------------------------------------------------------------
# Hardware detection (sysfs + optional CLI probes; no third-party imports here)
# ----------------------------------------------------------------------------
@dataclasses.dataclass
class UsbDevice:
    vid: str
    pid: str
    product: str
    manufacturer: str
    serial: str
    sysfs: str


@dataclasses.dataclass
class HwTag:
    available: bool
    detail: str


@dataclasses.dataclass
class Hardware:
    usb: list[UsbDevice]
    ttys: dict[str, Optional[UsbDevice]]
    hci: list[str]
    groups: list[str]
    commands: dict[str, bool]
    imports: dict[str, bool]
    modemmanager_active: bool
    adb_devices: list[str]
    tags: dict[str, HwTag]


def normalize_mac(value: str) -> Optional[str]:
    raw = re.sub(r"[^0-9A-Fa-f]", "", value or "")
    if len(raw) != 12:
        return None
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2)).upper()


def _read(path: Path) -> str:
    try:
        return path.read_text(errors="replace").strip()
    except OSError:
        return ""


def _detect_usb() -> list[UsbDevice]:
    if IS_LINUX:
        return _detect_usb_sysfs()
    return _detect_usb_serial()


def _detect_usb_sysfs() -> list[UsbDevice]:
    devices: list[UsbDevice] = []
    base = Path("/sys/bus/usb/devices")
    if not base.is_dir():
        return devices
    for entry in base.iterdir():
        vid = _read(entry / "idVendor").lower()
        pid = _read(entry / "idProduct").lower()
        if not vid or not pid:
            continue
        devices.append(UsbDevice(
            vid=vid, pid=pid,
            product=_read(entry / "product"),
            manufacturer=_read(entry / "manufacturer"),
            serial=_read(entry / "serial"),
            sysfs=str(entry),
        ))
    return devices


def _detect_usb_serial() -> list[UsbDevice]:
    """Windows / macOS: derive USB identities from serial port enumeration.

    pyserial (already required by SweynTooth / Sniffle) exposes VID/PID for
    COM ports; devices without a serial port (e.g. the CSR8510 BLE dongle)
    are not visible this way and stay undetected, which is the same behaviour
    as a Linux box without usbutils.
    """
    devices: list[UsbDevice] = []
    for info in _list_serial_ports():
        if info.vid is None or info.pid is None:
            continue
        devices.append(UsbDevice(
            vid=f"{info.vid:04x}", pid=f"{info.pid:04x}",
            product=info.product or "", manufacturer="",
            serial=info.serial_number or "", sysfs=info.device,
        ))
    return devices


def _list_serial_ports() -> list:
    try:
        from serial.tools import list_ports
    except Exception:
        return []
    return list(list_ports.comports())


def _usb_for_tty(name: str) -> Optional[UsbDevice]:
    node = Path("/sys/class/tty") / name / "device"
    try:
        current = node.resolve()
    except OSError:
        return None
    for _ in range(8):
        vid = _read(current / "idVendor").lower()
        pid = _read(current / "idProduct").lower()
        if vid and pid:
            return UsbDevice(vid, pid, _read(current / "product"),
                             _read(current / "manufacturer"),
                             _read(current / "serial"), str(current))
        if current.parent == current:
            break
        current = current.parent
    return None


def _detect_ttys() -> dict[str, Optional[UsbDevice]]:
    result: dict[str, Optional[UsbDevice]] = {}
    if IS_LINUX:
        for pattern in ("ttyACM*", "ttyUSB*"):
            for dev in sorted(Path("/dev").glob(pattern)):
                result[str(dev)] = _usb_for_tty(dev.name)
        return result
    # Windows: COM ports.  pyserial reports USB VID/PID per port.
    by_device: dict[str, UsbDevice] = {
        d.sysfs: d for d in _detect_usb_serial()
    }
    for info in _list_serial_ports():
        result[info.device] = by_device.get(info.device)
    return result


def _run_quiet(cmd: list[str], timeout: float = 4.0) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, errors="replace")
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return 127, ""


def _detect_commands() -> dict[str, bool]:
    names = ["bluetoothctl", "hciconfig", "hcitool", "systemctl", "adb",
             "nrfutil", "wble-central", "arm-none-eabi-gcc", "wireshark",
             "btmon", "udevadm"]
    return {name: shutil.which(name) is not None for name in names}


def _detect_imports(python: str) -> dict[str, bool]:
    sniffle_path = str(SNIFFLE_DIR)
    return {
        "whad": _py_import(python, "whad"),
        "bleak": _py_import(python, "bleak"),
        "serial": _py_import(python, "serial"),
        "scapy": _py_import(python, "scapy"),
        "scapy_bt": _py_import_sweyntooth_scapy(python),
        "sniffle": _py_import(python, "sniffle", sniffle_path),
        "Crypto": _py_import(python, "Crypto"),
    }


def _py_import_sweyntooth_scapy(python: str) -> bool:
    """Import the old bundled Scapy exactly the way SweynTooth does.

    The lab venv's Python 3.10 needs scripts/pycompat/sitecustomize.py to get
    past ctypes.util.find_library("libc"); see that file for details.
    """
    key = (python, "scapy.layers.bluetooth", str(PYCOMPAT_DIR))
    if key in _IMPORT_CACHE:
        return _IMPORT_CACHE[key]
    env = os.environ.copy()
    current = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(PYCOMPAT_DIR) + ((os.pathsep + current) if current else "")
    code = (
        "import sys; sys.path.insert(0, 'libs'); "
        "import scapy.layers.bluetooth; import scapy.layers.bluetooth4LE"
    )
    try:
        proc = subprocess.run([python, "-c", code], cwd=str(LAB_ROOT / ST_REPO),
                              env=env, capture_output=True, timeout=20)
        ok = proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        ok = False
    _IMPORT_CACHE[key] = ok
    return ok


_IMPORT_CACHE: dict[tuple[str, str, str], bool] = {}


def _py_import(python: str, module: str, extra_path: str = "") -> bool:
    key = (python, module, extra_path)
    if key in _IMPORT_CACHE:
        return _IMPORT_CACHE[key]
    env = os.environ.copy()
    if extra_path:
        current = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = extra_path + ((os.pathsep + current) if current else "")
    try:
        proc = subprocess.run([python, "-c", f"import {module}"],
                              env=env, capture_output=True, timeout=15)
        ok = proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        ok = False
    _IMPORT_CACHE[key] = ok
    return ok


def _detect_hci() -> list[str]:
    if IS_LINUX:
        adapters = sorted(p.name for p in Path("/sys/class/bluetooth").glob("hci*"))
        if adapters:
            return adapters
        if shutil.which("bluetoothctl"):
            rc, out = _run_quiet(["bluetoothctl", "list"], timeout=4)
            if rc == 0:
                found = re.findall(r"Controller\s+([0-9A-Fa-f:]{17})", out)
                if found:
                    return ["hci0"]
        return []
    # Windows / macOS: there is no hciX.  Host BLE support is provided by
    # Bleak (WinRT backend on Windows, CoreBluetooth on macOS), which the
    # import checks already measure; HOST tag logic accounts for that.
    return []


def _detect_groups() -> list[str]:
    if not IS_LINUX:
        return []
    rc, out = _run_quiet(["id", "-nG"], timeout=3)
    return out.split() if rc == 0 else []


def _detect_adb() -> list[str]:
    if not shutil.which("adb"):
        return []
    rc, out = _run_quiet(["adb", "devices"], timeout=5)
    if rc != 0:
        return []
    devices = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


def detect_hardware(ctx: Context) -> Hardware:
    usb = _detect_usb()
    ttys = _detect_ttys()
    hci = _detect_hci()
    groups = _detect_groups()
    commands = _detect_commands()
    imports = _detect_imports(ctx.python)
    mm_active = False
    if commands.get("systemctl"):
        rc, _ = _run_quiet(["systemctl", "is-active", "--quiet", "ModemManager"])
        mm_active = (rc == 0)
    adb_devices = _detect_adb()

    def has_usb(vid: str, pid: Optional[str] = None) -> bool:
        return any(d.vid == vid and (pid is None or d.pid == pid) for d in usb)

    whad_usb = [d for d in usb if (d.vid, d.pid) == ("c0ff", "eeee")]
    nordic_usb = [d for d in usb if d.vid == "1915" or (d.vid, d.pid) == ("c0ff", "eeee")]
    ti_usb = [d for d in usb if d.vid == "0451"]
    serial_usb = [d for d in usb if (d.vid, d.pid) in {
        ("10c4", "ea60"), ("1a86", "7523"), ("0403", "6001"), ("1a86", "55d4"),
    }]
    microbit_usb = [d for d in usb if d.vid == "0d28"]
    csr_usb = [d for d in usb if (d.vid, d.pid) == ("0a12", "0001")]

    tty_names = list(ttys.keys())
    nordic_ttys = [name for name, dev in ttys.items()
                   if dev and (dev.vid == "1915" or (dev.vid, dev.pid) == ("c0ff", "eeee"))]
    ti_ttys = [name for name, dev in ttys.items() if dev and dev.vid == "0451"]
    serial_ttys = [name for name, dev in ttys.items()
                   if dev and (dev.vid, dev.pid) in {
                       ("10c4", "ea60"), ("1a86", "7523"), ("0403", "6001"),
                       ("1a86", "55d4")}]
    tty_writable = [n for n in tty_names if os.access(n, os.R_OK | os.W_OK)]

    tags: dict[str, HwTag] = {}

    if IS_WINDOWS:
        host_backend = "WinRT"
    elif IS_MACOS:
        host_backend = "CoreBluetooth"
    else:
        host_backend = "BlueZ"
    host_ok = (bool(hci) or not IS_LINUX) and imports["bleak"]
    host_detail = (f"{', '.join(hci) if hci else host_backend + ' BLE'}; "
                   f"bleak={'yes' if imports['bleak'] else 'MISSING'}")
    tags["HOST"] = HwTag(host_ok, host_detail)
    tags["HOST-BR"] = HwTag(bool(hci) and IS_LINUX,
                            f"{', '.join(hci) if hci else 'no hci adapter'}"
                            + (" (classic BR/EDR needs Linux/BlueZ)" if not IS_LINUX else ""))

    # Do not treat an arbitrary ttyACM (e.g. a phone modem) as the dongle.
    nordic_present = bool(whad_usb or nordic_usb or nordic_ttys)
    dongle_port = nordic_ttys[0] if nordic_ttys else (tty_names[0] if nordic_present and tty_names else "")
    dongle_ok = imports["whad"] and nordic_present and bool(dongle_port)
    tags["DONGLE"] = HwTag(
        dongle_ok,
        f"whad={'yes' if imports['whad'] else 'MISSING'}; "
        f"serial={dongle_port or 'MISSING'}; "
        f"USB={'c0ff:eeee' if whad_usb else ('nRF52840' if nordic_usb else 'not seen')}",
    )

    nrf_ok = bool(nordic_usb or nordic_ttys or whad_usb) and bool(tty_names)
    tags["NRF52-ST"] = HwTag(
        nrf_ok,
        f"nRF52840={'yes' if (nordic_usb or whad_usb) else 'not seen'}; "
        f"serial={nordic_ttys[0] if nordic_ttys else ('MISSING' if not nrf_ok else tty_names[0])}; "
        "firmware must be SweynTooth (not WHAD)",
    )

    sniffle_ok = imports["sniffle"] and bool(ti_usb or ti_ttys or ctx.sniffle_port)
    tags["SNIFFLE"] = HwTag(
        sniffle_ok,
        f"sniffle={'yes' if imports['sniffle'] else 'MISSING'}; "
        f"TI board={'yes' if (ti_usb or ti_ttys) else 'not seen'}; "
        f"port={ctx.sniffle_port or (ti_ttys[0] if ti_ttys else 'auto')}",
    )

    esp_ok = bool(serial_usb or serial_ttys)
    tags["ESP32"] = HwTag(
        esp_ok,
        f"USB-serial={'yes' if (serial_usb or serial_ttys) else 'not seen'} "
        f"({serial_ttys[0] if serial_ttys else 'no port'})",
    )
    tags["NEXUS5"] = HwTag(bool(adb_devices),
                           f"adb devices={len(adb_devices)}")
    tags["MICROBIT"] = HwTag(bool(microbit_usb),
                             "USB 0d28 seen" if microbit_usb else "not seen")
    tags["BLUING"] = HwTag(bool(csr_usb),
                           "CSR8510 0a12:0001 seen" if csr_usb else "not seen")
    tags["ZEPHYR-HCI"] = HwTag(
        ("hci1" in hci) or nrf_ok,
        f"hci1={'yes' if 'hci1' in hci else 'no'}; nRF52840={'yes' if nrf_ok else 'no'}",
    )
    tags["OFFLINE"] = HwTag(True, "no radio required")
    tags["TARGET"] = HwTag(True, ctx.target)

    return Hardware(usb=usb, ttys=ttys, hci=hci, groups=groups,
                    commands=commands, imports=imports,
                    modemmanager_active=mm_active, adb_devices=adb_devices,
                    tags=tags)


def required_tags(steps: Iterable[Step]) -> list[str]:
    present = {tag for step in steps for tag in step.hardware}
    return [tag for tag in HARDWARE_ORDER if tag in present]


def hw_skip_reason(step: Step, hw: Hardware, force: bool) -> Optional[str]:
    if force:
        return None
    missing = [tag for tag in step.hardware if not hw.tags.get(tag, HwTag(False, "")).available]
    if not missing:
        return None
    return "missing hardware: " + ", ".join(f"[{tag}]" for tag in missing)


# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------
class RunLogger:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(path, "w", encoding="utf-8", buffering=1)

    def emit(self, message: str = "", color: Optional[str] = None,
             console: bool = True) -> None:
        self._fh.write(strip_ansi(message) + "\n")
        self._fh.flush()
        if console:
            print(paint(message, color), flush=True)

    def close(self) -> None:
        try:
            self._fh.close()
        except OSError:
            pass


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "__", value).strip("_")[:120]


# ----------------------------------------------------------------------------
# Plan selection
# ----------------------------------------------------------------------------
@dataclasses.dataclass
class PlanEntry:
    step: Step
    reason: Optional[str] = None   # None -> will run


def _matches(step: Step, patterns: Iterable[str]) -> bool:
    name = Path(step.path).name
    return any(fnmatch.fnmatch(step.id, pat) or fnmatch.fnmatch(name, pat)
               for pat in patterns)


def effective_stages(args: argparse.Namespace) -> list[str]:
    stages = list(args.stage) if args.stage else list(PROFILES[args.profile])
    if args.skip_stage:
        stages = [s for s in stages if s not in set(args.skip_stage)]
    return stages


def ordered_all_steps() -> list[Step]:
    """Every manifest script in stage/execution order.

    The 1-based index of this list is what `-l` prints and what `-N` accepts.
    """
    stage_index = {name: idx for idx, name in enumerate(STAGES)}
    return [step for _, step in sorted(
        enumerate(ALL_STEPS),
        key=lambda pair: (stage_index.get(pair[1].stage, len(STAGES)), pair[0]),
    )]


def catalog_steps(args: argparse.Namespace) -> list[Step]:
    """The `-l` / `-N` list: every script minus explicitly skipped stages.

    The normal runner has no --skip-stage, so it lists all 66.  The no-WHAD
    wrapper passes --skip-stage whad, so both `-l` and `-N` use a 48-entry
    non-WHAD list and their numbers always agree.
    """
    steps = ordered_all_steps()
    skipped = set(args.skip_stage or [])
    if skipped:
        steps = [step for step in steps if step.stage not in skipped]
    return steps


def select_plan(ctx: Context, include_all: bool = False) -> list[PlanEntry]:
    args = ctx.args
    profile = args.profile
    stages = effective_stages(args)

    includes = set(args.include or [])
    attack_profile = profile in ATTACK_PROFILES

    # ALL_STEPS is grouped by source family; the plan must follow stage order.
    ordered_steps = ordered_all_steps()

    entries: list[PlanEntry] = []
    for step in ordered_steps:
        reason: Optional[str] = None

        if step.stage not in stages:
            reason = f"stage '{step.stage}' not in profile '{profile}'"
        elif args.only and not _matches(step, args.only):
            reason = "not matched by --only"
        elif args.skip and _matches(step, args.skip):
            reason = "matched by --skip"
        elif step.interactive and "interactive" not in includes:
            reason = "interactive tool (add --include interactive)"
        elif step.duplicate and "duplicates" not in includes:
            reason = "duplicate/bundled copy (add --include duplicates)"
        elif (step.optional and "optional" not in includes
              and profile not in {"all", "no-whad"}):
            reason = "optional utility (add --include optional)"
        elif step.destructive and not attack_profile and "destructive" not in includes:
            reason = "destructive step (add --include destructive)"
        elif step.long and profile in {"safe", "recon"} and "long" not in includes:
            reason = "long-running step (add --include long)"

        if include_all or reason is None:
            entries.append(PlanEntry(step, reason))
    return entries


def print_plan(entries: list[PlanEntry], hw: Optional[Hardware] = None) -> None:
    print()
    print(paint("=" * 100, "cyan"))
    print(paint(" EXECUTION PLAN", "bold"))
    print(paint("=" * 100, "cyan"))
    header = f"{'#':>3}  {'STEP':<46} {'HARDWARE':<22} {'TIMEOUT':>7}  FLAGS"
    print(paint(header, "bold"))
    total = len(entries)
    for idx, entry in enumerate(entries, 1):
        step = entry.step
        hw_text = ",".join(step.hardware) or "-"
        timeout = f"{step.timeout or 120}s" + ("*" if step.timeout_ok else "")
        flags = []
        if step.destructive:
            flags.append("DESTRUCTIVE")
        if step.long:
            flags.append("LONG")
        if step.timeout_ok:
            flags.append("TIMEOUT-OK")
        if step.soft_fail:
            flags.append("SOFT-FAIL")
        if step.optional:
            flags.append("OPTIONAL")
        if step.duplicate:
            flags.append("DUPLICATE")
        if step.interactive:
            flags.append("INTERACTIVE")
        flag_text = " ".join(flags) or "-"
        line = f"{idx:>3}  {step.id:<46} {hw_text:<22} {timeout:>7}  {flag_text}"
        if entry.reason:
            print(paint(line, "dim"))
            print(paint(f"     └─ SKIP: {entry.reason}", "dim"))
        else:
            print(line)
    print(paint("-" * 100, "cyan"))
    print(f"{total} step(s) in plan.  (* = timeout is expected for this tool)")
    print(paint(
        "Classic/BR-EDR YAML exploits (BlueToolkit/Sbleedy) are not launched "
        "by this BLE runner; see RUNNER_README.md.", "dim"))
    print()


def print_script_catalog(steps: list[Step],
                         skipped_stages: Iterable[str] = ()) -> None:
    """`-l`: every script, a two-word function, and its required hardware."""
    skipped_stages = list(skipped_stages)
    if not steps:
        print("No scripts selected (all stages were skipped).")
        return
    id_width = max(len(step.id) for step in steps)
    func_width = 18

    print()
    print(paint("=" * 100, "cyan"))
    print(paint(" BLE LAB SCRIPT CATALOG", "bold"))
    print(paint("=" * 100, "cyan"))
    print(paint(
        f"{'#':>3}  {'SCRIPT':<{id_width}}  {'FUNCTION':<{func_width}}  "
        f"HARDWARE NEEDED", "bold"))
    print(paint("-" * 100, "cyan"))
    for idx, step in enumerate(steps, 1):
        if step.hardware:
            hw_text = ",".join(step.hardware)
            hw = paint(hw_text, "yellow")
        else:
            hw_text = "none"
            hw = paint(hw_text, "green")
        print(f"{idx:>3}  {step.id:<{id_width}}  "
              f"{step.summary:<{func_width}}  {hw}")
    print(paint("-" * 100, "cyan"))

    used_tags = required_tags(steps)
    if used_tags:
        print(paint("Hardware legend:", "bold"))
        for tag in used_tags:
            print(f"  {tag:<11} {HW_LABEL.get(tag, '')}")
        print()

    if skipped_stages:
        print(paint(f"Stages excluded: {', '.join(skipped_stages)} "
                    f"({len(steps)} scripts listed)", "dim"))
    print(f"{len(steps)} script(s). HARDWARE NEEDED lists the dongle/board each "
          "script uses; 'none' needs no hardware. TARGET = your BLE device.")
    launcher = "run.bat" if IS_WINDOWS else "./run-all-ble.sh"
    print(f"Run one with: {paint(f'{launcher} -N <number>', 'bold')}   "
          f"example: -N 2")
    print(paint("Missing hardware is skipped at run time; add --force to run anyway.",
                "dim"))
    print()


def print_hardware(hw: Hardware, steps: Iterable[Step], full: bool = False,
                   python: Optional[str] = None) -> None:
    steps = list(steps)
    tags = required_tags(steps)
    if full:
        tags = HARDWARE_ORDER

    print()
    print(paint("=" * 100, "cyan"))
    print(paint(" HARDWARE / DONGLE CHECK", "bold"))
    print(paint("=" * 100, "cyan"))
    if full or not tags:
        if python:
            print(f"Python        : {python}")
        print(f"OS            : {sys.platform} ({os.name})")
        print(f"HCI adapters  : {', '.join(hw.hci) if hw.hci else ('none' if IS_LINUX else 'n/a (' + ('WinRT' if IS_WINDOWS else 'CoreBluetooth') + ' backend)')}")
        print(f"Serial ports  : {', '.join(hw.ttys) if hw.ttys else 'none'}")
        if IS_LINUX:
            print(f"Groups        : {', '.join(hw.groups) if hw.groups else 'unknown'}")
            print(f"ModemManager  : {'ACTIVE (can steal the dongle - stop it)' if hw.modemmanager_active else 'not active'}")
        print(f"adb devices   : {', '.join(hw.adb_devices) if hw.adb_devices else 'none'}")
        tools = ", ".join(f"{name}={'yes' if ok else 'no'}"
                          for name, ok in hw.commands.items())
        print(f"Tools         : {tools}")
        st_dep = ("OK (bundled scapy.layers.bluetooth imports)"
                  if hw.imports.get("scapy_bt")
                  else "FAILED (bundled scapy.layers.bluetooth does not import)")
        print(f"SweynTooth py : {st_dep}")
        print()
        print("USB devices:")
        if hw.usb:
            for dev in hw.usb:
                print(f"  {dev.vid}:{dev.pid:<6} {dev.manufacturer} {dev.product}".rstrip())
        else:
            src = "/sys/bus/usb/devices" if IS_LINUX else "serial-port enumeration"
            print(f"  (none visible via {src})")
        print()
        print("Serial ports:")
        for port, dev in hw.ttys.items():
            ident = f"{dev.vid}:{dev.pid} {dev.product}" if dev else "no USB parent"
            print(f"  {port:<20} {ident}")
        if not hw.ttys:
            print("  (none)")
        print()

    usage: dict[str, int] = {}
    for step in steps:
        for tag in step.hardware:
            usage[tag] = usage.get(tag, 0) + 1

    print(f"{'TAG':<12} {'STATUS':<9} {'USED':>4}  DETAIL")
    for tag in tags:
        status = hw.tags.get(tag, HwTag(False, "unknown"))
        mark = paint("FOUND", "green") if status.available else paint("MISSING", "red")
        # pad without ANSI to keep the columns readable
        mark_plain = "FOUND" if status.available else "MISSING"
        pad = " " * max(0, 9 - len(mark_plain))
        used = usage.get(tag, 0)
        print(f"[{tag:<10}] {mark}{pad} {used:>4}  {status.detail}")
        print(f"{'':<12} {'':<9} {'':>4}  {HW_LABEL.get(tag, '')}")
    if python and any(step.stage == "sweyntooth" for step in steps):
        ok = bool(hw.imports.get("scapy_bt"))
        print(f"SweynTooth Python deps: "
              f"{paint('OK' if ok else 'FAILED', 'green' if ok else 'red')}"
              f"  (bundled scapy.layers.bluetooth)")
    print(paint("-" * 100, "cyan"))
    if any(not hw.tags.get(tag, HwTag(False, "")).available for tag in tags):
        print(paint("Missing hardware steps will be skipped. Use --force to run them anyway.", "yellow"))
    print()


# ----------------------------------------------------------------------------
# Target check
# ----------------------------------------------------------------------------
_TARGET_SCAN_CODE = r"""
import asyncio, sys
from bleak import BleakScanner

async def main():
    seconds = float(sys.argv[1])
    devices = await BleakScanner.discover(timeout=seconds)
    for d in devices:
        print("%s|%s|%s" % (d.address, d.name or "", d.rssi))

asyncio.run(main())
"""


def check_target(ctx: Context, hw: Hardware) -> None:
    if ctx.args.no_target_check:
        return
    if not hw.tags["HOST"].available or not hw.imports.get("bleak"):
        print(paint("[target] skipped: no usable host BLE adapter/bleak", "yellow"))
        return
    seconds = ctx.args.target_scan_time
    print(paint(f"[target] scanning {seconds}s for {ctx.target} ...", "cyan"), flush=True)
    try:
        proc = subprocess.run(
            [ctx.python, "-c", _TARGET_SCAN_CODE, str(seconds)],
            capture_output=True, text=True, timeout=seconds + 20,
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(paint(f"[target] scan failed: {exc}", "yellow"))
        return
    found = None
    seen: list[str] = []
    for line in proc.stdout.splitlines():
        parts = line.strip().split("|")
        if len(parts) < 2:
            continue
        seen.append(parts[0])
        if normalize_mac(parts[0]) == ctx.target:
            found = line.strip()
            break
    if found:
        addr, name, rssi = (found.split("|") + ["", "", ""])[:3]
        print(paint(f"[target] FOUND {addr}  name={name or '-'}  rssi={rssi or '-'}", "green"))
    else:
        print(paint(
            f"[target] NOT seen in {seconds}s ({len(seen)} device(s) heard). "
            "Continuing: it may use a private address or not be advertising.",
            "yellow",
        ))


# ----------------------------------------------------------------------------
# Authorization gate
# ----------------------------------------------------------------------------
def confirm_authorization(entries: Iterable[PlanEntry], assume_yes: bool) -> bool:
    destructive = [e.step for e in entries if e.reason is None and e.step.destructive]
    if not destructive:
        return True
    if assume_yes:
        print(paint("[auth] destructive steps enabled by --yes", "yellow"))
        return True
    print()
    print(paint("!" * 100, "red"))
    print(paint(" AUTHORIZATION REQUIRED", "bold"))
    print(paint("!" * 100, "red"))
    print(" The plan includes DoS / crash / fuzzing steps:")
    for step in destructive[:12]:
        print(f"   - {step.id}")
    if len(destructive) > 12:
        print(f"   ... and {len(destructive) - 12} more")
    print()
    print(" Only run these against a device you own or have explicit written")
    print(" authorization to test. Re-run with --yes for non-interactive use.")
    print()
    if not sys.stdin.isatty():
        print(paint("[auth] refused: stdin is not a TTY. Pass --yes to confirm.", "red"))
        return False
    answer = input(" Type 'I OWN THE TARGET' to continue: ").strip().lower()
    ok = answer == "i own the target"
    print(paint("[auth] accepted" if ok else "[auth] refused", "green" if ok else "red"))
    return ok


# ----------------------------------------------------------------------------
# Execution
# ----------------------------------------------------------------------------
@dataclasses.dataclass
class Frame:
    file: str
    line: int
    func: str
    source: str = ""


@dataclasses.dataclass
class Result:
    step: Step
    status: str                 # PASS FAIL TIMEOUT TIMEOUT-OK WARN SKIP DRYRUN
    rc: Optional[int] = None
    duration: float = 0.0
    reason: str = ""
    command: list[str] = dataclasses.field(default_factory=list)
    frames: list[Frame] = dataclasses.field(default_factory=list)
    tail: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.step.id,
            "stage": self.step.stage,
            "path": self.step.path,
            "status": self.status,
            "exit_code": self.rc,
            "duration_s": round(self.duration, 3),
            "reason": self.reason,
            "command": self.command,
            "failing_frames": [dataclasses.asdict(f) for f in self.frames],
            "tail": self.tail[-25:],
        }


_FRAME_RE = re.compile(r'File "(?P<file>[^"]+)", line (?P<line>\d+)(?:, in (?P<func>[^\n]+))?')
_FAIL_LINE_RE = re.compile(
    r"^(?:Fatal Python error:.*|[A-Za-z_][\w.]*(?:Error|Exception|Exit|Warning):.*)$")


def parse_frames(lines: Iterable[str]) -> list[Frame]:
    frames: list[Frame] = []
    seen: set[tuple[str, int, str]] = set()
    for line in lines:
        for match in _FRAME_RE.finditer(line):
            key = (match.group("file"), int(match.group("line")),
                   (match.group("func") or "").strip())
            if key in seen:
                continue
            seen.add(key)
            frames.append(Frame(key[0], key[1], key[2],
                                _source_line(key[0], key[1])))
    return frames


def _source_line(path: str, lineno: int) -> str:
    candidates = [Path(path)]
    if not Path(path).is_absolute():
        candidates.append(LAB_ROOT / path)
    for candidate in candidates:
        try:
            with open(candidate, "r", errors="replace") as fh:
                for idx, line in enumerate(fh, 1):
                    if idx == lineno:
                        return line.rstrip()[:220]
        except OSError:
            continue
    return ""


def _terminate(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (OSError, ProcessLookupError):
        try:
            proc.terminate()
        except OSError:
            pass
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                proc.kill()
            except OSError:
                pass


def _reader(pipe, out_queue: "queue.Queue[Optional[str]]") -> None:
    try:
        for line in pipe:
            out_queue.put(line)
    finally:
        out_queue.put(None)


def run_step(step: Step, ctx: Context, logger: RunLogger,
             per_script_log: Path, timeout: int) -> Result:
    cmd = step.command(ctx)
    cwd = step.cwd_path(ctx)
    cwd.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.update({
        "PYTHONUNBUFFERED": "1",
        "PYTHONFAULTHANDLER": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONBREAKPOINT": "0",
    })
    extra_paths: list[Path] = []
    if step.stage == "sniffle" or "tools/Sniffle" in step.path:
        extra_paths.append(SNIFFLE_DIR)
    if step.stage == "zephyr":
        extra_paths.append(LAB_ROOT / ZEPHYR_DIR)
    if step.stage == "sweyntooth":
        # Early Python 3.10 + new binutils workaround for bundled Scapy.
        extra_paths.append(PYCOMPAT_DIR)
    if extra_paths:
        current = env.get("PYTHONPATH", "")
        prefix = os.pathsep.join(str(path) for path in extra_paths)
        env["PYTHONPATH"] = prefix + ((os.pathsep + current) if current else "")

    started = time.monotonic()
    tail: deque[str] = deque(maxlen=80)
    logger.emit(paint("  $ " + " ".join(shlex.quote(part) for part in cmd), "dim"))
    logger.emit(paint(f"  cwd: {cwd}", "dim"))

    try:
        proc = subprocess.Popen(
            cmd, cwd=str(cwd), env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
            start_new_session=True,
        )
    except OSError as exc:
        return Result(step, "FAIL", rc=None, reason=f"could not start: {exc}",
                      command=cmd)

    out_queue: "queue.Queue[Optional[str]]" = queue.Queue()
    reader = threading.Thread(target=_reader, args=(proc.stdout, out_queue),
                              daemon=True)
    reader.start()

    timed_out = False
    deadline = started + timeout

    with open(per_script_log, "w", encoding="utf-8", buffering=1) as per_fh:
        try:
            while True:
                now = time.monotonic()
                if now >= deadline:
                    timed_out = True
                    logger.emit(paint(f"  ! timeout after {timeout}s - stopping process group", "yellow"))
                    _terminate(proc)
                    break
                try:
                    item = out_queue.get(timeout=min(0.2, max(0.01, deadline - now)))
                except queue.Empty:
                    if proc.poll() is not None and not reader.is_alive():
                        break
                    continue
                if item is None:
                    break
                line = item.rstrip("\r\n")
                tail.append(line)
                per_fh.write(strip_ansi(line) + "\n")
                per_fh.flush()
                if not ctx.args.quiet:
                    logger.emit(paint("    │ ", "dim") + line, console=True)

            # Drain anything the reader already buffered.
            while True:
                try:
                    item = out_queue.get_nowait()
                except queue.Empty:
                    break
                if item is None:
                    continue
                line = item.rstrip("\r\n")
                tail.append(line)
                per_fh.write(strip_ansi(line) + "\n")
                if not ctx.args.quiet:
                    logger.emit(paint("    │ ", "dim") + line, console=True)
        except KeyboardInterrupt:
            logger.emit(paint("  ! interrupted - stopping process group", "red"))
            _terminate(proc)
            raise

    try:
        rc = proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _terminate(proc)
        rc = proc.poll()

    duration = time.monotonic() - started
    lines = list(tail)
    frames = parse_frames(lines)
    tail_list = lines[-25:]

    if timed_out:
        status = "TIMEOUT-OK" if step.timeout_ok else "TIMEOUT"
        reason = (f"stopped after {timeout}s (expected for this long-running tool)"
                  if step.timeout_ok else f"timed out after {timeout}s")
    elif rc == 0:
        status = "PASS"
        reason = ""
    elif step.soft_fail:
        status = "WARN"
        reason = f"exit code {rc} (informational)"
    else:
        status = "FAIL"
        reason = f"exit code {rc}"
        fail_line = next((ln for ln in reversed(lines) if _FAIL_LINE_RE.match(ln.strip())), "")
        if fail_line:
            reason += f": {fail_line.strip()[:180]}"

    return Result(step, status, rc=rc, duration=duration, reason=reason,
                  command=cmd, frames=frames, tail=tail_list)


def print_failure(result: Result, logger: RunLogger) -> None:
    if result.status not in {"FAIL", "TIMEOUT"}:
        return
    logger.emit()
    logger.emit(paint("=" * 100, "red"))
    logger.emit(paint(f" FAILURE: {result.step.id}", "bold"))
    logger.emit(paint("=" * 100, "red"))
    logger.emit(f" status   : {result.status}")
    logger.emit(f" exit code: {result.rc}")
    logger.emit(f" reason   : {result.reason}")
    logger.emit(f" command  : {' '.join(shlex.quote(p) for p in result.command)}")
    logger.emit(f" log      : see per-script log in the run directory")

    if result.frames:
        deepest = result.frames[-1]
        logger.emit()
        logger.emit(paint(" FAILING FUNCTION", "yellow"))
        logger.emit(f"   {deepest.file}:{deepest.line}  in {deepest.func or '<module>'}")
        if deepest.source:
            logger.emit(paint(f"   {deepest.line:>5} | {deepest.source}", "dim"))
        if len(result.frames) > 1:
            logger.emit()
            logger.emit(paint(" CALL STACK (outer -> inner)", "yellow"))
            for frame in result.frames[-10:]:
                marker = "*" if frame is deepest else " "
                logger.emit(f"  {marker} {frame.file}:{frame.line}  in {frame.func or '<module>'}")

    if result.tail:
        logger.emit()
        logger.emit(paint(" LAST OUTPUT", "yellow"))
        for line in result.tail[-15:]:
            logger.emit(paint("   " + strip_ansi(line), "dim"))

    log_hint = result.step.id.replace("/", "__")
    logger.emit(paint(f" Full child output: logs/{safe_name(log_hint)}.log", "dim"))
    logger.emit(paint("=" * 100, "red"))
    logger.emit()


def execute(entries: list[PlanEntry], ctx: Context, hw: Hardware,
            logger: RunLogger) -> tuple[list[Result], bool]:
    results: list[Result] = []
    interrupted = False
    last_stage = ""
    total = len(entries)

    for idx, entry in enumerate(entries, 1):
        step = entry.step
        if entry.reason:
            results.append(Result(step, "SKIP", reason=entry.reason))
            continue

        if step.stage != last_stage:
            last_stage = step.stage
            logger.emit()
            logger.emit(paint(f"┌─ STAGE: {step.stage.upper()} " + "─" * (80 - len(step.stage)), "magenta"))
            if step.stage == "sweyntooth":
                logger.emit(paint(
                    "│  Requires SweynTooth driver firmware on the nRF52840.\n"
                    "│  A dongle running WHAD/ButteRFly cannot do this at the same time.\n"
                    "│  Re-flash first, or use a second nRF52840 dongle.",
                    "yellow"))
            if step.stage == "zephyr":
                logger.emit(paint(
                    "│  Requires ZEPHYR USB-HCI firmware (shows up as hci1),\n"
                    "│  not WHAD and not SweynTooth firmware.",
                    "yellow"))

        effective_timeout = step.timeout or ctx.args.timeout or 120
        flags = []
        if step.destructive:
            flags.append(paint("DESTRUCTIVE", "red"))
        if step.timeout_ok:
            flags.append(paint("TIMEOUT-OK", "cyan"))
        flag_text = ("  " + " ".join(flags)) if flags else ""

        logger.emit()
        logger.emit(paint(f"[{idx:>3}/{total}] {step.id}", "bold") + flag_text)
        logger.emit(paint(
            f"       hardware: {', '.join(step.hardware) or '-'}   "
            f"timeout: {effective_timeout}s", "dim"))
        if step.note:
            logger.emit(paint(f"       {step.note}", "dim"))

        if ctx.args.dry_run:
            logger.emit(paint("  $ " + " ".join(shlex.quote(p) for p in step.command(ctx)), "dim"))
            logger.emit(paint(f"  cwd: {step.cwd_path(ctx)}", "dim"))
            results.append(Result(step, "DRYRUN", command=step.command(ctx)))
            logger.emit(paint("  [DRY-RUN] not executed", "blue"))
            continue

        per_log = ctx.run_dir / "logs" / f"{safe_name(step.id)}.log"
        try:
            result = run_step(step, ctx, logger, per_log, effective_timeout)
        except KeyboardInterrupt:
            interrupted = True
            logger.emit(paint(" Interrupted by user.", "red"))
            break

        results.append(result)
        color = {
            "PASS": "green", "FAIL": "red", "TIMEOUT": "red",
            "TIMEOUT-OK": "cyan", "WARN": "yellow", "SKIP": "dim",
        }.get(result.status, "reset")
        logger.emit(paint(
            f"  => {result.status}  ({result.duration:.1f}s)"
            + (f"  {result.reason}" if result.reason else ""),
            color))

        if result.status in {"FAIL", "TIMEOUT"}:
            print_failure(result, logger)
            if ctx.args.stop_on_fail:
                logger.emit(paint(" Stopping: --stop-on-fail is set.", "yellow"))
                break

    return results, interrupted


# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------
def summarize(results: list[Result], ctx: Context, hw: Hardware,
              logger: RunLogger, interrupted: bool) -> int:
    counts: dict[str, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1

    failed = counts.get("FAIL", 0) + counts.get("TIMEOUT", 0)

    logger.emit()
    logger.emit(paint("=" * 100, "cyan"))
    logger.emit(paint(" SUMMARY", "bold"))
    logger.emit(paint("=" * 100, "cyan"))
    order = ["PASS", "FAIL", "TIMEOUT", "TIMEOUT-OK", "WARN", "SKIP", "DRYRUN"]
    logger.emit("  " + "   ".join(
        f"{name}={counts.get(name, 0)}" for name in order if counts.get(name, 0) or name in {"PASS", "FAIL"}))
    logger.emit(f"  target: {ctx.target}   profile: {ctx.args.profile}   "
                f"run dir: {ctx.run_dir}")

    if counts.get("TIMEOUT-OK"):
        logger.emit(paint(
            "  TIMEOUT-OK = long-running tool stopped on purpose; not a failure.", "dim"))

    if failed or interrupted:
        logger.emit()
        logger.emit(paint(" FAILED / TIMED OUT STEPS", "red"))
        for result in results:
            if result.status in {"FAIL", "TIMEOUT"}:
                logger.emit(f"   {paint(result.status, 'red'):<18} {result.step.id}")
                if result.frames:
                    frame = result.frames[-1]
                    logger.emit(paint(
                        f"      -> {frame.file}:{frame.line} in {frame.func or '<module>'}", "dim"))
                elif result.reason:
                    logger.emit(paint(f"      -> {result.reason}", "dim"))

    # machine-readable + markdown
    meta = {
        "started": ctx.args.started_at,
        "finished": _dt.datetime.now().isoformat(timespec="seconds"),
        "target": ctx.target,
        "profile": ctx.args.profile,
        "stages": effective_stages(ctx.args),
        "python": ctx.python,
        "whad_port": ctx.whad_port,
        "nrf_port": ctx.nrf_port,
        "sniffle_port": ctx.sniffle_port,
        "interrupted": interrupted,
        "counts": counts,
    }
    payload = {
        "meta": meta,
        "hardware": {
            tag: {"available": st.available, "detail": st.detail}
            for tag, st in hw.tags.items()
        },
        "results": [result.to_dict() for result in results],
    }
    try:
        (ctx.run_dir / "summary.json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8")
    except OSError as exc:
        logger.emit(paint(f"  could not write summary.json: {exc}", "yellow"))

    try:
        md = [
            f"# BLE lab run - {meta['started']}",
            "",
            f"- Target: `{ctx.target}`",
            f"- Profile: `{ctx.args.profile}`",
            f"- Interrupted: `{interrupted}`",
            f"- Counts: `{counts}`",
            "",
            "| Status | Step | Duration | Failing location |",
            "|---|---|---|---|",
        ]
        for result in results:
            loc = ""
            if result.frames:
                frame = result.frames[-1]
                loc = f"`{Path(frame.file).name}:{frame.line}` in `{frame.func}`"
            md.append(f"| {result.status} | `{result.step.id}` | "
                      f"{result.duration:.1f}s | {loc} |")
        (ctx.run_dir / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    except OSError:
        pass

    logger.emit()
    logger.emit(f"  Artifacts: {ctx.run_dir}")
    logger.emit(f"    runner.log, summary.json, summary.md, logs/, work/")
    logger.emit()

    if interrupted:
        return 130
    return 1 if failed else 0


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_all_ble.py",
        description="Run the BLE lab attack/assessment scripts in order, with "
                    "live output, hardware/dongle checks and failing-function reports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Profiles:
  safe        doctor + offline packet build + GATT recon only
  recon       safe + Sniffle passive capture (if a sniffer is attached)
  whad        WHAD/ButteRFly link-layer suite
  sweyntooth  nRF52840 + SweynTooth PoC suite
  iot-ble     full BLE assessment: recon -> sniffle -> WHAD -> host -> SweynTooth
  all         iot-ble + optional ZEPHYR HCI tests

Examples:
  ./scripts/run_all_ble.py --hw-check
  ./scripts/run_all_ble.py --list
  ./scripts/run_all_ble.py --profile safe --target C0:00:00:41:73:AC
  ./scripts/run_all_ble.py --profile iot-ble --target C0:00:00:41:73:AC --yes
  ./scripts/run_all_ble.py --stage whad --yes
  ./scripts/run_all_ble.py --only 'whad/2_send_packet' --dry-run --yes
  ./scripts/run_all_ble.py --profile sweyntooth --nrf-port COM3 --yes   # Windows
  ./scripts/run_all_ble.py --profile sweyntooth --nrf-port /dev/ttyACM1 --yes   # Linux

Safety:
  Destructive steps require --yes (or typing "I OWN THE TARGET" at a TTY).
""")

    parser.add_argument("--target", default=DEFAULT_TARGET,
                        help=f"target BLE MAC (default: {DEFAULT_TARGET})")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="iot-ble",
                        help="ordered test profile (default: iot-ble)")
    parser.add_argument("--stage", action="append", choices=STAGES,
                        help="run only this stage; repeatable (overrides profile stages)")
    parser.add_argument("--skip-stage", action="append", choices=STAGES,
                        help="skip this stage; repeatable")
    parser.add_argument("--only", action="append", metavar="ID_OR_GLOB",
                        help="run only matching step ids or script names; repeatable")
    parser.add_argument("--skip", action="append", metavar="ID_OR_GLOB",
                        help="skip matching step ids or script names; repeatable")
    parser.add_argument("--include", action="append",
                        choices=["destructive", "long", "duplicates", "optional",
                                 "interactive"],
                        help="include a class of steps normally filtered out; repeatable")

    parser.add_argument("--python", default=None,
                        help="Python interpreter for the target scripts "
                             "(default: lab venv, then current Python)")
    parser.add_argument("--whad-port", default=DEFAULT_WHAD_PORT,
                        help=f"WHAD logical port (default: {DEFAULT_WHAD_PORT})")
    parser.add_argument("--nrf-port", default=None,
                        help="serial port for SweynTooth scripts (default: auto)")
    parser.add_argument("--sniffle-port", default=None,
                        help="serial port for the Sniffle Launchpad (default: auto)")

    parser.add_argument("-l", "--list-scripts", action="store_true",
                        help="list every script with its 2-word function and "
                             "whether it needs hardware, then exit")
    parser.add_argument("-N", "--number", type=int, metavar="N",
                        help="run only script number N from the -l catalogue")
    parser.add_argument("--list", action="store_true",
                        help="show the plan for the selected profile and exit")
    parser.add_argument("--list-all", action="store_true",
                        help="show every manifest step, including filtered-out ones")
    parser.add_argument("--hw-check", action="store_true",
                        help="print the full hardware/dongle report and exit")
    parser.add_argument("--dry-run", action="store_true",
                        help="check hardware and print commands without running them")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="confirm authorization for destructive steps")
    parser.add_argument("--force", action="store_true",
                        help="run steps even when their hardware is not detected")
    parser.add_argument("--timeout", type=int, default=120,
                        help="default per-script timeout in seconds (default: 120)")
    parser.add_argument("--stop-on-fail", action="store_true",
                        help="stop after the first FAIL/TIMEOUT")
    parser.add_argument("--quiet", action="store_true",
                        help="do not stream child output (errors are still shown)")
    parser.add_argument("--no-target-check", action="store_true",
                        help="skip the preflight BLE scan for the target")
    parser.add_argument("--target-scan-time", type=int, default=8,
                        help="target preflight scan seconds (default: 8)")
    parser.add_argument("--log-dir", default=str(DEFAULT_RUNS_DIR),
                        help=f"where to write run artifacts (default: {DEFAULT_RUNS_DIR})")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI colours")
    return parser


def pick_python(explicit: Optional[str]) -> str:
    if explicit:
        candidate = Path(explicit).expanduser()
        if candidate.exists():
            return str(candidate.resolve())
        return explicit
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


def make_run_dir(base: str) -> Path:
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    root = Path(base).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    suffix = 0
    while True:
        name = stamp if suffix == 0 else f"{stamp}-{suffix}"
        run_dir = root / name
        try:
            run_dir.mkdir(parents=True, exist_ok=False)  # atomic reservation
        except FileExistsError:
            suffix += 1
            continue
        (run_dir / "logs").mkdir(exist_ok=True)
        (run_dir / "work").mkdir(exist_ok=True)
        return run_dir


def _auto_nrf_port() -> str:
    # Prefer a real Nordic / WHAD serial port over an unrelated ttyACM.
    ttys = _detect_ttys()
    for name, dev in ttys.items():
        if dev and (dev.vid == "1915" or (dev.vid, dev.pid) == ("c0ff", "eeee")):
            return name
    if IS_LINUX:
        for pattern in ("ttyACM*", "ttyUSB*"):
            ports = sorted(Path("/dev").glob(pattern))
            if ports:
                return str(ports[0])
        return "/dev/ttyACM0"
    # Windows / macOS: first enumerated serial port, else a sensible guess.
    ports = list(ttys.keys())
    if ports:
        return sorted(ports)[0]
    return "COM3" if IS_WINDOWS else "/dev/ttyACM0"


def main(argv: Optional[list[str]] = None) -> int:
    global USE_COLOR
    enable_windows_ansi()
    args = build_parser().parse_args(argv)
    USE_COLOR = (not args.no_color) and sys.stdout.isatty()

    target = normalize_mac(args.target)
    if not target:
        print(f"error: '{args.target}' is not a valid Bluetooth MAC address", file=sys.stderr)
        return 2
    if args.timeout < 1:
        print("error: --timeout must be at least 1 second", file=sys.stderr)
        return 2
    if args.target_scan_time < 1:
        print("error: --target-scan-time must be at least 1 second", file=sys.stderr)
        return 2
    args.target = target
    args.started_at = _dt.datetime.now().isoformat(timespec="seconds")

    catalog = catalog_steps(args)
    numbered_step: Optional[Step] = None
    if args.number is not None:
        if not (1 <= args.number <= len(catalog)):
            print(f"error: -N/--number must be between 1 and {len(catalog)} "
                  f"(see -l)", file=sys.stderr)
            return 2
        numbered_step = catalog[args.number - 1]

    preview_only = (args.hw_check or args.list or args.list_all
                    or args.list_scripts)
    if preview_only:
        run_dir = Path(args.log_dir).expanduser().resolve() / "_preview"
    else:
        run_dir = make_run_dir(args.log_dir)
    ctx = Context(
        args=args,
        python=pick_python(args.python),
        target=target,
        whad_port=args.whad_port,
        nrf_port=args.nrf_port or _auto_nrf_port(),
        sniffle_port=args.sniffle_port,
        run_dir=run_dir,
    )

    if args.list_scripts:
        print_script_catalog(catalog, args.skip_stage or [])
        return 0

    if args.hw_check:
        hw = detect_hardware(ctx)
        print(paint("=" * 100, "cyan"))
        print(paint(" BLE LAB HARDWARE REPORT", "bold"))
        print(paint("=" * 100, "cyan"))
        print_hardware(hw, ALL_STEPS, full=True, python=ctx.python)
        return 0

    if numbered_step is not None and not (args.list or args.list_all):
        entries = [PlanEntry(numbered_step)]
    else:
        entries = select_plan(ctx, include_all=bool(args.list_all))
    if args.list or args.list_all:
        print(paint("=" * 100, "cyan"))
        print(paint(" BLE LAB RUNNER - MANIFEST", "bold"))
        print(paint("=" * 100, "cyan"))
        print(f" Target : {ctx.target}")
        print(f" Profile: {args.profile}   Python: {ctx.python}")
        print(f" Stages : {', '.join(effective_stages(args))}")
        print_plan(entries)
        if args.list_all:
            print(paint("Legend: SKIP lines are filtered by the current profile/flags.", "dim"))
        return 0

    logger = RunLogger(run_dir / "runner.log")

    logger.emit(paint("=" * 100, "cyan"))
    logger.emit(paint(" BLE LAB ORCHESTRATOR - ordered IoT BLE security test run", "bold"))
    logger.emit(paint("=" * 100, "cyan"))
    logger.emit(f" Target : {ctx.target}")
    logger.emit(f" Profile: {args.profile}")
    logger.emit(f" Python : {ctx.python}")
    logger.emit(f" Run dir: {ctx.run_dir}")
    logger.emit(paint(
        " WARNING: attack/DoS tooling. Use only on devices you own or have "
        "explicit written authorization to test.", "yellow"))

    hw = detect_hardware(ctx)
    print_hardware(hw, [entry.step for entry in entries], python=ctx.python)

    # Re-evaluate hardware availability against the plan.
    for entry in entries:
        if entry.reason:
            continue
        missing = hw_skip_reason(entry.step, hw, args.force)
        if missing:
            entry.reason = missing
            continue
        if (entry.step.stage == "sweyntooth" and not args.force
                and not hw.imports.get("scapy_bt")):
            entry.reason = ("SweynTooth Python deps fail to import "
                            "(bundled scapy.layers.bluetooth; see hardware check)")

    print_plan(entries)

    if args.dry_run:
        logger.emit(paint("[dry-run] authorization prompt and target scan skipped", "blue"))
    else:
        if not confirm_authorization(entries, args.yes):
            logger.close()
            return 3
        if numbered_step is not None and "TARGET" not in numbered_step.hardware:
            print(paint("[target] skipped: the selected script does not use the "
                        "target", "dim"))
        else:
            check_target(ctx, hw)

    try:
        try:
            results, interrupted = execute(entries, ctx, hw, logger)
        except KeyboardInterrupt:
            results, interrupted = [], True
        return summarize(results, ctx, hw, logger, interrupted)
    finally:
        logger.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
