#!/usr/bin/env python3
import argparse, time, sys

def _parse_args():
    p = argparse.ArgumentParser(description="A/B diagnose: default vs custom Link Layer params, then interval sweep.")
    p.add_argument("mac", nargs="?", default="C0:00:00:41:73:AC", help="target MAC (default: %(default)s)")
    p.add_argument("--port", default="uart0", help="WHAD dongle port (default: %(default)s)")
    return p.parse_args()

ARGS = _parse_args()

TARGET=ARGS.mac; ADVA=bytes.fromhex(TARGET.replace(":",""))[::-1]
RAW=bytes.fromhex("8522AABBCCDDEEFFAC73410000C0A1B2C3D412345602000018000000C800FFFFFFFF1F2D")
T0=time.time()
def log(m): print(f"[{time.time()-T0:6.2f}s] {m}", flush=True)
from whad.device import WhadDevice
from whad.ble.connector import Central, Injector
from whad.hub.ble import ChannelMap

def open_conn(mode="scan"):
    for i in range(6):
        try:
            d=WhadDevice.create(ARGS.port); c=Central(d)
            if mode=="scan":
                ij=None
            try: c.set_bd_address("FF:EE:DD:CC:BB:AA")
            except Exception as e: log(f"  set_bd_address: {type(e).__name__}")
            return d,c
        except Exception: time.sleep(1.2)
    return None,None

def scan_present(secs=6):
    for i in range(4):
        try:
            d=WhadDevice.create(ARGS.port); ij=Injector(d)
            try: ij.enable_scan_mode()
            except Exception: pass
            try: ij.start()
            except Exception: pass
            n={"c":0}; orig=ij.on_adv_pdu
            def hook(p,*a,**k):
                try:
                    if ADVA in bytes(p): n["c"]+=1
                except Exception: pass
                try: return orig(p,*a,**k)
                except Exception: pass
            ij.on_adv_pdu=hook
            t=time.time()
            while time.time()-t<secs and n["c"]==0: time.sleep(0.1)
            try: d.close()
            except Exception: pass
            return n["c"]
        except Exception: time.sleep(1.2)
    return -1

def attempt(label, **kw):
    d,c=open_conn()
    if not c: log(f"[{label}] no dongle"); return None
    hook_orig=c.on_disconnected
    def dh(*a,**k):
        log(f"[{label}] !!! disconnect event: {a} {k}")
        try: return hook_orig(*a,**k)
        except Exception: pass
    c.on_disconnected=dh
    t=time.time()
    try:
        conn=c.connect(TARGET, random=True, **kw)
    except Exception as e:
        log(f"[{label}] CONNECT FAILED after {time.time()-t:.1f}s: {type(e).__name__}")
        try: d.close()
        except Exception: pass
        return "connfail"
    log(f"[{label}] CONNECTED at t+{time.time()-t:.2f}s")
    res="alive"
    for i in range(5):
        time.sleep(0.8)
        try:
            conn.discover()
            sv=conn.services
            if callable(sv): sv=sv()
            log(f"[{label}] probe{i+1}: ALIVE, {len(sv)} services  <-- LINK SURVIVES")
            res="alive"
            break
        except Exception as e:
            log(f"[{label}] probe{i+1}: link DEAD at t+{time.time()-t:.2f}s ({type(e).__name__})")
            res=f"dead@{time.time()-t:.1f}s"
            break
    try: d.close()
    except Exception: pass
    return res

log("device advertising now?  "+("YES" if scan_present()>0 else "NO -> make it advertise first"))
log("="*60)
log("PHASE 1a - DEFAULT params")
r1=attempt("default")
time.sleep(3)
log("PHASE 1b - CUSTOM params (30ms/hop13)")
r2=attempt("custom", access_address=0xD4C3B2A1, crc_init=0x563412,
           channel_map=ChannelMap.from_int(0x1FFFFFFFFF), hop_interval=24, hop_increment=13)
log("="*60)
if r1=="alive" and isinstance(r2,str) and r2.startswith("dead"):
    log("PHASE 2 - custom kills it -> interval sweep (hop13, longer intervals)")
    for iv in (80,160,320):
        time.sleep(3)
        r=attempt(f"iv{iv}({iv*1.25:.0f}ms)", access_address=0xD4C3B2A1, crc_init=0x563412,
                  channel_map=ChannelMap.from_int(0x1FFFFFFFFF), hop_interval=iv, hop_increment=13)
        if r=="alive":
            log(f">>> DEVICE TOLERATES interval {iv} ({iv*1.25:.0f}ms) with your AA/CRCInit!")
            break
elif r1=="alive" and r2=="alive":
    log(">>> BOTH SURVIVE - full custom connect functional. DEMO COMPLETE.")
elif isinstance(r1,str) and r1.startswith("dead"):
    log(">>> default ALSO dies at discovery -> device wants PAIRING or firmware lacks a control PDU")
    log("    next: try wble-central connect + 'discover' interactively; and try pairing after connect")
else:
    log(">>> connect-level failure - check advertising/phone interference")
log("post-mortem: device advertising again?  "+("YES" if scan_present(8)>0 else "NO"))
