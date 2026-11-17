#!/usr/bin/env python3
import argparse, time
from whad.device import WhadDevice
from whad.ble.connector import Central
from whad.hub.ble import ChannelMap

def _parse_args():
    p = argparse.ArgumentParser(description="Post-mortem: capture LL control/data PDUs and HCI termination codes while idle.")
    p.add_argument("mac", nargs="?", default="C0:00:00:41:73:AC", help="target MAC (default: %(default)s)")
    p.add_argument("--port", default="uart0", help="WHAD dongle port (default: %(default)s)")
    return p.parse_args()

ARGS = _parse_args()

TARGET = ARGS.mac
T0 = time.time()
def log(m): print(f"[{time.time()-T0:6.2f}s] {m}", flush=True)
HCI = {0x08:"CONNECTION TIMEOUT (supervision)", 0x13:"REMOTE USER TERMINATED (device killed us)",
       0x16:"LOCAL HOST TERMINATED", 0x3B:"UNREASONABLE INTERVAL",
       0x3E:"LL RESPONSE TIMEOUT", 0x06:"FAILED TO ESTABLISH"}

dev = WhadDevice.create(ARGS.port)   # ONE device the whole run -> no fd errors
central = Central(dev)
DIE = {"t": None, "why": None}

_orig_disc = central.on_disconnected
def _disc(evt=None, *a, **k):
    DIE["t"] = time.time() - T0
    dump = {}
    try:
        for attr in dir(evt):
            if attr.startswith("_"): continue
            try:
                v = getattr(evt, attr)
                if callable(v): continue
                dump[attr] = v if isinstance(v,(int,str,bytes,float,bool)) else repr(v)[:40]
            except Exception: pass
    except Exception as e: dump["err"] = str(e)
    why = dump.get("reason")
    if isinstance(why, int): why = f"0x{why:02X} = {HCI.get(why,'?')}"
    DIE["why"] = dump
    log(f"!!! DISCONNECTED  reason={why}  raw={dump}")
    try: return _orig_disc(evt, *a, **k) if callable(_orig_disc) else None
    except Exception: pass
central.on_disconnected = _disc

_orig_ctl = central.on_ctl_pdu
def _ctl(pdu=None, *a, **k):
    try: log(f"    <- LL CTRL : {bytes(pdu).hex()[:90]}")
    except Exception: pass
    try: return _orig_ctl(pdu)
    except Exception:
        try: return _orig_ctl(pdu, *a, **k)
        except Exception: return None
central.on_ctl_pdu = _ctl

_orig_data = central.on_data_pdu
def _data(pdu=None, *a, **k):
    try: log(f"    <- DATA    : {bytes(pdu).hex()[:90]}")
    except Exception: pass
    try: return _orig_data(pdu)
    except Exception:
        try: return _orig_data(pdu, *a, **k)
        except Exception: return None
central.on_data_pdu = _data

def attempt(label, idle=6.0, **kw):
    DIE["t"] = None; DIE["why"] = None
    t = time.time()
    try:
        conn = central.connect(TARGET, random=True, **kw)
    except Exception as e:
        log(f"[{label}] connect failed: {type(e).__name__}"); return "connfail"
    log(f"[{label}] CONNECTED t+{time.time()-t:.2f}s -- IDLE TEST (no discovery at all)")
    log(f"[{label}] conn API: {[x for x in dir(conn) if not x.startswith('_')]}")
    end = time.time() + idle
    while time.time() < end:
        if DIE["t"] is not None:
            log(f"[{label}] link DIED t+{DIE['t']-t:.2f}s while IDLE (no ATT traffic)")
            return "idledeath"
        time.sleep(0.2)
    log(f"[{label}] link SURVIVED {idle:.0f}s idle <-- peripheral does NOT kill idle links")
    try: conn.disconnect()
    except Exception: pass
    return "idlesurvive"

log("TEST A - DEFAULT params, idle 6s")
rA = attempt("A-default")
time.sleep(3)
log("TEST B - CUSTOM params, idle 6s")
rB = attempt("B-custom", access_address=0xD4C3B2A1, crc_init=0x563412,
             channel_map=ChannelMap.from_int(0x1FFFFFFFFF),
             hop_interval=24, hop_increment=13)
log("="*62)
if rA=="idledeath" and rB=="idledeath":
    log("VERDICT: device kills EVERY connection ~1s in, even idle.")
    log("  -> CUSTOM FIELDS FULLY EXONERATED. Device demands pairing or an LL")
    log("     procedure -- read reason= line + LL CTRL hex dump above for its dying words.")
elif rA=="idlesurvive" and rB=="idledeath":
    log("VERDICT: idle fine, custom-only death -> params DO matter -> interval sweep next")
elif rA=="idlesurvive" and rB=="idlesurvive":
    log("VERDICT: links survive idle! Death is triggered by DISCOVERY traffic (ATT/MTU)")
    log("  -> next round: minimal manual ATT exchange instead of full discover")
else:
    log(f"VERDICT: A={rA} B={rB} -> read log above")
log("="*62)
