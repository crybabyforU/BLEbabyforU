#!/usr/bin/env python3
import argparse, time, inspect
from whad.device import WhadDevice
from whad.ble.connector import Central
from whad.hub.ble import ChannelMap

def _parse_args():
    p = argparse.ArgumentParser(description="Answer ATT_EXCHANGE_MTU_REQ on a rogue link to keep it alive.")
    p.add_argument("mac", nargs="?", default="C0:00:00:41:73:AC", help="target MAC (default: %(default)s)")
    p.add_argument("--mtu", type=int, default=247, help="MTU to reply with (default: %(default)s)")
    p.add_argument("--port", default="uart0", help="WHAD dongle port (default: %(default)s)")
    return p.parse_args()

ARGS = _parse_args()

TARGET, DEV_MTU = ARGS.mac, ARGS.mtu
T0 = time.time()
def log(m): print(f"[{time.time()-T0:6.2f}s] {m}", flush=True)

dev = WhadDevice.create(ARGS.port); central = Central(dev)
try: central.set_bd_address("FF:EE:DD:CC:BB:AA")
except Exception as e: log(f"set_bd_address: {type(e).__name__}: {e}")

if hasattr(central, "send_data_pdu"):
    try: log("send_data_pdu" + str(inspect.signature(central.send_data_pdu)))
    except Exception: pass
else:
    log("send_data_pdu MISSING. hub data methods: "
        + str([m for m in dir(central.hub.ble) if 'data' in m.lower() or 'pdu' in m.lower()]))

S = {"handle": None, "pending": False, "reqs": 0, "answered": 0}

def respond(handle):
    frames = [("L2CAP frame bytes", b"\x03\x00\x04\x00\x03" + DEV_MTU.to_bytes(2, 'little'))]
    try:
        from scapy.layers.bluetooth4LE import BTLE_DATA
        from scapy.layers.bluetooth import L2CAP_Hdr, ATT_Exchange_MTU_Response
        frames.insert(0, ("scapy stack", BTLE_DATA() / L2CAP_Hdr(cid=0x0004)
                          / ATT_Exchange_MTU_Response(mtu=DEV_MTU)))
    except Exception as e: log(f"(scapy ATT unavailable: {type(e).__name__})")
    for name, pkt in frames:
        try:
            r = central.send_data_pdu(pkt, conn_handle=handle)
            log(f">> MTU_RSP sent ({name}) -> {r}")
            S["answered"] += 1
            return True
        except Exception as e:
            log(f"  x {name}: {type(e).__name__}: {e}")
    return False

_orig = central.on_data_pdu
def _data(pdu=None, *a, **k):
    try:
        b = bytes(pdu)                       # RX format: [2B hdr][2B len][2B CID][ATT...]
        if len(b) >= 9 and b[4:6] == b"\x04\x00" and b[6] == 0x02:
            S["reqs"] += 1; S["pending"] = True
            log(f"<<< ATT_EXCHANGE_MTU_REQ (mtu={int.from_bytes(b[7:9],'little')}) - queued")
            return None
    except Exception: pass
    try: return _orig(pdu, *a, **k)
    except Exception: return None
central.on_data_pdu = _data

log("connecting (CUSTOM params) ...")
t = time.time()
try:
    conn = central.connect(TARGET, random=True, access_address=0xD4C3B2A1, crc_init=0x563412,
                           channel_map=ChannelMap.from_int(0x1FFFFFFFFF),
                           hop_interval=24, hop_increment=13)
except Exception as e:
    log(f"connect failed: {type(e).__name__}: {e}"); raise SystemExit(1)
S["handle"] = getattr(conn, "conn_handle", None)
log(f"CONNECTED t+{time.time()-t:.2f}s  conn_handle={S['handle']}")

alive = True
for i in range(1, 15):
    time.sleep(0.2)
    if S["pending"] and S["handle"] is not None:
        S["pending"] = False
        respond(S["handle"])
    if i in (5, 10): log(f"  t+{i*0.2:.1f}s ... still running (answered={S['answered']})")
    if i == 6 and S["answered"]:
        log("attempting GATT discovery ...")
        try:
            conn.discover()
            sv = conn.services
            if callable(sv): sv = sv()
            log(f"[+] DISCOVERY OK - {len(sv)} services")
            for s in sv: log(f"    {s}")
        except Exception as e:
            log(f"[!] discovery: {type(e).__name__}: '{e}'")
try: conn.disconnect()
except Exception: pass
log("="*58)
log(f"MTU reqs seen: {S['reqs']} | answered: {S['answered']}")
if S["answered"]: log("LINK SURVIVED THE MTU EXCHANGE -> read the DISCOVERY line above")
else: log("no send path worked -> paste this output, next stop: WHAD host-stack binding fix")
log("="*58)
