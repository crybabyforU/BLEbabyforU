#!/usr/bin/env python3
# ============ CONNECT_IND SENDER (via ButteRFly firmware) ============
import argparse, sys
from whad.device import WhadDevice
from whad.ble.connector import Central
from whad.ble.exceptions import PeripheralNotFound
from whad.hub.ble import ChannelMap

def _parse_args():
    p = argparse.ArgumentParser(description="Connect to a target with custom Link Layer parameters via WHAD ButteRFly.")
    p.add_argument("mac", nargs="?", default="C0:00:00:41:73:AC", help="target MAC (default: %(default)s)")
    p.add_argument("--public", action="store_true", help="target uses a public address (default: random)")
    p.add_argument("--port", default="uart0", help="WHAD dongle port (default: %(default)s)")
    return p.parse_args()

ARGS = _parse_args()

TARGET    = ARGS.mac
IS_RANDOM = not ARGS.public                       # ADV_IND showed TxAdd=1 (random static)

# ---- same custom LLData fields as the builder ----
CUSTOM = dict(
    access_address=0xD4C3B2A1,                     # A1 B2 C3 D4
    crc_init=0x563412,                             # 12 34 56
    channel_map=ChannelMap.from_int(0x1FFFFFFFFF), # FF FF FF FF 1F  <- object, not int!
    hop_interval=24,                               # 30 ms
    hop_increment=13,                              # hop 13
)

central = Central(WhadDevice.create("uart0"))
print(f"[*] Sending custom CONNECT_IND -> {TARGET} (random/static)")
print(f"    AA=0x{CUSTOM['access_address']:08X}  CRCInit=0x{CUSTOM['crc_init']:06X}  "
      f"Interval={CUSTOM['hop_interval']*1.25:.0f}ms  Hop={CUSTOM['hop_increment']}")

try:
    conn = central.connect(TARGET, random=IS_RANDOM, **CUSTOM)
except PeripheralNotFound:
    print("[-] FAILED - device not advertising connectably, or it rejected the packet")
    print("    -> rescan: wble-central -i uart0 scan")
    print("    -> A/B control: central.connect(TARGET, random=True) with defaults")
    sys.exit(1)

print("[+] CONNECTED - live link running on YOUR AA / CRCInit / interval / hop")
try:
    conn.discover()
    print("[+] GATT discovery OK - link fully functional")
    svcs = conn.services
    if callable(svcs): svcs = svcs()
    for s in svcs: print(f"    service: {s}")
except Exception as e:
    print(f"[!] discovery hiccup (link may still be alive): {e}")

try: conn.disconnect()
except Exception: pass
print("[*] Done - terminated on your AA.")
