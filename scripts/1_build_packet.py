#!/usr/bin/env python3
# ============ CONNECT_IND PACKET CREATOR ============
import argparse, re

def _parse_args():
    p = argparse.ArgumentParser(description="Build & verify a 36-byte BLE CONNECT_IND packet (offline, no hardware).")
    p.add_argument("mac", nargs="?", default=None, help="target AdvA MAC (default: C0:00:00:41:73:AC)")
    p.add_argument("--inita", default="FF:EE:DD:CC:BB:AA", help="claimed central InitA (default: %(default)s)")
    return p.parse_args()

ARGS = _parse_args()

# ---- THE 13 KNOBS (same values used in the sender) ----
INITA, INITA_RANDOM = ARGS.inita, False                  # claimed central  -> TxAdd=0
ADVA,  ADVA_RANDOM  = ARGS.mac or "C0:00:00:41:73:AC", True  # target -> RxAdd=1
AA, CRCINIT         = 0xD4C3B2A1, 0x563412          # connection AA + CRC seed
WINSIZE, WINOFFSET  = 2, 0x0000                     # 2.5 ms / 0 ms
INTERVAL, LATENCY   = 0x0018, 0x0000                # 30 ms / 0
TIMEOUT             = 0x00C8                        # 2000 ms
CHANMAP, HOP, SCA   = "FFFFFFFF1F", 13, 1           # 37 ch / hop 13 / SCA 1
ADV_AA = 0x8E89BED6

# ---- helpers ----
def ble_crc24(d: bytes, init=0x555555) -> int:      # BLE CRC: LSB-first, poly 0x100065B
    c = init
    for b in d:
        for i in range(8):
            c = ((c << 1) ^ 0x100065B) & 0xFFFFFF if ((c >> 23) & 1) ^ ((b >> i) & 1) else (c << 1) & 0xFFFFFF
    return c

def mac(s): return bytes.fromhex(s.replace(":", ""))[::-1]   # wire order = LSB octet first

def aa_bad(a):
    if a in (0, 0xFFFFFFFF): return "all-0s/all-1s"
    if a == ADV_AA:          return "== advertising AA"
    b = f"{a:032b}"
    if max(len(r) for r in re.findall(r"0+|1+", b)) > 6:  return ">6 same bits"
    if sum(x != y for x, y in zip(b, b[1:])) > 26:        return ">26 transitions"
    return None

# ---- BUILD (Length and CRC computed, never typed) ----
lld = (AA.to_bytes(4,'little') + CRCINIT.to_bytes(3,'little') + bytes([WINSIZE])
     + WINOFFSET.to_bytes(2,'little') + INTERVAL.to_bytes(2,'little')
     + LATENCY.to_bytes(2,'little') + TIMEOUT.to_bytes(2,'little')
     + bytes.fromhex(CHANMAP) + bytes([HOP | (SCA << 5)]))
payload = mac(INITA) + mac(ADVA) + lld                      # 6 + 6 + 22 = 34
hdr0 = 0x05 | (0x40 if INITA_RANDOM else 0) | (0x80 if ADVA_RANDOM else 0)
pdu  = bytes([hdr0, len(payload)]) + payload                # <- Length auto = 0x22
crc  = ble_crc24(pdu)

def hx(b): return b.hex(" ").upper()
print(f"{'Field':<16} {'Hex':<26} Meaning"); print("-"*90)
for n, h, m in [
    ("Preamble",      "AA",                             "derived (radio adds it)"),
    ("Access Addr",   "D6 BE 89 8E",                    "fixed 0x8E89BED6 (radio adds it)"),
    ("PDU Header",    hx(bytes([hdr0, len(payload)])),  f"CONNECT_IND TxAdd={'rnd' if INITA_RANDOM else 'pub'} RxAdd={'rnd' if ADVA_RANDOM else 'pub'} Len={len(payload)} (auto)"),
    ("InitA",         hx(mac(INITA)),                   f"{INITA}"),
    ("AdvA",          hx(mac(ADVA)),                    f"{ADVA} - random static"),
    ("LL AA",         hx(AA.to_bytes(4,'little')),      f"0x{AA:08X}"),
    ("LL CRCInit",    hx(CRCINIT.to_bytes(3,'little')), f"0x{CRCINIT:06X}"),
    ("LL WinSize",    f"{WINSIZE:02X}",                 f"{WINSIZE*1.25:.1f} ms"),
    ("LL WinOffset",  hx(WINOFFSET.to_bytes(2,'little')), f"{WINOFFSET*1.25:.0f} ms"),
    ("LL Interval",   hx(INTERVAL.to_bytes(2,'little')), f"{INTERVAL*1.25:.0f} ms"),
    ("LL Latency",    hx(LATENCY.to_bytes(2,'little')), f"{LATENCY}"),
    ("LL Timeout",    hx(TIMEOUT.to_bytes(2,'little')), f"{TIMEOUT*10} ms"),
    ("LL ChanMap",    hx(bytes.fromhex(CHANMAP)),       "37 channels"),
    ("LL Hop/SCA",    f"{HOP|(SCA<<5):02X}",            f"hop={HOP} sca={SCA}"),
    ("CRC (radio)",   hx(crc.to_bytes(3,'little')),     "computed, air-order"),
]: print(f"{n:<16} {h:<26} {m}")

print("\nPDU (TX buffer) :", pdu.hex().upper())
print("CRC on-air      :", crc.to_bytes(3,'little').hex().upper())

print("\nSpec checks:")
bad = aa_bad(AA)
print(f"  [{'PASS' if not bad else 'FAIL'}] AA legality {bad or ''}")
print(f"  [{'PASS' if 5<=HOP<=16 else 'FAIL'}] hop 5-16")
print(f"  [{'PASS' if TIMEOUT > 2*(1+LATENCY)*INTERVAL else 'FAIL'}] timeout rule")
print(f"  [{'PASS' if WINOFFSET <= INTERVAL else 'FAIL'}] WinOffset <= Interval")
top = mac(ADVA)[-1] >> 6
print(f"  AdvA top bits {top:02b} -> " + {0b11:"static random (stable MAC)", 0b01:"RPA", 0b00:"non-resolvable", 0b10:"reserved"}[top])
