#!/usr/bin/env python3
import argparse, time, inspect
from whad.device import WhadDevice
from whad.ble.connector import Central
from whad.hub.ble import ChannelMap
from scapy.layers.bluetooth4LE import BTLE_DATA
from scapy.layers.bluetooth import L2CAP_Hdr, ATT_Exchange_MTU_Response

def _parse_args():
    p = argparse.ArgumentParser(description="Manual ATT over raw L2CAP data PDUs (bypasses the host GATT stack).")
    p.add_argument("mac", nargs="?", default="C0:00:00:41:73:AC", help="target MAC (default: %(default)s)")
    p.add_argument("--mtu", type=int, default=247, help="local ATT MTU to advertise (default: %(default)s)")
    p.add_argument("--port", default="uart0", help="WHAD dongle port (default: %(default)s)")
    return p.parse_args()

ARGS = _parse_args()

TARGET, OUR_MTU, AA = ARGS.mac, ARGS.mtu, 0xD4C3B2A1
T0=time.time()
def log(m): print(f"[{time.time()-T0:6.2f}s] {m}", flush=True)

# ---------- builders (bypass WHAD host stack entirely) ----------
def l2cap(att):  return len(att).to_bytes(2,'little') + b"\x04\x00" + att   # CID 4 = ATT
def fullp(frm):  return bytes([0x02, len(frm)]) + frm                      # LLID=2, L2CAP start
MTU_RSP      = fullp(l2cap(bytes([0x03]) + OUR_MTU.to_bytes(2,'little')))
def svc_req(s,e): return fullp(l2cap(bytes([0x10]) + s.to_bytes(2,'little') + e.to_bytes(2,'little') + (0x2800).to_bytes(2,'little')))
def chr_req(s,e): return fullp(l2cap(bytes([0x08]) + s.to_bytes(2,'little') + e.to_bytes(2,'little') + (0x2803).to_bytes(2,'little')))
RAW_RSP      = bytes.fromhex("0300040003f700")                             # bare L2CAP frame
try:
    RSP_SCAPY = BTLE_DATA(LLID=2) / L2CAP_Hdr(cid=0x0004) / ATT_Exchange_MTU_Response(mtu=OUR_MTU)
    SCAPY_OK = True
except Exception as e:
    log(f"(scapy object format skipped: {type(e).__name__}: {e})"); SCAPY_OK = False

FORMATS = [("bare L2CAP frame",  RAW_RSP, None),
           ("full PDU w/LL hdr", MTU_RSP, None),
           ("raw + our AA",      RAW_RSP, AA)]
if SCAPY_OK: FORMATS.insert(2, ("scapy object", RSP_SCAPY, None))

dev = WhadDevice.create(ARGS.port); central = Central(dev)
try: central.set_bd_address("FF:EE:DD:CC:BB:AA")
except Exception as e: log(f"set_bd_address: {type(e).__name__}")

with open("send_src.txt","w") as f:
    fn = getattr(type(central), "send_data_pdu", None)
    if fn: f.write(f"===== Central.send_data_pdu{inspect.signature(fn)} =====\n" + inspect.getsource(fn))

TERM = {"x": False}
_orig_ctl = central.on_ctl_pdu
def _ctl(pdu=None,*a,**k):
    try:
        b=bytes(pdu)
        if b[:2]==b"\x0b\x02": TERM["x"]=True; log(f"<<< LL_TERMINATE_IND err=0x{b[3]:02x}")
        else: log(f"<<< LLCTRL {b.hex()}")
    except Exception: pass
    try: return _orig_ctl(pdu,*a,**k)
    except Exception: return None
central.on_ctl_pdu=_ctl

SEEN={"att":[]}
_orig_data = central.on_data_pdu
def _data(pdu=None,*a,**k):
    try:
        b=bytes(pdu)
        if len(b)>=7 and b[4:6]==b"\x04\x00":
            op=b[6]; SEEN["att"].append((time.time(),b))
            if   op==0x02: log(f"<<< MTU_REQ mtu={int.from_bytes(b[7:9],'little')}")
            elif op==0x11: log(f"<<< SVC_RSP {b.hex()}")
            elif op==0x09: log(f"<<< CHR_RSP {b.hex()}")
            elif op==0x01: log(f"<<< ATT_ERR req_op=0x{b[7]:02x} err=0x{b[9]:02x}")
            else:          log(f"<<< ATT op=0x{op:02x} {b.hex()[:70]}")
    except Exception: pass
    try: return _orig_data(pdu,*a,**k)
    except Exception: return None
central.on_data_pdu=_data

def conn_custom():
    TERM["x"]=False; SEEN["att"]=[]
    conn=central.connect(TARGET, random=True, access_address=AA, crc_init=0x563412,
                         channel_map=ChannelMap.from_int(0x1FFFFFFFFF),
                         hop_interval=24, hop_increment=13)
    return conn, getattr(conn,"conn_handle",0)

def send(h,payload,aa):
    kw={"access_address":aa} if aa else {}
    try: return central.send_data_pdu(payload, conn_handle=h, **kw)
    except Exception as e:
        log(f"   x send: {type(e).__name__}: {e}"); return False

def pump_rsp(h,payload,aa,until):
    n=0
    while time.time()<until:
        for (t,b) in list(SEEN["att"]):
            if b[6]==0x02 and time.time()-t<0.3:
                if send(h,payload,aa): n+=1
                SEEN["att"]=[x for x in SEEN["att"] if x[0]!=t]
        if TERM["x"]: break
        time.sleep(0.005)
    return n

# ---------- PHASE 1: find a TX format that keeps the link alive ----------
win=None
for name,payload,aa in FORMATS:
    log(f"--- format: {name} ---")
    try: conn,h=conn_custom()
    except Exception as e: log(f"connect fail: {type(e).__name__}"); time.sleep(2); continue
    log(f"connected h={h}; optimistic MTU_RSP now")
    send(h,payload,aa)
    n=pump_rsp(h,payload,aa,time.time()+3.0)
    if TERM["x"]: log(f"[{name}] FAILED (terminated)"); time.sleep(2.5)
    else:
        log(f"[{name}] LINK HELD 3s (answers={n})  << WINNER"); win=(name,payload,aa,conn,h); break
    try: conn.disconnect()
    except Exception: pass

# ---------- PHASE 2: manual ATT discovery on winner ----------
if not win: log("no format survived -> cat send_src.txt and paste it"); raise SystemExit(1)
name,payload,aa,conn,h = win
log("="*58); log(f"PHASE 2: manual GATT discovery via '{name}'")

def att_xchg(req, want, tries=4, wait=0.6):
    for i in range(tries):
        if TERM["x"]: return None
        send(h, req, aa); t=time.time()
        while time.time()-t<wait:
            for (tt,b) in SEEN["att"]:
                if b[6]==want: return b
                if b[6]==0x01 and b[7]==req[6]: return None   # req[6] = ATT opcode
            time.sleep(0.01)
        SEEN["att"]=[x for x in SEEN["att"] if x[1][6]!=want]
    return None

svcs=[]; s=1
while s<=0xFFFF and len(svcs)<12:
    r=att_xchg(svc_req(s,0xFFFF),0x11)
    if r is None: break
    it=r[7]
    for o in range(8,len(r)-3,it):
        st=int.from_bytes(r[o:o+2],'little'); en=int.from_bytes(r[o+2:o+4],'little')
        uu=r[o+4:o+it]
        uuid=uu[::-1].hex().upper()
        svcs.append((st,en,uuid)); log(f"    service {st:04X}-{en:04X}  uuid 0x{uuid}")
    s=svcs[-1][1]+1
log(f"[+] {len(svcs)} SERVICES discovered via MANUAL ATT on YOUR custom link")

if svcs:
    st,en,_=svcs[0]; chs=[]; s=st
    while s<=en:
        r=att_xchg(chr_req(s,en),0x09)
        if r is None: break
        it=r[7]
        for o in range(8,len(r)-4,it):
            vh=int.from_bytes(r[o+3:o+5],'little')          # item: decl(2) props(1) valHnd(2)
            uu=r[o+5:o+it]; uuid=uu and uu[::-1].hex().upper() or "?"
            chs.append((vh,uuid)); log(f"    characteristic val-handle {vh:04X} uuid 0x{uuid}")
        s=(chs[-1][0]+1) if chs else en+1
    log(f"[+] {len(chs)} characteristics in first service")

log("="*58)
log("VERDICT: custom CONNECT_IND -> accepted -> MTU negotiated -> GATT enumerated."
    if svcs else "link held but discovery incomplete - paste output")
log("="*58)
try: conn.disconnect()
except Exception: pass
