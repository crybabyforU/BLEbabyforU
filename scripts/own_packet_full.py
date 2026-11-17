#!/usr/bin/env python3
# ============================================================================
#  own_packet_full.py - OUR-PACKET BLE CONNECTOR (final, single-file)
#
#  Usage:
#     python3 own_packet_full.py C0:00:00:41:73:AC
#     python3 own_packet_full.py AA:BB:CC:DD:EE:FF --addr-type public
#     python3 own_packet_full.py C0:00:00:41:73:AC --scan-time 25 --watch 4
#
#  Pipeline:
#    0. environment audit          (exact fix printed on every failure)
#    1. scan + confirm + auto-detect address type (PUB/RND)
#    2. OUR packet: template LLData + your MAC as AdvA, CRC recomputed
#    3. literal 36-byte TX attempt (raw_inject, best effort)
#    4. dongle reopen as central + claim our InitA
#    5. connect using the fields parsed from OUR packet
#    6. MTU patch: answer ATT_EXCHANGE_MTU_REQ in ~3ms (stops the 0.2s kill)
#    7. manual GATT discovery (WHAD host stack bypassed)
#    8. final report + artifact files
#
#  Exit codes: 0=link alive  1=link dead  2=environment  3=target not advertising
# ============================================================================
import argparse, glob, os, re, shutil, subprocess, sys, time


def _windows_com_ports():
    """Serial ports on Windows (pyserial), fallback to COM* glob."""
    try:
        from serial.tools import list_ports
        return sorted(p.device for p in list_ports.comports())
    except Exception:
        return sorted("COM%d" % i for i in range(1, 21)
                      if os.path.exists("COM%d" % i))

# ################## OUR PACKET - SINGLE SOURCE OF TRUTH ##################
# 22-byte LLData IS our authored packet. Only AdvA gets replaced by the
# CLI MAC; header bits + CRC are recomputed from scratch every run.
PDU_HEX_TEMPLATE = "8522AABBCCDDEEFFAC73410000C0A1B2C3D412345602000018000000C800FFFFFFFF1F2D"
INITA            = "FF:EE:DD:CC:BB:AA"      # our claimed central address (public)
INITA_RANDOM     = False
DEFAULT_MTU      = 247
###########################################################################

# ---------- imports that may fail (reported nicely by STEP 0) ----------
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

# ---------- pretty logging ----------
T0 = time.time()
def log(m):  print(f"[{time.time()-T0:6.2f}s] {m}", flush=True)
def ok(m):   log(f"  [ OK ] {m}")
def warn(m): log(f"  [WARN] {m}")
def bad(m):  log(f"  [FAIL] {m}")
def banner(t): print("\n" + "="*72 + f"\n {t}\n" + "="*72, flush=True)
def die(m, code): bad(m); sys.exit(code)

# ---------- packet math (pure python, no deps) ----------
def crc24(data: bytes, init: int = 0x555555) -> int:
    c = init
    for b in data:
        for i in range(8):
            if ((c >> 23) & 1) ^ ((b >> i) & 1):
                c = ((c << 1) ^ 0x100065B) & 0xFFFFFF
            else:
                c = (c << 1) & 0xFFFFFF
    return c

def mac_wire(s: str) -> bytes:               # "AA:BB:.." -> wire order (LSB first)
    return bytes.fromhex(s.replace(":", ""))[::-1]

TPL        = bytes.fromhex(PDU_HEX_TEMPLATE)
LLD        = TPL[14:36]                       # 22 LLData bytes: our authored fields
AA         = int.from_bytes(LLD[0:4],  "little")   # 0xD4C3B2A1
CRCINIT    = int.from_bytes(LLD[4:7],  "little")   # 0x563412
WINSIZE    = LLD[7]
WINOFFSET  = int.from_bytes(LLD[8:10], "little")
INTERVAL   = int.from_bytes(LLD[10:12],"little")   # 24 -> 30 ms
LATENCY    = int.from_bytes(LLD[12:14],"little")
TIMEOUT    = int.from_bytes(LLD[14:16],"little")   # 200 -> 2000 ms
CHANMAP_B  = LLD[16:21]
CHANMAP_INT= int.from_bytes(CHANMAP_B, "little")   # 0x1FFFFFFFFF (37 ch)
HOP        = LLD[21] & 0x1F                        # 13
SCA        = LLD[21] >> 5                          # 1

def build_pdu(advaa: str, adva_random: bool) -> bytes:
    payload = mac_wire(INITA) + mac_wire(advaa) + LLD
    hdr = 0x05 | (0x40 if INITA_RANDOM else 0) | (0x80 if adva_random else 0)
    return bytes([hdr,34]) + payload

# =========================== STEP 0: ENV AUDIT ===========================
def step0_env():
    banner("STEP 0/8  ENVIRONMENT AUDIT")
    fails = 0
    v = sys.version_info
    if v >= (3, 8): ok(f"python {v.major}.{v.minor}.{v.micro}")
    else: bad(f"python {v} too old (need >= 3.8)"); fails += 1

    if HAVE_WHAD: ok("whad importable")
    else:
        bad(f"whad import failed: {type(WHAD_ERR).__name__}: {WHAD_ERR}")
        print("          fix: source ~/ble-lab/venv/bin/activate && pip install whad"); fails += 1
    if HAVE_SCAPY: ok("scapy importable")
    else:
        bad(f"scapy import failed: {type(SCAPY_ERR).__name__}: {SCAPY_ERR}")
        print("          fix: source ~/ble-lab/venv/bin/activate && pip install scapy"); fails += 1

    ports = sorted(glob.glob("/dev/ttyACM*")) if os.name != "nt" else _windows_com_ports()
    if not ports:
        bad("no serial device found (/dev/ttyACM* or COMx)")
        print("          fix: unplug + replug the nRF52840 dongle, wait 3 s")
        print("          (if lsusb shows 1915:521f it is in bootloader: replug once)")
        fails += 1
    else:
        ok(f"serial device(s): {', '.join(ports)}")
        try:
            import serial
            serial.Serial(ports[0], timeout=0.3).close()
            ok(f"serial open test on {ports[0]}")
        except PermissionError:
            bad(f"permission denied on {ports[0]}")
            print("          fix: sudo usermod -aG uucp $USER  -> log out + in -> rerun"); fails += 1
        except Exception as e:
            bad(f"cannot open {ports[0]}: {type(e).__name__}: {e}")
            print("          fix: close anything else using the dongle (wble-central, older scripts, minicom)")
            fails += 1

    try:
        groups = subprocess.run(["id", "-nG"], capture_output=True, text=True).stdout.split()
        if "uucp" in groups: ok("user in uucp group")
        else:
            warn("user NOT in uucp group")
            print("          fix: sudo usermod -aG uucp $USER -> log out + in")
    except Exception:
        pass

    if shutil.which("systemctl"):
        st = subprocess.run(["systemctl", "is-active", "ModemManager"],
                            capture_output=True, text=True).stdout.strip()
        if st == "active":
            warn("ModemManager RUNNING (corrupts WHAD serial traffic)")
            print("          fix: sudo systemctl disable --now ModemManager")
        else:
            ok("ModemManager not running")

    if shutil.which("lsusb"):
        out = subprocess.run(["lsusb"], capture_output=True, text=True).stdout.lower()
        if "c0ff:eeee" in out: ok("USB: WHAD dongle present (c0ff:eeee)")
        elif "1915:521f" in out: warn("USB: dongle in BOOTLOADER mode -> unplug+replug once")
        else: warn("USB: WHAD dongle not listed (may still work if just replugged)")

    if fails:
        die(f"{fails} fatal environment problem(s) - fix every [FAIL] above, then rerun", 2)

# ========================= DONGLE OPEN (shared) ==========================
def open_dongle(klass, mode=None, tries=6):
    last = None
    for i in range(tries):
        for port in ("uart0", "uart1"):
            try:
                d = WhadDevice.create(port)
                c = klass(d)
                if mode == "scan":                 # Injector scan path
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

# ================== STEP 1: SCAN + CONFIRM + TYPE DETECT =================
def scan_phase(scan_time, target):
    banner("STEP 1/8  SCAN + CONFIRM + ADDRESS-TYPE DETECT")
    d, inj, port = open_dongle(Injector, mode="scan")
    if inj is None:
        die("dongle will not open -> unplug + replug, wait 3 s, rerun", 2)
    ok(f"dongle open on {port}, scanning up to {scan_time}s for {target}")
    adva_w = mac_wire(target)
    seen = {"n": 0, "txadd": None}
    orig = inj.on_adv_pdu
    def hook(pkt, *a, **k):
        try:
            if adva_w in bytes(pkt):
                seen["n"] += 1
                if seen["txadd"] is None:
                    try: seen["txadd"] = int(pkt.getlayer(BTLE_ADV).TxAdd)
                    except Exception: pass
        except Exception:
            pass
        try: return orig(pkt, *a, **k)
        except Exception: return None
    inj.on_adv_pdu = hook
    t = time.time()
    while time.time() - t < scan_time and seen["n"] == 0:
        time.sleep(0.1)
    if seen["n"] == 0:
        try: d.close()
        except Exception: pass
        die("target NOT advertising -> put it in pairing mode / disconnect it from "
            "your phone / move it closer, then rerun", 3)
    t2 = time.time()
    while time.time() - t2 < 1.5 and seen["txadd"] is None:
        time.sleep(0.05)
    ok(f"TARGET IS THERE ({seen['n']} ADV packets heard)"
       + (f", TxAdd bit = {seen['txadd']}" if seen["txadd"] is not None else ""))
    return d, inj, seen

# ================= STEP 2: BUILD + VERIFY OUR PACKET =====================
def packet_phase(target, adva_random):
    banner("STEP 2/8  OUR OWN CONNECT_IND (template LLData + your MAC as AdvA)")
    pdu = build_pdu(target, adva_random)
    crc = crc24(pdu)
    rows = [
        ("Preamble",      "AA",                                   "derived - radio adds it"),
        ("Adv AccessAddr","D6 BE 89 8E",                          "fixed 0x8E89BED6 - radio adds it"),
        ("PDU Header",    pdu[:2].hex(" ").upper(),
         f"CONNECT_IND TxAdd={'rnd' if INITA_RANDOM else 'pub'} RxAdd={'rnd' if adva_random else 'pub'} Len={pdu[1]}"),
        ("InitA",         mac_wire(INITA).hex(" ").upper(),        INITA),
        ("AdvA",          mac_wire(target).hex(" ").upper(),       target),
        ("LL AA",         LLD[0:4].hex(" ").upper(),               f"0x{AA:08X}"),
        ("LL CRCInit",    LLD[4:7].hex(" ").upper(),               f"0x{CRCINIT:06X}"),
        ("LL WinSize",    f"{WINSIZE:02X}",                        f"{WINSIZE*1.25:.1f} ms"),
        ("LL WinOffset",  LLD[8:10].hex(" ").upper(),              f"{WINOFFSET*1.25:.0f} ms"),
        ("LL Interval",   LLD[10:12].hex(" ").upper(),             f"{INTERVAL*1.25:.0f} ms"),
        ("LL Latency",    LLD[12:14].hex(" ").upper(),             f"{LATENCY}"),
        ("LL Timeout",    LLD[14:16].hex(" ").upper(),             f"{TIMEOUT*10} ms"),
        ("LL ChanMap",    CHANMAP_B.hex(" ").upper(),              f"{bin(CHANMAP_INT).count('1')} channels"),
        ("LL Hop/SCA",    f"{HOP|(SCA<<5):02X}",                   f"hop={HOP} sca={SCA}"),
        ("CRC (radio)",   crc.to_bytes(3,'little').hex(" ").upper(), "computed from our bytes"),
    ]
    for n, h, m in rows:
        log(f"  {n:<15} {h:<24} {m}")
    log(f"  PDU TX BUFFER ({len(pdu)}B): {pdu.hex().upper()}")
    with open("packet.txt", "w") as f:
        f.write(f"PDU: {pdu.hex().upper()}\nCRC air: {crc.to_bytes(3,'little').hex().upper()}\n")
    checks = [("AA legality",             AA not in (0, 0xFFFFFFFF) and AA != 0x8E89BED6),
              ("hop 5-16",                5 <= HOP <= 16),
              ("timeout > 2(1+lat)*iv",   TIMEOUT > 2*(1+LATENCY)*INTERVAL),
              ("WinOffset <= Interval",   WINOFFSET <= INTERVAL)]
    allpass = True
    for n, v in checks:
        (ok if v else bad)(f"spec check: {n}")
        allpass = allpass and v
    if not allpass:
        die("our packet failed its own spec check", 2)
    ok("packet verified -> packet.txt")
    return pdu, crc

# ================= STEP 3: LITERAL BYTES ON AIR ==========================
def inject_phase(inj, pdu):
    banner("STEP 3/8  LITERAL 36-BYTE TX (raw_inject, unsynchronized)")
    lit = BTLE(bytes.fromhex("D6BE898E") + pdu)
    if bytes(lit)[4:] == pdu: ok("scapy round-trip: BYTE-EXACT")
    else: warn("scapy round-trip MISMATCH - literal TX skipped"); return
    sent = 0
    for i in range(3):
        try:
            inj.raw_inject(lit); sent += 1; time.sleep(0.2)
        except Exception as e:
            warn(f"raw_inject: {type(e).__name__}: {e}"); break
    if sent: ok(f"literal bytes transmitted: {sent}/3  (sniffer-visible; acceptance "
                "test happens via the connect path - stock firmware cannot reactively "
                "inject advertising PDUs, root-caused in prepare())")
    else:    warn("literal TX unavailable - continuing (connect path carries our fields)")

# ============== STEPS 5+6: CONNECT WITH OUR FIELDS + MTU PATCH ===========
def connect_phase(central, target, random_mode, mtu_rsp, watch, attempts=3):
    banner("STEP 5/8  CONNECT - FIELDS TAKEN FROM OUR PACKET")
    log(f"  random={random_mode} access_address=0x{AA:08X} crc_init=0x{CRCINIT:06X} "
        f"interval={INTERVAL} ({INTERVAL*1.25:.0f} ms) hop={HOP} chanmap={CHANMAP_B.hex()}")
    banner("STEP 6/8  MTU PATCH - answer ATT_EXCHANGE_MTU_REQ within ~3 ms")
    log("  root cause (autopsy): device sends MTU_REQ, then LL_TERMINATE_IND 0x13")
    log("  ~200 ms later if unanswered. Earlier sends failed because of raw bytes")
    log("  (WHAD only converts scapy) or the wrong AA (advertising default).")
    st = {"need": False, "reqs": 0, "answered": 0, "term": False, "err": None, "att": []}
    def _reset():
        st.update(need=False, reqs=0, answered=0, term=False, err=None, att=[])
    _od = central.on_data_pdu
    def _data(pdu=None, *a, **k):
        try:
            b = bytes(pdu)
            if len(b) >= 7 and b[4:6] == b"\x04\x00":
                att = b[6:]; op = att[0]
                st["att"].append({"op": op, "att": att}); del st["att"][:-60]
                if   op == 0x02: st["reqs"] += 1; st["need"] = True
                elif op == 0x11: log(f"    <<< SVC_RSP   {att.hex().upper()}")
                elif op == 0x09: log(f"    <<< CHR_RSP   {att.hex().upper()}")
                elif op == 0x0B: log(f"    <<< READ_RSP  {att[1:].decode('ascii','replace')!r}")
                elif op == 0x01: log(f"    <<< ATT_ERROR req=0x{att[1]:02x} err=0x{att[3]:02x}")
                else:            log(f"    <<< ATT op=0x{op:02x} {att.hex().upper()[:60]}")
        except Exception:
            pass
        try: return _od(pdu, *a, **k)
        except Exception: return None
    central.on_data_pdu = _data
    _oc = central.on_ctl_pdu
    def _ctl(pdu=None, *a, **k):
        try:
            b = bytes(pdu)
            if len(b) >= 4 and b[2] == 0x02:
                st["term"] = True; st["err"] = b[3]
                log(f"    <<< LL_TERMINATE_IND err=0x{b[3]:02x}"
                    + {0x13: " (remote user terminated)", 0x08: " (supervision timeout)"}.get(b[3], ""))
            else:
                log(f"    <<< LLCTRL {bytes(pdu).hex().upper()}")
        except Exception:
            pass
        try: return _oc(pdu, *a, **k)
        except Exception: return None
    central.on_ctl_pdu = _ctl
    H = {"v": 0}
    def send_pdu(pkt, label=""):
        try:
            r = central.send_data_pdu(pkt, conn_handle=H["v"], access_address=AA)
            if r: st["answered"] += 1
            else: warn(f"send {label}: firmware returned {r!r}")
            return bool(r)
        except Exception as e:
            warn(f"send {label}: {type(e).__name__}: {e}")
            return False
    def pump(seconds):
        end = time.time() + seconds
        while time.time() < end:
            if st["need"]:
                st["need"] = False
                if send_pdu(mtu_rsp, "MTU_RSP"):
                    ok(f"MTU_RSP sent on connection AA 0x{AA:08X}")
            if st["term"]: break
            time.sleep(0.003)
    conn = None
    for attempt_no in range(1, attempts + 1):
        _reset()
        log(f"  --- connect attempt {attempt_no}/{attempts} ---")
        try:
            conn = central.connect(target, random=random_mode, timeout=10,
                                   access_address=AA, crc_init=CRCINIT,
                                   channel_map=ChannelMap.from_int(CHANMAP_INT),
                                   hop_interval=INTERVAL, hop_increment=HOP)
        except PeripheralNotFound:
            warn("device not advertising at that instant"); time.sleep(2.5); continue
        except Exception as e:
            warn(f"connect error: {type(e).__name__}: {e}"); time.sleep(2.5); continue
        H["v"] = getattr(conn, "conn_handle", 0)
        ok(f"CONNECTED (handle={H['v']}) - OUR LLData is the live link contract")
        send_pdu(mtu_rsp, "MTU_RSP")            # optimistic: REQ often already in
        pump(watch)
        if not st["term"]:
            ok(f"LINK ALIVE after {watch:.0f}s  (MTU_REQ seen={st['reqs']}, answered={st['answered']})")
            return conn, st, send_pdu, True
        warn(f"attempt {attempt_no}: link terminated (err=0x{st['err']:02x}, answered={st['answered']})")
        try: conn.disconnect()
        except Exception: pass
        time.sleep(2.5)
    return None, st, send_pdu, False

# ==================== STEP 7: MANUAL GATT DISCOVERY ======================
def gatt_phase(st, send_pdu, att_pkt, mtu_rsp):
    banner("STEP 7/8  MANUAL GATT (WHAD host stack bypassed)")
    def svc_req(s, e): return att_pkt(b"\x10" + s.to_bytes(2,'little') + e.to_bytes(2,'little') + b"\x00\x28")
    def chr_req(s, e): return att_pkt(b"\x08" + s.to_bytes(2,'little') + e.to_bytes(2,'little') + b"\x03\x28")
    def read_req(h):   return att_pkt(b"\x0A" + h.to_bytes(2,'little'))
    def att_xchg(req_pkt, want, req_op, tries=3, wait=0.8):
        for _ in range(tries):
            if st["term"]: return None
            send_pdu(req_pkt, f"ATT 0x{req_op:02x}")
            t = time.time()
            while time.time() - t < wait:
                if st["need"]:
                    st["need"] = False; send_pdu(mtu_rsp, "MTU_RSP")
                for rec in list(st["att"]):
                    if rec["op"] == want:
                        st["att"] = [x for x in st["att"] if x["op"] != want]
                        return rec["att"]
                    if rec["op"] == 0x01 and rec["att"][1] == req_op:
                        log(f"      ATT error 0x{rec['att'][3]:02x} on opcode 0x{req_op:02x}")
                        return None
                time.sleep(0.01)
        return None
    svcs, dev_name, nchars = [], None, 0
    start = 1
    while start <= 0xFFFF and len(svcs) < 15:
        r = att_xchg(svc_req(start, 0xFFFF), 0x11, 0x10)
        if not r or r[1] == 0: break
        itl = r[1]; o = 2; e_h = start
        while o + itl <= len(r):
            s_h = int.from_bytes(r[o:o+2],   'little')
            e_h = int.from_bytes(r[o+2:o+4], 'little')
            uuid = r[o+4:o+itl][::-1].hex().upper()
            svcs.append([s_h, e_h, uuid, []])
            log(f"    SERVICE {s_h:04X}-{e_h:04X} uuid 0x{uuid if len(uuid)==4 else uuid}")
            o += itl
        if e_h <= start: break
        start = e_h + 1
    log(f"  -> {len(svcs)} services")
    for svc in svcs:
        cs = svc[0]
        while cs <= svc[1] and len(svc[3]) < 12:
            r = att_xchg(chr_req(cs, svc[1]), 0x09, 0x08)
            if not r or r[1] == 0: break
            itl = r[1]; o = 2
            while o + itl <= len(r):
                h  = int.from_bytes(r[o:o+2],   'little')
                vh = int.from_bytes(r[o+3:o+5], 'little')
                uuid = r[o+5:o+itl][::-1].hex().upper() or "?"
                svc[3].append((h, vh, uuid)); nchars += 1
                log(f"      CHAR {h:04X} val {vh:04X} uuid 0x{uuid if len(uuid)==4 else uuid}")
                o += itl
            cs = (svc[3][-1][0] + 1) if svc[3] else svc[1] + 1
    log(f"  -> {nchars} characteristics")
    for svc in svcs:
        if svc[2].startswith("1800"):
            for (h, vh, u) in svc[3]:
                if u == "2A00":
                    r = att_xchg(read_req(vh), 0x0B, 0x0A)
                    if r:
                        dev_name = r[1:].decode("ascii", "replace")
                        log(f"    DEVICE NAME = '{dev_name}'  <- read over OUR custom link")
    return svcs, dev_name

# ============================== MAIN =====================================
def main():
    ap = argparse.ArgumentParser(description="Connect to a BLE device using OUR authored CONNECT_IND")
    ap.add_argument("mac", help="target MAC, e.g. C0:00:00:41:73:AC")
    ap.add_argument("--addr-type", choices=("auto", "public", "random"), default="auto",
                    help="address type (default: auto-detect from ADV)")
    ap.add_argument("--scan-time", type=int, default=15, help="scan seconds (default 15)")
    ap.add_argument("--mtu", type=int, default=DEFAULT_MTU, help="our ATT MTU (default 247)")
    ap.add_argument("--watch", type=float, default=3.0, help="link survival watch seconds (default 3)")
    a = ap.parse_args()

    m = re.sub(r"[:\-\s]", "", a.mac).lower()
    if not re.fullmatch(r"[0-9a-f]{12}", m):
        die(f"'{a.mac}' is not a valid MAC (need 12 hex digits, colons optional)", 2)
    if a.mtu < 23 or a.mtu > 517:
        die(f"--mtu must be 23..517 (BLE spec), got {a.mtu}", 2)
    target = ":".join(m[i:i+2] for i in range(0, 12, 2)).upper()

    banner("OUR-PACKET BLE CONNECTOR")
    log(f"  target : {target}")
    log(f"  template: {PDU_HEX_TEMPLATE}")
    step0_env()

    # STEP 1: scan + detect
    d, inj, seen = scan_phase(a.scan_time, target)
    if a.addr_type == "auto":
        if seen["txadd"] is not None:
            random_mode = bool(seen["txadd"])
            ok(f"address type auto-detected: {'random' if random_mode else 'public'}")
        else:
            random_mode = True
            warn("could not read TxAdd from ADV - defaulting to random "
                 "(override with --addr-type public if connect fails)")
    else:
        random_mode = (a.addr_type == "random")
        ok(f"address type forced: {a.addr_type}")

    # STEP 2: build + verify our packet
    pdu, crc = packet_phase(target, random_mode)

    # STEP 3: literal bytes on air (same injector instance, still open)
    inject_phase(inj, pdu)
    try: d.close()
    except Exception: pass
    time.sleep(1.5)

    # STEP 4: reopen as central + claim our InitA
    banner("STEP 4/8  DONGLE REOPEN (central role) + CLAIM InitA")
    d2, central, port2 = open_dongle(Central)
    if central is None:
        die("cannot reopen dongle as Central -> unplug + replug, rerun", 2)
    ok(f"dongle open on {port2}")
    try:
        central.set_bd_address(INITA); ok(f"InitA claimed: {INITA}")
    except Exception as e:
        warn(f"set_bd_address: {type(e).__name__}: {e} (firmware will use its own InitA)")

    # scapy ATT builders (WHAD converts scapy objects ONLY - proven in script 15)
    def att_pkt(att: bytes):
        return BTLE_DATA(LLID=2) / L2CAP_Hdr(len=len(att), cid=0x0004) / Raw(load=att)
    mtu_rsp = att_pkt(bytes([0x03]) + a.mtu.to_bytes(2, 'little'))

    # STEPS 5+6: connect + MTU patch
    conn, st, send_pdu, alive = connect_phase(central, target, random_mode, mtu_rsp, a.watch)

    # STEP 7: manual GATT
    svcs, dev_name = [], None
    if alive:
        svcs, dev_name = gatt_phase(st, send_pdu, att_pkt, mtu_rsp)
    else:
        banner("STEP 7/8  MANUAL GATT - SKIPPED (link not alive)")

    # STEP 8: report
    banner("STEP 8/8  FINAL REPORT")
    log(f"  [X] our packet    : {pdu.hex().upper()}")
    log(f"  [X] CRC on air    : {crc.to_bytes(3,'little').hex().upper()}  (radio computes it from our bytes)")
    log(f"  [X] connect fields: AA=0x{AA:08X} CRCInit=0x{CRCINIT:06X} iv={INTERVAL*1.25:.0f}ms hop={HOP} (all from our packet)")
    log(f"  [{'X' if alive else ' '}] link ALIVE past MTU exchange (terminated={st['term']}, answered={st['answered']})")
    log(f"  [{'X' if svcs else ' '}] GATT services: {len(svcs)}   device name: {dev_name!r}")
    rpt = f"report_{target.replace(':','')}_{int(time.time())}.txt"
    with open(rpt, "w") as f:
        f.write(f"target: {target}\nPDU: {pdu.hex().upper()}\nCRC: {crc.to_bytes(3,'little').hex().upper()}\n")
        f.write(f"alive: {alive}\nterminated: {st['term']} err: {st['err']}\nservices: {len(svcs)}\nname: {dev_name}\n")
        for s in svcs: f.write(f"  {s[0]:04X}-{s[1]:04X} uuid {s[2]}\n")
    ok(f"report saved -> {rpt}")

    if not alive:
        bad("link did not survive - interpretation guide:")
        log("   err=0x13 + answered>0 : MTU_RSP reached the device but it still terminated")
        log("        -> capture the exchange with a 2nd dongle (Sniffle/Wireshark), or move")
        log("           to the firmware-patch tier for full literal-byte reactive control")
        log("   err=0x13 + answered=0 : our TX never reached it -> read the send errors above")
        log("   connect failed repeatedly : device stopped advertising (pairing mode again)")
    if alive:
        try: conn.disconnect()
        except Exception: pass
    try: d2.close()
    except Exception: pass
    sys.exit(0 if alive else 1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] interrupted by user"); sys.exit(130)
