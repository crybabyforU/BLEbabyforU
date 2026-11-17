#!/usr/bin/env python3
import argparse
import asyncio
import json
import time
from datetime import datetime
from bleak import BleakClient

def _parse_args():
    p = argparse.ArgumentParser(description="GATT explorer + writable-characteristic byte-length prober with checkpoints.")
    p.add_argument("mac", nargs="?", default="00:1F:FF:C1:63:9F", help="target MAC (default: %(default)s)")
    p.add_argument("--address-type", choices=["public", "random"], default="public", help="BLE address type (default: %(default)s)")
    p.add_argument("--reset-checkpoint", action="store_true", help="ignore probe_checkpoint.json and start fresh")
    p.add_argument("--explore-only", action="store_true", help="run only the GATT explorer (Part 1), skip probing")
    return p.parse_args()

ARGS = _parse_args()

# Your target device MAC address
DEVICE_ADDRESS = ARGS.mac

async def explore_ble_device(address):
    print(f"[*] Connecting to device: {address}...")
    
    async with BleakClient(address, address_type=ARGS.address_type) as client:
        if not client.is_connected:
            print("[!] Failed to connect.")
            return

        print(f"[+] Connected to {address}\n")
        
        # Access services directly
        services = client.services
        print(f"[+] Discovering services and characteristics...\n")
        
        for service in services:
            print(f"==================================================")
            print(f"Service UUID: {service.uuid} | Handle: {service.handle}")
            print(f"Description: {service.description}")
            print(f"==================================================")
            
            for char in service.characteristics:
                print(f"  ├── Characteristic UUID: {char.uuid}")
                print(f"  │   ├── Handle: {char.handle}")
                print(f"  │   ├── Properties: {', '.join(char.properties)}")
                
                # Check if the characteristic is readable
                if "read" in char.properties:
                    try:
                        value = await client.read_gatt_char(char.uuid)
                        print(f"  │   └── Data (Bytes): {value}")
                        try:
                            # Try decoding as UTF-8 string if possible
                            decoded_val = value.decode("utf-8")
                            print(f"  │   └── Data (String): {decoded_val}")
                        except UnicodeDecodeError:
                            print(f"  │   └── Data (Hex): {value.hex()}")
                    except Exception as e:
                        print(f"  │   └── Failed to read data: {e}")
                else:
                    print(f"  │   └── Data: [Not Readable]")
                
                # Print descriptors if any exist
                for descriptor in char.descriptors:
                    print(f"  │       ├── Descriptor UUID: {descriptor.uuid}")
                    print(f"  │       └── Handle: {descriptor.handle}")
            print("")


# =====================================================================
# ================  PART 2 — ADDED CODE (NEW)  ========================
# =====================================================================
# NEW IN THIS VERSION — "LAST SENT" STATE CHECKER:
#   - every payload length that goes out on the air (ACCEPTED, ATT-REJECTED
#     or even HUNG-with-no-ACK) is recorded as "last sent" per handle
#   - after a reconnect the probe does NOT repeat the old length — it
#     resumes at last_sent + 1  (1 sent -> reconnect -> now sends 2)
#   - the checkpoint is saved to probe_checkpoint.json, so even restarting
#     the whole script resumes where it stopped
# Original exploration code above is UNTOUCHED.
# =====================================================================

# ---------------- probing settings (tweak here) ----------------
PROBE_MIN_LEN   = 1      # smallest payload to try (bytes)
PROBE_MAX_LEN   = 244    # biggest payload (auto-clamped to device MTU-3)
PROBE_FILL_BYTE = 0x41   # filler byte ('A')  -> try 0x00 if writes keep hanging!
PROBE_DELAY     = 0.30   # seconds between successful writes

# ---------------- connection settings ----------------
WATCHDOG_INTERVAL = 10.0   # seconds between uptime pings
CONNECT_TIMEOUT   = 8.0    # max secs per connect attempt
CONNECT_RETRIES   = 3      # connect attempts before giving up
RECONNECT_DELAY   = 0.20   # gap between connect retries (fast: 200 ms)

# ---------------- fast-recovery settings ----------------
WRITE_TIMEOUT        = 1.5   # hung longer than this = no ACK from device
POST_CONNECT_DELAY   = 0.05  # 50 ms settle after connect, then write
MAX_TOTAL_RECONNECTS = 200   # global safety cap
SUBSCRIBE_ON_CONNECT = True  # subscribe notify/indicate after every connect
TRY_PAIR_ON_CONNECT  = False # flip True if device might need bonding
RECONNECT_ON_DROP    = True  # auto-reconnect via BLESession.ensure(); False = stop probing on drop

# ---------------- STATE-CHECKER settings (the new stuff) ----------------
CHECKPOINT_FILE     = "probe_checkpoint.json"  # None = memory only
RESET_CHECKPOINT    = ARGS.reset_checkpoint  # True = wipe checkpoint and start from 1
MAX_CONSECUTIVE_HANGS = 8      # this many silent writes in a row = give up
                                # with a diagnosis (0 = disable, sweep everything)

# "auto" = write-with-response (char declares it)
# "without_response" = force write-without-response (try if device ignores writes)
FORCE_WRITE_MODE = "auto"
TRY_WO_RESPONSE_DIAGNOSTIC = True  # one silent 1-byte WO-R test per handle

# ---------------- common ATT error codes ----------------
ATT_ERRORS = {
    "0x01": "Invalid Handle",
    "0x02": "Read Not Permitted",
    "0x03": "Write Not Permitted",
    "0x04": "Insufficient Authentication",
    "0x05": "Request Not Supported",
    "0x06": "Invalid Offset",
    "0x07": "Insufficient Authorization",
    "0x0c": "Invalid Attribute Value Length  <-- LENGTH MISMATCH!",
    "0x0d": "Unlikely Error (custom fw often uses this for wrong length)",
    "0x10": "Insufficient Resources",
}

def classify_write_error(err: Exception) -> str:
    """Translate a raw bleak exception into a readable reason."""
    s = str(err).lower()
    if "0x0c" in s or "invalid attribute value length" in s or "invalid value length" in s:
        return "0x0C Invalid Attribute Value Length (length mismatch)"
    if "0x06" in s or "invalid offset" in s:
        return "0x06 Invalid Offset"
    if "0x03" in s or "write not permitted" in s:
        return "0x03 Write Not Permitted"
    if "0x0d" in s or "unlikely" in s:
        return "0x0D Unlikely Error (often = wrong length)"
    if "0x05" in s or "request not supported" in s:
        return "0x05 Request Not Supported"
    if "not supported" in s:
        return "NotSupported (op not possible on this char)"
    if "mtu" in s:
        return "Payload larger than negotiated MTU"
    if "disconnect" in s or "not connected" in s or "was closed" in s or "org.bluez.error" in s:
        return "CONNECTION LOST (device dropped us)"
    if "timeout" in s or "timed out" in s:
        return "TIMEOUT (no ATT response from device)"
    for code, meaning in ATT_ERRORS.items():
        if code in s:
            return f"{code.upper()} {meaning}"
    return str(err)


# =====================================================================
# ============  CONNECTION TRACKER (uptime / errors / drops)  =========
# =====================================================================
class ConnectionTracker:
    def __init__(self, address):
        self.address = address
        self.connect_time = None
        self.sessions = []       # [{'start': unix_ts, 'duration': secs}, ...]
        self.errors = []         # [(timestamp, message), ...]
        self.reconnects = 0
        self.last_drop_ts = None

    def on_disconnected(self, *args):
        ts = datetime.now().strftime("%H:%M:%S")
        self.last_drop_ts = time.time()
        if self.connect_time is not None:
            dur = time.time() - self.connect_time
            self.sessions.append({"start": self.connect_time, "duration": dur})
            self.connect_time = None
            print(f"\n[!!] [{ts}] DEVICE DISCONNECTED — that session lasted {dur:.2f} seconds")
        else:
            print(f"\n[!!] [{ts}] DEVICE DISCONNECTED (no active session mark)")

    def mark_connected(self):
        self.connect_time = time.time()
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[OK] [{ts}] Connected to {self.address}")

    def uptime(self) -> float:
        return 0.0 if self.connect_time is None else time.time() - self.connect_time

    def last_session_duration(self) -> float:
        return self.sessions[-1]["duration"] if self.sessions else 0.0

    def log_error(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.errors.append((ts, msg))


def connection_summary(tracker: ConnectionTracker):
    print("\n" + "=" * 60)
    print(" CONNECTION / ERROR SUMMARY")
    print("=" * 60)
    print(f"  Total connect sessions    : {len(tracker.sessions)}")
    print(f"  Auto-reconnects performed : {tracker.reconnects}")
    if tracker.sessions:
        durs = [s["duration"] for s in tracker.sessions]
        print(f"  Total connected time      : {sum(durs):.2f} s")
        print(f"  Longest session           : {max(durs):.2f} s")
        print(f"  Shortest session          : {min(durs):.2f} s")
        print(f"  Average session           : {sum(durs)/len(durs):.2f} s")
        print("  --- session breakdown ---")
        for i, s in enumerate(tracker.sessions, 1):
            t = datetime.fromtimestamp(s["start"]).strftime("%H:%M:%S")
            print(f"    #{i}: connected at {t}  ->  lasted {s['duration']:.2f} s")
    if tracker.errors:
        print(f"\n  Errors logged ({len(tracker.errors)}):")
        for ts, msg in tracker.errors:
            print(f"    [{ts}] {msg}")
    else:
        print("  No errors logged. Clean run ✅")
    print("=" * 60)


def attach_disconnect_callback(client, tracker):
    """Tries BOTH bleak API names; polling fallback covers the rest."""
    for name in ("set_disconnected_callback", "add_disconnected_callback"):
        fn = getattr(client, name, None)
        if fn is not None:
            try:
                fn(tracker.on_disconnected)
                print(f"[*] Disconnect callback registered via .{name}()")
                return True
            except Exception:
                pass
    print("[!] No disconnect callback available on this bleak — "
          "drops are caught by polling before every write.")
    return False


async def acquire_mtu(client):
    try:
        await client._backend._acquire_mtu()   # BlueZ backend
    except Exception:
        pass


async def maybe_pair(client):
    if not TRY_PAIR_ON_CONNECT:
        return
    try:
        await client.pair()
        print("[*] Pairing done/verified")
    except Exception as e:
        print(f"[!] Pairing attempt failed: {e}")


async def connect_with_retry(address, tracker, retries=CONNECT_RETRIES):
    for attempt in range(1, retries + 1):
        try:
            print(f"[*] Connect attempt {attempt}/{retries} to {address} ...")
            client = BleakClient(address, address_type=ARGS.address_type, timeout=CONNECT_TIMEOUT)
            attach_disconnect_callback(client, tracker)
            await client.connect()
            tracker.mark_connected()
            await acquire_mtu(client)
            await maybe_pair(client)
            return client
        except Exception as e:
            tracker.log_error(f"connect attempt {attempt} failed: {e}")
            print(f"[!] Connect attempt {attempt} failed: {e}")
            if attempt < retries:
                await asyncio.sleep(RECONNECT_DELAY)
    return None


async def subscribe_all_notifications(client, notif_sink):
    if not SUBSCRIBE_ON_CONNECT:
        print("[*] Notification subscription DISABLED (SUBSCRIBE_ON_CONNECT=False)")
        return
    for service in client.services:
        for ch in service.characteristics:
            if "notify" in ch.properties or "indicate" in ch.properties:
                def make_handler(c):
                    def _h(_sender, data: bytearray):
                        b = bytes(data)
                        notif_sink.append((c.handle, b))
                        print(f"    << REPLY from handle {c.handle}: {b.hex()} ({len(b)} bytes)")
                    return _h
                try:
                    await client.start_notify(ch, make_handler(ch))
                except Exception as e:
                    print(f"    [!] Could not subscribe to {ch.uuid}: {e}")


async def connection_watchdog(session, tracker, interval=WATCHDOG_INTERVAL):
    try:
        while True:
            await asyncio.sleep(interval)
            if session.alive:
                print(f"[WATCHDOG] connected — uptime {tracker.uptime():.1f}s | "
                      f"reconnects: {tracker.reconnects} | errors: {len(tracker.errors)}")
            else:
                print(f"[WATCHDOG] link DEAD — last session {tracker.last_session_duration():.2f}s "
                      f"(probe loop will reconnect instantly)")
    except asyncio.CancelledError:
        pass


class BLESession:
    """Owns the connection; reconnects immediately whenever it's dead."""

    def __init__(self, address, tracker, notif_sink):
        self.address = address
        self.tracker = tracker
        self.notif_sink = notif_sink
        self.client = None
        self.force_reconnect = False

    @property
    def alive(self):
        return (self.client is not None
                and self.client.is_connected
                and not self.force_reconnect)

    async def connect(self):
        self.force_reconnect = False
        self.client = await connect_with_retry(self.address, self.tracker)
        if self.client is not None:
            await asyncio.sleep(POST_CONNECT_DELAY)     # ~50 ms settle
            await subscribe_all_notifications(self.client, self.notif_sink)
        return self.client is not None

    def mtu_payload_limit(self):
        try:
            mtu = self.client.mtu_size or 23
        except Exception:
            mtu = 23
        return max(20, mtu - 3)

    async def ensure(self):
        """Make sure the link is alive; reconnect RIGHT NOW if not."""
        if self.alive:
            return True
        if self.client is not None:
            try:
                await self.client.disconnect()
            except Exception:
                pass
            self.client = None
        if self.tracker.last_drop_ts is not None:
            gap_ms = (time.time() - self.tracker.last_drop_ts) * 1000
            print(f"[⚡] Link is dead — reconnecting ({gap_ms:.0f} ms since disconnect) ...")
        else:
            print("[⚡] Link is dead — reconnecting NOW ...")
        ok = await self.connect()
        if ok:
            self.tracker.reconnects += 1
            if self.tracker.last_drop_ts is not None:
                total_ms = (time.time() - self.tracker.last_drop_ts) * 1000
                print(f"[⚡] Back online — from DROP to READY-FOR-WRITE took {total_ms:.0f} ms")
            else:
                print("[⚡] Back online — ready to write.")
        return ok

    async def write(self, char, payload, use_response):
        await asyncio.wait_for(
            self.client.write_gatt_char(char, payload, response=use_response),
            timeout=WRITE_TIMEOUT,
        )


# =====================================================================
# ==========  NEW: PROBE STATE — "what was the last byte sent" ========
# =====================================================================
class ProbeState:
    """
    THE CHECKER you asked for:
      - remembers the last payload length SENT for every handle
      - after a reconnect, the next write is last_sent + 1 (never a repeat)
      - persisted to a JSON file so even a script restart resumes
    """
    def __init__(self, path=CHECKPOINT_FILE):
        self.path = path
        self.last_sent = {}      # {char_uuid: last_sent_length}
        if RESET_CHECKPOINT:
            self.reset()
        else:
            self.load()

    def reset(self):
        self.last_sent = {}
        if self.path:
            try:
                import os
                os.remove(self.path)
            except FileNotFoundError:
                pass
            except Exception:
                pass
        print("[STATE] checkpoint RESET — probe will start from byte-length 1")

    def load(self):
        if not self.path:
            return
        try:
            with open(self.path) as f:
                data = json.load(f)
            self.last_sent = {k: int(v) for k, v in data.get("last_sent", {}).items()}
            if self.last_sent:
                print(f"[STATE] checkpoint loaded: {self.last_sent} "
                      f"-> probe RESUMES from last_sent + 1")
            else:
                print("[STATE] no checkpoint data — starting fresh from byte-length 1")
        except FileNotFoundError:
            print("[STATE] no checkpoint file — starting fresh from byte-length 1")
        except Exception as e:
            print(f"[STATE] could not read checkpoint ({e}) — starting fresh")

    def mark_sent(self, char, length):
        """Called the moment a payload goes on the air (any outcome)."""
        key = str(char.uuid)
        if length > self.last_sent.get(key, 0):
            self.last_sent[key] = length
            self.save()

    def last_for(self, char) -> int:
        return self.last_sent.get(str(char.uuid), 0)

    def next_for(self, char) -> int:
        return self.last_for(char) + 1

    def save(self):
        if not self.path:
            return
        try:
            with open(self.path, "w") as f:
                json.dump({
                    "device": DEVICE_ADDRESS,
                    "updated": datetime.now().isoformat(timespec="seconds"),
                    "last_sent": self.last_sent,
                }, f, indent=2)
        except Exception:
            pass


async def wo_response_diagnostic(session, char):
    """One-time silent test: does the device take write-without-response?
    (Some firmwares ignore write-REQUESTS but happily take WO-R commands
    even when the char doesn't declare it.) Purely diagnostic."""
    try:
        await asyncio.wait_for(
            session.client.write_gatt_char(char, bytes([PROBE_FILL_BYTE]), response=False),
            timeout=WRITE_TIMEOUT,
        )
        print("  [DIAG] write-WITHOUT-response was taken silently! The firmware")
        print("         probably only implements WO-R -> rerun with")
        print('         FORCE_WRITE_MODE = "without_response"  for a clean sweep.')
        return True
    except asyncio.TimeoutError:
        print("  [DIAG] write-without-response also HUNG — firmware write path is dead silent.")
    except Exception as e:
        print(f"  [DIAG] write-without-response refused: {e}")
    return False


# =====================================================================
# =====================  HANDLE PROBER  ===============================
# =====================================================================
async def probe_one_handle(session, char, max_payload, tracker, state):
    """
    Sweeps payload lengths 1..max_payload for ONE writable handle.
    THE NEW BEHAVIOUR: whatever happens (accepted / ATT-rejected / hung
    with no ACK), the length is marked as SENT. After a reconnect the
    sweep continues at last_sent + 1 — never repeats an old length.
    """
    if FORCE_WRITE_MODE == "without_response":
        use_response = False
    else:
        use_response = "write" in char.properties

    notif_sink = session.notif_sink
    print(f"  [*] Probing mode: "
          f"{'WRITE WITH RESPONSE (device ACKs / errors back)' if use_response else 'WRITE WITHOUT RESPONSE (no ATT feedback — silent!)'}")

    if use_response and TRY_WO_RESPONSE_DIAGNOSTIC:
        await wo_response_diagnostic(session, char)

    accepted, rejected, replied = [], {}, []
    hung = {}                       # length -> times it hung with no ACK
    consecutive_hangs = 0
    lost_connection = False

    # ---- resume from the checkpoint: last sent + 1 ----
    last = state.last_for(char)
    length = max(PROBE_MIN_LEN, state.next_for(char))
    if last > 0:
        print(f"  [STATE] last byte-length sent = {last}  ->  resuming at {length}")

    limit = min(PROBE_MAX_LEN, max_payload)

    while length <= limit:
        # global runaway protection
        if tracker.reconnects >= MAX_TOTAL_RECONNECTS:
            print(f"[!!] Global reconnect cap ({MAX_TOTAL_RECONNECTS}) hit — aborting this handle.")
            lost_connection = True
            break

        # too many silent writes in a row -> diagnose and stop wasting time
        if MAX_CONSECUTIVE_HANGS and consecutive_hangs >= MAX_CONSECUTIVE_HANGS:
            print(f"[!!] {consecutive_hangs} writes in a row with ZERO response from device —")
            print("     the write path looks dead. Try in this order:")
            print("       1) PROBE_FILL_BYTE = 0x00        (maybe 'A' crashes the fw parser)")
            print("       2) TRY_PAIR_ON_CONNECT = True    (maybe it needs bonding)")
            print("       3) SUBSCRIBE_ON_CONNECT = False  (maybe CCCD write upsets it)")
            print("       4) FORCE_WRITE_MODE = \"without_response\"")
            print("     Delete probe_checkpoint.json (or RESET_CHECKPOINT=True) to sweep again.")
            lost_connection = True
            break

        # ---- INSTANT-RECONNECT GATE (resume at last_sent + 1) ----
        if not await session.ensure():
            print(f"        len={length:3d} bytes  ->  SKIPPED (could not re-establish connection)")
            lost_connection = True
            break

        mark = len(notif_sink)
        payload = bytes([PROBE_FILL_BYTE]) * length
        try:
            await session.write(char, payload, use_response)
            # ---- SENT + ACKED ----
            state.mark_sent(char, length)
            accepted.append(length)
            consecutive_hangs = 0
            print(f"        len={length:3d} bytes  ->  ACCEPTED   [last-sent={length}, next={length+1}]")
            length += 1
        except asyncio.TimeoutError:
            # ---- SENT but device gave NO ACK: count it as sent, MOVE ON ----
            state.mark_sent(char, length)
            hung[length] = hung.get(length, 0) + 1
            consecutive_hangs += 1
            print(f"        len={length:3d} bytes  ->  SENT, NO ACK (hung >{WRITE_TIMEOUT}s) "
                  f"[last-sent={length}, next={length+1}] — reconnecting")
            tracker.log_error(f"handle {char.handle} len={length}: no ACK (hung >{WRITE_TIMEOUT}s)")
            session.force_reconnect = True
            length += 1
        except asyncio.CancelledError:
            raise
        except Exception as e:
            reason = classify_write_error(e)
            state.mark_sent(char, length)
            r_low = reason.lower()
            if ("CONNECTION LOST" in reason or "TIMEOUT" in reason or "mtu" in r_low):
                # link-level problem -> sent?, reconnect, keep moving forward
                hung[length] = hung.get(length, 0) + 1
                consecutive_hangs += 1
                print(f"        len={length:3d} bytes  ->  LINK ERROR ({reason}) "
                      f"[last-sent={length}, next={length+1}] — reconnecting")
                tracker.log_error(f"handle {char.handle} len={length}: {reason}")
                session.force_reconnect = True
                length += 1
            else:
                # real ATT answer (e.g. 0x0C wrong length) -> that's DATA, move on
                rejected[length] = reason
                consecutive_hangs = 0
                print(f"        len={length:3d} bytes  ->  REJECTED ({reason}) "
                      f"[last-sent={length}, next={length+1}]")
                length += 1

        # show any notifications fired right after this write
        fresh = notif_sink[mark:]
        for h, b in fresh:
            print(f"            << REPLY from handle {h}: {b.hex()}  ({len(b)} bytes)")
        if fresh:
            replied.append(length)

        if session.alive:
            await asyncio.sleep(PROBE_DELAY)

    # ---------------- interpretation ----------------
    print("  [*] Interpretation:")
    verdict, expected = "unknown", None
    if not accepted and not rejected and hung:
        verdict = ("every write was SENT but the device gave NO ATT response — "
                   "firmware ignores write-requests (needs pairing? different "
                   "payload? only WO-R? see hints above)")
    elif not accepted:
        reasons = set(rejected.values())
        if any("Write Not Permitted" in r for r in reasons):
            verdict = "NOT actually writable (0x03) — skip this handle"
        else:
            verdict = f"all lengths rejected — reasons: {reasons}"
    else:
        lo, hi = min(accepted), max(accepted)
        contiguous = (set(accepted) == set(range(lo, hi + 1)))
        if len(accepted) == limit:
            verdict = (f"accepts EVERY length 1..{hi} -> no fixed length enforced; "
                       f"payload only limited by MTU ({max_payload} bytes)")
        elif len(accepted) == 1:
            expected = lo
            verdict = f"accepts ONLY {lo} bytes -> FIXED-LENGTH: handle expects exactly {lo} bytes"
        elif contiguous:
            expected = hi
            verdict = f"accepts {lo}..{hi} bytes -> variable-length, max expected = {hi} bytes"
        else:
            verdict = f"accepts patchy lengths {accepted} -> protocol-dependent structure"

    print(f"      >>> {verdict}")
    if replied:
        print(f"      >>> lengths that triggered a device reply: {replied}")

    if "read" in char.properties and accepted and session.alive:
        try:
            val = await session.client.read_gatt_char(char)
            print(f"      >>> read-back after writes: {val.hex()} ({len(val)} bytes)")
        except Exception as e:
            print(f"      >>> read-back failed: {e}")

    return {"char": char, "accepted": accepted, "rejected": rejected,
            "hung": hung, "verdict": verdict, "expected_len": expected,
            "replied": replied, "lost_connection": lost_connection}


async def probe_writable_handles(address):
    print("\n" + "#" * 60)
    print("#   PART 2 : BYTE-LENGTH PROBER (SELF-HEALING + LAST-SENT STATE)")
    print("#" * 60)
    print("[!] Filler bytes are REAL writes — device may react.\n")

    tracker = ConnectionTracker(address)
    state = ProbeState()          # <-- loads probe_checkpoint.json if present
    notif_sink = []
    session = BLESession(address, tracker, notif_sink)

    ok = await session.connect()
    if not ok:
        print("[!] Could not connect after retries — aborting probe.")
        connection_summary(tracker)
        return

    watchdog = asyncio.create_task(connection_watchdog(session, tracker))

    try:
        max_payload = session.mtu_payload_limit()
        print(f"[+] Negotiated MTU = {max_payload + 3}  ->  max payload per single write = {max_payload} bytes\n")

        targets = []
        for service in session.client.services:
            for char in service.characteristics:
                if "write" in char.properties or "write-without-response" in char.properties:
                    targets.append((service, char))

        if not targets:
            print("[!] No writable characteristics found.")
            return

        print(f"[+] Found {len(targets)} writable handle(s) — starting probe...\n")

        results = []
        for i, (service, char) in enumerate(targets, 1):
            print("=" * 60)
            print(f"  PROBE {i}/{len(targets)}  |  Handle: {char.handle}")
            print(f"  Service : {service.uuid}")
            print(f"  Char    : {char.uuid}")
            print(f"  Props   : {', '.join(char.properties)}")
            print("-" * 60)
            r = await probe_one_handle(session, char, max_payload, tracker, state)
            results.append(r)
            print("")
            if r["lost_connection"] and not RECONNECT_ON_DROP:
                print("[!] Auto-reconnect disabled — stopping.")
                break

        # ---------------- FINAL REPORT ----------------
        print("\n" + "=" * 60)
        print(" FINAL REPORT — what each writable handle expects")
        print("=" * 60)
        for r in results:
            char = r["char"]
            exp = f"~{r['expected_len']} bytes" if r["expected_len"] else "variable / see verdict"
            print(f"  Handle {char.handle:>4} | {char.uuid}")
            print(f"      last-sent : {state.last_for(char)} bytes (checkpoint)")
            print(f"      expected  : {exp}")
            print(f"      accepted  : {r['accepted'] if r['accepted'] else 'none'}")
            if r["rejected"]:
                print(f"      rejected  : {r['rejected']}")
            if r["hung"]:
                print(f"      no-ACK    : {sorted(r['hung'])}")
            if r["replied"]:
                print(f"      replied   : {r['replied']}")
            print(f"      verdict   : {r['verdict']}\n")

    finally:
        watchdog.cancel()
        if session.client is not None and session.client.is_connected:
            total = tracker.uptime()
            print(f"\n[*] Closing connection — this session lasted {total:.2f}s")
            try:
                await session.client.disconnect()
            except Exception:
                pass
            if tracker.connect_time is not None:
                tracker.sessions.append({"start": tracker.connect_time, "duration": total})
                tracker.connect_time = None
        connection_summary(tracker)


if __name__ == "__main__":
    # STEP 1 — your original exploration code (UNCHANGED)
    t0 = time.time()
    try:
        asyncio.run(explore_ble_device(DEVICE_ADDRESS))
    except Exception as e:
        print(f"\n[!] ERROR after {time.time() - t0:.2f}s in exploration phase: {e!r}")

    # STEP 2 — probe writable handles with last-sent state checker
    if ARGS.explore_only:
        print("[*] --explore-only: skipping probe phase.")
    else:
        try:
            asyncio.run(probe_writable_handles(DEVICE_ADDRESS))
        except Exception as e:
            print(f"\n[!] FATAL ERROR in prober: {e!r}")
