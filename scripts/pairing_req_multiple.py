#!/usr/bin/env python3
# pairing_req_multiple.py  (v2 — "connect once, stay forever")
# Based on ble_busy.py — fire pairing/connection requests very fast.
# FIRST successful connect = final: never disconnect, never go back to
# hammering. Just hold that one link stable forever. If the device drops
# it later, quietly reconnect once to restore the stable link.

import asyncio
import logging
import sys
from bleak import BleakClient
from bleak.exc import BleakError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger("PairingRepeater")


def _parse_args():
    import argparse
    p = argparse.ArgumentParser(
        description="Rapid pairing requests until ONE connect, then hold that link stable forever (authorized targets only)."
    )
    p.add_argument("mac", nargs="?", default="00:1F:FF:C1:63:9F",
                   help="target MAC (default: %(default)s)")
    p.add_argument("--timeout", type=float, default=0.3,
                   help="per-attempt connect timeout seconds (default: %(default)s)")
    p.add_argument("--delay", type=float, default=0.02,
                   help="delay between fast attempts (default: %(default)s)")
    p.add_argument("--reconnect-timeout", type=float, default=5.0,
                   help="timeout for auto-reconnect if link later drops (default: %(default)s)")
    p.add_argument("--stable-check", type=float, default=1.0,
                   help="seconds between stability checks while connected (default: %(default)s)")
    p.add_argument("--max-attempts", type=int, default=0,
                   help="give up after N fast requests if never connected (0 = run until Ctrl+C)")
    return p.parse_args()


ARGS = _parse_args()
TARGET_MAC = ARGS.mac


class PairingRepeater:
    def __init__(self, mac: str):
        self.mac = mac.upper()
        self.attempts = 0
        self.connects = 0

    # ---------- PHASE 1: fast requests until the FIRST connect ----------
    async def hammer_until_connected(self) -> BleakClient | None:
        logger.info(f"[*] Rapid pairing requests -> {self.mac}")
        logger.info("[*] FIRST successful connect = final. Link will be held stable forever.")
        logger.info("[*] Press Ctrl+C to stop.\n")

        while ARGS.max_attempts == 0 or self.attempts < ARGS.max_attempts:
            try:
                self.attempts += 1
                logger.info(f"[{self.attempts}] Sending pairing/connection request to {self.mac}...")

                client = BleakClient(self.mac, timeout=ARGS.timeout)
                await client.connect()

                if client.is_connected:
                    self.connects += 1
                    logger.info(
                        f"    [+] CONNECTED on attempt {self.attempts} "
                        f"(total connects: {self.connects})"
                    )
                    # NOTE: not using `async with`, so the link stays open
                    # after we return. We NEVER disconnect from here on.
                    return client

                # is_connected false right after connect() -> clean close, retry
                try:
                    await client.disconnect()
                except Exception:
                    pass

            except (BleakError, asyncio.TimeoutError):
                # Request timed out / radio busy — keep hammering
                pass
            except Exception as e:
                logger.debug(f"Iteration error: {e}")

            await asyncio.sleep(ARGS.delay)

        logger.info(f"[*] Reached max attempts ({ARGS.max_attempts}) without connecting.")
        return None

    # ---------- PHASE 2: hold the ONE connection stable forever ----------
    async def hold_forever(self, client: BleakClient):
        logger.info("[*] Holding connection STABLE — no more requests, no disconnects.\n")

        while True:
            if client.is_connected:
                await asyncio.sleep(ARGS.stable_check)
                continue

            # Device dropped the link. Quietly reconnect to keep it stable.
            logger.info("    [-] Link dropped — silently reconnecting to restore stability...")
            restored = None
            while restored is None:
                try:
                    restored = BleakClient(self.mac, timeout=ARGS.reconnect_timeout)
                    await restored.connect()
                    if not restored.is_connected:
                        await restored.disconnect()
                        restored = None
                except (BleakError, asyncio.TimeoutError):
                    restored = None
                    await asyncio.sleep(ARGS.reconnect_timeout)
                except Exception as e:
                    logger.debug(f"Reconnect error: {e}")
                    restored = None
                    await asyncio.sleep(ARGS.reconnect_timeout)

            client = restored
            self.connects += 1
            logger.info("    [+] Link restored — holding stable again.")


if __name__ == "__main__":
    repeater = PairingRepeater(TARGET_MAC)

    try:
        client = asyncio.run(repeater.hammer_until_connected())
        if client is not None:
            asyncio.run(repeater.hold_forever(client))
    except KeyboardInterrupt:
        logger.info(
            f"\n[*] Stopped by user. Requests sent: {repeater.attempts}, "
            f"successful connects: {repeater.connects}"
        )
        sys.exit(0)
