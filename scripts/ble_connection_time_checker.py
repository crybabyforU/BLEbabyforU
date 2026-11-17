#!/usr/bin/env python3

import argparse
import asyncio
import sys
from datetime import datetime
from bleak import BleakClient


def parse_args():
    p = argparse.ArgumentParser(description="Monitor BLE connection uptime and log durations (crash/watchdog detector).")
    p.add_argument("mac", nargs="?", default=None, help="target MAC (required unless --help)")
    p.add_argument("--timeout", type=float, default=10.0, help="connect timeout seconds (default: %(default)s)")
    p.add_argument("--retry", type=float, default=2.0, help="delay between reconnect attempts (default: %(default)s)")
    return p.parse_args()


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


async def monitor_ble(mac, timeout, retry):

    while True:
        print(f"\n[{timestamp()}] Connecting to {mac}...")

        connected_time = None

        try:
            async with BleakClient(mac, timeout=timeout) as client:

                if client.is_connected:
                    connected_time = datetime.now()

                    print(f"[{timestamp()}] CONNECTED")
                    print(f"[{timestamp()}] MAC: {mac}")

                    # Keep connection alive
                    while client.is_connected:
                        await asyncio.sleep(0.5)

        except Exception as e:
            print(f"[{timestamp()}] Connection error: {e}")

        finally:
            if connected_time:
                disconnected_time = datetime.now()
                duration = disconnected_time - connected_time

                print(f"[{timestamp()}] DISCONNECTED")
                print(f"[{timestamp()}] Connection duration: {duration}")

            else:
                print(f"[{timestamp()}] NOT CONNECTED")

        print(f"[{timestamp()}] Retrying in {retry:g} seconds...")
        await asyncio.sleep(retry)


def main():

    args = parse_args()
    if not args.mac:
        print("error: MAC address required (or use --help)")
        sys.exit(1)

    try:
        asyncio.run(monitor_ble(args.mac, args.timeout, args.retry))
    except KeyboardInterrupt:
        print(f"\n[{timestamp()}] Stopped.")


if __name__ == "__main__":
    main()
