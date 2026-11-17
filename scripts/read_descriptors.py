#!/usr/bin/env python3
import argparse
import asyncio
from bleak import BleakClient

def _parse_args():
    p = argparse.ArgumentParser(description="Read specific GATT descriptor handles and print raw/ASCII content.")
    p.add_argument("mac", nargs="?", default="80:E1:27:4D:A8:3F", help="target MAC (default: %(default)s)")
    p.add_argument("--handles", default="19,22", help="comma-separated descriptor handles (default: %(default)s)")
    return p.parse_args()

ARGS = _parse_args()

ADDR = ARGS.mac
HANDLES = [int(h) for h in ARGS.handles.split(",")]

async def main():
    async with BleakClient(ADDR) as client:
        for handle in HANDLES:
            try:
                data = await client.read_gatt_descriptor(handle)
                print(f"Handle {handle}: {data!r}")
                print(f"ASCII: {data.decode(errors='replace')}")
            except Exception as e:
                print(f"Handle {handle}: ERROR: {e}")

asyncio.run(main())
