#!/usr/bin/env python3
import argparse
import asyncio
from bleak import BleakClient

def _parse_args():
    p = argparse.ArgumentParser(description="Enumerate all GATT services, characteristics, values and descriptors.")
    p.add_argument("mac", nargs="?", default="00:1F:FF:C1:63:9F", help="target MAC (default: %(default)s)")
    return p.parse_args()

ARGS = _parse_args()

# Your target device MAC address
DEVICE_ADDRESS = ARGS.mac

async def explore_ble_device(address):
    print(f"[*] Connecting to device: {address}...")
    
    async with BleakClient(address) as client:
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

if __name__ == "__main__":
    asyncio.run(explore_ble_device(DEVICE_ADDRESS))
