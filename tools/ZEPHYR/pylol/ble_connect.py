#!/usr/bin/env python3

import argparse
import asyncio
from bleak import BleakClient

# Use the same characteristic UUID you defined in your server script
CHARACTERISTIC_UUID = "87654321-4321-4321-4321-ba9876543210"

async def connect_and_send_packet(mac_address, message):
    print(f"[*] Attempting to connect to target MAC: {mac_address}...")
    
    try:
        async with BleakClient(mac_address) as client:
            # 1. CLEAR CONNECTION CHECK
            if client.is_connected:
                print(f"[+] SUCCESS: Connected to {mac_address}!")
            else:
                print(f"[!] FAILED: Could not establish connection.")
                return

            # 2. SENDING A PACKET (Write Data)
            print(f"[*] Sending packet payload: '{message}'")
            data_bytes = message.encode("utf-8")
            
            # This is how you send a packet to the device
            await client.write_gatt_char(CHARACTERISTIC_UUID, data_bytes)
            print("[+] Packet sent successfully!")

            # 3. OPTIONAL: Read back response from the device
            print("[*] Reading response from device...")
            response = await client.read_gatt_char(CHARACTERISTIC_UUID)
            print(f"[+] Received data back: {bytes(response).decode('utf-8')}")

            # Keep connection alive for a few seconds to let things settle
            print("[*] Holding connection open for 5 seconds...")
            await asyncio.sleep(5)

    except Exception as error:
        print(f"[!] Connection or packet error: {error}")

def main():
    parser = argparse.ArgumentParser(description="BLE Connection & Packet Sender")
    parser.add_argument("-m", "--mac", required=True, help="Target device MAC address")
    parser.add_argument("-p", "--packet", default="Hello Server!", help="Data packet string to send")
    args = parser.parse_args()
    
    asyncio.run(connect_and_send_packet(args.mac, args.packet))

if __name__ == "__main__":
    main()
