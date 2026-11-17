#!/usr/bin/env python3

import dbus
import dbus.service
import time
import subprocess
import threading
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

# Enable D-Bus main loop
DBusGMainLoop(set_as_default=True)

BUS_NAME = "org.bluez"
ADAPTER = "/org/bluez/hci1"
ADVERTISEMENT_PATH = "/org/bluez/example/advertisement0"

bus = dbus.SystemBus()

# Get the Zephyr Bluetooth adapter
adapter_obj = bus.get_object(BUS_NAME, ADAPTER)
adapter_props = dbus.Interface(
    adapter_obj,
    "org.freedesktop.DBus.Properties"
)

# Enable adapter
adapter_props.Set(
    "org.bluez.Adapter1",
    "Powered",
    dbus.Boolean(True)
)


class Advertisement(dbus.service.Object):
    def __init__(self, bus, path):
        self.path = path
        super().__init__(bus, path)

    @dbus.service.method(
        "org.freedesktop.DBus.Properties",
        in_signature="s",
        out_signature="a{sv}"
    )
    def GetAll(self, interface):
        if interface != "org.bluez.LEAdvertisement1":
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.InvalidArgs"
            )

        return {
            "Type": dbus.String("peripheral"),
            "LocalName": dbus.String("MDT2410161"),
            "ServiceUUIDs": dbus.Array([], signature="s"),
            "Includes": dbus.Array(["tx-power"], signature="s"),
            "TxPower": dbus.Int16(8),
            "MinInterval": dbus.UInt32(100),
            "MaxInterval": dbus.UInt32(200),
        }

    @dbus.service.method(
        "org.freedesktop.DBus.Properties",
        in_signature="ss",
        out_signature="v"
    )
    def Get(self, interface, prop):
        properties = self.GetAll(interface)
        if prop not in properties:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.InvalidArgs"
            )
        return properties[prop]

    @dbus.service.method(
        "org.freedesktop.DBus.Properties",
        in_signature="ssv",
        out_signature=""
    )
    def Set(self, interface, prop, value):
        raise dbus.exceptions.DBusException(
            "org.freedesktop.DBus.Error.PropertyReadOnly"
        )

    @dbus.service.method(
        "org.freedesktop.DBus.Introspectable",
        in_signature="",
        out_signature="s"
    )
    def Introspect(self):
        return ""

    @dbus.service.method(
        "org.bluez.LEAdvertisement1",
        in_signature="",
        out_signature=""
    )
    def Release(self):
        print("Advertisement released")

# ==================== ADDED: live HCI logs via btmon ====================
btmon_process = None

def start_btmon():
    """Spawn btmon in the background and stream its output to the console."""
    global btmon_process
    try:
        # -i 1 -> hci1 (your nRF dongle, hci0 would be -i 0)
        # -t   -> timestamps on every HCI packet
        btmon_process = subprocess.Popen(
            ["btmon", "-i", "1", "-t"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        threading.Thread(target=_stream_btmon, daemon=True).start()
        print("btmon attached to hci1 — live HCI logs below\n")
    except FileNotFoundError:
        print("btmon not found! Run it manually in another terminal: sudo btmon -i 1")

def _stream_btmon():
    for line in btmon_process.stdout:
        print(f"[HCI] {line}", end="")
# ========================================================================

try:
    manager_obj = bus.get_object(BUS_NAME, ADAPTER)
    manager = dbus.Interface(
        manager_obj,
        "org.bluez.LEAdvertisingManager1"
    )

    advertisement = Advertisement(bus, ADVERTISEMENT_PATH)

    start_btmon()

    loop = GLib.MainLoop()

    def started():
        print("Advertising started: Zephyr-Test")
        print("Use Ctrl+C to stop.")

    def failed(error):
        print(f"Advertising failed: {error}")
        loop.quit()

    manager.RegisterAdvertisement(
        advertisement.path,
        {},
        reply_handler=started,
        error_handler=failed
    )

    try:
        loop.run()
    except KeyboardInterrupt:
        print("\nStopping advertisement...")
    finally:
        try:
            manager.UnregisterAdvertisement(
                advertisement.path
            )
        except dbus.exceptions.DBusException:
            pass

except dbus.exceptions.DBusException as error:
    print(f"D-Bus error: {error}")
    print("Check that BlueZ is running and hci1 supports LE advertising.")
