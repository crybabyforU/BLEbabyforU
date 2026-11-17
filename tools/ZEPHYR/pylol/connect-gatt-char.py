#!/usr/bin/env python3

import dbus
import dbus.service
import time
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

# Enable D-Bus main loop
DBusGMainLoop(set_as_default=True)

BUS_NAME = "org.bluez"
ADAPTER = "/org/bluez/hci1"
ADVERTISEMENT_PATH = "/org/bluez/example/advertisement0"
GATT_SERVICE_PATH = "/org/bluez/example/service0"

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


# --- ADDED: GATT APPLICATION CLASSES ---
class Application(dbus.service.Object):
    def __init__(self, bus):
        self.path = "/"
        self.services = []
        super().__init__(bus, self.path)

    def add_service(self, service):
        self.services.append(service)

    @dbus.service.method("org.freedesktop.DBus.ObjectManager", in_signature="", out_signature="a{oa{sa{sv}}}")
    def GetManagedObjects(self):
        response = {}
        for service in self.services:
            response[service.path] = service.get_properties()
            for char in service.characteristics:
                response[char.path] = char.get_properties()
        return response


class Service(dbus.service.Object):
    def __init__(self, bus, index, uuid, primary):
        self.path = GATT_SERVICE_PATH + str(index)
        self.uuid = uuid
        self.primary = primary
        self.characteristics = []
        super().__init__(bus, self.path)

    def add_characteristic(self, characteristic):
        self.characteristics.append(characteristic)

    def get_properties(self):
        return {
            "org.bluez.GattService1": {
                "UUID": dbus.String(self.uuid),
                "Primary": dbus.Boolean(self.primary),
            }
        }


class Characteristic(dbus.service.Object):
    def __init__(self, bus, index, uuid, flags, service):
        self.path = service.path + "/char" + str(index)
        self.uuid = uuid
        self.flags = flags
        self.service = service
        super().__init__(bus, self.path)

    def get_properties(self):
        return {
            "org.bluez.GattCharacteristic1": {
                "Service": dbus.ObjectPath(self.service.path),
                "UUID": dbus.String(self.uuid),
                "Flags": dbus.Array(self.flags, signature="s"),
            }
        }

    @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != "org.bluez.GattCharacteristic1":
            raise dbus.exceptions.DBusException("org.freedesktop.DBus.Error.InvalidArgs")
        return {
            "UUID": dbus.String(self.uuid),
            "Service": dbus.ObjectPath(self.service.path),
            "Flags": dbus.Array(self.flags, signature="s"),
        }

    # --- ADD THESE TWO METHODS HERE ---
    @dbus.service.method("org.bluez.GattCharacteristic1", in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        print("Read request received from a client!")
        data_to_send = "Hello from Linux BlueZ!"
        return dbus.Array([dbus.Byte(b) for b in data_to_send.encode("utf-8")], signature="y")

    @dbus.service.method("org.bluez.GattCharacteristic1", in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        received_data = bytes(value)
        print(f"Write request received! Data: {received_data}")
    # ----------------------------------
# ----------------------------------------


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
            "ServiceUUIDs": dbus.Array(["12345678-1234-5678-1234-567812345678"], signature="s"),
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
        "org.bluez.LEAdvertisement1",
        in_signature="",
        out_signature=""
    )
    def Release(self):
        print("Advertisement released")


try:
    # --- ADDED: REGISTER GATT APPLICATION ---
    app = Application(bus)
    service = Service(bus, 0, "12345678-1234-5678-1234-567812345678", True)
    char = Characteristic(bus, 0, "87654321-4321-4321-4321-ba9876543210", ["read", "write"], service)
    service.add_characteristic(char)
    app.add_service(service)

    gatt_manager = dbus.Interface(bus.get_object(BUS_NAME, ADAPTER), "org.bluez.GattManager1")
    gatt_manager.RegisterApplication(
        app.path, 
        {}, 
        reply_handler=lambda: print("GATT Application registered successfully"), 
        error_handler=lambda e: print(f"GATT Registration failed: {e}")
    )
    # ----------------------------------------

    manager_obj = bus.get_object(BUS_NAME, ADAPTER)
    manager = dbus.Interface(
        manager_obj,
        "org.bluez.LEAdvertisingManager1"
    )

    advertisement = Advertisement(bus, ADVERTISEMENT_PATH)
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
