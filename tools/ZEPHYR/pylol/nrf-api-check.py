
#!/usr/bin/env python3

import argparse
import logging
import shutil
import subprocess
import sys

LOG = logging.getLogger("nrf_probe")


def run_command(command):
    """Run a system command and return its output."""
    LOG.debug("Executing: %s", " ".join(command))

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except FileNotFoundError:
        LOG.error("Required command not found: %s", command[0])
        return None
    except subprocess.TimeoutExpired:
        LOG.error("Command timed out: %s", command[0])
        return None

    LOG.debug("Return code: %d", result.returncode)

    if result.returncode != 0:
        LOG.warning("Command failed: %s", result.stderr.strip())
        return None

    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(
        description="Inspect Linux Bluetooth controller APIs and information."
    )
    parser.add_argument(
        "-i", "--interface",
        default="hci1",
        help="Bluetooth controller to inspect (default: hci1)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable detailed diagnostic logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    print(f"Bluetooth controller probe: {args.interface}")

    # Check required tools
    required = ["btmgmt", "busctl"]
    missing = [tool for tool in required if not shutil.which(tool)]

    if missing:
        print("Missing tools:", ", ".join(missing))
        print("Install the required BlueZ utilities and retry.")
        return 1

    # 1. List available controllers
    print("\n=== Available Bluetooth controllers ===")
    output = run_command(["bluetoothctl", "list"])
    print(output or "No controller list available.")

    # 2. Query controller information directly through BlueZ management
    print(f"\n=== Controller information: {args.interface} ===")
    output = run_command(["btmgmt", "-i", args.interface, "info"])
    print(output or "Unable to retrieve controller information.")

    # 3. List BlueZ D-Bus objects
    print("\n=== BlueZ D-Bus object tree ===")
    output = run_command(["busctl", "tree", "org.bluez"])
    print(output or "Unable to retrieve D-Bus object tree.")

    # 4. Inspect the selected controller's D-Bus interfaces
    path = f"/org/bluez/{args.interface}"
    print(f"\n=== D-Bus interfaces at {path} ===")
    output = run_command(
        ["busctl", "introspect", "org.bluez", path]
    )
    print(output or "Unable to introspect this controller path.")

    print("\nProbe completed.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)

