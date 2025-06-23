import serial.tools.list_ports
import usb.core
import usb.util
import subprocess
import time
import json
import wmi

def get_serial_ports():
    ports = serial.tools.list_ports.comports()
    diagnostic_ports = []
    for port in ports:
        desc = port.description.lower()
        print(f"Port: {port.device}")
        print(f"Description: {port.description}")
        print(f"HWID: {port.hwid}")
        print(f"VID: {port.vid}, PID: {port.pid}")
        print(f"Serial Number: {port.serial_number}")
        print(f"Manufacturer: {port.manufacturer}")
        print("-" * 40)
        if ("diagnostics" in desc and "90db" in desc) or \
            ("diag" in desc and "901d" in desc):
            diagnostic_ports.append(port.device)
    return sorted(diagnostic_ports)

def get_adb_devices():
    result = subprocess.run(["adb", "devices"], capture_output=True, text=True)
    lines = result.stdout.strip().splitlines()[1:]
    return [line.split()[0] for line in lines if "device" in line]

def reboot_device(device_id):
    subprocess.run(["adb", "-s", device_id, "reboot"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

def wait_for_port_disappearance(before_ports, timeout=30):
    for _ in range(timeout):
        time.sleep(1)
        after_ports = get_serial_ports()
        disappeared = list(set(before_ports) - set(after_ports))
        if disappeared:
            return disappeared[0]
    return None

def wait_for_port_reappearance(port, timeout=30):
    for _ in range(timeout):
        time.sleep(1)
        if port in get_serial_ports():
            return True
    return False

def map_devices_to_ports():
    device_ids = get_adb_devices()

    if not device_ids:
        print("No ADB devices found.")
        return

    if len(device_ids) > 8:
        print(f"Found {len(device_ids)} devices. This script is optimized for up to 8 devices.")

    print("Step 1: Initial Qualcomm HS-USB Diagnostics 9025 COM Ports")
    initial_ports = get_serial_ports()
    print(f"Diagnostic ports found: {initial_ports}\n")

    device_to_port = {}

    for index, device in enumerate(device_ids[:8], start=1):
        print(f"Processing Device {index}: {device}")
        ports_before = get_serial_ports()
        # reboot_device(device)

        print("Waiting for diagnostic COM port to disappear...")
        disappearing_port = wait_for_port_disappearance(ports_before)

        if not disappearing_port:
            print(f"No diagnostic port disappeared for device {device}. Skipping.\n")
            continue

        print(f"Disappearing port: {disappearing_port}")
        print("Waiting for diagnostic COM port to reappear...")

        if wait_for_port_reappearance(disappearing_port):
            print(f"Port {disappearing_port} reappeared.")
            device_to_port[device] = disappearing_port
        else:
            print(f"Port {disappearing_port} did not reappear.")

        print("")

    print("Final Device to Diagnostic Port Mapping:")
    for i, (dev, port) in enumerate(device_to_port.items(), start=1):
        print(f"Device {i}: {dev} => Port {port}")

    # Save mapping to JSON file
    with open("device_port_mapping.json", "w") as f:
        json.dump(device_to_port, f, indent=4)
    print("\nMapping saved to device_port_mapping.json")

    return device_to_port

if __name__ == "__main__":
    map_devices_to_ports()
