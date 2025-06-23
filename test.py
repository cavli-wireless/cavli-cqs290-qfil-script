import wmi
import serial.tools.list_ports
import usb.core
import usb.util
import subprocess
import time
import json

c = wmi.WMI()
adb_serials = []

# 1. Get all ADB serials from connected Android devices
import subprocess
out = subprocess.check_output(["adb", "devices"]).decode()
for line in out.strip().split("\n")[1:]:
    if line.strip():
        serial = line.split()[0]
        adb_serials.append(serial)

# 2. Map COM ports to USB devices
ports = serial.tools.list_ports.comports()
for port in ports:
    print("=" * 50)
    print(f"COM Port: {port.device}")
    print(f"Description: {port.description}")
    print(f"VID: {port.vid}, PID: {port.pid}")
    print(f"HWID: {port.hwid}")

    # Use WMI to query USB device info
    for usb in c.Win32_PnPEntity():
        if usb.Name and port.device in usb.Name:
            print(f"WMI Name: {usb.Name}")
            print(f"DeviceID: {usb.DeviceID}")
            print(f"PNPDeviceID: {usb.PNPDeviceID}")
            print(f"Serial candidate: {usb.PNPDeviceID.split('\\')[-1]}")
            for serial in adb_serials:
                if serial in usb.PNPDeviceID:
                    print(f"✅ Matched ADB Serial: {serial}")
