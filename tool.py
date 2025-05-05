import os
import re
import sys
import time
import shutil
import logging
import hashlib
import zipfile
import argparse
import threading
import subprocess
import serial.tools.list_ports
from tqdm import tqdm
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime

active_ports = set()
flash_threads = []
print_lock = threading.Lock()

logger = None
log_dir = None

def setup_logger():
    """Sets up the logger to log messages to both the console and a file."""
    global logger
    global log_dir
    # Create the logs directory if it doesn't exist
    log_dir = os.path.join(os.getcwd(), "logs")
    os.makedirs(log_dir, exist_ok=True)

    # Generate a time-stamped log file name
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = os.path.join(log_dir, f"cavli_flash_{timestamp}.log")

    logger = logging.getLogger("CavliLogger")
    logger.setLevel(logging.DEBUG)  # Set the logging level

    # Create handlers for console and file logging
    console_handler = logging.StreamHandler()
    file_handler = logging.FileHandler(log_file)

    # Set the logging level for each handler
    console_handler.setLevel(logging.INFO)
    file_handler.setLevel(logging.DEBUG)

    # Create a logging format
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    logger.info(f"Logging initialized. Log file: {log_file}")
    
def close_logger():
    """Closes all handlers of the logger."""
    global logger
    handlers = logger.handlers[:]
    for handler in handlers:
        handler.close()
        logger.removeHandler(handler)

def get_com_port_description(com_port):
    com_ports = serial.tools.list_ports.comports()
    for port, desc, hwid in sorted(com_ports):
        if port == com_port:
            return desc
    return None

def list_com_ports(list_ports):
    ports = serial.tools.list_ports.comports()
    if ports:
        for port in ports:
            desc = get_com_port_description(port.name)
            # if not port.name in list_ports :
            if not port.name in list_ports and len(list_ports) < 4:
            # if (desc != None and "Qualcomm HS-USB QDLoader 9008" in desc) and not port.name in list_ports and len(list_ports) < 4:
                return port.name
    return None

# ProgressReporter lets flash logic report progress manually
class ProgressReporter:
    def __init__(self, total, desc, position):
        self.bar = tqdm(total=total,
                        desc=desc,
                        position=position,
                        leave=True,
                        dynamic_ncols=True)
        self.lock = threading.Lock()

    def update(self, n=1):
        with self.lock:
            self.bar.update(n)

    def set(self, n):
        with self.lock:
            self.bar.n = n
            self.bar.refresh()

    def close(self):
        with self.lock:
            self.bar.close()

# Your actual flashing logic receives a ProgressReporter
def default_flash_function(port, flash_file, progress):
    for _ in range(100):
        time.sleep(0.02)  # Simulate step
        progress.update(1)

def flash_function(port, flash_file, progress):
    parser.flash = True
    parser.skip-nhlos = True
    parser.fw_path = "emmc"
    parser.patch_xml = "patch0.xml"
    parser.raw_xml = "rawprogram_unsparse0.xml.xml"
    parser.add_argument('--flash', action='store_true', help='Enable flash operation')
    parser.add_argument('--skip-nhlos', action='store_true', help='Skip flashing NON-HLOS partition (requires --flash)')    

    progress.update(5)

    # Check if --flash is provided and enforce required arguments
    if args.flash:
        if not all([args.fw_path, args.patch_xml, args.raw_xml]):
            parser.error("--flash requires --fw_path, --patch_xml, and --raw_xml arguments.")

    # Check if --skip-nhlos is provided and enforce that --flash is also provided
    if args.skip_nhlos and not args.flash:
        parser.error("--skip-nhlos requires the --flash option.")

    logger.info(f"Firmware Path: {args.fw_path}")
    logger.info(f"Patch XML: {args.patch_xml}")
    logger.info(f"Raw XML: {args.raw_xml}")
    logger.info(f"Flash Enabled: {args.flash}")
    logger.info(f"Skip NON-HLOS: {args.skip_nhlos}")

    progress.update(5)

    fw_path = os.path.abspath(args.fw_path)  # Get absolute path
    unsafe_partitiion = check_safe_xml(fw_path + "\\" +args.raw_xml)
    unsafe_partitiion += check_safe_xml(fw_path + "\\" +args.patch_xml)
    if unsafe_partitiion > 0:
        logger.error("Found %i partitions are unsafe. DO YOU WANT TO FLASH ?" % unsafe_partitiion) 
        if not confirm_before_continue():
            exit(1)
    processed_raw_xml_file = "processed_" + args.raw_xml    
    process_xml(fw_path + "\\" +args.raw_xml, fw_path + "\\" +processed_raw_xml_file , args.skip_nhlos)            
    patch_xml = args.patch_xml
    raw_xml = processed_raw_xml_file
    prog_firehose = os.path.join(fw_path, 'prog_firehose_ddr.elf')
    patch_xml_file = os.path.join(fw_path, patch_xml)
    raw_xml_file = os.path.join(fw_path, raw_xml)
    search_path = fw_path
    if check_file_path(prog_firehose) and check_file_path(patch_xml_file) and check_file_path(raw_xml_file):

        progress.update(5)

        qsahara_command = f"QSaharaServer.exe -p \\\\.\\{com_port} -s 13:{prog_firehose} | tee -a firehose_log.txt"
        fh_loader_getstorageinfo_command = (
            f"fh_loader.exe --port=\\\\.\\{com_port} --getstorageinfo=0 --noprompt "
            f"--showpercentagecomplete --verbose --zlpawarehost=1 --memoryname=emmc | tee -a firehose_log.txt"
        )
        

        
        fh_loader_patch_command = (
            f"fh_loader.exe --port=\\\\.\\{com_port} --sendxml={patch_xml_file} "
            f"--search_path={search_path} --noprompt --showpercentagecomplete --verbose "
            f"--zlpawarehost=1 --memoryname=emmc | tee -a firehose_log.txt"
        )
        

        fh_loader_raw_command = (
            f"fh_loader.exe --port=\\\\.\\{com_port} --sendxml={raw_xml_file} "
            f"--search_path={search_path} --noprompt --showpercentagecomplete --verbose "
            f"--zlpawarehost=1 --memoryname=emmc | tee -a firehose_log.txt"
        )

        fh_loader_setactivepartition_command = (
            f"fh_loader.exe --port=\\\\.\\{com_port} --setactivepartition=0 --noprompt "
            f"--showpercentagecomplete --verbose --zlpawarehost=1 --memoryname=emmc | tee -a firehose_log.txt"
        )

        fh_loader_reset_command = (
            f"fh_loader.exe --port=\\\\.\\{com_port} --reset --noprompt --showpercentagecomplete "
            f"--verbose --zlpawarehost=1 --memoryname=emmc | tee -a firehose_log.txt"
        )

        progress.update(5)
        run_command(qsahara_command ,None, None,"File transferred successfully")
        progress.update(10)
        run_command(fh_loader_getstorageinfo_command, None, None,"{All Finished Successfully}")
        progress.update(10)
        run_command(fh_loader_raw_command, None, None,"{All Finished Successfully}")
        progress.update(10)
        run_command(fh_loader_patch_command ,None, None,"{All Finished Successfully}")
        progress.update(10)
        run_command(fh_loader_setactivepartition_command, None, None,"{All Finished Successfully}")
        progress.update(10)
        run_command(fh_loader_reset_command, None, None,"{All Finished Successfully}")
        progress.update(10)

        end_time = time.time()  # Record the end time
        elapsed_time = end_time - start_time            
        logger.info(f"Script execution time: {elapsed_time:.2f} seconds")
    print("Flash success!!! ")
    move_port_trace(log_dir)
    zip_logs(log_dir)
    progress.update(1)

# Thread target
cnt = 0
def flash_device(port, flash_file, position, flash_function, list_port):
    global cnt
    progress = ProgressReporter(total=100, desc=f"Flashing {port} {cnt}", position=position)
    cnt=cnt+1
    try:
        flash_function(port, flash_file, progress)
    finally:
        progress.close()

    with print_lock:
        sys.stdout.write("\033[K")
        list_port.remove(port)
        tqdm.write(f"\n[✓] {port} flashed successfully with {flash_file}")

def on_new_device(port, flash_function, list_port):
    flash_file = "firmware.bin"
    t = threading.Thread(target=flash_device, args=(port, flash_file, len(active_ports) - 1, flash_function, list_port))
    t.start()
    flash_threads.append(t)

def usb_detect_simulate(port_list, detected_callback):
    dummy_ports = ["COM1", "COM2", "COM3", "COM4"]
    for port in dummy_ports:
        time.sleep(1)
        if port not in port_list:
            port_list.add(port)
            detected_callback(port)

def usb_detect(port_list, detected_callback):
    while(True):
        edl_com_port = list_com_ports(port_list)
        if edl_com_port is not None:
            # logger.info(f"Device is already in EDL mode... flashing ")
            port_list.add(edl_com_port)
            detected_callback(edl_com_port)
            time.sleep(0.5)

def get_connected_devices():
    """Returns a list of connected devices' serial numbers."""
    result = subprocess.run(["adb", "devices"], stdout=subprocess.PIPE, text=True)
    lines = result.stdout.strip().splitlines()
    devices = []

    for line in lines[1:]:  # Skip the first line
        if line.strip() and "device" in line:
            serial = line.split()[0]
            devices.append(serial)
    return devices

def reboot_to_edl(serial):
    """Reboots a specific device into EDL mode."""
    print(f"Rebooting device {serial} into EDL mode...")
    subprocess.run(["adb", "-s", serial, "reboot", "edl"])

def force_enter_edl():
    while True:
        devices = get_connected_devices()
        if not devices:
            time.sleep(1)
            continue
        for i, serial in enumerate(devices):
            print(f"{i + 1}: {serial}")
        for serial in devices:
            reboot_to_edl(serial)
        time.sleep(1)

def run_cmd_flash(com_port):
    setup_logger()
    start_time = time.time()  # Record the start time

    parser.flash = True
    parser.skip-nhlos = True
    parser.fw_path = "emmc"
    parser.patch_xml = "patch0.xml"
    parser.raw_xml = "rawprogram_unsparse0.xml.xml"
    parser.add_argument('--flash', action='store_true', help='Enable flash operation')
    parser.add_argument('--skip-nhlos', action='store_true', help='Skip flashing NON-HLOS partition (requires --flash)')    

    # Check if --flash is provided and enforce required arguments
    if args.flash:
        if not all([args.fw_path, args.patch_xml, args.raw_xml]):
            parser.error("--flash requires --fw_path, --patch_xml, and --raw_xml arguments.")

    # Check if --skip-nhlos is provided and enforce that --flash is also provided
    if args.skip_nhlos and not args.flash:
        parser.error("--skip-nhlos requires the --flash option.")

    logger.info(f"Firmware Path: {args.fw_path}")
    logger.info(f"Patch XML: {args.patch_xml}")
    logger.info(f"Raw XML: {args.raw_xml}")
    logger.info(f"Flash Enabled: {args.flash}")
    logger.info(f"Skip NON-HLOS: {args.skip_nhlos}")

    fw_path = os.path.abspath(args.fw_path)  # Get absolute path
    unsafe_partitiion = check_safe_xml(fw_path + "\\" +args.raw_xml)
    unsafe_partitiion += check_safe_xml(fw_path + "\\" +args.patch_xml)
    if unsafe_partitiion > 0:
        logger.error("Found %i partitions are unsafe. DO YOU WANT TO FLASH ?" % unsafe_partitiion) 
        if not confirm_before_continue():
            exit(1)
    processed_raw_xml_file = "processed_" + args.raw_xml    
    process_xml(fw_path + "\\" +args.raw_xml, fw_path + "\\" +processed_raw_xml_file , args.skip_nhlos)            
    patch_xml = args.patch_xml
    raw_xml = processed_raw_xml_file
    prog_firehose = os.path.join(fw_path, 'prog_firehose_ddr.elf')
    patch_xml_file = os.path.join(fw_path, patch_xml)
    raw_xml_file = os.path.join(fw_path, raw_xml)
    search_path = fw_path
    if check_file_path(prog_firehose) and check_file_path(patch_xml_file) and check_file_path(raw_xml_file):
        qsahara_command = f"QSaharaServer.exe -p \\\\.\\{com_port} -s 13:{prog_firehose} | tee -a firehose_log.txt"
        fh_loader_getstorageinfo_command = (
            f"fh_loader.exe --port=\\\\.\\{com_port} --getstorageinfo=0 --noprompt "
            f"--showpercentagecomplete --verbose --zlpawarehost=1 --memoryname=emmc | tee -a firehose_log.txt"
        )
        fh_loader_patch_command = (
            f"fh_loader.exe --port=\\\\.\\{com_port} --sendxml={patch_xml_file} "
            f"--search_path={search_path} --noprompt --showpercentagecomplete --verbose "
            f"--zlpawarehost=1 --memoryname=emmc | tee -a firehose_log.txt"
        )
        fh_loader_raw_command = (
            f"fh_loader.exe --port=\\\\.\\{com_port} --sendxml={raw_xml_file} "
            f"--search_path={search_path} --noprompt --showpercentagecomplete --verbose "
            f"--zlpawarehost=1 --memoryname=emmc | tee -a firehose_log.txt"
        )
        fh_loader_setactivepartition_command = (
            f"fh_loader.exe --port=\\\\.\\{com_port} --setactivepartition=0 --noprompt "
            f"--showpercentagecomplete --verbose --zlpawarehost=1 --memoryname=emmc | tee -a firehose_log.txt"
        )
        fh_loader_reset_command = (
            f"fh_loader.exe --port=\\\\.\\{com_port} --reset --noprompt --showpercentagecomplete "
            f"--verbose --zlpawarehost=1 --memoryname=emmc | tee -a firehose_log.txt"
        )

        run_command(qsahara_command ,None, None,"File transferred successfully")
        run_command(fh_loader_getstorageinfo_command, None, None,"{All Finished Successfully}")
        run_command(fh_loader_raw_command, None, None,"{All Finished Successfully}")
        run_command(fh_loader_patch_command ,None, None,"{All Finished Successfully}")   
        run_command(fh_loader_setactivepartition_command, None, None,"{All Finished Successfully}")
        run_command(fh_loader_reset_command, None, None,"{All Finished Successfully}")

        end_time = time.time()  # Record the end time
        elapsed_time = end_time - start_time            
        logger.info(f"Script execution time: {elapsed_time:.2f} seconds")
    print("Flash success!!! ")
    move_port_trace(log_dir)
    zip_logs(log_dir)

def main(flash_function=default_flash_function):
    setup_logger()
    force_edl_thread = threading.Thread(target=force_enter_edl)
    detect_thread = threading.Thread(target=usb_detect, args=(active_ports, lambda port: on_new_device(port, flash_function, active_ports)))
    detect_thread.start()
    force_edl_thread.start()
    detect_thread.join()
    force_edl_thread.join()

    for t in flash_threads:
        t.join()

    with print_lock:
        print("\n🔚 All devices have been flashed.")

if __name__ == "__main__":
    main()
