import struct
import uuid
import json
import subprocess
import serial.tools.list_ports
import json
import os
import time
import os
import re
import sys
import time
import signal
import logging
import argparse
import threading
import subprocess
import zipfile
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from dataclasses import dataclass
from datetime import datetime

GPT_HEADER_FILE = "fh_gpt_header_0"
GPT_ENTRIES_FILE = "fh_gpt_entries_0"
SECTOR_SIZE = 512
OUTPUT_JSON = "gpt_parsed.json"
OUTPUT2_JSON = "gpt_parsed_after.json"

PROJECT_DIR = os.getcwd()

class ProgressReporter:
    def __init__(self, total, desc, progress):
        self.desc = desc
        self.progress = progress
        self.task_id = self.progress.add_task(desc, total=total)
        self.lock = threading.Lock()

    def update(self, n=1):
        with self.lock:
            self.progress.update(self.task_id, advance=n)

    def update_desc(self, sub_desc):
        with self.lock:
            self.progress.update(self.task_id, description=f"{self.desc} {sub_desc}")

    def set(self, n):
        with self.lock:
            self.progress.update(self.task_id, completed=n)

    def close(self):
        with self.lock:
            self.progress.remove_task(self.task_id)

def zip_logs(log_dir):
    """Zips all files in the logs directory and removes the original files."""
    # Generate a zip file name with a timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    zip_file_path = os.path.join(log_dir, f"logs_{timestamp}.zip")
    
    logger.info(f"Zipped all log files to {zip_file_path} and removed the originals.")
    close_logger()
    # Create a zip file
    with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(log_dir):
            for file in files:
                file_path = os.path.join(root, file)
                # Skip zipping the zip file itself
                if file.endswith(".zip"):
                    continue
                zipf.write(file_path, os.path.relpath(file_path, log_dir))
                os.remove(file_path)  # Remove the original file after adding to the zip

def load_gpt_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def print_partition(gpt_data, name=None):
    for p in gpt_data["partitions"]:
        if name == None or name == p['name']:
            first = p["first_lba"]
            last = p["last_lba"]
            total = last - first + 1
            logger.info(f"Partition {p['index']}: {p['name']}")
            logger.info(f"  First LBA : {first}")
            logger.info(f"  Last LBA  : {last}")
            logger.info(f"  Total LBAs: {total}")

def find_partition(gpt_data, name):
    for p in gpt_data["partitions"]:
        if name == p["name"]:
            first = p["first_lba"]
            last = p["last_lba"]
            p["number_lba"] = last - first + 1
            return p
    return None

def setup_logger(console):
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
    if console:
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
 
def clean_resource():
    logger.info("clean resource")
    zip_logs(log_dir)

def run_command(command, fail_expect=None , fail_expect2=None , success_expect=None, savelog=False, 
                _progress_reporter=None, port="None", parser=None, sub_desc=None):
    logger.info(f"Executing command: {command}")
    if _progress_reporter is not None and sub_desc is not None:
        _progress_reporter.update_desc(sub_desc)
    try:
        sucess_count = 0
        # Run the command with subprocess.PIPE for capturing output
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        stdout_lines = []
        for line in process.stdout:
            # Detect progress
            match = re.search(r'\b(\d+)%', line)

            if match:
                percent = match.group(1)
                logger.info(f"Detected percent: {percent}")
                if _progress_reporter is not None:
                    _progress_reporter.set(float(percent))
            if parser != None:
                parsed = parser(line)
            if fail_expect is not None and fail_expect in line :
                logger.info(f"Found the specific string in the output {fail_expect} --> EXIT !!!")
                clean_resource()
                exit(5)
            if fail_expect is not None and fail_expect2 in line :
                logger.info(f"Found the specific string in the output {fail_expect2} --> EXIT !!!")
                clean_resource()
                exit(6)
            if success_expect is not None and success_expect in line: 
                logger.info(f"Found the specific string in the output {success_expect} --> MATCH !!!")
                sucess_count = 1
            logger.info(line[:len(line)-1])
            stdout_lines.append(line)
            if savelog:
                with open(f"firehose_log_{port}.txt", "a") as log_file:
                    log_file.write(line)

        process.wait()

        if success_expect is not None and sucess_count == 0 :
            logger.info(f"Can not found string {success_expect} in the output  --> EXIT !!!")
            clean_resource()
            exit(13)

        if process.returncode != 0:
            sys.stderr.write(process.stderr.read())
            clean_resource()
            exit(1)

        if _progress_reporter is not None:
            # _progress_reporter.update(100)
            time.sleep(1)

    except subprocess.CalledProcessError as e:
        logger.info(f"Command failed with error: {e.stderr}")
        clean_resource()
        exit(1)

def parse_gpt_header(data: bytes):
    if data[0:8] != b"EFI PART":
        raise ValueError("Invalid GPT header signature")

    header = {
        "revision": struct.unpack("<I", data[8:12])[0],
        "header_size": struct.unpack("<I", data[12:16])[0],
        "current_lba": struct.unpack("<Q", data[24:32])[0],
        "backup_lba": struct.unpack("<Q", data[32:40])[0],
        "first_usable_lba": struct.unpack("<Q", data[40:48])[0],
        "last_usable_lba": struct.unpack("<Q", data[48:56])[0],
        "disk_guid": str(uuid.UUID(bytes_le=data[56:72])),
        "partition_entries_lba": struct.unpack("<Q", data[72:80])[0],
        "num_partition_entries": struct.unpack("<I", data[80:84])[0],
        "size_of_partition_entry": struct.unpack("<I", data[84:88])[0],
    }

    return header

def parse_gpt_entries(data: bytes, entry_size: int, max_entries: int = 128):
    entries = []
    for i in range(max_entries):
        offset = i * entry_size
        entry = data[offset:offset + entry_size]
        if entry[0:16] == b"\x00" * 16:
            continue  # Unused

        part = {
            "index": i,
            "type_guid": str(uuid.UUID(bytes_le=entry[0:16])),
            "unique_guid": str(uuid.UUID(bytes_le=entry[16:32])),
            "first_lba": struct.unpack("<Q", entry[32:40])[0],
            "last_lba": struct.unpack("<Q", entry[40:48])[0],
            "attributes": struct.unpack("<Q", entry[48:56])[0],
            "name": entry[56:128].decode("utf-16le").rstrip("\x00")
        }
        entries.append(part)
    return entries

def parser_gpt(header, entries, out_json):
    with open(header, "rb") as f:
        header_data = f.read(SECTOR_SIZE)

    gpt_header = parse_gpt_header(header_data)

    with open(entries, "rb") as f:
        entries_data = f.read()

    gpt_entries = parse_gpt_entries(
        entries_data,
        gpt_header["size_of_partition_entry"],
        gpt_header["num_partition_entries"]
    )

    # Save to JSON
    output = {
        "header": gpt_header,
        "partitions": gpt_entries
    }

    with open(out_json, "w", encoding="utf-8") as out:
        json.dump(output, out, indent=4)

    logger.info(f"GPT data saved to: {out_json}")

def get_com_port_description(com_port):
    com_ports = serial.tools.list_ports.comports()
    for port, desc, hwid in sorted(com_ports):
        if port == com_port:
            return desc
    return None

def list_com_ports(list_ports=None):
    ports = serial.tools.list_ports.comports()
    if ports:
        for port in ports:
            desc = get_com_port_description(port.name)
            if (list_ports == None) or ((desc != None and "Qualcomm HS-USB QDLoader 9008" in desc) and (not port.name in list_ports) and (len(list_ports) < 4)):
                return port.name
    return None

def usb_edl_detect(port_list, detected_callback=None, progress=None):
    while True:
        edl_com_port = list_com_ports(port_list)
        if edl_com_port is not None:
            logger.info(f"Detected COM port: {edl_com_port}")
            if not port_list is None:
                port_list.add(edl_com_port)
            if detected_callback != None:
                time.sleep(1)
                detected_callback(edl_com_port)
            continue
        time.sleep(0.5)

def flash_device(args, port, flash_file, position, flash_function, list_port, progress):
    if progress != None:
        progress_reporter = ProgressReporter(total=100, desc=f"Flashing {port}", progress=progress)
    else:
        progress_reporter = None
    args.port = port
    flash_function(args, progress_reporter, list_port)
    if progress_reporter != None:
        progress_reporter.close()
    print(f"[✓] {port} flashed successfully")

def on_new_device(args, port, flash_function, active_ports, progress, flash_file="./emmc"):
    if flash_function != None:
        t = threading.Thread(target=flash_device, args=(args, port, flash_file, len(active_ports) - 1, flash_function, active_ports, progress))
        t.start()

def force_exit(sig, frame):
    global g_run
    g_run=False
    zip_logs(log_dir)
    os._exit(1)

def check_file_path(file_path):
    if os.path.isfile(file_path):
        logger.debug(f"The file at {file_path} exists.")
        return True
    else:
        logger.info(f"The file at {file_path} does not exist.")
        return False

def dump_partition(serial_device, gpt, com_port, search_path, partition, progress_reporter=None):
    infor = find_partition(gpt, partition)
    fh_loader_dump_partition_command = (
        f"{PROJECT_DIR}\\fh_loader.exe --port=\\\\.\\{com_port} "
        f"--search_path={search_path} "
        f"--convertprogram2read "
        f"--sendimage=dump_{serial_device}_{partition}.bin "
        f"--start_sector={infor['first_lba']} "
        f"--lun=0 "
        f"--num_sectors={infor['number_lba']} "
        f"--noprompt "
        f"--showpercentagecomplete "
        f"--zlpawarehost=1 "
        f"--memoryname=emmc "
    )
    run_command(fh_loader_dump_partition_command, None, None, None, True, None, com_port)

def flash_partition(serial_device, gpt, com_port, search_path, partition, progress_reporter=None):
    infor = find_partition(gpt, partition)
    fh_loader_flash_partition_command = (
        f"{PROJECT_DIR}\\fh_loader.exe --port=\\\\.\\{com_port} "
        f"--search_path={search_path} "
        f"--sendimage=dump_{serial_device}_{partition}.bin "
        f"--start_sector={infor['first_lba']} "
        f"--lun=0 "
        f"--noprompt "
        f"--showpercentagecomplete "
        f"--zlpawarehost=1 "
        f"--memoryname=emmc "
    )
    run_command(fh_loader_flash_partition_command, None, None, None, True, None, com_port)

def check_infor_function(args, progress_reporter=None, active_port=None):
    start_time = time.time()
    os.chdir(PROJECT_DIR)
    fw_path = os.path.abspath(args.fw_path)
    com_port = args.port
    patch_xml = args.patch_xml
    raw_xml = args.raw_xml
    prog_firehose = os.path.join(fw_path, 'prog_firehose_ddr.elf')
    patch_xml_file = os.path.join(fw_path, patch_xml)
    raw_xml_file = os.path.join(fw_path, raw_xml)
    search_path = fw_path
    os.chdir(fw_path)
    if check_file_path(prog_firehose) and check_file_path(patch_xml_file) and check_file_path(raw_xml_file):
        result_holder = {"serial": None}
        qsahara_command = f"{PROJECT_DIR}\\QSaharaServer.exe -p \\\\.\\{com_port} -s 13:{prog_firehose}"
        fh_loader_getstorageinfo_command = (
            f"{PROJECT_DIR}\\fh_loader.exe --port=\\\\.\\{com_port} --getstorageinfo=0 --noprompt "
            f"--showpercentagecomplete --verbose --zlpawarehost=1 --memoryname=emmc"
        )
        fh_loader_getstorageinfo_command = (
            f"{PROJECT_DIR}\\fh_loader.exe --port=\\\\.\\{com_port} --search_path={search_path} --getstorageinfo=0 --noprompt "
            f"--showpercentagecomplete --verbose --zlpawarehost=1 --memoryname=emmc"
        )
        fh_loader_resetedl_command = (
            f"{PROJECT_DIR}\\fh_loader.exe --port=\\\\.\\{com_port} --search_path={PROJECT_DIR} --sendxml=ResetToEDL.xml --noprompt "
            f"--showpercentagecomplete --verbose --zlpawarehost=1 --memoryname=emmc"
        )
        fh_loader_patch_command = (
            f"{PROJECT_DIR}\\fh_loader.exe --port=\\\\.\\{com_port} --sendxml={patch_xml_file} "
            f"--search_path={search_path} --noprompt --showpercentagecomplete --verbose "
            f"--zlpawarehost=1 --memoryname=emmc"
        )
        
        fh_loader_raw_command = (
            f"{PROJECT_DIR}\\fh_loader.exe --port=\\\\.\\{com_port} --sendxml={raw_xml_file} "
            f"--search_path={search_path} --noprompt --showpercentagecomplete --verbose "
            f"--zlpawarehost=1 --memoryname=emmc"
        )
        
        fh_loader_setactivepartition_command = (
            f"{PROJECT_DIR}\\fh_loader.exe --port=\\\\.\\{com_port} --setactivepartition=0 --noprompt "
            f"--showpercentagecomplete --verbose --zlpawarehost=1 --memoryname=emmc"
        )
        fh_loader_reset_command = (
            f"{PROJECT_DIR}\\fh_loader.exe --port=\\\\.\\{com_port} --reset --noprompt --showpercentagecomplete "
            f"--verbose --zlpawarehost=1 --memoryname=emmc"
        )
        fh_loader_dump_gpt_header_command = (
            f"{PROJECT_DIR}\\fh_loader.exe --port=\\\\.\\{com_port} "
            f"--search_path={search_path} "
            f"--convertprogram2read "
            f"--sendimage=fh_gpt_header_0 "
            f"--start_sector=1 "
            f"--lun=0 "
            f"--num_sectors=1 "
            f"--noprompt "
            f"--showpercentagecomplete "
            f"--zlpawarehost=1 "
            f"--memoryname=emmc"
        )
        fh_loader_dump_gpt_entries_command = (
            f"{PROJECT_DIR}\\fh_loader.exe --port=\\\\.\\{com_port} "
            f"--search_path={search_path} "
            f"--convertprogram2read "
            f"--sendimage=fh_gpt_entries_0 "
            f"--start_sector=2 "
            f"--lun=0 "
            f"--num_sectors=32 "
            f"--noprompt "
            f"--showpercentagecomplete "
            f"--zlpawarehost=1 "
            f"--memoryname=emmc"
        )
        fh_loader_dump_gpt_entries_2_command = (
            f"{PROJECT_DIR}\\fh_loader.exe --port=\\\\.\\{com_port} "
            f"--search_path={search_path} "
            f"--convertprogram2read "
            f"--sendimage=fh_gpt_entries_0 "
            f"--start_sector=2 "
            f"--lun=0 "
            f"--noprompt "
            f"--showpercentagecomplete "
            f"--zlpawarehost=1 "
            f"--memoryname=emmc"
        )
        fh_loader_reset_command = (
            f"{PROJECT_DIR}\\fh_loader.exe --port=\\\\.\\{com_port} --reset --noprompt "
            f"--showpercentagecomplete --verbose --zlpawarehost=1 --memoryname=emmc"
        )
        find_serial = lambda line: (
            result_holder.update({"serial": re.search(r"Device Serial Number: (0x[0-9a-fA-F]+)", line).group(1)})
            if re.search(r"Device Serial Number: (0x[0-9a-fA-F]+)", line)
            else None
        )
        run_command(qsahara_command ,None, None,"File transferred successfully", True, progress_reporter, com_port, None, "[1/11] Qsahara")
        run_command(fh_loader_getstorageinfo_command, None, None, None, True, progress_reporter, com_port, find_serial, "[2/11] GetSerialno")
        serial_device = result_holder["serial"]
        logger.info(f"Founded device {serial_device}")

        run_command(fh_loader_dump_gpt_header_command, None, None, None, True, progress_reporter, com_port, None, "[3/11] GetGPTHead")
        run_command(fh_loader_dump_gpt_entries_command, None, None, None, True, progress_reporter, com_port, None, "[4/11] GetGPTEntries")
        run_command(fh_loader_dump_gpt_entries_2_command, None, None, None, True, progress_reporter, com_port, None, "[5/11] VerifyGPT")
        gpt_header = os.path.join(fw_path, GPT_HEADER_FILE)
        gpt_etries = os.path.join(fw_path, GPT_ENTRIES_FILE)
        gpt_out = os.path.join(fw_path, OUTPUT_JSON)
        parser_gpt(gpt_header, gpt_etries, gpt_out)
        gpt = load_gpt_json(gpt_out)
        if progress_reporter:
            progress_reporter.update_desc("[6/11] Backup modem")
            progress_reporter.update(0)
        dump_partition(serial_device, gpt, com_port, search_path, "modemst1")
        dump_partition(serial_device, gpt, com_port, search_path, "persist")
        dump_partition(serial_device, gpt, com_port, search_path, "fsc")
        if progress_reporter:
            progress_reporter.update(20)
        dump_partition(serial_device, gpt, com_port, search_path, "modemst2")
        if progress_reporter:
            progress_reporter.update(40)
        dump_partition(serial_device, gpt, com_port, search_path, "fsg")
        if progress_reporter:
            progress_reporter.update(60)
        dump_partition(serial_device, gpt, com_port, search_path, "modem_a")
        if progress_reporter:
            progress_reporter.update(80)
        dump_partition(serial_device, gpt, com_port, search_path, "modem_b")
        if progress_reporter:
            progress_reporter.update(100)

        run_command(fh_loader_raw_command, None, None, None, True, progress_reporter, com_port, None, "[7/11] SendRaw")
        run_command(fh_loader_patch_command ,None, None, None, True, progress_reporter, com_port, None, "[8/11] SendPatch")
        run_command(fh_loader_setactivepartition_command, None, None, None, True, progress_reporter, com_port, None, "[9/11] SetActive")
    
        run_command(fh_loader_dump_gpt_header_command, None, None, None, True, progress_reporter, com_port, None, None)
        run_command(fh_loader_dump_gpt_entries_command, None, None, None, True, progress_reporter, com_port, None, None)
        run_command(fh_loader_dump_gpt_entries_2_command, None, None, None, True, progress_reporter, com_port, None, None)
        gpt_header = os.path.join(fw_path, GPT_HEADER_FILE)
        gpt_etries = os.path.join(fw_path, GPT_ENTRIES_FILE)
        gpt_out = os.path.join(fw_path, OUTPUT2_JSON)
        parser_gpt(gpt_header, gpt_etries, gpt_out)
        gpt = load_gpt_json(gpt_out)
        if progress_reporter:
            progress_reporter.update_desc("[10/11] Restore modem")
            progress_reporter.update(0)
        flash_partition(serial_device, gpt, com_port, search_path, "modemst1")
        flash_partition(serial_device, gpt, com_port, search_path, "persist")
        flash_partition(serial_device, gpt, com_port, search_path, "fsc")
        if progress_reporter:
            progress_reporter.update(20)
        flash_partition(serial_device, gpt, com_port, search_path, "modemst2")
        if progress_reporter:
            progress_reporter.update(40)
        flash_partition(serial_device, gpt, com_port, search_path, "fsg")
        if progress_reporter:
            progress_reporter.update(60)
        flash_partition(serial_device, gpt, com_port, search_path, "modem_a")
        if progress_reporter:
            progress_reporter.update(80)
        flash_partition(serial_device, gpt, com_port, search_path, "modem_b")
        if progress_reporter:
            progress_reporter.update(100)
            progress_reporter.update_desc("[11/11] Reset")
            progress_reporter.update(0)
        run_command(fh_loader_reset_command, None, None, None, True, progress_reporter, com_port, None, None)
        if progress_reporter:
            progress_reporter.update(100)
        if active_port!=None:
            active_port.add(serial_device)

def get_connected_devices(list):
    """Returns a list of connected devices' serial numbers."""
    result = subprocess.run(["adb", "devices"], stdout=subprocess.PIPE, text=True)
    lines = result.stdout.strip().splitlines()
    devices = []

    for line in lines[1:]:  # Skip the first line
        if line.strip() and "device" in line:
            serial = line.split()[0]
            if not serial in list:
                devices.append(serial)
    return devices

def reboot_to_edl(serial):
    """Reboots a specific device into bootloader mode."""
    subprocess.run(["adb", "-s", serial, "root"], stdout=subprocess.PIPE, text=True)
    subprocess.run(["adb", "-s", serial, "wait-for-device"], stdout=subprocess.PIPE, text=True)
    subprocess.run(["adb", "-s", serial, "reboot", "edl"], stdout=subprocess.PIPE, text=True)

def force_enter_edl(ports_list):
    try:
        while True:
            devices = get_connected_devices(ports_list)
            if not devices:
                time.sleep(1)
                continue
            for serial in devices:
                reboot_to_edl(serial)
                ports_list.add(serial)
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Exiting...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=("Cavli Wireless Flashing tool \n\n"
                "Example usage:\n"
                "    python <tool> --fw_path=./emmc --patch_xml=patch0.xml --raw_xml=rawprogram_unsparse0.xml --flash\n"
                "    python <tool> --fw_path=./emmc --patch_xml=patch0.xml --raw_xml=rawprogram_unsparse0.xml --flash --skip-nhlos\n"
                ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    # Optional flags
    parser.add_argument('--flash', action='store_true', help='Enable flash operation')
    parser.add_argument('--skip-nhlos', action='store_true', help='Skip flashing NON-HLOS partition (requires --flash)')    
    # Keyword-like arguments
    parser.add_argument('--port', type=str, help='Force flash on the specified port')
    parser.add_argument('--fw_path', type=str, help='Cavli Firmware Path')
    parser.add_argument('--patch_xml', type=str, help='Patch XML name (e.g., patch0.xml)')
    parser.add_argument('--raw_xml', type=str, help='Raw XML name (e.g., rawprogram_unsparse0.xml.xml)')
    parser.add_argument('--serialno', type=str, help='Serial number')
    parser.add_argument('--verbose', action='store_true', help='Show console log')
    args = parser.parse_args()
    signal.signal(signal.SIGINT, force_exit)
    if args.verbose:
        progress =None
        setup_logger(True)
    else:
        progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn(),
            transient=False  # Keep progress display active until explicitly stopped
        )
        progress.start()
        setup_logger(False)
    ports_list = set()
    force_edl_thread = threading.Thread(target=force_enter_edl, args=(ports_list,))
    force_edl_thread.start()
    detect_thread = threading.Thread(target=usb_edl_detect, 
                args=(ports_list, 
                        lambda port: on_new_device(args, port, check_infor_function, ports_list, progress)
                        )
                    )
    detect_thread.start()
    while True:
        time.sleep(1)
