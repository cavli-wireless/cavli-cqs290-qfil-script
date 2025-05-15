import os
import re
import sys
import time
import signal
import hashlib
import logging
import shutil
import zipfile
import argparse
import threading
import subprocess
import serial.tools.list_ports
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from dataclasses import dataclass

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
    # logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    logger.info(f"Logging initialized. Log file: {log_file}")
    
def close_logger():
    """Closes all handlers of the logger."""
    global logger
    handlers = logger.handlers[:]
    for handler in handlers:
        handler.close()
        logger.removeHandler(handler)
        
def read_short_content(file_path, num_lines=4):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            logger.info("\nShort content of the file:")
            for line in lines[:num_lines]:
                logger.info(line.strip())
    except FileNotFoundError:
        logger.info(f"Error: File not found: {file_path}")
        clean_resource()
        exit()

def parse_nand_layout_file(file_path):
    partitions = []
    start_parsing = False
    pattern = re.compile(r'0x([0-9a-f]+)-0x([0-9a-f]+) : "(\w+)"')
    
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if "Creating" in line and "MTD partitions" in line:
                    start_parsing = True
                    continue
                
                if start_parsing:
                    matches = pattern.finditer(line)
                    for match in matches:
                        start_addr = int(match.group(1), 16)
                        end_addr = int(match.group(2), 16)
                        name = match.group(3)
                        size = end_addr - start_addr
                        partitions.append((start_addr, size, name))
    except FileNotFoundError:
        logger.info(f"Error: File not found: {file_path}")
        clean_resource()
        exit()
    
    return partitions

def parse_xml_content(xml_file_path):
    partitions = []
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
        for program in root.findall('program'):
            start_sector = int(program.get('start_sector'))
            num_sectors = int(program.get('num_partition_sectors'))
            size = num_sectors * int(program.get('SECTOR_SIZE_IN_BYTES'))
            partitions.append((start_sector * int(program.get('SECTOR_SIZE_IN_BYTES')), size))
    except ET.ParseError as e:
        logger.info(f"Error: Error parsing XML file: {e}")
        clean_resource()
        exit()
    except FileNotFoundError:
        logger.info(f"Error: XML file not found: {xml_file_path}")
        clean_resource()
        exit()
    return partitions

def print_nand_layout(nand_layout):
    logger.info("\nNAND Layout:")
    for start_addr, size, name in nand_layout:
        logger.info(f"  Name: {name}")
        logger.info(f"  Start Address: {start_addr}")
        logger.info(f"  Size: {size}")

def compare_layouts(nand_layout, xml_content):
    # Sets of critical partitions that should not differ
    critical_partitions = {"sbl", "efs2",   "modem", "misc"}
    critical_differences = []
    non_critical_differences = []

    max_length = max(len(nand_layout), len(xml_content))
    for i in range(max_length):
        if i >= len(nand_layout):
            logger.info(f"\nExtra entry in XML content:")
            logger.info(f"  XML Start Address: {xml_content[i][0]}")
            logger.info(f"  XML Size: {xml_content[i][1]}")
            continue
        if i >= len(xml_content):
            logger.info(f"\nExtra entry in NAND layout:")
            logger.info(f"  NAND Start Address: {nand_layout[i][0]}")
            logger.info(f"  NAND Size: {nand_layout[i][1]}")
            logger.info(f"  NAND Name: {nand_layout[i][2]}")
            continue
        
        nand_start, nand_size, nand_name = nand_layout[i]
        xml_start, xml_size = xml_content[i]
        
        if nand_start == xml_start and nand_size == xml_size:
            # if nand_name in critical_partitions:
            logger.info(f"\nName: {nand_name} --> Match:")
            logger.info(f"  NAND layout: Start Address: {nand_start}, Size: {nand_size}")
            logger.info(f"  XML content: Start Address: {xml_start}, Size: {xml_size}")
        else:
            if nand_name in critical_partitions:
                critical_differences.append(nand_name)
                logger.info(f"\nName: {nand_name} --> Difference:")
                logger.info(f"  NAND layout: Start Address: {nand_start}, Size: {nand_size}")
                logger.info(f"  XML content: Start Address: {xml_start}, Size: {xml_size}")
            else:
                non_critical_differences.append(nand_name)
                logger.info(f"\nName: {nand_name} --> Warning:")
                logger.info(f"  NAND layout: Start Address: {nand_start}, Size: {nand_size}")
                logger.info(f"  XML content: Start Address: {xml_start}, Size: {xml_size}")
                logger.info("  Warning: Data may be lost for non-critical partitions.")

    if critical_differences:
        logger.info("Error: Critical partitions differ. Not allowed.")
        logger.info("Error: Critical partitions with differences:")
        for name in critical_differences:
            logger.info(f"  - {name}")
        clean_resource()
        exit()
    else:
        logger.info("\nAll are fine.")
    
    if non_critical_differences:
        logger.info("\nWarnings for non-critical partitions with differences:")
        for name in non_critical_differences:
            logger.info(f"  - {name}")
       
def remove_old_file(file_path):
    """Remove the old file if it exists."""
    if os.path.exists(file_path):
        os.remove(file_path)
        logger.info(f"Removed old file: {file_path}")
    else:
        logger.info(f"No old file to remove: {file_path}")
        
def pull_nand_layout_file():
   
    # Pull the file from the device
    try:
        logger.info("Waiting for ADB ready")
        subprocess.check_call(["adb", "wait-for-device"])
        # Run adb shell command to dump dmesg
        subprocess.check_call(["adb", "shell", "dmesg", ">", "/tmp/dmsg.txt"])
        # Pull the file from the device
        subprocess.check_call(["adb", "pull", "/tmp/dmsg.txt", "dmsg.txt"])
        logger.info("NAND layout file pulled successfully.")
    except subprocess.CalledProcessError:
        logger.info("Failed to pull NAND layout file from device.")
        clean_resource()
        exit(1)
        
def check_the_layout_is_safe(xml_file_path):
    nand_layout_file_path = "dmsg.txt"   # Path after pulling from the device
    remove_old_file(nand_layout_file_path)
    # Pull the NAND layout file
    pull_nand_layout_file()

    # Print short content of NAND layout file
    read_short_content(nand_layout_file_path)

    # Parse NAND layout and XML content
    nand_layout = parse_nand_layout_file(nand_layout_file_path)
    xml_partitions = parse_xml_content(xml_file_path)

    # Print NAND layout
    print_nand_layout(nand_layout)

    # Compare NAND layout and XML content
    logger.info("Comparing NAND layout and XML content:")
    result = compare_layouts(nand_layout, xml_partitions)

    # Exit with appropriate status
    return 0 if result else 1

def check_file_path(file_path):
    if os.path.isfile(file_path):
        logger.debug(f"The file at {file_path} exists.")
        return True
    else:
        logger.info(f"The file at {file_path} does not exist.")
        return False

def run_command(command, fail_expect=None , fail_expect2=None , success_expect=None, savelog=False, progress_reporter=None, port="None"):
    logger.info(f"Executing command: {command}")
    
    try:
        sucess_count = 0
        # Run the command with subprocess.PIPE for capturing output
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        stdout_lines = []
        for line in process.stdout:
            match = re.search(r'{percent files transferred\s+([\d.]+)%\}', line)
            if match:
                percent = match.group(1)
                logger.info(f"Detected percent: {percent}")
                if progress_reporter is not None:
                    progress_reporter.set(float(percent))
            if fail_expect is not None and fail_expect in line :
                logger.info(f"Found the specific string in the output {fail_expect} --> EXIT !!!")
                clean_resource()
                exit(5)
            if fail_expect is not None and fail_expect2 in line :
                logger.info(f"Found the specific string in the output {fail_expect2} --> EXIT !!!")
                clean_resource()
                exit(6)
            if success_expect  is not None and success_expect in line: 
                logger.debug(f"Found the specific string in the output {success_expect} --> MATCH !!!")
                sucess_count = 1 
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

    except subprocess.CalledProcessError as e:
        logger.info(f"Command failed with error: {e.stderr}")
        clean_resource()
        exit(1)

def list_com_ports(list_ports=None):
    ports = serial.tools.list_ports.comports()
    if ports:
        for port in ports:
            desc = get_com_port_description(port.name)
            if (list_ports == None) or ((desc != None and "Qualcomm HS-USB QDLoader 9008" in desc) and (not port.name in list_ports) and (len(list_ports) < 4)):
                return port.name
    return None

def get_com_port_description(com_port):
    com_ports = serial.tools.list_ports.comports()
    for port, desc, hwid in sorted(com_ports):
        if port == com_port:
            return desc
    return None

def find_com_ports():
    ports = serial.tools.list_ports.comports()
    activeport = ""
    if ports:
        logger.info("Available COM ports:")
        for port in ports:
            logger.info(f"Name: {port.name}, Number: {port.device}")
            desc = get_com_port_description(port.name)
            if "Qualcomm HS-USB Diagnostics 9025" in desc:
                logger.info(f"Choice Name: {port.name}, Number: {port.device}")
                activeport = port.name
                match = re.search(r'\d+', activeport)
                if match:
                    return match.group()
                return activeport
            
    else:
        logger.info("No COM ports found.")

def run_adb_command(command):
    # Run a command in the shell and capture its output
    logger.info(f"Executing command: {command}")
    try:
        # Execute the command in the shell
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        # Split the output by lines
        output_lines = result.stdout.strip().split('\n')
        # Ignore the first line
        device_lines = output_lines[1:]
        # Extract device IDs
        devices = [line.split()[0] for line in device_lines]
        return devices
    except subprocess.CalledProcessError as e:
        # Print an error message if the command fails
        logger.info(f"Command failed with error: {e.stderr}")
        clean_resource()
        exit(1)  # Exit script if command fails

def process_xml(input_file, output_file, skip_nonhlos):
    # remove_old_file(output_file)
    if os.path.exists(output_file):
        with open(output_file, 'r') as file:
            existing_content = file.read()
    else:
        existing_content = None
    # Read the XML content from the input file
    with open(input_file, 'r') as file:
        xml_content = file.read()

    # Print the content of the input file
    logger.debug("Input XML Content:")
    logger.debug(xml_content)
    logger.debug("-" * 50)

    # Parse the XML content
    root = ET.fromstring(xml_content)

    # List to keep track of elements to be inserted
    elements_to_insert = []

    # Iterate over the program elements
    for program in root.findall('program'):
        filename = program.get('filename')
        if filename:
            if filename == "NON-HLOS.bin" and skip_nonhlos == True :
                # Set filename to empty and skip insertion of <erase> tag
                program.set('filename', '')
            else:
                # Create a new 'erase' element with the same attributes, excluding 'filename'
                erase_element = ET.Element('erase', {k: v for k, v in program.attrib.items() if k != 'filename'})
                # Keep track of the element to insert later
                elements_to_insert.append((program, erase_element))

    # Insert the new elements in reverse order to avoid affecting indices
    for program, erase_element in reversed(elements_to_insert):
        index = list(root).index(program) + 1
        root.insert(index, erase_element)

    # Convert the modified XML back to a string
    rough_string = ET.tostring(root, encoding='unicode', method='xml')

    # Prettify the XML output
    reparsed = minidom.parseString(rough_string)
    pretty_xml_content = reparsed.toprettyxml(indent="  ")

    # Remove extra blank lines added by topprettyxml
    pretty_xml_content = "\n".join([line for line in pretty_xml_content.splitlines() if line.strip()])

    # Print the content of the output XML (before writing it to a file)
    logger.debug("Output XML Content:")
    logger.debug(pretty_xml_content)
    logger.debug("-" * 50)

    # Only write if content differs
    if pretty_xml_content != existing_content:
        remove_old_file(output_file)
        with open(output_file, 'w') as file:
            file.write(pretty_xml_content)
        logger.info(f"Modified XML has been written to {output_file}")
    else:
        logger.info("No changes detected, output file not overwritten.!!!")

def safe_int(s, n):
    try:
        return int(s,n)
    except:
        return -1

def check_is_belong_critical(start, stop):
    critical_list = [
        (10504448 ,11241728),
        (12845056 ,12853248),
        (12976128 ,12980224),
    ]
    for begin,end in critical_list:
        if (start>=begin and start<end) or (stop>begin and stop<=end):
            return True
    return False

def check_safe_xml(input_file):
    # Read the XML content from the input file
    i=0
    with open(input_file, 'r') as file:
        xml_content = file.read()

    # Parse the XML content
    root = ET.fromstring(xml_content)

    # Iterate over the program elements
    for program in root.findall('program'):
        start_sector = safe_int(program.get('start_sector'), 10)
        num_partition_sectors = safe_int(program.get('num_partition_sectors'), 10)
        end_sector = start_sector + num_partition_sectors
        if check_is_belong_critical(start_sector, end_sector):
            logger.error("ERROR partition %s is un-safe" % program.get('label'))
            i=i+1
    return i

def str_to_bool(value):
    if isinstance(value, bool):
        return value
    if value.lower() in {'false', '0', 'no', 'n', 'off'}:
        return False
    elif value.lower() in {'true', '1', 'yes', 'y', 'on'}:
        return True
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

def calculate_md5(file_path):
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as file:
        # Read and update hash in chunks to avoid memory issues with large files
        for byte_block in iter(lambda: file.read(4096), b""):
            md5_hash.update(byte_block)
    return md5_hash.hexdigest()

def move_port_trace(log_dir, port):
    """Moves the port_trace.txt file to the logs directory and renames it with a timestamp."""
    source_file = f"firehose_log_{port}.txt"
    if os.path.exists(source_file):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        destination_file = os.path.join(log_dir, f"cavli_flash_firehose_log_{port}_{timestamp}.txt")
        shutil.move(source_file, destination_file)
        logger.info(f"Moved {source_file} to {destination_file}")
    else:
        logger.warning(f"{source_file} not found. Skipping move operation.")

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

def clean_resource():
    zip_logs(log_dir)

def confirm_before_continue():
    while True:
        user_input = input("Do you want to continue? (y/n): ").strip().lower()
        if user_input in ('y', 'yes'):
            return True
        elif user_input in ('n', 'no'):
            return False
        else:
            print("Invalid input. Please enter n or y")

def flash_function(args, progress_reporter):
    start_time = time.time()
    fw_path = os.path.abspath(args.fw_path)
    unsafe_partitiion = check_safe_xml(fw_path + "\\" +args.raw_xml)
    unsafe_partitiion += check_safe_xml(fw_path + "\\" +args.patch_xml)
    if unsafe_partitiion > 0:
        logger.error("Found %i partitions are unsafe. DO YOU WANT TO FLASH ?" % unsafe_partitiion) 
        if not confirm_before_continue():
            exit(1)
    processed_raw_xml_file = "processed_" + args.raw_xml    
    process_xml(fw_path + "\\" +args.raw_xml, fw_path + "\\" +processed_raw_xml_file , args.skip_nhlos)            
    com_port = args.port
    patch_xml = args.patch_xml
    raw_xml = processed_raw_xml_file
    prog_firehose = os.path.join(fw_path, 'prog_firehose_ddr.elf')
    patch_xml_file = os.path.join(fw_path, patch_xml)
    raw_xml_file = os.path.join(fw_path, raw_xml)
    search_path = fw_path
    if check_file_path(prog_firehose) and check_file_path(patch_xml_file) and check_file_path(raw_xml_file):
        qsahara_command = f"QSaharaServer.exe -p \\\\.\\{com_port} -s 13:{prog_firehose}"
        fh_loader_getstorageinfo_command = (
            f"fh_loader.exe --port=\\\\.\\{com_port} --getstorageinfo=0 --noprompt "
            f"--showpercentagecomplete --verbose --zlpawarehost=1 --memoryname=emmc"
        )

        fh_loader_patch_command = (
            f"fh_loader.exe --port=\\\\.\\{com_port} --sendxml={patch_xml_file} "
            f"--search_path={search_path} --noprompt --showpercentagecomplete --verbose "
            f"--zlpawarehost=1 --memoryname=emmc"
        )
        
        fh_loader_raw_command = (
            f"fh_loader.exe --port=\\\\.\\{com_port} --sendxml={raw_xml_file} "
            f"--search_path={search_path} --noprompt --showpercentagecomplete --verbose "
            f"--zlpawarehost=1 --memoryname=emmc"
        )
        
        fh_loader_setactivepartition_command = (
            f"fh_loader.exe --port=\\\\.\\{com_port} --setactivepartition=0 --noprompt "
            f"--showpercentagecomplete --verbose --zlpawarehost=1 --memoryname=emmc"
        )
        fh_loader_reset_command = (
            f"fh_loader.exe --port=\\\\.\\{com_port} --reset --noprompt --showpercentagecomplete "
            f"--verbose --zlpawarehost=1 --memoryname=emmc"
        )

        run_command(qsahara_command ,None, None,"File transferred successfully", True, progress_reporter, com_port)
        run_command(fh_loader_getstorageinfo_command, None, None,"{All Finished Successfully}", True, progress_reporter, com_port)
        run_command(fh_loader_raw_command, None, None,"{All Finished Successfully}", True, progress_reporter, com_port)
        run_command(fh_loader_patch_command ,None, None,"{All Finished Successfully}", True, progress_reporter, com_port)
        run_command(fh_loader_setactivepartition_command, None, None,"{All Finished Successfully}", True, progress_reporter, com_port)
        run_command(fh_loader_reset_command, None, None,"{All Finished Successfully}", True, progress_reporter, com_port)

        end_time = time.time()
        elapsed_time = end_time - start_time
    move_port_trace(log_dir, com_port)

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
    subprocess.run(["adb", "-s", serial, "reboot", "edl"])

def force_enter_edl():
    try:
        list = []
        while True:
            devices = get_connected_devices(list)
            if not devices:
                time.sleep(1)
                continue
            for serial in devices:
                reboot_to_edl(serial)
                list.append(serial)
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Exiting...")

class ProgressReporter:
    def __init__(self, total, desc, progress):
        self.progress = progress
        self.task_id = self.progress.add_task(desc, total=total)
        self.lock = threading.Lock()

    def update(self, n=1):
        with self.lock:
            self.progress.update(self.task_id, advance=n)

    def set(self, n):
        with self.lock:
            self.progress.update(self.task_id, completed=n)

    def close(self):
        with self.lock:
            self.progress.remove_task(self.task_id)

@dataclass
class FlashArgs:
    fw_path: str = "emmc"
    patch_xml: str = "patch0.xml"
    raw_xml: str = "rawprogram_unsparse0.xml"
    flash: bool = True
    skip_nhlos: bool = True
    port: str = None

def usb_edl_detect(port_list, detected_callback=None, progress=None):
    while True:
        edl_com_port = list_com_ports(port_list)
        if edl_com_port is not None:
            logger.info(f"Detected COM port: {edl_com_port}")
            if not port_list is None:
                port_list.add(edl_com_port)
            if detected_callback != None:
                detected_callback(edl_com_port)
            continue
        time.sleep(0.5)

def force_exit(sig, frame):
    print("Force exit on Ctrl+C")
    zip_logs(log_dir)
    os._exit(1)

def flash_device(args, port, flash_file, position, flash_function, list_port, progress):
    progress_reporter = ProgressReporter(total=100, desc=f"Flashing {port}", progress=progress)
    args.port = port
    flash_function(args, progress_reporter)
    progress_reporter.close()
    print(f"[✓] {port} flashed successfully")

def on_new_device(args, port, flash_function, active_ports, progress, flash_file="./emmc"):
    t = threading.Thread(target=flash_device, args=(args, port, flash_file, len(active_ports) - 1, flash_function, active_ports, progress))
    t.start()

def main():
    setup_logger()

    parser = argparse.ArgumentParser(
               description=("Cavli Wireless Flashing tool \n\n"
                     "Example usage:\n"
                     "    python cavli_flash_multi_edl.py --fw_path=/path/to/firmware --patch_xml=patch0.xml --raw_xml=rawprogram_unsparse0.xml --flash\n"
                     "    python cavli_flash_multi_edl.py --fw_path=/path/to/firmware --patch_xml=patch0.xml --raw_xml=rawprogram_unsparse0.xml --flash --skip-nhlos\n"
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

    args = parser.parse_args()

    stop_event = threading.Event()
    signal.signal(signal.SIGINT, force_exit)
    force_edl_thread = threading.Thread(target=force_enter_edl, daemon=True)
    force_edl_thread.start()

    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn(),
        transient=False  # Keep progress display active until explicitly stopped
    )
    progress.start()

    ports_list = set()
    detect_thread = threading.Thread(target=usb_edl_detect, 
                args=(ports_list, lambda port: on_new_device(args, port, flash_function, ports_list, progress)))
    detect_thread.start()

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()