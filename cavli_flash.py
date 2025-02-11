import os
import argparse
import subprocess
import serial.tools.list_ports
import time
import re
import xml.etree.ElementTree as ET
from xml.dom import minidom
import sys
import hashlib
import logging
import shutil  # For moving files
import zipfile  # For zipping files
from datetime import datetime

# Global logger instance
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
        logger.info(f"The file at {file_path} exists.")
        return True
    else:
        logger.info(f"The file at {file_path} does not exist.")
        return False

def run_command(command, fail_expect=None , fail_expect2=None , success_expect=None):
    logger.info(f"Executing command: {command}")
    
    try:
        sucess_count = 0
        # Run the command with subprocess.PIPE for capturing output
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Capture output line by line while printing to the terminal
        for line in process.stdout:
            sys.stdout.write(line)  # Print each line to the terminal in real-time
            # You can also inspect the line here for specific content
            if fail_expect is not None and fail_expect in line :            
                logger.info(f"Found the specific string in the output {fail_expect} --> EXIT !!!")
                clean_resource()
                exit(5)
            if fail_expect is not None and fail_expect2 in line :            
                logger.info(f"Found the specific string in the output {fail_expect2} --> EXIT !!!")
                clean_resource()
                exit(6)
            if success_expect  is not None and success_expect in line: 
                logger.info(f"Found the specific string in the output {success_expect} --> MATCH !!!")
                sucess_count = 1 
        if success_expect is not None and sucess_count == 0 :
            logger.info(f"Can not found string {success_expect} in the output  --> EXIT !!!")
            clean_resource()
            exit(13)
        # Wait for the process to complete and get the final return code
        process.wait()
        
        if process.returncode != 0:
            # If the process failed, logger.info the error
            sys.stderr.write(process.stderr.read())
            clean_resource()
            exit(1)  # Exit script if command fails
            
    except subprocess.CalledProcessError as e:
        logger.info(f"Command failed with error: {e.stderr}")
        clean_resource()
        exit(1)  # Exit script if command fails

def list_com_ports():
    ports = serial.tools.list_ports.comports()
    activeport = ""
    if ports:
        logger.info("Available COM ports:")
        for port in ports:
            logger.info(f"Name: {port.name}, Number: {port.device}")
            desc = get_com_port_description(port.name)
            if "Qualcomm HS-USB QDLoader 9008" in desc:
                logger.info(f"Choice Name: {port.name}, Number: {port.device}")
                activeport = port.name
                return activeport
            
    else:
        logger.info("No COM ports found.")
    logger.info("No COM ports found.")
    # exit(3)
        
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
    logger.info("Input XML Content:")
    logger.info(xml_content)
    logger.info("-" * 50)

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
    logger.info("Output XML Content:")
    logger.info(pretty_xml_content)
    logger.info("-" * 50)

# Only write if content differs
    if pretty_xml_content != existing_content:
        remove_old_file(output_file)
        with open(output_file, 'w') as file:
            file.write(pretty_xml_content)
        logger.info(f"Modified XML has been written to {output_file}")
    else:
        logger.info("No changes detected, output file not overwritten.!!!")    

def str_to_bool(value):
    if isinstance(value, bool):
        return value
    if value.lower() in {'false', '0', 'no', 'n', 'off'}:
        return False
    elif value.lower() in {'true', '1', 'yes', 'y', 'on'}:
        return True
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

# Function to calculate the MD5 checksum
def calculate_md5(file_path):
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as file:
        # Read and update hash in chunks to avoid memory issues with large files
        for byte_block in iter(lambda: file.read(4096), b""):
            md5_hash.update(byte_block)
    return md5_hash.hexdigest()

def move_port_trace(log_dir):
    """Moves the port_trace.txt file to the logs directory and renames it with a timestamp."""
    source_file = "firehose_log.txt"
    if os.path.exists(source_file):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        destination_file = os.path.join(log_dir, f"cavli_flash_firehose_log_{timestamp}.txt")
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
    move_port_trace(log_dir)
    zip_logs(log_dir)
            
def main():
    setup_logger()
    start_time = time.time()  # Record the start time
    # Set up the argument parser with example usage in the description e
    parser = argparse.ArgumentParser(
               description=("Cavli Wireless Flashing tool \n\n"
                     "Example usage:\n"
                     "    python cavli_flash.py --fw_path=/path/to/firmware --patch_xml=patch0.xml --raw_xml=rawprogram_unsparse0.xml --flash\n"
                     "    python cavli_flash.py --fw_path=/path/to/firmware --patch_xml=patch0.xml --raw_xml=rawprogram_unsparse0.xml --flash --skip-nhlos\n"                     
                     ),
               formatter_class=argparse.RawTextHelpFormatter
    )
    # Optional flags
    parser.add_argument('--flash', action='store_true', help='Enable flash operation')
    parser.add_argument('--skip-nhlos', action='store_true', help='Skip flashing NON-HLOS partition (requires --flash)')    

    # Keyword-like arguments
    parser.add_argument('--fw_path', type=str, help='Cavli Firmware Path')
    parser.add_argument('--patch_xml', type=str, help='Patch XML name (e.g., patch0.xml)')
    parser.add_argument('--raw_xml', type=str, help='Raw XML name (e.g., rawprogram_unsparse0.xml.xml)')
    
    
    args = parser.parse_args()

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
        # Process the raw XML file
    processed_raw_xml_file = "processed_" + args.raw_xml    
    process_xml(fw_path + "\\" +args.raw_xml, fw_path + "\\" +processed_raw_xml_file , args.skip_nhlos)            
    
    logger.info(f"Checking if device already in EDL mode...") 
    edl_com_port = list_com_ports()
    edl_com_port_desc = get_com_port_description(edl_com_port)
    if edl_com_port_desc is not None:
        logger.info(f"Device is already in EDL mode... flashing ")   
        com_port = edl_com_port
    else:             
        logger.info(f"Waiting for device connecting !!!")    
        run_command("adb wait-for-device")
        adb_devices_output = run_adb_command("adb devices")
        logger.info(f"ADB device list is {len(adb_devices_output)} !!! ")    
        if len(adb_devices_output) != 1 :
            logger.error(f"No device found in ADB yet!!! ")
            clean_resource()
            exit(5)
        # TODO: Verify the EMMC layout safe when overwrite         
        # logger.info(f"Verify the memory layout and the new layout in {args.fw_path} ...")    
        # check_the_layout_is_safe(fw_path + "\\" +args.raw_xml)            
        logger.info(f"Flashing Binary at {args.fw_path}, put device into EDL mode ... ")
        run_command("adb wait-for-device && adb reboot edl")
        logger.info(f"Waiting for Windows detect EDL USB ")                    
        counter = 10
        while counter > 0:
            logger.info(f"Getting COM PORT description")
            com_port = list_com_ports()
            com_port_desc = get_com_port_description(com_port)

            if com_port_desc is None:
                logger.info(f"Cannot find any COM PORT in EDL mode")
            else:
                logger.info(f"COM PORT is {com_port}: {com_port_desc} !!!")
                if "Qualcomm HS-USB QDLoader 9008" in com_port_desc:
                    logger.info(f"Description of {com_port}: {com_port_desc}")
                    break
                else:
                    logger.info(f"This COM port is not in EDL mode")

            time.sleep(1)
            counter -= 1  # Decrement the counter after each attempt

        if counter == 0:
            logger.info("Cannot find any COM PORT in EDL mode")
            clean_resource()
            exit(2)
                    
        # Sleep 3 second for stable.    
        logger.info("Wait 3 seconds wait for EDL mode stable")
        time.sleep(3)
    
    patch_xml = args.patch_xml  # Get patch file name
    raw_xml = processed_raw_xml_file  # Use the processed raw XML file
    
    # current_dir = os.getcwd()        
    
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
    
if __name__ == "__main__":    
    main()
