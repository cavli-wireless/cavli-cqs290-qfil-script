import subprocess
import serial.tools.list_ports
import json
import os
import time
import re
import time
import signal
import logging
import zipfile
import argparse
import threading
import subprocess
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from dataclasses import dataclass
from datetime import datetime

DB_FILE = "serial_com_map.json"
g_run : bool = True
logger = None
log_dir = None

import serial.tools.list_ports

import time
import serial.tools.list_ports

cwd = os.getcwd()

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
        self.sub_desc = sub_desc
        with self.lock:
            self.progress.update(self.task_id, description=f"{self.desc} {self.sub_desc}")

    def update_sub_desc(self, stt):
        with self.lock:
            self.progress.update(self.task_id, description=f"{self.desc} {self.sub_desc} {stt}")

    def set(self, n):
        with self.lock:
            self.progress.update(self.task_id, completed=n)

    def close(self):
        with self.lock:
            self.progress.remove_task(self.task_id)

def _is_qdloader_port(port_info):
    """
    Check if the port looks like a Qualcomm QDLoader port.
    You can customize this based on VID/PID or description.
    """
    desc = port_info.description.lower()
    return (
        "qdloader" in desc and
        "9008" in desc
    )

def get_qdloader_ports():
    """
    Get current list of QDLoader ports.
    """
    return [p for p in serial.tools.list_ports.comports() if _is_qdloader_port(p)]

def _is_diag_port(port_info):
    """
    Check if the port looks like a Qualcomm DIAG port.
    """
    desc = port_info.description.lower()
    return (
        "diag" in desc and
        "901D" in desc
    )

def get_diag_ports():
    """
    Get current list of QDLoader ports.
    """
    return [p for p in serial.tools.list_ports.comports() if _is_diag_port(p)]

def get_ports_from_serial(serialno):
    """
    Get current list of QDLoader ports.
    """
    return [p for p in serial.tools.list_ports.comports() if p.serial_number.lower() == serialno]

def get_new_qdloader_before():
    """
    Take a snapshot of current QDLoader ports before switching mode.
    """
    return get_qdloader_ports()

def get_new_qdloader_after(before_ports, timeout=30, poll_interval=0.5):
    """
    Wait until a new QDLoader port appears (not in before_ports).
    
    Args:
        before_ports: List of port objects (from get_new_qdloader_before()).
        timeout: Timeout in seconds.
        poll_interval: How often to check (in seconds).

    Returns:
        A list of new COM port names (e.g., ['COM5']), or empty list if timeout.
    """
    before_set = set(p.device for p in before_ports)
    logger.info("Waiting for new QDLoader port (timeout={timeout}s)...")

    start_time = time.time()
    while (time.time() - start_time) < timeout:
        current_ports = get_qdloader_ports()
        new_ports = [p.device for p in current_ports if p.device not in before_set]
        if new_ports:
            logger.info("Detected new QDLoader port(s): {new_ports}")
            return new_ports[0]
        time.sleep(poll_interval)

    logger.warning("Timeout waiting for QDLoader port.")
    return []

def wait_serialno(serialno, timeout=15, poll_interval=0.5):
    start_time = time.time()
    while (time.time() - start_time) < timeout:
        ports = get_ports_from_serial(serialno)
        if ports != []:
            return ports[0]
        time.sleep(poll_interval)

    logger.warning("[WARN] Timeout waiting for QDLoader port.")
    return []

def setup_logger(console=False):
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
    zip_logs(log_dir)


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
                if os.path.exists(file_path):
                    if file.endswith(".zip"):
                        continue
                    zipf.write(file_path, os.path.relpath(file_path, log_dir))
                    os.remove(file_path)  # Remove the original file after adding to the zip

def run_command(command, fail_expect=None , fail_expect2=None , success_expect=None, savelog=False, 
                progress_reporter=None, port="None", parser=None, timeout=180):
    logger.info(f"Executing command: {command}")
    process = None
    running = True
    def kill_process():
        nonlocal process
        nonlocal running
        running = False
        if progress_reporter is not None:
            progress_reporter.update_sub_desc("Timeout")
        process.kill()

    timer = threading.Timer(timeout, kill_process)
    timer.start()
    try:
        sucess_count = 0
        # Run the command with subprocess.PIPE for capturing output
        process = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout_lines = []
        for line in process.stdout:
            # Detect progress
            match = re.search(r'(\d+(?:\.\d+)?)\s*%', line)
            if match:
                percent = float(match.group(1))
                logger.info(f"Detected percent: {percent}")
                if progress_reporter is not None:
                    progress_reporter.set(float(percent))
            if parser != None:
                parsed = parser(line)
            if fail_expect is not None and fail_expect in line :
                logger.info(f"Found the specific string in the output {fail_expect} --> EXIT !!!")
                clean_resource()
                return 5
            if fail_expect is not None and fail_expect2 in line :
                logger.info(f"Found the specific string in the output {fail_expect2} --> EXIT !!!")
                clean_resource()
                return 6
            if success_expect is not None and success_expect in line: 
                logger.info(f"Found the specific string in the output {success_expect} --> MATCH !!!")
                progress_reporter.set(100)
                sucess_count = 1
            logger.info(line)
            stdout_lines.append(line)
            if savelog:
                with open(f"firehose_log_{port}.txt", "a") as log_file:
                    log_file.write(line)
            
            if not running:
                break

        timer.cancel()
        process.wait()

        if success_expect is not None and sucess_count == 0 :
            logger.info(f"Can not found string {success_expect} in the output  --> EXIT !!!")
            clean_resource()
            return 13

        if process.returncode != 0:
            clean_resource()
            return 1

    except subprocess.CalledProcessError as e:
        logger.info(f"Command failed with error: {e.stderr}")
        clean_resource()
        return 1
    return 0

def adb_devices():
    result = subprocess.run(["adb", "devices"], capture_output=True, text=True)
    lines = result.stdout.strip().splitlines()[1:]
    return [line.split()[0] for line in lines if "device" in line]

def adb_set_diag(serial):
    subprocess.run(["adb", "-s", serial, "root"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["adb", "-s", serial, "wait-for-device"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["adb", "-s", serial, "shell", "setprop sys.usb.config diag,adb"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["adb", "-s", serial, "wait-for-device"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def get_ports():
    return list(serial.tools.list_ports.comports())

def load_db(force):
    if not force and os.path.exists(DB_FILE):
        with open(DB_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_db(db):
    with open(DB_FILE, 'w') as f:
        json.dump(db, f, indent=4)

def find_com(serialid):
    ports = serial.tools.list_ports.comports()
    for port in ports:
        if (serialid == port.serial_number.lower()):
            logger.info(f"Find {serialid} -> {port.device}")
            return port.device
    return None

def remove_old_file(file_path):
    """Remove the old file if it exists."""
    if os.path.exists(file_path):
        os.remove(file_path)
        logger.info(f"Removed old file: {file_path}")
    else:
        logger.info(f"No old file to remove: {file_path}")

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
        label = program.get('label')
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

def check_file_path(file_path):
    if os.path.isfile(file_path):
        logger.debug(f"The file at {file_path} exists.")
        return True
    else:
        logger.info(f"The file at {file_path} does not exist.")
        return False

import threading

def flash_function(args, progress_reporter=None):
    fw_path = os.path.abspath(args.fw_path)
    processed_raw_xml_file = "processed_" + args.raw_xml
    process_xml(fw_path + "\\" +args.raw_xml, fw_path + "\\" + processed_raw_xml_file , args.skip_nhlos)
    com_port = args.port
    patch_xml = args.patch_xml
    raw_xml = processed_raw_xml_file
    prog_firehose = os.path.join(fw_path, 'prog_firehose_ddr.elf')
    patch_xml_file = os.path.join(fw_path, patch_xml)
    raw_xml_file = os.path.join(fw_path, raw_xml)
    search_path = fw_path

    if check_file_path(prog_firehose) and check_file_path(patch_xml_file) and check_file_path(raw_xml_file):
        old_ports=get_new_qdloader_before()
        subprocess.run(["adb", "-s", args.serialno, "wait-for-device"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["adb", "-s", args.serialno, "root"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["adb", "-s", args.serialno, "wait-for-device"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["adb", "-s", args.serialno, "reboot", "edl"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        com_port = get_new_qdloader_after(old_ports)
        logger.info(f"Found new port {com_port}")
        qsahara_command = f"{cwd}\\QSaharaServer.exe -p \\\\.\\{com_port} -s 13:{prog_firehose}"
        logger.info(f"qsahara_command {qsahara_command}")
        time.sleep(3)
        fh_loader_getstorageinfo_command = (
            f"{cwd}\\fh_loader.exe --port=\\\\.\\{com_port} --getstorageinfo=0 --noprompt "
            f"--showpercentagecomplete --verbose --zlpawarehost=1 --memoryname=emmc"
        )

        fh_loader_patch_command = (
            f"{cwd}\\fh_loader.exe --port=\\\\.\\{com_port} --sendxml={patch_xml_file} "
            f"--search_path={search_path} --noprompt --showpercentagecomplete --verbose "
            f"--zlpawarehost=1 --memoryname=emmc"
        )
        
        fh_loader_raw_command = (
            f"{cwd}\\fh_loader.exe --port=\\\\.\\{com_port} --sendxml={raw_xml_file} "
            f"--search_path={search_path} --noprompt --showpercentagecomplete --verbose "
            f"--zlpawarehost=1 --memoryname=emmc"
        )
        
        fh_loader_setactivepartition_command = (
            f"{cwd}\\fh_loader.exe --port=\\\\.\\{com_port} --setactivepartition=0 --noprompt "
            f"--showpercentagecomplete --verbose --zlpawarehost=1 --memoryname=emmc"
        )
        fh_loader_reset_command = (
            f"{cwd}\\fh_loader.exe --port=\\\\.\\{com_port} --reset --noprompt --showpercentagecomplete "
            f"--verbose --zlpawarehost=1 --memoryname=emmc"
        )

        run_command(qsahara_command ,None, None,"File transferred successfully", True, progress_reporter, com_port)
        run_command(fh_loader_getstorageinfo_command, None, None,"{All Finished Successfully}", True, progress_reporter, com_port)
        run_command(fh_loader_raw_command, None, None,"{All Finished Successfully}", True, progress_reporter, com_port)
        run_command(fh_loader_patch_command ,None, None,"{All Finished Successfully}", True, progress_reporter, com_port)
        run_command(fh_loader_setactivepartition_command, None, None,"{All Finished Successfully}", True, progress_reporter, com_port)
        run_command(fh_loader_reset_command, None, None,"{All Finished Successfully}", True, progress_reporter, com_port)

def process_device(db, serial_id, device_info, args, progress_reporter, db_lock):
    serialno = device_info["name"]
    comport = device_info["port"]
    xqcn_path = f"C:\\Temp\\{serialno}.xqcn"
    start_time = time.time()
    retcode=0
    # 1. Backup QCN
    if not device_info["QCN_backup"]:
        logger.debug(f"Backup QCN: serialno={serialno} comport={comport}")
        qfil_cmd = (
            f"{cwd}\\QFIL.exe -RESETPARAM -Mode=3 "
            f"-QCNPATH=\"{xqcn_path}\" "
            f"-COM={comport} -RESETAFTERDOWNLOAD=false -SPCCODE=\"000000\" -BACKUPQCN"
        )
        progress_reporter[serial_id].update_desc("[1/3] Backup XQCN")
        progress_reporter[serial_id].update(0)
        if 0 == run_command(qfil_cmd, None, None, "Finish Backup QCN", True, progress_reporter[serial_id], comport, timeout=600):
            logger.info("Done backup QCN")
            progress_reporter[serial_id].update(100)
        else:
            retcode=-1

        if os.path.exists(xqcn_path):
            with db_lock:
                db[serial_id]["QCN_backup"] = True
                db[serial_id]["xqcn"] = xqcn_path
                save_db(db)

    # 2. Flash
    if not device_info["flashed"]:
        logger.info(f"Start flash: {serialno}")
        args.serialno = serialno
        args.port = comport
        progress_reporter[serial_id].update_desc("[2/3] Flash IMG")
        progress_reporter[serial_id].update(0)
        flash_function(args=args, progress_reporter=progress_reporter[serial_id])
        progress_reporter[serial_id].update(100)
        with db_lock:
            db[serial_id]["flashed"] = True
            save_db(db)

    # 3. Restore QCN
    if not device_info["QCN_restore"]:
        logger.debug(f"Restore QCN: serialno={serialno} comport={comport}")
        qfil_cmd = (
            f"{cwd}\\QFIL.exe -RESETPARAM -Mode=3 "
            f"-QCNPATH=\"{xqcn_path}\" "
            f"-COM={comport} -RESETAFTERDOWNLOAD=false -SPCCODE=\"000000\" -RESTOREQCN"
        )
        wait_serialno(serialno, 90)
        time.sleep(3)
        progress_reporter[serial_id].update_desc("[3/3] Restore XQCN")
        progress_reporter[serial_id].update(0)
        run_command(qfil_cmd, None, None, "Finish Restore QCN", True, progress_reporter[serial_id], comport)
        progress_reporter[serial_id].update(100)

        if os.path.exists(xqcn_path):
            with db_lock:
                db[serial_id]["QCN_restore"] = True
                save_db(db)

    subprocess.run(["adb", "-s", serialno, "root"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["adb", "-s", serialno, "wait-for-device"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["adb", "-s", serialno, "reboot"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    progress_reporter.get(serial_id, None) and progress_reporter[serial_id].close()
    end_time = time.time()
    elapsed_time = end_time - start_time
    if retcode == 0:
        print(f"[✓] {serialno} flashed successfully. Time={elapsed_time:.3f}")
    elif retcode == -1:
        print(f"[X] {serialno} flashed FAILED at backupQCN. Time={elapsed_time:.3f}")
def map_serial_com(args, progress):
    db = load_db(args.force)
    progress_reporter = {}
    for d in db:
        _serialno = d
        progress_reporter[_serialno] = ProgressReporter(total=100, desc=f"{_serialno}", progress=progress)
    if True:
        threads = []
        db_lock = threading.Lock()

        serials = adb_devices()
        for serial_id in serials:
            if serial_id in db:
                continue
            adb_set_diag(serial_id)
            new_com = find_com(serial_id)
            if new_com:
                db[serial_id] = {
                    "name": serial_id,
                    "port": new_com,
                    "xqcn": None,
                    "flashed": False,
                    "QCN_backup": False,
                    "QCN_restore": False
                }
                save_db(db)
                print(f"Mapped {serial_id} -> {new_com}")
                progress_reporter[serial_id] = ProgressReporter(total=100, desc=f"{serial_id}", progress=progress)
            else:
                logger.error(f"Could not find COM port for {serial_id}")

        for serial_id in db:
            t = threading.Thread(
                target=process_device,
                args=(db, serial_id, db[serial_id], args, progress_reporter, db_lock)
            )
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

def force_exit(sig, frame):
    global g_run
    g_run=False
    zip_logs(log_dir)
    os._exit(1)

def main():
    parser = argparse.ArgumentParser(
                description=("Cavli Wireless Flashing tool \n\n"
                     "Example usage:\n"
                     "    python <tool> --fw_path=emmc --patch_xml=patch0.xml --raw_xml=rawprogram_unsparse0.xml --flash\n"
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
    parser.add_argument('--force', action='store_true', help='Force flash')

    args = parser.parse_args()
    if args.verbose:
        progress =None
        setup_logger(True)
    else:
        progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>0.01f}%",
            TimeRemainingColumn(),
            transient=False
        )
        progress.start()
        setup_logger(False)

    signal.signal(signal.SIGINT, force_exit)
    threading.Thread(target=map_serial_com, args=(args,progress)).start()
    while g_run:
        time.sleep(3)

if __name__ == "__main__":
    main()
