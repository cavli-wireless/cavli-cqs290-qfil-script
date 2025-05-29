# Cavli Flash Multi EDL Tool

This Python tool allows flashing firmware to devices using EDL (Emergency Download) mode.

## How It Works

- The device is forced into EDL mode using:
  ```bash
  adb reboot edl
  ```
- Once in EDL mode, the tool uses `fh_loader` and `QSahara` to perform the firmware flashing process.

## Requirements

- Windows 10 or 11  
- Python 3  
- Python packages:
  ```bash
  python3 -m pip install pyserial rich
  ```

## Usage

### Flash Full Firmware

```bash
python3 .\cavli_flash_multi_edl.py --fw_path=emmc --patch_xml=patch0.xml --raw_xml=rawprogram_unsparse0.xml --flash
```

### Flash Without Modem (Skip `nhlos`)

```bash
python3 .\cavli_flash_multi_edl.py --fw_path=emmc --patch_xml=patch0.xml --raw_xml=rawprogram_unsparse0.xml --flash --skip-nhlos
```

## Logs

- Logs are automatically saved in the `logs` folder.
- Each log file is compressed as a `.zip` archive and named with the current date and time.
- To share a log, simply send the most recent `.zip` file from the `logs` folder.
Ex: logs\logs_2025-06-04_19-18-47.zip