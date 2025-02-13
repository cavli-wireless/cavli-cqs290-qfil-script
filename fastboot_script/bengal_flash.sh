#!/bin/bash

PARTITION_LIST="boot dtbo metadata persist recovery super userdata vbmeta vbmeta_system"

# Check if fastboot is installed
function check_fastboot() {
  if [ -z "$(which fastboot)" ]; then
    echo "Fastboot is not installed!"
    exit 1
  else
    return 0
  fi
}

# Check if adb is installed
function check_adb() {
  if [ -z "$(which adb)" ]; then
    echo "ADB is not installed!"
    exit 1
  else
    return 0
  fi
}

# Check if device is connected
function check_device() {
  if [ -z "$(fastboot devices)" ]; then
    echo "No Fastboot device found!"
  else
    echo "Fastboot Device found!"
    return 0
  fi

  if [ -z "$(adb devices)" ]; then
    echo "No ADB device found!"
    exit 1
  else
    echo "ADB Device found!"
    adb reboot bootloader
    fastboot devices
    return 0
  fi
}

function do_flash() {
  echo "Flashing images..."
  if [ -f abl_ecc.elf ]; then
    fastboot flash abl abl_ecc.elf
  else
    echo "abl_ecc.elf not found!"
  fi

  for partition in $PARTITION_LIST; do
    if [ -f $partition.img ]; then
      fastboot flash $partition $partition.img
    else
      echo "$partition.img not found!"
    fi
  done
  # fastboot erase misc
  fastboot reboot
}

function _main() {
  check_fastboot
  check_adb
  check_device
  do_flash
}

_main
