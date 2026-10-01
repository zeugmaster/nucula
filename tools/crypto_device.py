#!/usr/bin/env python3
"""Run bounded synthetic crypto diagnostics on the connected Nucula C3.

Application flashes preserve the partition table and wallet NVS. Raw flash
backups may contain wallet secrets: keep them outside the repository, private.
"""
import argparse
import os
import re
from pathlib import Path
import subprocess
import sys
import time

import serial
from serial.tools import list_ports


def esptool(args, command):
    run = [args.idf_python, "-m", "esptool", "--chip", "esp32c3", "--port", args.port,
           "--baud", "921600"] + command
    result = subprocess.run(run, text=True, capture_output=True, timeout=180)
    output = re.sub(r"\d+ \(\d+ %\)(?:\x08)+", "", result.stdout)
    print(output[-1800:], end="", flush=True)
    if result.returncode:
        print(result.stderr, file=sys.stderr)
        raise RuntimeError("esptool failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default="/dev/cu.usbmodem101")
    parser.add_argument("--serial-number", default="1C:DB:D4:ED:2A:C8")
    parser.add_argument("--idf-python", default=str(Path.home()/".espressif/python_env/idf5.5_py3.10_env/bin/python"))
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--flash", type=Path)
    parser.add_argument("--bootloader", type=Path, help="Optional measured flash-mode experiment; leaves partition table and NVS intact")
    parser.add_argument("--log", type=Path)
    parser.add_argument("--command", action="append", default=[])
    parser.add_argument("--timeout", type=float, default=240)
    args = parser.parse_args()
    port = next((p for p in list_ports.comports() if p.device == args.port), None)
    if not port or port.serial_number.upper() != args.serial_number.upper():
        raise SystemExit("Device identity mismatch; refusing to use another board")
    for command in args.command:
        if command.split()[0] not in {"help", "log", "heap", "tasks", "bench", "selftest"}:
            raise SystemExit("Only synthetic diagnostics are accepted")
    if args.backup:
        if args.backup.exists():
            raise SystemExit("Backup exists; refusing to replace it")
        args.backup.parent.mkdir(parents=True, exist_ok=True)
        old = os.umask(0o077)
        try:
            esptool(args, ["read_flash", "0", "0x400000", str(args.backup)])
        finally:
            os.umask(old)
    if args.bootloader and not args.flash:
        raise SystemExit("A bootloader experiment requires its matching application")
    if args.flash:
        if not 0 < args.flash.stat().st_size <= 0x1D0000:
            raise SystemExit("Application exceeds the existing factory partition")
        images = []
        if args.bootloader:
            if not 0 < args.bootloader.stat().st_size <= 0x8000:
                raise SystemExit("Bootloader overlaps the existing partition table")
            images = ["0", str(args.bootloader)]
        esptool(args, ["write_flash", "--flash_mode", "keep", "--flash_freq", "keep",
                       "--flash_size", "keep"] + images + ["0x30000", str(args.flash)])
    if not args.command:
        return
    if not args.log:
        raise SystemExit("--log is required for diagnostic commands")
    args.log.parent.mkdir(parents=True, exist_ok=True)
    with args.log.open("w") as log:
        s = serial.Serial(port=None, baudrate=115200, timeout=0.15, write_timeout=2)
        s.dtr = False
        s.rts = False
        s.port = args.port
        s.open()

        def collect(seconds, until_prompt=False):
            data = bytearray()
            end = time.monotonic() + seconds
            while time.monotonic() < end:
                part = s.read(4096)
                if part:
                    data.extend(part)
                    log.write(part.decode(errors="replace"))
                    log.flush()
                    if until_prompt and b"nucula> " in data:
                        return bytes(data)
            if until_prompt:
                raise TimeoutError("Nucula prompt not received")
            return bytes(data)

        try:
            collect(5)
            s.write(b"\x03")
            collect(15, True)
            for command in args.command:
                marker = f"\nRESEARCH_COMMAND {command}\n"
                log.write(marker)
                print(marker.strip(), flush=True)
                s.write(command.encode()+b"\r")
                data = collect(args.timeout, True).decode(errors="replace")
                print(data, end="", flush=True)
                if re.search(r"\bFAILED\b", data) or any(word in data for word in ["Guru Meditation", "Brownout", "abort() was called", "assert failed:", "Rebooting..."]):
                    raise RuntimeError("Device diagnostic failed")
        finally:
            s.close()


if __name__ == "__main__":
    main()
