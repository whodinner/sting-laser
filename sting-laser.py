#!/usr/bin/env python3
"""
StingLaser: The No-dongle IMSI Catcher heuristic detector

DISCLAIMER:
This tool does NOT prove the presence of a Stingray/IMSI catcher.
It only highlights anomalies (downgrades, strange IDs, no encryption).
For EDUCATIONAL USE ONLY.
"""

import subprocess
import re
import time
import argparse
import sys
from datetime import datetime

# ANSI color codes
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"

def get_modem_info(modem_index: int) -> str:
    """Query modem info using mmcli (part of ModemManager)."""
    try:
        output = subprocess.check_output(
            ["mmcli", "-m", str(modem_index)], text=True
        )
        return output
    except FileNotFoundError:
        print(f"{RED}[!] mmcli not found. Please install ModemManager.{RESET}")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Could not query modem {modem_index}: {e}{RESET}")
        return ""

def analyze(info: str, expected_mcc: str, expected_mnc: str, log_file=None):
    """Look for suspicious parameters in modem info."""
    mcc = re.search(r"MCC:\s*'(\d+)'", info)
    mnc = re.search(r"MNC:\s*'(\d+)'", info)
    rat = re.search(r"access tech:\s*'([^']+)'", info)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    messages = []

    if mcc and mnc:
        if mcc.group(1) != expected_mcc or mnc.group(1) != expected_mnc:
            msg = (f"[!] WARNING: Unexpected network MCC={mcc.group(1)}, "
                   f"MNC={mnc.group(1)}")
            print(f"{YELLOW}{msg}{RESET}")
            messages.append(f"{timestamp} {msg}")

    if rat:
        tech = rat.group(1)
        if "gsm" in tech.lower():
            msg = f"[!] ALERT: Downgraded to {tech.upper()} (2G) – possible stingray?"
            print(f"{RED}{msg}{RESET}")
            messages.append(f"{timestamp} {msg}")
        else:
            print(f"{GREEN}[+] Access Tech: {tech}{RESET}")

    # Log anomalies
    if log_file and messages:
        with open(log_file, "a") as f:
            for msg in messages:
                f.write(msg + "\n")

def main():
    parser = argparse.ArgumentParser(
        description="StingScan-Lite: Heuristic IMSI catcher detection (no dongle)"
    )
    parser.add_argument("-m", "--modem", type=int, default=0,
                        help="Modem index (default: 0)")
    parser.add_argument("--mcc", default="310",
                        help="Expected MCC (default: 310, USA)")
    parser.add_argument("--mnc", default="260",
                        help="Expected MNC (default: 260, T-Mobile)")
    parser.add_argument("-i", "--interval", type=int, default=10,
                        help="Polling interval in seconds (default: 10)")
    parser.add_argument("-l", "--log", type=str, default=None,
                        help="Optional log file to record anomalies")

    args = parser.parse_args()

    print(f"{GREEN}[+] Starting StingScan-Lite (no dongle)...{RESET}")
    print("DISCLAIMER: This tool detects *anomalies* only, not proof of IMSI catchers.\n")

    try:
        while True:
            info = get_modem_info(args.modem)
            if info:
                analyze(info, args.mcc, args.mnc, args.log)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[+] Exiting StingScan-Lite.{RESET}")

if __name__ == "__main__":
    main()
