# log_tools.py
# Shared scan log utility.
# write_scan_log: appends one scan result row to the activity CSV log.

import csv
import os
import sys
from datetime import datetime
from pathlib import Path

from config import LOG_FILE, LOG_FOLDER

MAX_LOG_ROWS = 1000

_HEADER = ["timestamp", "filename", "sha256", "vt_result", "sig_status", "verdict", "operation"]


def _rotate_log():
    try:
        # Skip the full read if the file is too small to need rotation
        if os.path.getsize(LOG_FILE) < MAX_LOG_ROWS * 200:
            return
        with open(LOG_FILE, newline="") as f:
            reader = csv.reader(f)
            rows = list(reader)
        if not rows:
            return
        header = rows[0]
        data = rows[1:]
        if len(data) <= MAX_LOG_ROWS:
            return
        kept = data[-MAX_LOG_ROWS:]
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(kept)
    except (OSError, csv.Error) as e:
        sys.stderr.write(f"log_tools warning: {e}\n")
        return


def read_scan_log() -> list:
    try:
        with open(LOG_FILE, newline="") as f:
            reader = csv.DictReader(f)
            rows = [
                {
                    "time": row.get("timestamp", ""),
                    "filename": row.get("filename", ""),
                    "sha256": row.get("sha256", ""),
                    "vt_result": row.get("vt_result", ""),
                    "sig_status": row.get("sig_status", ""),
                    "verdict": row.get("verdict", ""),
                    "operation": row.get("operation", "verify"),
                }
                for row in reader
            ]
        rows.reverse()
        return rows
    except FileNotFoundError:
        return []
    except (OSError, csv.Error) as e:
        sys.stderr.write(f"log_tools warning: {e}\n")
        return []


def write_scan_log_rows(rows: list) -> None:
    try:
        os.makedirs(LOG_FOLDER, exist_ok=True)
        with open(LOG_FILE, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=_HEADER)
            writer.writeheader()
            for row in rows:
                safe_name = row.get("filename", "").lstrip("=+-@")
                writer.writerow({
                    "timestamp": row.get("time", row.get("timestamp", "")),
                    "filename": safe_name,
                    "sha256": row.get("sha256", ""),
                    "vt_result": row.get("vt_result", ""),
                    "sig_status": row.get("sig_status", ""),
                    "verdict": row.get("verdict", ""),
                    "operation": row.get("operation", ""),
                })
    except (OSError, csv.Error) as e:
        sys.stderr.write(f"log_tools warning: {e}\n")
        return
    _rotate_log()


def write_scan_log(
    filename: str,
    sha256: str,
    vt_result: str,
    sig_status: str,
    verdict: str,
    operation: str = "verify",
) -> None:
    safe_name = filename.lstrip("=+-@")
    try:
        os.makedirs(LOG_FOLDER, exist_ok=True)
        write_header = not Path(LOG_FILE).exists()
        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=_HEADER)
            if write_header:
                writer.writeheader()
            writer.writerow({
                "timestamp": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z"),
                "filename": safe_name,
                "sha256": sha256,
                "vt_result": vt_result,
                "sig_status": sig_status,
                "verdict": verdict,
                "operation": operation,
            })
    except (OSError, csv.Error) as e:
        sys.stderr.write(f"log_tools warning: {e}\n")
        return
    _rotate_log()


def write_operation_log(
    filename: str,
    sha256: str,
    operation: str,
    status: str,
) -> None:
    """Append one encrypt/decrypt/sign/keygen operation row to the activity log."""
    safe_name = filename.lstrip("=+-@")
    try:
        os.makedirs(LOG_FOLDER, exist_ok=True)
        write_header = not Path(LOG_FILE).exists()
        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=_HEADER)
            if write_header:
                writer.writeheader()
            writer.writerow({
                "timestamp": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z"),
                "filename": safe_name,
                "sha256": sha256,
                "vt_result": "",
                "sig_status": "",
                "verdict": status,
                "operation": operation,
            })
    except (OSError, csv.Error) as e:
        sys.stderr.write(f"log_tools warning: {e}\n")
        return
    _rotate_log()
