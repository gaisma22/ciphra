# test_log_tools.py
# Tests for utils/log_tools.py.
# Covers: write_scan_log, CSV injection, rotation, read ordering.

import csv
import os
from unittest.mock import patch

import pytest

from utils.log_tools import (
    write_scan_log,
    write_scan_log_rows,
    read_scan_log,
    write_operation_log,
    MAX_LOG_ROWS,
)


def test_write_scan_log_creates_file(tmp_path):
    log_file = str(tmp_path / "activity.csv")
    log_folder = str(tmp_path)
    with patch("utils.log_tools.LOG_FILE", log_file), \
         patch("utils.log_tools.LOG_FOLDER", log_folder):
        write_scan_log("testfile.zip", "abc123", "0/72", "not_checked", "CLEAN")
    assert os.path.exists(log_file)
    with open(log_file, newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["filename"] == "testfile.zip"
    assert rows[0]["verdict"] == "CLEAN"


def test_write_scan_log_csv_injection(tmp_path):
    log_file = str(tmp_path / "activity.csv")
    log_folder = str(tmp_path)
    with patch("utils.log_tools.LOG_FILE", log_file), \
         patch("utils.log_tools.LOG_FOLDER", log_folder):
        write_scan_log("=malicious.zip", "abc123", "0/72", "not_checked", "CLEAN")
    with open(log_file, newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 1
    assert not rows[0]["filename"].startswith("=")
    assert rows[0]["filename"].startswith("malicious.zip")


def test_write_scan_log_rotation(tmp_path):
    log_file = str(tmp_path / "activity.csv")
    log_folder = str(tmp_path)
    # Patch getsize so the size guard always passes and rotation actually runs.
    with patch("utils.log_tools.LOG_FILE", log_file), \
         patch("utils.log_tools.LOG_FOLDER", log_folder), \
         patch("utils.log_tools.MAX_LOG_ROWS", 5), \
         patch("utils.log_tools.os.path.getsize", return_value=999999):
        for i in range(1, 8):
            write_scan_log(f"file{i}.zip", "abc123", "0/72", "not_checked", "CLEAN")
    with open(log_file, newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 5
    assert rows[-1]["filename"] == "file7.zip"
    assert rows[0]["filename"] == "file3.zip"


def test_write_scan_log_silent_on_error(tmp_path, capsys):
    log_file = str(tmp_path / "activity.csv")
    log_folder = str(tmp_path)
    with patch("utils.log_tools.LOG_FILE", log_file), \
         patch("utils.log_tools.LOG_FOLDER", log_folder), \
         patch("builtins.open", side_effect=PermissionError("denied")):
        # Should not raise, but writes warning to stderr.
        write_scan_log("test.zip", "abc123", "0/72", "not_checked", "CLEAN")
    captured = capsys.readouterr()
    assert "log_tools warning:" in captured.err


def test_read_scan_log_order(tmp_path):
    # Most recent row should be first.
    log_file = str(tmp_path / "activity.csv")
    log_folder = str(tmp_path)
    with patch("utils.log_tools.LOG_FILE", log_file), \
         patch("utils.log_tools.LOG_FOLDER", log_folder):
        write_scan_log("older.zip", "aaa111", "0/72", "not_checked", "CLEAN")
        write_scan_log("newer.zip", "bbb222", "0/72", "not_checked", "CLEAN")
    with patch("utils.log_tools.LOG_FILE", log_file):
        rows = read_scan_log()
    assert len(rows) == 2
    assert rows[0]["filename"] == "newer.zip"
    assert rows[1]["filename"] == "older.zip"


def test_write_scan_log_rows_csv_injection(tmp_path):
    # write_scan_log_rows should sanitize filenames against CSV injection.
    log_file = str(tmp_path / "activity.csv")
    log_folder = str(tmp_path)
    with patch("utils.log_tools.LOG_FILE", log_file), \
         patch("utils.log_tools.LOG_FOLDER", log_folder):
        rows = [
            {
                "time": "2026-04-07 12:00:00 +0000",
                "filename": "=malicious.zip",
                "sha256": "abc123",
                "vt_result": "0/72",
                "sig_status": "not_checked",
                "verdict": "CLEAN",
            }
        ]
        write_scan_log_rows(rows)
    with open(log_file, newline="") as f:
        reader = csv.DictReader(f)
        result_rows = list(reader)
    assert len(result_rows) == 1
    assert not result_rows[0]["filename"].startswith("=")
    assert result_rows[0]["filename"].startswith("malicious.zip")


def test_write_operation_log_creates_entry(tmp_path):
    # write_operation_log must append a row with the correct operation and verdict fields.
    log_file = str(tmp_path / "activity.csv")
    log_folder = str(tmp_path)
    with patch("utils.log_tools.LOG_FILE", log_file), \
         patch("utils.log_tools.LOG_FOLDER", log_folder):
        write_operation_log("testfile.bin", "abc123", "encrypt", "ok")
    with patch("utils.log_tools.LOG_FILE", log_file):
        rows = read_scan_log()
    assert len(rows) >= 1
    assert rows[0]["operation"] == "encrypt"
    assert rows[0]["verdict"] == "ok"
    assert rows[0]["filename"] == "testfile.bin"
