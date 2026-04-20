# test_hash.py
# Tests for utils/hash_tools.py.
# Covers: known hash, empty file, large file chunked read.

import hashlib
import os

import pytest

from utils.hash_tools import compute_hash


def test_known_hash(tmp_path):
    content = b"ciphra test"
    f = tmp_path / "test.bin"
    f.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()
    assert compute_hash(str(f), algo="sha256") == expected


def test_empty_file(tmp_path):
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    with pytest.raises(ValueError):
        compute_hash(str(f), algo="sha256")


def test_large_file(tmp_path):
    content = b"x" * (1024 * 1024)  # 1 MB
    f = tmp_path / "large.bin"
    f.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()
    assert compute_hash(str(f), algo="sha256") == expected


def test_nonexistent_file():
    with pytest.raises(FileNotFoundError):
        compute_hash("nonexistent_file_xyz.bin", algo="sha256")
