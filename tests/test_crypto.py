# test_crypto.py
# Tests for utils/crypto_tools.py — AES-256-GCM + Argon2id symmetric encryption.
# All tests use tmp_path and are isolated from real filesystem state.

import os

import pytest

from utils.crypto_tools import (
    CHUNK_SIZE,
    MAGIC_HEADER,
    decrypt_file,
    detect_format,
    encrypt_file,
)


def test_encrypt_decrypt_roundtrip(tmp_path):
    """Decrypted content must match original. Returned filename must match."""
    original_content = b"ciphra test content 1234567890"
    input_file = tmp_path / "testfile.bin"
    input_file.write_bytes(original_content)

    encrypted_file = tmp_path / "testfile.bin.ciphra"
    encrypt_file(str(input_file), str(encrypted_file), "correct-password")

    decrypted_file = tmp_path / "testfile.bin.out"
    returned_name = decrypt_file(
        str(encrypted_file), str(decrypted_file), "correct-password"
    )

    assert decrypted_file.read_bytes() == original_content
    assert returned_name == "testfile.bin"


def test_wrong_password_raises_value_error(tmp_path):
    """Wrong password must raise ValueError with 'Wrong password' in message.
    No temp file must remain after failure."""
    input_file = tmp_path / "secret.txt"
    input_file.write_bytes(b"secret data")

    encrypted_file = tmp_path / "secret.txt.ciphra"
    encrypt_file(str(input_file), str(encrypted_file), "correct-password")

    decrypted_file = tmp_path / "secret.txt.out"
    temp_path = str(decrypted_file) + ".tmp"

    with pytest.raises(ValueError, match="Wrong password"):
        decrypt_file(str(encrypted_file), str(decrypted_file), "wrong-password")

    assert not os.path.exists(temp_path)


def test_tampered_ciphertext_raises(tmp_path):
    """Flipping a byte in the ciphertext section must cause decrypt to raise ValueError."""
    input_file = tmp_path / "data.bin"
    input_file.write_bytes(b"data to protect from tampering")

    encrypted_file = tmp_path / "data.bin.ciphra"
    encrypt_file(str(input_file), str(encrypted_file), "password")

    raw = bytearray(encrypted_file.read_bytes())

    # Header ends at: 8 + 1 + 1 + 4 + 4 + 1 + 16 + 12 + 2 + filename_len
    # filename = "data.bin" = 8 bytes, so header = 57 bytes
    # Flip a byte in the middle of the ciphertext (well past the header)
    ciphertext_start = 57
    flip_offset = ciphertext_start + 4
    raw[flip_offset] ^= 0xFF
    encrypted_file.write_bytes(bytes(raw))

    decrypted_file = tmp_path / "data.bin.out"
    with pytest.raises(ValueError):
        decrypt_file(str(encrypted_file), str(decrypted_file), "password")


def test_tampered_header_raises(tmp_path):
    """Flipping a byte in the header section must cause decrypt to raise ValueError.
    GCM authentication covers the header, so any tampering fails the tag check."""
    input_file = tmp_path / "header_test.bin"
    input_file.write_bytes(b"header authentication test")

    encrypted_file = tmp_path / "header_test.bin.ciphra"
    encrypt_file(str(input_file), str(encrypted_file), "password")

    raw = bytearray(encrypted_file.read_bytes())
    # Byte 10 is inside the kdf params section (past the 8-byte magic and 2 algo bytes)
    raw[10] ^= 0xFF
    encrypted_file.write_bytes(bytes(raw))

    decrypted_file = tmp_path / "header_test.bin.out"
    with pytest.raises(ValueError):
        decrypt_file(str(encrypted_file), str(decrypted_file), "password")


def test_format_detection_ciphra(tmp_path):
    """detect_format must return 'ciphra' for a real encrypted file."""
    input_file = tmp_path / "sample.txt"
    input_file.write_bytes(b"sample content")

    encrypted_file = tmp_path / "sample.txt.ciphra"
    encrypt_file(str(input_file), str(encrypted_file), "password")

    assert detect_format(str(encrypted_file)) == "ciphra"


def test_format_detection_gpg_armored(tmp_path):
    """detect_format must return 'gpg' for armored PGP message files."""
    gpg_file = tmp_path / "message.asc"
    gpg_file.write_bytes(b"-----BEGIN PGP MESSAGE-----\nfakedata")

    assert detect_format(str(gpg_file)) == "gpg"


def test_format_detection_gpg_binary(tmp_path):
    """detect_format must return 'gpg' for binary GPG files starting with 0x85."""
    gpg_file = tmp_path / "message.gpg"
    gpg_file.write_bytes(b"\x85\x00\x00\x00")

    assert detect_format(str(gpg_file)) == "gpg"


def test_format_detection_unknown(tmp_path):
    """detect_format must return 'unknown' for unrecognized files."""
    plain_file = tmp_path / "plain.txt"
    plain_file.write_bytes(b"this is not encrypted")

    assert detect_format(str(plain_file)) == "unknown"


def test_original_filename_preserved(tmp_path):
    """decrypt_file must return the exact filename embedded during encryption."""
    input_file = tmp_path / "myspecialfile.iso"
    input_file.write_bytes(b"iso content")

    encrypted_file = tmp_path / "myspecialfile.iso.ciphra"
    encrypt_file(str(input_file), str(encrypted_file), "password")

    decrypted_file = tmp_path / "myspecialfile.iso.out"
    returned_name = decrypt_file(
        str(encrypted_file), str(decrypted_file), "password"
    )

    assert returned_name == "myspecialfile.iso"


def test_no_partial_plaintext_on_wrong_password(tmp_path):
    """After a failed decrypt, neither the output path nor a .tmp file may exist."""
    input_file = tmp_path / "sensitive.bin"
    input_file.write_bytes(b"sensitive content that must not leak")

    encrypted_file = tmp_path / "sensitive.bin.ciphra"
    encrypt_file(str(input_file), str(encrypted_file), "correct-password")

    decrypted_file = tmp_path / "sensitive.bin.out"
    temp_path = str(decrypted_file) + ".tmp"

    with pytest.raises(ValueError):
        decrypt_file(str(encrypted_file), str(decrypted_file), "wrong-password")

    assert not os.path.exists(str(decrypted_file))
    assert not os.path.exists(temp_path)


def test_decrypt_symmetric_dec_collision_uses_fallback(tmp_path):
    """When the embedded filename already exists at the output dir,
    _decrypt_symmetric prompts the user. Selecting Overwrite must replace
    the existing file with the decrypted content."""
    from unittest.mock import MagicMock, patch
    from ciphra import _decrypt_symmetric

    content = b"collision test content"
    src = tmp_path / "myfile.txt"
    src.write_bytes(content)

    enc = tmp_path / "myfile.txt.ciphra"
    encrypt_file(str(src), str(enc), "testpassword")

    # Create the collision: myfile.txt already exists in the output dir
    collision_file = tmp_path / "myfile.txt"
    collision_file.write_bytes(b"existing file that will be overwritten")

    mock_password = MagicMock()
    mock_password.ask.return_value = "testpassword"
    mock_select = MagicMock()
    mock_select.ask.return_value = "Overwrite"

    with patch("ciphra.questionary.password", return_value=mock_password), \
         patch("ciphra.questionary.select", return_value=mock_select), \
         patch("ciphra.console"):
        _decrypt_symmetric(str(enc))

    assert collision_file.read_bytes() == content
