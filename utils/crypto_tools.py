# crypto_tools.py
# AES-256-GCM + Argon2id symmetric encryption and decryption.
# All operations write to a temp file first. Atomic rename on success.
# Temp file deleted on any failure including KeyboardInterrupt.

import os
import struct
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

MAGIC_HEADER = b"CIPHRA1\n"
ALGO_AES256GCM = 0x01
KDF_ARGON2ID = 0x01
CHUNK_SIZE = 65536


def calibrate_argon2_params() -> tuple[int, int, int]:
    """Time Argon2id key derivation and return (time_cost, memory_cost, parallelism)
    targeting 300-500ms on the current hardware.

    Starts at time_cost=3, memory_cost=131072 (128MB), parallelism=4.
    Increments time_cost by 1 until derivation takes 300ms+ or time_cost reaches 10.
    Returns the first params that hit 300ms, or the capped values if never reached.
    """
    memory_cost = 131072
    parallelism = 4
    calibration_salt = b"\x00" * 16
    calibration_password = b"calibration"

    for time_cost in range(3, 11):
        kdf = Argon2id(
            salt=calibration_salt,
            length=32,
            iterations=time_cost,
            lanes=parallelism,
            memory_cost=memory_cost,
        )
        start = time.monotonic()
        kdf.derive(calibration_password)
        elapsed = time.monotonic() - start

        if elapsed >= 0.300:
            return (time_cost, memory_cost, parallelism)

    # time_cost=10 reached without hitting 300ms — return the cap
    return (10, memory_cost, parallelism)


def derive_key(
    password: bytes,
    salt: bytes,
    time_cost: int,
    memory_cost: int,
    parallelism: int,
) -> bytes:
    """Derive and return a 32-byte key using Argon2id.

    Raises ValueError if derivation fails.
    """
    try:
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=time_cost,
            lanes=parallelism,
            memory_cost=memory_cost,
        )
        return kdf.derive(password)
    except Exception as e:
        # Translation layer: cryptography exceptions vary by platform/version.
        # Re-raise as ValueError so callers handle one error type.
        raise ValueError(f"Key derivation failed: {e}") from e


def encrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    progress_callback=None,
    _precomputed_key: bytes | None = None,
    _precomputed_params: tuple[int, int, int] | None = None,
    _precomputed_salt: bytes | None = None,
) -> None:
    """Encrypt input_path to output_path using AES-256-GCM + Argon2id.

    Writes to output_path + ".tmp" first. Atomic rename on success.
    Deletes temp on any failure including KeyboardInterrupt.

    File format (CIPHRA1):
      MAGIC_HEADER (8 bytes)
      algo_id (1 byte) = ALGO_AES256GCM
      kdf_id (1 byte) = KDF_ARGON2ID
      time_cost (4 bytes, little-endian uint32)
      memory_cost (4 bytes, little-endian uint32)
      parallelism (1 byte, uint8)
      salt (16 bytes)
      nonce (12 bytes)
      filename_len (2 bytes, little-endian uint16)
      filename (filename_len bytes, UTF-8)
      ciphertext (rest, GCM tag is the last 16 bytes)

    The full header (everything above) is authenticated via GCM AAD.
    Encryption is chunked — AESGCM.encrypt() on the full file is never used.
    """
    salt = _precomputed_salt if _precomputed_salt is not None else os.urandom(16)
    nonce = os.urandom(12)
    if _precomputed_params is not None:
        time_cost, memory_cost, parallelism = _precomputed_params
    else:
        time_cost, memory_cost, parallelism = calibrate_argon2_params()
    if _precomputed_key is not None:
        key = _precomputed_key
    else:
        key = derive_key(password.encode(), salt, time_cost, memory_cost, parallelism)

    filename_bytes = os.path.basename(input_path).encode("utf-8")
    filename_len = len(filename_bytes)

    header = (
        MAGIC_HEADER
        + bytes([ALGO_AES256GCM, KDF_ARGON2ID])
        + struct.pack("<II", time_cost, memory_cost)
        + struct.pack("<B", parallelism)
        + salt
        + nonce
        + struct.pack("<H", filename_len)
        + filename_bytes
    )

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(header)

    temp_path = output_path + ".tmp"
    try:
        with open(input_path, "rb") as fin, open(temp_path, "wb") as fout:
            fout.write(header)
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                fout.write(encryptor.update(chunk))
                if progress_callback:
                    progress_callback(len(chunk))
            fout.write(encryptor.finalize())
            fout.write(encryptor.tag)
        os.replace(temp_path, output_path)
    except BaseException:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise


def decrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    progress_callback=None,
    _precomputed_key: bytes | None = None,
) -> str:
    """Decrypt input_path to output_path.

    Returns the original filename embedded in the header.

    Raises ValueError("Wrong password or the file was tampered with.")
      on GCM tag failure.
    Raises ValueError("Not a recognized encrypted format.")
      if MAGIC_HEADER is not found.

    Writes to output_path + ".tmp" first. Atomic rename on success.
    Deletes temp on any failure including KeyboardInterrupt.
    No partial plaintext is ever left on disk.
    """
    temp_path = output_path + ".tmp"
    try:
        with open(input_path, "rb") as fin:
            magic = fin.read(8)
            if magic != MAGIC_HEADER:
                raise ValueError("Not a recognized encrypted format.")

            algo_id = fin.read(1)
            kdf_id = fin.read(1)
            time_cost_bytes = fin.read(4)
            memory_cost_bytes = fin.read(4)
            parallelism_bytes = fin.read(1)
            salt = fin.read(16)
            nonce = fin.read(12)
            filename_len_bytes = fin.read(2)
            filename_len = struct.unpack("<H", filename_len_bytes)[0]
            filename_bytes = fin.read(filename_len)

            # Reconstruct header bytes exactly as written by encrypt_file.
            # These are passed as AAD so the GCM tag covers them.
            header = (
                magic
                + algo_id
                + kdf_id
                + time_cost_bytes
                + memory_cost_bytes
                + parallelism_bytes
                + salt
                + nonce
                + filename_len_bytes
                + filename_bytes
            )

            time_cost = struct.unpack("<I", time_cost_bytes)[0]
            memory_cost = struct.unpack("<I", memory_cost_bytes)[0]
            parallelism = struct.unpack("<B", parallelism_bytes)[0]

            ciphertext_and_tag = fin.read()

        # Last 16 bytes are the GCM tag; the rest is ciphertext.
        tag = ciphertext_and_tag[-16:]
        ciphertext_body = ciphertext_and_tag[:-16]

        if _precomputed_key is not None:
            key = _precomputed_key
        else:
            key = derive_key(password.encode(), salt, time_cost, memory_cost, parallelism)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(header)

        with open(temp_path, "wb") as fout:
            plaintext = decryptor.update(ciphertext_body)
            if progress_callback:
                progress_callback(len(plaintext))
            fout.write(plaintext)
            try:
                fout.write(decryptor.finalize())
            except InvalidTag:
                # Delete temp before raising — no partial plaintext on disk.
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                raise ValueError("Wrong password or the file was tampered with.")

        os.replace(temp_path, output_path)
        return filename_bytes.decode("utf-8")

    except ValueError:
        # ValueError covers both our format error and the wrong-password error.
        # Temp already deleted inside the InvalidTag branch above if needed.
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise
    except BaseException:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise


def _read_kdf_params(
    input_path: str,
) -> tuple[bytes, int, int, int] | None:
    """Read salt and KDF params from a .ciphra file header.

    Returns (salt, time_cost, memory_cost, parallelism) or None on error.
    Does not decrypt anything.
    """
    try:
        with open(input_path, "rb") as fin:
            magic = fin.read(8)
            if magic != MAGIC_HEADER:
                return None
            fin.read(1)  # algo_id
            fin.read(1)  # kdf_id
            time_cost_bytes = fin.read(4)
            memory_cost_bytes = fin.read(4)
            parallelism_bytes = fin.read(1)
            salt = fin.read(16)
            time_cost = struct.unpack("<I", time_cost_bytes)[0]
            memory_cost = struct.unpack("<I", memory_cost_bytes)[0]
            parallelism = struct.unpack("<B", parallelism_bytes)[0]
            return (salt, time_cost, memory_cost, parallelism)
    except OSError:
        return None


def detect_format(input_path: str) -> str:
    """Detect encryption format by magic bytes.

    Returns 'ciphra', 'gpg', or 'unknown'.
    Never raises — returns 'unknown' on any OSError.
    """
    try:
        with open(input_path, "rb") as f:
            header = f.read(27)
    except OSError:
        return "unknown"

    if header[:8] == MAGIC_HEADER:
        return "ciphra"
    if header[:27] == b"-----BEGIN PGP MESSAGE-----":
        return "gpg"
    # Old-format packets (bit 7=1, bit 6=0): type encoded in bits 5-2
    # Type 1 (Public-Key Encrypted Session Key): 0x84-0x87
    # Type 3 (Symmetrically Encrypted Session Key): 0x8C-0x8F
    # New-format packets (bit 7=1, bit 6=1): type encoded in bits 5-0
    # Type 1 (Public-Key Encrypted Session Key): 0xC1
    # Type 3 (Symmetrically Encrypted Session Key): 0xC3
    # These are the ONLY valid first packets in a GPG encrypted file.
    if header[0:1] in (
        b"\x84", b"\x85", b"\x86", b"\x87",  # old-format type 1
        b"\x8c", b"\x8d", b"\x8e", b"\x8f",  # old-format type 3
        b"\xc1", b"\xc3",                      # new-format types 1 and 3
    ):
        return "gpg"
    return "unknown"
