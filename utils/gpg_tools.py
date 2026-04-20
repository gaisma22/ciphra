# gpg_tools.py
# GPG signature verification utility.
# gpg_available: checks if gpg is installed.
# verify_signature: runs gpg --verify via subprocess.
# fetch_gpg_key: fetches a public key from a keyserver.
# set_key_trust: sets ownertrust level via --import-ownertrust.
# get_imported_key_fingerprint: reads fingerprint from key file without importing.
# import_and_trust_key: imports a key file and sets trust if it matches the sig.

import logging
import os
import re as _re_gpg
import subprocess
import shutil as _shutil
import platform as _platform

_KEY_ID_RE = _re_gpg.compile(r'[0-9A-Fa-f]{8,}')
_fp_cache = {}


def _find_gpg() -> str | None:
    for binary in ("gpg", "gpg2"):
        if _shutil.which(binary):
            return binary
    system = _platform.system()
    if system == "Darwin":
        for path in (
            "/usr/local/bin/gpg",
            "/opt/homebrew/bin/gpg",
            "/usr/local/bin/gpg2",
            "/opt/homebrew/bin/gpg2",
        ):
            if os.path.isfile(path):
                return path
    elif system == "Windows":
        for path in (
            r"C:\Program Files (x86)\GnuPG\bin\gpg.exe",
            r"C:\Program Files\GnuPG\bin\gpg.exe",
        ):
            if os.path.isfile(path):
                return path
    return None


GPG_BIN = _find_gpg()


def gpg_available() -> bool:
    return GPG_BIN is not None


def extract_key_id(output: str):
    patterns = [
        r'using \w+ key ([0-9A-Fa-f]{16,})',
        r'NO_PUBKEY ([0-9A-Fa-f]{16,})',
        r'key ([0-9A-Fa-f]{16,})',
        r'requesting key ([0-9A-Fa-f]{16,})',
        r'KEY_CONSIDERED ([0-9A-Fa-f]{16,})',
    ]
    for line in output.splitlines():
        for pattern in patterns:
            match = _re_gpg.search(pattern, line, _re_gpg.IGNORECASE)
            if match:
                return match.group(1)
    return None


# Callers on slow systems can pass a higher timeout value.
def verify_signature(data_path, sig_path, timeout=30) -> dict:
    # msg in the returned dict contains raw GPG output.
    # All callers must pass msg through _translate_error() before display.
    if not gpg_available():
        return {
            "ok": False,
            "status": "error",
            "msg": "gpg not installed",
            "key_id": None,
            "fingerprint": None,
            "trust": None,
        }

    for path in (data_path, sig_path):
        if not os.path.exists(path):
            return {
                "ok": False,
                "status": "error",
                "msg": f"File not found: {path}",
                "key_id": None,
                "fingerprint": None,
                "trust": None,
            }

    cmd = [GPG_BIN, "--batch", "--status-fd", "2", "--verify", sig_path, data_path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return {
            "ok": False,
            "status": "error",
            "msg": "gpg not found",
            "key_id": None,
            "fingerprint": None,
            "trust": None,
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "status": "error",
            "msg": "gpg timed out",
            "key_id": None,
            "fingerprint": None,
            "trust": None,
        }
    except (subprocess.SubprocessError, OSError) as e:
        return {
            "ok": False,
            "status": "error",
            "msg": f"gpg failed: {e}",
            "key_id": None,
            "fingerprint": None,
            "trust": None,
        }

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    output = (stdout + "\n" + stderr).strip()

    if proc.returncode == 0:
        fingerprint = None
        trust = "unknown"
        for line in (stdout + "\n" + stderr).splitlines():
            # Extract fingerprint from [GNUPG:] VALIDSIG status line
            if line.startswith("[GNUPG:] VALIDSIG"):
                parts = line.split()
                if len(parts) >= 3:
                    fingerprint = parts[2]
            # Parse machine-readable [GNUPG:] status lines for trust level.
            if "[GNUPG:] TRUST_FULLY" in line:
                trust = "full"
            elif "[GNUPG:] TRUST_ULTIMATE" in line:
                trust = "ultimate"
            elif "[GNUPG:] TRUST_MARGINAL" in line:
                trust = "marginal"
            elif "[GNUPG:] TRUST_UNDEFINED" in line or "[GNUPG:] TRUST_NEVER" in line:
                trust = "untrusted"
        return {
            "ok": True,
            "status": "verified",
            "msg": "Signature verified. The file matches the signature.",
            "key_id": None,
            "fingerprint": fingerprint,
            "trust": trust,
        }

    if (
        "No public key" in output
        or "Can't check signature: No public key" in output
        or "NO_PUBKEY" in output
    ):
        return {
            "ok": False,
            "status": "no_pubkey",
            "msg": output.splitlines()[-1] if output else "Missing public key.",
            "key_id": extract_key_id(stdout + "\n" + stderr),
            "fingerprint": None,
            "trust": None,
        }

    if "BAD signature" in output or "gpg: BAD signature" in output:
        return {
            "ok": False,
            "status": "bad",
            "msg": "Signature does not match the file. Do not trust this file.",
            "key_id": None,
            "fingerprint": None,
            "trust": None,
        }

    return {
        "ok": False,
        "status": "error",
        "msg": output or "Unknown gpg verification result.",
        "key_id": None,
        "fingerprint": None,
        "trust": None,
    }


def _check_key_in_keyring(key_id: str) -> bool:
    try:
        proc = subprocess.run(
            [GPG_BIN, "--list-keys", key_id],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as e:
        logging.error("_check_key_in_keyring failed: %s", e)
        return False


def fetch_gpg_key(
    key_id: str,
    keyserver: str = "keyserver.ubuntu.com",
    timeout: int = 30,
) -> dict:
    if not key_id:
        return {"ok": False, "msg": "No key ID provided.", "in_keyring": False}
    cmd = [GPG_BIN, "--keyserver", keyserver, "--recv-keys", key_id]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode == 0:
            in_keyring = _check_key_in_keyring(key_id)
            return {
                "ok": True,
                "msg": f"Key {key_id} imported.",
                "in_keyring": in_keyring,
            }
        output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        return {"ok": False, "msg": output or "Key fetch failed.", "in_keyring": False}
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": "Keyserver request timed out.", "in_keyring": False}
    except FileNotFoundError:
        return {"ok": False, "msg": "gpg not installed.", "in_keyring": False}
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "msg": str(e), "in_keyring": False}


def set_key_trust(
    fingerprint: str,
    level: int = 4,
    timeout: int = 10,
) -> dict:
    if not fingerprint:
        return {"ok": False, "msg": "No fingerprint provided."}
    if level not in [1, 2, 3, 4, 5, 6]:
        return {"ok": False, "msg": f"Invalid trust level: {level}"}
    trust_input = f"{fingerprint}:{level}:\n".encode()
    cmd = [GPG_BIN, "--import-ownertrust"]
    try:
        proc = subprocess.run(
            cmd,
            input=trust_input,
            capture_output=True,
            timeout=timeout,
        )
        if proc.returncode == 0:
            try:
                subprocess.run(
                    [GPG_BIN, "--check-trustdb"],
                    capture_output=True,
                    timeout=15,
                )
            except (subprocess.SubprocessError, OSError):
                pass
            # ok: True means the command ran, not that the key will show as trusted in GPG output.
            return {
                "ok": True,
                "msg": f"Trust level {level} set for {fingerprint}.",
                "trust_anchor_required": True,
            }
        return {
            "ok": False,
            "msg": proc.stderr.decode(errors="replace").strip() or "Failed to set trust.",
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": "Trust operation timed out."}
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "msg": str(e)}


def get_imported_key_fingerprint(
    key_file: str,
    timeout: int = 10,
) -> str | None:
    if key_file in _fp_cache:
        return _fp_cache[key_file]
    cmd = [
        GPG_BIN,
        "--with-colons",
        "--with-fingerprint",
        "--import-options", "import-show",
        "--dry-run",
        "--import",
        key_file,
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        result = None
        for line in proc.stdout.splitlines():
            if line.startswith("fpr:"):
                parts = line.split(":")
                if len(parts) >= 10 and parts[9]:
                    result = parts[9].strip()
                    break
        _fp_cache[key_file] = result
        return result
    except (subprocess.SubprocessError, OSError, ValueError):
        return None


def import_and_trust_key(
    key_file: str,
    sig_key_id: str | None = None,
) -> dict:
    if not os.path.isfile(key_file):
        return {
            "ok": False,
            "matched": False,
            "msg": "Key file not found.",
            "fingerprint": None,
        }

    fp = get_imported_key_fingerprint(key_file)

    if fp and _check_key_in_keyring(fp):
        return {
            "ok": True,
            "matched": True,
            "already_imported": True,
            "mismatch_warning": None,
            "fingerprint": fp,
            "trust_set": False,
            "msg": "Key already in keyring.",
        }

    matched = False
    mismatch_warning = None

    if sig_key_id and fp:
        sig_id_clean = sig_key_id.upper().strip()
        fp_clean = fp.upper().strip()
        if (
            fp_clean.endswith(sig_id_clean)
            or sig_id_clean.endswith(fp_clean)
            or fp_clean == sig_id_clean
        ):
            matched = True
        else:
            mismatch_warning = (
                f"Key in file: {fp}\n"
                f"Key in signature: {sig_key_id}"
            )
    elif fp:
        matched = True

    try:
        import_result = subprocess.run(
            [GPG_BIN, "--import", key_file],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as e:
        return {
            "ok": False,
            "matched": matched,
            "msg": str(e),
            "fingerprint": fp,
            "mismatch_warning": mismatch_warning,
            "trust_set": False,
        }

    if import_result.returncode != 0:
        return {
            "ok": False,
            "matched": matched,
            "msg": import_result.stderr.strip() or "Import failed.",
            "fingerprint": fp,
        }

    trust_result = None
    if matched and fp:
        trust_result = set_key_trust(fp, 4)

    return {
        "ok": True,
        "matched": matched,
        "mismatch_warning": mismatch_warning,
        "fingerprint": fp,
        "trust_set": trust_result["ok"] if trust_result else False,
        "msg": f"Key imported{' and trusted' if trust_result and trust_result['ok'] else ''}.",
    }


def list_encryption_keys() -> list[dict]:
    """List public keys that are capable of encryption.
    Filters out signing-only keys and keys with no valid encryption subkey.
    Returns list of dicts: {fingerprint, uid}
    Returns [] if GPG not available or on any error.
    """
    if GPG_BIN is None:
        return []
    try:
        proc = subprocess.run(
            [GPG_BIN, "--list-keys", "--with-colons"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        return []

    # Build a list of all pub key records with their fingerprint,
    # uid, and whether they have an encryption-capable subkey or primary key.
    records = []
    current = None

    for line in proc.stdout.splitlines():
        parts = line.split(":")
        record_type = parts[0] if parts else ""

        if record_type == "pub":
            # Save previous record if it exists
            if current is not None:
                records.append(current)
            caps = parts[11] if len(parts) > 11 else ""
            validity = parts[1] if len(parts) > 1 else ""
            expiry_ts = parts[6] if len(parts) > 6 else ""
            if expiry_ts:
                try:
                    import datetime as _dt
                    expiry_str = _dt.datetime.fromtimestamp(
                        int(expiry_ts)
                    ).strftime("%Y-%m-%d")
                except (ValueError, OSError):
                    expiry_str = "never"
            else:
                expiry_str = "never"
            current = {
                "fingerprint": "",
                "uid": "",
                "can_encrypt": "E" in caps,
                "algo_id": parts[3] if len(parts) > 3 else "",
                "key_size": parts[2] if len(parts) > 2 else "",
                "expired": validity == "e",
                "expiry": expiry_str,
            }

        elif record_type == "fpr" and current is not None:
            if not current["fingerprint"]:
                current["fingerprint"] = parts[9].strip() if len(parts) > 9 else ""

        elif record_type == "uid" and current is not None:
            if not current["uid"]:
                current["uid"] = parts[9].strip() if len(parts) > 9 else ""

        elif record_type == "sub" and current is not None:
            validity = parts[1] if len(parts) > 1 else ""
            caps = parts[8] if len(parts) > 8 else ""
            # Skip revoked subkeys
            if validity != "r" and "e" in caps:
                current["can_encrypt"] = True

    # Append last record
    if current is not None:
        records.append(current)

    def _algo_name(algo_id: str, key_size: str) -> str:
        mapping = {"1": "RSA", "17": "DSA", "18": "ECDH", "22": "Ed25519"}
        name = mapping.get(algo_id, f"algo-{algo_id}")
        if key_size and algo_id in ("1", "17"):
            return f"{name}-{key_size}"
        return name

    # Return only keys that can encrypt and have a fingerprint
    return [
        {
            "fingerprint": r["fingerprint"],
            "uid": r["uid"],
            "algo": _algo_name(r["algo_id"], r["key_size"]),
            "expired": r["expired"],
            "expiry": r["expiry"],
        }
        for r in records
        if r["can_encrypt"] and r["fingerprint"]
    ]


def import_public_key_file(key_path: str) -> dict:
    """Import a public key from a file into the GPG keyring.
    Returns {ok: bool, msg: str, fingerprint: str | None}
    """
    if GPG_BIN is None:
        return {"ok": False, "msg": "GPG is not installed.", "fingerprint": None}
    if not os.path.isfile(key_path):
        return {"ok": False, "msg": "File not found.", "fingerprint": None}
    try:
        proc = subprocess.run(
            [GPG_BIN, "--batch", "--import", key_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0:
            msg = proc.stderr.strip() or "Import failed."
            return {"ok": False, "msg": msg, "fingerprint": None}
        # Extract fingerprint from import output
        fingerprint = None
        for line in proc.stderr.splitlines():
            if "key" in line.lower() and "imported" in line.lower():
                parts = line.split()
                for part in parts:
                    part_clean = part.strip(":")
                    if len(part_clean) >= 8 and all(
                        c in "0123456789abcdefABCDEF"
                        for c in part_clean
                    ):
                        fingerprint = part_clean.upper()
                        break
        return {
            "ok": True,
            "msg": "Key imported.",
            "fingerprint": fingerprint,
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": "GPG timed out.", "fingerprint": None}
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "msg": str(e), "fingerprint": None}


def encrypt_file_asymmetric(
    input_path: str,
    output_path: str,
    recipient_fingerprint: str,
    timeout: int | None = None,
) -> dict:
    """Encrypt input_path for recipient_fingerprint. Writes to output_path.

    Returns {"ok": True/False, "msg": str}.
    """
    if GPG_BIN is None:
        return {"ok": False, "msg": "gpg not installed."}
    cmd = [
        GPG_BIN,
        "--batch",
        "--yes",
        "--trust-model", "always",
        "--encrypt",
        "--recipient", recipient_fingerprint,
        "--output", output_path,
        input_path,
    ]
    try:
        if timeout is None:
            try:
                file_size_mb = os.path.getsize(input_path) / (1024 * 1024)
            except OSError:
                file_size_mb = 0
            timeout = max(60, min(3600, int(60 + (file_size_mb / 1024) * 30)))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode == 0:
            return {"ok": True, "msg": "File encrypted."}
        output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        return {"ok": False, "msg": output or "Encryption failed."}
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": "GPG timed out."}
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "msg": str(e)}


def decrypt_file_asymmetric(
    input_path: str,
    output_path: str,
    passphrase: str,
    timeout: int | None = None,
) -> dict:
    """Decrypt input_path using the keyring. Writes to output_path.

    Passphrase is passed via stdin (--passphrase-fd 0).
    Returns {"ok": True/False, "msg": str}.
    """
    if GPG_BIN is None:
        return {"ok": False, "msg": "gpg not installed."}
    cmd = [
        GPG_BIN,
        "--batch",
        "--yes",
        "--passphrase-fd", "0",
        "--pinentry-mode", "loopback",
        "--decrypt",
        "--output", output_path,
        input_path,
    ]
    try:
        if timeout is None:
            try:
                file_size_mb = os.path.getsize(input_path) / (1024 * 1024)
            except OSError:
                file_size_mb = 0
            timeout = max(120, min(3600, int(180 + (file_size_mb / 1024) * 30)))
        proc = subprocess.run(
            cmd,
            input=passphrase,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode == 0:
            return {"ok": True, "msg": "File decrypted."}
        output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        return {"ok": False, "msg": output or "Decryption failed."}
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": "GPG timed out."}
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "msg": str(e)}


def get_encrypted_for_key_id(input_path: str) -> str | None:
    """Return the key ID the file was encrypted for, or None.

    Parses gpg --list-packets output for a keyid or key id line.
    Returns the hex key ID (uppercased) or None on any error.
    """
    if GPG_BIN is None:
        return None
    cmd = [GPG_BIN, "--batch", "--list-packets", input_path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        for line in output.splitlines():
            line_lower = line.lower()
            if "keyid" in line_lower or "key id" in line_lower:
                match = _KEY_ID_RE.search(line)
                if match:
                    return match.group(0).upper()
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        return None
    return None


def generate_key_pair(
    name: str,
    email: str,
    expiry: str,
    passphrase: str,
) -> dict:
    """Generate an Ed25519 signing key + cv25519 encryption subkey via GPG batch mode.

    expiry: GPG-format string -- "1y", "2y", "5y", "0", or custom like "180d".
    Returns {ok: bool, msg: str, fingerprint: str | None}
    """
    if GPG_BIN is None:
        return {"ok": False, "msg": "GPG is not installed.", "fingerprint": None}

    name = name.replace("\n", " ").replace("\r", " ").replace(":", " ").strip()
    email = email.replace("\n", "").replace("\r", "").replace(" ", "").strip()
    if not name or not email:
        return {
            "ok": False,
            "msg": "Name and email are required.",
            "fingerprint": None,
        }

    batch_params = (
        "Key-Type: eddsa\n"
        "Key-Curve: Ed25519\n"
        "Key-Usage: sign\n"
        "Subkey-Type: ecdh\n"
        "Subkey-Curve: Curve25519\n"
        "Subkey-Usage: encrypt\n"
        f"Name-Real: {name}\n"
        f"Name-Email: {email}\n"
        f"Expire-Date: {expiry}\n"
        f"Passphrase: {passphrase}\n"
        "%commit\n"
    )

    try:
        proc = subprocess.run(
            [GPG_BIN, "--batch", "--pinentry-mode", "loopback",
             "--gen-key", "--status-fd", "2"],
            input=batch_params,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode != 0:
            msg = proc.stderr.strip() or "Key generation failed."
            return {"ok": False, "msg": msg, "fingerprint": None}

        fingerprint = None
        for line in proc.stderr.splitlines():
            if "[GNUPG:] KEY_CREATED" in line:
                parts = line.split()
                if len(parts) >= 4:
                    fingerprint = parts[3].upper()
                    break

        return {
            "ok": True,
            "msg": "Key pair created.",
            "fingerprint": fingerprint,
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": "GPG timed out.", "fingerprint": None}
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "msg": str(e), "fingerprint": None}


def list_signing_keys() -> list[dict]:
    """List secret keys available for signing.

    Returns list of dicts: {fingerprint, uid, algo, expired}
    expired is True if key validity field is 'e'.
    Returns [] if GPG not available or on any error.
    """
    if GPG_BIN is None:
        return []
    try:
        proc = subprocess.run(
            [GPG_BIN, "--list-secret-keys", "--with-colons"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        return []

    records = []
    current = None

    for line in proc.stdout.splitlines():
        parts = line.split(":")
        record_type = parts[0] if parts else ""

        if record_type == "sec":
            if current is not None:
                records.append(current)
            algo_id = parts[3] if len(parts) > 3 else ""
            key_size = parts[2] if len(parts) > 2 else ""
            validity = parts[1] if len(parts) > 1 else ""
            expiry_ts = parts[6] if len(parts) > 6 else ""
            if expiry_ts:
                try:
                    import datetime as _dt
                    expiry_str = _dt.datetime.fromtimestamp(
                        int(expiry_ts)
                    ).strftime("%Y-%m-%d")
                except (ValueError, OSError):
                    expiry_str = "never"
            else:
                expiry_str = "never"
            mapping = {"1": "RSA", "17": "DSA", "18": "ECDH", "22": "Ed25519"}
            algo_base = mapping.get(algo_id, f"algo-{algo_id}")
            if key_size and algo_id in ("1", "17"):
                algo_name = f"{algo_base}-{key_size}"
            else:
                algo_name = algo_base

            current = {
                "fingerprint": "",
                "uid": "",
                "algo": algo_name,
                "expired": validity == "e",
                "expiry": expiry_str,
            }

        elif record_type == "fpr" and current is not None:
            if not current["fingerprint"]:
                current["fingerprint"] = (
                    parts[9].strip() if len(parts) > 9 else ""
                )

        elif record_type == "uid" and current is not None:
            if not current["uid"]:
                current["uid"] = parts[9].strip() if len(parts) > 9 else ""

    if current is not None:
        records.append(current)

    return [
        {
            "fingerprint": r["fingerprint"],
            "uid": r["uid"],
            "algo": r["algo"],
            "expired": r["expired"],
            "expiry": r["expiry"],
        }
        for r in records if r["fingerprint"]
    ]


def sign_file_detached(
    input_path: str,
    output_path: str,
    fingerprint: str,
    passphrase: str,
) -> dict:
    """Create a detached armored signature for input_path.

    Uses --passphrase-fd 0 to pass passphrase via stdin.
    Returns {ok: bool, msg: str}
    """
    if GPG_BIN is None:
        return {"ok": False, "msg": "GPG is not installed."}
    try:
        proc = subprocess.run(
            [
                GPG_BIN,
                "--batch",
                "--yes",
                "--passphrase-fd", "0",
                "--pinentry-mode", "loopback",
                "--detach-sign",
                "--armor",
                "--local-user", fingerprint,
                "--output", output_path,
                input_path,
            ],
            input=passphrase,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode == 0:
            return {"ok": True, "msg": "Signature created."}
        msg = proc.stderr.strip() or "Signing failed."
        return {"ok": False, "msg": msg}
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": "GPG timed out."}
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "msg": str(e)}


def export_public_key(
    fingerprint: str,
    output_path: str,
) -> dict:
    """Export the public key for fingerprint to output_path in armored format.

    Returns {ok: bool, msg: str}
    """
    if GPG_BIN is None:
        return {"ok": False, "msg": "GPG is not installed."}
    try:
        proc = subprocess.run(
            [
                GPG_BIN,
                "--batch",
                "--armor",
                "--export",
                fingerprint,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            msg = proc.stderr.strip() or "Export failed."
            return {"ok": False, "msg": msg}
        try:
            with open(output_path, "w") as f:
                f.write(proc.stdout)
        except OSError as e:
            return {"ok": False, "msg": str(e)}
        return {"ok": True, "msg": "Public key exported."}
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": "GPG timed out."}
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "msg": str(e)}


def export_private_key(
    fingerprint: str,
    output_path: str,
    passphrase: str = "",
) -> dict:
    """Export the private key for fingerprint to output_path in armored format.

    The exported file retains passphrase protection.
    Returns {ok: bool, msg: str}
    """
    if GPG_BIN is None:
        return {"ok": False, "msg": "GPG is not installed."}
    try:
        proc = subprocess.run(
            [
                GPG_BIN,
                "--batch",
                "--yes",
                "--passphrase-fd", "0",
                "--pinentry-mode", "loopback",
                "--armor",
                "--export-secret-keys",
                fingerprint,
            ],
            input=passphrase,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            msg = proc.stderr.strip() or "Export failed."
            return {"ok": False, "msg": msg}
        try:
            with open(output_path, "w") as f:
                f.write(proc.stdout)
        except OSError as e:
            return {"ok": False, "msg": str(e)}
        return {"ok": True, "msg": "Private key exported."}
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": "GPG timed out."}
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "msg": str(e)}


def list_signing_keys_without_encryption_subkey() -> list[dict]:
    """List secret keys that have signing capability but no active
    (non-revoked, non-expired) encryption subkey.
    Returns list of dicts: {fingerprint, uid, algo, expired}
    Returns [] if GPG not available or on any error.
    """
    if GPG_BIN is None:
        return []
    try:
        proc = subprocess.run(
            [GPG_BIN, "--list-secret-keys", "--with-colons"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        return []

    records = []
    current = None

    for line in proc.stdout.splitlines():
        parts = line.split(":")
        record_type = parts[0] if parts else ""

        if record_type == "sec":
            if current is not None:
                records.append(current)
            algo_id = parts[3] if len(parts) > 3 else ""
            key_size = parts[2] if len(parts) > 2 else ""
            validity = parts[1] if len(parts) > 1 else ""
            expiry_ts = parts[6] if len(parts) > 6 else ""
            if expiry_ts:
                try:
                    import datetime as _dt
                    expiry_str = _dt.datetime.fromtimestamp(
                        int(expiry_ts)
                    ).strftime("%Y-%m-%d")
                except (ValueError, OSError):
                    expiry_str = "never"
            else:
                expiry_str = "never"
            mapping = {"1": "RSA", "17": "DSA", "18": "ECDH", "22": "Ed25519"}
            algo_base = mapping.get(algo_id, f"algo-{algo_id}")
            if key_size and algo_id in ("1", "17"):
                algo_name = f"{algo_base}-{key_size}"
            else:
                algo_name = algo_base
            current = {
                "fingerprint": "",
                "uid": "",
                "algo": algo_name,
                "expired": validity == "e",
                "expiry": expiry_str,
                "has_encryption_subkey": False,
            }

        elif record_type == "fpr" and current is not None:
            if not current["fingerprint"]:
                current["fingerprint"] = (
                    parts[9].strip() if len(parts) > 9 else ""
                )

        elif record_type == "uid" and current is not None:
            if not current["uid"]:
                current["uid"] = parts[9].strip() if len(parts) > 9 else ""

        elif record_type == "ssb" and current is not None:
            validity = parts[1] if len(parts) > 1 else ""
            caps = parts[11] if len(parts) > 11 else ""
            if validity not in ("r", "e") and "e" in caps.lower():
                current["has_encryption_subkey"] = True

    if current is not None:
        records.append(current)

    return [
        {
            "fingerprint": r["fingerprint"],
            "uid": r["uid"],
            "algo": r["algo"],
            "expired": r["expired"],
            "expiry": r["expiry"],
        }
        for r in records
        if r["fingerprint"] and not r["has_encryption_subkey"]
    ]


def add_encryption_subkey(
    fingerprint: str,
    passphrase: str,
    expiry: str = "2y",
    timeout: int = 60,
) -> dict:
    """Add a Curve25519 encryption subkey to an existing key pair.

    fingerprint: full fingerprint of the primary key.
    passphrase: passphrase for the primary key.
    expiry: GPG-format expiry string e.g. "2y", "1y", "0".
    Returns {ok: bool, msg: str}
    """
    if GPG_BIN is None:
        return {"ok": False, "msg": "GPG is not installed."}

    commands = (
        "addkey\n"
        "12\n"
        "\n"
        f"{expiry}\n"
        f"{passphrase}\n"
        "save\n"
    )

    try:
        proc = subprocess.run(
            [
                GPG_BIN,
                "--yes",
                "--no-tty",
                "--command-fd", "0",
                "--pinentry-mode", "loopback",
                "--status-fd", "2",
                "--edit-key", fingerprint,
            ],
            input=commands,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        if proc.returncode == 0 or "[GNUPG:] KEY_CREATED" in output:
            return {"ok": True, "msg": "Encryption subkey added."}
        return {"ok": False, "msg": output or "Failed to add subkey."}
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": "GPG timed out."}
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "msg": str(e)}


def list_secret_keys_with_encryption_subkey() -> list[dict]:
    """List secret keys that have at least one active (non-revoked,
    non-expired) encryption subkey.
    Returns list of dicts:
      {fingerprint, uid, algo, expired,
       subkey_fingerprint, subkey_algo, subkey_expiry}
    subkey_fingerprint: fingerprint of the first active encryption subkey
    subkey_algo: algorithm name of that subkey
    subkey_expiry: expiry date string "YYYY-MM-DD" or "never"
    Returns [] if GPG not available or on any error.
    """
    if GPG_BIN is None:
        return []
    try:
        proc = subprocess.run(
            [GPG_BIN, "--list-secret-keys", "--with-colons"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        return []

    records = []
    current = None
    current_subkeys = []

    for line in proc.stdout.splitlines():
        parts = line.split(":")
        record_type = parts[0] if parts else ""

        if record_type == "sec":
            if current is not None:
                enc_subkeys = [
                    s for s in current_subkeys
                    if s["can_encrypt"]
                ]
                if enc_subkeys:
                    current["subkey_fingerprint"] = enc_subkeys[0]["fingerprint"]
                    current["subkey_algo"] = enc_subkeys[0]["algo"]
                    current["subkey_expiry"] = enc_subkeys[0]["expiry"]
                    records.append(current)
            algo_id = parts[3] if len(parts) > 3 else ""
            key_size = parts[2] if len(parts) > 2 else ""
            validity = parts[1] if len(parts) > 1 else ""
            expiry_ts = parts[6] if len(parts) > 6 else ""
            if expiry_ts:
                try:
                    import datetime as _dt
                    expiry_str = _dt.datetime.fromtimestamp(
                        int(expiry_ts)
                    ).strftime("%Y-%m-%d")
                except (ValueError, OSError):
                    expiry_str = "never"
            else:
                expiry_str = "never"
            mapping = {"1": "RSA", "17": "DSA", "18": "ECDH", "22": "Ed25519"}
            algo_base = mapping.get(algo_id, f"algo-{algo_id}")
            if key_size and algo_id in ("1", "17"):
                algo_name = f"{algo_base}-{key_size}"
            else:
                algo_name = algo_base
            current = {
                "fingerprint": "",
                "uid": "",
                "algo": algo_name,
                "expired": validity == "e",
                "expiry": expiry_str,
                "subkey_fingerprint": "",
                "subkey_algo": "",
                "subkey_expiry": "never",
            }
            current_subkeys = []

        elif record_type == "fpr" and current is not None:
            if not current["fingerprint"]:
                current["fingerprint"] = (
                    parts[9].strip() if len(parts) > 9 else ""
                )
            else:
                if current_subkeys:
                    current_subkeys[-1]["fingerprint"] = (
                        parts[9].strip() if len(parts) > 9 else ""
                    )

        elif record_type == "uid" and current is not None:
            if not current["uid"]:
                current["uid"] = parts[9].strip() if len(parts) > 9 else ""

        elif record_type == "ssb" and current is not None:
            validity = parts[1] if len(parts) > 1 else ""
            caps = parts[11] if len(parts) > 11 else ""
            algo_id = parts[3] if len(parts) > 3 else ""
            expiry_ts = parts[6] if len(parts) > 6 else ""
            mapping = {"1": "RSA", "17": "DSA", "18": "ECDH", "22": "Ed25519"}
            subkey_algo = mapping.get(algo_id, f"algo-{algo_id}")
            if expiry_ts:
                try:
                    import datetime as _dt
                    expiry_str = _dt.datetime.fromtimestamp(
                        int(expiry_ts)
                    ).strftime("%Y-%m-%d")
                except (ValueError, OSError):
                    expiry_str = "unknown"
            else:
                expiry_str = "never"
            can_encrypt = (
                validity not in ("r", "e") and "e" in caps.lower()
            )
            current_subkeys.append({
                "fingerprint": "",
                "algo": subkey_algo,
                "expiry": expiry_str,
                "can_encrypt": can_encrypt,
            })

    if current is not None:
        enc_subkeys = [s for s in current_subkeys if s["can_encrypt"]]
        if enc_subkeys:
            current["subkey_fingerprint"] = enc_subkeys[0]["fingerprint"]
            current["subkey_algo"] = enc_subkeys[0]["algo"]
            current["subkey_expiry"] = enc_subkeys[0]["expiry"]
            records.append(current)

    return [r for r in records if r["fingerprint"]]


def _get_active_encryption_subkey_index(
    fingerprint: str,
    timeout: int = 10,
) -> int:
    """Return the 1-based index of the first active encryption subkey.

    Reads --list-secret-keys --with-colons output for fingerprint.
    Counts all ssb: entries in order. Returns the index (1-based) of
    the first ssb entry that is not revoked (r) and not expired (e)
    and has encryption capability (e in caps field parts[11]).

    Returns 1 if GPG not available, on any error, or if no active
    encryption subkey found (caller handles the error via GPG output).
    """
    if GPG_BIN is None:
        return 1
    try:
        proc = subprocess.run(
            [GPG_BIN, "--list-secret-keys", "--with-colons", fingerprint],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        index = 0
        for line in proc.stdout.splitlines():
            parts = line.split(":")
            if parts[0] != "ssb":
                continue
            index += 1
            validity = parts[1] if len(parts) > 1 else ""
            caps = parts[11] if len(parts) > 11 else ""
            if validity in ("r", "e"):
                continue
            if "e" not in caps.lower():
                continue
            return index
    except (subprocess.SubprocessError, OSError, ValueError):
        pass
    return 1


def extend_key_expiry(
    fingerprint: str,
    passphrase: str,
    new_expiry: str = "2y",
    timeout: int = 60,
) -> dict:
    """Extend the expiry date on the primary key.

    fingerprint: full fingerprint of the primary key.
    passphrase: passphrase for the primary key.
    new_expiry: GPG-format expiry string e.g. "2y", "1y", "0".
    Returns {ok: bool, msg: str}

    Confirmed command sequence for GPG 2.4.4:
      expire       -> GET_LINE keyedit.prompt
      {new_expiry} -> GET_LINE keygen.valid
      {passphrase} -> GET_HIDDEN passphrase.enter
      save         -> GET_LINE keyedit.prompt
    """
    if GPG_BIN is None:
        return {"ok": False, "msg": "GPG is not installed."}

    commands = (
        "expire\n"
        f"{new_expiry}\n"
        f"{passphrase}\n"
        "save\n"
    )

    try:
        proc = subprocess.run(
            [
                GPG_BIN,
                "--yes",
                "--no-tty",
                "--command-fd", "0",
                "--pinentry-mode", "loopback",
                "--status-fd", "2",
                "--edit-key", fingerprint,
            ],
            input=commands,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode == 0:
            return {"ok": True, "msg": "Key expiry updated."}
        output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        return {"ok": False, "msg": output or "Failed to extend key expiry."}
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": "GPG timed out."}
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "msg": str(e)}


def rotate_encryption_subkey(
    fingerprint: str,
    passphrase: str,
    new_expiry: str = "2y",
    timeout: int = 60,
) -> dict:
    """Revoke the first active encryption subkey and add a new
    Curve25519 encryption subkey.

    fingerprint: full fingerprint of the primary key.
    passphrase: passphrase for the primary key.
    new_expiry: GPG-format expiry string e.g. "2y", "1y", "0".
    Returns {ok: bool, msg: str}
    """
    if GPG_BIN is None:
        return {"ok": False, "msg": "GPG is not installed."}

    subkey_index = _get_active_encryption_subkey_index(fingerprint)
    commands = (
        f"key {subkey_index}\n"
        "revkey\n"
        "y\n"
        "0\n"
        "\n"
        "y\n"
        f"{passphrase}\n"
        "addkey\n"
        "12\n"
        "\n"
        f"{new_expiry}\n"
        f"{passphrase}\n"
        "save\n"
    )

    try:
        proc = subprocess.run(
            [
                GPG_BIN,
                "--yes",
                "--no-tty",
                "--command-fd", "0",
                "--pinentry-mode", "loopback",
                "--status-fd", "2",
                "--edit-key", fingerprint,
            ],
            input=commands,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        if proc.returncode == 0 or "[GNUPG:] KEY_CREATED" in output:
            return {"ok": True, "msg": "Encryption subkey rotated."}
        return {"ok": False, "msg": output or "Failed to rotate subkey."}
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": "GPG timed out."}
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "msg": str(e)}


def extend_subkey_expiry(
    fingerprint: str,
    passphrase: str,
    new_expiry: str = "2y",
    timeout: int = 60,
) -> dict:
    """Extend the expiry date on the first active encryption subkey."""
    if GPG_BIN is None:
        return {"ok": False, "msg": "GPG is not installed."}

    subkey_index = _get_active_encryption_subkey_index(fingerprint)
    commands = (
        f"key {subkey_index}\n"
        "expire\n"
        f"{new_expiry}\n"
        f"{passphrase}\n"
        "save\n"
    )
    try:
        proc = subprocess.run(
            [
                GPG_BIN,
                "--yes",
                "--no-tty",
                "--command-fd", "0",
                "--pinentry-mode", "loopback",
                "--status-fd", "2",
                "--edit-key", fingerprint,
            ],
            input=commands,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        if proc.returncode == 0:
            return {"ok": True, "msg": "Subkey expiry updated."}
        return {"ok": False, "msg": output or "Failed to extend subkey expiry."}
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": "GPG timed out."}
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "msg": str(e)}


def verify_key_passphrase(
    fingerprint: str,
    passphrase: str,
    timeout: int = 30,
) -> dict:
    """Verify passphrase is correct for the given key.

    Uses --export-secret-keys which requires the correct passphrase.
    Returns {ok: bool, msg: str}
    """
    if GPG_BIN is None:
        return {"ok": False, "msg": "GPG is not installed."}

    try:
        proc = subprocess.run(
            [
                GPG_BIN,
                "--batch",
                "--passphrase-fd", "0",
                "--pinentry-mode", "loopback",
                "--armor",
                "--export-secret-keys",
                fingerprint,
            ],
            input=passphrase,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode == 0 and proc.stdout:
            return {"ok": True, "msg": "Passphrase verified."}
        return {"ok": False, "msg": "Bad passphrase."}
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": "GPG timed out."}
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "msg": str(e)}


def delete_key_pair(
    fingerprint: str,
    timeout: int = 30,
) -> dict:
    """Delete the secret and public key for fingerprint from the keyring.

    fingerprint: full fingerprint of the primary key.
    Returns {ok: bool, msg: str}
    """
    if GPG_BIN is None:
        return {"ok": False, "msg": "GPG is not installed."}

    try:
        proc = subprocess.run(
            [
                GPG_BIN,
                "--batch",
                "--yes",
                "--delete-secret-and-public-key",
                fingerprint,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode == 0:
            return {"ok": True, "msg": "Key pair deleted."}
        output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        return {"ok": False, "msg": output or "Failed to delete key pair."}
    except subprocess.TimeoutExpired:
        return {"ok": False, "msg": "GPG timed out."}
    except (subprocess.SubprocessError, OSError) as e:
        return {"ok": False, "msg": str(e)}
