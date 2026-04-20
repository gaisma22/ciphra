# test_gpg.py
# Tests for utils/gpg_tools.py.
# Covers: gpg_available true/false, verify_signature all status paths,
#   fetch_gpg_key success/failure/timeout, set_key_trust,
#   get_imported_key_fingerprint, import_and_trust_key,
#   list_encryption_keys, encrypt_file_asymmetric, get_encrypted_for_key_id.

import subprocess
from unittest.mock import MagicMock, patch

import pytest

import utils.gpg_tools as _gpg_module
from utils.gpg_tools import (
    gpg_available,
    verify_signature,
    fetch_gpg_key,
    set_key_trust,
    get_imported_key_fingerprint,
    import_and_trust_key,
    list_encryption_keys,
    encrypt_file_asymmetric,
    get_encrypted_for_key_id,
    generate_key_pair,
    list_signing_keys,
    sign_file_detached,
    export_public_key,
    export_private_key,
    list_signing_keys_without_encryption_subkey,
    add_encryption_subkey,
    list_secret_keys_with_encryption_subkey,
    rotate_encryption_subkey,
    extend_subkey_expiry,
    verify_key_passphrase,
    delete_key_pair,
    extend_key_expiry,
)


@pytest.fixture(autouse=True)
def clear_fp_cache():
    _gpg_module._fp_cache.clear()
    yield
    _gpg_module._fp_cache.clear()


def test_gpg_available_true():
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"):
        assert gpg_available() is True


def test_gpg_available_false_not_found():
    with patch("utils.gpg_tools.GPG_BIN", None):
        assert gpg_available() is False


def test_verify_signature_gpg_missing():
    with patch("utils.gpg_tools.gpg_available", return_value=False):
        result = verify_signature("any.file", "any.sig")
    assert result["ok"] is False
    assert result["status"] == "error"
    assert "not installed" in result["msg"]
    assert "key_id" in result


def test_verify_signature_verified(tmp_path):
    data_file = tmp_path / "test.bin"
    sig_file = tmp_path / "test.sig"
    data_file.write_bytes(b"test content")
    sig_file.write_bytes(b"fake sig bytes")
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = ""
    mock_proc.stderr = "Good signature"
    with patch("utils.gpg_tools.gpg_available", return_value=True), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = verify_signature(str(data_file), str(sig_file))
    assert result["ok"] is True
    assert result["status"] == "verified"
    assert "key_id" in result


def test_verify_signature_bad(tmp_path):
    data_file = tmp_path / "test.bin"
    sig_file = tmp_path / "test.sig"
    data_file.write_bytes(b"test content")
    sig_file.write_bytes(b"fake sig bytes")
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stdout = ""
    mock_proc.stderr = "BAD signature from ..."
    with patch("utils.gpg_tools.gpg_available", return_value=True), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = verify_signature(str(data_file), str(sig_file))
    assert result["ok"] is False
    assert result["status"] == "bad"
    assert "key_id" in result


def test_verify_signature_no_pubkey(tmp_path):
    data_file = tmp_path / "test.bin"
    sig_file = tmp_path / "test.sig"
    data_file.write_bytes(b"test content")
    sig_file.write_bytes(b"fake sig bytes")
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stdout = ""
    mock_proc.stderr = "gpg: Can't check signature: No public key"
    with patch("utils.gpg_tools.gpg_available", return_value=True), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = verify_signature(str(data_file), str(sig_file))
    assert result["ok"] is False
    assert result["status"] == "no_pubkey"
    assert "key_id" in result


def test_verify_signature_subprocess_timeout():
    """verify_signature returns error status when subprocess times out."""
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="gpg", timeout=30)):
        result = verify_signature("/fake/file.iso", "/fake/file.sig")
    assert result["status"] == "error"
    assert result["msg"] != ""


def test_verify_signature_timeout(tmp_path):
    data_file = tmp_path / "test.bin"
    sig_file = tmp_path / "test.sig"
    data_file.write_bytes(b"test content")
    sig_file.write_bytes(b"fake sig bytes")
    with patch("utils.gpg_tools.gpg_available", return_value=True), \
         patch("utils.gpg_tools.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="gpg", timeout=10)):
        result = verify_signature(str(data_file), str(sig_file))
    assert result["ok"] is False
    assert result["status"] == "error"
    assert "timed out" in result["msg"]


def test_verify_signature_generic_exception(tmp_path):
    data_file = tmp_path / "test.bin"
    sig_file = tmp_path / "test.sig"
    data_file.write_bytes(b"test content")
    sig_file.write_bytes(b"fake sig bytes")
    with patch("utils.gpg_tools.gpg_available", return_value=True), \
         patch("utils.gpg_tools.subprocess.run",
               side_effect=OSError("unexpected")):
        result = verify_signature(str(data_file), str(sig_file))
    assert result["ok"] is False
    assert result["status"] == "error"
    assert result["msg"] != ""


def test_verify_signature_no_pubkey_extracts_key_id(tmp_path):
    data_file = tmp_path / "test.bin"
    sig_file = tmp_path / "test.sig"
    data_file.write_bytes(b"test content")
    sig_file.write_bytes(b"fake sig bytes")
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stdout = ""
    mock_proc.stderr = (
        "gpg: using key CEB36DE785728E708F593B75C69FF0E4C08F8209\n"
        "gpg: Can't check signature: No public key"
    )
    with patch("utils.gpg_tools.gpg_available", return_value=True), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = verify_signature(str(data_file), str(sig_file))
    assert result["status"] == "no_pubkey"
    assert result["key_id"] == "CEB36DE785728E708F593B75C69FF0E4C08F8209"


def test_fetch_gpg_key_success():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "key imported"
    mock_proc.stderr = ""
    with patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = fetch_gpg_key("ABCD1234EF5678")
    assert result["ok"] is True
    assert "ABCD1234EF5678" in result["msg"]


def test_fetch_gpg_key_failure():
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stdout = ""
    mock_proc.stderr = "keyserver unreachable"
    with patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = fetch_gpg_key("ABCD1234EF5678")
    assert result["ok"] is False
    assert result["msg"] != ""


def test_fetch_gpg_key_timeout():
    with patch(
        "utils.gpg_tools.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="gpg", timeout=30),
    ):
        result = fetch_gpg_key("ABCD1234EF5678")
    assert result["ok"] is False
    assert "timed out" in result["msg"].lower()


def test_set_key_trust_success():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    with patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = set_key_trust("ABCD1234EF567890")
    assert result["ok"] is True


def test_set_key_trust_failure():
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stderr = b"no such key"
    with patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = set_key_trust("ABCD1234EF567890")
    assert result["ok"] is False
    assert result["msg"] != ""


def test_set_key_trust_timeout():
    with patch(
        "utils.gpg_tools.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="gpg", timeout=10),
    ):
        result = set_key_trust("ABCD1234EF567890")
    assert result["ok"] is False
    assert "timed out" in result["msg"].lower()


def test_get_imported_key_fingerprint_found():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "pub::-::-:::::::\nfpr:::::::::ABCD1234:\n"
    with patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = get_imported_key_fingerprint("fake.key")
    assert result == "ABCD1234"


def test_get_imported_key_fingerprint_not_found():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "pub::-::-:::::::\n"
    with patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = get_imported_key_fingerprint("fake.key")
    assert result is None


def test_import_and_trust_key_matched(tmp_path):
    key_file = tmp_path / "fake.key"
    key_file.write_bytes(b"fake key data")
    mock_import_proc = MagicMock()
    mock_import_proc.returncode = 0
    mock_import_proc.stderr = ""

    with patch(
        "utils.gpg_tools.get_imported_key_fingerprint",
        return_value="ABCD1234EF567890ABCD1234EF567890",
    ), patch(
        "utils.gpg_tools._check_key_in_keyring",
        return_value=False,
    ), patch(
        "utils.gpg_tools.subprocess.run",
        return_value=mock_import_proc,
    ), patch(
        "utils.gpg_tools.set_key_trust",
        return_value={"ok": True, "msg": "trusted"},
    ):
        result = import_and_trust_key(str(key_file), "ABCD1234EF567890")

    assert result["ok"] is True
    assert result["matched"] is True
    assert result["trust_set"] is True


def test_import_and_trust_key_mismatch(tmp_path):
    key_file = tmp_path / "fake.key"
    key_file.write_bytes(b"fake key data")
    mock_import_proc = MagicMock()
    mock_import_proc.returncode = 0
    mock_import_proc.stderr = ""

    with patch(
        "utils.gpg_tools.get_imported_key_fingerprint",
        return_value="FFFFFFFF00000000DEADBEEF12345678",
    ), patch(
        "utils.gpg_tools._check_key_in_keyring",
        return_value=False,
    ), patch(
        "utils.gpg_tools.subprocess.run",
        return_value=mock_import_proc,
    ):
        result = import_and_trust_key(str(key_file), "ABCD1234EF567890")

    assert result["ok"] is True
    assert result["matched"] is False
    assert result["mismatch_warning"] is not None


def test_import_and_trust_key_already_in_keyring(tmp_path):
    # Key is already in keyring -- should return early without importing.
    key_file = tmp_path / "fake.key"
    key_file.write_bytes(b"fake key data")

    with patch(
        "utils.gpg_tools.get_imported_key_fingerprint",
        return_value="ABCD1234EF567890ABCD1234EF567890",
    ), patch(
        "utils.gpg_tools._check_key_in_keyring",
        return_value=True,
    ):
        result = import_and_trust_key(str(key_file), "ABCD1234EF567890")

    assert result["ok"] is True
    assert result["already_imported"] is True


def test_import_and_trust_key_file_not_found():
    result = import_and_trust_key("nonexistent.key", "ABCD1234")
    assert result["ok"] is False
    assert "not found" in result["msg"].lower()


def test_import_and_trust_key_subprocess_raises_oserror(tmp_path):
    """import_and_trust_key returns ok=False when subprocess raises OSError."""
    key_file = tmp_path / "fake.asc"
    key_file.write_text("fake key content")

    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run") as mock_run:

        # First call is get_imported_key_fingerprint (returns empty)
        # Second call is the --import call that raises OSError
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),
            OSError("Permission denied"),
        ]

        result = import_and_trust_key(str(key_file), None)

    assert result["ok"] is False
    assert result["trust_set"] is False


def test_verify_signature_trust_full(tmp_path):
    # GPG writes [GNUPG:] TRUST_FULLY to stderr when the key has full trust set.
    # Verify that verify_signature parses the status line and returns trust="full".
    data_file = tmp_path / "test.bin"
    sig_file = tmp_path / "test.sig"
    data_file.write_bytes(b"test content")
    sig_file.write_bytes(b"fake sig bytes")
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = ""
    mock_proc.stderr = (
        "gpg: Good signature from \"Test User <test@example.com>\"\n"
        "[GNUPG:] TRUST_FULLY 0 pgp"
    )
    with patch("utils.gpg_tools.gpg_available", return_value=True), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = verify_signature(str(data_file), str(sig_file))
    assert result["ok"] is True
    assert result["status"] == "verified"
    assert result["trust"] == "full"


def test_verify_signature_validsig_fingerprint(tmp_path):
    # GPG writes [GNUPG:] VALIDSIG with the fingerprint as the third field.
    # Verify that verify_signature extracts the fingerprint correctly.
    data_file = tmp_path / "test.bin"
    sig_file = tmp_path / "test.sig"
    data_file.write_bytes(b"test content")
    sig_file.write_bytes(b"fake sig bytes")
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = ""
    mock_proc.stderr = (
        "gpg: Good signature from \"Test User <test@example.com>\"\n"
        "[GNUPG:] VALIDSIG ABC123DEF456ABC123DEF456ABC123DEF456ABCD 2024-01-01 1234567890"
    )
    with patch("utils.gpg_tools.gpg_available", return_value=True), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = verify_signature(str(data_file), str(sig_file))
    assert result["ok"] is True
    assert result["status"] == "verified"
    assert result["fingerprint"] == "ABC123DEF456ABC123DEF456ABC123DEF456ABCD"


def test_list_encryption_keys_returns_empty_when_gpg_missing():
    with patch("utils.gpg_tools.GPG_BIN", None):
        result = list_encryption_keys()
    assert result == []


def test_list_encryption_keys_parses_colons_output():
    # Realistic --list-keys --with-colons output for a key with an encryption subkey.
    # list_encryption_keys() returns {"fingerprint": ..., "uid": ...} per entry.
    # The sub line has "e" in position 8 (capabilities), so this key is included.
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = (
        "pub:u:4096:1:ABCD1234ABCD1234:2024-01-01:::scSC:\n"
        "fpr:::::::::AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD:\n"
        "uid:u::::2024-01-01::HASH::Test User <test@example.com>:\n"
        "sub:u:4096:1:EEEE1234EEEE1234:2024-01-01:::e:\n"
    )
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = list_encryption_keys()
    assert len(result) == 1
    assert result[0]["fingerprint"] == "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD"
    assert "Test User" in result[0]["uid"]
    assert "test@example.com" in result[0]["uid"]


def test_encrypt_file_asymmetric_success():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = ""
    mock_proc.stderr = ""
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = encrypt_file_asymmetric(
            "/fake/input.txt", "/fake/output.gpg", "AABBCCDDAABBCCDD"
        )
    assert result["ok"] is True
    assert "encrypted" in result["msg"].lower()


def test_encrypt_file_asymmetric_gpg_missing():
    with patch("utils.gpg_tools.GPG_BIN", None):
        result = encrypt_file_asymmetric(
            "/fake/input.txt", "/fake/output.gpg", "AABBCCDDAABBCCDD"
        )
    assert result["ok"] is False
    assert "gpg" in result["msg"].lower() or "not installed" in result["msg"].lower()


def test_get_encrypted_for_key_id_returns_none_when_gpg_missing():
    with patch("utils.gpg_tools.GPG_BIN", None):
        result = get_encrypted_for_key_id("/fake/file.gpg")
    assert result is None


def test_get_encrypted_for_key_id_parses_keyid():
    # gpg --list-packets output contains a keyid line; function returns it uppercased.
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = ":pubkey enc packet: version 3, algo 1, keyid ABCD1234ABCD1234\n"
    mock_proc.stderr = ""
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = get_encrypted_for_key_id("/fake/file.gpg")
    assert result == "ABCD1234ABCD1234"


def test_generate_key_pair_gpg_missing():
    with patch("utils.gpg_tools.GPG_BIN", None):
        result = generate_key_pair("Test", "test@test.com", "2y", "pass")
    assert result["ok"] is False
    assert "not installed" in result["msg"].lower() or "GPG" in result["msg"]
    assert result["fingerprint"] is None


def test_generate_key_pair_success():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stderr = (
        "[GNUPG:] KEY_CREATED P AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD\n"
    )
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = generate_key_pair("Test User", "test@test.com", "2y", "passphrase")
    assert result["ok"] is True
    assert result["fingerprint"] == "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD"


def test_generate_key_pair_failure():
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stderr = "gpg: key generation failed"
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = generate_key_pair("Test User", "test@test.com", "2y", "passphrase")
    assert result["ok"] is False
    assert result["fingerprint"] is None


def test_list_signing_keys_gpg_missing():
    with patch("utils.gpg_tools.GPG_BIN", None):
        result = list_signing_keys()
    assert result == []


def test_list_signing_keys_parses_output():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = (
        "sec:-:255:22:ABCD1234ABCD1234:2024-01-01:::-:::scESCA:\n"
        "fpr:::::::::AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD:\n"
        "uid:-::::2024-01-01::HASH::Test User <test@example.com>:\n"
    )
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = list_signing_keys()
    assert len(result) == 1
    assert result[0]["fingerprint"] == "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD"
    assert result[0]["expired"] is False
    assert "Ed25519" in result[0]["algo"]


def test_sign_file_detached_gpg_missing():
    with patch("utils.gpg_tools.GPG_BIN", None):
        result = sign_file_detached("/fake/input.txt", "/fake/output.asc",
                                    "AABBCCDD", "passphrase")
    assert result["ok"] is False


def test_sign_file_detached_success():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = sign_file_detached("/fake/input.txt", "/fake/output.asc",
                                    "AABBCCDD", "passphrase")
    assert result["ok"] is True


def test_sign_file_detached_wrong_passphrase():
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stderr = "gpg: signing failed: Bad passphrase"
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = sign_file_detached("/fake/input.txt", "/fake/output.asc",
                                    "AABBCCDD", "wrongpass")
    assert result["ok"] is False
    assert "passphrase" in result["msg"].lower() or result["msg"] != ""


def test_export_public_key_gpg_missing():
    with patch("utils.gpg_tools.GPG_BIN", None):
        result = export_public_key("AABBCCDD", "/fake/key-public.asc")
    assert result["ok"] is False


def test_export_public_key_success(tmp_path):
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfakedata\n"
    mock_proc.stderr = ""
    output_file = tmp_path / "key-public.asc"
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = export_public_key("AABBCCDD", str(output_file))
    assert result["ok"] is True
    assert output_file.exists()
    assert output_file.read_text().startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")


def test_export_private_key_gpg_missing():
    with patch("utils.gpg_tools.GPG_BIN", None):
        result = export_private_key("AABBCCDD", "/fake/output.asc")
    assert result["ok"] is False
    assert "not installed" in result["msg"].lower() or "GPG" in result["msg"]


def test_export_private_key_success(tmp_path):
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nfakedata\n"
    mock_proc.stderr = ""
    output_file = tmp_path / "key-private.asc"
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = export_private_key("AABBCCDD", str(output_file))
    assert result["ok"] is True
    assert output_file.exists()
    assert output_file.read_text().startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----")


def test_list_signing_keys_without_encryption_subkey_gpg_missing():
    with patch("utils.gpg_tools.GPG_BIN", None):
        result = list_signing_keys_without_encryption_subkey()
    assert result == []


def test_list_signing_keys_without_encryption_subkey_returns_signing_only():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = (
        "sec:u:255:22:AABBCCDD11223344:2024-01-01:::u:::scESC:\n"
        "fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:\n"
        "uid:u::::2024-01-01::HASH::Test User <test@example.com>::::::::::0:\n"
    )
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = list_signing_keys_without_encryption_subkey()
    assert len(result) == 1
    assert result[0]["uid"] == "Test User <test@example.com>"
    assert result[0]["algo"] == "Ed25519"


def test_list_signing_keys_without_encryption_subkey_excludes_with_subkey():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = (
        "sec:u:255:22:AABBCCDD11223344:2024-01-01:::u:::scESC:\n"
        "fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:\n"
        "uid:u::::2024-01-01::HASH::Test User <test@example.com>::::::::::0:\n"
        "ssb:u:255:18:1122334455667788:2024-01-01::::::e:\n"
    )
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = list_signing_keys_without_encryption_subkey()
    assert result == []


def test_add_encryption_subkey_gpg_missing():
    with patch("utils.gpg_tools.GPG_BIN", None):
        result = add_encryption_subkey("AABBCCDD", "passphrase")
    assert result["ok"] is False
    assert "not installed" in result["msg"].lower() or "GPG" in result["msg"]


def test_add_encryption_subkey_success():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = ""
    mock_proc.stderr = "[GNUPG:] KEY_CREATED S AABBCCDD11223344AABBCCDD11223344AABBCCDD\n"
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = add_encryption_subkey("AABBCCDD", "passphrase", "2y")
    assert result["ok"] is True


def test_add_encryption_subkey_failure():
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stdout = ""
    mock_proc.stderr = "gpg: bad passphrase\n"
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = add_encryption_subkey("AABBCCDD", "wrongpass", "2y")
    assert result["ok"] is False


def test_list_secret_keys_with_encryption_subkey_gpg_missing():
    with patch("utils.gpg_tools.GPG_BIN", None):
        result = list_secret_keys_with_encryption_subkey()
    assert result == []


def test_list_secret_keys_with_encryption_subkey_returns_key():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = (
        "sec:u:255:22:AABBCCDD11223344:2024-01-01:::u:::scESC:\n"
        "fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:\n"
        "uid:u::::2024-01-01::HASH::Test User <test@example.com>::::::::::0:\n"
        "ssb:u:255:18:1122334455667788:2024-01-01::::::e:\n"
        "fpr:::::::::1122334455667788112233445566778811223344:\n"
    )
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = list_secret_keys_with_encryption_subkey()
    assert len(result) == 1
    assert result[0]["uid"] == "Test User <test@example.com>"


def test_list_secret_keys_with_encryption_subkey_excludes_signing_only():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = (
        "sec:u:255:22:AABBCCDD11223344:2024-01-01:::u:::scESC:\n"
        "fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:\n"
        "uid:u::::2024-01-01::HASH::Test User <test@example.com>::::::::::0:\n"
    )
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = list_secret_keys_with_encryption_subkey()
    assert result == []


def test_rotate_encryption_subkey_gpg_missing():
    with patch("utils.gpg_tools.GPG_BIN", None):
        result = rotate_encryption_subkey("AABBCCDD", "passphrase")
    assert result["ok"] is False
    assert "not installed" in result["msg"].lower() or "GPG" in result["msg"]


def test_rotate_encryption_subkey_success():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = ""
    mock_proc.stderr = "[GNUPG:] KEY_CREATED S AABBCCDD11223344AABBCCDD11223344AABBCCDD\n"
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = rotate_encryption_subkey("AABBCCDD", "passphrase", "2y")
    assert result["ok"] is True


def test_rotate_encryption_subkey_failure():
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stdout = ""
    mock_proc.stderr = "gpg: bad passphrase\n"
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = rotate_encryption_subkey("AABBCCDD", "wrongpass", "2y")
    assert result["ok"] is False


def test_extend_subkey_expiry_gpg_missing():
    with patch("utils.gpg_tools.GPG_BIN", None):
        result = extend_subkey_expiry("AABBCCDD", "passphrase")
    assert result["ok"] is False
    assert "not installed" in result["msg"].lower() or "GPG" in result["msg"]


def test_extend_subkey_expiry_success():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = ""
    mock_proc.stderr = ""
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = extend_subkey_expiry("AABBCCDD", "passphrase", "2y")
    assert result["ok"] is True
    assert result["msg"] == "Subkey expiry updated."


def test_extend_subkey_expiry_failure():
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stdout = ""
    mock_proc.stderr = "gpg: bad passphrase\n"
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = extend_subkey_expiry("AABBCCDD", "wrongpass", "2y")
    assert result["ok"] is False


def test_verify_key_passphrase_gpg_missing():
    with patch("utils.gpg_tools.GPG_BIN", None):
        result = verify_key_passphrase("AABBCCDD", "passphrase")
    assert result["ok"] is False


def test_verify_key_passphrase_success():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nfakedata\n"
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = verify_key_passphrase("AABBCCDD", "correctpass")
    assert result["ok"] is True


def test_verify_key_passphrase_wrong():
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stdout = ""
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = verify_key_passphrase("AABBCCDD", "wrongpass")
    assert result["ok"] is False


def test_delete_key_pair_gpg_missing():
    with patch("utils.gpg_tools.GPG_BIN", None):
        result = delete_key_pair("AABBCCDD")
    assert result["ok"] is False


def test_delete_key_pair_success():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = ""
    mock_proc.stderr = ""
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = delete_key_pair("AABBCCDD")
    assert result["ok"] is True


def test_delete_key_pair_failure():
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stdout = ""
    mock_proc.stderr = "gpg: key not found\n"
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = delete_key_pair("AABBCCDD")
    assert result["ok"] is False


def test_extend_key_expiry_gpg_missing():
    with patch("utils.gpg_tools.GPG_BIN", None):
        result = extend_key_expiry("AABBCCDD", "passphrase")
    assert result["ok"] is False


def test_extend_key_expiry_success():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = ""
    mock_proc.stderr = ""
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = extend_key_expiry("AABBCCDD", "passphrase", "2y")
    assert result["ok"] is True


def test_extend_key_expiry_failure():
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stdout = ""
    mock_proc.stderr = "gpg: signing failed: Bad passphrase\n"
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"), \
         patch("utils.gpg_tools.subprocess.run", return_value=mock_proc):
        result = extend_key_expiry("AABBCCDD", "wrongpass", "2y")
    assert result["ok"] is False
