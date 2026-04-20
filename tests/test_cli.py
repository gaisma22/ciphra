# test_cli.py
# CLI integration tests using click's CliRunner.
# Covers: hash command, verify --no-vt, config --show.

import hashlib
import os
import tempfile
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from ciphra import cli
from utils.verdict_tools import VERDICT_CHECKED


def _make_file(tmp_path, content=b"ciphra test"):
    f = tmp_path / "testfile.bin"
    f.write_bytes(content)
    return str(f)


# Suppress first_run_check and check_dirs for all CLI tests
# by patching them at module level via autouse fixture.
@pytest.fixture(autouse=True)
def _patch_startup(tmp_path):
    fake_config = tmp_path / "config.json"
    fake_config.write_text("{}")
    with patch("ciphra.first_run_check"), \
         patch("ciphra.check_dirs"), \
         patch("ciphra.setup_logging"):
        yield


def test_hash_command_known_file(tmp_path):
    fp = _make_file(tmp_path)
    expected = hashlib.sha256(b"ciphra test").hexdigest()
    runner = CliRunner()
    result = runner.invoke(cli, ["hash", fp])
    assert result.exit_code == 0, result.output
    assert expected in result.output


def test_hash_command_algo_md5(tmp_path):
    fp = _make_file(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["hash", fp, "--algo", "md5"])
    assert result.exit_code == 0, result.output
    assert "MD5" in result.output


def test_verify_no_vt_no_sig(tmp_path):
    fp = _make_file(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["verify", fp, "--no-vt"])
    assert result.exit_code == 0, result.output
    output_lower = result.output.lower()
    assert "sha256" in output_lower
    assert VERDICT_CHECKED in result.output
    expected_hash = hashlib.sha256(b"ciphra test").hexdigest()
    assert expected_hash in result.output


def test_config_show(tmp_path):
    runner = CliRunner()
    with patch("ciphra.get_vt_key", return_value=None), \
         patch("ciphra.get_vt_tier", return_value="free"), \
         patch("ciphra.get_vt_upload_limit", return_value=32 * 1024 * 1024):
        result = runner.invoke(cli, ["config", "--show"])
    assert result.exit_code == 0, result.output
    assert "1.3.0" in result.output
    assert "VirusTotal API key" in result.output
    assert "not set" in result.output
    assert "not configured" in result.output
    assert "GPG" in result.output


def test_config_show_with_key(tmp_path):
    runner = CliRunner()
    with patch("ciphra.get_vt_key", return_value="a" * 64), \
         patch("ciphra.get_vt_tier", return_value="free"), \
         patch("ciphra.get_vt_upload_limit", return_value=32 * 1024 * 1024):
        result = runner.invoke(cli, ["config", "--show"])
    assert result.exit_code == 0, result.output
    assert "aaaa" in result.output  # First 4 chars of key visible
    assert "free" in result.output
    assert "32 MB" in result.output
    assert "VirusTotal API key" in result.output


def test_hash_nonexistent_file():
    runner = CliRunner()
    result = runner.invoke(cli, ["hash", "nonexistent_xyz_abc.bin"])
    assert result.exit_code != 0


def test_verify_nonexistent_file():
    runner = CliRunner()
    result = runner.invoke(cli, ["verify", "nonexistent_xyz.bin", "--no-vt"])
    assert (
        result.exit_code != 0
        or "not found" in result.output.lower()
        or "no such file" in result.output.lower()
    )


def test_encrypt_decrypt_command_registered():
    # encrypt-decrypt must be a registered Click command and respond to --help.
    runner = CliRunner()
    result = runner.invoke(cli, ["encrypt-decrypt", "--help"])
    assert result.exit_code == 0
    assert "Encrypt" in result.output or "decrypt" in result.output.lower()


def test_digital_signatures_command_registered():
    runner = CliRunner()
    result = runner.invoke(cli, ["digital-signatures", "--help"])
    assert result.exit_code == 0
    assert "signature" in result.output.lower() or "digital" in result.output.lower()


def test_detect_format_unknown_for_plaintext(tmp_path):
    # detect_format must return "unknown" for a file that is not encrypted.
    from utils.crypto_tools import detect_format
    fp = tmp_path / "plain.txt"
    fp.write_bytes(b"this is not encrypted at all")
    assert detect_format(str(fp)) == "unknown"


def test_detect_format_known_formats(tmp_path):
    # detect_format must return the correct format for each recognized magic header.
    from utils.crypto_tools import detect_format, MAGIC_HEADER
    ciphra_file = tmp_path / "sample.ciphra"
    ciphra_file.write_bytes(MAGIC_HEADER + b"\x00" * 50)
    assert detect_format(str(ciphra_file)) == "ciphra"

    gpg_armored = tmp_path / "message.asc"
    gpg_armored.write_bytes(b"-----BEGIN PGP MESSAGE-----\nfakedata")
    assert detect_format(str(gpg_armored)) == "gpg"

    gpg_binary = tmp_path / "message.gpg"
    gpg_binary.write_bytes(b"\x85\x00\x00\x00")
    assert detect_format(str(gpg_binary)) == "gpg"


def test_encrypt_symmetric_calls_write_operation_log(tmp_path):
    # write_operation_log must be called after a successful symmetric encryption.
    import ciphra as ciphra_module
    fp = _make_file(tmp_path)

    with patch("ciphra.questionary.password") as mock_pw, \
         patch("ciphra.questionary.text") as mock_text, \
         patch("ciphra._crypto_encrypt_file") as mock_encrypt, \
         patch("ciphra.write_operation_log") as mock_log, \
         patch("ciphra.compute_hash", return_value="a" * 64), \
         patch("ciphra.calibrate_argon2_params", return_value=(3, 65536, 1)), \
         patch("ciphra.derive_key", return_value=b"\x00" * 32):

        mock_pw.return_value.ask.return_value = "correctpassword"
        mock_text.return_value.ask.return_value = str(tmp_path / "out.ciphra")
        mock_encrypt.return_value = None

        ciphra_module._encrypt_symmetric(fp)

    mock_log.assert_called_once()
    call_args = mock_log.call_args[0]
    assert call_args[0] == "testfile.bin"
    assert len(call_args[1]) == 64
    assert call_args[2] == "encrypt"
    assert call_args[3] == "ok"


def test_run_verify_keyserver_fetch_recovery(tmp_path):
    """When verify_signature returns no_pubkey, ciphra fetches the key
    from keyserver and calls verify_signature a second time."""
    import ciphra as ciphra_module

    fp = _make_file(tmp_path)

    # Create a fake .sig file so sig validation passes
    sig_path = tmp_path / "testfile.bin.sig"
    sig_path.write_bytes(b"fake sig content")

    no_pubkey_result = {
        "status": "no_pubkey",
        "key_id": "ABCD1234ABCD1234",
        "fingerprint": None,
        "trust": None,
        "msg": "Missing public key.",
    }
    verified_result = {
        "status": "verified",
        "key_id": "ABCD1234ABCD1234",
        "fingerprint": "A" * 40,
        "trust": "unknown",
        "msg": "",
    }
    fetch_ok = {
        "ok": True,
        "msg": "Key imported.",
        "in_keyring": True,
    }

    with patch("ciphra.verify_signature",
               side_effect=[no_pubkey_result, verified_result]) as mock_verify, \
         patch("ciphra.fetch_gpg_key", return_value=fetch_ok) as mock_fetch, \
         patch("ciphra.get_vt_key", return_value=None), \
         patch("ciphra.GPG_BIN", "/usr/bin/gpg"), \
         patch("ciphra.questionary.select") as mock_select, \
         patch("ciphra.write_scan_log"):

        # Simulate user choosing "Fetch key from keyserver automatically"
        mock_select.return_value.ask.return_value = (
            "Fetch key from keyserver automatically"
        )

        ciphra_module._run_verify(
            file=str(fp),
            sig=str(sig_path),
            vt=False,
            algo="sha256",
            expected=None,
        )

    # verify_signature must be called twice:
    # once for the initial check (returns no_pubkey)
    # once after keyserver fetch (returns verified)
    assert mock_verify.call_count == 2
    # Both calls must use the same file and sig paths
    first_call_args = mock_verify.call_args_list[0][0]
    second_call_args = mock_verify.call_args_list[1][0]
    assert first_call_args[0] == str(fp)
    assert second_call_args[0] == str(fp)
    # fetch_gpg_key must be called once with the correct key ID
    assert mock_fetch.call_count == 1
    assert mock_fetch.call_args[0][0] == "ABCD1234ABCD1234"
