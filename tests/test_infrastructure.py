# test_infrastructure.py
# Tests for infrastructure added in the 1.0.0 rewrite.
# Covers: _translate_error, _supports_unicode, UNICODE_OK,
#         GPG_BIN, _find_gpg, gpg_available, VT transparency logic.

from unittest.mock import patch
import pytest

from config import get_vt_upload_limit


# --- _translate_error ---

def test_translate_error_known_gpg_no_data():
    from ciphra import _translate_error
    result = _translate_error("no valid OpenPGP data found")
    assert "GPG key" in result or "contain" in result.lower()


def test_translate_error_http_401():
    from ciphra import _translate_error
    result = _translate_error("http_401")
    assert "API key" in result or "rejected" in result.lower()


def test_translate_error_http_429():
    from ciphra import _translate_error
    result = _translate_error("http_429")
    assert "rate" in result.lower() or "limit" in result.lower()


def test_translate_error_network_error():
    from ciphra import _translate_error
    result = _translate_error("network_error")
    assert "network" in result.lower() or "connection" in result.lower()


def test_translate_error_permission_denied():
    from ciphra import _translate_error
    result = _translate_error("permission denied")
    assert "permission" in result.lower()


def test_translate_error_empty_string():
    from ciphra import _translate_error
    result = _translate_error("")
    assert "unexpected" in result.lower() or "ciphra.log" in result


def test_translate_error_unknown_falls_back():
    from ciphra import _translate_error
    result = _translate_error("some completely unknown error xyz123abc")
    assert "ciphra.log" in result


def test_translate_error_context_prefix():
    from ciphra import _translate_error
    result = _translate_error("http_401", context="VirusTotal")
    assert result.startswith("VirusTotal:")


def test_translate_error_invalid_tag():
    from ciphra import _translate_error
    result = _translate_error("invalid tag")
    assert "password" in result.lower() or "tampered" in result.lower()


def test_translate_error_bad_passphrase():
    from ciphra import _translate_error
    result = _translate_error("bad passphrase")
    assert "passphrase" in result.lower() or "wrong" in result.lower()


# --- _supports_unicode and UNICODE_OK ---

def test_supports_unicode_returns_bool():
    from ciphra import _supports_unicode
    result = _supports_unicode()
    assert isinstance(result, bool)


def test_unicode_ok_is_bool():
    from ciphra import UNICODE_OK
    assert isinstance(UNICODE_OK, bool)


def test_supports_unicode_false_on_ascii():
    from ciphra import _supports_unicode
    with patch("sys.stdout") as mock_stdout:
        mock_stdout.encoding = "ascii"
        result = _supports_unicode()
    assert result is False


def test_supports_unicode_false_on_none():
    from ciphra import _supports_unicode
    with patch("sys.stdout") as mock_stdout:
        mock_stdout.encoding = None
        result = _supports_unicode()
    assert result is False


# --- GPG_BIN and _find_gpg ---

def test_gpg_bin_is_string_or_none():
    from utils.gpg_tools import GPG_BIN
    assert GPG_BIN is None or isinstance(GPG_BIN, str)


def test_gpg_available_true_when_bin_set():
    from utils.gpg_tools import gpg_available
    with patch("utils.gpg_tools.GPG_BIN", "/usr/bin/gpg"):
        assert gpg_available() is True


def test_gpg_available_false_when_bin_none():
    from utils.gpg_tools import gpg_available
    with patch("utils.gpg_tools.GPG_BIN", None):
        assert gpg_available() is False


def test_find_gpg_returns_none_when_nothing_found():
    from utils.gpg_tools import _find_gpg
    with patch("utils.gpg_tools._shutil.which", return_value=None), \
         patch("os.path.isfile", return_value=False):
        result = _find_gpg()
    assert result is None


def test_find_gpg_returns_gpg_on_path():
    from utils.gpg_tools import _find_gpg
    def mock_which(binary):
        return "/usr/bin/gpg" if binary == "gpg" else None
    with patch("utils.gpg_tools._shutil.which", side_effect=mock_which):
        result = _find_gpg()
    assert result == "gpg"


def test_find_gpg_falls_back_to_gpg2():
    from utils.gpg_tools import _find_gpg
    def mock_which(binary):
        return "/usr/bin/gpg2" if binary == "gpg2" else None
    with patch("utils.gpg_tools._shutil.which", side_effect=mock_which):
        result = _find_gpg()
    assert result == "gpg2"


# --- VT upload limit logic ---

def test_vt_upload_limit_default_is_free():
    """get_vt_upload_limit() returns 32 MB when no config exists."""
    import json
    import tempfile
    import pathlib
    with tempfile.TemporaryDirectory() as tmp:
        config_path = pathlib.Path(tmp) / "config.json"
        with patch("config.get_config_path", return_value=config_path), \
             patch("config._cache", {}):
            limit = get_vt_upload_limit()
    assert limit == 32 * 1024 * 1024


def test_vt_upload_limit_free_stored():
    """get_vt_upload_limit() returns 32 MB when tier is stored as free."""
    import json
    import tempfile
    import pathlib
    with tempfile.TemporaryDirectory() as tmp:
        config_path = pathlib.Path(tmp) / "config.json"
        config_path.write_text(json.dumps({
            "vt_tier": "free",
            "vt_upload_limit": 32 * 1024 * 1024,
        }))
        with patch("config.get_config_path", return_value=config_path), \
             patch("config._cache", {}):
            limit = get_vt_upload_limit()
    assert limit == 32 * 1024 * 1024


def test_vt_upload_limit_premium_stored():
    """get_vt_upload_limit() returns 650 MB when tier is stored as premium."""
    import json
    import tempfile
    import pathlib
    with tempfile.TemporaryDirectory() as tmp:
        config_path = pathlib.Path(tmp) / "config.json"
        config_path.write_text(json.dumps({
            "vt_tier": "premium",
            "vt_upload_limit": 650 * 1024 * 1024,
        }))
        with patch("config.get_config_path", return_value=config_path), \
             patch("config._cache", {}):
            limit = get_vt_upload_limit()
    assert limit == 650 * 1024 * 1024


def test_vt_hash_only_logic_free():
    """File over free limit triggers hash-only path."""
    import json
    import tempfile
    import pathlib
    with tempfile.TemporaryDirectory() as tmp:
        config_path = pathlib.Path(tmp) / "config.json"
        config_path.write_text(json.dumps({
            "vt_tier": "free",
            "vt_upload_limit": 32 * 1024 * 1024,
        }))
        with patch("config.get_config_path", return_value=config_path), \
             patch("config._cache", {}):
            limit = get_vt_upload_limit()
    large_file_size = 100 * 1024 * 1024
    small_file_size = 10 * 1024 * 1024
    assert large_file_size > limit   # hash only
    assert small_file_size <= limit  # would be uploaded
