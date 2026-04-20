# test_config.py
# Tests for config.py credential manager.
# Covers: get_config_path, load_credentials,
#   save_credentials, get_vt_key, set_vt_key.

import sys
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

import config as _config_module
from config import (
    get_config_path,
    get_vt_key,
    load_credentials,
    save_credentials,
    set_vt_key,
)


@pytest.fixture(autouse=True)
def clear_config_cache():
    _config_module._cache.clear()
    yield
    _config_module._cache.clear()


def test_get_config_path_linux():
    with patch("os.name", "posix"):
        path = get_config_path()
    assert path.parts[-1] == "config.json"
    assert path.parts[-2] == ".ciphra"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows path test, runs on Windows only")
def test_get_config_path_windows():
    appdata = "C:\\Users\\test\\AppData\\Roaming"
    with patch("os.name", "nt"), \
         patch.dict(os.environ, {"APPDATA": appdata}):
        path = get_config_path()
    path_str = str(path)
    assert "ciphra" in path_str
    assert "config.json" in path_str


def test_load_credentials_missing_file():
    with patch("builtins.open", side_effect=FileNotFoundError):
        result = load_credentials()
    assert result == {}


def test_load_credentials_valid_json():
    data = '{"vt_key": "testkey123"}'
    with patch("builtins.open", mock_open(read_data=data)):
        result = load_credentials()
    assert result == {"vt_key": "testkey123"}


def test_load_credentials_bad_json():
    bad_data = "not valid json{{"
    with patch("builtins.open", mock_open(read_data=bad_data)):
        result = load_credentials()
    assert result == {}


def test_get_vt_key_present():
    with patch("config.load_credentials", return_value={"vt_key": "mykey"}):
        result = get_vt_key()
    assert result == "mykey"


def test_get_vt_key_missing():
    with patch("config.load_credentials", return_value={}):
        result = get_vt_key()
    assert result is None


def test_set_vt_key():
    mock_save = MagicMock()
    with patch("config.load_credentials", return_value={}), \
         patch("config.save_credentials", mock_save):
        set_vt_key("newkey")
    mock_save.assert_called_once_with({"vt_key": "newkey"})


def test_remove_vt_key_clears_all_three_fields(tmp_path):
    """remove_vt_key() must clear vt_key, vt_tier, and vt_upload_limit."""
    import json
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "vt_key": "a" * 64,
        "vt_tier": "free",
        "vt_upload_limit": 32 * 1024 * 1024,
    }))
    with patch("config.get_config_path", return_value=config_path), \
         patch("config._cache", {}):
        from config import remove_vt_key
        remove_vt_key()
        with patch("config._cache", {}):
            from config import load_credentials
            creds = load_credentials()
    assert "vt_key" not in creds
    assert "vt_tier" not in creds
    assert "vt_upload_limit" not in creds


def test_remove_vt_key_when_no_key_set(tmp_path):
    """remove_vt_key() is safe to call when no key is configured."""
    import json
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({}))
    with patch("config.get_config_path", return_value=config_path), \
         patch("config._cache", {}):
        from config import remove_vt_key
        remove_vt_key()  # Must not raise


def test_set_vt_tier_free(tmp_path):
    """set_vt_tier('free') stores tier and 32 MB upload limit."""
    import json
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({}))
    with patch("config.get_config_path", return_value=config_path), \
         patch("config._cache", {}):
        from config import set_vt_tier, get_vt_tier, get_vt_upload_limit
        set_vt_tier("free")
        with patch("config._cache", {}):
            assert get_vt_tier() == "free"
            assert get_vt_upload_limit() == 32 * 1024 * 1024


def test_set_vt_tier_premium(tmp_path):
    """set_vt_tier('premium') stores tier and 650 MB upload limit."""
    import json
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({}))
    with patch("config.get_config_path", return_value=config_path), \
         patch("config._cache", {}):
        from config import set_vt_tier, get_vt_tier, get_vt_upload_limit
        set_vt_tier("premium")
        with patch("config._cache", {}):
            assert get_vt_tier() == "premium"
            assert get_vt_upload_limit() == 650 * 1024 * 1024


def test_set_vt_tier_invalid():
    """set_vt_tier() raises ValueError for invalid tier values."""
    from config import set_vt_tier
    with pytest.raises(ValueError):
        set_vt_tier("enterprise")


def test_get_vt_tier_default(tmp_path):
    """get_vt_tier() returns 'free' when no tier is stored."""
    import json
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({}))
    with patch("config.get_config_path", return_value=config_path), \
         patch("config._cache", {}):
        from config import get_vt_tier
        assert get_vt_tier() == "free"
