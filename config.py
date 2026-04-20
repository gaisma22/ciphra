# config.py
# CLI constants and credential manager.
# Handles config path, VT key storage in ~/.ciphra/config.json.

import json
import os
from pathlib import Path

import sys as _sys

_cache = {}
def _get_base_dir():
    if getattr(_sys, "frozen", False):
        # Running as PyInstaller bundle
        return os.path.dirname(_sys.executable)
    return os.path.dirname(os.path.abspath(__file__))
BASE_DIR = _get_base_dir()

# --- Constants ---

APP_NAME = "ciphra"
LOG_FOLDER = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(BASE_DIR, "logs", "activity.csv")
ERROR_LOG = os.path.join(BASE_DIR, "logs", "ciphra.log")
VT_TIMEOUT = 60        # seconds max for polling
VT_POLL_INTERVAL = 3   # seconds between polls
SUPPORTED_SIG_EXTENSIONS = [".sig", ".asc", ".gpg"]
VERSION = "1.3.0"

# --- Credential manager ---

def get_config_path() -> Path:
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            base = Path(appdata)
        else:
            base = Path.home()
    else:
        base = Path.home()
    return base / f".{APP_NAME}" / "config.json"
    

def load_credentials() -> dict:
    if "_creds" in _cache:
        return _cache["_creds"]
    path = get_config_path()
    try:
        with open(path, "r") as f:
            data = json.load(f)
        result = data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError, ValueError):
        result = {}
    _cache["_creds"] = result
    return result


def save_credentials(data: dict) -> None:
    _cache.clear()
    path = get_config_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except OSError as e:
        _sys.stderr.write(
            f"ciphra: could not save config to {path}: {e}\n"
        )


def get_vt_key() -> "str | None":
    return load_credentials().get("vt_key")


def set_vt_key(key: str) -> None:
    data = load_credentials()
    data["vt_key"] = key
    save_credentials(data)


def remove_vt_key() -> None:
    data = load_credentials()
    data.pop("vt_key", None)
    data.pop("vt_tier", None)
    data.pop("vt_upload_limit", None)
    save_credentials(data)


def set_vt_tier(tier: str) -> None:
    if tier not in ("free", "premium"):
        raise ValueError(f"Invalid tier: {tier}. Must be 'free' or 'premium'.")
    data = load_credentials()
    data["vt_tier"] = tier
    data["vt_upload_limit"] = (
        650 * 1024 * 1024 if tier == "premium" else 32 * 1024 * 1024
    )
    save_credentials(data)


def get_vt_tier() -> str:
    return load_credentials().get("vt_tier", "free")


def get_vt_upload_limit() -> int:
    return load_credentials().get("vt_upload_limit", 32 * 1024 * 1024)


# --- Manual sanity check ---

if __name__ == "__main__":
    path = get_config_path()
    creds = load_credentials()

    print(f"Config path : {path}")

    if "vt_key" in creds:
        raw = creds["vt_key"]
        masked = raw[:4] + "*" * max(0, len(raw) - 4) if len(raw) > 4 else "****"
        display = {**creds, "vt_key": masked}
    else:
        display = creds

    print(f"Credentials : {display if display else '(none)'}")
