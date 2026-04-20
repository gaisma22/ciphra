# vt_tools.py
# VirusTotal API integration.
# lookup_by_hash, upload_file, poll_analysis, check_file.

import os
import time

import requests

from config import VT_TIMEOUT, VT_POLL_INTERVAL

_VT_BASE = "https://www.virustotal.com/api/v3"
_FREE_LIMIT = 32 * 1024 * 1024  # 32 MB free tier upload limit


def _empty_result(available: bool, found: bool, reason: str) -> dict:
    return {
        "available": available,
        "found": found,
        "ratio": "",
        "positives": 0,
        "total": 0,
        "engines": [],
        "permalink": "",
        "reason": reason,
    }


def _parse_engines(results: dict) -> list:
    # Extract up to 20 flagging engines from last_analysis_results
    engines = []
    for name, data in results.items():
        if data.get("category") in ("malicious", "suspicious"):
            engines.append({"name": name, "result": data.get("result") or ""})
        if len(engines) >= 20:
            break
    return engines


def _build_result(attrs: dict, sha256: str = "") -> dict:
    stats = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})
    positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0
    engines = _parse_engines(results)
    permalink = f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else ""
    return {
        "available": True,
        "found": True,
        "ratio": f"{positives}/{total}",
        "positives": positives,
        "total": total,
        "engines": engines,
        "permalink": permalink,
        "reason": "",
    }


def lookup_by_hash(sha256: str, api_key: str) -> dict:
    try:
        resp = requests.get(
            f"{_VT_BASE}/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=30,
        )
    except (requests.exceptions.RequestException, OSError):
        # One retry on transient network error
        time.sleep(2)
        try:
            resp = requests.get(
                f"{_VT_BASE}/files/{sha256}",
                headers={"x-apikey": api_key},
                timeout=30,
            )
        except (requests.exceptions.RequestException, OSError):
            return {"found": False, "reason": "network_error"}

    if resp.status_code == 200:
        attrs = resp.json().get("data", {}).get("attributes", {})
        result = _build_result(attrs, sha256)
        result["found"] = True
        return result
    elif resp.status_code == 404:
        return {"found": False, "reason": "not_in_db"}
    else:
        return {"found": False, "reason": f"http_{resp.status_code}"}


def upload_file(fp: str, api_key: str) -> dict:
    try:
        with open(fp, "rb") as f:
            resp = requests.post(
                f"{_VT_BASE}/files",
                headers={"x-apikey": api_key},
                files={"file": f},
                timeout=120,
            )
    except (requests.exceptions.RequestException, OSError):
        # One retry on transient network error
        time.sleep(2)
        try:
            with open(fp, "rb") as f:
                resp = requests.post(
                    f"{_VT_BASE}/files",
                    headers={"x-apikey": api_key},
                    files={"file": f},
                    timeout=120,
                )
        except (requests.exceptions.RequestException, OSError):
            return {"uploaded": False, "reason": "network_error"}

    if resp.status_code == 200:
        analysis_id = resp.json().get("data", {}).get("id", "")
        return {"uploaded": True, "analysis_id": analysis_id}
    else:
        return {"uploaded": False, "reason": f"http_{resp.status_code}"}


def poll_analysis(analysis_id: str, api_key: str, sha256: str | None = None) -> dict:
    deadline = time.time() + VT_TIMEOUT

    while time.time() < deadline:
        try:
            resp = requests.get(
                f"{_VT_BASE}/analyses/{analysis_id}",
                headers={"x-apikey": api_key},
                timeout=30,
            )
        except (requests.exceptions.RequestException, OSError):
            return {"found": False, "reason": "network_error"}

        if resp.status_code != 200:
            return {"found": False, "reason": f"http_{resp.status_code}"}

        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        status = attrs.get("status")

        if status == "completed":
            # analyses endpoint uses "stats" and "results" (not last_analysis_*)
            stats = attrs.get("stats", {})
            results = attrs.get("results", {})
            positives = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0
            engines = _parse_engines(results)
            permalink = f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else ""
            return {
                "available": True,
                "found": True,
                "ratio": f"{positives}/{total}",
                "positives": positives,
                "total": total,
                "engines": engines,
                "permalink": permalink,
                "reason": "",
            }

        remaining = deadline - time.time()
        if remaining <= 0:
            break
        time.sleep(min(VT_POLL_INTERVAL, remaining))

    return {"found": False, "reason": "timeout"}


def check_file(
    fp: str,
    sha256: str,
    api_key: str,
    file_size: int = 0,
    upload_limit: int = 32 * 1024 * 1024,
    tier: str = "free",
) -> dict:
    if not api_key:
        return _empty_result(False, False, "no_key")

    lookup = lookup_by_hash(sha256, api_key)

    if lookup.get("found"):
        # already had available/found/ratio etc from _build_result
        return lookup

    reason = lookup.get("reason", "")

    if reason != "not_in_db":
        return _empty_result(False, False, reason)

    # Skip upload if the file exceeds the limit for the current tier
    if file_size > 0 and file_size > upload_limit:
        return _empty_result(False, False, "not_in_db")

    # Premium users with large files use the upload_url endpoint
    if tier == "premium" and _FREE_LIMIT < file_size <= upload_limit:
        try:
            url_resp = requests.get(
                f"{_VT_BASE}/files/upload_url",
                headers={"x-apikey": api_key},
                timeout=30,
            )
            if url_resp.status_code == 200:
                upload_url = url_resp.json().get("data", "")
                if upload_url:
                    try:
                        with open(fp, "rb") as f:
                            post_resp = requests.post(
                                upload_url,
                                headers={"x-apikey": api_key},
                                files={"file": f},
                                timeout=120,
                            )
                        if post_resp.status_code == 200:
                            analysis_id = post_resp.json().get("data", {}).get("id", "")
                            return poll_analysis(analysis_id, api_key, sha256)
                    except (requests.exceptions.RequestException, OSError):
                        pass  # fall through to standard upload
        except (requests.exceptions.RequestException, OSError):
            pass  # fall through to standard upload

    # Standard upload path
    upload = upload_file(fp, api_key)
    if not upload.get("uploaded"):
        return _empty_result(False, False, upload.get("reason", "upload_failed"))

    return poll_analysis(upload["analysis_id"], api_key, sha256)
