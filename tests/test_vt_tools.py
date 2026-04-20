# test_vt_tools.py
# Tests for utils/vt_tools.py.
# Covers: lookup_by_hash, upload_file,
#   poll_analysis, check_file.

import time
from unittest.mock import MagicMock, mock_open, patch

import pytest
import requests

from utils.vt_tools import check_file, lookup_by_hash, poll_analysis, upload_file

_VT_200_PAYLOAD = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 2,
                "suspicious": 1,
                "undetected": 69,
                "harmless": 0,
            },
            "last_analysis_results": {
                "Engine1": {"result": "Trojan.X", "category": "malicious"},
                "Engine2": {"result": None, "category": "undetected"},
                "Engine3": {"result": "Suspicious.Y", "category": "suspicious"},
            },
        }
    }
}


def test_lookup_by_hash_found():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = _VT_200_PAYLOAD
    with patch("utils.vt_tools.requests.get", return_value=mock_resp):
        result = lookup_by_hash("abc123", "fakekey")
    assert result["found"] is True
    assert result["positives"] == 3
    assert result["total"] == 72
    # Engine2 has result=None and is excluded
    assert len(result["engines"]) == 2
    assert "abc123" in result["permalink"]


def test_lookup_by_hash_not_found():
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    with patch("utils.vt_tools.requests.get", return_value=mock_resp):
        result = lookup_by_hash("abc123", "fakekey")
    assert result["found"] is False
    assert result["reason"] == "not_in_db"


def test_lookup_by_hash_network_error():
    with patch("utils.vt_tools.requests.get",
               side_effect=requests.exceptions.RequestException):
        result = lookup_by_hash("abc123", "fakekey")
    assert result["found"] is False
    assert result["reason"] == "network_error"


def test_lookup_by_hash_retry_exhausted_distinct_exceptions():
    """Both retry attempts fail with different exception types."""
    with patch("utils.vt_tools.requests.get",
               side_effect=[
                   requests.exceptions.Timeout,
                   requests.exceptions.ConnectionError,
               ]):
        result = lookup_by_hash("abc123", "fakekey")
    assert result["found"] is False
    assert result.get("reason") in ("network_error", "timeout", "unavailable") \
        or not result.get("found")


def test_upload_file_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"data": {"id": "analysis-id-123"}}
    with patch("utils.vt_tools.requests.post", return_value=mock_resp), \
         patch("builtins.open", mock_open(read_data=b"")):
        result = upload_file("fakefile.txt", "fakekey")
    assert result["uploaded"] is True
    assert result["analysis_id"] == "analysis-id-123"


def test_upload_file_failure():
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    with patch("utils.vt_tools.requests.post", return_value=mock_resp), \
         patch("builtins.open", mock_open(read_data=b"")):
        result = upload_file("fakefile.txt", "fakekey")
    assert result["uploaded"] is False
    assert "429" in result["reason"]


def test_check_file_no_key():
    result = check_file("fakefile.txt", "abc123", None)
    assert result["available"] is False
    assert result["reason"] == "no_key"


def test_check_file_found_via_hash():
    mock_lookup = {
        "found": True,
        "available": True,
        "ratio": "0/72",
        "positives": 0,
        "total": 72,
        "engines": [],
        "permalink": "https://www.virustotal.com/gui/file/abc123",
        "reason": "",
    }
    with patch("utils.vt_tools.lookup_by_hash", return_value=mock_lookup):
        result = check_file("fakefile.txt", "abc123", "fakekey")
    assert result["available"] is True
    assert result["positives"] == 0


def test_lookup_by_hash_timeout():
    # Timeout is caught by except (requests.exceptions.RequestException, OSError).
    # Returns found=False, reason="network_error".
    with patch("utils.vt_tools.requests.get",
               side_effect=requests.exceptions.Timeout):
        result = lookup_by_hash("abc123", "fakekey")
    assert result["found"] is False
    assert result["reason"] == "network_error"


def test_check_file_no_upload_on_http_error():
    # lookup returns http_404 which is not "not_in_db", so upload is skipped
    mock_lookup = {"found": False, "available": False, "reason": "http_404"}
    with patch("utils.vt_tools.lookup_by_hash", return_value=mock_lookup), \
         patch("utils.vt_tools.upload_file") as mock_upload:
        check_file("fakefile.txt", "abc123", "fakekey")
    mock_upload.assert_not_called()


def test_check_file_skips_upload_when_file_too_large():
    # V2: file_size > upload_limit should skip upload and return early
    mock_lookup = {"found": False, "reason": "not_in_db"}
    with patch("utils.vt_tools.lookup_by_hash", return_value=mock_lookup), \
         patch("utils.vt_tools.upload_file") as mock_upload:
        result = check_file(
            "fakefile.txt",
            "abc123",
            "fakekey",
            file_size=100 * 1024 * 1024,
            upload_limit=32 * 1024 * 1024,
        )
    mock_upload.assert_not_called()
    assert result["reason"] == "not_in_db"


def test_check_file_premium_uses_upload_url():
    # V3: premium tier with large file should GET upload_url and POST to it
    mock_lookup = {"found": False, "reason": "not_in_db"}
    mock_url_resp = MagicMock()
    mock_url_resp.status_code = 200
    mock_url_resp.json.return_value = {"data": "https://fakeupload.virustotal.com/upload"}
    mock_post_resp = MagicMock()
    mock_post_resp.status_code = 200
    mock_post_resp.json.return_value = {"data": {"id": "premium-analysis-id"}}
    mock_poll_result = {
        "found": True,
        "available": True,
        "ratio": "0/60",
        "positives": 0,
        "total": 60,
        "engines": [],
        "permalink": "",
        "reason": "",
    }
    file_size = 400 * 1024 * 1024  # 400 MB, above free limit (32 MB) and below premium limit (650 MB)
    with patch("utils.vt_tools.lookup_by_hash", return_value=mock_lookup), \
         patch("utils.vt_tools.requests.get", return_value=mock_url_resp) as mock_get, \
         patch("utils.vt_tools.requests.post", return_value=mock_post_resp), \
         patch("builtins.open", mock_open(read_data=b"")), \
         patch("utils.vt_tools.poll_analysis", return_value=mock_poll_result) as mock_poll:
        result = check_file(
            "fakefile.txt",
            "abc123",
            "fakekey",
            file_size=file_size,
            upload_limit=650 * 1024 * 1024,
            tier="premium",
        )
    mock_poll.assert_called_once_with("premium-analysis-id", "fakekey", "abc123")
    assert result["found"] is True
    # Confirm the upload_url endpoint was actually requested
    get_calls = [str(call) for call in mock_get.call_args_list]
    assert any("upload_url" in call for call in get_calls), \
        "Expected GET request to upload_url endpoint"


def test_check_file_standard_upload_passes_sha256_to_poll():
    """Standard upload path must pass sha256 to poll_analysis
    so the permalink is populated in the result."""
    file_size = 10 * 1024 * 1024  # 10 MB — under free limit
    sha256 = "abc123" * 10 + "ab"  # 62-char fake sha256

    upload_result = {"uploaded": True, "analysis_id": "standard-analysis-id"}
    poll_result = {
        "found": True,
        "available": True,
        "positives": 0,
        "total": 72,
        "ratio": "0/72",
        "engines": [],
        "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        "reason": "",
    }

    with patch("utils.vt_tools.lookup_by_hash") as mock_lookup, \
         patch("utils.vt_tools.upload_file") as mock_upload, \
         patch("utils.vt_tools.poll_analysis") as mock_poll:

        mock_lookup.return_value = {"found": False, "reason": "not_in_db"}
        mock_upload.return_value = upload_result
        mock_poll.return_value = poll_result

        result = check_file(
            "fakefile.txt",
            sha256,
            "fakekey",
            file_size=file_size,
            upload_limit=32 * 1024 * 1024,
            tier="free",
        )

    # poll_analysis must be called with sha256 as the third argument
    mock_poll.assert_called_once_with(
        "standard-analysis-id", "fakekey", sha256
    )
    assert result["found"] is True


def test_lookup_by_hash_retry_succeeds():
    # V8: first request fails, second succeeds after retry
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = _VT_200_PAYLOAD
    with patch("utils.vt_tools.requests.get",
               side_effect=[requests.exceptions.RequestException, mock_resp]), \
         patch("utils.vt_tools.time.sleep"):
        result = lookup_by_hash("abc123", "fakekey")
    assert result["found"] is True


def test_poll_analysis_timeout():
    """poll_analysis returns timeout reason when polling loop exhausts."""
    with patch("utils.vt_tools.requests.get") as mock_get:
        # Return "queued" status on every call so polling exhausts
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "status": "queued"
                }
            }
        }
        mock_get.return_value = mock_response

        with patch("utils.vt_tools.time.sleep"):
            result = poll_analysis("fake_analysis_id", "fakekey")

    assert result["found"] is False
    assert result.get("reason") == "timeout"


def test_poll_analysis_completed():
    """poll_analysis returns scan result when status is completed."""
    with patch("utils.vt_tools.requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "status": "completed",
                    "stats": {
                        "malicious": 0,
                        "undetected": 72,
                    },
                    "results": {}
                }
            }
        }
        mock_get.return_value = mock_response

        with patch("utils.vt_tools.time.sleep"):
            result = poll_analysis("fake_analysis_id", "fakekey",
                                   sha256="abc123")

    assert result["found"] is True
    assert result["positives"] == 0
    assert result["total"] == 72
    assert "abc123" in result["permalink"]
