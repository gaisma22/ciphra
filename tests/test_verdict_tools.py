# test_verdict_tools.py
# Tests for utils/verdict_tools.py.
# Covers all verdict states.

from utils.verdict_tools import (
    compute_verdict,
    VERDICT_CLEAN,
    VERDICT_FLAGGED,
    VERDICT_REVIEW,
    VERDICT_LIKELY_SAFE,
    VERDICT_UNVERIFIED,
    VERDICT_CHECKED,
)


def test_verdict_flagged_bad_sig():
    sig = {"status": "bad", "trust": None, "fingerprint": None, "key_id": None}
    verdict, notes = compute_verdict({"available": False}, sig, True)
    assert verdict == VERDICT_FLAGGED


def test_verdict_flagged_high_vt():
    vt = {"available": True, "positives": 15, "total": 72, "ratio": "15/72"}
    verdict, notes = compute_verdict(vt, None, False)
    assert verdict == VERDICT_FLAGGED


def test_verdict_review_low_vt():
    vt = {"available": True, "positives": 3, "total": 72, "ratio": "3/72"}
    verdict, notes = compute_verdict(vt, None, False)
    assert verdict == VERDICT_REVIEW
    assert any("false positive" in n.lower() for n in notes)


def test_verdict_clean_sig_verified():
    sig = {"status": "verified", "trust": "unknown", "fingerprint": "ABC123", "key_id": None}
    vt = {"available": False}
    verdict, notes = compute_verdict(vt, sig, True)
    assert verdict == VERDICT_CLEAN


def test_verdict_likely_safe_vt_clean():
    vt = {"available": True, "positives": 0, "total": 72, "ratio": "0/72"}
    verdict, notes = compute_verdict(vt, None, False)
    assert verdict == VERDICT_LIKELY_SAFE


def test_verdict_not_in_db_real_path():
    # Real production path: vt_tools returns available=False,
    # reason=not_in_db. This hits VERDICT_CHECKED via line 79
    # in verdict_tools.py.
    verdict, notes = compute_verdict(
        vt={"available": False, "reason": "not_in_db"},
        sig_result=None,
        vt_skipped=False,
    )
    assert verdict == VERDICT_CHECKED


def test_verdict_unverified_available_branch():
    # Exercises the available=True, total=0 branch explicitly.
    # This branch is unreachable from real vt_tools data but
    # exists in the code. Tested here for completeness.
    verdict, notes = compute_verdict(
        vt={"available": True, "positives": 0, "total": 0,
            "ratio": "0/0"},
        sig_result=None,
        vt_skipped=False,
    )
    assert verdict == VERDICT_UNVERIFIED


def test_verdict_checked_hash_only():
    vt = {"available": False, "reason": "no_key"}
    verdict, notes = compute_verdict(vt, None, False)
    assert verdict == VERDICT_CHECKED


def test_verdict_skipped_nothing_ran():
    vt = {"available": False, "reason": "no_key"}
    verdict, notes = compute_verdict(vt, None, True)
    assert verdict == VERDICT_CHECKED


def test_verdict_note_untrusted_key():
    sig = {"status": "verified", "trust": "unknown", "fingerprint": "ABC123", "key_id": None}
    verdict, notes = compute_verdict({"available": False}, sig, True)
    assert verdict == VERDICT_CLEAN
    assert not any("fingerprint" in n.lower() for n in notes)


def test_hash_mismatch_overrides_verdict_to_flagged(tmp_path):
    """Hash mismatch must override verdict to FLAGGED even when
    VT and signature would produce CLEAN."""
    from ciphra import _run_verify
    from unittest.mock import patch, MagicMock

    # Create a real file to hash
    test_file = tmp_path / "testfile.bin"
    test_file.write_bytes(b"ciphra test content")

    # Real SHA256 of the file
    import hashlib
    real_hash = hashlib.sha256(b"ciphra test content").hexdigest()

    # Wrong expected hash — will cause mismatch
    wrong_hash = "a" * 64

    # Mock VT and sig to return clean results
    clean_vt = {
        "available": True,
        "found": True,
        "positives": 0,
        "total": 72,
        "ratio": "0/72",
        "engines": [],
        "permalink": "",
        "reason": "",
    }
    clean_sig = {
        "status": "verified",
        "trust": "full",
        "fingerprint": "A" * 40,
        "key_id": "ABCD1234",
        "msg": "",
    }

    with patch("ciphra.vt_check_file", return_value=clean_vt), \
         patch("ciphra.verify_signature", return_value=clean_sig), \
         patch("ciphra.get_vt_key", return_value="a" * 64), \
         patch("ciphra.write_scan_log") as mock_write_log, \
         patch("ciphra.questionary.select") as mock_select:

        # User chooses "Continue scan (verdict will be FLAGGED)"
        mock_select.return_value.ask.return_value = (
            "Continue scan (verdict will be FLAGGED)"
        )

        # Capture console output
        from io import StringIO
        from rich.console import Console
        output = StringIO()
        test_console = Console(file=output, no_color=True)

        with patch("ciphra.console", test_console):
            _run_verify(
                file=str(test_file),
                sig=None,
                vt=True,
                algo="sha256",
                expected=wrong_hash,
            )

    result_output = output.getvalue()
    assert "FLAGGED" in result_output
    assert "CLEAN" not in result_output
    mock_write_log.assert_called_once()
    call_kwargs = mock_write_log.call_args
    args = call_kwargs[0] if call_kwargs[0] else []
    kwargs = call_kwargs[1] if call_kwargs[1] else {}
    verdict_arg = kwargs.get("verdict") or (args[4] if len(args) > 4 else None)
    assert verdict_arg == VERDICT_FLAGGED
