# verdict_tools.py
# Verdict computation logic.
# compute_verdict: takes vt dict, sig_result dict, and vt_skipped bool,
#   returns verdict string and notes list.

VERDICT_CLEAN = "CLEAN"
VERDICT_FLAGGED = "FLAGGED"
VERDICT_REVIEW = "REVIEW"
VERDICT_LIKELY_SAFE = "LIKELY SAFE"
VERDICT_UNVERIFIED = "UNVERIFIED"  # File not in VT database
VERDICT_CHECKED = "CHECKED"  # Only hash verified, no sig or VT data


def compute_verdict(
    vt: dict,
    sig_result: dict | None,
    vt_skipped: bool,
) -> tuple[str, list[str]]:

    notes = []

    # Signature bad -- highest priority
    if sig_result and sig_result["status"] == "bad":
        return VERDICT_FLAGGED, [
            "Signature invalid. The file was modified after signing. Do not use it."
        ]

    # VT detection levels
    vt_positives = 0
    vt_total = 0
    vt_has_data = False

    if vt.get("available") and vt.get("total", 0) > 0:
        vt_has_data = True
        vt_positives = vt.get("positives", 0)
        vt_total = vt.get("total", 0)

    if vt_has_data and vt_positives >= 10:
        return VERDICT_FLAGGED, [
            f"{vt_positives}/{vt_total} engines flagged this file. Likely malicious."
        ]

    if vt_has_data and 1 <= vt_positives <= 9:
        notes.append(
            f"{vt_positives}/{vt_total} engines flagged. "
            "Possible false positive. Check the full VirusTotal report."
        )
        verdict_from_vt = VERDICT_REVIEW
    elif vt_has_data and vt_positives == 0:
        verdict_from_vt = VERDICT_LIKELY_SAFE
    # Defensive guard. vt_tools.check_file() never returns
    # available=True with total=0 in practice, but this branch
    # is kept in case that changes in a future implementation.
    elif not vt_skipped and vt.get("available") and vt.get("total", 0) == 0:
        verdict_from_vt = VERDICT_UNVERIFIED
    else:
        verdict_from_vt = None

    # Signature verified
    sig_verified = sig_result and sig_result["status"] == "verified"

    # Determine final verdict
    if sig_verified and verdict_from_vt != VERDICT_REVIEW:
        return VERDICT_CLEAN, notes

    if sig_verified and verdict_from_vt == VERDICT_REVIEW:
        return VERDICT_REVIEW, notes

    if verdict_from_vt == VERDICT_LIKELY_SAFE:
        return VERDICT_LIKELY_SAFE, notes

    if verdict_from_vt == VERDICT_REVIEW:
        return VERDICT_REVIEW, notes

    if verdict_from_vt == VERDICT_UNVERIFIED:
        return VERDICT_UNVERIFIED, notes

    # VT check failed with specific error
    if vt.get("reason") is not None and not vt_skipped and not vt_has_data:
        reason = vt.get("reason")
        if reason not in ("not_in_db", "http_404", "no_key"):
            notes.append(f"VirusTotal check failed: {reason}.")
        return VERDICT_CHECKED, notes

    # Hash computed only -- minimum verdict since hash always runs
    if not vt_has_data and sig_result is None:
        return VERDICT_CHECKED, [
            "Hash computed. Compare this value against what the developer "
            "published on their download page."
        ]

    return VERDICT_CHECKED, notes
