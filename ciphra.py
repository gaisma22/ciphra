# ciphra.py
# CLI entry point for Ciphra.
# Defines click commands: verify, hash, config, completions.

import datetime
import hashlib
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

import click
import questionary
from questionary import Style as QStyle
from rich.console import Console
from rich.progress import BarColumn, DownloadColumn, Progress, TransferSpeedColumn

from config import (
    ERROR_LOG,
    LOG_FOLDER,
    SUPPORTED_SIG_EXTENSIONS,
    VERSION,
    get_config_path,
    get_vt_key,
    get_vt_tier,
    get_vt_upload_limit,
    remove_vt_key as _remove_vt_key,
    save_credentials,
    set_vt_key,
    set_vt_tier,
)
from utils.crypto_tools import (
    encrypt_file as _crypto_encrypt_file,
    decrypt_file as _crypto_decrypt_file,
    detect_format as _detect_format,
    calibrate_argon2_params,
    derive_key,
    _read_kdf_params,
)
from utils.gpg_tools import (
    GPG_BIN,
    gpg_available,
    verify_signature,
    fetch_gpg_key,
    import_and_trust_key,
    extract_key_id,
    list_encryption_keys,
    encrypt_file_asymmetric,
    decrypt_file_asymmetric,
    get_encrypted_for_key_id,
    import_public_key_file,
    generate_key_pair,
    list_signing_keys,
    list_signing_keys_without_encryption_subkey,
    list_secret_keys_with_encryption_subkey,
    sign_file_detached,
    export_public_key,
    export_private_key,
    add_encryption_subkey,
    rotate_encryption_subkey,
    extend_subkey_expiry,
    verify_key_passphrase,
    delete_key_pair,
    extend_key_expiry,
)
from utils.hash_tools import compute_hash
from utils.log_tools import write_scan_log, write_operation_log
from utils.verdict_tools import (
    compute_verdict,
    VERDICT_CLEAN,
    VERDICT_FLAGGED,
    VERDICT_REVIEW,
    VERDICT_LIKELY_SAFE,
    VERDICT_UNVERIFIED,
    VERDICT_CHECKED,
)
from utils.vt_tools import check_file as vt_check_file

_no_color = os.environ.get("NO_COLOR", "") != ""
console = Console(no_color=_no_color)

ACCENT  = "#c9dff0"
GOOD    = "#4caf50"
CAUTION = "#e8a838"
BAD     = "#e05c5c"

PROGRESS_THRESHOLD = 10 * 1024 * 1024     # 10 MB

_BANNER_SHOWN = False
_IN_OPERATION = False

BANNER_LINES = [
    "   ██████╗██╗██████╗ ██╗  ██╗██████╗  █████╗ ",
    "  ██╔════╝██║██╔══██╗██║  ██║██╔══██╗██╔══██╗",
    "  ██║     ██║██████╔╝███████║██████╔╝███████║",
    "  ██║     ██║██╔═══╝ ██╔══██║██╔══██╗██╔══██║",
    "  ╚██████╗██║██║     ██║  ██║██║  ██║██║  ██║",
    "   ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝",
]

BANNER_LINES_ASCII = [
    "   CIPHRA  ",
    "   ------  ",
]


def _supports_unicode() -> bool:
    try:
        encoding = sys.stdout.encoding or ""
        if encoding.lower() in ("ascii", "ansi", ""):
            return False
        "─".encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError, AttributeError):
        return False


UNICODE_OK = _supports_unicode()


def _translate_error(raw: str, context: str = "") -> str:
    if not raw:
        return "An unexpected error occurred. Details in logs/ciphra.log."
    logging.error("Raw error: %s", raw)
    r = raw.lower()
    if "no valid" in r:
        msg = "That file does not contain a GPG key."
    elif "keyserver receive failed: no name" in r:
        msg = "Keyserver did not respond."
    elif "keyserver receive failed" in r:
        msg = "Could not reach the keyserver."
    elif "connection timed out" in r or "timed out" in r:
        msg = "The request timed out."
    elif "http_401" in r:
        msg = "API key rejected. Check your key in Configure settings."
    elif "http_429" in r:
        msg = "Rate limit reached. Free API allows 4 lookups per minute."
    elif "http_500" in r or "http_502" in r or "http_503" in r:
        msg = "VirusTotal is temporarily unavailable."
    elif "http_" in r:
        msg = "VirusTotal returned an unexpected error."
    elif "network_error" in r:
        msg = "No network connection or server did not respond."
    elif "not_in_db" in r:
        msg = "File not found in VirusTotal database."
    elif "file_too_large" in r:
        msg = "File is too large to upload. Hash lookup only."
    elif "no_key" in r:
        msg = "No VirusTotal API key configured."
    elif "invalid tag" in r or "invalidtag" in r:
        msg = "Wrong password or the file was tampered with."
    elif "bad passphrase" in r:
        msg = "Wrong passphrase."
    elif "no secret key" in r:
        msg = "The private key for this file is not in your keyring."
    elif "permission denied" in r:
        msg = "Permission denied. Check file permissions."
    elif "no such file" in r or "file not found" in r:
        msg = "File not found."
    elif "is a directory" in r:
        msg = "That is a folder. Select a file inside it."
    elif "unusable public key" in r:
        msg = "That key cannot encrypt files. It may be expired, revoked, or signing-only."
    elif "key_not_created" in r or "key not created" in r:
        msg = "Key generation failed. Check that GPG is correctly installed."
    elif "invalid algorithm" in r or "invalid algo" in r:
        msg = "Key algorithm not supported by your GPG version."
    elif "already exists" in r and "gnupg" in r:
        msg = "A key with this identity already exists in your keyring."
    elif "signing failed" in r:
        msg = "Signing failed. Check your passphrase and try again."
    elif "export failed" in r or "nothing exported" in r:
        msg = "Export failed. The key may not exist in your keyring."
    elif "key not changed" in r or "no update needed" in r:
        msg = "No change was made. The expiry date may already be set to that value."
    else:
        msg = "An unexpected error occurred. Details in logs/ciphra.log."
    return f"{context}: {msg}" if context else msg


CIPHRA_STYLE = QStyle([
    ("qmark",       "fg:#c9dff0 bold"),
    ("question",    "fg:#c9dff0 bold"),
    ("answer",      "fg:#c9dff0 bold"),
    ("pointer",     "fg:#c9dff0 bold"),
    ("highlighted", "fg:#c9dff0 bold"),
    ("selected",    "fg:#ffffff"),
    ("separator",   "fg:#6c6c6c"),
    ("instruction", "fg:#6c6c6c"),
    ("text",        "fg:#ffffff"),
    ("disabled",    "fg:#6c6c6c italic"),
])


def _outcome_recoverable(msg: str, choices: list[str]) -> str | None:
    console.print(f"  [{CAUTION}][WARN] {msg}[/{CAUTION}]")
    return questionary.select(
        "What do you want to do?", choices=choices, style=CIPHRA_STYLE
    ).ask()


def _outcome_degraded(msg: str) -> None:
    console.print(f"  [dim]{msg}[/dim]")


def _outcome_hard_stop(msg: str) -> bool:
    console.print(f"  [{BAD}][ERROR] {msg}[/{BAD}]")
    retry = questionary.confirm(
        "  Try again?", default=True, style=CIPHRA_STYLE
    ).ask()
    return bool(retry)


# --- helpers ---

def _norm(s):
    return re.sub(r'[^a-z0-9]', '', s.lower())


def _resolve_path(raw: str) -> str:
    if not raw:
        return raw
    return os.path.abspath(os.path.expanduser(raw.strip()))


def _prompt_for_file(prompt_text, start_dir=None):
    """Prompt for a file path with tab completion, starting in start_dir."""
    display_dir = start_dir or os.path.expanduser("~")

    default_val = display_dir.rstrip("/") + "/" if display_dir else "/"

    fp = questionary.path(
        prompt_text,
        default=default_val,
        style=CIPHRA_STYLE,
    ).ask()

    if fp is None:
        return None

    fp = fp.strip()
    if not fp:
        return None

    return _resolve_path(fp)


def setup_logging():
    os.makedirs(LOG_FOLDER, exist_ok=True)
    handler = RotatingFileHandler(
        ERROR_LOG,
        maxBytes=1_000_000,
        backupCount=3,
    )
    handler.setLevel(logging.ERROR)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.ERROR)


def _get_master_key_fp(subkey_id: str) -> str | None:
    if not subkey_id or GPG_BIN is None:
        return None
    try:
        proc = subprocess.run(
            [GPG_BIN, "--list-keys", "--with-colons", subkey_id],
            capture_output=True,
            text=True,
            timeout=10,
        )
        master_fp = None
        for line in proc.stdout.splitlines():
            if line.startswith("fpr:"):
                parts = line.split(":")
                if len(parts) >= 10 and parts[9]:
                    if master_fp is None:
                        master_fp = parts[9].strip()
        return master_fp
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        return None


def _hash_with_progress(fp: str, algo: str) -> str:
    chunk_size = 1048576
    h = hashlib.new(algo)
    file_size = os.path.getsize(fp)
    with Progress(
        "[progress.description]{task.description}",
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task(
            f"  Hashing ({algo.upper()})...",
            total=file_size,
        )
        try:
            with open(fp, "rb") as f:
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    h.update(chunk)
                    progress.advance(task, len(chunk))
        except (PermissionError, OSError, IOError):
            raise
    return h.hexdigest()


def _gpg_install_hint() -> str:
    system = platform.system()
    if system == "Linux":
        if shutil.which("apt"):
            return "  sudo apt install gnupg"
        elif shutil.which("dnf"):
            return "  sudo dnf install gnupg2"
        elif shutil.which("pacman"):
            return "  sudo pacman -S gnupg"
        elif shutil.which("apk"):
            return "  apk add gnupg"
        elif shutil.which("zypper"):
            return "  sudo zypper install gpg2"
        return "  Install gnupg using your package manager"
    elif system == "Darwin":
        return "  brew install gnupg"
    return "  Download Gpg4win: https://gpg4win.org"


def check_dirs():
    for d, name in [
        (LOG_FOLDER, "logs"),
    ]:
        os.makedirs(d, exist_ok=True)
        if not os.access(d, os.W_OK):
            logging.error("Directory not writable: %s", d)
            console.print(f"  [{BAD}][ERROR] {name} directory is not writable: {d}[/{BAD}]")
            sys.exit(1)


def _validate_vt_key(key: str) -> bool:
    return bool(re.match(r'^[0-9a-fA-F]{64}$', key.strip()))


def _set_vt_key_flow() -> str | None:
    """Full VT key setup flow. Returns 'free', 'premium', or None if cancelled."""

    # Preamble — shown once before the first prompt
    console.print()
    console.print("  [dim]VirusTotal scans files against 70+ antivirus engines.[/dim]")
    console.print("  [dim]Get a free API key at: https://virustotal.com/gui/my-apikey[/dim]")
    console.print()

    # Password loop
    while True:
        key = questionary.password(
            "VirusTotal API key:",
            style=CIPHRA_STYLE,
        ).ask()

        # Ctrl+C or ESC
        if key is None:
            console.print("  [dim]Cancelled.[/dim]")
            return None

        # Blank or whitespace — silently re-ask, no warning
        if not key.strip():
            continue

        # Invalid format
        if not _validate_vt_key(key):
            console.print(
                f"\n  [{CAUTION}][WARN] That is not a valid API key."
                f" Keys are exactly 64 hex characters.[/{CAUTION}]\n"
            )
            retry = questionary.confirm(
                "Try again?",
                default=True,
                style=CIPHRA_STYLE,
            ).ask()
            if not retry or retry is None:
                console.print("  [dim]Cancelled.[/dim]")
                return None
            continue

        # Valid key — ask tier
        break

    # Tier selection
    tier_choice = questionary.select(
        "Is this a premium VirusTotal account?",
        choices=[
            "No, standard free account",
            "Yes, I have a paid premium account",
        ],
        style=CIPHRA_STYLE,
    ).ask()

    if tier_choice is None:
        console.print("  [dim]Cancelled. Key not saved.[/dim]")
        return None

    tier = "premium" if tier_choice.startswith("Yes") else "free"

    # Save key and tier
    set_vt_key(key.strip())
    set_vt_tier(tier)

    if tier == "premium":
        console.print(
            f"  [{GOOD}]Key saved. Tier: premium. Upload limit: 650 MB.[/{GOOD}]"
        )
    else:
        console.print(
            f"  [{GOOD}]Key saved. Tier: free. Upload limit: 32 MB.[/{GOOD}]"
        )
        console.print(
            "  [dim]Free API is for personal use only."
            " Commercial use requires a paid license.[/dim]"
        )

    return tier


def _show_banner(animate: bool = True) -> None:
    lines_to_use = BANNER_LINES if UNICODE_OK else BANNER_LINES_ASCII
    for line in lines_to_use:
        console.print(f"[{ACCENT}]{line}[/{ACCENT}]")
        if animate:
            time.sleep(0.04)


def first_run_check() -> None:
    config_path = get_config_path()
    if config_path.exists():
        return

    click.clear()
    _show_banner(animate=True)
    console.print(
        f"\n  [{ACCENT}]ciphra[/{ACCENT}]  [dim]know what protects you.[/dim]"
    )
    console.print(
        "  [dim]Hash, GPG signature, and VirusTotal checks. Runs locally.[/dim]"
    )
    console.print(
        "  [dim]To add a VirusTotal API key, go to Configure settings.[/dim]\n"
    )
    save_credentials({})


def _show_faq():
    _old_less = os.environ.get("LESS", "")
    os.environ["LESS"] = "-R -+F"
    try:
        faq_text = (
            f"\n"
            f"  [bold {ACCENT}]FAQ[/bold {ACCENT}]\n"
            f"  [dim]{'─' * 54 if UNICODE_OK else '-' * 54}[/dim]\n"
            f"\n"

            f"  [bold {ACCENT}]What do the verdicts mean?[/bold {ACCENT}]\n"
            f"\n"
            f"  [{GOOD}]CLEAN[/{GOOD}]          signature verified, nothing failed.\n"
            f"\n"
            f"  [{GOOD}]LIKELY SAFE[/{GOOD}]    VirusTotal found zero threats. No signature checked.\n"
            f"\n"
            f"  [{CAUTION}]REVIEW[/{CAUTION}]         a few engines flagged it. Possible false positive.\n"
            f"                 Check the full VirusTotal report before opening.\n"
            f"\n"
            f"  [{BAD}]FLAGGED[/{BAD}]        hard failure. Invalid signature, 10 or more detections,\n"
            f"                 or hash mismatch. Do not open the file.\n"
            f"                 Download it again from the official source.\n"
            f"\n"
            f"  [dim]CHECKED[/dim]        hash computed. Everything else was skipped.\n"
            f"\n"
            f"  [dim]UNVERIFIED[/dim]     not in VirusTotal database. Common for new or niche files.\n"
            f"\n"
            f"\n"

            f"  [bold {ACCENT}]Symmetric vs asymmetric encryption[/bold {ACCENT}]\n"
            f"\n"
            f"  [dim]Symmetric[/dim]    password-based. You encrypt it, you decrypt it with the\n"
            f"               same password. Good for files you keep yourself.\n"
            f"               Produces a [dim].ciphra[/dim] file. Only ciphra can decrypt it.\n"
            f"\n"
            f"  [dim]Asymmetric[/dim]   public key-based. Only the person with the matching\n"
            f"               private key can open it. Good for sending to someone.\n"
            f"               Produces a [dim].gpg[/dim] file. Any GPG tool can decrypt it.\n"
            f"\n"
            f"\n"
            f"  [bold {ACCENT}]Lost your .ciphra password?[/bold {ACCENT}]\n"
            f"\n"
            f"  No recovery. AES-256-GCM with Argon2id means the file cannot be\n"
            f"  decrypted without the correct password. No backdoor, no reset.\n"
            f"  Keep passwords somewhere safe.\n"
            f"\n"
            f"\n"
            f"  [bold {ACCENT}]Key expired vs subkey expired[/bold {ACCENT}]\n"
            f"\n"
            f"  Your key pair has two expiry dates.\n"
            f"\n"
            f"  [dim]Primary key[/dim]        your signing identity. Cannot sign files if expired.\n"
            f"                     Fix: Digital Signatures > Extend key expiry\n"
            f"\n"
            f"  [dim]Encryption subkey[/dim]  others use this to encrypt files to you.\n"
            f"                     Fix: Manage subkeys > Extend subkey expiry\n"
            f"\n"
            f"  When in doubt, extend both.\n"
            f"\n"
            f"\n"

            f"  [bold {ACCENT}]How do I receive encrypted files from someone?[/bold {ACCENT}]\n"
            f"\n"
            f"  Share your public key. Digital Signatures > Export public key.\n"
            f"  Send them the .asc file. They import it and encrypt files to you\n"
            f"  using ciphra or any GPG tool. Your private key never leaves your machine.\n"
            f"\n"
            f"\n"

            f"  [bold {ACCENT}]What gets sent to VirusTotal?[/bold {ACCENT}]\n"
            f"\n"
            f"  The file hash. Always.\n"
            f"  If not found and the file is under your upload limit, ciphra uploads it.\n"
            f"  Files over the limit are never uploaded.\n"
            f"  The result line tells you which path ran.\n"
            f"\n"
            f"  To keep everything local, skip VirusTotal when prompted or remove\n"
            f"  your API key in Configure settings.\n"
            f"\n"
            f"\n"

            f"  [bold {ACCENT}]CLI commands[/bold {ACCENT}]  [dim](skip the menu)[/dim]\n"
            f"\n"
            f"  [{ACCENT}]ciphra verify file.iso[/{ACCENT}]\n"
            f"  [{ACCENT}]ciphra verify file.iso --sig file.iso.sig[/{ACCENT}]\n"
            f"  [{ACCENT}]ciphra verify file.iso --sig file.iso.sig --no-vt[/{ACCENT}]\n"
            f"  [{ACCENT}]ciphra verify file.iso --expected a1b2c3... --algo sha256[/{ACCENT}]\n"
            f"  [{ACCENT}]ciphra verify file.iso --algo sha512[/{ACCENT}]\n"
            f"\n"
            f"  [{ACCENT}]ciphra hash file.iso[/{ACCENT}]\n"
            f"  [{ACCENT}]ciphra hash file.iso --algo sha512[/{ACCENT}]\n"
            f"\n"
            f"  [{ACCENT}]ciphra config --vt-key YOUR_KEY[/{ACCENT}]\n"
            f"  [{ACCENT}]ciphra config --show[/{ACCENT}]\n"
            f"  [{ACCENT}]ciphra config --remove-vt-key[/{ACCENT}]\n"
            f"\n"
            f"  [{ACCENT}]ciphra --version[/{ACCENT}]\n"
            f"\n"
            f"  [dim]Tab completion: ciphra completions --shell bash[/dim]\n"
            f"  [dim]Also works with zsh and fish.[/dim]\n"
            f"\n"
            f"\n"

            f"  [bold {ACCENT}]Is my passphrase stored anywhere?[/bold {ACCENT}]\n"
            f"\n"
            f"  No. ciphra uses a masked prompt and never writes passphrases to disk.\n"
            f"\n"

            f"  [dim]Press q to return to the menu.[/dim]\n"
        )
        with console.pager(styles=True):
            console.print(faq_text)
    finally:
        if _old_less:
            os.environ["LESS"] = _old_less
        else:
            os.environ.pop("LESS", None)
    console.print("  [dim]Returned to menu.[/dim]")


def _validate_sig_input(sig: str, fp: str) -> str | None:
    """Check a manually entered sig path and return None with a warning if invalid."""
    sig_ext = os.path.splitext(sig)[1].lower()
    key_extensions = [".key", ".pem", ".pub"]
    if sig == fp:
        console.print(
            f"\n  [{CAUTION}][WARN] Signature file cannot be the same as "
            f"the verified file.[/{CAUTION}]"
        )
        return None
    if sig_ext in key_extensions:
        console.print(
            f"\n  [{CAUTION}][WARN] {os.path.basename(sig)} is a public key file, "
            f"not a signature.\n"
            f"  Import this key using a GPG tool.\n"
            f"  Then find the .sig file from the developer's download page.[/{CAUTION}]"
        )
        return None
    if sig_ext not in [".sig", ".asc", ".gpg"]:
        console.print(
            f"\n  [{CAUTION}][WARN] Unsupported file type: {sig_ext}\n"
            f"  Signature files use: .sig .asc .gpg[/{CAUTION}]"
        )
        return None
    return sig


def show_launch_screen():
    try:
        _show_launch_screen_inner()
    except (KeyboardInterrupt, click.Abort):
        if not _IN_OPERATION:
            console.print("  [dim]Goodbye.[/dim]")
            sys.exit(0)
        console.print("  [dim]Cancelled.[/dim]")
        show_launch_screen()


def _configure_settings_loop(ctx, first_entry: bool = True) -> None:
    """Configure settings menu loop."""
    console.print()
    sub = questionary.select(
        "Configure settings",
        choices=[
            "Set VirusTotal API key",
            "Remove VirusTotal API key",
            "Show current config",
            "Back",
        ],
        style=CIPHRA_STYLE,
    ).ask()

    if sub is None or sub == "Back":
        return

    if sub == "Set VirusTotal API key":
        existing = get_vt_key()
        if existing is not None and _validate_vt_key(existing):
            confirmed = questionary.confirm(
                "  A key is already set. Overwrite?",
                default=False,
                style=CIPHRA_STYLE,
            ).ask()
            if not confirmed:
                console.print("  [dim]Key unchanged.[/dim]")
                _configure_settings_loop(ctx, first_entry=False)
                return
        _set_vt_key_flow()
    elif sub == "Remove VirusTotal API key":
        ctx.invoke(config, vt_key=None, show=False, remove_vt_key=True)
    elif sub == "Show current config":
        ctx.invoke(config, vt_key=None, show=True, remove_vt_key=False)

    _configure_settings_loop(ctx, first_entry=False)


def _show_launch_screen_inner():
    global _BANNER_SHOWN, _IN_OPERATION

    if not _BANNER_SHOWN:
        # Step 1 -- separate from previous terminal output
        console.print()
        # Step 2 -- animate banner line by line
        _show_banner(animate=True)

        # Step 3 -- typewriter tagline
        tagline = "  know what protects you."
        console.print()
        for char in tagline:
            console.print(char, end="", style="dim")
            time.sleep(0.03)
        console.print(f"\n  v{VERSION}", style="dim")
        console.print()

        _BANNER_SHOWN = True

    # Step 4 -- interactive menu
    choices = [
        "Verify a file",
        "Hash a file",
        "Encrypt & Decrypt",
        "Digital Signatures",
        questionary.Separator("─" * 18 if UNICODE_OK else "-" * 18),
        "Configure settings",
        "What is this? (FAQ)",
        "Exit",
    ]

    answer = questionary.select(
        "What do you want to do?",
        choices=choices,
        style=CIPHRA_STYLE,
    ).ask()

    if answer is None:
        console.print("  [dim]Goodbye.[/dim]")
        sys.exit(0)

    if answer == "Exit":
        console.print("\n  [dim]Goodbye.[/dim]")
        sys.exit(0)

    if answer == "What is this? (FAQ)":
        _show_faq()
        show_launch_screen()
        return

    ctx = click.get_current_context()

    if answer == "Verify a file":
        # STEP 1 -- File selection with retry loop
        console.print(
            "  [dim]Check a file's integrity, scan for threats,"
            " or verify a developer's signature.[/dim]"
        )
        console.print("  [dim]Start with / or ~, Tab to complete, Ctrl+C to cancel.[/dim]")
        console.print()
        fp = _prompt_for_file("File path:", start_dir="/")
        if fp is None:
            console.print("  [dim]Cancelled.[/dim]")
            show_launch_screen()
            return

        while True:
            if os.path.isdir(fp):
                if not _outcome_hard_stop("That is a folder. Select a file inside it."):
                    show_launch_screen()
                    return
                fp = _prompt_for_file("File path:", start_dir="/")
                if fp is None:
                    show_launch_screen()
                    return
                continue
            if not os.path.exists(fp):
                if not _outcome_hard_stop("File not found."):
                    show_launch_screen()
                    return
                fp = _prompt_for_file("File path:", start_dir="/")
                if fp is None:
                    show_launch_screen()
                    return
                continue
            if os.path.getsize(fp) == 0:
                if not _outcome_hard_stop("The file is empty."):
                    show_launch_screen()
                    return
                fp = _prompt_for_file("File path:", start_dir="/")
                if fp is None:
                    show_launch_screen()
                    return
                continue
            try:
                with open(fp, "rb") as f:
                    f.read(1)
            except PermissionError:
                console.print(f"  [{BAD}][ERROR] Cannot read that file. Check file permissions.[/{BAD}]")
                show_launch_screen()
                return
            except OSError as e:
                console.print(f"  [{BAD}][ERROR] {_translate_error(str(e))}[/{BAD}]")
                show_launch_screen()
                return
            break  # validation passed

        fp = os.path.abspath(fp)
        size_mb = os.path.getsize(fp) / (1024 * 1024)
        console.print(f"\n  [{ACCENT}]{os.path.basename(fp)}[/{ACCENT}]  [dim]{size_mb:.1f} MB[/dim]")

        # STEP 2 -- Expected hash (early, near file selection)
        console.print(
            "  [dim]Paste the expected hash from the developer's page,"
            " or press Enter to skip.[/dim]"
        )
        expected_raw = questionary.text(
            "Expected hash:",
            style=CIPHRA_STYLE,
        ).ask()
        if expected_raw:
            expected_raw = expected_raw.strip() or None
        else:
            expected_raw = None

        # STEP 3 -- Algorithm selection
        algo_choice = questionary.select(
            "Hash algorithm:",
            choices=[
                "sha256   standard. use this if unsure",
                "sha512   stronger. some developers publish sha512 checksums",
                "sha1     legacy. only if the developer specifically requires it",
                "md5      legacy. only if the developer specifically requires it",
            ],
            default="sha256   standard. use this if unsure",
            style=CIPHRA_STYLE,
        ).ask()
        algo = algo_choice.split()[0] if algo_choice else "sha256"

        expected_lengths = {"sha256": 64, "sha512": 128, "sha1": 40, "md5": 32}
        if expected_raw and len(expected_raw) != expected_lengths.get(algo, 0):
            _outcome_degraded(
                f"That does not look like a {algo.upper()} hash. "
                f"{algo.upper()} hashes are {expected_lengths[algo]} characters. Continuing."
            )

        # STEP 4 -- Auto-detect sig file
        sig_dir = os.path.dirname(fp)
        base = os.path.basename(fp)
        auto_sig = None
        for _ext in [".sig", ".asc", ".gpg"]:
            candidate = os.path.join(sig_dir, base + _ext)
            if os.path.isfile(candidate):
                # Reject .asc files that are actually public keys
                if _ext == ".asc":
                    try:
                        with open(candidate, "r", errors="ignore") as f:
                            first_line = f.readline().strip()
                        if "BEGIN PGP PUBLIC KEY BLOCK" in first_line:
                            console.print(
                                f"  [{CAUTION}][WARN] Found {os.path.basename(candidate)}"
                                f" but it is a public key, not a signature. Skipping.[/{CAUTION}]"
                            )
                            continue
                    except OSError:
                        pass
                auto_sig = candidate
                break

        # STEP 5 -- Offer sig file with three options
        sig = None
        key_choice = None

        if auto_sig:
            console.print(
                f"\n  [dim]Found signature file: {os.path.basename(auto_sig)}[/dim]"
            )
            sig_choice = questionary.select(
                "Use this signature file?",
                choices=[
                    "Yes, use it",
                    "No, enter a different path",
                    "Skip signature check",
                ],
                style=CIPHRA_STYLE,
            ).ask()

            if sig_choice is None:
                sig = None
            elif sig_choice == "Skip signature check":
                sig = None
            elif sig_choice == "Yes, use it":
                sig = auto_sig
            else:
                sig_input = _prompt_for_file(
                    "Signature file path:",
                    start_dir=sig_dir,
                )
                if sig_input and os.path.isfile(sig_input):
                    sig = _validate_sig_input(sig_input, fp)
                    # Extra content check for manually entered .asc
                    if sig and sig.lower().endswith(".asc"):
                        try:
                            with open(sig, "r", errors="ignore") as f:
                                first_line = f.readline().strip()
                            if "BEGIN PGP PUBLIC KEY BLOCK" in first_line:
                                console.print(
                                    f"  [{CAUTION}][WARN] That file is a public key,"
                                    f" not a signature. Skipping.[/{CAUTION}]"
                                )
                                sig = None
                        except OSError:
                            pass
        else:
            console.print()
            sig_choice = questionary.select(
                "Signature file:",
                choices=[
                    "Enter path",
                    "Skip signature check",
                ],
                style=CIPHRA_STYLE,
            ).ask()
            if sig_choice is None:
                sig = None
            elif sig_choice == "Enter path":
                sig_input = _prompt_for_file(
                    "Signature file path:",
                    start_dir=sig_dir,
                )
                if sig_input and os.path.isfile(sig_input):
                    sig = _validate_sig_input(sig_input, fp)
                    # Extra content check for manually entered .asc
                    if sig and sig.lower().endswith(".asc"):
                        try:
                            with open(sig, "r", errors="ignore") as f:
                                first_line = f.readline().strip()
                            if "BEGIN PGP PUBLIC KEY BLOCK" in first_line:
                                console.print(
                                    f"  [{CAUTION}][WARN] That file is a public key,"
                                    f" not a signature. Skipping.[/{CAUTION}]"
                                )
                                sig = None
                        except OSError:
                            pass

        # STEP 5b -- GPG availability check
        if sig is not None:
            if GPG_BIN is None:
                _outcome_degraded(
                    f"GPG is not installed. Signature check skipped.\n"
                    f"{_gpg_install_hint()}\n"
                    f"  Hash and VirusTotal checks will still run."
                )
                sig = None

        # STEP 6 -- Extract key ID from sig silently
        sig_key_id = None
        if sig and os.path.isfile(sig):
            with console.status(
                "  Reading signature...",
                spinner="dots",
                spinner_style=ACCENT,
            ):
                try:
                    _tmp = verify_signature(fp, sig)
                    sig_key_id = _tmp.get("key_id")
                    if not sig_key_id:
                        if GPG_BIN:
                            _proc = subprocess.run(
                                [GPG_BIN, "--batch", "--verify", sig, fp],
                                capture_output=True,
                                text=True,
                                timeout=30,
                            )
                            sig_key_id = extract_key_id(
                                _proc.stdout + "\n" + _proc.stderr
                            )
                except subprocess.TimeoutExpired:
                    _outcome_degraded("Could not read key ID from signature. Continuing.")
                    sig_key_id = None
                except subprocess.SubprocessError:
                    _outcome_degraded("Could not read key ID from signature. Continuing.")
                    sig_key_id = None
                except (OSError, ValueError):
                    sig_key_id = None

        if sig is not None:
            # STEP 7 -- Auto-detect key file
            auto_key = None

            file_norm = _norm(os.path.splitext(os.path.basename(fp))[0])
            try:
                for _f in sorted(os.listdir(sig_dir)):
                    _f_lower = _f.lower()
                    _f_path = os.path.join(sig_dir, _f)
                    if not os.path.isfile(_f_path):
                        continue
                    is_key_ext = (
                        _f_lower.endswith(".key") or
                        (_f_lower.endswith(".asc") and
                         any(word in _f_lower for word in ["sign", "key", "pub", "pgp", "gpg"]))
                    )
                    if not is_key_ext:
                        continue
                    _f_norm = _norm(os.path.splitext(_f_lower)[0])
                    if (
                        file_norm[:4] == _f_norm[:4] or
                        _f_norm in file_norm or
                        file_norm in _f_norm
                    ):
                        auto_key = _f_path
                        break
            except PermissionError:
                pass

            # STEP 8 -- Offer key file with options
            key_file = None

            if auto_key:
                console.print(
                    f"\n  [dim]Found key file: {os.path.basename(auto_key)}[/dim]"
                )
                key_choice = questionary.select(
                    "Use this key file?",
                    choices=[
                        "Yes",
                        "No, enter a different path",
                        "Fetch from keyserver instead",
                        "Skip key import",
                    ],
                    style=CIPHRA_STYLE,
                ).ask()

                if key_choice is None:
                    key_choice = "Skip key import"
                if key_choice == "Yes":
                    key_file = auto_key
                elif key_choice == "No, enter a different path":
                    key_input = _prompt_for_file(
                        "Key file path:",
                        start_dir=sig_dir,
                    )
                    if key_input and os.path.isfile(key_input):
                        key_file = key_input
                elif key_choice == "Fetch from keyserver instead":
                    key_file = None
                else:
                    key_file = None
            elif sig_key_id:
                console.print(
                    "\n  [dim]No key file found in this directory.[/dim]"
                )
                key_choice = questionary.select(
                    "Key setup:",
                    choices=[
                        "Fetch key from keyserver automatically",
                        "Enter key file path",
                        "Skip key import",
                    ],
                    style=CIPHRA_STYLE,
                ).ask()

                if key_choice is None:
                    key_choice = "Skip key import"
                if key_choice == "Enter key file path":
                    key_input = _prompt_for_file(
                        "Key file path:",
                        start_dir=sig_dir,
                    )
                    if key_input and os.path.isfile(key_input):
                        key_file = key_input
                elif key_choice == "Fetch key from keyserver automatically":
                    key_file = None
                else:
                    key_file = None

            # STEP 9 -- Import key file if selected
            if key_file:
                with console.status("  Reading key file...", spinner="dots", spinner_style=ACCENT):
                    result = import_and_trust_key(key_file, sig_key_id)

                if result.get("already_imported"):
                    console.print("  [dim]Key already in keyring.[/dim]")
                    if result.get("fingerprint"):
                        console.print(f"  [dim]Fingerprint: {result['fingerprint']}[/dim]")
                elif result["ok"]:
                    if result["matched"]:
                        console.print(f"  [{GOOD}]Key imported.[/{GOOD}]")
                        if result["fingerprint"]:
                            console.print(f"  [dim]Fingerprint: {result['fingerprint']}[/dim]")
                    else:
                        console.print(
                            f"\n  [{CAUTION}][WARN] Key fingerprint mismatch.[/{CAUTION}]\n\n"
                            f"  File key:      {result.get('fingerprint', 'unknown')}\n"
                            f"  Signature key: {sig_key_id}\n\n"
                            "  [dim]Developers sign with subkeys, not the master key.\n"
                            "  This is expected for most software.[/dim]\n"
                        )
                        proceed = questionary.select(
                            "How do you want to proceed?",
                            choices=[
                                "Continue verification anyway",
                                "Fetch key from keyserver instead",
                                "Skip signature check",
                            ],
                            style=CIPHRA_STYLE,
                        ).ask()

                        if proceed is None or proceed == "Skip signature check":
                            sig = None
                        elif proceed == "Fetch key from keyserver instead":
                            key_file = None
                            key_choice = "Fetch key from keyserver automatically"
                else:
                    translated = _translate_error(result.get("msg", ""))
                    retry = _outcome_recoverable(
                        translated,
                        choices=[
                            "Enter a different key file path",
                            "Fetch key from keyserver instead",
                            "Skip signature check",
                        ],
                    )
                    if retry is None or retry == "Skip signature check":
                        sig = None
                    elif retry == "Fetch key from keyserver instead":
                        key_file = None
                        key_choice = "Fetch key from keyserver automatically"
                    elif retry == "Enter a different key file path":
                        key_input = _prompt_for_file(
                            "Key file path:",
                            start_dir=sig_dir,
                        )
                        if key_input and os.path.isfile(key_input):
                            with console.status(
                                "  Reading key file...",
                                spinner="dots",
                                spinner_style=ACCENT,
                            ):
                                result = import_and_trust_key(key_input, sig_key_id)
                            if result["ok"]:
                                console.print(f"  [{GOOD}]Key imported.[/{GOOD}]")
                                if result.get("fingerprint"):
                                    console.print(f"  [dim]Fingerprint: {result['fingerprint']}[/dim]")
                            else:
                                _outcome_degraded("Import failed again. Skipping key import.")
                                sig = None
                        else:
                            _outcome_degraded("No file selected. Skipping key import.")
                            sig = None

            # STEP 10 -- Keyserver fetch if chosen
            if key_choice in (
                "Fetch from keyserver instead",
                "Fetch key from keyserver automatically",
            ):
                if not sig_key_id:
                    _outcome_degraded(
                        "Cannot fetch key without a signature file. Select a .sig file first."
                    )
                else:
                    KEYSERVERS = [
                        "keyserver.ubuntu.com",
                        "keys.openpgp.org",
                        "pgp.mit.edu",
                    ]
                    fetch_success = False
                    for ks in KEYSERVERS:
                        console.print(f"  [dim]Trying {ks}...[/dim]")
                        with console.status(f"  Fetching from {ks}...", spinner="dots", spinner_style=ACCENT):
                            _ks_result = fetch_gpg_key(sig_key_id, keyserver=ks)
                        if _ks_result["ok"]:
                            console.print(f"  [{GOOD}]Key imported from {ks}.[/{GOOD}]")
                            fetch_success = True
                            break
                        else:
                            _outcome_degraded(_translate_error(_ks_result.get("msg", "")))

                    if not fetch_success:
                        fallback = _outcome_recoverable(
                            "Could not find the key on any keyserver.",
                            choices=[
                                "Enter key file path",
                                "Check the developer's website",
                                "Skip signature check",
                            ],
                        )

                        if fallback is None or fallback == "Skip signature check":
                            sig = None
                        elif fallback == "Check the developer's website":
                            console.print(
                                "\n  [dim]The developer publishes their public key "
                                "on their download page. Look for a file ending in:\n"
                                "    .key  .asc  -signing-key.asc\n\n"
                                "  Download it and run ciphra again.[/dim]"
                            )
                            sig = None
                        elif fallback == "Enter key file path":
                            key_input = _prompt_for_file(
                                "Key file path:",
                                start_dir=sig_dir,
                            )
                            if key_input and os.path.isfile(key_input):
                                with console.status("  Reading key file...", spinner="dots", spinner_style=ACCENT):
                                    _import_result = import_and_trust_key(key_input, sig_key_id)
                                if not _import_result.get("ok"):
                                    _msg = _translate_error(_import_result.get("msg", ""))
                                    _outcome_degraded(f"Key import failed. {_msg}")

        # STEP 11 -- VirusTotal
        console.print()
        vt_key = get_vt_key()
        if not vt_key:
            vt_no_key_choice = questionary.select(
                "No VirusTotal API key configured.",
                choices=[
                    "Add a key now",
                    "Continue without VirusTotal",
                ],
                style=CIPHRA_STYLE,
            ).ask()
            if vt_no_key_choice is None or vt_no_key_choice == "Continue without VirusTotal":
                use_vt = False
            elif vt_no_key_choice == "Add a key now":
                _tier_result = _set_vt_key_flow()
                if _tier_result is None:
                    # User cancelled key setup
                    use_vt = False
                else:
                    use_vt = questionary.confirm(
                        "Run VirusTotal check now?",
                        default=True,
                        style=CIPHRA_STYLE,
                    ).ask() or False
        else:
            use_vt_choice = questionary.confirm(
                "Run VirusTotal check?",
                default=True,
                style=CIPHRA_STYLE,
            ).ask()
            if use_vt_choice is None:
                console.print("  [dim]Cancelled.[/dim]")
                show_launch_screen()
                return
            use_vt = use_vt_choice

        # STEP 12 -- Invoke verify and return to menu
        _IN_OPERATION = True
        try:
            ctx.invoke(verify, file=fp, sig=sig, vt=use_vt, algo=algo, expected=expected_raw)
        finally:
            _IN_OPERATION = False
        show_launch_screen()

    elif answer == "Hash a file":
        console.print(
            "  [dim]Generate a fingerprint to confirm"
            " a file has not been changed.[/dim]"
        )
        console.print("  [dim]Start with / or ~, Tab to complete, Ctrl+C to cancel.[/dim]")
        console.print()
        fp = _prompt_for_file("File path:", start_dir="/")
        if fp is None:
            console.print("  [dim]Cancelled.[/dim]")
            show_launch_screen()
            return

        while True:
            if os.path.isdir(fp):
                if not _outcome_hard_stop("That is a folder. Select a file inside it."):
                    show_launch_screen()
                    return
                fp = _prompt_for_file("File path:", start_dir="/")
                if fp is None:
                    show_launch_screen()
                    return
                continue
            if not os.path.exists(fp):
                if not _outcome_hard_stop("File not found."):
                    show_launch_screen()
                    return
                fp = _prompt_for_file("File path:", start_dir="/")
                if fp is None:
                    show_launch_screen()
                    return
                continue
            if os.path.getsize(fp) == 0:
                if not _outcome_hard_stop("The file is empty."):
                    show_launch_screen()
                    return
                fp = _prompt_for_file("File path:", start_dir="/")
                if fp is None:
                    show_launch_screen()
                    return
                continue
            try:
                with open(fp, "rb") as f:
                    f.read(1)
            except PermissionError:
                console.print(f"  [{BAD}][ERROR] Cannot read that file. Check file permissions.[/{BAD}]")
                show_launch_screen()
                return
            except OSError as e:
                console.print(f"  [{BAD}][ERROR] {_translate_error(str(e))}[/{BAD}]")
                show_launch_screen()
                return
            break

        fp = os.path.abspath(fp)
        size_mb = os.path.getsize(fp) / (1024 * 1024)
        console.print(f"\n  [{ACCENT}]{os.path.basename(fp)}[/{ACCENT}]  [dim]{size_mb:.1f} MB[/dim]")
        console.print()

        algo_choice = questionary.select(
            "Hash algorithm:",
            choices=[
                "sha256   standard. use this if unsure",
                "sha512   stronger. some developers publish sha512 checksums",
                "sha1     legacy. only if the developer specifically requires it",
                "md5      legacy. only if the developer specifically requires it",
            ],
            default="sha256   standard. use this if unsure",
            style=CIPHRA_STYLE,
        ).ask()
        if algo_choice is None:
            console.print("  [dim]Cancelled.[/dim]")
            show_launch_screen()
            return
        algo = algo_choice.split()[0]

        _IN_OPERATION = True
        try:
            ctx.invoke(hash_cmd, file=fp, algo=algo)
        except (KeyboardInterrupt, click.Abort):
            console.print("  [dim]Cancelled.[/dim]")
        finally:
            _IN_OPERATION = False
        show_launch_screen()

    elif answer == "Encrypt & Decrypt":
        _IN_OPERATION = True
        try:
            ctx.invoke(encrypt_decrypt_cmd)
        finally:
            _IN_OPERATION = False
        show_launch_screen()

    elif answer == "Digital Signatures":
        _IN_OPERATION = True
        try:
            ctx.invoke(digital_signatures_cmd)
        except (KeyboardInterrupt, click.Abort):
            pass
        finally:
            _IN_OPERATION = False
        show_launch_screen()

    elif answer == "Configure settings":
        _IN_OPERATION = True
        try:
            _configure_settings_loop(ctx)
        except (KeyboardInterrupt, click.Abort):
            pass
        finally:
            _IN_OPERATION = False
        show_launch_screen()


# --- CLI ---

@click.group(invoke_without_command=True)
@click.version_option(version=VERSION, prog_name="ciphra")
@click.pass_context
def cli(ctx):
    try:
        first_run_check()
        check_dirs()
        setup_logging()
        if ctx.invoked_subcommand is None:
            show_launch_screen()
    except KeyboardInterrupt:
        console.print("\n  [dim]Goodbye.[/dim]")
        sys.exit(0)


@cli.command(
    context_settings={"max_content_width": 80},
    epilog=(
        "Examples:\n\n"
        "  ciphra verify myfile.zip\n"
        "  ciphra verify myfile.zip --sig myfile.zip.asc\n"
        "  ciphra verify myfile.zip --no-vt\n"
        "  ciphra verify myfile.zip --expected a1b2c3d4...\n"
        "  ciphra verify myfile.zip --algo sha512\n\n"
        "Note:\n\n"
        "  File paths support tab completion.\n"
        "  Start typing and press Tab to autocomplete."
    ),
)
@click.argument("file", type=click.Path(exists=True))
@click.option("--sig", default=None, help="Signature file (.sig .asc .gpg)")
@click.option("--vt/--no-vt", default=True, help="Run VirusTotal check (requires API key)")
@click.option(
    "--algo",
    default="sha256",
    type=click.Choice(["md5", "sha1", "sha256", "sha512"], case_sensitive=False),
    help="Hash algorithm to use (default: sha256)",
)
@click.option("--expected", default=None, help="Expected hash value to compare against")
def verify(file, sig, vt, algo, expected):
    """Verify a file: hash, VirusTotal, and optional GPG signature check. No file size limit for local checks."""
    _run_verify(file, sig, vt, algo, expected)


def _run_verify(file, sig, vt, algo, expected):
    try:
        _run_verify_inner(file, sig, vt, algo, expected)
    except KeyboardInterrupt:
        console.print("  [dim]Scan cancelled.[/dim]")
        return
    except Exception as e:
        logging.error("Unhandled exception in _run_verify: %s", e, exc_info=True)
        console.print(
            f"  [{BAD}][ERROR] An unexpected error occurred."
            f" Details in logs/ciphra.log.[/{BAD}]"
        )
        return


def _run_verify_inner(file, sig, vt, algo, expected):
    fp = os.path.abspath(file)
    filename = os.path.basename(fp)

    # File validation
    try:
        if not os.path.exists(fp):
            console.print(f"  [{BAD}][ERROR] File not found: {filename}[/{BAD}]")
            return
        if os.path.isdir(fp):
            console.print(
                f"  [{BAD}][ERROR] That is a folder. Select a file inside it.[/{BAD}]"
            )
            return
        file_size = os.path.getsize(fp)
        if file_size == 0:
            console.print(f"  [{BAD}][ERROR] The file is empty.[/{BAD}]")
            return
        with open(fp, "rb") as f:
            f.read(1)
    except PermissionError:
        console.print(
            f"  [{BAD}][ERROR] Cannot read that file. Check file permissions.[/{BAD}]"
        )
        return
    except OSError as e:
        console.print(f"  [{BAD}][ERROR] {_translate_error(str(e))}[/{BAD}]")
        return

    size_mb = file_size / (1024 * 1024)
    console.print(
        f"  [{ACCENT}]{filename}[/{ACCENT}]  [dim]{size_mb:.1f} MB[/dim]"
    )

    # Hash
    try:
        if file_size > PROGRESS_THRESHOLD:
            computed_hash = _hash_with_progress(fp, algo)
        else:
            with console.status(
                f"  Hashing ({algo.upper()})...",
                spinner="dots",
                spinner_style=ACCENT,
            ):
                computed_hash = compute_hash(fp, algo=algo)
    except PermissionError as e:
        console.print(f"  [{BAD}][ERROR] {_translate_error(str(e))}[/{BAD}]")
        return
    except (OSError, IOError) as e:
        console.print(f"  [{BAD}][ERROR] {_translate_error(str(e))}[/{BAD}]")
        return
    except (FileNotFoundError, ValueError) as e:
        console.print(f"  [{BAD}][ERROR] {_translate_error(str(e))}[/{BAD}]")
        return

    # Expected hash comparison with mismatch pause
    hash_matched = None

    if expected:
        expected = expected.strip()
        if expected.lower() == computed_hash.lower():
            hash_matched = True
        else:
            hash_matched = False
            console.print(f"\n  [{BAD}]Hash mismatch.[/{BAD}]")
            console.print(f"  [dim]Expected: {expected}[/dim]")
            console.print(f"  [dim]Got:      {computed_hash}[/dim]")
            console.print()
            mismatch_choice = questionary.select(
                "What do you want to do?",
                choices=[
                    "Re-enter the expected hash",
                    "Continue scan (verdict will be FLAGGED)",
                    "Abort and return to menu",
                ],
                style=CIPHRA_STYLE,
            ).ask()
            if mismatch_choice is None or mismatch_choice == "Abort and return to menu":
                return
            elif mismatch_choice == "Re-enter the expected hash":
                while True:
                    new_exp = questionary.text(
                        "Expected hash:", style=CIPHRA_STYLE
                    ).ask()
                    if new_exp is None:
                        # Ctrl+C — treat as abort
                        hash_matched = False
                        break
                    if not new_exp.strip():
                        # Blank input — silently re-ask
                        continue
                    expected = new_exp.strip()
                    break

                if new_exp is not None and new_exp.strip():
                    # Ask whether to keep current algo or change it
                    algo_choice = questionary.select(
                        "Hash algorithm:",
                        choices=[
                            f"Continue with {algo.upper()}",
                            "Change algorithm (will rehash the file)",
                        ],
                        style=CIPHRA_STYLE,
                    ).ask()

                    if algo_choice is None:
                        hash_matched = False
                    elif algo_choice == "Change algorithm (will rehash the file)":
                        console.print(
                            "  [dim]Changing the algorithm will rehash the file.[/dim]"
                        )
                        new_algo_choice = questionary.select(
                            "Hash algorithm:",
                            choices=[
                                "sha256   standard. use this if unsure",
                                "sha512   stronger. some developers publish sha512 checksums",
                                "sha1     legacy. only if the developer specifically requires it",
                                "md5      legacy. only if the developer specifically requires it",
                            ],
                            style=CIPHRA_STYLE,
                        ).ask()
                        if new_algo_choice is None:
                            hash_matched = False
                        else:
                            algo = new_algo_choice.split()[0]
                            # Rehash with new algorithm
                            try:
                                if file_size > PROGRESS_THRESHOLD:
                                    computed_hash = _hash_with_progress(fp, algo)
                                else:
                                    with console.status(
                                        f"  Hashing ({algo.upper()})...",
                                        spinner="dots",
                                        spinner_style=ACCENT,
                                    ):
                                        computed_hash = compute_hash(fp, algo=algo)
                            except (PermissionError, OSError, IOError,
                                    FileNotFoundError, ValueError) as e:
                                console.print(
                                    f"  [{BAD}][ERROR] {_translate_error(str(e))}[/{BAD}]"
                                )
                                return
                            if expected.lower() == computed_hash.lower():
                                hash_matched = True
                            else:
                                hash_matched = False
                    else:
                        # Continue with existing algo and already computed hash
                        if expected.lower() == computed_hash.lower():
                            hash_matched = True
                        else:
                            hash_matched = False

                    # Length validation after algo is finalized
                    if algo_choice is not None:
                        _re_lengths = {"sha256": 64, "sha512": 128, "sha1": 40, "md5": 32}
                        if len(expected) != _re_lengths.get(algo, 0):
                            _outcome_degraded(
                                f"That does not look like a {algo.upper()} hash. "
                                f"{algo.upper()} hashes are {_re_lengths[algo]} characters. Continuing."
                            )
            elif mismatch_choice == "Continue scan (verdict will be FLAGGED)":
                hash_matched = False

    # VirusTotal + Signature check — single outer spinner covers the gap
    # after the hash progress bar. Interactive branches (no_pubkey prompts)
    # naturally cause the spinner to stop when console output is needed.
    vt_result = None
    vt_ratio = "skipped"
    vt_skipped = True
    sig_status = "not_checked"
    sig_result = None

    with console.status(
        "  Checking...",
        spinner="dots",
        spinner_style=ACCENT,
    ):
        # VirusTotal
        if not vt:
            vt_skipped = True
        else:
            api_key = get_vt_key()
            if not api_key:
                vt_ratio = "no_key"
                vt_skipped = True
            else:
                vt_skipped = False
                vt_upload_limit = get_vt_upload_limit()
                vt_result = vt_check_file(
                    fp,
                    computed_hash,
                    api_key,
                    file_size=file_size,
                    upload_limit=vt_upload_limit,
                    tier=get_vt_tier(),
                )
                vt_ratio = vt_result["ratio"] if vt_result.get("available") else vt_result.get("reason", "unavailable")

        # Signature check (initial verification — interactive branches follow outside)
        if sig is not None:
            sig_path = os.path.abspath(sig)
            ext = Path(sig_path).suffix.lower()
            key_extensions = [".key", ".pem", ".pub"]

            if ext in key_extensions:
                sig_status = "wrong_file_type"
                _sig_warn_wrong_type = f"That looks like a public key file ({ext}), not a signature file."
            elif ext not in SUPPORTED_SIG_EXTENSIONS:
                sig_status = "wrong_file_type"
                _sig_warn_wrong_type = f"Unsupported signature file type: {ext}. Supported: .sig .asc .gpg"
            else:
                _sig_warn_wrong_type = None
                # .asc content check
                if ext == ".asc":
                    try:
                        with open(sig_path, "r", errors="ignore") as f:
                            first_line = f.readline().strip()
                        if "BEGIN PGP PUBLIC KEY BLOCK" in first_line:
                            sig_status = "wrong_file_type"
                            _sig_warn_wrong_type = "That is a public key file, not a signature file."
                            sig_result = None
                    except OSError:
                        pass

                if sig_status != "wrong_file_type":
                    if GPG_BIN is None:
                        sig_status = "gpg_missing"
                    else:
                        sig_result = verify_signature(fp, sig_path)
                        sig_status = sig_result["status"]
        else:
            sig_path = None
            _sig_warn_wrong_type = None

    # Build a normalised vt dict for verdict logic
    if vt_result is not None:
        vt_data = vt_result
    elif not vt or not get_vt_key():
        vt_data = {"available": False, "reason": "no_key"}
    else:
        vt_data = {"available": False, "reason": "unavailable"}

    # Post-spinner: emit any warnings/interactive prompts that need console output
    if sig is not None:
        if sig_status == "wrong_file_type":
            console.print(
                f"  [{CAUTION}][WARN] {_sig_warn_wrong_type}[/{CAUTION}]"
            )
        elif sig_status == "gpg_missing":
            _outcome_degraded(
                f"GPG is not installed. Signature check skipped.\n"
                f"{_gpg_install_hint()}"
            )
        elif sig_result is not None and sig_result["status"] == "no_pubkey":
            key_id = sig_result.get("key_id")
            _outcome_degraded(
                "Public key not found."
                + (f" Key ID: {key_id}" if key_id else "")
            )
            if key_id:
                use_fetch = questionary.select(
                    "Key not found. What do you want to do?",
                    choices=[
                        "Fetch key from keyserver automatically",
                        "I have a key file to import",
                        "Skip signature check",
                    ],
                    style=CIPHRA_STYLE,
                ).ask()

                if use_fetch == "Fetch key from keyserver automatically":
                    KEYSERVERS = [
                        "keyserver.ubuntu.com",
                        "keys.openpgp.org",
                        "pgp.mit.edu",
                    ]
                    fetch_result = None
                    for ks in KEYSERVERS:
                        console.print(f"  [dim]Trying {ks}...[/dim]")
                        with console.status(f"  Fetching from {ks}...", spinner="dots", spinner_style=ACCENT):
                            result = fetch_gpg_key(key_id, keyserver=ks)
                        if result["ok"]:
                            fetch_result = result
                            console.print(f"  [{GOOD}]Key imported from {ks}.[/{GOOD}]")
                            break
                        else:
                            _outcome_degraded(_translate_error(result.get("msg", "")))

                    if fetch_result and fetch_result["ok"]:
                        sig_result = verify_signature(fp, sig_path)
                        sig_status = sig_result["status"]
                        if sig_result["status"] != "verified":
                            _outcome_degraded(
                                "Key imported but signature could not be verified. "
                                "Verify the fingerprint on the developer's website."
                            )
                    else:
                        _outcome_degraded(
                            "Could not fetch key from any keyserver. "
                            "Download the key from the developer's website and import it."
                        )

                elif use_fetch == "I have a key file to import":
                    key_path = _prompt_for_file(
                        "Key file path:",
                        start_dir=os.path.dirname(fp),
                    )
                    if key_path and os.path.isfile(key_path):
                        with console.status("  Reading key file...", spinner="dots", spinner_style=ACCENT):
                            import_result = import_and_trust_key(key_path, key_id)
                        if import_result["ok"]:
                            if not import_result["matched"]:
                                _outcome_degraded(
                                    "Imported key does not match the signature key ID."
                                )
                                proceed = questionary.confirm(
                                    "  Continue anyway?",
                                    default=False,
                                    style=CIPHRA_STYLE,
                                ).ask()
                                if not proceed:
                                    sig_status = "not_checked"
                                    sig_result = None
                            if sig_result is not None:
                                sig_result = verify_signature(fp, sig_path)
                                sig_status = sig_result["status"]
                        else:
                            _outcome_degraded(
                                _translate_error(import_result.get("msg", ""))
                            )
                    else:
                        _outcome_degraded("No key file selected.")

                else:
                    _outcome_degraded("Signature check skipped.")

    # Result output
    DIVIDER = ("─" if UNICODE_OK else "-") * min(60, console.width - 4)
    LABEL_WIDTH = 12

    console.print(f"\n  [dim]{DIVIDER}[/dim]\n")

    # Hash value — own lines
    console.print(f"  [dim]{algo.upper()}[/dim]")
    console.print(f"  [{ACCENT}]{computed_hash}[/{ACCENT}]")
    console.print()

    # Hash match line
    if hash_matched is True:
        console.print(
            f"  {'Hash':<{LABEL_WIDTH}}[{GOOD}]matched[/{GOOD}]"
        )
    elif hash_matched is False:
        console.print(
            f"  {'Hash':<{LABEL_WIDTH}}[{BAD}]MISMATCH[/{BAD}]"
        )
        if expected:
            console.print(
                f"  [dim]{'Expected':<{LABEL_WIDTH}}  {expected}[/dim]"
            )

    # VT line
    if vt_skipped:
        if not vt:
            console.print(f"  {'VirusTotal':<{LABEL_WIDTH}}[dim]skipped[/dim]")
        else:
            console.print(
                f"  {'VirusTotal':<{LABEL_WIDTH}}[dim]no API key configured[/dim]"
            )
    elif vt_data.get("available") and vt_data.get("total", 0) > 0:
        _vt_upload_limit = get_vt_upload_limit()
        _vt_hash_only = file_size > _vt_upload_limit
        _vt_method = "[dim](hash lookup only)[/dim]" if _vt_hash_only else "[dim](file uploaded)[/dim]"
        positives = vt_data["positives"]
        ratio = vt_data["ratio"]
        permalink = vt_data.get("permalink", "")
        if positives == 0:
            console.print(
                f"  {'VirusTotal':<{LABEL_WIDTH}}"
                f"[{GOOD}]{ratio}, no threats[/{GOOD}]  {_vt_method}"
            )
            if permalink:
                console.print(f"  {'':<{LABEL_WIDTH}}[dim]{permalink}[/dim]")
        elif positives <= 9:
            console.print(
                f"  {'VirusTotal':<{LABEL_WIDTH}}"
                f"[{CAUTION}]{ratio}, low detection[/{CAUTION}]  {_vt_method}"
            )
            if permalink:
                console.print(f"  {'':<{LABEL_WIDTH}}[dim]{permalink}[/dim]")
        else:
            console.print(
                f"  {'VirusTotal':<{LABEL_WIDTH}}"
                f"[{BAD}]{ratio}, flagged[/{BAD}]  {_vt_method}"
            )
            if permalink:
                console.print(f"  {'':<{LABEL_WIDTH}}[dim]{permalink}[/dim]")
            for eng in vt_data.get("engines", [])[:5]:
                result_text = eng.get("result") or ""
                console.print(
                    f"    [dim]{eng['name']}[/dim]  [{BAD}]{result_text}[/{BAD}]"
                )
    else:
        reason = vt_data.get("reason", "unavailable")
        if reason == "not_in_db":
            console.print(
                f"  {'VirusTotal':<{LABEL_WIDTH}}"
                f"[dim]not in database  (hash lookup only)[/dim]"
            )
        else:
            display = _translate_error(reason)
            console.print(
                f"  {'VirusTotal':<{LABEL_WIDTH}}[dim]{display}[/dim]"
            )

    # Signature line
    if sig_result is None:
        status_map = {
            "not_checked": "not checked",
            "wrong_file_type": "wrong file type",
            "gpg_missing": "GPG not installed",
            "error": "error",
        }
        text = status_map.get(sig_status, sig_status)
        console.print(f"  {'Signature':<{LABEL_WIDTH}}[dim]{text}[/dim]")
    elif sig_result["status"] == "verified":
        trust = sig_result.get("trust", "unknown")
        fp_short = (sig_result.get("fingerprint") or "")[-16:]
        short_suffix = f"  [dim]...{fp_short}[/dim]" if fp_short else ""
        if trust in ("full", "ultimate"):
            console.print(
                f"  {'Signature':<{LABEL_WIDTH}}"
                f"[{GOOD}]verified, trusted[/{GOOD}]{short_suffix}"
            )
        else:
            console.print(
                f"  {'Signature':<{LABEL_WIDTH}}"
                f"[{CAUTION}]verified, trust unconfirmed[/{CAUTION}]{short_suffix}"
            )
    elif sig_result["status"] == "bad":
        console.print(
            f"  {'Signature':<{LABEL_WIDTH}}"
            f"[{BAD}]invalid. File may be tampered.[/{BAD}]"
        )
    elif sig_result["status"] == "no_pubkey":
        key_id = sig_result.get("key_id", "")
        suffix = f" ({key_id})" if key_id else ""
        console.print(
            f"  {'Signature':<{LABEL_WIDTH}}"
            f"[{CAUTION}]key not found{suffix}[/{CAUTION}]"
        )
    else:
        msg = _translate_error(sig_result.get("msg", ""))
        console.print(
            f"  {'Signature':<{LABEL_WIDTH}}[{CAUTION}]{msg}[/{CAUTION}]"
        )

    # Second separator
    console.print(f"\n  [dim]{DIVIDER}[/dim]\n")

    # Verdict
    verdict, notes = compute_verdict(vt_data, sig_result, vt_skipped)

    # Hash mismatch overrides everything
    if hash_matched is False:
        verdict = VERDICT_FLAGGED
        notes = ["Hash does not match. File may be corrupt or tampered."]

    # Hash matched with no VT/sig — replace the generic "compare manually" note
    if hash_matched is True and verdict == VERDICT_CHECKED:
        notes = ["Hash matched. VirusTotal and signature checks were skipped."]

    # VT not in database with sig verified — explain this is normal
    if (
        vt_data.get("reason") == "not_in_db"
        and sig_result
        and sig_result.get("status") == "verified"
    ):
        notes.append(
            "Having no VirusTotal record is common for privacy-focused"
            " or niche projects."
            " The signature check is the stronger verification here."
        )

    # VT not in database, no sig — tell user what to do
    if (
        vt_data.get("reason") == "not_in_db"
        and (sig_result is None or sig_result.get("status") != "verified")
        and not vt_skipped
    ):
        notes.append(
            "None of the 70+ antivirus engines have seen this file before. "
            "Verify the hash against the developer's published value."
        )

    VERDICT_SYMBOLS_UNICODE = {
        VERDICT_CLEAN:       "✓",
        VERDICT_FLAGGED:     "✗",
        VERDICT_REVIEW:      "△",
        VERDICT_LIKELY_SAFE: "✓",
        VERDICT_UNVERIFIED:  "?",
        VERDICT_CHECKED:     "-",
    }
    VERDICT_SYMBOLS_ASCII = {
        VERDICT_CLEAN:       "+",
        VERDICT_FLAGGED:     "x",
        VERDICT_REVIEW:      "!",
        VERDICT_LIKELY_SAFE: "+",
        VERDICT_UNVERIFIED:  "?",
        VERDICT_CHECKED:     "-",
    }
    symbols = VERDICT_SYMBOLS_UNICODE if UNICODE_OK else VERDICT_SYMBOLS_ASCII

    VERDICT_COLORS = {
        VERDICT_CLEAN:       GOOD,
        VERDICT_FLAGGED:     BAD,
        VERDICT_REVIEW:      CAUTION,
        VERDICT_LIKELY_SAFE: GOOD,
        VERDICT_UNVERIFIED:  CAUTION,
        VERDICT_CHECKED:     "dim",
    }

    symbol = symbols.get(verdict, "-")
    color = VERDICT_COLORS.get(verdict, "dim")
    bold_verdicts = (VERDICT_CLEAN, VERDICT_FLAGGED, VERDICT_LIKELY_SAFE)
    bold = " bold" if verdict in bold_verdicts else ""

    console.print(f"  [{color}{bold}]{symbol}  {verdict}[/{color}{bold}]")

    for note in notes:
        console.print(f"  [dim]{note}[/dim]")

    # Fingerprint block — only when sig verified and trust not full/ultimate
    if (
        sig_result
        and sig_result["status"] == "verified"
        and sig_result.get("trust") not in ("full", "ultimate")
    ):
        fingerprint = sig_result.get("fingerprint", "")
        display_fp = _get_master_key_fp(fingerprint) or fingerprint
        if display_fp:
            console.print(
                "  [dim]Verify this fingerprint on the developer's website:[/dim]"
            )
            console.print(f"  [{ACCENT}]{display_fp}[/{ACCENT}]")
            console.print(
                "  [dim]If it matches, the file is safe to use.[/dim]"
            )
            console.print()
    else:
        console.print()

    write_scan_log(filename, computed_hash, vt_ratio, sig_status, verdict)


@cli.command(
    name="hash",
    context_settings={"max_content_width": 80},
    epilog=(
        "Examples:\n\n"
        "  ciphra hash myfile.zip\n"
        "  ciphra hash myfile.zip --algo sha512\n"
        "  ciphra hash /path/to/file.iso"
    ),
)
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--algo",
    default="sha256",
    type=click.Choice(["sha256", "sha512", "sha1", "md5"]),
    help="Hash algorithm.",
)
@click.pass_context
def hash_cmd(ctx, file, algo):
    """Hash a file using SHA-256 or other algorithms. No file size limit."""
    fp = os.path.abspath(file)
    filename = os.path.basename(fp)

    try:
        if not os.path.exists(fp):
            console.print(f"  [{BAD}][ERROR] File not found: {filename}[/{BAD}]")
            return
        if os.path.isdir(fp):
            console.print(
                f"  [{BAD}][ERROR] That is a folder. Select a file inside it.[/{BAD}]"
            )
            return
        file_size = os.path.getsize(fp)
        if file_size == 0:
            console.print(f"  [{BAD}][ERROR] The file is empty.[/{BAD}]")
            return
        with open(fp, "rb") as f:
            f.read(1)
    except PermissionError:
        console.print(
            f"  [{BAD}][ERROR] Cannot read that file. Check file permissions.[/{BAD}]"
        )
        return
    except OSError as e:
        console.print(f"  [{BAD}][ERROR] {_translate_error(str(e))}[/{BAD}]")
        return

    try:
        if file_size > PROGRESS_THRESHOLD:
            digest = _hash_with_progress(fp, algo)
        else:
            with console.status(
                f"  Hashing ({algo.upper()})...",
                spinner="dots",
                spinner_style=ACCENT,
            ):
                digest = compute_hash(fp, algo=algo)
    except PermissionError as e:
        console.print(f"  [{BAD}][ERROR] {_translate_error(str(e))}[/{BAD}]")
        return
    except (OSError, IOError, FileNotFoundError, ValueError) as e:
        console.print(f"  [{BAD}][ERROR] {_translate_error(str(e))}[/{BAD}]")
        return

    console.print()
    console.print(f"  [dim]{algo.upper()}[/dim]")
    console.print(f"  [{ACCENT}]{digest}[/{ACCENT}]")
    console.print(f"  [dim]{filename}[/dim]")
    console.print()


def _encrypt_decrypt_loop(first_entry: bool = True) -> None:
    """Encrypt & Decrypt menu loop."""
    if first_entry:
        console.print(
            "  [dim]Protect a file so only you or a"
            " specific recipient can read it.[/dim]"
        )
    console.print()
    answer = questionary.select(
        "Encrypt & Decrypt",
        choices=[
            "Encrypt a file",
            "Decrypt a file",
            "Back",
        ],
        style=CIPHRA_STYLE,
    ).ask()

    if answer is None or answer == "Back":
        return

    if answer == "Encrypt a file":
        _encrypt_file_flow()
    elif answer == "Decrypt a file":
        _decrypt_file_flow()
    _encrypt_decrypt_loop(first_entry=False)


@cli.command(name="encrypt-decrypt")
def encrypt_decrypt_cmd():
    """Encrypt or decrypt a file."""
    _encrypt_decrypt_loop(first_entry=True)


def _validate_file_for_crypto(fp: str) -> bool:
    """Validate file for encrypt/decrypt operations.

    Returns True if valid. Prints error and returns False if not.
    """
    if os.path.isdir(fp):
        console.print(f"  [{BAD}][ERROR] That is a folder. Select a file inside it.[/{BAD}]")
        return False
    if not os.path.exists(fp):
        console.print(f"  [{BAD}][ERROR] File not found.[/{BAD}]")
        return False
    if os.path.getsize(fp) == 0:
        console.print(f"  [{BAD}][ERROR] The file is empty.[/{BAD}]")
        return False
    try:
        with open(fp, "rb") as f:
            f.read(1)
    except PermissionError:
        console.print(f"  [{BAD}][ERROR] Cannot read that file. Check file permissions.[/{BAD}]")
        return False
    except OSError as e:
        console.print(f"  [{BAD}][ERROR] {_translate_error(str(e))}[/{BAD}]")
        return False
    return True


def _prompt_output_path(default_out: str) -> str | None:
    """Ask user for output path. Handle overwrite/timestamp/cancel if file exists.

    Returns chosen path, or None if cancelled.
    """
    out = questionary.text(
        "  Output path:", default=default_out, style=CIPHRA_STYLE
    ).ask()
    if out is None:
        console.print("  [dim]Cancelled.[/dim]")
        return None
    out = out.strip()
    if not out:
        console.print("  [dim]Cancelled.[/dim]")
        return None

    if os.path.exists(out):
        choice = questionary.select(
            "  Output file already exists.",
            choices=[
                "Overwrite",
                "Enter new path",
                "Cancel",
            ],
            style=CIPHRA_STYLE,
        ).ask()
        if choice is None or choice == "Cancel":
            console.print("  [dim]Cancelled.[/dim]")
            return None
        if choice == "Enter new path":
            new_path = questionary.text(
                "  Save as:", default=out, style=CIPHRA_STYLE
            ).ask()
            if not new_path or new_path is None:
                console.print("  [dim]Cancelled.[/dim]")
                return None
            out = os.path.abspath(new_path.strip())
        # "Overwrite" falls through with original out

    return out


def _encrypt_file_flow() -> None:
    """Handle Encrypt a file sub-flow."""
    method = questionary.select(
        "  Encryption method:",
        choices=[
            "Symmetric    AES-256-GCM + Argon2id  password-based, no recipients needed",
            "Asymmetric   GPG public key encryption  encrypt for a specific recipient",
            "Back",
        ],
        style=CIPHRA_STYLE,
    ).ask()

    if method is None or method == "Back":
        return

    console.print("  [dim]Start with / or ~, Tab to complete, Ctrl+C to cancel.[/dim]")
    console.print()
    fp = _prompt_for_file("  File path:", start_dir="/")
    if fp is None:
        console.print("  [dim]Cancelled.[/dim]")
        return

    fp = os.path.abspath(fp)
    if not _validate_file_for_crypto(fp):
        return

    size_mb = os.path.getsize(fp) / (1024 * 1024)
    console.print(
        f"  [{ACCENT}]{os.path.basename(fp)}[/{ACCENT}]  [dim]{size_mb:.1f} MB[/dim]"
    )
    console.print()

    if size_mb >= 1024:
        console.print(
            f"  [{CAUTION}][WARN] Large file ({size_mb / 1024:.1f} GB)."
            f" Decryption requires ~128 MB of free RAM for key derivation.[/{CAUTION}]"
        )
        proceed = questionary.confirm(
            "  Continue?", default=True, style=CIPHRA_STYLE
        ).ask()
        if proceed is None or not proceed:
            console.print("  [dim]Cancelled.[/dim]")
            return

    if fp.endswith(".ciphra"):
        console.print(
            f"  [{CAUTION}][WARN] This file is already"
            f" ciphra-encrypted.[/{CAUTION}]"
        )
        console.print(
            "  [dim]Encrypting it again adds no security benefit.[/dim]"
        )
        proceed = questionary.confirm(
            "  Encrypt anyway?", default=False, style=CIPHRA_STYLE
        ).ask()
        if proceed is None or not proceed:
            console.print("  [dim]Cancelled.[/dim]")
            return

    elif fp.endswith(".gpg"):
        console.print(
            f"  [{CAUTION}][WARN] This file is already"
            f" GPG-encrypted.[/{CAUTION}]"
        )
        console.print(
            "  [dim]Encrypting it again adds no security benefit.[/dim]"
        )
        proceed = questionary.confirm(
            "  Encrypt anyway?", default=False, style=CIPHRA_STYLE
        ).ask()
        if proceed is None or not proceed:
            console.print("  [dim]Cancelled.[/dim]")
            return

    if method.startswith("Symmetric"):
        _encrypt_symmetric(fp)
    else:
        _encrypt_asymmetric(fp)


def _encrypt_symmetric(fp: str) -> None:
    """Symmetric encryption flow for a validated file path."""
    console.print(
        "  [dim]Recommended: 12+ characters using uppercase,"
        " lowercase, numbers, and symbols.[/dim]"
    )
    console.print()
    password = None
    attempts = 0
    while attempts < 3:
        pw = questionary.password("  Password:", style=CIPHRA_STYLE).ask()
        if pw is None:
            console.print("  [dim]Cancelled.[/dim]")
            return
        if not pw:
            continue
        while True:
            confirm = questionary.password("  Confirm password:", style=CIPHRA_STYLE).ask()
            if confirm is None:
                console.print("  [dim]Cancelled.[/dim]")
                return
            if confirm:
                break
        if pw != confirm:
            attempts += 1
            console.print(f"  [{CAUTION}][WARN] Passwords do not match.[/{CAUTION}]")
            if attempts >= 3:
                console.print(
                    f"  [{BAD}][ERROR] Too many mismatches. Returning to menu.[/{BAD}]"
                )
                return
            console.print()
            continue
        if len(pw) < 12:
            console.print(
                f"  [{CAUTION}][WARN] Short password."
                f" Weak passwords can be brute-forced.[/{CAUTION}]"
            )
            retry = questionary.confirm(
                "  Choose a different password?", default=True, style=CIPHRA_STYLE
            ).ask()
            if retry is None or retry:
                continue
        password = pw
        break

    if password is None:
        return

    default_out = fp + ".ciphra"
    console.print()
    output_path = _prompt_output_path(default_out)
    if output_path is None:
        return

    # Compute sha256 of input before encryption for the log
    sha256 = compute_hash(fp, algo="sha256")
    console.print()

    try:
        with console.status(
            "  Calibrating key strength...", spinner="dots", spinner_style=ACCENT
        ):
            params = calibrate_argon2_params()

        enc_salt = os.urandom(16)

        with console.status(
            "  Deriving key...", spinner="dots", spinner_style=ACCENT
        ):
            enc_key = derive_key(password.encode(), enc_salt, *params)

        with console.status(
            "  Encrypting...", spinner="dots", spinner_style=ACCENT
        ):
            _crypto_encrypt_file(
                fp, output_path, password,
                _precomputed_key=enc_key,
                _precomputed_params=params,
                _precomputed_salt=enc_salt,
            )
    except KeyboardInterrupt:
        console.print("\n  [dim]Cancelled.[/dim]")
        return
    except OSError as e:
        console.print(f"  [{BAD}][ERROR] {_translate_error(str(e))}[/{BAD}]")
        return
    except Exception as e:
        console.print(f"  [{BAD}][ERROR] {_translate_error(str(e))}[/{BAD}]")
        return

    console.print()
    console.print(f"  [{GOOD}]Encrypted:[/{GOOD}]")
    console.print(f"  [{ACCENT}]{output_path}[/{ACCENT}]")
    console.print("  [dim]The original file was not deleted.[/dim]")
    console.print(
        "  [dim].ciphra files can only be decrypted with ciphra.[/dim]"
    )
    write_operation_log(os.path.basename(fp), sha256, "encrypt", "ok")


def _encrypt_asymmetric(fp: str) -> None:
    """Asymmetric encryption flow for a validated file path."""
    if GPG_BIN is None:
        _outcome_degraded(
            "GPG is not installed. Asymmetric encryption requires GPG.\n"
            "  Use symmetric encryption instead, or install GPG."
        )
        return

    keys = list_encryption_keys()

    keyring_path = (
        os.path.join(os.environ.get("APPDATA", "%APPDATA%"), "gnupg")
        if platform.system() == "Windows"
        else os.path.expanduser("~/.gnupg")
    )
    console.print(
        "  [dim]Locked with the recipient's public key."
        " Only their private key can open it.[/dim]"
    )
    console.print(
        f"  [dim]Keys are from your local GPG keyring: {keyring_path}[/dim]"
    )
    console.print()
    console.print(f"  [{ACCENT}]Recipient public keys[/{ACCENT}]")
    console.print(
        "  [dim]Only encryption-capable keys from your GPG"
        " keyring are shown.[/dim]"
    )
    console.print()

    if not keys:
        console.print(
            f"  [{CAUTION}][WARN] No public keys found in keyring.[/{CAUTION}]"
        )
        console.print(
            "  [dim]Import a recipient's public key file (.asc or .gpg) to continue.[/dim]"
        )

    key_choices = []
    for k in keys:
        label = f"{k['uid']}  {k['algo']}  ...{k['fingerprint'][-8:]}"
        if k.get("expired"):
            label += "  [expired]"
        elif k.get("expiry") and k["expiry"] != "never":
            label += f"  expires {k['expiry']}"
        key_choices.append(label)
    key_choices.append(questionary.Separator("─" * 18 if UNICODE_OK else "-" * 18))
    key_choices.append("Import from file...")
    key_choices.append("Cancel")

    selected = questionary.select(
        "  Encrypt for:", choices=key_choices, style=CIPHRA_STYLE
    ).ask()

    if selected == "Import from file...":
        console.print(
            "  [dim]Enter path to a .asc or .gpg public key file.[/dim]"
        )
        console.print(
            "  [dim]Start with / or ~, Tab to complete, Ctrl+C to cancel.[/dim]"
        )
        key_file = _prompt_for_file("  Key file path:", start_dir="/")
        if key_file is None:
            console.print("  [dim]Cancelled.[/dim]")
            return
        key_file = os.path.abspath(key_file)
        console.print()
        with console.status(
            "  Importing key...", spinner="dots", spinner_style=ACCENT
        ):
            import_result = import_public_key_file(key_file)
        if not import_result["ok"]:
            console.print(
                f"  [{BAD}][ERROR]"
                f" {_translate_error(import_result['msg'])}[/{BAD}]"
            )
            return
        console.print()
        console.print(f"  [{GOOD}]Key imported.[/{GOOD}]")
        console.print()
        # Reload keys from keyring after import
        keys = list_encryption_keys()
        if not keys:
            console.print(
                f"  [{CAUTION}][WARN] Key imported but no"
                f" encryption-capable keys found.[/{CAUTION}]"
            )
            console.print(
                "  [dim]The imported key may be signing-only.[/dim]"
            )
            return
        # Rebuild key_choices with updated keyring
        key_choices = []
        for k in keys:
            label = f"{k['uid']}  {k['algo']}  ...{k['fingerprint'][-8:]}"
            if k.get("expired"):
                label += "  [expired]"
            elif k.get("expiry") and k["expiry"] != "never":
                label += f"  expires {k['expiry']}"
            key_choices.append(label)
        key_choices.append(questionary.Separator("─" * 18 if UNICODE_OK else "-" * 18))
        key_choices.append("Import from file...")
        key_choices.append("Cancel")
        selected = questionary.select(
            "  Encrypt for:", choices=key_choices, style=CIPHRA_STYLE
        ).ask()
        if selected is None or selected == "Cancel":
            return
        if selected == "Import from file...":
            console.print(
                "  [dim]Import completed. Select a key from the list.[/dim]"
            )
            return

    if selected is None or selected == "Cancel":
        return

    # Find matching key by fingerprint suffix
    chosen_key = None
    for k in keys:
        if f"...{k['fingerprint'][-8:]}" in selected:
            chosen_key = k
            break

    if chosen_key is None:
        console.print(f"  [{BAD}][ERROR] Could not resolve selected key.[/{BAD}]")
        return

    if chosen_key.get("expired"):
        console.print(
            f"  [{CAUTION}][WARN] This key has expired."
            f" Encryption may fail.[/{CAUTION}]"
        )
        proceed = questionary.confirm(
            "  Use it anyway?", default=False, style=CIPHRA_STYLE
        ).ask()
        if proceed is None or not proceed:
            console.print("  [dim]Cancelled.[/dim]")
            return

    default_out = fp + ".gpg"
    output_path = _prompt_output_path(default_out)
    if output_path is None:
        return

    # Compute sha256 of input before encryption for the log
    sha256 = compute_hash(fp, algo="sha256")
    console.print()

    with console.status("  Encrypting...", spinner="dots", spinner_style=ACCENT):
        result = encrypt_file_asymmetric(fp, output_path, chosen_key["fingerprint"])

    if not result["ok"]:
        console.print(f"  [{BAD}][ERROR] {_translate_error(result['msg'])}[/{BAD}]")
        return

    console.print()
    console.print(f"  [{GOOD}]Encrypted:[/{GOOD}]")
    console.print(f"  [{ACCENT}]{output_path}[/{ACCENT}]")
    console.print("  [dim]The original file was not deleted.[/dim]")
    console.print(
        "  [dim].gpg files can be decrypted with any GPG-compatible tool.[/dim]"
    )
    write_operation_log(os.path.basename(fp), sha256, "encrypt", "ok")


def _decrypt_file_flow() -> None:
    """Handle Decrypt a file sub-flow."""
    console.print(
        "  [dim]Accepts .ciphra files (symmetric) and .gpg files (asymmetric)."
        " Format is detected automatically.[/dim]"
    )
    console.print("  [dim]Start with / or ~, Tab to complete, Ctrl+C to cancel.[/dim]")
    console.print()
    fp = _prompt_for_file("  File path:", start_dir="/")
    if fp is None:
        console.print("  [dim]Cancelled.[/dim]")
        return

    fp = os.path.abspath(fp)
    if not _validate_file_for_crypto(fp):
        return

    size_mb = os.path.getsize(fp) / (1024 * 1024)
    console.print(
        f"  [{ACCENT}]{os.path.basename(fp)}[/{ACCENT}]  [dim]{size_mb:.1f} MB[/dim]"
    )
    console.print()

    if size_mb >= 1024:
        console.print(
            f"  [{CAUTION}][WARN] Large file ({size_mb / 1024:.1f} GB)."
            f" Decryption requires ~128 MB of free RAM for key"
            f" derivation.[/{CAUTION}]"
        )
        proceed = questionary.confirm(
            "  Continue?", default=True, style=CIPHRA_STYLE
        ).ask()
        if proceed is None or not proceed:
            console.print("  [dim]Cancelled.[/dim]")
            return

    fmt = _detect_format(fp)
    if fmt == "unknown":
        console.print(f"  [{BAD}][ERROR] Not a recognized encrypted format.[/{BAD}]")
        console.print(
            "  [dim]Ciphra can decrypt .ciphra (symmetric) and"
            " .gpg (asymmetric) files.[/dim]"
        )
        return

    if fmt == "ciphra":
        _decrypt_symmetric(fp)
    else:
        _decrypt_asymmetric(fp)


def _decrypt_symmetric(fp: str) -> None:
    """Symmetric decryption flow for a validated .ciphra file path."""
    console.print(
        "  [dim]This is a ciphra-encrypted file."
        " Enter the password used to encrypt it.[/dim]"
    )
    console.print()

    # Decrypt to temp path first — original_filename comes from the header
    output_path = fp + ".dec.tmp"

    original_filename = None
    max_attempts = 3
    attempt = 0
    while attempt < max_attempts:
        password = questionary.password("  Password:", style=CIPHRA_STYLE).ask()
        if password is None:
            console.print("  [dim]Cancelled.[/dim]")
            return
        if not password:
            continue
        attempt += 1
        console.print()

        try:
            with console.status(
                "  Deriving key...", spinner="dots", spinner_style=ACCENT
            ):
                dec_params = _read_kdf_params(fp)
                if dec_params is not None:
                    dec_salt, dec_tc, dec_mc, dec_par = dec_params
                    dec_key = derive_key(
                        password.encode(), dec_salt, dec_tc, dec_mc, dec_par
                    )
                else:
                    dec_key = None

            with console.status(
                "  Decrypting...", spinner="dots", spinner_style=ACCENT
            ):
                original_filename = _crypto_decrypt_file(
                    fp, output_path, password,
                    _precomputed_key=dec_key,
                )
                break
        except ValueError as e:
            console.print(f"  [{BAD}][ERROR] {str(e)}[/{BAD}]")
            if attempt >= max_attempts:
                console.print(
                    f"  [{BAD}][ERROR] Too many failed attempts.[/{BAD}]"
                )
                return
            remaining = max_attempts - attempt
            retry = questionary.confirm(
                f"  Try again? ({remaining} attempt{'s' if remaining != 1 else ''} remaining)",
                default=True,
                style=CIPHRA_STYLE,
            ).ask()
            if retry is None or not retry:
                console.print("  [dim]Cancelled.[/dim]")
                return
        except KeyboardInterrupt:
            if os.path.exists(output_path):
                os.unlink(output_path)
            console.print("\n  [dim]Cancelled.[/dim]")
            return
        except OSError as e:
            console.print(
                f"\n  [{BAD}][ERROR] {_translate_error(str(e))}[/{BAD}]"
            )
            return
        except BaseException:
            if os.path.exists(output_path):
                os.unlink(output_path)
            raise

    if original_filename is None:
        if os.path.exists(output_path):
            os.unlink(output_path)
        return

    # Move to final path using the embedded original filename
    final_dir = os.path.dirname(fp)
    final_path = os.path.join(final_dir, original_filename)
    if os.path.exists(final_path):
        choice = questionary.select(
            f"  {original_filename} already exists.",
            choices=["Overwrite", "Enter new path", "Cancel"],
            style=CIPHRA_STYLE,
        ).ask()
        if choice is None or choice == "Cancel":
            if os.path.exists(output_path):
                os.unlink(output_path)
            console.print("  [dim]Cancelled.[/dim]")
            return
        if choice == "Enter new path":
            new_path = questionary.text(
                "  Save as:", default=final_path, style=CIPHRA_STYLE
            ).ask()
            if not new_path or new_path is None:
                if os.path.exists(output_path):
                    os.unlink(output_path)
                console.print("  [dim]Cancelled.[/dim]")
                return
            final_path = os.path.abspath(new_path.strip())
        # "Overwrite" falls through with original final_path
    os.replace(output_path, final_path)

    console.print()
    console.print(f"  [{GOOD}]Decrypted:[/{GOOD}]")
    console.print(f"  [{ACCENT}]{final_path}[/{ACCENT}]")
    console.print("  [dim]The encrypted file was not deleted.[/dim]")
    write_operation_log(original_filename, "", "decrypt", "ok")


def _decrypt_asymmetric(fp: str) -> None:
    """Asymmetric decryption flow for a validated GPG file path."""
    if GPG_BIN is None:
        _outcome_degraded("GPG is not installed. Cannot decrypt this file.")
        return

    key_id = get_encrypted_for_key_id(fp)
    if key_id:
        console.print(f"  [dim]Encrypted for key: ...{key_id[-8:]}[/dim]")
        console.print()

    # Determine base output name from input filename
    input_name = os.path.basename(fp)
    if input_name.endswith(".gpg"):
        out_name = input_name[:-4]
    else:
        out_name = input_name + ".dec"
    base_output_path = os.path.join(os.path.dirname(fp), out_name)
    temp_path = base_output_path + ".tmp"

    max_attempts = 3
    attempt = 0
    success = False

    while attempt < max_attempts:
        passphrase = questionary.password(
            "  Passphrase:", style=CIPHRA_STYLE
        ).ask()
        if passphrase is None:
            console.print("  [dim]Cancelled.[/dim]")
            return
        if not passphrase:
            continue
        attempt += 1
        console.print()

        with console.status(
            "  Decrypting...", spinner="dots", spinner_style=ACCENT
        ):
            result = decrypt_file_asymmetric(fp, temp_path, passphrase)

        if result["ok"]:
            success = True
            break

        if os.path.exists(temp_path):
            os.unlink(temp_path)

        error_msg = _translate_error(result["msg"])
        console.print(f"  [{BAD}][ERROR] {error_msg}[/{BAD}]")

        if attempt >= max_attempts:
            console.print(
                f"  [{BAD}][ERROR] Too many failed attempts.[/{BAD}]"
            )
            return

        remaining = max_attempts - attempt
        retry = questionary.confirm(
            f"  Try again? ({remaining}"
            f" attempt{'s' if remaining != 1 else ''} remaining)",
            default=True,
            style=CIPHRA_STYLE,
        ).ask()
        if retry is None or not retry:
            console.print("  [dim]Cancelled.[/dim]")
            return

    if not success:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        return

    # Determine final output path with collision handling
    output_path = base_output_path
    if os.path.exists(output_path):
        choice = questionary.select(
            f"  {out_name} already exists.",
            choices=["Overwrite", "Enter new path", "Cancel"],
            style=CIPHRA_STYLE,
        ).ask()
        if choice is None or choice == "Cancel":
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            console.print("  [dim]Cancelled.[/dim]")
            return
        if choice == "Enter new path":
            new_path = questionary.text(
                "  Save as:", default=output_path, style=CIPHRA_STYLE
            ).ask()
            if not new_path or new_path is None:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                console.print("  [dim]Cancelled.[/dim]")
                return
            output_path = os.path.abspath(new_path.strip())
        # "Overwrite" falls through with original output_path

    os.replace(temp_path, output_path)
    console.print()
    console.print(f"  [{GOOD}]Decrypted:[/{GOOD}]")
    console.print(f"  [{ACCENT}]{output_path}[/{ACCENT}]")
    console.print("  [dim]The encrypted file was not deleted.[/dim]")
    write_operation_log(os.path.basename(fp), "", "decrypt", "ok")


def _create_key_pair_flow() -> None:
    """Create key pair sub-flow."""
    console.print(
        "  [dim]Ed25519 signing key with Curve25519 encryption subkey.[/dim]"
    )
    console.print(
        "  [dim]Modern elliptic curve cryptography."
        " Faster and stronger than RSA.[/dim]"
    )
    console.print()

    # Name
    name = None
    while not name:
        _n = questionary.text("  Your name:", style=CIPHRA_STYLE).ask()
        if _n is None:
            console.print("  [dim]Cancelled.[/dim]")
            return
        if _n.strip():
            name = _n.strip()

    # Email
    email = None
    while not email:
        _e = questionary.text("  Your email:", style=CIPHRA_STYLE).ask()
        if _e is None:
            console.print("  [dim]Cancelled.[/dim]")
            return
        if _e.strip():
            email = _e.strip()
    console.print()

    console.print(
        "  [dim]Keys expire to limit damage if your private"
        " key is ever compromised.[/dim]"
    )
    console.print()
    # Expiry selection
    expiry_choice = questionary.select(
        "  Key expiry:",
        choices=[
            "2 years  (recommended)",
            "1 year",
            "5 years",
            "No expiry  (not recommended)",
            "Custom...",
        ],
        style=CIPHRA_STYLE,
    ).ask()
    if expiry_choice is None:
        console.print("  [dim]Cancelled.[/dim]")
        return

    expiry_map = {
        "2 years  (recommended)": "2y",
        "1 year": "1y",
        "5 years": "5y",
        "No expiry  (not recommended)": "0",
    }

    if expiry_choice == "Custom...":
        console.print(
            "  [dim]Format: number + d/w/m/y"
            " — examples: 30d  6m  2y  or 0 for no expiry.[/dim]"
        )
        console.print()
        while True:
            custom = questionary.text(
                "  Custom expiry:", style=CIPHRA_STYLE
            ).ask()
            if custom is None:
                console.print("  [dim]Cancelled.[/dim]")
                return
            custom = custom.strip()
            if not custom:
                continue
            if custom == "0":
                expiry = "0"
                break
            if re.match(r'^\d+[dwmy]$', custom):
                expiry = custom
                break
            console.print(
                f"  [{CAUTION}][WARN] Invalid format."
                f" Examples: 30d  6m  2y  or 0 for no expiry.[/{CAUTION}]"
            )
    else:
        expiry = expiry_map[expiry_choice]

    console.print()

    # Passphrase with full retry pattern
    console.print(
        "  [dim]Recommended: 12+ characters using uppercase,"
        " lowercase, numbers, and symbols.[/dim]"
    )
    console.print()
    passphrase = None
    attempts = 0
    while attempts < 3:
        pw = questionary.password(
            "  Passphrase:", style=CIPHRA_STYLE
        ).ask()
        if pw is None:
            console.print("  [dim]Cancelled.[/dim]")
            return
        if not pw:
            continue
        while True:
            confirm = questionary.password(
                "  Confirm passphrase:", style=CIPHRA_STYLE
            ).ask()
            if confirm is None:
                console.print("  [dim]Cancelled.[/dim]")
                return
            if confirm:
                break
        if pw != confirm:
            attempts += 1
            console.print(
                f"  [{CAUTION}][WARN] Passphrases do not match.[/{CAUTION}]"
            )
            if attempts >= 3:
                console.print(
                    f"  [{BAD}][ERROR] Too many mismatches."
                    f" Returning to menu.[/{BAD}]"
                )
                return
            continue
        if len(pw) < 12:
            console.print(
                f"  [{CAUTION}][WARN] Short passphrase."
                f" Weak passphrases can be brute-forced.[/{CAUTION}]"
            )
            retry = questionary.confirm(
                "  Choose a different passphrase?",
                default=True,
                style=CIPHRA_STYLE,
            ).ask()
            if retry is None or retry:
                continue
        passphrase = pw
        break

    if passphrase is None:
        return

    console.print()

    # Generate
    with console.status(
        "  Generating key pair...", spinner="dots", spinner_style=ACCENT
    ):
        result = generate_key_pair(name, email, expiry, passphrase)

    if not result["ok"]:
        console.print(
            f"  [{BAD}][ERROR] {_translate_error(result['msg'])}[/{BAD}]"
        )
        return

    console.print(f"  [{GOOD}]Key pair created.[/{GOOD}]")
    if result["fingerprint"]:
        console.print(f"  [{ACCENT}]{result['fingerprint']}[/{ACCENT}]")

    keyring_path = (
        os.path.join(os.environ.get("APPDATA", "%APPDATA%"), "gnupg")
        if platform.system() == "Windows"
        else os.path.expanduser("~/.gnupg")
    )
    console.print(
        f"  [dim]Keys stored in your local GPG"
        f" keyring: {keyring_path}[/dim]"
    )
    write_operation_log("", "", "keygen", "ok")
    console.print()

    export_now = questionary.confirm(
        "  Export your public key now?",
        default=True,
        style=CIPHRA_STYLE,
    ).ask()
    if export_now:
        _export_public_key_flow(
            preselected_fingerprint=result["fingerprint"]
        )


def _sign_file_flow() -> None:
    """Sign a file sub-flow."""
    console.print(
        "  [dim]Detached armored signature (.asc)"
        " using your Ed25519 private key.[/dim]"
    )
    console.print(
        "  [dim]Share the .asc file alongside the original."
        " Recipients use ciphra verify.[/dim]"
    )
    console.print()
    console.print(
        "  [dim]Start with / or ~, Tab to complete,"
        " Ctrl+C to cancel.[/dim]"
    )
    console.print()

    fp = _prompt_for_file("  File path:", start_dir="/")
    if fp is None:
        console.print("  [dim]Cancelled.[/dim]")
        return
    fp = os.path.abspath(fp)
    if not _validate_file_for_crypto(fp):
        return

    size_mb = os.path.getsize(fp) / (1024 * 1024)
    console.print(
        f"  [{ACCENT}]{os.path.basename(fp)}[/{ACCENT}]"
        f"  [dim]{size_mb:.1f} MB[/dim]"
    )
    console.print()

    # List signing keys
    keys = list_signing_keys()

    if not keys:
        console.print(
            f"  [{CAUTION}][WARN] No signing keys found"
            f" in your keyring.[/{CAUTION}]"
        )
        console.print()
        create_now = questionary.confirm(
            "  Create a key pair now?",
            default=True,
            style=CIPHRA_STYLE,
        ).ask()
        if create_now:
            _create_key_pair_flow()
        return

    console.print(f"  [{ACCENT}]Your private keys[/{ACCENT}]")
    console.print(
        "  [dim]Only signing-capable keys from your"
        " GPG keyring are shown.[/dim]"
    )
    console.print()

    key_choices = []
    for k in keys:
        label = (
            f"{k['uid']}  {k['algo']}"
            f"  ...{k['fingerprint'][-8:]}"
        )
        if k["expired"]:
            label += "  [expired]"
        elif k.get("expiry") and k["expiry"] != "never":
            label += f"  expires {k['expiry']}"
        key_choices.append(label)
    key_choices.append(questionary.Separator("─" * 18 if UNICODE_OK else "-" * 18))
    key_choices.append("Import from file...")
    key_choices.append("Cancel")

    selected = questionary.select(
        "  Sign with:", choices=key_choices, style=CIPHRA_STYLE
    ).ask()

    if selected is None or selected == "Cancel":
        return

    if selected == "Import from file...":
        console.print(
            "  [dim]Enter path to a .asc or .gpg key file.[/dim]"
        )
        console.print(
            "  [dim]Start with / or ~, Tab to complete,"
            " Ctrl+C to cancel.[/dim]"
        )
        key_file = _prompt_for_file("  Key file path:", start_dir="/")
        if key_file is None:
            console.print("  [dim]Cancelled.[/dim]")
            return
        key_file = os.path.abspath(key_file)
        with console.status(
            "  Importing key...", spinner="dots", spinner_style=ACCENT
        ):
            import_result = import_public_key_file(key_file)
        if not import_result["ok"]:
            console.print(
                f"  [{BAD}][ERROR]"
                f" {_translate_error(import_result['msg'])}[/{BAD}]"
            )
            return
        console.print(f"  [{GOOD}]Key imported.[/{GOOD}]")
        keys = list_signing_keys()
        if not keys:
            console.print(
                f"  [{CAUTION}][WARN] No signing keys"
                f" found after import.[/{CAUTION}]"
            )
            return
        key_choices = []
        for k in keys:
            label = (
                f"{k['uid']}  {k['algo']}"
                f"  ...{k['fingerprint'][-8:]}"
            )
            if k["expired"]:
                label += "  [expired]"
            elif k.get("expiry") and k["expiry"] != "never":
                label += f"  expires {k['expiry']}"
            key_choices.append(label)
        key_choices.append(questionary.Separator("─" * 18 if UNICODE_OK else "-" * 18))
        key_choices.append("Cancel")
        selected = questionary.select(
            "  Sign with:", choices=key_choices, style=CIPHRA_STYLE
        ).ask()
        if selected is None or selected == "Cancel":
            return

    # Find matching key
    chosen_key = None
    for k in keys:
        if f"...{k['fingerprint'][-8:]}" in selected:
            chosen_key = k
            break

    if chosen_key is None:
        console.print(
            f"  [{BAD}][ERROR] Could not resolve selected key.[/{BAD}]"
        )
        return

    # Expired key warning
    if chosen_key["expired"]:
        console.print(
            f"  [{CAUTION}][WARN] This key has expired."
            f" Some tools may reject this signature.[/{CAUTION}]"
        )
        proceed = questionary.confirm(
            "  Use it anyway?", default=False, style=CIPHRA_STYLE
        ).ask()
        if proceed is None or not proceed:
            console.print("  [dim]Cancelled.[/dim]")
            return

    console.print()

    # Output path
    default_out = fp + ".asc"
    output_path = _prompt_output_path(default_out)
    if output_path is None:
        return

    # Compute sha256 before signing — spec §9 requires hash for all
    # operations with an input file
    sha256 = compute_hash(fp, algo="sha256")

    console.print()

    # Passphrase with retry — same pattern as _decrypt_symmetric
    console.print(
        "  [dim]Recommended: 12+ characters using uppercase,"
        " lowercase, numbers, and symbols.[/dim]"
    )
    max_attempts = 3
    attempt = 0
    success = False

    while attempt < max_attempts:
        passphrase = questionary.password(
            "  Passphrase:", style=CIPHRA_STYLE
        ).ask()
        if passphrase is None:
            console.print("  [dim]Cancelled.[/dim]")
            return
        if not passphrase:
            continue
        attempt += 1

        with console.status(
            "  Creating signature...", spinner="dots", spinner_style=ACCENT
        ):
            result = sign_file_detached(
                fp, output_path,
                chosen_key["fingerprint"], passphrase
            )

        if result["ok"]:
            success = True
            break

        if os.path.exists(output_path):
            os.unlink(output_path)

        console.print(
            f"  [{BAD}][ERROR]"
            f" {_translate_error(result['msg'])}[/{BAD}]"
        )
        if attempt >= max_attempts:
            console.print(
                f"  [{BAD}][ERROR] Too many failed attempts.[/{BAD}]"
            )
            return
        remaining = max_attempts - attempt
        retry = questionary.confirm(
            f"  Try again?"
            f" ({remaining}"
            f" attempt{'s' if remaining != 1 else ''} remaining)",
            default=True,
            style=CIPHRA_STYLE,
        ).ask()
        if retry is None or not retry:
            console.print("  [dim]Cancelled.[/dim]")
            return

    if not success:
        console.print(
            f"  [{BAD}][ERROR] Too many failed attempts.[/{BAD}]"
        )
        return

    console.print()
    console.print(f"  [{GOOD}]Signature created:[/{GOOD}]")
    console.print(f"  [{ACCENT}]{output_path}[/{ACCENT}]")
    console.print("  [dim]The original file was not deleted.[/dim]")
    console.print(
        f"  [dim]Share {os.path.basename(fp)} alongside"
        f" {os.path.basename(output_path)}.[/dim]"
    )
    console.print(
        "  [dim]Recipients use ciphra verify to check it.[/dim]"
    )
    write_operation_log(os.path.basename(fp), sha256, "sign", "ok")


def _export_public_key_flow(
    preselected_fingerprint: str | None = None,
) -> None:
    """Export public key sub-flow."""
    console.print(
        "  [dim]Your public key lets others verify your"
        " signatures and encrypt files to you.[/dim]"
    )
    console.print()

    keys = list_signing_keys()

    if not keys:
        console.print(
            f"  [{CAUTION}][WARN] No keys found in"
            f" your keyring.[/{CAUTION}]"
        )
        console.print()
        create_now = questionary.confirm(
            "  Create a key pair now?",
            default=True,
            style=CIPHRA_STYLE,
        ).ask()
        if create_now:
            _create_key_pair_flow()
        return

    chosen_key = None

    if preselected_fingerprint:
        chosen_key = next(
            (k for k in keys
             if k["fingerprint"] == preselected_fingerprint),
            None,
        )

    if chosen_key is None:
        console.print(f"  [{ACCENT}]Your keys[/{ACCENT}]")
        console.print(
            "  [dim]Keys from your local GPG keyring.[/dim]"
        )
        console.print()
        key_choices = []
        for k in keys:
            label = f"{k['uid']}  {k['algo']}  ...{k['fingerprint'][-8:]}"
            if k.get("expired"):
                label += "  [expired]"
            elif k.get("expiry") and k["expiry"] != "never":
                label += f"  expires {k['expiry']}"
            key_choices.append(label)
        key_choices.append(questionary.Separator("─" * 18 if UNICODE_OK else "-" * 18))
        key_choices.append("Cancel")
        selected = questionary.select(
            "  Export which key?",
            choices=key_choices,
            style=CIPHRA_STYLE,
        ).ask()
        if selected is None or selected == "Cancel":
            return
        for k in keys:
            if f"...{k['fingerprint'][-8:]}" in selected:
                chosen_key = k
                break
        if chosen_key is None:
            console.print(
                f"  [{BAD}][ERROR] Could not resolve"
                f" selected key.[/{BAD}]"
            )
            return

    # Default output path
    email_part = chosen_key["uid"]
    if "<" in email_part and ">" in email_part:
        email_part = (
            email_part.split("<")[1].rstrip(">").strip()
        )
    default_out = os.path.join(
        os.path.expanduser("~/Downloads"),
        f"{email_part}-public.asc",
    )
    output_path = _prompt_output_path(default_out)
    if output_path is None:
        return

    with console.status(
        "  Exporting public key...",
        spinner="dots",
        spinner_style=ACCENT,
    ):
        result = export_public_key(
            chosen_key["fingerprint"], output_path
        )

    if not result["ok"]:
        console.print(
            f"  [{BAD}][ERROR] {_translate_error(result['msg'])}[/{BAD}]"
        )
        return

    console.print()
    console.print(f"  [{GOOD}]Public key exported:[/{GOOD}]")
    console.print(f"  [{ACCENT}]{output_path}[/{ACCENT}]")
    console.print(
        "  [dim]Publish this so others can verify"
        " your signatures.[/dim]"
    )


def _export_private_key_flow() -> None:
    """Export private key sub-flow with strong warning."""
    console.print(f"  [{BAD}]{'─' * 54}[/{BAD}]")
    console.print(
        f"  [{BAD}]  PRIVATE KEY EXPORT[/{BAD}]"
    )
    console.print(f"  [{BAD}]{'─' * 54}[/{BAD}]")
    console.print()
    console.print(
        "  [dim]Your private key is already protected in"
        " your local GPG keyring.[/dim]"
    )
    console.print(
        "  [dim]You do not need to export it for"
        " normal use.[/dim]"
    )
    console.print()
    console.print(
        "  [dim]Only proceed if you are moving to a new"
        " machine or creating an encrypted backup.[/dim]"
    )
    console.print(
        "  [dim]Store the export in an encrypted location."
        " Never share it.[/dim]"
    )
    console.print()
    console.print(
        f"  [{CAUTION}][WARN] If someone gets this file AND your"
        f" passphrase, they can impersonate you and decrypt"
        f" files sent to you.[/{CAUTION}]"
    )
    console.print()

    proceed = questionary.confirm(
        "  I understand the risks. Export anyway?",
        default=False,
        style=CIPHRA_STYLE,
    ).ask()
    if proceed is None or not proceed:
        console.print("  [dim]Cancelled.[/dim]")
        return

    console.print()

    keys = list_signing_keys()
    if not keys:
        console.print(
            f"  [{CAUTION}][WARN] No keys found in"
            f" your keyring.[/{CAUTION}]"
        )
        console.print()
        create_now = questionary.confirm(
            "  Create a key pair now?",
            default=True,
            style=CIPHRA_STYLE,
        ).ask()
        if create_now:
            _create_key_pair_flow()
        return

    console.print(f"  [{ACCENT}]Your keys[/{ACCENT}]")
    console.print(
        "  [dim]Keys from your local GPG keyring.[/dim]"
    )
    console.print()
    key_choices = []
    for k in keys:
        label = f"{k['uid']}  {k['algo']}  ...{k['fingerprint'][-8:]}"
        if k.get("expired"):
            label += "  [expired]"
        elif k.get("expiry") and k["expiry"] != "never":
            label += f"  expires {k['expiry']}"
        key_choices.append(label)
    key_choices.append(questionary.Separator("─" * 18 if UNICODE_OK else "-" * 18))
    key_choices.append("Cancel")
    selected = questionary.select(
        "  Export which key?",
        choices=key_choices,
        style=CIPHRA_STYLE,
    ).ask()
    if selected is None or selected == "Cancel":
        return

    chosen_key = None
    for k in keys:
        if f"...{k['fingerprint'][-8:]}" in selected:
            chosen_key = k
            break
    if chosen_key is None:
        console.print(
            f"  [{BAD}][ERROR] Could not resolve selected key.[/{BAD}]"
        )
        return

    console.print()

    email_part = chosen_key["uid"]
    if "<" in email_part and ">" in email_part:
        email_part = (
            email_part.split("<")[1].rstrip(">").strip()
        )
    default_out = os.path.join(
        os.path.expanduser("~/Downloads"),
        f"{email_part}-private.asc",
    )
    output_path = _prompt_output_path(default_out)
    if output_path is None:
        return

    console.print()

    # Passphrase to unlock private key for export
    console.print(
        "  [dim]Enter the passphrase for this key to authorize export.[/dim]"
    )
    console.print()

    max_attempts = 3
    attempt = 0
    export_passphrase = None

    while attempt < max_attempts:
        pw = questionary.password(
            "  Passphrase:", style=CIPHRA_STYLE
        ).ask()
        if pw is None:
            console.print("  [dim]Cancelled.[/dim]")
            return
        if not pw:
            continue
        attempt += 1

        with console.status(
            "  Exporting private key...",
            spinner="dots",
            spinner_style=ACCENT,
        ):
            result = export_private_key(
                chosen_key["fingerprint"], output_path, pw
            )

        if not result["ok"]:
            msg = _translate_error(result["msg"])
            console.print(
                f"  [{BAD}][ERROR] {msg}[/{BAD}]"
            )
            if attempt < max_attempts:
                console.print()
                try_again = questionary.confirm(
                    f"  Try again? ({max_attempts - attempt} attempts left)",
                    default=True,
                    style=CIPHRA_STYLE,
                ).ask()
                if try_again is None or not try_again:
                    return
            continue

        export_passphrase = pw
        break

    if export_passphrase is None:
        console.print(
            f"  [{BAD}][ERROR] Too many failed attempts.[/{BAD}]"
        )
        return

    console.print()
    console.print(f"  [{GOOD}]Private key exported:[/{GOOD}]")
    console.print(f"  [{ACCENT}]{output_path}[/{ACCENT}]")
    console.print(
        "  [dim]Keep this file secure. Do not share it.[/dim]"
    )
    write_operation_log(chosen_key["uid"], "", "export_key", "ok")


def _add_encryption_subkey_flow() -> None:
    """Add encryption subkey sub-flow."""
    console.print(
        "  [dim]Add a Curve25519 encryption subkey to an existing key.[/dim]"
    )
    console.print(
        "  [dim]This lets others encrypt files to you using your public key.[/dim]"
    )
    console.print()

    keys = list_signing_keys_without_encryption_subkey()

    if not keys:
        console.print(
            f"  [{CAUTION}][WARN] All your keys already have"
            f" encryption subkeys.[/{CAUTION}]"
        )
        console.print()
        return

    console.print(f"  [{ACCENT}]Your key pairs[/{ACCENT}]")
    console.print(
        "  [dim]Only keys without an encryption subkey are shown.[/dim]"
    )
    console.print()

    key_choices = []
    for k in keys:
        label = (
            f"{k['uid']}  {k['algo']}"
            f"  ...{k['fingerprint'][-8:]}"
        )
        if k["expired"]:
            label += "  [expired]"
        elif k.get("expiry") and k["expiry"] != "never":
            label += f"  expires {k['expiry']}"
        key_choices.append(label)
    key_choices.append(questionary.Separator("─" * 18 if UNICODE_OK else "-" * 18))
    key_choices.append("Cancel")

    selected = questionary.select(
        "  Add subkey to:", choices=key_choices, style=CIPHRA_STYLE
    ).ask()
    if selected is None or selected == "Cancel":
        console.print("  [dim]Cancelled.[/dim]")
        return

    chosen_key = None
    for k in keys:
        if f"...{k['fingerprint'][-8:]}" in selected:
            chosen_key = k
            break
    if chosen_key is None:
        console.print(f"  [{BAD}][ERROR] Could not resolve selected key.[/{BAD}]")
        return

    if chosen_key.get("expired"):
        console.print(
            f"  [{CAUTION}][WARN] This key has expired.[/{CAUTION}]"
        )
        proceed = questionary.confirm(
            "  Add subkey anyway?", default=False, style=CIPHRA_STYLE
        ).ask()
        if proceed is None or not proceed:
            console.print("  [dim]Cancelled.[/dim]")
            return

    console.print()

    console.print(
        "  [dim]Keys expire to limit damage if your private"
        " key is ever compromised.[/dim]"
    )
    console.print()
    expiry_choice = questionary.select(
        "  Subkey expiry:",
        choices=[
            "2 years  (recommended)",
            "1 year",
            "5 years",
            "No expiry  (not recommended)",
            "Custom...",
            questionary.Separator("─" * 18 if UNICODE_OK else "-" * 18),
            "Cancel",
        ],
        style=CIPHRA_STYLE,
    ).ask()
    if expiry_choice is None or expiry_choice == "Cancel":
        console.print("  [dim]Cancelled.[/dim]")
        return

    expiry_map = {
        "2 years  (recommended)": "2y",
        "1 year": "1y",
        "5 years": "5y",
        "No expiry  (not recommended)": "0",
    }

    if expiry_choice == "Custom...":
        console.print(
            "  [dim]Format: number + d/w/m/y — examples: 30d  6m  2y  or 0 for no expiry.[/dim]"
        )
        while True:
            custom = questionary.text(
                "  Custom expiry:", style=CIPHRA_STYLE
            ).ask()
            if custom is None:
                console.print("  [dim]Cancelled.[/dim]")
                return
            custom = custom.strip()
            if not custom:
                continue
            if custom == "0" or re.match(r"^\d+[dwmy]$", custom):
                expiry = custom
                break
            console.print(
                f"  [{CAUTION}][WARN] Invalid format."
                f" Examples: 30d  6m  2y  or 0 for no expiry.[/{CAUTION}]"
            )
    else:
        expiry = expiry_map[expiry_choice]

    console.print()
    console.print(
        "  [dim]Enter your key passphrase to authorize this change.[/dim]"
    )

    max_attempts = 3
    attempt = 0
    while attempt < max_attempts:
        pw = questionary.password(
            "  Passphrase:", style=CIPHRA_STYLE
        ).ask()
        if pw is None:
            console.print("  [dim]Cancelled.[/dim]")
            return
        if not pw:
            continue
        attempt += 1

        with console.status(
            "  Adding encryption subkey...",
            spinner="dots",
            spinner_style=ACCENT,
        ):
            result = add_encryption_subkey(
                chosen_key["fingerprint"], pw, expiry
            )

        if result["ok"]:
            break

        console.print(
            f"\n  [{BAD}][ERROR]"
            f" {_translate_error(result['msg'])}[/{BAD}]"
        )
        if attempt >= max_attempts:
            console.print(
                f"  [{BAD}][ERROR] Too many failed attempts.[/{BAD}]"
            )
            return
        remaining = max_attempts - attempt
        retry = questionary.confirm(
            f"  Try again?"
            f" ({remaining}"
            f" attempt{'s' if remaining != 1 else ''} remaining)",
            default=True,
            style=CIPHRA_STYLE,
        ).ask()
        if retry is None or not retry:
            console.print("  [dim]Cancelled.[/dim]")
            return

    keyring_path = (
        os.path.join(os.environ.get("APPDATA", "%APPDATA%"), "gnupg")
        if platform.system() == "Windows"
        else os.path.expanduser("~/.gnupg")
    )
    console.print(f"  [{GOOD}]Encryption subkey added.[/{GOOD}]")
    console.print()
    console.print(
        f"  [dim]Keys stored in your local GPG"
        f" keyring: {keyring_path}[/dim]"
    )
    write_operation_log(chosen_key["uid"], "", "subkey", "ok")
    console.print()

    export_now = questionary.confirm(
        "  Export your updated public key now?",
        default=True,
        style=CIPHRA_STYLE,
    ).ask()
    if export_now:
        _export_public_key_flow(
            preselected_fingerprint=chosen_key["fingerprint"]
        )


def _rotate_encryption_subkey_flow() -> None:
    """Rotate encryption subkey sub-flow."""
    console.print(
        "  [dim]Revoke your current encryption subkey and generate a new one.[/dim]"
    )
    console.print(
        "  [dim]Your signing key and identity are not affected.[/dim]"
    )
    console.print()
    console.print(
        f"  [{CAUTION}][WARN] Recipients will need your updated"
        f" public key to encrypt to you.[/{CAUTION}]"
    )
    console.print()

    keys = list_secret_keys_with_encryption_subkey()

    if not keys:
        console.print(
            f"  [{CAUTION}][WARN] No keys with an encryption"
            f" subkey found.[/{CAUTION}]"
        )
        console.print(
            "  [dim]Use Add encryption subkey to add one first.[/dim]"
        )
        console.print()
        return

    console.print(f"  [{ACCENT}]Your key pairs[/{ACCENT}]")
    console.print(
        "  [dim]Only keys with an encryption subkey are shown.[/dim]"
    )
    console.print()

    key_choices = []
    for k in keys:
        label = (
            f"{k['uid']}  {k['algo']}"
            f"  ...{k['fingerprint'][-8:]}"
        )
        if k["expired"]:
            label += "  [expired]"
        elif k.get("subkey_expiry") and k["subkey_expiry"] != "never":
            label += f"  subkey expires {k['subkey_expiry']}"
        key_choices.append(label)
    key_choices.append(questionary.Separator("─" * 18 if UNICODE_OK else "-" * 18))
    key_choices.append("Cancel")

    selected = questionary.select(
        "  Rotate subkey for:", choices=key_choices, style=CIPHRA_STYLE
    ).ask()
    if selected is None or selected == "Cancel":
        console.print("  [dim]Cancelled.[/dim]")
        return

    chosen_key = None
    for k in keys:
        if f"...{k['fingerprint'][-8:]}" in selected:
            chosen_key = k
            break
    if chosen_key is None:
        console.print(f"  [{BAD}][ERROR] Could not resolve selected key.[/{BAD}]")
        return

    if chosen_key.get("expired"):
        console.print(
            f"  [{CAUTION}][WARN] This key has expired.[/{CAUTION}]"
        )
        proceed = questionary.confirm(
            "  Rotate subkey anyway?", default=False, style=CIPHRA_STYLE
        ).ask()
        if proceed is None or not proceed:
            console.print("  [dim]Cancelled.[/dim]")
            return

    console.print()
    console.print(
        f"  [dim]Current encryption subkey:[/dim]"
    )
    expiry_display = (
        f"expires {chosen_key['subkey_expiry']}"
        if chosen_key["subkey_expiry"] != "never"
        else "no expiry"
    )
    console.print(
        f"  [dim]{chosen_key['subkey_algo']}"
        f"  ...{chosen_key['subkey_fingerprint'][-8:] if chosen_key['subkey_fingerprint'] else 'unknown'}"
        f"  {expiry_display}[/dim]"
    )
    console.print()

    proceed = questionary.confirm(
        "  Confirm rotation? This will revoke the current subkey.",
        default=False,
        style=CIPHRA_STYLE,
    ).ask()
    if proceed is None or not proceed:
        console.print("  [dim]Cancelled.[/dim]")
        return

    console.print()
    console.print(
        "  [dim]Keys expire to limit damage if your private"
        " key is ever compromised.[/dim]"
    )
    console.print()
    expiry_choice = questionary.select(
        "  New subkey expiry:",
        choices=[
            "2 years  (recommended)",
            "1 year",
            "5 years",
            "No expiry  (not recommended)",
            "Custom...",
            questionary.Separator("─" * 18 if UNICODE_OK else "-" * 18),
            "Cancel",
        ],
        style=CIPHRA_STYLE,
    ).ask()
    if expiry_choice is None or expiry_choice == "Cancel":
        console.print("  [dim]Cancelled.[/dim]")
        return

    expiry_map = {
        "2 years  (recommended)": "2y",
        "1 year": "1y",
        "5 years": "5y",
        "No expiry  (not recommended)": "0",
    }

    if expiry_choice == "Custom...":
        console.print(
            "  [dim]Format: number + d/w/m/y — examples: 30d  6m  2y  or 0 for no expiry.[/dim]"
        )
        while True:
            custom = questionary.text(
                "  Custom expiry:", style=CIPHRA_STYLE
            ).ask()
            if custom is None:
                console.print("  [dim]Cancelled.[/dim]")
                return
            custom = custom.strip()
            if not custom:
                continue
            if custom == "0" or re.match(r"^\d+[dwmy]$", custom):
                expiry = custom
                break
            console.print(
                f"  [{CAUTION}][WARN] Invalid format."
                f" Examples: 30d  6m  2y  or 0 for no expiry.[/{CAUTION}]"
            )
    else:
        expiry = expiry_map[expiry_choice]

    console.print()
    console.print(
        "  [dim]Enter your key passphrase to authorize this change.[/dim]"
    )

    max_attempts = 3
    attempt = 0
    while attempt < max_attempts:
        pw = questionary.password(
            "  Passphrase:", style=CIPHRA_STYLE
        ).ask()
        if pw is None:
            console.print("  [dim]Cancelled.[/dim]")
            return
        if not pw:
            continue
        attempt += 1

        with console.status(
            "  Verifying passphrase...",
            spinner="dots",
            spinner_style=ACCENT,
        ):
            verify_result = verify_key_passphrase(
                chosen_key["fingerprint"], pw
            )

        if not verify_result["ok"]:
            console.print(
                f"\n  [{BAD}][ERROR] Wrong passphrase.[/{BAD}]"
            )
            if attempt >= max_attempts:
                console.print(
                    f"  [{BAD}][ERROR] Too many failed attempts.[/{BAD}]"
                )
                return
            remaining = max_attempts - attempt
            retry = questionary.confirm(
                f"  Try again?"
                f" ({remaining}"
                f" attempt{'s' if remaining != 1 else ''} remaining)",
                default=True,
                style=CIPHRA_STYLE,
            ).ask()
            if retry is None or not retry:
                console.print("  [dim]Cancelled.[/dim]")
                return
            continue

        with console.status(
            "  Rotating encryption subkey...",
            spinner="dots",
            spinner_style=ACCENT,
        ):
            result = rotate_encryption_subkey(
                chosen_key["fingerprint"], pw, expiry
            )

        if result["ok"]:
            break

        console.print(
            f"  [{BAD}][ERROR]"
            f" {_translate_error(result['msg'])}[/{BAD}]"
        )
        if attempt >= max_attempts:
            console.print(
                f"  [{BAD}][ERROR] Too many failed attempts.[/{BAD}]"
            )
            return
        remaining = max_attempts - attempt
        retry = questionary.confirm(
            f"  Try again?"
            f" ({remaining}"
            f" attempt{'s' if remaining != 1 else ''} remaining)",
            default=True,
            style=CIPHRA_STYLE,
        ).ask()
        if retry is None or not retry:
            console.print("  [dim]Cancelled.[/dim]")
            return

    keyring_path = (
        os.path.join(os.environ.get("APPDATA", "%APPDATA%"), "gnupg")
        if platform.system() == "Windows"
        else os.path.expanduser("~/.gnupg")
    )
    console.print(f"  [{GOOD}]Encryption subkey rotated.[/{GOOD}]")
    console.print()
    console.print(
        f"  [dim]Keys stored in your local GPG"
        f" keyring: {keyring_path}[/dim]"
    )
    console.print(
        f"  [{CAUTION}][WARN] Recipients who have your old public key"
        f" cannot encrypt to you until they import your updated"
        f" public key.[/{CAUTION}]"
    )
    write_operation_log(chosen_key["uid"], "", "subkey", "ok")
    console.print()

    export_now = questionary.confirm(
        "  Export your updated public key now?",
        default=True,
        style=CIPHRA_STYLE,
    ).ask()
    if export_now:
        _export_public_key_flow(
            preselected_fingerprint=chosen_key["fingerprint"]
        )


def _extend_subkey_expiry_flow() -> None:
    """Extend subkey expiry sub-flow."""
    console.print(
        "  [dim]Extend the expiry date on your encryption subkey.[/dim]"
    )
    console.print()

    keys = list_secret_keys_with_encryption_subkey()

    if not keys:
        console.print(
            f"  [{CAUTION}][WARN] No keys with an encryption"
            f" subkey found.[/{CAUTION}]"
        )
        console.print(
            "  [dim]Use Add encryption subkey to add one first.[/dim]"
        )
        console.print()
        return

    console.print(f"  [{ACCENT}]Your key pairs[/{ACCENT}]")
    console.print(
        "  [dim]Only keys with an encryption subkey are shown.[/dim]"
    )
    console.print()

    key_choices = []
    for k in keys:
        label = (
            f"{k['uid']}  {k['algo']}"
            f"  ...{k['fingerprint'][-8:]}"
        )
        if k["expired"]:
            label += "  [expired]"
        elif k.get("subkey_expiry") and k["subkey_expiry"] != "never":
            label += f"  subkey expires {k['subkey_expiry']}"
        key_choices.append(label)
    key_choices.append(questionary.Separator("─" * 18 if UNICODE_OK else "-" * 18))
    key_choices.append("Cancel")

    selected = questionary.select(
        "  Extend expiry for:", choices=key_choices, style=CIPHRA_STYLE
    ).ask()
    if selected is None or selected == "Cancel":
        console.print("  [dim]Cancelled.[/dim]")
        return

    chosen_key = None
    for k in keys:
        if f"...{k['fingerprint'][-8:]}" in selected:
            chosen_key = k
            break
    if chosen_key is None:
        console.print(f"  [{BAD}][ERROR] Could not resolve selected key.[/{BAD}]")
        return

    if chosen_key.get("expired"):
        console.print()
        console.print(
            f"  [{CAUTION}][WARN] This key has expired.[/{CAUTION}]"
        )
        proceed = questionary.confirm(
            "  Extend subkey anyway?", default=False, style=CIPHRA_STYLE
        ).ask()
        if proceed is None or not proceed:
            console.print("  [dim]Cancelled.[/dim]")
            return

    console.print()
    console.print(
        f"  [dim]Current encryption subkey:[/dim]"
    )
    expiry_display = (
        f"expires {chosen_key['subkey_expiry']}"
        if chosen_key["subkey_expiry"] != "never"
        else "no expiry"
    )
    console.print(
        f"  [dim]{chosen_key['subkey_algo']}"
        f"  ...{chosen_key['subkey_fingerprint'][-8:] if chosen_key['subkey_fingerprint'] else 'unknown'}"
        f"  {expiry_display}[/dim]"
    )
    console.print()

    console.print(
        "  [dim]Keys expire to limit damage if your private"
        " key is ever compromised.[/dim]"
    )
    console.print()
    expiry_choice = questionary.select(
        "  New subkey expiry:",
        choices=[
            "2 years  (recommended)",
            "1 year",
            "5 years",
            "No expiry  (not recommended)",
            "Custom...",
            questionary.Separator("─" * 18 if UNICODE_OK else "-" * 18),
            "Cancel",
        ],
        style=CIPHRA_STYLE,
    ).ask()
    if expiry_choice is None or expiry_choice == "Cancel":
        console.print("  [dim]Cancelled.[/dim]")
        return

    expiry_map = {
        "2 years  (recommended)": "2y",
        "1 year": "1y",
        "5 years": "5y",
        "No expiry  (not recommended)": "0",
    }

    if expiry_choice == "Custom...":
        console.print(
            "  [dim]Format: number + d/w/m/y — examples: 30d  6m  2y  or 0 for no expiry.[/dim]"
        )
        console.print()
        while True:
            custom = questionary.text(
                "  Custom expiry:", style=CIPHRA_STYLE
            ).ask()
            if custom is None:
                console.print("  [dim]Cancelled.[/dim]")
                return
            custom = custom.strip()
            if not custom:
                continue
            if custom == "0" or re.match(r"^\d+[dwmy]$", custom):
                expiry = custom
                break
            console.print(
                f"  [{CAUTION}][WARN] Invalid format."
                f" Examples: 30d  6m  2y  or 0 for no expiry.[/{CAUTION}]"
            )
    else:
        expiry = expiry_map[expiry_choice]

    console.print()
    console.print(
        "  [dim]Enter your key passphrase to authorize this change.[/dim]"
    )

    max_attempts = 3
    attempt = 0
    while attempt < max_attempts:
        pw = questionary.password(
            "  Passphrase:", style=CIPHRA_STYLE
        ).ask()
        if pw is None:
            console.print("  [dim]Cancelled.[/dim]")
            return
        if not pw:
            continue
        attempt += 1

        with console.status(
            "  Verifying passphrase...",
            spinner="dots",
            spinner_style=ACCENT,
        ):
            verify_result = verify_key_passphrase(
                chosen_key["fingerprint"], pw
            )

        if not verify_result["ok"]:
            console.print(
                f"\n  [{BAD}][ERROR] Wrong passphrase.[/{BAD}]"
            )
            if attempt >= max_attempts:
                console.print(
                    f"  [{BAD}][ERROR] Too many failed attempts.[/{BAD}]"
                )
                return
            remaining = max_attempts - attempt
            retry = questionary.confirm(
                f"  Try again?"
                f" ({remaining}"
                f" attempt{'s' if remaining != 1 else ''} remaining)",
                default=True,
                style=CIPHRA_STYLE,
            ).ask()
            if retry is None or not retry:
                console.print("  [dim]Cancelled.[/dim]")
                return
            continue

        with console.status(
            "  Extending subkey expiry...",
            spinner="dots",
            spinner_style=ACCENT,
        ):
            result = extend_subkey_expiry(
                chosen_key["fingerprint"], pw, expiry
            )

        if result["ok"]:
            break

        console.print(
            f"  [{BAD}][ERROR]"
            f" {_translate_error(result['msg'])}[/{BAD}]"
        )
        if attempt >= max_attempts:
            console.print(
                f"  [{BAD}][ERROR] Too many failed attempts.[/{BAD}]"
            )
            return
        remaining = max_attempts - attempt
        retry = questionary.confirm(
            f"  Try again?"
            f" ({remaining}"
            f" attempt{'s' if remaining != 1 else ''} remaining)",
            default=True,
            style=CIPHRA_STYLE,
        ).ask()
        if retry is None or not retry:
            console.print("  [dim]Cancelled.[/dim]")
            return

    keyring_path = (
        os.path.join(os.environ.get("APPDATA", "%APPDATA%"), "gnupg")
        if platform.system() == "Windows"
        else os.path.expanduser("~/.gnupg")
    )
    console.print(f"  [{GOOD}]Subkey expiry extended.[/{GOOD}]")
    console.print()
    console.print(
        f"  [dim]Keys stored in your local GPG"
        f" keyring: {keyring_path}[/dim]"
    )
    write_operation_log(chosen_key["uid"], "", "subkey", "ok")
    console.print()

    export_now = questionary.confirm(
        "  Export your updated public key now?",
        default=True,
        style=CIPHRA_STYLE,
    ).ask()
    if export_now:
        _export_public_key_flow(
            preselected_fingerprint=chosen_key["fingerprint"]
        )


def _manage_subkeys_flow(first_entry: bool = True) -> None:
    """Manage subkeys sub-flow."""
    if first_entry:
        console.print(
            "  [dim]Add, rotate, or extend expiry on your encryption subkeys.[/dim]"
        )
    console.print()
    answer = questionary.select(
        "Manage subkeys",
        choices=[
            "Add encryption subkey",
            "Rotate encryption subkey",
            "Extend subkey expiry",
            "Back",
        ],
        style=CIPHRA_STYLE,
    ).ask()

    if answer is None or answer == "Back":
        return
    if answer == "Add encryption subkey":
        _add_encryption_subkey_flow()
        _manage_subkeys_flow(first_entry=False)
    elif answer == "Rotate encryption subkey":
        _rotate_encryption_subkey_flow()
        _manage_subkeys_flow(first_entry=False)
    elif answer == "Extend subkey expiry":
        _extend_subkey_expiry_flow()
        _manage_subkeys_flow(first_entry=False)


def _delete_key_pair_flow() -> None:
    """Delete key pair sub-flow."""
    console.print(f"  [{BAD}]{'─' * 54}[/{BAD}]")
    console.print(
        f"  [{BAD}]  DELETE KEY PAIR[/{BAD}]"
    )
    console.print(f"  [{BAD}]{'─' * 54}[/{BAD}]")
    console.print()
    console.print(
        "  [dim]This permanently removes your key pair from"
        " your local GPG keyring.[/dim]"
    )
    console.print(
        "  [dim]Files encrypted to this key cannot be"
        " decrypted after deletion.[/dim]"
    )
    console.print(
        "  [dim]Signatures made with this key cannot be"
        " verified after deletion.[/dim]"
    )
    console.print()
    console.print(
        f"  [{CAUTION}][WARN] This action cannot be undone."
        f" Export your private key first"
        f" if you may need it later.[/{CAUTION}]"
    )
    console.print()

    proceed = questionary.confirm(
        "  I understand the risks. Proceed?",
        default=False,
        style=CIPHRA_STYLE,
    ).ask()
    if proceed is None or not proceed:
        console.print("  [dim]Cancelled.[/dim]")
        return

    console.print()

    keys = list_signing_keys()

    if not keys:
        console.print(
            f"  [{CAUTION}][WARN] No keys found in"
            f" your keyring.[/{CAUTION}]"
        )
        console.print()
        return

    console.print(f"  [{ACCENT}]Your key pairs[/{ACCENT}]")
    console.print(
        "  [dim]Select the key pair to permanently delete.[/dim]"
    )
    console.print()

    key_choices = []
    for k in keys:
        label = (
            f"{k['uid']}  {k['algo']}"
            f"  ...{k['fingerprint'][-8:]}"
        )
        if k["expired"]:
            label += "  [expired]"
        elif k.get("expiry") and k["expiry"] != "never":
            label += f"  expires {k['expiry']}"
        key_choices.append(label)
    key_choices.append(questionary.Separator("─" * 18 if UNICODE_OK else "-" * 18))
    key_choices.append("Cancel")

    selected = questionary.select(
        "  Delete which key pair?",
        choices=key_choices,
        style=CIPHRA_STYLE,
    ).ask()
    if selected is None or selected == "Cancel":
        console.print("  [dim]Cancelled.[/dim]")
        return

    chosen_key = None
    for k in keys:
        if f"...{k['fingerprint'][-8:]}" in selected:
            chosen_key = k
            break
    if chosen_key is None:
        console.print(f"  [{BAD}][ERROR] Could not resolve selected key.[/{BAD}]")
        console.print()
        return

    console.print()
    console.print(f"  [{BAD}]{'─' * 54}[/{BAD}]")
    console.print(f"  [{BAD}]  {chosen_key['uid']}[/{BAD}]")
    console.print(
        f"  [{BAD}]  {chosen_key['algo']}"
        f"  {chosen_key['fingerprint']}[/{BAD}]"
    )
    expiry_display = (
        f"expires {chosen_key['expiry']}"
        if chosen_key.get("expiry") and chosen_key["expiry"] != "never"
        else None
    )
    if expiry_display:
        console.print(f"  [{BAD}]  {expiry_display}[/{BAD}]")
    console.print(f"  [{BAD}]{'─' * 54}[/{BAD}]")
    console.print()
    console.print(
        f"  [{CAUTION}][WARN] Once deleted this cannot be recovered.[/{CAUTION}]"
    )
    console.print()
    console.print(
        "  [dim]Enter your passphrase to authorize deletion.[/dim]"
    )

    max_attempts = 3
    attempt = 0
    while attempt < max_attempts:
        pw = questionary.password(
            "  Passphrase:", style=CIPHRA_STYLE
        ).ask()
        if pw is None:
            console.print("  [dim]Cancelled.[/dim]")
            return
        if not pw:
            continue
        attempt += 1

        with console.status(
            "  Verifying...",
            spinner="dots",
            spinner_style=ACCENT,
        ):
            verify_result = verify_key_passphrase(
                chosen_key["fingerprint"], pw
            )

        if not verify_result["ok"]:
            console.print(
                f"  [{BAD}][ERROR] Wrong passphrase.[/{BAD}]"
            )
            if attempt >= max_attempts:
                console.print(
                    f"  [{BAD}][ERROR] Too many failed attempts.[/{BAD}]"
                )
                console.print()
                return
            remaining = max_attempts - attempt
            retry = questionary.confirm(
                f"  Try again?"
                f" ({remaining}"
                f" attempt{'s' if remaining != 1 else ''} remaining)",
                default=True,
                style=CIPHRA_STYLE,
            ).ask()
            if retry is None or not retry:
                console.print("  [dim]Cancelled.[/dim]")
                return
            continue

        with console.status(
            "  Deleting key pair...",
            spinner="dots",
            spinner_style=ACCENT,
        ):
            result = delete_key_pair(chosen_key["fingerprint"])

        if not result["ok"]:
            console.print(
                f"  [{BAD}][ERROR] {_translate_error(result['msg'])}[/{BAD}]"
            )
            console.print()
            return

        console.print(f"  [{GOOD}]Key pair deleted.[/{GOOD}]")
        console.print()
        console.print(
            f"  [dim]{chosen_key['uid']} has been removed"
            f" from your local GPG keyring.[/dim]"
        )
        write_operation_log(chosen_key["uid"], "", "delete_key", "ok")
        return


def _extend_key_expiry_flow() -> None:
    """Extend primary key expiry sub-flow."""
    console.print(
        "  [dim]Extend how long your key identity remains valid.[/dim]"
    )
    console.print()

    keys = list_signing_keys()

    if not keys:
        console.print(
            f"  [{CAUTION}][WARN] No keys found in"
            f" your keyring.[/{CAUTION}]"
        )
        console.print()
        return

    console.print(f"  [{ACCENT}]Your key pairs[/{ACCENT}]")
    console.print(
        "  [dim]Keys from your local GPG keyring.[/dim]"
    )
    console.print()

    key_choices = []
    for k in keys:
        label = (
            f"{k['uid']}  {k['algo']}"
            f"  ...{k['fingerprint'][-8:]}"
        )
        if k["expired"]:
            label += "  [expired]"
        elif k.get("expiry") and k["expiry"] != "never":
            label += f"  expires {k['expiry']}"
        key_choices.append(label)
    key_choices.append(questionary.Separator("─" * 18 if UNICODE_OK else "-" * 18))
    key_choices.append("Cancel")

    selected = questionary.select(
        "  Extend expiry for:",
        choices=key_choices,
        style=CIPHRA_STYLE,
    ).ask()
    if selected is None or selected == "Cancel":
        console.print("  [dim]Cancelled.[/dim]")
        return

    chosen_key = None
    for k in keys:
        if f"...{k['fingerprint'][-8:]}" in selected:
            chosen_key = k
            break
    if chosen_key is None:
        console.print(f"  [{BAD}][ERROR] Could not resolve selected key.[/{BAD}]")
        return

    console.print()
    console.print(
        "  [dim]Keys expire to limit damage if your private"
        " key is ever compromised.[/dim]"
    )
    expiry_choice = questionary.select(
        "  New key expiry:",
        choices=[
            "2 years  (recommended)",
            "1 year",
            "5 years",
            "No expiry  (not recommended)",
            "Custom...",
            questionary.Separator("─" * 18 if UNICODE_OK else "-" * 18),
            "Cancel",
        ],
        style=CIPHRA_STYLE,
    ).ask()
    if expiry_choice is None or expiry_choice == "Cancel":
        console.print("  [dim]Cancelled.[/dim]")
        return

    expiry_map = {
        "2 years  (recommended)": "2y",
        "1 year": "1y",
        "5 years": "5y",
        "No expiry  (not recommended)": "0",
    }

    if expiry_choice == "Custom...":
        console.print(
            "  [dim]Format: number + d/w/m/y"
            " or 0 for no expiry.[/dim]"
        )
        while True:
            custom = questionary.text(
                "  Custom expiry:", style=CIPHRA_STYLE
            ).ask()
            if custom is None:
                console.print("  [dim]Cancelled.[/dim]")
                return
            custom = custom.strip()
            if not custom:
                continue
            if custom == "0" or re.match(r"^\d+[dwmy]$", custom):
                expiry = custom
                break
            console.print(
                f"  [{CAUTION}][WARN] Invalid format."
                f" Examples: 30d  6m  2y  or 0 for no expiry.[/{CAUTION}]"
            )
    else:
        expiry = expiry_map[expiry_choice]

    console.print()
    console.print(
        "  [dim]Enter your key passphrase to authorize this change.[/dim]"
    )

    max_attempts = 3
    attempt = 0
    while attempt < max_attempts:
        pw = questionary.password(
            "  Passphrase:", style=CIPHRA_STYLE
        ).ask()
        if pw is None:
            console.print("  [dim]Cancelled.[/dim]")
            return
        if not pw:
            continue
        attempt += 1

        with console.status(
            "  Verifying passphrase...",
            spinner="dots",
            spinner_style=ACCENT,
        ):
            verify_result = verify_key_passphrase(
                chosen_key["fingerprint"], pw
            )

        if not verify_result["ok"]:
            console.print(
                f"\n  [{BAD}][ERROR] Wrong passphrase.[/{BAD}]"
            )
            if attempt >= max_attempts:
                console.print(
                    f"  [{BAD}][ERROR] Too many failed attempts.[/{BAD}]"
                )
                return
            remaining = max_attempts - attempt
            retry = questionary.confirm(
                f"  Try again?"
                f" ({remaining}"
                f" attempt{'s' if remaining != 1 else ''} remaining)",
                default=True,
                style=CIPHRA_STYLE,
            ).ask()
            if retry is None or not retry:
                console.print("  [dim]Cancelled.[/dim]")
                return
            continue

        with console.status(
            "  Extending key expiry...",
            spinner="dots",
            spinner_style=ACCENT,
        ):
            result = extend_key_expiry(
                chosen_key["fingerprint"], pw, expiry
            )

        if result["ok"]:
            break

        console.print(
            f"\n  [{BAD}][ERROR]"
            f" {_translate_error(result['msg'])}[/{BAD}]"
        )
        if attempt >= max_attempts:
            console.print(
                f"  [{BAD}][ERROR] Too many failed attempts.[/{BAD}]"
            )
            return
        remaining = max_attempts - attempt
        retry = questionary.confirm(
            f"  Try again?"
            f" ({remaining}"
            f" attempt{'s' if remaining != 1 else ''} remaining)",
            default=True,
            style=CIPHRA_STYLE,
        ).ask()
        if retry is None or not retry:
            console.print("  [dim]Cancelled.[/dim]")
            return

    keyring_path = (
        os.path.join(os.environ.get("APPDATA", "%APPDATA%"), "gnupg")
        if platform.system() == "Windows"
        else os.path.expanduser("~/.gnupg")
    )
    console.print(f"  [{GOOD}]Key expiry updated.[/{GOOD}]")
    console.print()
    console.print(
        f"  [dim]Keys stored in your local GPG"
        f" keyring: {keyring_path}[/dim]"
    )
    write_operation_log(chosen_key["uid"], "", "extend_key", "ok")
    console.print()

    export_now = questionary.confirm(
        "  Export your updated public key now?",
        default=True,
        style=CIPHRA_STYLE,
    ).ask()
    if export_now:
        _export_public_key_flow(
            preselected_fingerprint=chosen_key["fingerprint"]
        )


def _digital_signatures_loop(first_entry: bool = True) -> None:
    """Digital Signatures menu loop."""
    if first_entry:
        console.print(
            "  [dim]Prove a file came from you and"
            " has not been modified.[/dim]"
        )
    console.print()
    answer = questionary.select(
        "Digital Signatures",
        choices=[
            "Create key pair",
            "Sign a file",
            "Manage subkeys",
            questionary.Separator("─" * 18 if UNICODE_OK else "-" * 18),
            "Export public key",
            "Export private key",
            "Extend key expiry",
            "Delete key pair",
            questionary.Separator("─" * 18 if UNICODE_OK else "-" * 18),
            "Back",
        ],
        style=CIPHRA_STYLE,
    ).ask()

    if answer is None or answer == "Back":
        return
    if answer == "Create key pair":
        _create_key_pair_flow()
    elif answer == "Sign a file":
        _sign_file_flow()
    elif answer == "Manage subkeys":
        _manage_subkeys_flow()
    elif answer == "Export public key":
        _export_public_key_flow()
    elif answer == "Export private key":
        _export_private_key_flow()
    elif answer == "Extend key expiry":
        _extend_key_expiry_flow()
    elif answer == "Delete key pair":
        _delete_key_pair_flow()
    _digital_signatures_loop(first_entry=False)


@cli.command(name="digital-signatures")
def digital_signatures_cmd():
    """Create and manage digital signatures."""
    _digital_signatures_loop(first_entry=True)


@cli.command(
    context_settings={"max_content_width": 80},
    epilog=(
        "Examples:\n\n"
        "  ciphra config --vt-key YOUR_API_KEY\n"
        "  ciphra config --show\n"
        "  ciphra config --remove-vt-key\n\n"
        "Get a free VirusTotal key at: https://virustotal.com"
    ),
)
@click.option("--vt-key", default=None, help="Set your VirusTotal API key")
@click.option("--show", is_flag=True, help="Show current config")
@click.option(
    "--remove-vt-key",
    is_flag=True,
    default=False,
    help="Remove the stored VirusTotal API key",
)
@click.pass_context
def config(ctx, vt_key, show, remove_vt_key):
    """Manage ciphra configuration."""
    if remove_vt_key:
        existing = get_vt_key()
        if not existing:
            console.print("  [dim]No VirusTotal API key is set.[/dim]")
            return
        confirmed = questionary.confirm(
            "  Remove VirusTotal API key?",
            default=False,
            style=CIPHRA_STYLE,
        ).ask()
        if confirmed is None:
            console.print("  [dim]Cancelled.[/dim]")
            return
        if confirmed:
            _remove_vt_key()
            console.print(f"  [{GOOD}]VirusTotal API key removed.[/{GOOD}]")
        else:
            console.print("  [dim]Key unchanged.[/dim]")
        return

    if vt_key:
        if not _validate_vt_key(vt_key):
            console.print(
                f"\n  [{CAUTION}][WARN] Invalid VirusTotal API key format.\n"
                "  Keys are exactly 64 hexadecimal characters.\n"
                f"  Get a free key at: https://virustotal.com[/{CAUTION}]\n"
            )
            return
        existing = get_vt_key()
        if existing is not None and _validate_vt_key(existing):
            confirmed = click.confirm(
                "  A key is already set. Overwrite?",
                default=False,
            )
            if not confirmed:
                console.print("  [dim]Key unchanged.[/dim]")
                return
        tier_choice = questionary.select(
            "Is this a premium VirusTotal account?",
            choices=[
                "No, standard free account",
                "Yes, I have a paid premium account",
            ],
            style=CIPHRA_STYLE,
        ).ask()
        if tier_choice is None:
            console.print("  [dim]Cancelled. Key not saved.[/dim]")
            return
        tier = "premium" if tier_choice.startswith("Yes") else "free"
        set_vt_key(vt_key)
        set_vt_tier(tier)
        if tier == "premium":
            console.print(
                f"  [{GOOD}]Key saved. Tier: premium. Upload limit: 650 MB.[/{GOOD}]"
            )
        else:
            console.print(
                f"  [{GOOD}]Key saved. Tier: free. Upload limit: 32 MB.[/{GOOD}]"
            )
            console.print(
                "  [dim]Free API is for personal use only."
                " Commercial use requires a paid license.[/dim]"
            )
        return

    if show:
        LW = 20
        key = get_vt_key()

        if gpg_available():
            try:
                proc = subprocess.run(
                    [GPG_BIN, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if proc.stdout.strip():
                    first_line = proc.stdout.splitlines()[0]
                    gpg_display = f"installed ({first_line})"
                else:
                    gpg_display = "installed"
            except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
                gpg_display = "installed"
        else:
            gpg_display = "not installed"

        console.print()

        if key:
            vt_display = key[:4] + "*" * max(0, len(key) - 4)
            vt_tier = get_vt_tier()
            vt_limit_mb = get_vt_upload_limit() // (1024 * 1024)
            if vt_tier == "premium":
                rate_display = "per your VirusTotal license"
            else:
                rate_display = "4 lookups per minute (VirusTotal free tier)"
            console.print(
                f"  [dim]{'VirusTotal API key':<{LW}}[/dim]"
                f"[{ACCENT}]{vt_display}[/{ACCENT}]"
            )
            console.print(
                f"  [dim]{'Tier':<{LW}}[/dim][dim]{vt_tier}[/dim]"
            )
            console.print(
                f"  [dim]{'Upload limit':<{LW}}[/dim][dim]{vt_limit_mb} MB[/dim]"
            )
            console.print(
                f"  [dim]{'Rate limit':<{LW}}[/dim][dim]{rate_display}[/dim]"
            )
        else:
            console.print(
                f"  [dim]{'VirusTotal API key':<{LW}}[/dim][dim]not set[/dim]"
            )
            console.print(
                f"  [dim]{'Tier':<{LW}}[/dim][dim]not configured[/dim]"
            )
            console.print(
                f"  [dim]{'Upload limit':<{LW}}[/dim][dim]not configured[/dim]"
            )
            console.print(
                f"  [dim]{'Rate limit':<{LW}}[/dim][dim]not configured[/dim]"
            )

        console.print(
            f"  [dim]{'GPG':<{LW}}[/dim][dim]{gpg_display}[/dim]"
        )
        console.print(
            f"  [dim]{'Version':<{LW}}[/dim][dim]{VERSION}[/dim]"
        )
        console.print(
            f"  [dim]{'Config':<{LW}}[/dim][dim]{get_config_path()}[/dim]"
        )
        console.print()

        if key:
            console.print(
                f"  [dim]Files under {vt_limit_mb} MB are uploaded when the hash"
                f" is not found in the database.[/dim]"
            )
            console.print(
                f"  [dim]Files over {vt_limit_mb} MB are checked by hash only."
                f" The file is never uploaded.[/dim]"
            )
            console.print()

        return

    console.print(ctx.get_help())


@cli.command(hidden=True)
@click.pass_context
def completion(ctx):
    pass


@cli.command(
    context_settings={"max_content_width": 80},
    epilog=(
        "Examples:\n\n"
        "  ciphra completions --shell bash\n"
        "  ciphra completions --shell zsh\n"
        "  ciphra completions --shell fish"
    ),
)
@click.option(
    "--shell",
    type=click.Choice(["bash", "zsh", "fish"]),
    required=True,
    help="Shell to generate completion for",
)
def completions(shell):
    """Print instructions to enable shell tab completion."""
    shell_map = {
        "bash": "_CIPHRA_COMPLETE=bash_source",
        "zsh":  "_CIPHRA_COMPLETE=zsh_source",
        "fish": "_CIPHRA_COMPLETE=fish_source",
    }
    env_var = shell_map[shell]
    console.print(
        f"  Run this to enable completions:\n\n"
        f"  {env_var} ciphra > ~/.ciphra-complete.{shell}\n"
    )
    if shell == "bash":
        console.print(
            "  Then add to ~/.bashrc:\n"
            "  source ~/.ciphra-complete.bash"
        )
    elif shell == "zsh":
        console.print(
            "  Then add to ~/.zshrc:\n"
            "  source ~/.ciphra-complete.zsh"
        )
    elif shell == "fish":
        console.print(
            "  Then add to ~/.config/fish/config.fish:\n"
            "  source ~/.ciphra-complete.fish"
        )


if __name__ == "__main__":
    cli()
