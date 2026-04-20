# Changelog

## [1.3.0] - 2026-04-19

### Added
- Manage subkeys menu: Add encryption subkey, Rotate encryption
  subkey, Extend subkey expiry
- Extend key expiry flow for primary key expiry management
- Delete key pair with passphrase verification before deletion
- Expiry dates shown in all key selection lists across all flows
- Subkey expiry shown in rotate and extend subkey flows
- Dynamic subkey index detection via _get_active_encryption_subkey_index
  to correctly target active subkeys after rotation
- Passphrase pre-validation via verify_key_passphrase before rotate,
  extend subkey, extend key, and delete operations
- CAUTION warning when expired key selected in subkey management flows
- Empty input guard on all custom expiry fields
- Digital Signatures menu loops back after each sub-flow
- Encrypt and Decrypt menu loops back after each sub-flow
- Configure settings menu loops back after each sub-flow
- Key list labels show expiry dates across all flows
- FAQ rewritten with 8 focused items: verdicts, encryption types,
  password recovery, key vs subkey expiry, receiving encrypted files,
  VirusTotal privacy, CLI reference, passphrase storage
- Colored verdict names in FAQ pager matching on-screen colors
- _translate_error updated with key not changed and no update needed entries

### Fixed
- Rotate and extend subkey operations now correctly target the first
  active non-revoked encryption subkey instead of hardcoded key 1
- Wrong passphrase on extend and rotate operations now correctly
  rejected before GPG operation runs
- Empty input on custom expiry no longer triggers invalid format warning
- Spinner text consistency: Deriving key across encrypt and decrypt flows
- Export public and private key flows now show expiry dates in key list

## [1.2.0] - 2026-04-18

### Added
- Digital Signatures menu: Create key pair, Create a signature, Export public key, Export private key
- Ed25519 signing key + cv25519 encryption subkey generation via GPG batch mode
- Passphrase-protected key generation (passphrase retry loop, mismatch detection)
- Expiry selection with 1y/2y/5y/custom options. "2 years (recommended)" default.
- Detached signature creation (.asc armored output)
- Public and private key export to Downloads/ with default filenames derived from key email
- Collision handling on export: overwrite, timestamp rename, or cancel
- Expired key warning with "Use it anyway?" confirm in sign flow
- Keyserver recovery offer when no public key found during export
- "Create a key pair now?" offer when keyring is empty in export flows
- write_operation_log("", "", "keygen", "ok") for key generation (empty sha256, no input file)
- Immediate export offer after key pair creation

### Fixed
- Removed %no-protection from GPG batch key generation. Keys are now properly passphrase-protected.

## [1.1.0] - 2026-04-15

### Added
- Encrypt & Decrypt menu: symmetric (AES-256-GCM + Argon2id) and asymmetric (GPG)
- .ciphra format: magic header CIPHRA1, AES-256-GCM ciphertext, Argon2id key derivation
- Argon2id parameters stored in file header, calibrated to target hardware
- Streaming encryption/decryption via low-level Cipher API (no full-file AESGCM.encrypt)
- Temp file safety: atomic rename on success, delete on failure
- Asymmetric encryption: GPG public key, .gpg binary output, encryption-capable keys only
- Asymmetric decryption: retry loop matching symmetric behavior exactly
- Key algorithm shown in selection list (RSA-4096, ECDH, etc.)
- Import public key from local file during asymmetric encrypt flow
- Collision handling: Overwrite / Enter new path / Cancel (both decrypt flows)
- Large file warning at 1 GB for both encrypt and decrypt
- Already-encrypted file warning (.ciphra and .gpg) before proceeding
- Password recommendation shown before prompt (12+ chars, mixed types)
- Short password warning with retry option after confirmation
- Three-phase spinner for symmetric encrypt: calibrating, deriving key, encrypting
- Two-phase spinner for symmetric decrypt: deriving key, decrypting
- Post-operation notes: original not deleted, .ciphra ciphra-only, .gpg cross-compatible
- Activity log operation field (encrypt, decrypt, verify, hash, sign, keygen)
- utils/crypto_tools.py with detect_format(), MAGIC_HEADER constant

## [1.0.0] - 2026-04-15

### Changed
- Full rewrite of ciphra.py and utils/gpg_tools.py
- Design system: five-token color system (ACCENT, GOOD, CAUTION, BAD, DIM)
- Error model: four outcomes, single _translate_error() function,
  no raw errors reach the user
- Interactive flow: file selection with retry loop, expected hash moved
  to right after file selection, algo selection with plain descriptions,
  auto-return to menu after every action
- First run: no VT gate, no sys.exit, drops into menu directly
- GPG binary detection: _find_gpg() tries gpg, gpg2, and platform paths
- Unicode fallback: ASCII banner and symbols for non-Unicode terminals
- VT result shows whether file was uploaded or hash-only
- VT tier is user-declared at key setup, not auto-detected
- VT rate limit labelled as published tier limit in Show config
- Show config hides VT fields when no key is set
- No VT key during verify: offer to add key inline
- Configure settings Ctrl+C returns to menu
- Removed post-action menu and file confirmation prompts
- Removed fake delays and internal status messages
- All subprocess calls use explicit timeouts and GPG_BIN
- save_credentials wrapped in OSError handler
- pytest moved to requirements-dev.txt

### Removed
- Flask web app (removed in pre-1.0.0 development)
- First run VirusTotal setup wizard
- Post-action What next menu
- Auto-detection of VT tier via API call

## [0.1.0] - 2026-04-07

### Added
- CLI entry point with verify, hash, config, completions commands
- SHA-256, MD5, SHA-1, SHA-512 file hashing
- VirusTotal hash lookup and file upload
- GPG signature verification
- Local CSV scan log with rotation
- Interactive arrow-key menu
- Animated launch screen
- Shell completion support for bash, zsh, fish
