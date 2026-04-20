# Credits

Ciphra uses the following open source libraries.

## Runtime dependencies

| Library | Version | License | Use |
|---|---|---|---|
| requests | 2.33.1 | Apache-2.0 | HTTP API calls |
| click | 8.3.2 | BSD-3-Clause | CLI framework |
| rich | 14.3.3 | MIT | Terminal output |
| questionary | 2.0.1 | MIT | Interactive menus |
| cryptography | >=41.0.0 | Apache-2.0 | AES-256-GCM + Argon2id encryption |

## Dev dependencies

| Library | Version | License | Use |
|---|---|---|---|
| pytest | 9.0.3 | MIT | Test runner |

## External services

| Service | Use | Requires |
|---|---|---|
| VirusTotal | File hash scanning | Free API key |
| GnuPG | Signature verification, signing, encryption, decryption, key management | System install |
