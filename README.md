# cryptosis

Menu-driven terminal front-end for [GnuPG](https://gnupg.org). Pre-release.

cryptosis implements no cryptography: every operation runs the system `gpg`, shown in full and confirmed first. Passphrases go only through gpg-agent's pinentry.

- **Keys:** list, generate, import (previewed), export, delete, expiry, owner trust, revocation cert
- **Files:** encrypt, decrypt, sign, verify
- **Text & clipboard:** encrypt/decrypt pasted text, clipboard or file
- **Keyserver / WKD:** fetch, search, publish

## Requirements

- Linux or macOS, amd64/arm64
- GnuPG ≥ 2.2.17 with a working pinentry
- Clipboard: `pbcopy`, `wl-copy`, `xclip` or `xsel`

## Install

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/turiya-fps/cryptosis/main/install.sh | bash
```

Installs to `~/.local/bin`. Env: `CRYPTOSIS_VERSION` (pin tag), `CRYPTOSIS_INSTALL_DIR`, `CRYPTOSIS_REQUIRE_COSIGN=1`.

The sha256 check proves integrity only. Authenticity needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/): if installed, the script verifies `checksums.txt` was signed by this repo's release workflow.

From source: `go install github.com/turiya-fps/cryptosis/cmd/cryptosis@latest`

Manual verification:

```sh
sha256sum --ignore-missing -c checksums.txt   # macOS: shasum -a 256 …
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/turiya-fps/cryptosis/.github/workflows/release.yml@refs/tags/<tag>" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
gh attestation verify --repo turiya-fps/cryptosis cryptosis_<version>_<os>_<arch>.tar.gz
```

macOS binaries are not notarized; browser downloads need `xattr -d com.apple.quarantine cryptosis` (curl downloads don't).

Builds are reproducible: `go version -m cryptosis` shows the Go version to rebuild the tag with.

## Usage

Run `cryptosis` in a terminal (piped I/O is refused). Settings live in `~/.config/cryptosis/config.json` (or `$XDG_CONFIG_HOME`): keyserver (default keys.openpgp.org), clipboard auto-clear, key defaults, armor, accessible mode.

## Security model

Goal: no more attack surface than typing the gpg commands yourself. Trusted: gpg, gpg-agent, pinentry, OS, your account.

- No shell; typed operations only; positional args after `--`
- Every command previewed; secret export/delete need the typed fingerprint
- Warns on risky `gpg.conf` options (`always-trust`, `encrypt-to`, `pinentry-mode loopback`…)
- Untrusted text (UIDs, keyserver data, plaintext) stripped of control/ANSI/bidi characters; plaintext shown on a cleared alt-screen
- Imports: read once, previewed with `show-only`, same bytes imported; fetched keys must match the fingerprint or email asked for
- No expired/revoked recipients; unverified ones only if enabled, flagged per use
- Per-signature verify report; clearsign warns about unsigned surrounding text
- Output via temp file + rename on success; no silent overwrite
- Core dumps off; text ops use pipes, no temp files
- Network only on keyserver actions: HTTPS, timeouts, size caps; no telemetry or auto-update

Limits: anything running as your user can reach your keys; clipboard is readable by other apps (and macOS Universal Clipboard); keyserver keys are unverified claims—check fingerprints.

Vulnerabilities: see [SECURITY.md](SECURITY.md).

## Troubleshooting

- **Ctrl-C ignored at passphrase prompt:** use pinentry's Cancel/Esc.
- **pinentry "Required environment variable not set":** no terminfo for `$TERM`; install it or use `TERM=xterm-256color`.
- **No passphrase prompt on macOS:** pinentry-mac saved it in Keychain; remove it there.
- **keys.openpgp.org key "no user ID":** owner hasn't verified their address; get the key from them.

## Development

```sh
make lint test build
make race fuzz vuln
```

Release: push a `v*` tag (`.github/workflows/release.yml`).

## License

Apache-2.0. Copyright 2026 turiya-fps. See [LICENSE](LICENSE).
