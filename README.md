# cryptosis

Interactive, menu-driven terminal front-end for [GnuPG](https://gnupg.org).

> **Status:** early development, not yet usable.

cryptosis implements no cryptography. Every operation runs the system `gpg` (≥ 2.2.17).
Before anything runs, cryptosis shows the exact `gpg` command and asks you to confirm it.
Passphrases are entered only through your gpg-agent's pinentry; cryptosis never sees them.

## Requirements

- Linux or macOS (amd64 / arm64)
- GnuPG ≥ 2.2.17 with a working pinentry

## License

Copyright 2026 turiya-fps

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
