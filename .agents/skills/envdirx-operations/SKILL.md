---
name: envdirx-operations
description: Use when changing or operating envdirx encrypted DJB envdirs.
---

# envdirx operations

- Preserve DJB envdir first-line, trim, NUL-to-newline and empty-file-unset behavior in `run`.
- Keep private keys outside the envdir; never print values or put secrets in CLI arguments. Encrypt through stdin, and fail closed on decryption errors.
- `run` finds the private key only via `--key` (before DIRECTORY) or the fixed `DIRECTORY/.envdirx.key` pointer (symlink or one-line path file); never add an adjacent-key fallback. Key targets must resolve outside the envdir, be owned by the user and have no group/other bits; failures exit 111 before exec.
- Run `uv run python -m unittest discover -s tests -v` after changes. Check generated keys remain 0600 and are excluded from git.

See `README.md` for user-facing commands and format boundaries.
