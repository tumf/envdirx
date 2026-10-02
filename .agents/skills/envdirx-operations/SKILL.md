---
name: envdirx-operations
description: Use when changing or operating envdirx plaintext or encrypted DJB envdirs.
---

# envdirx operations

- Grammar: `envdirx [-d DIR] mkdir | keygen (-k FILE | -K DIR) | set [-c] NAME | get [--key K] NAME | encrypt [NAME ...] | run [--key K] -- CMD`. `-d` goes before the subcommand and defaults to `./.envs` (cwd-relative); only `mkdir` creates directories. Positional directories for set/encrypt/run are gone, and `init` was removed (it now fails with exit 2); create envdirs with `mkdir` + `keygen`. Existing regular-file text pointers written by the old init stay valid; never convert or delete them.
- `set NAME` stores **plaintext** by default and reads no key. Never assume `set` encrypts: pass `-c` for anything secret, and verify the stored file starts with `envdirx:v1:` when it must be encrypted. Plaintext values starting with `envdirx:` are refused; use `-c` for those.
- `get` prints the raw stored/decrypted bytes (no newline, no DJB trimming). It discloses secrets: only run it when the user explicitly asks, and never into logs or transcripts.
- Preserve DJB envdir first-line, trim, NUL-to-newline and empty-file-unset behavior in `run`; `run` requires the literal `--` and `--key` must precede it.
- Keep private keys outside the envdir; never print values or put secrets in CLI arguments. Write values through stdin, and fail closed on decryption errors.
- `keygen` never overwrites (no force flag); it writes the 0600 private key, 0644 `.envdirx.pub` and an absolute `.envdirx.key` symlink. `set -c` and `encrypt` use only the public key.
- `run`/`get` find the private key only via `--key` or the fixed `DIR/.envdirx.key` pointer (symlink or one-line path file); never add an adjacent-key fallback. Key targets must resolve outside the envdir, be owned by the user and have no group/other bits; failures exit 111 before exec or output.
- Run `uv run python -m unittest discover -s tests -v` after changes. Check generated keys remain 0600 and are excluded from git.

See `README.md` for user-facing commands and format boundaries.
