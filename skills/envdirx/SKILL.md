---
name: envdirx
description: Use when installing, using, testing, or changing the envdirx CLI and its encrypted DJB envdir format.
---

# envdirx

Use the repository's `README.md`, `openspec/specs/`, source, and tests as the authority; do not infer current behavior from older CLI versions. Run `uv run envdirx --help` and the relevant subcommand's `--help` before changing or documenting a command.

- `envdirx (-V | --version)` prints the installed version without reading any envdir.
- Put `-d DIR` before the subcommand; the default is `./.envs`. Only `mkdir` creates the envdir. There is no `init` command.
- `set NAME` reads stdin and stores plaintext; `set -c NAME` encrypts with the public key. `encrypt` and `decrypt` require names or `--all`.
- `run [--key KEY] -- COMMAND` applies DJB envdir semantics and decrypts encrypted entries for the child. `get` emits raw bytes without a newline. Repeat global `-d` for `get` to search in priority order; only absent entries fall back, and empty entries win. Permission, format, or decryption errors stop the search. Use the selected directory’s key pointer unless `--key` overrides it. Never print real values or private keys in logs or transcripts.
- Store private keys outside the envdir. `keygen -k FILE`, `keygen -K DIR`, or plain `keygen` (default key directory `$XDG_DATA_HOME/envdirx/keys` for an absolute `XDG_DATA_HOME`, else `~/.local/share/envdirx/keys`, created at 0700) creates `.envdirx.pub` and a `.envdirx.key` pointer. In tests, isolate `HOME` and unset or set `XDG_DATA_HOME` so the real key store is never touched. `run`, `get`, and `decrypt` use `--key` or that pointer for encrypted entries; never rely on an adjacent-key fallback.
- `rekey --output DEST [--key OLDKEY] [-k/--new-key FILE | -K/--new-key-dir DIR]` writes a new envdir under a fresh key and leaves the source and old key unchanged. Its `--key` is the OLD key (unlike `keygen`); existing plaintext entries stay plaintext. It never switches consumers or deletes the old key: verify DEST before cutover, and rotate service credentials if a key or ciphertext leaked.
- `decrypt` writes secrets as plaintext on disk; do not run it on real data without an explicit request for the target entries. Validate key ownership and permissions, preserve fail-closed errors, and do not weaken the `*.key` Git ignore rule.
- Keep changes minimal, align specifications and tests, and run `uv run python -m unittest discover -s tests -v`. Commit by theme and leave the worktree clean; do not push or publish without instruction.

Read `README.md` for command examples, byte-format limits, migration, and release procedure. Read `openspec/specs/cli-workflow/spec.md` and `openspec/specs/key-reference/spec.md` for behavioral requirements.
