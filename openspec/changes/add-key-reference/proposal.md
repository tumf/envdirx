---
change_type: implementation
priority: medium
verifications:
  - id: key-reference-tests
    requirement: Key references work end to end and fail closed without changing envdir semantics
    phase: pre-integration
    owner: conflux-acceptance
    trigger: pull-request-validation
    automation: tests/test_envdirx.py
    evidence: uv run python -m unittest discover -s tests -v
    rerun: uv run python -m unittest discover -s tests -v
    prerequisites: []
    execution_class: repository-local
    completion_role: change-blocking
---
# Add external private-key references

**Change Type**: implementation

## Context
The user wants a fixed `.envdirx.key` entry inside each envdir to point to a private key outside that envdir. The entry may be a symlink or a regular file containing a file path, never private-key bytes. Current `_key_path` guesses the adjacent DIRECTORY.key and `_private` rejects all symlinks. `run` uses argparse REMAINDER, so `--key` must precede DIRECTORY.

## Proposed Solution
Keep `.envdirx.pub` and encrypted entries in the envdir. On init create an external private key and a regular UTF-8 `.envdirx.key` pointer with its fully resolved absolute path plus newline. Default init key location remains the adjacent DIRECTORY.key; explicit --key is allowed. For run, explicit --key overrides the pointer, otherwise resolve only the fixed pointer (no adjacent-file fallback). Use lstat to accept only a pointer symlink or regular file (reject FIFO/socket/device before reading); a regular file contains one nonempty UTF-8 path line with optional LF/CRLF terminator. Preserve spaces in path names; reject NUL, embedded newlines and empty paths. Expand leading ~/ only in text pointers, not symlinks. Relative pointer contents and symlink targets resolve against envdir. Explicit --key relative paths continue to resolve against process cwd and expand leading ~/.

Fully resolve the final key target, require a regular file outside the fully resolved envdir, owned by effective uid with no group/other permission bits. Broken/cyclic links, missing pointers/keys, invalid text, directories, invalid keys and insecure keys exit 111 without starting the child or printing key bytes. This applies to explicit --key and init destinations too. Existing ciphertext format, public key format, plaintext mixing, envdir semantics and exec/exit propagation remain unchanged. Plaintext-only run still needs no key/pointer. `_regular` protections for normal envdir entries stay unchanged; only key reference resolution follows links.

Init must fail without overwriting a preexisting public key, private-key path or pointer (including dangling symlink), and reject private-key destinations inside envdir after symlink resolution. Parent directories are not auto-created. Write pointer 0600 and key 0600; public key stays 0644. Preflight all paths before writing; on failure remove only files created by this invocation, never preexisting files. Existing envdirs migrate by manually adding a pointer to their existing key; no re-encryption or automatic fallback.

## Acceptance Criteria
Integration tests cover text and symlink pointers with absolute and relative paths, text ~/ expansion, explicit override including a missing/invalid pointer, directory relocation with valid relative pointer, and init-created pointer roundtrip. Failure cases cover missing/empty/multiline/non-UTF8/NUL text, dangling/cyclic symlink, directory target, key inside envdir through aliases, nonregular pointer including FIFO, bad permissions, wrong key, wrong owner (unit test may mock uid metadata), and existing pointer collision; no child marker is created on failures and stderr contains no secret. Plaintext-only run, NUL/newline/trimming/unset/empty behavior, filename-authenticated ciphertext, and exit code 7 remain proven by regression tests. Tests must exercise real encrypted values and child environments, not only path-return assertions.

## Explicit Completion Conditions
The bounded verification command succeeds against actual production code; README notes that *.key ignores also match the pointer (do not weaken private-key ignores); subcommand-specific CLI help distinguishes init destination, run override and unused set/encrypt --key. README and CLI help accurately describe `.envdirx.key`, option ordering, migration, permission/owner checks and symlink dereference distribution risk. Canonical specs are promoted during archive and the archived proposal still references tracked tests in tests/ (not active-change scripts).

## Boundary / Out of Scope
Change only src/envdirx/, tests/, README.md, the existing project operations skill if needed, and OpenSpec artifacts. No cryptography/format redesign, new dependencies, key rotation, keychain, central key discovery, automatic migration, GitHub publication, or writes to actual operational keys. Do not modify the external Obsidian vault from the worker; parent updates its note after independent acceptance. Documentation and runtime are one coupled interface change.
