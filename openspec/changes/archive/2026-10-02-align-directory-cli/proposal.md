---
change_type: implementation
priority: medium
dependencies: []
verifications:
  - id: cli-tests
    requirement: Real CLI supports directory-oriented plaintext and encrypted workflows safely
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
# Align envdirx with the directory-oriented CLI

**Change Type**: implementation

## Problem / Context
User approved the workflow in the external note envdirxこんなふうに使いたい: global -d default ./.envs, mkdir, keygen, plaintext-default set, opt-in encrypted set -c, get and run. User explicitly removed keygen -f and corrected the private-key link to .envdirx.key. Current CLI requires positional directories, has init instead of keygen, encrypts every set and lacks get/mkdir. Source is src/envdirx/__init__.py, tests are unittest subprocess integration tests. No tracked unconditional hook exists.

## Proposed Solution
One coupled CLI migration: shared parser/directory selection, changed set grammar, keygen and docs must land together; do not split incompatible intermediate command examples. Keep existing v1 cryptography and bytes unchanged; use stdlib plus installed cryptography, no new dependency.

### Fixed command grammar
- Global `-d/--directory DIRECTORY` defaults to `./.envs` relative to cwd and is specified BEFORE the subcommand; no automatic directory creation except mkdir.
- `envdirx [-d D] mkdir`: create the directory including missing parents, mode 0700 for newly created envdir; existing directory succeeds without chmod, non-directory fails 111. Other commands require the directory already exists.
- `envdirx [-d D] keygen (-k/--key PATH | -K/--key-dir DIRECTORY)`: exactly one destination option required (argparse exit 2 on missing/conflicting options), no default destination and NO -f/--force. Key-dir must already exist. Generate X25519 key; for -K the basename is lowercase full SHA-256 hex of raw 32-byte public key plus `.key`. -k is a filename even when it names an existing directory (reject as collision). Leading ~/ expands and relative destination paths use cwd.
- keygen writes external raw private key 0600, envdir `.envdirx.pub` raw public key 0644 and `.envdirx.key` symlink to fully resolved absolute private-key path. Reject ANY preexisting destination/public/pointer including dangling links, key destinations within fully resolved envdir, missing/non-directory key parents; no overwrite or rotation. Preflight before writes; cleanup only files created by this invocation if a later write fails. No secret printed. Reuse existing init helpers rather than add a new crypto format.
- `envdirx [-d D] set [-c] NAME`: read stdin bytes; DEFAULT store plaintext bytes atomically with 0600 and NO key lookup, except reserved `envdirx:` leading bytes are rejected with 111 before writing (preserve any old entry). Document this reserved format prefix; use -c for such values. -c encrypts with existing public key only. Preserve name/nonregular-entry protections. No key option for set (unused option removed).
- `envdirx [-d D] get [--key PATH] NAME`: output exact stored plaintext bytes, or decrypted original bytes when encrypted, to stdout with NO added newline and NO envdir first-line/trim/NUL transformation. Empty entry outputs zero bytes and succeeds. This is explicit secret disclosure by user request; diagnostics must never contain values. Missing/invalid entry or key fails 111 with no stdout. Use same format validation/name binding as run, including unsupported envdirx: formats. --key overrides pointer for encrypted get only.
- `envdirx [-d D] run [--key PATH] -- COMMAND [ARGS...]`: no positional directory; require literal -- separator before the child command so child flags cannot be parsed as tool flags. Validate/resolve only keys needed by encrypted values, preserving exec/exit and DJB semantics. Missing command or separator fails safely (2 or 111), no child. --key must precede separator.
- `envdirx [-d D] encrypt [NAME ...]`: preserve existing in-place public-key-only encryption behavior with directory moved to global option. Remove unused --key. Existing ciphertext unchanged/skipped as before.
- Retain `init [--key PATH] DIRECTORY` as a documented legacy-only exception with its existing positional directory, adjacent default key destination and regular text pointer; do not change it to symlink. Explicit global -d/--directory combined with init is rejected with argparse exit 2 (no writes); default implicit directory is not considered an explicit flag. No deprecation warning required. Existing init canonical contract remains supported.

### Compatibility / migration
set/encrypt/run positional directory syntax is intentionally replaced (pre-release 0.1.0); do not heuristic-detect legacy set/run forms or retain implicit encrypted set. README clearly maps old commands to -d and set -c; adapt all existing tests to changed grammar, keep encrypted regression fixtures explicitly -c (do not weaken encrypted assertions). Document new get raw-byte contract and avoid examples exposing actual secrets or expanding variables in the calling shell: `run -- sh -c 'test -n "$AAA"'`.

## Preserved Contracts
Public key remains a regular raw-key file, symlinks rejected. Private reference accepts symlink or UTF-8 one-line path, text ~/ only, relative to envdir; explicit --key uses cwd. External key validation/owner/mode and no adjacent fallback remain. DJB first-line, trimming, NUL conversion, unset/empty, filename authentication, unsupported cipher rejection, mixed plaintext and cipher entries, exit propagation remain. Key overwrite is forbidden. Existing init users still function, but must use the new -d/set -c/run grammar afterwards.

## Acceptance Criteria
Subprocess tests in isolated temporary cwd/HOME prove default .envs and explicit -d; mkdir idempotence and non-directory errors; plaintext set/get exact bytes without keys; encrypted set/get and run with real values and no plaintext on disk; public-key-only encryption; -k and fingerprint -K real key generation and absolute symlink; all collision cases preserve preexisting bytes and dangling links; failure cleanup and inside-envdir alias rejection. Missing/conflicting keygen options and -f rejected, no files written. Explicit global -d with legacy init rejected; plaintext set of reserved envdirx: prefix rejected without changing existing entry. get rejects missing/invalid/corrupt/unsupported/wrong-name ciphertext without stdout; bad pointer/owner/mode blocks get/run without child. Child flags work after --; missing separator/command does not spawn. Run and encrypted get agree on key override. Keep all prior security/regression coverage and execute all README shell blocks. Test init exception and migration, SHA256 filename and key/public modes.

## Explicit Completion Conditions
Actual CLI, tests and README land and bounded unittest gate succeeds. Canonical cli-workflow specs added; existing key-reference init scenario updated to call set -c. Help reflects all grammar/default/legacy behavior. Repository operations skill updated to prevent implicit encrypted-set assumptions. No active-path test artifacts needed after archive.

## Boundary / Out of Scope
Only src/envdirx/, tests/, README.md, .agents/skills/envdirx-operations/ and OpenSpec. No real operational keys, dotenvx migration, new dependencies, key rotation, global installation, GitHub writes, package publishing or external Obsidian editing by worker. Parent updates use note after acceptance. No production changes for TOCTOU hardening beyond existing local POSIX trusted-directory ceiling.
