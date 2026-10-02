---
change_type: implementation
priority: medium
dependencies: []
verifications:
  - id: local-cli
    requirement: Real CLI and regression tests meet the revised command contract
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
# Require explicit transformation targets and add decrypt
**Change Type**: implementation

## Problem / Context
Current encrypt accepts no name and silently converts every plaintext entry. User wants either entry names or --all and symmetric in-place decrypt. Do not confuse environment entry NAME with cryptographic --key.

## Proposed Solution
Grammar: `envdirx [-d D] encrypt (NAME [NAME ...] | --all)`; `envdirx [-d D] decrypt [--key PATH] (NAME [NAME ...] | --all)`. No-target and --all+names combinations fail argparse exit 2 BEFORE directory/key reads or writes. Encrypt has no --key. --key for decrypt uses existing get/run external-key validation/override semantics (cwd-relative, text-pointer vs symlink rules). Duplicate names are rejected at parsing (2) to avoid double conversion. Global -d stays before subcommand; default ./.envs.

For explicit names: encrypt requires plaintext entries; v1 ciphertext is already encrypted and fails 111. decrypt requires v1 ciphertext; ordinary plaintext is already decrypted and fails 111. For --all: sorted visible regular entries as existing _files; dotfiles (including key metadata) untouched; skip entries already in target state. Empty envdir or all already converted succeeds with no key lookup. Encrypt reads public key only when at least one entry needs encryption. Decrypt reads private key only when at least one v1 ciphertext needs decryption. No private key required by encrypt, and no public key required by decrypt.

Reserved `envdirx:` malformed/unsupported non-v1 envelopes MUST fail 111 in either operation, not be skipped or encrypted as ordinary plaintext. Existing v1 envelope when encrypt --all is skipped without validation or private lookup (same existing policy). Decrypt fully authenticates envelope and filename via _decrypt and rejects corruption/truncation/wrong key. Restored raw bytes exactly match original, no DJB trim/NUL/newline transformations. Existing -c can encrypt original plaintext beginning `envdirx:`; in-place decrypt MUST reject any restored bytes beginning `envdirx:` with 111 before replacing ANY entry, preserving ciphertext, because raw restore would be misclassified by get/run. Explain this deliberate reserved-prefix restriction and recommend get redirected to a separate outside-envdir file with appropriate permissions for such values. No format change/escaping.

Plan/read/validate ALL selected entries and prepare transformed bytes in memory BEFORE first write. A validation/key/decryption/unsupported-prefix/nonregular/missing-entry failure changes no files. Reuse _atomic to individually replace entries with 0600. On late filesystem write failure exit 111; already replaced earlier entries remain transformed, current failed _atomic target retains old bytes, no attempt at whole-batch rollback. Document preflight vs per-file atomicity, not transactional. Snapshot confidential content only in memory; no logging or output of values/keys, successful command stdout empty. Paths/names-only diagnostics.

## Acceptance Criteria / Explicit Completion Conditions
Subprocess tests prove no-target/mixed/duplicate selection rejected without writes; specific multiple names and --all real roundtrip binary/NUL/newlines/empty; unrelated entries and dotfiles untouched; private/public-only operation; invalid default pointer with explicit --key override; no-key no-op; all target skip vs explicit target-state errors; wrong-name/corrupt/unsupported/nonregular/dangling entries fail with entire preflight batch unchanged, no stdout/secret diagnostics; valid A before invalid Z doesn't modify A; reserved original plaintext prefix decrypt rejected while get still returns original; late _atomic failure semantics via focused fixture. Tests for legacy encrypt syntax updated. README/help/operations skill show required selectors and decrypt's deliberate plaintext-on-disk disclosure. All previous applicable security tests retained. Full bounded unittest and README shell execution pass; canonical specs reflect explicit transformation behavior.

## Boundary / Preserved Contracts / Out of Scope
Only src/envdirx/, tests/test_envdirx.py, README.md, operations skill and OpenSpec. Preserve bytes/crypto formats, plaintext-default set, -c, get/run, mkdir/keygen and existing external-key reference protections. No dependencies, locks, rotation, secret store, actual operational keys, global install, GitHub/publish or vault writes by worker. Parent owns user note update. No whole-batch transactional writes or hostile concurrent directory protection. Init removal is separate and requires no hard dependency; run sequentially after removal to avoid overlapping files. No alteration of historical archive.
