---
change_type: implementation
priority: high
verifications:
  - id: rekey-contract
    requirement: Lossless fail-closed out-of-place key rotation and existing CLI compatibility
    phase: pre-integration
    owner: conflux-acceptance
    trigger: after implementation and before archive
    automation: tests/test_envdirx.py
    evidence: uv run python -m unittest discover -s tests -v
    rerun: uv run python -m unittest discover -s tests -v
    prerequisites:
      - Python 3.13+ and locked dependencies; fixtures isolate HOME and XDG_DATA_HOME
    execution_class: repository-local
    completion_role: change-blocking
---
# Add rekey

**Change Type**: implementation

## Context
Existing keygen refuses replacement; encrypt/decrypt operate in place and late write failures are not batch transactions. Rotating by replacing metadata strands existing ciphertext. Add a safe out-of-place command, not an in-place multi-file transaction.

## Proposed solution
`envdirx [-d SOURCE] rekey --output DEST [--key OLDKEY] [-k/--new-key NEWKEYFILE | -K/--new-key-dir NEWKEYDIR]` generates a fresh X25519 key and a complete new envdir. DEST is required and must not exist (including dangling links); its parent must already exist. Paths are cwd-relative with leading ~/ expansion, consistent with current key paths. SOURCE defaults to ./.envs; repeated -d is rejected as for other non-get commands. OLDKEY only selects the old decrypt key; -k/-K select the NEW external key with keygen destination semantics, including the default key store, but different long option names. --key OLDKEY and --output have no short aliases; -k/--new-key and -K/--new-key-dir are mutually exclusive. Rekey help must explicitly distinguish old --key from keygen --key, which names the new key. New key destinations must be outside both resolved SOURCE and DEST; no overwrite, no -f.

Source and old key are never changed or deleted. Only ciphertext entries are re-encrypted, preserving original bytes and names; plaintext entries are copied unchanged, including zero-byte unset entries. Read printable and legacy ciphertext; output encrypted entries use the current printable format. Decrypted reserved-prefix values stay encrypted and are allowed. No decrypted ciphertext bytes are written to disk or logs. Existing plaintext remains plaintext, explicitly documented. Ignore no arbitrary metadata silently: reject any source dotfile except .envdirx.pub and .envdirx.key (these are replaced, never copied). All visible entries must satisfy existing name/regular-file rules. No old public key is required; an old private key is required only if an encrypted entry exists. Empty or plaintext-only source still gets a fresh key and does not resolve or validate OLDKEY. Source .envdirx.pub/.envdirx.key are matched by name only, not type-checked; the pointer is read only when ciphertext exists and no OLDKEY is supplied.

Preflight all entries and authenticate all encrypted entries before creating default-store directories, a new key or staging files. Prepare all output bytes in memory. Generate a fresh pair, re-encrypt and verify every encrypted result using the new private key before publication. Build new metadata and entries in a private 0700 sibling staging directory under DEST's existing resolved parent. Write private key 0600 externally, public key 0644, absolute secret-key pointer, and entries 0600. Explicitly chmod staging 0700 regardless of umask. DEST basename must not be empty, `.` or `..`. Publish complete staging directory with one os.rename only after every write succeeds and an lstat re-check confirms DEST is absent. Rename failure removes invocation-created staging/key and exits 111. No-clobber applies under the existing no-concurrent-mutation ceiling: rename may replace a concurrently created empty directory, not a hostile-race guarantee. Refuse DEST inside SOURCE or SOURCE inside DEST, including symlink aliases; do not follow invalid/dangling/cyclic destination parent paths. Existing key-store directory modes remain unchanged; only default-store missing dirs may be created at 0700.

On handled validation or I/O failure: exit 111, empty stdout, no secret diagnostics, SOURCE/old key/existing unrelated files unchanged, no published DEST, remove only staging and new key artifacts created by this invocation. Parser failures exit 2 without writes. Newly created empty default-store dirs may remain. On success exit 0 with empty stdout. Interruption/crash may leave ciphertext staging and a new external key, but SOURCE/old key stay usable; document this bounded guarantee rather than claiming crash-proof atomic durability or secure RAM erasure. No automatic active-path switch, deletion, service restart, rollback journal, new dependency, format change, installed-tool update, release, push, real-data rotation or .cflx.jsonc.

## Acceptance criteria
1. Real CLI rotates a fixture containing both ciphertext formats, binary/newline/NUL/empty/reserved-prefix encrypted values and ordinary plaintext; new get/run work and old source get/run still work. Keys differ and old key fails to decrypt new ciphertext. Validate output bytes, modes, absolute pointer and source snapshot invariance.
2. Explicit OLDKEY works when source pointer is absent; absent source public key works. Plaintext-only/empty inputs need no old key. New key destinations cover default XDG/home, -k/-K, umasks and no-overwrite semantics without touching real stores.
3. Malformed/unsupported/wrong-name/wrong-key ciphertext, nonregular files, invalid names, unexpected dotfiles, existing/dangling/overlapping destinations, unsafe external-key destinations and parser errors fail closed with unchanged source and no output. Inspect fixtures before/after; diagnostics must not include secret values/key bytes.
4. Inject staging entry/metadata/key write, verification and publication failures, including a failure after an earlier output entry was staged; no complete or partial published DEST and no newly created key remain. Verify disk writes never contain recovered ciphertext plaintext: use a random encrypted-only sentinel, inspect intercepted filesystem writes (excluding initial fixture setup) and scan every regular file under the fixture root and isolated HOME plus stderr after success and each failure for sentinel bytes. Existing plaintext copies are explicitly exempt.
5. Preserve existing commands and ciphertext/key-reference formats. Full bounded unittest suite succeeds. Update English/Japanese README, tracked public skill and CLI help with executable isolated fixture examples and retention/leak caveats. Archive canonical spec accurately.

## Fable review
Claude Fable 5.1 (claude-fable-5-1), job 608d68dcca683826bd2ed895f5118f1f, conditional GO. Accepted all five text corrections: distinct long key options, fixed rename publication/umask contract, preflight before default-store creation, lazy old-key/metadata semantics and canonical grammar/docs. Also made the secret-write sentinel check executable in the test contract. Update both README no-rotation claims and command tables; locate the Japanese counterpart. Keep the main help free of the word legacy to preserve existing tests; explain legacy support in subcommand help.

## Change boundary
Source src/envdirx/__init__.py, tests/test_envdirx.py (and test_public_skill.py where needed), README.md, README.ja.md, skills/envdirx/SKILL.md, cli-workflow spec. No independent cleanup or unrelated architecture.

## Explicit completion conditions
Real argparse/dispatch invokes rekey, the isolated CLI tests prove non-stub success and failure paths, all existing tests pass, docs reflect actual grammar, delta is archived into canonical spec, local base is clean. Feature readiness is not installation/release or real credential rotation.

## Out of scope
In-place replacement and automatic path cutover, concurrent hostile mutation (existing local POSIX threat ceiling), secure erase, API credential reissue, old-key deletion, external publication. The user switches their consumer to DEST after verification. Key leakage also requires rotating the underlying service credentials.
