---
change_type: implementation
priority: high
verifications:
  - id: in-place-rekey
    requirement: Same-path verified key rotation with interruption-safe directory publication
    phase: pre-integration
    owner: conflux-acceptance
    trigger: after implementation and before archive
    automation: tests/test_envdirx.py
    evidence: uv run python -m unittest discover -s tests -v
    rerun: uv run python -m unittest discover -s tests -v
    prerequisites:
      - Python 3.13+, locked dependencies, isolated HOME and XDG_DATA_HOME, native atomic directory exchange support
    execution_class: repository-local
    completion_role: change-blocking
---
# Rotate the key at the existing envdir path

**Change Type**: implementation

## Why
The user corrected the actual behavior, not merely the help: rekey must update the existing envdir, not create a separate destination requiring manual consumer cutover. The previous out-of-place proposal was the assistant's incorrect design. Replace it, do not preserve it as the default or add another mode.

## Contract and CLI
`envdirx [-d DIR] rekey [--key OLDKEY] [-k/--new-key NEWKEYFILE | -K/--new-key-dir NEWKEYDIR]` replaces encrypted entries, `.envdirx.pub` and `.envdirx.key` at the SAME resolved DIR path. Default DIR remains ./.envs. Reject legacy --output with exit 2 and a clear migration error before any writes; no output directory option, force flag or extra rotation mode. Keep old/new key-option distinction, default key-store selection, no-overwrite and external-key rules. Do not delete or modify the old external private key. New private key is fresh, external, 0600. Plaintext entries remain byte-identical (including empty) and mode-identical. Preserve DIR permission bits; regenerated encrypted entries 0600, public key 0644, new absolute key symlink. No change to ciphertext or pointer formats. Retain lazy OLDKEY lookup, absent source public-key support, both ciphertext inputs, reserved-prefix decrypted data, and current unsupported dotfile/name/nonregular refusals.

## Fixed implementation mechanism
Use a small ctypes native exchange helper: Darwin libc `renamex_np(a, b, RENAME_SWAP=2)`; Linux libc `renameat2(AT_FDCWD=-100, a, AT_FDCWD, b, RENAME_EXCHANGE=2)`. Set argtypes/restype, use_errno, fsencode; translate errno to OSError. Missing symbol/platform or unsupported filesystem fails closed with actionable diagnostic; NO two-rename fallback, no temporary absence of active DIR. No new dependency, architecture-specific syscall numbers, daemon, journal or automatic reader mutations.

Resolve DIR once and exchange its real path so user-facing symlink aliases remain intact. Refuse filesystem root, mountpoints, and invocation cwd equal to/inside resolved DIR BEFORE writes. Require parent directory access suitable for sibling staging/exchange. Other processes must not hold cwd/open directory handles into DIR during rotation; such handles keep the old inode, which exchange cannot retarget. Callers coordinate against concurrent mutations. Readers already in flight may fail authentication/read; never claim transparent concurrent-reader success. Existing get/run fail-closed authentication and no partial secret stdout/child exec must remain covered. A reader started after publication sees the new directory at the unchanged path.

Preflight/read/authenticate all entries and construct/re-encrypt/verify new ciphertext entirely in memory before creating key/store/staging artifacts, as today. Create fresh external key and a private sibling staging dir. Populate complete metadata and entries, apply original directory/ plaintext modes only after writes. Fsync files and staging directory before exchange; unsupported fsync must fail before exchange, not be silently ignored. Test native exchange capability using TWO invocation-private empty sibling directories before creating the new key; failure cleans only those probes, leaves DIR and old key unchanged and no new key. Probe success is not a promise of actual swap success: final swap failure must also clean staged new key/tree with source intact.

Publish by ONE native atomic directory exchange between resolved DIR and complete staging. Successful return from this syscall is the COMMIT POINT. Before commit, handled errors remove only invocation-created staging/key (empty default store dirs may remain), exit 111, keep original DIR snapshot and old key unchanged. After commit, NEVER unlink the new key or exchange back on cleanup failure: active DIR references the new key. The staging path now holds OLD data; cleanup that old tree without following its key symlink. Make the old tree owner-writable/traversable before removal if necessary. Parent fsync and old-tree cleanup failures after commit yield exit 111 with explicit 'rotation completed' plus cleanup/durability caveat and safe residue path, no misleading rollback claim. On success exit 0, empty stdout, no staging/probes remain. Do not auto-delete an unrecognized old key or scan/purge prior runs.

SIGKILL/process interruption before exchange leaves original DIR usable plus optional staged new tree/key; after exchange leaves new DIR usable plus optional old tree. At neither point is active DIR absent or partially replaced. Document which artifacts may remain and that cleanup must first check active pointer before deleting ANY key/tree. This is process-interruption atomic namespace publication, NOT guaranteed power-loss durability, secure deletion, hostile concurrent filesystem mutation, ACL/xattr/ownership/inode preservation, or service credential rotation. Old key plus copies/backups/history still decrypt old ciphertext. Plaintext copies were already plaintext; recovered encrypted plaintext is never persisted/logged.

## Acceptance
- Isolated real CLI same-path rotation with printable+legacy encrypted binary/NUL/newline/empty/reserved-prefix values and plaintext; new get/run equal original values, new pub/pointer and ciphertext differ, old key remains unchanged and fails on new ciphertext. Preserve plaintext and DIR modes under umask 000/022/077; ciphertext/new key 0600, pub 0644. No permanent new envdir or caller cutover. symlink DIR remains symlink to updated target.
- Default/explicit -d, default XDG/home and explicit -k/-K stores, lazy old-key and plaintext-only/empty fixtures; --output/repeated -d/conflicting options exit 2 with zero writes; unsafe key/path, corrupt data and unsupported metadata fail 111 with invariant source.
- Native helper tests for Darwin/Linux ABI and errno/missing-symbol/unsupported-platform paths with mocks; real host successful exchange and real helper failure. No claim Linux end-to-end was run on macOS. Probes/final unsupported exchange fail without data change and remove owned artifacts.
- Deterministic injected failure at preflight, re-encryption verification, key creation, staging metadata/entry writes, probe, fsync, swap, post-commit parent fsync and cleanup. Assert BEFORE versus AFTER commit behavior, especially that post-commit failure retains new key and fully readable new DIR. Never catch an exception and remove the active key. Random encrypted-only sentinel write-interception and file scans retain existing coverage; test is not weakened to permit recovered plaintext.
- Real subprocess SIGKILL barrier immediately before and immediately after native swap; fresh independent CLI reads the active path with the matching pointer in BOTH cases. No missing-path window; restart requires no manual consumer switching. Explicit cwd-inside/root/mountpoint refusal and caller symlink tests.
- Tests and docs updated together: README.md, README.ja.md, tracked skills/envdirx/SKILL.md, tests/test_public_skill.py, help and canonical cli-workflow. Main help one-line rekey purpose 'rotate the encryption key'; remove --output grammar and manual mv cutover instructions, use direct rekey examples. Preserve all unrelated tests/requirements. Existing unittest full suite and strict/archive gates pass. No version bump: 0.2.0 currently local untagged; release policy is unchanged and release is out of scope.

## Required focused-review amendments (A1-A6)
- Commit detection MUST use staging's recorded `(st_dev, st_ino)` versus `os.lstat(resolved DIR)`, NOT a Python flag assigned after exchange. On BaseException immediately before/after syscall, determine filesystem commit first; preserve active new key after commit, clean owned new artifacts before commit. Convert handled KeyboardInterrupt into ValueError/exit 111 with stage-aware diagnostic. If commit cannot be determined, retain keys and both trees and report ambiguous state rather than deleting possibly active data. Add real exchange-wrapper KeyboardInterrupt pre/post tests.
- Dispatch on sys.platform darwin/linux; unsupported platform or missing libc symbol raises ValueError("atomic directory exchange is not supported on this platform/libc"). Nonzero native result raises OSError(errno, os.strerror(errno), a, None, b). Existing main maps to 111. README: Linux requires libc renameat2 wrapper and supporting filesystem; unavailable wrapper fails closed (do not claim all musl versions lack it).
- Keep --output hidden with argparse.SUPPRESS and detect presence (including empty supplied value), calling parser.error("--output was removed: rekey now rotates the key in place at DIR (use -d DIR)") before filesystem access; remove it from usage.
- Open staging dir O_RDONLY while 0700; stage plaintext via existing _create with stat.S_IMODE(original mode), ciphertext 0600. After writes fchmod(dirfd, original DIR mode), fsync(dirfd), close. After commit chmod old real tree 0700 before rmtree; propagate cleanup errors. Include DIR 0500/plaintext 0444 across all three umasks.
- Unsafe target: resolved DIR equals Path.anchor, os.path.ismount(DIR), or resolved cwd equals/is inside DIR; exit 111 before writes. Include all explicit negatives.
- Update Directory-oriented command grammar delta without losing existing scenarios; Rekey directory selection selects DIR, not SOURCE. Real SIGKILL barriers use tests-only _exchange wrapper before/after actual swap, no production test hooks.
Fable job 1cead7d5d387d98aff00ed434cfb78f1 (claude-fable-5-1) returned CONDITIONAL GO contingent on these exact safety/consistency repairs. All adopted; review is not implementation acceptance.

## Review basis
Fable diagnostic job 0606a0446dfb227f3aab846d54e76102 (claude-fable-5-1) confirmed wrong out-of-place semantics, recommended two renames with a missing-path crash window. That recommendation is NOT adopted: it conflicts with stable-path interruption safety. A direct local macOS synthetic spike verified native atomic exchange, stable symlink alias, old open-fd generation and source invariance on failed swap. This fixed proposal requires its own focused review before Conflux.

## Boundary
Source, tests, README pair, public skill and cli-workflow spec only; tests may add a small fixture/barrier helper under tests. No external publication, real-data rekey, services restart, .cflx.jsonc, unrelated refactoring or extra commands. After verified local merge, rebuild existing local tool from the same local source and run isolated synthetic installed-CLI smoke tests. Installation/readiness and real credential rotation are separate.
