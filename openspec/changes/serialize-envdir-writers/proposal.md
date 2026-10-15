---
change_type: implementation
priority: high
dependencies: []
verifications:
  - id: writer-safety
    requirement: Cooperating writers cannot overlap rotation and process termination preserves the active generation and releases exclusion
    phase: pre-integration
    owner: conflux-acceptance
    trigger: change-acceptance
    automation: tests/test_envdirx.py
    evidence: uv run python -m unittest discover -s tests -v
    rerun: uv run python -m unittest discover -s tests -v
    prerequisites: []
    execution_class: repository-local
    completion_role: change-blocking
---
# Serialize envdir writers across in-place rotation

**Change Type**: implementation

## Context / observed defect

Current main 8e64975 publishes rekey through a native atomic directory exchange, but takes no interprocess lock. Two rekeys can succeed concurrently. A successful set between rekey's read and exchange is discarded by the stale staged tree. Existing pre/post-commit failure handling preserves one active generation, not concurrent writes. The requested artifact is implementation, tests and synchronized documentation, not another review-only report.

## Fixed approach

Use standard-library `fcntl.flock(LOCK_EX | LOCK_NB)` on an open FD for the resolved envdir's **parent directory**, before any mutable command reads entries/keys or consumes set input. Keep it through the complete command, including rollback/retirement. Same-version cooperating `keygen`, `set` (both modes), `encrypt`, `decrypt`, and `rekey` use one shared context manager in `main`. Pass the resolved envdir path into the guarded operation. No persistent lock file, PID record, migration, new dependency, wait loop or new option. Failure to open/lock the directory fails closed (111, empty stdout); contention emits a clear busy/retry diagnostic. Different envdirs in the same parent intentionally contend. Separate parents remain independent.

This coarse parent-inode lock is stable across the existing child-directory exchange and handles relative/symlink aliases. On this macOS host a disposable real-process/native-exchange spike verified alias contention across exchange, an unrelated parent proceeding, SIGKILL release, and zero lock artifacts. That spike is approach evidence, not product acceptance or Linux runtime evidence. Linux/macOS local filesystems with directory flock support are the target; filesystems rejecting flock fail closed; filesystems accepting only client-local locks without cross-host exclusion (e.g. NFS configurations) are outside the guarantee.

## Acceptance criteria

1. All five mutating command families are admitted by the same lock before metadata/entry snapshots and are held through final mutation/cleanup; rekey cannot lose a successful cooperating write.
2. A contender at a paused pre-exchange OR post-exchange rekey barrier fails promptly with 111, empty stdout, sanitized busy diagnostic, and no key/store/staging/envdir changes. Direct, relative, directory alias and parent alias access share exclusion.
3. Normal release, validation/I/O/KeyboardInterrupt failure, SIGTERM and SIGKILL release exclusion. Fresh get/run can read the complete corresponding generation after rekey dies; subsequent set/rekey can succeed without deleting lock artifacts or leftover trees. Before exchange original ciphertext/key are unchanged; after it the new active key remains and there is no rollback to an older generation. Old private keys remain unchanged.
4. A writer admitted after successful rekey uses current metadata, preserves a newly created entry and updated value, and `set -c` remains decryptable. Read-only help/version/get/run are not locked and create no locking artifacts; existing reader fail-closed ceiling during exchange remains unchanged.
5. Same-parent sibling envdirs contend; different parents do not. Parent open/flock errors fail closed without file mutation. Existing bytes/modes/crypto/parser/exit contracts are preserved except the documented 111 busy result, resolved-path diagnostics, and the need for parent read/search permission (search-only 0711/0311 parents may now fail 111).
6. English/Japanese READMEs, CLI help, tracked skill and canonical OpenSpec describe exclusion scope, retry, parent read/search permissions, old-writer upgrade requirement, crash/residue boundaries without claiming power-loss safety or automatic residue removal. Full repository tests and strict/archive validation pass.

## Boundary and completion

Allowed product files: `src/envdirx/__init__.py`, `tests/test_envdirx.py` (a single focused test helper/file only if needed), `README.md`, `README.ja.md`, `skills/envdirx/SKILL.md`, and this change's/canonical cli-workflow specs. No package version change or new dependency. Implement and test actual CLI admission; docs or mocked flock calls alone cannot complete the change. Tests use bounded subprocess barriers and synthetic HOME/XDG stores only. The gate remains at tracked stable paths after archive. There is no tracked unconditional whole-repo commit hook; the full existing unittest suite remains an explicit acceptance command.

## Split rationale

Lock admission, all writer wiring, and crash-release tests must ship together: guarding only rekey still permits lost set/transform writes. They are one safety change. Destructive residue recovery is independent and explicitly excluded.

## Out of scope

Automatic deletion/adoption of abandoned staging or keys, recovery journals, post-commit rollback, power-loss durability, distributed/NFS locks, hostile filesystem/path mutation, old binaries/direct shell editors, reader snapshot locking, unrelated exception-audit edits, publishing/push/release, or real credentials. Existing `mkdir` creates no entries in an existing envdir and is unchanged. Stop old-version writers before first use; only upgraded cooperating writers are protected. Parent performs normal local installation and isolated installed-CLI verification after integration, not inside Apply.
