## ADDED Requirements

### Requirement: Cooperating CLI writer exclusion

On supported local POSIX filesystems, `keygen`, `set` including `-c`, `encrypt`, `decrypt`, and `rekey` SHALL acquire one exclusive nonblocking `fcntl.flock` on an open FD for the strictly resolved envdir's parent directory before reading stdin or entries/keys and SHALL hold it through all mutation and cleanup. The selected envdir SHALL be resolved once for the guarded operation. The FD SHALL be non-inheritable and closed on every exit; no lock file, PID lease, chmod or lock-related filesystem artifacts SHALL be created. Contention SHALL fail promptly with exit 111, empty stdout, a sanitized busy/retry diagnostic, and no mutation; other parent-open or locking failure SHALL fail closed with exit 111 and no mutation, never retry unlocked. Same-parent sibling envdirs intentionally SHALL contend, whereas different resolved parents SHALL be independent. Relative paths and symlink aliases SHALL address the same real parent inode. The parent inode, unlike the exchanged child envdir inode, SHALL remain the lock identity across publication. Help, version, get, run and mkdir SHALL remain outside writer locking. Parser validation remains prior to lock acquisition. SIGTERM/SIGKILL release the lock through OS descriptor closure, and handled errors/interruptions SHALL close it. This guarantee covers only cooperating upgraded writers on supported local filesystems; old binaries and external editors must be quiesced separately, and hostile parent replacement, distributed locks, reader consistency across exchange, automatic garbage collection and power-loss durability are not guaranteed. Opening the parent for locking requires read/search permission; unavailable permissions SHALL not weaken exclusion.

#### Scenario: Rekey excludes competing writers across publication
- **WHEN** one CLI rekey is paused just before the final exchange or just after exchange before cleanup completes, and another rekey/keygen/set/encrypt/decrypt selects the same real envdir through a direct, relative or symlink path
- **THEN** the contender exits 111 promptly with the busy diagnostic and empty stdout and creates/modifies no envdir entries, keys, default-store or staging paths; the original invocation completes without losing any successful write

#### Scenario: Existing writer excludes rotation
- **WHEN** set/keygen/encrypt/decrypt holds the writer lock through its input/read/write boundary and a rekey begins
- **THEN** rekey refuses busy without key/staging artifacts; after the writer finishes, a retried rekey retains that writer's successful result

#### Scenario: Retry after normal release
- **WHEN** rotation finishes and a previously refused plaintext or encrypted set retries against the current envdir
- **THEN** the new or updated entry is retained and get returns its exact expected value using the current key metadata

#### Scenario: Error and signal release
- **WHEN** a guarded command exits normally, fails validation or filesystem I/O, is interrupted by Ctrl-C, or is killed with SIGTERM/SIGKILL
- **THEN** exclusion is released and a fresh command can acquire it without deleting artifacts; the prior mutation's documented pre/post-commit data-retention contract and old-key retention remain unchanged

#### Scenario: Coarse scope and read-only access
- **WHEN** a writer holds one parent lock and another command addresses a sibling envdir, an envdir in another parent, or performs get/run/help/version
- **THEN** sibling mutation refuses busy, independent-parent mutation can proceed, read-only paths do not take writer locks, and no persistent locking artifacts appear

#### Scenario: Parent lock error
- **WHEN** parent open or flock is unsupported or fails
- **THEN** the mutation exits 111 without consuming stdin or writing any entry/key/staging artifact, and does not continue unlocked

## MODIFIED Requirements

### Requirement: Out-of-place verified key rotation
Despite the historical requirement title, rekey SHALL now rotate encryption keys IN PLACE at the existing resolved envdir path with `envdirx [-d DIR] rekey [--key OLDKEY] [-k/--new-key NEWKEYFILE | -K/--new-key-dir NEWKEYDIR]`. It SHALL NOT require a destination or manual consumer cutover. Legacy --output SHALL fail exit 2 with a migration explanation and no writes. Repeated -d and invalid/missing/conflicting parser options SHALL fail exit 2 without writes. New external private key SHALL be fresh, 0600, never overwrite existing files, and obey keygen default/explicit destination rules. Old external key SHALL remain unchanged and SHALL NOT be deleted. Plaintext entries SHALL preserve bytes/modes; encrypted values SHALL preserve decrypted bytes/names, use printable output and 0600. DIR permission bits SHALL be preserved, new public key 0644, new pointer an absolute symlink. Existing old-key lazy lookup, supported formats, metadata/name validation and no-public-key-needed rules SHALL remain. Caller symlink aliases SHALL remain intact by exchanging the resolved real path. Root, mountpoint and invocation cwd inside DIR SHALL be refused before writes. Cooperating upgraded CLI writers SHALL obey Requirement: Cooperating CLI writer exclusion. Existing handles/cwd into DIR, mutation by old binaries or direct editors, ACL/xattr/ownership/inode preservation and real credential rotation are outside the guarantee.

#### Scenario: Lossless rotation and retained source
- **WHEN** rekey rotates a mixed isolated fixture with printable/legacy encrypted binary, empty and reserved-prefix values and plaintext entries
- **THEN** the SAME path contains the fully rotated envdir, values and plaintext modes match, directory mode is preserved across umasks, metadata/new key change, old key remains unmodified but cannot decrypt new ciphertext, get/run succeed and no manual cutover or permanent destination is created; exit 0 and empty stdout

#### Scenario: Old-key override and empty input
- **WHEN** source public key is absent and OLDKEY overrides an absent source pointer, or source contains only plaintext/no entries
- **THEN** ciphertext uses OLDKEY and plaintext-only/empty input needs no old key, and all cases produce a fresh external key at the existing envdir path

#### Scenario: Caller paths and removed output syntax
- **WHEN** DIR is a valid symlink alias, or legacy --output/repeated -d is passed, or root/mountpoint/cwd-inside is selected
- **THEN** valid aliases survive and point at updated content; parser cases exit 2 and unsafe rotation targets exit 111 without writes

### Requirement: Fail-closed rekey preparation and publication
Rekey SHALL hold the shared CLI writer lock before authenticating/preflighting every entry and through all pre/post-publication cleanup. Rekey SHALL authenticate/preflight every entry and prepare/verify ciphertext in memory before new store/key/staging creation. It SHALL reject unsupported dotfiles except replaced .envdirx.pub/.envdirx.key. It SHALL use a complete private sibling staging tree and one native atomic directory exchange (Darwin renamex_np RENAME_SWAP, Linux renameat2 RENAME_EXCHANGE) as the commit point, NEVER a two-rename fallback. A two-private-directory native capability probe SHALL precede new-key creation; missing symbol/platform or unsupported filesystem fails closed. Staged files/directory SHALL be fsynced before exchange; failure SHALL preserve source. Before commit handled failure SHALL keep DIR and old key invariant, remove only invocation-owned staging/probes/key, exit 111 and empty stdout; empty newly created default-store directories may remain. Commit state SHALL be determined from the active directory inode versus the pre-exchange staging inode, never an in-process flag; ambiguous inspection SHALL retain potentially active artifacts and fail closed. Handled KeyboardInterrupt before/after exchange SHALL preserve the corresponding complete active tree and return exit 111. After commit cleanup or parent-fsync failure SHALL NEVER delete the new active key or swap back, SHALL retain fully readable new DIR and exit 111 with explicit completed-rotation caveat and safe residue path. Successful cleanup SHALL remove the exchanged old tree without following its key symlink; old external key SHALL remain. Process interruption before/after exchange SHALL leave a complete active DIR and matching key reference, never an absent path or mixed tree; staging/key or old-tree residue may remain. OS lock release on process exit SHALL permit a subsequent CLI write/rekey without deleting lock records or staging residue. Recovery documentation SHALL distinguish this admission recovery from automatic residue cleanup (not implemented) and require checking the active pointer before removing artifacts. Power-loss durability, secure erasure, concurrent hostile mutation and transparent success of readers spanning publication SHALL NOT be claimed. Existing reader fail-closed authentication/no partial stdout/no child exec guarantees SHALL remain. Decrypted encrypted values SHALL NOT reach disk/logs; copying existing plaintext remains permitted.

#### Scenario: Validation refusal before writes
- **WHEN** ciphertext/key/name/metadata/path is invalid, new key destination is unsafe/colliding or exchange support/probe fails
- **THEN** exit 111 without secret diagnostics/stdout, source and old key unchanged and no new published envdir/key or owned probe remains

#### Scenario: Late staging or publication failure
- **WHEN** preparation/staging/fsync/final exchange fails before commit, or parent fsync/old-tree cleanup fails after commit
- **THEN** pre-commit failure leaves source invariant and removes owned artifacts; post-commit failure retains readable rotated DIR/new key and explicitly reports completed rotation plus cleanup/durability failure, without claiming rollback

#### Scenario: Retention and operational cutover
- **WHEN** rekey succeeds or a subprocess is killed at a deterministic barrier immediately before/after exchange
- **THEN** fresh readers use the same active path with a complete matching key/tree, old key is not deleted, no manual consumer cutover is required, residual cleanup is documented and leaked old key plus retained ciphertext still requires service-credential rotation

#### Scenario: Secret-write and platform boundaries
- **WHEN** isolated success/failure fixtures intercept filesystem writes and scan random encrypted-only sentinels, and helper ABI/error tests exercise Darwin/Linux interfaces
- **THEN** no recovered encrypted plaintext appears on disk/logs, the host native exchange runs for real, unsupported cases fail closed and mocked Linux ABI checks are not represented as Linux runtime acceptance
