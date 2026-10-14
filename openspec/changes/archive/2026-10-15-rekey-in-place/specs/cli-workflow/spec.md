## MODIFIED Requirements

### Requirement: Directory-oriented command grammar
CLI SHALL use global -d/--directory before subcommand with cwd-relative default ./.envs for mkdir, keygen, set, get, encrypt, decrypt, rekey and run. Only get MAY repeat -d for ordered lookup. Run SHALL require -- before command, preserve child flags and DJB semantics and exit codes. Init SHALL NOT be a recognized subcommand, and SHALL fail parsing without writes. Positional directories for set/encrypt/run SHALL no longer be accepted as such.

#### Scenario: Default and explicit directories
- **WHEN** mkdir followed by plaintext set AAA, get AAA and run -- sh -c 'test -n "$AAA"' execute with default or explicit -d
- **THEN** only the selected envdir is used and child receives the value

#### Scenario: Child separator
- **WHEN** run lacks -- or command
- **THEN** it fails without starting a child

#### Scenario: Removed init
- **WHEN** init is requested
- **THEN** exit is 2 and no files are changed

#### Scenario: Decrypt directory selection
- **WHEN** decrypt NAME executes with default or explicit -d
- **THEN** only the selected envdir entry is converted

#### Scenario: Rekey directory selection
- **WHEN** rekey uses default or a single explicit -d, or repeats -d
- **THEN** default/single selects DIR and repeated -d fails parsing exit 2 without writes


### Requirement: Out-of-place verified key rotation
Despite the historical requirement title, rekey SHALL now rotate encryption keys IN PLACE at the existing resolved envdir path with `envdirx [-d DIR] rekey [--key OLDKEY] [-k/--new-key NEWKEYFILE | -K/--new-key-dir NEWKEYDIR]`. It SHALL NOT require a destination or manual consumer cutover. Legacy --output SHALL fail exit 2 with a migration explanation and no writes. Repeated -d and invalid/missing/conflicting parser options SHALL fail exit 2 without writes. New external private key SHALL be fresh, 0600, never overwrite existing files, and obey keygen default/explicit destination rules. Old external key SHALL remain unchanged and SHALL NOT be deleted. Plaintext entries SHALL preserve bytes/modes; encrypted values SHALL preserve decrypted bytes/names, use printable output and 0600. DIR permission bits SHALL be preserved, new public key 0644, new pointer an absolute symlink. Existing old-key lazy lookup, supported formats, metadata/name validation and no-public-key-needed rules SHALL remain. Caller symlink aliases SHALL remain intact by exchanging the resolved real path. Root, mountpoint and invocation cwd inside DIR SHALL be refused before writes. Existing handles/cwd into DIR, concurrent mutation, ACL/xattr/ownership/inode preservation and real credential rotation are outside the guarantee.

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
Rekey SHALL authenticate/preflight every entry and prepare/verify ciphertext in memory before new store/key/staging creation. It SHALL reject unsupported dotfiles except replaced .envdirx.pub/.envdirx.key. It SHALL use a complete private sibling staging tree and one native atomic directory exchange (Darwin renamex_np RENAME_SWAP, Linux renameat2 RENAME_EXCHANGE) as the commit point, NEVER a two-rename fallback. A two-private-directory native capability probe SHALL precede new-key creation; missing symbol/platform or unsupported filesystem fails closed. Staged files/directory SHALL be fsynced before exchange; failure SHALL preserve source. Before commit handled failure SHALL keep DIR and old key invariant, remove only invocation-owned staging/probes/key, exit 111 and empty stdout; empty newly created default-store directories may remain. Commit state SHALL be determined from the active directory inode versus the pre-exchange staging inode, never an in-process flag; ambiguous inspection SHALL retain potentially active artifacts and fail closed. Handled KeyboardInterrupt before/after exchange SHALL preserve the corresponding complete active tree and return exit 111. After commit cleanup or parent-fsync failure SHALL NEVER delete the new active key or swap back, SHALL retain fully readable new DIR and exit 111 with explicit completed-rotation caveat and safe residue path. Successful cleanup SHALL remove the exchanged old tree without following its key symlink; old external key SHALL remain. Process interruption before/after exchange SHALL leave a complete active DIR and matching key reference, never an absent path or mixed tree; staging/key or old-tree residue may remain. Recovery documentation SHALL require checking the active pointer before removing artifacts. Power-loss durability, secure erasure, concurrent hostile mutation and transparent success of readers spanning publication SHALL NOT be claimed. Existing reader fail-closed authentication/no partial stdout/no child exec guarantees SHALL remain. Decrypted encrypted values SHALL NOT reach disk/logs; copying existing plaintext remains permitted.

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
