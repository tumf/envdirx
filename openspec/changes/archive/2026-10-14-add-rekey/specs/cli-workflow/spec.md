## ADDED Requirements

### Requirement: Out-of-place verified key rotation
CLI SHALL implement `envdirx [-d SOURCE] rekey --output DEST [--key OLDKEY] [-k/--new-key NEWKEYFILE | -K/--new-key-dir NEWKEYDIR]` under the existing directory/exit-code rules. It SHALL create a fresh X25519 key and complete new envdir without modifying SOURCE or the old key. DEST SHALL be absent with existing resolved parent and nonoverlapping with resolved SOURCE. New key SHALL be external to SOURCE and DEST and obey keygen destination/default-store, mode and no-overwrite rules. SOURCE public key is not needed; OLDKEY or the source pointer is used only if encrypted entries exist. Repeated -d and invalid/missing/conflicting parser options SHALL fail exit 2 without writes.

#### Scenario: Lossless rotation and retained source
- **WHEN** rekey rotates a mixed fixture with printable/legacy encrypted binary, empty and reserved-prefix values and plaintext entries
- **THEN** encrypted values are re-encrypted under a different fresh key in printable format, plaintext entries are preserved exactly, new get/run work, old source/key remain usable and unchanged, private key/entries are 0600, public key 0644, directory 0700 and pointer is an absolute symlink; exit 0 and stdout empty

#### Scenario: Old-key override and empty input
- **WHEN** source public key is absent and OLDKEY overrides an absent source pointer, or source contains only plaintext/no entries
- **THEN** encrypted input uses OLDKEY and plaintext-only/empty input needs no old key, while all cases produce a fresh external key and complete new envdir

### Requirement: Fail-closed rekey preparation and publication
Rekey SHALL preflight all visible regular valid-name entries and authenticate every ciphertext before creating even default-store directories, the new key or staging artifacts. Unsupported metadata dotfiles other than .envdirx.pub/.envdirx.key SHALL be rejected. It SHALL transform ciphertext in memory, verify re-encrypted bytes with the new private key, stage a complete envdir in a private sibling directory and publish only after all writes succeed. Staging SHALL be chmod 0700 regardless of umask. Publication SHALL use one os.rename after an lstat absence re-check; DEST basename SHALL not be empty, `.` or `..`. Rename failure SHALL clean invocation-created staging/key and exit 111. No-clobber SHALL apply only under the existing no-concurrent-mutation ceiling. Source public/pointer metadata SHALL be ignored by name without type checking except that the pointer is read when ciphertext exists without OLDKEY. OLDKEY SHALL not be resolved/validated if no ciphertext exists. --key OLDKEY and --output SHALL have no short aliases; -k/--new-key and -K/--new-key-dir SHALL be mutually exclusive. Decrypted ciphertext plaintext SHALL NOT be written to disk or diagnostics; copied existing plaintext is explicitly allowed. Handled failures SHALL exit 111 with empty stdout, preserve SOURCE/old key/all preexisting unrelated data, leave DEST absent and remove only newly created staging/key artifacts (new empty default-store directories may remain). Abrupt crash may leave staging/new key artifacts but SHALL not mutate SOURCE or old key; no concurrent hostile filesystem mutation guarantee is introduced.

#### Scenario: Validation refusal before writes
- **WHEN** any ciphertext is malformed, unsupported, bound to a wrong name or fails authentication, an entry/name/metadata is invalid, DEST exists including a dangling symlink, paths overlap or a new key destination is unsafe/colliding
- **THEN** exit 111 without secret stdout/diagnostics, SOURCE and existing keys/files unchanged, no new published envdir or key

#### Scenario: Late staging or publication failure
- **WHEN** staging metadata/entry/key writes, verification or publication fails, including after an earlier entry was staged
- **THEN** no partial DEST is published, newly created key/staging artifacts are removed, and SOURCE/old key remain usable with no recovered ciphertext plaintext written to disk

#### Scenario: Retention and operational cutover
- **WHEN** rekey succeeds
- **THEN** no consumer path is switched, old key is not deleted, docs require verifying DEST before operator cutover and state that leaked keys plus retained old ciphertext require service-credential rotation


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
- **THEN** default/single selects SOURCE and repeated -d fails parsing exit 2 without writes
