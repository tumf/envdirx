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

### Requirement: Ordered get directory lookup
Get SHALL accept repeated global `-d/--directory` options before the subcommand and search them in argument order; absent entries are skipped and the first existing entry wins, including an empty file. With no `-d`, get SHALL use `./.envs`. The selected encrypted entry SHALL use its own directory's key pointer unless `--key` overrides it. Invalid names, missing or non-directory paths encountered during the search, nonregular or malformed entries, and decryption failure SHALL stop with exit 111 and empty stdout rather than falling back. If the name is absent everywhere, exit 111. Other subcommands SHALL reject repeated `-d` with exit 2 and no writes.

#### Scenario: Priority and failure
- **WHEN** get searches two envdirs and the first has no named entry
- **THEN** it returns the second entry's original bytes; if the first has an empty entry it returns zero bytes instead, and if the first has a malformed entry it fails without consulting the second

### Requirement: Clean input interruption
While `set` or `set -c` reads stdin, Ctrl-C SHALL exit 130 without a traceback or writing the entry.

#### Scenario: Cancel entry input
- **WHEN** stdin reading is interrupted before EOF
- **THEN** the command exits 130, writes no entry, and emits no traceback

### Requirement: Closed or broken standard streams
When `set` runs with a closed stdin, or `get` runs with a closed stdout, the command SHALL exit 111 with an `envdirx:` diagnostic and no traceback, writing no entry. When `get` hits a broken stdout pipe, it SHALL exit 111 with the `envdirx:` diagnostic only; the interpreter's exit-time stdout flush SHALL NOT turn that into status 120 or an "Exception ignored" message.

#### Scenario: Closed streams
- **WHEN** `set NAME <&-` or `get NAME >&-` runs
- **THEN** exit is 111, stderr holds one `envdirx:` line, no entry is written and no traceback appears

#### Scenario: Reader gone before get writes
- **WHEN** get writes to a pipe whose reader has already exited
- **THEN** exit is 111 and stderr holds only the broken-pipe diagnostic

### Requirement: Safe external key generation
Keygen SHALL accept mutually exclusive optional -k/--key filename or -K/--key-dir existing directory, no force flag, no overwrite. When neither destination is specified, it SHALL use nonempty absolute XDG_DATA_HOME plus envdirx/keys, otherwise HOME/.local/share/envdirx/keys; unset, empty and relative XDG_DATA_HOME SHALL use the HOME fallback. Literal ~ in XDG_DATA_HOME SHALL NOT be expanded. Only this implicit default SHALL lazily create missing directories at 0700 regardless of umask, leaving existing modes unchanged. Explicit -K SHALL require an existing directory. The implicit resolved destination SHALL be validated as outside resolved envdir before directory creation, including symlink aliases and descendants; missing envdir, existing public/pointer, invalid path, non-directory, dangling/cyclic links and filesystem errors SHALL fail 111 without new key/public/pointer artifacts. Existing data SHALL remain unchanged. Newly created empty default directories MAY remain after a subsequent key write failure. Directory destinations SHALL name the key SHA256(raw public key) as full lowercase hex plus .key. Keygen SHALL write external private key 0600, regular public key 0644 and absolute-target .envdirx.key symlink, preflight all collisions including dangling links, reject resolved in-envdir key destinations and cleanup only newly created key/public/pointer artifacts on failure. Explicit -k/-K SHALL ignore the default location, and reads SHALL continue to require the selected envdir pointer or --key without scanning or migrating the key store.

#### Scenario: Generate and use keys
- **WHEN** keygen succeeds with either explicit destination form or the implicit default then set -c SECRET and get/run execute
- **THEN** real values decrypt and fingerprint/link/permissions meet the contract

#### Scenario: Existing files or unsafe destinations
- **WHEN** key/public/pointer already exists or destination is unsafe or -f is supplied
- **THEN** no existing data is overwritten and no partial new key/public/pointer artifacts remain

#### Scenario: Default location and creation
- **WHEN** keygen omits -k and -K in an isolated home with unset, empty or relative XDG_DATA_HOME, or with an absolute XDG_DATA_HOME
- **THEN** it creates missing default directories at 0700 under HOME/.local/share or the absolute XDG data root respectively, and stores the fingerprint-named key without modifying existing directory modes

#### Scenario: Overrides and stable pointers
- **WHEN** keygen specifies -k or -K, or an existing encrypted envdir is read after XDG_DATA_HOME changes
- **THEN** only the explicit destination is used for generation, and existing reads use their pointer without consulting or creating a default store

### Requirement: Plaintext default and explicit encrypted entries
New ciphertext SHALL be one printable ASCII line `encrypted:B` followed by standard padded Base64 of the existing v1 binary payload (ephemeral public key, nonce, authenticated ciphertext), terminated by exactly one LF. Readers SHALL accept no trailing LF for backward compatibility but SHALL reject embedded LF, repeated LF and CRLF. The entry name remains the envdir filename, not a `NAME=` prefix in the file. Readers SHALL also accept existing binary `envdirx:v1:\n` ciphertext without rewriting it; `encrypt --all` SHALL skip both forms. Neither form is dotenvx-compatible. Malformed `encrypted:` values SHALL fail closed without exposing the value or changing files. Both `envdirx:` and `encrypted:` prefixes SHALL be reserved for plaintext writes and restored plaintext.

#### Scenario: Printable storage and legacy read
- **WHEN** `set -c NAME` or `encrypt NAME` writes a value, or an existing binary v1 entry is read via `get`, `run` or `decrypt`
- **THEN** new files contain `encrypted:B` plus valid Base64 text, existing ciphertext remains readable, and each result preserves the original value

Set SHALL atomically save exact stdin bytes at 0600 without any key by default, except reserved `envdirx:` or `encrypted:` prefixes SHALL fail 111 before writing or overwriting any entry. -c SHALL encrypt using only regular .envdirx.pub. Existing entry/name protections SHALL remain; encrypt/decrypt SHALL follow Explicit in-place transformation selection and Preflight validation and individual atomic transformation. Get SHALL output original plaintext bytes, decrypt ciphertext using the same validated key rules as run, add no newline and apply no DJB transformation. Missing/invalid entry or ciphertext SHALL fail 111 with no stdout; values SHALL never be printed in diagnostics.

#### Scenario: Plaintext without keys
- **WHEN** binary stdin with newline, NUL or empty bytes is set without -c then get is invoked
- **THEN** stored and returned bytes match exactly without any key lookup

#### Scenario: Encrypted read failure
- **WHEN** encrypted get has corrupt/unsupported/wrong-name ciphertext or invalid private-key reference
- **THEN** it fails without plaintext stdout or diagnostic secret disclosure

### Requirement: Explicit in-place transformation selection
Raw NAME arguments SHALL pass existing set/get name validation before path construction; invalid path traversal or dot metadata names SHALL fail 111 with no writes. Explicit names SHALL retain argument order.
Encrypt and decrypt SHALL require either one or more unique entry names or --all, mutually exclusive. Missing/combined/duplicate selectors SHALL fail parsing exit 2 before key/directory reads or writes. Encrypt SHALL convert plaintext to v1 ciphertext with regular public key only; decrypt SHALL restore authenticated exact plaintext bytes with validated external private key and optional --key override. Explicit target already in desired state SHALL fail 111; --all SHALL skip it. Dotfiles SHALL remain untouched. Empty/no-work batches SHALL succeed without key lookup. Unknown/malformed reserved `envdirx:` or `encrypted:` envelopes SHALL fail 111 in either operation. Decrypt SHALL reject restored reserved-prefix plaintext before writes, preserving ciphertext so run/get never misclassify restored files. Get remains available for those original bytes.

#### Scenario: Reversible selected values
- **WHEN** selected raw binary/newline/NUL/empty entries are encrypted then decrypted
- **THEN** original bytes return at 0600, unrelated entries/metadata are unchanged and stdout contains no values

#### Scenario: Explicit all and no-op
- **WHEN** --all selects a mixed or already-converted directory
- **THEN** only entries needing conversion change, and a no-work batch needs no key

#### Scenario: Unsafe raw names
- **WHEN** ../X, an absolute path, .envdirx.pub or .envdirx.key is supplied to encrypt/decrypt
- **THEN** exit is 111 and every envdir and external file remains unchanged

#### Scenario: Invalid selection
- **WHEN** no targets, duplicate names or --all with names are provided
- **THEN** exit is 2 and files are unchanged

### Requirement: Preflight validation and individual atomic transformation
Both transformations SHALL validate/read/prepare the entire selected batch before replacing any file. Missing/nonregular entry, unsupported envelope, invalid key, authentication failure or reserved restored prefix SHALL fail 111 with all files unchanged and no stdout/secrets in diagnostics. Each resulting entry SHALL be atomically replaced at 0600. A subsequent write failure MAY leave previous successful replacements committed; it SHALL fail 111 and preserve the failed target, with no claim of whole-batch transactionality.

#### Scenario: Late validation failure
- **WHEN** valid A sorts before corrupt Z in a decrypt --all batch
- **THEN** neither A nor Z changes and no secret is output

#### Scenario: Reserved original plaintext
- **WHEN** a valid ciphertext decrypts to bytes starting envdirx:
- **THEN** decrypt fails 111 before any replacement and get still returns the original bytes

#### Scenario: Write failure
- **WHEN** a validated multi-entry batch fails during its second atomic replacement
- **THEN** first replacement remains, second target remains unchanged and exit is 111

### Requirement: Package version reporting
The CLI SHALL accept global `--version` and `-V` without a subcommand and SHALL write exactly the installed envdirx distribution version plus one LF to stdout, with empty stderr and exit status 0. The version SHALL be read using standard-library `importlib.metadata.version("envdirx")`; runtime code SHALL NOT duplicate the version string, read a source checkout's pyproject.toml, or invent a fallback. `pyproject.toml` project.version SHALL remain the sole release-version source, initially 0.1.0. Version reporting SHALL require no envdir or key, SHALL NOT read or write envdir entries, and SHALL work from unrelated working directories, including with `-d` naming a nonexistent directory before the version flag. `--help` SHALL list both flags and explain that the global flags precede a subcommand; `run --version` without the child separator is invalid. `run -- COMMAND --version` SHALL preserve the child command's version argument. English and Japanese READMEs SHALL document both version flags and a manual release policy: semantic MAJOR.MINOR.PATCH versions, bump via `uv version <version>` (synchronizing pyproject.toml and uv.lock), commit after verification and tag as `v<version>`; tag/push/package publication are separate operator actions. Before 1.0, incompatible CLI changes SHALL increment MINOR and compatible additions/fixes SHALL increment PATCH.

#### Scenario: Version without envdir
- **WHEN** either version flag runs in an unrelated empty directory, with the default directory or an explicit nonexistent -d directory
- **THEN** stdout is the installed package version and one LF, stderr is empty, exit is 0 and no files are created

#### Scenario: Distribution and project consistency
- **WHEN** envdirx is installed from a built wheel into an isolated environment and run outside the checkout through both the console script and python -m envdirx
- **THEN** version output matches that distribution's metadata and the version declared in pyproject.toml

#### Scenario: Version is not a child flag interceptor
- **WHEN** run -- executes a child with its own --version argument
- **THEN** the child receives --version unchanged

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
