### Requirement: Directory-oriented command grammar
CLI SHALL use global -d/--directory before subcommand with cwd-relative default ./.envs for mkdir, keygen, set, get, encrypt, decrypt and run. Run SHALL require -- before command, preserve child flags and DJB semantics and exit codes. Init SHALL NOT be a recognized subcommand, and SHALL fail parsing without writes. Positional directories for set/encrypt/run SHALL no longer be accepted as such.

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

### Requirement: Safe external key generation
Keygen SHALL require exactly one of -k/--key filename or -K/--key-dir existing directory, no force flag, no overwrite. -K SHALL name key SHA256(raw public key) as full lowercase hex plus .key. It SHALL write external private key 0600, regular public key 0644 and absolute-target .envdirx.key symlink, preflight all collisions including dangling links, reject resolved in-envdir key destinations and cleanup only newly created artifacts on failure.

#### Scenario: Generate and use keys
- **WHEN** keygen succeeds with either destination form then set -c SECRET and get/run execute
- **THEN** real values decrypt and fingerprint/link/permissions meet the contract

#### Scenario: Existing files or unsafe destinations
- **WHEN** key/public/pointer already exists or destination is unsafe or -f is supplied
- **THEN** no existing data is overwritten and no partial new artifacts remain

### Requirement: Plaintext default and explicit encrypted entries
Set SHALL atomically save exact stdin bytes at 0600 without any key by default, except a reserved envdirx: prefix SHALL fail 111 before writing or overwriting any entry. -c SHALL encrypt using only regular .envdirx.pub. Existing entry/name protections SHALL remain; encrypt/decrypt SHALL follow Explicit in-place transformation selection and Preflight validation and individual atomic transformation. Get SHALL output original plaintext bytes, decrypt ciphertext using the same validated key rules as run, add no newline and apply no DJB transformation. Missing/invalid entry or ciphertext SHALL fail 111 with no stdout; values SHALL never be printed in diagnostics.

#### Scenario: Plaintext without keys
- **WHEN** binary stdin with newline, NUL or empty bytes is set without -c then get is invoked
- **THEN** stored and returned bytes match exactly without any key lookup

#### Scenario: Encrypted read failure
- **WHEN** encrypted get has corrupt/unsupported/wrong-name ciphertext or invalid private-key reference
- **THEN** it fails without plaintext stdout or diagnostic secret disclosure

### Requirement: Explicit in-place transformation selection
Raw NAME arguments SHALL pass existing set/get name validation before path construction; invalid path traversal or dot metadata names SHALL fail 111 with no writes. Explicit names SHALL retain argument order.
Encrypt and decrypt SHALL require either one or more unique entry names or --all, mutually exclusive. Missing/combined/duplicate selectors SHALL fail parsing exit 2 before key/directory reads or writes. Encrypt SHALL convert plaintext to v1 ciphertext with regular public key only; decrypt SHALL restore authenticated exact plaintext bytes with validated external private key and optional --key override. Explicit target already in desired state SHALL fail 111; --all SHALL skip it. Dotfiles SHALL remain untouched. Empty/no-work batches SHALL succeed without key lookup. Unknown/malformed reserved envdirx: envelopes SHALL fail 111 in either operation. Decrypt SHALL reject restored reserved-prefix plaintext before writes, preserving ciphertext so run/get never misclassify restored files. Get remains available for those original bytes.

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
