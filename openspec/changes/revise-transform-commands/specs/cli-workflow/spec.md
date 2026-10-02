## ADDED Requirements

### Requirement: Explicit in-place transformation selection
Encrypt and decrypt SHALL require either one or more unique entry names or --all, mutually exclusive. Missing/combined/duplicate selectors SHALL fail parsing exit 2 before key/directory reads or writes. Encrypt SHALL convert plaintext to v1 ciphertext with regular public key only; decrypt SHALL restore authenticated exact plaintext bytes with validated external private key and optional --key override. Explicit target already in desired state SHALL fail 111; --all SHALL skip it. Dotfiles SHALL remain untouched. Empty/no-work batches SHALL succeed without key lookup. Unknown/malformed reserved envdirx: envelopes SHALL fail 111 in either operation. Decrypt SHALL reject restored reserved-prefix plaintext before writes, preserving ciphertext so run/get never misclassify restored files. Get remains available for those original bytes.

#### Scenario: Reversible selected values
- **WHEN** selected raw binary/newline/NUL/empty entries are encrypted then decrypted
- **THEN** original bytes return at 0600, unrelated entries/metadata are unchanged and stdout contains no values

#### Scenario: Explicit all and no-op
- **WHEN** --all selects a mixed or already-converted directory
- **THEN** only entries needing conversion change, and a no-work batch needs no key

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

## MODIFIED Requirements

### Requirement: Directory-oriented command grammar
CLI SHALL use global -d/--directory before subcommand with cwd-relative default ./.envs for mkdir, keygen, set, get, encrypt, decrypt and run. Run SHALL require -- before command, preserve child flags and DJB semantics and exit codes. Legacy init SHALL retain its explicit positional directory and existing behavior when no explicit global directory flag is supplied; explicit global -d with init SHALL fail exit 2 without writes. Positional directories for set/encrypt/run SHALL no longer be accepted as such.

#### Scenario: Default and explicit directories
- **WHEN** mkdir followed by plaintext set AAA, get AAA and run -- sh -c 'test -n "$AAA"' execute with default or explicit -d
- **THEN** only the selected envdir is used and child receives the value

#### Scenario: Child separator
- **WHEN** run lacks -- or command
- **THEN** it fails without starting a child

#### Scenario: Decrypt directory selection
- **WHEN** decrypt NAME executes with default or explicit -d
- **THEN** only the selected envdir entry is converted


### Requirement: Plaintext default and explicit encrypted entries
Set SHALL atomically save exact stdin bytes at 0600 without any key by default, except a reserved envdirx: prefix SHALL fail 111 before writing or overwriting any entry. -c SHALL encrypt using only regular .envdirx.pub. Existing entry/name protections SHALL remain; encrypt/decrypt SHALL follow Explicit in-place transformation selection and Preflight validation and individual atomic transformation. Get SHALL output original plaintext bytes, decrypt ciphertext using the same validated key rules as run, add no newline and apply no DJB transformation. Missing/invalid entry or ciphertext SHALL fail 111 with no stdout; values SHALL never be printed in diagnostics.

#### Scenario: Plaintext without keys
- **WHEN** binary stdin with newline, NUL or empty bytes is set without -c then get is invoked
- **THEN** stored and returned bytes match exactly without any key lookup

#### Scenario: Encrypted read failure
- **WHEN** encrypted get has corrupt/unsupported/wrong-name ciphertext or invalid private-key reference
- **THEN** it fails without plaintext stdout or diagnostic secret disclosure
