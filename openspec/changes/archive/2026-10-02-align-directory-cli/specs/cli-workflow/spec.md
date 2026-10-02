## ADDED Requirements

### Requirement: Directory-oriented command grammar
CLI SHALL use global -d/--directory before subcommand with cwd-relative default ./.envs for mkdir, keygen, set, get, encrypt and run. Run SHALL require -- before command, preserve child flags and DJB semantics and exit codes. Legacy init SHALL retain its explicit positional directory and existing behavior when no explicit global directory flag is supplied; explicit global -d with init SHALL fail exit 2 without writes. Positional directories for set/encrypt/run SHALL no longer be accepted as such.

#### Scenario: Default and explicit directories
- **WHEN** mkdir followed by plaintext set AAA, get AAA and run -- sh -c 'test -n "$AAA"' execute with default or explicit -d
- **THEN** only the selected envdir is used and child receives the value

#### Scenario: Child separator
- **WHEN** run lacks -- or command
- **THEN** it fails without starting a child

### Requirement: Safe external key generation
Keygen SHALL require exactly one of -k/--key filename or -K/--key-dir existing directory, no force flag, no overwrite. -K SHALL name key SHA256(raw public key) as full lowercase hex plus .key. It SHALL write external private key 0600, regular public key 0644 and absolute-target .envdirx.key symlink, preflight all collisions including dangling links, reject resolved in-envdir key destinations and cleanup only newly created artifacts on failure.

#### Scenario: Generate and use keys
- **WHEN** keygen succeeds with either destination form then set -c SECRET and get/run execute
- **THEN** real values decrypt and fingerprint/link/permissions meet the contract

#### Scenario: Existing files or unsafe destinations
- **WHEN** key/public/pointer already exists or destination is unsafe or -f is supplied
- **THEN** no existing data is overwritten and no partial new artifacts remain

### Requirement: Plaintext default and explicit encrypted entries
Set SHALL atomically save exact stdin bytes at 0600 without any key by default, except a reserved envdirx: prefix SHALL fail 111 before writing or overwriting any entry. -c SHALL encrypt using only regular .envdirx.pub. Existing entry/name protections and encrypt behavior SHALL remain. Get SHALL output original plaintext bytes, decrypt ciphertext using the same validated key rules as run, add no newline and apply no DJB transformation. Missing/invalid entry or ciphertext SHALL fail 111 with no stdout; values SHALL never be printed in diagnostics.

#### Scenario: Plaintext without keys
- **WHEN** binary stdin with newline, NUL or empty bytes is set without -c then get is invoked
- **THEN** stored and returned bytes match exactly without any key lookup

#### Scenario: Encrypted read failure
- **WHEN** encrypted get has corrupt/unsupported/wrong-name ciphertext or invalid private-key reference
- **THEN** it fails without plaintext stdout or diagnostic secret disclosure
