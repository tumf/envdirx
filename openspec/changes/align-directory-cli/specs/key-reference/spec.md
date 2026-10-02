## MODIFIED Requirements

### Requirement: Fixed external private key reference
The CLI SHALL resolve `.envdirx.key` as a symlink target or a regular UTF-8 one-line file path, relative to envdir when relative. Leading ~/ SHALL expand only for text pointers. Explicit --key SHALL override the pointer and resolve relative to cwd for run/get. Run and get SHALL NOT guess an adjacent key when the pointer is absent. Plaintext-only reads/runs SHALL not require a key.

#### Scenario: Roundtrip from either pointer form
- **WHEN** a valid text or symlink pointer refers to an external private key and run executes a child
- **THEN** the child receives the decrypted values and its exit code is preserved

#### Scenario: Explicit override
- **WHEN** --key before run's -- separator or as get's option names a valid external key and the default pointer is missing or invalid, with envdir selected by global -d or default ./.envs
- **THEN** run/get uses the explicit key without reading the pointer

### Requirement: Fail closed key target validation
The resolved key SHALL be a regular file outside the resolved envdir, owned by effective uid and inaccessible to group/other. Invalid pointers, link cycles, malformed/wrong keys or insecure targets SHALL exit 111 without child execution or secret disclosure. The existing encrypted and plaintext envdir formats SHALL remain unchanged.

#### Scenario: Invalid reference or insecure key
- **WHEN** an encrypted run or get has an invalid reference or key target
- **THEN** exit is 111, run's child marker is absent and get's stdout is empty, and stderr contains no secret bytes


### Requirement: Init creates an external key pointer safely
Init SHALL remain a legacy command with its explicit positional DIRECTORY, with explicit global -d rejected before writes (exit 2). It SHALL create the public key, external private key (explicit destination or default adjacent DIRECTORY.key) and regular 0600 pointer containing a fully resolved absolute key path plus newline. Init SHALL refuse every preexisting key/public/pointer entry including dangling symlinks and reject destinations inside envdir. Failures SHALL not overwrite preexisting files and SHALL remove only newly created invocation artifacts.

#### Scenario: Fresh init
- **WHEN** legacy init completes for a new envdir
- **THEN** set -c followed by run with that envdir selected via global -d decrypts via the created pointer

#### Scenario: Collision preflight
- **WHEN** a pointer already exists including a dangling symlink
- **THEN** init fails before creating keys and preserves that entry
