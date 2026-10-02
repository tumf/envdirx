## MODIFIED Requirements

### Requirement: Fixed external private key reference
The CLI SHALL resolve `.envdirx.key` as a symlink target or a regular UTF-8 one-line file path, relative to envdir when relative. Leading ~/ SHALL expand only for text pointers. Explicit --key SHALL override the pointer and resolve relative to cwd for run/get/decrypt. Run, get and decrypt SHALL NOT guess an adjacent key when the pointer is absent. Plaintext-only reads/runs and no-work decrypt batches SHALL not require a key.

#### Scenario: Roundtrip from either pointer form
- **WHEN** a valid text or symlink pointer refers to an external private key and run executes a child
- **THEN** the child receives the decrypted values and its exit code is preserved

#### Scenario: Explicit override
- **WHEN** --key before run's -- separator or as get/decrypt option names a valid external key and the default pointer is missing or invalid, with envdir selected by global -d or default ./.envs
- **THEN** run/get/decrypt uses the explicit key without reading the pointer

### Requirement: Fail closed key target validation
The resolved key SHALL be a regular file outside the resolved envdir, owned by effective uid and inaccessible to group/other. Invalid pointers, link cycles, malformed/wrong keys or insecure targets SHALL exit 111 without child execution, file replacement or secret disclosure. The existing encrypted and plaintext envdir formats SHALL remain unchanged.

#### Scenario: Invalid reference or insecure key
- **WHEN** encrypted run/get or a decrypt batch has an invalid reference or key target
- **THEN** exit is 111, run's child marker is absent, stdout has no secret, decrypt preserves the entire batch, and stderr contains no secret bytes
