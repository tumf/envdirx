## MODIFIED Requirements

### Requirement: Directory-oriented command grammar
CLI SHALL use global -d/--directory before subcommand with cwd-relative default ./.envs for mkdir, keygen, set, get, encrypt and run. Run SHALL require -- before command, preserve child flags and DJB semantics and exit codes. Init SHALL NOT be a recognized subcommand, and SHALL fail parsing without writes. Positional directories for set/encrypt/run SHALL no longer be accepted as such.

#### Scenario: Default and explicit directories
- **WHEN** mkdir followed by plaintext set AAA, get AAA and run -- sh -c 'test -n "$AAA"' execute with default or explicit -d
- **THEN** only the selected envdir is used and child receives the value

#### Scenario: Child separator
- **WHEN** run lacks -- or command
- **THEN** it fails without starting a child

#### Scenario: Removed init
- **WHEN** init is requested
- **THEN** exit is 2 and no files are changed
