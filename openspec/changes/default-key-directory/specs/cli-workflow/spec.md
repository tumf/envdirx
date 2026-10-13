## MODIFIED Requirements

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
