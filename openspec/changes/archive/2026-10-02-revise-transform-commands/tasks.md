## Implementation Tasks
- [x] Implement selector validation and symmetric preflight-based encrypt/decrypt runtime with per-file atomic writes; completion: real CLI positive and no-write validation paths pass, bytes/formats/security unchanged. (verification: integration - tests/test_envdirx.py; verification-id: local-cli)
- [x] Add subprocess and fault tests for selection, raw-name traversal/absolute/dot-metadata rejection without writes, no-key no-op, batch validation, reserved-prefix and late-write failures; completion: each acceptance criterion exercised, prior applicable regressions retained. (verification: integration - tests/test_envdirx.py; verification-id: local-cli)
- [x] Update help/README/operations skill to explicit --all and plaintext-on-disk decrypt, execute new README shell blocks; completion: supported examples match runtime and no implicit all instructions remain. (verification: integration - tests/test_envdirx.py; verification-id: local-cli)

## Final Validation
Archive gate: `cflx openspec validate revise-transform-commands --archive-gate`. Promote cli-workflow delta and keep canonical grammar including decrypt consistent with init removal (latest base). Historical archives remain unchanged.
