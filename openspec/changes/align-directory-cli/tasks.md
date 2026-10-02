## Implementation Tasks

- [ ] Wire the directory-oriented parser, mkdir, plaintext-default atomic set, -c and encrypt/run migration while retaining legacy init; completion: real subprocess tests prove defaults, explicit directory, child flags/separator and DJB semantics. (verification: integration - tests/test_envdirx.py; verification-id: cli-tests)
- [ ] Implement safe keygen -k/-K, fingerprint filename and absolute symlink; completion: tests prove real roundtrip, modes, no-force, conflict/preflight/cleanup and resolved outside-envdir constraints. (verification: integration - tests/test_envdirx.py; verification-id: cli-tests)
- [ ] Implement get raw-byte output and shared validation; completion: tests prove plaintext/binary/empty and encrypted bytes, explicit override, failure no stdout and existing security regressions updated without weakening encryption assertions. (verification: integration - tests/test_envdirx.py; verification-id: cli-tests)
- [ ] Update README/help/operations skill and test README shell workflows/migration; completion: docs and runnable examples match new CLI, public-only writes and secret-disclosure boundaries, existing init remains documented. (verification: integration - tests/test_envdirx.py; verification-id: cli-tests)

## Final Validation
Archive readiness: `cflx openspec validate align-directory-cli --archive-gate`. Promote cli-workflow and key-reference deltas to canonical specs. Bounded local gate: `uv run python -m unittest discover -s tests -v`.

## Future Work
Global installation, release/push and user-vault documentation are parent-owned followup, not worker side effects.
