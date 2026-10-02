## Implementation Tasks
- [ ] Remove init implementation/help/dispatch and migrate shared fixtures to keygen, retaining explicit text-pointer coverage and all other regression assertions; add rejected-init no-write test. Completion: supported CLI tests and README execution pass. (verification: integration - tests/test_envdirx.py; verification-id: local-cli)
- [ ] Update README and operations skill to supported keygen workflow and init removal. Completion: no obsolete live init instructions remain and README shell tests pass. (verification: integration - tests/test_envdirx.py; verification-id: local-cli)

## Final Validation
Archive gate: `cflx openspec validate remove-init-command --archive-gate`. Promote both deltas to canonical specs; historical archives remain immutable.
