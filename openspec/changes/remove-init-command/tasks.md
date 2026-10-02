## Implementation Tasks
- [x] Remove init implementation/help/dispatch and migrate shared fixtures to keygen, retaining explicit text-pointer coverage and all other regression assertions; add rejected-init no-write test. Completion: supported CLI tests and README execution pass. (verification: integration - tests/test_envdirx.py; verification-id: local-cli)
- [x] Update README and operations skill to supported keygen workflow and init removal. Completion: no obsolete live init instructions remain and README shell tests pass. (verification: integration - tests/test_envdirx.py; verification-id: local-cli)

## Final Validation
Archive gate: `cflx openspec validate remove-init-command --archive-gate`. Promote both deltas to canonical specs; historical archives remain immutable.

## Notes
- evidence: `uv run python -m unittest discover -s tests -v` ran 40 tests, OK (includes test_init_is_rejected_without_writes and test_readme_commands)
- Shared fixture `keygen_encrypted` uses `keygen -k ROOT/service.key`; `text_pointer()` explicitly writes the regular-file pointer for tests that cover legacy text pointers
