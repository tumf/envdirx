## Implementation Tasks

- [x] Implement fixed pointer resolution, explicit --key precedence, external-target validation and fail-closed run wiring while preserving existing formats/semantics (verification: integration - tests/test_envdirx.py; verification-id: key-reference-tests).
- [x] Implement init pointer creation with preflight collision checks and cleanup of only newly created files; preserve adjacent external default key destination (verification: integration - tests/test_envdirx.py; verification-id: key-reference-tests).
- [x] Add real CLI roundtrip and negative-path integration tests plus bounded owner-mismatch unit coverage for every acceptance case (verification: integration - uv run python -m unittest discover -s tests -v; verification-id: key-reference-tests).
- [x] Update README and CLI help with pointer forms, migration commands, --key-before-DIRECTORY ordering and symlink dereference risk; verify documented commands with temporary fixtures (verification: integration - tests/test_envdirx.py; verification-id: key-reference-tests).

## Final Validation

Archive validation is authoritative: cflx openspec validate add-key-reference --archive-gate. Gate references tests/test_envdirx.py, which remains valid after archive.

## Future Work

Parent updates the Obsidian usage note after checking the merged implementation. No external deployment or publication is part of this change.

## Notes

- evidence: `uv run python -m unittest discover -s tests -v` ran 23 tests, all OK (integration CLI roundtrips/negative paths in `EnvdirxTest`; pure-logic unit tests in `KeyMetadataUnitTest`; owner mismatch covered by `_check_key` unit test plus a mocked-`geteuid` in-process test).
- `test_readme_commands` executes every README `sh` block (quickstart, explicit `--key`, text and symlink pointer migration) through a `uv run envdirx` shim against temporary fixtures.
- Decision: mode checks reject any group/other bit (0700/0400 are accepted); init uses `O_EXCL|O_NOFOLLOW` creation for key, pointer and public key so nothing preexisting is overwritten.
