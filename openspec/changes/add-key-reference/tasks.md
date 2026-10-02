## Implementation Tasks

- [ ] Implement fixed pointer resolution, explicit --key precedence, external-target validation and fail-closed run wiring while preserving existing formats/semantics (verification: integration - tests/test_envdirx.py; verification-id: key-reference-tests).
- [ ] Implement init pointer creation with preflight collision checks and cleanup of only newly created files; preserve adjacent external default key destination (verification: integration - tests/test_envdirx.py; verification-id: key-reference-tests).
- [ ] Add real CLI roundtrip and negative-path integration tests plus bounded owner-mismatch unit coverage for every acceptance case (verification: integration - uv run python -m unittest discover -s tests -v; verification-id: key-reference-tests).
- [ ] Update README and CLI help with pointer forms, migration commands, --key-before-DIRECTORY ordering and symlink dereference risk; verify documented commands with temporary fixtures (verification: integration - tests/test_envdirx.py; verification-id: key-reference-tests).

## Final Validation

Archive validation is authoritative: cflx openspec validate add-key-reference --archive-gate. Gate references tests/test_envdirx.py, which remains valid after archive.

## Future Work

Parent updates the Obsidian usage note after checking the merged implementation. No external deployment or publication is part of this change.
