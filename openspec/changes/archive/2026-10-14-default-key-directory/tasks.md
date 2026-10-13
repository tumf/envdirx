## Implementation
- [x] 1. Implement optional default destination selection and safe lazy creation. verification-id: key-directory-contract (verification: integration: uv run python -m unittest discover -s tests -v; tests/test_envdirx.py)
- [x] 2. Add isolated default/override/security/failure regression cases and update obsolete required-destination tests. verification-id: key-directory-contract (verification: integration: uv run python -m unittest discover -s tests -v; tests/test_envdirx.py)
- [x] 3. Align CLI help, bilingual README, public skill, and canonical specification while preserving other requirements. verification-id: key-directory-contract (verification: integration: uv run python -m unittest discover -s tests -v; tests/test_public_skill.py)
- [x] 4. Run full suite and real CLI fixture roundtrip and leave all change-owned files staged with a clean worktree (archive and the final commit are Conflux-owned). verification-id: key-directory-contract (verification: integration: uv run python -m unittest discover -s tests -v; tests/test_envdirx.py)

## Notes
- evidence: `uv run python -m unittest discover -s tests -v` passed (73 tests) including DefaultKeyDirectoryTest and the updated README/public-skill contract checks.
- evidence: real CLI fixture with umask 022 and absolute XDG_DATA_HOME created xdg/envdirx/keys at 0700, a 0600 fingerprint-named key and an absolute pointer; encrypted set then run succeeded with XDG_DATA_HOME unset; a repeated keygen failed 111 with "refusing to overwrite".
- The canonical `openspec/specs/cli-workflow/spec.md` requirement is replaced by this change's MODIFIED delta when the change is archived; it is not edited in place during apply.

## Final Validation
- `cflx openspec validate default-key-directory --strict` passed.
- `cflx openspec validate default-key-directory --archive-gate` passed.
