## 1. Implementation
- [x] 1.1 Add argparse's native version action for global --version/-V using importlib.metadata.version, with no duplicate version constant or fallback. (verification-id: local-cli)
- [x] 1.2 Add regression tests comparing pyproject.toml, installed distribution metadata and exact stdout/stderr/status for both flags from unrelated cwd with no envdir, including nonexistent -d; assert no filesystem mutations, --help flags and child --version preservation. (verification-id: local-cli)
- [x] 1.3 Document command and manual release policy in both READMEs; retain initial package version 0.1.0 and update the project operation skill's command grammar. (verification-id: local-cli)

## 2. Verification
- [x] 2.1 Run uv run python -m unittest discover -s tests -v and verify no regression. (verification-id: local-cli)
- [x] 2.2 Build wheel and sdist with uv build; install the wheel into an isolated temporary environment and verify console script and python -m envdirx --version outside the checkout, checking version against wheel metadata and pyproject.toml. (verification-id: local-cli)
- [x] 2.3 Ensure built distributions contain no keys/envdirs and validate strict OpenSpec. Tagging/publishing is operator work outside this change. (verification: integration - tests/test_envdirx.py, uv build, cflx openspec validate add-cli-version --strict; verification-id: local-cli)

## Notes
- Task 2.3 originally also named archiving and a clean committed Git state; archive (applying the canonical version requirement to openspec/specs/cli-workflow/spec.md) and the final commit are owned by Conflux, not apply, so they were left out of the apply task.
- Evidence 2.2: uv build produced envdirx-0.1.0 wheel and sdist; the wheel installed into a fresh temporary venv printed 0.1.0 via the envdirx console script (--version and -V) and python -m envdirx --version from an unrelated directory, matching the wheel METADATA Version and pyproject.toml.
- Evidence 2.3: the wheel and sdist file lists contain only package sources, READMEs, pyproject.toml and metadata (no *.key, *.pub, .envs or envdir files); cflx openspec validate add-cli-version --strict passed.

## Final Validation
uv run python -m unittest discover -s tests -v: 54 tests OK.

