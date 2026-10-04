## 1. Implementation
- [ ] 1.1 Add argparse's native version action for global --version/-V using importlib.metadata.version, with no duplicate version constant or fallback. (verification-id: local-cli)
- [ ] 1.2 Add regression tests comparing pyproject.toml, installed distribution metadata and exact stdout/stderr/status for both flags from unrelated cwd with no envdir, including nonexistent -d; assert no filesystem mutations, --help flags and child --version preservation. (verification-id: local-cli)
- [ ] 1.3 Document command and manual release policy in both READMEs; retain initial package version 0.1.0 and update the project operation skill's command grammar. (verification-id: local-cli)

## 2. Verification
- [ ] 2.1 Run uv run python -m unittest discover -s tests -v and verify no regression. (verification-id: local-cli)
- [ ] 2.2 Build wheel and sdist with uv build; install the wheel into an isolated temporary environment and verify console script and python -m envdirx --version outside the checkout, checking version against wheel metadata and pyproject.toml. (verification-id: local-cli)
- [ ] 2.3 Ensure built distributions contain no keys/envdirs, validate strict OpenSpec, archive with canonical version requirement and clean committed Git state. Tagging/publishing is operator work outside this change. (verification-id: local-cli)

