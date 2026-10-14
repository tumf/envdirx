## Implementation Tasks
- [x] Replace out-of-place rekey with the fixed same-path CLI, preflight, native exchange capability probe, verified staging, atomic exchange commit boundary and stage-aware cleanup defined in proposal.md. Preserve all other contracts. (verification: integration: tests/test_envdirx.py; uv run python -m unittest discover -s tests -v; verification-id: in-place-rekey)
- [x] Update isolated CLI regression tests for same-path values/modes/keys, key destinations, parser and negative cases, native ABI and real host exchange, injected pre/post-commit failures, encrypted-only sentinel interception and real subprocess SIGKILL barriers before/after publication. Keep existing unrelated coverage. (verification: integration: tests/test_envdirx.py; uv run python -m unittest discover -s tests -v; verification-id: in-place-rekey)
- [x] Update help, English/Japanese README and tracked public skill/tests; synchronize canonical cli-workflow by archive, remove --output/manual cutover instructions, document process-interruption/residue and concurrency limits, and execute documented examples using isolated synthetic data. (verification: integration: tests/test_envdirx.py and tests/test_public_skill.py; uv run python -m unittest discover -s tests -v; verification-id: in-place-rekey)

## Notes
- evidence: `uv run python -m unittest discover -s tests -v` ran 95 tests OK on macOS (Darwin), including new RekeyTest, NativeExchangeUnitTest and NativeExchangeHostTest.
- The real native exchange (renamex_np RENAME_SWAP), SIGKILL barriers and KeyboardInterrupt pre/post-commit tests ran on the macOS host only. Linux renameat2 coverage is mocked ABI/errno unit tests; no Linux end-to-end run is claimed.
- Mountpoint refusal is exercised by mocking os.path.ismount in-process; root and cwd-inside-DIR (direct and through a symlink alias) are refused by real CLI tests.
- The canonical openspec/specs/cli-workflow/spec.md is synchronized from the delta at archive time; it is not edited during apply.
- Help example `envdirx -d ./app.env rekey -k ~/keys/app.env.key` was executed manually with isolated HOME and synthetic data; README sh blocks are executed by test_readme_commands.

## Final Validation
`cflx openspec validate rekey-in-place --strict` and `cflx openspec validate rekey-in-place --archive-gate`; run full tests before archive. Do not mark tasks complete without actual execution evidence. Tests and verification paths remain available after archive.

## Out of scope
No real credential/key rotation, public push/release, .cflx.jsonc or unrelated cleanup. Installed CLI update follows independent local result acceptance.
