## Implementation Tasks
- [ ] Replace out-of-place rekey with the fixed same-path CLI, preflight, native exchange capability probe, verified staging, atomic exchange commit boundary and stage-aware cleanup defined in proposal.md. Preserve all other contracts. (verification: integration: tests/test_envdirx.py; uv run python -m unittest discover -s tests -v; verification-id: in-place-rekey)
- [ ] Update isolated CLI regression tests for same-path values/modes/keys, key destinations, parser and negative cases, native ABI and real host exchange, injected pre/post-commit failures, encrypted-only sentinel interception and real subprocess SIGKILL barriers before/after publication. Keep existing unrelated coverage. (verification: integration: tests/test_envdirx.py; uv run python -m unittest discover -s tests -v; verification-id: in-place-rekey)
- [ ] Update help, English/Japanese README and tracked public skill/tests; synchronize canonical cli-workflow by archive, remove --output/manual cutover instructions, document process-interruption/residue and concurrency limits, and execute documented examples using isolated synthetic data. (verification: integration: tests/test_envdirx.py and tests/test_public_skill.py; uv run python -m unittest discover -s tests -v; verification-id: in-place-rekey)

## Final Validation
`cflx openspec validate rekey-in-place --strict` and `cflx openspec validate rekey-in-place --archive-gate`; run full tests before archive. Do not mark tasks complete without actual execution evidence. Tests and verification paths remain available after archive.

## Out of scope
No real credential/key rotation, public push/release, .cflx.jsonc or unrelated cleanup. Installed CLI update follows independent local result acceptance.
