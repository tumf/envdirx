## Implementation Tasks
- [x] Implement rekey parser/help/dispatch and the complete preflight, memory-only ciphertext transformation, fresh external key, verified private staging and publish/cleanup path defined in proposal.md; retain all existing contracts. (verification: integration: tests/test_envdirx.py; uv run python -m unittest discover -s tests -v; verification-id: rekey-contract)
- [x] Add isolated CLI success, old/source preservation, key-selection, format/byte/mode, parser and negative-path regression cases, plus deterministic injected late write/verification/publication failure tests and intercepted filesystem-write inspection plus encrypted-only random sentinel scanning across fixture/isolated HOME after success and each injected failure. (verification: integration: tests/test_envdirx.py; uv run python -m unittest discover -s tests -v; verification-id: rekey-contract)
- [x] Update English/Japanese README, tracked public skill, help and canonical cli-workflow via archive with distinct old --key and new -k/--new-key / -K/--new-key-dir syntax, revised no-rotation claims and command tables, main-help compatibility (no legacy word), safe out-of-place switch instructions, existing plaintext behavior, retained old-key/ciphertext leak caveat and interruption guarantee; execute fixture examples in isolated HOME/XDG and retain existing suite coverage. (verification: integration: tests/test_envdirx.py and tests/test_public_skill.py; uv run python -m unittest discover -s tests -v; verification-id: rekey-contract)

## Notes
- evidence: `uv run python -m unittest discover -s tests -v` ran 85 tests, OK (RekeyTest covers success, key stores, refusals, parser errors, injected failures with write interception and sentinel scans).
- evidence: a temporary mutant that appended decrypted plaintext to staged ciphertext was caught by the sentinel/write-interception tests (7 failures), then reverted.
- evidence: `cflx openspec validate add-rekey --strict` passed; the canonical cli-workflow spec is updated from the delta at archive time.

## Final Validation
Archive gate: `cflx openspec validate add-rekey --archive-gate`. Verification path remains tests/test_envdirx.py after archive.

## Future Work
Operational path cutover and actual secret/key rotation require separately specified real-data targets. No push/release is authorized.
