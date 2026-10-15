## Implementation Tasks

- [ ] Add the stable parent-directory nonblocking OS lock context and fail-closed errors; no filesystem artifacts, close FDs on all paths (verification: unit - parent open/flock errors, alias identity, non-inheritance and no-artifact assertions in tests/test_envdirx.py; verification-id: writer-safety)
- [ ] Wire all mutation families through the shared lock before input/entry/key reads, retaining it through rekey exchange/retirement and all cleanup; leave read-only commands and mkdir unguarded (verification: integration - tests/test_envdirx.py real blocked rekey versus each CLI writer, reverse writer versus rekey, pre/post-exchange barriers; verification-id: writer-safety)
- [ ] Add causal bounded subprocess regressions for normal/error/interrupt release, SIGTERM/SIGKILL pre/post-publication, unchanged contender snapshots and successful subsequent set/rekey without residue removal (verification: integration - real native exchange and fresh get/run in tests/test_envdirx.py plus an isolated disabled-flock causal control; verification-id: writer-safety)
- [ ] Synchronize CLI help and English/Japanese READMEs, tracked skills/envdirx/SKILL.md, and cli-workflow deltas with coarse exclusion, busy retry, required parent read/search permissions, resolved-path diagnostics, upgrade and crash-residue limits; keep existing behavior regressions green (verification: integration - documented examples and full unittest discovery through tests/test_envdirx.py; verification-id: writer-safety)

## Final Validation

Run the declared writer-safety gate once against final code. Archive validation is authoritative final OpenSpec validation: `cflx openspec validate serialize-envdir-writers --archive-gate`. Canonical specs must retain later unrelated requirements and replace only this change's targeted blocks.

## Future Work

Parent-owned operational step after merge: normal local CLI install and isolated installed-CLI smoke. No push/release, production envdir rotation, automatic residue deletion or power-loss claims.
