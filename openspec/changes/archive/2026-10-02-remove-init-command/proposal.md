---
change_type: implementation
priority: medium
dependencies: []
verifications:
  - id: local-cli
    requirement: Real CLI and regression tests meet the revised command contract
    phase: pre-integration
    owner: conflux-acceptance
    trigger: pull-request-validation
    automation: tests/test_envdirx.py
    evidence: uv run python -m unittest discover -s tests -v
    rerun: uv run python -m unittest discover -s tests -v
    prerequisites: []
    execution_class: repository-local
    completion_role: change-blocking
---
# Remove init command
**Change Type**: implementation

## Problem / Context
User explicitly wants init removed. Current parser and _init implement a legacy adjacent-key/text-pointer generator. mkdir/keygen already cover new creation; existing key references are still valid and must not be deleted or migrated.

## Proposed Solution
Delete init parser, handler, _init and init-specific help/dispatch branches, keeping shared keygen helpers. `envdirx init ...` must be argparse exit 2 with no filesystem changes. Help and README list only supported commands and recommend mkdir/keygen. Delete obsolete init-only tests; migrate shared regression fixtures from init to mkdir/keygen, explicitly create regular text pointers for tests that require them. Preserve existing text-pointer/symlink, private-key validation, set/get/run coverage. No automatic conversion of existing text pointers. Remove legacy-init instruction from operations skill. No new dependencies or compatibility alias.

## Acceptance Criteria / Explicit Completion Conditions
Real subprocess init rejection/no writes and help exclusion; keygen fixtures still cover all prior supported reference and ciphertext contracts. README shell examples execute, full bounded unittest succeeds. Canonical Directory-oriented command grammar no longer promises init; remove Init creates an external key pointer safely requirement. No dangling init references except historical archived proposals/migration prose documenting removal.

## Boundary / Out of Scope
src/envdirx/, tests/test_envdirx.py, README.md, operations skill, OpenSpec only. Do not change crypto formats, keygen/default directory, transformations, operational keys, config or GitHub. No hook duplicates (no unconditional tracked hooks). Separate from transformation selector/decrypt change; sequential execution recommended due overlapping parser/docs/tests, no hard dependency required.
