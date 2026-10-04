---
change_type: implementation
priority: medium
dependencies: []
verifications:
  - id: local-cli
    requirement: Version reporting and existing CLI tests pass
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
# Add CLI version reporting
**Change Type**: implementation

## Why

envdirx has a package version in `pyproject.toml`, but users and automation cannot query the installed CLI version.

## What Changes

- Define the package version in `pyproject.toml` as the authoritative release version.
- Add `envdirx --version` and `envdirx -V`, printing exactly the installed distribution version followed by one newline.
- Document the version command in English and Japanese command references.

## Impact

- `pyproject.toml`
- `src/envdirx/__init__.py`
- `tests/test_envdirx.py`
- `README.md`
- `README.ja.md`
- `.agents/skills/envdirx-operations/SKILL.md`
- `openspec/specs/cli-workflow/spec.md`
