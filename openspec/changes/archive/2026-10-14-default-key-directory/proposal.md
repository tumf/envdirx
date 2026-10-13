---
change_type: implementation
verifications:
  - id: key-directory-contract
    requirement: Safe default private-key directory selection and creation
    phase: pre-integration
    execution_class: repository-local
    completion_role: change-blocking
    owner: conflux-acceptance
    trigger: after implementation and before archive
    automation: tests/test_envdirx.py
    evidence: uv run python -m unittest discover -s tests -v; real CLI fixture checks
    rerun: uv run python -m unittest discover -s tests -v
    prerequisites:
      - Python 3.13+ and locked project dependencies
---

# Default key directory

**Change Type**: implementation

## Why
Make `envdirx keygen` usable without specifying an external key destination while preserving explicit overrides and fail-closed key handling.

## What Changes
- If neither -k nor -K is provided, use `$XDG_DATA_HOME/envdirx/keys` when XDG_DATA_HOME is nonempty and absolute; otherwise use `$HOME/.local/share/envdirx/keys`. Unset, empty, and relative XDG_DATA_HOME use the home fallback, per XDG conventions. Do not expand literal ~ in XDG_DATA_HOME.
- Lazily create the default directory and missing parents only for keygen without destinations; newly created directories are mode 0700 regardless of umask. Leave existing directory modes unchanged. Explicit -K still requires an existing directory; -k still selects an exact file. They remain mutually exclusive.
- Validate the resolved default destination before creation: it must remain outside resolved envdir, including symlink aliases and descendants. Reject an existing non-directory, dangling/cyclic links, or filesystem errors with exit 111, no key material output, and no new key/public/pointer artifacts. Missing envdir or existing public/pointer must fail before default-directory creation.
- Keep full lowercase SHA256(raw public key)+.key naming, 0600 private key, 0644 public key, absolute symlink pointer, collision/no-overwrite and newly created key artifact cleanup. Empty default directories may remain after write failure; do not remove existing directories or change existing permissions.
- Reads continue to use only the selected envdir pointer or --key; changing XDG_DATA_HOME does not relocate or affect existing keys. No implicit key discovery or migration, release, push, installed-tool update, new dependency, or .cflx.jsonc.
- Update English/Japanese README, public `skills/envdirx/SKILL.md`, CLI help and canonical spec through archive. Tests must isolate HOME/XDG_DATA_HOME and never touch real key stores: Fixture must remove inherited XDG_DATA_HOME (including README block execution), then individual cases set it explicitly. Update the obsolete empty-argv option-error test to default-generation success; preserve missing option value and mutually exclusive option failures.
- Create each missing parent at 0700 using mkdir plus chmod only for newly created directories; do not reuse envdir `_mkdir` whose intermediate parents depend on umask. Convert Path.home() resolution RuntimeError into the existing handled ValueError/exit-111 path. Preserve help's `sha256` and `no force option` wording used by tests.

## Fable review
Claude Fable 5.1 (`claude-fable-5-1`), job `03cc9332283aafa421e7c6c3c0df6376`, final GO with required fixture XDG isolation, obsolete empty-argv test update and all-new-parent 0700 handling. These conditions are included above. Proposal metadata was aligned with the strict validator (sequence prerequisites; owner conflux-acceptance).

## Acceptance
1. Default CLI encrypted set/get/run roundtrip works with unset, empty, absolute, and relative XDG_DATA_HOME in isolated fixtures; fingerprint, absolute pointer and modes match the contract, including restrictive and permissive umasks.
2. Existing default directory modes and keys remain unchanged, and distinct envdirs receive distinct fingerprint-named keys. Pointer reads still work when XDG_DATA_HOME changes.
3. -k/-K ignore default environment values; absent explicit -K fails without automatic creation. Both options together or missing option values fail parsing exit 2 with no writes.
4. Default destinations inside envdir (direct and symlink alias), non-directory/dangling/cyclic paths, collision and injected write failures fail closed. Existing data is preserved; new key/public/pointer artifacts are cleaned. Test filesystem failures where feasible without relying on root permission behavior.
5. Full unittest suite and strict/archive validation pass. README command blocks remain executable in isolated HOME/XDG fixtures; public skill stays consistent.

## Impact
Source: src/envdirx/__init__.py. Tests: tests/test_envdirx.py, tests/test_public_skill.py as needed. Docs: README.md, README.ja.md, skills/envdirx/SKILL.md. Capability: cli-workflow. Existing ciphertext and key-reference formats unchanged.
