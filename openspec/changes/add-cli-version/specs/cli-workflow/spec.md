## ADDED Requirements

### Requirement: Package version reporting
The CLI SHALL accept global `--version` and `-V` without a subcommand and SHALL write exactly the installed envdirx distribution version plus one LF to stdout, with empty stderr and exit status 0. The version SHALL be read using standard-library `importlib.metadata.version("envdirx")`; runtime code SHALL NOT duplicate the version string, read a source checkout's pyproject.toml, or invent a fallback. `pyproject.toml` project.version SHALL remain the sole release-version source, initially 0.1.0. Version reporting SHALL require no envdir or key, SHALL NOT read or write envdir entries, and SHALL work from unrelated working directories, including with `-d` naming a nonexistent directory before the version flag. `--help` SHALL list both flags and explain that the global flags precede a subcommand; `run --version` without the child separator is invalid. `run -- COMMAND --version` SHALL preserve the child command's version argument. English and Japanese READMEs SHALL document both version flags and a manual release policy: semantic MAJOR.MINOR.PATCH versions, bump via `uv version <version>` (synchronizing pyproject.toml and uv.lock), commit after verification and tag as `v<version>`; tag/push/package publication are separate operator actions. Before 1.0, incompatible CLI changes SHALL increment MINOR and compatible additions/fixes SHALL increment PATCH.

#### Scenario: Version without envdir
- **WHEN** either version flag runs in an unrelated empty directory, with the default directory or an explicit nonexistent -d directory
- **THEN** stdout is the installed package version and one LF, stderr is empty, exit is 0 and no files are created

#### Scenario: Distribution and project consistency
- **WHEN** envdirx is installed from a built wheel into an isolated environment and run outside the checkout through both the console script and python -m envdirx
- **THEN** version output matches that distribution's metadata and the version declared in pyproject.toml

#### Scenario: Version is not a child flag interceptor
- **WHEN** run -- executes a child with its own --version argument
- **THEN** the child receives --version unchanged
