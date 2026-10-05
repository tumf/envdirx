# envdirx

[日本語版 README](README.ja.md)

`envdirx` is a CLI that keeps the DJB `envdir` convention: one file per environment variable. `set` stores plaintext by default; `set -c` encrypts. Plaintext and encrypted entries can coexist, and `run` reads both. An encrypted entry named `GOG_KEYRING_PASSWORD` has printable `encrypted:B...` Base64 text inside its file, **not** a `GOG_KEYRING_PASSWORD=` line. Existing binary `envdirx:v1:` entries remain readable; new writes use the printable format with one trailing LF. Readers also accept no trailing LF; embedded or repeated newlines and CRLF are rejected. It serves a similar purpose to dotenvx, but its ciphertext and keys are **not compatible**.

Requires Python 3.13 or newer on POSIX. The default envdir is `./.envs` relative to the current working directory. Put `-d/--directory DIRECTORY` **before** the subcommand. Only `mkdir` creates the envdir; other commands require it to exist.

## Install and quick start

From this repository, while preparing the first PyPI release:

```sh
uv sync
mkdir -p ~/.envdirx-keys
uv run envdirx mkdir
uv run envdirx keygen -K ~/.envdirx-keys
printf 'plain-value' | uv run envdirx set AAA
printf 'example-token' | uv run envdirx set -c API_TOKEN
uv run envdirx get AAA > /dev/null
uv run envdirx run -- sh -c 'test -n "$AAA" && test -n "$API_TOKEN"'
```

After publication, install with `uv tool install envdirx` and replace `uv run envdirx` with `envdirx`. Do not put real secrets on a shell command line: supply them from a file or standard input instead of `printf` literals.

| Command | Action |
| --- | --- |
| `envdirx --version` / `envdirx -V` | Print the installed envdirx version and one newline, then exit 0. Like `-d`, it goes before any subcommand and needs no envdir or key. |
| `envdirx [-d D] mkdir` | Create the envdir and missing parents; a new envdir has mode 0700. An existing directory is left unchanged; a non-directory fails with status 111. |
| `envdirx [-d D] keygen (-k KEYFILE \| -K KEYDIR)` | Create a key pair and the `.envdirx.key` symlink. |
| `envdirx [-d D] set [-c] NAME` | Store stdin unchanged as plaintext, or encrypt with `-c`. |
| `envdirx [-d D] get [--key KEY] NAME` | Write the original bytes to stdout. |
| `envdirx [-d D] encrypt (NAME [NAME ...] \| --all)` | Encrypt existing plaintext entries in place, using only the public key. |
| `envdirx [-d D] decrypt [--key KEY] (NAME [NAME ...] \| --all)` | Restore encrypted entries to plaintext files, using the private key. |
| `envdirx [-d D] run [--key KEY] -- COMMAND [ARGS...]` | Execute a command with the envdir applied. |

For an explicit directory and key file:

```sh
uv run envdirx -d service.env mkdir
uv run envdirx -d service.env keygen -k "$HOME/service.env.key"
printf 'example-token\n' | uv run envdirx -d service.env set -c API_TOKEN
uv run envdirx -d service.env run --key "$HOME/service.env.key" -- sh -c 'test "$API_TOKEN" = example-token'
```

Quote the `sh -c` program with single quotes so the calling shell does not expand the variables.

## Storing and reading values

`set NAME` atomically stores stdin byte-for-byte as a mode-0600 plaintext file. It does not read a key or key pointer. Plaintext values beginning with `envdirx:` or `encrypted:` are reserved for ciphertext formats and are rejected with status 111 without changing the existing entry; use `set -c` for such values. `set -c NAME` needs only `.envdirx.pub`, not the private key.

`get NAME` writes plaintext or the decrypted original bytes without adding a newline. Unlike `run`, it does not trim the first line or convert NUL bytes. Empty entries return zero bytes. **`get` can expose secrets to terminals and logs**; direct its output carefully. Missing or invalid entries, unsupported `envdirx:` or `encrypted:` formats, ciphertext bound to a different name, and invalid keys fail with status 111 and no value on stdout. `--key` overrides the pointer for encrypted entries only.

## Encrypting and decrypting files

Both commands require either one or more names or `--all`. No target, mixing names with `--all`, or duplicate names fails with status 2 before reading the directory or key. Names follow the same validation as `set`/`get`: `../X`, absolute paths, and dotfiles such as `.envdirx.pub` are rejected without writes (status 111).

- `encrypt` changes plaintext files to encrypted files using only `.envdirx.pub`.
- `decrypt` authenticates ciphertext and restores its original bytes, including newlines, NUL bytes and empty files, using only the private key. It does not require the public key. `--key` overrides `.envdirx.key`.
- An explicitly named entry already in the requested state fails with status 111. `--all` skips entries already in that state and ignores dotfiles. If nothing needs conversion, it succeeds without reading a key. Unsupported or invalid `envdirx:` or `encrypted:` formats fail with status 111.

**`decrypt` intentionally leaves secrets as plaintext on disk.** Back up sensitive files before converting, then verify the result. Atomic replacement does not securely erase prior plaintext or ciphertext from storage or backups. If a decrypted value begins with reserved prefix `envdirx:` or `encrypted:`, `decrypt` rejects the batch before writing anything (status 111) because `get`/`run` would misidentify that plaintext as ciphertext. For such a value, direct `get` output to a suitably protected file outside the envdir instead.

All selected entries are read, validated, and transformed in memory before the first write. A missing or non-regular entry, invalid format or key, failed authentication, or reserved plaintext prefix leaves all entries unchanged (status 111). Each subsequent file replacement is atomic and mode 0600, but **the batch is not transactional**: if a later write fails, earlier successful replacements remain. Success writes nothing to stdout; errors contain names and paths, not values.

```sh
printf 'old-plain' | uv run envdirx -d service.env set DB_PASSWORD
uv run envdirx -d service.env encrypt --all
uv run envdirx -d service.env run --key "$PWD/service.env.key" -- sh -c 'test "$DB_PASSWORD" = old-plain'
```

To target one entry and restore it afterward:

```sh
uv run envdirx -d app.env mkdir
uv run envdirx -d app.env keygen -k "$PWD/app.env.key"
printf 'db-secret' | uv run envdirx -d app.env set DB_PASSWORD
printf 'visible' | uv run envdirx -d app.env set LOG_LEVEL
uv run envdirx -d app.env encrypt DB_PASSWORD
uv run envdirx -d app.env decrypt DB_PASSWORD
uv run envdirx -d app.env encrypt --all
uv run envdirx -d app.env decrypt --key "$PWD/app.env.key" --all
```

Do not run `decrypt` on real data unless restoring those specified files to plaintext is intended.

## Keys and `.envdirx.key`

`keygen` creates a mode-0600 private key outside the envdir, a mode-0644 raw 32-byte public key at `.envdirx.pub`, and a symlink `.envdirx.key` pointing to the fully resolved absolute private-key path. `-k KEYFILE` selects an exact file; `-K KEYDIR` stores the private key in an existing directory as `<lowercase SHA-256 of raw public key>.key`. Exactly one is required. Relative key destinations are relative to the current directory; leading `~/` expands to home.

It never overwrites a private key, public key, or pointer (including broken symlinks); there is no `-f/--force` or rotation command. It does not create the key's parent directory, refuses a private-key destination inside the resolved envdir, and removes only files it created if an operation fails. **Never put the private key in the repository, envdir, or a distribution. Back it up separately: losing it makes encrypted values unrecoverable.**

`run` and `get` read the private key only for encrypted entries. `--key` takes precedence over the pointer; its relative paths use the current directory and leading `~/` expands to home. Without it, only `.envdirx.key` is consulted—there is no fallback to a nearby key. A plaintext-only envdir needs neither a key nor a pointer.

The pointer can be a symlink (whose `~/` is not expanded) or a regular UTF-8 file containing one path. For a regular file, one trailing LF or CRLF is optional, spaces in the path are preserved, and leading `~/` expands to home. Empty or multiline content, NUL, and invalid UTF-8 are rejected. Relative paths in either pointer form resolve against the envdir. The fully resolved private key must be a regular file outside the resolved envdir, owned by the executing user, with no group or other permission bits (for example 0600). Missing, broken, cyclic, or invalid pointers/keys fail with status 111 without starting a child process or revealing values.

For an older envdir using a neighboring `service.env.key`, add a pointer without re-encrypting:

```sh
printf '%s\n' "$PWD/service.env.key" > service.env/.envdirx.key
chmod 600 service.env/.envdirx.key
uv run envdirx -d service.env run -- true
```

Alternatively, if the pointer does not already exist, use `ln -s ../service.env.key service.env/.envdirx.key`. The `*.key` rule in `.gitignore` also excludes `.envdirx.key`; do not weaken it. **Copies that follow symlinks (`tar -h`, `rsync -L`, `cp -L`) can package the private key instead of the pointer.** Exclude `.envdirx.key` from distributions or use a regular-file pointer.

## Migration from older CLI versions

`init` has been removed. Use `mkdir` followed by `keygen`; old envdirs with text-file pointers still work and are not rewritten automatically. Before the first 0.1.0 release, positional directory arguments were also removed. Specify `-d` before the subcommand:

| Old | New |
| --- | --- |
| `envdirx set DIR NAME` | `envdirx -d DIR set -c NAME` (include `-c` to retain encryption) |
| `envdirx encrypt DIR [NAME ...]` | `envdirx -d DIR encrypt (NAME [NAME ...] \| --all)` |
| `envdirx encrypt` (implicitly all) | `envdirx encrypt --all` |
| `envdirx run [--key K] DIR -- CMD` | `envdirx -d DIR run [--key K] -- CMD` |
| `envdirx set --key K DIR NAME` / `encrypt --key K ...` | Omit `--key`; these operations only use the public key. |

## Versioning and releases

`envdirx --version` reports the installed distribution's version; `project.version` in `pyproject.toml` is the only place the version is defined. `run -- COMMAND --version` passes `--version` to the child unchanged.

Releases are manual and use semantic `MAJOR.MINOR.PATCH` versions. Before 1.0, incompatible CLI changes increment MINOR, and compatible additions and fixes increment PATCH. To release, run `uv version <version>` (which updates both `pyproject.toml` and `uv.lock`), run the tests, commit, and tag the commit as `v<version>`. Pushing the tag and publishing the package are separate operator actions.

## Runtime behavior

`run` requires `--` followed by a command. Arguments after `--`, even `-d` and `--key`, belong to the child command. Put envdirx's `--key` before `--`. Missing `--` or command fails without starting a child. `run` execs the command and inherits its exit status. Following DJB semantics, a zero-byte entry unsets the variable; a nonempty entry uses only the first line, strips trailing spaces and tabs, and converts NUL bytes to newlines. Ciphertext uses an ephemeral X25519 key and ChaCha20-Poly1305; authentication binds the entry to its filename.

```sh
uv run python -m unittest discover -s tests -v
```

`ponytail:` This is currently for local POSIX environments. It does not defend against another user changing the directory concurrently; add dirfd-based race protection and stronger key management if that threat becomes relevant.
