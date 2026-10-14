# envdirx

[日本語版 README](README.ja.md)

`envdirx` is a CLI that keeps the DJB `envdir` convention: one file per environment variable. `set` stores plaintext by default; `set -c` encrypts. Plaintext and encrypted entries can coexist, and `run` reads both. An encrypted entry named `GOG_KEYRING_PASSWORD` has printable `encrypted:B...` Base64 text inside its file, **not** a `GOG_KEYRING_PASSWORD=` line. Existing binary `envdirx:v1:` entries remain readable; new writes use the printable format with one trailing LF. Readers also accept no trailing LF; embedded or repeated newlines and CRLF are rejected. It serves a similar purpose to dotenvx, but its ciphertext and keys are **not compatible**.

Requires Python 3.13 or newer on POSIX. By default, envdirx uses `./.envs` in the current directory. Only `mkdir` creates it; other commands require it to exist.

Licensed under the [MIT License](LICENSE).

## Install and quick start

Install the published CLI:

```sh
uv tool install envdirx
envdirx mkdir
envdirx keygen
printf 'plain-value' | envdirx set AAA
printf 'example-token' | envdirx set -c API_TOKEN
envdirx get AAA > /dev/null
envdirx run -- sh -c 'test -n "$AAA" && test -n "$API_TOKEN"'
```

Do not put real secrets on a shell command line: supply them from a file or standard input instead of `printf` literals.

The quick start creates `./.envs` and a private key outside it (in `~/.local/share/envdirx/keys`, or under an absolute `XDG_DATA_HOME`). `keygen` records the key path in `./.envs/.envdirx.key`; `run` and `get` use that pointer automatically. Back up the private key separately. `set AAA` writes plaintext; `set -c API_TOKEN` encrypts. `run -- COMMAND` applies both entries to the child process. Quote the `sh -c` program with single quotes so the calling shell does not expand the variables.

| Command (default envdir) | Action |
| --- | --- |
| `envdirx mkdir` | Create `./.envs` and missing parents (mode 0700 for a new envdir). |
| `envdirx keygen` | Create a key pair outside the envdir and a `.envdirx.key` pointer inside it. |
| `envdirx set NAME` / `envdirx set -c NAME` | Store stdin as plaintext / encrypted. |
| `envdirx get NAME` | Write the original bytes to stdout; redirect secrets away from terminals and logs. |
| `envdirx encrypt NAME` / `envdirx encrypt --all` | Encrypt existing plaintext entries in place. |
| `envdirx decrypt NAME` / `envdirx decrypt --all` | Restore ciphertext to plaintext **on disk**. |
| `envdirx rekey --output DEST` | Copy the envdir under a fresh key; the original stays unchanged. |
| `envdirx run -- COMMAND [ARGS...]` | Execute a command with the envdir applied. |
| `envdirx --version` / `envdirx -V` | Print the installed version without reading the envdir. |

For a different directory, put `-d/--directory DIRECTORY` **before** the subcommand. `keygen -k KEYFILE` chooses a private-key file; `-K KEYDIR` chooses an existing key directory. `run`, `get`, and `decrypt` use the pointer unless `--key KEYFILE` overrides it. For example:

```sh
envdirx -d service.env mkdir
envdirx -d service.env keygen -k "$HOME/service.env.key"
printf 'example-token\n' | envdirx -d service.env set -c API_TOKEN
envdirx -d service.env run --key "$HOME/service.env.key" -- sh -c 'test "$API_TOKEN" = example-token'
```

Advanced command forms (options are shown here after the default workflow):

- `envdirx [-d D] keygen [-k KEYFILE \| -K KEYDIR]`
- `envdirx [-d D ...] get [--key KEY] NAME`
- `envdirx [-d D] encrypt (NAME [NAME ...] \| --all)`
- `envdirx [-d D] decrypt [--key KEY] (NAME [NAME ...] \| --all)`
- `envdirx [-d SOURCE] rekey --output DEST [--key OLDKEY] [-k NEWKEYFILE \| -K NEWKEYDIR]`

## Storing and reading values

`set NAME` atomically stores stdin byte-for-byte as a mode-0600 plaintext file. It does not read a key or key pointer. Plaintext values beginning with `envdirx:` or `encrypted:` are reserved for ciphertext formats and are rejected with status 111 without changing the existing entry; use `set -c` for such values. `set -c NAME` needs only `.envdirx.pub`, not the private key.

`get NAME` writes plaintext or the decrypted original bytes without adding a newline. Repeat `-d` before `get` to search directories in priority order: absent entries are skipped, but an empty entry wins. The selected directory supplies its own key pointer unless `--key` is given. Missing directories, invalid entries, and decryption errors stop the search rather than falling back. Repeated `-d` on other commands fails with status 2. Example (with existing envdirs): `envdirx -d ./local.env -d ./shared.env get API_TOKEN > /dev/null`. Unlike `run`, it does not trim the first line or convert NUL bytes. Empty entries return zero bytes. **`get` can expose secrets to terminals and logs**; direct its output carefully. Missing or invalid entries, unsupported `envdirx:` or `encrypted:` formats, ciphertext bound to a different name, and invalid keys fail with status 111 and no value on stdout. `--key` overrides the pointer for encrypted entries only.

## Encrypting and decrypting files

Both commands require either one or more names or `--all`. No target, mixing names with `--all`, or duplicate names fails with status 2 before reading the directory or key. Names follow the same validation as `set`/`get`: `../X`, absolute paths, and dotfiles such as `.envdirx.pub` are rejected without writes (status 111).

- `encrypt` changes plaintext files to encrypted files using only `.envdirx.pub`.
- `decrypt` authenticates ciphertext and restores its original bytes, including newlines, NUL bytes and empty files, using only the private key. It does not require the public key. `--key` overrides `.envdirx.key`.
- An explicitly named entry already in the requested state fails with status 111. `--all` skips entries already in that state and ignores dotfiles. If nothing needs conversion, it succeeds without reading a key. Unsupported or invalid `envdirx:` or `encrypted:` formats fail with status 111.

**`decrypt` intentionally leaves secrets as plaintext on disk.** Back up sensitive files before converting, then verify the result. Atomic replacement does not securely erase prior plaintext or ciphertext from storage or backups. If a decrypted value begins with reserved prefix `envdirx:` or `encrypted:`, `decrypt` rejects the batch before writing anything (status 111) because `get`/`run` would misidentify that plaintext as ciphertext. For such a value, direct `get` output to a suitably protected file outside the envdir instead.

All selected entries are read, validated, and transformed in memory before the first write. A missing or non-regular entry, invalid format or key, failed authentication, or reserved plaintext prefix leaves all entries unchanged (status 111). Each subsequent file replacement is atomic and mode 0600, but **the batch is not transactional**: if a later write fails, earlier successful replacements remain. Success writes nothing to stdout; errors contain names and paths, not values.

```sh
printf 'old-plain' | envdirx -d service.env set DB_PASSWORD
envdirx -d service.env encrypt --all
envdirx -d service.env run --key "$PWD/service.env.key" -- sh -c 'test "$DB_PASSWORD" = old-plain'
```

To target one entry and restore it afterward:

```sh
envdirx -d app.env mkdir
envdirx -d app.env keygen -k "$PWD/app.env.key"
printf 'db-secret' | envdirx -d app.env set DB_PASSWORD
printf 'visible' | envdirx -d app.env set LOG_LEVEL
envdirx -d app.env encrypt DB_PASSWORD
envdirx -d app.env decrypt DB_PASSWORD
envdirx -d app.env encrypt --all
envdirx -d app.env decrypt --key "$PWD/app.env.key" --all
```

Do not run `decrypt` on real data unless restoring those specified files to plaintext is intended.

## Keys and `.envdirx.key`

`keygen` creates a mode-0600 private key outside the envdir, a mode-0644 raw 32-byte public key at `.envdirx.pub`, and a symlink `.envdirx.key` pointing to the fully resolved absolute private-key path. `-k KEYFILE` selects an exact file; `-K KEYDIR` stores the private key in an existing directory as `<lowercase SHA-256 of raw public key>.key`. They are mutually exclusive. Relative key destinations are relative to the current directory; leading `~/` expands to home.

With neither option, the private key is stored as `<lowercase SHA-256 of raw public key>.key` in the default key directory: `$XDG_DATA_HOME/envdirx/keys` when `XDG_DATA_HOME` is a non-empty absolute path, otherwise `$HOME/.local/share/envdirx/keys` (an unset, empty, or relative `XDG_DATA_HOME` is ignored, and a literal `~` in it is not expanded). Only this default directory is created when missing: each new directory, including missing parents, gets mode 0700 regardless of umask, and existing directories keep their modes. Before anything is created, the resolved default directory must lie outside the resolved envdir (symlink aliases included); a non-directory, broken or cyclic symlink, or filesystem error fails with status 111 and writes no key, public key, or pointer. `-k` and `-K` never consult the default, and `-K` never creates its directory. Reading (`get`, `run`, `decrypt`) uses only the envdir's pointer or `--key`, so changing `XDG_DATA_HOME` later does not move or hide existing keys, and nothing scans or migrates the key directory.

It never overwrites a private key, public key, or pointer (including broken symlinks); there is no `-f/--force`, and `keygen` never replaces an existing key. To rotate to a new key, use `rekey` (see [Rotating keys with `rekey`](#rotating-keys-with-rekey)). Apart from the default key directory, it does not create the key's parent directory. It refuses a private-key destination inside the resolved envdir and removes only files it created if an operation fails (a newly created, empty default key directory may remain). **Never put the private key in the repository, envdir, or a distribution. Back it up separately: losing it makes encrypted values unrecoverable.**

`run` and `get` read the private key only for encrypted entries. `--key` takes precedence over the pointer; its relative paths use the current directory and leading `~/` expands to home. Without it, only `.envdirx.key` is consulted—there is no fallback to a nearby key. A plaintext-only envdir needs neither a key nor a pointer.

The pointer can be a symlink (whose `~/` is not expanded) or a regular UTF-8 file containing one path. For a regular file, one trailing LF or CRLF is optional, spaces in the path are preserved, and leading `~/` expands to home. Empty or multiline content, NUL, and invalid UTF-8 are rejected. Relative paths in either pointer form resolve against the envdir. The fully resolved private key must be a regular file outside the resolved envdir, owned by the executing user, with no group or other permission bits (for example 0600). Missing, broken, cyclic, or invalid pointers/keys fail with status 111 without starting a child process or revealing values.

For an older envdir using a neighboring `service.env.key`, add a pointer without re-encrypting:

```sh
printf '%s\n' "$PWD/service.env.key" > service.env/.envdirx.key
chmod 600 service.env/.envdirx.key
envdirx -d service.env run -- true
```

Alternatively, if the pointer does not already exist, use `ln -s ../service.env.key service.env/.envdirx.key`. The `*.key` rule in `.gitignore` also excludes `.envdirx.key`; do not weaken it. **Copies that follow symlinks (`tar -h`, `rsync -L`, `cp -L`) can package the private key instead of the pointer.** Exclude `.envdirx.key` from distributions or use a regular-file pointer.

## Rotating keys with `rekey`

`envdirx [-d SOURCE] rekey --output DEST [--key OLDKEY] [-k/--new-key NEWKEYFILE | -K/--new-key-dir NEWKEYDIR]` rotates out of place: it generates a fresh X25519 key and writes a complete new envdir at `DEST`. It never changes or deletes `SOURCE` (default `./.envs`) or the old key, and it does not switch anything over for you.

- **`--key OLDKEY` names the old key, unlike `keygen --key`, which names the new one.** It is used only to decrypt `SOURCE` (default: `SOURCE/.envdirx.key`) and is read only when `SOURCE` holds encrypted entries. `SOURCE/.envdirx.pub` is not needed.
- The new private key goes to `-k/--new-key NEWKEYFILE`, to the existing `-K/--new-key-dir NEWKEYDIR` as `<sha256>.key`, or by default to the same default key directory as `keygen`. It must be outside both `SOURCE` and `DEST`, and existing files are never overwritten (no `-f`).
- `DEST` must not exist (not even as a dangling symlink), its parent must already exist, and it must not be inside `SOURCE` or contain it, including through symlink aliases. Relative paths use the current directory; leading `~/` expands to home.
- Encrypted entries (printable `encrypted:B` or older `envdirx:v1:`) are decrypted in memory, re-encrypted for the new key in the printable format, and verified with the new private key before anything is written. Values with a reserved prefix stay encrypted. **Decrypted values are never written to disk or printed.**
- **Existing plaintext entries are copied unchanged and stay plaintext**, including empty (unset) entries; run `encrypt` on `DEST` afterwards if they should be encrypted.
- Every visible entry must be a regular file with a valid name. Dotfiles other than `.envdirx.pub`/`.envdirx.key` are refused; those two are replaced by new metadata, never copied.
- `DEST` gets mode 0700, a new `.envdirx.pub` (0644), a `.envdirx.key` symlink to the new key's absolute path, and 0600 entries. It is built in a private staging directory next to `DEST` and published with one rename.

Any validation, key, or decryption error is detected before the default key directory, the new key, or the staging directory is created. A handled failure exits 111 with empty stdout and no values or key bytes in the error; nothing is published at `DEST`, and only the staging directory and new key created by this run are removed (a newly created, empty default key directory may remain). Success exits 0 with empty stdout. If the process is killed or the machine crashes, a `.envdirx-rekey-*` staging directory and the new key may be left behind; that directory holds re-encrypted entries and staged copies of existing plaintext entries, but never decrypted ciphertext values. `SOURCE` and the old key remain usable; this is not crash-proof atomic durability or secure erasure of memory. Like the rest of envdirx, it does not defend against concurrent changes to the directories by another process.

```sh
envdirx -d app.env mkdir
envdirx -d app.env keygen -k "$PWD/app.env.key"
printf 'example-token' | envdirx -d app.env set -c API_TOKEN
printf 'visible' | envdirx -d app.env set LOG_LEVEL
envdirx -d app.env rekey --output app.env.new -k "$PWD/app.env.new.key"
envdirx -d app.env.new run -- sh -c 'test "$API_TOKEN" = example-token && test "$LOG_LEVEL" = visible'
envdirx -d app.env run -- sh -c 'test "$API_TOKEN" = example-token'
mv app.env app.env.old
mv app.env.new app.env
envdirx -d app.env run -- sh -c 'test "$API_TOKEN" = example-token'
```

Switch consumers only after verifying `DEST` as above, and back up the new key separately. The pointer in `DEST` is absolute, so renaming the envdir keeps it working. **Rotation does not revoke anything**: the old key still decrypts `SOURCE` and every backup or copy of its ciphertext. Delete them only once you no longer need them; if the old key or its ciphertext may have leaked, rotate the underlying service credentials as well, since `rekey` only re-encrypts the same values.

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
uv sync
.venv/bin/python -m unittest discover -s tests -v
```

`ponytail:` This is currently for local POSIX environments. It does not defend against another user changing the directory concurrently; add dirfd-based race protection and stronger key management if that threat becomes relevant.
