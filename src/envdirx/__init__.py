"""DJB envdir files, plaintext or encrypted. Ciphertext remains in the envdir; keys do not."""

import argparse
import base64
import binascii
import contextlib
import ctypes
import hashlib
import importlib.metadata
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

MAGIC = b"encrypted:B"
LEGACY_MAGIC = b"envdirx:v1:\n"
PUB = ".envdirx.pub"
POINTER = ".envdirx.key"
RESERVED = (b"envdirx:", b"encrypted:")
DEFAULT_DIRECTORY = ".envs"


def _reserved(data: bytes) -> bool:
    return data.startswith(RESERVED)


def _home(text: str) -> Path:
    # Only a leading "~/" expands; "~user" and symlink targets stay literal.
    return Path.home() / text[2:] if text.startswith("~/") else Path(text)


def _inside(path: Path, directory: Path) -> bool:
    return path == directory or directory in path.parents


def _pointer(directory: Path) -> Path:
    """Return the unresolved key location named by DIRECTORY/.envdirx.key."""
    path = directory / POINTER
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        raise ValueError(f"missing key pointer: {path}") from None
    if stat.S_ISLNK(mode):
        return path  # resolved (relative to the envdir) by _resolve_key
    if not stat.S_ISREG(mode):
        raise ValueError(f"key pointer must be a symlink or regular file: {path}")
    data = path.read_bytes()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(f"key pointer is not UTF-8: {path}") from None
    text = text.removesuffix("\r\n") if text.endswith("\r\n") else text.removesuffix("\n")
    if not text or "\n" in text or "\r" in text or "\x00" in text:
        raise ValueError(f"key pointer must contain one non-empty path line: {path}")
    return directory / _home(text)


def _check_key(mode: int, uid: int, euid: int, path: Path) -> None:
    if not stat.S_ISREG(mode):
        raise ValueError(f"private key is not a regular file: {path}")
    if uid != euid:
        raise ValueError(f"private key must be owned by the current user: {path}")
    if mode & 0o077:
        raise ValueError(f"private key permissions must be 0600: {path}")


def _resolve_key(directory: Path, override: str | None) -> Path:
    """Resolve and validate the private key: explicit --key, else the fixed pointer."""
    candidate = _home(override) if override else _pointer(directory)
    try:
        path = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"cannot resolve private key {candidate}: {exc.strerror or exc}") from None
    if _inside(path, directory.resolve(strict=True)):
        raise ValueError(f"private key must be outside the envdir: {path}")
    st = path.stat()
    _check_key(st.st_mode, st.st_uid, os.geteuid(), path)
    return path


def _atomic(path: Path, data: bytes, mode: int) -> None:
    fd, name = tempfile.mkstemp(prefix=".envdirx-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _name(name: str) -> None:
    if not name or name.startswith(".") or name in (".", "..") or "=" in name or "\x00" in name or "/" in name:
        raise ValueError(f"invalid environment variable name: {name!r}")


def _regular(path: Path) -> None:
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f"not a regular file: {path}")


def _public(directory: Path) -> X25519PublicKey:
    path = directory / PUB
    _regular(path)
    return X25519PublicKey.from_public_bytes(path.read_bytes())


def _private(directory: Path, override: str | None) -> X25519PrivateKey:
    path = _resolve_key(directory, override)
    try:
        return X25519PrivateKey.from_private_bytes(path.read_bytes())
    except ValueError:
        raise ValueError(f"invalid private key: {path}") from None


def _cipher(shared: bytes) -> ChaCha20Poly1305:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"envdirx:v1").derive(shared)
    return ChaCha20Poly1305(key)


def _encrypt(data: bytes, name: str, public: X25519PublicKey) -> bytes:
    ephemeral = X25519PrivateKey.generate()
    nonce = os.urandom(12)
    raw_pub = ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    payload = raw_pub + nonce + _cipher(ephemeral.exchange(public)).encrypt(nonce, data, name.encode())
    return MAGIC + base64.b64encode(payload) + b"\n"


def _decrypt(data: bytes, name: str, private: X25519PrivateKey) -> bytes:
    if data.startswith(MAGIC):
        try:
            payload = base64.b64decode(data[len(MAGIC):].removesuffix(b"\n"), validate=True)
        except binascii.Error:
            raise ValueError(f"invalid ciphertext: {name}") from None
    else:
        payload = data[len(LEGACY_MAGIC):]
    if len(payload) < 32 + 12 + 16:
        raise ValueError(f"invalid ciphertext: {name}")
    ephemeral = X25519PublicKey.from_public_bytes(payload[:32])
    nonce = payload[32:44]
    try:
        return _cipher(private.exchange(ephemeral)).decrypt(nonce, payload[44:], name.encode())
    except InvalidTag as exc:
        raise ValueError(f"decryption failed: {name}") from exc


def _files(directory: Path):
    for path in sorted(directory.iterdir()):
        if path.name.startswith("."):
            continue
        _name(path.name)
        _regular(path)
        yield path


def _create(path: Path, data: bytes, mode: int) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as file:
            os.fchmod(file.fileno(), mode)
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
    except BaseException:
        path.unlink(missing_ok=True)  # O_EXCL guarantees this invocation created it
        raise


def _destination(key: Path, *envdirs: Path) -> Path:
    """Return a fully resolved key destination outside every ENVDIR whose parent exists."""
    if key.name in ("", ".", ".."):
        raise ValueError(f"invalid private key path: {key}")
    parent = key.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError(f"not a directory: {key.parent}")
    key = parent / key.name
    if any(_inside(key, envdir) for envdir in envdirs):
        raise ValueError(f"private key must be outside the envdir: {key}")
    if os.path.lexists(key):
        raise ValueError(f"already exists; refusing to overwrite: {key}")
    return key


def _raw(private: X25519PrivateKey) -> tuple[bytes, bytes]:
    secret = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return secret, private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _link(path: Path, target: Path) -> None:
    os.symlink(target, path)  # fails if PATH exists, like O_EXCL


def _write_all(steps) -> None:
    """Run (path, writer) steps in order; on failure remove only what was created."""
    created = []
    try:
        for path, write in steps:
            write(path)
            created.append(path)
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise


def _refuse_existing(*paths: Path) -> None:
    for path in paths:
        if os.path.lexists(path):
            raise ValueError(f"already exists; refusing to overwrite: {path}")


def _key_store(environ=os.environ) -> Path:
    """Return the implicit key directory: $XDG_DATA_HOME/envdirx/keys, else ~/.local/share/envdirx/keys.

    Per the XDG spec an empty or relative XDG_DATA_HOME is ignored; a literal ~ is never expanded.
    """
    data = environ.get("XDG_DATA_HOME", "")
    if data and os.path.isabs(data):
        return Path(data) / "envdirx" / "keys"
    try:
        home = Path.home()
    except RuntimeError as exc:
        raise ValueError(f"cannot determine home directory for the default key directory: {exc}") from None
    if not home.is_absolute():
        raise ValueError(f"home directory must be absolute for the default key directory: {home}")
    return home / ".local" / "share" / "envdirx" / "keys"


def _make_key_store(folder: Path, *envdirs: Path) -> Path:
    """Validate FOLDER as outside every ENVDIR, then create its missing directories at 0700; return it resolved.

    The deepest existing path is resolved strictly (dangling or cyclic links fail),
    so symlink aliases of the envdir are rejected before anything is created.
    Existing directories keep their modes.
    """
    missing = []
    existing = folder
    while not os.path.lexists(existing):
        missing.append(existing.name)
        existing = existing.parent
    if ".." in missing:
        raise ValueError(f"invalid default key directory: {folder}")
    try:
        resolved = existing.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"cannot resolve default key directory {existing}: {exc}") from None
    if not resolved.is_dir():
        raise ValueError(f"not a directory: {existing}")
    target = resolved.joinpath(*reversed(missing))
    if any(_inside(target, envdir) for envdir in envdirs):
        raise ValueError(f"default key directory must be outside the envdir: {target}")
    path = resolved
    for name in reversed(missing):
        path = path / name
        os.mkdir(path, 0o700)
        os.chmod(path, 0o700)  # umask must not loosen or tighten a new key directory
    return target


def _key_destination(key: str | None, key_dir: str | None, public: bytes, *envdirs: Path) -> Path:
    """Select a new private-key path (-k file, -K directory or default store) outside every ENVDIR.

    Only the default store may be created here, and only after it is validated.
    """
    if key is None and key_dir is None:
        folder = _make_key_store(_key_store(), *envdirs)
        destination = folder / (hashlib.sha256(public).hexdigest() + ".key")
    elif key_dir is not None:
        folder = _home(key_dir)
        if not folder.is_dir():
            raise ValueError(f"key directory must be an existing directory: {folder}")
        destination = folder / (hashlib.sha256(public).hexdigest() + ".key")
    else:
        destination = _home(key)
        _refuse_existing(destination)  # -k names a file, even when a directory already sits there
    return _destination(destination, *envdirs)


def _keygen(directory: Path, key: str | None, key_dir: str | None) -> None:
    """Write an external key (file or fingerprint-named), public key and absolute symlink pointer."""
    envdir = directory.resolve(strict=True)
    pub, pointer = directory / PUB, directory / POINTER
    _refuse_existing(pub, pointer)
    secret, public = _raw(X25519PrivateKey.generate())
    destination = _key_destination(key, key_dir, public, envdir)
    _write_all((
        (destination, lambda path: _create(path, secret, 0o600)),
        (pub, lambda path: _create(path, public, 0o644)),
        (pointer, lambda path: _link(path, destination)),
    ))


def _mkdir(directory: Path) -> None:
    if directory.is_dir():
        return  # existing directories are left untouched (no chmod)
    if os.path.lexists(directory):
        raise ValueError(f"not a directory: {directory}")
    directory.parent.mkdir(parents=True, exist_ok=True)
    os.mkdir(directory, 0o700)
    os.chmod(directory, 0o700)  # umask must not loosen or tighten the new envdir


def _value(path: Path, private) -> bytes:
    """Return the stored plaintext bytes of an entry; PRIVATE() supplies the key on demand."""
    data = path.read_bytes()
    if data.startswith((MAGIC, LEGACY_MAGIC)):
        return _decrypt(data, path.name, private())
    if _reserved(data):
        raise ValueError(f"unsupported ciphertext format: {path.name}")
    return data


def _get(directory: Path, key: str | None, name: str) -> bytes:
    _name(name)
    path = directory / name
    _regular(path)
    return _value(path, lambda: _private(directory, key))


def _get_first(directories: list[Path], key: str | None, name: str) -> bytes:
    _name(name)
    for directory in directories:
        if not directory.is_dir():
            raise ValueError(f"not a directory: {directory}")
        path = directory / name
        try:
            _regular(path)
        except FileNotFoundError:
            continue
        return _value(path, lambda: _private(directory, key))
    raise ValueError(f"missing entry: {name}")


def _set(directory: Path, name: str, data: bytes, encrypt: bool) -> None:
    _name(name)
    path = directory / name
    if path.exists() or path.is_symlink():
        _regular(path)
    if encrypt:
        data = _encrypt(data, name, _public(directory))
    elif _reserved(data):
        raise ValueError("plaintext must not start with a reserved ciphertext prefix; use set -c")
    _atomic(path, data, 0o600)


def _transform(directory: Path, names: list[str], decrypt: bool, key: str | None) -> None:
    """Encrypt or decrypt NAMES (or, when empty, every visible entry) in place.

    The whole batch is read, validated and transformed in memory before the
    first write, so any validation, key or decryption failure changes nothing.
    Each entry is then replaced atomically on its own; a late write failure
    keeps earlier replacements (not a transaction) and the failed target intact.
    """
    explicit = bool(names)
    for name in names:
        _name(name)  # validate raw names before any path is built
    paths = [directory / name for name in names] if explicit else list(_files(directory))
    work = []
    for path in paths:
        _regular(path)
        data = path.read_bytes()
        if data.startswith((MAGIC, LEGACY_MAGIC)):
            encrypted = True
        elif _reserved(data):
            raise ValueError(f"unsupported ciphertext format: {path.name}")
        else:
            encrypted = False
        if encrypted != decrypt:
            if explicit:
                raise ValueError(f"already {'decrypted' if decrypt else 'encrypted'}: {path.name}")
            continue
        work.append((path, data))
    if not work:
        return  # nothing to convert: no key is looked up
    if decrypt:
        private = _private(directory, key)
        prepared = []
        for path, data in work:
            plain = _decrypt(data, path.name, private)
            if _reserved(plain):
                # Restored plaintext would be misread as ciphertext; keep it encrypted.
                raise ValueError(f"decrypted value starts with a reserved ciphertext prefix; kept encrypted: {path.name}")
            prepared.append((path, plain))
    else:
        public = _public(directory)
        prepared = [(path, _encrypt(data, path.name, public)) for path, data in work]
    for path, data in prepared:
        _atomic(path, data, 0o600)


EXCHANGE_UNSUPPORTED = "atomic directory exchange is not supported on this platform/libc"


def _native_exchange(platform: str, libc):
    """Bind libc's atomic exchange: Darwin renamex_np(RENAME_SWAP), Linux renameat2(RENAME_EXCHANGE).

    There is deliberately no two-rename fallback: it would leave a window in
    which the active envdir path does not exist.
    """
    try:
        if platform == "darwin":
            function = libc.renamex_np
            function.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
            function.restype = ctypes.c_int
            return lambda a, b: function(a, b, 2)  # RENAME_SWAP
        if platform == "linux":
            function = libc.renameat2
            function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
            function.restype = ctypes.c_int
            return lambda a, b: function(-100, a, -100, b, 2)  # AT_FDCWD, RENAME_EXCHANGE
    except AttributeError:
        pass  # libc without the wrapper
    raise ValueError(EXCHANGE_UNSUPPORTED)


def _exchange(a: Path, b: Path) -> None:
    """Atomically swap the directory entries A and B."""
    call = _native_exchange(sys.platform, ctypes.CDLL(None, use_errno=True))
    if call(os.fsencode(a), os.fsencode(b)) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(a), None, str(b))


def _probe_exchange(parent: Path) -> None:
    """Swap two private empty sibling directories so an unsupported exchange fails before any key exists."""
    probes = []
    try:
        for _ in range(2):
            probes.append(Path(tempfile.mkdtemp(prefix=".envdirx-probe-", dir=parent)))
        _exchange(*probes)
    except OSError as exc:
        raise ValueError(f"atomic directory exchange failed in {parent}: {exc.strerror or exc}") from None
    finally:
        for probe in probes:
            with contextlib.suppress(OSError):
                probe.rmdir()


def _rotation_target(directory: Path) -> Path:
    """Return DIRECTORY's real path once it is safe to replace by a sibling exchange."""
    envdir = directory.resolve(strict=True)
    if envdir == Path(envdir.anchor) or os.path.ismount(envdir):
        raise ValueError(f"refusing to rotate a filesystem root or mountpoint: {envdir}")
    if _inside(Path.cwd().resolve(), envdir):
        raise ValueError(f"refusing to rotate the envdir containing the current directory; run from outside it: {envdir}")
    if not os.access(envdir.parent, os.W_OK | os.X_OK):
        raise ValueError(f"the envdir's parent must be writable for staging: {envdir.parent}")
    return envdir


def _identity(path: Path) -> tuple[int, int]:
    st = os.lstat(path)
    return st.st_dev, st.st_ino


def _commit_state(envdir: Path, original: tuple[int, int], staged: tuple[int, int] | None) -> bool | None:
    """True once ENVDIR is the staged inode, False while it is still ORIGINAL, None when unknown."""
    try:
        active = _identity(envdir)
    except OSError:
        return None
    if staged is not None and active == staged:
        return True
    return False if active == original else None


def _remove_tree(path: Path) -> None:
    """Remove PATH after making its directories owner-accessible; symlinks are removed, never followed."""
    os.chmod(path, 0o700)
    for root, dirs, _ in os.walk(path):
        for name in dirs:
            child = os.path.join(root, name)
            if not os.path.islink(child):
                os.chmod(child, 0o700)
    shutil.rmtree(path)


def _retire(envdir: Path, old: Path, key: Path) -> None:
    """After commit: make the exchange durable and remove the previous tree at OLD. Never touches KEY."""
    problems = []
    try:
        fd = os.open(envdir.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        problems.append(f"syncing {envdir.parent} failed ({exc.strerror or exc}), so the rotation may not survive a power loss")
    try:
        _remove_tree(old)
    except OSError as exc:
        problems.append(f"removing the previous envdir failed ({exc.strerror or exc}); it remains at {old}")
    if problems:
        raise ValueError(f"rotation completed: {envdir} now uses the new key {key}; but " + "; ".join(problems))


def _rekey(directory: Path, key: str | None, new_key: str | None, new_key_dir: str | None) -> None:
    """Rotate DIRECTORY in place to a fresh external key; the old key is never modified.

    Everything is validated, decrypted, re-encrypted and verified in memory
    before the first write. A complete private sibling staging tree is then
    swapped with the resolved envdir by one native atomic exchange, the commit
    point: the path always names a complete envdir. Commit is judged from the
    active inode, not from control flow. Before commit a failure removes only
    this run's staging tree and new key; after commit the new key is never
    removed. Decrypted values never reach the disk: only ciphertext is staged.
    """
    envdir = _rotation_target(directory)
    original = os.lstat(envdir)
    entries = []
    for path in sorted(envdir.iterdir()):
        if path.name in (PUB, POINTER):
            continue  # replaced by new metadata, never copied
        if path.name.startswith("."):
            raise ValueError(f"unexpected metadata file: {path}")
        _name(path.name)
        _regular(path)
        mode = stat.S_IMODE(path.lstat().st_mode)
        data = path.read_bytes()
        if not data.startswith((MAGIC, LEGACY_MAGIC)) and _reserved(data):
            raise ValueError(f"unsupported ciphertext format: {path.name}")
        entries.append((path.name, data, data.startswith((MAGIC, LEGACY_MAGIC)), mode))
    if any(encrypted for _, _, encrypted, _ in entries):
        old = _private(envdir, key)  # resolved only when ciphertext exists
        entries = [(name, _decrypt(data, name, old) if encrypted else data, encrypted, mode) for name, data, encrypted, mode in entries]
    private = X25519PrivateKey.generate()
    secret, public = _raw(private)
    prepared = []
    for name, data, encrypted, mode in entries:
        if encrypted:
            ciphertext = _encrypt(data, name, private.public_key())
            if _decrypt(ciphertext, name, private) != data:
                raise ValueError(f"re-encryption verification failed: {name}")
            data, mode = ciphertext, 0o600
        prepared.append((name, data, mode))  # plaintext entries keep their bytes and mode
    del entries
    _probe_exchange(envdir.parent)
    key_path = _key_destination(new_key, new_key_dir, public, envdir)
    _create(key_path, secret, 0o600)
    staging = staged = None
    try:
        staging = Path(tempfile.mkdtemp(prefix=".envdirx-rekey-", dir=envdir.parent))
        os.chmod(staging, 0o700)  # writable and readable by us until fully written
        fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY)
        try:
            _create(staging / PUB, public, 0o644)
            _link(staging / POINTER, key_path)
            for name, data, mode in prepared:
                _create(staging / name, data, mode)
            os.fchmod(fd, stat.S_IMODE(original.st_mode))
            os.fsync(fd)
        finally:
            os.close(fd)
        staged = _identity(staging)
        _exchange(envdir, staging)  # commit point
    except BaseException as exc:
        reason = "interrupted" if isinstance(exc, KeyboardInterrupt) else str(exc)
        state = _commit_state(envdir, (original.st_dev, original.st_ino), staged)
        if state is None:
            raise ValueError(f"rotation state is unknown ({reason}); kept the new key {key_path} and staging {staging}: "
                             f"check which key {envdir / POINTER} references before removing anything") from None
        if state:
            raise ValueError(f"rotation completed: {envdir} now uses the new key {key_path}; but it was {reason} "
                             f"before cleanup; the previous envdir remains at {staging}") from None
        if staging is not None:
            with contextlib.suppress(OSError):
                _remove_tree(staging)
        key_path.unlink(missing_ok=True)  # _create's O_EXCL guarantees this invocation created it
        if isinstance(exc, KeyboardInterrupt):
            raise ValueError(f"interrupted before publication; {envdir} and the old key are unchanged") from None
        raise
    try:
        _retire(envdir, staging, key_path)
    except KeyboardInterrupt:
        raise ValueError(f"rotation completed: {envdir} now uses the new key {key_path}; but cleanup was interrupted; "
                         f"the previous envdir may remain at {staging}") from None


def _run(directory: Path, key: str | None, command: list[str]) -> None:
    env = os.environ.copy()
    keys = []

    def private():
        if not keys:
            keys.append(_private(directory, key))
        return keys[0]

    for path in _files(directory):
        data = _value(path, private)
        if not data:
            env.pop(path.name, None)
        else:
            value = data.split(b"\n", 1)[0].rstrip(b" \t").replace(b"\x00", b"\n")
            env[os.fsdecode(path.name)] = os.fsdecode(value)
    os.execvpe(command[0], command, env)


DESCRIPTION = """\
Store DJB envdir entries as plaintext or encrypted files and run commands with
them. -d/--directory goes BEFORE the subcommand and defaults to ./.envs
relative to the current directory; only mkdir creates it. -V/--version is
global too: it prints the installed version and reads no envdir.

  envdirx (-V | --version)
  envdirx [-d DIR] mkdir
  envdirx [-d DIR] keygen [-k KEYFILE | -K KEYDIR]
  envdirx [-d DIR] set [-c] NAME          < value
  envdirx [-d DIR ...] get [--key KEY] NAME
  envdirx [-d DIR] encrypt (NAME [NAME ...] | --all)
  envdirx [-d DIR] decrypt [--key KEY] (NAME [NAME ...] | --all)
  envdirx [-d DIR] rekey [--key OLDKEY] [-k NEWKEYFILE | -K NEWKEYDIR]
  envdirx [-d DIR] run [--key KEY] -- COMMAND [ARGS...]"""

KEY_HELP = """\
An encrypted entry needs the private key: --key when given (relative to the
current directory, leading ~/ expanded), otherwise DIRECTORY/.envdirx.key,
either a symlink or a regular file holding one path line; relative targets
resolve against DIRECTORY and a leading ~/ expands in text pointers only.
There is no fallback to an adjacent key. The resolved key must be a regular
file outside DIRECTORY, owned by you, with mode 0600 (no group/other bits).
Plaintext entries need no key or pointer."""

RUN_HELP = """\
Runs COMMAND with the envdir applied (first line, trailing blanks trimmed,
NUL becomes newline, empty file unsets). The literal -- separator is
required, and --key must precede it; everything after -- belongs to COMMAND.

""" + KEY_HELP

GET_HELP = """\
Writes the stored value to stdout exactly: the plaintext bytes, or the
decrypted original bytes. No newline is added and no envdir trimming is
applied. This deliberately discloses a secret; nothing is written to stdout
on failure. Repeat -d before get to search directories in priority order;
the first existing entry wins. Missing entries are skipped, but an invalid
directory or entry fails without falling back to a lower-priority value.

""" + KEY_HELP

SET_HELP = """\
Reads the value from stdin and stores it atomically (mode 0600). Without -c
the exact bytes are stored as plaintext and no key is read; values starting
with reserved "envdirx:" or "encrypted:" prefixes are refused; use -c. With -c
the value is encrypted using only DIRECTORY/.envdirx.pub."""

SELECT_HELP = """\
Name one or more entries, or pass --all for every visible entry (dotfiles such
as .envdirx.pub/.envdirx.key are never touched); one of the two is required.
A named entry already in the target state is an error; --all skips it. The
whole batch is validated and prepared before the first write, so a failure
changes nothing; each entry is then replaced atomically (mode 0600) on its
own. This is not a transaction: if a write fails part-way, entries replaced
before it stay converted and the failing entry keeps its old bytes."""

ENCRYPT_HELP = """\
Encrypts plaintext entries in place using only DIRECTORY/.envdirx.pub; no
private key is read. The public key is read only when something needs
encrypting.

""" + SELECT_HELP

DECRYPT_HELP = """\
Decrypts envdirx ciphertext entries in place back to their exact original
bytes. This deliberately writes the secret to disk as plaintext. A value
whose original bytes start with the reserved "envdirx:" prefix cannot be
stored as plaintext and is refused (the entry stays encrypted); read it with
get and redirect it to a file outside the envdir instead. The private key is
read only when something needs decrypting.

""" + SELECT_HELP + """

""" + KEY_HELP

KEYGEN_HELP = """\
Creates a new X25519 key pair: the private key (0600) outside DIRECTORY at
-k KEYFILE, or in the existing -K KEYDIR named <sha256 of public key>.key;
DIRECTORY/.envdirx.pub (0644); and DIRECTORY/.envdirx.key, a symlink to the
key's resolved absolute path. Relative paths use the current directory and a
leading ~/ expands. Existing files are never overwritten (no force option).

Without -k or -K the key goes to the default directory
$XDG_DATA_HOME/envdirx/keys when XDG_DATA_HOME is a non-empty absolute path,
otherwise $HOME/.local/share/envdirx/keys, named <sha256 of public key>.key.
Only this default directory is created when missing (mode 0700); existing
directories keep their modes. Reading never consults it: get, run and
decrypt use DIRECTORY/.envdirx.key or --key."""

REKEY_HELP = """\
Examples:
  envdirx rekey
  envdirx -d ./app.env rekey -k ~/keys/app.env.key

This rotates the encryption key of DIR in place: encrypted entries are
re-encrypted under a fresh key and DIR keeps its path, so consumers need no
switch-over. Plaintext entries stay plaintext. The new key is generated
automatically; no keygen step is needed. The old key is never deleted.

Directories and keys:
  DIR: -d DIR before rekey (default: ./.envs); symlink aliases stay intact.
    DIR must not be a filesystem root or mountpoint, must not contain the
    current directory, and its parent must be writable.
  OLD key: --key OLDKEY overrides DIR/.envdirx.key for decryption.
    Unlike keygen, --key selects an existing OLD key; it never creates one.
    The old key is read only when DIR contains encrypted entries.
  NEW key: -k/--new-key NEWKEYFILE sets the private key file to CREATE;
    -K/--new-key-dir NEWKEYDIR selects an existing directory for <sha256>.key.
    Omit both to use $XDG_DATA_HOME/envdirx/keys (absolute XDG_DATA_HOME only),
    else $HOME/.local/share/envdirx/keys, created mode 0700 when missing.
    The new key must be outside DIR; it is never overwritten.
    Relative paths use the current directory and a leading ~/ expands.

Safety:
  Encrypted entries (printable or legacy binary) are decrypted in memory,
  re-encrypted in printable format and verified before writing; decrypted
  values are never written to disk. Existing plaintext is copied unchanged
  with its mode. Dotfiles other than .envdirx.pub/.envdirx.key are refused;
  those two are replaced with a new public key (0644) and absolute
  private-key symlink. DIR keeps its mode; re-encrypted entries and the new
  private key are 0600. A complete sibling staging directory replaces DIR by
  one atomic directory exchange (renamex_np on macOS, renameat2 on Linux);
  without it rekey fails and changes nothing. On failure before the exchange,
  DIR and the old key are unchanged and the new key is removed; after it, the
  new key is kept even if cleanup fails. A killed run may leave a
  .envdirx-rekey-* directory or a new key behind: check which key
  DIR/.envdirx.key points to before deleting anything. Processes reading DIR
  during the exchange may fail; stop writers first. The old key still decrypts
  old copies of DIR. If a key leaked, rotate the underlying service
  credentials too."""

def main() -> None:
    text = argparse.RawDescriptionHelpFormatter
    parser = argparse.ArgumentParser(prog="envdirx", description=DESCRIPTION, formatter_class=text)
    parser.add_argument("-d", "--directory", dest="envdirs", type=Path, action="append", metavar="DIRECTORY", help="envdir (default: ./.envs); repeat for get priority order; must precede the subcommand")
    parser.add_argument("-V", "--version", action="version", version=importlib.metadata.version("envdirx"), help="print the installed version and exit; global like -d")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("mkdir", help="create the envdir (mode 0700) and missing parents")
    keygen = sub.add_parser("keygen", help="create a key pair and .envdirx.key symlink", description=KEYGEN_HELP, formatter_class=text)
    set_cmd = sub.add_parser("set", help="store stdin as one entry (plaintext by default)", description=SET_HELP, formatter_class=text)
    get = sub.add_parser("get", help="print one entry's raw value", description=GET_HELP, formatter_class=text)
    encrypt = sub.add_parser("encrypt", help="encrypt plaintext entries in place (public key only)", usage="%(prog)s (NAME [NAME ...] | --all)", description=ENCRYPT_HELP, formatter_class=text)
    decrypt = sub.add_parser("decrypt", help="decrypt entries in place to plaintext on disk", usage="%(prog)s [--key KEY] (NAME [NAME ...] | --all)", description=DECRYPT_HELP, formatter_class=text)
    rekey = sub.add_parser("rekey", help="rotate the encryption key", usage="%(prog)s [--key OLDKEY] [-k NEWKEYFILE | -K NEWKEYDIR]", description=REKEY_HELP, formatter_class=text)
    run = sub.add_parser("run", help="run command with envdir entries", description=RUN_HELP, formatter_class=text)
    destination = keygen.add_mutually_exclusive_group()
    destination.add_argument("-k", "--key", help="private key file to create outside the envdir")
    destination.add_argument("-K", "--key-dir", help="existing directory for <sha256>.key (default: created XDG data directory envdirx/keys)")
    set_cmd.add_argument("-c", "--encrypt", action="store_true", help="encrypt with .envdirx.pub instead of storing plaintext")
    set_cmd.add_argument("name")
    get.add_argument("--key", help="private key to use instead of .envdirx.key")
    get.add_argument("name")
    for transform, verb in ((encrypt, "encrypt"), (decrypt, "decrypt")):
        transform.add_argument("--all", action="store_true", help=f"{verb} every visible entry that needs it")
        transform.add_argument("names", nargs="*", metavar="NAME", help=f"entry to {verb}")
    decrypt.add_argument("--key", help="private key to use instead of .envdirx.key")
    rekey.add_argument("--output", nargs="?", const="", help=argparse.SUPPRESS)  # removed; detected for a clear error
    rekey.add_argument("--key", metavar="OLDKEY", help="OLD private key for decrypting DIR instead of DIR/.envdirx.key")
    new_key = rekey.add_mutually_exclusive_group()
    new_key.add_argument("-k", "--new-key", metavar="NEWKEYFILE", help="NEW private key file to create outside DIR")
    new_key.add_argument("-K", "--new-key-dir", metavar="NEWKEYDIR", help="existing directory for the NEW <sha256>.key (default: created XDG data directory envdirx/keys)")
    run.add_argument("--key", help="private key to use instead of .envdirx.key; must precede --")
    run.add_argument("command", nargs=argparse.REMAINDER, help="-- COMMAND [ARGS...]")
    args = parser.parse_args()
    directories = args.envdirs or [Path(DEFAULT_DIRECTORY)]
    directory = directories[0]
    if args.action != "get" and len(directories) > 1:
        parser.error("multiple -d directories are supported only for get")
    if args.action == "rekey" and args.output is not None:
        parser.error("--output was removed: rekey now rotates the key in place at DIR (use -d DIR)")
    if args.action == "run" and (args.command[:1] != ["--"] or len(args.command) < 2):
        run.error("expected -- COMMAND [ARGS...]")
    if args.action in ("encrypt", "decrypt"):
        transform = encrypt if args.action == "encrypt" else decrypt
        if args.all == bool(args.names):
            transform.error("expected NAME [NAME ...] or --all (not both)")
        if len(set(args.names)) != len(args.names):
            transform.error("duplicate entry name")
    try:
        if args.action == "get":
            value = _get_first(directories, args.key, args.name)
            sys.stdout.buffer.write(value)
            sys.stdout.buffer.flush()
            return
        if args.action == "mkdir":
            _mkdir(directory)
            return
        if not directory.is_dir():
            raise ValueError(f"not a directory: {directory}")
        if args.action == "keygen":
            _keygen(directory, args.key, args.key_dir)
        elif args.action in ("encrypt", "decrypt"):
            _transform(directory, args.names, args.action == "decrypt", getattr(args, "key", None))
        elif args.action == "rekey":
            _rekey(directory, args.key, args.new_key, args.new_key_dir)
        elif args.action == "set":
            _set(directory, args.name, sys.stdin.buffer.read(), args.encrypt)
        else:
            _run(directory, args.key, args.command[1:])
    except KeyboardInterrupt:
        parser.exit(130)
    except (OSError, ValueError) as exc:
        parser.exit(111, f"envdirx: {exc}\n")


if __name__ == "__main__":
    main()
