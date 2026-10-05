"""DJB envdir files, plaintext or encrypted. Ciphertext remains in the envdir; keys do not."""

import argparse
import base64
import binascii
import hashlib
import importlib.metadata
import os
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
    return MAGIC + base64.b64encode(payload)


def _decrypt(data: bytes, name: str, private: X25519PrivateKey) -> bytes:
    if data.startswith(MAGIC):
        try:
            payload = base64.b64decode(data[len(MAGIC):], validate=True)
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


def _destination(key: Path, envdir: Path) -> Path:
    """Return a fully resolved key destination outside ENVDIR whose parent exists."""
    if key.name in ("", ".", ".."):
        raise ValueError(f"invalid private key path: {key}")
    parent = key.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError(f"not a directory: {key.parent}")
    key = parent / key.name
    if _inside(key, envdir):
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


def _keygen(directory: Path, key: str | None, key_dir: str | None) -> None:
    """Write an external key (file or fingerprint-named), public key and absolute symlink pointer."""
    envdir = directory.resolve(strict=True)
    pub, pointer = directory / PUB, directory / POINTER
    _refuse_existing(pub, pointer)
    secret, public = _raw(X25519PrivateKey.generate())
    if key_dir is not None:
        folder = _home(key_dir)
        if not folder.is_dir():
            raise ValueError(f"key directory must be an existing directory: {folder}")
        destination = folder / (hashlib.sha256(public).hexdigest() + ".key")
    else:
        destination = _home(key)
        _refuse_existing(destination)  # -k names a file, even when a directory already sits there
    destination = _destination(destination, envdir)
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
  envdirx [-d DIR] keygen (-k KEYFILE | -K KEYDIR)
  envdirx [-d DIR] set [-c] NAME          < value
  envdirx [-d DIR] get [--key KEY] NAME
  envdirx [-d DIR] encrypt (NAME [NAME ...] | --all)
  envdirx [-d DIR] decrypt [--key KEY] (NAME [NAME ...] | --all)
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
on failure.

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
leading ~/ expands. Existing files are never overwritten (no force option)."""

def main() -> None:
    text = argparse.RawDescriptionHelpFormatter
    parser = argparse.ArgumentParser(prog="envdirx", description=DESCRIPTION, formatter_class=text)
    parser.add_argument("-d", "--directory", dest="envdir", type=Path, metavar="DIRECTORY", help="envdir (default: ./.envs); must precede the subcommand")
    parser.add_argument("-V", "--version", action="version", version=importlib.metadata.version("envdirx"), help="print the installed version and exit; global like -d")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("mkdir", help="create the envdir (mode 0700) and missing parents")
    keygen = sub.add_parser("keygen", help="create a key pair and .envdirx.key symlink", description=KEYGEN_HELP, formatter_class=text)
    set_cmd = sub.add_parser("set", help="store stdin as one entry (plaintext by default)", description=SET_HELP, formatter_class=text)
    get = sub.add_parser("get", help="print one entry's raw value", description=GET_HELP, formatter_class=text)
    encrypt = sub.add_parser("encrypt", help="encrypt plaintext entries in place (public key only)", usage="%(prog)s (NAME [NAME ...] | --all)", description=ENCRYPT_HELP, formatter_class=text)
    decrypt = sub.add_parser("decrypt", help="decrypt entries in place to plaintext on disk", usage="%(prog)s [--key KEY] (NAME [NAME ...] | --all)", description=DECRYPT_HELP, formatter_class=text)
    run = sub.add_parser("run", help="run command with envdir entries", description=RUN_HELP, formatter_class=text)
    destination = keygen.add_mutually_exclusive_group(required=True)
    destination.add_argument("-k", "--key", help="private key file to create outside the envdir")
    destination.add_argument("-K", "--key-dir", help="existing directory for <sha256>.key")
    set_cmd.add_argument("-c", "--encrypt", action="store_true", help="encrypt with .envdirx.pub instead of storing plaintext")
    set_cmd.add_argument("name")
    get.add_argument("--key", help="private key to use instead of .envdirx.key")
    get.add_argument("name")
    for transform, verb in ((encrypt, "encrypt"), (decrypt, "decrypt")):
        transform.add_argument("--all", action="store_true", help=f"{verb} every visible entry that needs it")
        transform.add_argument("names", nargs="*", metavar="NAME", help=f"entry to {verb}")
    decrypt.add_argument("--key", help="private key to use instead of .envdirx.key")
    run.add_argument("--key", help="private key to use instead of .envdirx.key; must precede --")
    run.add_argument("command", nargs=argparse.REMAINDER, help="-- COMMAND [ARGS...]")
    args = parser.parse_args()
    directory = args.envdir if args.envdir is not None else Path(DEFAULT_DIRECTORY)
    if args.action == "run" and (args.command[:1] != ["--"] or len(args.command) < 2):
        run.error("expected -- COMMAND [ARGS...]")
    if args.action in ("encrypt", "decrypt"):
        transform = encrypt if args.action == "encrypt" else decrypt
        if args.all == bool(args.names):
            transform.error("expected NAME [NAME ...] or --all (not both)")
        if len(set(args.names)) != len(args.names):
            transform.error("duplicate entry name")
    try:
        if args.action == "mkdir":
            _mkdir(directory)
            return
        if not directory.is_dir():
            raise ValueError(f"not a directory: {directory}")
        if args.action == "keygen":
            _keygen(directory, args.key, args.key_dir)
        elif args.action in ("encrypt", "decrypt"):
            _transform(directory, args.names, args.action == "decrypt", getattr(args, "key", None))
        elif args.action == "set":
            _set(directory, args.name, sys.stdin.buffer.read(), args.encrypt)
        elif args.action == "get":
            value = _get(directory, args.key, args.name)
            sys.stdout.buffer.write(value)
            sys.stdout.buffer.flush()
        else:
            _run(directory, args.key, args.command[1:])
    except (OSError, ValueError) as exc:
        parser.exit(111, f"envdirx: {exc}\n")


if __name__ == "__main__":
    main()
