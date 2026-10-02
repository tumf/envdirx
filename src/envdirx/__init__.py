"""Encrypted DJB envdir files. Ciphertext remains in the envdir; keys do not."""

import argparse
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

MAGIC = b"envdirx:v1:\n"
PUB = ".envdirx.pub"
POINTER = ".envdirx.key"


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
    return MAGIC + raw_pub + nonce + _cipher(ephemeral.exchange(public)).encrypt(nonce, data, name.encode())


def _decrypt(data: bytes, name: str, private: X25519PrivateKey) -> bytes:
    if len(data) < len(MAGIC) + 32 + 12 + 16:
        raise ValueError(f"invalid ciphertext: {name}")
    offset = len(MAGIC)
    ephemeral = X25519PublicKey.from_public_bytes(data[offset:offset + 32])
    nonce = data[offset + 32:offset + 44]
    try:
        return _cipher(private.exchange(ephemeral)).decrypt(nonce, data[offset + 44:], name.encode())
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


def _init(directory: Path, override: str | None) -> None:
    envdir = directory.resolve(strict=True)
    if override:
        key = _home(override)
    else:
        absolute = Path(os.path.abspath(directory))
        if not absolute.name:
            raise ValueError(f"cannot derive default key path for {directory}; use --key")
        key = absolute.with_name(absolute.name + ".key")
    pub, pointer = directory / PUB, directory / POINTER
    for path in (pub, pointer, key):
        if os.path.lexists(path):
            raise ValueError(f"already exists; refusing to overwrite: {path}")
    if key.name in ("", ".", ".."):
        raise ValueError(f"invalid private key path: {key}")
    parent = key.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError(f"not a directory: {key.parent}")
    key = parent / key.name
    if _inside(key, envdir):
        raise ValueError(f"private key must be outside the envdir: {key}")
    reference = (str(key) + "\n").encode("utf-8")
    private = X25519PrivateKey.generate()
    created = []
    try:
        for path, data, mode in (
            (key, private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()), 0o600),
            (pointer, reference, 0o600),
            (pub, private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), 0o644),
        ):
            _create(path, data, mode)
            created.append(path)
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise


def _run(directory: Path, key: str | None, command: list[str]) -> None:
    if not command:
        raise ValueError("missing command")
    if command[0] == "--":
        command = command[1:]
    if not command:
        raise ValueError("missing command")
    env = os.environ.copy()
    private = None
    for path in _files(directory):
        data = path.read_bytes()
        if data.startswith(MAGIC):
            if private is None:
                private = _private(directory, key)
            data = _decrypt(data, path.name, private)
        elif data.startswith(b"envdirx:"):
            raise ValueError(f"unsupported ciphertext format: {path.name}")
        if not data:
            env.pop(path.name, None)
        else:
            value = data.split(b"\n", 1)[0].rstrip(b" \t").replace(b"\x00", b"\n")
            env[os.fsdecode(path.name)] = os.fsdecode(value)
    os.execvpe(command[0], command, env)


RUN_HELP = """\
The private key comes from --key when given (which must precede DIRECTORY,
because everything after DIRECTORY is the command). Otherwise it comes from
DIRECTORY/.envdirx.key, either a symlink or a regular file holding one path
line; relative targets resolve against DIRECTORY and a leading ~/ expands in
text pointers only. There is no fallback to DIRECTORY.key. The resolved key
must be a regular file outside DIRECTORY, owned by you, with mode 0600 (no
group/other bits). Plaintext-only envdirs need no key or pointer."""

INIT_HELP = """\
Writes DIRECTORY/.envdirx.pub (0644), the private key (0600) at --key or
DIRECTORY.key beside the directory, and DIRECTORY/.envdirx.key (0600)
containing the key's resolved absolute path. Parent directories are not
created; existing files are never overwritten."""


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypt DJB envdir entries without plaintext at runtime")
    sub = parser.add_subparsers(dest="action", required=True)
    text = argparse.RawDescriptionHelpFormatter
    init = sub.add_parser("init", help="create a new key pair and key pointer for an existing directory", description=INIT_HELP, formatter_class=text)
    encrypt = sub.add_parser("encrypt", help="encrypt existing plaintext entries in place")
    set_cmd = sub.add_parser("set", help="encrypt stdin as one entry (no plaintext file)")
    run = sub.add_parser("run", help="run command with envdir entries", description=RUN_HELP, formatter_class=text)
    init.add_argument("--key", help="private key destination outside DIRECTORY; default: DIRECTORY.key beside it")
    for cmd in (encrypt, set_cmd):
        cmd.add_argument("--key", help="unused; kept for compatibility (only the public key is needed)")
    run.add_argument("--key", help="private key to use instead of DIRECTORY/.envdirx.key; must precede DIRECTORY")
    for cmd in (init, encrypt, set_cmd, run):
        cmd.add_argument("directory", type=Path)
    encrypt.add_argument("names", nargs="*", help="entries to encrypt; default: all plaintext entries")
    set_cmd.add_argument("name")
    run.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    directory = args.directory
    try:
        if not directory.is_dir():
            raise ValueError(f"not a directory: {directory}")
        if args.action == "init":
            _init(directory, args.key)
        elif args.action == "encrypt":
            public = _public(directory)
            paths = [directory / name for name in args.names] if args.names else list(_files(directory))
            for path in paths:
                _name(path.name)
                _regular(path)
                data = path.read_bytes()
                if data.startswith(MAGIC):
                    if args.names:
                        raise ValueError(f"already encrypted: {path.name}")
                    continue
                _atomic(path, _encrypt(data, path.name, public), 0o600)
        elif args.action == "set":
            _name(args.name)
            path = directory / args.name
            if path.exists() or path.is_symlink():
                _regular(path)
            _atomic(path, _encrypt(sys.stdin.buffer.read(), args.name, _public(directory)), 0o600)
        else:
            _run(directory, args.key, args.command)
    except (OSError, ValueError) as exc:
        parser.exit(111, f"envdirx: {exc}\n")


if __name__ == "__main__":
    main()
