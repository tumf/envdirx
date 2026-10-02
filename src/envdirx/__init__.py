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


def _key_path(directory: Path, override: str | None) -> Path:
    return Path(override) if override else directory.with_name(directory.name + ".key")


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


def _private(path: Path) -> X25519PrivateKey:
    _regular(path)
    if path.stat().st_mode & 0o077:
        raise ValueError(f"private key permissions must be 0600: {path}")
    return X25519PrivateKey.from_private_bytes(path.read_bytes())


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


def _run(directory: Path, key_path: Path, command: list[str]) -> None:
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
                private = _private(key_path)
            data = _decrypt(data, path.name, private)
        elif data.startswith(b"envdirx:"):
            raise ValueError(f"unsupported ciphertext format: {path.name}")
        if not data:
            env.pop(path.name, None)
        else:
            value = data.split(b"\n", 1)[0].rstrip(b" \t").replace(b"\x00", b"\n")
            env[os.fsdecode(path.name)] = os.fsdecode(value)
    os.execvpe(command[0], command, env)


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypt DJB envdir entries without plaintext at runtime")
    sub = parser.add_subparsers(dest="action", required=True)
    init = sub.add_parser("init", help="create a new key pair for an existing directory")
    encrypt = sub.add_parser("encrypt", help="encrypt existing plaintext entries in place")
    set_cmd = sub.add_parser("set", help="encrypt stdin as one entry (no plaintext file)")
    run = sub.add_parser("run", help="run command with envdir entries")
    for cmd in (init, encrypt, set_cmd, run):
        cmd.add_argument("directory", type=Path)
        cmd.add_argument("--key", help="private key file; default is DIRECTORY.key beside the directory")
    encrypt.add_argument("names", nargs="*", help="entries to encrypt; default: all plaintext entries")
    set_cmd.add_argument("name")
    run.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    directory = args.directory
    key_path = _key_path(directory, args.key)
    try:
        if not directory.is_dir():
            raise ValueError(f"not a directory: {directory}")
        if args.action == "init":
            if (directory / PUB).exists() or key_path.exists():
                raise ValueError("key pair already exists; refusing to overwrite")
            private = X25519PrivateKey.generate()
            raw_private = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as file:
                file.write(raw_private)
            _atomic(directory / PUB, private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), 0o644)
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
            _run(directory, key_path, args.command)
    except (OSError, ValueError) as exc:
        parser.exit(111, f"envdirx: {exc}\n")


if __name__ == "__main__":
    main()
