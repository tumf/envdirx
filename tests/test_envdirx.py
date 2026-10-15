import base64
import contextlib
import ctypes
import errno
import importlib.metadata
import hashlib
import io
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import tomllib
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import envdirx  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402

CLI = [sys.executable, "-m", "envdirx"]
SECRET = b"top-secret-value"
SHOW = [sys.executable, "-c", "import os,json;print(json.dumps({k:os.environ.get(k) for k in ('TOKEN','EMPTY','UNSET','MULTI','PLAIN')}))"]


class Fixture:
    """A temporary parent directory holding an envdir and its external key."""

    def __init__(self, test):
        self.test = test
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir()
        self.directory = self.root / "service"
        self.directory.mkdir()
        self.marker = self.root / "child-ran"
        self.env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "UNSET": "inherited", "HOME": str(self.home)}
        self.env.pop("XDG_DATA_HOME", None)  # never touch the real default key store

    def call(self, *args, input=None, cwd=None, umask=-1):
        return subprocess.run([*CLI, *map(str, args)], env=self.env, input=input, capture_output=True, cwd=cwd or self.root, timeout=30, umask=umask)

    def on(self, action, *args, input=None, cwd=None, directory=None, umask=-1):
        """Call ACTION with the envdir selected through the global -d option."""
        return self.call("-d", directory or self.directory, action, *args, input=input, cwd=cwd, umask=umask)

    def snapshot(self):
        """Every path under the fixture root with its bytes or link target."""
        return {p: (os.readlink(p) if p.is_symlink() else None if p.is_dir() else p.read_bytes()) for p in self.root.rglob("*")}

    def keygen_encrypted(self):
        """keygen ROOT/service.key (symlink pointer) and store an encrypted TOKEN."""
        result = self.on("keygen", "-k", self.root / "service.key")
        self.test.assertEqual(result.returncode, 0, result.stderr)
        self.test.assertEqual(self.on("set", "-c", "TOKEN", input=SECRET + b"\n").returncode, 0)
        return result

    def text_pointer(self) -> None:
        """Replace the pointer with a regular file holding the key path, as old envdirs have."""
        self.write_pointer(str(self.root / "service.key").encode() + b"\n")

    def move_key(self, destination: Path) -> Path:
        """Move the current key (default: ROOT/service.key) and drop the pointer."""
        key = getattr(self, "key", self.root / "service.key")
        destination.parent.mkdir(parents=True, exist_ok=True)
        key.rename(destination)
        self.key = destination
        pointer = self.directory / ".envdirx.key"
        if os.path.lexists(pointer):
            pointer.unlink()
        return destination

    def write_pointer(self, data: bytes) -> None:
        pointer = self.directory / ".envdirx.key"
        if os.path.lexists(pointer):
            pointer.unlink()
        pointer.write_bytes(data)
        pointer.chmod(0o600)

    def link_pointer(self, target: str) -> None:
        pointer = self.directory / ".envdirx.key"
        if os.path.lexists(pointer):
            pointer.unlink()
        pointer.symlink_to(target)

    def run_ok(self, *before):
        result = self.on("run", *before, "--", *SHOW)
        self.test.assertEqual(result.returncode, 0, result.stderr)
        self.test.assertIn('"TOKEN": "top-secret-value"', result.stdout.decode())
        return result

    def run_fails(self, *before, directory=None):
        self.marker.unlink(missing_ok=True)
        marker = [sys.executable, "-c", f"open({str(self.marker)!r}, 'w').close()"]
        result = self.on("run", *before, "--", *marker, directory=directory)
        self.test.assertEqual(result.returncode, 111, result.stderr)
        self.test.assertFalse(self.marker.exists(), "child must not start")
        self.test.assertNotIn(SECRET, result.stderr)
        self.test.assertNotIn(SECRET, result.stdout)
        for key in self.root.rglob("*.key"):
            if key.is_file() and not key.is_symlink() and key.stat().st_size == 32:
                self.test.assertNotIn(key.read_bytes(), result.stderr)
        self.test.assertTrue(result.stderr.startswith(b"envdirx: "), result.stderr)
        return result


class EnvdirxTest(unittest.TestCase):
    def test_set_interrupt_does_not_write_or_traceback(self):
        fx = Fixture(self)
        for flags in ((), ("-c",)):
            with self.subTest(flags=flags):
                argv = ["envdirx", "-d", str(fx.directory), "set", *flags, "TOKEN"]
                stdin = mock.Mock()
                stdin.buffer.read.side_effect = KeyboardInterrupt
                stderr = io.StringIO()
                with mock.patch.object(sys, "argv", argv), mock.patch.object(sys, "stdin", stdin), contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as exited:
                        envdirx.main()
                self.assertEqual(exited.exception.code, 130)
                self.assertEqual(stderr.getvalue(), "")
                self.assertFalse((fx.directory / "TOKEN").exists())

    def test_set_closed_stdin_exits_111_without_traceback(self):
        """Python sets sys.stdin to None when fd 0 is closed (set NAME <&-)."""
        fx = Fixture(self)
        for flags in ((), ("-c",)):
            with self.subTest(flags=flags):
                argv = ["envdirx", "-d", str(fx.directory), "set", *flags, "TOKEN"]
                stderr = io.StringIO()
                with mock.patch.object(sys, "argv", argv), mock.patch.object(sys, "stdin", None), contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as exited:
                        envdirx.main()
                self.assertEqual(exited.exception.code, 111)
                self.assertEqual(stderr.getvalue(), "envdirx: stdin is closed; set reads the value from stdin\n")
                self.assertFalse((fx.directory / "TOKEN").exists())

    def test_get_searches_directories_in_order(self):
        fx = Fixture(self)
        second = fx.root / "second"
        second.mkdir()
        (second / "TOKEN").write_bytes(b"fallback")
        def get(*dirs, name="TOKEN"):
            return fx.call(*(arg for directory in dirs for arg in ("-d", directory)), "get", name)

        result = get(fx.directory, second)
        self.assertEqual((result.returncode, result.stdout), (0, b"fallback"))
        (fx.directory / "TOKEN").write_bytes(b"primary")
        result = get(fx.directory, second)
        self.assertEqual((result.returncode, result.stdout), (0, b"primary"))
        (fx.directory / "TOKEN").write_bytes(b"")
        result = get(fx.directory, second)
        self.assertEqual((result.returncode, result.stdout), (0, b""))
        (fx.directory / "TOKEN").write_bytes(b"encrypted:invalid")
        result = get(fx.directory, second)
        self.assertEqual((result.returncode, result.stdout), (111, b""))
        (fx.directory / "TOKEN").unlink()
        (fx.directory / "TOKEN").symlink_to(second / "TOKEN")
        result = get(fx.directory, second)
        self.assertEqual((result.returncode, result.stdout), (111, b""))
        (fx.directory / "TOKEN").unlink()
        self.assertEqual((get(fx.root / "missing", second).returncode, get(fx.directory, second, name="ABSENT").returncode), (111, 111))
        self.assertEqual(get(fx.directory, second, name="../TOKEN").returncode, 111)
        before = fx.snapshot()
        result = fx.call("-d", fx.directory, "-d", second, "set", "TOKEN", input=b"no")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(fx.snapshot(), before)
        self.assertEqual((second / "TOKEN").read_bytes(), b"fallback")

    def test_get_does_not_skip_invalid_entries(self):
        for label, create, error in (
            ("dangling symlink", lambda p: p.symlink_to("missing"), b"not a regular file"),
            ("FIFO", os.mkfifo, b"not a regular file"),
            ("directory", Path.mkdir, b"not a regular file"),
            ("malformed ciphertext", lambda p: p.write_bytes(b"encrypted:" + SECRET), b"unsupported ciphertext format"),
        ):
            with self.subTest(entry=label):
                fx = Fixture(self)
                second = fx.root / "second"
                second.mkdir()
                (second / "TOKEN").write_bytes(SECRET)
                create(fx.directory / "TOKEN")
                result = fx.call("-d", fx.directory, "-d", second, "get", "TOKEN")
                self.assertEqual((result.returncode, result.stdout), (111, b""))
                self.assertIn(error, result.stderr)
                self.assertNotIn(SECRET, result.stderr)

    def test_get_does_not_skip_non_directory(self):
        fx = Fixture(self)
        second = fx.root / "second"
        second.mkdir()
        (second / "TOKEN").write_bytes(SECRET)
        fx.directory.rmdir()
        fx.directory.write_bytes(SECRET)
        result = fx.call("-d", fx.directory, "-d", second, "get", "TOKEN")
        self.assertEqual((result.returncode, result.stdout), (111, b""))
        self.assertIn(b"not a directory", result.stderr)
        self.assertNotIn(SECRET, result.stderr)

    def test_get_does_not_skip_unreadable_entry(self):
        fx = Fixture(self)
        second = fx.root / "second"
        second.mkdir()
        (second / "TOKEN").write_bytes(SECRET)
        entry = fx.directory / "TOKEN"
        entry.write_bytes(SECRET + b"-primary")
        entry.chmod(0)
        try:
            result = fx.call("-d", fx.directory, "-d", second, "get", "TOKEN")
            self.assertEqual((result.returncode, result.stdout), (111, b""))
            self.assertIn(b"Permission denied", result.stderr)
            self.assertNotIn(SECRET, result.stderr)
        finally:
            entry.chmod(0o600)
        result = fx.call("-d", fx.directory, "-d", second, "get", "TOKEN")
        self.assertEqual((result.returncode, result.stdout), (0, SECRET + b"-primary"))

    def test_get_does_not_skip_decryption_failure(self):
        fx = Fixture(self)
        fx.keygen_encrypted()
        second = fx.root / "second"
        second.mkdir()
        wrong_key = fx.root / "wrong.key"
        self.assertEqual(fx.on("keygen", "-k", wrong_key, directory=second).returncode, 0)
        (second / "TOKEN").write_bytes(SECRET)
        before = fx.snapshot()
        result = fx.call("-d", fx.directory, "-d", second, "get", "--key", wrong_key, "TOKEN")
        self.assertEqual((result.returncode, result.stdout), (111, b""))
        self.assertIn(b"decryption failed", result.stderr)
        for value in (SECRET, wrong_key.read_bytes(), (fx.root / "service.key").read_bytes()):
            self.assertNotIn(value, result.stderr)
        self.assertEqual(fx.snapshot(), before)
        result = fx.call("-d", fx.directory, "-d", second, "get", "TOKEN")
        self.assertEqual((result.returncode, result.stdout), (0, SECRET + b"\n"))

    def test_get_does_not_skip_inaccessible_directory(self):
        fx = Fixture(self)
        second = fx.root / "second"
        second.mkdir()
        (second / "TOKEN").write_bytes(SECRET)
        fx.directory.chmod(0)
        try:
            result = fx.call("-d", fx.directory, "-d", second, "get", "TOKEN")
            self.assertEqual(result.returncode, 111)
            self.assertEqual(result.stdout, b"")
            self.assertNotIn(SECRET, result.stderr)
        finally:
            fx.directory.chmod(0o700)

    def test_get_uses_selected_directory_pointer(self):
        fx = Fixture(self)
        second = fx.root / "second"
        second.mkdir()
        self.assertEqual(fx.on("keygen", "-k", fx.root / "first.key").returncode, 0)
        self.assertEqual(fx.on("keygen", "-k", fx.root / "second.key", directory=second).returncode, 0)
        self.assertEqual(fx.on("set", "-c", "TOKEN", input=SECRET, directory=second).returncode, 0)
        result = fx.call("-d", fx.directory, "-d", second, "get", "TOKEN")
        self.assertEqual((result.returncode, result.stdout), (0, SECRET))
        (second / ".envdirx.key").unlink()
        result = fx.call("-d", fx.directory, "-d", second, "get", "TOKEN")
        self.assertEqual((result.returncode, result.stdout), (111, b""))
        result = fx.call("-d", fx.directory, "-d", second, "get", "--key", fx.root / "second.key", "TOKEN")
        self.assertEqual((result.returncode, result.stdout), (0, SECRET))
        (fx.directory / "TOKEN").write_bytes(b"encrypted:invalid")
        result = fx.call("-d", fx.directory, "-d", second, "get", "--key", fx.root / "second.key", "TOKEN")
        self.assertEqual((result.returncode, result.stdout), (111, b""))

    def test_encrypted_and_plain_envdir_semantics(self):
        fx = Fixture(self)
        directory = fx.directory
        (directory / "TOKEN").write_bytes(b"top-secret  \nignored")
        (directory / "EMPTY").write_bytes(b"\n")
        (directory / "UNSET").write_bytes(b"")
        (directory / "MULTI").write_bytes(b"one\x00two\n")
        key = fx.root / "service.key"
        _keygen(fx, "-k", key)
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertEqual((directory / ".envdirx.pub").stat().st_mode & 0o777, 0o644)
        self.assertEqual(os.readlink(directory / ".envdirx.key"), str(key))
        # Regular-file text pointers keep working alongside keygen's symlinks.
        fx.text_pointer()
        self.assertEqual((directory / ".envdirx.key").read_bytes(), str(key).encode() + b"\n")
        self.assertEqual(fx.on("encrypt", "--all").returncode, 0)
        self.assertNotIn(b"top-secret", (directory / "TOKEN").read_bytes())
        result = fx.on("run", "--", *SHOW)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.decode().strip(), '{"TOKEN": "top-secret", "EMPTY": "", "UNSET": null, "MULTI": "one\\ntwo", "PLAIN": null}')
        self.assertEqual(fx.on("set", "-c", "TOKEN", input=b"replacement\n").returncode, 0)
        self.assertNotIn(b"replacement", (directory / "TOKEN").read_bytes())
        self.assertIn(b"replacement", fx.on("run", "--", *SHOW).stdout)
        payload = (directory / "TOKEN").read_bytes()
        (directory / "OTHER").write_bytes(payload)
        result = fx.on("run", "--", *SHOW)
        self.assertEqual(result.returncode, 111)
        self.assertNotIn(b"replacement", result.stderr)
        (directory / "OTHER").unlink()
        result = fx.on("run", "--", sys.executable, "-c", "import sys;sys.exit(7)")
        self.assertEqual(result.returncode, 7)
        (directory / "TOKEN").write_bytes(b"envdirx:v2:\nunsafe")
        self.assertEqual(fx.on("run", "--", *SHOW).returncode, 111)

    def test_encrypted_entries_are_printable_and_legacy_remains_readable(self):
        import base64

        fx = Fixture(self)
        fx.keygen_encrypted()
        stored = (fx.directory / "TOKEN").read_bytes()
        self.assertRegex(stored, rb"\Aencrypted:B[A-Za-z0-9+/]+={0,2}\n\Z")
        self.assertNotIn(SECRET, stored)
        self.assertEqual(fx.on("get", "TOKEN").stdout, SECRET + b"\n")
        (fx.directory / "TOKEN").write_bytes(stored.removesuffix(b"\n"))
        self.assertEqual(fx.on("get", "TOKEN").stdout, SECRET + b"\n")
        legacy = b"envdirx:v1:\n" + base64.b64decode(stored[len(b"encrypted:B"):].removesuffix(b"\n"), validate=True)
        (fx.directory / "TOKEN").write_bytes(legacy)
        self.assertEqual(fx.on("get", "TOKEN").stdout, SECRET + b"\n")
        self.assertEqual(fx.on("encrypt", "--all").returncode, 0)
        self.assertEqual((fx.directory / "TOKEN").read_bytes(), legacy)
        self.assertEqual(fx.on("decrypt", "TOKEN").returncode, 0)
        self.assertEqual((fx.directory / "TOKEN").read_bytes(), SECRET + b"\n")

    def test_malformed_printable_ciphertext_fails_without_disclosure(self):
        fx = Fixture(self)
        fx.keygen_encrypted()
        original = (fx.directory / "TOKEN").read_bytes()
        for bad in (b"encrypted:B!", b"encrypted:B", b"encrypted:future", original[:-2] + b"!!", original + b"\n", original.replace(b"encrypted:B", b"encrypted:B\n"), original.removesuffix(b"\n") + b"\r\n"):
            with self.subTest(bad=bad):
                (fx.directory / "TOKEN").write_bytes(bad)
                result = fx.on("get", "TOKEN")
                self.assertEqual(result.returncode, 111)
                self.assertEqual(result.stdout, b"")
                self.assertNotIn(SECRET, result.stderr)
                self.assertEqual(fx.on("decrypt", "TOKEN").returncode, 111)
                self.assertEqual((fx.directory / "TOKEN").read_bytes(), bad)

    def test_plaintext_only_run_needs_no_key_or_pointer(self):
        fx = Fixture(self)
        (fx.directory / "PLAIN").write_bytes(b"visible \n")
        (fx.directory / "UNSET").write_bytes(b"")
        result = fx.on("run", "--", *SHOW)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"PLAIN": "visible"', result.stdout.decode())
        self.assertIn('"UNSET": null', result.stdout.decode())

    def test_keygen_pointer_roundtrip_and_exit_code(self):
        fx = Fixture(self)
        fx.keygen_encrypted()
        (fx.directory / "PLAIN").write_bytes(b"mixed\n")
        result = fx.run_ok()
        self.assertIn('"PLAIN": "mixed"', result.stdout.decode())
        result = fx.on("run", "--", sys.executable, "-c", "import sys;sys.exit(7)")
        self.assertEqual(result.returncode, 7)

    def test_text_pointer_forms(self):
        fx = Fixture(self)
        fx.keygen_encrypted()
        key = fx.move_key(fx.root / "keys dir" / "svc key ")
        for content in (
            str(key).encode() + b"\n",
            str(key).encode(),
            str(key).encode() + b"\r\n",
            b"../keys dir/svc key \n",
        ):
            with self.subTest(content=content):
                fx.write_pointer(content)
                fx.run_ok()
        home_key = fx.move_key(fx.home / "svc.key")
        fx.write_pointer(b"~/svc.key\n")
        fx.run_ok()
        self.assertTrue(home_key.exists())

    def test_symlink_pointer_forms(self):
        fx = Fixture(self)
        fx.keygen_encrypted()
        key = fx.move_key(fx.root / "keys" / "svc.key")
        for target in (str(key), "../keys/svc.key"):
            with self.subTest(target=target):
                fx.link_pointer(target)
                fx.run_ok()
        # A chain of symlinks is followed to the final regular file.
        (fx.root / "alias.key").symlink_to(key)
        fx.link_pointer("../alias.key")
        fx.run_ok()
        # Symlink targets never get ~/ expansion.
        home_key = fx.move_key(fx.home / "svc.key")
        fx.link_pointer("~/svc.key")
        result = fx.run_fails()
        self.assertIn(b"cannot resolve private key", result.stderr)
        self.assertNotIn(b"not a regular file", result.stderr)
        self.assertTrue(home_key.exists())

    def test_relative_pointer_survives_relocation(self):
        fx = Fixture(self)
        fx.keygen_encrypted()
        fx.move_key(fx.root / "service.key")
        fx.write_pointer(b"../service.key\n")
        moved = fx.root / "elsewhere"
        moved.mkdir()
        (fx.root / "service").rename(moved / "service")
        (fx.root / "service.key").rename(moved / "service.key")
        fx.directory = moved / "service"
        fx.run_ok()

    def test_explicit_key_overrides_missing_or_invalid_pointer(self):
        fx = Fixture(self)
        fx.keygen_encrypted()
        key = fx.move_key(fx.root / "keys" / "svc.key")
        fx.run_ok("--key", key)
        result = fx.call("-d", "service", "run", "--key", "keys/svc.key", "--", *SHOW, cwd=fx.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"top-secret-value", result.stdout)
        fx.write_pointer(b"\xff\xfe")
        fx.run_ok("--key", key)
        fx.link_pointer("missing.key")
        fx.run_ok("--key", key)
        key.rename(fx.home / "svc.key")
        fx.run_ok("--key", "~/svc.key")
        # Explicit keys get the same validation as pointer targets.
        fx.run_fails("--key", fx.root / "nope.key")
        (fx.home / "svc.key").chmod(0o640)
        fx.run_fails("--key", "~/svc.key")

    def test_no_adjacent_fallback_without_pointer(self):
        fx = Fixture(self)
        fx.keygen_encrypted()
        (fx.directory / ".envdirx.key").unlink()
        self.assertTrue((fx.root / "service.key").exists())
        result = fx.run_fails()
        self.assertIn(b"missing key pointer", result.stderr)

    def test_invalid_text_pointers_fail_closed(self):
        fx = Fixture(self)
        fx.keygen_encrypted()
        key = str(fx.root / "service.key").encode()
        for content in (b"", b"\n", b"\r\n", key + b"\n" + key + b"\n", key + b"\n\n", key + b"\r", b"\xff" + key, key + b"\x00", b"rel\nmore"):
            with self.subTest(content=content):
                fx.write_pointer(content)
                fx.run_fails()

    def test_invalid_symlink_pointers_fail_closed(self):
        fx = Fixture(self)
        fx.keygen_encrypted()
        fx.link_pointer("../does-not-exist.key")
        fx.run_fails()
        (fx.root / "loop-a").symlink_to(fx.root / "loop-b")
        (fx.root / "loop-b").symlink_to(fx.root / "loop-a")
        fx.link_pointer(str(fx.root / "loop-a"))
        fx.run_fails()
        fx.link_pointer(".envdirx.key")
        fx.run_fails()

    def test_nonregular_pointer_fails_closed(self):
        fx = Fixture(self)
        fx.keygen_encrypted()
        pointer = fx.directory / ".envdirx.key"
        pointer.unlink()
        os.mkfifo(pointer)
        result = fx.run_fails()
        self.assertIn(b"symlink or regular file", result.stderr)
        pointer.unlink()
        pointer.mkdir()
        fx.run_fails()

    def test_invalid_key_targets_fail_closed(self):
        fx = Fixture(self)
        fx.keygen_encrypted()
        key = fx.root / "service.key"
        (fx.root / "keydir").mkdir()
        fx.write_pointer(b"../keydir\n")
        fx.run_fails()
        fx.write_pointer(str(key).encode() + b"\n")
        for mode in (0o640, 0o604, 0o610, 0o644):
            with self.subTest(mode=oct(mode)):
                key.chmod(mode)
                result = fx.run_fails()
                self.assertIn(b"0600", result.stderr)
        key.chmod(0o600)
        good = key.read_bytes()
        key.write_bytes(b"short")
        fx.run_fails()
        key.write_bytes(os.urandom(32))
        result = fx.run_fails()
        self.assertIn(b"decryption failed", result.stderr)
        key.write_bytes(good)
        fx.run_ok()

    def test_key_inside_envdir_rejected_through_aliases(self):
        fx = Fixture(self)
        fx.keygen_encrypted()
        inner = fx.directory / ".private"
        inner.write_bytes((fx.root / "service.key").read_bytes())
        inner.chmod(0o600)
        alias = fx.root / "alias"
        alias.symlink_to(fx.directory)
        for pointer in (b".private\n", str(alias / ".private").encode() + b"\n", b"../alias/.private\n"):
            with self.subTest(pointer=pointer):
                fx.write_pointer(pointer)
                fx.run_fails()
        fx.link_pointer("../alias/.private")
        fx.run_fails()
        fx.write_pointer(str(fx.root / "service.key").encode())
        result = fx.run_fails("--key", alias / ".private", directory=alias)
        self.assertIn(b"outside the envdir", result.stderr)
        fx.run_fails("--key", inner)
        # The envdir itself is not a key either.
        fx.write_pointer(b".\n")
        fx.run_fails()

    def test_wrong_owner_rejected(self):
        fx = Fixture(self)
        fx.keygen_encrypted()
        with mock.patch.object(envdirx.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(ValueError, "owned by the current user"):
                envdirx._private(fx.directory, None)

    def test_help_describes_grammar(self):
        fx = Fixture(self)
        main_help = fx.call("--help").stdout
        for text in (b"./.envs", b"BEFORE the subcommand", b"keygen [-k KEYFILE | -K KEYDIR]", b"set [-c] NAME", b"run [--key KEY] -- COMMAND", b"encrypt (NAME [NAME ...] | --all)", b"decrypt [--key KEY] (NAME [NAME ...] | --all)"):
            self.assertIn(text, main_help)
        self.assertNotIn(b"init", main_help)
        self.assertNotIn(b"encrypt [NAME ...]", main_help)
        encrypt_help = fx.call("encrypt", "--help").stdout
        self.assertIn(b"(NAME [NAME ...] | --all)", encrypt_help)
        self.assertIn(b"no\nprivate key is read", encrypt_help)
        decrypt_help = fx.call("decrypt", "--help").stdout
        for text in (b"[--key KEY] (NAME [NAME ...] | --all)", b"plaintext", b'"envdirx:"', b"not a transaction", b".envdirx.key"):
            self.assertIn(text, decrypt_help)
        self.assertNotIn(b"legacy", main_help.lower())
        self.assertIn(b"envdirx [-d DIR] rekey [--key OLDKEY] [-k NEWKEYFILE | -K NEWKEYDIR]", main_help)
        self.assertNotIn(b"--output", main_help)
        self.assertIn(b"rekey               rotate the encryption key", main_help)
        self.assertNotIn(b"copy the envdir to a new directory under a fresh key", main_help)
        rekey_help = fx.call("rekey", "--help").stdout
        self.assertIn(b"usage: envdirx rekey [--key OLDKEY] [-k NEWKEYFILE | -K NEWKEYDIR]\n\nExamples:\n  envdirx rekey\n", rekey_help)
        for text in (b"rotates the encryption key of DIR in place", b"envdirx -d ./app.env rekey -k", b"DIR: -d DIR", b"symlink aliases stay intact", b"mountpoint", b"OLD key: --key OLDKEY", b"NEW key: -k/--new-key", b"-k, --new-key NEWKEYFILE", b"-K, --new-key-dir NEWKEYDIR", b"legacy", b"never written to disk", b"stay plaintext", b"atomic directory exchange", b"renamex_np", b"renameat2", b"DIR/.envdirx.key points to", b"rotate the underlying service\n  credentials"):
            self.assertIn(text, rekey_help)
        for text in (b"--output", b"DEST", b"SOURCE", b"one rename", b"point consumers"):
            self.assertNotIn(text, rekey_help)
        run_help = fx.call("run", "--help").stdout
        self.assertIn(b"must precede it", run_help)
        self.assertIn(b".envdirx.key", run_help)
        self.assertIn(b"No newline is added", fx.call("get", "--help").stdout)
        set_help = fx.call("set", "--help").stdout
        self.assertIn(b"no key is read", set_help)
        self.assertIn(b'"envdirx:"', set_help)
        keygen_help = fx.call("keygen", "--help").stdout
        self.assertIn(b"sha256", keygen_help)
        self.assertIn(b"no force option", keygen_help)
        for text in (b"XDG_DATA_HOME", b".local/share/envdirx/keys", b"0700"):
            self.assertIn(text, keygen_help)
        for action in ("set", "encrypt", "keygen"):
            self.assertNotIn(b"unused", fx.call(action, "--help").stdout)

    def test_readme_commands(self):
        """Run every README ``sh`` block with an installed-CLI shim for this checkout."""
        readme = (ROOT / "README.md").read_text()
        blocks = [b for document in (readme, (ROOT / "README.ja.md").read_text())
                  for b in re.findall(r"```sh\n(.*?)```", document, re.S)
                  if "envdirx" in b and "unittest" not in b]
        self.assertGreaterEqual(len(blocks), 5)
        for text in ("envdirx -d DIR set -c NAME", "envdirx -d DIR run [--key K] -- CMD", "`set -c`", "`init` has been removed"):
            self.assertIn(text, readme)
        self.assertNotIn("envdirx init", readme)
        for text in ("encrypt (NAME [NAME ...] \\| --all)", "decrypt [--key KEY] (NAME [NAME ...] \\| --all)", "encrypt --all", 'decrypt --key "$PWD/app.env.key" --all', "intentionally leaves secrets as plaintext on disk"):
            self.assertIn(text, readme)
        readme_ja = (ROOT / "README.ja.md").read_text()
        for text in ("`init` は削除した", "意図的に秘密を平文のままディスクへ書く"):
            self.assertIn(text, readme_ja)
        self.assertNotIn("encrypt [NAME ...]`", readme)
        self.assertIsNone(re.search(r"envdirx(?: -d \S+)? encrypt\s*$", readme, re.M), "no implicit-all encrypt")
        skill = (ROOT / "skills" / "envdirx" / "SKILL.md").read_text()
        self.assertIn("stores plaintext", skill)
        self.assertIn("`encrypt` and `decrypt` require names or `--all`", skill)
        self.assertIn("plaintext on disk", skill)
        self.assertNotIn("encrypt [NAME ...]", skill)
        for text in ("`envdirx --version` / `envdirx -V`", "`uv version <version>`", "`v<version>`", "MAJOR.MINOR.PATCH"):
            self.assertIn(text, readme)
            self.assertIn(text, readme_ja)
        self.assertIn("envdirx (-V | --version)", skill)
        for text in ("keygen [-k KEYFILE \\| -K KEYDIR]", "$XDG_DATA_HOME/envdirx/keys", "$HOME/.local/share/envdirx/keys", "0700"):
            self.assertIn(text, readme)
            self.assertIn(text, readme_ja)
        self.assertNotIn("既定の保存先はない", readme_ja)
        self.assertNotIn("rotation command", readme)
        self.assertNotIn("鍵ローテーションはない", readme_ja)
        for document in (readme, readme_ja):
            for text in ("envdirx [-d D] rekey [--key OLDKEY] [-k NEWKEYFILE \\| -K NEWKEYDIR]", "envdirx [-d DIR] rekey [--key OLDKEY] [-k/--new-key NEWKEYFILE | -K/--new-key-dir NEWKEYDIR]", "keygen --key", "envdirx -d app.env rekey -k", "`rekey --output DEST`", ".envdirx-rekey-*", "readlink DIR/.envdirx.key", "`renamex_np`", "`renameat2`", "`RENAME_EXCHANGE`", "`rotation completed`"):
                self.assertIn(text, document)
            for text in ("rekey --output app.env.new", "mv app.env.new app.env", "[-d SOURCE]", "rekey --output DEST [--key"):
                self.assertNotIn(text, document)
        for text in ("rotates the encryption key in place", "nothing to switch over", "names the old key", "stay plaintext", "never written to disk", "rotate the underlying service credentials", "never missing or half-replaced", "power loss", "Readers running during the exchange may fail", "keeps seeing the previous envdir", "There is no non-atomic fallback"):
            self.assertIn(text, readme)
        for text in ("その場でローテーション", "切り替え作業はない", "旧鍵を指す", "平文のまま残る", "ディスクに書いたり表示したりすることはない", "認証情報も更新する", "消えたり一部だけ置き換わったりすることはない", "電源断", "交換の最中に読み込んでいるプロセスは失敗することがある", "以前の envdir を見続ける", "原子的でない代替手段はない"):
            self.assertIn(text, readme_ja)
        self.assertIn("Its `--key` is the OLD key", skill)
        self.assertNotIn("ciphertext only", readme)
        self.assertNotIn("暗号文のみ", readme_ja)
        self.assertIn("staged copies of existing plaintext entries", readme)
        self.assertIn("既存の平文エントリのコピーが含まれる", readme_ja)
        version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
        for text, heading in ((readme, "## Versioning and releases"), (readme_ja, "## バージョンとリリース")):
            section = text.split(heading, 1)[1].split("\n## ", 1)[0]
            self.assertNotIn(version, section, f"{heading} must not hard-code the current version")
        for block in blocks:
            with self.subTest(block=block.splitlines()[0]):
                fx = Fixture(self)
                fx.directory.rmdir()
                bin_dir = fx.root / "bin"
                bin_dir.mkdir()
                shim = bin_dir / "envdirx"
                shim.write_text(f'#!/bin/sh\nexec {sys.executable} -m envdirx "$@"\n')
                shim.chmod(0o755)
                uv_shim = bin_dir / "uv"
                uv_shim.write_text('#!/bin/sh\n[ "$1 $2 $3" = "tool install envdirx" ] || exit 99\n')
                uv_shim.chmod(0o755)
                # Blocks that do not create their own envdir start from a legacy one:
                # adjacent key, encrypted entry, no pointer.
                legacy = "envdirx -d service.env mkdir\nenvdirx -d service.env keygen -k service.env.key\nprintf s | envdirx -d service.env set -c API_TOKEN\nrm service.env/.envdirx.key\n"
                creates = any(word in block for word in ("keygen", "mkdir"))
                prelude = "set -eu\n" + ("" if creates else legacy)
                env = {**fx.env, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
                result = subprocess.run(["sh", "-c", prelude + block], cwd=fx.root, env=env, capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr.decode() + block)


class VersionTest(unittest.TestCase):
    """Global -V/--version reports the installed distribution version and touches nothing."""

    def version(self):
        declared = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
        installed = importlib.metadata.version("envdirx")
        self.assertEqual(installed, declared, "reinstall the project: metadata and pyproject.toml disagree")
        return installed

    def test_version_flags_from_unrelated_directory(self):
        version = self.version()
        fx = Fixture(self)
        empty = fx.root / "elsewhere"
        empty.mkdir()
        before = fx.snapshot()
        for args in (["--version"], ["-V"], ["-d", fx.root / "missing", "--version"], ["-d", fx.root / "missing", "-V"]):
            with self.subTest(args=args):
                result = fx.call(*args, cwd=empty)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, version.encode() + b"\n", b""))
                self.assertEqual(fx.snapshot(), before)
                self.assertFalse((empty / ".envs").exists())

    def test_version_has_no_duplicate_source(self):
        source = (ROOT / "src" / "envdirx" / "__init__.py").read_text()
        self.assertNotIn(self.version(), source)
        self.assertNotIn("pyproject", source)
        self.assertIn('importlib.metadata.version("envdirx")', source)

    def test_help_and_child_version_flags(self):
        fx = Fixture(self)
        main_help = fx.call("--help").stdout
        for text in (b"-V, --version", b"envdirx (-V | --version)", b"global like -d", b"-V/--version is\nglobal too"):
            self.assertIn(text, main_help)
        result = fx.on("run", "--version")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, b"")
        argv = [sys.executable, "-c", "import sys;print(sys.argv[1:])", "--version", "-V"]
        result = fx.on("run", "--", *argv)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), b"['--version', '-V']")


class TransformTest(unittest.TestCase):
    """encrypt/decrypt: explicit selection, preflight validation, per-entry atomic writes."""

    VALUES = {"BIN": bytes(range(256)), "LINES": b"one \nnul\x00two\n", "EMPTY": b"", "SPACED": b"  spaced \t\n"}

    def setup(self, fx, **values):
        _keygen(fx, "-k", fx.root / "svc.key")
        for name, value in (values or self.VALUES).items():
            path = fx.directory / name
            path.write_bytes(value)
            path.chmod(0o644)
        return fx.root / "svc.key"

    def ok(self, fx, *args, **kw):
        result = fx.on(*args, **kw)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")
        return result

    def fails(self, fx, *args, code=111, **kw):
        """ACTION fails with CODE, writes nothing anywhere and discloses nothing."""
        before = fx.snapshot()
        result = fx.on(*args, **kw)
        self.assertEqual(result.returncode, code, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(fx.snapshot(), before)
        for value in (SECRET, *(v for v in self.VALUES.values() if len(v) > 4)):
            self.assertNotIn(value, result.stderr)
        for key in fx.root.rglob("*.key"):
            if key.is_file() and not key.is_symlink() and key.stat().st_size == 32:
                self.assertNotIn(key.read_bytes(), result.stderr)
        return result

    def dotfiles(self, fx):
        return {p.name: (os.readlink(p) if p.is_symlink() else p.read_bytes()) for p in fx.directory.iterdir() if p.name.startswith(".")}

    def test_selection_is_required_unique_and_exclusive(self):
        fx = Fixture(self)
        self.setup(fx)
        self.ok(fx, "encrypt", "BIN")
        # Broken key material proves parsing fails before any key or directory read.
        (fx.directory / ".envdirx.key").unlink()
        (fx.directory / ".envdirx.key").symlink_to("nowhere")
        for action in ("encrypt", "decrypt"):
            for args in ((), ("--all", "LINES"), ("LINES", "--all"), ("LINES", "LINES"), ("BIN", "LINES", "BIN"), ("--all", "--all", "LINES")):
                with self.subTest(action=action, args=args):
                    result = self.fails(fx, action, *args, code=2)
                    self.assertIn(b"usage:", result.stderr)
        self.fails(fx, "decrypt", "--key", fx.root / "svc.key", code=2)
        self.fails(fx, "encrypt", "--key", fx.root / "svc.key", "LINES", code=2)
        missing = fx.root / "missing"
        for action in ("encrypt", "decrypt"):
            self.fails(fx, action, directory=missing, code=2)
            self.assertFalse(os.path.lexists(missing))

    def test_named_and_all_roundtrip_exact_bytes(self):
        fx = Fixture(self)
        self.setup(fx, **self.VALUES, UNRELATED=b"unrelated")
        meta = self.dotfiles(fx)
        self.ok(fx, "encrypt", "LINES", "BIN", "EMPTY")
        for name in ("LINES", "BIN", "EMPTY"):
            stored = (fx.directory / name).read_bytes()
            self.assertTrue(stored.startswith(b"encrypted:B"), name)
            if self.VALUES[name]:
                self.assertNotIn(self.VALUES[name], stored)
            self.assertEqual((fx.directory / name).stat().st_mode & 0o777, 0o600)
        for name in ("SPACED", "UNRELATED"):
            self.assertEqual((fx.directory / name).stat().st_mode & 0o777, 0o644)
        self.assertEqual((fx.directory / "UNRELATED").read_bytes(), b"unrelated")
        self.ok(fx, "decrypt", "EMPTY", "BIN")
        for name in ("EMPTY", "BIN"):
            self.assertEqual((fx.directory / name).read_bytes(), self.VALUES[name])
            self.assertEqual((fx.directory / name).stat().st_mode & 0o777, 0o600)
        self.assertTrue((fx.directory / "LINES").read_bytes().startswith(b"encrypted:B"))
        self.ok(fx, "encrypt", "--all")  # skips the already encrypted LINES
        for name in (*self.VALUES, "UNRELATED"):
            self.assertTrue((fx.directory / name).read_bytes().startswith(b"encrypted:B"), name)
        self.assertEqual(fx.on("get", "LINES").stdout, self.VALUES["LINES"])
        self.ok(fx, "decrypt", "--all")
        for name, value in {**self.VALUES, "UNRELATED": b"unrelated"}.items():
            self.assertEqual((fx.directory / name).read_bytes(), value, name)
            self.assertEqual((fx.directory / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.dotfiles(fx), meta)

    def test_default_and_explicit_directory_selection(self):
        fx = Fixture(self)
        self.assertEqual(fx.call("mkdir").returncode, 0)
        self.assertEqual(fx.call("keygen", "-k", fx.root / "default.key").returncode, 0)
        self.assertEqual(fx.call("set", "-c", "AAA", input=SECRET).returncode, 0)
        self.setup(fx, AAA=b"explicit")
        self.ok(fx, "encrypt", "AAA")
        explicit = (fx.directory / "AAA").read_bytes()
        result = fx.call("decrypt", "AAA")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((fx.root / ".envs" / "AAA").read_bytes(), SECRET)
        self.assertEqual((fx.directory / "AAA").read_bytes(), explicit)
        self.ok(fx, "decrypt", "AAA")
        self.assertEqual((fx.directory / "AAA").read_bytes(), b"explicit")

    def test_encrypt_needs_only_public_and_decrypt_only_private(self):
        fx = Fixture(self)
        key = self.setup(fx, TOKEN=SECRET)
        hidden = fx.root / "keys" / "hidden.key"
        hidden.parent.mkdir()
        key.rename(hidden)
        (fx.directory / ".envdirx.key").unlink()
        self.ok(fx, "encrypt", "TOKEN")
        (fx.directory / ".envdirx.pub").unlink()
        # Missing pointer fails closed; explicit --key (cwd-relative or ~/) overrides.
        self.assertIn(b"missing key pointer", self.fails(fx, "decrypt", "TOKEN").stderr)
        fx.link_pointer("missing.key")
        self.fails(fx, "decrypt", "--all")
        fx.write_pointer(b"\xff\xfe")
        self.fails(fx, "decrypt", "TOKEN")
        result = fx.call("-d", "service", "decrypt", "--key", "keys/hidden.key", "TOKEN", cwd=fx.root)
        self.assertEqual((result.returncode, result.stdout), (0, b""), result.stderr)
        self.assertEqual((fx.directory / "TOKEN").read_bytes(), SECRET)
        # Encrypting again now needs the public key that was removed.
        self.fails(fx, "encrypt", "TOKEN")
        (fx.directory / ".envdirx.pub").write_bytes(_public_of(hidden))
        self.ok(fx, "encrypt", "TOKEN")
        hidden.rename(fx.home / "svc.key")
        self.ok(fx, "decrypt", "--key", "~/svc.key", "--all")
        self.assertEqual((fx.directory / "TOKEN").read_bytes(), SECRET)

    def test_invalid_keys_preserve_batch(self):
        fx = Fixture(self)
        key = self.setup(fx, AAA=b"a-value", TOKEN=SECRET)
        self.ok(fx, "encrypt", "--all")
        good = key.read_bytes()
        key.chmod(0o640)
        self.assertIn(b"0600", self.fails(fx, "decrypt", "--all").stderr)
        key.chmod(0o600)
        key.write_bytes(os.urandom(32))
        self.assertIn(b"decryption failed", self.fails(fx, "decrypt", "AAA", "TOKEN").stderr)
        key.write_bytes(b"short")
        self.fails(fx, "decrypt", "--all")
        key.write_bytes(good)
        inner = fx.directory / ".private"
        inner.write_bytes(good)
        inner.chmod(0o600)
        self.assertIn(b"outside the envdir", self.fails(fx, "decrypt", "--key", inner, "--all").stderr)
        self.ok(fx, "decrypt", "--all")

    def test_no_work_needs_no_key(self):
        fx = Fixture(self)
        for action in ("encrypt", "decrypt"):
            self.ok(fx, action, "--all")  # empty envdir, no key material at all
        (fx.directory / ".hidden").write_bytes(b"envdirx:v9:\nignored dotfile")
        (fx.directory / "PLAIN").write_bytes(b"plain")
        fx.link_pointer("nowhere")
        self.ok(fx, "decrypt", "--all")
        self.assertEqual((fx.directory / "PLAIN").read_bytes(), b"plain")
        fx2 = Fixture(self)
        self.setup(fx2, TOKEN=SECRET)
        self.ok(fx2, "encrypt", "--all")
        cipher = (fx2.directory / "TOKEN").read_bytes()
        (fx2.directory / ".envdirx.pub").unlink()
        self.ok(fx2, "encrypt", "--all")
        self.assertEqual((fx2.directory / "TOKEN").read_bytes(), cipher)

    def test_explicit_target_state_errors(self):
        fx = Fixture(self)
        self.setup(fx, PLAIN=b"plain", TOKEN=SECRET)
        self.ok(fx, "encrypt", "TOKEN")
        self.assertIn(b"already encrypted: TOKEN", self.fails(fx, "encrypt", "PLAIN", "TOKEN").stderr)
        self.assertIn(b"already decrypted: PLAIN", self.fails(fx, "decrypt", "TOKEN", "PLAIN").stderr)

    def test_unsafe_raw_names_fail_without_writes(self):
        fx = Fixture(self)
        self.setup(fx, AAA=b"a-value")
        (fx.root / "X").write_bytes(b"outside")
        for name in ("../X", str(fx.root / "X"), ".envdirx.pub", ".envdirx.key", "A=B", "", ".", "..", "sub/AAA", "../service/AAA"):
            for action in ("encrypt", "decrypt"):
                with self.subTest(action=action, name=name):
                    result = self.fails(fx, action, "AAA", name)
                    self.assertIn(b"invalid environment variable name", result.stderr)

    def test_invalid_entries_fail_whole_batch(self):
        fx = Fixture(self)
        self.setup(fx, AAA=b"a-value", TOKEN=SECRET)
        target = fx.root / "target"
        target.write_bytes(b"outside")
        self.ok(fx, "encrypt", "--all")
        cipher = (fx.directory / "TOKEN").read_bytes()
        tampered = bytearray(cipher)
        tampered[-1] ^= 1
        corrupt = {
            "tampered": bytes(tampered),
            "truncated": cipher[:40],
            "short": b"envdirx:v1:\nshort",
            "wrong name": cipher,
            "unsupported": b"envdirx:v2:\nx",
            "reserved only": b"envdirx:",
        }
        for label, data in corrupt.items():
            with self.subTest(label=label):
                (fx.directory / "ZZZ").write_bytes(data)
                self.fails(fx, "decrypt", "--all")
                self.fails(fx, "decrypt", "AAA", "ZZZ")
        for label, make in (("symlink", lambda p: p.symlink_to(target)), ("dangling", lambda p: p.symlink_to("nowhere")), ("directory", os.mkdir)):
            with self.subTest(label=label):
                (fx.directory / "ZZZ").unlink()
                make(fx.directory / "ZZZ")
                self.assertIn(b"not a regular file", self.fails(fx, "decrypt", "--all").stderr)
                self.fails(fx, "decrypt", "AAA", "ZZZ")
                if label == "directory":
                    (fx.directory / "ZZZ").rmdir()
                    (fx.directory / "ZZZ").write_bytes(b"")
        (fx.directory / "ZZZ").unlink()
        self.fails(fx, "decrypt", "AAA", "MISSING")
        self.ok(fx, "decrypt", "--all")
        # Encrypt validates the whole batch the same way.
        for label, make in (("unsupported", lambda p: p.write_bytes(b"envdirx:v9:\nx")), ("symlink", lambda p: p.symlink_to(target)), ("directory", os.mkdir)):
            with self.subTest(encrypt=label):
                make(fx.directory / "ZZZ")
                self.fails(fx, "encrypt", "--all")
                self.fails(fx, "encrypt", "AAA", "ZZZ")
                (fx.directory / "ZZZ").rmdir() if label == "directory" else (fx.directory / "ZZZ").unlink()
        self.fails(fx, "encrypt", "AAA", "MISSING")
        self.assertEqual(target.read_bytes(), b"outside")

    def test_reserved_original_plaintext_stays_encrypted(self):
        fx = Fixture(self)
        self.setup(fx, TOKEN=SECRET)
        self.assertEqual(fx.on("set", "-c", "AAA", input=b"envdirx:v1:\nlooks-encrypted").returncode, 0)
        self.ok(fx, "encrypt", "TOKEN")
        for args in (("--all",), ("TOKEN", "AAA"), ("AAA",)):
            with self.subTest(args=args):
                result = self.fails(fx, "decrypt", *args)
                self.assertIn(b"reserved", result.stderr)
                self.assertNotIn(b"looks-encrypted", result.stderr)
        self.assertEqual(fx.on("get", "AAA").stdout, b"envdirx:v1:\nlooks-encrypted")
        self.assertEqual(fx.on("set", "-c", "AAA", input=b"encrypted:Blooks-encrypted").returncode, 0)
        self.assertIn(b"reserved", self.fails(fx, "decrypt", "AAA").stderr)
        self.assertEqual(fx.on("get", "AAA").stdout, b"encrypted:Blooks-encrypted")
        self.ok(fx, "decrypt", "TOKEN")
        self.assertEqual((fx.directory / "TOKEN").read_bytes(), SECRET)

    def test_late_write_failure_keeps_earlier_and_failed_entries(self):
        for action in ("encrypt", "decrypt"):
            with self.subTest(action=action):
                fx = Fixture(self)
                self.setup(fx, AAA=b"a-value", BBB=b"b-value")
                if action == "decrypt":
                    self.ok(fx, "encrypt", "--all")
                before = {name: (fx.directory / name).read_bytes() for name in ("AAA", "BBB")}
                real_replace, calls = os.replace, []

                def replace(src, dst):
                    calls.append(dst)
                    if len(calls) == 2:
                        raise OSError("disk full")
                    real_replace(src, dst)

                argv = ["envdirx", "-d", str(fx.directory), action, "AAA", "BBB"]
                stderr = io.StringIO()
                with mock.patch.object(envdirx.os, "replace", replace), mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as raised:
                        envdirx.main()
                self.assertEqual(raised.exception.code, 111)
                self.assertIn("disk full", stderr.getvalue())
                self.assertEqual([Path(p).name for p in calls], ["AAA", "BBB"])
                self.assertNotEqual((fx.directory / "AAA").read_bytes(), before["AAA"])
                self.assertEqual((fx.directory / "BBB").read_bytes(), before["BBB"])
                self.assertEqual(fx.on("get", "AAA").stdout, b"a-value")
                self.assertEqual([p.name for p in fx.directory.iterdir() if p.name.startswith(".envdirx-")], [])


def _keygen(fx, *args, directory=None):
    result = fx.on("keygen", *args, directory=directory)
    fx.test.assertEqual(result.returncode, 0, result.stderr)
    fx.test.assertEqual(result.stdout, b"")
    return result


def _public_of(key: Path) -> bytes:
    private = X25519PrivateKey.from_private_bytes(key.read_bytes())
    return private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class DirectoryWorkflowTest(unittest.TestCase):
    """Directory-oriented grammar: global -d, mkdir, plaintext-default set, get and run --."""

    def test_default_directory_and_explicit_directory_are_isolated(self):
        fx = Fixture(self)
        result = fx.call("mkdir")
        self.assertEqual(result.returncode, 0, result.stderr)
        default = fx.root / ".envs"
        self.assertEqual(default.stat().st_mode & 0o777, 0o700)
        self.assertEqual(fx.call("set", "AAA", input=b"default-value").returncode, 0)
        self.assertEqual(fx.call("get", "AAA").stdout, b"default-value")
        result = fx.call("run", "--", "sh", "-c", 'test "$AAA" = default-value')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fx.on("set", "AAA", input=b"explicit").returncode, 0)
        self.assertEqual(fx.on("get", "AAA").stdout, b"explicit")
        result = fx.call("--directory", fx.directory, "run", "--", "sh", "-c", 'test "$AAA" = explicit')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((default / "AAA").read_bytes(), b"default-value")
        self.assertEqual(sorted(p.name for p in default.iterdir()), ["AAA"])
        # Relative -d is relative to the current directory.
        result = fx.call("-d", "service", "get", "AAA", cwd=fx.root)
        self.assertEqual(result.stdout, b"explicit")

    def test_mkdir_creates_parents_and_is_idempotent(self):
        fx = Fixture(self)
        nested = fx.root / "a" / "b" / "envs"
        self.assertEqual(fx.call("-d", nested, "mkdir").returncode, 0)
        self.assertEqual(nested.stat().st_mode & 0o777, 0o700)
        fx.directory.chmod(0o750)
        (fx.directory / "KEEP").write_bytes(b"x")
        result = fx.on("mkdir")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fx.directory.stat().st_mode & 0o777, 0o750)
        self.assertEqual((fx.directory / "KEEP").read_bytes(), b"x")
        (fx.root / "file").write_bytes(b"data")
        for target in (fx.root / "file", fx.root / "file" / "sub"):
            with self.subTest(target=target):
                result = fx.call("-d", target, "mkdir")
                self.assertEqual(result.returncode, 111, result.stderr)
        self.assertEqual((fx.root / "file").read_bytes(), b"data")
        dangling = fx.root / "dangling"
        dangling.symlink_to("nowhere")
        self.assertEqual(fx.call("-d", dangling, "mkdir").returncode, 111)
        self.assertTrue(dangling.is_symlink())

    def test_other_commands_require_existing_directory(self):
        fx = Fixture(self)
        missing = fx.root / "missing"
        for args, stdin in ((["set", "A"], b"v"), (["get", "A"], None), (["encrypt", "--all"], None), (["decrypt", "--all"], None), (["keygen", "-k", fx.root / "k"], None), (["run", "--", "true"], None)):
            with self.subTest(args=args[0]):
                result = fx.call("-d", missing, *args, input=stdin)
                self.assertEqual(result.returncode, 111, result.stderr)
                self.assertFalse(os.path.lexists(missing))
                self.assertFalse(os.path.lexists(fx.root / ".envs"))
        self.assertFalse(os.path.lexists(fx.root / "k"))

    def test_plaintext_set_get_exact_bytes_without_keys(self):
        fx = Fixture(self)
        for value in (b"plain", b"a b \nsecond\x00line\n", bytes(range(256)), b"", b"\n"):
            with self.subTest(value=value[:12]):
                result = fx.on("set", "VALUE", input=value)
                self.assertEqual(result.returncode, 0, result.stderr)
                entry = fx.directory / "VALUE"
                self.assertEqual(entry.read_bytes(), value)
                self.assertEqual(entry.stat().st_mode & 0o777, 0o600)
                result = fx.on("get", "VALUE")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, value)
                self.assertEqual(result.stderr, b"")
        # No key material was ever needed or created.
        self.assertEqual(sorted(p.name for p in fx.directory.iterdir()), ["VALUE"])
        (fx.directory / "TOKEN").write_bytes(b"  first  \nsecond")
        result = fx.on("run", "--", sys.executable, "-c", "import os;print(repr(os.environ['TOKEN']))")
        self.assertEqual(result.stdout.strip(), b"'  first'")
        self.assertEqual(fx.on("get", "TOKEN").stdout, b"  first  \nsecond")

    def test_plaintext_set_rejects_reserved_prefix_and_preserves_entry(self):
        fx = Fixture(self)
        (fx.directory / "TOKEN").write_bytes(b"old")
        for value in (b"envdirx:", b"envdirx:v1:\nlooks-encrypted", b"envdirx:v9:\nx", b"encrypted:Blooks-encrypted", b"encrypted:future"):
            with self.subTest(value=value):
                result = fx.on("set", "TOKEN", input=value)
                self.assertEqual(result.returncode, 111)
                self.assertIn(b"reserved", result.stderr)
                if value[8:]:
                    self.assertNotIn(value[8:], result.stderr)
                self.assertEqual((fx.directory / "TOKEN").read_bytes(), b"old")
                self.assertFalse(os.path.lexists(fx.directory / "NEW"))
                self.assertEqual(fx.on("set", "NEW", input=value).returncode, 111)
                self.assertFalse(os.path.lexists(fx.directory / "NEW"))
        # The prefix inside a value, or after other bytes, is ordinary plaintext.
        self.assertEqual(fx.on("set", "TOKEN", input=b" envdirx:").returncode, 0)
        self.assertEqual(fx.on("get", "TOKEN").stdout, b" envdirx:")
        # Encrypted entries may hold the reserved prefix.
        _keygen(fx, "-k", fx.root / "svc.key")
        self.assertEqual(fx.on("set", "-c", "TOKEN", input=b"envdirx:v1:\nx").returncode, 0)
        self.assertEqual(fx.on("get", "TOKEN").stdout, b"envdirx:v1:\nx")

    def test_set_protects_names_and_nonregular_entries(self):
        fx = Fixture(self)
        for name in (".hidden", "A=B", "..", "a/b"):
            with self.subTest(name=name):
                self.assertEqual(fx.on("set", name, input=b"v").returncode, 111)
                self.assertEqual(fx.on("get", name).returncode, 111)
        target = fx.root / "target"
        target.write_bytes(b"keep")
        (fx.directory / "LINK").symlink_to(target)
        (fx.directory / "DIR").mkdir()
        for name in ("LINK", "DIR"):
            for extra in ([], ["-c"]):
                with self.subTest(name=name, extra=extra):
                    self.assertEqual(fx.on("set", *extra, name, input=b"v").returncode, 111)
            self.assertEqual(fx.on("get", name).stdout, b"")
            self.assertEqual(fx.on("get", name).returncode, 111)
        self.assertEqual(target.read_bytes(), b"keep")

    def test_set_without_c_never_encrypts_and_c_needs_public_key(self):
        fx = Fixture(self)
        result = fx.on("set", "-c", "TOKEN", input=SECRET)
        self.assertEqual(result.returncode, 111)
        self.assertFalse(os.path.lexists(fx.directory / "TOKEN"))
        _keygen(fx, "-k", fx.root / "svc.key")
        self.assertEqual(fx.on("set", "PLAIN", input=b"visible").returncode, 0)
        self.assertEqual((fx.directory / "PLAIN").read_bytes(), b"visible")
        # A broken pointer does not matter for plaintext set/get or encrypted set.
        (fx.directory / ".envdirx.key").unlink()
        (fx.directory / ".envdirx.key").symlink_to("nowhere")
        self.assertEqual(fx.on("get", "PLAIN").stdout, b"visible")
        self.assertEqual(fx.on("set", "--encrypt", "TOKEN", input=SECRET).returncode, 0)
        self.assertNotIn(SECRET, (fx.directory / "TOKEN").read_bytes())
        self.assertTrue((fx.directory / "TOKEN").read_bytes().startswith(b"encrypted:B"))
        self.assertEqual(fx.on("get", "--key", fx.root / "svc.key", "TOKEN").stdout, SECRET)

    def test_encrypted_set_get_run_roundtrip(self):
        fx = Fixture(self)
        self.assertEqual(fx.on("mkdir").returncode, 0)
        _keygen(fx, "-k", fx.root / "svc.key")
        for value in (SECRET + b"\n", b"", b"bin\x00ary\nlines \n"):
            with self.subTest(value=value):
                self.assertEqual(fx.on("set", "-c", "TOKEN", input=value).returncode, 0)
                stored = (fx.directory / "TOKEN").read_bytes()
                self.assertTrue(stored.startswith(b"encrypted:B"))
                if value:
                    self.assertNotIn(value, stored)
                self.assertEqual((fx.directory / "TOKEN").stat().st_mode & 0o777, 0o600)
                result = fx.on("get", "TOKEN")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, value)
        fx.on("set", "-c", "TOKEN", input=SECRET + b"  \nignored")
        fx.on("set", "PLAIN", input=b"mixed\n")
        result = fx.on("run", "--", *SHOW)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"TOKEN": "top-secret-value"', result.stdout.decode())
        self.assertIn('"PLAIN": "mixed"', result.stdout.decode())
        for path in fx.root.rglob("*"):
            if path.is_file() and not path.is_symlink():
                self.assertNotIn(SECRET, path.read_bytes(), path)

    def test_encrypt_uses_public_key_only_with_global_directory(self):
        fx = Fixture(self)
        _keygen(fx, "-k", fx.root / "svc.key")
        (fx.directory / "TOKEN").write_bytes(SECRET)
        (fx.directory / "OTHER").write_bytes(b"other")
        key = fx.root / "svc.key"
        key.rename(fx.root / "hidden.key")
        (fx.directory / ".envdirx.key").unlink()
        self.assertEqual(fx.on("encrypt", "TOKEN").returncode, 0)
        self.assertEqual((fx.directory / "OTHER").read_bytes(), b"other")
        cipher = (fx.directory / "TOKEN").read_bytes()
        self.assertNotIn(SECRET, cipher)
        self.assertEqual(fx.on("encrypt", "TOKEN").returncode, 111)  # explicitly named: already encrypted
        self.assertEqual(fx.on("encrypt", "--all").returncode, 0)
        self.assertEqual((fx.directory / "TOKEN").read_bytes(), cipher)  # skipped, unchanged
        self.assertNotIn(b"other", (fx.directory / "OTHER").read_bytes())
        self.assertEqual(fx.on("get", "--key", fx.root / "hidden.key", "TOKEN").stdout, SECRET)
        self.assertEqual(fx.on("encrypt", "--key", "x").returncode, 2)
        self.assertEqual(fx.on("set", "--key", "x", "A", input=b"v").returncode, 2)

    def test_run_requires_separator_and_preserves_child_flags(self):
        fx = Fixture(self)
        (fx.directory / "AAA").write_bytes(b"value")
        marker = [sys.executable, "-c", f"open({str(fx.marker)!r}, 'w').close()"]
        for args in (marker, [], ["--"], ["--key", fx.root / "k"], ["--key", fx.root / "k", *marker], [*marker[:1], "--", *marker[1:]]):
            with self.subTest(args=args):
                result = fx.on("run", *args)
                self.assertIn(result.returncode, (2, 111), result.stderr)
                self.assertFalse(fx.marker.exists())
        argv = [sys.executable, "-c", "import sys,os;print(sys.argv[1:], os.environ['AAA'])", "--key", "x", "-d", "y", "--", "-c"]
        result = fx.on("run", "--", *argv)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), b"['--key', 'x', '-d', 'y', '--', '-c'] value")
        result = fx.on("run", "--", sys.executable, "-c", "import sys;sys.exit(9)")
        self.assertEqual(result.returncode, 9)
        result = fx.on("run", "--", fx.root / "no-such-command")
        self.assertEqual(result.returncode, 111)

    def test_legacy_positional_forms_are_rejected(self):
        fx = Fixture(self)
        (fx.directory / "AAA").write_bytes(b"value")
        marker = [sys.executable, "-c", f"open({str(fx.marker)!r}, 'w').close()"]
        result = fx.call("run", fx.directory, "--", *marker)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(fx.marker.exists())
        self.assertEqual(fx.call("set", fx.directory, "AAA", input=b"new").returncode, 2)
        self.assertEqual((fx.directory / "AAA").read_bytes(), b"value")
        # -d after the subcommand is not the global option.
        self.assertEqual(fx.call("set", "-d", fx.directory, "AAA", input=b"new").returncode, 2)
        self.assertEqual((fx.directory / "AAA").read_bytes(), b"value")

    def test_init_is_rejected_without_writes(self):
        fx = Fixture(self)
        (fx.directory / "AAA").write_bytes(b"value")
        before = fx.snapshot()
        for args in (
            ("init", fx.directory),
            ("init", "--key", fx.root / "svc.key", fx.directory),
            ("-d", fx.directory, "init"),
            ("--directory", fx.root / "other", "init", fx.directory),
        ):
            with self.subTest(args=args):
                result = fx.call(*args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(b"invalid choice: 'init'", result.stderr)
                self.assertEqual(fx.snapshot(), before)
        # Envdirs with a regular text pointer (as init used to write) still work.
        fx.keygen_encrypted()
        fx.text_pointer()
        self.assertFalse((fx.directory / ".envdirx.key").is_symlink())
        self.assertEqual(fx.on("get", "TOKEN").stdout, SECRET + b"\n")
        fx.run_ok()


class GetFailureTest(unittest.TestCase):
    """get fails with 111, nothing on stdout and no secrets in diagnostics."""

    def get_fails(self, fx, *args, name="TOKEN", directory=None):
        result = fx.on("get", *args, name, directory=directory)
        self.assertEqual(result.returncode, 111, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(SECRET, result.stderr)
        self.assertTrue(result.stderr.startswith(b"envdirx: "), result.stderr)
        return result

    def test_missing_and_invalid_entries(self):
        fx = Fixture(self)
        fx.keygen_encrypted()
        self.get_fails(fx, name="MISSING")
        (fx.directory / "BAD").write_bytes(b"envdirx:v2:\nunsupported")
        self.get_fails(fx, name="BAD")
        (fx.directory / "SHORT").write_bytes(b"envdirx:v1:\nshort")
        self.get_fails(fx, name="SHORT")
        cipher = (fx.directory / "TOKEN").read_bytes()
        (fx.directory / "OTHER").write_bytes(cipher)
        result = self.get_fails(fx, name="OTHER")
        self.assertIn(b"decryption failed", result.stderr)
        tampered = bytearray(cipher)
        tampered[-1] ^= 1
        (fx.directory / "TOKEN").write_bytes(bytes(tampered))
        self.get_fails(fx)

    def test_invalid_key_references(self):
        fx = Fixture(self)
        fx.keygen_encrypted()
        key = fx.root / "service.key"
        (fx.directory / ".envdirx.key").unlink()
        self.assertIn(b"missing key pointer", self.get_fails(fx).stderr)
        fx.write_pointer(b"\xff\xfe")
        self.get_fails(fx)
        fx.link_pointer("../does-not-exist.key")
        self.get_fails(fx)
        fx.write_pointer(str(key).encode() + b"\n")
        key.chmod(0o640)
        self.assertIn(b"0600", self.get_fails(fx).stderr)
        key.chmod(0o600)
        good = key.read_bytes()
        key.write_bytes(os.urandom(32))
        self.get_fails(fx)
        key.write_bytes(good)
        inner = fx.directory / ".private"
        inner.write_bytes(good)
        inner.chmod(0o600)
        self.assertIn(b"outside the envdir", self.get_fails(fx, "--key", inner).stderr)
        fx.write_pointer(b".private\n")
        self.get_fails(fx)
        with mock.patch.object(envdirx.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(ValueError, "owned by the current user"):
                envdirx._get(fx.directory, str(key), "TOKEN")

    def test_closed_stdout_exits_111_without_traceback(self):
        """Python sets sys.stdout to None when fd 1 is closed (get NAME >&-)."""
        fx = Fixture(self)
        fx.keygen_encrypted()
        argv = ["envdirx", "-d", str(fx.directory), "get", "TOKEN"]
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", argv), mock.patch.object(sys, "stdout", None), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as exited:
                envdirx.main()
        self.assertEqual(exited.exception.code, 111)
        self.assertEqual(stderr.getvalue(), "envdirx: stdout is closed; get writes the value to stdout\n")

    def test_broken_pipe_exits_111_without_shutdown_error(self):
        """A reader that is already gone must not turn exit 111 into Python's status 120 flush failure."""
        fx = Fixture(self)
        fx.keygen_encrypted()
        reader, writer = os.pipe()
        os.close(reader)  # no reader exists before the child starts: every write gets EPIPE
        try:
            result = subprocess.run([*CLI, "-d", str(fx.directory), "get", "TOKEN"], env=fx.env, cwd=fx.root, stdout=writer, stderr=subprocess.PIPE, timeout=30)
        finally:
            os.close(writer)
        self.assertEqual(result.returncode, 111, result.stderr)
        self.assertEqual(result.stderr, b"envdirx: [Errno 32] Broken pipe\n")

    def test_key_override_agrees_with_run(self):
        fx = Fixture(self)
        fx.keygen_encrypted()
        key = fx.move_key(fx.root / "keys" / "svc.key")
        fx.link_pointer("missing.key")
        self.get_fails(fx)
        fx.run_fails()
        self.assertEqual(fx.on("get", "--key", key, "TOKEN").stdout, SECRET + b"\n")
        fx.run_ok("--key", key)
        result = fx.call("-d", "service", "get", "--key", "keys/svc.key", "TOKEN", cwd=fx.root)
        self.assertEqual(result.stdout, SECRET + b"\n")
        key.rename(fx.home / "svc.key")
        self.assertEqual(fx.on("get", "--key", "~/svc.key", "TOKEN").stdout, SECRET + b"\n")
        fx.run_ok("--key", "~/svc.key")
        (fx.home / "svc.key").chmod(0o644)
        self.get_fails(fx, "--key", "~/svc.key")
        fx.run_fails("--key", "~/svc.key")


class KeygenTest(unittest.TestCase):
    def test_key_file_destination(self):
        fx = Fixture(self)
        _keygen(fx, "-k", fx.root / "svc.key")
        key, pub, pointer = fx.root / "svc.key", fx.directory / ".envdirx.pub", fx.directory / ".envdirx.key"
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(key.read_bytes()), 32)
        self.assertEqual(pub.stat().st_mode & 0o777, 0o644)
        self.assertFalse(pub.is_symlink())
        self.assertEqual(pub.read_bytes(), _public_of(key))
        self.assertTrue(pointer.is_symlink())
        self.assertEqual(os.readlink(pointer), str(key))
        self.assertTrue(Path(os.readlink(pointer)).is_absolute())
        self.assertEqual(fx.on("set", "-c", "TOKEN", input=SECRET).returncode, 0)
        self.assertEqual(fx.on("get", "TOKEN").stdout, SECRET)

    def test_relative_tilde_and_aliased_destinations_resolve(self):
        fx = Fixture(self)
        (fx.root / "real").mkdir()
        (fx.root / "alias").symlink_to(fx.root / "real")
        result = fx.call("-d", "service", "keygen", "--key", "alias/svc.key", cwd=fx.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(os.readlink(fx.directory / ".envdirx.key"), str(fx.root / "real" / "svc.key"))
        other = fx.root / "other"
        other.mkdir()
        _keygen(fx, "-k", "~/other.key", directory=other)
        self.assertEqual(os.readlink(other / ".envdirx.key"), str(fx.home / "other.key"))

    def test_key_dir_fingerprint_name(self):
        fx = Fixture(self)
        keys = fx.root / "keys"
        keys.mkdir()
        result = fx.call("-d", "service", "keygen", "-K", "keys", cwd=fx.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")
        public = (fx.directory / ".envdirx.pub").read_bytes()
        [key] = list(keys.iterdir())
        self.assertEqual(key.name, hashlib.sha256(public).hexdigest() + ".key")
        self.assertRegex(key.name, r"^[0-9a-f]{64}\.key$")
        self.assertEqual(_public_of(key), public)
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(os.readlink(fx.directory / ".envdirx.key"), str(key))
        fx.on("set", "-c", "TOKEN", input=SECRET + b"\n")
        fx.run_ok()
        other = fx.root / "other"
        other.mkdir()
        _keygen(fx, "--key-dir", "~/", directory=other)
        self.assertEqual(Path(os.readlink(other / ".envdirx.key")).parent, fx.home)
        self.assertNotIn(SECRET, (fx.directory / "TOKEN").read_bytes())

    def test_option_errors_write_nothing(self):
        fx = Fixture(self)
        (fx.root / "keys").mkdir()
        before = fx.snapshot()
        for args in (["-k", fx.root / "a.key", "-K", fx.root / "keys"], ["-f", "-k", fx.root / "a.key"], ["-k", fx.root / "a.key", "--force"], ["-k"], ["-K"], ["--key-dir"]):
            with self.subTest(args=args):
                result = fx.on("keygen", *args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(fx.snapshot(), before)

    def test_collisions_preserve_existing_entries(self):
        cases = {
            "public key": lambda fx: (fx.directory / ".envdirx.pub").write_bytes(b"p"),
            "pointer file": lambda fx: (fx.directory / ".envdirx.key").write_text("/x\n"),
            "dangling pointer": lambda fx: (fx.directory / ".envdirx.key").symlink_to("nowhere"),
            "dangling public": lambda fx: (fx.directory / ".envdirx.pub").symlink_to("nowhere"),
            "key file": lambda fx: (fx.root / "svc.key").write_bytes(b"k"),
            "dangling key": lambda fx: (fx.root / "svc.key").symlink_to("nowhere"),
            "key is directory": lambda fx: (fx.root / "svc.key").mkdir(),
        }
        for name, prepare in cases.items():
            with self.subTest(name):
                fx = Fixture(self)
                prepare(fx)
                before = fx.snapshot()
                result = fx.on("keygen", "-k", fx.root / "svc.key")
                self.assertEqual(result.returncode, 111, result.stderr)
                self.assertIn(b"refusing to overwrite", result.stderr)
                self.assertEqual(fx.snapshot(), before)

    def test_unsafe_destinations_write_nothing(self):
        fx = Fixture(self)
        (fx.root / "file").write_bytes(b"")
        alias = fx.root / "alias"
        alias.symlink_to(fx.directory)
        (fx.directory / "sub").mkdir()
        bad = (
            ("-k", fx.directory / "k"),
            ("-k", alias / "k"),
            ("-k", fx.directory / "sub" / "k"),
            ("-k", fx.directory / ".." / "service" / "k"),
            ("-k", fx.root / "missing-parent" / "k"),
            ("-k", fx.root / "file" / "k"),
            ("-k", fx.directory),
            ("-k", fx.root / "x" / ".."),
            ("-K", fx.directory),
            ("-K", alias),
            ("-K", fx.directory / "sub"),
            ("-K", fx.root / "missing"),
            ("-K", fx.root / "file"),
        )
        before = fx.snapshot()
        for option, destination in bad:
            with self.subTest(option=option, destination=destination):
                result = fx.on("keygen", option, destination)
                self.assertEqual(result.returncode, 111, result.stderr)
                self.assertEqual(fx.snapshot(), before)
        result = fx.on("keygen", "-K", alias)
        self.assertIn(b"outside the envdir", result.stderr)

    def test_failure_removes_only_created_files(self):
        for failing in ("public", "pointer"):
            with self.subTest(failing=failing):
                fx = Fixture(self)
                (fx.directory / "TOKEN").write_bytes(b"keep")
                (fx.root / "other.key").write_bytes(b"keep")
                before = fx.snapshot()
                real_create, real_link = envdirx._create, envdirx._link
                calls = []

                def create(path, data, mode):
                    calls.append(path)
                    if failing == "public" and path.name == ".envdirx.pub":
                        raise OSError("disk full")
                    real_create(path, data, mode)

                def link(path, target):
                    calls.append(path)
                    if failing == "pointer":
                        raise OSError("disk full")
                    real_link(path, target)

                argv = ["envdirx", "-d", str(fx.directory), "keygen", "-k", str(fx.root / "svc.key")]
                with mock.patch.object(envdirx, "_create", create), mock.patch.object(envdirx, "_link", link), mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        envdirx.main()
                self.assertEqual(raised.exception.code, 111)
                self.assertEqual(len(calls), 2 if failing == "public" else 3)
                self.assertEqual(fx.snapshot(), before)


class DefaultKeyDirectoryTest(unittest.TestCase):
    """keygen without -k/-K: XDG data key store, created lazily at 0700, validated before creation."""

    def keygen(self, fx, xdg=None, umask=-1, directory=None):
        if xdg is None:
            fx.env.pop("XDG_DATA_HOME", None)
        else:
            fx.env["XDG_DATA_HOME"] = str(xdg)
        return fx.on("keygen", directory=directory, umask=umask)

    def assert_key(self, fx, store, directory=None):
        directory = directory or fx.directory
        public = (directory / ".envdirx.pub").read_bytes()
        key = store / (hashlib.sha256(public).hexdigest() + ".key")
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(_public_of(key), public)
        self.assertEqual((directory / ".envdirx.pub").stat().st_mode & 0o777, 0o644)
        self.assertEqual(os.readlink(directory / ".envdirx.key"), str(key))
        return key

    def test_location_modes_and_roundtrip(self):
        for value in (None, "", "relative/data", "~/data", "absolute"):
            for umask in (0o077, 0o000):
                with self.subTest(xdg=value, umask=oct(umask)):
                    fx = Fixture(self)
                    if value == "absolute":
                        xdg = fx.root / "xdg"
                        base, created = xdg, [xdg, xdg / "envdirx", xdg / "envdirx" / "keys"]
                    else:
                        xdg, base = value, fx.home / ".local" / "share"
                        created = [fx.home / ".local", base, base / "envdirx", base / "envdirx" / "keys"]
                    result = self.keygen(fx, xdg, umask=umask)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, b"")
                    for path in created:
                        self.assertEqual(path.stat().st_mode & 0o777, 0o700, path)
                    self.assert_key(fx, base / "envdirx" / "keys")
                    self.assertFalse((fx.root / "relative").exists())
                    self.assertFalse((fx.root / "~").exists(), "literal ~ must not be expanded or created")
                    self.assertEqual(fx.on("set", "-c", "TOKEN", input=SECRET + b"\n").returncode, 0)
                    self.assertEqual(fx.on("get", "TOKEN").stdout, SECRET + b"\n")
                    fx.run_ok()

    def test_existing_store_is_preserved_and_pointers_survive_xdg_changes(self):
        fx = Fixture(self)
        store = fx.home / ".local" / "share" / "envdirx" / "keys"
        store.mkdir(parents=True)
        for path in (store, *store.parents):
            if fx.home in path.parents:
                path.chmod(0o755)
        (store / "existing.key").write_bytes(b"keep")
        other = fx.root / "other"
        other.mkdir()
        self.assertEqual(self.keygen(fx).returncode, 0)
        self.assertEqual(self.keygen(fx, directory=other).returncode, 0)
        first, second = self.assert_key(fx, store), self.assert_key(fx, store, other)
        self.assertNotEqual(first, second)
        self.assertEqual((store / "existing.key").read_bytes(), b"keep")
        for path in (store, store.parent, store.parent.parent, fx.home / ".local"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o755, path)
        fx.on("set", "-c", "TOKEN", input=SECRET + b"\n")
        fx.env["XDG_DATA_HOME"] = str(fx.root / "moved")
        fx.run_ok()
        self.assertEqual(fx.on("get", "TOKEN").stdout, SECRET + b"\n")
        self.assertFalse((fx.root / "moved").exists())

    def test_explicit_destinations_ignore_default(self):
        fx = Fixture(self)
        (fx.root / "blocked").write_bytes(b"")  # an XDG root that would fail if consulted
        fx.env["XDG_DATA_HOME"] = str(fx.root / "blocked")
        keys = fx.root / "keys"
        keys.mkdir()
        other = fx.root / "other"
        other.mkdir()
        _keygen(fx, "-k", fx.root / "svc.key")
        _keygen(fx, "-K", keys, directory=other)
        third = fx.root / "third"
        third.mkdir()
        before = fx.snapshot()
        result = fx.on("keygen", "-K", fx.root / "absent", directory=third)
        self.assertEqual(result.returncode, 111, result.stderr)
        self.assertEqual(fx.snapshot(), before)
        self.assertFalse((fx.home / ".local").exists())

    def test_unsafe_defaults_fail_closed_before_creation(self):
        def alias(fx):
            (fx.root / "alias").symlink_to(fx.directory)
            return fx.root / "alias"

        def keys_link(target):
            def prepare(fx):
                (fx.root / "xdg" / "envdirx").mkdir(parents=True)
                (fx.root / "xdg" / "envdirx" / "keys").symlink_to(target(fx))
                return fx.root / "xdg"
            return prepare

        def file_at(relative):
            def prepare(fx):
                path = fx.root / "xdg" / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"keep")
                return fx.root / "xdg"
            return prepare

        def cycle(fx):
            (fx.root / "xdg").mkdir()
            (fx.root / "xdg" / "envdirx").symlink_to(fx.root / "xdg" / "loop")
            (fx.root / "xdg" / "loop").symlink_to(fx.root / "xdg" / "envdirx")
            return fx.root / "xdg"

        cases = {
            "envdir": lambda fx: fx.directory,
            "envdir alias": alias,
            "missing descendant": lambda fx: fx.directory / "sub",
            "keys links into envdir": keys_link(lambda fx: fx.directory),
            "dangling keys": keys_link(lambda fx: fx.root / "nowhere"),
            "keys is file": file_at("envdirx/keys"),
            "parent is file": file_at("envdirx"),
            "cyclic link": cycle,
            "dotdot through missing": lambda fx: fx.root / "missing" / ".." / "x",
        }
        for name, prepare in cases.items():
            with self.subTest(name):
                fx = Fixture(self)
                xdg = prepare(fx)
                before = fx.snapshot()
                result = self.keygen(fx, xdg)
                self.assertEqual(result.returncode, 111, result.stderr)
                self.assertEqual(result.stdout, b"")
                self.assertTrue(result.stderr.startswith(b"envdirx: "), result.stderr)
                self.assertEqual(fx.snapshot(), before)

    def test_envdir_and_metadata_checks_precede_creation(self):
        for name in ("missing envdir", ".envdirx.pub", ".envdirx.key"):
            with self.subTest(name):
                fx = Fixture(self)
                if name == "missing envdir":
                    fx.directory.rmdir()
                else:
                    (fx.directory / name).write_bytes(b"keep")
                before = fx.snapshot()
                result = self.keygen(fx)
                self.assertEqual(result.returncode, 111, result.stderr)
                self.assertEqual(fx.snapshot(), before)
                self.assertFalse((fx.home / ".local").exists())

    def main(self, fx, environ, patches=()):
        """Run main() in-process for keygen without destinations; return the exit code."""
        argv = ["envdirx", "-d", str(fx.directory), "keygen"]
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, environ))
            if "XDG_DATA_HOME" not in environ:
                os.environ.pop("XDG_DATA_HOME", None)  # restored by patch.dict
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            stdout = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            for patch in patches:
                stack.enter_context(patch)
            with self.assertRaises(SystemExit) as raised:
                envdirx.main()
        self.assertEqual(stdout.getvalue(), "")
        return raised.exception.code

    def test_injected_failures_clean_new_artifacts(self):
        fx = Fixture(self)
        (fx.directory / "TOKEN").write_bytes(b"keep")
        store = fx.root / "xdg" / "envdirx" / "keys"
        real_create = envdirx._create

        def create(path, data, mode):
            if path.name == ".envdirx.pub":
                raise OSError("disk full")
            real_create(path, data, mode)

        code = self.main(fx, {"XDG_DATA_HOME": str(fx.root / "xdg")}, [mock.patch.object(envdirx, "_create", create)])
        self.assertEqual(code, 111)
        self.assertEqual(list(store.iterdir()), [], "new key is removed; the empty store may remain")
        self.assertEqual(sorted(p.name for p in fx.directory.iterdir()), ["TOKEN"])
        self.assertEqual((fx.directory / "TOKEN").read_bytes(), b"keep")

    def test_filesystem_and_home_errors_exit_111(self):
        fx = Fixture(self)
        before = fx.snapshot()
        denied = mock.patch.object(envdirx.os, "mkdir", side_effect=PermissionError(13, "Permission denied"))
        self.assertEqual(self.main(fx, {"XDG_DATA_HOME": str(fx.root / "xdg")}, [denied]), 111)
        homeless = mock.patch.object(envdirx.Path, "home", side_effect=RuntimeError("Could not determine home directory."))
        self.assertEqual(self.main(fx, {"HOME": str(fx.home)}, [homeless]), 111)
        self.assertEqual(fx.snapshot(), before)

    def test_resolve_runtime_error_exits_111(self):
        fx = Fixture(self)
        xdg = fx.root / "xdg"
        xdg.mkdir()
        before = fx.snapshot()
        resolve = Path.resolve

        def fail_store(path, *args, **kwargs):
            if path == xdg:
                raise RuntimeError("Symlink loop")
            return resolve(path, *args, **kwargs)

        patch = mock.patch.object(envdirx.Path, "resolve", fail_store)
        self.assertEqual(self.main(fx, {"XDG_DATA_HOME": str(xdg)}, [patch]), 111)
        self.assertEqual(fx.snapshot(), before)

    def test_fingerprint_collision_preserves_existing_key(self):
        fx = Fixture(self)
        fixed = X25519PrivateKey.generate()
        public = fixed.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        store = fx.root / "xdg" / "envdirx" / "keys"
        store.mkdir(parents=True)
        (store / (hashlib.sha256(public).hexdigest() + ".key")).write_bytes(b"keep")
        before = fx.snapshot()
        generate = mock.patch.object(envdirx.X25519PrivateKey, "generate", return_value=fixed)
        self.assertEqual(self.main(fx, {"XDG_DATA_HOME": str(fx.root / "xdg")}, [generate]), 111)
        self.assertEqual(fx.snapshot(), before)


BARRIER = """
import os, signal, sys
from pathlib import Path
import envdirx
real, target, when = envdirx._exchange, Path(sys.argv[1]), sys.argv[2]

def exchange(a, b):
    if Path(a) == target and when == "before":
        os.kill(os.getpid(), signal.SIGKILL)
    real(a, b)
    if Path(a) == target and when == "after":
        os.kill(os.getpid(), signal.SIGKILL)

envdirx._exchange = exchange
sys.argv = ["envdirx", *sys.argv[3:]]
envdirx.main()
"""


class RekeyTest(unittest.TestCase):
    """rekey: in-place rotation to a fresh key by one atomic exchange, fail-closed, never writing decrypted values."""

    def mixed(self, fx, dir_mode=0o700, plain_mode=0o644):
        """Envdir with printable/legacy ciphertext, binary/empty/reserved values, plaintext and a random sentinel."""
        fx.keygen_encrypted()
        self.sentinel = os.urandom(16).hex().encode()
        public = envdirx.X25519PublicKey.from_public_bytes((fx.directory / ".envdirx.pub").read_bytes())
        encrypted = {"BIN": b"\x00\xffa\nb\x00", "VOID": b"", "PREFIXED": b"envdirx:v1:looks-encrypted", "SENTINEL": self.sentinel}
        for name, value in encrypted.items():
            (fx.directory / name).write_bytes(envdirx._encrypt(value, name, public))
        printable = envdirx._encrypt(self.sentinel + b"-legacy", "OLDFORM", public)
        legacy = envdirx.LEGACY_MAGIC + base64.b64decode(printable[len(envdirx.MAGIC):].removesuffix(b"\n"), validate=True)
        (fx.directory / "OLDFORM").write_bytes(legacy)
        encrypted["OLDFORM"] = self.sentinel + b"-legacy"
        encrypted["TOKEN"] = SECRET + b"\n"
        plain = {"PLAIN": b"plain-value\n", "EMPTY": b""}
        for name, value in plain.items():
            (fx.directory / name).write_bytes(value)
            (fx.directory / name).chmod(plain_mode)
        fx.directory.chmod(dir_mode)
        self.encrypted, self.plain = encrypted, plain
        self.old_key = fx.root / "service.key"
        self.old_key_bytes = self.old_key.read_bytes()
        self.old_ciphertext = {name: (fx.directory / name).read_bytes() for name in encrypted}
        self.dir_mode, self.plain_mode = dir_mode, plain_mode

    def residue(self, fx):
        return sorted(p for p in fx.root.iterdir() if p.name.startswith(".envdirx-"))

    def outside(self, fx):
        """Bytes/link targets of every path outside the envdir and the new-key locations (old key, HOME, ...)."""
        skip = (fx.directory, fx.root / "new.key", fx.root / "xdg")
        return {p: v for p, v in fx.snapshot().items() if not any(envdirx._inside(p, s) for s in skip) and not p.name.startswith(".envdirx-")}

    def assert_clean(self, fx, result, *outputs):
        """No sentinel/secret/key bytes in any file under the fixture (incl. isolated HOME) or OUTPUTS."""
        secrets = [self.sentinel, self.sentinel + b"-legacy", SECRET]
        keys = [p.read_bytes() for p in fx.root.rglob("*.key") if p.is_file() and not p.is_symlink()]
        for path in fx.root.rglob("*"):
            if path.is_file() and not path.is_symlink() and path.name not in self.plain:
                for secret in secrets:
                    self.assertNotIn(secret, path.read_bytes(), path)
        for output in (result.stdout, result.stderr, *outputs):
            for secret in secrets + keys:
                self.assertNotIn(secret, output)

    def rekey(self, fx, *args, umask=-1, directory=None, cwd=None):
        return fx.call("-d", directory or fx.directory, "rekey", *args, umask=umask, cwd=cwd)

    def fails(self, fx, *args, directory=None, code=111, cwd=None):
        before = fx.snapshot()
        result = self.rekey(fx, *args, directory=directory, cwd=cwd)
        self.assertEqual(result.returncode, code, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(fx.snapshot(), before, "nothing is written")
        if code == 111:
            self.assertTrue(result.stderr.startswith(b"envdirx: "), result.stderr)
        self.assert_clean(fx, result)
        return result

    def assert_rotated(self, fx, key):
        """FX.directory, at its unchanged path, holds every value under KEY; the old key is untouched and useless."""
        envdir = fx.directory
        self.assertEqual(envdir.stat().st_mode & 0o777, self.dir_mode)
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        public = envdir / ".envdirx.pub"
        self.assertEqual(public.stat().st_mode & 0o777, 0o644)
        self.assertEqual(_public_of(key), public.read_bytes())
        self.assertEqual(os.readlink(envdir / ".envdirx.key"), str(key))
        self.assertTrue(os.path.isabs(os.readlink(envdir / ".envdirx.key")))
        self.assertEqual(self.old_key.read_bytes(), self.old_key_bytes, "old key unchanged")
        self.assertNotEqual(key.read_bytes(), self.old_key_bytes)
        names = {**self.encrypted, **self.plain}
        self.assertEqual(sorted(p.name for p in envdir.iterdir()), sorted([".envdirx.key", ".envdirx.pub", *names]))
        for name, value in self.plain.items():
            self.assertEqual((envdir / name).read_bytes(), value)
            self.assertEqual((envdir / name).stat().st_mode & 0o777, self.plain_mode, name)
        for name, value in self.encrypted.items():
            stored = (envdir / name).read_bytes()
            self.assertTrue(stored.startswith(envdirx.MAGIC) and stored.endswith(b"\n"), name)
            self.assertEqual(stored.count(b"\n"), 1)
            self.assertNotEqual(stored, self.old_ciphertext[name])
            self.assertEqual((envdir / name).stat().st_mode & 0o777, 0o600)
            result = fx.on("get", name)
            self.assertEqual((result.returncode, result.stdout), (0, value), result.stderr)
            # The old key cannot read the new ciphertext.
            self.assertEqual(fx.on("get", "--key", self.old_key, name).returncode, 111)
        self.assertEqual(self.residue(fx), [], "no staging or probe directory remains")

    def test_same_path_rotation_preserves_values_and_modes(self):
        for dir_mode, plain_mode in ((0o700, 0o644), (0o500, 0o444), (0o755, 0o600)):
            for umask in (0o000, 0o022, 0o077):
                with self.subTest(dir_mode=oct(dir_mode), plain_mode=oct(plain_mode), umask=oct(umask)):
                    fx = Fixture(self)
                    self.mixed(fx, dir_mode, plain_mode)
                    before = self.outside(fx)
                    key = fx.root / "new.key"
                    result = self.rekey(fx, "-k", key, umask=umask)
                    self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"", b""))
                    self.assertEqual(self.outside(fx), before, "old key and everything else unchanged")
                    self.assert_rotated(fx, key)
                    self.assertEqual(sorted(p.name for p in fx.root.iterdir()), ["home", "new.key", "service", "service.key"], "no second envdir")
                    child = fx.on("run", "--", *SHOW)
                    self.assertEqual(child.returncode, 0, child.stderr)
                    self.assertEqual(json.loads(child.stdout)["PLAIN"], "plain-value")
                    self.assertEqual(json.loads(child.stdout)["TOKEN"], "top-secret-value")
                    self.assertEqual(fx.on("get", "SENTINEL").stdout, self.sentinel)
                    self.assert_clean(fx, result)

    def test_symlink_alias_relative_and_tilde_paths(self):
        fx = Fixture(self)
        self.mixed(fx)
        (fx.root / "alias").symlink_to("service")
        (fx.home / "keys").mkdir()
        result = fx.call("-d", "alias", "rekey", "-K", "~/keys")
        self.assertEqual((result.returncode, result.stdout), (0, b""), result.stderr)
        self.assertEqual(os.readlink(fx.root / "alias"), "service", "the caller's alias stays a symlink")
        key = fx.home / "keys" / (hashlib.sha256((fx.directory / ".envdirx.pub").read_bytes()).hexdigest() + ".key")
        self.assert_rotated(fx, key)
        self.assertEqual(fx.call("-d", "alias", "get", "SENTINEL").stdout, self.sentinel)
        os.symlink(fx.root, fx.root / "rootalias")
        self.old_key, self.old_key_bytes = key, key.read_bytes()
        self.old_ciphertext = {name: (fx.directory / name).read_bytes() for name in self.encrypted}
        result = fx.call("-d", "service", "rekey", "-k", "rootalias/new2.key")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_rotated(fx, fx.root / "new2.key")

    def test_old_key_selection_and_missing_metadata(self):
        fx = Fixture(self)
        self.mixed(fx)
        moved = fx.move_key(fx.root / "elsewhere" / "old.key")
        self.old_key = moved
        (fx.directory / ".envdirx.pub").unlink()
        self.fails(fx, "-k", fx.root / "new.key")
        result = self.rekey(fx, "--key", moved, "-k", fx.root / "new.key")
        self.assertEqual((result.returncode, result.stdout), (0, b""), result.stderr)
        self.assert_rotated(fx, fx.root / "new.key")
        # The pointer is matched by name only: a directory there is ignored with --key and removed with the old tree.
        (fx.directory / ".envdirx.key").unlink()
        (fx.directory / ".envdirx.key").mkdir(mode=0o500)
        self.old_ciphertext = {name: (fx.directory / name).read_bytes() for name in self.encrypted}
        result = self.rekey(fx, "--key", fx.root / "new.key", "-k", fx.root / "new3.key")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.old_key, self.old_key_bytes = fx.root / "new.key", (fx.root / "new.key").read_bytes()
        self.assert_rotated(fx, fx.root / "new3.key")

    def test_plaintext_only_and_empty_need_no_old_key(self):
        for contents in ({}, {"PLAIN": b"p\n", "EMPTY": b""}):
            with self.subTest(names=sorted(contents)):
                fx = Fixture(self)
                for name, value in contents.items():
                    (fx.directory / name).write_bytes(value)
                    (fx.directory / name).chmod(0o644)
                (fx.directory / ".envdirx.key").symlink_to("missing")  # never read without ciphertext
                result = self.rekey(fx, "--key", fx.root / "missing.key", "-k", fx.root / "new.key")
                self.assertEqual((result.returncode, result.stdout), (0, b""), result.stderr)
                self.assertEqual(sorted(p.name for p in fx.directory.iterdir()), sorted([".envdirx.key", ".envdirx.pub", *contents]))
                for name, value in contents.items():
                    self.assertEqual((fx.directory / name).read_bytes(), value)
                    self.assertEqual((fx.directory / name).stat().st_mode & 0o777, 0o644, name)
                self.assertEqual(_public_of(fx.root / "new.key"), (fx.directory / ".envdirx.pub").read_bytes())
                self.assertEqual(os.readlink(fx.directory / ".envdirx.key"), str(fx.root / "new.key"))
                self.assertEqual(self.residue(fx), [])

    def test_default_and_explicit_key_stores(self):
        for label in ("home", "xdg", "keydir", "keyfile"):
            for umask in (0o022, 0o077):
                with self.subTest(label, umask=oct(umask)):
                    fx = Fixture(self)
                    self.mixed(fx)
                    args = []
                    if label == "xdg":
                        fx.env["XDG_DATA_HOME"] = str(fx.root / "xdg")
                        store = fx.root / "xdg" / "envdirx" / "keys"
                    elif label == "home":
                        store = fx.home / ".local" / "share" / "envdirx" / "keys"
                    elif label == "keydir":
                        store = fx.root / "keys"
                        store.mkdir(mode=0o755)
                        store.chmod(0o755)
                        args = ["-K", store]
                    else:
                        args = ["--new-key", fx.root / "file.key"]
                    result = self.rekey(fx, *args, umask=umask)
                    self.assertEqual((result.returncode, result.stdout), (0, b""), result.stderr)
                    if label == "keyfile":
                        key = fx.root / "file.key"
                    else:
                        key = store / (hashlib.sha256((fx.directory / ".envdirx.pub").read_bytes()).hexdigest() + ".key")
                        expected = 0o755 if label == "keydir" else 0o700
                        self.assertEqual(store.stat().st_mode & 0o777, expected)
                    self.assert_rotated(fx, key)
                    if label != "home":
                        self.assertFalse((fx.home / ".local").exists())
                    if label == "keyfile":  # no overwrite: the same key file is refused for a second rotation
                        self.fails(fx, *args)

    def test_validation_refusals_write_nothing(self):
        def wrong_name(fx):
            (fx.directory / "COPY").write_bytes((fx.directory / "TOKEN").read_bytes())

        def wrong_key(fx):
            other = fx.root / "other.key"
            other.write_bytes(envdirx._raw(X25519PrivateKey.generate())[0])
            other.chmod(0o600)
            return ["--key", other, "-k", fx.root / "new.key"]

        def readonly_parent(fx):
            fx.root.chmod(0o555)
            self.addCleanup(fx.root.chmod, 0o755)

        new_key = lambda fx: fx.root / "new.key"
        cases = {
            "malformed": lambda fx: (fx.directory / "BAD").write_bytes(b"encrypted:B!!!\n"),
            "truncated legacy": lambda fx: (fx.directory / "BAD").write_bytes(envdirx.LEGACY_MAGIC + b"short"),
            "unsupported": lambda fx: (fx.directory / "BAD").write_bytes(b"encrypted:Xfuture"),
            "wrong name": wrong_name,
            "wrong key": wrong_key,
            "missing pointer": lambda fx: (fx.directory / ".envdirx.key").unlink(),
            "symlink entry": lambda fx: (fx.directory / "LINK").symlink_to(fx.directory / "PLAIN"),
            "directory entry": lambda fx: (fx.directory / "SUB").mkdir(),
            "invalid name": lambda fx: (fx.directory / "A=B").write_bytes(b"x"),
            "unexpected dotfile": lambda fx: (fx.directory / ".env").write_bytes(b"x"),
            "existing key file": lambda fx: (fx.root / "new.key").write_bytes(b"keep"),
            "dangling key file": lambda fx: (fx.root / "new.key").symlink_to("nowhere"),
            "default store after bad entry": lambda fx: ((fx.directory / "BAD").write_bytes(b"encrypted:B!!!\n"), [])[1],
            "key inside envdir": lambda fx: ["-k", fx.directory / "new.key"],
            "key inside envdir alias": lambda fx: ((fx.root / "alias").symlink_to(fx.directory), ["-k", fx.root / "alias" / "new.key"])[1],
            "key equals envdir": lambda fx: ["-k", fx.directory],
            "key equals old key": lambda fx: ["-k", fx.root / "service.key"],
            "key dir missing": lambda fx: ["-K", fx.root / "nokeys"],
            "key dir is envdir": lambda fx: ["-K", fx.directory],
            "default store in envdir": lambda fx: (fx.env.__setitem__("XDG_DATA_HOME", str(fx.directory / "xdg")), [])[1],
            "parent not writable": readonly_parent,
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                fx = Fixture(self)
                self.mixed(fx)
                args = mutate(fx)
                args = args if isinstance(args, list) else ["-k", new_key(fx)]
                self.fails(fx, *args)
                self.assertFalse((fx.home / ".local").exists(), "default store is not created")
                self.assertFalse((fx.root / "xdg").exists())
                self.assertEqual(self.residue(fx), [])

    def test_unsafe_rotation_targets_write_nothing(self):
        fx = Fixture(self)
        self.mixed(fx)
        (fx.root / "alias").symlink_to(fx.directory)
        for label, kwargs in (
            ("cwd is DIR", {"cwd": fx.directory}),
            ("cwd inside DIR", {"cwd": fx.directory / "sub"}),
            ("cwd inside DIR through alias", {"cwd": fx.root / "alias" / "sub"}),
            ("filesystem root", {"directory": Path("/")}),
        ):
            with self.subTest(label):
                (fx.directory / "sub").mkdir(exist_ok=True)  # would be refused as an entry, but the target check comes first
                result = self.fails(fx, "-k", fx.root / "new.key", **kwargs)
                self.assertIn(b"current directory" if "cwd" in label else b"root or mountpoint", result.stderr)
        (fx.directory / "sub").rmdir()
        with mock.patch.object(envdirx.os.path, "ismount", side_effect=lambda path: Path(path) == fx.directory):
            before = fx.snapshot()
            code, stderr, writes = self.main(fx, ["-k", fx.root / "new.key"])
            self.assertEqual((code, writes), (111, []))
            self.assertIn(b"mountpoint", stderr)
            self.assertEqual(fx.snapshot(), before)

    def test_missing_source_fails(self):
        fx = Fixture(self)
        self.sentinel, self.plain = b"unused-sentinel", {}
        fx.directory.rmdir()
        self.fails(fx, "-k", fx.root / "new.key")

    def test_parser_errors_write_nothing(self):
        fx = Fixture(self)
        self.mixed(fx)
        key = str(fx.root / "new.key")
        for args in (["--output", str(fx.root / "new")], ["--output"], ["--output", ""], ["--output=x", "-k", key], ["--key", str(self.old_key), "--output", "x"]):
            with self.subTest(args=args):
                result = self.fails(fx, *args, code=2)
                self.assertIn(b"--output was removed: rekey now rotates the key in place at DIR (use -d DIR)", result.stderr)
        for args in (["-k", key, "-K", str(fx.root)], ["-o", "new"], ["--bogus"], ["-K"], ["-k"], ["--key"], ["extra"]):
            with self.subTest(args=args):
                self.fails(fx, *args, code=2)
        before = fx.snapshot()
        result = fx.call("-d", fx.directory, "-d", fx.root, "rekey", "-k", key)
        self.assertEqual((result.returncode, result.stdout), (2, b""))
        self.assertEqual(fx.snapshot(), before)

    def test_default_directory_selection(self):
        fx = Fixture(self)
        self.mixed(fx)
        fx.directory.rename(fx.root / ".envs")
        fx.directory = fx.root / ".envs"
        result = fx.call("rekey", "-k", "new.key")
        self.assertEqual((result.returncode, result.stdout), (0, b""), result.stderr)
        self.assert_rotated(fx, fx.root / "new.key")

    def main(self, fx, args, patches=(), environ=None):
        """Run main() in-process; record every write; return (code, stderr, writes)."""
        argv = ["envdirx", "-d", str(fx.directory), "rekey", *map(str, args)]
        writes, opened = [], []

        def create(path, data, mode):
            writes.append((Path(path), data))
            return real_create(path, data, mode)

        def link(path, target):
            writes.append((Path(path), os.fsencode(target)))
            return real_link(path, target)

        def tracking_open(path, flags, *rest, **kwargs):
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC):
                opened.append(Path(path))
            return real_open(path, flags, *rest, **kwargs)

        stderr = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(fx.home), **(environ or {})}))
            if not environ or "XDG_DATA_HOME" not in environ:
                os.environ.pop("XDG_DATA_HOME", None)  # restored by patch.dict
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            stdout = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            for patch in patches:
                stack.enter_context(patch)
            # Record on top of any injected failure so attempted writes are inspected too.
            real_create, real_link, real_open = envdirx._create, envdirx._link, os.open
            stack.enter_context(mock.patch.object(envdirx, "_create", create))
            stack.enter_context(mock.patch.object(envdirx, "_link", link))
            stack.enter_context(mock.patch.object(envdirx.os, "open", tracking_open))
            try:
                envdirx.main()
                code = 0
            except SystemExit as exc:
                code = exc.code
        self.assertEqual(stdout.getvalue(), "")
        # Every file opened for writing went through the recorded writers.
        self.assertLessEqual(set(opened), {path for path, _ in writes}, "no unrecorded write")
        for path, data in writes:
            for secret in (self.sentinel, self.sentinel + b"-legacy", SECRET):
                self.assertNotIn(secret, data, path)
        return code, stderr.getvalue().encode(), writes

    def test_intercepted_writes_on_success(self):
        fx = Fixture(self)
        self.mixed(fx)
        before = fx.snapshot()
        key = fx.root / "new.key"
        code, stderr, writes = self.main(fx, ["-k", key])
        self.assertEqual(code, 0, stderr)
        self.assertEqual(writes[0], (key, key.read_bytes()))
        staged = {path.name for path, _ in writes[1:]}
        self.assertEqual(staged, {p.name for p in fx.directory.iterdir()})
        self.assertTrue(all(path.parent.name.startswith(".envdirx-rekey-") and path.parent.parent == fx.root for path, _ in writes[1:]))
        self.assertEqual(set(fx.snapshot()) - set(before), {key})
        self.assert_rotated(fx, key)
        self.assert_clean(fx, subprocess.CompletedProcess([], 0, b"", stderr))

    def exchange_wrapper(self, fx, before=None, after=None, probe=None):
        """Patch _exchange: run BEFORE/AFTER around the real publication swap, PROBE instead of the probe swap."""
        real = envdirx._exchange

        def exchange(a, b):
            if Path(a) != fx.directory:
                return probe(a, b) if probe else real(a, b)
            if before:
                before(a, b)
            real(a, b)
            if after:
                after(a, b)
        return mock.patch.object(envdirx, "_exchange", exchange)

    @staticmethod
    def raiser(exc):
        def fail(*args, **kwargs):
            raise exc
        return fail

    @staticmethod
    def fail_directory_fsync(match):
        real = os.fsync

        def fsync(fd):
            st = os.fstat(fd)
            if stat.S_ISDIR(st.st_mode) and match(st):
                raise OSError(errno.EINVAL, "Invalid argument")
            return real(fd)
        return mock.patch.object(envdirx.os, "fsync", fsync)

    def test_injected_failures_before_commit_change_nothing(self):
        def fail_create(predicate):
            real = envdirx._create

            def create(path, data, mode):
                if predicate(Path(path)):
                    raise OSError(28, "No space left on device")
                return real(path, data, mode)
            return mock.patch.object(envdirx, "_create", create)

        def fail_mkdtemp(prefix):
            real = tempfile.mkdtemp

            def mkdtemp(*args, **kwargs):
                if kwargs.get("prefix") == prefix:
                    raise OSError(13, "Permission denied")
                return real(*args, **kwargs)
            return mock.patch.object(envdirx.tempfile, "mkdtemp", mkdtemp)

        real_encrypt = envdirx._encrypt
        root = lambda fx: (fx.root.stat().st_dev, fx.root.stat().st_ino)
        cases = {
            "verification": lambda fx: [mock.patch.object(envdirx, "_encrypt", lambda data, name, public: real_encrypt(data + b"!", name, public))],
            "probe unsupported": lambda fx: [self.exchange_wrapper(fx, probe=self.raiser(OSError(errno.ENOTSUP, "Operation not supported")))],
            "probe missing symbol": lambda fx: [self.exchange_wrapper(fx, probe=self.raiser(ValueError(envdirx.EXCHANGE_UNSUPPORTED)))],
            "probe directory": lambda fx: [fail_mkdtemp(".envdirx-probe-")],
            "new key write": lambda fx: [fail_create(lambda p: p.suffix == ".key" and p.parent.name in ("keys", fx.root.name))],
            "staging directory": lambda fx: [fail_mkdtemp(".envdirx-rekey-")],
            "public key write": lambda fx: [fail_create(lambda p: p.name == ".envdirx.pub")],
            "pointer write": lambda fx: [mock.patch.object(envdirx, "_link", side_effect=OSError(5, "I/O error"))],
            "first entry write": lambda fx: [fail_create(lambda p: p.name == "BIN")],
            "later entry write": lambda fx: [fail_create(lambda p: p.name == "VOID")],
            "staging fsync": lambda fx: [self.fail_directory_fsync(lambda st: (st.st_dev, st.st_ino) != root(fx))],
            "final swap unsupported": lambda fx: [self.exchange_wrapper(fx, before=self.raiser(OSError(errno.EXDEV, "Cross-device link")))],
            "interrupt before swap": lambda fx: [self.exchange_wrapper(fx, before=self.raiser(KeyboardInterrupt()))],
        }
        for label, patches in cases.items():
            for store in ("keyfile", "default"):
                with self.subTest(label, store=store):
                    fx = Fixture(self)
                    self.mixed(fx, 0o500, 0o444)
                    before = fx.snapshot()
                    args = ["-k", fx.root / "new.key"] if store == "keyfile" else []
                    environ = {"XDG_DATA_HOME": str(fx.root / "xdg")} if store == "default" else None
                    code, stderr, writes = self.main(fx, args, patches(fx), environ)
                    self.assertEqual(code, 111, stderr)
                    self.assertTrue(stderr.startswith(b"envdirx: "), stderr)
                    self.assertNotIn(b"rotation completed", stderr)
                    after = fx.snapshot()
                    keys = fx.root / "xdg" / "envdirx" / "keys"
                    self.assertEqual(list(keys.iterdir()) if keys.exists() else [], [], "new key removed; empty store may remain")
                    self.assertEqual({p: v for p, v in after.items() if not envdirx._inside(p, fx.root / "xdg")}, before, "envdir and old key unchanged")
                    self.assertEqual(fx.directory.stat().st_mode & 0o777, 0o500)
                    self.assertEqual(self.residue(fx), [])
                    if label.startswith("probe"):
                        self.assertFalse((fx.root / "xdg").exists(), "probe precedes the default store")
                        self.assertIn(b"exchange", stderr)
                    if label == "interrupt before swap":
                        self.assertIn(b"interrupted before publication", stderr)
                    if label == "later entry write":
                        self.assertIn("BIN", {path.name for path, _ in writes}, "an earlier entry was staged first")
                    self.assert_clean(fx, subprocess.CompletedProcess([], 111, b"", stderr))
                    fx.run_ok()

    def test_injected_failures_after_commit_keep_new_key(self):
        root = lambda fx: (fx.root.stat().st_dev, fx.root.stat().st_ino)
        cases = {
            "parent fsync": (lambda fx: [self.fail_directory_fsync(lambda st: (st.st_dev, st.st_ino) == root(fx))], False),
            "old tree cleanup": (lambda fx: [mock.patch.object(envdirx.shutil, "rmtree", side_effect=OSError(errno.EBUSY, "Resource busy"))], True),
            "interrupt after swap": (lambda fx: [self.exchange_wrapper(fx, after=self.raiser(KeyboardInterrupt()))], True),
            "interrupt during cleanup": (lambda fx: [mock.patch.object(envdirx.shutil, "rmtree", side_effect=KeyboardInterrupt())], True),
        }
        for label, (patches, leftover) in cases.items():
            with self.subTest(label):
                fx = Fixture(self)
                self.mixed(fx, 0o500, 0o444)
                key = fx.root / "new.key"
                code, stderr, _ = self.main(fx, ["-k", key], patches(fx))
                self.assertEqual(code, 111, stderr)
                self.assertTrue(stderr.startswith(b"envdirx: rotation completed: "), stderr)
                self.assertIn(str(key).encode(), stderr)
                self.assertNotIn(b"rolled back", stderr)
                residue = self.residue(fx)
                if leftover:
                    self.assertEqual(len(residue), 1)
                    self.assertIn(str(residue[0]).encode(), stderr, "the safe residue path is reported")
                    self.assertEqual(os.readlink(residue[0] / ".envdirx.key"), str(self.old_key), "residue is the previous envdir")
                    self.assertEqual((residue[0] / "TOKEN").read_bytes(), self.old_ciphertext["TOKEN"])
                    envdirx._remove_tree(residue[0])
                self.assert_rotated(fx, key)
                fx.run_ok()
                self.assert_clean(fx, subprocess.CompletedProcess([], 111, b"", stderr))

    def test_unknown_commit_state_retains_everything(self):
        fx = Fixture(self)
        self.mixed(fx)
        key = fx.root / "new.key"

        def replace_envdir(a, b):
            fx.directory.rename(fx.root / "moved")
            fx.directory.mkdir()
            raise OSError(errno.EIO, "I/O error")

        code, stderr, _ = self.main(fx, ["-k", key], [self.exchange_wrapper(fx, before=replace_envdir)])
        self.assertEqual(code, 111, stderr)
        self.assertIn(b"rotation state is unknown", stderr)
        self.assertTrue(key.exists(), "a possibly active key is kept")
        self.assertEqual(len(self.residue(fx)), 1, "the staged tree is kept")
        self.assertEqual(os.readlink(self.residue(fx)[0] / ".envdirx.key"), str(key))

    def test_sigkill_barriers_keep_a_complete_active_envdir(self):
        for when in ("before", "after"):
            with self.subTest(when=when):
                fx = Fixture(self)
                self.mixed(fx)
                key = fx.root / "new.key"
                result = subprocess.run([sys.executable, "-c", BARRIER, str(fx.directory), when, "-d", str(fx.directory), "rekey", "-k", str(key)],
                                        env=fx.env, capture_output=True, cwd=fx.root, timeout=30)
                self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
                self.assertTrue(fx.directory.is_dir(), "the active path never disappears")
                residue = self.residue(fx)
                self.assertEqual(len(residue), 1, "the staged or previous tree remains")
                self.assertTrue(key.exists(), "the new key remains in both cases")
                active, other = (self.old_key, key) if when == "before" else (key, self.old_key)
                self.assertEqual(os.readlink(fx.directory / ".envdirx.key"), str(active))
                self.assertEqual(os.readlink(residue[0] / ".envdirx.key"), str(other))
                for name, value in {**self.encrypted, **self.plain}.items():
                    got = fx.on("get", name)  # a fresh, independent reader of the unchanged path
                    self.assertEqual((got.returncode, got.stdout), (0, value), got.stderr)
                fx.run_ok()
                if when == "after":
                    envdirx._remove_tree(residue[0])
                    self.assert_rotated(fx, key)
                else:
                    self.assertEqual({name: (fx.directory / name).read_bytes() for name in self.encrypted}, self.old_ciphertext)
                self.assert_clean(fx, result)


class NativeExchangeUnitTest(unittest.TestCase):
    """ABI binding and error mapping of the native exchange with fake libc objects; no syscall is made."""

    class Function:
        def __init__(self, result=0):
            self.result, self.calls = result, []

        def __call__(self, *args):
            self.calls.append(args)
            return self.result

    def test_darwin_binding(self):
        libc = types.SimpleNamespace(renamex_np=self.Function())
        envdirx._native_exchange("darwin", libc)(b"a", b"b")
        self.assertEqual(libc.renamex_np.calls, [(b"a", b"b", 2)])
        self.assertEqual(libc.renamex_np.argtypes, (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint))
        self.assertIs(libc.renamex_np.restype, ctypes.c_int)

    def test_linux_binding(self):
        libc = types.SimpleNamespace(renameat2=self.Function())
        envdirx._native_exchange("linux", libc)(b"a", b"b")
        self.assertEqual(libc.renameat2.calls, [(-100, b"a", -100, b"b", 2)])
        self.assertEqual(libc.renameat2.argtypes, (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint))
        self.assertIs(libc.renameat2.restype, ctypes.c_int)

    def test_missing_symbol_and_platform_fail_closed(self):
        both = types.SimpleNamespace(renamex_np=self.Function(), renameat2=self.Function())
        for platform, libc in (("darwin", types.SimpleNamespace()), ("linux", types.SimpleNamespace()), ("win32", both), ("freebsd14", both)):
            with self.subTest(platform=platform):
                with self.assertRaisesRegex(ValueError, "^atomic directory exchange is not supported on this platform/libc$"):
                    envdirx._native_exchange(platform, libc)
        self.assertEqual(both.renamex_np.calls + both.renameat2.calls, [], "no fallback call")

    def test_errno_becomes_oserror(self):
        libc = types.SimpleNamespace(renamex_np=self.Function(-1), renameat2=self.Function(-1))
        with mock.patch.object(envdirx.ctypes, "CDLL", return_value=libc) as cdll, \
                mock.patch.object(envdirx.ctypes, "get_errno", return_value=errno.ENOTSUP):
            with self.assertRaises(OSError) as caught:
                envdirx._exchange(Path("/x/a"), Path("/x/b"))
        cdll.assert_called_once_with(None, use_errno=True)
        exc = caught.exception
        self.assertEqual((exc.errno, exc.strerror, exc.filename, exc.filename2), (errno.ENOTSUP, os.strerror(errno.ENOTSUP), "/x/a", "/x/b"))

    def test_commit_state(self):
        with mock.patch.object(envdirx, "_identity", return_value=(1, 2)):
            self.assertIs(envdirx._commit_state(Path("d"), (1, 1), (1, 2)), True)
            self.assertIs(envdirx._commit_state(Path("d"), (1, 2), None), False)
            self.assertIs(envdirx._commit_state(Path("d"), (1, 1), (1, 3)), None)
        with mock.patch.object(envdirx, "_identity", side_effect=FileNotFoundError):
            self.assertIsNone(envdirx._commit_state(Path("d"), (1, 1), (1, 2)))


class NativeExchangeHostTest(unittest.TestCase):
    """Integration: the host libc exchange really runs (this does not stand in for the other platform)."""

    def test_real_exchange_and_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / "a", Path(tmp) / "b"
            a.mkdir()
            b.mkdir()
            (a / "f").write_bytes(b"A")
            (b / "f").write_bytes(b"B")
            ids = (os.lstat(a).st_ino, os.lstat(b).st_ino)
            envdirx._exchange(a, b)
            self.assertEqual(((a / "f").read_bytes(), (b / "f").read_bytes()), (b"B", b"A"))
            self.assertEqual((os.lstat(a).st_ino, os.lstat(b).st_ino), ids[::-1])
            with self.assertRaises(OSError) as caught:
                envdirx._exchange(a, Path(tmp) / "missing")
            self.assertEqual(caught.exception.errno, errno.ENOENT)
            self.assertEqual(((a / "f").read_bytes(), (b / "f").read_bytes()), (b"B", b"A"))
            envdirx._probe_exchange(Path(tmp))
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["a", "b"], "probes removed")


class KeyMetadataUnitTest(unittest.TestCase):
    """Pure decision logic for key metadata; no filesystem access."""

    def test_check_key(self):
        path = Path("k")
        envdirx._check_key(stat.S_IFREG | 0o600, 501, 501, path)
        envdirx._check_key(stat.S_IFREG | 0o400, 501, 501, path)
        with self.assertRaisesRegex(ValueError, "owned"):
            envdirx._check_key(stat.S_IFREG | 0o600, 0, 501, path)
        with self.assertRaisesRegex(ValueError, "0600"):
            envdirx._check_key(stat.S_IFREG | 0o640, 501, 501, path)
        with self.assertRaisesRegex(ValueError, "regular"):
            envdirx._check_key(stat.S_IFDIR | 0o700, 501, 501, path)

    def test_home_expands_only_leading_tilde_slash(self):
        with mock.patch.object(envdirx.Path, "home", return_value=Path("/h")):
            self.assertEqual(envdirx._home("~/a b"), Path("/h/a b"))
            self.assertEqual(envdirx._home("~user/a"), Path("~user/a"))
            self.assertEqual(envdirx._home("a/~/b"), Path("a/~/b"))

    def test_key_store_selection(self):
        with mock.patch.object(envdirx.Path, "home", return_value=Path("/h")):
            fallback = Path("/h/.local/share/envdirx/keys")
            for environ in ({}, {"XDG_DATA_HOME": ""}, {"XDG_DATA_HOME": "rel"}, {"XDG_DATA_HOME": "~/data"}):
                self.assertEqual(envdirx._key_store(environ), fallback, environ)
            self.assertEqual(envdirx._key_store({"XDG_DATA_HOME": "/x"}), Path("/x/envdirx/keys"))
        with mock.patch.object(envdirx.Path, "home", side_effect=RuntimeError("no home")):
            with self.assertRaisesRegex(ValueError, "home directory"):
                envdirx._key_store({})
            self.assertEqual(envdirx._key_store({"XDG_DATA_HOME": "/x"}), Path("/x/envdirx/keys"))
        with mock.patch.object(envdirx.Path, "home", return_value=Path("")):
            with self.assertRaisesRegex(ValueError, "absolute"):
                envdirx._key_store({})


if __name__ == "__main__":
    unittest.main()
