import contextlib
import io
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import envdirx  # noqa: E402

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

    def call(self, *args, input=None, cwd=None):
        return subprocess.run([*CLI, *map(str, args)], env=self.env, input=input, capture_output=True, cwd=cwd, timeout=30)

    def init_encrypted(self, *extra):
        result = self.call("init", *extra, self.directory)
        self.test.assertEqual(result.returncode, 0, result.stderr)
        self.test.assertEqual(self.call("set", self.directory, "TOKEN", input=SECRET + b"\n").returncode, 0)
        return result

    def move_key(self, destination: Path) -> Path:
        """Move the current key (init default: ROOT/service.key) and drop the pointer."""
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
        result = self.call("run", *before, self.directory, "--", *SHOW)
        self.test.assertEqual(result.returncode, 0, result.stderr)
        self.test.assertIn('"TOKEN": "top-secret-value"', result.stdout.decode())
        return result

    def run_fails(self, *before, directory=None):
        self.marker.unlink(missing_ok=True)
        marker = [sys.executable, "-c", f"open({str(self.marker)!r}, 'w').close()"]
        result = self.call("run", *before, directory or self.directory, "--", *marker)
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
    def test_encrypted_and_plain_envdir_semantics(self):
        fx = Fixture(self)
        directory = fx.directory
        (directory / "TOKEN").write_bytes(b"top-secret  \nignored")
        (directory / "EMPTY").write_bytes(b"\n")
        (directory / "UNSET").write_bytes(b"")
        (directory / "MULTI").write_bytes(b"one\x00two\n")
        self.assertEqual(fx.call("init", directory).returncode, 0)
        key = fx.root / "service.key"
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertEqual((directory / ".envdirx.pub").stat().st_mode & 0o777, 0o644)
        self.assertEqual((directory / ".envdirx.key").stat().st_mode & 0o777, 0o600)
        self.assertEqual((directory / ".envdirx.key").read_bytes(), str(key).encode() + b"\n")
        self.assertEqual(fx.call("encrypt", directory).returncode, 0)
        self.assertNotIn(b"top-secret", (directory / "TOKEN").read_bytes())
        result = fx.call("run", directory, "--", *SHOW)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.decode().strip(), '{"TOKEN": "top-secret", "EMPTY": "", "UNSET": null, "MULTI": "one\\ntwo", "PLAIN": null}')
        self.assertEqual(fx.call("set", directory, "TOKEN", input=b"replacement\n").returncode, 0)
        self.assertIn(b"replacement", fx.call("run", directory, "--", *SHOW).stdout)
        payload = (directory / "TOKEN").read_bytes()
        (directory / "OTHER").write_bytes(payload)
        result = fx.call("run", directory, "--", *SHOW)
        self.assertEqual(result.returncode, 111)
        self.assertNotIn(b"replacement", result.stderr)
        (directory / "OTHER").unlink()
        result = fx.call("run", directory, "--", sys.executable, "-c", "import sys;sys.exit(7)")
        self.assertEqual(result.returncode, 7)
        (directory / "TOKEN").write_bytes(b"envdirx:v2:\nunsafe")
        self.assertEqual(fx.call("run", directory, "--", *SHOW).returncode, 111)

    def test_plaintext_only_run_needs_no_key_or_pointer(self):
        fx = Fixture(self)
        (fx.directory / "PLAIN").write_bytes(b"visible \n")
        (fx.directory / "UNSET").write_bytes(b"")
        result = fx.call("run", fx.directory, "--", *SHOW)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"PLAIN": "visible"', result.stdout.decode())
        self.assertIn('"UNSET": null', result.stdout.decode())

    def test_init_pointer_roundtrip_and_exit_code(self):
        fx = Fixture(self)
        fx.init_encrypted()
        (fx.directory / "PLAIN").write_bytes(b"mixed\n")
        result = fx.run_ok()
        self.assertIn('"PLAIN": "mixed"', result.stdout.decode())
        result = fx.call("run", fx.directory, "--", sys.executable, "-c", "import sys;sys.exit(7)")
        self.assertEqual(result.returncode, 7)

    def test_init_explicit_destination_relative_to_cwd(self):
        fx = Fixture(self)
        (fx.root / "keys").mkdir()
        result = fx.call("init", "--key", "keys/svc.key", "service", cwd=fx.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((fx.directory / ".envdirx.key").read_text(), f"{fx.root / 'keys' / 'svc.key'}\n")
        self.assertFalse((fx.root / "service.key").exists())
        self.assertEqual(fx.call("set", fx.directory, "TOKEN", input=SECRET).returncode, 0)
        fx.run_ok()

    def test_init_tilde_destination(self):
        fx = Fixture(self)
        result = fx.call("init", "--key", "~/svc.key", fx.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((fx.directory / ".envdirx.key").read_text(), f"{fx.home / 'svc.key'}\n")

    def test_text_pointer_forms(self):
        fx = Fixture(self)
        fx.init_encrypted()
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
        fx.init_encrypted()
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
        fx.init_encrypted()
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
        fx.init_encrypted()
        key = fx.move_key(fx.root / "keys" / "svc.key")
        fx.run_ok("--key", key)
        result = fx.call("run", "--key", "keys/svc.key", "service", "--", *SHOW, cwd=fx.root)
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
        fx.init_encrypted()
        (fx.directory / ".envdirx.key").unlink()
        self.assertTrue((fx.root / "service.key").exists())
        result = fx.run_fails()
        self.assertIn(b"missing key pointer", result.stderr)

    def test_invalid_text_pointers_fail_closed(self):
        fx = Fixture(self)
        fx.init_encrypted()
        key = str(fx.root / "service.key").encode()
        for content in (b"", b"\n", b"\r\n", key + b"\n" + key + b"\n", key + b"\n\n", key + b"\r", b"\xff" + key, key + b"\x00", b"rel\nmore"):
            with self.subTest(content=content):
                fx.write_pointer(content)
                fx.run_fails()

    def test_invalid_symlink_pointers_fail_closed(self):
        fx = Fixture(self)
        fx.init_encrypted()
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
        fx.init_encrypted()
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
        fx.init_encrypted()
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
        fx.init_encrypted()
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

    def test_init_refuses_existing_entries_and_preserves_them(self):
        cases = {
            "dangling pointer": lambda fx: (fx.directory / ".envdirx.key").symlink_to("nowhere"),
            "pointer file": lambda fx: (fx.directory / ".envdirx.key").write_text("/x\n"),
            "public key": lambda fx: (fx.directory / ".envdirx.pub").write_bytes(b"p"),
            "private key": lambda fx: (fx.root / "service.key").write_bytes(b"k"),
            "dangling private key": lambda fx: (fx.root / "service.key").symlink_to("nowhere"),
        }
        for name, prepare in cases.items():
            with self.subTest(name):
                fx = Fixture(self)
                prepare(fx)
                before = {p: (os.readlink(p) if p.is_symlink() else p.read_bytes()) for p in (fx.directory / ".envdirx.key", fx.directory / ".envdirx.pub", fx.root / "service.key") if os.path.lexists(p)}
                result = fx.call("init", fx.directory)
                self.assertEqual(result.returncode, 111)
                self.assertIn(b"refusing to overwrite", result.stderr)
                after = {p: (os.readlink(p) if p.is_symlink() else p.read_bytes()) for p in (fx.directory / ".envdirx.key", fx.directory / ".envdirx.pub", fx.root / "service.key") if os.path.lexists(p)}
                self.assertEqual(before, after)

    def test_init_rejects_bad_destinations_without_writing(self):
        fx = Fixture(self)
        alias = fx.root / "alias"
        alias.symlink_to(fx.directory)
        for key in (fx.directory / "k", alias / "sub.key", fx.root / "missing-parent" / "k", fx.root / "file" / "k", fx.directory):
            with self.subTest(key=key):
                (fx.root / "file").write_bytes(b"")
                result = fx.call("init", "--key", key, fx.directory)
                self.assertEqual(result.returncode, 111, result.stderr)
                self.assertEqual(sorted(p.name for p in fx.directory.iterdir()), [])
                self.assertFalse((fx.root / "missing-parent").exists())
        result = fx.call("init", "--key", fx.directory / ".." / "service" / "k", fx.directory)
        self.assertEqual(result.returncode, 111)
        self.assertIn(b"outside the envdir", result.stderr)

    def test_init_failure_removes_only_created_files(self):
        fx = Fixture(self)
        (fx.directory / "TOKEN").write_bytes(b"keep")
        real = envdirx._create
        calls = []

        def flaky(path, data, mode):
            calls.append(path)
            if len(calls) == 3:
                raise OSError("disk full")
            real(path, data, mode)

        argv = ["envdirx", "init", str(fx.directory)]
        with mock.patch.object(envdirx, "_create", flaky), mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                envdirx.main()
        self.assertEqual(raised.exception.code, 111)
        self.assertEqual(len(calls), 3)
        self.assertFalse(os.path.lexists(fx.root / "service.key"))
        self.assertFalse(os.path.lexists(fx.directory / ".envdirx.key"))
        self.assertFalse(os.path.lexists(fx.directory / ".envdirx.pub"))
        self.assertEqual((fx.directory / "TOKEN").read_bytes(), b"keep")

    def test_wrong_owner_rejected(self):
        fx = Fixture(self)
        fx.init_encrypted()
        with mock.patch.object(envdirx.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(ValueError, "owned by the current user"):
                envdirx._private(fx.directory, None)

    def test_help_distinguishes_key_roles(self):
        fx = Fixture(self)
        self.assertIn(b"destination", fx.call("init", "--help").stdout)
        run_help = fx.call("run", "--help").stdout
        self.assertIn(b"must precede DIRECTORY", run_help)
        self.assertIn(b".envdirx.key", run_help)
        for action in ("set", "encrypt"):
            self.assertIn(b"unused", fx.call(action, "--help").stdout)

    def test_readme_commands(self):
        """Run every README ``sh`` block, with ``uv run envdirx`` bound to this checkout."""
        readme = (ROOT / "README.md").read_text()
        blocks = [b for b in re.findall(r"```sh\n(.*?)```", readme, re.S) if "envdirx" in b and "unittest" not in b]
        self.assertGreaterEqual(len(blocks), 3)
        for block in blocks:
            with self.subTest(block=block.splitlines()[0]):
                fx = Fixture(self)
                fx.directory.rmdir()
                bin_dir = fx.root / "bin"
                bin_dir.mkdir()
                shim = bin_dir / "uv"
                shim.write_text(f'#!/bin/sh\n[ "$1" = sync ] && exit 0\n[ "$1 $2" = "run envdirx" ] || exit 99\nshift 2\nexec {sys.executable} -m envdirx "$@"\n')
                shim.chmod(0o755)
                # Migration blocks start from a legacy envdir: adjacent key, encrypted entry, no pointer.
                legacy = "mkdir -p service.env\nuv run envdirx init service.env\nprintf s | uv run envdirx set service.env API_TOKEN\nrm service.env/.envdirx.key\n"
                prelude = "set -eu\n" + ("" if "init" in block else legacy)
                env = {**fx.env, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
                result = subprocess.run(["sh", "-c", prelude + block], cwd=fx.root, env=env, capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr.decode() + block)


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


if __name__ == "__main__":
    unittest.main()
