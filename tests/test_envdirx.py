import contextlib
import hashlib
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

    def call(self, *args, input=None, cwd=None):
        return subprocess.run([*CLI, *map(str, args)], env=self.env, input=input, capture_output=True, cwd=cwd or self.root, timeout=30)

    def on(self, action, *args, input=None, cwd=None, directory=None):
        """Call ACTION with the envdir selected through the global -d option."""
        return self.call("-d", directory or self.directory, action, *args, input=input, cwd=cwd)

    def snapshot(self):
        """Every path under the fixture root with its bytes or link target."""
        return {p: (os.readlink(p) if p.is_symlink() else None if p.is_dir() else p.read_bytes()) for p in self.root.rglob("*")}

    def init_encrypted(self, *extra):
        result = self.call("init", *extra, self.directory)
        self.test.assertEqual(result.returncode, 0, result.stderr)
        self.test.assertEqual(self.on("set", "-c", "TOKEN", input=SECRET + b"\n").returncode, 0)
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
        self.assertEqual(fx.on("encrypt").returncode, 0)
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

    def test_plaintext_only_run_needs_no_key_or_pointer(self):
        fx = Fixture(self)
        (fx.directory / "PLAIN").write_bytes(b"visible \n")
        (fx.directory / "UNSET").write_bytes(b"")
        result = fx.on("run", "--", *SHOW)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"PLAIN": "visible"', result.stdout.decode())
        self.assertIn('"UNSET": null', result.stdout.decode())

    def test_init_pointer_roundtrip_and_exit_code(self):
        fx = Fixture(self)
        fx.init_encrypted()
        (fx.directory / "PLAIN").write_bytes(b"mixed\n")
        result = fx.run_ok()
        self.assertIn('"PLAIN": "mixed"', result.stdout.decode())
        result = fx.on("run", "--", sys.executable, "-c", "import sys;sys.exit(7)")
        self.assertEqual(result.returncode, 7)

    def test_init_explicit_destination_relative_to_cwd(self):
        fx = Fixture(self)
        (fx.root / "keys").mkdir()
        result = fx.call("init", "--key", "keys/svc.key", "service", cwd=fx.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((fx.directory / ".envdirx.key").read_text(), f"{fx.root / 'keys' / 'svc.key'}\n")
        self.assertFalse((fx.root / "service.key").exists())
        self.assertEqual(fx.on("set", "-c", "TOKEN", input=SECRET).returncode, 0)
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

    def test_help_describes_grammar(self):
        fx = Fixture(self)
        main_help = fx.call("--help").stdout
        for text in (b"./.envs", b"BEFORE the subcommand", b"keygen (-k KEYFILE | -K KEYDIR)", b"set [-c] NAME", b"run [--key KEY] -- COMMAND", b"legacy; rejects -d"):
            self.assertIn(text, main_help)
        self.assertIn(b"destination", fx.call("init", "--help").stdout)
        self.assertIn(b"Legacy", fx.call("init", "--help").stdout)
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
        for action in ("set", "encrypt", "keygen"):
            self.assertNotIn(b"unused", fx.call(action, "--help").stdout)

    def test_readme_commands(self):
        """Run every README ``sh`` block, with ``uv run envdirx`` bound to this checkout."""
        readme = (ROOT / "README.md").read_text()
        blocks = [b for b in re.findall(r"```sh\n(.*?)```", readme, re.S) if "envdirx" in b and "unittest" not in b]
        self.assertGreaterEqual(len(blocks), 5)
        for text in ("envdirx -d DIR set -c NAME", "envdirx -d DIR run [--key K] -- CMD", "`init [--key KEY] DIRECTORY`", "`set -c`"):
            self.assertIn(text, readme)
        skill = (ROOT / ".agents" / "skills" / "envdirx-operations" / "SKILL.md").read_text()
        self.assertIn("stores **plaintext** by default", skill)
        for block in blocks:
            with self.subTest(block=block.splitlines()[0]):
                fx = Fixture(self)
                fx.directory.rmdir()
                bin_dir = fx.root / "bin"
                bin_dir.mkdir()
                shim = bin_dir / "uv"
                shim.write_text(f'#!/bin/sh\n[ "$1" = sync ] && exit 0\n[ "$1 $2" = "run envdirx" ] || exit 99\nshift 2\nexec {sys.executable} -m envdirx "$@"\n')
                shim.chmod(0o755)
                # Blocks that do not create their own envdir start from a legacy one:
                # adjacent key, encrypted entry, no pointer.
                legacy = "mkdir -p service.env\nuv run envdirx init service.env\nprintf s | uv run envdirx -d service.env set -c API_TOKEN\nrm service.env/.envdirx.key\n"
                creates = any(word in block for word in ("envdirx init", "keygen", "mkdir"))
                prelude = "set -eu\n" + ("" if creates else legacy)
                env = {**fx.env, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
                result = subprocess.run(["sh", "-c", prelude + block], cwd=fx.root, env=env, capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr.decode() + block)


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
        for args, stdin in ((["set", "A"], b"v"), (["get", "A"], None), (["encrypt"], None), (["keygen", "-k", fx.root / "k"], None), (["run", "--", "true"], None)):
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
        for value in (b"envdirx:", b"envdirx:v1:\nlooks-encrypted", b"envdirx:v9:\nx"):
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
        self.assertTrue((fx.directory / "TOKEN").read_bytes().startswith(b"envdirx:v1:\n"))
        self.assertEqual(fx.on("get", "--key", fx.root / "svc.key", "TOKEN").stdout, SECRET)

    def test_encrypted_set_get_run_roundtrip(self):
        fx = Fixture(self)
        self.assertEqual(fx.on("mkdir").returncode, 0)
        _keygen(fx, "-k", fx.root / "svc.key")
        for value in (SECRET + b"\n", b"", b"bin\x00ary\nlines \n"):
            with self.subTest(value=value):
                self.assertEqual(fx.on("set", "-c", "TOKEN", input=value).returncode, 0)
                stored = (fx.directory / "TOKEN").read_bytes()
                self.assertTrue(stored.startswith(b"envdirx:v1:\n"))
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
        self.assertEqual(fx.on("encrypt").returncode, 0)
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

    def test_init_rejects_explicit_global_directory(self):
        fx = Fixture(self)
        other = fx.root / "other"
        other.mkdir()
        before = fx.snapshot()
        for flag in ("-d", "--directory"):
            for target in (other, fx.directory, Path(".envs")):
                with self.subTest(flag=flag, target=target):
                    result = fx.call(flag, target, "init", fx.directory)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(fx.snapshot(), before)
        # Without -d the legacy positional init works and the new grammar uses it.
        fx.init_encrypted()
        self.assertEqual((fx.directory / ".envdirx.key").read_bytes(), str(fx.root / "service.key").encode() + b"\n")
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
        fx.init_encrypted()
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
        fx.init_encrypted()
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

    def test_key_override_agrees_with_run(self):
        fx = Fixture(self)
        fx.init_encrypted()
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
        for args in ([], ["-k", fx.root / "a.key", "-K", fx.root / "keys"], ["-f", "-k", fx.root / "a.key"], ["-k", fx.root / "a.key", "--force"], ["-k"]):
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
