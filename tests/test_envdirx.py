import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, "-m", "envdirx"]


class EnvdirxTest(unittest.TestCase):
    def test_encrypted_and_plain_envdir_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "service"
            directory.mkdir()
            (directory / "TOKEN").write_bytes(b"top-secret  \nignored")
            (directory / "EMPTY").write_bytes(b"\n")
            (directory / "UNSET").write_bytes(b"")
            (directory / "MULTI").write_bytes(b"one\x00two\n")
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "UNSET": "inherited"}

            def call(*args, input=None):
                return subprocess.run([*CLI, *map(str, args)], env=env, input=input, capture_output=True)

            self.assertEqual(call("init", directory).returncode, 0)
            self.assertEqual((directory.with_name("service.key")).stat().st_mode & 0o777, 0o600)
            self.assertEqual(call("encrypt", directory).returncode, 0)
            self.assertNotIn(b"top-secret", (directory / "TOKEN").read_bytes())
            command = [sys.executable, "-c", "import os,json;print(json.dumps({k:os.environ.get(k) for k in ('TOKEN','EMPTY','UNSET','MULTI')}))"]
            result = call("run", directory, "--", *command)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.decode().strip(), '{"TOKEN": "top-secret", "EMPTY": "", "UNSET": null, "MULTI": "one\\ntwo"}')
            self.assertEqual(call("set", directory, "TOKEN", input=b"replacement\n").returncode, 0)
            self.assertIn(b'replacement', call("run", directory, "--", *command).stdout)
            payload = (directory / "TOKEN").read_bytes()
            (directory / "OTHER").write_bytes(payload)
            result = call("run", directory, "--", *command)
            self.assertEqual(result.returncode, 111)
            self.assertNotIn(b"replacement", result.stderr)
            (directory / "OTHER").unlink()
            result = call("run", directory, "--", sys.executable, "-c", "import sys;sys.exit(7)")
            self.assertEqual(result.returncode, 7)
            (directory / "TOKEN").write_bytes(b"envdirx:v2:\nunsafe")
            self.assertEqual(call("run", directory, "--", *command).returncode, 111)


if __name__ == "__main__":
    unittest.main()
