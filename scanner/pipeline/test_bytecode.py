"""A full unit test run must leave no __pycache__ behind: the leak gate reads .pyc files, and a cached module carries
the absolute path it was compiled from. The suite is run on a copy of scanner/ with the interpreter started with -B
and without PYTHONDONTWRITEBYTECODE, so a child process started with -I and no -B is
caught."""
import os, pathlib, shutil, subprocess, sys, tempfile, unittest

SCANNER = pathlib.Path(__file__).resolve().parent.parent
INNER = "MOMUS_BYTECODE_INNER"


@unittest.skipIf(os.environ.get(INNER), "inner run")
class TestNoBytecode(unittest.TestCase):
    def test_full_run_writes_no_pycache(self):
        with tempfile.TemporaryDirectory() as d:
            copy = pathlib.Path(d) / "scanner"
            shutil.copytree(SCANNER, copy, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "out"))
            env = {k: v for k, v in os.environ.items() if k != "PYTHONDONTWRITEBYTECODE"}
            env[INNER] = "1"
            r = subprocess.run([sys.executable, "-B", "-m", "unittest"], cwd=copy / "pipeline", env=env,
                               capture_output=True, text=True, timeout=600)
            self.assertEqual(r.returncode, 0, r.stderr[-2000:])
            left = sorted(str(p.relative_to(copy)) for p in copy.rglob("__pycache__"))
            self.assertEqual(left, [], "bytecode written during the unit test run")


if __name__ == "__main__":
    unittest.main()
