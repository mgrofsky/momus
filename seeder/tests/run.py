"""The seeder's unit tests, run only inside the seeder image by seeder/tests/run_tests.sh. Never with the host's Python.

What this file guarantees before any test module is imported (the same rules as brain/tests/conftest.py):
- it refuses to run unless MOMUS_SEED_TEST_CONTAINER=1 (set only by run_tests.sh, as a literal on the command line);
- every AWS credential and endpoint variable is an obvious dummy or points at nothing, the profile and container
  credential variables are removed, the instance metadata service is off, and HOME points at nothing;
- a suite-wide guard replaces socket.connect, connect_ex, getaddrinfo and create_connection: every outbound attempt
  is recorded and the test that made it fails, even when the code under test caught the error itself.
run_tests.sh adds --network none as the second barrier.
"""
import os
import socket
import sys
import unittest

# the tests reach the guard's record through this name (importing "run" again would install a second guard)
sys.modules["seed_test_guard"] = sys.modules[__name__]

if os.environ.get("MOMUS_SEED_TEST_CONTAINER") != "1":
    sys.exit("Run the seeder tests with seeder/tests/run_tests.sh (the seeder image, no network), never with the host's Python.")

DUMMY = "dummy-not-a-key"
SDK_ENV = {
    "AWS_ACCESS_KEY_ID": DUMMY, "AWS_SECRET_ACCESS_KEY": DUMMY, "AWS_SESSION_TOKEN": DUMMY,
    "AWS_CONFIG_FILE": "/nonexistent/aws-config", "AWS_SHARED_CREDENTIALS_FILE": "/nonexistent/aws-credentials",
    "AWS_EC2_METADATA_DISABLED": "true", "HOME": "/nonexistent",
    "AWS_ENDPOINT_URL": "http://sdk-env-was-read.invalid",
}
os.environ.update(SDK_ENV)
for _v in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
           "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_BEARER_TOKEN_BEDROCK"):
    os.environ.pop(_v, None)

OUTBOUND_ATTEMPTS = []
_real_connect, _real_connect_ex = socket.socket.connect, socket.socket.connect_ex


def _blocked(what, target):
    OUTBOUND_ATTEMPTS.append((what, repr(target)[:100]))
    raise OSError(f"outbound network use is blocked in the seeder tests ({what})")


def _guard_connect(self, address):
    if self.family == getattr(socket, "AF_UNIX", None):
        return _real_connect(self, address)
    return _blocked("connect", address)


def _guard_connect_ex(self, address):
    if self.family == getattr(socket, "AF_UNIX", None):
        return _real_connect_ex(self, address)
    return _blocked("connect_ex", address)


socket.socket.connect = _guard_connect
socket.socket.connect_ex = _guard_connect_ex
socket.getaddrinfo = lambda *a, **k: _blocked("getaddrinfo", a[:2])
socket.create_connection = lambda address, *a, **k: _blocked("create_connection", address)


class GuardedResult(unittest.TextTestResult):
    """A test that tried to open an outbound connection fails, whatever its own assertions said."""

    def startTest(self, test):
        self._attempts_before = len(OUTBOUND_ATTEMPTS)
        super().startTest(test)

    def stopTest(self, test):
        made = OUTBOUND_ATTEMPTS[self._attempts_before:]
        if made:
            try:
                raise AssertionError(f"this test tried to open an outbound connection: {made[:3]}")
            except AssertionError:
                self.addFailure(test, sys.exc_info())
        super().stopTest(test)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, here)
    suite = unittest.defaultTestLoader.discover(here, pattern="test_*.py", top_level_dir=here)
    runner = unittest.TextTestRunner(resultclass=GuardedResult, verbosity=1)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
