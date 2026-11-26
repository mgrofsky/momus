import os
import re
import socket
import sys

import pytest

# ---------------------------------------------------------------- no test may reach or authenticate to a provider
# The tests run only in the brain's test container (brain/tests/run_tests.sh: --network none, no home folder, the
# repository read-only). Anything that imports an SDK or an adapter must never run with the host's Python, where the
# SDKs would find real credentials by themselves.
if os.environ.get("MOMUS_TEST_CONTAINER") != "1":
    pytest.exit("Run the brain tests with brain/tests/run_tests.sh (the test container), never with the host's Python.", returncode=2)

DUMMY = "dummy-not-a-key"
# every standard credential or endpoint variable of the four SDKs: an obvious dummy, or pointed at nothing
SDK_ENV = {
    "ANTHROPIC_API_KEY": DUMMY, "ANTHROPIC_AUTH_TOKEN": DUMMY, "ANTHROPIC_BASE_URL": "http://sdk-env-was-read.invalid",
    "OPENAI_API_KEY": DUMMY, "OPENAI_BASE_URL": "http://sdk-env-was-read.invalid", "OPENAI_ORG_ID": "org-dummy",
    "OPENAI_PROJECT_ID": "proj-dummy", "GEMINI_API_KEY": DUMMY, "GOOGLE_API_KEY": DUMMY,
    "GOOGLE_GEMINI_BASE_URL": "http://sdk-env-was-read.invalid/", "GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent/adc.json",
    "AWS_ACCESS_KEY_ID": DUMMY, "AWS_SECRET_ACCESS_KEY": DUMMY, "AWS_SESSION_TOKEN": DUMMY, "AWS_BEARER_TOKEN_BEDROCK": DUMMY,
    "AWS_CONFIG_FILE": "/nonexistent/aws-config", "AWS_SHARED_CREDENTIALS_FILE": "/nonexistent/aws-credentials",
    "AWS_EC2_METADATA_DISABLED": "true", "HOME": "/nonexistent",
}
os.environ.update(SDK_ENV)
for _v in ("AWS_PROFILE", "ANTHROPIC_PROFILE", "ANTHROPIC_CONFIG_DIR", "GOOGLE_GENAI_USE_VERTEXAI", "GOOGLE_GENAI_USE_ENTERPRISE",
           "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_WEB_IDENTITY_TOKEN_FILE"):
    os.environ.pop(_v, None)

# Suite-wide outbound-socket guard. An SDK catches a connection error and raises its own, so a guard that only raised
# could let a "provider error" test pass by accident: every attempt is recorded, and the test that made one fails at
# teardown. Local in-process sockets (AF_UNIX, socketpair) are allowed.
OUTBOUND_ATTEMPTS = []
_real_connect, _real_connect_ex = socket.socket.connect, socket.socket.connect_ex
_real_getaddrinfo, _real_create_connection = socket.getaddrinfo, socket.create_connection


def _blocked(what, target):
    OUTBOUND_ATTEMPTS.append((what, repr(target)[:100]))
    raise OSError(f"outbound network use is blocked in the brain tests ({what})")


def _guard_connect(self, address):
    if self.family == getattr(socket, "AF_UNIX", None):
        return _real_connect(self, address)
    _blocked("connect", address)


def _guard_connect_ex(self, address):
    if self.family == getattr(socket, "AF_UNIX", None):
        return _real_connect_ex(self, address)
    _blocked("connect_ex", address)


socket.socket.connect = _guard_connect
socket.socket.connect_ex = _guard_connect_ex
socket.getaddrinfo = lambda *a, **k: _blocked("getaddrinfo", a[:2])
socket.create_connection = lambda address, *a, **k: _blocked("create_connection", address)


@pytest.fixture(autouse=True)
def no_outbound_network():
    before = len(OUTBOUND_ATTEMPTS)
    yield
    made = OUTBOUND_ATTEMPTS[before:]
    assert not made, f"this test tried to open an outbound connection: {made[:3]}"

BRAIN = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BRAIN)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient  # noqa: E402

from app.config import Settings  # noqa: E402
from app.web import create_app  # noqa: E402
import fixtures  # noqa: E402

ORIGIN = "http://testserver"
PASSWORD = "correct horse battery"


@pytest.fixture(autouse=True)
def restore_environ():
    """The brain's start-up scrub (app/llm/envguard.py) removes variables from os.environ; a test that runs it
    in this process gets the environment back afterwards, so the container's dummy SDK variables stay for the rest."""
    saved = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(saved)


def make_settings(tmp_path, **kw):
    base = dict(data_dir=str(tmp_path / "appdata"), jobs_dir=str(tmp_path / "jobq"), published_dir=str(tmp_path / "pub"),
                allowed_origins=(ORIGIN,), scrypt_n=2 ** 10, scheduler_enabled=False)
    base.update(kw)
    os.makedirs(base["jobs_dir"], exist_ok=True)
    return Settings(**base)


class Browser:
    """A test client that behaves like a same-origin browser: it sends Origin on POST and the session's token."""

    def __init__(self, app):
        self.c = TestClient(app, base_url=ORIGIN, follow_redirects=False)
        self.csrf = None

    def get(self, url, **kw):
        return self.c.get(url, **kw)

    def post(self, url, data=None, origin=ORIGIN, csrf=True, **kw):
        data = dict(data or {})
        if csrf and self.csrf and "csrf" not in data:
            data["csrf"] = self.csrf
        headers = kw.pop("headers", {})
        if origin:
            headers["Origin"] = origin
        return self.c.post(url, data=data, headers=headers, **kw)

    def api_post(self, url, json=None, origin=ORIGIN, csrf=True):
        headers = {}
        if origin:
            headers["Origin"] = origin
        if csrf and self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        return self.c.post(url, json=json or {}, headers=headers)

    def pre_token(self, path="/login"):
        r = self.c.get(path)
        m = re.search(r'name="csrf" value="([^"]+)"', r.text)
        return m.group(1) if m else None

    def login(self, username="admin", password=PASSWORD):
        pre = self.pre_token("/login")
        r = self.c.post("/login", data={"username": username, "password": password, "csrf": pre, "next": "/"}, headers={"Origin": ORIGIN})
        self.refresh_csrf()
        return r

    def refresh_csrf(self):
        r = self.c.get("/api/v1/me")
        self.csrf = r.json().get("csrf_token") if r.status_code == 200 else None


def bootstrap_token(app_settings):
    """Read the bootstrap token by resetting it (the real one only goes to the log)."""
    from app import auth, db
    conn = db.connect(app_settings.db_path)
    try:
        return auth.ensure_bootstrap(conn)
    finally:
        conn.close()


@pytest.fixture
def settings(tmp_path):
    return make_settings(tmp_path)


@pytest.fixture
def app(settings, capsys):
    return create_app(settings, start_background=False)


@pytest.fixture
def anon(app):
    return Browser(app)


@pytest.fixture
def admin(app, settings):
    b = Browser(app)
    tok = bootstrap_token(settings)
    pre = b.pre_token("/bootstrap")
    r = b.c.post("/bootstrap", data={"token": tok, "username": "admin", "password": PASSWORD, "password2": PASSWORD,
                                     "owner_rule": "yes", "csrf": pre}, headers={"Origin": ORIGIN})
    assert r.status_code == 303, r.text
    b.refresh_csrf()
    assert b.csrf
    return b


@pytest.fixture
def published(settings):
    fixtures.build_published(settings.published_dir, hostile=True)
    return settings.published_dir
