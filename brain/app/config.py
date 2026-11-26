"""Settings, read once from the environment. Every setting is listed in .env.example with a safe default."""
import os
from dataclasses import dataclass, field


def _bool(v, default):
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _int(v, default, lo, hi):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return default
    return min(max(n, lo), hi)


def _docs_dir():
    """docs/ beside the app in the image (/opt/brain/docs), else the repository's docs/ in a working copy."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for d in (os.path.join(here, "docs"), os.path.join(os.path.dirname(here), "docs")):
        if os.path.isfile(os.path.join(d, "data-flows.md")):
            return d
    return os.path.join(here, "docs")


class Secret:
    """A credential read from the environment or a secret file. It never prints itself: repr and str give a fixed
    placeholder, so a key cannot reach a log line, an error page or a template by accident. reveal() is called in one
    place per provider adapter, to hand the key to the SDK client's constructor."""
    __slots__ = ("_v",)

    def __init__(self, value=""):
        object.__setattr__(self, "_v", (value or "").strip())

    def __setattr__(self, k, v):
        raise AttributeError("Secret is read-only")

    def __bool__(self):
        return bool(self._v)

    def __repr__(self):
        return "Secret(set)" if self._v else "Secret(empty)"

    __str__ = __repr__

    def __eq__(self, other):
        return isinstance(other, Secret) and other._v == self._v

    def __hash__(self):
        return hash(("Secret", bool(self._v)))

    def __reduce__(self):
        raise TypeError("a Secret cannot be pickled")

    def reveal(self):
        return self._v


ANALYST_PROVIDERS = ("none", "anthropic", "openai", "gemini", "bedrock", "mock", "susceptible")
TEST_PROVIDERS = ("mock", "susceptible")
MAX_KEY_FILE_BYTES = 16 * 1024


@dataclass(frozen=True)
class Settings:
    data_dir: str = "/data"
    jobs_dir: str = "/srv/jobs"
    published_dir: str = "/srv/published"
    allowed_origins: tuple = ("http://127.0.0.1:8080", "http://localhost:8080")
    cookie_secure: bool = False
    session_idle_minutes: int = 30
    session_max_hours: int = 12
    password_min_length: int = 12
    login_max_failures: int = 5      # failures count for 24 hours (auth.LOOKBACK); there is no window setting
    scheduler_enabled: bool = True
    scrypt_n: int = 2 ** 15
    lab: bool = False
    lab_cidr: str = ""
    trusted_proxy: str = ""      # one reverse-proxy address whose X-Forwarded-For is honoured; "" = off (the default)
    login_max_delay_seconds: int = 300   # the sign-in delay grows to at most this (auth.py)
    login_hash_concurrency: int = 2      # password hashes at once (scrypt N=2^15, r=8 needs 32 MiB each)
    snapshot_query_seconds: float = 2.0  # every request's snapshot queries stop after this long
    # largest snapshot accepted. A synthetic scanner database with 30 runs of 1,000 hosts and 1,000 findings (about
    # 1.5 KB of stored evidence each; the scanner caps one at 16 KB) measured 137 MiB, so 512 MiB leaves about 3.7x
    # headroom while bounding the copy, the hash and the quick check. The brain keeps up to
    # three verified copies in its data volume.
    snapshot_max_mb: int = 512
    docs_dir: str = field(default_factory=lambda: _docs_dir())
    # ---- the analyst (app/llm, app/analyst). Every value comes from MOMUS_ANALYST_* variables or a secret file only.
    analyst_provider: str = "none"            # none (the default), anthropic, openai, gemini, bedrock; mock, susceptible (lab only)
    analyst_model: str = ""                   # the provider's model id: configuration, never written into the code's logic
    analyst_key: Secret = field(default_factory=Secret, repr=False, compare=False)
    analyst_key_source: str = ""              # "MOMUS_ANALYST_API_KEY", "file", or "" (never the key itself)
    analyst_region: str = ""                  # Bedrock only
    analyst_timeout_seconds: int = 120        # one provider request
    analyst_max_steps: int = 12               # model calls per run, corrective retries included
    analyst_max_tokens_per_call: int = 16000  # output tokens per call; reasoning tokens count against it on every provider
    analyst_run_token_budget: int = 200000    # input + output tokens per run
    analyst_daily_token_budget: int = 1000000 # input + output tokens per UTC day, all runs
    analyst_run_seconds: int = 300            # wall clock per run
    analyst_max_proposals: int = 10           # proposals kept per run; more are dropped and recorded
    analyst_max_invalid: int = 2              # corrective retries for an invalid answer before the run fails
    analyst_metadata_only: bool = False       # tools omit every untrusted (target-derived) part
    analyst_auto_brief: bool = False          # a brief for each new snapshot
    analyst_debug: bool = False               # store prompts and responses (never in lab mode)
    analyst_memory_chars: int = 4000          # accepted notes included in a prompt, newest first
    analyst_mock_record: str = ""             # lab only: the mock provider appends every prompt it is sent to this file
    analyst_proxy: str = ""                   # MOMUS_ANALYST_PROXY: http(s)://host:port, passed explicitly to each SDK client
    analyst_proxy_invalid: bool = False       # set but not a valid proxy URL: the analyst refuses to run (factory.problem)

    @property
    def db_path(self):
        return os.path.join(self.data_dir, "brain.sqlite")

    @property
    def snapshot_cache(self):
        return os.path.join(self.data_dir, "snapshot-cache")

    @property
    def cookie_name(self):
        # the __Host- prefix makes the browser refuse the cookie unless it is Secure, path / and host-only
        return "__Host-momus_session" if self.cookie_secure else "momus_session"

    @property
    def pre_cookie_name(self):
        return "__Host-momus_pre" if self.cookie_secure else "momus_pre"


def listen_port(env=None):
    """MOMUS_PORT as a port number; empty or unset means 8080. Raises ValueError with one plain line otherwise."""
    e = os.environ if env is None else env
    v = (e.get("MOMUS_PORT") or "").strip()
    if not v:
        return 8080
    if not (v.isascii() and v.isdigit()) or not 1 <= int(v) <= 65535:
        raise ValueError("MOMUS_PORT must be a whole number from 1 to 65535, or empty for 8080")
    return int(v)


IGNORED_WINDOW = ("brain: MOMUS_LOGIN_WINDOW_MINUTES is set but has no effect: sign-in failures always count for 24 hours. "
                  "Remove it from the environment.")


def from_env(env=None):
    e = os.environ if env is None else env
    if (e.get("MOMUS_LOGIN_WINDOW_MINUTES") or "").strip():
        print(IGNORED_WINDOW, flush=True)
    origins = tuple(o.strip().rstrip("/") for o in (e.get("MOMUS_ALLOWED_ORIGINS") or "").split(",") if o.strip())
    return Settings(
        data_dir=e.get("MOMUS_DATA_DIR") or "/data",
        jobs_dir=e.get("MOMUS_JOBS_DIR") or "/srv/jobs",
        published_dir=e.get("MOMUS_PUBLISHED_DIR") or "/srv/published",
        allowed_origins=origins or ("http://127.0.0.1:8080", "http://localhost:8080"),
        cookie_secure=_bool(e.get("MOMUS_COOKIE_SECURE"), False),
        session_idle_minutes=_int(e.get("MOMUS_SESSION_IDLE_MINUTES"), 30, 5, 24 * 60),
        session_max_hours=_int(e.get("MOMUS_SESSION_MAX_HOURS"), 12, 1, 24 * 7),
        password_min_length=_int(e.get("MOMUS_PASSWORD_MIN_LENGTH"), 12, 12, 128),
        login_max_failures=_int(e.get("MOMUS_LOGIN_MAX_FAILURES"), 5, 3, 50),
        scheduler_enabled=_bool(e.get("MOMUS_SCHEDULER"), True),
        lab=_bool(e.get("MOMUS_LAB"), False),
        lab_cidr=(e.get("MOMUS_LAB_CIDR") or "").strip(),
        trusted_proxy=_address(e.get("MOMUS_TRUSTED_PROXY")),
        login_max_delay_seconds=_int(e.get("MOMUS_LOGIN_MAX_DELAY_SECONDS"), 300, 30, 3600),
        login_hash_concurrency=_int(e.get("MOMUS_LOGIN_HASH_CONCURRENCY"), 2, 1, 8),
        snapshot_query_seconds=float(_int(e.get("MOMUS_SNAPSHOT_QUERY_SECONDS"), 2, 1, 60)),
        snapshot_max_mb=_int(e.get("MOMUS_SNAPSHOT_MAX_MB"), 512, 16, 4096),
        **_analyst(e),
    )


def _analyst(e):
    """The analyst settings. The key comes from MOMUS_ANALYST_API_KEY or from the file named by MOMUS_ANALYST_API_KEY_FILE
    (a Docker secret, for example /run/secrets/momus_analyst_api_key). Nothing else is read: no SDK variable
    (ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY, ...) and no file in a home folder. Bedrock alone, with no
    key set, uses the default AWS credential chain, so an instance or container role works without a key."""
    provider = (e.get("MOMUS_ANALYST_PROVIDER") or "none").strip().lower()
    if provider not in ANALYST_PROVIDERS:
        provider = "invalid"
    key, source = (e.get("MOMUS_ANALYST_API_KEY") or "").strip(), ""
    if key:
        source = "MOMUS_ANALYST_API_KEY"
    else:
        path = (e.get("MOMUS_ANALYST_API_KEY_FILE") or "").strip()
        if path:
            key = _read_key_file(path)
            source = "file" if key else ""
    return dict(
        analyst_provider=provider,
        analyst_model=(e.get("MOMUS_ANALYST_MODEL") or "").strip()[:200],
        analyst_key=Secret(key),
        analyst_key_source=source,
        analyst_region=(e.get("MOMUS_ANALYST_REGION") or "").strip()[:40],
        analyst_timeout_seconds=_int(e.get("MOMUS_ANALYST_TIMEOUT_SECONDS"), 120, 10, 600),
        analyst_max_steps=_int(e.get("MOMUS_ANALYST_MAX_STEPS"), 12, 1, 40),
        analyst_max_tokens_per_call=_int(e.get("MOMUS_ANALYST_MAX_TOKENS_PER_CALL"), 16000, 1024, 64000),
        analyst_run_token_budget=_int(e.get("MOMUS_ANALYST_RUN_TOKEN_BUDGET"), 200000, 1000, 5000000),
        analyst_daily_token_budget=_int(e.get("MOMUS_ANALYST_DAILY_TOKEN_BUDGET"), 1000000, 1000, 100000000),
        analyst_run_seconds=_int(e.get("MOMUS_ANALYST_RUN_SECONDS"), 300, 10, 3600),
        analyst_max_proposals=_int(e.get("MOMUS_ANALYST_MAX_PROPOSALS"), 10, 0, 50),
        analyst_max_invalid=_int(e.get("MOMUS_ANALYST_MAX_INVALID"), 2, 0, 5),
        analyst_metadata_only=_bool(e.get("MOMUS_ANALYST_METADATA_ONLY"), False),
        analyst_auto_brief=_bool(e.get("MOMUS_ANALYST_AUTO_BRIEF"), False),
        analyst_debug=_bool(e.get("MOMUS_ANALYST_DEBUG"), False),
        analyst_memory_chars=_int(e.get("MOMUS_ANALYST_MEMORY_CHARS"), 4000, 0, 20000),
        analyst_mock_record=_mock_record((e.get("MOMUS_ANALYST_MOCK_RECORD") or "").strip()[:300]),
        **_proxy((e.get("MOMUS_ANALYST_PROXY") or "").strip()),
    )


PROXY_RE = __import__("re").compile(r"(https?)://([A-Za-z0-9.-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\]):([0-9]{1,5})/?", __import__("re").I)


def _proxy(v):
    """MOMUS_ANALYST_PROXY: one http:// or https:// URL with a host and a port, nothing else (no user name or password,
    no path, query or fragment). Anything else is invalid, and an invalid value stops the analyst instead of letting it
    go direct (factory.problem)."""
    if not v:
        return dict(analyst_proxy="", analyst_proxy_invalid=False)
    m = PROXY_RE.fullmatch(v[:300])
    ok = bool(m) and 1 <= int(m.group(3)) <= 65535 and not m.group(2).startswith(("-", ".")) and ".." not in m.group(2)
    if not ok:
        return dict(analyst_proxy="", analyst_proxy_invalid=True)
    return dict(analyst_proxy=f"{m.group(1).lower()}://{m.group(2).lower()}:{int(m.group(3))}", analyst_proxy_invalid=False)


def _mock_record(path):
    """MOMUS_ANALYST_MOCK_RECORD (lab tests only) is accepted only as a file directly or deeper under the brain's
    temporary folder; anything else is ignored and logged. The mock opens it without following links."""
    if not path:
        return ""
    import tempfile
    base = os.path.realpath(tempfile.gettempdir())
    real = os.path.normpath(path)
    if not os.path.isabs(path) or ".." in path.split(os.sep) or not real.startswith(base + os.sep):
        print("brain: MOMUS_ANALYST_MOCK_RECORD is ignored: it must name a file under the temporary folder " + base, flush=True)
        return ""
    return real


def _read_key_file(path):
    """The first line of a secret file, at most 16 KiB; "" when it cannot be read. The path is never shown with the
    error, and the content never."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return ""
    try:
        with os.fdopen(fd, "rb") as fh:
            data = fh.read(MAX_KEY_FILE_BYTES + 1)
    except OSError:
        return ""
    if len(data) > MAX_KEY_FILE_BYTES:
        return ""
    try:
        return data.decode("utf-8").strip().splitlines()[0].strip() if data.strip() else ""
    except (UnicodeDecodeError, IndexError):
        return ""


def _address(v):
    """One IP address, normalized; anything else (empty, a name, a range, a list) leaves the setting off."""
    import ipaddress
    try:
        return str(ipaddress.ip_address((v or "").strip()))
    except ValueError:
        return ""
