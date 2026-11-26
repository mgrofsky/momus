"""The provider interface every model adapter implements, its errors, and its result type.

One small interface:
  chat_text(system, user, max_tokens)          -> Result whose .text is the answer
  chat_json(system, user, schema, max_tokens)  -> Result whose .data is a dict that matches `schema`
  check_model()                                -> a short fixed description when the configured model can be used

Each failure has one error class, and every error carries one of the fixed sentences below and nothing else: never
the provider's own text (some SDK messages quote request details or part of a key), never the key, never the prompt.
Adapters raise errors `from None`, so no SDK exception travels along as a cause.

The SDKs' own retries are turned off in every adapter (max_retries 0, one attempt): the agent loop owns retries, so
that its step, token and time limits count every request that is actually made."""
import threading

TEXT_SYSTEM_SUFFIX = ""
DEADLINE_GRACE_SECONDS = 2      # a provider call ends at its timeout plus this, whatever the SDK's per-read timeouts do
JSON_SYSTEM_SUFFIX = "Answer with exactly one JSON object that matches the given schema. No prose, no code fences."

# the fixed sentences (shown on the analyst's run page and in the run record)
E_AUTH = "The model provider refused the credentials (authentication or permission). Check the key and its access."
E_RATE = "The model provider is rate limiting or out of quota. Try again later."
E_TIMEOUT = "The model provider did not answer in time."
E_REFUSED = "The model declined to answer this request."
E_BAD = "The model's answer was empty, cut short, or not the JSON the request asked for."
E_UNAVAILABLE = "The model provider could not be reached or failed on its side."
E_MODEL = "The configured model was not found or cannot be used with this account."
E_REQUEST = "The model provider rejected the request."


class LLMError(Exception):
    """Base class. str(e) is always one fixed sentence."""
    kind = "error"
    default = E_UNAVAILABLE

    def __init__(self, message=None):
        super().__init__(message or self.default)


class AuthError(LLMError):
    kind, default = "auth", E_AUTH


class RateLimited(LLMError):
    kind, default = "rate-limit", E_RATE


class Timeout(LLMError):
    kind, default = "timeout", E_TIMEOUT


class Refused(LLMError):
    kind, default = "refused", E_REFUSED


class BadResponse(LLMError):
    kind, default = "bad-response", E_BAD


class Unavailable(LLMError):
    kind, default = "unavailable", E_UNAVAILABLE


class NotConfigured(LLMError):
    """The analyst cannot start: no provider, a missing key, a missing SDK, a test provider outside lab mode..."""
    kind, default = "not-configured", "The analyst is not configured."


ERROR_CLASSES = (AuthError, RateLimited, Timeout, Refused, BadResponse, Unavailable)


class Result:
    """One provider answer: text or parsed data, and the tokens it used. Tokens a provider reports separately for
    reasoning are added to tokens_out, because they are billed as output."""
    __slots__ = ("text", "data", "tokens_in", "tokens_out")

    def __init__(self, text="", data=None, tokens_in=0, tokens_out=0):
        self.text, self.data = text, data
        self.tokens_in, self.tokens_out = _n(tokens_in), _n(tokens_out)

    def __repr__(self):
        return f"Result(tokens_in={self.tokens_in}, tokens_out={self.tokens_out})"


def _n(v):
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0


def status_of(exc):
    """The HTTP status code an SDK error carries, read from its attributes (never from its message)."""
    for name in ("status_code", "code"):
        v = getattr(exc, name, None)
        if isinstance(v, int) and not isinstance(v, bool):
            return v
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        meta = resp.get("ResponseMetadata")
        if isinstance(meta, dict) and isinstance(meta.get("HTTPStatusCode"), int):
            return meta["HTTPStatusCode"]
    return None


def by_status(status):
    """The error class for an HTTP status, or None."""
    if status in (401, 403):
        return AuthError
    if status == 404:
        return BadModel
    if status == 429:
        return RateLimited
    if status in (408, 504):
        return Timeout
    if isinstance(status, int) and 400 <= status < 500:
        return RequestRejected
    if isinstance(status, int) and status >= 500:
        return Unavailable
    return None


class BadModel(LLMError):
    kind, default = "model", E_MODEL


class RequestRejected(LLMError):
    kind, default = "request", E_REQUEST


def spent(err, tokens_in, tokens_out):
    """Attach the tokens a failed answer still used, so the loop can count them against its budgets."""
    err.tokens = (_n(tokens_in), _n(tokens_out))      # the same clamp as Result: non-negative integers only
    return err


def tokens_of(err):
    """The (input, output) tokens a failed answer used, clamped like Result's."""
    t = getattr(err, "tokens", None)
    return (_n(t[0]), _n(t[1])) if isinstance(t, tuple) and len(t) == 2 else (0, 0)


def log_failure(provider, exc):
    """One log line for a failed call: provider, error class name and status only."""
    print(f"analyst: {provider} call failed: {type(exc).__name__} status={status_of(exc)}", flush=True)


class Provider:
    """Base for adapters. Subclasses set name and implement _call(system, user, schema, max_tokens) -> (text, tin, tout)
    and check_model()."""
    name = "provider"
    structured = "none"      # how chat_json asks for JSON: "native" (the provider's structured output) or "prompt"

    def __init__(self, model, timeout_seconds):
        if not model:
            raise NotConfigured("No model is configured: set MOMUS_ANALYST_MODEL.")
        self.model = model
        self.timeout_seconds = timeout_seconds

    def __repr__(self):
        return f"{type(self).__name__}(model={self.model!r})"

    def chat_text(self, system, user, max_tokens):
        text, tin, tout = self._call_with_deadline(system, user, None, max_tokens)
        if not text.strip():
            raise BadResponse()
        return Result(text=text, tokens_in=tin, tokens_out=tout)

    def _call_with_deadline(self, system, user, schema, max_tokens):
        """self._call with a hard overall deadline. The SDKs' timeouts are per read, so an endpoint that
        sends a little data inside each read timeout could keep one call open without end. The call runs in its own
        thread; past timeout_seconds plus a short grace the run gets Timeout and goes on (the thread is left to end on
        its own, its answer is dropped)."""
        box = {}

        def go():
            try:
                box["ok"] = self._call(system, user, schema, max_tokens)
            except BaseException as e:          # handed to the caller below
                box["err"] = e
        t = threading.Thread(target=go, name=f"momus-{self.name}-call", daemon=True)
        t.start()
        t.join(max(1.0, float(self.timeout_seconds)) + DEADLINE_GRACE_SECONDS)
        if t.is_alive():
            raise Timeout()
        if "err" in box:
            raise box["err"]
        return box["ok"]

    def chat_json(self, system, user, schema, max_tokens):
        from .schema import extract_json, validate
        text, tin, tout = self._call_with_deadline(system + "\n\n" + JSON_SYSTEM_SUFFIX, user, schema, max_tokens)
        data = extract_json(text)
        problems = validate(data, schema) if data is not None else ["not a JSON object"]
        if problems:
            err = spent(BadResponse(), tin, tout)      # a bad answer still spent tokens; the loop counts them
            err.problems = problems[:5]
            raise err
        return Result(text=text, data=data, tokens_in=tin, tokens_out=tout)

    def _call(self, system, user, schema, max_tokens):     # pragma: no cover - abstract
        raise NotImplementedError

    def check_model(self):                                  # pragma: no cover - abstract
        raise NotImplementedError
