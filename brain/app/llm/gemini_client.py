"""Adapter for the Gemini API, on the official `google-genai` SDK (pinned 3.6.1).

Request: models.generate_content(model, contents=<user text>, config=GenerateContentConfig(system_instruction,
max_output_tokens, response_mime_type="application/json", response_json_schema=...)) for JSON (the provider's
structured output). Thought parts are never read as the answer; thought tokens count as output.

Credentials: Client(api_key=<the project's key>, vertexai=False, enterprise=False, http_options=HttpOptions(base_url=
the Gemini API, timeout in milliseconds, one attempt)). So the SDK reads neither GEMINI_API_KEY, GOOGLE_API_KEY,
GOOGLE_GEMINI_BASE_URL, nor the Vertex switches, and never uses Google Cloud application default credentials (they are
only used in Vertex mode). With no key in the project's settings no client is built. The SDK is imported only here,
and only when a client is built.

HTTP: the SDK gets an HTTP client built here: trust_env=False, so no proxy, CA bundle or
netrc variable has any effect; follow_redirects=False, so a redirect answer is an error, never followed with the key;
the proxy is MOMUS_ANALYST_PROXY when set (passed explicitly), else none. Variables the SDK reads at import or that no
constructor argument overrides (its log level, extra headers, tracing) are removed at start-up (envguard.py)."""
from .base import (AuthError, BadModel, BadResponse, NotConfigured, Provider, RateLimited, Refused, Timeout,
                   Unavailable, by_status, log_failure, spent, status_of)
from .schema import wire

NAME = "gemini"
BASE_URL = "https://generativelanguage.googleapis.com/"
NO_KEY = ("The Gemini adapter needs MOMUS_ANALYST_API_KEY or MOMUS_ANALYST_API_KEY_FILE. It never uses GEMINI_API_KEY, "
          "GOOGLE_API_KEY or Google Cloud credentials.")
_COMPLETE = ("STOP",)
_TRUNCATED = ("MAX_TOKENS",)
_DECLINED = ("SAFETY", "RECITATION", "LANGUAGE", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "IMAGE_SAFETY",
             "IMAGE_PROHIBITED_CONTENT", "IMAGE_RECITATION", "MODEL_ARMOR")


def _sdk():
    try:
        from google import genai
        from google.genai import errors, types
    except Exception:
        raise NotConfigured("The google-genai SDK is not installed in this image.") from None
    return genai, types, errors


def http_options(types, timeout_seconds):
    return types.HttpOptions(base_url=BASE_URL, timeout=int(timeout_seconds * 1000),
                             retry_options=types.HttpRetryOptions(attempts=1))


def http_client(timeout_seconds, proxy=""):
    import httpx2
    return httpx2.Client(trust_env=False, follow_redirects=False, timeout=float(timeout_seconds), proxy=proxy or None)


def build_sdk_client(key, timeout_seconds, proxy=""):
    if not key:
        raise NotConfigured(NO_KEY)
    genai, types, _ = _sdk()
    opts = types.HttpOptions(base_url=BASE_URL, timeout=int(timeout_seconds * 1000), retry_options=types.HttpRetryOptions(attempts=1),
                             httpx_client=http_client(timeout_seconds, proxy))
    return genai.Client(api_key=key, vertexai=False, enterprise=False, http_options=opts)


def _name(v):
    v = getattr(v, "value", v)
    return v if isinstance(v, str) and v else None


class GeminiProvider(Provider):
    name = NAME
    structured = "native"

    def __init__(self, model, key, timeout_seconds, sdk_client=None, proxy=""):
        super().__init__(model, timeout_seconds)
        _, self._types, self._errors = _sdk()
        self._client = sdk_client if sdk_client is not None else build_sdk_client(key, timeout_seconds, proxy)

    def _transport_errors(self):
        out = [self._errors.APIError]
        try:
            import httpx2
            out.append(httpx2.HTTPError)
        except Exception:
            pass
        return tuple(out)

    def _classify(self, exc):
        name = type(exc).__name__.lower()
        if "timeout" in name:
            return Timeout
        if isinstance(exc, self._errors.APIError):
            return by_status(status_of(exc)) or Unavailable
        return Unavailable

    def _call(self, system, user, schema, max_tokens):
        # the per-request timeout (the loop lowers it as the run's time runs out); one attempt, as for the client
        cfg = {"system_instruction": system, "max_output_tokens": int(max_tokens),
               "http_options": http_options(self._types, self.timeout_seconds)}
        if schema is not None:
            cfg.update(response_mime_type="application/json", response_json_schema=wire(schema))
        config = self._types.GenerateContentConfig(**cfg)
        try:
            r = self._client.models.generate_content(model=self.model, contents=user, config=config)
        except self._transport_errors() as e:
            log_failure(NAME, e)
            raise self._classify(e)() from None
        u = getattr(r, "usage_metadata", None)
        tin = getattr(u, "prompt_token_count", 0) or 0
        tout = (getattr(u, "candidates_token_count", 0) or 0) + (getattr(u, "thoughts_token_count", 0) or 0)
        if _name(getattr(getattr(r, "prompt_feedback", None), "block_reason", None)):
            raise spent(Refused(), tin, tout)
        cands = getattr(r, "candidates", None) or []
        if not cands:
            raise spent(BadResponse(), tin, tout)
        c = cands[0]
        finish = _name(getattr(c, "finish_reason", None))
        if finish in _DECLINED:
            raise spent(Refused(), tin, tout)
        if finish not in _COMPLETE:
            raise spent(BadResponse(), tin, tout)
        text = "".join(p.text for p in (getattr(getattr(c, "content", None), "parts", None) or [])
                       if isinstance(getattr(p, "text", None), str) and getattr(p, "thought", None) is not True)
        if not text.strip():
            raise spent(BadResponse(), tin, tout)
        return text, tin, tout

    def check_model(self):
        try:
            m = self._client.models.get(model=self.model)
        except self._transport_errors() as e:
            log_failure(NAME, e)
            raise self._classify(e)() from None
        return f"model {getattr(m, 'name', self.model)} is available to this key"


__all__ = ["GeminiProvider", "build_sdk_client", "NAME", "BASE_URL", "NO_KEY", "AuthError", "BadModel", "RateLimited"]
