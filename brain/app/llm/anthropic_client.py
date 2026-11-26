"""Adapter for Anthropic's Messages API (Claude), on the official `anthropic` SDK (pinned 2.14.0).

Request: messages.create(model, max_tokens, system, messages=[one user message], output_config={"format":
{"type": "json_schema", "schema": ...}} for JSON (the provider's structured output); per-request timeout. No
sampling parameters, no thinking setting, no tools: the model's defaults apply.

Credentials: the key from this project's settings is passed to the constructor, together with an explicit base URL,
so the SDK reads neither ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, a profile, nor ANTHROPIC_BASE_URL. With no key in
the project's settings no client is built. SDK retries are off (max_retries=0). The SDK is imported only here, and
only when a client is built.

HTTP: the SDK gets an HTTP client built here: trust_env=False, so no proxy, CA bundle or
netrc variable has any effect; follow_redirects=False, so a redirect answer is an error, never followed with the key;
the proxy is MOMUS_ANALYST_PROXY when set (passed explicitly), else none. Variables the SDK reads at import or that no
constructor argument overrides (its log level, extra headers, tracing) are removed at start-up (envguard.py)."""
from .base import (AuthError, BadModel, BadResponse, LLMError, NotConfigured, Provider, RateLimited, Refused,
                   RequestRejected, Timeout, Unavailable, by_status, log_failure, spent, status_of)
from .schema import wire

NAME = "anthropic"
BASE_URL = "https://api.anthropic.com"
NO_KEY = "The Anthropic adapter needs MOMUS_ANALYST_API_KEY or MOMUS_ANALYST_API_KEY_FILE. It never uses ANTHROPIC_API_KEY."
_COMPLETE = ("end_turn", "stop_sequence")
_TRUNCATED = ("max_tokens", "model_context_window_exceeded")


def _sdk():
    try:
        import anthropic
    except Exception:
        raise NotConfigured("The anthropic SDK is not installed in this image.") from None
    return anthropic


def http_client(sdk, timeout_seconds, proxy=""):
    return sdk.DefaultHttpxClient(trust_env=False, follow_redirects=False, timeout=float(timeout_seconds), proxy=proxy or None)


def build_sdk_client(key, timeout_seconds, proxy=""):
    if not key:
        raise NotConfigured(NO_KEY)
    sdk = _sdk()
    return sdk.Anthropic(api_key=key, base_url=BASE_URL, timeout=float(timeout_seconds), max_retries=0,
                         http_client=http_client(sdk, timeout_seconds, proxy))


class AnthropicProvider(Provider):
    name = NAME
    structured = "native"

    def __init__(self, model, key, timeout_seconds, sdk_client=None, proxy=""):
        super().__init__(model, timeout_seconds)
        self._sdk_mod = _sdk()
        self._client = sdk_client if sdk_client is not None else build_sdk_client(key, timeout_seconds, proxy)

    def _classify(self, exc):
        a = self._sdk_mod
        if isinstance(exc, a.APITimeoutError):
            return Timeout
        if isinstance(exc, (a.AuthenticationError, a.PermissionDeniedError)):
            return AuthError
        if isinstance(exc, a.RateLimitError):
            return RateLimited
        if isinstance(exc, a.NotFoundError):
            return BadModel
        if isinstance(exc, a.APIConnectionError):
            return Unavailable
        return by_status(status_of(exc)) or Unavailable

    def _call(self, system, user, schema, max_tokens):
        kw = {"model": self.model, "max_tokens": int(max_tokens), "system": system,
              "messages": [{"role": "user", "content": user}], "timeout": float(self.timeout_seconds)}
        if schema is not None:
            kw["output_config"] = {"format": {"type": "json_schema", "schema": wire(schema)}}
        try:
            msg = self._client.messages.create(**kw)
        except self._sdk_mod.AnthropicError as e:
            log_failure(NAME, e)
            raise self._classify(e)() from None
        usage = getattr(msg, "usage", None)
        tin, tout = getattr(usage, "input_tokens", 0) or 0, getattr(usage, "output_tokens", 0) or 0
        stop = getattr(msg, "stop_reason", None)
        if stop == "refusal":
            raise spent(Refused(), tin, tout)
        if stop in _TRUNCATED or stop not in _COMPLETE:
            raise spent(BadResponse(), tin, tout)
        text = "".join(b.text for b in (getattr(msg, "content", None) or [])
                       if getattr(b, "type", None) == "text" and isinstance(getattr(b, "text", None), str))
        if not text.strip():
            raise spent(BadResponse(), tin, tout)
        return text, tin, tout

    def check_model(self):
        try:
            m = self._client.models.retrieve(self.model)
        except self._sdk_mod.AnthropicError as e:
            log_failure(NAME, e)
            raise self._classify(e)() from None
        return f"model {getattr(m, 'id', self.model)} is available to this key"


__all__ = ["AnthropicProvider", "build_sdk_client", "NAME", "BASE_URL", "NO_KEY", "LLMError", "RequestRejected"]
