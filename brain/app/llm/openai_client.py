"""Adapter for OpenAI's Responses API, on the official `openai` SDK (pinned 3.59.0).

Request: responses.create(model, instructions=<system text>, input=<user text>, max_output_tokens, store=False,
text={"format": {"type": "json_schema", "name": ..., "schema": ..., "strict": True}} for JSON (the provider's
structured output, strict mode); per-request timeout. store=False: the provider is asked not to keep the response
for later retrieval. No sampling parameters, no tools.

Credentials: the key from this project's settings and an explicit base URL are passed to the constructor, and the
organization and project headers are omitted, so the SDK reads neither OPENAI_API_KEY, OPENAI_BASE_URL,
OPENAI_ORG_ID nor OPENAI_PROJECT_ID. With no key in the project's settings no client is built. SDK retries are off.
The SDK is imported only here, and only when a client is built.

HTTP: the SDK gets an HTTP client built here: trust_env=False, so no proxy, CA bundle or
netrc variable has any effect; follow_redirects=False, so a redirect answer is an error, never followed with the key;
the proxy is MOMUS_ANALYST_PROXY when set (passed explicitly), else none. Variables the SDK reads at import or that no
constructor argument overrides (its log level, extra headers) are removed at start-up (envguard.py)."""
from .base import (AuthError, BadModel, BadResponse, NotConfigured, Provider, RateLimited, Refused, Timeout,
                   Unavailable, by_status, log_failure, spent, status_of)
from .schema import wire

NAME = "openai"
BASE_URL = "https://api.openai.com/v1"
NO_KEY = "The OpenAI adapter needs MOMUS_ANALYST_API_KEY or MOMUS_ANALYST_API_KEY_FILE. It never uses OPENAI_API_KEY."
SCHEMA_NAME = "momus_answer"


def _sdk():
    try:
        import openai
    except Exception:
        raise NotConfigured("The openai SDK is not installed in this image.") from None
    return openai


def http_client(sdk, timeout_seconds, proxy=""):
    """trust_env=False (no proxy, CA bundle or netrc variable), no redirects, MOMUS_ANALYST_PROXY or no proxy."""
    return sdk.DefaultHttpxClient(trust_env=False, follow_redirects=False, timeout=float(timeout_seconds), proxy=proxy or None)


def build_sdk_client(key, timeout_seconds, proxy=""):
    if not key:
        raise NotConfigured(NO_KEY)
    sdk = _sdk()
    return sdk.OpenAI(api_key=key, organization="", project="", base_url=BASE_URL, timeout=float(timeout_seconds),
                      max_retries=0, default_headers={"OpenAI-Organization": sdk.omit, "OpenAI-Project": sdk.omit},
                      http_client=http_client(sdk, timeout_seconds, proxy))


class OpenAIProvider(Provider):
    name = NAME
    structured = "native"

    def __init__(self, model, key, timeout_seconds, sdk_client=None, proxy=""):
        super().__init__(model, timeout_seconds)
        self._sdk_mod = _sdk()
        self._client = sdk_client if sdk_client is not None else build_sdk_client(key, timeout_seconds, proxy)

    def _classify(self, exc):
        o = self._sdk_mod
        if isinstance(exc, o.APITimeoutError):
            return Timeout
        if isinstance(exc, (o.AuthenticationError, o.PermissionDeniedError)):
            return AuthError
        if isinstance(exc, o.RateLimitError):
            return RateLimited
        if isinstance(exc, o.NotFoundError):
            return BadModel
        if isinstance(exc, o.APIConnectionError):
            return Unavailable
        return by_status(status_of(exc)) or Unavailable

    def _call(self, system, user, schema, max_tokens):
        kw = {"model": self.model, "instructions": system, "input": user, "max_output_tokens": int(max_tokens),
              "store": False, "timeout": float(self.timeout_seconds)}
        if schema is not None:
            kw["text"] = {"format": {"type": "json_schema", "name": SCHEMA_NAME, "schema": wire(schema), "strict": True}}
        try:
            r = self._client.responses.create(**kw)
        except self._sdk_mod.OpenAIError as e:
            log_failure(NAME, e)
            raise self._classify(e)() from None
        usage = getattr(r, "usage", None)
        # output_tokens already includes reasoning tokens (output_tokens_details.reasoning_tokens is a part of it)
        tin, tout = getattr(usage, "input_tokens", 0) or 0, getattr(usage, "output_tokens", 0) or 0
        texts, refused = [], False
        for item in getattr(r, "output", None) or []:
            if getattr(item, "type", None) != "message":
                continue
            for part in getattr(item, "content", None) or []:
                kind = getattr(part, "type", None)
                if kind == "refusal":
                    refused = True
                elif kind == "output_text" and isinstance(getattr(part, "text", None), str):
                    texts.append(part.text)
        if refused:
            raise spent(Refused(), tin, tout)
        status = getattr(r, "status", None)
        if status != "completed":
            reason = getattr(getattr(r, "incomplete_details", None), "reason", None)
            if reason == "content_filter":
                raise spent(Refused(), tin, tout)
            raise spent(BadResponse(), tin, tout)
        text = "".join(texts)
        if not text.strip():
            raise spent(BadResponse(), tin, tout)
        return text, tin, tout

    def check_model(self):
        try:
            m = self._client.models.retrieve(self.model)
        except self._sdk_mod.OpenAIError as e:
            log_failure(NAME, e)
            raise self._classify(e)() from None
        return f"model {getattr(m, 'id', self.model)} is available to this key"
