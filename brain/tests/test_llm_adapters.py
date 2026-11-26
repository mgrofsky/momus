"""The provider adapters, with each SDK's client stubbed (no test contacts a provider; see conftest.py). For each
adapter: the request it builds, its handling of each error class, a malformed JSON answer, an empty answer, a cut-off
answer and a refusal. Then: credentials are only ever the project's own (the SDKs' variables are set to dummies in
this container and must never be used), a missing SDK affects only its own provider, and test providers are refused
outside lab mode."""
import builtins
import json
from types import SimpleNamespace as NS

import pytest

from app.config import Secret, Settings
from app.llm import base, factory, schema as schemam
from app.llm.anthropic_client import AnthropicProvider
from app.llm.bedrock_client import BedrockProvider
from app.llm.gemini_client import GeminiProvider
from app.llm.openai_client import OpenAIProvider
from app.analyst import prompts

SCHEMA = {"type": "object", "properties": {"answer": {"type": "string", "maxLength": 50}}, "required": ["answer"],
          "additionalProperties": False}
GOOD = json.dumps({"answer": "ok"})
KEY = "momus-test-project-key-" + "0123456789"


class Rec:
    """A stub method: records its keyword arguments, then returns (or raises) the next scripted item."""

    def __init__(self, *items):
        self.items, self.calls = list(items), []

    def __call__(self, *a, **kw):
        self.calls.append(kw)
        item = self.items.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


# ---------------------------------------------------------------- answers in each SDK's shape
def a_msg(text=GOOD, stop="end_turn", tin=11, tout=7):
    return NS(stop_reason=stop, usage=NS(input_tokens=tin, output_tokens=tout), content=[NS(type="text", text=text)] if text is not None else [])


def o_resp(text=GOOD, status="completed", refusal=False, reason=None, tin=11, tout=7):
    parts = [NS(type="refusal", refusal="no")] if refusal else ([NS(type="output_text", text=text)] if text is not None else [])
    return NS(status=status, incomplete_details=NS(reason=reason) if reason else None, usage=NS(input_tokens=tin, output_tokens=tout),
              output=[NS(type="reasoning", content=None), NS(type="message", content=parts)])


def g_resp(text=GOOD, finish="STOP", block=None, tin=11, tout=5, thoughts=2):
    parts = [NS(text="thinking...", thought=True)] + ([NS(text=text, thought=None)] if text is not None else [])
    return NS(prompt_feedback=NS(block_reason=block) if block else None,
              usage_metadata=NS(prompt_token_count=tin, candidates_token_count=tout, thoughts_token_count=thoughts),
              candidates=[NS(finish_reason=NS(value=finish), content=NS(parts=parts))])


def b_resp(text=GOOD, stop="end_turn", tin=11, tout=7):
    return {"stopReason": stop, "usage": {"inputTokens": tin, "outputTokens": tout},
            "output": {"message": {"role": "assistant", "content": [{"text": text}] if text is not None else []}}}


def make(kind, *items):
    rec = Rec(*items)
    if kind == "anthropic":
        return AnthropicProvider("model-a", KEY, 30, sdk_client=NS(messages=NS(create=rec), models=NS(retrieve=Rec(NS(id="model-a"))))), rec
    if kind == "openai":
        return OpenAIProvider("model-o", KEY, 30, sdk_client=NS(responses=NS(create=rec), models=NS(retrieve=Rec(NS(id="model-o"))))), rec
    if kind == "gemini":
        return GeminiProvider("model-g", KEY, 30, sdk_client=NS(models=NS(generate_content=rec, get=Rec(NS(name="models/model-g"))))), rec
    return BedrockProvider("model-b", KEY, "us-east-1", 30, sdk_client=NS(converse=rec),
                           control_client=NS(get_foundation_model=Rec({"modelDetails": {"modelLifecycle": {"status": "ACTIVE"}}}))), rec


ANSWERS = {"anthropic": a_msg, "openai": o_resp, "gemini": g_resp, "bedrock": b_resp}
ALL = list(ANSWERS)


# ---------------------------------------------------------------- the request each adapter builds
def test_anthropic_request():
    p, rec = make("anthropic", a_msg())
    r = p.chat_json("SYS", "USER", SCHEMA, 321)
    kw = rec.calls[0]
    assert r.data == {"answer": "ok"} and (r.tokens_in, r.tokens_out) == (11, 7)
    assert kw["model"] == "model-a" and kw["max_tokens"] == 321 and kw["timeout"] == 30.0
    assert kw["system"].startswith("SYS") and base.JSON_SYSTEM_SUFFIX in kw["system"]
    assert kw["messages"] == [{"role": "user", "content": "USER"}]
    assert kw["output_config"] == {"format": {"type": "json_schema", "schema": schemam.wire(SCHEMA)}}
    assert "maxLength" not in json.dumps(kw["output_config"])          # bounds are enforced locally, not sent
    assert not {"temperature", "top_p", "top_k", "thinking", "tools"} & set(kw)
    p2, rec2 = make("anthropic", a_msg(text="hello"))
    assert p2.chat_text("SYS", "USER", 50).text == "hello" and "output_config" not in rec2.calls[0]


def test_openai_request():
    p, rec = make("openai", o_resp())
    r = p.chat_json("SYS", "USER", SCHEMA, 321)
    kw = rec.calls[0]
    assert r.data == {"answer": "ok"} and (r.tokens_in, r.tokens_out) == (11, 7)
    assert kw["model"] == "model-o" and kw["max_output_tokens"] == 321 and kw["timeout"] == 30.0
    assert kw["instructions"].startswith("SYS") and kw["input"] == "USER" and kw["store"] is False
    assert kw["text"] == {"format": {"type": "json_schema", "name": "momus_answer", "schema": schemam.wire(SCHEMA), "strict": True}}
    assert not {"temperature", "top_p", "tools"} & set(kw)


def test_gemini_request():
    p, rec = make("gemini", g_resp())
    r = p.chat_json("SYS", "USER", SCHEMA, 321)
    kw = rec.calls[0]
    assert r.data == {"answer": "ok"}
    assert (r.tokens_in, r.tokens_out) == (11, 7)            # thought tokens count as output
    assert kw["model"] == "model-g" and kw["contents"] == "USER"
    cfg = kw["config"]
    assert cfg.max_output_tokens == 321 and cfg.system_instruction.startswith("SYS")
    assert cfg.response_mime_type == "application/json" and cfg.response_json_schema == schemam.wire(SCHEMA)
    assert cfg.http_options.timeout == 30000 and cfg.http_options.retry_options.attempts == 1


def test_bedrock_request():
    p, rec = make("bedrock", b_resp())
    r = p.chat_json("SYS", "USER", SCHEMA, 321)
    kw = rec.calls[0]
    assert r.data == {"answer": "ok"} and (r.tokens_in, r.tokens_out) == (11, 7)
    assert kw["modelId"] == "model-b" and kw["inferenceConfig"] == {"maxTokens": 321}
    assert kw["system"][0]["text"].startswith("SYS") and kw["messages"] == [{"role": "user", "content": [{"text": "USER"}]}]
    js = kw["outputConfig"]["textFormat"]
    assert js["type"] == "json_schema" and json.loads(js["structure"]["jsonSchema"]["schema"]) == schemam.wire(SCHEMA)


def test_bedrock_timeout_and_retries_are_in_the_client_config(monkeypatch):
    """The client is built with read_timeout = the request timeout, connect 10 s, and one attempt (no SDK retries)."""
    from app.llm import bedrock_client
    seen = {}
    import boto3

    class FakeSession:
        def __init__(self, **kw):
            seen["session"] = kw

        def client(self, service, config=None, **kw):       # endpoint_url and verify are passed explicitly too
            seen["service"], seen["config"], seen["kw"] = service, config, kw
            return NS(converse=Rec())
    monkeypatch.setattr(boto3.session, "Session", FakeSession)
    bedrock_client.build_sdk_client("", "eu-west-1", 77)
    cfg = seen["config"]
    assert seen["service"] == "bedrock-runtime" and seen["session"] == {"region_name": "eu-west-1"}
    assert cfg.read_timeout == 77 and cfg.connect_timeout == 10 and cfg.retries == {"total_max_attempts": 1, "mode": "standard"}
    assert seen["kw"]["endpoint_url"] == "https://bedrock-runtime.eu-west-1.amazonaws.com"


@pytest.mark.parametrize("kind", ALL)
def test_check_model(kind):
    p, _ = make(kind)
    assert "model" in p.check_model()


# ---------------------------------------------------------------- answers that are not usable
@pytest.mark.parametrize("kind", ALL)
@pytest.mark.parametrize("text", ["not json at all", '{"answer": 5}', '{"answer": "ok", "extra": 1}', '{"answer": "' + "x" * 60 + '"}',
                                  '{"answer": "a", "answer": "b"}', "[1, 2]"])
def test_malformed_json_is_a_bad_response_that_still_counts_tokens(kind, text):
    p, _ = make(kind, ANSWERS[kind](text=text))
    with pytest.raises(base.BadResponse) as e:
        p.chat_json("S", "U", SCHEMA, 100)
    assert e.value.tokens[0] == 11 and str(e.value) == base.E_BAD


@pytest.mark.parametrize("kind", ALL)
def test_empty_answer(kind):
    for empty in (None, "", "   "):
        p, _ = make(kind, ANSWERS[kind](text=empty))
        with pytest.raises(base.BadResponse):
            p.chat_json("S", "U", SCHEMA, 100)


def test_cut_off_answers():
    for kind, ans in (("anthropic", a_msg(stop="max_tokens")), ("openai", o_resp(status="incomplete", reason="max_output_tokens")),
                      ("gemini", g_resp(finish="MAX_TOKENS")), ("bedrock", b_resp(stop="max_tokens"))):
        p, _ = make(kind, ans)
        with pytest.raises(base.BadResponse):
            p.chat_json("S", "U", SCHEMA, 100)


def test_refusals():
    for kind, ans in (("anthropic", a_msg(stop="refusal")), ("openai", o_resp(refusal=True)),
                      ("openai", o_resp(status="incomplete", reason="content_filter")), ("gemini", g_resp(finish="SAFETY")),
                      ("gemini", g_resp(block="PROHIBITED_CONTENT")), ("bedrock", b_resp(stop="content_filtered")),
                      ("bedrock", b_resp(stop="guardrail_intervened"))):
        p, _ = make(kind, ans)
        with pytest.raises(base.Refused) as e:
            p.chat_json("S", "U", SCHEMA, 100)
        assert str(e.value) == base.E_REFUSED and e.value.tokens == (11, 7)


# ---------------------------------------------------------------- each error class, from the real SDK exception types
def _httpx2():
    import httpx2
    return httpx2


def anthropic_errors():
    import anthropic
    h = _httpx2()
    req = h.Request("POST", "https://api.anthropic.com/v1/messages")

    def st(cls, code):
        return cls("SECRET-IN-SDK-MESSAGE " + KEY, response=h.Response(code, request=req), body=None)
    return [(st(anthropic.AuthenticationError, 401), base.AuthError), (st(anthropic.PermissionDeniedError, 403), base.AuthError),
            (st(anthropic.RateLimitError, 429), base.RateLimited), (anthropic.APITimeoutError(request=req), base.Timeout),
            (st(anthropic.NotFoundError, 404), base.BadModel), (st(anthropic.BadRequestError, 400), base.RequestRejected),
            (st(anthropic.InternalServerError, 500), base.Unavailable), (anthropic.APIConnectionError(request=req), base.Unavailable)]


def openai_errors():
    import openai
    h = _httpx2()
    req = h.Request("POST", "https://api.openai.com/v1/responses")

    def st(cls, code):
        return cls("SECRET-IN-SDK-MESSAGE " + KEY, response=h.Response(code, request=req), body=None)
    return [(st(openai.AuthenticationError, 401), base.AuthError), (st(openai.PermissionDeniedError, 403), base.AuthError),
            (st(openai.RateLimitError, 429), base.RateLimited), (openai.APITimeoutError(request=req), base.Timeout),
            (st(openai.NotFoundError, 404), base.BadModel), (st(openai.BadRequestError, 400), base.RequestRejected),
            (st(openai.InternalServerError, 500), base.Unavailable), (openai.APIConnectionError(request=req), base.Unavailable)]


def gemini_errors():
    from google.genai import errors
    h = _httpx2()

    def ce(code, cls=errors.ClientError):
        return cls(code, {"error": {"code": code, "message": "SECRET-IN-SDK-MESSAGE " + KEY, "status": "X"}})
    return [(ce(401), base.AuthError), (ce(403), base.AuthError), (ce(429), base.RateLimited), (ce(404), base.BadModel),
            (ce(400), base.RequestRejected), (ce(500, errors.ServerError), base.Unavailable), (ce(503, errors.ServerError), base.Unavailable),
            (h.ReadTimeout("SECRET-IN-SDK-MESSAGE"), base.Timeout), (h.ConnectError("SECRET-IN-SDK-MESSAGE"), base.Unavailable)]


def bedrock_errors():
    from botocore.exceptions import ClientError, NoCredentialsError, ReadTimeoutError, EndpointConnectionError

    def ce(code, status):
        return ClientError({"Error": {"Code": code, "Message": "SECRET-IN-SDK-MESSAGE " + KEY}, "ResponseMetadata": {"HTTPStatusCode": status}}, "Converse")
    return [(ce("AccessDeniedException", 403), base.AuthError), (ce("UnrecognizedClientException", 403), base.AuthError),
            (ce("ThrottlingException", 429), base.RateLimited), (ce("ModelTimeoutException", 408), base.Timeout),
            (ReadTimeoutError(endpoint_url="https://x"), base.Timeout), (ce("ResourceNotFoundException", 404), base.BadModel),
            (ce("ValidationException", 400), base.RequestRejected), (ce("ServiceUnavailableException", 503), base.Unavailable),
            (NoCredentialsError(), base.AuthError), (EndpointConnectionError(endpoint_url="https://x"), base.Unavailable)]


ERRORS = {"anthropic": anthropic_errors, "openai": openai_errors, "gemini": gemini_errors, "bedrock": bedrock_errors}


@pytest.mark.parametrize("kind", ALL)
def test_each_error_class_maps_to_one_fixed_message(kind, capsys):
    cases = ERRORS[kind]()
    assert {want for _, want in cases} >= {base.AuthError, base.RateLimited, base.Timeout, base.Unavailable}
    for exc, want in cases:
        p, _ = make(kind, exc)
        with pytest.raises(base.LLMError) as e:
            p.chat_json("S", "U", SCHEMA, 100)
        assert type(e.value) is want, (kind, type(exc).__name__)
        assert str(e.value) == want.default
        assert e.value.__cause__ is None and e.value.__suppress_context__        # raised "from None"
        assert "SECRET-IN-SDK-MESSAGE" not in str(e.value) and KEY not in str(e.value)
    out = capsys.readouterr().out
    assert "SECRET-IN-SDK-MESSAGE" not in out and KEY not in out                # the log line names the class and status only
    assert f"analyst: {kind} call failed:" in out


# ---------------------------------------------------------------- credentials: only the project's own, never the SDKs'
def _settings(provider, key="", **kw):
    return Settings(analyst_provider=provider, analyst_model="m", analyst_key=Secret(key), **kw)


def test_the_sdk_variables_are_dummies_in_this_container():
    import os
    for v in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_BEARER_TOKEN_BEDROCK"):
        assert os.environ[v] == "dummy-not-a-key", v
    assert os.environ["AWS_EC2_METADATA_DISABLED"] == "true" and os.environ["HOME"] == "/nonexistent"
    assert os.environ["AWS_CONFIG_FILE"].startswith("/nonexistent") and os.environ["AWS_SHARED_CREDENTIALS_FILE"].startswith("/nonexistent")


@pytest.mark.parametrize("provider,module,ctor", [("anthropic", "anthropic", "Anthropic"), ("openai", "openai", "OpenAI"),
                                                   ("gemini", "google.genai", "Client")])
def test_no_project_key_means_no_client_even_with_the_sdk_variable_set(monkeypatch, provider, module, ctor):
    import importlib
    mod = importlib.import_module(module)
    built = []
    monkeypatch.setattr(mod, ctor, lambda *a, **k: built.append(k))
    s = _settings(provider, "")
    assert factory.problem(s) and "MOMUS_ANALYST_API_KEY" in factory.problem(s)
    with pytest.raises(base.NotConfigured):
        factory.build(s)
    from app.llm import anthropic_client, gemini_client, openai_client
    for m in (anthropic_client, openai_client, gemini_client):          # the adapters' own builders refuse too
        with pytest.raises(base.NotConfigured):
            m.build_sdk_client("", 30)
    assert built == []


def test_real_clients_use_only_the_explicit_key_and_endpoint():
    """Built for real in this container (no network): every credential, base URL and organization value comes from
    the project's settings, never from the SDK variables (set to dummies and to an *.invalid base URL here)."""
    from app.llm import anthropic_client, gemini_client, openai_client
    a = anthropic_client.build_sdk_client(KEY, 30)
    assert a.api_key == KEY and a.auth_token is None and str(a.base_url).startswith("https://api.anthropic.com") and a.max_retries == 0
    o = openai_client.build_sdk_client(KEY, 30)
    import openai
    req = o._build_request(openai._models.FinalRequestOptions.construct(method="post", url="/responses", json_data={}))
    assert o.api_key == KEY and str(o.base_url) == "https://api.openai.com/v1/" and o.max_retries == 0
    assert req.headers["authorization"] == "Bearer " + KEY
    assert "openai-organization" not in req.headers and "openai-project" not in req.headers
    g = gemini_client.build_sdk_client(KEY, 30)
    assert g._api_client.vertexai is False and g._api_client.api_key == KEY
    assert g._api_client._http_options.base_url == gemini_client.BASE_URL and g._api_client._http_options.timeout == 30000


def test_bedrock_with_a_project_key_sends_only_that_bearer_token():
    """With a project key the request carries Authorization: Bearer <that key>; the dummy AWS_* variables (access key,
    bearer token) set in this container are not used. The request is captured before it is sent."""
    from app.llm import bedrock_client
    client = bedrock_client.build_sdk_client(KEY, "us-east-1", 30)
    seen = {}

    def capture(request, **kw):
        seen["auth"] = request.headers.get("Authorization")
        seen["url"] = request.url
        from botocore.awsrequest import AWSResponse

        class Raw:
            def stream(self, **k):
                yield b""
        body = json.dumps(b_resp()).encode()
        r = AWSResponse(request.url, 200, {"content-type": "application/json"}, Raw())
        r._content = body
        return r
    client.meta.events.register("before-send.bedrock-runtime.Converse", capture)
    p = BedrockProvider("anthropic.model-b", KEY, "us-east-1", 30, sdk_client=client)
    assert p.chat_json("S", "U", SCHEMA, 100).data == {"answer": "ok"}
    auth = seen["auth"].decode() if isinstance(seen["auth"], bytes) else seen["auth"]
    assert auth == "Bearer " + KEY
    assert "dummy-not-a-key" not in auth and "AWS4-HMAC" not in auth
    assert seen["url"].startswith("https://bedrock-runtime.us-east-1.amazonaws.com/")


def test_bedrock_needs_a_region_and_never_builds_without_one():
    s = _settings("bedrock", "")
    assert factory.problem(s) == "Set MOMUS_ANALYST_REGION for Bedrock."
    with pytest.raises(base.NotConfigured):
        factory.build(s)


def test_a_missing_sdk_affects_only_its_own_provider(monkeypatch):
    real_import = builtins.__import__

    def no_anthropic(name, *a, **k):
        if name == "anthropic" or name.startswith("anthropic."):
            raise ImportError("simulated: not installed")
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", no_anthropic)
    with pytest.raises(base.NotConfigured) as e:
        AnthropicProvider("m", KEY, 30, sdk_client=NS())
    assert "anthropic SDK is not installed" in str(e.value)
    for kind in ("openai", "gemini", "bedrock"):            # the others still work
        p, _ = make(kind, ANSWERS[kind]())
        assert p.chat_json("S", "U", SCHEMA, 100).data == {"answer": "ok"}


def test_importing_the_adapter_modules_imports_no_sdk():
    import subprocess
    import sys
    code = ("import sys; sys.path.insert(0, '/src/brain'); import app.llm.factory, app.llm.anthropic_client, app.llm.openai_client, "
            "app.llm.gemini_client, app.llm.bedrock_client, app.web; "
            "print(sorted(m for m in ('anthropic', 'openai', 'google.genai', 'boto3', 'botocore') if m in sys.modules))")
    out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() == "[]", out.stderr[-500:]


# ---------------------------------------------------------------- provider choice
def test_test_providers_are_refused_outside_lab_mode():
    for p in ("mock", "susceptible"):
        s = _settings(p, lab=False)
        assert factory.problem(s) == factory.E_TEST_ONLY
        with pytest.raises(base.NotConfigured) as e:
            factory.build(s)
        assert str(e.value) == factory.E_TEST_ONLY
        assert factory.build(_settings(p, lab=True)).name == p


def test_real_providers_are_refused_in_lab_mode():
    for p in factory.REAL:
        s = _settings(p, KEY, lab=True, analyst_region="us-east-1")
        assert factory.problem(s) == factory.E_LAB_REAL


def test_none_is_the_default_and_unknown_values_are_refused():
    from app import config
    assert config.from_env({}).analyst_provider == "none"
    assert factory.problem(config.from_env({})) == factory.E_NONE
    assert factory.problem(config.from_env({"MOMUS_ANALYST_PROVIDER": "evil"})) == factory.E_INVALID


# ---------------------------------------------------------------- configuration and the key holder
def test_secret_never_prints_itself():
    s = Secret(KEY)
    assert KEY not in repr(s) and KEY not in str(s) and KEY not in f"{s}" and s.reveal() == KEY
    st = Settings(analyst_key=s)
    assert KEY not in repr(st)
    with pytest.raises(TypeError):
        import pickle
        pickle.dumps(s)


def test_key_from_variable_or_secret_file(tmp_path):
    from app import config
    f = tmp_path / "key"
    f.write_text(KEY + "\n")
    s = config.from_env({"MOMUS_ANALYST_PROVIDER": "openai", "MOMUS_ANALYST_MODEL": "m", "MOMUS_ANALYST_API_KEY_FILE": str(f)})
    assert s.analyst_key.reveal() == KEY and s.analyst_key_source == "file"
    s = config.from_env({"MOMUS_ANALYST_API_KEY": "  k1  ", "MOMUS_ANALYST_API_KEY_FILE": str(f)})
    assert s.analyst_key.reveal() == "k1" and s.analyst_key_source == "MOMUS_ANALYST_API_KEY"
    s = config.from_env({"MOMUS_ANALYST_API_KEY_FILE": str(tmp_path / "missing")})
    assert not s.analyst_key and s.analyst_key_source == ""
    big = tmp_path / "big"
    big.write_text("k" * 20000)
    assert not config.from_env({"MOMUS_ANALYST_API_KEY_FILE": str(big)}).analyst_key
    # the SDKs' own variables are never read by the configuration
    assert not config.from_env({"ANTHROPIC_API_KEY": "x", "OPENAI_API_KEY": "x", "GEMINI_API_KEY": "x"}).analyst_key


# ---------------------------------------------------------------- the one schema dialect
def test_every_outgoing_schema_is_in_the_common_dialect():
    for name, s in prompts.all_schemas().items():
        assert schemam.dialect_problems(s) == [], name
        w = json.dumps(schemam.wire(s))
        for kw in schemam.LOCAL_ONLY:
            assert f'"{kw}"' not in w, (name, kw)


def test_validator_and_extractor():
    assert schemam.extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert schemam.extract_json('Sure! {"a": 1} hope that helps') == {"a": 1}
    assert schemam.extract_json('{"a": 1, "a": 2}') is None
    assert schemam.extract_json("[" * 50 + "]" * 50) is None
    assert schemam.validate({"answer": "ok"}, SCHEMA) == []
    assert schemam.validate({"answer": True}, SCHEMA) and schemam.validate({}, SCHEMA)


def test_the_socket_guard_records_and_blocks_an_outbound_attempt():
    """The guard this whole suite relies on: an outbound connection is refused and recorded (the autouse fixture then
    fails the test that made it; here the record is taken back so this test itself passes)."""
    import socket
    import conftest
    before = len(conftest.OUTBOUND_ATTEMPTS)
    for attempt in (lambda: socket.create_connection(("192.0.2.1", 443), timeout=1),
                    lambda: socket.getaddrinfo("api.anthropic.com", 443),
                    lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("192.0.2.1", 443))):
        with pytest.raises(OSError):
            attempt()
    made = conftest.OUTBOUND_ATTEMPTS[before:]
    assert [m[0] for m in made] == ["create_connection", "getaddrinfo", "connect"]
    del conftest.OUTBOUND_ATTEMPTS[before:]
    a, b = socket.socketpair()          # local in-process sockets still work
    a.sendall(b"x")
    assert b.recv(1) == b"x"
    a.close()
    b.close()


def test_the_mock_record_file_stops_growing_at_its_cap(tmp_path, monkeypatch):
    from app.llm import mock as mockm
    monkeypatch.setattr(mockm, "MAX_RECORD_BYTES", 3000)
    p = tmp_path / "rec.jsonl"
    m = mockm.MockProvider(record_path=str(p), script=[GOOD] * 20)
    for _ in range(20):
        m.chat_json("S" * 100, "U" * 400, SCHEMA, 100)
    assert len(m.prompts) == 20 and p.stat().st_size <= 3000 and p.read_text().count("\n") >= 4
