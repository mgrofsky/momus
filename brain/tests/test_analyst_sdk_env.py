"""The analyst reads only its own MOMUS_ANALYST_* settings. Proxy, CA bundle, extra-header,
debug-log and (Bedrock) endpoint variables have no effect on any built client or on any SDK's log level; with
MOMUS_ANALYST_PROXY set the client uses exactly that proxy; a redirect answer is not followed. Everything here runs in the
test container with dummy values; no request leaves (stub transports, the socket guard)."""
import io
import json
import os
import subprocess
import sys
import textwrap

import pytest

from app.config import Secret, from_env

try:
    from app.llm import envguard
except ImportError:          # without the module, each test below shows its own failing line
    envguard = None

PLANTED = {
    "HTTPS_PROXY": "http://env-proxy.invalid:9", "HTTP_PROXY": "http://env-proxy.invalid:9", "ALL_PROXY": "http://env-proxy.invalid:9",
    "https_proxy": "http://env-proxy.invalid:9",
    "REQUESTS_CA_BUNDLE": "/nonexistent/planted-ca.pem", "SSL_CERT_FILE": "/nonexistent/planted-ca.pem",
    "SSL_CERT_DIR": "/nonexistent/planted-ca-dir", "CURL_CA_BUNDLE": "/nonexistent/planted-ca.pem", "AWS_CA_BUNDLE": "/nonexistent/planted-ca.pem",
    "SSLKEYLOGFILE": "/tmp/planted-keylog.txt",
    "ANTHROPIC_CUSTOM_HEADERS": "X-Planted: anthropic", "OPENAI_CUSTOM_HEADERS": "X-Planted: openai",
    "GOOGLE_GENAI_DEFAULT_HEADERS": '{"X-Planted": "gemini"}',
    "ANTHROPIC_LOG": "debug", "OPENAI_LOG": "debug", "GOOGLE_GENAI_DEBUG": "1",
    "AWS_ENDPOINT_URL": "https://endpoint.invalid", "AWS_ENDPOINT_URL_BEDROCK_RUNTIME": "https://endpoint-runtime.invalid",
    "AWS_ENDPOINT_URL_BEDROCK": "https://endpoint-control.invalid",
    "GOOGLE_GENAI_API_VERSION": "v0planted", "GOOGLE_GENAI_CLIENT_MODE": "replay", "GOOGLE_GENAI_REPLAY_ID": "planted",
    "GOOGLE_GENAI_REPLAYS_DIRECTORY": "/tmp/planted-replays", "GOOGLE_GENAI_HTTP_CLIENT": "httpx",
    "ANTHROPIC_OPEN_TELEMETRY": "1", "ANTHROPIC_OPEN_TELEMETRY_TRACES_CONTENT_MODE": "full",
    "BOTOCORE_EXPERIMENTAL__PLUGINS": "planted=planted_module", "AWS_DATA_PATH": "/tmp/planted-data",
    "AWS_CSM_ENABLED": "true", "AWS_USE_FIPS_ENDPOINT": "true", "AWS_USE_DUALSTACK_ENDPOINT": "true",
}

PROBE = textwrap.dedent('''
    import json, logging, os, sys
    sys.path.insert(0, os.path.join(os.environ["MOMUS_REPO"], "brain"))
    try:
        from app.llm import envguard
        out = {"removed": envguard.scrub() if sys.argv[1] == "start-up" else []}
    except ImportError:
        out = {"removed": []}
    proxy = sys.argv[2]
    planted = json.loads(sys.argv[3])
    def pool(httpx_client, url):
        import httpx2
        t = httpx_client._transport_for_url(httpx2.URL(url))
        p = getattr(t, "_pool", None)
        u = getattr(p, "_proxy_url", None)
        return {"trust_env": httpx_client.trust_env, "follow_redirects": httpx_client.follow_redirects,
                "proxy": None if u is None else f"{u.scheme.decode()}://{u.host.decode()}:{u.port}"}
    def safe(name, fn):
        try:
            out[name] = fn()
        except Exception as e:
            out[name] = {"error": type(e).__name__}
    from app.llm import anthropic_client, openai_client, gemini_client, bedrock_client
    def anth():
        c = anthropic_client.build_sdk_client("dummy-key", 30, *([proxy] if proxy else []))
        return {**pool(c._client, "https://api.anthropic.com/v1/messages"), "log": logging.getLogger("anthropic").level,
                "planted_header": any(k.lower() == "x-planted" for k in c.default_headers), "base": str(c.base_url)}
    def oai():
        c = openai_client.build_sdk_client("dummy-key", 30, *([proxy] if proxy else []))
        return {**pool(c._client, "https://api.openai.com/v1/responses"), "log": logging.getLogger("openai").level,
                "planted_header": any(k.lower() == "x-planted" for k in c.default_headers), "base": str(c.base_url)}
    def gem():
        c = gemini_client.build_sdk_client("dummy-key", 30, *([proxy] if proxy else []))
        api = c._api_client
        h = api._http_options.headers or {}
        return {**pool(api._httpx_client, "https://generativelanguage.googleapis.com/"),
                "log": logging.getLogger("google_genai").level, "planted_header": any(k.lower() == "x-planted" for k in h),
                "api_version": api._http_options.api_version, "mode": type(api).__name__, "base": api._http_options.base_url}
    def bed(key):
        def go():
            kw = {"proxy": proxy} if proxy else {}
            c = bedrock_client.build_sdk_client(key, "eu-west-1", 30, **kw)
            ctl = bedrock_client.build_sdk_client(key, "eu-west-1", 30, service="bedrock", **kw)
            s = c._endpoint.http_session
            return {"runtime": c._endpoint.host, "control": ctl._endpoint.host, "proxies": s._proxy_config._proxies,
                    "verify": s._verify, "log": logging.getLogger("botocore").level}
        return go
    safe("anthropic", anth)
    safe("openai", oai)
    safe("gemini", gem)
    safe("bedrock_key", bed("dummy-key"))
    safe("bedrock_chain", bed(""))
    out["env_left"] = sorted(k for k in os.environ if k in planted)
    print(json.dumps(out))
''')


def every_listed_name():
    """PLANTED (values chosen to act if read) plus every name envguard removes: each exact name, and one example per
    prefix, so the start-up test plants the whole list docs/analyst.md describes, not a subset."""
    out = dict(PLANTED)
    for name in envguard.EXACT:
        out.setdefault(name, "planted-by-the-test")
    for prefix in envguard.PREFIXES:
        out[prefix + ("" if prefix.endswith("_") else "_") + "MOMUS_PLANTED"] = "planted-by-the-test"
    return out


def probe(mode, proxy="", planted=None):
    planted = PLANTED if planted is None else planted
    env = {k: v for k, v in os.environ.items() if k not in planted}
    env.update(planted)
    path = os.path.join(os.environ.get("TMPDIR", "/tmp"), "momus_sdk_probe.py")
    with open(path, "w") as fh:
        fh.write(PROBE)
    r = subprocess.run([sys.executable, "-I", "-B", path, mode, proxy, json.dumps(sorted(planted))], env=env, capture_output=True,
                       text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_at_start_up_no_planted_variable_has_any_effect_on_any_client():
    planted = every_listed_name()
    assert len(planted) >= len(envguard.EXACT) + len(envguard.PREFIXES)
    out = probe("start-up", planted=planted)
    import logging
    for name in ("anthropic", "openai", "gemini"):
        d = out[name]
        assert "error" not in d, (name, d)
        assert d["trust_env"] is False and d["follow_redirects"] is False and d["proxy"] is None, (name, d)
        assert d["log"] in (logging.NOTSET, logging.WARNING) and d["planted_header"] is False, (name, d)
    assert out["anthropic"]["base"].startswith("https://api.anthropic.com")
    assert out["openai"]["base"].startswith("https://api.openai.com/v1")
    assert out["gemini"]["base"] == "https://generativelanguage.googleapis.com/" and out["gemini"]["api_version"] != "v0planted"
    for name in ("bedrock_key", "bedrock_chain"):                       # both Bedrock paths
        d = out[name]
        assert d["runtime"] == "https://bedrock-runtime.eu-west-1.amazonaws.com", (name, d)
        assert d["control"] == "https://bedrock.eu-west-1.amazonaws.com", (name, d)
        assert d["proxies"] == {} and "planted" not in str(d["verify"]) and d["verify"].endswith("cacert.pem"), (name, d)
    assert out["env_left"] == []
    assert set(planted) <= set(out["removed"])


def test_the_explicit_clients_alone_defeat_the_proxy_ca_and_endpoint_variables():
    """The control: no start-up scrub. The builders' own arguments still win for proxies, trust stores and the Bedrock
    endpoint; only the variables a constructor cannot override (log level, extra headers) still act, which is why the
    start-up scrub exists. This shows the start-up test above can fail."""
    out = probe("no-scrub")
    import logging
    for name in ("anthropic", "openai"):
        d = out[name]
        assert d["trust_env"] is False and d["follow_redirects"] is False and d["proxy"] is None, (name, d)
    assert out["anthropic"]["log"] == logging.DEBUG and out["anthropic"]["planted_header"] is True     # the scrub is needed
    for name in ("bedrock_key", "bedrock_chain"):
        d = out[name]
        assert d["runtime"] == "https://bedrock-runtime.eu-west-1.amazonaws.com" and d["proxies"] == {}, (name, d)


def test_with_the_proxy_setting_every_client_uses_exactly_that_proxy():
    out = probe("start-up", "http://egress-proxy.invalid:3128")
    for name in ("anthropic", "openai", "gemini"):
        assert out[name]["proxy"] == "http://egress-proxy.invalid:3128", (name, out[name])
    for name in ("bedrock_key", "bedrock_chain"):
        assert out[name]["proxies"] == {"https": "http://egress-proxy.invalid:3128"}, (name, out[name])


def test_the_scrub_keeps_the_aws_credential_variables():
    env = {"AWS_ACCESS_KEY_ID": "d", "AWS_SECRET_ACCESS_KEY": "d", "AWS_SESSION_TOKEN": "d", "AWS_PROFILE": "p",
           "AWS_CONFIG_FILE": "/x", "AWS_SHARED_CREDENTIALS_FILE": "/x", "AWS_WEB_IDENTITY_TOKEN_FILE": "/x", "AWS_ROLE_ARN": "a",
           "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/x", "AWS_EC2_METADATA_DISABLED": "true", "AWS_REGION": "eu-west-1",
           "AWS_BEARER_TOKEN_BEDROCK": "d", "MOMUS_ANALYST_PROVIDER": "bedrock", "HTTPS_PROXY": "x", "OPENAI_LOG": "debug"}
    gone = envguard.scrub(env)
    assert gone == ["HTTPS_PROXY", "OPENAI_LOG"] and "AWS_ACCESS_KEY_ID" in env and "MOMUS_ANALYST_PROVIDER" in env


def test_run_py_scrubs_before_it_imports_anything_else():
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "run.py")).read()
    body = src.split("envguard.scrub_at_start()")[0]
    assert "import uvicorn" not in body and "from app.web" not in body and "from app.config" not in body


# ---------------------------------------------------------------- redirects are not followed (stub transports)
def _stub():
    import httpx2
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx2.Response(307, headers={"location": "https://evil.invalid/steal"})
    return seen, httpx2.MockTransport(handler)


@pytest.mark.parametrize("kind", ["anthropic", "openai", "gemini"])
def test_a_redirect_answer_is_not_followed(kind):
    from app.llm import anthropic_client, base, gemini_client, openai_client
    seen, transport = _stub()
    mod, cls = {"anthropic": (anthropic_client, anthropic_client.AnthropicProvider), "openai": (openai_client, openai_client.OpenAIProvider),
                "gemini": (gemini_client, gemini_client.GeminiProvider)}[kind]
    sdk = mod.build_sdk_client("dummy-key", 10)
    http = sdk._api_client._httpx_client if kind == "gemini" else sdk._client
    http._transport = transport                     # the stub answers every request with a redirect to another host
    p = cls("model-x", "dummy-key", 10, sdk_client=sdk)
    with pytest.raises(base.LLMError):
        p.chat_json("system", "user", {"type": "object", "properties": {}, "required": [], "additionalProperties": False}, 100)
    assert len(seen) == 1 and "evil.invalid" not in seen[0]


def test_bedrock_does_not_follow_a_redirect(monkeypatch):
    import urllib3
    from urllib3.connectionpool import HTTPConnectionPool
    from app.llm import base, bedrock_client
    seen = []

    def make_request(self, conn, method, url, **kw):
        seen.append((self.host, url))
        return urllib3.response.HTTPResponse(body=io.BytesIO(b""), headers={"Location": "https://evil.invalid/steal"}, status=302,
                                             preload_content=False, request_method=method, request_url=url)
    monkeypatch.setattr(HTTPConnectionPool, "_make_request", make_request)
    p = bedrock_client.BedrockProvider("model-x", "dummy-key", "eu-west-1", 10)
    with pytest.raises(base.LLMError):
        p.chat_json("system", "user", {"type": "object", "properties": {}, "required": [], "additionalProperties": False}, 100)
    assert [h for h, _ in seen] == ["bedrock-runtime.eu-west-1.amazonaws.com"]


def test_an_invalid_region_is_refused_before_any_client_is_built():
    from app.llm import factory
    s = from_env({"MOMUS_ANALYST_PROVIDER": "bedrock", "MOMUS_ANALYST_MODEL": "m", "MOMUS_ANALYST_REGION": "evil.example/x"})
    assert factory.problem(s) == factory.E_REGION
    assert from_env({"MOMUS_ANALYST_PROVIDER": "bedrock", "MOMUS_ANALYST_MODEL": "m", "MOMUS_ANALYST_REGION": "eu-west-1"}).analyst_key == Secret("")
