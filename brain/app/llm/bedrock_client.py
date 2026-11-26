"""Adapter for Amazon Bedrock's Converse API, on the official `boto3` SDK (pinned 1.44.11, botocore 1.44.11).

Request: bedrock-runtime converse(modelId, system=[{"text": ...}], messages=[one user message], inferenceConfig=
{"maxTokens": ...}, outputConfig={"textFormat": {"type": "json_schema", "structure": {"jsonSchema": {"schema":
<the schema as a JSON string>, "name": ...}}}}) for JSON (Bedrock's structured output; where a model does not
support it, the request is refused and the run fails with a fixed message). Timeouts: botocore Config read_timeout
(the request timeout) and connect_timeout 10 s; retries off (one attempt).

Credentials:
  - with a key in this project's settings (MOMUS_ANALYST_API_KEY or its file), the key is a Bedrock API key. The
    client is built on a botocore session whose session variables have no environment or config-file source, whose
    token provider returns only that key and whose credential provider finds nothing; requests carry
    "Authorization: Bearer <key>". AWS_BEARER_TOKEN_BEDROCK and the AWS credential variables are not used.
  - with no key, the default AWS credential chain is used (environment, shared files, container or instance role),
    with the region from MOMUS_ANALYST_REGION. Its client is never built by the tests' requests; they stub it.
On both paths the endpoint is passed explicitly, built from the validated region
(https://bedrock-runtime.<region>.amazonaws.com, and bedrock.<region> for the model check), so AWS_ENDPOINT_URL and its
service-specific forms cannot move it; the CA bundle is the image's certifi file, passed explicitly; the proxy is
MOMUS_ANALYST_PROXY when set, else none (Config proxies is never left to the environment); botocore never follows a
redirect. Variables no argument overrides are removed at start-up (envguard.py). boto3 and botocore are imported only
here, and only when a client is built."""
import re
import json

from .base import (AuthError, BadModel, BadResponse, NotConfigured, Provider, RateLimited, Refused, RequestRejected,
                   Timeout, Unavailable, by_status, log_failure, spent, status_of)
from .schema import wire

NAME = "bedrock"
NO_REGION = "The Bedrock adapter needs MOMUS_ANALYST_REGION."
BAD_REGION = "MOMUS_ANALYST_REGION is not an AWS region name (for example us-east-1)."
REGION_RE = re.compile(r"[a-z]{2}(?:-[a-z]{2,12}){1,2}-[0-9]{1,2}")       # always fullmatch
CONNECT_TIMEOUT = 10
SCHEMA_NAME = "momus_answer"
_COMPLETE = ("end_turn", "stop_sequence")
_DECLINED = ("guardrail_intervened", "content_filtered")
_CODES = {
    "AccessDeniedException": AuthError, "UnrecognizedClientException": AuthError, "ExpiredTokenException": AuthError,
    "ThrottlingException": RateLimited, "ServiceQuotaExceededException": RateLimited, "ModelNotReadyException": RateLimited,
    "ModelTimeoutException": Timeout, "ResourceNotFoundException": BadModel, "ValidationException": RequestRejected,
    "InternalServerException": Unavailable, "ServiceUnavailableException": Unavailable, "ModelErrorException": Unavailable,
}
PROFILE_PREFIXES = ("us.", "eu.", "apac.", "ca.", "au.", "jp.", "us-gov.", "global.")


def _sdk():
    try:
        import boto3
        import botocore
        from botocore.config import Config
        from botocore.exceptions import BotoCoreError, ClientError
    except Exception:
        raise NotConfigured("The boto3 SDK is not installed in this image.") from None
    return boto3, botocore, Config, BotoCoreError, ClientError


class _NoCredentials:
    def load_credentials(self):
        return None


class _KeyToken:
    """The project's Bedrock API key, whatever botocore asks for."""

    def __init__(self, key):
        from botocore.tokens import FrozenAuthToken
        self._token = FrozenAuthToken(key)

    def __repr__(self):
        return "_KeyToken()"

    def load_token(self, **_kw):
        return self._token


def isolated_session(key, region):
    """A boto3 session that holds only the project's Bedrock API key and region: every botocore session variable
    loses its environment and config-file source, no shared file is named, configured endpoint URLs are ignored."""
    boto3, botocore_mod, _, _, _ = _sdk()
    import botocore.session
    from botocore.configprovider import BOTOCORE_DEFAUT_SESSION_VARIABLES
    session_vars = {name: (None, None, default, convert)
                    for name, (_cfg, _env, default, convert) in BOTOCORE_DEFAUT_SESSION_VARIABLES.items()}
    session_vars["ignore_configured_endpoint_urls"] = (None, None, True, None)
    core = botocore.session.Session(session_vars=session_vars)
    core.register_component("token_provider", _KeyToken(key))
    core.register_component("credential_provider", _NoCredentials())
    return boto3.session.Session(region_name=region, botocore_session=core)


def endpoint(service, region):
    if not region:
        raise NotConfigured(NO_REGION)
    if not REGION_RE.fullmatch(region):
        raise NotConfigured(BAD_REGION)
    return f"https://{service}.{region}.amazonaws.com"


def build_sdk_client(key, region, timeout_seconds, service="bedrock-runtime", proxy=""):
    url = endpoint(service, region)
    boto3, _, Config, _, _ = _sdk()
    import certifi
    cfg = Config(signature_version="bearer" if key else None, connect_timeout=CONNECT_TIMEOUT,
                 read_timeout=int(timeout_seconds), retries={"total_max_attempts": 1, "mode": "standard"},
                 proxies={"https": proxy} if proxy else {})        # never None: None would read the proxy variables
    args = dict(config=cfg, endpoint_url=url, verify=certifi.where())
    if key:
        return isolated_session(key, region).client(service, **args)
    # no project key: the default AWS credential chain (environment, shared files, container or instance role)
    return boto3.session.Session(region_name=region).client(service, **args)


class BedrockProvider(Provider):
    name = NAME
    structured = "native"

    def __init__(self, model, key, region, timeout_seconds, sdk_client=None, control_client=None, proxy=""):
        super().__init__(model, timeout_seconds)
        _, _, _, self._BotoCoreError, self._ClientError = _sdk()
        self._key, self._region, self._proxy = key, region, proxy
        self._client = sdk_client if sdk_client is not None else build_sdk_client(key, region, timeout_seconds, proxy=proxy)
        self._control = control_client

    def _classify(self, exc):
        if isinstance(exc, self._ClientError):
            code = ((getattr(exc, "response", None) or {}).get("Error") or {}).get("Code")
            return _CODES.get(code) or by_status(status_of(exc)) or Unavailable
        name = type(exc).__name__
        if "Timeout" in name:
            return Timeout
        if name in ("NoCredentialsError", "PartialCredentialsError", "NoAuthTokenError", "TokenRetrievalError"):
            return AuthError
        return Unavailable

    def _call(self, system, user, schema, max_tokens):
        kw = {"modelId": self.model, "system": [{"text": system}],
              "messages": [{"role": "user", "content": [{"text": user}]}],
              "inferenceConfig": {"maxTokens": int(max_tokens)}}
        if schema is not None:
            kw["outputConfig"] = {"textFormat": {"type": "json_schema", "structure": {"jsonSchema": {
                "schema": json.dumps(wire(schema), separators=(",", ":")), "name": SCHEMA_NAME}}}}
        try:
            r = self._client.converse(**kw)
        except (self._ClientError, self._BotoCoreError) as e:
            log_failure(NAME, e)
            raise self._classify(e)() from None
        r = r if isinstance(r, dict) else {}
        usage = r.get("usage") if isinstance(r.get("usage"), dict) else {}
        tin, tout = usage.get("inputTokens") or 0, usage.get("outputTokens") or 0
        stop = r.get("stopReason")
        if stop in _DECLINED:
            raise spent(Refused(), tin, tout)
        if stop not in _COMPLETE:
            raise spent(BadResponse(), tin, tout)
        msg = ((r.get("output") or {}).get("message") or {}) if isinstance(r.get("output"), dict) else {}
        text = "".join(b["text"] for b in (msg.get("content") or []) if isinstance(b, dict) and isinstance(b.get("text"), str))
        if not text.strip():
            raise spent(BadResponse(), tin, tout)
        return text, tin, tout

    def check_model(self):
        ctl = self._control or build_sdk_client(self._key, self._region, self.timeout_seconds, service="bedrock", proxy=self._proxy)
        try:
            if self.model.startswith(PROFILE_PREFIXES):
                d = ctl.get_inference_profile(inferenceProfileIdentifier=self.model)
                status = d.get("status")
            else:
                d = ctl.get_foundation_model(modelIdentifier=self.model)
                status = ((d.get("modelDetails") or {}).get("modelLifecycle") or {}).get("status")
        except (self._ClientError, self._BotoCoreError) as e:
            log_failure(NAME, e)
            raise self._classify(e)() from None
        return f"model {self.model} is known to Bedrock in {self._region} (status {str(status)[:20]})"
