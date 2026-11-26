"""The brain process's environment, cleaned before any model SDK is imported.

The analyst reads only its MOMUS_ANALYST_* settings. The SDKs and their HTTP stacks also read environment variables of
their own; where a constructor argument overrides one, the adapters pass that argument (explicit key, base URL,
endpoint, CA bundle, an HTTP client built with trust_env=False and no redirects, retries off). The variables below are
read at import, or in a way no constructor argument can override, or are simply not wanted in this process; they are
removed from os.environ at start-up (run.py, tools/smoke_provider.py), before any SDK import, and their names (never
their values) are logged.

Kept on purpose: the standard AWS credential variables that Bedrock's default credential chain
reads when no project key is set (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_PROFILE, the shared
config and credentials file paths, the container and web-identity variables, the instance metadata settings,
AWS_BEARER_TOKEN_BEDROCK) and AWS_REGION / AWS_DEFAULT_REGION (the Bedrock clients pass the region explicitly)."""
import os

# every name in any letter case
EXACT = (
    # proxies: the clients take MOMUS_ANALYST_PROXY explicitly, or none
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    # trust stores and TLS key logging: certificates come from the image's certifi bundle; no session key is ever written
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "AWS_CA_BUNDLE", "SSLKEYLOGFILE",
    "NETRC",
    # Google: keys, endpoints, Vertex and mTLS switches, application default credentials
    "GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GEMINI_BASE_URL", "GOOGLE_VERTEX_BASE_URL", "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_LOCATION", "GOOGLE_API_USE_MTLS_ENDPOINT", "GOOGLE_API_USE_CLIENT_CERTIFICATE",
    "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES",
    # botocore: plugins loaded from the environment, extra data folders, endpoint overrides and variants, client-side
    # monitoring (UDP), and behavior switches the client config sets explicitly
    "BOTOCORE_EXPERIMENTAL__PLUGINS", "BOTO_EXPERIMENTAL__ADD_PROXY_HOST_HEADER", "BOTO_EXPERIMENTAL__NO_EMPTY_CONTINUE",
    "AWS_DATA_PATH", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "AWS_USE_FIPS_ENDPOINT", "AWS_USE_DUALSTACK_ENDPOINT",
    "AWS_DEFAULTS_MODE", "AWS_MAX_ATTEMPTS", "AWS_RETRY_MODE", "AWS_SDK_UA_APP_ID", "AWS_DISABLE_HOST_PREFIX_INJECTION",
    "AWS_REQUEST_CHECKSUM_CALCULATION", "AWS_RESPONSE_CHECKSUM_VALIDATION", "AWS_DISABLE_REQUEST_COMPRESSION",
    "AWS_REQUEST_MIN_COMPRESSION_SIZE_BYTES", "AWS_ACCOUNT_ID_ENDPOINT_MODE", "AWS_AUTH_SCHEME_PREFERENCE",
    "AWS_SIGV4A_SIGNING_REGION_SET", "AWS_ENDPOINT_DISCOVERY_ENABLED",
)
PREFIXES = (
    "ANTHROPIC_",            # keys, base URLs, ANTHROPIC_LOG (read at import), ANTHROPIC_CUSTOM_HEADERS, OpenTelemetry tracing
    "OPENAI_",               # keys, base URL, OPENAI_LOG, OPENAI_CUSTOM_HEADERS, organization and project
    "AZURE_OPENAI_",
    "GOOGLE_GENAI_",         # record and replay mode, HTTP client choice, default headers, debug, API version, Vertex switches
    "AWS_ENDPOINT_URL",      # AWS_ENDPOINT_URL and every AWS_ENDPOINT_URL_<SERVICE>
    "AWS_CSM_",              # client-side monitoring
)


def unwanted(name):
    u = name.upper()
    return u in EXACT or u.startswith(PREFIXES)


def scrub(environ=None):
    """Remove the unwanted names from environ (os.environ by default). Returns the sorted names removed."""
    env = os.environ if environ is None else environ
    gone = sorted(n for n in list(env) if unwanted(n))
    for n in gone:
        env.pop(n, None)
    return gone


def scrub_at_start():
    """scrub() plus one log line naming what was removed (names only)."""
    gone = scrub()
    if gone:
        print("brain: removed from the environment before any model SDK is loaded (see app/llm/envguard.py): "
              + ", ".join(gone), flush=True)
    return gone
