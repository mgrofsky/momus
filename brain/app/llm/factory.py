"""Choose and build the provider for the analyst, from the settings only.

  none (the default)          no provider: the analyst is off and everything else works
  anthropic, openai, gemini   need MOMUS_ANALYST_API_KEY (or its file) and MOMUS_ANALYST_MODEL
  bedrock                     needs MOMUS_ANALYST_REGION and MOMUS_ANALYST_MODEL; a key (a Bedrock API key) is optional:
                              without one the default AWS credential chain is used
  mock, susceptible           test providers, refused unless the brain runs in lab mode (MOMUS_LAB=1)

In lab mode only the test providers work (the brain has no route out). A provider is built only when a run starts,
never at import, at start-up or for a page view. Each adapter module imports its SDK only when it builds a client,
so a missing or broken SDK affects only its own provider."""
from .base import NotConfigured

REAL = ("anthropic", "openai", "gemini", "bedrock")
LABELS = {
    "anthropic": "Anthropic (api.anthropic.com)",
    "openai": "OpenAI (api.openai.com)",
    "gemini": "Google, the Gemini API (generativelanguage.googleapis.com)",
    "bedrock": "Amazon Bedrock in {region} (bedrock-runtime.{region}.amazonaws.com)",
    "mock": "the built-in mock provider (test only; nothing leaves the brain)",
    "susceptible": "the built-in susceptible provider (test only; nothing leaves the brain)",
}
E_NONE = "No model provider is configured (MOMUS_ANALYST_PROVIDER is none). Everything else works without it."
E_INVALID = "MOMUS_ANALYST_PROVIDER must be one of: none, anthropic, openai, gemini, bedrock (or mock, susceptible in lab mode)."
E_TEST_ONLY = ("The mock and susceptible providers are test providers: they are refused unless the brain runs in lab mode "
               "(MOMUS_LAB=1).")
E_LAB_REAL = "In lab mode only the test providers (mock, susceptible) work: the brain has no route to a model provider."
E_REGION = "MOMUS_ANALYST_REGION is not an AWS region name (for example us-east-1)."
REGION_RE = __import__("re").compile(r"[a-z]{2}(?:-[a-z]{2,12}){1,2}-[0-9]{1,2}")    # bedrock_client.REGION_RE (no SDK import here)
E_PROXY = ("MOMUS_ANALYST_PROXY is not valid: give one http:// or https:// URL with a host and a port, with no user name, "
           "password or path (for example http://egress-proxy:3128).")


def label(settings):
    p = settings.analyst_provider
    return LABELS.get(p, "no provider").format(region=settings.analyst_region or "(no region set)")


def problem(settings):
    """Why no provider can be built, as a fixed sentence, or None. Builds nothing and imports no SDK."""
    p = settings.analyst_provider
    if p == "none":
        return E_NONE
    if p not in REAL + ("mock", "susceptible"):
        return E_INVALID
    if p in ("mock", "susceptible") and not settings.lab:
        return E_TEST_ONLY
    if p in REAL and settings.lab:
        return E_LAB_REAL
    if p in REAL and getattr(settings, "analyst_proxy_invalid", False):
        return E_PROXY
    if p in REAL and not settings.analyst_model:
        return "No model is configured: set MOMUS_ANALYST_MODEL."
    if p in ("anthropic", "openai", "gemini") and not settings.analyst_key:
        return {"anthropic": "Set MOMUS_ANALYST_API_KEY or MOMUS_ANALYST_API_KEY_FILE for Anthropic.",
                "openai": "Set MOMUS_ANALYST_API_KEY or MOMUS_ANALYST_API_KEY_FILE for OpenAI.",
                "gemini": "Set MOMUS_ANALYST_API_KEY or MOMUS_ANALYST_API_KEY_FILE for Gemini."}[p]
    if p == "bedrock" and not settings.analyst_region:
        return "Set MOMUS_ANALYST_REGION for Bedrock."
    if p == "bedrock" and not REGION_RE.fullmatch(settings.analyst_region):
        return E_REGION
    return None


def build(settings):
    """The provider for these settings, or NotConfigured with a fixed sentence."""
    why = problem(settings)
    if why:
        raise NotConfigured(why)
    p, model, t = settings.analyst_provider, settings.analyst_model, settings.analyst_timeout_seconds
    if p == "mock":
        from .mock import MockProvider
        return MockProvider(model or "mock-1", record_path=settings.analyst_mock_record, timeout_seconds=t)
    if p == "susceptible":
        from .susceptible import SusceptibleProvider
        return SusceptibleProvider(model or "susceptible-1", record_path=settings.analyst_mock_record, timeout_seconds=t)
    key = settings.analyst_key.reveal()
    proxy = getattr(settings, "analyst_proxy", "")
    if p == "anthropic":
        from .anthropic_client import AnthropicProvider
        return AnthropicProvider(model, key, t, proxy=proxy)
    if p == "openai":
        from .openai_client import OpenAIProvider
        return OpenAIProvider(model, key, t, proxy=proxy)
    if p == "gemini":
        from .gemini_client import GeminiProvider
        return GeminiProvider(model, key, t, proxy=proxy)
    from .bedrock_client import BedrockProvider
    return BedrockProvider(model, key, settings.analyst_region, t, proxy=proxy)
