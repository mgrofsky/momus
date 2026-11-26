"""tools/smoke_provider.py, the owner's hand check of a real provider: run here with the provider stubbed (no test
contacts a provider), so the demo snapshot, the model check and the real loop are exercised exactly as it would run."""
import os

from analyst_helpers import final, tool
from app.llm import factory
from app.llm.mock import MockProvider


def test_smoke_provider_runs_a_real_brief_on_demo_data(monkeypatch, capsys):
    from tools import smoke_provider
    seen = []

    class Stub(MockProvider):
        name = "openai"

        def check_model(self):
            seen.append("checked")
            return "model stub is available to this key"
    stub = Stub("model-o", script=[tool("search_findings", {"state": "open"}), tool("get_finding", {"finding_key": "1a2b3c4d5e6f70819203"}),
                                   final("brief", top=[{"title": "Env file", "reason": "Exposed.",
                                                        "references": [{"kind": "finding", "id": "1a2b3c4d5e6f70819203"}]}])])
    monkeypatch.setattr(factory, "build", lambda s: stub)
    monkeypatch.setenv("MOMUS_ANALYST_PROVIDER", "openai")
    monkeypatch.setenv("MOMUS_ANALYST_MODEL", "model-o")
    monkeypatch.setenv("MOMUS_ANALYST_API_KEY", "momus-smoke-test-key-0123456789")
    assert smoke_provider.main() == 0
    out = capsys.readouterr().out
    assert seen == ["checked"] and "outcome: ok" in out and "Env file" in out and "step 2: tool get_finding" in out
    assert "momus-smoke-test-key-0123456789" not in out and "key: set" in out
    assert "Environment file exposed" in "\n".join(u for _, u in stub.prompts)        # the demo data went to the "provider"


def test_smoke_provider_refuses_test_providers_and_none(monkeypatch, capsys):
    from tools import smoke_provider
    for p in ("none", "mock", "susceptible"):
        monkeypatch.setenv("MOMUS_ANALYST_PROVIDER", p)
        assert smoke_provider.main() == 1
    assert "Set MOMUS_ANALYST_PROVIDER" in capsys.readouterr().out
