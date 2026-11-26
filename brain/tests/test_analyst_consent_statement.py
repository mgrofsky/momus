"""The consent statement says that host IP addresses are sent in every mode and that the
reasons people typed for manual marks are sent unless metadata-only is on; and the confirmation counts only while the
stored statement hash equals the hash of the statement as it reads now, so any change to it asks again."""
import dataclasses

from analyst_helpers import app_db, confirm, lab_settings
from app.analyst import consent
from app.config import Settings, from_env
from app.llm import factory


def test_the_statement_names_ip_addresses_in_every_mode_and_typed_mark_reasons():
    s = Settings(analyst_provider="anthropic", analyst_model="m-1")
    t = consent.statement(s)
    assert "IP addresses of your hosts (sent in every mode, metadata-only included)" in t
    assert "the reasons people typed for manual marks" in t
    m = consent.statement(dataclasses.replace(s, analyst_metadata_only=True))
    assert "IP addresses of your hosts (sent in every mode, metadata-only included)" in m
    assert "the reasons people typed for marks are not sent" in m


def test_the_statement_names_the_model_the_automatic_brief_and_the_proxy():
    s = Settings(analyst_provider="openai", analyst_model="m-1")
    assert "model m-1" in consent.statement(s) and "the automatic brief is off" in consent.statement(s)
    assert "automatically for each new scan snapshot" in consent.statement(dataclasses.replace(s, analyst_auto_brief=True))
    p = consent.statement(dataclasses.replace(s, analyst_proxy="http://egress:3128"))
    assert "through the proxy http://egress:3128" in p and "TLS inspection by the proxy is not supported" in p


def test_any_change_to_the_statement_asks_again(tmp_path, capsys):
    s = lab_settings(tmp_path)
    from app.web import create_app
    create_app(s, start_background=False)
    confirm(s)
    db = app_db(s)
    assert consent.current(db, s)
    for change in (dict(analyst_model="mock-2"),                 # a model change alone asks again
                   dict(analyst_auto_brief=True),                # ... and so did the automatic brief
                   dict(analyst_metadata_only=True),
                   dict(analyst_proxy="http://egress:3128")):
        changed = dataclasses.replace(s, **change)
        assert not consent.current(db, changed), change
    assert consent.current(db, s)


def test_the_proxy_setting_is_validated_and_an_invalid_value_stops_the_analyst():
    ok = {"http://egress-proxy:3128": "http://egress-proxy:3128", "HTTPS://Proxy.Example.Test:8443/": "https://proxy.example.test:8443",
          "http://[2001:db8::1]:3128": "http://[2001:db8::1]:3128", "http://192.0.2.10:8080": "http://192.0.2.10:8080"}
    for raw, norm in ok.items():
        s = from_env({"MOMUS_ANALYST_PROXY": raw})
        assert (s.analyst_proxy, s.analyst_proxy_invalid) == (norm, False), raw
    for bad in ("egress:3128", "socks5://egress:1080", "http://user:pw@egress:3128", "http://egress", "http://egress:3128/path",
                "http://egress:99999", "http://egress:3128?x=1", "http://-bad:3128", "ftp://egress:21"):
        s = from_env({"MOMUS_ANALYST_PROXY": bad, "MOMUS_ANALYST_PROVIDER": "anthropic", "MOMUS_ANALYST_MODEL": "m", "MOMUS_ANALYST_API_KEY": "k"})
        assert (s.analyst_proxy, s.analyst_proxy_invalid) == ("", True), bad
        assert factory.problem(s) == factory.E_PROXY
