"""What leaves for the provider. Secrets planted in snapshot fields, in the formats the redaction module covers,
appear in no prompt the mock recorded; in metadata-only mode no string from the untrusted fields appears at all.
Each check also asserts that prompts were recorded and that a harmless string from the same field did get through,
so it cannot pass by sending nothing. The secrets are assembled at run time, so none sits in the source."""
import hashlib
import os

import pytest

import fixtures
from analyst_helpers import KEYS, app_db, confirm, edit_snapshot, lab_settings, run
from app.llm import redaction
from app.llm.mock import MockProvider
from app.web import create_app


def secrets():
    """{name: value} in formats scanner/pipeline/redact.py covers."""
    j = "".join
    return {
        "aws_key": j(["AK", "IA", "Q3EGT7KZ", "W2RMXP4N"]),
        "github": j(["gh", "p_", "9fK2mQ7xLp4Rt8Wv3Yz6Bn1Cd5Gh0Js2Kl4Mn"]),
        "slack": j(["xo", "xb-", "2048123456-4096123456-", "Zq8Rk3Tv6Wy9Bn2Cd5Fg7Hj"]),
        "stripe": j(["sk", "_live_", "51Hc9Qx2Lm4Np6Rs8Tv0Wy3Zb5Dc7Fe9Gh"]),
        "jwt": j(["ey", "JhbGciOiJIUzI1NiJ9.", "eyJzdWIiOiJtb211cy10ZXN0In0.", "c2lnbmF0dXJlLW1vbXVzLXRlc3QtMTIzNDU2"]),
        "password": j(["Hun", "ter2-", "Plant3d-", "Pw"]),
        "url_pass": j(["S3cret", "UrlPass", "77"]),
        "email": j(["alice.plant", "@", "corp-mail.example"]),
    }


HARMLESS = "harmless-marker-momus-outbound"


@pytest.fixture
def setup(tmp_path, capsys):
    s = lab_settings(tmp_path)
    fixtures.build_published(s.published_dir, hostile=False)
    sec = secrets()
    edit_snapshot(s.published_dir, [
        ("UPDATE findings SET title=? WHERE finding_key=?", (f"{HARMLESS} title aws {sec['aws_key']}", KEYS["env"])),
        ("UPDATE finding_observations SET description=?, matched=?, verification=?, raw_json=? WHERE finding_key=?",
         (f"{HARMLESS} description DB_PASSWORD={sec['password']} slack {sec['slack']}",
          f"https://admin:{sec['url_pass']}@target.demo.test/.env?token={sec['github']}",
          f"{HARMLESS} contact {sec['email']} key {sec['stripe']}",
          '{"extracted-results": ["Authorization: Bearer ' + sec["jwt"] + '"], "note": "' + HARMLESS + ' evidence"}',
          KEYS["env"])),
        ("UPDATE asset_observations SET title=?, server=? WHERE hostname='target.demo.test'",
         (f"{HARMLESS} page title {sec['github']}", f"Tidewater {sec['aws_key']}"))])
    create_app(s, start_background=False)
    confirm(s)
    return s, sec


def provider():
    from analyst_helpers import final, tool
    return MockProvider("mock-1", script=[tool("search_findings", {"state": "open"}), tool("get_finding", {"finding_key": KEYS["env"]}),
                                          tool("get_asset", {"hostname": "target.demo.test"}), final("brief")])


def test_no_planted_secret_reaches_any_prompt(setup):
    s, sec = setup
    p = provider()
    r = run(s, p)
    assert r["outcome"] == "ok" and len(p.prompts) == 4
    blob = "\n".join(sys_ + "\n" + user for sys_, user in p.prompts)
    assert blob.count(HARMLESS) >= 5                                 # the fields did reach the prompt ...
    assert "corp-mail.example" in blob                               # (an email address is reduced to its domain)
    for name, v in sec.items():
        assert v not in blob, name                                   # ... without the secrets in them


def test_chat_questions_and_accepted_notes_are_redacted_too(setup):
    s, sec = setup
    db = app_db(s)
    db.execute("INSERT INTO notes(body, source, accepted_by, created_at) VALUES(?, 'agent', 'admin', '2030-01-01T00:00:00Z')",
               (f"{HARMLESS} note with {sec['github']}",))
    from analyst_helpers import final
    p = MockProvider("mock-1", script=[final("chat")])
    run(s, p, kind="chat", question=f"{HARMLESS} question: is {sec['aws_key']} or password={sec['password']} exposed?")
    user = p.prompts[0][1]
    assert user.count(HARMLESS) == 2
    for name in ("github", "aws_key", "password"):
        assert sec[name] not in user, name


def test_metadata_only_sends_no_untrusted_text_at_all(setup):
    import dataclasses
    s, sec = setup
    s = dataclasses.replace(s, analyst_metadata_only=True)
    confirm(s)
    db = app_db(s)
    db.execute("INSERT INTO notes(body, source, accepted_by, created_at) VALUES(?, 'agent', 'admin', '2030-01-01T00:00:00Z')",
               (f"{HARMLESS} accepted note text",))
    p = provider()
    r = run(s, p)
    assert r["outcome"] == "ok" and len(p.prompts) == 4 and r["metadata_only"] == 1
    blob = "\n".join(u for _, u in p.prompts)
    assert KEYS["env"] in blob and "target.demo.test" in blob and "High" in blob          # identifiers and vocabulary still go
    assert '{"omitted":"metadata-only"}' in blob
    assert HARMLESS not in blob and "Tidewater" not in blob and "Demo shop" not in blob and "Env file" not in blob
    for v in sec.values():
        assert v not in blob
    # every untrusted string the tools would return in normal mode is absent
    from app import snapshot
    from app.analyst import tools as toolsm
    st = snapshot.current(s.published_dir, s.snapshot_cache)
    ctx = toolsm.Ctx(st, toolsm.app_db_readonly(s.db_path), s.published_dir, False)
    seen = 0
    for name, args in (("search_findings", {"state": "open"}), ("get_finding", {"finding_key": KEYS["env"]}),
                       ("get_asset", {"hostname": "target.demo.test"})):
        for fields in toolsm.call(ctx, name, args)["untrusted"].values():
            for v in fields.values():
                if len(v) >= 6:
                    seen += 1
                    assert v not in blob, (name, v[:60])
    assert seen >= 10


def test_the_brain_uses_the_scanners_redaction_module_unchanged():
    """One source of truth: the module loaded is scanner/pipeline/redact.py itself (in a working copy) or the image's
    copy of it; the image copies the file at build time (brain/Dockerfile), and nothing in brain/ forks it."""
    repo = os.environ["MOMUS_REPO"]
    src = os.path.join(repo, "scanner", "pipeline", "redact.py")
    want = hashlib.sha256(open(src, "rb").read()).hexdigest()
    assert redaction.digest() == want
    assert "COPY scanner/pipeline/redact.py ./shared/redact.py" in open(os.path.join(repo, "brain", "Dockerfile")).read()
    for dp, _, files in os.walk(os.path.join(repo, "brain")):
        for f in files:
            if f == "redact.py":
                raise AssertionError(f"a copy of redact.py in the source tree: {dp}")
    m = redaction.load()
    assert m.__file__ in redaction.CANDIDATES


def test_without_the_redaction_module_the_analyst_refuses_to_run(setup, monkeypatch):
    s, _ = setup
    monkeypatch.setattr(redaction, "CANDIDATES", ("/nonexistent/redact.py",))
    monkeypatch.setattr(redaction, "_mod", None)
    from app.analyst import runner
    with pytest.raises(runner.RunRefused) as e:
        run(s, provider())
    assert "redaction module" in str(e.value)
