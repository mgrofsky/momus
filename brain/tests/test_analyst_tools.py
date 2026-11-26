"""The tool registry: enumerated, read-only, nothing reaches the network, files, jobs, scope or settings. Every tool
validates its arguments, caps what it returns, and keeps text from scanned sites in its labeled untrusted part."""
import ast
import hashlib
import json
import os

import pytest

import fixtures
from analyst_helpers import KEYS, lab_settings
from app import snapshot
from app.analyst import tools as toolsm
from app.web import create_app

EXPECTED = {"list_runs", "run_summary", "search_findings", "get_finding", "get_asset", "list_components", "expiring_certificates",
            "domain_posture", "diff_runs", "version_watch_status", "hosts_held_back", "existing_marks", "accepted_notes"}
SAMPLE_ARGS = {"list_runs": {}, "run_summary": {"run_id": "full-2"}, "search_findings": {"state": "open"},
               "get_finding": {"finding_key": KEYS["env"]}, "get_asset": {"hostname": "target.demo.test"}, "list_components": {},
               "expiring_certificates": {"days": 365}, "domain_posture": {}, "diff_runs": {"run_a": "full-1", "run_b": "full-2"},
               "version_watch_status": {"watch_id": fixtures.WATCH_ID}, "hosts_held_back": {}, "existing_marks": {}, "accepted_notes": {}}


@pytest.fixture
def ctx(tmp_path, capsys):
    s = lab_settings(tmp_path)
    fixtures.build_published(s.published_dir, hostile=True)
    with open(os.path.join(s.published_dir, "held_back.json"), "w") as fh:
        json.dump({"schema": "momus-held-back-v1", "run_id": "full-2", "inventory_run": "inv-1",
                   "hosts": [{"host": "new.demo.test", "reason": "new-since-approved-inventory", "approved_ips": [], "current_ips": ["10.89.47.20"]}],
                   "domains": []}, fh)
    create_app(s, start_background=False)
    from app import db as dbm
    w = dbm.connect(s.db_path)
    w.execute("INSERT INTO notes(finding_key, body, source, accepted_by, created_at) VALUES(?, 'remember this', 'agent', 'admin', '2030-01-01T00:00:00Z')",
              (KEYS["env"],))
    w.execute("INSERT INTO finding_marks(finding_key, kind, reason, evidence_fp, run_id, run_seq, created_by, created_at) "
              "VALUES(?, 'accepted_risk', ?, 'x', 'full-2', 3, 'admin', '2030-01-01T00:00:00Z')", (KEYS["git"], "reason " + fixtures.HOSTILE))
    w.close()
    st = snapshot.current(s.published_dir, s.snapshot_cache)
    assert st.ok
    return toolsm.Ctx(st, toolsm.app_db_readonly(s.db_path), s.published_dir, False), s


def test_the_registry_is_exactly_the_read_only_tool_list():
    assert set(toolsm.TOOLS) == EXPECTED
    assert set(toolsm.UNTRUSTED_FIELDS) == EXPECTED
    for name, (fn, desc, schema) in toolsm.TOOLS.items():
        assert callable(fn) and desc and schema["type"] == "object" and schema["additionalProperties"] is False
        assert fn.__module__ == "app.analyst.tools"
    # no tool can reach the network, a shell, the file system, the jobs folder, the scope or the settings: the module
    # imports none of those, and no tool calls a writer
    tree = ast.parse(open(toolsm.__file__).read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported |= {(node.module or "").split(".")[0]} | {a.name for a in node.names}
    for forbidden in ("os", "subprocess", "socket", "shutil", "http", "requests", "httpx", "httpx2", "pathlib", "jobs", "scope",
                      "auth", "config", "scheduler", "audit", "urllib.request", "anthropic", "openai", "boto3", "google"):
        assert forbidden not in imported, forbidden
    names = {n.attr if isinstance(n, ast.Attribute) else n.id for n in ast.walk(tree) if isinstance(n, (ast.Attribute, ast.Name))}
    for writer in ("add", "withdraw", "queue", "write_job_file", "save", "remove", "confirm", "set_profile", "add_entry", "add_domain",
                   "executescript", "commit", "open"):
        assert writer not in names, writer


def test_every_tool_is_read_only_against_the_databases_and_files(ctx):
    c, s = ctx

    def digest():
        h = hashlib.sha256()
        for root in (s.data_dir, s.published_dir, s.jobs_dir):
            for dp, dn, fn in sorted(os.walk(root)):
                for f in sorted(fn):
                    if f.endswith(("-wal", "-shm")):
                        continue
                    p = os.path.join(dp, f)
                    h.update(p.encode() + b"\0" + open(p, "rb").read())
        return h.hexdigest()
    before = digest()
    for name in EXPECTED:
        r = toolsm.call(c, name, SAMPLE_ARGS[name])
        assert r["tool"] == name and isinstance(r["data"], dict)
    assert digest() == before
    # the app database connection the tools get cannot write
    import sqlite3
    with pytest.raises(sqlite3.OperationalError):
        c.app_db.execute("INSERT INTO notes(body, accepted_by, created_at) VALUES('x', 'y', 'z')")


def walk_strings(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield str(k)
            yield from walk_strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from walk_strings(x)


def test_text_from_scanned_sites_is_only_in_the_untrusted_part(ctx):
    c, _ = ctx
    shown = 0
    for name in EXPECTED:
        r = toolsm.call(c, name, SAMPLE_ARGS[name])
        for v in walk_strings(r["data"]):
            assert "momus-xss" not in v and "DROP TABLE" not in v and "javascript:" not in v, (name, v[:80])
        if any("momus-xss" in v or "DROP TABLE" in v for v in walk_strings(r["untrusted"])):
            shown += 1
    assert shown >= 6, shown          # the hostile fixture text does reach the untrusted parts (the check is not vacuous)


def test_version_watch_status_puts_exactly_hosts_server_in_untrusted(ctx):
    c, _ = ctx
    r = toolsm.call(c, "version_watch_status", {"watch_id": fixtures.WATCH_ID})
    assert {f for host in r["untrusted"].values() for f in host} == {"server"}
    rows = {h["hostname"]: h for h in r["data"]["hosts"]}
    # the fixture's reason carries hostile text appended to a fixed reason: it is not passed on as data
    assert rows["target.demo.test"]["reason"] == "unrecognized reason"
    assert rows["notice.demo.test"]["reason"].startswith("HTTP - (https) / 200 (http), no PHP version")
    assert "momus-xss" in r["untrusted"]["target.demo.test"]["server"]
    lst = toolsm.call(c, "version_watch_status", {})
    assert [w["watch_id"] for w in lst["data"]["watches"]] == [fixtures.WATCH_ID]


def test_version_watch_status_uses_the_brains_reader_and_its_caps(ctx, monkeypatch):
    c, _ = ctx
    from app import published
    seen = []
    real = published.watch_result
    monkeypatch.setattr(published, "watch_result", lambda pub, wid: seen.append(wid) or real(pub, wid))
    toolsm.call(c, "version_watch_status", {"watch_id": fixtures.WATCH_ID})
    assert seen == [fixtures.WATCH_ID]
    assert (published.VW_MAX_JSON, published.VW_MAX_HOSTS, published.VW_MAX_CHANGES, published.VW_MAX_HISTORY) == (4 * 1024 * 1024, 5000, 5000, 100)


def test_metadata_only_omits_every_untrusted_part(ctx):
    c, _ = ctx
    c.metadata_only = True
    for name in EXPECTED:
        r = toolsm.call(c, name, SAMPLE_ARGS[name])
        assert r["untrusted"] == {"omitted": "metadata-only"}, name
        assert not any("momus-xss" in v for v in walk_strings(r))


def test_arguments_are_validated(ctx):
    c, _ = ctx
    for name, args in (("get_finding", {"finding_key": "x' OR 1=1"}), ("get_asset", {"hostname": "../settings"}),
                       ("search_findings", {"band": "Catastrophic"}), ("search_findings", {"limit": 51}), ("list_runs", {"page": 0}),
                       ("run_summary", {}), ("diff_runs", {"run_a": "full-1"}), ("domain_posture", {"extra": 1}),
                       ("version_watch_status", {"watch_id": "../x"}), ("get_finding", {"finding_key": 5})):
        with pytest.raises(toolsm.ToolError) as e:
            toolsm.call(c, name, args)
        assert str(e.value).startswith("Invalid arguments"), (name, args)
    for name, args in (("get_finding", {"finding_key": "f" * 20}), ("run_summary", {"run_id": "full-77"}),
                       ("get_asset", {"hostname": "nope.demo.test"}), ("diff_runs", {"run_a": "full-1", "run_b": "full-99"})):
        with pytest.raises(toolsm.ToolError):
            toolsm.call(c, name, args)
    with pytest.raises(toolsm.ToolError):
        toolsm.call(c, "shell", {})


def test_rows_and_fields_are_capped(ctx):
    c, _ = ctx
    r = toolsm.call(c, "get_finding", {"finding_key": KEYS["env"]})
    for field, v in r["untrusted"][KEYS["env"]].items():
        assert len(v) <= toolsm.MAX_EVIDENCE + 3, field
    assert len(r["untrusted"][KEYS["env"]]["description"]) <= toolsm.MAX_TEXT + 3        # the fixture's is 3,000+ characters
    r = toolsm.call(c, "search_findings", {"limit": 1})
    assert len(r["data"]["findings"]) == 1 and r["data"]["total_matching"] >= 3
    assert len(json.dumps(r)) <= toolsm.MAX_RESULT_CHARS


def test_a_query_past_the_deadline_becomes_snapshot_gone(ctx, monkeypatch):
    c, _ = ctx
    from app import queries

    def slow(*a, **k):
        raise snapshot.Timeout()
    monkeypatch.setattr(queries, "runs", slow)
    with pytest.raises(toolsm.SnapshotGone):
        toolsm.call(c, "list_runs", {})
