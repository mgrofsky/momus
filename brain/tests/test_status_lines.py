"""Status lines come from a fixed table looked up by a short code, never from the query string's
own text. Application-wide."""
import ast
import os
import re

import pytest

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app")
PAGES = ["/", "/findings", "/runs", "/scope", "/schedules", "/settings", "/version-watch", "/analyst", "/audit"]


@pytest.mark.parametrize("param", ["msg", "err"])
def test_a_link_cannot_put_its_own_sentence_on_any_page(admin, param):
    planted = "Verified by the security team: safe to accept."
    for path in PAGES:
        page = admin.get(f"{path}?{param}={planted.replace(' ', '+')}").text
        assert "Verified by the security team" not in page, path


def test_a_code_shows_its_fixed_sentence_and_a_bad_value_shows_nothing(admin):
    page = admin.get("/settings?msg=session-revoked").text
    assert "Session signed out." in page
    page = admin.get("/runs?msg=job-abandoned&fp_job=full-20301001-000000-abc123").text
    assert "Job full-20301001-000000-abc123 marked abandoned" in page
    page = admin.get("/runs?msg=job-abandoned&fp_job=Trust+me.+Click+accept").text
    assert "marked abandoned" not in page and "Trust me" not in page
    page = admin.get("/settings?msg=no-such-code").text
    assert 'class="flash' not in page


def _constants(tree):
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                v = ast.literal_eval(node.value)
            except ValueError:
                v = None
            if isinstance(v, str):
                out[node.targets[0].id] = v
    return out


def _sentences():
    """Every sentence in app/ that can reach a status line: messages of the exceptions the page routes turn into a
    status line, the reasons returned by the functions whose text they show, and the texts routes pass themselves."""
    classes = {"QueueError", "ScopeError", "AuthError", "MarkError", "WatchError", "ProposalError", "RunRefused",
               "NotConfigured", "RedactionUnavailable"}
    reasons = {"password_problem", "abandonable", "problem", "readiness"}
    found = []
    for dirpath, _, files in os.walk(APP):
        for f in files:
            if not f.endswith(".py"):
                continue
            p = os.path.join(dirpath, f)
            tree = ast.parse(open(p).read())
            consts = _constants(tree)

            def add(node, where):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    found.append((where, node.value, None))
                elif isinstance(node, ast.JoinedStr):
                    skel = "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in node.values)
                    found.append((where, None, skel))
                elif isinstance(node, ast.Name) and node.id in consts:
                    found.append((where, consts[node.id], None))
            for n in ast.walk(tree):
                where = f"{os.path.relpath(p, APP)}:{getattr(n, 'lineno', 0)}"
                if isinstance(n, ast.Raise) and isinstance(n.exc, ast.Call) and n.exc.args:
                    fn = n.exc.func
                    name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                    if name in classes or (name == "ValueError" and f == "consent.py"):
                        add(n.exc.args[0], where)
                if isinstance(n, ast.FunctionDef) and n.name in reasons:
                    for r in ast.walk(n):
                        if isinstance(r, ast.Return) and r.value is not None:
                            if isinstance(r.value, ast.Dict):
                                for v in r.value.values:
                                    add(v, where)
                            else:
                                add(r.value, where)
                if isinstance(n, ast.Call) and getattr(n.func, "id", getattr(n.func, "attr", "")) == "flash_url":
                    for kw in n.keywords:
                        if kw.arg in ("msg", "err"):
                            if isinstance(kw.value, ast.IfExp):
                                add(kw.value.body, where)
                                add(kw.value.orelse, where)
                            else:
                                add(kw.value, where)
    return found


COMPOSED = {"Lab mode: {}.", 'Tick the ownership statement to add a domain: "{}"'}     # checked whole below


def test_every_status_sentence_has_a_table_entry():
    from app import flash
    table = flash.table()
    skeletons = {flash.PLACEHOLDER.sub("{}", t) for t in table.values()}
    found = _sentences()
    assert len(found) > 100
    missing = []
    for where, text, skel in found:
        if text is not None:
            if text.endswith(".") and flash.encode(text)[0] in ("done", "refused") and text not in ("Done.",):
                missing.append((where, text))
        elif skel not in skeletons and skel not in COMPOSED:
            missing.append((where, skel))
    # sentences built from parts, checked whole
    from app.scope import OWNERSHIP_STATEMENT
    for text in (f'Tick the ownership statement to add a domain: "{OWNERSHIP_STATEMENT}"',
                 "Lab mode: no lab range is known (MOMUS_LAB_CIDR).", "Lab mode: the lab range is not a valid CIDR.",
                 "Add a domain (with the ownership statement) on the Scope page first.",
                 "Add a domain (with the ownership statement) on the Scope page first. In lab mode only inventory, full and "
                 "version-watch runs of lab targets are possible."):
        if flash.encode(text)[0] in ("done", "refused"):
            missing.append(("composed", text))
    assert missing == []


def test_the_table_uses_only_checked_values():
    from app import flash
    for code, text in flash.table().items():
        assert re.fullmatch(r"[a-z0-9-]{2,30}", code), code
        for name in flash.PLACEHOLDER.findall(text):
            assert name in flash.PARAMS, (code, name)
