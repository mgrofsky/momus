"""The outgoing redaction pass runs on each free-text segment (the chat question, accepted
notes, every untrusted part, corrective notes), never on the assembled prompt, so it cannot rewrite identifiers in the
data parts. In exchange, this proves the data parts need no second pass: every string in every tool's data part
fullmatches a strict identifier, vocabulary, date, version or address pattern. (The planted-secret tests in
test_analyst_outbound.py pass unchanged.)"""
import ipaddress
import re

import fixtures
from analyst_helpers import KEYS, edit_snapshot, final, mock, run, tool
from app import published, queries, snapshot
from app.analyst import tools as toolsm
from test_analyst_proposals import admin, app, settings  # noqa: F401  (fixtures)

CARD_KEY = "ab4111111111111111cd"            # hex, and holds a 16-digit run that passes the Luhn check


def test_a_finding_key_that_looks_like_a_card_number_reaches_the_prompt_unchanged(settings, app):
    tables = ("findings", "finding_observations", "finding_triage")
    edit_snapshot(settings.published_dir, [(f"UPDATE {t} SET finding_key=? WHERE finding_key=?", (CARD_KEY, KEYS["env"])) for t in tables])
    p = mock([tool("search_findings", {}), final("brief")])
    run(settings, p)
    user = p.prompts[1][1]
    data_line = user.splitlines()[user.splitlines().index("[step 1] result of search_findings (data):") + 1]
    assert CARD_KEY in data_line and "REDACTED" not in data_line          # not ab<REDACTED card>cd


# ---- the strict patterns a data string may match (and nothing else)
VOCAB = set()
for v in (queries.BANDS, queries.STATES, queries.SOURCES, queries.SORTS, toolsm.CLASSES, toolsm.VERDICTS,
          ("false_positive", "accepted_risk", "duplicate", "human", "agent", "other", "metadata-only",
           "inventory", "full", "recheck", "tcp", "udp", "open", "A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA", "PTR", "SRV",
           "too large; ask for fewer rows", "unrecognized reason")):
    VOCAB.update(x for x in v if isinstance(x, str))
PATTERNS = [toolsm.FINDING_KEY_RE, published.HOSTNAME_RE, published.ID_RE, toolsm.CHECK_ID_RE, toolsm.CVE_RE, toolsm.VERSION_RE,
            toolsm.DATE_RE, toolsm.SECRET_TYPE_RE, toolsm.CATEGORY_RE, published.VW_WATCH_ID_RE,
            published.VW_READ_FROM_RE] + list(toolsm.VW_REASON_RES)        # version-watch read_from and reason: fixed shapes


def strict(v):
    if v in VOCAB or any(p.fullmatch(v) for p in PATTERNS):
        return True
    try:
        ipaddress.ip_network(v, strict=False)
        return True
    except ValueError:
        return False


def strings(v, path="data"):
    if isinstance(v, str):
        yield path, v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield from strings(k, path + ".<key>")
            yield from strings(x, f"{path}.{k}")
    elif isinstance(v, list):
        for i, x in enumerate(v):
            yield from strings(x, f"{path}[{i}]")


def test_every_string_in_every_data_part_is_a_strict_value(settings, app, admin):
    fixtures.build_published(settings.published_dir, hostile=True)          # the hostile fixture: text everywhere
    st = snapshot.current(settings.published_dir, settings.snapshot_cache)
    ctx = toolsm.Ctx(st, toolsm.app_db_readonly(settings.db_path), settings.published_dir, False)
    c = ctx.snap()
    known = queries.known_ids(c)
    c.close()
    calls = [("list_runs", {}), ("search_findings", {}), ("search_findings", {"state": "fixed"}), ("expiring_certificates", {"days": 365}),
             ("domain_posture", {}), ("list_components", {}), ("hosts_held_back", {}), ("existing_marks", {}), ("accepted_notes", {}),
             ("version_watch_status", {}), ("version_watch_status", {"watch_id": "php-cgi"})]
    calls += [("get_finding", {"finding_key": k}) for k in sorted(known["finding"])]
    calls += [("get_asset", {"hostname": h}) for h in sorted(known["host"])]
    calls += [("run_summary", {"run_id": r}) for r in sorted(known["run"])]
    runs = sorted(known["run"])
    calls += [("diff_runs", {"run_a": runs[0], "run_b": runs[-1]})]
    assert set(n for n, _ in calls) == set(toolsm.TOOLS)                     # every tool is walked
    bad, seen = [], 0
    for name, args in calls:
        res = toolsm.call(ctx, name, args)
        for path, v in strings(res["data"]):
            seen += 1
            if not strict(v):
                bad.append((name, path, v[:80]))
    assert seen > 200
    assert bad == []
