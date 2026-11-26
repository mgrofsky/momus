"""The `mock` test provider: scripted answers, and a record of every prompt it was sent. Lab mode and tests only
(factory.py refuses it otherwise). It sends nothing anywhere.

  MockProvider(script=[...])  each item is a dict (answered as JSON text), a str (answered as is), an LLMError instance
                              (raised), or a callable(system, user) returning one of those. When the script runs out,
                              the default agent below answers.
  MockProvider()              the default agent: a deterministic stand-in for a model, used by the lab end-to-end
                              test. Step 1 searches open findings; then it reads each finding it saw (get_finding, at
                              most five, so stored evidence reaches the prompts the end-to-end test checks for canary
                              secrets); then it gives a final answer built from the finding keys it saw: the first three as the top items, one remediation group, and one
                              proposal (a false positive on the last finding it saw) so the proposal queue has
                              something a person can accept.

Every prompt is kept in .prompts as (system, user). With record_path set (MOMUS_ANALYST_MOCK_RECORD, lab only), each is
also appended to that file as one JSON line, so the end-to-end test can check what would have left the machine."""
import json
import os
import re
import threading

from .base import LLMError, Provider

MAX_RECORD_BYTES = 16 * 1024 * 1024     # the record file stops growing here (the lab brain's /tmp is a 64 MiB tmpfs)
KEY_RE = re.compile(r'"finding_key":"([0-9a-f]{8,64})"')
RUN_RE = re.compile(r"latest scored run is ([a-z0-9][a-z0-9-]{0,62}[a-z0-9])")
_lock = threading.Lock()


def tokens(s):
    return max(1, len(s) // 4)


def seen_keys(user):
    """Finding keys in the transcript part of the user text, in order of first appearance."""
    tx = user.split("TRANSCRIPT", 1)[-1]
    out = []
    for k in KEY_RE.findall(tx):
        if k not in out:
            out.append(k)
    return out


def tool_answer(kind, tool, args):
    from ..analyst.prompts import EMPTY_FINAL
    return {"action": "tool", "tool": tool, "arguments": json.dumps(args), "final": EMPTY_FINAL[kind]}


def final_answer(kind, final):
    return {"action": "final", "tool": "none", "arguments": "{}", "final": final}


def kind_of(user):
    return "chat" if "Kind of final answer: chat." in user else "brief"


def default_agent(system, user):
    kind = kind_of(user)
    if "[step" not in user.split("TRANSCRIPT", 1)[-1]:
        return tool_answer(kind, "search_findings", {"state": "open", "limit": 10})
    keys = seen_keys(user)
    read = set(re.findall(r'you called get_finding with \{"finding_key":"([0-9a-f]{8,64})"\}', user))
    for k in keys[:5]:
        if k not in read:
            return tool_answer(kind, "get_finding", {"finding_key": k})
    refs = [{"kind": "finding", "id": k} for k in keys]
    proposals = []
    if keys:
        proposals.append({"kind": "false_positive", "finding_key": keys[-1],
                          "text": "Mock analyst: proposed for the lab test. Check the stored evidence before accepting.",
                          "references": [{"kind": "finding", "id": keys[-1]}]})
    if kind == "chat":
        return final_answer("chat", {"answer": f"Mock analyst answer: the search returned {len(keys)} open finding(s).",
                                     "references": refs[:5], "proposals": []})
    m = RUN_RE.search(user)
    run_ref = [{"kind": "run", "id": m.group(1)}] if m else []
    return final_answer("brief", {
        "top": [{"title": f"Open finding {k[:8]}", "reason": "Mock analyst: listed in priority order by the search tool.",
                 "references": [{"kind": "finding", "id": k}]} for k in keys[:3]],
        "change_commentary": "Mock analyst: the application lists what changed above; this text is a placeholder.",
        "remediation": [{"cause": "Mock grouping", "advice": "Review each finding's stored evidence and fix the cause.",
                         "references": refs[:5] + run_ref}] if keys else [],
        "proposals": proposals})


class MockProvider(Provider):
    name = "mock"
    structured = "native"

    def __init__(self, model="mock-1", script=None, record_path="", timeout_seconds=30):
        super().__init__(model or "mock-1", timeout_seconds)
        self.script = list(script or [])
        self.prompts = []
        self.record_path = record_path

    def _record(self, system, user):
        self.prompts.append((system, user))
        if self.record_path:
            line = json.dumps({"system": system, "user": user}, ensure_ascii=False) + "\n"
            with _lock:
                try:
                    size = os.path.getsize(self.record_path)
                except OSError:
                    size = 0
                if size + len(line.encode("utf-8")) <= MAX_RECORD_BYTES:
                    try:            # never through a link (O_NOFOLLOW), only appended to
                        fd = os.open(self.record_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                                     | getattr(os, "O_CLOEXEC", 0), 0o600)
                    except OSError:
                        return
                    with os.fdopen(fd, "a", encoding="utf-8") as fh:
                        fh.write(line)

    def answer(self, system, user):
        item = self.script.pop(0) if self.script else default_agent
        if callable(item):
            item = item(system, user)
        return item

    def _call(self, system, user, schema, max_tokens):
        self._record(system, user)
        item = self.answer(system, user)
        if isinstance(item, LLMError):
            raise item
        text = item if isinstance(item, str) else json.dumps(item)
        return text, tokens(system + user), tokens(text)

    def check_model(self):
        return "the mock provider (no model; nothing is sent anywhere)"
