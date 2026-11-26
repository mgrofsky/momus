"""Status lines on pages. The green and red line a page shows after a form comes from this fixed table,
looked up by a short code in the query string (msg=<code>, err=<code>), never from the query string's own text. A
message that names a value (a job id, a number, a host name) carries that value in its own query parameter (fp_<name>),
and the value is shown only when it fullmatches the strict pattern for its kind; otherwise the line is not shown.

Callers pass the sentence they mean (most come from fixed sentences raised by the modules below); url() finds its
entry and code. A sentence with no entry is shown as the generic line for its kind and logged once, and the test
test_every_status_sentence_has_a_table_entry walks the code for every sentence that can reach a status line."""
import ipaddress
import re
import urllib.parse

from . import published
from .scope import OWNERSHIP_STATEMENT

JOB_TYPES = ("scope-sync", "inventory", "full", "recheck", "version-watch", "update-templates", "retention")   # jobs.TYPES
STATES = ("queued", "running", "done", "failed", "rejected", "interrupted", "unknown")
WHATS = ("host name", "domain name", "exclusion (a host name, *.suffix, .suffix, or a CIDR range)")


def _host(v):
    if published.is_hostname(v):
        return True
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


PARAMS = {
    "job": published.is_id,                                       # a job id (also the fixed words too-many-job-files, unrecognized-job)
    "jtype": lambda v: v in JOB_TYPES,
    "n": lambda v: bool(re.fullmatch(r"[0-9]{1,9}", v)),
    "host": _host,
    "watch": published.is_watch_id,
    "state": lambda v: v in STATES,
    "what": lambda v: v in WHATS,
}


def _messages():
    from . import auth, watches
    from .llm import factory
    m = {
        # ---- done (msg=)
        "job-queued": "Queued {jtype} job {job}.",
        "job-abandoned": "Job {job} marked abandoned: the scanner will not run it, and new jobs can be queued.",
        "lab-added": "Added lab target {host}.",
        "domain-added": "Added {host}. A scope-sync job asks the scanner for its TXT record; it appears below once the scanner has published it.",
        "domain-removed": "Removed {host}.",
        "sync-queued": "Queued scope-sync job {job}: the scanner checks every domain's TXT record.",
        "inventory-approved": "Approved inventory {job}. The next full run carries this approval.",
        "approval-withdrawn": "Approval withdrawn: full runs do discovery and web checks only until an inventory is approved.",
        "mark-saved": "Mark saved. It does not change the finding's score, verdict or status.",
        "mark-withdrawn": "Mark withdrawn.",
        "watch-added": "Watch {watch} added. The next version-watch job carries it.",
        "watch-saved": "Watch {watch} saved. The next version-watch job carries the change.",
        "nothing-changed": "Nothing changed.",
        "watch-removed": "Watch {watch} removed. Its published results stay until the scanner's retention removes them (90 days after its last result).",
        "schedule-saved": "Schedule saved.",
        "password-changed": "Password changed. {n} other session(s) were signed out.",
        "session-revoked": "Session signed out.",
        "account-created": "Account created (admin).",
        "scope-saved": "Scope saved. The next job carries it.",
        "profile-saved": "Profile saved. The next job carries it.",
        "brief-started": "Analyst run {n} started. This page shows its status.",
        "chat-started": "Analyst run {n} started. The answer appears below when it is done.",
        "mark-accepted": "Accepted: the mark was saved (it does not change any score, verdict or status).",
        "note-accepted": "Accepted: the note is saved and later analyst runs will see it.",
        "proposal-rejected": "Rejected. Nothing was changed.",
        "proposal-closed": "Closed as out of date. Nothing was changed.",
        "consent-given": "Confirmed. The analyst can now be used.",
        # ---- refused (err=): accounts and sign-in
        "pw-differ": "The two new passwords differ.",
        "pw-short": "The password must be at least {n} characters.",
        "pw-long": "The password must be at most {n} characters.",
        "pw-is-name": "The password must not be the username.",
        "pw-wrong": "The current password is wrong.",
        "pw-same": "The new password must differ from the current one.",
        "bad-username": "Usernames are 3 to 64 characters: letters, digits, space, dot, underscore, @ and hyphen.",
        "reserved-username": auth.RESERVED_MESSAGE,
        "username-taken": "That username is taken.",
        "unknown-session": "Unknown session.",
        "wrong-login": "Wrong username or password.",
        "bad-bootstrap": "That bootstrap token is not valid, or the first account already exists.",
        # ---- jobs
        "unknown-job-type": "Unknown job type.",
        "no-statement": "{host} has no ownership statement. Remove it and add it again with the statement.",
        "lab-no-target": "Lab mode: add a lab target on the Scope page first.",
        "lab-no-range": "Lab mode: no lab range is known (MOMUS_LAB_CIDR).",
        "lab-bad-range": "Lab mode: the lab range is not a valid CIDR.",
        "no-domain": "Add a domain (with the ownership statement) on the Scope page first.",
        "no-domain-lab": "Add a domain (with the ownership statement) on the Scope page first. In lab mode only inventory, full "
                         "and version-watch runs of lab targets are possible.",
        "recheck-needs-approval": "A recheck needs an approved inventory (Scope page).",
        "bad-retention": "Retention days: a whole number from 1 to 3650.",
        "watch-invalid": "A stored watch is not valid any more; edit it on the Version watch page.",
        "no-watch": watches.NONE_FOR_JOB,
        "in-flight": "A job is in flight ({job}). The scanner runs one job at a time; queue this after it ends.",
        "job-too-large": "The job would be larger than the scanner accepts (1 MiB). Shorten the scope (domains, exclusions, "
                         "approved hosts or watches).",
        "jobs-not-writable": "The jobs folder is not writable by the brain.",
        "bad-job-id": "Invalid job id.",
        "job-file-exists": "A job file with that id exists.",
        "not-inventory": "Not a finished inventory run of this scope (lab mode must match).",
        "no-approval": "No approval to withdraw.",
        "confirm-abandon": "Confirm that the scanner is not running this job.",
        "not-a-job": "Not a job id.",
        "job-ended": "Job {job} already ended ({state}).",
        "job-running": "The scanner reports that it is running {job} now.",
        "no-such-job": "No job {job} was written by this brain.",
        "already-abandoned": "Job {job} is already marked abandoned.",
        "marker-failed": "The abandoned marker could not be written in the jobs folder; nothing was changed.",
        # ---- scope
        "lab-only": "Lab targets can only be added in lab mode.",
        "bad-name": "Not a valid {what}: use lower-case labels of a-z, 0-9, '-' and '_', separated by dots.",
        "bad-range": "Not an address or CIDR range.",
        "private-range": "Owned ranges must be public addresses; the scanner never scans private, loopback or link-local ranges.",
        "tick-statement": f'Tick the ownership statement to add a domain: "{OWNERSHIP_STATEMENT}"',
        "too-many-domains": "At most {n} domains.",
        "domain-exists": "That domain is already in scope.",
        "no-such-domain": "No such domain.",
        "too-many-entries": "At most {n} entries.",
        "already-listed": "Already listed.",
        "not-listed": "Not listed.",
        "bad-profile": "Unknown profile value.",
        # ---- marks
        "mark-kind": "Choose false positive, accepted risk or duplicate.",
        "mark-reason": "Give a reason (3 to 2000 characters).",
        "no-such-finding": "No such finding in the current snapshot.",
        "no-last-run": "The finding's last run is not in the snapshot.",
        "no-mark": "That finding has no mark.",
        "review-again": "The evidence changed since this page was shown. Nothing was saved: review the finding again.",
        # ---- the analyst
        "no-such-proposal": "No such proposal.",
        "proposal-decided": "That proposal was already decided.",
        "proposal-out-of-date": "This proposal is out of date: it can only be closed. Nothing was saved.",
        "consent-tick": "Tick the box to confirm the statement.",
        "consent-none": "There is no usable model provider to confirm.",
        "consent-needed": "An admin must first confirm on the Settings page what the analyst sends and to whom.",
        "question-length": "Type a question of 1 to {n} characters.",
        "no-snapshot": "There is no verified scan snapshot to analyse yet.",
        "budget-used": "Today's token budget for the analyst is used up (MOMUS_ANALYST_DAILY_TOKEN_BUDGET).",
        "run-busy": "Analyst run {n} is still running. One run at a time.",
        "no-model": "No model is configured: set MOMUS_ANALYST_MODEL.",
        "key-anthropic": "Set MOMUS_ANALYST_API_KEY or MOMUS_ANALYST_API_KEY_FILE for Anthropic.",
        "key-openai": "Set MOMUS_ANALYST_API_KEY or MOMUS_ANALYST_API_KEY_FILE for OpenAI.",
        "key-gemini": "Set MOMUS_ANALYST_API_KEY or MOMUS_ANALYST_API_KEY_FILE for Gemini.",
        "no-region": "Set MOMUS_ANALYST_REGION for Bedrock.",
        "provider-none": factory.E_NONE,
        "provider-invalid": factory.E_INVALID,
        "provider-test-only": factory.E_TEST_ONLY,
        "provider-lab-real": factory.E_LAB_REAL,
        "adapter-anthropic-key": "The Anthropic adapter needs MOMUS_ANALYST_API_KEY or MOMUS_ANALYST_API_KEY_FILE. It never uses ANTHROPIC_API_KEY.",
        "adapter-openai-key": "The OpenAI adapter needs MOMUS_ANALYST_API_KEY or MOMUS_ANALYST_API_KEY_FILE. It never uses OPENAI_API_KEY.",
        "adapter-gemini-key": "The Gemini adapter needs MOMUS_ANALYST_API_KEY or MOMUS_ANALYST_API_KEY_FILE. It never uses GEMINI_API_KEY, "
                              "GOOGLE_API_KEY or Google Cloud credentials.",
        "adapter-bedrock-region": "The Bedrock adapter needs MOMUS_ANALYST_REGION.",
        "sdk-anthropic": "The anthropic SDK is not installed in this image.",
        "sdk-openai": "The openai SDK is not installed in this image.",
        "sdk-gemini": "The google-genai SDK is not installed in this image.",
        "sdk-boto3": "The boto3 SDK is not installed in this image.",
        "redaction-missing": "The redaction module (scanner/pipeline/redact.py) is not in this image.",
        "redaction-broken": "The redaction module could not be loaded.",
        "redaction-shape": "The redaction module does not have the expected functions.",
        # ---- the generic lines, for a sentence with no entry (logged)
        "done": "Done.",
        "refused": "The request was refused. Nothing was changed.",
    }
    for name in dir(watches):                                     # the version-watch form's fixed sentences
        if name.startswith("E_") and isinstance(getattr(watches, name), str):
            m["watch-" + name[2:].lower().replace("_", "-")] = getattr(watches, name)
    m["provider-proxy"] = factory.E_PROXY
    m["provider-region"] = factory.E_REGION
    return m


_TABLE = None
_EXACT = None
_PATTERNS = None
_logged = set()
PLACEHOLDER = re.compile(r"\{(\w+)\}")


def table():
    global _TABLE, _EXACT, _PATTERNS
    if _TABLE is None:
        t = _messages()
        exact, pats = {}, []
        for code, text in t.items():
            names = PLACEHOLDER.findall(text)
            assert all(n in PARAMS for n in names), (code, names)
            if not names:
                exact.setdefault(text, code)
                continue
            parts = PLACEHOLDER.split(text)
            rx = "".join(re.escape(p) if i % 2 == 0 else f"(?P<{p}>.+?)" for i, p in enumerate(parts))
            pats.append((code, re.compile(rx, re.S)))
        _TABLE, _EXACT, _PATTERNS = t, exact, pats
    return _TABLE


def encode(text, kind="err"):
    """(code, params) for a sentence: its table entry, or the generic line for its kind (msg or err)."""
    table()
    text = text or ""
    if text in _EXACT:
        return _EXACT[text], {}
    for code, rx in _PATTERNS:
        m = rx.fullmatch(text)
        if m and all(PARAMS[k](v) for k, v in m.groupdict().items()):
            return code, m.groupdict()
    if text not in _logged and len(_logged) < 100:
        _logged.add(text)
        print(f"brain: a status sentence has no entry in the fixed table (app/flash.py); shown as the generic line: "
              f"{ascii(text[:120])}", flush=True)
    return ("done" if kind == "msg" else "refused"), {}


def url(base, msg=None, err=None):
    q = {}
    for kind, text in (("msg", msg), ("err", err)):
        if text:
            code, params = encode(text, kind)
            q[kind] = code
            for k, v in params.items():
                q["fp_" + k] = v
    return base + ("?" + urllib.parse.urlencode(q) if q else "")


def render(code, query):
    """The sentence for a code from the query string, or None (unknown code, or a value that fails its pattern)."""
    t = table()
    text = t.get(code or "")
    if text is None:
        return None
    out = text
    for name in PLACEHOLDER.findall(text):
        v = query.get("fp_" + name)
        if not isinstance(v, str) or not PARAMS[name](v):
            return None
        out = out.replace("{" + name + "}", v, 1)
    return out


def read(request):
    q = request.query_params
    return {"msg": render(q.get("msg"), q), "err": render(q.get("err"), q)}
