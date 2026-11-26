"""The admin's confirmation of what the analyst sends, and to whom. The analyst refuses to run until a signed-in
person has confirmed the plain statement below on the Settings page. The confirmation stores the SHA-256 of the
statement's exact text, and it counts only while that equals the hash of the statement as it reads now:
any change to what the statement says (the provider, its region, the model, the metadata-only or automatic-brief
setting, the proxy) asks again. Each confirmation is one audit entry (analyst-consent) under the signed-in person."""
import hashlib
import json

from .. import audit
from ..db import iso
from ..llm import factory

KEY = "analyst_consent"


def basis(settings):
    return {"provider": settings.analyst_provider, "region": settings.analyst_region if settings.analyst_provider == "bedrock" else "",
            "metadata_only": bool(settings.analyst_metadata_only)}


def statement(settings):
    s = settings
    sent = ("identifiers (finding keys, host names, run ids, watch ids), severities, scores, versions, counts and fixed "
            "vocabulary values (states, verdicts, classes), and the IP addresses of your hosts (sent in every mode, "
            "metadata-only included)")
    if s.analyst_metadata_only:
        text_part = ("Metadata-only mode is on: text taken from scanned sites (titles, descriptions, evidence, banners, DNS values), "
                     "accepted notes and the reasons people typed for marks are not sent.")
    else:
        text_part = ("Text taken from the scanned sites is sent too: finding titles, descriptions, remediation text, stored evidence "
                     "excerpts, page titles, server banners, certificate names and DNS values, after best-effort redaction by the "
                     "scanner's redaction module; the notes a person has accepted; and the reasons people typed for manual marks. "
                     "Redaction will miss some secrets; turn on metadata-only mode (MOMUS_ANALYST_METADATA_ONLY=1) to keep all of that "
                     "text out.")
    when = ("when a person asks for a brief or a chat answer, and automatically for each new scan snapshot "
            "(MOMUS_ANALYST_AUTO_BRIEF=1)" if s.analyst_auto_brief else
            "only when a person asks for a brief or a chat answer (the automatic brief is off)")
    via = (f", through the proxy {s.analyst_proxy} (MOMUS_ANALYST_PROXY; it sees which provider is contacted and how much is "
           "sent, not the content: TLS inspection by the proxy is not supported)" if getattr(s, "analyst_proxy", "") else "")
    return (f"The analyst sends requests to {factory.label(s)}, model {s.analyst_model or '(the test model)'}{via}, {when}. "
            f"Each request holds fixed instructions, the task (for chat, the question as typed), and the tool results so far: {sent}. "
            f"{text_part} The provider's API key is sent only as its credential. Nothing is sent until you confirm, and you are asked "
            "again whenever this statement changes: the provider, its region, the model, the metadata-only or automatic-brief "
            "setting, or the proxy.")


def statement_sha(settings):
    return hashlib.sha256(statement(settings).encode("utf-8")).hexdigest()


def stored(db):
    r = db.execute("SELECT value, updated_by, updated_at FROM settings WHERE key=?", (KEY,)).fetchone()
    if not r:
        return None
    try:
        v = json.loads(r["value"])
    except ValueError:
        return None
    return {**v, "by": r["updated_by"], "at": r["updated_at"]} if isinstance(v, dict) else None


def current(db, settings):
    """The confirmation counts only for the statement exactly as it reads now (its SHA-256)."""
    st = stored(db)
    return bool(st) and st.get("statement_sha256") == statement_sha(settings) and all(st.get(k) == v for k, v in basis(settings).items())


def confirm(db, settings, actor, address):
    if factory.problem(settings):
        raise ValueError("There is no usable model provider to confirm.")
    value = json.dumps({**basis(settings), "statement_sha256": statement_sha(settings)}, sort_keys=True)
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute("INSERT INTO settings(key, value, updated_by, updated_at) VALUES(?,?,?,?) "
                   "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_by=excluded.updated_by, updated_at=excluded.updated_at",
                   (KEY, value, actor, iso()))
        b = basis(settings)
        audit.write(db, actor, "analyst-consent", target=b["provider"],
                    detail=f"region {b['region'] or '-'}; metadata-only {'on' if b['metadata_only'] else 'off'}; statement sha256 "
                           f"{statement_sha(settings)}", address=address)
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
