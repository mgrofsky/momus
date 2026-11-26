"""Marks on findings (false positive, accepted risk, duplicate). A mark lives in the app database, joins to findings
by finding key, and never changes a score, verdict, status or count. It records the evidence fingerprint and the
run it was made against; when the finding reopens after that run, or its evidence fingerprint changes, the mark is
stale: it is shown as stale and the finding counts as unmarked again."""
from . import audit, queries
from .db import iso

KINDS = {"false_positive": "False positive", "accepted_risk": "Accepted risk", "duplicate": "Duplicate"}
# Refused when the evidence the person was shown (its fingerprint, carried by the form) is not the evidence now.
REVIEW_AGAIN = "The evidence changed since this page was shown. Nothing was saved: review the finding again."


class MarkError(Exception):
    pass


def active(db):
    """The newest unwithdrawn mark per finding key."""
    out = {}
    for r in db.execute("SELECT * FROM finding_marks WHERE withdrawn_at IS NULL ORDER BY id"):
        out[r["finding_key"]] = dict(r)
    labeled(out.values())
    return out


def with_staleness(db, snap):
    """{key: mark dict + stale (bool) + stale_why} for every active mark."""
    marks = active(db)
    if not marks or snap is None:
        for m in marks.values():
            m["stale"], m["stale_why"] = False, None
        return marks
    fps = queries.current_fingerprints(snap, list(marks))
    reopened = queries.reopened_after(snap, [(k, m["run_seq"]) for k, m in marks.items()])
    for k, m in marks.items():
        why = None
        if k in reopened:
            why = "the finding reopened after this mark was made"
        elif k in fps and fps[k][0] != m["evidence_fp"]:
            why = "the finding's evidence changed after this mark was made"
        m["stale"], m["stale_why"] = why is not None, why
    return marks


def reason_source(m):
    """Who wrote a mark's reason, for every place the reason is shown: a reason that came from an analyst
    proposal is the model's text, accepted by the person named; any other reason was typed by that person."""
    if m.get("proposal_id"):
        return f"written by the analyst (proposal {int(m['proposal_id'])}) and accepted by {m.get('created_by')}"
    return f"written by {m.get('created_by')}"


def labeled(rows):
    for m in rows:
        m["reason_source"] = reason_source(m)
    return rows


def current_keys(db, snap):
    return {k for k, m in with_staleness(db, snap).items() if not m["stale"]}


def add(db, snap, actor, key, kind, reason, address, proposal=None, shown_fp=None):
    """Mark a finding. proposal: None for a manual mark, or (proposal id, agent run id, text) when a person accepts an
    analyst proposal; the proposal's status then changes in the same transaction (only from pending), the mark records
    the proposal, and the audit entry names the person (actor) and the agent run. shown_fp: the evidence fingerprint
    of the page the person decided on (every form and API request passes it); the mark is refused unless it is the
    finding's fingerprint now, so a mark is always tied to evidence someone saw."""
    if kind not in KINDS:
        raise MarkError("Choose false positive, accepted risk or duplicate.")
    reason = (reason or "").strip()
    if not 3 <= len(reason) <= 2000:
        raise MarkError("Give a reason (3 to 2000 characters).")
    d = queries.finding(snap, key) if snap is not None else None
    if not d:
        raise MarkError("No such finding in the current snapshot.")
    if shown_fp is not None and shown_fp != d["evidence_fp"]:
        raise MarkError(REVIEW_AGAIN)
    run_id = d["finding"]["last_seen_run"]
    seq = queries.run_seq(snap, run_id)
    if seq is None:
        raise MarkError("The finding's last run is not in the snapshot.")
    db.execute("BEGIN IMMEDIATE")
    try:
        t = iso()
        db.execute("UPDATE finding_marks SET withdrawn_at=?, withdrawn_by=? WHERE finding_key=? AND withdrawn_at IS NULL", (t, actor, key))
        db.execute("INSERT INTO finding_marks(finding_key, kind, reason, evidence_fp, run_id, run_seq, created_by, created_at, proposal_id) "
                   "VALUES(?,?,?,?,?,?,?,?,?)", (key, kind, reason, d["evidence_fp"], run_id, seq, actor, t,
                                                 proposal[0] if proposal is not None else None))
        if proposal is not None:
            pid, run_id, via = proposal
            n = db.execute("UPDATE proposals SET status='accepted', decided_by=?, decided_at=? WHERE id=? AND status='pending'",
                           (actor, t, pid)).rowcount
            if n != 1:
                raise MarkError("That proposal was already decided.")
            audit.write(db, actor, "mark-add", target=key, detail=f"{KINDS[kind]} ({via}): {reason}", address=address)
            audit.write(db, actor, "proposal-accept", target=f"proposal {pid}", detail=f"{kind}; analyst run {run_id}", address=address)
        else:
            audit.write(db, actor, "mark-add", target=key, detail=f"{KINDS[kind]}: {reason}", address=address)
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise


def withdraw(db, actor, key, address):
    db.execute("BEGIN IMMEDIATE")
    n = db.execute("UPDATE finding_marks SET withdrawn_at=?, withdrawn_by=? WHERE finding_key=? AND withdrawn_at IS NULL",
                   (iso(), actor, key)).rowcount
    if n:
        audit.write(db, actor, "mark-withdraw", target=key, address=address)
    db.execute("COMMIT")
    if not n:
        raise MarkError("That finding has no mark.")


def history(db, key):
    return labeled([dict(r) for r in db.execute("SELECT * FROM finding_marks WHERE finding_key=? ORDER BY id DESC", (key,))])
