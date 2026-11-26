"""Proposals, the only thing the analyst can write, and the validator that runs on every final answer.

The validator drops any proposal or brief item that references a finding, host or run that does not exist in the
snapshot the run used, and records each drop (what was dropped and the fixed reason; never the model's text). It
proves existence, not correctness: a person decides every proposal.

A proposal is stored as pending. A person accepts or rejects each one on its own page. Accepting a mark proposal calls
marks.add, the same code path as a manual mark, so marks keep their rules (they never change counts or scores, and go
stale when the finding reopens or its evidence changes); the audit entry names the person and the agent run. Accepting
a note stores it in notes, the only memory later runs see."""
import json
import re

from .. import audit, marks as marksm, published, queries
from ..db import iso

FINDING_KEY_RE = re.compile(r"[0-9a-f]{8,64}")
STRICT = {"finding": FINDING_KEY_RE.fullmatch, "host": published.is_hostname, "run": published.is_id}

ANALYST = "analyst"       # the one fixed actor for audit entries written on the analyst's behalf
MARK_KINDS = ("false_positive", "duplicate", "accepted_risk")
MAX_NOTE = 2000

# Wording that reads like instructions to an AI system. A hint shown on the proposal page, not a control: an attacker
# can phrase instructions that match none of these.
INSTRUCTION_PATTERNS = [re.compile(p, re.I) for p in (
    r"\bignore\b.{0,40}\b(instructions?|prompts?|rules|above|previous|prior)\b",
    r"\bdisregard\b.{0,40}\b(instructions?|prompts?|rules|above|previous|prior)\b",
    r"\b(system|developer)\s+(prompt|message|text|instructions?)\b",
    r"\byou are (an?|the) (ai|assistant|language model|llm|analyst|model)\b",
    r"\b(ai|llm|language model|assistant|analyst|chatbot)\b.{0,60}\b(must|should|shall|will|need to|are to)\b",
    r"\b(as an ai|dear (ai|assistant|model))\b",
    r"\bmark\b.{0,40}\b(false positive|accepted risk|duplicate)\b",
    r"\b(reveal|print|repeat|output|show)\b.{0,40}\b(system|prompt|instructions)\b",
    r"\b(call|use|invoke|run)\s+the\s+tool\b",
    r"\bfuture (runs?|analysts?|models?)\b",
    r"<\|?(im_start|im_end|system|assistant|user)\|?>",
    r"\b(assistant|system|user)\s*:\s",
)]


def reads_like_instructions(*texts):
    for t in texts:
        if isinstance(t, str) and any(p.search(t[:50000]) for p in INSTRUCTION_PATTERNS):
            return True
    return False


def untrusted_reads_like_instructions(untrusted):
    """True when any string in a tool result's untrusted part matches the word list (the run records it
    and every proposal of that run shows the warning). A hint, not a control."""
    stack, seen = [untrusted], 0
    while stack and seen < 20000:
        v = stack.pop()
        seen += 1
        if isinstance(v, str):
            if reads_like_instructions(v):
                return True
        elif isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, (list, tuple)):
            stack.extend(v)
    return False


def finding_texts(d):
    """The stored text of a finding (from the snapshot), as one list, for the instruction hint."""
    if not d:
        return []
    tri = d.get("triage") or {}
    return [d["finding"].get("title"), d.get("description"), d.get("remediation"), d.get("matched"), d.get("verification"),
            d.get("evidence_text"), tri.get("summary"), tri.get("fix"), " ".join(tri.get("exposed") or [])]


# ---------------------------------------------------------------- the validator
class Known:
    """The identifiers in the run's snapshot."""

    def __init__(self, ids):
        self.ids = ids

    def exists(self, ref):
        if not isinstance(ref, dict) or ref.get("kind") not in self.ids or not isinstance(ref.get("id"), str):
            return False
        rx = STRICT[ref["kind"]]
        return bool(rx(ref["id"])) and ref["id"] in self.ids[ref["kind"]]


def validate_final(kind, final, known, max_proposals):
    """(cleaned final, proposals to store, drops). drops: [{"what", "index", "why"}] with fixed reasons only."""
    drops = []
    out = json.loads(json.dumps(final))           # a copy
    if kind == "brief":
        keep = []
        for i, item in enumerate(out.get("top", [])):
            bad = [r for r in item.get("references", []) if not known.exists(r)]
            if bad:
                drops.append({"what": "top item", "index": i, "why": f"references {len(bad)} id(s) not in this run's snapshot"})
            else:
                keep.append(item)
        out["top"] = keep
        keep = []
        for i, item in enumerate(out.get("remediation", [])):
            bad = [r for r in item.get("references", []) if not known.exists(r)]
            if bad:
                drops.append({"what": "remediation group", "index": i, "why": f"references {len(bad)} id(s) not in this run's snapshot"})
            else:
                keep.append(item)
        out["remediation"] = keep
    else:
        refs = out.get("references", [])
        bad = [r for r in refs if not known.exists(r)]
        if bad:
            drops.append({"what": "answer references", "index": None, "why": f"{len(bad)} reference(s) not in this run's snapshot removed"})
        out["references"] = [r for r in refs if known.exists(r)]
    proposals = []
    for i, p in enumerate(out.get("proposals", [])):
        fk = p.get("finding_key") or ""
        if p["kind"] in MARK_KINDS and not fk:
            drops.append({"what": "proposal", "index": i, "why": "a mark proposal names no finding"})
            continue
        if fk and not (FINDING_KEY_RE.fullmatch(fk) and fk in known.ids["finding"]):
            drops.append({"what": "proposal", "index": i, "why": "names a finding not in this run's snapshot"})
            continue
        bad = [r for r in p.get("references", []) if not known.exists(r)]
        if bad:
            drops.append({"what": "proposal", "index": i, "why": f"references {len(bad)} id(s) not in this run's snapshot"})
            continue
        if not (p.get("text") or "").strip():
            drops.append({"what": "proposal", "index": i, "why": "no reason or note text"})
            continue
        if len(proposals) >= max_proposals:
            drops.append({"what": "proposal", "index": i, "why": f"over the cap of {max_proposals} proposals per run"})
            continue
        proposals.append(p)
    out["proposals"] = []           # stored separately; the result keeps only the counts
    return out, proposals, drops


def store(db, run_id, proposals, snap, snap_sha, created_at=None):
    """Insert the run's proposals as pending, each with the finding's current evidence fingerprint and the
    instruction hint computed from its stored text. Called inside the caller's transaction."""
    ids = []
    for p in proposals:
        fk = p.get("finding_key") or None
        fp, warn, frun = None, False, None
        if fk:
            d = queries.finding(snap, fk)
            fp = d["evidence_fp"] if d else None
            frun = d["finding"]["last_seen_run"] if d else None
            warn = reads_like_instructions(*finding_texts(d))
        cur = db.execute("INSERT INTO proposals(agent_run_id, kind, finding_key, reason, references_json, evidence_fp, snapshot_sha256, "
                         "instruction_warning, status, created_at, finding_run_id) VALUES(?,?,?,?,?,?,?,?, 'pending', ?, ?)",
                         (run_id, p["kind"], fk, p["text"].strip()[:MAX_NOTE], json.dumps(p.get("references", [])[:10]), fp, snap_sha,
                          int(warn), created_at or iso(), frun))
        ids.append(cur.lastrowid)
        audit.write(db, ANALYST, "analyst-proposal", target=fk or f"note (run {run_id})",
                    detail=f"proposal {cur.lastrowid}: {p['kind']} from analyst run {run_id}")
    return ids


# ---------------------------------------------------------------- decisions (always a signed-in person)
class ProposalError(Exception):
    pass


OUT_OF_DATE = "This proposal is out of date: it can only be closed. Nothing was saved."
REVIEW_AGAIN = marksm.REVIEW_AGAIN
CLOSED_REASON = "closed as out of date: the analyst's reason was written about evidence that no longer exists"


def out_of_date(snap, p):
    """Why a proposal about a finding can no longer be accepted, or None: the finding is gone, its
    evidence fingerprint differs from the one stored with the proposal, or it reopened after the proposal was made.
    A note that names no finding is never out of date."""
    fk = p.get("finding_key")
    if not fk:
        return None
    d = queries.finding(snap, fk) if snap is not None else None
    if not d:
        return "the finding is not in the current snapshot any more"
    if p.get("evidence_fp") != d["evidence_fp"]:
        return "the finding's evidence changed after this proposal was made"
    frun = p.get("finding_run_id")
    seq = queries.run_seq(snap, frun) if published.is_id(frun) else None
    if seq is None:
        return "the scan run this proposal was made against is not in the current snapshot"
    if fk in queries.reopened_after(snap, [(fk, seq)]):
        return "the finding reopened after this proposal was made"
    return None


def get(db, pid):
    r = db.execute("SELECT * FROM proposals WHERE id=?", (pid,)).fetchone()
    if not r:
        return None
    d = dict(r)
    try:
        d["references"] = json.loads(d.pop("references_json") or "[]")
    except ValueError:
        d["references"] = []
    return d


def pending(db, limit=100):
    return [dict(r) for r in db.execute("SELECT id, agent_run_id, kind, finding_key, instruction_warning, created_at FROM proposals "
                                        "WHERE status='pending' ORDER BY id LIMIT ?", (limit,))]


def recent_decided(db, limit=20):
    return [dict(r) for r in db.execute("SELECT id, agent_run_id, kind, finding_key, status, decided_by, decided_at FROM proposals "
                                        "WHERE status != 'pending' ORDER BY decided_at DESC, id DESC LIMIT ?", (limit,))]


def accept(db, snap, actor, pid, address, shown_fp, shown_sha, current_sha):
    """Accept one pending proposal, bound to what the person was shown: shown_fp and shown_sha are the
    finding's evidence fingerprint and the snapshot SHA-256 the page (or API client) had; the accept is refused when
    either differs from the current values, and an out-of-date proposal cannot be accepted at all. A mark goes through
    marks.add (the manual path, which checks the fingerprint again against the same snapshot it writes from); a note
    goes into notes. The proposal's status changes in the same transaction, and only from pending, so a double click
    accepts once."""
    p = get(db, pid)
    if not p:
        raise ProposalError("No such proposal.")
    if p["status"] != "pending":
        raise ProposalError("That proposal was already decided.")
    if out_of_date(snap, p):
        raise ProposalError(OUT_OF_DATE)
    if not isinstance(shown_sha, str) or not current_sha or shown_sha != current_sha:
        raise ProposalError(REVIEW_AGAIN)
    if p["finding_key"]:
        d = queries.finding(snap, p["finding_key"])
        if not d or shown_fp != d["evidence_fp"]:
            raise ProposalError(REVIEW_AGAIN)
    via = f"accepted from proposal {pid} of analyst run {p['agent_run_id']}"
    if p["kind"] in MARK_KINDS:
        try:
            marksm.add(db, snap, actor, p["finding_key"], p["kind"], p["reason"], address, proposal=(pid, p["agent_run_id"], via),
                       shown_fp=shown_fp)
        except marksm.MarkError as e:
            raise ProposalError(str(e)) from None
        return "mark"
    db.execute("BEGIN IMMEDIATE")
    try:
        n = db.execute("UPDATE proposals SET status='accepted', decided_by=?, decided_at=? WHERE id=? AND status='pending'",
                       (actor, iso(), pid)).rowcount
        if n != 1:
            raise ProposalError("That proposal was already decided.")
        cur = db.execute("INSERT INTO notes(finding_key, body, source, accepted_by, created_at, agent_run_id, proposal_id) "
                         "VALUES(?,?, 'agent', ?,?,?,?)", (p["finding_key"], p["reason"], actor, iso(), p["agent_run_id"], pid))
        audit.write(db, actor, "note-add", target=p["finding_key"] or f"note {cur.lastrowid}", detail=via, address=address)
        audit.write(db, actor, "proposal-accept", target=f"proposal {pid}", detail=f"note; analyst run {p['agent_run_id']}", address=address)
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    return "note"


def reject(db, actor, pid, address):
    db.execute("BEGIN IMMEDIATE")
    try:
        p = db.execute("SELECT agent_run_id, kind, status FROM proposals WHERE id=?", (pid,)).fetchone()
        if not p:
            raise ProposalError("No such proposal.")
        n = db.execute("UPDATE proposals SET status='rejected', decided_by=?, decided_at=? WHERE id=? AND status='pending'",
                       (actor, iso(), pid)).rowcount
        if n != 1:
            raise ProposalError("That proposal was already decided.")
        audit.write(db, actor, "proposal-reject", target=f"proposal {pid}", detail=f"{p['kind']}; analyst run {p['agent_run_id']}",
                    address=address)
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise


def close(db, snap, actor, pid, address):
    """Close an out-of-date proposal: a rejection recorded with a fixed reason. Refused for a proposal that is not out
    of date (it is accepted or rejected instead)."""
    p = get(db, pid)
    if not p:
        raise ProposalError("No such proposal.")
    why = out_of_date(snap, p)
    if not why:
        raise ProposalError("That proposal was already decided." if p["status"] != "pending" else REVIEW_AGAIN)
    db.execute("BEGIN IMMEDIATE")
    try:
        n = db.execute("UPDATE proposals SET status='rejected', decided_by=?, decided_at=?, closed_reason=? WHERE id=? AND status='pending'",
                       (actor, iso(), CLOSED_REASON, pid)).rowcount
        if n != 1:
            raise ProposalError("That proposal was already decided.")
        audit.write(db, actor, "proposal-reject", target=f"proposal {pid}",
                    detail=f"{p['kind']}; analyst run {p['agent_run_id']}; {CLOSED_REASON} ({why})", address=address)
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise


def accepted_notes(db, max_chars):
    """The notes later prompts include: newest first, up to max_chars of note text in all."""
    out, used = [], 0
    for r in db.execute("SELECT id, finding_key, body FROM notes ORDER BY id DESC LIMIT 200"):
        body = r["body"] or ""
        if used + len(body) > max_chars:
            break
        used += len(body)
        out.append(dict(r))
    return out
