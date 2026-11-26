"""The analyst's pages and API routes. Same rules as every other route: a session, and for every state-changing
request the anti-forgery token and an allowed Origin (web.py). Every value the model wrote is shown as escaped plain
text (no markdown, no links, no images); the templates never use |safe."""
from typing import Literal

from fastapi import Body, Depends, Form, Path, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, StrictBool
from starlette.exceptions import HTTPException

from .. import marks as marksm
from ..web import Ctx, get_ctx
from . import consent, proposals, runner, views

RUN_ID = Path(..., ge=1, le=10 ** 12)
PROPOSAL_ID = Path(..., ge=1, le=10 ** 12)
LIVE_PATH = "/analyst/live"      # fixed path: polling it never keeps a session alive (web.NO_TOUCH_PATHS)
V1 = "/api/v1"


class ChatIn(BaseModel):
    question: str = Field(min_length=1, max_length=2000)


class ConsentIn(BaseModel):
    confirm: StrictBool = False


class DecisionIn(BaseModel):
    decision: Literal["accept", "reject", "close"]
    # accept: the values GET /api/v1/analyst/proposals/{id} returned as shown_evidence_fp and shown_snapshot_sha256
    evidence_fp: str = Field("", max_length=64)
    snapshot_sha256: str = Field("", max_length=64)


def _start(c, kind, question=None):
    return runner.start(c.settings, c.db, kind, c.user, "request", question=question, address=c.address)


def register(app, render, back, flash_url):
    # ---------------------------------------------------------------- pages
    @app.get("/analyst", response_class=HTMLResponse, include_in_schema=False)
    def analyst_page(request: Request, c: Ctx = Depends(get_ctx)):
        from ..pages import flash
        return render(c, "analyst.html", nav="analyst", d=views.page(c, request.query_params.get("runs_page")), f=flash(request))

    @app.get(LIVE_PATH, response_class=HTMLResponse, include_in_schema=False)
    def analyst_live(c: Ctx = Depends(get_ctx)):
        return render(c, "partials/analyst_live.html", s=views.state(c))

    @app.get("/analyst/runs/{agent_run_id}", response_class=HTMLResponse, include_in_schema=False)
    def analyst_run(agent_run_id: int = RUN_ID, c: Ctx = Depends(get_ctx)):
        d = views.run_detail(c, agent_run_id)
        if not d:
            raise HTTPException(404, "No such analyst run.")
        return render(c, "analyst_run.html", nav="analyst", r=d)

    @app.get("/analyst/proposals/{proposal_id}", response_class=HTMLResponse, include_in_schema=False)
    def analyst_proposal(request: Request, proposal_id: int = PROPOSAL_ID, c: Ctx = Depends(get_ctx)):
        from ..pages import flash
        d = views.proposal_detail(c, proposal_id)
        if not d:
            raise HTTPException(404, "No such proposal.")
        return render(c, "analyst_proposal.html", nav="analyst", d=d, kinds=marksm.KINDS, f=flash(request))

    @app.post("/analyst/brief", include_in_schema=False)
    def analyst_brief(c: Ctx = Depends(get_ctx)):
        try:
            rid = _start(c, "brief")
        except runner.RunRefused as e:
            return back(flash_url("/analyst", err=str(e)))
        return back(flash_url("/analyst", msg=f"Analyst run {rid} started. This page shows its status."))

    @app.post("/analyst/chat", include_in_schema=False)
    def analyst_chat(question: str = Form(""), c: Ctx = Depends(get_ctx)):
        try:
            rid = _start(c, "chat", question)
        except runner.RunRefused as e:
            return back(flash_url("/analyst", err=str(e)))
        return back(flash_url("/analyst", msg=f"Analyst run {rid} started. The answer appears below when it is done."))

    @app.post("/analyst/proposals/{proposal_id}/accept", include_in_schema=False)
    def analyst_accept(proposal_id: int = PROPOSAL_ID, evidence_fp: str = Form(""), snapshot_sha256: str = Form(""),
                       c: Ctx = Depends(get_ctx)):
        here = f"/analyst/proposals/{proposal_id}"
        try:
            what = proposals.accept(c.db, c.snap, c.user, proposal_id, c.address, evidence_fp, snapshot_sha256, views.current_sha(c))
        except proposals.ProposalError as e:
            return back(flash_url(here, err=str(e)))
        return back(flash_url(here, msg="Accepted: the mark was saved (it does not change any score, verdict or status)." if what == "mark"
                              else "Accepted: the note is saved and later analyst runs will see it."))

    @app.post("/analyst/proposals/{proposal_id}/reject", include_in_schema=False)
    def analyst_reject(proposal_id: int = PROPOSAL_ID, c: Ctx = Depends(get_ctx)):
        here = f"/analyst/proposals/{proposal_id}"
        try:
            proposals.reject(c.db, c.user, proposal_id, c.address)
        except proposals.ProposalError as e:
            return back(flash_url(here, err=str(e)))
        return back(flash_url(here, msg="Rejected. Nothing was changed."))

    @app.post("/analyst/proposals/{proposal_id}/close", include_in_schema=False)
    def analyst_close(proposal_id: int = PROPOSAL_ID, c: Ctx = Depends(get_ctx)):
        here = f"/analyst/proposals/{proposal_id}"
        try:
            proposals.close(c.db, c.snap, c.user, proposal_id, c.address)
        except proposals.ProposalError as e:
            return back(flash_url(here, err=str(e)))
        return back(flash_url(here, msg="Closed as out of date. Nothing was changed."))

    @app.post("/settings/analyst/consent", include_in_schema=False)
    def analyst_consent(confirm: str = Form(""), c: Ctx = Depends(get_ctx)):
        if confirm != "yes":
            return back(flash_url("/settings", err="Tick the box to confirm the statement."))
        try:
            consent.confirm(c.db, c.settings, c.user, c.address)
        except ValueError as e:
            return back(flash_url("/settings", err=str(e)))
        return back(flash_url("/settings", msg="Confirmed. The analyst can now be used."))

    # ---------------------------------------------------------------- API
    @app.get(f"{V1}/analyst", summary="Analyst state, the latest brief, pending proposals, recent chats and runs")
    def api_analyst(c: Ctx = Depends(get_ctx)):
        return views.page(c, 1)

    @app.get(f"{V1}/analyst/runs/{{agent_run_id}}", summary="One analyst run with its steps")
    def api_run(agent_run_id: int = RUN_ID, c: Ctx = Depends(get_ctx)):
        d = views.run_detail(c, agent_run_id)
        if not d:
            raise HTTPException(404, "No such analyst run.")
        return d

    @app.get(f"{V1}/analyst/proposals/{{proposal_id}}", summary="One proposal with the finding's stored evidence")
    def api_proposal(proposal_id: int = PROPOSAL_ID, c: Ctx = Depends(get_ctx)):
        d = views.proposal_detail(c, proposal_id)
        if not d:
            raise HTTPException(404, "No such proposal.")
        return d

    @app.post(f"{V1}/analyst/brief", summary="Start a run brief")
    def api_brief(c: Ctx = Depends(get_ctx)):
        try:
            return {"agent_run_id": _start(c, "brief")}
        except runner.RunRefused as e:
            raise HTTPException(409, str(e))

    @app.post(f"{V1}/analyst/chat", summary="Ask the analyst a question")
    def api_chat(body: ChatIn = Body(...), c: Ctx = Depends(get_ctx)):
        try:
            return {"agent_run_id": _start(c, "chat", body.question)}
        except runner.RunRefused as e:
            raise HTTPException(409, str(e))

    @app.post(f"{V1}/analyst/proposals/{{proposal_id}}/decide", summary="Accept or reject one proposal")
    def api_decide(body: DecisionIn = Body(...), proposal_id: int = PROPOSAL_ID, c: Ctx = Depends(get_ctx)):
        try:
            if body.decision == "accept":
                return {"outcome": proposals.accept(c.db, c.snap, c.user, proposal_id, c.address, body.evidence_fp,
                                                    body.snapshot_sha256, views.current_sha(c))}
            if body.decision == "close":
                proposals.close(c.db, c.snap, c.user, proposal_id, c.address)
                return {"outcome": "closed"}
            proposals.reject(c.db, c.user, proposal_id, c.address)
            return {"outcome": "rejected"}
        except proposals.ProposalError as e:
            raise HTTPException(409, str(e))

    @app.post(f"{V1}/settings/analyst/consent", summary="Confirm what the analyst sends and to whom")
    def api_consent(body: ConsentIn = Body(...), c: Ctx = Depends(get_ctx)):
        if not body.confirm:
            raise HTTPException(400, "Send {\"confirm\": true} to confirm the statement.")
        try:
            consent.confirm(c.db, c.settings, c.user, c.address)
        except ValueError as e:
            raise HTTPException(409, str(e))
        return {"confirmed": True, "statement": consent.statement(c.settings)}
