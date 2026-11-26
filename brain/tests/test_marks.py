import fixtures
from helpers import shown
from app import db as dbm

ENV = fixtures.K["env"]


def mark(b, key, kind="false_positive", reason="checked by hand"):
    r = b.post(f"/findings/{key}/mark", data={"kind": kind, "reason": reason, **shown(b, f"/findings/{key}")})   # the shown evidence
    assert r.status_code == 303 and "err=" not in r.headers["location"], r.headers.get("location")


def test_mark_never_changes_counts_by_band(admin, published):
    before = admin.get("/api/v1/overview").json()["counts"]
    for k in fixtures.K.values():
        if k != fixtures.K["fixed"]:
            mark(admin, k)
    after = admin.get("/api/v1/overview").json()["counts"]
    assert before == after and before["High"] == 1 and before["Medium"] == 2
    f = admin.get(f"/api/v1/findings/{ENV}").json()["finding"]
    assert f["status"] == "open" and f["score"] == 80 and f["verdict"] == "confirmed" and f["band"] == "High"


def test_marked_finding_leaves_default_list_and_filters(admin, published):
    assert ENV in admin.get("/findings").text
    mark(admin, ENV)
    assert ENV not in admin.get("/findings").text                      # default: open and unmarked
    assert ENV in admin.get("/findings?marked=marked").text
    assert ENV not in admin.get("/findings?marked=unmarked&state=open").text
    keys = [r["finding_key"] for r in admin.get("/api/v1/findings?marked=marked").json()["rows"]]
    assert keys == [ENV]


def test_reopened_finding_shows_mark_as_stale(admin, published, settings):
    fixed = fixtures.K["fixed"]
    mark(admin, fixed, "accepted_risk", "accepted for now")
    d = admin.get(f"/api/v1/findings/{fixed}").json()
    assert d["mark"]["stale"] is False
    fixtures.build_published(settings.published_dir, hostile=True, reopen=True)    # a later run reopens it
    d = admin.get(f"/api/v1/findings/{fixed}").json()
    assert d["mark"]["stale"] is True and "reopened" in d["mark"]["stale_why"]
    assert fixed in admin.get("/findings").text                        # listed again
    assert "This mark is stale" in admin.get(f"/findings/{fixed}").text
    rows = admin.get("/api/v1/findings?marked=marked").json()["rows"]
    assert fixed not in [r["finding_key"] for r in rows]


def test_changed_evidence_makes_mark_stale(admin, published, settings):
    mark(admin, ENV)
    fixtures.build_published(settings.published_dir, hostile=True, change_evidence=True)
    d = admin.get(f"/api/v1/findings/{ENV}").json()
    assert d["mark"]["stale"] is True and "evidence changed" in d["mark"]["stale_why"]


def test_same_evidence_in_a_later_run_keeps_mark_current(admin, published, settings):
    """full-3 repeats the finding with a new timestamp only: the fingerprint ignores per-run fields."""
    mark(admin, fixtures.K["git"])
    fixtures.build_published(settings.published_dir, hostile=True, reopen=True)
    d = admin.get(f"/api/v1/findings/{fixtures.K['git']}").json()
    assert d["finding"]["last_seen_run"] == "full-3"
    assert d["mark"]["stale"] is False


def test_mark_records_fingerprint_and_run(admin, published, settings):
    mark(admin, ENV)
    conn = dbm.connect(settings.db_path)
    m = dict(conn.execute("SELECT * FROM finding_marks").fetchone())
    conn.close()
    assert len(m["evidence_fp"]) == 64 and m["run_id"] == "full-2" and m["run_seq"] == 3


def test_mark_needs_reason_and_existing_finding(admin, published):
    r = admin.post(f"/findings/{ENV}/mark", data={"kind": "false_positive", "reason": ""})
    assert "err=" in r.headers["location"]
    r = admin.post("/findings/ffffffffffffffffffff/mark", data={"kind": "false_positive", "reason": "nope nope"})
    assert "err=" in r.headers["location"]
    r = admin.api_post(f"/api/v1/findings/{ENV}/mark", {"kind": "delete_it", "reason": "xxx"})
    assert r.status_code == 422
