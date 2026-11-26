import datetime as dt

from app import scheduler as S

U = dt.timezone.utc


def t(*a):
    return dt.datetime(*a, tzinfo=U)


def daily(h=2, m=0, **kw):
    return {"kind": "daily-recheck", "hour": h, "minute": m, "enabled": 1, **kw}


def monthly(dom=1, h=3, m=0, **kw):
    return {"kind": "monthly-full", "hour": h, "minute": m, "day_of_month": dom, "enabled": 1, **kw}


def test_daily_next_run_same_day_next_day_and_year_end():
    assert S.next_run(daily(2), t(2030, 3, 10, 1, 0)) == t(2030, 3, 10, 2, 0)
    assert S.next_run(daily(2), t(2030, 3, 10, 2, 0)) == t(2030, 3, 11, 2, 0)      # strictly after
    assert S.next_run(daily(2), t(2030, 3, 31, 23, 59)) == t(2030, 4, 1, 2, 0)     # month boundary
    assert S.next_run(daily(0, 5), t(2030, 12, 31, 23, 0)) == t(2031, 1, 1, 0, 5)  # year boundary
    assert S.next_run(daily(2), t(2032, 2, 28, 5, 0)) == t(2032, 2, 29, 2, 0)      # leap day


def test_monthly_next_run_and_short_months():
    assert S.next_run(monthly(1), t(2030, 1, 15)) == t(2030, 2, 1, 3, 0)
    assert S.next_run(monthly(31), t(2030, 1, 31, 4)) == t(2030, 2, 28, 3, 0)      # February has no 31st
    assert S.next_run(monthly(31), t(2032, 2, 1)) == t(2032, 2, 29, 3, 0)          # leap year
    assert S.next_run(monthly(30), t(2030, 4, 30, 3, 0)) == t(2030, 5, 30, 3, 0)
    assert S.next_run(monthly(15), t(2030, 12, 20)) == t(2031, 1, 15, 3, 0)        # year boundary
    assert S.next_run(monthly(1), t(2030, 12, 1, 2, 59)) == t(2030, 12, 1, 3, 0)


def test_due_slot_across_boundaries():
    assert S.due_slot(daily(2), t(2031, 1, 1, 1, 0)) == t(2030, 12, 31, 2, 0)
    assert S.due_slot(monthly(31), t(2030, 3, 1, 0, 0)) == t(2030, 2, 28, 3, 0)
    assert S.due_slot(monthly(5), t(2031, 1, 2)) == t(2030, 12, 5, 3, 0)


def test_decide_runs_once_per_slot():
    now = t(2030, 3, 10, 2, 1)
    d = S.decide(daily(2), now, busy=None)
    assert d == ("run", "2030-03-10T02:00:00Z")
    assert S.decide(daily(2, last_slot="2030-03-10T02:00:00Z"), now, busy=None) is None
    assert S.decide(daily(2, enabled=0), now, busy=None) is None


def test_slot_is_skipped_while_a_job_runs():
    d = S.decide(daily(2), t(2030, 3, 10, 2, 1), busy="full-x")
    assert d[0] == "skip" and d[1] == "2030-03-10T02:00:00Z" and "full-x" in d[2]


def test_missed_slot_is_skipped_not_run_late():
    d = S.decide(daily(2), t(2030, 3, 10, 9, 0), busy=None)
    assert d[0] == "skip" and "not running" in d[2]


def test_schedule_page_shows_utc_and_next_run(admin):
    r = admin.post("/schedules", data={"kind": "monthly-full", "enabled": "on", "hour": "4", "minute": "30", "day_of_month": "31"})
    assert r.status_code == 303 and "err=" not in r.headers["location"]
    d = admin.get("/api/v1/schedules").json()
    row = [x for x in d["rows"] if x["kind"] == "monthly-full"][0]
    assert row["enabled"] == 1 and row["next_run"].endswith("T04:30:00Z")
    assert "UTC" in admin.get("/schedules").text
