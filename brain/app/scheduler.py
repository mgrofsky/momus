"""The scheduler: a thread inside the brain process. It computes the next daily recheck, daily version watch and
monthly full run from the schedule rows (times in UTC), and when a slot is due it queues the job, or skips the slot when a job is still in
flight. A slot is identified by its UTC time, so each slot is acted on at most once, also across restarts.

Monthly runs: day_of_month 1-31; in a month without that day the run happens on the month's last day."""
import calendar
import datetime as dt
import threading

UTC = dt.timezone.utc
DAILY_KINDS = ("daily-recheck", "daily-version-watch")
KINDS = ("daily-recheck", "monthly-full", "daily-version-watch")


def _monthly_slot(year, month, dom, hour, minute):
    day = min(dom, calendar.monthrange(year, month)[1])
    return dt.datetime(year, month, day, hour, minute, tzinfo=UTC)


def next_run(row, now):
    """The first slot strictly after `now` for one schedule row (dict with kind, hour, minute, day_of_month)."""
    h, m = int(row["hour"]), int(row["minute"])
    if row["kind"] in DAILY_KINDS:
        t = now.replace(hour=h, minute=m, second=0, microsecond=0)
        return t if t > now else t + dt.timedelta(days=1)
    dom = int(row.get("day_of_month") or 1)
    y, mo = now.year, now.month
    for _ in range(3):
        t = _monthly_slot(y, mo, dom, h, m)
        if t > now:
            return t
        y, mo = (y + 1, 1) if mo == 12 else (y, mo + 1)
    raise AssertionError("unreachable")


def due_slot(row, now):
    """The most recent slot at or before `now` (the one that may be due), or None."""
    h, m = int(row["hour"]), int(row["minute"])
    if row["kind"] in DAILY_KINDS:
        t = now.replace(hour=h, minute=m, second=0, microsecond=0)
        return t if t <= now else t - dt.timedelta(days=1)
    dom = int(row.get("day_of_month") or 1)
    y, mo = now.year, now.month
    for _ in range(3):
        t = _monthly_slot(y, mo, dom, h, m)
        if t <= now:
            return t
        y, mo = (y - 1, 12) if mo == 1 else (y, mo - 1)
    raise AssertionError("unreachable")


def slot_key(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def decide(row, now, busy, grace=dt.timedelta(hours=1)):
    """What to do for one schedule row at `now`: None (nothing due), ('run', slot) or ('skip', slot, reason).
    A slot is acted on once (row['last_slot']); a slot older than `grace` (the brain was down) is skipped, not
    run late, so a restart never starts a burst of old runs."""
    if not row.get("enabled"):
        return None
    t = due_slot(row, now)
    key = slot_key(t)
    if row.get("last_slot") and row["last_slot"] >= key:
        return None
    if now - t > grace:
        return ("skip", key, "missed while the brain was not running")
    if busy:
        return ("skip", key, f"a job was still in flight ({busy})")
    return ("run", key)


class Scheduler(threading.Thread):
    """Calls tick() once a minute. tick is given by the app (it needs the database and the job writer)."""

    def __init__(self, tick, interval=30):
        super().__init__(name="momus-scheduler", daemon=True)
        self.tick, self.interval = tick, interval
        self.stopped = threading.Event()

    def run(self):
        while not self.stopped.is_set():
            try:
                self.tick(dt.datetime.now(UTC))
            except Exception as e:   # never let one bad tick stop the scheduler
                print(f"scheduler: tick failed: {type(e).__name__}", flush=True)
            self.stopped.wait(self.interval)

    def stop(self):
        self.stopped.set()
