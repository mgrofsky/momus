"""A long name cannot empty the flood summary, the lists are shortened longest
entry first and never emptied while the other list could still give up an entry, and each existing account's entry
names the source keys that failed on it."""
import datetime as dt
import json
import re

from app import db as dbm, jobs
from test_signin_limits import Clock, attempt, clock, q  # noqa: F401  (clock is a fixture)


def flood_detail(settings, clock):
    clock.advance(120)
    jobs.tick(settings, dbm.now())
    rows = q(settings, "SELECT detail FROM audit_log WHERE action='login-flood'")
    assert len(rows) == 1, rows
    return rows[0][0]


def section(detail, name, nxt):
    return detail[detail.index(name + ": ") + len(name) + 2:detail.index(nxt) if nxt else len(detail)]


def entries(text):
    return re.findall(r'"(?:[^"\\]|\\.)*" \d+', text)


def test_one_long_name_outside_the_basic_plane_does_not_empty_the_lists(app, admin, settings, clock):
    """The 31-name flood plus one made-up name of 100 characters outside the basic plane, failed five
    times. The other usernames and the source keys are still listed, and the account's entry names the addresses that
    guessed at it."""
    clock.t = clock.t.replace(second=0, microsecond=0) + dt.timedelta(minutes=1)
    for i in range(31):
        if i % 10 == 0:
            clock.advance(1)
        attempt(settings, f"junk-{i}", "wrong password!!", address=f"198.18.0.{i + 1}")
    for i in range(5):
        attempt(settings, "\U0001F600" * 100, "wrong password!!", address=f"198.18.1.{i + 1}")
    for i in range(6):
        attempt(settings, "admin", f"guess-number-{i}!!", address=f"203.0.113.{i + 1}")
    d = flood_detail(settings, clock)
    print("ADD1 b1b:", d)
    assert len(d) <= 1000
    acc = section(d, "Existing accounts", "Other usernames")
    assert acc.startswith('"admin" 5 (sources ')
    for i in range(1, 6):
        assert f'"203.0.113.{i}" 1' in acc, acc
    others = entries(section(d, "Other usernames", "Source keys"))
    keys = entries(section(d, "Source keys", None))
    assert len(others) >= 5 and len(keys) >= 5, (others, keys)
    assert all(len(e) <= 80 for e in others + keys), others + keys
    long_entry = [e for e in others if "\\ud83d" in e]
    assert long_entry and long_entry[0].endswith(' 5') and '..."' in long_entry[0]    # cut, then quoted: no broken escape
    json.loads(long_entry[0].rsplit(" ", 1)[0])


def test_the_longest_entry_goes_first_not_the_last(app, admin, settings, clock):
    """When the text must be shortened, the longest entry of the two lower lists goes first, not the lowest-ranked."""
    clock.t = clock.t.replace(second=0, microsecond=0) + dt.timedelta(minutes=1)
    n = 0

    def fail(name, times=1):
        nonlocal n
        for _ in range(times):
            n += 1
            attempt(settings, name, "wrong password!!", address=f"198.18.{n // 200}.{n % 200 + 1}")
    longest = "a-" + "l" * 62                               # ranked first (3 failures), the longest entry
    fail(longest, 3)
    middle = [f"m-{i}-" + "m" * 50 for i in range(9)]       # ranked next (1 failure each, sorted before "s-")
    for name in middle:
        fail(name)
    for i in range(20):
        fail(f"s-{i:02d}")
    d = flood_detail(settings, clock)
    assert len(d) <= 1000
    others = section(d, "Other usernames", "Source keys")
    assert json.dumps(longest) not in others, others
    for name in middle:
        assert json.dumps(name) in others, (name, others)
    assert len(entries(section(d, "Source keys", None))) == 10


def test_a_list_is_never_emptied_while_the_other_can_still_give_up_an_entry(app, admin, settings, clock):
    clock.t = clock.t.replace(second=0, microsecond=0) + dt.timedelta(minutes=1)
    for i in range(31):
        attempt(settings, f"z{i:02d}-" + "\U0001F600" * 40, "wrong password!!", address=f"198.18.0.{i + 1}")
    d = flood_detail(settings, clock)
    assert len(d) <= 1000
    assert entries(section(d, "Other usernames", "Source keys")), d
    assert entries(section(d, "Source keys", None)), d
