"""The brain's copies of scanner constants must equal the scanner's own."""
import os
import sys

import fixtures
from app import scope as brain_scope

sys.path.insert(0, os.path.join(fixtures.REPO, "scanner", "pipeline"))
import scope as scanner_scope  # noqa: E402


def test_constants_match_the_scanner():
    assert brain_scope.OWNERSHIP_RULE == scanner_scope.OWNERSHIP_RULE
    assert brain_scope.OWNERSHIP_STATEMENT == scanner_scope.OWNERSHIP_STATEMENT


def test_name_rule_matches_the_scanner():
    for n in ("example.test", "a.b.example.test", "x_y.example.test", "EXAMPLE.test.", "-a.test", "a..test", "192.0.2.4", "a", "a.b_c",
              "x" * 64 + ".test", "ex ample.test", "xn--bcher-kva.test", "a\n.test", "a.test\n", "a\n.b.test", "a.b\n.test"):
        assert brain_scope.norm_name(n) == scanner_scope.norm_name(n), n
    # a label may not end in a line break ("$" matched before a final newline; both copies now use fullmatch). An outer
    # line break is still removed by strip(), as any outer whitespace is.
    for n in ("a\n.test", "a\n.b.test", "a.b\n.test"):
        assert scanner_scope.norm_name(n) is None and brain_scope.norm_name(n) is None, repr(n)
    assert scanner_scope.norm_name("a.test\n") == "a.test"


# ---------------------------------------------------------------- version watch: the brain's rules equal the scanner's
import copy  # noqa: E402
import datetime as dt  # noqa: E402
import importlib.util  # noqa: E402
import json  # noqa: E402

import pytest  # noqa: E402

import version_watch as scanner_vw  # noqa: E402
from app import published as brain_pub, watches as brain_watches  # noqa: E402

_spec = importlib.util.spec_from_file_location("momus_runner_contract", os.path.join(fixtures.REPO, "scanner", "runner.py"))
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)

GOOD = {"id": "php-cgi", "name": "PHP CGI, 2024", "product": "php", "cves": ["CVE-2099-0003"],
        "floors": {"8.1": 29, "8.2": 20, "8.3": 8}, "hosts": ["www.example.test"]}


def _job(watches):
    return {"schema": "momus-job-v1", "id": "vw-contract", "type": "version-watch", "created_at": "2030-01-01T00:00:00Z",
            "scope": {"domains": ["example.test"], "exclude": [], "owned_ranges": [], "approved_hosts": [], "strict_sla_hosts": [],
                      "ownership": [{"apex": "example.test", "statement": scanner_scope.OWNERSHIP_STATEMENT, "attested_by": "admin",
                                     "attested_at": "2030-01-01T00:00:00Z"}],
                      "approval": None, "check_profile": "safe", "rate_profile": "low", "evidence": "minimal"},
            "options": {"watches": watches}}


def scanner_answer(watches):
    """The scanner's answer through runner.validate_job on a whole job (its _name rule checks the host names)."""
    try:
        return True, runner.validate_job(copy.deepcopy(_job(watches)), "vw-contract", None)["options"]["watches"]
    except runner.Invalid:
        return False, None


def brain_answer(watches):
    try:
        return True, brain_watches.validate_watches(copy.deepcopy(watches))
    except brain_watches.WatchError:
        return False, None


def _with(**kw):
    w = copy.deepcopy(GOOD)
    for k, v in kw.items():
        if v is _DROP:
            w.pop(k, None)
        else:
            w[k] = v
    return w


_DROP = object()
CVES20 = [f"CVE-2099-{1000 + i}" for i in range(20)]
HOSTS100 = [f"h{i}.example.test" for i in range(100)]
SINGLE = [
    # id
    *[_with(id=v) for v in ("a", "ab", "a" * 32, "a" * 33, "-ab", "ab-", "AB", "a_b", "a.b", "a b", "ab\n", "", None, 5, "a-b", "0-9",
                            "https://evil.test/x", ".*", "<script>", "php/../x", "x" * 2)],
    # name
    *[_with(name=v) for v in ("", "x", "x" * 80, "x" * 81, "PHP/(.*)", "<script>alert(1)</script>", "a\n", "a ", " a", "a.", "a,", "a-",
                              "Ab-c_d.e f", "naive café", None, 1, "a" * 79 + ".", "https://evil.test/x", ".*", "a\tb")],
    # product
    *[_with(product=v) for v in ("php", "nginx", "apache-httpd", "PHP", "apache", "", None, 1, ["php"], "php\n", ".*")],
    # CVE ids
    *[_with(cves=v) for v in ([], ["CVE-2099-0003"] * 2, ["CVE-2099-123"], ["CVE-2099-1234567"], ["CVE-2099-12345678"], ["cve-2099-0003"],
                              ["CVE-2099-0003\n"], CVES20, CVES20 + ["CVE-2099-0006"], "CVE-2099-0003", None, [1], [".*"],
                              ["<script>"], ["https://evil.test/x"], ["CVE-24-4577"], [None])],
    # fixed releases
    *[_with(floors=v) for v in ({}, {"8.1": 0}, {"8.1": 99999}, {"8.1": 100000}, {"8.1": -1}, {"8.1": True}, {"8.1": False}, {"8.1": 1.0},
                                {"8.1": "29"}, {"08.1": 1}, {"8.01": 1}, {"0.0": 1}, {"10000.1": 1}, {"9999.9999": 1}, {"8": 1}, {"8.1.2": 1},
                                {"8.1\n": 1}, {".*": 1}, {f"{i}.0": 1 for i in range(1, 17)}, {f"{i}.0": 1 for i in range(1, 18)}, [], None,
                                {"8.1": None}, {"<script>": 1}, {"8.1": [29]})],
    # OpenSSL: floors on 3.x or newer only
    *[_with(product="openssl", floors=v) for v in ({"1.1": 1}, {"3.0": 14}, {"2.9": 1}, {"10.0": 1}, {"0.9": 8}, {"3.0": 14, "1.1": 1})],
    _with(product="nginx", floors={"1.1": 1}), _with(product="apache-httpd", floors={"2.4": 62}),
    # extra host names
    *[_with(hosts=v) for v in ([], HOSTS100, HOSTS100 + ["h100.example.test"], ["a.example.test", "a.example.test"], ["WWW.example.test"],
                               ["www.example.test."], [" www.example.test"], ["https://evil.test/x"], ["*.example.test"], ["192.0.2.1"],
                               ["localhost"], ["a.test\n"], [1], None, "www.example.test", ["x" * 300 + ".test"], ["xn--bcher-kva.test"],
                               ["a_b.example.test"], ["a.b_c"], ["<script>.test"], [".*"], [""], ["a..test"],
                               HOSTS100[:99] + ["h0.example.test", "h0.example.test"])],
    # fields
    *[_with(**{k: _DROP}) for k in ("id", "name", "product", "cves", "floors", "hosts")],
    _with(pattern="PHP/(.*)"), _with(headers=["server"]), _with(url="https://evil.test/x"),
    "not an object", None, [GOOD],
]
LISTS = [
    [], None, "x", {}, [GOOD, GOOD], [GOOD, _with(id="php-cgi-2")],
    [_with(id=f"w{i:02d}") for i in range(20)], [_with(id=f"w{i:02d}") for i in range(21)],
    [GOOD, "not an object"], [{}],
]


@pytest.mark.parametrize("i", range(len(SINGLE)))
def test_one_watch_is_accepted_exactly_when_the_scanner_accepts_it(i):
    w = SINGLE[i]
    s_ok, s_out = scanner_answer([w])
    b_ok, b_out = brain_answer([w])
    assert b_ok == s_ok, (i, repr(w)[:200], s_ok)
    assert b_out == s_out                               # and both normalize it the same way


@pytest.mark.parametrize("i", range(len(LISTS)))
def test_a_watch_list_is_accepted_exactly_when_the_scanner_accepts_it(i):
    s_ok, s_out = scanner_answer(LISTS[i])
    b_ok, b_out = brain_answer(LISTS[i])
    assert b_ok == s_ok, (i, s_ok)
    assert b_out == s_out


def test_the_corpus_has_both_answers():
    answers = [scanner_answer([w])[0] for w in SINGLE]
    assert answers.count(True) >= 20 and answers.count(False) >= 60


def test_watch_constants_match_the_scanner():
    assert brain_watches.PRODUCTS == {k: v["name"] for k, v in scanner_vw.PRODUCTS.items()}
    assert brain_watches.MIN_FLOOR_MAJOR == {k: v["min_floor_major"] for k, v in scanner_vw.PRODUCTS.items() if "min_floor_major" in v}
    for k in ("MAX_WATCHES", "MAX_CVES", "MAX_FLOORS", "MAX_HOSTS", "MAX_PATCH", "WATCH_KEYS", "WATCH_REQUIRED"):
        assert getattr(brain_watches, k) == getattr(scanner_vw, k), k
    for k in ("WATCH_ID_RE", "WATCH_NAME_RE", "CVE_RE", "BRANCH_RE"):
        assert getattr(brain_watches, k).pattern == getattr(scanner_vw, k).pattern, k
    # the reader of published results uses the same patterns and codes as the writer
    assert brain_pub.VW_SCHEMA == scanner_vw.SCHEMA and brain_pub.VW_DIR == scanner_vw.STATE_DIR
    assert brain_pub.VW_WATCH_ID_RE.pattern == scanner_vw.WATCH_ID_RE.pattern
    assert brain_pub.VW_NAME_RE.pattern == scanner_vw.WATCH_NAME_RE.pattern
    assert brain_pub.VW_VERSION_RE.pattern == scanner_vw.VERSION_RE.pattern
    assert brain_pub.VW_BRANCH_RE.pattern == scanner_vw.BRANCH_RE.pattern and brain_pub.VW_CVE_RE.pattern == scanner_vw.CVE_RE.pattern
    assert set(brain_pub.VW_VERDICTS) == set(scanner_vw.VERDICTS) and set(brain_pub.VW_SOURCES) == set(scanner_vw.SOURCES)
    assert brain_pub.VW_PRODUCTS == brain_watches.PRODUCTS
    assert brain_pub.VW_SERVER_CAP >= scanner_vw.SERVER_CAP
    assert scanner_vw.TARGET_DERIVED == ("hosts[].server",)
    assert brain_pub.VW_MAX_DATED <= scanner_vw.KEEP


def test_the_reader_keeps_everything_in_a_result_the_scanner_builds(tmp_path):
    """A document made by the scanner's own build_doc passes the brain's checks with nothing dropped."""
    w = scanner_vw.validate_watches([GOOD])[0]
    hosts = [{"hostname": "www.example.test", "version": "8.1.2", "verdict": "FAIL", "reason": "8.1.2 is below 8.1.29",
              "read_from": "http x-powered-by (after redirect)", "https_status": None, "http_status": 200, "server": "Apache/2.4.62 (Debian)",
              "scan_db_version": "8.1.2", "source": "both"},
             {"hostname": "shop.example.test", "version": "8.3.9", "verdict": "PASS", "reason": "8.3.9 is at or above 8.3.8",
              "read_from": "https server", "https_status": 200, "http_status": 301, "server": "PHP/8.3.9", "scan_db_version": None, "source": "job"},
             {"hostname": "old.example.test", "version": None, "verdict": "UNREACHABLE", "reason": "no HTTP response on https or http (timed out)",
              "read_from": None, "https_status": None, "http_status": None, "server": None, "scan_db_version": None, "source": "carried"}]
    earlier = [{"date": "2030-01-01", "hosts": [{"hostname": "www.example.test", "version": "8.1.1", "verdict": "FAIL"}],
                "headline": {"hosts": 1, "fail": 1, "pass": 0, "unknown": 0, "unreachable": 0}}]
    now = dt.datetime(2030, 1, 2, 4, 0, tzinfo=dt.timezone.utc)
    info = {"total": 3, "from_scan_db": 1, "from_job": 2, "carried": 1, "not_probed": 0, "scan_db_run": "full-2"}
    doc = scanner_vw.build_doc(w, hosts, info, ["example.test"], earlier, now, "vw-20300102-040000-abcdef")
    d = tmp_path / "version-watch" / "php-cgi"
    d.mkdir(parents=True)
    (d / "2030-01-02.json").write_text(json.dumps(doc))
    (d / "latest.json").write_text(json.dumps(doc))
    r = brain_pub.watch_result(str(tmp_path), "php-cgi")
    got = r["result"]
    assert r["folder"] and r["suspect"] is None and r["dates"] == ["2030-01-02"]
    assert got["date"] == "2030-01-02" and got["job_id"] == "vw-20300102-040000-abcdef" and got["generated_at"] == "2030-01-02T04:00:00Z"
    assert got["watch"] == {"id": "php-cgi", "name": "PHP CGI, 2024", "product": "php", "product_name": "PHP"}
    assert got["cves"] == ["CVE-2099-0003"] and got["floors"] == {"8.1": "8.1.29", "8.2": "8.2.20", "8.3": "8.3.8"}
    assert got["headline"] == doc["headline"] and got["targets"] == info and got["history"] == doc["history"]
    assert len(got["hosts"]) == 3 and len(got["by_version"]) == len(doc["by_version"]) and len(got["by_domain"]) == 1
    for mine, theirs in zip(got["hosts"], doc["hosts"]):
        assert mine == {k: theirs[k] for k in scanner_vw.HOST_KEYS}
    assert got["changes"] == doc["changes"] and len(got["changes"]["items"]) == 3
