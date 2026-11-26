"""The whole PowerDNS request (status line, headers, chunk-size lines,
body) is under one deadline and each network source has one overall deadline; one zone cannot take a source's whole
share; names are not repaired after decoding; the size limits are lower. Run only by seeder/tests/run_tests.sh. The
slow-server tests use a server on the loopback address inside the --network none container, reached through the
suite guard's own connect, as the check did."""
import http.client
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import seed_dns as sd  # noqa: E402
import seed_test_guard as guard  # noqa: E402
from test_seed_dns import APEXES, FakeSocket, cfg, message, rd, rr, scope_status, soa, wr  # noqa: E402


class LoopConn(http.client.HTTPConnection):
    """A connection to 127.0.0.1 inside the no-network container (the suite guard blocks every other connect)."""

    def connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        guard._real_connect(s, ("127.0.0.1", self.port))
        self.sock = s


def loop_opener():
    """The seeder's own opener, connecting to loopback. (If pdns_opener takes no argument, the
    test's own loopback handler is used, so such code fails these tests on time, not on a name.)"""
    try:
        return sd.pdns_opener(http_connection=LoopConn)
    except TypeError:
        import urllib.request

        class LoopHandler(urllib.request.HTTPHandler):
            def http_open(self, req):
                return self.do_open(LoopConn, req)
        return urllib.request.build_opener(urllib.request.ProxyHandler({}), sd._NoRedirect(), LoopHandler())


def drip_server(fast: bytes, slow: bytes, after: bytes, gap: float):
    """One connection on loopback: read the request, send fast at once, slow one byte per gap, then after."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        try:
            c, _ = srv.accept()
            c.settimeout(10)
            try:
                c.recv(65536)
                if fast:
                    c.sendall(fast)
                for i in range(len(slow)):
                    c.sendall(slow[i:i + 1])
                    time.sleep(gap)
                if after:
                    c.sendall(after)
            except OSError:
                pass
            finally:
                c.close()
        finally:
            srv.close()
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    return port, th


BODY = json.dumps({"rrsets": [{"name": "www.example.test.", "type": "A", "records": []}]}).encode()
HEAD = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(BODY)).encode() + b"\r\n"
CHUNKED = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"


class PdnsWholeRequest(unittest.TestCase):
    def run_case(self, fast, slow, after, gap=0.25):
        port, th = drip_server(fast, slow, after, gap)
        with tempfile.TemporaryDirectory() as t:
            key = os.path.join(t, "k")
            wr(key, "abc\n")
            c = cfg(SEED_PDNS_URL=f"http://127.0.0.1:{port}", SEED_PDNS_ZONES="example.test", SEED_PDNS_API_KEY_FILE=key)
            col = sd.Collector(APEXES)
            with unittest.mock.patch.object(sd, "PDNS_DEADLINE_S", 2), unittest.mock.patch.object(sd, "PDNS_TIMEOUT_S", 1):
                t0 = time.monotonic()
                sd.collect_pdns(col, c, opener=loop_opener())
                took = time.monotonic() - t0
        th.join(5)
        return col, took

    def test_a_fast_answer_still_works_through_the_tracked_connection(self):
        col, took = self.run_case(HEAD + b"\r\n" + BODY, b"", b"")
        self.assertEqual((sorted(col.hosts), col.errors["pdns"]), (["www.example.test"], []))

    def test_a_slow_header_ends_at_the_deadline(self):
        col, took = self.run_case(b"", HEAD + b"\r\n", BODY)
        self.assertEqual(col.errors["pdns"], ["pdns-timeout"])
        self.assertLess(took, 4)
        self.assertEqual(col.hosts, {})

    def test_a_slow_chunk_size_line_ends_at_the_deadline(self):
        col, took = self.run_case(CHUNKED, b"5;" + b"x" * 58, b"")
        self.assertEqual(col.errors["pdns"], ["pdns-timeout"])
        self.assertLess(took, 4)


class SourceDeadlines(unittest.TestCase):
    def test_the_pdns_source_has_one_overall_deadline(self):
        with tempfile.TemporaryDirectory() as t:
            key = os.path.join(t, "k")
            wr(key, "abc\n")
            opened = []
            op = type("Op", (), {"open": lambda self, req, timeout=None: opened.append(req) or self.fail()})()
            col = sd.Collector(APEXES)
            with unittest.mock.patch.object(sd, "PDNS_SOURCE_DEADLINE_S", -1, create=True):
                sd.collect_pdns(col, cfg(SEED_PDNS_URL="http://192.0.2.80", SEED_PDNS_ZONES="example.test example-two.test",
                                         SEED_PDNS_API_KEY_FILE=key), opener=op)
        self.assertEqual((opened, col.errors["pdns"], sorted(col.failed)), ([], ["pdns-source-deadline"], ["pdns"]))

    def test_the_transfer_source_has_one_overall_deadline(self):
        class Drip(FakeSocket):
            def recv(self, n):
                time.sleep(0.05)
                return super().recv(1)

        def build(qid):
            return [message(qid, [rr("example.test", 6, soa())] + [rr(f"h{i}.example.test", 1) for i in range(200)]
                            + [rr("example.test", 6, soa())])]
        col = sd.Collector(APEXES)
        t0 = time.monotonic()
        with unittest.mock.patch.object(sd, "AXFR_SOURCE_DEADLINE_S", 1, create=True), \
                unittest.mock.patch.object(sd, "AXFR_DEADLINE_S", 2):      # each transfer alone would take 2 s
            sd.collect_axfr(col, cfg(SEED_AXFR="example.test@192.0.2.53 example-two.test@192.0.2.54"),
                            connect=lambda a: Drip(build))
        self.assertLess(time.monotonic() - t0, 3)
        self.assertIn("axfr-source-deadline", col.errors["axfr"])
        self.assertEqual(col.hosts, {})


class ShareBetweenZones(unittest.TestCase):
    def server(self, names):
        return FakeSocket(lambda qid: [message(qid, [rr(names[0], 6, soa())] + [rr(n, 1) for n in names[1:]]
                                               + [rr(names[0], 6, soa())])])

    def test_one_zone_cannot_take_the_whole_share(self):
        """Share 10, zone 1 sends 41 names, zone 2 sends 3."""
        socks = {"192.0.2.53": self.server(["example.test"] + [f"flood-{i}.example.test" for i in range(40)]),
                 "192.0.2.54": self.server(["example-two.test", "www.example-two.test", "mail.example-two.test"])}
        col = sd.Collector(APEXES, share=10)
        sd.collect_axfr(col, cfg(SEED_AXFR="example.test@192.0.2.53 example-two.test@192.0.2.54"), connect=lambda a: socks[a[0]])
        two = sorted(h for h in col.hosts if h.endswith("example-two.test"))
        self.assertEqual(two, ["example-two.test", "mail.example-two.test", "www.example-two.test"])
        self.assertEqual(len([h for h in col.hosts if h.endswith(".example.test") or h == "example.test"]), 5)
        self.assertEqual((col.errors["axfr"], sorted(col.failed)), (["too-many-names"], ["axfr"]))

    def test_through_run_once_the_source_is_listed_as_failed(self):
        with tempfile.TemporaryDirectory() as t:
            scope_status(os.path.join(t, "s"), {"example.test": "verified", "example-two.test": "verified"})
            os.makedirs(os.path.join(t, "o"))
            socks = {"192.0.2.53": self.server(["example.test"] + [f"f{i}.example.test" for i in range(30)]),
                     "192.0.2.54": self.server(["example-two.test", "www.example-two.test"])}
            with unittest.mock.patch.object(sd, "MAX_NAMES", 20), contextlib_quiet():
                st = sd.run_once(cfg(SEED_AXFR="example.test@192.0.2.53 example-two.test@192.0.2.54"), os.path.join(t, "s"),
                                 os.path.join(t, "o"), os.path.join(t, "z"), clients={"axfr": lambda a: socks[a[0]]})
            out = rd(os.path.join(t, "o", "seed_hosts.txt")).split()
        self.assertIn("www.example-two.test", out)
        self.assertEqual(st["failed_sources"], ["axfr"])
        self.assertIn("too-many-names", st["sources"]["axfr"]["errors"])


def contextlib_quiet():
    import contextlib
    import io
    return contextlib.redirect_stderr(io.StringIO())


class NoRepair(unittest.TestCase):
    def test_wire_labels_are_bytes_not_escapes_and_are_not_trimmed(self):
        col = sd.Collector(APEXES)
        sock = FakeSocket(lambda qid: [message(qid, [rr("example.test", 6, soa())] + [rr(n, 1) for n in (
            " lead.example.test", "tail.example.test\n", "a b.example.test", "\\032esc.example.test", "x\\097.example.test",
            "a\\056b.example.test", "ok.example.test")] + [rr("example.test", 6, soa())])])
        sd.collect_axfr(col, cfg(SEED_AXFR="example.test@192.0.2.53"), connect=lambda a: sock)
        self.assertEqual(sorted(col.hosts), ["example.test", "ok.example.test"])

    def test_a_decoded_name_is_not_trimmed_or_folded(self):
        col = sd.Collector(APEXES)
        for name in ("\\032www.example.test", "www.example.test\\010", "www.example.test\\032\\032", " www.example.test",
                     "www.example.test ", "Kali.example.test", "www.example.test..", "İx.example.test"):
            self.assertIsNone(col.accept(name), ascii(name))
        self.assertEqual(col.accept("Www.Example.TEST."), "www.example.test")       # ASCII letters are still lower-cased
        self.assertEqual(sd.decode_dns_name("\\087ww.example.test"), "www.example.test")


class Limits(unittest.TestCase):
    def test_the_size_limits_are_lower(self):
        self.assertEqual((sd.MAX_PDNS_BYTES, sd.MAX_ZONE_FILE_BYTES), (8 << 20, 16 << 20))


if __name__ == "__main__":
    unittest.main()
