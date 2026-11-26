"""enrich.py: the endoflife.date request refuses redirects (a local http.server on loopback stands in for the API)."""
import io, os, sys, tempfile, threading, unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import enrich  # noqa: E402

BODY = b'[{"cycle": "1.0", "eol": false}]'


class _Handler(BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        _Handler.hits.append(self.path)
        if self.path == "/api/moved.json":
            self.send_response(302)
            self.send_header("Location", "/elsewhere/moved.json")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *a):
        pass


class EolLookup(unittest.TestCase):
    def setUp(self):
        _Handler.hits = []
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        url = f"http://127.0.0.1:{self.srv.server_port}/api/{{slug}}.json"
        self.old = enrich.EOL_URL
        enrich.EOL_URL = url
        self.addCleanup(setattr, enrich, "EOL_URL", self.old)
        self.addCleanup(setattr, enrich, "cymru", enrich.cymru)
        enrich.cymru = lambda ips: {}

    def run_enrich(self, slugs):
        products = os.path.join(self.tmp.name, "products.txt")
        with open(products, "w") as f:
            f.write("\n".join(slugs) + "\n")
        open(os.path.join(self.tmp.name, "assets.jsonl"), "w").close()   # no live hosts: no ASN lookup
        argv, sys.argv = sys.argv, ["enrich.py", self.tmp.name, products]
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                enrich.main()
        finally:
            sys.argv = argv
        return out.getvalue()

    def test_redirect_is_refused_and_not_followed(self):
        out = self.run_enrich(["moved", "nginx"])
        eol = os.path.join(self.tmp.name, "eol")
        self.assertFalse(os.path.exists(os.path.join(eol, "moved.json")))
        self.assertEqual(open(os.path.join(eol, "nginx.json"), "rb").read(), BODY)
        self.assertNotIn("/elsewhere/moved.json", _Handler.hits)
        self.assertIn("eol: 1/2 products", out)


if __name__ == "__main__":
    unittest.main()
