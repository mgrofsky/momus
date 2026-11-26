#!/usr/bin/env python3
"""Demo target for lab mode: a small standard-library web server with invented weaknesses the scanner detects.

Never expose it outside the lab network. Every value here is invented (see ../canaries.json).

One process on port 80; the Host header picks the site (both names point at this container on the lab network):
  target.demo.test (and any other name)
            /               page whose title and X-Demo-Banner header carry a script tag; Set-Cookie with a canary
                            session id; a signed download link; a version-revealing Server header; an old PHP version
                            in X-Powered-By (for the version watch); no security headers
            /.env           an exposed environment file (canary key, secret, JWT, lowercase password)
            /.git/config    an exposed Git configuration with a password in the remote URL
            /config/        an open directory listing of two configuration files holding canaries
  notice.demo.test
            /               page whose title and X-Demo-Notice header address an AI model with instructions

  python3 -I -B server.py [--canaries FILE] [--port 80] [--access-log]
"""
import argparse
import html
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERVER = "Tidewater-httpd/1.4.2"   # an invented product and version
# The one real product named here, on purpose: the version watch reads versions only in the formats of real products,
# so the demo serves an old PHP version for the example watch (docs/version-watch.md) to fail: 8.2.20 is below 8.2.35.
# Nothing here runs PHP; it is only this header.
POWERED_BY = "PHP/8.2.20"
ACCESS_LOG = False


def load(path):
    with open(path) as fh:
        doc = json.load(fh)
    secrets = {k: "".join(v["parts"]) for k, v in doc["secrets"].items()}
    return doc, secrets


def pages(doc, s):
    signed = ("https://files.demo.test/exports/q3-report.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256"
              f"&X-Amz-Credential={s['aws_key_id']}%2F20300101%2Fus-east-1%2Fs3%2Faws4_request"
              f"&X-Amz-Date=20300101T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature={s['signed_url_signature']}")
    home = (f"<!doctype html><html><head><title>{doc['script']['title']}</title></head><body>"
            "<h1>Demo shop</h1><p>A deliberately weak lab target.</p>"
            f"<p><a href=\"{html.escape(signed)}\">Download the quarterly report</a></p></body></html>")
    notice = (f"<!doctype html><html><head><title>{doc['injection']['title']}</title></head><body>"
              "<h1>Status board</h1><p>Nothing to see here.</p></body></html>")
    env = ("APP_NAME=demo-shop\nAPP_ENV=production\nAPP_DEBUG=true\n"
           "DB_HOST=db.demo.test\nDB_DATABASE=shop\nDB_USERNAME=shop\n"
           f"DB_PASSWORD={s['lowercase_password']}\n"
           f"AWS_ACCESS_KEY_ID={s['aws_key_id']}\nAWS_SECRET_ACCESS_KEY={s['aws_secret']}\n"
           f"JWT_TOKEN={s['jwt']}\n")
    gitcfg = ("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
              "[remote \"origin\"]\n"
              f"\turl = https://deploy:{s['git_password']}@git.demo.test/shop/site.git\n"
              "\tfetch = +refs/heads/*:refs/remotes/origin/*\n")
    app_conf = (f"# demo shop service settings\nservice_name = shop\napi_key = {s['api_key']}\n"
                f"session_signing_token = {s['jwt']}\n"
                f"export_url = https://files.demo.test/x.csv?X-Amz-Signature={s['signed_url_signature']}\n")
    settings = f"[database]\nhost = db.demo.test\nuser = shop\npassword = {s['lowercase_password']}\n"
    listing = ("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n<html>\n <head>\n  <title>Index of /config</title>\n"
               " </head>\n <body>\n<h1>Index of /config</h1>\n<pre><a href=\"?C=N;O=D\">Name</a> <a href=\"?C=M;O=A\">Last modified</a>"
               " <a href=\"?C=S;O=A\">Size</a>\n<hr><a href=\"/\">Parent Directory</a>\n"
               "<a href=\"app.conf\">app.conf</a>          2030-01-01 00:00  210\n"
               "<a href=\"settings.ini\">settings.ini</a>      2030-01-01 00:00   80\n<hr></pre>\n</body></html>\n")
    return {
        "shop": {"/": ("text/html; charset=utf-8", home), "/.env": ("text/plain", env), "/.git/config": ("text/plain", gitcfg),
                 "/config/": ("text/html; charset=utf-8", listing), "/config/app.conf": ("text/plain", app_conf),
                 "/config/settings.ini": ("text/plain", settings)},
        "notice": {"/": ("text/html; charset=utf-8", notice)},
    }


def site_of(host_header):
    host = (host_header or "").split(":", 1)[0].strip().lower()
    return "notice" if host.startswith("notice.") else "shop"


def handler_for(sites, doc, s):
    class H(BaseHTTPRequestHandler):
        server_version = SERVER
        sys_version = ""

        def _send(self, body_wanted):
            site = site_of(self.headers.get("Host"))
            routes = sites[site]
            path = self.path.split("?", 1)[0]
            if path == "/config":
                path = "/config/"
            hit = routes.get(path)
            status = 200 if hit else 404
            ctype, body = hit or ("text/html; charset=utf-8", "<!doctype html><title>404 Not Found</title><h1>Not Found</h1>")
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            if path == "/" and site == "shop":
                self.send_header("X-Powered-By", POWERED_BY)
                self.send_header(doc["script"]["header_name"], doc["script"]["header"])
                self.send_header("Set-Cookie", f"sessionid={s['session_cookie']}; Path=/")
            if path == "/" and site == "notice":
                self.send_header(doc["injection"]["header_name"], doc["injection"]["header"])
            self.end_headers()
            if body_wanted:
                self.wfile.write(data)

        def do_GET(self):
            self._send(True)

        def do_HEAD(self):
            self._send(False)

        def log_message(self, fmt, *args):   # quiet unless --access-log: one line per request, see log_request
            pass

        def log_request(self, code="-", size="-"):
            if ACCESS_LOG:
                headers = getattr(self, "headers", None)      # absent when the request line itself was malformed
                site = site_of(headers.get("Host")) if headers is not None else "-"
                path = getattr(self, "path", "") or ""
                print(f"access {time.strftime('%H:%M:%S')} {self.client_address[0]} {site} {getattr(self, 'command', None) or '-'} "
                      f"{path.split('?', 1)[0][:200]!r} {code}", flush=True)

    return H


class LabServer(ThreadingHTTPServer):
    """A deep listen queue. A scanner opens dozens of connections at once (nuclei -c 75 in the fast profile); with
    socketserver's default backlog of 5 the kernel drops the excess, requests time out waiting for headers, and demo
    findings are missed at random. With 1024 the threads take every connection."""
    request_queue_size = 1024
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser(description="lab-only demo target with invented weaknesses")
    ap.add_argument("--canaries", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "canaries.json"))
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--access-log", action="store_true", help="print one line per request (time, client, site, method, path, status)")
    a = ap.parse_args()
    global ACCESS_LOG
    ACCESS_LOG = a.access_log
    doc, s = load(a.canaries)
    srv = LabServer(("0.0.0.0", a.port), handler_for(pages(doc, s), doc, s))
    print(f"demo target listening on {a.port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
