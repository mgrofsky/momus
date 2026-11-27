"""Local-browser bridge for the lab brain. Every request goes to one fixed upstream.

The browser-facing Compose port is bound to host loopback. The brain remains on
its own internal network, and this process mounts no data or credentials.
"""
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re


HOST = re.compile(r"(?:127\.0\.0\.1|localhost):([0-9]{1,5})\Z", re.I)
HOP_HEADERS = {"connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization",
               "te", "trailer", "transfer-encoding", "upgrade"}
MAX_BODY = 8 * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    # HTTP/1.0 closes each response, so an upstream response without Content-Length
    # can be streamed without inventing a chunked body.
    def log_message(self, _format, *_args):
        pass  # URL paths may contain tokens; leave access logging to the brain.

    def forward(self):
        hosts = self.headers.get_all("Host") or []
        host = hosts[0].strip() if len(hosts) == 1 else ""
        match = HOST.fullmatch(host)
        if not match or not 1 <= int(match.group(1)) <= 65535:
            self.send_error(400, "Only a local browser host is accepted")
            return
        if not self.path.startswith("/") or self.path.startswith("//"):
            self.send_error(400, "Only origin-form paths are accepted")
            return
        if "transfer-encoding" in self.headers:
            self.send_error(411, "A Content-Length is required")
            return
        lengths = self.headers.get_all("Content-Length") or []
        if len(lengths) > 1:
            self.send_error(400, "Duplicate Content-Length")
            return
        length = lengths[0] if lengths else None
        if length is not None and (not length.isascii() or not length.isdigit() or int(length) > MAX_BODY):
            self.send_error(413, "Invalid or oversized request body")
            return
        if self.command in ("POST", "PUT", "PATCH") and length is None:
            self.send_error(411, "A Content-Length is required")
            return

        body = self.rfile.read(int(length)) if length else None
        connection_headers = {part.strip().lower() for part in (self.headers.get("Connection") or "").split(",")}
        headers = {key: value for key, value in self.headers.items()
                   if key.lower() not in HOP_HEADERS | connection_headers and not key.lower().startswith("x-forwarded-")
                   and key.lower() != "forwarded"}
        headers["Connection"] = "close"
        upstream = HTTPConnection("brain", 8080, timeout=60)
        sent_headers = False
        try:
            upstream.request(self.command, self.path, body=body, headers=headers)
            response = upstream.getresponse()
            self.send_response_only(response.status, response.reason)
            response_connection_headers = {part.strip().lower() for part in (response.getheader("Connection") or "").split(",")}
            chunked = response.getheader("Transfer-Encoding") is not None
            for key, value in response.getheaders():
                if key.lower() not in HOP_HEADERS | response_connection_headers and not (chunked and key.lower() == "content-length"):
                    self.send_header(key, value)
            self.send_header("Connection", "close")
            self.end_headers()
            sent_headers = True
            if self.command != "HEAD":
                while chunk := response.read(65536):
                    self.wfile.write(chunk)
        except (OSError, TimeoutError):
            # A dropped browser connection needs no response. A failed upstream
            # connection is reported with a generic status, without an endpoint.
            if not sent_headers and not self.wfile.closed:
                try:
                    self.send_error(502, "Lab brain unavailable")
                except OSError:
                    pass
        finally:
            upstream.close()

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = forward


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
