"""Test helper: a resolver and a connector for safefetch.Pinned that record every lookup and every address
connected to, and answer with canned HTTP responses over a local socket pair. No real network is used."""
import socket, threading


class FakeNet:
    def __init__(self, answers, responses):
        """answers: list of address lists, one per lookup (the last repeats); responses: raw HTTP responses, one per
        connection (the last repeats)."""
        self.answers, self.responses = list(answers), list(responses)
        self.lookups, self.connects, self.requests = [], [], []

    def resolve(self, host):
        self.lookups.append(host)
        return self.answers[min(len(self.lookups), len(self.answers)) - 1]

    def connect(self, ip, port, timeout):
        self.connects.append((ip, port))
        resp = self.responses[min(len(self.connects), len(self.responses)) - 1]
        a, b = socket.socketpair()

        def serve():
            with b:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = b.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                self.requests.append(data.decode("latin-1"))
                b.sendall(resp.encode())
        threading.Thread(target=serve, daemon=True).start()
        return a


def http(status, headers=None, body=""):
    lines = [f"HTTP/1.1 {status} X"] + [f"{k}: {v}" for k, v in (headers or {}).items()]
    lines.append(f"Content-Length: {len(body.encode())}")
    return "\r\n".join(lines) + "\r\n\r\n" + body
