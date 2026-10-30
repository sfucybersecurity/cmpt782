"""
proxy.py — OPTIONAL live-capture passthrough in front of the lab backend.

DETECTION ONLY. It records every POST /api/attack body to logs/calls.jsonl and
forwards every request to the real backend UNCHANGED, returning the backend's
status, headers and body UNCHANGED (including errors). It never blocks or
rewrites anything. backend.py is not modified.

Mode 1 — capture your own scripted attacks (simplest):
    python backend.py                         # terminal 1, :8085 as usual
    python bonus/proxy.py                     # terminal 2, listens on :8086
    curl -X POST http://localhost:8086/api/attack -H 'Content-Type: application/json' -d '...'

Mode 2 — capture the Streamlit UI too (app.py talks to :8085, so put the proxy there):
    uvicorn backend:app --port 8095                              # terminal 1 (from repo root)
    PROXY_PORT=8085 MCP_BACKEND=http://localhost:8095 python bonus/proxy.py   # terminal 2
    streamlit run app.py                                         # terminal 3

Then:  python bonus/scan.py --jsonl bonus/logs/calls.jsonl [--follow]

Each log line: {timestamp, student_id, server, tool, parameters, exploited}
`timestamp` is when the request ARRIVED (microseconds), which is what you want
for rate/race detection; `exploited` is copied from the backend's response so
you can compare your input-side alerts with the lab's output-side verdict.

Standard library only.
"""

import json
import os
import threading
import urllib.error
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BACKEND = os.environ.get("MCP_BACKEND", "http://localhost:8085").rstrip("/")
LISTEN_PORT = int(os.environ.get("PROXY_PORT", "8086"))
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
LOG_PATH = os.environ.get("PROXY_LOG", os.path.join(LOG_DIR, "calls.jsonl"))

_HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
               "trailers", "transfer-encoding", "upgrade", "host", "content-length"}
_write_lock = threading.Lock()


def _log_call(arrived, request_body, response_body):
    try:
        req = json.loads(request_body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return
    if not isinstance(req, dict):
        return
    try:
        exploited = json.loads(response_body.decode("utf-8")).get("exploited")
    except (ValueError, UnicodeDecodeError, AttributeError):
        exploited = None
    record = {
        "timestamp": arrived,
        "student_id": req.get("student_id"),
        "server": req.get("mcp_server"),
        "tool": req.get("tool"),
        "parameters": req.get("parameters", {}),
        "exploited": exploited,
    }
    with _write_lock:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _forward(self):
        arrived = datetime.now().isoformat(timespec="microseconds")
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        req = urllib.request.Request(BACKEND + self.path, data=body, method=self.command)
        for name, value in self.headers.items():
            if name.lower() not in _HOP_BY_HOP:
                req.add_header(name, value)
        try:
            resp = urllib.request.urlopen(req, timeout=60)
        except urllib.error.HTTPError as err:
            resp = err                      # 4xx/5xx: relay exactly what the backend said
        except Exception as e:              # backend down: the only response we author
            msg = json.dumps({"success": False, "proxy_error": str(e)}).encode()
            self._reply(502, [("Content-Type", "application/json")], msg)
            return
        with resp:
            data = resp.read()
            self._reply(resp.status if hasattr(resp, "status") else resp.code,
                        [(k, v) for k, v in resp.headers.items() if k.lower() not in _HOP_BY_HOP], data)
        if self.command == "POST" and self.path.split("?")[0] == "/api/attack" and body:
            _log_call(arrived, body, data)  # observe only, after the client has its answer

    def _reply(self, status, headers, data):
        self.send_response_only(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _forward

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("MCP capture proxy  http://localhost:%d  ->  %s" % (LISTEN_PORT, BACKEND))
    print("Logging POST /api/attack to %s  (detection only — nothing is blocked or modified)" % LOG_PATH)
    try:
        ThreadingHTTPServer(("127.0.0.1", LISTEN_PORT), ProxyHandler).serve_forever()
    except KeyboardInterrupt:
        pass
