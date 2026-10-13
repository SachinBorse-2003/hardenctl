"""
`hardenctl gui`: a local web dashboard over the same pipeline as the CLI.

It runs as root (so it can attribute sockets and apply plans), which makes the
server itself part of the attack surface. So:

  - it listens on 127.0.0.1 only; there is no option to bind elsewhere
  - every request needs a random per-session token: in the URL for the page,
    in a custom header for the API (a cross-site page cannot set that header
    without a CORS preflight, which this server never grants)
  - the Host header must name the loopback address (DNS rebinding), and any
    Origin header must be a loopback http origin; the port is not pinned, so
    an SSH tunnel from any local port works (ssh -L 9000:127.0.0.1:8765)
  - anything that changes state is a JSON POST; apply additionally needs the
    typed confirmation "APPLY" and a plan the server generated itself
  - a strict Content-Security-Policy: no external scripts, styles or frames

Standard library only, so the trusted base does not grow a web framework.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlparse

from . import api

MAX_BODY = 1_000_000

# One request at a time. The eval sandbox works by setting environment
# variables for the whole process, so a scan must never run during an eval.
_LOCK = threading.Lock()

GET_ROUTES = {
    "/api/status": api.status,
    "/api/intent": api.intent_get,
    "/api/runs": api.runs,
    "/api/fingerprint": api.fingerprint,
    "/api/presets": api.presets,
    "/api/results": api.results,
}
POST_ROUTES = {
    "/api/scan": lambda b: api.scan(bool(b.get("explain"))),
    "/api/intent/init": lambda b: api.intent_init(),
    "/api/intent/allow": api.intent_allow,
    "/api/intent/forbid": api.intent_forbid,
    "/api/intent/remove": api.intent_remove,
    "/api/plan": api.plan,
    "/api/apply": api.apply,
    "/api/rollback": api.rollback,
    "/api/validate": api.validate,
    "/api/corpus": lambda b: api.corpus(),
    "/api/eval": api.rerun,
}

CSP = ("default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; "
       "frame-ancestors 'none'")


def _page() -> str:
    return resources.files("hardenctl.gui").joinpath("static/index.html").read_text(encoding="utf-8")


LOOPBACK_NAMES = {"127.0.0.1", "localhost"}


def _loopback_host(value: str) -> bool:
    """
    True for "127.0.0.1" or "localhost", with or without a port.

    The name is what defeats DNS rebinding (a rebinding attack arrives with
    the attacker's domain in Host). The port is deliberately not checked, so
    an SSH tunnel from a different local port (ssh -L 9000:127.0.0.1:8765)
    still works.
    """
    name, _, port = value.rpartition(":") if value.count(":") == 1 else (value, "", "")
    return name in LOOPBACK_NAMES and (port == "" or port.isdigit())


def _loopback_origin(value: str) -> bool:
    scheme, sep, rest = value.partition("://")
    return scheme == "http" and sep == "://" and "/" not in rest and _loopback_host(rest)


def make_handler(token: str, port: int):

    class Handler(BaseHTTPRequestHandler):
        server_version = "hardenctl"
        sys_version = ""

        def log_message(self, fmt, *args):  # never log the token
            path = urlparse(self.path).path
            sys.stderr.write(f"  {self.command} {path} -> {args[1] if len(args) > 1 else ''}\n")

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", CSP)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, data: dict) -> None:
            self._send(code, json.dumps(data, default=str).encode(), "application/json")

        def _origin_ok(self) -> bool:
            if not _loopback_host(self.headers.get("Host", "")):
                return False
            origin = self.headers.get("Origin")
            return origin is None or _loopback_origin(origin)

        def _token_ok(self, given: str | None) -> bool:
            return bool(given) and hmac.compare_digest(given, token)

        def do_GET(self):
            url = urlparse(self.path)
            if not self._origin_ok():
                return self._json(403, {"error": "requests must come from this machine's dashboard"})
            if url.path == "/":
                if not self._token_ok(parse_qs(url.query).get("t", [None])[0]):
                    return self._send(403, b"Open the URL printed in the terminal (it carries the "
                                           b"session token).", "text/plain; charset=utf-8")
                page = _page().replace("__HCTL_TOKEN__", token)
                return self._send(200, page.encode(), "text/html; charset=utf-8")
            if url.path in GET_ROUTES:
                if not self._token_ok(self.headers.get("X-HardenCTL-Token")):
                    return self._json(403, {"error": "missing or wrong session token"})
                return self._run(GET_ROUTES[url.path], None)
            return self._json(404, {"error": "not found"})

        def do_POST(self):
            url = urlparse(self.path)
            if not self._origin_ok():
                return self._json(403, {"error": "requests must come from this machine's dashboard"})
            if not self._token_ok(self.headers.get("X-HardenCTL-Token")):
                return self._json(403, {"error": "missing or wrong session token"})
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                return self._json(415, {"error": "JSON only"})
            route = POST_ROUTES.get(url.path)
            if route is None:
                return self._json(404, {"error": "not found"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 <= length <= MAX_BODY:
                return self._json(413, {"error": "request too large"})
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._json(400, {"error": "body is not valid JSON"})
            if not isinstance(body, dict):
                return self._json(400, {"error": "body must be a JSON object"})
            return self._run(route, body)

        def _run(self, fn, body):
            with _LOCK:
                try:
                    data = fn() if body is None else fn(body)
                except api.ApiError as e:
                    return self._json(e.status, {"error": str(e)})
                except Exception as e:  # report, never crash the server
                    return self._json(500, {"error": f"{type(e).__name__}: {e}"[:400]})
            return self._json(200, data)

    return Handler


def make_server(port: int = 8765) -> tuple[ThreadingHTTPServer, str]:
    """Bind to loopback and return (server, session token). port=0 picks a free port."""
    token = secrets.token_urlsafe(24)
    server = ThreadingHTTPServer(("127.0.0.1", port), None)  # handler set once the port is known
    server.RequestHandlerClass = make_handler(token, server.server_address[1])
    server.daemon_threads = True
    return server, token


def serve(port: int = 8765, open_browser: bool = True) -> None:
    server, token = make_server(port)
    url = f"http://127.0.0.1:{server.server_address[1]}/?t={token}"
    print("\n  HardenCTL dashboard\n")
    print(f"  {url}\n")
    print("  Listening on 127.0.0.1 only. The token in the URL is valid until you stop the server.")
    if os.geteuid() != 0:
        print("  Not root: attribution is limited and apply/rollback are disabled. Use sudo for the full tool.")
    print("  Ctrl+C to stop.\n", flush=True)
    if open_browser and os.geteuid() != 0:
        import webbrowser
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped")
    finally:
        server.server_close()
