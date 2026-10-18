"""Intentionally vulnerable local server for DAST testing.

Exposes:
  GET /?search=<term>   — reflects <term> directly into HTML (XSS)
  GET /api/user?id=<n>  — leaks user info without auth (BOLA)
  GET /health           — baseline health check (clean endpoint)

Missing security headers intentionally:
  Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy, Strict-Transport-Security.
"""
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

FAKE_USERS = {
    "1": {"id": 1, "name": "Alice Admin", "role": "admin", "email": "alice@kelan.local"},
    "2": {"id": 2, "name": "Bob User",   "role": "user",  "email": "bob@kelan.local"},
}


class DummyTargetApp(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):  # silence default access log noise
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        path = parsed.path

        if path == "/health":
            self._send_json(200, {"status": "ok"})

        elif path == "/api/user":
            # CWE-639 BOLA: returns any user record with no auth check
            uid = params.get("id", [""])[0]
            user = FAKE_USERS.get(uid)
            if user:
                self._send_json(200, user)
            else:
                self._send_json(404, {"error": "user not found"})

        else:
            # CWE-79 Reflected XSS: search term injected unescaped
            search_term = params.get("search", [""])[0]
            self._send_html(200, f"""
<html>
  <head><title>Search System</title></head>
  <body>
    <h1>Search Results</h1>
    <p>You searched for: {search_term}</p>
    <form action="/" method="GET">
      <input type="text" name="search" placeholder="Search...">
      <button type="submit">Go</button>
    </form>
    <a href="/api/user?id=1">View profile</a>
  </body>
</html>""")

    def _send_html(self, code: int, body: str):
        enc = body.encode("utf-8")
        # Intentionally omits all security headers
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(enc)))
        self.end_headers()
        self.wfile.write(enc)

    def _send_json(self, code: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    server = HTTPServer(("localhost", 8080), DummyTargetApp)
    print("🚀  Dummy target running on http://localhost:8080")
    print("    Endpoints:")
    print("      GET /?search=<term>      ← reflected XSS (CWE-79)")
    print("      GET /api/user?id=<n>     ← BOLA, no auth (CWE-639)")
    print("      GET /health              ← clean baseline")
    print("    Ctrl-C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[stopped]")
