import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from security_headers import check_security_headers


def test_check_security_headers_detects_present_and_missing_headers():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "X-Frame-Options": "DENY",
    }

    results = check_security_headers(headers)

    by_name = {result["header"]: result for result in results}

    assert by_name["Content-Security-Policy"]["present"] is True
    assert by_name["Content-Security-Policy"]["value"] == "default-src 'self'"

    assert by_name["X-Content-Type-Options"]["present"] is True
    assert by_name["X-Content-Type-Options"]["value"] == "nosniff"

    assert by_name["X-Frame-Options"]["present"] is True
    assert by_name["X-Frame-Options"]["value"] == "DENY"

    assert by_name["Strict-Transport-Security"]["present"] is False
    assert by_name["Referrer-Policy"]["present"] is False
    assert by_name["Permissions-Policy"]["present"] is False


from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread


class LocalHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("X-Test-Header", "test-value")
        self.end_headers()

    def log_message(self, format, *args):
        pass


def test_fetch_headers_uses_local_http_server():
    from security_headers import fetch_headers

    server = HTTPServer(("127.0.0.1", 0), LocalHTTPHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        port = server.server_address[1]
        status, headers = fetch_headers(f"http://127.0.0.1:{port}/")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert status == 200
    assert headers["X-Test-Header"] == "test-value"
