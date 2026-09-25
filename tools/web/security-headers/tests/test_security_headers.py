import sys
from pathlib import Path

import pytest

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


def test_fetch_headers_uses_validated_public_url(monkeypatch):
    from security_headers import fetch_headers

    class FakeResponse:
        status = 200
        headers = {"X-Test-Header": "test-value"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class FakeOpener:
        def open(self, request, timeout):
            assert request.full_url == "https://example.com/"
            assert timeout == 10.0
            return FakeResponse()

    monkeypatch.setattr(
        "security_headers.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("93.184.216.34", 443))
        ],
    )

    monkeypatch.setattr(
        "security_headers.urllib.request.build_opener",
        lambda *args: FakeOpener(),
    )

    status, headers = fetch_headers("https://example.com/")

    assert status == 200
    assert headers["X-Test-Header"] == "test-value"


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/",
        "http://localhost/",
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/",
    ],
)
def test_fetch_headers_rejects_ssrf_targets(url):
    from security_headers import fetch_headers

    with pytest.raises(ValueError):
        fetch_headers(url)


def test_validate_url_rejects_hostname_with_private_dns_result(monkeypatch):
    from security_headers import _validate_url

    monkeypatch.setattr(
        "security_headers.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("192.168.1.10", 443)),
        ],
    )

    with pytest.raises(ValueError):
        _validate_url("https://example.com/")


def test_validate_url_accepts_hostname_with_only_public_dns_results(monkeypatch):
    from security_headers import _validate_url

    monkeypatch.setattr(
        "security_headers.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("93.184.216.35", 443)),
        ],
    )

    _validate_url("https://example.com/")
