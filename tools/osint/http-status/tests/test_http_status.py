import ipaddress
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from http_status import _validate_url, check_http_status


def test_validate_url_accepts_public_destination():
    with patch(
        "http_status.socket.getaddrinfo",
        return_value=[
            (
                socket_family,
                1,
                6,
                "",
                ("93.184.216.34", 443),
            )
            for socket_family in (2,)
        ],
    ):
        assert _validate_url("https://example.com/path") == "https://example.com/path"


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com",
        "file:///etc/passwd",
        "http://user:pass@example.com",
        "https:///path",
    ],
)
def test_validate_url_rejects_unsafe_urls(url):
    with pytest.raises(ValueError):
        _validate_url(url)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
    ],
)
def test_validate_url_rejects_non_public_destinations(address):
    with patch(
        "http_status.socket.getaddrinfo",
        return_value=[
            (
                2,
                1,
                6,
                "",
                (address, 80),
            )
        ],
    ):
        with pytest.raises(
            ValueError,
            match="URL must resolve only to public IP addresses",
        ):
            _validate_url("https://example.com")


def test_validate_url_rejects_dns_resolution_failure():
    with patch(
        "http_status.socket.getaddrinfo",
        side_effect=OSError,
    ):
        with pytest.raises(
            ValueError,
            match="URL hostname could not be resolved",
        ):
            _validate_url("https://example.com")


def test_check_http_status_returns_metadata():
    response = MagicMock()
    response.__enter__.return_value = response
    response.status = 200
    response.reason = "OK"
    response.headers.get.side_effect = lambda name, default="": {
        "Content-Type": "text/html",
        "Content-Length": "1234",
    }.get(name, default)

    opener = MagicMock()
    opener.open.return_value = response

    with patch(
        "http_status.socket.getaddrinfo",
        return_value=[
            (
                2,
                1,
                6,
                "",
                ("93.184.216.34", 443),
            )
        ],
    ), patch(
        "http_status.urllib.request.build_opener",
        return_value=opener,
    ):
        result = check_http_status("https://example.com")

    assert result == {
        "url": "https://example.com",
        "status": 200,
        "reason": "OK",
        "content_type": "text/html",
        "content_length": "1234",
    }

    opener.open.assert_called_once()


def test_check_http_status_rejects_invalid_timeout():
    with pytest.raises(
        ValueError,
        match="timeout must be greater than zero",
    ):
        check_http_status("https://example.com", timeout=0)
