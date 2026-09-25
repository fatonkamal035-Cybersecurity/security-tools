import ipaddress
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from robots_info import _validate_url, fetch_robots


def test_validate_url_normalizes_to_robots_path():
    with patch(
        "robots_info.socket.getaddrinfo",
        return_value=[
            (
                2,
                1,
                6,
                "",
                ("93.184.216.34", 80),
            )
        ],
    ):
        result = _validate_url("HTTPS://Example.COM/path")

    assert result == "https://Example.COM/robots.txt"


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com",
        "file:///etc/passwd",
        "http://user:pass@example.com",
        "https://example.com?x=1",
        "https://example.com/#fragment",
        "https:///robots.txt",
    ],
)
def test_validate_url_rejects_unsafe_urls(url):
    with pytest.raises(ValueError):
        _validate_url(url)


@pytest.mark.parametrize(
    "address",
    [
        ipaddress.ip_address("127.0.0.1"),
        ipaddress.ip_address("10.0.0.1"),
        ipaddress.ip_address("172.16.0.1"),
        ipaddress.ip_address("192.168.1.1"),
    ],
)
def test_validate_url_rejects_non_public_destinations(address):
    with patch(
        "robots_info.socket.getaddrinfo",
        return_value=[
            (
                2,
                1,
                6,
                "",
                (str(address), 80),
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
        "robots_info.socket.getaddrinfo",
        side_effect=OSError,
    ):
        with pytest.raises(
            ValueError,
            match="URL hostname could not be resolved",
        ):
            _validate_url("https://example.com")


def test_fetch_robots_uses_validated_url_and_no_redirect():
    response = MagicMock()
    response.status = 200
    response.read.return_value = b"User-agent: *\nDisallow: /private\n"

    context = response.__enter__.return_value
    context.status = 200
    context.read.return_value = response.read.return_value

    opener = MagicMock()
    opener.open.return_value.__enter__.return_value = context

    with patch(
        "robots_info.socket.getaddrinfo",
        return_value=[
            (
                2,
                1,
                6,
                "",
                ("93.184.216.34", 80),
            )
        ],
    ), patch(
        "robots_info.urllib.request.build_opener",
        return_value=opener,
    ):
        status, content = fetch_robots("https://example.com")

    assert status == 200
    assert content == "User-agent: *\nDisallow: /private\n"
    opener.open.assert_called_once()


def test_fetch_robots_rejects_invalid_timeout():
    with pytest.raises(
        ValueError,
        match="timeout must be greater than zero",
    ):
        fetch_robots("https://example.com", timeout=0)
