import socket
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from whois_info import WHOIS_PORT, WHOIS_SERVER, _validate_domain, query_whois


def test_validate_domain_normalizes_domain():
    assert _validate_domain(" Example.COM. ") == "example.com"


@pytest.mark.parametrize(
    "domain",
    [
        "",
        "example",
        "example..com",
        "example .com",
        "-example.com",
        "example-.com",
        "example.com/",
    ],
)
def test_validate_domain_rejects_invalid_domains(domain):
    with pytest.raises(ValueError):
        _validate_domain(domain)


def test_query_whois_uses_fixed_server():
    response = MagicMock()
    response.recv.side_effect = [b"WHOIS DATA\r\n", b""]

    connection = MagicMock()
    connection.__enter__.return_value = response

    with patch(
        "whois_info.socket.create_connection",
        return_value=connection,
    ) as create_connection:
        result = query_whois("Example.COM")

    assert result == "WHOIS DATA\r\n"
    create_connection.assert_called_once_with(
        (WHOIS_SERVER, WHOIS_PORT),
        timeout=5.0,
    )
    response.sendall.assert_called_once_with(b"example.com\r\n")


def test_query_whois_rejects_invalid_timeout():
    with pytest.raises(ValueError, match="timeout must be greater than zero"):
        query_whois("example.com", timeout=0)


def test_query_whois_propagates_connection_error():
    with patch(
        "whois_info.socket.create_connection",
        side_effect=socket.timeout,
    ):
        with pytest.raises(socket.timeout):
            query_whois("example.com")
