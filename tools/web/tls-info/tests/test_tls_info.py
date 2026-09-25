import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tls_info import _parse_certificate_time, _validate_host, get_tls_info


def test_validate_host_normalizes_hostname():
    assert _validate_host("  example.com  ") == "example.com"


@pytest.mark.parametrize(
    "host",
    [
        "",
        "example com",
        "a" * 254,
    ],
)
def test_validate_host_rejects_invalid_hosts(host):
    with pytest.raises(ValueError):
        _validate_host(host)


@pytest.mark.parametrize(
    "port",
    [0, 65536],
)
def test_get_tls_info_rejects_invalid_ports(port):
    with pytest.raises(
        ValueError,
        match="port must be between 1 and 65535",
    ):
        get_tls_info("example.com", port=port)


def test_get_tls_info_rejects_invalid_timeout():
    with pytest.raises(
        ValueError,
        match="timeout must be greater than zero",
    ):
        get_tls_info("example.com", timeout=0)


def test_parse_certificate_time_returns_utc_iso8601():
    result = _parse_certificate_time(
        "Jan 02 03:04:05 2026 GMT"
    )

    assert result == "2026-01-02T03:04:05+00:00"


def test_get_tls_info_returns_certificate_metadata():
    certificate = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("commonName", "Example CA"),),),
        "serialNumber": "123456",
        "notBefore": "Jan 02 03:04:05 2026 GMT",
        "notAfter": "Jan 02 03:04:05 2027 GMT",
    }

    tls_socket = MagicMock()
    tls_socket.getpeercert.return_value = certificate
    tls_socket.version.return_value = "TLSv1.3"
    tls_socket.cipher.return_value = (
        "TLS_AES_256_GCM_SHA384",
        "TLSv1.3",
        256,
    )

    tls_context = MagicMock()
    tls_context.wrap_socket.return_value.__enter__.return_value = tls_socket

    raw_socket = MagicMock()
    raw_socket.__enter__.return_value = raw_socket

    with patch(
        "tls_info.socket.create_connection",
        return_value=raw_socket,
    ) as create_connection, patch(
        "tls_info.ssl.create_default_context",
        return_value=tls_context,
    ):
        result = get_tls_info("example.com")

    assert result == {
        "host": "example.com",
        "port": 443,
        "tls_version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "subject": certificate["subject"],
        "issuer": certificate["issuer"],
        "serial_number": "123456",
        "not_before": "2026-01-02T03:04:05+00:00",
        "not_after": "2027-01-02T03:04:05+00:00",
    }

    create_connection.assert_called_once_with(
        ("example.com", 443),
        timeout=5.0,
    )
    tls_context.wrap_socket.assert_called_once_with(
        raw_socket,
        server_hostname="example.com",
    )
