import socket
import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from dns_info import resolve_hostname


def test_resolve_hostname_returns_unique_ipv4_and_ipv6(monkeypatch):
    monkeypatch.setattr(
        "dns_info.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, 0, 0, "", ("192.0.2.10", 0)),
            (socket.AF_INET, 0, 0, "", ("192.0.2.10", 0)),
            (socket.AF_INET6, 0, 0, "", ("2001:db8::10", 0, 0, 0)),
        ],
    )

    assert resolve_hostname("example.test") == [
        {"version": "IPv4", "address": "192.0.2.10"},
        {"version": "IPv6", "address": "2001:db8::10"},
    ]


@pytest.mark.parametrize("hostname", ["", "   "])
def test_resolve_hostname_rejects_empty_hostname(hostname):
    with pytest.raises(ValueError, match="must not be empty"):
        resolve_hostname(hostname)


@pytest.mark.parametrize(
    "hostname",
    [
        "127.0.0.1",
        "::1",
        "192.168.1.1",
    ],
)
def test_resolve_hostname_rejects_ip_address(hostname):
    with pytest.raises(ValueError, match="must be a hostname"):
        resolve_hostname(hostname)


def test_resolve_hostname_rejects_resolution_error(monkeypatch):
    def raise_gaierror(*args, **kwargs):
        raise socket.gaierror

    monkeypatch.setattr(
        "dns_info.socket.getaddrinfo",
        raise_gaierror,
    )

    with pytest.raises(ValueError, match="could not be resolved"):
        resolve_hostname("does-not-exist.test")


def test_resolve_hostname_rejects_empty_resolution(monkeypatch):
    monkeypatch.setattr(
        "dns_info.socket.getaddrinfo",
        lambda *args, **kwargs: [],
    )

    with pytest.raises(ValueError, match="no IP addresses"):
        resolve_hostname("empty.test")
