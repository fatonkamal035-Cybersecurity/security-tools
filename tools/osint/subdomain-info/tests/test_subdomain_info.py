import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

import socket

import pytest

from subdomain_info import resolve_subdomain


def test_resolve_subdomain(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("192.0.2.10", 0),
            ),
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                6,
                "",
                ("2001:db8::10", 0, 0, 0),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("192.0.2.10", 0),
            ),
        ]

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    assert resolve_subdomain("API.Example.COM") == {
        "hostname": "api.example.com",
        "resolved": True,
        "addresses": [
            "192.0.2.10",
            "2001:db8::10",
        ],
    }


def test_unresolved_subdomain(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        raise socket.gaierror

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    assert resolve_subdomain("missing.example.com") == {
        "hostname": "missing.example.com",
        "resolved": False,
        "addresses": [],
    }


@pytest.mark.parametrize(
    "hostname",
    [
        "",
        "example .com",
        "-example.com",
        "example-.com",
        "example..com",
    ],
)
def test_reject_invalid_hostname(hostname):
    with pytest.raises(ValueError):
        resolve_subdomain(hostname)


def test_reject_hostname_longer_than_253_characters():
    hostname = "a" * 254

    with pytest.raises(
        ValueError,
        match="hostname is too long",
    ):
        resolve_subdomain(hostname)
