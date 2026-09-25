import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1]),
)

import socket

import pytest

from src.dns_records import resolve_dns_records


def test_resolve_a_record(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 0),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 0),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.35", 0),
            ),
        ]

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    assert resolve_dns_records(
        "Example.COM",
        "A",
    ) == [
        "93.184.216.34",
        "93.184.216.35",
    ]


def test_resolve_aaaa_record(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                6,
                "",
                ("2001:db8::1", 0, 0, 0),
            )
        ]

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    assert resolve_dns_records(
        "example.com",
        "AAAA",
    ) == [
        "2001:db8::1"
    ]


def test_empty_result_on_resolution_failure(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        raise socket.gaierror

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    assert resolve_dns_records(
        "example.com",
        "A",
    ) == []


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
        resolve_dns_records(hostname)


def test_reject_unsupported_record_type():
    with pytest.raises(
        ValueError,
        match="unsupported record type",
    ):
        resolve_dns_records(
            "example.com",
            "MX",
        )
