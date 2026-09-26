import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

import dns.resolver
import pytest

from dns_mx_info import resolve_mx_records


class FakeAnswer:
    def __init__(self, preference, exchange):
        self.preference = preference
        self.exchange = exchange


def test_resolve_mx_records(monkeypatch):
    def fake_resolve(*args, **kwargs):
        return [
            FakeAnswer(20, "MAIL2.EXAMPLE.COM."),
            FakeAnswer(10, "MAIL1.EXAMPLE.COM."),
            FakeAnswer(20, "MAIL2.EXAMPLE.COM."),
        ]

    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        fake_resolve,
    )

    assert resolve_mx_records("Example.COM") == [
        {
            "priority": 10,
            "exchange": "mail1.example.com",
        },
        {
            "priority": 20,
            "exchange": "mail2.example.com",
        },
    ]


def test_preserve_null_mx_exchange(monkeypatch):
    def fake_resolve(*args, **kwargs):
        return [
            FakeAnswer(0, "."),
        ]

    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        fake_resolve,
    )

    assert resolve_mx_records("example.com") == [
        {
            "priority": 0,
            "exchange": ".",
        },
    ]


def test_empty_result_on_dns_error(monkeypatch):
    def fake_resolve(*args, **kwargs):
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        fake_resolve,
    )

    assert resolve_mx_records("missing.example.com") == []


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
        resolve_mx_records(hostname)


def test_reject_hostname_longer_than_253_characters():
    hostname = "a" * 254

    with pytest.raises(
        ValueError,
        match="hostname is too long",
    ):
        resolve_mx_records(hostname)
