import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

import dns.resolver
import pytest

from dns_srv_info import _validate_hostname, resolve_srv_records


class FakeAnswer:
    def __init__(
        self,
        priority,
        weight,
        port,
        target,
    ):
        self.priority = priority
        self.weight = weight
        self.port = port
        self.target = target


def test_validate_hostname_normalizes():
    assert _validate_hostname("Example.COM.") == "example.com"


@pytest.mark.parametrize(
    "hostname",
    [
        "",
        "   ",
        "example .com",
        "a" * 254,
        "example..com",
        "-example.com",
        "example-.com",
        "example.com/",
    ],
)
def test_validate_hostname_rejects_invalid(hostname):
    with pytest.raises(ValueError):
        _validate_hostname(hostname)


def test_resolve_srv_records(monkeypatch):
    class FakeResolver:
        def resolve(self, hostname, record_type):
            assert hostname == "_sip._tcp.example.com"
            assert record_type == "SRV"

            return [
                FakeAnswer(10, 20, 5060, "SIP2.EXAMPLE.COM."),
                FakeAnswer(10, 10, 5060, "sip1.example.com."),
                FakeAnswer(10, 10, 5060, "sip1.example.com."),
            ]

    monkeypatch.setattr(
        dns.resolver,
        "Resolver",
        lambda: FakeResolver(),
    )

    assert resolve_srv_records(
        "_sip._tcp.example.com"
    ) == [
        {
            "priority": 10,
            "weight": 10,
            "port": 5060,
            "target": "sip1.example.com",
        },
        {
            "priority": 10,
            "weight": 20,
            "port": 5060,
            "target": "sip2.example.com",
        },
    ]


def test_resolve_srv_records_dns_error(monkeypatch):
    class FakeResolver:
        def resolve(self, hostname, record_type):
            raise dns.resolver.NoAnswer()

    monkeypatch.setattr(
        dns.resolver,
        "Resolver",
        lambda: FakeResolver(),
    )

    assert resolve_srv_records(
        "_sip._tcp.example.com"
    ) == []


def test_resolve_srv_records_uses_explicit_hostname(monkeypatch):
    class FakeResolver:
        def resolve(self, hostname, record_type):
            assert hostname == "_ldap._tcp.example.org"
            assert record_type == "SRV"
            return []

    monkeypatch.setattr(
        dns.resolver,
        "Resolver",
        lambda: FakeResolver(),
    )

    assert resolve_srv_records(
        "_ldap._tcp.example.org"
    ) == []
