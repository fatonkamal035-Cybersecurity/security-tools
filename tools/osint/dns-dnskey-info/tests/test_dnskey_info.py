import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

import dns.resolver
import pytest

from dnskey_info import _validate_hostname, resolve_dnskey_records


class FakeAnswer:
    def __init__(self, flags, protocol, algorithm, key):
        self.flags = flags
        self.protocol = protocol
        self.algorithm = algorithm
        self.key = key


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


def test_resolve_dnskey_records(monkeypatch):
    class FakeResolver:
        def resolve(self, hostname, record_type):
            assert hostname == "example.com"
            assert record_type == "DNSKEY"

            return [
                FakeAnswer(257, 3, 13, "key-b"),
                FakeAnswer(256, 3, 13, "key-a"),
                FakeAnswer(257, 3, 13, "key-b"),
            ]

    monkeypatch.setattr(
        dns.resolver,
        "Resolver",
        lambda: FakeResolver(),
    )

    assert resolve_dnskey_records("Example.COM.") == [
        {
            "flags": 256,
            "protocol": 3,
            "algorithm": 13,
            "key": "key-a",
        },
        {
            "flags": 257,
            "protocol": 3,
            "algorithm": 13,
            "key": "key-b",
        },
    ]


def test_resolve_dnskey_records_dns_error(monkeypatch):
    class FakeResolver:
        def resolve(self, hostname, record_type):
            raise dns.resolver.NoAnswer()

    monkeypatch.setattr(
        dns.resolver,
        "Resolver",
        lambda: FakeResolver(),
    )

    assert resolve_dnskey_records("example.com") == []


def test_resolve_dnskey_records_uses_explicit_hostname(monkeypatch):
    class FakeResolver:
        def resolve(self, hostname, record_type):
            assert hostname == "example.org"
            assert record_type == "DNSKEY"
            return []

    monkeypatch.setattr(
        dns.resolver,
        "Resolver",
        lambda: FakeResolver(),
    )

    assert resolve_dnskey_records("example.org") == []
