import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

import dns.resolver
import pytest

from dns_naptr_info import (
    _validate_hostname,
    resolve_naptr_records,
)


class FakeAnswer:
    def __init__(
        self,
        order,
        preference,
        flags,
        service,
        regexp,
        replacement,
    ):
        self.order = order
        self.preference = preference
        self.flags = flags
        self.service = service
        self.regexp = regexp
        self.replacement = replacement


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


def test_resolve_naptr_records(monkeypatch):
    class FakeResolver:
        def resolve(self, hostname, record_type):
            assert hostname == "example.com"
            assert record_type == "NAPTR"

            return [
                FakeAnswer(
                    100,
                    10,
                    "U",
                    "E2U+sip",
                    "!^.*$!sip:info@example.com!",
                    ".",
                ),
                FakeAnswer(
                    100,
                    20,
                    "S",
                    "SIP+D2U",
                    "",
                    "_sip._udp.example.com.",
                ),
                FakeAnswer(
                    100,
                    10,
                    "U",
                    "E2U+sip",
                    "!^.*$!sip:info@example.com!",
                    ".",
                ),
            ]

    monkeypatch.setattr(
        dns.resolver,
        "Resolver",
        lambda: FakeResolver(),
    )

    assert resolve_naptr_records("Example.COM.") == [
        {
            "order": 100,
            "preference": 10,
            "flags": "U",
            "service": "E2U+sip",
            "regexp": "!^.*$!sip:info@example.com!",
            "replacement": "",
        },
        {
            "order": 100,
            "preference": 20,
            "flags": "S",
            "service": "SIP+D2U",
            "regexp": "",
            "replacement": "_sip._udp.example.com",
        },
    ]


def test_resolve_naptr_records_dns_error(monkeypatch):
    class FakeResolver:
        def resolve(self, hostname, record_type):
            raise dns.resolver.NoAnswer()

    monkeypatch.setattr(
        dns.resolver,
        "Resolver",
        lambda: FakeResolver(),
    )

    assert resolve_naptr_records("example.com") == []


def test_resolve_naptr_records_uses_explicit_hostname(monkeypatch):
    class FakeResolver:
        def resolve(self, hostname, record_type):
            assert hostname == "example.org"
            assert record_type == "NAPTR"
            return []

    monkeypatch.setattr(
        dns.resolver,
        "Resolver",
        lambda: FakeResolver(),
    )

    assert resolve_naptr_records("example.org") == []
