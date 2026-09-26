import sys
from pathlib import Path

import dns.exception
import pytest

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

import dns_cname_info


class FakeAnswer:
    def __init__(self, target: str):
        self.target = target


class FakeResolver:
    def __init__(self, answers=None, error=None):
        self.answers = answers or []
        self.error = error
        self.queries = []

    def resolve(self, hostname, record_type):
        self.queries.append((hostname, record_type))

        if self.error:
            raise self.error

        return self.answers


def test_validate_hostname_normalizes():
    assert dns_cname_info._validate_hostname(" Example.COM. ") == "example.com"


@pytest.mark.parametrize(
    "hostname",
    [
        "",
        "   ",
        "example .com",
        "example..com",
        "-example.com",
        "example-.com",
        "example_com",
    ],
)
def test_validate_hostname_rejects_invalid(hostname):
    with pytest.raises(ValueError):
        dns_cname_info._validate_hostname(hostname)


def test_validate_hostname_rejects_long_hostname():
    hostname = ".".join(["a" * 63] * 4)

    with pytest.raises(ValueError, match="hostname is too long"):
        dns_cname_info._validate_hostname(hostname)


def test_resolve_cname_records(monkeypatch):
    resolver = FakeResolver(
        answers=[
            FakeAnswer("Target.EXAMPLE.COM."),
            FakeAnswer("alias.example.com."),
            FakeAnswer("Target.EXAMPLE.COM."),
        ]
    )

    monkeypatch.setattr(
        dns_cname_info.dns.resolver,
        "Resolver",
        lambda: resolver,
    )

    result = dns_cname_info.resolve_cname_records("Alias.Example.COM.")

    assert result == [
        "alias.example.com",
        "target.example.com",
    ]
    assert resolver.queries == [
        ("alias.example.com", "CNAME"),
    ]


def test_resolve_cname_records_dns_error(monkeypatch):
    resolver = FakeResolver(
        error=dns.exception.DNSException("lookup failed")
    )

    monkeypatch.setattr(
        dns_cname_info.dns.resolver,
        "Resolver",
        lambda: resolver,
    )

    assert dns_cname_info.resolve_cname_records("example.com") == []
