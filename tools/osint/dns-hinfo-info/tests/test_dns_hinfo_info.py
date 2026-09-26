import sys
from pathlib import Path

import dns.exception
import pytest

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

import dns_hinfo_info


class FakeAnswer:
    def __init__(self, cpu: str, os: str):
        self.cpu = cpu
        self.os = os


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
    assert (
        dns_hinfo_info._validate_hostname(" Example.COM. ")
        == "example.com"
    )


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
        dns_hinfo_info._validate_hostname(hostname)


def test_validate_hostname_rejects_long_hostname():
    hostname = ".".join(["a" * 63] * 4)

    with pytest.raises(ValueError, match="hostname is too long"):
        dns_hinfo_info._validate_hostname(hostname)


def test_resolve_hinfo_records(monkeypatch):
    resolver = FakeResolver(
        answers=[
            FakeAnswer("x86_64", "Linux"),
            FakeAnswer("ARM64", "FreeBSD"),
            FakeAnswer("x86_64", "Linux"),
        ]
    )

    monkeypatch.setattr(
        dns_hinfo_info.dns.resolver,
        "Resolver",
        lambda: resolver,
    )

    result = dns_hinfo_info.resolve_hinfo_records(
        "Host.Example.COM."
    )

    assert result == [
        {
            "cpu": "ARM64",
            "os": "FreeBSD",
        },
        {
            "cpu": "x86_64",
            "os": "Linux",
        },
    ]

    assert resolver.queries == [
        ("host.example.com", "HINFO"),
    ]


def test_resolve_hinfo_records_dns_error(monkeypatch):
    resolver = FakeResolver(
        error=dns.exception.DNSException("lookup failed")
    )

    monkeypatch.setattr(
        dns_hinfo_info.dns.resolver,
        "Resolver",
        lambda: resolver,
    )

    assert dns_hinfo_info.resolve_hinfo_records(
        "example.com"
    ) == []
