import sys
from pathlib import Path

import dns.exception
import pytest

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

import dns_ptr_info


class FakeAnswer:
    def __init__(self, target: str):
        self.target = target


class FakeResolver:
    def __init__(self, answers=None, error=None):
        self.answers = answers or []
        self.error = error
        self.queries = []

    def resolve(self, reverse_name, record_type):
        self.queries.append((reverse_name, record_type))

        if self.error:
            raise self.error

        return self.answers


@pytest.mark.parametrize(
    ("ip_address", "expected"),
    [
        ("192.0.2.1", "192.0.2.1"),
        (" 192.0.2.1 ", "192.0.2.1"),
        ("2001:db8::1", "2001:db8::1"),
        ("2001:0db8:0:0:0:0:0:1", "2001:db8::1"),
    ],
)
def test_validate_ip_address_normalizes(ip_address, expected):
    assert dns_ptr_info._validate_ip_address(ip_address) == expected


@pytest.mark.parametrize(
    "ip_address",
    [
        "",
        "   ",
        "192.0.2.999",
        "not-an-ip",
        "192.0.2.1 extra",
    ],
)
def test_validate_ip_address_rejects_invalid(ip_address):
    with pytest.raises(ValueError):
        dns_ptr_info._validate_ip_address(ip_address)


def test_resolve_ptr_records(monkeypatch):
    resolver = FakeResolver(
        answers=[
            FakeAnswer("Host.EXAMPLE.COM."),
            FakeAnswer("alias.example.com."),
            FakeAnswer("Host.EXAMPLE.COM."),
        ]
    )

    monkeypatch.setattr(
        dns_ptr_info.dns.resolver,
        "Resolver",
        lambda: resolver,
    )

    result = dns_ptr_info.resolve_ptr_records("192.0.2.1")

    assert result == [
        "alias.example.com",
        "host.example.com",
    ]
    assert resolver.queries[0][1] == "PTR"


def test_resolve_ptr_records_ipv6(monkeypatch):
    resolver = FakeResolver(
        answers=[
            FakeAnswer("IPv6.EXAMPLE.COM."),
        ]
    )

    monkeypatch.setattr(
        dns_ptr_info.dns.resolver,
        "Resolver",
        lambda: resolver,
    )

    result = dns_ptr_info.resolve_ptr_records(
        "2001:0db8:0:0:0:0:0:1"
    )

    assert result == ["ipv6.example.com"]
    assert resolver.queries[0][1] == "PTR"


def test_resolve_ptr_records_dns_error(monkeypatch):
    resolver = FakeResolver(
        error=dns.exception.DNSException("lookup failed")
    )

    monkeypatch.setattr(
        dns_ptr_info.dns.resolver,
        "Resolver",
        lambda: resolver,
    )

    assert dns_ptr_info.resolve_ptr_records("192.0.2.1") == []
