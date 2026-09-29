import sys
from pathlib import Path

import pytest

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

import dns_uri_info


class FakeAnswer:
    def __init__(
        self,
        priority: int,
        weight: int,
        target: str,
    ) -> None:
        self.priority = priority
        self.weight = weight
        self.target = target


class FakeResolver:
    def resolve(self, hostname: str, record_type: str):
        assert hostname == "example.com"
        assert record_type == "URI"

        return [
            FakeAnswer(10, 20, "https://example.com/service"),
            FakeAnswer(1, 5, "https://example.com/primary"),
            FakeAnswer(10, 20, "https://example.com/service"),
        ]


def test_validate_hostname_normalizes():
    assert (
        dns_uri_info._validate_hostname(" Example.COM. ")
        == "example.com"
    )


@pytest.mark.parametrize(
    "hostname",
    [
        "",
        " ",
        "example .com",
        "-example.com",
        "example-.com",
        "example..com",
        "example_foo.com",
    ],
)
def test_validate_hostname_rejects_invalid(hostname: str):
    with pytest.raises(ValueError):
        dns_uri_info._validate_hostname(hostname)


def test_validate_hostname_rejects_long_hostname():
    hostname = ".".join(["a" * 63] * 5)

    with pytest.raises(ValueError, match="hostname is too long"):
        dns_uri_info._validate_hostname(hostname)


def test_resolve_uri_records(monkeypatch):
    monkeypatch.setattr(
        dns_uri_info.dns.resolver,
        "Resolver",
        lambda: FakeResolver(),
    )

    assert dns_uri_info.resolve_uri_records("Example.COM.") == [
        {
            "priority": 1,
            "weight": 5,
            "target": "https://example.com/primary",
        },
        {
            "priority": 10,
            "weight": 20,
            "target": "https://example.com/service",
        },
    ]


def test_resolve_uri_records_dns_error(monkeypatch):
    class ErrorResolver:
        def resolve(self, hostname: str, record_type: str):
            raise dns_uri_info.dns.exception.DNSException()

    monkeypatch.setattr(
        dns_uri_info.dns.resolver,
        "Resolver",
        lambda: ErrorResolver(),
    )

    assert dns_uri_info.resolve_uri_records("example.com") == []
