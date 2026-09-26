import sys
from pathlib import Path

import pytest

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

import dns_https_info


class FakeAnswer:
    def __init__(
        self,
        priority: int,
        target: str,
        record: str,
    ) -> None:
        self.priority = priority
        self.target = target
        self._record = record

    def to_text(self) -> str:
        return self._record


class FakeResolver:
    def resolve(self, hostname: str, record_type: str):
        assert hostname == "example.com"
        assert record_type == "HTTPS"

        return [
            FakeAnswer(
                1,
                "svc.example.com.",
                "1 svc.example.com. alpn=h2",
            ),
            FakeAnswer(
                0,
                ".",
                "0 .",
            ),
            FakeAnswer(
                1,
                "svc.example.com.",
                "1 svc.example.com. alpn=h2",
            ),
        ]


def test_validate_hostname_normalizes():
    assert (
        dns_https_info._validate_hostname(" Example.COM. ")
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
        dns_https_info._validate_hostname(hostname)


def test_validate_hostname_rejects_long_hostname():
    hostname = ".".join(["a" * 63] * 5)

    with pytest.raises(ValueError, match="hostname is too long"):
        dns_https_info._validate_hostname(hostname)


def test_resolve_https_records(monkeypatch):
    monkeypatch.setattr(
        dns_https_info.dns.resolver,
        "Resolver",
        lambda: FakeResolver(),
    )

    assert dns_https_info.resolve_https_records("Example.COM.") == [
        {
            "priority": 0,
            "target": ".",
            "record": "0 .",
        },
        {
            "priority": 1,
            "target": "svc.example.com",
            "record": "1 svc.example.com. alpn=h2",
        },
    ]


def test_resolve_https_records_dns_error(monkeypatch):
    class ErrorResolver:
        def resolve(self, hostname: str, record_type: str):
            raise dns_https_info.dns.exception.DNSException()

    monkeypatch.setattr(
        dns_https_info.dns.resolver,
        "Resolver",
        lambda: ErrorResolver(),
    )

    assert dns_https_info.resolve_https_records("example.com") == []
