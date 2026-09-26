import sys
from pathlib import Path

import pytest

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

import dns_rp_info


class FakeAnswer:
    def __init__(self, mbox: str, txt: str) -> None:
        self.mbox = mbox
        self.txt = txt


class FakeResolver:
    def resolve(self, hostname: str, record_type: str):
        assert hostname == "example.com"
        assert record_type == "RP"

        return [
            FakeAnswer(
                "admin.example.com.",
                "info.example.com.",
            ),
            FakeAnswer(
                "admin.example.com.",
                "info.example.com.",
            ),
            FakeAnswer(
                "security.example.com.",
                "security-info.example.com.",
            ),
        ]


def test_validate_hostname_normalizes():
    assert dns_rp_info._validate_hostname(" Example.COM. ") == "example.com"


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
        dns_rp_info._validate_hostname(hostname)


def test_validate_hostname_rejects_long_hostname():
    hostname = ".".join(["a" * 63] * 5)

    with pytest.raises(ValueError, match="hostname is too long"):
        dns_rp_info._validate_hostname(hostname)


def test_resolve_rp_records(monkeypatch):
    monkeypatch.setattr(
        dns_rp_info.dns.resolver,
        "Resolver",
        lambda: FakeResolver(),
    )

    assert dns_rp_info.resolve_rp_records("Example.COM.") == [
        {
            "mailbox": "admin.example.com",
            "txt": "info.example.com",
        },
        {
            "mailbox": "security.example.com",
            "txt": "security-info.example.com",
        },
    ]


def test_resolve_rp_records_dns_error(monkeypatch):
    class ErrorResolver:
        def resolve(self, hostname: str, record_type: str):
            raise dns_rp_info.dns.exception.DNSException()

    monkeypatch.setattr(
        dns_rp_info.dns.resolver,
        "Resolver",
        lambda: ErrorResolver(),
    )

    assert dns_rp_info.resolve_rp_records("example.com") == []
