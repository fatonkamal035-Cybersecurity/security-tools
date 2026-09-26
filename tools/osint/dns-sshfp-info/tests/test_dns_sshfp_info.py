import sys
from pathlib import Path

import dns.exception
import pytest

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

import dns_sshfp_info


class FakeAnswer:
    def __init__(
        self,
        algorithm: int,
        fp_type: int,
        fingerprint: str,
    ):
        self.algorithm = algorithm
        self.fp_type = fp_type
        self.fingerprint = fingerprint


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
        dns_sshfp_info._validate_hostname(" Example.COM. ")
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
        dns_sshfp_info._validate_hostname(hostname)


def test_validate_hostname_rejects_long_hostname():
    hostname = ".".join(["a" * 63] * 4)

    with pytest.raises(ValueError, match="hostname is too long"):
        dns_sshfp_info._validate_hostname(hostname)


def test_resolve_sshfp_records(monkeypatch):
    resolver = FakeResolver(
        answers=[
            FakeAnswer(
                algorithm=2,
                fp_type=2,
                fingerprint="ABCDEF",
            ),
            FakeAnswer(
                algorithm=1,
                fp_type=1,
                fingerprint="123456",
            ),
            FakeAnswer(
                algorithm=2,
                fp_type=2,
                fingerprint="ABCDEF",
            ),
        ]
    )

    monkeypatch.setattr(
        dns_sshfp_info.dns.resolver,
        "Resolver",
        lambda: resolver,
    )

    result = dns_sshfp_info.resolve_sshfp_records(
        "SSH.Example.COM."
    )

    assert result == [
        {
            "algorithm": 1,
            "fingerprint_type": 1,
            "fingerprint": "123456",
        },
        {
            "algorithm": 2,
            "fingerprint_type": 2,
            "fingerprint": "abcdef",
        },
    ]

    assert resolver.queries == [
        ("ssh.example.com", "SSHFP"),
    ]


def test_resolve_sshfp_records_dns_error(monkeypatch):
    resolver = FakeResolver(
        error=dns.exception.DNSException("lookup failed")
    )

    monkeypatch.setattr(
        dns_sshfp_info.dns.resolver,
        "Resolver",
        lambda: resolver,
    )

    assert dns_sshfp_info.resolve_sshfp_records(
        "example.com"
    ) == []
