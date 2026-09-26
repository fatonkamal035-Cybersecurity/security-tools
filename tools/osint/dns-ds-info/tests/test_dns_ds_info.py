import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

import dns.resolver
import pytest

from dns_ds_info import resolve_ds_records


class FakeAnswer:
    def __init__(
        self,
        key_tag,
        algorithm,
        digest_type,
        digest,
    ):
        self.key_tag = key_tag
        self.algorithm = algorithm
        self.digest_type = digest_type
        self.digest = digest


def test_resolve_ds_records(monkeypatch):
    def fake_resolve(*args, **kwargs):
        return [
            FakeAnswer(
                2371,
                13,
                2,
                "ABCDEF123456",
            ),
            FakeAnswer(
                1234,
                8,
                2,
                "FEDCBA654321",
            ),
            FakeAnswer(
                2371,
                13,
                2,
                "ABCDEF123456",
            ),
        ]

    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        fake_resolve,
    )

    assert resolve_ds_records("Example.COM") == [
        {
            "key_tag": 1234,
            "algorithm": 8,
            "digest_type": 2,
            "digest": "fedcba654321",
        },
        {
            "key_tag": 2371,
            "algorithm": 13,
            "digest_type": 2,
            "digest": "abcdef123456",
        },
    ]


def test_empty_result_on_dns_error(monkeypatch):
    def fake_resolve(*args, **kwargs):
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        fake_resolve,
    )

    assert resolve_ds_records("missing.example.com") == []


@pytest.mark.parametrize(
    "hostname",
    [
        "",
        "example .com",
        "-example.com",
        "example-.com",
        "example..com",
    ],
)
def test_reject_invalid_hostname(hostname):
    with pytest.raises(ValueError):
        resolve_ds_records(hostname)


def test_reject_hostname_longer_than_253_characters():
    hostname = "a" * 254

    with pytest.raises(
        ValueError,
        match="hostname is too long",
    ):
        resolve_ds_records(hostname)
