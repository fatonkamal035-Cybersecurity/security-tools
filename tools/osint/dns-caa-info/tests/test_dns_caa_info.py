import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

import dns.resolver
import pytest

from dns_caa_info import resolve_caa_records


class FakeAnswer:
    def __init__(self, flags, tag, value):
        self.flags = flags
        self.tag = tag
        self.value = value


def test_resolve_caa_records(monkeypatch):
    def fake_resolve(*args, **kwargs):
        return [
            FakeAnswer(0, "issue", "letsencrypt.org"),
            FakeAnswer(0, "issuewild", "letsencrypt.org"),
            FakeAnswer(0, "issue", "letsencrypt.org"),
        ]

    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        fake_resolve,
    )

    assert resolve_caa_records("Example.COM") == [
        {
            "flags": 0,
            "tag": "issue",
            "value": "letsencrypt.org",
        },
        {
            "flags": 0,
            "tag": "issuewild",
            "value": "letsencrypt.org",
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

    assert resolve_caa_records("missing.example.com") == []


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
        resolve_caa_records(hostname)


def test_reject_hostname_longer_than_253_characters():
    hostname = "a" * 254

    with pytest.raises(
        ValueError,
        match="hostname is too long",
    ):
        resolve_caa_records(hostname)
