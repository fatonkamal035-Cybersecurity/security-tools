import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

import dns.resolver
import pytest

from dns_txt_info import resolve_txt_records


class FakeAnswer:
    def __init__(self, strings):
        self.strings = strings


def test_resolve_txt_records(monkeypatch):
    def fake_resolve(*args, **kwargs):
        return [
            FakeAnswer([b"v=spf1 ", b"-all"]),
            FakeAnswer([b"google-site-verification=abc123"]),
            FakeAnswer([b"v=spf1 ", b"-all"]),
        ]

    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        fake_resolve,
    )

    assert resolve_txt_records("Example.COM") == [
        "google-site-verification=abc123",
        "v=spf1 -all",
    ]


def test_empty_result_on_dns_error(monkeypatch):
    def fake_resolve(*args, **kwargs):
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        fake_resolve,
    )

    assert resolve_txt_records("missing.example.com") == []


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
        resolve_txt_records(hostname)


def test_reject_hostname_longer_than_253_characters():
    hostname = "a" * 254

    with pytest.raises(
        ValueError,
        match="hostname is too long",
    ):
        resolve_txt_records(hostname)
