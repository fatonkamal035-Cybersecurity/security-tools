import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

import dns.resolver
import pytest

from dns_soa_info import resolve_soa_record


class FakeAnswer:
    mname = "NS1.EXAMPLE.COM."
    rname = "HOSTMASTER.EXAMPLE.COM."
    serial = 2026092601
    refresh = 3600
    retry = 600
    expire = 1209600
    minimum = 300


def test_resolve_soa_record(monkeypatch):
    def fake_resolve(*args, **kwargs):
        return [FakeAnswer()]

    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        fake_resolve,
    )

    assert resolve_soa_record("Example.COM") == {
        "mname": "ns1.example.com",
        "rname": "hostmaster.example.com",
        "serial": 2026092601,
        "refresh": 3600,
        "retry": 600,
        "expire": 1209600,
        "minimum": 300,
    }


def test_empty_result_on_dns_error(monkeypatch):
    def fake_resolve(*args, **kwargs):
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        fake_resolve,
    )

    assert resolve_soa_record("missing.example.com") == {}


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
        resolve_soa_record(hostname)


def test_reject_hostname_longer_than_253_characters():
    hostname = "a" * 254

    with pytest.raises(
        ValueError,
        match="hostname is too long",
    ):
        resolve_soa_record(hostname)
