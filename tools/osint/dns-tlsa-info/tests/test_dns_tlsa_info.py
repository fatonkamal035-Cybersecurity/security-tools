import sys
from pathlib import Path

import pytest

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src"),
)

import dns_tlsa_info


class FakeAnswer:
    def __init__(
        self,
        usage: int,
        selector: int,
        mtype: int,
        cert: bytes,
    ) -> None:
        self.usage = usage
        self.selector = selector
        self.mtype = mtype
        self.cert = cert


class FakeResolver:
    def resolve(self, owner: str, record_type: str):
        assert owner == "_443._tcp.example.com"
        assert record_type == "TLSA"

        return [
            FakeAnswer(3, 1, 1, bytes.fromhex("aabb")),
            FakeAnswer(0, 0, 1, bytes.fromhex("ccdd")),
            FakeAnswer(3, 1, 1, bytes.fromhex("aabb")),
        ]


def test_validate_tlsa_owner_normalizes():
    assert (
        dns_tlsa_info._validate_tlsa_owner(
            " _443._TCP.Example.COM. "
        )
        == "_443._tcp.example.com"
    )


@pytest.mark.parametrize(
    "owner",
    [
        "",
        "example.com",
        "_https._tcp.example.com",
        "_65536._tcp.example.com",
        "_443._http.example.com",
        "_443._tcp.example..com",
        "_443._tcp.-example.com",
        "_443._tcp.example-.com",
        "_443._tcp.example_foo.com",
    ],
)
def test_validate_tlsa_owner_rejects_invalid(owner: str):
    with pytest.raises(ValueError):
        dns_tlsa_info._validate_tlsa_owner(owner)


def test_validate_tlsa_owner_rejects_long_owner():
    owner = "_443._tcp." + ".".join(["a" * 63] * 4)

    with pytest.raises(ValueError, match="TLSA owner is too long"):
        dns_tlsa_info._validate_tlsa_owner(owner)


def test_resolve_tlsa_records(monkeypatch):
    monkeypatch.setattr(
        dns_tlsa_info.dns.resolver,
        "Resolver",
        lambda: FakeResolver(),
    )

    assert dns_tlsa_info.resolve_tlsa_records(
        "_443._tcp.Example.COM."
    ) == [
        {
            "usage": 0,
            "selector": 0,
            "matching_type": 1,
            "certificate_association_data": "ccdd",
        },
        {
            "usage": 3,
            "selector": 1,
            "matching_type": 1,
            "certificate_association_data": "aabb",
        },
    ]


def test_resolve_tlsa_records_dns_error(monkeypatch):
    class ErrorResolver:
        def resolve(self, owner: str, record_type: str):
            raise dns_tlsa_info.dns.exception.DNSException()

    monkeypatch.setattr(
        dns_tlsa_info.dns.resolver,
        "Resolver",
        lambda: ErrorResolver(),
    )

    assert dns_tlsa_info.resolve_tlsa_records(
        "_443._tcp.example.com"
    ) == []
