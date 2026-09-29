"""Read-only DNS TLSA record lookup."""

import dns.exception
import dns.resolver


def _validate_tlsa_owner(owner: str) -> str:
    """Validate a TLSA owner name such as _443._tcp.example.com."""
    owner = owner.strip().rstrip(".")

    if not owner:
        raise ValueError("TLSA owner must not be empty")

    if len(owner) > 253:
        raise ValueError("TLSA owner is too long")

    labels = owner.split(".")

    if len(labels) < 3:
        raise ValueError(
            "TLSA owner must include port, protocol, and hostname"
        )

    port_label, protocol_label = labels[0], labels[1]

    if not port_label.startswith("_") or not port_label[1:].isdigit():
        raise ValueError("TLSA owner must start with a numeric port label")

    port = int(port_label[1:])
    if not 0 <= port <= 65535:
        raise ValueError("TLSA port must be between 0 and 65535")

    if protocol_label.lower() not in {"_tcp", "_udp", "_sctp"}:
        raise ValueError("TLSA protocol must be _tcp, _udp, or _sctp")

    hostname = ".".join(labels[2:])

    if any(not label for label in hostname.split(".")):
        raise ValueError("TLSA hostname contains an empty label")

    for label in hostname.split("."):
        if (
            len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(char.isalnum() or char == "-" for char in label)
        ):
            raise ValueError("TLSA hostname contains an invalid label")

    return owner.lower()


def resolve_tlsa_records(owner: str) -> list[dict[str, object]]:
    """Resolve TLSA records for one explicitly provided owner name."""
    owner = _validate_tlsa_owner(owner)
    resolver = dns.resolver.Resolver()

    try:
        answers = resolver.resolve(owner, "TLSA")
    except dns.exception.DNSException:
        return []

    records = {
        (
            int(answer.usage),
            int(answer.selector),
            int(answer.mtype),
            answer.cert.hex().lower(),
        )
        for answer in answers
    }

    return [
        {
            "usage": usage,
            "selector": selector,
            "matching_type": matching_type,
            "certificate_association_data": association_data,
        }
        for usage, selector, matching_type, association_data in sorted(records)
    ]
