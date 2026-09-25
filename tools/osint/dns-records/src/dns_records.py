"""Read-only DNS record lookup."""

import socket


SUPPORTED_RECORD_TYPES = ("A", "AAAA")


def _validate_hostname(hostname: str) -> str:
    """Validate and normalize a hostname."""
    hostname = hostname.strip().rstrip(".")

    if not hostname:
        raise ValueError("hostname must not be empty")

    if len(hostname) > 253:
        raise ValueError("hostname is too long")

    if any(char.isspace() for char in hostname):
        raise ValueError("hostname must not contain whitespace")

    labels = hostname.split(".")

    for label in labels:
        if not label:
            raise ValueError("hostname contains an empty label")

        if len(label) > 63:
            raise ValueError("hostname label is too long")

        if label.startswith("-") or label.endswith("-"):
            raise ValueError("hostname label must not start or end with '-'")

        if not all(char.isalnum() or char == "-" for char in label):
            raise ValueError("hostname contains invalid characters")

    return hostname.lower()


def resolve_dns_records(
    hostname: str,
    record_type: str = "A",
) -> list[str]:
    """Resolve A or AAAA records for one hostname."""
    hostname = _validate_hostname(hostname)
    record_type = record_type.upper()

    if record_type not in SUPPORTED_RECORD_TYPES:
        raise ValueError(
            f"unsupported record type: {record_type}"
        )

    family = (
        socket.AF_INET
        if record_type == "A"
        else socket.AF_INET6
    )

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            family=family,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        return []

    addresses = {
        result[4][0]
        for result in results
    }

    return sorted(addresses)
