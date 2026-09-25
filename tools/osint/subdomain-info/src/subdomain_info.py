"""Read-only explicit subdomain resolution."""

import socket


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


def resolve_subdomain(
    hostname: str,
) -> dict[str, object]:
    """Resolve one explicitly provided hostname."""
    hostname = _validate_hostname(hostname)

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        return {
            "hostname": hostname,
            "resolved": False,
            "addresses": [],
        }

    addresses = sorted(
        {
            result[4][0]
            for result in results
            if result[0] in {
                socket.AF_INET,
                socket.AF_INET6,
            }
        }
    )

    return {
        "hostname": hostname,
        "resolved": bool(addresses),
        "addresses": addresses,
    }
