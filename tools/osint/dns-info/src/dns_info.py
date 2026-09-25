"""Read-only DNS resolution."""

import ipaddress
import socket


def resolve_hostname(hostname: str) -> list[dict[str, str]]:
    """Resolve a hostname to unique IPv4 and IPv6 addresses."""
    hostname = hostname.strip()

    if not hostname:
        raise ValueError("hostname must not be empty")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("hostname must be a hostname, not an IP address")

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        raise ValueError("hostname could not be resolved") from None

    addresses: dict[tuple[int, str], dict[str, str]] = {}

    for family, _, _, _, sockaddr in results:
        address = sockaddr[0]

        if family == socket.AF_INET:
            version = "IPv4"
        elif family == socket.AF_INET6:
            version = "IPv6"
        else:
            continue

        addresses[(family, address)] = {
            "version": version,
            "address": address,
        }

    if not addresses:
        raise ValueError("hostname returned no IP addresses")

    return sorted(
        addresses.values(),
        key=lambda item: (item["version"], item["address"]),
    )
