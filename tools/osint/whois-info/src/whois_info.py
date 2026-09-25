"""Read-only WHOIS lookup."""

import socket


WHOIS_SERVER = "whois.iana.org"
WHOIS_PORT = 43
DEFAULT_TIMEOUT = 5.0


def _validate_domain(domain: str) -> str:
    """Validate and normalize a domain name."""
    domain = domain.strip().rstrip(".")

    if not domain:
        raise ValueError("domain must not be empty")

    if len(domain) > 253:
        raise ValueError("domain is too long")

    if any(char.isspace() for char in domain):
        raise ValueError("domain must not contain whitespace")

    labels = domain.split(".")

    if len(labels) < 2:
        raise ValueError("domain must contain a suffix")

    for label in labels:
        if not label:
            raise ValueError("domain contains an empty label")

        if len(label) > 63:
            raise ValueError("domain label is too long")

        if label.startswith("-") or label.endswith("-"):
            raise ValueError("domain label must not start or end with '-'")

        if not all(char.isalnum() or char == "-" for char in label):
            raise ValueError("domain contains invalid characters")

    return domain.lower()


def query_whois(
    domain: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> str:
    """Query the fixed IANA WHOIS server for a domain."""
    domain = _validate_domain(domain)

    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    with socket.create_connection(
        (WHOIS_SERVER, WHOIS_PORT),
        timeout=timeout,
    ) as connection:
        connection.sendall(f"{domain}\r\n".encode("ascii"))

        chunks: list[bytes] = []

        while True:
            chunk = connection.recv(4096)

            if not chunk:
                break

            chunks.append(chunk)

    return b"".join(chunks).decode("utf-8", errors="replace")
