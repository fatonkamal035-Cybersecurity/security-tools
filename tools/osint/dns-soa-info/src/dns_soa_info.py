"""Read-only DNS SOA record lookup."""

import dns.exception
import dns.resolver


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
            raise ValueError(
                "hostname label must not start or end with '-'"
            )

        if not all(char.isalnum() or char == "-" for char in label):
            raise ValueError("hostname contains invalid characters")

    return hostname.lower()


def resolve_soa_record(hostname: str) -> dict[str, object]:
    """Resolve the SOA record for one explicitly provided hostname."""
    hostname = _validate_hostname(hostname)

    resolver = dns.resolver.Resolver()

    try:
        answer = resolver.resolve(
            hostname,
            "SOA",
        )[0]
    except dns.exception.DNSException:
        return {}

    return {
        "mname": str(answer.mname).rstrip(".").lower(),
        "rname": str(answer.rname).rstrip(".").lower(),
        "serial": int(answer.serial),
        "refresh": int(answer.refresh),
        "retry": int(answer.retry),
        "expire": int(answer.expire),
        "minimum": int(answer.minimum),
    }
