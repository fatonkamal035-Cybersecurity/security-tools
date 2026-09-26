"""Read-only DNS SVCB record lookup."""

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


def resolve_svcb_records(
    hostname: str,
) -> list[dict[str, object]]:
    """Resolve SVCB records for one explicitly provided hostname."""
    hostname = _validate_hostname(hostname)

    resolver = dns.resolver.Resolver()

    try:
        answers = resolver.resolve(
            hostname,
            "SVCB",
        )
    except dns.exception.DNSException:
        return []

    records = {
        (
            int(answer.priority),
            (
                "."
                if str(answer.target) == "."
                else str(answer.target).rstrip(".").lower()
            ),
            str(answer.to_text()),
        )
        for answer in answers
    }

    return [
        {
            "priority": priority,
            "target": target,
            "record": record,
        }
        for priority, target, record in sorted(records)
    ]
