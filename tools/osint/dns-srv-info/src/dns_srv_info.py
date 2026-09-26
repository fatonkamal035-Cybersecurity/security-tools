"""Read-only DNS SRV record lookup."""

import dns.exception
import dns.resolver


def _validate_hostname(hostname: str) -> str:
    """Validate and normalize a hostname used as an SRV owner name."""
    hostname = hostname.strip().rstrip(".")

    if not hostname:
        raise ValueError("hostname must not be empty")

    if len(hostname) > 253:
        raise ValueError("hostname is too long")

    if any(char.isspace() for char in hostname):
        raise ValueError("hostname must not contain whitespace")

    labels = hostname.split(".")

    for index, label in enumerate(labels):
        if not label:
            raise ValueError("hostname contains an empty label")

        if len(label) > 63:
            raise ValueError("hostname label is too long")

        if label.startswith("_"):
            if index > 1:
                raise ValueError(
                    "underscore-prefixed labels are only allowed "
                    "for service and protocol labels"
                )

            label_body = label[1:]

            if not label_body:
                raise ValueError(
                    "underscore-prefixed label must not be empty"
                )

            if not all(
                char.isalnum() or char == "-"
                for char in label_body
            ):
                raise ValueError(
                    "hostname contains invalid characters"
                )

            continue

        if label.startswith("-") or label.endswith("-"):
            raise ValueError(
                "hostname label must not start or end with '-'"
            )

        if not all(char.isalnum() or char == "-" for char in label):
            raise ValueError("hostname contains invalid characters")

    return hostname.lower()


def resolve_srv_records(
    hostname: str,
) -> list[dict[str, object]]:
    """Resolve SRV records for one explicitly provided hostname."""
    hostname = _validate_hostname(hostname)

    resolver = dns.resolver.Resolver()

    try:
        answers = resolver.resolve(
            hostname,
            "SRV",
        )
    except dns.exception.DNSException:
        return []

    records = {
        (
            int(answer.priority),
            int(answer.weight),
            int(answer.port),
            str(answer.target).rstrip(".").lower(),
        )
        for answer in answers
    }

    return [
        {
            "priority": priority,
            "weight": weight,
            "port": port,
            "target": target,
        }
        for priority, weight, port, target in sorted(records)
    ]
