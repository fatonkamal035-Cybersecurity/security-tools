"""Read-only DNS DS record lookup."""

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


def resolve_ds_records(
    hostname: str,
) -> list[dict[str, object]]:
    """Resolve DS records for one explicitly provided hostname."""
    hostname = _validate_hostname(hostname)

    resolver = dns.resolver.Resolver()

    try:
        answers = resolver.resolve(
            hostname,
            "DS",
        )
    except dns.exception.DNSException:
        return []

    records = {
        (
            int(answer.key_tag),
            int(answer.algorithm),
            int(answer.digest_type),
            str(answer.digest).lower(),
        )
        for answer in answers
    }

    return [
        {
            "key_tag": key_tag,
            "algorithm": algorithm,
            "digest_type": digest_type,
            "digest": digest,
        }
        for key_tag, algorithm, digest_type, digest in sorted(records)
    ]
