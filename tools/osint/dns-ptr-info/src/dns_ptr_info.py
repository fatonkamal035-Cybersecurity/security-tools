"""Read-only DNS PTR record lookup."""

import dns.exception
import dns.resolver


def _validate_ip_address(ip_address: str) -> str:
    """Validate and normalize an IP address."""
    ip_address = ip_address.strip()

    if not ip_address:
        raise ValueError("ip address must not be empty")

    if any(char.isspace() for char in ip_address):
        raise ValueError("ip address must not contain whitespace")

    try:
        import ipaddress

        address = ipaddress.ip_address(ip_address)
    except ValueError as exc:
        raise ValueError("invalid IP address") from exc

    return str(address)


def resolve_ptr_records(
    ip_address: str,
) -> list[str]:
    """Resolve PTR records for one explicitly provided IP address."""
    ip_address = _validate_ip_address(ip_address)

    resolver = dns.resolver.Resolver()

    try:
        reverse_name = dns.reversename.from_address(ip_address)
        answers = resolver.resolve(
            reverse_name,
            "PTR",
        )
    except dns.exception.DNSException:
        return []

    records = {
        str(answer.target).rstrip(".").lower()
        for answer in answers
    }

    return sorted(records)
