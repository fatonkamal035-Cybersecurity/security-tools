"""Read-only TLS certificate metadata."""

import socket
import ssl
from datetime import datetime, timezone


DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 5.0


def _validate_host(host: str) -> str:
    """Validate and normalize a TLS hostname."""
    host = host.strip()

    if not host:
        raise ValueError("host must not be empty")

    if any(char.isspace() for char in host):
        raise ValueError("host must not contain whitespace")

    if len(host) > 253:
        raise ValueError("host is too long")

    return host


def _parse_certificate_time(value: str) -> str:
    """Convert an OpenSSL certificate timestamp to UTC ISO 8601."""
    parsed = datetime.strptime(
        value,
        "%b %d %H:%M:%S %Y %Z",
    ).replace(tzinfo=timezone.utc)

    return parsed.isoformat()


def get_tls_info(
    host: str,
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, object]:
    """Retrieve basic TLS certificate metadata from one host."""
    host = _validate_host(host)

    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")

    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    context = ssl.create_default_context()

    with socket.create_connection(
        (host, port),
        timeout=timeout,
    ) as raw_socket:
        with context.wrap_socket(
            raw_socket,
            server_hostname=host,
        ) as tls_socket:
            certificate = tls_socket.getpeercert()

            return {
                "host": host,
                "port": port,
                "tls_version": tls_socket.version(),
                "cipher": tls_socket.cipher()[0],
                "subject": certificate.get("subject", ()),
                "issuer": certificate.get("issuer", ()),
                "serial_number": certificate.get("serialNumber", ""),
                "not_before": _parse_certificate_time(
                    certificate["notBefore"]
                ),
                "not_after": _parse_certificate_time(
                    certificate["notAfter"]
                ),
            }
