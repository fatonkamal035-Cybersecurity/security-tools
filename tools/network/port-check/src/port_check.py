"""Read-only TCP port connectivity check."""

import socket


DEFAULT_TIMEOUT = 3.0


def check_tcp_port(
    host: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, object]:
    """Check whether a TCP connection can be established."""
    host = host.strip()

    if not host:
        raise ValueError("host must not be empty")

    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")

    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {
                "host": host,
                "port": port,
                "reachable": True,
            }
    except (ConnectionRefusedError, TimeoutError, OSError):
        return {
            "host": host,
            "port": port,
            "reachable": False,
        }
