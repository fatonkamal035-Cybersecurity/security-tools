"""Read-only robots.txt retrieval."""

import ipaddress
import socket
import urllib.parse
import urllib.request


DEFAULT_TIMEOUT = 5.0


def _validate_url(url: str) -> str:
    """Validate an HTTP(S) URL and reject non-public destinations."""
    parsed = urllib.parse.urlsplit(url)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("only http and https URLs are allowed")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed")

    if parsed.query or parsed.fragment:
        raise ValueError("query strings and fragments are not allowed")

    hostname = parsed.hostname

    if not hostname:
        raise ValueError("URL must contain a hostname")

    try:
        addresses = {
            ipaddress.ip_address(info[4][0])
            for info in socket.getaddrinfo(
                hostname,
                parsed.port,
                type=socket.SOCK_STREAM,
            )
        }
    except (OSError, ValueError):
        raise ValueError("URL hostname could not be resolved") from None

    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("URL must resolve only to public IP addresses")

    return urllib.parse.urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc,
            "/robots.txt",
            "",
            "",
        )
    )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent redirects from bypassing destination validation."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("HTTP redirects are not allowed")


def fetch_robots(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[int, str]:
    """Fetch robots.txt from a validated public HTTP(S) origin."""
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    robots_url = _validate_url(url)

    request = urllib.request.Request(
        robots_url,
        headers={"User-Agent": "security-tools/robots-info"},
        method="GET",
    )

    opener = urllib.request.build_opener(_NoRedirectHandler)

    with opener.open(request, timeout=timeout) as response:
        content = response.read().decode("utf-8", errors="replace")
        return response.status, content
