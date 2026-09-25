"""Read-only security header analysis."""

import ipaddress
import socket
import urllib.parse
import urllib.request

RECOMMENDED_HEADERS = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


def check_security_headers(headers: dict[str, str]) -> list[dict[str, str | bool]]:
    """Check whether recommended security headers are present."""
    normalized_headers = {name.lower(): value for name, value in headers.items()}
    results = []

    for header in RECOMMENDED_HEADERS:
        value = normalized_headers.get(header.lower(), "")
        results.append(
            {
                "header": header,
                "present": bool(value),
                "value": value,
            }
        )

    return results


def _validate_url(url: str) -> None:
    """Reject unsupported schemes, credentials, and non-public destinations."""
    parsed = urllib.parse.urlsplit(url)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http and https URLs are allowed")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed")

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


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent redirects from bypassing destination validation."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("HTTP redirects are not allowed")


def fetch_headers(url: str, timeout: float = 10.0) -> tuple[int, dict[str, str]]:
    """Fetch HTTP response headers from a validated public HTTP(S) URL."""
    _validate_url(url)
    request = urllib.request.Request(url, method="GET")
    opener = urllib.request.build_opener(_NoRedirectHandler)

    with opener.open(request, timeout=timeout) as response:
        headers = {name: value for name, value in response.headers.items()}
        return response.status, headers
