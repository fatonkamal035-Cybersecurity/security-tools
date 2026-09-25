"""Read-only HTTP status and response metadata."""

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

    if not parsed.hostname:
        raise ValueError("URL must contain a hostname")

    try:
        addresses = {
            ipaddress.ip_address(info[4][0])
            for info in socket.getaddrinfo(
                parsed.hostname,
                parsed.port,
                type=socket.SOCK_STREAM,
            )
        }
    except (OSError, ValueError):
        raise ValueError("URL hostname could not be resolved") from None

    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("URL must resolve only to public IP addresses")

    return url


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent redirects from changing the destination."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("HTTP redirects are not allowed")


def check_http_status(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, object]:
    """Return HTTP status and basic response metadata."""
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    validated_url = _validate_url(url)

    request = urllib.request.Request(
        validated_url,
        headers={"User-Agent": "security-tools/http-status"},
        method="HEAD",
    )

    opener = urllib.request.build_opener(_NoRedirectHandler)

    with opener.open(request, timeout=timeout) as response:
        return {
            "url": validated_url,
            "status": response.status,
            "reason": response.reason,
            "content_type": response.headers.get("Content-Type", ""),
            "content_length": response.headers.get("Content-Length", ""),
        }
