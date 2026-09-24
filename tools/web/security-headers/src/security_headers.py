"""Read-only security header analysis."""

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


def fetch_headers(url: str, timeout: float = 10.0) -> tuple[int, dict[str, str]]:
    """Fetch HTTP response headers using a read-only GET request."""
    request = urllib.request.Request(url, method="GET")

    with urllib.request.urlopen(request, timeout=timeout) as response:
        headers = {name: value for name, value in response.headers.items()}
        return response.status, headers
