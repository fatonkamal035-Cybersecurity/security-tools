"""Read-only file hash verification."""

import hashlib
import hmac
from pathlib import Path


DEFAULT_ALGORITHM = "sha256"


def verify_file_hash(
    path: str | Path,
    expected_hash: str,
    algorithm: str = DEFAULT_ALGORITHM,
    chunk_size: int = 1024 * 1024,
) -> bool:
    """Verify a file against an expected cryptographic hash."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    expected = expected_hash.strip().lower()

    if not expected:
        raise ValueError("expected_hash must not be empty")

    try:
        hasher = hashlib.new(algorithm)
    except ValueError:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}") from None

    file_path = Path(path)

    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(chunk_size), b""):
            hasher.update(chunk)

    actual = hasher.hexdigest()

    return hmac.compare_digest(actual, expected)
