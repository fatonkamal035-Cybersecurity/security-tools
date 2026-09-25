"""Read-only file integrity hashing."""

import hashlib
from pathlib import Path


DEFAULT_ALGORITHM = "sha256"


def calculate_file_hash(
    path: str | Path,
    algorithm: str = DEFAULT_ALGORITHM,
    chunk_size: int = 1024 * 1024,
) -> str:
    """Calculate a cryptographic hash of a file."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    try:
        hasher = hashlib.new(algorithm)
    except ValueError:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}") from None

    file_path = Path(path)

    with file_path.open("rb") as file:
        for chunk in iter(lambda: file.read(chunk_size), b""):
            hasher.update(chunk)

    return hasher.hexdigest()
