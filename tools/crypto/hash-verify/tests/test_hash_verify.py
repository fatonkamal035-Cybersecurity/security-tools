import hashlib
import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from hash_verify import verify_file_hash


def test_verify_file_hash_matches_sha256(tmp_path):
    test_file = tmp_path / "sample.txt"
    data = b"security-tools"
    test_file.write_bytes(data)

    expected = hashlib.sha256(data).hexdigest()

    assert verify_file_hash(test_file, expected) is True


def test_verify_file_hash_rejects_wrong_hash(tmp_path):
    test_file = tmp_path / "sample.txt"
    test_file.write_bytes(b"security-tools")

    assert verify_file_hash(test_file, "0" * 64) is False


def test_verify_file_hash_supports_sha512(tmp_path):
    test_file = tmp_path / "sample.txt"
    data = b"security-tools"
    test_file.write_bytes(data)

    expected = hashlib.sha512(data).hexdigest()

    assert verify_file_hash(test_file, expected, "sha512") is True


def test_verify_file_hash_normalizes_expected_hash(tmp_path):
    test_file = tmp_path / "sample.txt"
    data = b"security-tools"
    test_file.write_bytes(data)

    expected = hashlib.sha256(data).hexdigest().upper()

    assert verify_file_hash(test_file, f"  {expected}  ") is True


def test_verify_file_hash_rejects_empty_expected_hash(tmp_path):
    test_file = tmp_path / "sample.txt"
    test_file.write_bytes(b"test")

    with pytest.raises(ValueError, match="expected_hash"):
        verify_file_hash(test_file, "")


def test_verify_file_hash_rejects_invalid_algorithm(tmp_path):
    test_file = tmp_path / "sample.txt"
    test_file.write_bytes(b"test")

    with pytest.raises(ValueError, match="Unsupported hash algorithm"):
        verify_file_hash(test_file, "0" * 64, "not-a-real-hash")


def test_verify_file_hash_rejects_invalid_chunk_size(tmp_path):
    test_file = tmp_path / "sample.txt"
    test_file.write_bytes(b"test")

    with pytest.raises(ValueError, match="chunk_size"):
        verify_file_hash(test_file, "0" * 64, chunk_size=0)


def test_verify_file_hash_missing_file(tmp_path):
    missing_file = tmp_path / "missing.txt"

    with pytest.raises(FileNotFoundError):
        verify_file_hash(missing_file, "0" * 64)
