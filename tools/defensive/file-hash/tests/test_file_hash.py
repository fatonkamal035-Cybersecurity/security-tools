import hashlib
import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from file_hash import calculate_file_hash


def test_calculate_file_hash_sha256(tmp_path):
    test_file = tmp_path / "sample.txt"
    test_file.write_bytes(b"security-tools")

    expected = hashlib.sha256(b"security-tools").hexdigest()

    assert calculate_file_hash(test_file) == expected


def test_calculate_file_hash_supports_sha512(tmp_path):
    test_file = tmp_path / "sample.txt"
    test_file.write_bytes(b"security-tools")

    expected = hashlib.sha512(b"security-tools").hexdigest()

    assert calculate_file_hash(test_file, "sha512") == expected


def test_calculate_file_hash_reads_binary_data(tmp_path):
    test_file = tmp_path / "binary.bin"
    data = bytes(range(256))
    test_file.write_bytes(data)

    expected = hashlib.sha256(data).hexdigest()

    assert calculate_file_hash(test_file) == expected


def test_calculate_file_hash_rejects_invalid_algorithm(tmp_path):
    test_file = tmp_path / "sample.txt"
    test_file.write_bytes(b"test")

    with pytest.raises(ValueError, match="Unsupported hash algorithm"):
        calculate_file_hash(test_file, "not-a-real-hash")


def test_calculate_file_hash_rejects_invalid_chunk_size(tmp_path):
    test_file = tmp_path / "sample.txt"
    test_file.write_bytes(b"test")

    with pytest.raises(ValueError, match="chunk_size"):
        calculate_file_hash(test_file, chunk_size=0)


def test_calculate_file_hash_missing_file(tmp_path):
    missing_file = tmp_path / "missing.txt"

    with pytest.raises(FileNotFoundError):
        calculate_file_hash(missing_file)
