"""
Automated Functional Tests for Baseline Implementation.

Verifies:
1. Round-trip byte-for-byte fidelity across small text, binary, PDF-like, and image-like files.
2. Empty file handling (0 bytes).
3. Nonce and salt randomness / freshness across identical plaintext and passwords.
4. Exact container structure compliance: [salt(16)][nonce(12)][ciphertext + tag].
"""

import hashlib
import os
import pytest
from baseline.crypto import encrypt_bytes, decrypt_bytes
from baseline.file_format import (
    unpack_container,
    SALT_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    MIN_CONTAINER_SIZE,
)


def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TestBaselineFunctional:
    """Functional correctness test suite for baseline file encryption and decryption."""

    def test_empty_file_roundtrip(self):
        """Confirm that an empty file (0 bytes) encrypts and decrypts with byte-for-byte equality."""
        plaintext = b""
        password = "SecurePassword123!"

        container = encrypt_bytes(plaintext, password)
        # Empty plaintext produces a container of exactly 16 (salt) + 12 (nonce) + 16 (tag) = 44 bytes
        assert len(container) == MIN_CONTAINER_SIZE

        salt, nonce, ciphertext = unpack_container(container)
        assert len(salt) == SALT_SIZE
        assert len(nonce) == NONCE_SIZE
        assert len(ciphertext) == TAG_SIZE

        restored = decrypt_bytes(container, password)
        assert restored == plaintext
        assert len(restored) == 0

    def test_small_text_roundtrip(self):
        """Confirm that a small text file (< 100 KB) encrypts and decrypts faithfully."""
        plaintext = ("The quick brown fox jumps over the lazy dog. " * 50).encode("utf-8")
        password = "CorrectHorseBatteryStaple"

        container = encrypt_bytes(plaintext, password)
        assert len(container) == len(plaintext) + MIN_CONTAINER_SIZE

        restored = decrypt_bytes(container, password)
        assert restored == plaintext
        assert sha256_hash(restored) == sha256_hash(plaintext)

    @pytest.mark.parametrize("size_bytes", [
        100 * 1024,         # 100 KB (~0.1 MB, matching F1)
        1250 * 1024,        # 1.25 MB (matching F2 PDF)
        3 * 1024 * 1024,    # 3 MB
    ])
    def test_binary_files_roundtrip(self, size_bytes):
        """Confirm that binary files of various sizes encrypt and restore with SHA-256 equality."""
        plaintext = os.urandom(size_bytes)
        password = f"TestPass_{size_bytes}"

        container = encrypt_bytes(plaintext, password)
        assert len(container) == size_bytes + MIN_CONTAINER_SIZE

        restored = decrypt_bytes(container, password)
        assert sha256_hash(restored) == sha256_hash(plaintext)

    def test_random_salt_and_nonce_freshness(self):
        """
        Confirm that encrypting the exact same plaintext with the exact same password
        produces distinct ciphertexts due to fresh CSPRNG salt and nonce generation.
        """
        plaintext = b"Deterministic payload to test probabilistic encryption output"
        password = "ConstantPassword456"

        container1 = encrypt_bytes(plaintext, password)
        container2 = encrypt_bytes(plaintext, password)

        # Whole container must differ
        assert container1 != container2

        # Salts must differ
        salt1, nonce1, ct1 = unpack_container(container1)
        salt2, nonce2, ct2 = unpack_container(container2)
        assert salt1 != salt2
        assert nonce1 != nonce2
        assert ct1 != ct2

        # Both decrypt back to identical plaintext
        assert decrypt_bytes(container1, password) == plaintext
        assert decrypt_bytes(container2, password) == plaintext

    def test_container_exact_structure(self):
        """Confirm that the container layout strictly follows [salt (16)][nonce (12)][ciphertext]."""
        plaintext = b"Payload structure validation"
        password = "LayoutTestPassword"

        container = encrypt_bytes(plaintext, password)
        salt, nonce, ciphertext_with_tag = unpack_container(container)

        assert len(salt) == 16
        assert len(nonce) == 12
        assert len(ciphertext_with_tag) == len(plaintext) + 16
        assert container[:16] == salt
        assert container[16:28] == nonce
        assert container[28:] == ciphertext_with_tag
