"""
Automated Functional Tests for Improved Implementation.

Verifies:
1. Round-trip byte-for-byte fidelity across empty, text, and multi-megabyte binary files.
2. Metadata preservation (confidential filename, MIME type).
3. CSPRNG freshness of salts, DEKs, KEK nonces, and stream prefixes.
"""

import hashlib
import os
import pytest
from improved.crypto import encrypt_bytes, decrypt_bytes
from improved.file_format import ContainerHeader, FIXED_HEADER_SIZE


def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TestImprovedFunctional:
    """Functional correctness test suite for improved file encryption and decryption."""

    def test_empty_file_roundtrip(self):
        """Confirm that an empty file (0 bytes) roundtrips faithfully with metadata."""
        plaintext = b""
        password = "Argon2Password123!"
        fname = "empty_test.txt"

        container = encrypt_bytes(plaintext, password, filename=fname, mime_type="text/plain")
        assert len(container) > FIXED_HEADER_SIZE

        restored, meta = decrypt_bytes(container, password)
        assert restored == plaintext
        assert meta["filename"] == fname
        assert meta["mime_type"] == "text/plain"

    def test_small_text_roundtrip(self):
        """Confirm small text file roundtrips faithfully."""
        plaintext = "Cryptographic integrity is paramount for file security.\n" * 100
        plaintext_bytes = plaintext.encode("utf-8")
        password = "PassphraseAlpha"
        fname = "manifesto.txt"

        container = encrypt_bytes(plaintext_bytes, password, filename=fname)
        restored, meta = decrypt_bytes(container, password)

        assert restored == plaintext_bytes
        assert sha256_hash(restored) == sha256_hash(plaintext_bytes)
        assert meta["filename"] == fname

    @pytest.mark.parametrize("size_bytes", [
        100 * 1024,       # 100 KB
        1250 * 1024,      # 1.25 MB
        5 * 1024 * 1024,  # 5 MB (crosses multiple 64 KB chunks)
    ])
    def test_binary_files_roundtrip(self, size_bytes):
        """Confirm binary files spanning multiple chunks roundtrip with exact SHA-256 match."""
        plaintext = os.urandom(size_bytes)
        password = f"TestPass_{size_bytes}"
        fname = f"sample_data_{size_bytes}.bin"

        container = encrypt_bytes(plaintext, password, filename=fname)
        restored, meta = decrypt_bytes(container, password)

        assert sha256_hash(restored) == sha256_hash(plaintext)
        assert meta["filename"] == fname

    def test_cryptographic_freshness(self):
        """Confirm repeated encryption of same data produces unique containers, salts, and DEKs."""
        plaintext = b"Payload for probabilistic verification"
        password = "ConstantPassword789"

        c1 = encrypt_bytes(plaintext, password, filename="test.dat")
        c2 = encrypt_bytes(plaintext, password, filename="test.dat")

        assert c1 != c2

        h1 = ContainerHeader.deserialize(c1)
        h2 = ContainerHeader.deserialize(c2)

        # Salts, KEK nonces, wrapped DEKs, and stream prefixes must all be independent
        assert h1.salt != h2.salt
        assert h1.kek_nonce != h2.kek_nonce
        assert h1.wrapped_dek != h2.wrapped_dek
        assert h1.stream_nonce_prefix != h2.stream_nonce_prefix
        assert h1.file_id != h2.file_id
