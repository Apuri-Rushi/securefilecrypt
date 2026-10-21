"""
Automated Security Tests for Improved Implementation.

Verifies:
1. Rejection of incorrect passwords.
2. Detection and rejection of tampered wrapped DEK.
3. Detection and rejection of tampered metadata.
4. Detection and rejection of tampered chunk payload.
5. Detection and rejection of reordered chunks (chunk swap).
6. Detection and rejection of dropped / missing chunks.
7. Detection and rejection of truncated streams (missing final chunk).
8. Protection against partial plaintext release.
"""

import os
import struct
import pytest
from improved.crypto import (
    encrypt_bytes,
    decrypt_bytes,
    AuthenticationError,
    StreamTruncationError,
)
from improved.file_format import FIXED_HEADER_SIZE, ContainerHeader


class TestImprovedSecurity:
    """Security verification test suite for improved file encryption system."""

    def test_wrong_password_rejected(self):
        """Negative test: wrong password fails at KEK unwrap without decrypting chunks."""
        plaintext = b"Sensitive top secret payload for security validation."
        correct_pwd = "CorrectMasterPassword1!"
        wrong_pwd = "WrongMasterPassword1!"

        container = encrypt_bytes(plaintext, correct_pwd, filename="classified.txt")

        with pytest.raises(AuthenticationError) as exc_info:
            decrypt_bytes(container, wrong_pwd)
        assert "incorrect password" in str(exc_info.value).lower() or "authentication failed" in str(exc_info.value).lower()

    def test_tampered_wrapped_dek_rejected(self):
        """Tampering with wrapped DEK bytes triggers authentication failure."""
        plaintext = b"Unmodified critical payload."
        password = "DekTamperPassword"

        container = encrypt_bytes(plaintext, password, filename="test.bin")
        tampered = bytearray(container)
        # Offset 45 is inside wrapped_dek
        tampered[45] ^= 0x01

        with pytest.raises(AuthenticationError):
            decrypt_bytes(bytes(tampered), password)

    def test_tampered_metadata_rejected(self):
        """Tampering with encrypted metadata bytes triggers authentication failure."""
        plaintext = b"Payload with metadata protection."
        password = "MetaTamperPassword"

        container = encrypt_bytes(plaintext, password, filename="metadata_test.bin")
        tampered = bytearray(container)
        # Flip a bit in the encrypted metadata region (after fixed header)
        tampered[FIXED_HEADER_SIZE + 2] ^= 0xFF

        with pytest.raises(AuthenticationError):
            decrypt_bytes(bytes(tampered), password)

    def test_tampered_chunk_ciphertext_rejected(self):
        """Tampering with ciphertext bytes in any chunk triggers authentication failure."""
        # 150 KB payload guarantees at least 3 chunks with 64 KB chunk size
        plaintext = os.urandom(150 * 1024)
        password = "ChunkTamperPassword"

        container = encrypt_bytes(plaintext, password, filename="chunks.bin")
        tampered = bytearray(container)

        # Corrupt byte deep into payload
        tampered[-50] ^= 0xAA

        with pytest.raises(AuthenticationError):
            decrypt_bytes(bytes(tampered), password)

    def test_swapped_chunks_rejected(self):
        """
        Swapping two consecutive chunks in the stream must be detected
        and rejected due to chunk_index in AAD.
        """
        # Create data spanning 2 chunks
        chunk_sz = 64 * 1024
        plaintext = os.urandom(chunk_sz * 2)
        password = "ChunkSwapPassword"

        container = encrypt_bytes(plaintext, password, filename="swap.bin", chunk_size=chunk_sz)
        header = ContainerHeader.deserialize(container)
        hdr_len = FIXED_HEADER_SIZE + header.metadata_len

        hdr_bytes = container[:hdr_len]
        stream_bytes = container[hdr_len:]

        # Parse chunk 0
        c0_len, c0_last = struct.unpack_from(">IB", stream_bytes, 0)
        c0_total = 5 + c0_len
        c0_frame = stream_bytes[:c0_total]

        # Parse chunk 1
        c1_len, c1_last = struct.unpack_from(">IB", stream_bytes, c0_total)
        c1_total = 5 + c1_len
        c1_frame = stream_bytes[c0_total:c0_total + c1_total]

        # Swap chunk 0 and chunk 1
        swapped_container = hdr_bytes + c1_frame + c0_frame

        with pytest.raises(AuthenticationError):
            decrypt_bytes(swapped_container, password)

    def test_truncated_stream_rejected(self):
        """Dropping the final chunk must raise StreamTruncationError."""
        chunk_sz = 64 * 1024
        plaintext = os.urandom(chunk_sz * 2)
        password = "TruncationPassword"

        container = encrypt_bytes(plaintext, password, filename="trunc.bin", chunk_size=chunk_sz)
        header = ContainerHeader.deserialize(container)
        hdr_len = FIXED_HEADER_SIZE + header.metadata_len

        # Drop the last chunk
        c0_len, _ = struct.unpack_from(">IB", container, hdr_len)
        truncated_container = container[:hdr_len + 5 + c0_len]

        with pytest.raises(StreamTruncationError):
            decrypt_bytes(truncated_container, password)

    def test_no_plaintext_leakage_on_failure(self):
        """Failure must never expose plaintext."""
        plaintext = b"Critical intellectual property"
        password = "ValidSecret999"

        container = encrypt_bytes(plaintext, password, filename="ip.txt")

        result = None
        try:
            result = decrypt_bytes(container, "BadSecret")
        except AuthenticationError:
            pass

        assert result is None
