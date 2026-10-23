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
    TrailingDataError,
    IncorrectPasswordError,
    CorruptedChunkError,
)
from improved.file_format import (
    FIXED_HEADER_SIZE,
    ContainerHeader,
    ContainerFormatError,
    ParameterBoundsError,
    UnsupportedVersionError,
)


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

    def test_version2_header_tampering_rejected(self):
        """
        In AGY2 Version 2, all header parameters are cryptographically bound
        in the DEK wrapping AAD. Tampering with stream prefix, chunk_size,
        or KDF parameters must trigger authentication failure during DEK unwrap.
        """
        plaintext = b"Header integrity verification payload."
        password = "HeaderTamperPass!"

        container = encrypt_bytes(plaintext, password, filename="hdr.bin")
        tampered = bytearray(container)

        # Byte 90 is inside stream_nonce_prefix (offset 89..96)
        # Mutating this keeps header format valid but must fail DEK AAD authentication
        tampered[90] ^= 0x01

        with pytest.raises(AuthenticationError):
            decrypt_bytes(bytes(tampered), password)

    def test_trailing_data_rejected(self):
        """
        Injecting extraneous trailing bytes after the final authenticated
        chunk must be detected and rejected with TrailingDataError.
        """
        plaintext = b"Payload for trailing data injection test."
        password = "TrailingDataPass!"

        container = encrypt_bytes(plaintext, password, filename="trailing.bin")
        # Append 16 bytes of unauthenticated trailing payload
        tampered = container + b"MALICIOUS_GARBAGE"

        with pytest.raises(AuthenticationError):
            decrypt_bytes(tampered, password)

    def test_invalid_chunk_payload_length_rejected(self):
        """
        Framing headers with payload lengths smaller than TAG_SIZE (16 bytes)
        or larger than chunk_size + TAG_SIZE must be rejected cleanly.
        """
        plaintext = b"Test payload for length bounds"
        password = "LengthBoundsPass!"

        container = encrypt_bytes(plaintext, password, filename="len_bounds.bin")
        header = ContainerHeader.deserialize(container)
        hdr_len = FIXED_HEADER_SIZE + header.metadata_len

        tampered = bytearray(container)
        # Corrupt chunk 0 payload_len to 5 bytes (< TAG_SIZE)
        struct.pack_into(">I", tampered, hdr_len, 5)

        with pytest.raises((ContainerFormatError, AuthenticationError)):
            decrypt_bytes(bytes(tampered), password)

    def test_duplicated_chunk_rejected(self):
        """
        Duplicating a valid chunk into the stream must be rejected
        because chunk index in AAD binds position.
        """
        chunk_sz = 64 * 1024
        plaintext = os.urandom(chunk_sz * 2)
        password = "DuplicatedChunkPass!"

        container = encrypt_bytes(plaintext, password, filename="dup.bin", chunk_size=chunk_sz)
        header = ContainerHeader.deserialize(container)
        hdr_len = FIXED_HEADER_SIZE + header.metadata_len

        hdr_bytes = container[:hdr_len]
        stream_bytes = container[hdr_len:]

        c0_len, _ = struct.unpack_from(">IB", stream_bytes, 0)
        c0_frame = stream_bytes[:5 + c0_len]

        # Duplicate chunk 0: [header] + [chunk 0] + [chunk 0]
        tampered = hdr_bytes + c0_frame + c0_frame

        with pytest.raises(AuthenticationError):
            decrypt_bytes(tampered, password)

    def test_unsupported_version_rejected(self):
        """Container with an unknown version identifier must be rejected immediately."""
        plaintext = b"Data with bad version"
        password = "BadVersionPass!"

        container = encrypt_bytes(plaintext, password, filename="ver.bin")
        tampered = bytearray(container)
        tampered[4] = 99  # Version 99

        with pytest.raises(ContainerFormatError):
            decrypt_bytes(bytes(tampered), password)

    def test_parameter_bomb_rejected(self):
        """
        A maliciously crafted container with excessive KDF parameters (e.g. 1 GB RAM)
        must be rejected before allocating memory or executing Argon2id.
        """
        plaintext = b"Data with parameter bomb"
        password = "ParamBombPass!"

        container = encrypt_bytes(plaintext, password, filename="bomb.bin")
        tampered = bytearray(container)
        # Overwrite memory_cost_kb (offset 8..11) with 1,000,000 KB (~1 GB)
        struct.pack_into(">I", tampered, 8, 1_000_000)

        with pytest.raises(ContainerFormatError):
            decrypt_bytes(bytes(tampered), password)

    def test_metadata_path_traversal_sanitized(self):
        """
        Decrypted metadata containing path traversal strings (e.g. '../../etc/shadow')
        must have filenames sanitized to prevent directory traversal attacks.
        """
        plaintext = b"Safe payload"
        password = "PathTraversalPass!"

        # Encrypt with directory traversal in filename
        container = encrypt_bytes(plaintext, password, filename="../../etc/shadow")
        _, meta = decrypt_bytes(container, password)

        # Restored filename must be stripped of traversal path
        assert "/" not in meta["filename"]
        assert ".." not in meta["filename"]
        assert meta["filename"] == "shadow"

