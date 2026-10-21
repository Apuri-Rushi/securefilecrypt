"""
Automated Security Tests for Baseline Implementation.

Verifies:
1. Rejection of incorrect passwords (negative testing matching paper).
2. Detection and rejection of modified ciphertext (integrity).
3. Detection and rejection of modified nonce (AEAD tag mismatch).
4. Detection and rejection of modified salt.
5. Detection and safe rejection of truncated/malformed containers.
6. Zero plaintext leakage upon authentication failure.
7. Disallowance of empty passwords.
"""

import os
import pytest
from baseline.crypto import (
    encrypt_bytes,
    decrypt_bytes,
    AuthenticationError,
)
from baseline.file_format import (
    unpack_container,
    pack_container,
    InvalidContainerError,
    MIN_CONTAINER_SIZE,
)


class TestBaselineSecurity:
    """Security and negative test suite for baseline file encryption and decryption."""

    def test_wrong_password_rejected(self):
        """Negative test per paper: wrong password must raise AuthenticationError without returning data."""
        plaintext = b"Sensitive corporate financial statement."
        correct_password = "CorrectPassphrase2026!"
        wrong_password = "WrongPassphrase2026!"

        container = encrypt_bytes(plaintext, correct_password)

        with pytest.raises(AuthenticationError) as exc_info:
            decrypt_bytes(container, wrong_password)
        assert "Incorrect password" in str(exc_info.value) or "corrupted" in str(exc_info.value)

    def test_tampered_ciphertext_rejected(self):
        """Tampering with a single bit in the ciphertext must trigger an authentication failure."""
        plaintext = b"Unmodified critical payload"
        password = "PassphraseTestTag1"

        container = encrypt_bytes(plaintext, password)
        salt, nonce, ct = unpack_container(container)

        # Flip one bit in the middle of the ciphertext
        tampered_ct = bytearray(ct)
        tampered_ct[len(tampered_ct) // 2] ^= 0x01
        tampered_container = pack_container(salt, nonce, bytes(tampered_ct))

        with pytest.raises(AuthenticationError):
            decrypt_bytes(tampered_container, password)

    def test_tampered_nonce_rejected(self):
        """Tampering with the AES-GCM nonce must trigger an authentication failure."""
        plaintext = b"Nonce integrity verification test payload"
        password = "PassphraseNonceTest"

        container = encrypt_bytes(plaintext, password)
        salt, nonce, ct = unpack_container(container)

        # Corrupt the nonce
        tampered_nonce = bytearray(nonce)
        tampered_nonce[0] ^= 0xFF
        tampered_container = pack_container(salt, bytes(tampered_nonce), ct)

        with pytest.raises(AuthenticationError):
            decrypt_bytes(tampered_container, password)

    def test_tampered_salt_rejected(self):
        """Modifying the salt leads to an incorrect derived key, failing authentication."""
        plaintext = b"Salt integrity test payload"
        password = "PassphraseSaltTest"

        container = encrypt_bytes(plaintext, password)
        salt, nonce, ct = unpack_container(container)

        tampered_salt = bytearray(salt)
        tampered_salt[0] ^= 0x01
        tampered_container = pack_container(bytes(tampered_salt), nonce, ct)

        with pytest.raises(AuthenticationError):
            decrypt_bytes(tampered_container, password)

    def test_truncated_container_rejected(self):
        """A container shorter than 44 bytes must raise InvalidContainerError."""
        for short_len in [0, 1, 15, 16, 27, 28, 43]:
            short_data = b"X" * short_len
            with pytest.raises(InvalidContainerError):
                decrypt_bytes(short_data, "AnyPassword")

    def test_truncated_ciphertext_rejected(self):
        """Truncating the authentication tag or ciphertext bytes must fail securely."""
        plaintext = b"Longer payload designed to test truncation detection in baseline."
        password = "TruncationPassword"

        container = encrypt_bytes(plaintext, password)
        # Drop last 4 bytes (corrupts the 16-byte authentication tag)
        truncated_container = container[:-4]

        with pytest.raises(AuthenticationError):
            decrypt_bytes(truncated_container, password)

    def test_empty_password_rejected(self):
        """Empty passwords must be rejected at encryption and decryption time."""
        plaintext = b"Payload without password"
        with pytest.raises(ValueError, match="Password cannot be empty"):
            encrypt_bytes(plaintext, "")

        dummy_container = b"A" * MIN_CONTAINER_SIZE
        with pytest.raises(ValueError, match="Password cannot be empty"):
            decrypt_bytes(dummy_container, "")

    def test_no_plaintext_leakage_on_failure(self):
        """Verify that on any failure, no plaintext fragment is returned or persisted."""
        plaintext = b"Top secret classified memo"
        password = "RealPassword999"

        container = encrypt_bytes(plaintext, password)

        result = None
        try:
            result = decrypt_bytes(container, "BadPassword")
        except AuthenticationError:
            pass

        assert result is None, "Plaintext was leaked despite authentication failure!"
