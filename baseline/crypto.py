"""
Baseline cryptographic operations module.

Faithfully implements the cryptographic primitives described in:
Rosandi et al. (2026):
- Key derivation: PBKDF2-HMAC-SHA256 with random salt
- Encryption algorithm: AES-256-GCM (Galois/Counter Mode)
- Authentication: Built-in GCM integrity tag verification

Reconstruction assumptions:
- Iteration count: 100,000 (compliant with NIST SP 800-132 recommendation for PBKDF2-SHA256)
- Salt size: 16 bytes (128 bits)
- Nonce size: 12 bytes (96 bits)
- Key size: 32 bytes (256 bits)
"""

import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from baseline.file_format import (
    SALT_SIZE,
    NONCE_SIZE,
    pack_container,
    unpack_container,
    InvalidContainerError,
)

PBKDF2_ITERATIONS = 100_000
KEY_SIZE_BYTES = 32  # 256 bits


class CryptographicError(Exception):
    """Base exception for cryptographic errors."""
    pass


class AuthenticationError(CryptographicError):
    """Raised when authentication fails (incorrect password or corrupted data)."""
    pass


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Derives a 256-bit AES key using PBKDF2-HMAC-SHA256.

    Args:
        password: The user-supplied passphrase.
        salt: Cryptographic salt bytes (16 bytes).
        iterations: Number of PBKDF2 iterations (default: 100,000).

    Returns:
        32-byte derived key.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("Salt must be bytes or bytearray")
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt must be {SALT_SIZE} bytes")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE_BYTES,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    """
    Encrypts plaintext bytes using AES-256-GCM with a PBKDF2-derived key.

    Workflow:
    1. Generate 16-byte random salt.
    2. Derive 256-bit key from password and salt via PBKDF2-HMAC-SHA256.
    3. Generate 12-byte random nonce for AES-GCM.
    4. Encrypt plaintext using AES-256-GCM (produces ciphertext + 16-byte tag).
    5. Pack container in order [salt][nonce][ciphertext].

    Returns:
        Packed .enc file bytes.
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("Plaintext must be bytes or bytearray")
    if not password:
        raise ValueError("Password cannot be empty")

    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    nonce = os.urandom(NONCE_SIZE)

    aesgcm = AESGCM(key)
    # In cryptography library, encrypt appends the 16-byte GCM authentication tag
    ciphertext = aesgcm.encrypt(nonce, bytes(plaintext), None)

    return pack_container(salt, nonce, ciphertext)


def decrypt_bytes(encrypted_container: bytes, password: str) -> bytes:
    """
    Decrypts an .enc container using AES-256-GCM with a PBKDF2-derived key.

    Workflow:
    1. Unpack container into salt, nonce, and ciphertext.
    2. Derive 256-bit key from password and extracted salt.
    3. Authenticate and decrypt ciphertext using AES-256-GCM.
    4. If authentication fails, raise AuthenticationError without returning plaintext.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        AuthenticationError: If password is incorrect or data is tampered/corrupted.
        InvalidContainerError: If container is malformed or truncated.
    """
    if not password:
        raise ValueError("Password cannot be empty")

    try:
        salt, nonce, ciphertext = unpack_container(encrypted_container)
    except InvalidContainerError as e:
        raise InvalidContainerError(f"Malformed or truncated container: {e}") from e

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
    except InvalidTag as e:
        raise AuthenticationError(
            "Decryption failed: Incorrect password or corrupted/tampered file."
        ) from e
