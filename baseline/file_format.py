"""
Baseline file format module.

Faithfully implements the container packaging order specified in:
Rosandi et al. (2026): "[salt][nonce][ciphertext]"

Reconstruction Parameters:
- Salt length: 16 bytes (128 bits)
- Nonce length: 12 bytes (96 bits, standard AES-GCM IV)
- Authentication tag: 16 bytes (128 bits, appended to ciphertext by AESGCM)
- Minimum container size: 16 + 12 + 16 = 44 bytes (for empty plaintext)
"""

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
MIN_CONTAINER_SIZE = SALT_SIZE + NONCE_SIZE + TAG_SIZE


class InvalidContainerError(ValueError):
    """Raised when an encrypted container is truncated or structurally invalid."""
    pass


def pack_container(salt: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Packs cryptographic components into the baseline .enc file format.

    Order: [salt (16 B)][nonce (12 B)][ciphertext (variable B including tag)]
    """
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt must be exactly {SALT_SIZE} bytes, got {len(salt)}")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be exactly {NONCE_SIZE} bytes, got {len(nonce)}")
    if len(ciphertext) < TAG_SIZE:
        raise ValueError(f"Ciphertext must include at least {TAG_SIZE}-byte authentication tag")

    return salt + nonce + ciphertext


def unpack_container(data: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Unpacks the baseline .enc container into (salt, nonce, ciphertext).

    Raises:
        InvalidContainerError: If container length is below MIN_CONTAINER_SIZE.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Container data must be bytes or bytearray")

    if len(data) < MIN_CONTAINER_SIZE:
        raise InvalidContainerError(
            f"Container too short: {len(data)} bytes. "
            f"Minimum required is {MIN_CONTAINER_SIZE} bytes (16 salt + 12 nonce + 16 tag)."
        )

    salt = bytes(data[:SALT_SIZE])
    nonce = bytes(data[SALT_SIZE:SALT_SIZE + NONCE_SIZE])
    ciphertext = bytes(data[SALT_SIZE + NONCE_SIZE:])

    return salt, nonce, ciphertext
