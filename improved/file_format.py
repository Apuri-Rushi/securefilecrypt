"""
Improved versioned container format for authenticated streaming encryption.

Header structure (110 bytes fixed + variable encrypted metadata):
  [0..3]    MAGIC: b"AGY2" (4 bytes)
  [4]       VERSION: 0x01 or 0x02 (1 byte)
  [5]       KDF_ID: 0x01 (1 byte, 1=Argon2id)
  [6..7]    ARGON2_TIME_COST (uint16 big-endian)
  [8..11]   ARGON2_MEM_COST_KB (uint32 big-endian)
  [12]      ARGON2_PARALLELISM (uint8)
  [13..28]  SALT (16 bytes)
  [29..40]  KEK_NONCE (12 bytes)
  [41..88]  WRAPPED_DEK (48 bytes: 32 bytes DEK + 16 bytes GCM tag)
  [89..96]  STREAM_NONCE_PREFIX (8 bytes)
  [97..104] FILE_ID (8 bytes)
  [105..108] CHUNK_SIZE (uint32 big-endian)
  [109..110] METADATA_PAYLOAD_LEN (uint16 big-endian)
  [111..]   ENCRYPTED_METADATA (METADATA_PAYLOAD_LEN bytes, including 12B nonce + payload + 16B tag)

Followed by framed stream chunks:
  [chunk]   CHUNK_PAYLOAD_LEN (uint32 big-endian)
            IS_LAST (uint8: 0=no, 1=yes)
            CHUNK_CIPHERTEXT (CHUNK_PAYLOAD_LEN bytes, including 16-byte tag)

Version Innovations:
- Version 1 (Legacy): Wrapped DEK AAD binds only FILE_ID. Metadata is unpadded JSON.
- Version 2 (Current Default): Wrapped DEK AAD cryptographically binds the entire fixed header
  parameters (version, kdf_id, time_cost, mem_cost, parallelism, salt, stream_nonce_prefix,
  file_id, chunk_size). Metadata payload is block-padded to 64 bytes to eliminate filename length leakage.
"""

import struct
from dataclasses import dataclass
from typing import Optional, Set

MAGIC_BYTES = b"AGY2"

FORMAT_VERSION_1 = 1
FORMAT_VERSION_2 = 2
FORMAT_VERSION = FORMAT_VERSION_2
SUPPORTED_VERSIONS: Set[int] = {FORMAT_VERSION_1, FORMAT_VERSION_2}

KDF_ARGON2ID = 1

# Standard RFC 9106 recommended defaults
DEFAULT_TIME_COST = 2
DEFAULT_MEM_COST_KB = 64 * 1024  # 64 MB
DEFAULT_PARALLELISM = 4
DEFAULT_CHUNK_SIZE = 64 * 1024   # 64 KB

# Defensible bounds to prevent memory/computation exhaustion (parameter bombs)
MIN_TIME_COST = 1
MAX_TIME_COST = 10               # Defensive cap for interactive verification
MIN_MEM_COST_KB = 8 * 1024       # 8 MB min
MAX_MEM_COST_KB = 512 * 1024     # 512 MB defensive cap for memory DoS protection
MIN_PARALLELISM = 1
MAX_PARALLELISM = 8              # 8 thread max defensive bound
MIN_CHUNK_SIZE = 1024            # 1 KB min
MAX_CHUNK_SIZE = 64 * 1024 * 1024 # 64 MB max chunk size
MAX_METADATA_LEN = 65535         # uint16 max
METADATA_PADDING_BLOCK_SIZE = 64 # Obscures exact filename lengths

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
STREAM_NONCE_PREFIX_SIZE = 8
FILE_ID_SIZE = 8

FIXED_HEADER_FORMAT = ">4sBBHIB16s12s48s8s8sIH"
FIXED_HEADER_SIZE = struct.calcsize(FIXED_HEADER_FORMAT)


class ContainerFormatError(ValueError):
    """Raised when an improved container is malformed, corrupted, or violates security bounds."""
    pass


class InvalidMagicError(ContainerFormatError):
    """Raised when container does not start with AGY2 magic bytes."""
    pass


class UnsupportedVersionError(ContainerFormatError):
    """Raised when container format version is unknown or unsupported."""
    pass


class UnsupportedKdfError(ContainerFormatError):
    """Raised when container requests an unsupported KDF algorithm."""
    pass


class ParameterBoundsError(ContainerFormatError):
    """Raised when container parameters exceed defensible security bounds."""
    pass


def validate_kdf_parameters(time_cost: int, memory_cost_kb: int, parallelism: int) -> None:
    """Validates KDF parameters against strict denial-of-service bounds."""
    if not (MIN_TIME_COST <= time_cost <= MAX_TIME_COST):
        raise ParameterBoundsError(
            f"Argon2id time cost {time_cost} outside valid bounds [{MIN_TIME_COST}, {MAX_TIME_COST}]"
        )
    if not (MIN_MEM_COST_KB <= memory_cost_kb <= MAX_MEM_COST_KB):
        raise ParameterBoundsError(
            f"Argon2id memory cost {memory_cost_kb} KB outside safe bounds [{MIN_MEM_COST_KB}, {MAX_MEM_COST_KB}]"
        )
    if not (MIN_PARALLELISM <= parallelism <= MAX_PARALLELISM):
        raise ParameterBoundsError(
            f"Argon2id parallelism {parallelism} outside valid bounds [{MIN_PARALLELISM}, {MAX_PARALLELISM}]"
        )


def validate_chunk_size(chunk_size: int) -> None:
    """Validates chunk size against bounds."""
    if not (MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE):
        raise ParameterBoundsError(
            f"Chunk size {chunk_size} outside valid bounds [{MIN_CHUNK_SIZE}, {MAX_CHUNK_SIZE}]"
        )


def pad_metadata(data: bytes, block_size: int = METADATA_PADDING_BLOCK_SIZE) -> bytes:
    """Pads metadata bytes using PKCS#7 framing to obscure exact filename length."""
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def unpad_metadata(padded_data: bytes, block_size: int = METADATA_PADDING_BLOCK_SIZE) -> bytes:
    """Safely unpads metadata bytes, falling back to raw data if unpadded."""
    if not padded_data:
        return b""
    pad_len = padded_data[-1]
    if 1 <= pad_len <= block_size and len(padded_data) >= pad_len:
        if padded_data[-pad_len:] == bytes([pad_len]) * pad_len:
            return padded_data[:-pad_len]
    return padded_data


def compute_dek_aad(
    version: int,
    file_id: bytes,
    kdf_id: int = KDF_ARGON2ID,
    time_cost: int = DEFAULT_TIME_COST,
    memory_cost_kb: int = DEFAULT_MEM_COST_KB,
    parallelism: int = DEFAULT_PARALLELISM,
    salt: bytes = b"",
    stream_nonce_prefix: bytes = b"",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bytes:
    """
    Computes Authenticated Associated Data (AAD) for wrapping the DEK.
    
    Version 1: Uses file_id (legacy compatibility).
    Version 2: Cryptographically binds full container configuration header.
    """
    if version == FORMAT_VERSION_1:
        return file_id
    elif version == FORMAT_VERSION_2:
        return (
            b"AGY2-V2-DEK-WRAP:"
            + struct.pack(
                ">BBHIB16s8s8sI",
                version,
                kdf_id,
                time_cost,
                memory_cost_kb,
                parallelism,
                salt,
                stream_nonce_prefix,
                file_id,
                chunk_size,
            )
        )
    else:
        raise UnsupportedVersionError(f"Unsupported format version: {version}")


def compute_metadata_aad(version: int, file_id: bytes) -> bytes:
    """
    Computes Authenticated Associated Data (AAD) for metadata encryption.
    """
    if version == FORMAT_VERSION_1:
        return file_id
    elif version == FORMAT_VERSION_2:
        return b"AGY2-V2-META-WRAP:" + file_id
    else:
        raise UnsupportedVersionError(f"Unsupported format version: {version}")


@dataclass
class ContainerHeader:
    version: int
    kdf_id: int
    time_cost: int
    memory_cost_kb: int
    parallelism: int
    salt: bytes
    kek_nonce: bytes
    wrapped_dek: bytes
    stream_nonce_prefix: bytes
    file_id: bytes
    chunk_size: int
    metadata_len: int
    encrypted_metadata: bytes

    def get_dek_aad(self) -> bytes:
        """Returns the DEK wrapping AAD according to format version."""
        return compute_dek_aad(
            version=self.version,
            file_id=self.file_id,
            kdf_id=self.kdf_id,
            time_cost=self.time_cost,
            memory_cost_kb=self.memory_cost_kb,
            parallelism=self.parallelism,
            salt=self.salt,
            stream_nonce_prefix=self.stream_nonce_prefix,
            chunk_size=self.chunk_size,
        )

    def get_metadata_aad(self) -> bytes:
        """Returns metadata encryption AAD according to format version."""
        return compute_metadata_aad(self.version, self.file_id)

    def serialize(self) -> bytes:
        validate_kdf_parameters(self.time_cost, self.memory_cost_kb, self.parallelism)
        validate_chunk_size(self.chunk_size)
        fixed = struct.pack(
            FIXED_HEADER_FORMAT,
            MAGIC_BYTES,
            self.version,
            self.kdf_id,
            self.time_cost,
            self.memory_cost_kb,
            self.parallelism,
            self.salt,
            self.kek_nonce,
            self.wrapped_dek,
            self.stream_nonce_prefix,
            self.file_id,
            self.chunk_size,
            len(self.encrypted_metadata),
        )
        return fixed + self.encrypted_metadata

    @classmethod
    def deserialize(cls, data: bytes) -> "ContainerHeader":
        if len(data) < FIXED_HEADER_SIZE:
            raise ContainerFormatError(
                f"Header too short: {len(data)} bytes, expected at least {FIXED_HEADER_SIZE}"
            )

        magic, ver, kdf, t_cost, m_cost, paral, salt, kek_nonce, wrapped_dek, prefix, file_id, chunk_sz, meta_len = (
            struct.unpack_from(FIXED_HEADER_FORMAT, data, 0)
        )

        if magic != MAGIC_BYTES:
            raise InvalidMagicError(f"Invalid magic signature: {magic!r}, expected {MAGIC_BYTES!r}")
        if ver not in SUPPORTED_VERSIONS:
            raise UnsupportedVersionError(
                f"Unsupported format version: {ver}. Supported versions: {sorted(SUPPORTED_VERSIONS)}"
            )
        if kdf != KDF_ARGON2ID:
            raise UnsupportedKdfError(f"Unsupported KDF algorithm identifier: {kdf}")

        # Security bounds validation against parameter bombs
        validate_kdf_parameters(t_cost, m_cost, paral)
        validate_chunk_size(chunk_sz)

        min_meta_len = NONCE_SIZE + TAG_SIZE  # At minimum: 12B nonce + 16B GCM tag
        if meta_len < min_meta_len or meta_len > MAX_METADATA_LEN:
            raise ContainerFormatError(
                f"Encrypted metadata length {meta_len} outside valid bounds [{min_meta_len}, {MAX_METADATA_LEN}]"
            )

        expected_total = FIXED_HEADER_SIZE + meta_len
        if len(data) < expected_total:
            raise ContainerFormatError(
                f"Container truncated: expected {expected_total} bytes for header, got {len(data)}"
            )

        encrypted_metadata = data[FIXED_HEADER_SIZE:expected_total]

        return cls(
            version=ver,
            kdf_id=kdf,
            time_cost=t_cost,
            memory_cost_kb=m_cost,
            parallelism=paral,
            salt=salt,
            kek_nonce=kek_nonce,
            wrapped_dek=wrapped_dek,
            stream_nonce_prefix=prefix,
            file_id=file_id,
            chunk_size=chunk_sz,
            metadata_len=meta_len,
            encrypted_metadata=encrypted_metadata,
        )


def compute_chunk_nonce(prefix: bytes, chunk_index: int) -> bytes:
    """Derives a deterministic, strictly unique 12-byte IV for chunk index."""
    if len(prefix) != STREAM_NONCE_PREFIX_SIZE:
        raise ValueError(f"Prefix must be {STREAM_NONCE_PREFIX_SIZE} bytes")
    if not (0 <= chunk_index <= 0xFFFFFFFF):
        raise OverflowError(f"Chunk index {chunk_index} exceeds 32-bit uint maximum (2^32 - 1)")
    return prefix + struct.pack(">I", chunk_index)


def compute_chunk_aad(file_id: bytes, chunk_index: int, is_last: bool) -> bytes:
    """Builds authenticated associated data binding the chunk to its file, position, and status."""
    if len(file_id) != FILE_ID_SIZE:
        raise ValueError(f"File ID must be {FILE_ID_SIZE} bytes")
    if not (0 <= chunk_index <= 0xFFFFFFFF):
        raise OverflowError(f"Chunk index {chunk_index} exceeds 32-bit uint maximum (2^32 - 1)")
    return file_id + struct.pack(">IB", chunk_index, 1 if is_last else 0)


