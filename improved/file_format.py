"""
Improved versioned container format for authenticated streaming encryption.

Header structure:
  [0..3]    MAGIC: b"AGY2" (4 bytes)
  [4]       VERSION: 0x01 (1 byte)
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
  [111..]   ENCRYPTED_METADATA (METADATA_PAYLOAD_LEN bytes, including 16-byte tag)

Followed by framed stream chunks:
  [chunk]   CHUNK_PAYLOAD_LEN (uint32 big-endian)
            IS_LAST (uint8: 0=no, 1=yes)
            CHUNK_CIPHERTEXT (CHUNK_PAYLOAD_LEN bytes, including 16-byte tag)
"""

import struct
from dataclasses import dataclass
from typing import Optional

MAGIC_BYTES = b"AGY2"
FORMAT_VERSION = 1

KDF_ARGON2ID = 1

DEFAULT_TIME_COST = 2
DEFAULT_MEM_COST_KB = 64 * 1024  # 64 MB
DEFAULT_PARALLELISM = 4
DEFAULT_CHUNK_SIZE = 64 * 1024   # 64 KB

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
STREAM_NONCE_PREFIX_SIZE = 8
FILE_ID_SIZE = 8

FIXED_HEADER_FORMAT = ">4sBBHIB16s12s48s8s8sIH"
FIXED_HEADER_SIZE = struct.calcsize(FIXED_HEADER_FORMAT)


class ContainerFormatError(ValueError):
    """Raised when an improved container is malformed or invalid."""
    pass


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

    def serialize(self) -> bytes:
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
            raise ContainerFormatError(f"Invalid magic signature: {magic!r}, expected {MAGIC_BYTES!r}")
        if ver != FORMAT_VERSION:
            raise ContainerFormatError(f"Unsupported format version: {ver}")

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
    return prefix + struct.pack(">I", chunk_index)


def compute_chunk_aad(file_id: bytes, chunk_index: int, is_last: bool) -> bytes:
    """Builds authenticated associated data binding the chunk to its file, position, and status."""
    return file_id + struct.pack(">IB", chunk_index, 1 if is_last else 0)
