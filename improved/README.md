# Improved Cryptographic File System Implementation (AGY2)

This directory contains the advanced, experimentally validated implementation extending Rosandi et al. (2026).

---

## 1. Architectural Improvements Overview

| Area | Baseline System (Rosandi et al.) | Final Improved System (AGY2 v2) | Cryptographic & System Advantage |
| :--- | :--- | :--- | :--- |
| **Key Derivation** | PBKDF2-HMAC-SHA256 (100k iter) | **Argon2id (RFC 9106)** ($64\text{ MB}$, $t=2$, $p=4$) | Memory-hardness defeats GPU/ASIC parallelized dictionary cracking. |
| **KDF Defense Bounds** | None | **Strict Parameter Bounds** ($\le 512\text{ MB}$, $\le 10$ iter) | Prevents parameter bomb computational denial-of-service attacks. |
| **Payload Encryption** | Monolithic single-shot AES-256-GCM | **Chunked AEAD Streaming** ($64\text{ KB}$ default) | Peak RAM is strictly $O(1)$ ($< 0.3\text{ MB}$ constant), preventing OOM on large files. |
| **Streaming Integrity** | Single file-end MAC | **Per-Chunk AEAD Framing + Trailing Detection** | Nonce derived via CSPRNG prefix + uint32 counter. AAD binds `file_id`, `chunk_index`, and `is_last`. Verifies zero trailing garbage. |
| **Header Binding** | None | **Full Header AAD Cryptographic Binding** | In AGY2 v2, DEK wrapping AAD binds full header configuration parameters, detecting tampering before chunk decryption. |
| **Key Hierarchy** | Single password-derived key | **Envelope Encryption (DEK + KEK)** | Random 256-bit DEK encrypts data; Argon2id KEK wraps DEK. Enables instantaneous $O(1)$ password rotation. |
| **Metadata Privacy** | Plaintext filename guessing | **Encrypted & Block-Padded Header** | Filename and MIME type encrypted under KEK with 64-byte block padding to obscure filename lengths. |
| **File I/O Reliability** | In-place overwrite | **Atomic Operations & 0600 Permissions** | Temporary file staging + atomic replace (`os.replace`) with zero partial plaintext leakage on failure. |

---

## 2. Container Format Specification (`AGY2` Version 2)

```
[ Fixed Header (110 Bytes) ]
  [0..3]    Magic Bytes: b"AGY2" (4 bytes)
  [4]       Format Version: 0x02 (1 byte, supports backward-compatible v1 fallback)
  [5]       KDF Identifier: 0x01 (1 byte, Argon2id)
  [6..7]    Argon2 Time Cost: uint16 big-endian (default: 2)
  [8..11]   Argon2 Memory Cost: uint32 big-endian in KB (default: 65,536 KB = 64 MB)
  [12]      Argon2 Parallelism: uint8 (default: 4)
  [13..28]  CSPRNG Salt: 16 bytes
  [29..40]  KEK Nonce: 12 bytes
  [41..88]  Wrapped DEK: 48 bytes (32-byte DEK + 16-byte GCM authentication tag)
  [89..96]  Stream Nonce Prefix: 8 bytes
  [97..104] File Identifier: 8 bytes
  [105..108] Chunk Size: uint32 big-endian (default: 65,536 bytes)
  [109..110] Encrypted Metadata Payload Length: uint16 big-endian

[ Encrypted Metadata Payload (Variable, 64-byte block padded) ]
  Nonce: 12 bytes | AES-256-GCM Encrypted JSON (filename, mime_type, created_at) + Tag: 16 bytes

[ Framed Stream Chunks (Repeated until EOF) ]
  Payload Length: 4 bytes (uint32 big-endian, validated: 16 <= len <= chunk_size + 16)
  is_last Flag: 1 byte (uint8, 0=intermediate chunk, 1=final chunk)
  Ciphertext + GCM Tag: Payload Length bytes
```

### Cryptographic Invariants
1. **DEK AAD Binding (Version 2):**
   $$\text{AAD}_{\text{DEK}} = \text{b"AGY2-V2-DEK-WRAP:"} \;\|\; \text{HeaderPrefix}_{48}$$
   Tampering with any header field (version, KDF settings, salt, prefix, file ID, or chunk size) invalidates DEK unwrapping immediately.
2. **Chunk AAD Binding:**
   $$\text{AAD}_{\text{chunk}} = \text{FileID}_8 \;\|\; [i]_{32} \;\|\; [\text{is\_last}]_8$$
   Guarantees that chunks cannot be swapped, dropped, duplicated, or truncated.
3. **Trailing Data Prevention:**
   After the chunk with $\text{is\_last} = 1$ is processed, reading from the stream must return EOF. Any trailing bytes trigger `TrailingDataError`.

---

## 3. Python API & Programmatic Usage

### Streaming File Encryption & Decryption
```python
from pathlib import Path
from improved.crypto import encrypt_file, decrypt_file, change_password_file

# Memory-bounded file encryption (O(1) RAM)
encrypt_file(
    src_path=Path("document.pdf"),
    dest_path=Path("document.pdf.enc"),
    password="MasterSecretPassword2026!",
    chunk_size=64 * 1024, # 64 KB frames
)

# Atomic file decryption with integrity verification
decrypt_file(
    src_path=Path("document.pdf.enc"),
    dest_path=Path("recovered_document.pdf"),
    password="MasterSecretPassword2026!",
)

# Instantaneous password rotation without payload re-encryption
change_password_file(
    file_path=Path("document.pdf.enc"),
    old_password="MasterSecretPassword2026!",
    new_password="RotatedPassword2026!",
    atomic=True,
)
```

---

## 4. Running the Web Application & Tests

Launch the enhanced Streamlit application:
```bash
streamlit run improved/app.py
```

Run the automated test suite (31 improved tests, 46 total):
```bash
pytest improved/tests/ -v
```
