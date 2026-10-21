# Improved Cryptographic File System Implementation

This directory contains the separate, experimentally justified, improved implementation addressing the limitations demonstrated in the baseline reproduction of Rosandi et al. (2026).

---

## 1. Architectural Improvements Overview

| Area | Baseline System | Improved System | Cryptographic & System Advantage |
| :--- | :--- | :--- | :--- |
| **Key Derivation** | PBKDF2-HMAC-SHA256 (100k iter) | **Argon2id** (RFC 9106, 64 MB, $t=2$, $p=4$) | Memory-hardness defeats parallelized GPU/ASIC brute-force attacks. |
| **Payload Encryption** | Monolithic single-shot AES-256-GCM | **Chunked AEAD Streaming** ($64\text{ KB}$ frames) | Peak memory is $O(1)$ ($\le 2\text{ MB}$), supporting arbitrary gigabyte-scale files without RAM exhaustion. |
| **Streaming Integrity** | None (Single buffer) | **Rigorous AEAD Chunk Framing** | Nonce derived with 64-bit prefix + chunk counter; AAD cryptographically binds `file_id`, `chunk_index`, and `is_last` flag. |
| **Key Management** | Direct key derivation | **Envelope Encryption (DEK + KEK)** | Random 256-bit DEK encrypts data; password-derived KEK wraps DEK. Enables instantaneous in-place password modification. |
| **Metadata Privacy** | None (extension guessed from upload name) | **Encrypted Authenticated Header** | True filename, MIME type, and timestamp are encrypted under KEK. |

---

## 2. Container Format (`AGY2`)

The container layout consists of a fixed authenticated header, an encrypted metadata payload, and framed streaming chunks:

```
[ Fixed Header (111 Bytes) ]
  Magic: b"AGY2" | Version: 0x01 | KDF: 0x01 (Argon2id)
  Argon2 Parameters: Time=2, Memory=64MB, Parallelism=4
  Salt (16 B) | KEK Nonce (12 B) | Wrapped DEK (48 B)
  Stream Nonce Prefix (8 B) | File ID (8 B) | Chunk Size (4 B) | Metadata Len (2 B)

[ Encrypted Metadata Payload ]
  Nonce (12 B) | AES-256-GCM Encrypted JSON (filename, mime_type, created_at) + Tag (16 B)

[ Framed Stream Chunks (Repeat until EOF) ]
  Chunk Length (4 B, uint32) | is_last Flag (1 B, uint8) | Ciphertext (N B) + Tag (16 B)
```

---

## 3. Running the Improved Application

To launch the improved Streamlit interface:

```bash
streamlit run improved/app.py
```

To run the automated test suite:

```bash
pytest improved/tests/ -v
```
