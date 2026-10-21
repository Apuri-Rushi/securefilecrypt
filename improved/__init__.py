"""
Improved file encryption and decryption system.
Features:
- Memory-bounded authenticated chunked streaming AEAD (AES-256-GCM)
- Memory-hard password-derived key management (Argon2id)
- Envelope encryption (DEK + KEK) enabling instantaneous in-place password updates
- Encrypted and authenticated metadata header (filename, mime type, size)
"""

__version__ = "2.0.0"
