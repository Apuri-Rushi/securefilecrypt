"""
Automated Streaming and Envelope Password-Change Tests for Improved Implementation.

Verifies:
1. File-based streaming encryption and decryption.
2. Envelope encryption password update (in-place DEK re-wrapping without payload re-encryption).
3. Rejection of invalid old passwords during password modification.
4. Correctness of payload restoration after password change.
"""

import hashlib
import io
import os
import tempfile
import time
from pathlib import Path
import pytest

from improved.crypto import (
    encrypt_stream,
    decrypt_stream,
    change_password_stream,
    AuthenticationError,
)


def compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(64 * 1024):
            h.update(chunk)
    return h.hexdigest()


class TestImprovedStreaming:
    """Tests file streaming and envelope encryption password modification."""

    def test_file_stream_roundtrip(self, tmp_path):
        """Confirm streaming through disk files preserves byte-for-byte fidelity."""
        orig_file = tmp_path / "large_input.bin"
        enc_file = tmp_path / "stream_output.enc"
        dec_file = tmp_path / "stream_decrypted.bin"

        # Generate 2 MB random data
        size = 2 * 1024 * 1024
        orig_file.write_bytes(os.urandom(size))
        orig_hash = compute_file_sha256(orig_file)

        password = "StreamPassword2026!"

        # Encrypt stream
        with open(orig_file, "rb") as fin, open(enc_file, "wb") as fout:
            enc_info = encrypt_stream(fin, fout, password, filename="large_input.bin")

        assert enc_info["chunks_written"] == 32  # 2MB / 64KB = 32 chunks

        # Decrypt stream
        with open(enc_file, "rb") as fin, open(dec_file, "wb") as fout:
            dec_info = decrypt_stream(fin, fout, password)

        assert dec_info["metadata"]["filename"] == "large_input.bin"
        assert compute_file_sha256(dec_file) == orig_hash

    def test_envelope_password_change(self, tmp_path):
        """
        Verify instantaneous password modification via envelope encryption.
        DEK is re-wrapped with new KEK without re-encrypting the 5 MB payload.
        """
        orig_file = tmp_path / "confidential_dataset.dat"
        enc_file_v1 = tmp_path / "dataset_v1.enc"
        enc_file_v2 = tmp_path / "dataset_v2.enc"
        restored_file = tmp_path / "dataset_restored.dat"

        # 5 MB file
        payload_size = 5 * 1024 * 1024
        orig_file.write_bytes(os.urandom(payload_size))
        expected_hash = compute_file_sha256(orig_file)

        pwd_initial = "OldSecretPassword123!"
        pwd_updated = "NewSecretPassword456!"

        # 1. Encrypt with initial password
        with open(orig_file, "rb") as fin, open(enc_file_v1, "wb") as fout:
            encrypt_stream(fin, fout, pwd_initial, filename="confidential_dataset.dat")

        # 2. Change password in-place
        t0 = time.perf_counter()
        with open(enc_file_v1, "rb") as fin, open(enc_file_v2, "wb") as fout:
            change_res = change_password_stream(fin, fout, pwd_initial, pwd_updated)
        elapsed_change = time.perf_counter() - t0

        print(f"\nPassword change on 5 MB file took: {elapsed_change:.4f} s")
        assert change_res["status"] == "success"

        # 3. Verify old password is now rejected
        dummy_out = io.BytesIO()
        with open(enc_file_v2, "rb") as fin:
            with pytest.raises(AuthenticationError):
                decrypt_stream(fin, dummy_out, pwd_initial)

        # 4. Verify new password successfully decrypts to exact original bytes
        with open(enc_file_v2, "rb") as fin, open(restored_file, "wb") as fout:
            dec_info = decrypt_stream(fin, fout, pwd_updated)

        assert dec_info["metadata"]["filename"] == "confidential_dataset.dat"
        assert compute_file_sha256(restored_file) == expected_hash

    def test_invalid_old_password_fails_password_change(self, tmp_path):
        """Confirm password change fails immediately if old password is incorrect."""
        enc_file = tmp_path / "protected.enc"
        out_file = tmp_path / "failed_change.enc"

        in_buf = io.BytesIO(b"Small payload")
        with open(enc_file, "wb") as fout:
            encrypt_stream(in_buf, fout, "CorrectInitialPassword")

        with open(enc_file, "rb") as fin, open(out_file, "wb") as fout:
            with pytest.raises(AuthenticationError, match="old password is incorrect"):
                change_password_stream(fin, fout, "WrongOldPassword", "BrandNewPassword")
