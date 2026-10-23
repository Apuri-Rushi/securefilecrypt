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
    change_password_file,
    encrypt_file,
    decrypt_file,
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

    def test_inplace_file_password_change(self, tmp_path):
        """Verify in-place O(1) header re-wrapping directly on disk file."""
        orig_file = tmp_path / "doc.bin"
        enc_file = tmp_path / "doc.enc"
        restored_file = tmp_path / "doc_restored.bin"

        payload = b"Important classified dataset " * 1000
        orig_file.write_bytes(payload)
        expected_hash = hashlib.sha256(payload).hexdigest()

        pwd_1 = "InitialPassphrase2026!"
        pwd_2 = "RotatedPassphrase2026!"

        # Encrypt to file
        encrypt_file(orig_file, enc_file, pwd_1)
        orig_enc_size = enc_file.stat().st_size

        # In-place password change (overwrites header only)
        res = change_password_file(enc_file, pwd_1, pwd_2)
        assert res["status"] == "success"
        assert res["mode"] == "in-place"
        # File size must remain exact
        assert enc_file.stat().st_size == orig_enc_size

        # Verify old password rejected
        with pytest.raises(AuthenticationError):
            decrypt_file(enc_file, restored_file, pwd_1)

        # Verify new password decrypts faithfully
        dec_info = decrypt_file(enc_file, restored_file, pwd_2)
        assert dec_info["metadata"]["filename"] == "doc.bin"
        assert hashlib.sha256(restored_file.read_bytes()).hexdigest() == expected_hash

    def test_file_streaming_atomic_and_leak_free(self, tmp_path):
        """Verify disk streaming cleans up temporary unverified files on tamper failure."""
        orig_file = tmp_path / "data.bin"
        enc_file = tmp_path / "data.enc"
        dec_file = tmp_path / "recovered.bin"

        payload = os.urandom(256 * 1024)
        orig_file.write_bytes(payload)

        pwd = "TestPasswordSecure!"
        encrypt_file(orig_file, enc_file, pwd)

        # Corrupt one bit in payload
        corrupted_bytes = bytearray(enc_file.read_bytes())
        corrupted_bytes[-20] ^= 0x01
        enc_file.write_bytes(bytes(corrupted_bytes))

        # Decrypt must fail and leave NO plaintext files on disk
        with pytest.raises(AuthenticationError):
            decrypt_file(enc_file, dec_file, pwd)

        assert not dec_file.exists()
        # Ensure no dangling temporary files exist
        tmp_files = list(tmp_path.glob("*.tmp*"))
        assert len(tmp_files) == 0

    def test_atomic_file_password_change(self, tmp_path):
        """Verify atomic temporary-file replacement mode for password change."""
        orig_file = tmp_path / "atomic_doc.bin"
        enc_file = tmp_path / "atomic_doc.enc"
        restored_file = tmp_path / "atomic_doc_restored.bin"

        payload = b"Atomic rotation payload " * 500
        orig_file.write_bytes(payload)
        expected_hash = hashlib.sha256(payload).hexdigest()

        pwd_1 = "AtomicInitialPass2026!"
        pwd_2 = "AtomicUpdatedPass2026!"

        encrypt_file(orig_file, enc_file, pwd_1)

        # Execute password change with atomic=True
        res = change_password_file(enc_file, pwd_1, pwd_2, atomic=True)
        assert res["status"] == "success"
        assert res["mode"] == "atomic-replace"

        # Verify old password rejected
        with pytest.raises(AuthenticationError):
            decrypt_file(enc_file, restored_file, pwd_1)

        # Verify new password decrypts
        decrypt_file(enc_file, restored_file, pwd_2)
        assert hashlib.sha256(restored_file.read_bytes()).hexdigest() == expected_hash

    def test_password_change_payload_invariance(self, tmp_path):
        """
        Cryptographic Proof: Verify that envelope password rotation leaves
        the underlying payload ciphertext bytes 100% byte-for-byte identical.
        """
        orig_file = tmp_path / "invariance.dat"
        enc_v1 = tmp_path / "invariance_v1.enc"
        enc_v2 = tmp_path / "invariance_v2.enc"

        # 512 KB payload across multiple chunks
        payload = os.urandom(512 * 1024)
        orig_file.write_bytes(payload)

        pwd_old = "InvarianceOldPass!"
        pwd_new = "InvarianceNewPass!"

        encrypt_file(orig_file, enc_v1, pwd_old)

        # Read header length of v1
        with open(enc_v1, "rb") as f:
            from improved.file_format import ContainerHeader, FIXED_HEADER_SIZE
            fixed = f.read(FIXED_HEADER_SIZE)
            meta_len = int.from_bytes(fixed[-2:], "big")
            v1_header_len = FIXED_HEADER_SIZE + meta_len
            f.seek(v1_header_len)
            v1_payload_ciphertext = f.read()

        # Rotate password
        with open(enc_v1, "rb") as fin, open(enc_v2, "wb") as fout:
            change_password_stream(fin, fout, pwd_old, pwd_new)

        # Read payload ciphertext of v2
        with open(enc_v2, "rb") as f:
            fixed = f.read(FIXED_HEADER_SIZE)
            meta_len = int.from_bytes(fixed[-2:], "big")
            v2_header_len = FIXED_HEADER_SIZE + meta_len
            f.seek(v2_header_len)
            v2_payload_ciphertext = f.read()

        # PAYLOAD CIPHERTEXT MUST BE IDENTICAL BYTE-FOR-BYTE!
        assert len(v1_payload_ciphertext) == len(v2_payload_ciphertext)
        assert v1_payload_ciphertext == v2_payload_ciphertext

    def test_secure_file_permissions(self, tmp_path):
        """Verify created files have secure POSIX permissions (0600 on Linux/macOS)."""
        if os.name != "posix":
            pytest.skip("POSIX permission tests only apply to POSIX systems")

        orig_file = tmp_path / "perm_test.bin"
        enc_file = tmp_path / "perm_test.enc"
        dec_file = tmp_path / "perm_test_dec.bin"

        orig_file.write_bytes(b"Permission test payload")

        encrypt_file(orig_file, enc_file, "PermPass!")
        decrypt_file(enc_file, dec_file, "PermPass!")

        # Check permissions mask
        enc_stat = enc_file.stat().st_mode & 0o777
        dec_stat = dec_file.stat().st_mode & 0o777

        assert enc_stat == 0o600
        assert dec_stat == 0o600

