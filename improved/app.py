"""
Improved Streamlit Web Application.

Features:
1. Mode 'Encrypt': Memory-bounded authenticated chunked streaming with Argon2id and DEK/KEK envelope.
2. Mode 'Decrypt': Streamed authenticated decryption with confidential metadata recovery (original filename).
3. Mode 'Update Password': Instantaneous in-place envelope re-wrapping without payload re-encryption.
"""

import io
import os
import tempfile
import time
import streamlit as st

from improved.crypto import (
    encrypt_stream,
    decrypt_stream,
    change_password_stream,
    AuthenticationError,
    StreamTruncationError,
    DEFAULT_TIME_COST,
    DEFAULT_MEM_COST_KB,
    DEFAULT_PARALLELISM,
    DEFAULT_CHUNK_SIZE,
)
from improved.file_format import ContainerFormatError

st.set_page_config(
    page_title="AES-256 Advanced Cryptographic File System",
    page_icon="🛡️",
    layout="centered",
)

st.title("AES-256 Advanced File Encryption & Decryption (Improved System)")
st.markdown(
    "Enhanced cryptographic engine featuring **Argon2id (RFC 9106)** memory-hard key derivation, "
    "**Envelope Encryption (DEK/KEK)**, **Chunked AEAD Streaming (AES-256-GCM)**, and **Encrypted Metadata Privacy**."
)

mode = st.radio(
    "Choose Operation Mode",
    options=["Encrypt", "Decrypt", "Update Password (Envelope Re-wrap)"],
    horizontal=False,
)

if mode == "Encrypt":
    uploaded_file = st.file_uploader(
        "Choose file to encrypt",
        type=None,
        key="improved_enc_uploader",
    )

    password = st.text_input(
        "Enter encryption password",
        type="password",
        key="improved_enc_password",
        help="Derived via Argon2id into a 256-bit Key Encryption Key (KEK)",
    )

    with st.expander("Advanced Cryptographic Parameters (RFC 9106 / Streaming)"):
        chunk_size_kb = st.select_slider(
            "Chunk Size (KB)",
            options=[16, 32, 64, 128, 256, 512],
            value=64,
            help="Streaming chunk buffer size; keeps peak RAM strictly bounded.",
        )
        t_cost = st.number_input("Argon2id Iterations (Time Cost)", min_value=1, max_value=10, value=DEFAULT_TIME_COST)
        m_cost_mb = st.number_input("Argon2id Memory Cost (MB)", min_value=16, max_value=512, value=DEFAULT_MEM_COST_KB // 1024)

    if st.button("Encrypt File", key="improved_btn_encrypt"):
        if not uploaded_file:
            st.warning("Please upload a file to encrypt.")
        elif not password:
            st.warning("Please enter a password.")
        else:
            try:
                with st.spinner("Encrypting in memory-bounded stream..."):
                    in_buf = io.BytesIO(uploaded_file.read())
                    out_buf = io.BytesIO()

                    t0 = time.perf_counter()
                    enc_info = encrypt_stream(
                        input_stream=in_buf,
                        output_stream=out_buf,
                        password=password,
                        filename=uploaded_file.name,
                        mime_type=uploaded_file.type or "application/octet-stream",
                        chunk_size=chunk_size_kb * 1024,
                        time_cost=int(t_cost),
                        memory_cost_kb=int(m_cost_mb * 1024),
                    )
                    elapsed = time.perf_counter() - t0

                enc_bytes = out_buf.getvalue()
                throughput = (len(enc_bytes) / (1024 * 1024)) / elapsed if elapsed > 0 else 0

                st.success(
                    f"Encrypted {enc_info['total_plaintext_bytes']:,} bytes in {elapsed:.3f} s "
                    f"({throughput:.2f} MB/s) across {enc_info['chunks_written']} authenticated chunks!"
                )

                st.download_button(
                    label="Download Encrypted File (.enc)",
                    data=enc_bytes,
                    file_name=f"{uploaded_file.name}.enc",
                    mime="application/octet-stream",
                    key="improved_download_enc",
                )
            except Exception as e:
                st.error(f"Encryption failed: {str(e)}")

elif mode == "Decrypt":
    uploaded_file = st.file_uploader(
        "Choose .enc file to decrypt",
        type=None,
        key="improved_dec_uploader",
    )

    password = st.text_input(
        "Enter decryption password",
        type="password",
        key="improved_dec_password",
    )

    if st.button("Decrypt & Authenticate", key="improved_btn_decrypt"):
        if not uploaded_file:
            st.warning("Please upload an .enc file to decrypt.")
        elif not password:
            st.warning("Please enter the decryption password.")
        else:
            try:
                with st.spinner("Verifying cryptographic integrity & decrypting..."):
                    in_buf = io.BytesIO(uploaded_file.read())
                    out_buf = io.BytesIO()

                    t0 = time.perf_counter()
                    dec_info = decrypt_stream(
                        input_stream=in_buf,
                        output_stream=out_buf,
                        password=password,
                    )
                    elapsed = time.perf_counter() - t0

                dec_bytes = out_buf.getvalue()
                meta = dec_info["metadata"]
                restored_name = meta.get("filename", "restored_file.bin")
                restored_mime = meta.get("mime_type", "application/octet-stream")
                throughput = (len(dec_bytes) / (1024 * 1024)) / elapsed if elapsed > 0 else 0

                st.success(
                    f"Decrypted successfully in {elapsed:.3f} s ({throughput:.2f} MB/s)!\n\n"
                    f"**Restored Original Filename:** `{restored_name}`\n\n"
                    f"**Detected MIME Type:** `{restored_mime}`\n\n"
                    f"**Chunks Verified:** {dec_info['chunks_processed']}"
                )

                st.download_button(
                    label=f"Download {restored_name}",
                    data=dec_bytes,
                    file_name=restored_name,
                    mime=restored_mime,
                    key="improved_download_dec",
                )
            except (AuthenticationError, StreamTruncationError, ContainerFormatError) as e:
                st.error("Decryption failed: Incorrect password, corrupted chunks, or tampered file.")
            except Exception as e:
                st.error(f"Decryption error: An unexpected error occurred: {str(e)}")

elif mode == "Update Password (Envelope Re-wrap)":
    st.info(
        "**Envelope Encryption Advantage:** You can update the file password in milliseconds without "
        "re-encrypting the underlying data payload! The system verifies the old password, unwraps the "
        "internal Data Encryption Key (DEK), and re-wraps it with a new Key Encryption Key (KEK)."
    )

    uploaded_file = st.file_uploader(
        "Choose .enc file for password update",
        type=None,
        key="improved_pwd_uploader",
    )

    old_password = st.text_input(
        "Enter CURRENT password",
        type="password",
        key="improved_old_password",
    )

    new_password = st.text_input(
        "Enter NEW password",
        type="password",
        key="improved_new_password",
    )

    new_password_confirm = st.text_input(
        "Confirm NEW password",
        type="password",
        key="improved_new_password_confirm",
    )

    if st.button("Update File Password", key="improved_btn_update_pwd"):
        if not uploaded_file:
            st.warning("Please upload an .enc file.")
        elif not old_password or not new_password:
            st.warning("Please provide both current and new passwords.")
        elif new_password != new_password_confirm:
            st.error("New passwords do not match.")
        else:
            try:
                with st.spinner("Re-wrapping Data Encryption Key..."):
                    in_buf = io.BytesIO(uploaded_file.read())
                    out_buf = io.BytesIO()

                    t0 = time.perf_counter()
                    change_res = change_password_stream(
                        input_stream=in_buf,
                        output_stream=out_buf,
                        old_password=old_password,
                        new_password=new_password,
                    )
                    elapsed = time.perf_counter() - t0

                updated_bytes = out_buf.getvalue()

                st.success(
                    f"Password successfully updated in **{elapsed:.4f} seconds**!\n\n"
                    f"The underlying {change_res['payload_bytes_transferred']:,} bytes of payload "
                    "remained encrypted and untouched."
                )

                st.download_button(
                    label="Download Updated .enc File",
                    data=updated_bytes,
                    file_name=uploaded_file.name,
                    mime="application/octet-stream",
                    key="improved_download_updated_enc",
                )
            except AuthenticationError:
                st.error("Password update failed: Current password is incorrect.")
            except Exception as e:
                st.error(f"Password update error: {str(e)}")
