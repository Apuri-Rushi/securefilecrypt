"""
Baseline Streamlit Web Application.

Faithfully implements the interface and workflows presented in:
'Design of File Encryption and Decryption Application Using AES-256 Cryptography
Algorithm Based on Streamlit' (Rosandi et al., 2026).

Figures 1, 2, 3, 4:
- Header: AES-256 File Encryption & Decryption Application
- Mode Selection: Radio button for 'Encrypt' and 'Decrypt'
- File uploader: Choose file
- Password input: Masked password input field
- Process button: 'Encryption' / 'Decryption'
- Results: Download button for .enc or decrypted file
"""

import streamlit as st
import io
import time
from baseline.crypto import (
    encrypt_bytes,
    decrypt_bytes,
    AuthenticationError,
    CryptographicError,
)
from baseline.file_format import InvalidContainerError

st.set_page_config(
    page_title="AES-256 File Encryption & Decryption",
    page_icon="🔒",
    layout="centered",
)

st.title("AES-256 File Encryption & Decryption Application")
st.markdown(
    "A simple application for encrypting and decrypting files using the AES-256 algorithm (GCM mode)."
)

mode = st.radio(
    "Choose Operation Mode",
    options=["Encrypt", "Decrypt"],
    horizontal=False,
)

if mode == "Encrypt":
    uploaded_file = st.file_uploader(
        "Choose file",
        type=None,
        key="baseline_encrypt_uploader",
        help="Upload any file to encrypt",
    )

    password = st.text_input(
        "Enter your password",
        type="password",
        key="baseline_encrypt_password",
        help="Password used to derive the 256-bit AES encryption key",
    )

    if st.button("Encryption", key="baseline_btn_encrypt"):
        if not uploaded_file:
            st.warning("Please upload a file to encrypt.")
        elif not password:
            st.warning("Please enter a password.")
        else:
            try:
                with st.spinner("Encrypting file..."):
                    start_time = time.perf_counter()
                    file_bytes = uploaded_file.read()
                    encrypted_data = encrypt_bytes(file_bytes, password)
                    elapsed = time.perf_counter() - start_time

                st.success(f"File encrypted successfully in {elapsed:.3f} s!")

                output_filename = f"{uploaded_file.name}.enc"
                st.download_button(
                    label="Download results",
                    data=encrypted_data,
                    file_name=output_filename,
                    mime="application/octet-stream",
                    key="baseline_download_enc",
                )
            except Exception as e:
                st.error(f"Encryption failed: {str(e)}")

elif mode == "Decrypt":
    uploaded_file = st.file_uploader(
        "Choose file",
        type=None,
        key="baseline_decrypt_uploader",
        help="Upload an .enc file to decrypt",
    )

    password = st.text_input(
        "Enter your password",
        type="password",
        key="baseline_decrypt_password",
        help="Password used during encryption",
    )

    if st.button("Decryption", key="baseline_btn_decrypt"):
        if not uploaded_file:
            st.warning("Please upload an .enc file to decrypt.")
        elif not password:
            st.warning("Please enter the decryption password.")
        else:
            try:
                with st.spinner("Decrypting file..."):
                    start_time = time.perf_counter()
                    enc_bytes = uploaded_file.read()
                    decrypted_data = decrypt_bytes(enc_bytes, password)
                    elapsed = time.perf_counter() - start_time

                st.success(f"File decrypted successfully in {elapsed:.3f} s!")

                # Infer output filename: strip .enc if present
                in_name = uploaded_file.name
                if in_name.lower().endswith(".enc"):
                    out_name = in_name[:-4]
                else:
                    out_name = f"decrypted_{in_name}"

                st.download_button(
                    label="Download results",
                    data=decrypted_data,
                    file_name=out_name,
                    mime="application/octet-stream",
                    key="baseline_download_dec",
                )
            except (AuthenticationError, InvalidContainerError) as e:
                # Per paper: report error without generating or leaking plaintext
                st.error("Decryption failed: Password incorrect or file corrupted.")
            except Exception as e:
                st.error("Decryption error: An unexpected error occurred.")
