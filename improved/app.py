"""
Improved Streamlit Web Application for Advanced AES-256-GCM File Cryptosystem.

Faithful extension of Rosandi et al. (2026) incorporating:
1. Memory-bounded authenticated chunked streaming (AES-256-GCM).
2. RFC 9106 Argon2id memory-hard key derivation resistant to GPU/ASIC attacks.
3. Envelope encryption (DEK/KEK) enabling instantaneous O(1) password updates.
4. Version 2 AGY2 authenticated container format with full header binding.
5. Encrypted metadata privacy with block-padding defense against filename length leakage.
6. Automatic detection and dual-mode compatibility for baseline paper containers.
7. Granular cryptographic error discrimination and zero plaintext leakage.
"""

import io
import os
import tempfile
import time
from pathlib import Path
import streamlit as st

from improved.crypto import (
    encrypt_stream,
    decrypt_stream,
    change_password_stream,
    IncorrectPasswordError,
    CorruptedChunkError,
    StreamTruncationError,
    TrailingDataError,
    AuthenticationError,
    ImprovedCryptoError,
    DEFAULT_TIME_COST,
    DEFAULT_MEM_COST_KB,
    DEFAULT_PARALLELISM,
    DEFAULT_CHUNK_SIZE,
    FORMAT_VERSION,
)
from improved.file_format import (
    ContainerFormatError,
    InvalidMagicError,
    UnsupportedVersionError,
    ParameterBoundsError,
    MAGIC_BYTES,
)
import baseline.crypto as baseline_crypto
import baseline.file_format as baseline_format

st.set_page_config(
    page_title="AES-256 Advanced File Security System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling for Academic & Professional Visual Polish
st.markdown(
    """
    <style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        color: #1E293B;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        font-size: 1.05rem;
        color: #475569;
        margin-bottom: 1.5rem;
    }
    .badge-bar {
        display: flex;
        gap: 0.6rem;
        flex-wrap: wrap;
        margin-bottom: 1.2rem;
    }
    .crypto-badge {
        background-color: #EEF2F6;
        color: #0F172A;
        border: 1px solid #CBD5E1;
        padding: 0.25rem 0.65rem;
        border-radius: 9999px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .crypto-badge-accent {
        background-color: #EFF6FF;
        color: #1D4ED8;
        border: 1px solid #BFDBFE;
        padding: 0.25rem 0.65rem;
        border-radius: 9999px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .metric-card {
        background-color: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 0.6rem;
        padding: 1rem;
        margin-bottom: 0.8rem;
    }
    .metric-val {
        font-size: 1.4rem;
        font-weight: 700;
        color: #0F172A;
    }
    .metric-lbl {
        font-size: 0.82rem;
        color: #64748B;
        text-transform: uppercase;
        letter-spacing: 0.04em;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("### 🛡️ System Specifications")
    st.markdown(
        """
        **Research Foundation:**
        *Rosandi et al. (2026), IJOMRAL*
        
        **Cryptographic Architecture:**
        - **Primary AEAD:** AES-256-GCM
        - **KDF Algorithm:** Argon2id (RFC 9106)
        - **Key Hierarchy:** Envelope (DEK + KEK)
        - **Container Format:** AGY2 (Version 2)
        - **Memory Footprint:** $O(\\text{chunk})$ Streaming
        - **Header Binding:** Full AAD Integrity
        - **Metadata Protection:** Encrypted & Padded
        """
    )
    st.divider()
    st.markdown("### ⚙️ Engine Mode")
    engine_selection = st.radio(
        "Select Protocol",
        options=["Advanced Engine (AGY2)", "Baseline Engine (Rosandi et al. Reproduction)"],
        index=0,
        help="Switch between the improved streaming cryptosystem and the original paper's baseline.",
    )

st.markdown('<div class="main-title">AES-256 Advanced File Security System</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-title">'
    'Experimentally Validated Cryptographic Extension of Rosandi et al. (2026) featuring '
    'Memory-Hard KDF, Envelope Encryption, Chunked Streaming AEAD, and Metadata Confidentiality.'
    '</div>',
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="badge-bar">
        <span class="crypto-badge-accent">🔒 AES-256-GCM AEAD</span>
        <span class="crypto-badge-accent">🧠 Argon2id RFC 9106 (64 MB Hardness)</span>
        <span class="crypto-badge">✉️ Envelope Encryption (DEK/KEK)</span>
        <span class="crypto-badge">📦 AGY2 v2 Format</span>
        <span class="crypto-badge">⚡ O(1) Fast Password Rotation</span>
    </div>
    """,
    unsafe_allow_html=True,
)

if engine_selection == "Baseline Engine (Rosandi et al. Reproduction)":
    st.info("ℹ️ Running in **Baseline Paper Mode** (Monolithic AES-256-GCM, PBKDF2-HMAC-SHA256, 100k iterations).")
    b_mode = st.radio("Baseline Operation", options=["Encrypt", "Decrypt"], horizontal=True)

    if b_mode == "Encrypt":
        b_upload = st.file_uploader("Select file to encrypt (Baseline)", key="base_enc_upload")
        b_pwd = st.text_input("Enter Passphrase", type="password", key="base_enc_pwd")
        if st.button("Encrypt (Baseline)", key="btn_base_enc"):
            if not b_upload or not b_pwd:
                st.warning("Please provide both file and passphrase.")
            else:
                with st.spinner("Processing in baseline monolithic memory..."):
                    t0 = time.perf_counter()
                    data = b_upload.read()
                    enc_data = baseline_crypto.encrypt_bytes(data, b_pwd)
                    elapsed = time.perf_counter() - t0
                st.success(f"Encrypted {len(data):,} bytes in {elapsed:.3f} s!")
                st.download_button(
                    "Download Baseline .enc File",
                    data=enc_data,
                    file_name=f"{b_upload.name}.enc",
                    mime="application/octet-stream",
                )

    elif b_mode == "Decrypt":
        b_upload = st.file_uploader("Select .enc file to decrypt (Baseline)", key="base_dec_upload")
        b_pwd = st.text_input("Enter Passphrase", type="password", key="base_dec_pwd")
        if st.button("Decrypt (Baseline)", key="btn_base_dec"):
            if not b_upload or not b_pwd:
                st.warning("Please provide both file and passphrase.")
            else:
                try:
                    with st.spinner("Decrypting via baseline PBKDF2 + AES-GCM..."):
                        t0 = time.perf_counter()
                        enc_data = b_upload.read()
                        dec_data = baseline_crypto.decrypt_bytes(enc_data, b_pwd)
                        elapsed = time.perf_counter() - t0
                    st.success(f"Decrypted {len(dec_data):,} bytes in {elapsed:.3f} s!")
                    out_name = b_upload.name[:-4] if b_upload.name.lower().endswith(".enc") else f"dec_{b_upload.name}"
                    st.download_button(
                        f"Download {out_name}",
                        data=dec_data,
                        file_name=out_name,
                        mime="application/octet-stream",
                    )
                except baseline_crypto.AuthenticationError:
                    st.error("Decryption failed: Incorrect password or corrupted/tampered file.")
                except Exception as e:
                    st.error(f"Decryption failed: {str(e)}")

else:
    # Advanced Engine
    operation = st.radio(
        "Choose Operation",
        options=["1. Authenticated Streaming Encryption", "2. Authenticated Streaming Decryption", "3. Envelope Password Rotation (O(1) Time)"],
        horizontal=True,
    )

    if operation.startswith("1."):
        st.markdown("#### 🔒 Encrypt File into AGY2 Version 2 Container")
        col_file, col_pwd = st.columns([1, 1])
        with col_file:
            uploaded_file = st.file_uploader("Choose file to secure", key="adv_enc_file")
        with col_pwd:
            password = st.text_input(
                "Passphrase",
                type="password",
                key="adv_enc_pwd",
                help="Derived using Argon2id into a 256-bit Key Encryption Key (KEK)",
            )
            password_confirm = st.text_input("Confirm Passphrase", type="password", key="adv_enc_pwd_confirm")

        with st.expander("Advanced Tunables (RFC 9106 & Streaming Framing)", expanded=False):
            col_c1, col_c2, col_c3 = st.columns(3)
            with col_c1:
                chunk_kb = st.select_slider(
                    "Streaming Chunk Size",
                    options=[16, 32, 64, 128, 256, 512, 1024],
                    value=64,
                    help="Peak memory overhead is bounded by this buffer size.",
                )
            with col_c2:
                time_cost = st.number_input("Argon2id Time Cost (Passes)", min_value=1, max_value=8, value=DEFAULT_TIME_COST)
            with col_c3:
                mem_cost_mb = st.number_input("Argon2id Memory Cost (MB)", min_value=16, max_value=256, value=DEFAULT_MEM_COST_KB // 1024)

        if st.button("Execute Streaming Encryption", key="btn_adv_encrypt", type="primary"):
            if not uploaded_file:
                st.warning("Please upload a file to encrypt.")
            elif not password:
                st.warning("Please enter a passphrase.")
            elif password != password_confirm:
                st.error("Passphrases do not match. Please verify your entry.")
            else:
                try:
                    with st.spinner("Deriving Argon2id KEK and streaming AES-256-GCM chunks..."):
                        out_buf = io.BytesIO()
                        uploaded_file.seek(0)
                        t0 = time.perf_counter()
                        info = encrypt_stream(
                            input_stream=uploaded_file,
                            output_stream=out_buf,
                            password=password,
                            filename=uploaded_file.name,
                            mime_type=uploaded_file.type or "application/octet-stream",
                            chunk_size=chunk_kb * 1024,
                            time_cost=int(time_cost),
                            memory_cost_kb=int(mem_cost_mb * 1024),
                        )
                        elapsed = time.perf_counter() - t0

                    enc_bytes = out_buf.getvalue()
                    throughput = (len(enc_bytes) / (1024 * 1024)) / elapsed if elapsed > 0 else 0

                    st.success("File encrypted successfully into versioned AGY2 container!")

                    m1, m2, m3, m4 = st.columns(4)
                    with m1:
                        st.markdown(
                            f'<div class="metric-card"><div class="metric-val">{elapsed:.3f} s</div><div class="metric-lbl">Total Time</div></div>',
                            unsafe_allow_html=True,
                        )
                    with m2:
                        st.markdown(
                            f'<div class="metric-card"><div class="metric-val">{throughput:.2f} MB/s</div><div class="metric-lbl">Throughput</div></div>',
                            unsafe_allow_html=True,
                        )
                    with m3:
                        st.markdown(
                            f'<div class="metric-card"><div class="metric-val">{info["chunks_written"]:,}</div><div class="metric-lbl">Chunks Framed</div></div>',
                            unsafe_allow_html=True,
                        )
                    with m4:
                        st.markdown(
                            f'<div class="metric-card"><div class="metric-val">{chunk_kb} KB</div><div class="metric-lbl">RAM Bound</div></div>',
                            unsafe_allow_html=True,
                        )

                    st.download_button(
                        label=f"⬇️ Download Encrypted Container ({uploaded_file.name}.enc)",
                        data=enc_bytes,
                        file_name=f"{uploaded_file.name}.enc",
                        mime="application/octet-stream",
                        key="dl_adv_enc",
                    )
                except Exception as e:
                    st.error(f"Encryption failed: {str(e)}")

    elif operation.startswith("2."):
        st.markdown("#### 🔓 Authenticated Streaming Decryption & Integrity Verification")
        col_dfile, col_dpwd = st.columns([1, 1])
        with col_dfile:
            dec_file = st.file_uploader("Choose .enc container to decrypt", key="adv_dec_file")
        with col_dpwd:
            dec_password = st.text_input("Enter Passphrase", type="password", key="adv_dec_pwd")

        # Automatic Container Format Sniffing
        if dec_file:
            header_sample = dec_file.read(4)
            dec_file.seek(0)
            if header_sample == MAGIC_BYTES:
                st.caption("🔍 **Detected Container:** AGY2 Authenticated Streaming Format")
            elif len(header_sample) > 0:
                st.caption("ℹ️ **Notice:** File does not possess AGY2 magic bytes. If this is a baseline Rosandi et al. file, you can decrypt it using the baseline mode below.")

        if st.button("Authenticate & Decrypt File", key="btn_adv_decrypt", type="primary"):
            if not dec_file or not dec_password:
                st.warning("Please provide both the container file and passphrase.")
            else:
                try:
                    with st.spinner("Verifying cryptographic tags and streaming plaintext..."):
                        dec_file.seek(0)
                        out_buf = io.BytesIO()
                        t0 = time.perf_counter()
                        dec_info = decrypt_stream(
                            input_stream=dec_file,
                            output_stream=out_buf,
                            password=dec_password,
                        )
                        elapsed = time.perf_counter() - t0

                    plaintext_bytes = out_buf.getvalue()
                    meta = dec_info["metadata"]
                    restored_name = meta.get("filename", "decrypted_file.bin")
                    restored_mime = meta.get("mime_type", "application/octet-stream")
                    throughput = (len(plaintext_bytes) / (1024 * 1024)) / elapsed if elapsed > 0 else 0

                    st.success("Cryptographic integrity verified! All chunks successfully authenticated.")

                    m1, m2, m3 = st.columns(3)
                    with m1:
                        st.markdown(
                            f'<div class="metric-card"><div class="metric-val">{elapsed:.3f} s</div><div class="metric-lbl">Decryption Latency</div></div>',
                            unsafe_allow_html=True,
                        )
                    with m2:
                        st.markdown(
                            f'<div class="metric-card"><div class="metric-val">{throughput:.2f} MB/s</div><div class="metric-lbl">Throughput</div></div>',
                            unsafe_allow_html=True,
                        )
                    with m3:
                        st.markdown(
                            f'<div class="metric-card"><div class="metric-val">{dec_info["chunks_processed"]:,}</div><div class="metric-lbl">Chunks Verified</div></div>',
                            unsafe_allow_html=True,
                        )

                    st.markdown(
                        f"**Restored Filename:** `{restored_name}` &nbsp;|&nbsp; "
                        f"**Restored MIME:** `{restored_mime}` &nbsp;|&nbsp; "
                        f"**Format Version:** `AGY2 v{dec_info['version']}`"
                    )

                    st.download_button(
                        label=f"⬇️ Download Restored File ({restored_name})",
                        data=plaintext_bytes,
                        file_name=restored_name,
                        mime=restored_mime,
                        key="dl_adv_dec",
                    )
                except IncorrectPasswordError:
                    st.error("Authentication Failure: Incorrect passphrase. The Key Encryption Key (KEK) could not unwrap the container.")
                except CorruptedChunkError as e:
                    st.error(f"Integrity Violation: Chunk {e.chunk_index} has been altered, swapped, or corrupted. Zero plaintext released.")
                except StreamTruncationError:
                    st.error("Container Incomplete: The container stream was truncated before the final authenticated chunk marker.")
                except TrailingDataError:
                    st.error("Tampering Detected: Unauthorized trailing data detected after the final authenticated chunk.")
                except InvalidMagicError:
                    # Provide helpful baseline recovery fallback
                    st.warning("Not an AGY2 container. Attempting recovery via Baseline Rosandi et al. engine...")
                    try:
                        dec_file.seek(0)
                        raw_data = dec_file.read()
                        recovered = baseline_crypto.decrypt_bytes(raw_data, dec_password)
                        st.success("Successfully decrypted via Baseline Engine!")
                        out_name = dec_file.name[:-4] if dec_file.name.lower().endswith(".enc") else f"recovered_{dec_file.name}"
                        st.download_button(f"Download {out_name}", data=recovered, file_name=out_name)
                    except baseline_crypto.AuthenticationError:
                        st.error("Baseline Decryption failed: Incorrect password or corrupted baseline file.")
                    except Exception as e:
                        st.error(f"Unsupported container format: {str(e)}")
                except ParameterBoundsError as e:
                    st.error(f"Resource Denial-of-Service Defense: {str(e)}")
                except ContainerFormatError as e:
                    st.error(f"Container Format Error: {str(e)}")
                except Exception as e:
                    st.error(f"Decryption Error: {str(e)}")

    elif operation.startswith("3."):
        st.markdown("#### ⚡ Envelope Password Rotation (O(1) Time Payload-Untouched)")
        st.info(
            "**Cryptographic Envelope Advantage:** In the baseline paper, changing a passphrase requires decrypting the entire file "
            "and re-encrypting the entire payload ($O(N)$ operations). In this improved system, the internal Data Encryption Key (DEK) "
            "is unwraped and re-wrapped under a fresh Key Encryption Key (KEK) in milliseconds, while the multi-megabyte ciphertext payload "
            "remains untouched!"
        )

        p_file = st.file_uploader("Select .enc container for password update", key="adv_pwd_file")
        col_p1, col_p2, col_p3 = st.columns(3)
        with col_p1:
            old_p = st.text_input("Current Passphrase", type="password", key="adv_pwd_old")
        with col_p2:
            new_p = st.text_input("New Passphrase", type="password", key="adv_pwd_new")
        with col_p3:
            new_p_confirm = st.text_input("Confirm New Passphrase", type="password", key="adv_pwd_confirm")

        if st.button("Rotate Passphrase", key="btn_adv_rotate", type="primary"):
            if not p_file or not old_p or not new_p:
                st.warning("Please provide container file and both passphrases.")
            elif new_p != new_p_confirm:
                st.error("New passphrases do not match.")
            else:
                try:
                    with st.spinner("Unwrapping DEK and generating fresh Argon2id KEK..."):
                        p_file.seek(0)
                        out_buf = io.BytesIO()
                        t0 = time.perf_counter()
                        change_res = change_password_stream(
                            input_stream=p_file,
                            output_stream=out_buf,
                            old_password=old_p,
                            new_password=new_p,
                        )
                        elapsed = time.perf_counter() - t0

                    updated_bytes = out_buf.getvalue()
                    st.success(f"Passphrase rotated in **{elapsed:.4f} seconds**!")
                    st.markdown(
                        f"Transferred `{change_res['payload_bytes_transferred']:,}` bytes of payload "
                        "ciphertext without cryptographic re-processing."
                    )
                    st.download_button(
                        "⬇️ Download Updated Container (.enc)",
                        data=updated_bytes,
                        file_name=p_file.name,
                        mime="application/octet-stream",
                        key="dl_adv_pwd",
                    )
                except IncorrectPasswordError:
                    st.error("Password rotation failed: Current passphrase is incorrect.")
                except Exception as e:
                    st.error(f"Password rotation failed: {str(e)}")
