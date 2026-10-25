# Traceable Evidence Map: SecureFileCrypt Project Report

This document provides an end-to-end, traceable verification map connecting every major claim, architectural design, metric, test result, and limitation cited in the **SecureFileCrypt Project Report** to its concrete repository artifacts, source code files, line numbers, benchmark outputs, automated test cases, and academic literature.

---

## 1. Reference Paper Verification

| Report Claim / Topic | Reference Paper Passage | Verified Artifact / Location | Verification Notes |
| :--- | :--- | :--- | :--- |
| **Paper Title & Authors** | *"Design of File Encryption and Decryption Application Using AES-256 Cryptography Algorithm Based on Streamlit"* by Arditya Adjie Rosandi, Dhicky Hariyadi Supriyono, Teguh Tegar Aulia, and Jefry Sunupurwa Asri. | `papers/Rosandi2026_AES256_Streamlit_Baseline.pdf` (p. 162) | Published in *International Journal of Multidisciplinary Research and Literature (IJOMRAL)*, Vol. 5, No. 1, Jan. 2026, pp. 162–168. DOI: `10.53067/ijomral.v5i1.418`. |
| **Cipher & Mode Selection** | AES-256 in Galois/Counter Mode (GCM) with 128-bit authentication tag. | `papers/Rosandi2026_AES256_Streamlit_Baseline.pdf` (p. 163–165) | Authenticated encryption providing confidentiality and integrity. |
| **Key Derivation (KDF)** | PBKDF2-HMAC-SHA256 with random salt. | `papers/Rosandi2026_AES256_Streamlit_Baseline.pdf` (p. 164–165, Fig. 2) | Paper states "sufficient number of iterations" without providing numeric count. |
| **Container Layout** | `[salt][nonce][ciphertext]` monolithic packing. | `papers/Rosandi2026_AES256_Streamlit_Baseline.pdf` (p. 165) | Minimum container is 44 bytes (16 salt + 12 nonce + 16 GCM tag). |
| **Experimental Setup** | Intel Core i5-1135G7 @ 2.40 GHz, 8 GB RAM, Windows 11 Home 64-bit. | `papers/Rosandi2026_AES256_Streamlit_Baseline.pdf` (p. 165) | Executed locally via Streamlit web interface. |
| **Timing Methodology** | Stopwatch timing from button click to download button availability. | `papers/Rosandi2026_AES256_Streamlit_Baseline.pdf` (p. 165) | Explicitly acknowledged: *"manually measured using a stopwatch"*. |
| **Reported Results (Table 2)** | F1 (.txt, 0.1 MB): Enc 0.3s, Dec 0.2s<br>F2 (.pdf, 1.25 MB): Enc 0.8s, Dec 0.7s<br>F3 (.jpg, 5.4 MB): Enc 1.9s, Dec 1.7s<br>F4 (.mp4, 18.7 MB): Enc 5.4s, Dec 5.0s | `papers/Rosandi2026_AES256_Streamlit_Baseline.pdf` (p. 166, Table 2) | Single-run stopwatch measurements capturing UI rendering and browser WebSocket roundtrip. |
| **Negative Testing** | Decryption attempts with incorrect password display error message and release zero plaintext. | `papers/Rosandi2026_AES256_Streamlit_Baseline.pdf` (p. 166–167) | Verified in baseline implementation and test suite. |

---

## 2. Baseline Reproduction Verification

| Component / Claim | Source Code Reference | Verified Property | Verification Evidence |
| :--- | :--- | :--- | :--- |
| **PBKDF2 Parameter Selection** | `baseline/crypto.py:31, 45–70` | 100,000 iterations of HMAC-SHA256, 16-byte salt, 32-byte key. | NIST SP 800-132 recommendation; achieves ~12–25 ms desktop CPU latency. |
| **Monolithic AES-256-GCM** | `baseline/crypto.py:73–101, 103–138` | `AESGCM(key).encrypt(nonce, plaintext, None)` generates ciphertext with 16-byte appended tag. | Standard OpenSSL AES-NI accelerated execution. |
| **Binary Packaging** | `baseline/file_format.py:25–39, 41–62` | `pack_container(salt, nonce, ciphertext)` and `unpack_container(data)` enforce 44-byte minimum. | Tested in `baseline/tests/test_baseline_functional.py:test_container_exact_structure`. |
| **Streamlit Interface** | `baseline/app.py:34–135` | Radio buttons ("Encrypt" / "Decrypt"), file uploader, masked password, download button. | Visually verified via live browser subagent; screenshot captured at `deliverables/figures/screenshot_baseline_streamlit.png`. |
| **Automated Functional Tests** | `baseline/tests/test_baseline_functional.py` | 7 automated unit tests covering empty file, text, F1–F3 binary files, CSPRNG freshness, and container packing. | **7 passed** out of 7 (`pytest baseline/tests/`). |
| **Automated Security Tests** | `baseline/tests/test_baseline_security.py` | 8 automated security tests covering bad passwords, ciphertext tampering, nonce tampering, salt tampering, truncation, and zero plaintext leakage. | **8 passed** out of 8 (`pytest baseline/tests/`). |
| **Total Baseline Tests** | `baseline/tests/` | Complete functional and security baseline suite. | **15 passed out of 15 tests (100%)**. |

---

## 3. Identified Limitations and Technical Justifications

| Limitation | Technical Description | Impact Analysis | Evidence in Code / Literature |
| :--- | :--- | :--- | :--- |
| **1. Unbounded Memory Scaling ($O(N)$ Space Complexity)** | Loads entire plaintext and ciphertext into RAM simultaneously (`file_bytes = uploaded_file.read()`). | Peak RAM reaches $2N + O(1)$. F4 (18.7 MB) requires 37.4 MB; F6 (100 MB) requires 200 MB. Causes out-of-memory crashes on multi-GB files. | `baseline/app.py:69, 110`<br>`benchmark/results/comparative_benchmark.json` (F1–F6 RAM scaling). |
| **2. Key Derivation Brute-Force Susceptibility** | PBKDF2-HMAC-SHA256 requires negligible memory ($<1\text{ KB}$), making it compute-bound. | Massively parallel GPU/ASIC clusters can compute $>10^8$ PBKDF2 hashes/sec, leaving modest passphrases vulnerable to offline dictionary attack. | NIST SP 800-132;<br>RFC 9106 Section 1;<br>`benchmark/results/comparative_benchmark.json` (`memory_hardness: "None (O(1) RAM)"`). |
| **3. Payload Re-Encryption on Password Modification** | Payload is encrypted directly under the password-derived key. | Changing password requires decrypting entire payload to plaintext, deriving new key, and re-encrypting entire file. Scales linearly with file size ($O(N)$ time and I/O). | `baseline/crypto.py:73–101`<br>`benchmark/results/comparative_benchmark.json:password_change_comparison` (0.834s for 50 MB). |
| **4. Metadata Loss and Privacy Leakage** | Container format `[salt][nonce][ciphertext]` discards original filename and extension while leaking exact byte length. | Decrypted files require manual extension reconstruction. Exact byte length permits side-channel document identification. | `baseline/file_format.py:41–62`<br>`baseline/app.py:116–122`. |
| **5. Experimental Timing Conflation** | Original paper measured duration with a manual stopwatch on single runs. | Conflates human reaction time (200–300 ms) and Streamlit DOM WebSocket latency with cryptographic kernel execution. | `papers/Rosandi2026_AES256_Streamlit_Baseline.pdf` (p. 165)<br>`benchmark/results/baseline_benchmark.json` (microbenchmarks vs. app workflow). |

---

## 4. Proposed and Implemented Improvements

| Feature | Architectural Specification | Implementation File & Lines | Solved Limitation |
| :--- | :--- | :--- | :--- |
| **Argon2id KDF** | RFC 9106 compliant: $t=2$, $m=64\text{ MB}$, $p=4$, 16-byte CSPRNG salt. Derives 256-bit KEK. | `improved/crypto.py:60–89`<br>`improved/file_format.py:35–38` | Neutralizes parallel GPU/ASIC offline password cracking. |
| **Envelope Encryption (DEK/KEK)** | 256-bit random DEK (`os.urandom(32)`) encrypts file chunks; DEK is wrapped by KEK using AES-256-GCM. | `improved/crypto.py:112, 126–128, 230–235` | Decouples payload encryption from password management; enables instant password changes. |
| **Chunked Streaming AEAD** | Frames plaintext into 64 KB blocks. Individual AES-256-GCM encryption with 12-byte IV (`prefix_8 \|\| counter_4`). | `improved/crypto.py:91–190`<br>`improved/file_format.py:132–136` | Bounds memory consumption to $O(\text{chunk size})$; improves CPU cache locality on large files. |
| **Chunk-Level Integrity & AAD Binding** | AAD binds `file_id (8B) \|\| chunk_index (4B) \|\| is_last (1B)`. Monotonic counter and EOF verification. | `improved/crypto.py:171–178, 269–289`<br>`improved/file_format.py:139–141` | Prevents chunk swapping, reordering, duplication, and stream truncation. |
| **Encrypted Authenticated Metadata** | JSON header containing filename, MIME type, and timestamp encrypted under KEK via AES-256-GCM. | `improved/crypto.py:130–138, 237–244`<br>`improved/file_format.py:69–70` | Guarantees filename recovery while preserving confidentiality against unauthorized inspectors. |
| **$O(1)$ Instantaneous Password Rotation** | Unwraps 32-byte DEK, derives new KEK, re-wraps DEK in updated header, and copies ciphertext chunks unmodified. | `improved/crypto.py:298–399` | Reduces password modification time to constant sub-second duration regardless of file size. |
| **Automated Improved Tests** | 16 automated tests covering functional streaming, security tampering, swapping, truncation, and key rotation. | `improved/tests/test_improved_functional.py`<br>`improved/tests/test_improved_security.py`<br>`improved/tests/test_improved_streaming.py` | **16 passed out of 16 tests (100%)**. |

---

## 5. Experimental Benchmark Results Verification

All values verified against `benchmark/results/comparative_benchmark.json` and `benchmark/results/baseline_benchmark.json`:

| File ID | Size (MB) | Metric | Baseline Measured | Improved Measured | Measured Ratio / Speedup | Source File in Repo |
| :---: | :---: | :--- | :---: | :---: | :---: | :--- |
| **F1** | 0.10 MB | Encryption Time<br>Throughput<br>Peak Heap RAM | 0.0319 s<br>3.14 MB/s<br>0.20 MB | 0.0721 s<br>1.39 MB/s<br>0.42 MB | 0.44x Enc Time<br>0.44x Throughput<br>0.48x RAM | `comparative_benchmark.json:28–71` |
| **F2** | 1.25 MB | Encryption Time<br>Throughput<br>Peak Heap RAM | 0.0256 s<br>48.88 MB/s<br>2.50 MB | 0.0620 s<br>20.18 MB/s<br>0.50 MB | 0.41x Enc Time<br>0.41x Throughput<br>**5.00x RAM Reduction** | `comparative_benchmark.json:72–115` |
| **F3** | 5.40 MB | Encryption Time<br>Throughput<br>Peak Heap RAM | 0.0433 s<br>124.65 MB/s<br>10.80 MB | 0.1798 s<br>30.03 MB/s<br>0.50 MB | 0.24x Enc Time<br>0.24x Throughput<br>**21.60x RAM Reduction** | `comparative_benchmark.json:116–159` |
| **F4** | 18.70 MB | Encryption Time<br>Throughput<br>Peak Heap RAM | 0.0756 s<br>247.35 MB/s<br>37.40 MB | 0.2946 s<br>63.48 MB/s<br>0.50 MB | 0.26x Enc Time<br>0.26x Throughput<br>**74.80x RAM Reduction** | `comparative_benchmark.json:160–203` |
| **F5** | 50.00 MB | Encryption Time<br>Throughput<br>Peak Heap RAM | 0.1640 s<br>304.96 MB/s<br>100.00 MB | 0.4488 s<br>111.40 MB/s<br>0.50 MB | 0.37x Enc Time<br>0.37x Throughput<br>**200.00x RAM Reduction** | `comparative_benchmark.json:204–247` |
| **F6** | 100.00 MB | Encryption Time<br>Throughput<br>Peak Heap RAM | 0.2565 s<br>389.86 MB/s<br>200.00 MB | 0.9073 s<br>110.22 MB/s<br>**0.50 MB** | 0.28x Enc Time (Disk vs RAM)<br>0.28x Throughput<br>**400.00x RAM Reduction** | `comparative_benchmark.json:248–291` |
| **KDF** | N/A | Mean Latency<br>Memory Cost | 18.7 ms (PBKDF2)<br>0 MB ($<1\text{ KB}$) | 109.6 ms (Argon2id)<br>**64 MB RAM** | Standard Desktop Derivation Latency<br>**Massive Memory Hardness** | `comparative_benchmark.json:9–26` |
| **Rotation** | 1.25 MB (F2)<br>18.7 MB (F4)<br>100.0 MB (F6) | Password Update Time | 0.0521 s<br>0.1174 s<br>2.0043 s | 0.3005 s<br>0.2872 s<br>**0.3571 s** | 0.17x (KDF dominates)<br>0.41x<br>**5.61x Faster (O(1) at scale)** | `comparative_benchmark.json:293–338` |

---

## 6. Full Automated Test Suite Verification

Verified by executing `pytest baseline/tests/ improved/tests/ -v` on Python 3.10.11 / Python 3.12.3:

| Test Module | Total Tests | Passed | Failed | Execution Time | Key Verified Properties |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `baseline/tests/test_baseline_functional.py` | 7 | 7 | 0 | 0.12 s | Empty files, small text, binary F1–F3 roundtrips, CSPRNG freshness, container layout. |
| `baseline/tests/test_baseline_security.py` | 8 | 8 | 0 | 0.88 s | Wrong passwords, tampered ciphertext, tampered nonce/salt, truncation, zero plaintext leak. |
| `improved/tests/test_improved_functional.py` | 6 | 6 | 0 | 0.38 s | Empty files, text, binary roundtrips, cryptographic freshness, metadata recovery. |
| `improved/tests/test_improved_security.py` | 7 | 7 | 0 | 1.15 s | Bad passwords, tampered wrapped DEK, tampered metadata, chunk tampering, swapped chunks, truncation. |
| `improved/tests/test_improved_streaming.py` | 3 | 3 | 0 | 0.70 s | Disk stream roundtrip, envelope password update, invalid old password rejection. |
| **Combined Project Test Suite** | **31** | **31** | **0** | **3.23 s** | **100% Pass Rate across entire cryptographic codebase.** |

---

## 7. Frontend, Backend API, and Telemetry Verification

| Layer / Component | Source File & Implementation | Verified Feature | Status & Audit Findings |
| :--- | :--- | :--- | :--- |
| **FastAPI REST Backend** | `server.py:30–133` | `POST /api/encrypt` endpoint supporting `mode="baseline"` and `mode="improved"`. Ingests multipart files, executes crypto, returns binary payload with telemetry headers. | **Verified**. Returns `X-Exec-Time-Sec`, `X-Peak-Ram-Mb`, `X-Throughput-Mbs`. Note: buffers via `await file.read()`. |
| **FastAPI Decrypt Endpoint** | `server.py:135–198` | `POST /api/decrypt` endpoint. Handles baseline and improved container decryption, extracting confidential metadata filename. | **Verified**. Emits HTTP 400 on `AuthenticationError`. |
| **FastAPI Key Rewrap Endpoint** | `server.py:199–249` | `POST /api/rewrap-password` endpoint. Executes $O(1)$ DEK rewrapping under new Argon2id passphrase. | **Verified**. Returns rewrapped container with `X-Operation: Envelope DEK In-Place Re-wrap (O(1))`. |
| **FastAPI Benchmarks Endpoint** | `server.py:47–55` | `GET /api/benchmarks` serves `comparative_benchmark.json` data for interactive chart rendering. | **Verified**. Serves complete F1–F6 experimental records. |
| **React 19 Frontend Dashboard** | `frontend/src/App.jsx:208–242` | Global architecture toggle between `baseline` and `improved` engines. Dynamically updates UI styling and descriptors. | **Verified**. Confirmed via live browser inspection. |
| **Crypto Lab Tab** | `frontend/src/App.jsx:289–400` | Drag-and-drop file ingestion, password entry, operation toggling, loading state, automatic file download. | **Verified**. Screenshot at `deliverables/figures/screenshot_react_crypto_lab.png`. |
| **Envelope Key Rotation Tab** | `frontend/src/App.jsx:465–538` | Form accepting encrypted container, current password, and new password. Executes zero-re-encryption password updates. | **Verified**. Screenshot at `deliverables/figures/screenshot_react_key_rotation.png`. |
| **Benchmark Analytics Tab** | `frontend/src/App.jsx:541–589` | Interactive Recharts visual bar and line charts comparing throughput and RAM across F1–F6. | **Verified**. Screenshot at `deliverables/figures/screenshot_react_benchmarks.png`. |
