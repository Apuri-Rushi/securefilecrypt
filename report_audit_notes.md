# SecureFileCrypt Code Audit Notes & Verification Summary

**Date of Audit:** October 24, 2026  
**Auditor:** Antigravity (Advanced Agentic Systems Pair Programmer)  
**Target Repository:** SecureFileCrypt (`Apuri-Rushi/securefilecrypt`)  
**Workspace Path:** `c:\Users\rushi\Desktop\ICS_project\ics project`  
**Execution Environment:** Windows 10 (AMD64), Python 3.10.11 (`.venv_win`), `pytest 9.1.1`, `cryptography 50.0.2`, `argon2-cffi 25.1.0`

---

## 1. Executive Summary

This audit inspected the recent modifications made to the SecureFileCrypt repository (specifically analyzing commit `7cbf225` ("improve the results by updating the code") and the current working tree). All test suites were executed live, benchmarks were rerun on the local Windows testbed, and code paths across the baseline, improved engine, FastAPI backend, and React/Streamlit frontends were systematically audited.

### Key Audit Conclusions
1. **Baseline Integrity:** The baseline implementation (`baseline/crypto.py`, `baseline/file_format.py`, `baseline/app.py`) was **completely untouched** by recent commits. It remains a faithful reproduction of Rosandi et al. (2026) with 100,000 PBKDF2 iterations and monolithic AES-256-GCM.
2. **Improved Cryptographic Upgrades Verified:** The improved implementation genuinely contains the claimed architectural enhancements:
   - Version 2 Container Format (`AGY2` v2) with full fixed-header Authenticated Associated Data (AAD) cryptographic binding.
   - Encrypted metadata payload with 64-byte PKCS#7 block padding to eliminate filename length leakage.
   - Defensive parameter-bomb bounds validation (`validate_kdf_parameters`, `validate_chunk_size`).
   - Granular exception hierarchy (`IncorrectPasswordError`, `CorruptedChunkError`, `StreamTruncationError`, `TrailingDataError`).
   - Trailing unauthenticated data detection after final stream chunk.
   - Path-traversal sanitization (`sanitize_filename`).
   - File-to-file atomic streaming encryption, decryption, and password rotation.
3. **Test Suite Outcomes:** The unified test suite collected **46 tests**: **45 passed, 1 skipped** (0 failed, 0 errors). The single skipped test (`test_secure_file_permissions`) explicitly checks for POSIX `0600` file permission masks and is designed to skip on non-POSIX operating systems (Windows).
4. **Architectural Distinctions Verified:**
   - *Cryptographic Engine:* Genuinely streams chunk-by-chunk with bounded heap allocation ($O(\text{chunk\_size})$).
   - *Web API (`server.py`):* Buffers the entire upload in memory via `content = await file.read()` before passing to the engine. The entire application path is **not** constant-memory over HTTP.
   - *Password Rotation:* Cryptographic DEK re-wrapping is $O(1)$ in time and CPU work. However, stream-based password rotation (`change_password_stream` / `/api/rewrap-password`) copies the remaining ciphertext payload, incurring $O(N)$ transfer costs. True $O(1)$ disk I/O occurs only during in-place file header overwrites (`change_password_file(..., atomic=False)`).
5. **Fresh Benchmark Results:** Rerun with 3 trials per file on Windows 10. PBKDF2 mean latency was 0.0283 s; Argon2id mean latency was 0.2688 s (64 MB cost). Peak Python heap allocation during streaming remained constant at 0.25–0.27 MB up to 100 MB, whereas baseline scaled linearly up to 200.0 MB.

---

## 2. Code Changes Discovered in Recent Commits

### Commit `7cbf225` Analysis ("improve the results by updating the code")

| File Path | Nature of Modification | Verified Functionality |
| :--- | :--- | :--- |
| `improved/file_format.py` | Added Version 2 specification, DoS parameter bounds, PKCS#7 padding | `FORMAT_VERSION_2 = 2` is default. `pad_metadata` / `unpad_metadata` (64-byte blocks). Strict limits on time cost (1–10), memory cost (8 MB–512 MB), parallelism (1–8), chunk size (1 KB–64 MB). `compute_dek_aad` binds entire header in V2. |
| `improved/crypto.py` | Engine expansion (from ~350 lines to 812 lines) | Added `sanitize_filename`, granular exceptions (`CorruptedChunkError`, `StreamTruncationError`, `TrailingDataError`), trailing byte check, `change_password_file` (in-place vs atomic), `encrypt_file` / `decrypt_file` with atomic temporary files and `os.replace`. |
| `improved/tests/test_improved_security.py` | Added 6 new security tests | Verified rejection of V2 header tampering, trailing unauthenticated data, invalid chunk payload lengths, duplicated chunks, unsupported versions, parameter bombs, and path-traversal payloads. |
| `improved/tests/test_improved_streaming.py` | Added comprehensive file streaming suite (8 tests) | Verified roundtrip file streaming, envelope password rotation, rejection of bad old passwords, payload ciphertext invariance, atomic temporary file replacement, and memory bound. |
| `benchmark/run_comparative_benchmarks.py` | Added pure vs end-to-end timing, sensitivity analysis | Measures KDF isolation, password rotation comparison, chunk-size sensitivity across 32 KB–1024 KB, and saves structured JSON. |
| `baseline/` | **Zero modifications** | Preserved exact reference reproduction without deviation. |
| `server.py` | Last modified in `c7f32c5` | Endpoints for `/api/encrypt`, `/api/decrypt`, `/api/rewrap-password`, `/api/benchmarks`. Retains `await file.read()` full buffering. |
| `frontend/src/App.jsx` | Last modified in `5b7a1fc` | Configurable `API_BASE` (`import.meta.env.VITE_API_BASE_URL`), password confirmation field, telemetry rendering from headers. |

---

## 3. Verified Test Execution Details

### Execution Command
```powershell
.\.venv_win\Scripts\pytest.exe -v
```

### Environment
- **Platform:** Windows 10 (win32 / AMD64)
- **Python Version:** 3.10.11
- **Pytest Version:** 9.1.1
- **Plugins:** `anyio 4.15.1`, `dash 3.3.0`, `Faker 40.36.0`

### Test Count Summary
- **Collected Items:** 46
- **Passed:** 45
- **Skipped:** 1 (`improved/tests/test_improved_streaming.py::TestImprovedStreaming::test_secure_file_permissions`)
- **Failed:** 0
- **Errors:** 0
- **Duration:** 10.88 seconds

### Module-by-Module Breakdown

| Module | Category | Collected | Passed | Skipped | Failed | Notes |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| `baseline/tests/test_baseline_functional.py` | Functional | 7 | 7 | 0 | 0 | 0-byte, small text, 100KB, 1.25MB, 3MB binary, freshness, format. |
| `baseline/tests/test_baseline_security.py` | Security | 8 | 8 | 0 | 0 | Wrong pwd, tampered CT, tampered nonce, tampered salt, truncation, empty pwd, zero leakage. |
| `improved/tests/test_improved_functional.py` | Functional | 10 | 10 | 0 | 0 | Empty file, text, binary (100KB, 1.25MB, 5MB), Unicode/special names, long names, all 256 bytes, V1 legacy compat, freshness. |
| `improved/tests/test_improved_security.py` | Security | 13 | 13 | 0 | 0 | Wrong pwd, tampered wrapped DEK, tampered meta, tampered chunk CT, swapped chunks, truncation, V2 header tampering, trailing data, payload length bounds, duplicated chunk, unsupported version, parameter bomb, path traversal. |
| `improved/tests/test_improved_streaming.py` | Streaming / Password | 8 | 7 | 1 | 0 | File stream roundtrip, envelope password update, invalid old pwd, in-place change, atomic disk change, payload ciphertext invariance. (Permission test skipped on Windows). |
| **Total** | | **46** | **45** | **1** | **0** | **100% pass rate among platform-applicable tests.** |

---

## 4. Benchmark Re-generation Details

### Execution Command
```powershell
.\.venv_win\Scripts\python.exe benchmark/run_comparative_benchmarks.py --trials 3 --extended
.\.venv_win\Scripts\python.exe benchmark/plot_results.py
```

### Output Files Generated
1. `benchmark/results/comparative_benchmark.json` (Structured JSON dataset, 14,226 bytes)
2. `benchmark/results/benchmark_charts.png` (High-resolution 4-panel comparison visualization)

### Hardware & Platform Context
- **Operating System:** Windows 10 AMD64
- **Runtime:** CPython 3.10.11
- **Cryptographic Backend:** `cryptography 50.0.2` (OpenSSL 3.x with AES-NI support), `argon2-cffi 25.1.0`

### Summary of Fresh Numerical Findings

#### 1. Key Derivation Functions (3 trials)
- **PBKDF2-HMAC-SHA256 (100,000 iter):** Mean = 0.0283 s, Median = 0.0278 s, Stdev = 0.0012 s. Memory = 0 MB.
- **Argon2id (RFC 9106, t=2, m=64MB, p=4):** Mean = 0.2688 s, Median = 0.3162 s, Stdev = 0.0958 s. Memory = 64 MB.

#### 2. End-to-End Encryption & Memory Summary

| File ID | File Type | Size (MB) | Base Enc (s) | Impr Enc (s) | Base Throughput | Impr Throughput | Base Peak RAM | Stream Peak RAM | Peak RAM Reduction |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **F1** | Text (.txt) | 0.10 | 0.050 s | 0.467 s | 2.0 MB/s | 0.2 MB/s | 0.20 MB | 0.25 MB | ~1.2x higher (header) |
| **F2** | PDF Document | 1.25 | 0.126 s | 0.636 s | 9.9 MB/s | 2.0 MB/s | 2.50 MB | 0.27 MB | **9.3x less** |
| **F3** | Image (.jpg) | 5.40 | 0.170 s | 0.728 s | 31.8 MB/s | 7.4 MB/s | 10.80 MB | 0.27 MB | **40.0x less** |
| **F4** | Video (.mp4) | 18.70 | 0.258 s | 0.766 s | 72.4 MB/s | 24.4 MB/s | 37.40 MB | 0.27 MB | **138.4x less** |
| **F5** | Archive (.bin) | 50.00 | 0.328 s | 1.050 s | 152.4 MB/s | 47.6 MB/s | 100.00 MB | 0.27 MB | **370.0x less** |
| **F6** | Large Archive | 100.00 | 0.825 s | 2.583 s | 121.2 MB/s | 38.7 MB/s | 200.00 MB | 0.27 MB | **740.0x less** |

*Note on Memory:* All memory measurements represent peak Python heap allocations tracked via `tracemalloc`.

#### 3. Password Rotation Latency
- **F2 (1.25 MB):** Baseline Full Re-encryption = 0.2321 s vs. Envelope Re-wrap = 1.8225 s (Baseline is faster; 0.13x).
- **F4 (18.7 MB):** Baseline Full Re-encryption = 0.1797 s vs. Envelope Re-wrap = 0.4822 s (Baseline is faster; 0.37x).
- **F5 (50.0 MB):** Baseline Full Re-encryption = 0.8632 s vs. Envelope Re-wrap = 0.6493 s (**Envelope is 1.33x faster**).
- **F6 (100.0 MB):** Baseline Full Re-encryption = 1.1049 s vs. Envelope Re-wrap = 3.4136 s (Stream copy overhead in Python `BytesIO` on Windows).

---

## 5. Discrepancies with Previous Reports & Unverified Claims

1. **Test Count Discrepancy:**
   - *Previous report claim:* "All 31 unit tests passed."
   - *Audit finding:* There are now **46 tests** in the test discovery tree (15 baseline tests + 31 improved tests). In the verified run, **45 passed and 1 was skipped**. The statement that 31 tests passed is outdated and must not be used.
2. **Platform & Benchmark Provenance:**
   - *Previous report claim:* Recorded benchmarks executed on `Linux 6.18.54.1-microsoft-standard-WSL2 (Python 3.12.3)`.
   - *Audit finding:* The current repository was tested and benchmarked on `Windows 10 AMD64 (Python 3.10.11)`. The new report clearly distinguishes the newly generated Windows 10 dataset from the retained historical WSL2 dataset.
3. **Universality of "Speedup":**
   - *Previous report implication:* Implied the improved version was faster overall.
   - *Audit finding:* For small files (F1–F4), the improved version has **lower end-to-end throughput** because Argon2id derivation requires ~268 ms of CPU work vs. ~28 ms for PBKDF2. Only for large archives when measuring pure streaming without KDF dominance, or during memory-constrained operations, does the streaming engine display advantages. The report states this trade-off clearly.
4. **End-to-End Streaming vs. API Buffering:**
   - *Previous report claim:* Implied the complete application operates in constant memory.
   - *Audit finding:* While `improved/crypto.py` (`encrypt_file`, `decrypt_file`, `encrypt_stream`) is strictly $O(1)$ memory bounded, `server.py` uses `await file.read()`, buffering the entire upload into RAM before invoking the engine. The report explicitly documents this layer boundary.
5. **Password Rotation Complexity:**
   - *Previous report claim:* "O(1) password change across all contexts."
   - *Audit finding:* Cryptographic key modification is $O(1)$ (only the 32-byte DEK is decrypted and re-encrypted). However, generating a new container file or transmitting a re-wrapped stream requires transferring the ciphertext payload, which takes $O(N)$ I/O time unless performed as an in-place file header overwrite (`change_password_file(..., atomic=False)`).

---

## 6. Actions Completed During Audit

- [x] Inspected Git status and full diff of commit `7cbf225`.
- [x] Verified baseline modules: confirmed zero unintended modifications.
- [x] Verified improved modules: confirmed all Version 2 cryptographic features, padding, and DoS bounds.
- [x] Verified FastAPI backend (`server.py`) and React dashboard (`frontend/`).
- [x] Executed full test suite via `pytest` (45 passed, 1 skipped).
- [x] Re-executed complete comparative benchmark harness (`run_comparative_benchmarks.py`) with 3 trials across F1–F6.
- [x] Regenerated visual comparative charts (`benchmark_charts.png`).
- [x] Compiled `report_audit_notes.md` (this file).
- [x] Generated comprehensive updated project report (`report.md`) adhering to all nine faculty-mandated sections.
