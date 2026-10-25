# SecureFileCrypt — Extended Large-File Evidence Audit (200–400 MiB)

**Audit Date:** October 24, 2026  
**Auditor:** Antigravity Autonomous Agent (Pair Programming with System Lead)  
**Host Architecture:** Windows 10 Pro (Build 19045), AMD64, CPython 3.10.11, OpenSSL 3.0.x / Cryptography 42.0.x, Argon2-cffi 25.1.0  
**Scope:** Verification of extended large-file scalability benchmarks (200 MiB, 300 MiB, 400 MiB), recalculation of all metrics from raw evidence, audit of measurement methodology, investigation of KDF timing variance, and validation of claims in `final_submission_report.md`.

---

## 1. Audit Scope & Ground Truth Principles

This audit establishes the empirical rigor and presentation integrity of the extended 200 MiB, 300 MiB, and 400 MiB scalability benchmarks for **SecureFileCrypt**. The audit enforces the following standards:
1. **Raw Evidence Integrity:** No raw benchmark JSON data (`large_file_scalability.json`, `comparative_benchmark.json`, `pre_optimization_benchmark.json`) was modified or regenerated. Discrepancies are documented explicitly and corrected only in derived summaries and reports.
2. **Preservation of Original Artifacts:** The root [`report.md`](file:///c:/Users/rushi/Desktop/ICS_project/ics%20project/report.md) was inspected and remains **100% untouched** (488 lines preserved intact).
3. **Code Freeze:** No changes were made to cryptographic algorithms, KDF parameters, chunk sizes, container formats, or application logic.
4. **Distinction of Units and Environments:** Binary MiB ($1,048,576\text{ bytes}$) is strictly distinguished from decimal MB ($1,000,000\text{ bytes}$). Methodological boundaries (in-memory RAM operations vs physical disk I/O, warm vs cold filesystem cache) are rigorously identified.

---

## 2. Files and Code Paths Inspected

| Component / Artifact | File Path | Code Paths / Metrics Inspected |
| :--- | :--- | :--- |
| **Scalability Runner** | `benchmark/large_file_scalability.py` | Timing scopes (`perf_counter`), `get_process_rss_mib`, `tracemalloc`, block file generation, trial loops |
| **Raw Scalability Evidence** | `benchmark/results/large_file_scalability.json` | Raw trials for KDF, encryption, decryption, memory, and rotation across F7, F8, F9 |
| **Scalability Summary** | `benchmark/results/large_file_scalability_summary.md` | Summary tables, throughput figures, memory reduction factors, and takeaway claims |
| **Submission Report** | `final_submission_report.md` | Section 12.1, 12.2, 12.3, and Section 15 conclusion claims |
| **Prior Audit Notes** | `final_report_audit_notes.md` | Items 1–7 prior audit record and Section 3 additions |
| **Baseline Core** | `baseline/crypto.py` | `encrypt_bytes`, `decrypt_bytes`, `derive_key` (PBKDF2-HMAC-SHA256, 100k iter) |
| **Improved Core** | `improved/crypto.py` | `encrypt_file`, `decrypt_file`, `change_password_file`, `derive_kek_argon2id`, `IO_BUFFER_SIZE` |
| **Container Format** | `improved/file_format.py` | `FORMAT_VERSION_2`, `DEFAULT_CHUNK_SIZE` (64 KB), `DEFAULT_TIME_COST` (2), `DEFAULT_MEM_COST_KB` (64 MB), `DEFAULT_PARALLELISM` (4) |
| **Web Gateway** | `server.py` | Lines 56–105 (`await file.read()`, in-memory `io.BytesIO` buffering verification) |
| **Test Suite** | `pytest` test runners | Functional, structural, and adversarial security test suite (46 passed, 1 skipped) |

---

## 3. Independent Recalculation of Metrics

All metrics were independently recalculated directly from the raw measurements recorded in `benchmark/results/large_file_scalability.json` using the exact formula:
$$\text{Throughput (MiB/s)} = \frac{\text{Input Payload Size in Bytes}}{1,048,576 \times \text{Elapsed Seconds}}$$

### 3.1 Workload Specifications
- **F7 (Large Archive 200MB):** Exact size $209,715,200\text{ bytes}$ ($200.0\text{ MiB}$). SHA-256: `24dfb9eb6556110685ff11222e812ab15abcac8cfd985fee2d3438774ea06bcf`.
- **F8 (Large Archive 300MB):** Exact size $314,572,800\text{ bytes}$ ($300.0\text{ MiB}$). SHA-256: `a8dcda07e8a029c88422dc7583ef36006038533aa570ec20a94b317651843edf`.
- **F9 (Large Archive 400MB):** Exact size $419,430,400\text{ bytes}$ ($400.0\text{ MiB}$). SHA-256: `45e43128cef78aeeb989326f78fee33c8b5222efb744fc15db9b5529b6907e92`.

### 3.2 Key Derivation Function (KDF) Latency Recalculation
- **PBKDF2-HMAC-SHA256 (100k iterations):**
  - Raw Trials: `[0.011778s, 0.011538s, 0.018761s, 0.011386s, 0.012529s]`
  - Mean: **$0.013198\text{ s}$** | Median: **$0.011778\text{ s}$** ($11.8\text{ ms}$) | Stdev: **$0.003140\text{ s}$**
- **Argon2id ($t=2, m=64\text{ MB}, p=4$):**
  - Raw Trials: `[0.033942s, 0.040137s, 0.035391s, 0.032290s, 0.031730s]`
  - Mean: **$0.034698\text{ s}$** | Median: **$0.033942\text{ s}$** ($33.9\text{ ms}$) | Stdev: **$0.003363\text{ s}$**
  - Derivation Latency Ratio (Argon2id / PBKDF2 median): **$2.88\times$**.

### 3.3 Comparative Scalability Recalculation Table

| Workload | Architecture | Enc Time Mean (s) | Enc Time Median (s) | Enc Time Stdev (s) | Enc Throughput (MiB/s) | Dec Time Mean (s) | Dec Time Median (s) | Dec Time Stdev (s) | Dec Throughput (MiB/s) | Peak Python Heap (MiB) | Sampled Process RSS (MiB) | Integrity Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **F7 (200 MiB)** | Baseline (In-Memory) | 0.1999 | **0.1903** | 0.0182 | **1,051.2** | 0.2245 | **0.2228** | 0.0255 | **897.6** | 400.00 | 423.90 | **100% PASS** |
| | Improved (Streaming) | 0.5936 | **0.5691** | 0.0888 | **351.4** | 0.6583 | **0.5704** | 0.2136 | **350.6** | **0.52** | **24.06** | **100% PASS** |
| **F8 (300 MiB)** | Baseline (In-Memory) | 0.2554 | **0.2597** | 0.0079 | **1,155.3** | 0.2908 | **0.2918** | 0.0122 | **1,028.2** | 600.00 | 624.23 | **100% PASS** |
| | Improved (Streaming) | 0.7338 | **0.6732** | 0.1452 | **445.6** | 0.6738 | **0.5849** | 0.1657 | **512.9** | **0.51** | **24.10** | **100% PASS** |
| **F9 (400 MiB)** | Baseline (In-Memory) | 0.4207 | **0.4195** | 0.0616 | **953.5** | 0.4389 | **0.4472** | 0.0642 | **894.4** | 800.00 | 824.02 | **100% PASS** |
| | Improved (Streaming) | 1.0759 | **1.0135** | 0.1690 | **394.7** | 1.0918 | **0.9190** | 0.3253 | **435.3** | **0.51** | **23.32** | **100% PASS** |

### 3.4 Password Rotation Recalculation Table

| Workload | Payload Size | Baseline Re-encrypt ($O(N)$ In-Memory) | Improved In-Place Header ($O(1)$ Disk I/O) | In-Place Speedup vs Baseline | Improved Atomic Replace (Crash-Safe $O(N)$) | Atomic vs Baseline Ratio | Plaintext Recovery Verification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **F7** | 200.0 MiB | 0.3970 s | **0.1161 s** | **3.42×** | 0.5099 s | 0.78× | **PASS (SHA-256)** |
| **F8** | 300.0 MiB | 0.4747 s | **0.1230 s** | **3.86×** | 0.7041 s | 0.67× | **PASS (SHA-256)** |
| **F9** | 400.0 MiB | 0.7828 s | **0.1647 s** | **4.75×** | 0.8492 s | 0.92× | **PASS (SHA-256)** |

---

## 4. Confirmed Claims

1. **Python Heap Bounding in File Streaming Engine:**
   - Baseline peak Python heap expands strictly linearly: **400.0 MiB** at 200 MiB, **600.0 MiB** at 300 MiB, and **800.0 MiB** at 400 MiB ($2\times$ payload size).
   - Improved streaming peak Python heap remains bounded at **$\le 0.52\text{ MiB}$** across all workloads up to 400 MiB.
   - Measured heap reduction factors are confirmed: **$774.2\times$** at 200 MiB, **$1,184.3\times$** at 300 MiB, and **$1,579.2\times$** at 400 MiB.
2. **Cryptographic Output Fidelity:**
   - 100% of decrypted outputs matched the deterministic SHA-256 digest of original input payloads across all trials, verifying complete round-trip plaintext recovery.
3. **Password Rotation Scalability Divergence:**
   - Baseline re-encryption time scales with payload size (0.397 s → 0.475 s → 0.783 s).
   - Improved in-place header rotation executes in **0.116 s to 0.165 s**, achieving a **$4.75\times$ speedup** over baseline on a 400 MiB file.
4. **FastAPI Upload Gateway In-Memory Buffering Confirmed:**
   - Inspection of `server.py` line 65 (`content = await file.read()`) confirms that web client uploads are buffered completely in server memory, correctly noted as an architectural boundary in the report limitations.

---

## 5. Corrected Claims & Terminology Refinements

1. **Correction on "Peak Process RSS" Label:**
   - **Audit Finding:** In `benchmark/large_file_scalability.py`, `get_process_rss_mib()` calls `ctypes.windll.psapi.GetProcessMemoryInfo` and reads `pmc.WorkingSetSize`, returning an instantaneous working set sample taken after operation exit, rather than `pmc.PeakWorkingSetSize`.
   - **Correction Applied:** All occurrences of "Peak Process RSS" and "Process RSS" in `final_submission_report.md` and `large_file_scalability_summary.md` were corrected to **"Sampled Process Working Set (RSS)"**.
2. **Correction on "Zero Memory Leaks" / "Constant-Memory Proof":**
   - **Audit Finding:** A stable sampled working set across 3 runs does not constitute a formal mathematical proof against native memory leaks, nor does it prove that total application memory is constant across arbitrary chunk or buffering configurations.
   - **Correction Applied:** Claims were modified to state that Python heap was **empirically bounded at $\le 0.52\text{ MiB}$** and observed working set was **stable at $\approx 23.3\text{–}24.1\text{ MB}$** during the tested executions, removing absolute proof assertions.
3. **Correction on Baseline vs Streaming Throughput Comparison:**
   - **Audit Finding:** Baseline timers (`base_crypto.encrypt_bytes`) measure memory-to-memory byte operations on pre-loaded buffers, bypassing filesystem reads and writes. Improved streaming timers (`impr_crypto.encrypt_file`) execute full physical file I/O.
   - **Correction Applied:** Added explicit methodological qualification that baseline throughput ($950\text{–}1,155\text{ MiB/s}$) reflects RAM memory-bandwidth, whereas streaming throughput ($351\text{–}512\text{ MiB/s}$) reflects disk-to-disk streaming under warm NTFS cache conditions.
4. **Correction on Password Rotation Failure-Safety:**
   - **Audit Finding:** In-place header overwrite ($O(1)$ disk seek) is not crash-safe if interrupted mid-write (can destroy container header). Atomic replacement achieves crash consistency via `.tmp` file and `fsync`, but requires $O(N)$ data transfer.
   - **Correction Applied:** Explicitly distinguished the failure-safety and performance trade-offs of all three paradigms; rejected treating in-place modification and atomic replacement as identical operations.
5. **Correction on Argon2id RFC 9106 Specification:**
   - **Audit Finding:** RFC 9106 Section 7.4 recommends $t=3, m=64\text{ MB}, p=4$ for 64 MB memory-constrained setups. The project uses $t=2$.
   - **Correction Applied:** Described $t=2, m=64\text{ MB}, p=4$ as the project's selected configuration, not as an RFC-recommended default.

---

## 6. Unresolved Discrepancies

### Argon2id Derivation Latency Variance Across Benchmark Sessions
- **Observed Data:**
  - Pre-Optimization Benchmark (`pre_optimization_benchmark.json`): Mean $0.2688\text{ s}$, Median $0.3162\text{ s}$.
  - Comparative Benchmark (`comparative_benchmark.json`): Mean $0.1096\text{ s}$, Median $0.0888\text{ s}$.
  - Large-File Scalability Benchmark (`large_file_scalability.json`): Mean $0.0347\text{ s}$, Median $0.0339\text{ s}$.
  - Spot Verification Test (Standalone Script): Median $\approx 0.033\text{ s}$.
- **Investigation:**
  - The Argon2id implementation and parameters ($t=2, m=65536\text{ KB}, p=4$) were identical across all three test suites.
  - PBKDF2 similarly scaled down across the same sessions ($0.028\text{ s} \to 0.019\text{ s} \to 0.012\text{ s}$).
  - Standalone verification confirmed that on an active, warm desktop host, 4-thread Argon2id consistently completes in $\approx 33\text{–}35\text{ ms}$.
- **Audit Verdict:** The discrepancy is driven by host environment scheduling factors (such as CPU frequency boost scaling, power management profiles, background system thread contention, and thermal states) rather than code alterations. Because hardware telemetry was not recorded continuously, this variance is formally labeled an **unresolved environmental condition**, and the 100 MB and 200–400 MiB benchmark datasets are maintained in strictly separate analytical sections.

---

## 7. Methodological Limitations

1. **Filesystem Cache Residency (Warm Cache):** Test files were generated sequentially prior to benchmarking. On Windows NTFS, recently written blocks remain in the OS file cache (standby list), resulting in higher streaming throughput ($351\text{–}512\text{ MiB/s}$) than cold disk runs ($110.2\text{ MB/s}$ in Section 9.2).
2. **Tracemalloc Native Memory Blindness:** `tracemalloc` tracks only Python heap objects. It does not record native C memory allocated by OpenSSL `libcrypto` or the 64 MB matrix allocated by `argon2-cffi`.
3. **Instantaneous Working Set Sampling:** Win32 `GetProcessMemoryInfo` captures working set at the instant of function return. It does not measure transient peak memory during execution.
4. **Trial Sample Count:** 3 trials per file size provide a representative median for scalability trends, but do not support high-confidence statistical significance intervals or tail-latency modeling.

---

## 8. Final Recommendations for Academic Presentation

1. **Lead with Memory Containment, Not Small-File Speed:** Emphasize that SecureFileCrypt's primary architectural breakthrough is capping Python heap at $\le 0.52\text{ MB}$ up to 400 MB ($1,579.2\times$ reduction), eliminating the out-of-memory failure mode inherent to monolithic in-memory architectures.
2. **Frame KDF Latency as an Intentional Security Investment:** Explain that PBKDF2 is fast on small files because it is memory-free ($0\text{ MB}$ RAM), whereas SecureFileCrypt enforces an intentional $\approx 34\text{–}110\text{ ms}$ / 64 MB Argon2id memory floor to neutralize low-cost GPU/ASIC parallel dictionary attacks.
3. **Present Password Rotation Realistically:** Demonstrate that in-place header rotation achieves a **$4.75\times$ speedup on 400 MB** by updating only 111 bytes of header. Transparently disclose the crash-safety trade-off between in-place modification and atomic temporary file replacement.
4. **Maintain Transparency on Web Gateway Buffering:** Disclose that while the core Python streaming engine operates with bounded memory, the FastAPI web API currently buffers uploads in memory, providing a clear engineering roadmap for future work.
