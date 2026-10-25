# SecureFileCrypt — Large-File Scalability Benchmark Summary (200 MiB, 300 MiB, 400 MiB)

- **Benchmark Date:** 2026-10-24T12:24:06Z
- **Platform:** Windows 10 Pro (AMD64), CPython 3.10.11
- **Stream Configuration:** 64 KiB chunks, 128 KiB stream I/O buffering
- **Trials per Workload:** 3 repeated measurement trials (medians, means, stdev reported)
- **Methodological Distinction:** Baseline operates entirely in-memory on raw byte buffers (RAM-to-RAM, no disk I/O); Improved streaming performs authenticated chunked streaming with physical disk reads and writes (Disk-to-Disk).

---

## 1. Key Derivation Function Baseline

| KDF Algorithm | Parameters | Mean Latency | Median Latency | Standard Deviation | Memory Hardness |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **PBKDF2-HMAC-SHA256** | 100,000 iterations (reconstruction choice) | 0.0132 s | 0.0118 s | 0.0031 s | 0 MB (O(1) RAM) |
| **Argon2id** | Project Selected: t=2, m=64 MB, p=4 | 0.0347 s | 0.0339 s | 0.0034 s | 64 MB native matrix |

*Note on Parameter Specification:* The project parameters for Argon2id ($t=2, m=64\text{ MB}, p=4$) reflect a project design selection balancing memory-hardness with desktop interactive usability. RFC 9106 Section 7.4 recommends $t=3, m=64\text{ MB}, p=4$ for 64 MB memory-constrained deployments.

*Note on Timing Variance:* Argon2id derivation completed in 0.0339 s in this benchmark session, compared to 0.0888 s in the 100 MB comparative run and 0.2688 s in pre-optimization testing. PBKDF2 similarly scaled down (0.028 s → 0.019 s → 0.012 s). This variance is attributed to host CPU clock boost scaling, background thread contention, and thermal states, and is treated as an unresolved environmental condition.

---

## 2. Comparative Scalability Results (200 MiB, 300 MiB, 400 MiB)

### A. Encryption and Decryption Latency & Throughput
*Throughput formula: `throughput (MiB/s) = input_size_bytes / 1,048,576 / elapsed_seconds`.*

| File ID | Payload Size | Base Enc (Median) | Stream Enc (Median) | Base Enc Tput (Median) | Stream Enc Tput (Median) | Base Dec (Median) | Stream Dec (Median) | Base Dec Tput (Median) | Stream Dec Tput (Median) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **F7** | 200 MiB | 0.190 s | 0.569 s | 1,051.2 MiB/s | 351.4 MiB/s | 0.223 s | 0.570 s | 897.6 MiB/s | 350.6 MiB/s |
| **F8** | 300 MiB | 0.260 s | 0.673 s | 1,155.3 MiB/s | 445.6 MiB/s | 0.292 s | 0.585 s | 1,028.2 MiB/s | 512.9 MiB/s |
| **F9** | 400 MiB | 0.419 s | 1.014 s | 953.5 MiB/s | 394.7 MiB/s | 0.447 s | 0.919 s | 894.4 MiB/s | 435.3 MiB/s |

*Methodological Asymmetry:* Baseline throughput reflects pure memory-to-memory operations (bypassing disk I/O), whereas Improved streaming throughput includes physical filesystem reads and writes under warm NTFS cache conditions.

### B. Memory Scaling: Peak Python Heap vs Sampled Process Working Set (RSS)

| File ID | Payload Size | Baseline Peak Heap | Stream Peak Heap | Measured Heap Reduction | Baseline Sampled RSS | Stream Sampled RSS | Plaintext Fidelity Check |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **F7** | 200 MiB | 400.0 MiB | 0.52 MiB | **774.2x less heap** | 423.9 MiB | 24.1 MiB | **PASS (SHA-256)** |
| **F8** | 300 MiB | 600.0 MiB | 0.51 MiB | **1,184.3x less heap** | 624.2 MiB | 24.1 MiB | **PASS (SHA-256)** |
| **F9** | 400 MiB | 800.0 MiB | 0.51 MiB | **1,579.2x less heap** | 824.0 MiB | 23.3 MiB | **PASS (SHA-256)** |

*Memory Instrumentation Notes:*
- Python heap is instrumented via `tracemalloc`, which tracks Python runtime objects and byte buffers but excludes native C memory allocated by OpenSSL or `argon2-cffi` (such as the 64 MB Argon2id matrix).
- Process Working Set (RSS) is an instantaneous sample (`pmc.WorkingSetSize` via Win32 `GetProcessMemoryInfo`) taken at operation completion, not a continuous trace of `PeakWorkingSetSize`.
- Observed heap bounding and stable working set reflect measured behavior during these benchmark runs and do not constitute a formal proof of constant memory across all configurations or an absolute guarantee against native memory leaks.

---

## 3. Password Rotation Scalability Across Paradigms

| File ID | Payload Size | Baseline Re-encrypt ($O(N)$ Crypto) | Improved In-Place Header ($O(1)$ Disk I/O) | In-Place Speedup vs Baseline | Improved Atomic Replace (Crash-Safe $O(N)$) | Plaintext Fidelity |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **F7** | 200 MiB | 0.397 s | **0.116 s** | **3.42x** | 0.510 s | **PASS (SHA-256)** |
| **F8** | 300 MiB | 0.475 s | **0.123 s** | **3.86x** | 0.704 s | **PASS (SHA-256)** |
| **F9** | 400 MiB | 0.783 s | **0.165 s** | **4.75x** | 0.849 s | **PASS (SHA-256)** |

*Paradigm Failure-Safety and Performance Trade-Offs:*
1. **Baseline Full Re-encryption:** Decrypts the entire payload in RAM, derives a new PBKDF2 key, and re-encrypts the entire file ($O(N)$ crypto and RAM).
2. **Improved In-Place Header Rewrite:** Decrypts the wrapped DEK using the old KEK, derives a new Argon2id KEK, re-wraps the DEK, seeks to file offset 0, and overwrites the 111-byte header directly ($O(1)$ disk I/O, leaves all ciphertext chunks untouched). *Limitation:* Not crash-safe; an interruption during the 111-byte write can destroy the header and corrupt the container.
3. **Improved Atomic File Replacement:** Re-wraps the DEK, writes the new header, streams all existing ciphertext chunks into a `.tmp` file, calls `os.fsync`, and atomically replaces the original file via `os.replace`. Provides full crash consistency on supported filesystems (NTFS/POSIX) at the cost of $O(N)$ streaming data transfer.

---

## 4. Key Takeaways & Empirical Verification

1. **Linear Heap Expansion in Baseline:** Baseline peak Python heap expands strictly linearly: 400.0 MiB at 200 MiB, 600.0 MiB at 300 MiB, and 800.0 MiB at 400 MiB ($2\times$ payload size), accompanied by proportional working-set growth (up to 824.0 MiB at 400 MiB).
2. **Observed Python Heap Bounding in Improved Streaming:** Improved streaming peak Python heap remained bounded at **$\le 0.52\text{ MiB}$** across all workloads up to 400 MiB, demonstrating a **1,579.2x heap memory reduction** at 400 MiB (800.0 MiB vs 0.51 MiB) with sampled process working set remaining at ~23–24 MiB.
3. **Decoupled Key Management Efficiency:** In-place header rotation scales independently of file payload size, updating the 111-byte container header in **0.165 s** on 400 MiB (a **4.75x speedup** over baseline re-encryption at 0.783 s). Where crash safety is strictly required, atomic replacement achieves crash-consistency in 0.849 s.
4. **Complete Cryptographic Plaintext Fidelity:** 100% of decrypted outputs matched the deterministic SHA-256 digest of the original files across all trials.
