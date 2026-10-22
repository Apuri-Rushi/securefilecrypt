# Comparative Analysis & Feasibility Report: Current Implementation vs. Kaushik & Srivastava (2020)

**Subject:** Architectural comparison, feasibility study, and security/engineering evaluation of transitioning the current file encryption system to the approach described in:  
> *Kaushik, A., & Srivastava, V. K. (2020).* **"Performance Analysis Of AES And DESede On The Sensitive Data Stored In HDFS."** *2020 2nd International Conference on Advances in Computing, Communication Control and Networking (ICACCCN)*, IEEE, pp. 319–322. DOI: `10.1109/ICACCCN51052.2020.9362755`.

---

## Executive Summary

The direct answers to your core questions:

1. **"Can I change the current implementation to this paper?"**  
   **No, you should NOT replace or migrate your current implementation to the paper's model.**  
   Doing so would cause a **severe regression in cryptographic security, software architecture, and usability**.

2. **"Is it fine to improve this?"**  
   **Only at the conceptual level (specifically: selective field encryption for tabular datasets).**  
   You should definitely **not** adopt DESede (3DES), Hadoop MapReduce, or unauthenticated cipher modes. Your current codebase (`improved/` directory) is vastly superior in engineering, cryptographic integrity, and performance.

---

## 1. Summary of Both Systems

### A. The Provided Paper (Kaushik & Srivastava, 2020)
* **Objective:** Compare execution time and storage overhead of **AES** (128-bit) versus **DESede** (Triple-DES / 3DES, 168-bit) on sensitive attributes of data stored in the Hadoop Distributed File System (HDFS).
* **Environment & Tech Stack:**
  * Java on Eclipse.
  * Hadoop MapReduce (encryption and decryption executed inside the Mapper tasks).
  * Single-Node Hadoop cluster running in a virtual machine (CentOS 6.4, Linux Kernel 2.6.32, 4 GB RAM) via VMware on Windows 10.
  * Storage: HDFS blocks with default replication.
* **Target Dataset:** Kaggle PaySim synthetic mobile transaction dataset (11 attributes).
* **Strategy:** **Selective column encryption** — only 3 out of 11 fields (`Payment-type`, `NameOrig`, `Namedest`) are encrypted, leaving 8 fields in plaintext to maintain analytics efficiency.
* **Tested File Sizes:** 20 MB, 40 MB, 80 MB, 160 MB, and 320 MB.
* **Paper's Key Conclusions:**
  1. **Speed:** AES is significantly faster than DESede for both encryption and decryption across all file sizes.
  2. **Storage:** In their benchmark, AES ciphertext occupied ~7% more storage than DESede ciphertext on HDFS (due to block padding and string/base64 representation of 128-bit vs 64-bit cipher blocks).
  3. **Security:** AES is far more secure. The authors explicitly state that DESede is vulnerable to modern attacks.
  4. **Decryption vs Encryption Time:** Decryption took less time because MapReduce read/map operations were executed in parallel.

---

### B. Your Current Implementation (`ics project`)
* **Objective:** Secure, general-purpose file encryption and decryption application featuring both a baseline faithful reproduction (Rosandi et al., 2026) and a production-grade improved system.
* **Environment & Tech Stack:**
  * Modern Python 3.10+ / 3.12 stack with `cryptography`, `argon2-cffi`, and `streamlit`.
  * Standalone, lightweight, cross-platform local desktop/web UI.
* **Cryptographic Architecture:**
  * **Ciphers:** **AES-256-GCM** (Galois/Counter Mode — Authenticated Encryption with Associated Data / AEAD).
  * **KDF:** **Argon2id** (RFC 9106, memory-hard against GPU/ASIC attacks) with envelope encryption (KEK wrapping a random DEK) alongside a PBKDF2-HMAC-SHA256 baseline.
  * **Streaming / Memory:** Constant **$O(1)$ memory usage** with 64 KB chunk frames, per-chunk GHASH tags, monotonic chunk counters, and authenticated metadata headers.
  * **Security Properties:** Confidentiality, integrity, authenticity, chunk-swapping / truncation resistance, and instantaneous ($O(1)$) password changes without data re-encryption.

---

## 2. In-Depth Side-by-Side Comparison

| Feature / Dimension | Your Current Implementation (`ics project`) | Kaushik & Srivastava Paper (2020) | Evaluation / Verdict |
| :--- | :--- | :--- | :--- |
| **Primary Domain** | Universal File Encryption (arbitrary binaries, PDFs, images, archives) | Big Data Analytics (tabular CSV / structured records) | Different target domains |
| **Symmetric Cipher** | **AES-256** | **AES-128** vs. **DESede (3DES)** | Current is modern standard (256-bit vs 128/112-bit) |
| **Cipher Mode** | **GCM** (Authenticated Encryption with GHASH AEAD) | Unspecified (likely unauthenticated ECB/CBC with PKCS5) | Current guarantees message integrity; paper does not |
| **Key Derivation (KDF)** | **Argon2id** (Memory-hard) & PBKDF2-HMAC-SHA256 | Direct generation via `KeyGenerator` | Current supports secure user passphrases |
| **Integrity / Tamper Proofing** | **Full AEAD** (Per-chunk GHASH tags, AAD binding) | **None** (No MAC / HMAC / AEAD tag) | Paper is vulnerable to bit-flipping attacks |
| **Key Management** | **Envelope Encryption** (DEK wrapped by KEK, instant password change) | Single symmetric key loaded directly into Mapper | Current enables key rotation without re-encrypting data |
| **Memory Footprint** | **$O(1)$ Bounded** (64 KB streaming pipeline) | Loads entire records / files into JVM memory buffers | Current scales to multi-gigabyte files seamlessly |
| **Infrastructure Overhead** | **Zero** (Single Python script / lightweight Streamlit server) | **Extremely Heavy** (Hadoop cluster, HDFS NameNode/DataNode, MapReduce) | Requires dedicated cluster / complex VM setup |
| **Encryption Scope** | Full file binary encryption | Selective field encryption (3 of 11 columns) | Trade-off between universal safety vs queryability |

---

## 3. Why You Should NOT Migrate to the Paper's Approach

### 1. Severe Security Degradation (DESede / 3DES is Deprecated)
* **NIST Deprecation:** NIST Special Publication 800-131A formally **deprecated and disallowed Triple-DES (DESede)** for all applications after 2023.
* **Sweet32 Vulnerability (CVE-2016-2183):** Because DESede uses tiny **64-bit blocks**, it suffers from birthday-bound collision vulnerabilities after encrypting merely $\approx 32\text{ GB}$ under the same key.
* **Effective Key Length:** 3DES provides at most 112 bits of effective security (due to Meet-in-the-Middle attacks), while your current system provides **256-bit quantum-resistant symmetric security**.
* Adding DESede would weaken your system and violate modern security standards.

### 2. Lack of Authenticated Encryption (No AEAD)
* The paper relies on legacy Java Cryptography Extension defaults (`Cipher.getInstance("AES")` / `Cipher.getInstance("DESede")`), which lack built-in authentication (AEAD).
* Without an authentication tag (such as GCM's GHASH), ciphertexts are susceptible to:
  * **Chosen-Ciphertext Attacks (CCA)**
  * **Padding Oracle Attacks**
  * **Bit-Flipping Attacks** (an adversary can tamper with transaction details without detection).
* Your current system uses **AES-256-GCM**, which cryptographically guarantees that any tampered bit results in immediate decryption rejection.

### 3. Architecture & Infrastructure Mismatch
* The paper requires a **Hadoop Distributed File System (HDFS)** cluster with HDFS client libraries, a Java VM, NameNode/DataNode daemons, and MapReduce jobs.
* Your current codebase is a clean, self-contained, high-performance Python application designed for local and edge file encryption.
* Forcing Hadoop into your current project adds massive architectural bloat, complex dependencies (Java, Hadoop binaries, HDFS daemons), and slow JVM startup overhead for simple file encryption tasks.

### 4. File-Level vs. Column-Level Scope
* The current system encrypts **any file format** (PDF, PNG, MP4, DOCX, ZIP, binary datasets).
* The paper's technique parses a specific CSV schema (PaySim transactions) and encrypts only selected strings. If given an arbitrary binary file, the paper's method cannot function.

---

## 4. What CAN Be Adopted or Improved from the Paper?

While you should not replace your codebase with the paper's stack, you **can extract valuable concepts** to introduce an optional enhancement or module:

### Beneficial Concept: "Selective / Attribute-Level Data Encryption" (Format-Preserving / Column-Level Mode)
In real-world data engineering and cloud compliance (GDPR, HIPAA, PCI-DSS):
* Storing massive analytical tables entirely encrypted makes querying and aggregating non-sensitive data impossible without first decrypting the whole file.
* **Viable Enhancement:** Add a **"Dataset / CSV Protection"** utility module to your current project that:
  1. Accepts structured tabular files (CSV, Parquet, or JSON).
  2. Allows the user to select specific sensitive columns (e.g., `SSN`, `credit_card`, `customer_id`, `recipient`).
  3. Encrypts **only those specific columns using AES-256-GCM** (generating deterministic or randomized authenticated tokens) while leaving analytical fields (e.g., `timestamp`, `transaction_amount`, `category`) intact for search and analytics.

---

## 5. Final Recommendation & Conclusion

| Question | Assessment | Recommendation |
| :--- | :--- | :--- |
| **Can I change the current implementation to this paper?** | ❌ **Not recommended** | Do not replace the existing AES-256-GCM / Argon2id streaming implementation with DESede and Hadoop MapReduce. |
| **Is it fine to use this to improve the project?** | ⚠️ **Only conceptually** | Do not adopt DESede or legacy Hadoop setups. You may only borrow the idea of **selective column-level encryption** for tabular data if your project needs database/CSV analytics support. |
| **Current Implementation Quality** | ⭐⭐⭐⭐⭐ **State of the Art** | Your current `improved/` system (Argon2id, envelope encryption, chunked AEAD, $O(1)$ memory scaling) is vastly superior in security, engineering, and performance compared to the 2020 paper. |
