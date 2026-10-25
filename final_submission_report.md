# SecureFileCrypt: Password-Based File Encryption Using Argon2id and AES-256-GCM
## A Comparative Cryptosystem Study on Memory-Bounded Streaming, Envelope Encryption, and Authenticated File Storage

**Course / Degree:** Bachelor of Technology (B.Tech) in Computer Science and Engineering / Information and Cyber Security  
**Academic Year:** 2026–2027  
**Project Title:** SecureFileCrypt: Comparative Design, Implementation, and Evaluation of Password-Based File Cryptosystems  
**Repository:** `Apuri-Rushi/securefilecrypt`  
**Host Architecture:** Windows 10 Pro (Build 19045), AMD64 Architecture, CPython 3.10.11, OpenSSL 3.0.x / Cryptography 42.0.x, Argon2-cffi 25.1.0  
**Baseline Reference Paper:** Arditya Adjie Rosandi, Dhicky Hariyadi Supriyono, Teguh Tegar Aulia, and Jefry Sunupurwa Asri (2026), *"Design of File Encryption and Decryption Application Using AES-256 Cryptography Algorithm Based on Streamlit"*, published in *International Journal of Multidisciplinary Research and Literature*, Vol. 5, No. 1, January 2026, pp. 162–168.  
**Report Type:** Final Academic Submission Report  
**Date of Submission:** October 2026  

---

## Abstract

This paper presents an academic, empirical, and architectural investigation into password-based file encryption applications, using the **SecureFileCrypt** project as a primary reference testbed. We analyze and experimentally compare two distinct architectures: (1) a baseline cryptosystem reconstructed from the reported design of Rosandi et al. (2026), which relies on monolithic AES-256-GCM authenticated encryption paired with PBKDF2-HMAC-SHA256, and (2) an advanced, memory-bounded architecture that integrates RFC 9106 Argon2id memory-hard key derivation, dual-key envelope encryption (Data Encryption Key / Key Encryption Key), bounded chunk-based authenticated streaming AEAD, encrypted container metadata, and atomic passphrase rotation.

Using an empirical test suite of standardized files spanning 0.1 MB to 100.0 MB across multiple formats (text, PDF, image, video, and binary archives), we evaluate throughput, computational latency, Python heap allocations, and process Working Set (RSS). The empirical findings demonstrate significant architectural trade-offs. The baseline implementation exhibits lower overall latency on small files ($\le 5\text{ MB}$) due to the negligible computational cost of PBKDF2 ($18.7\text{ ms}$ with $O(1)$ RAM), but suffers from linear memory scaling ($O(N)$), consuming over $200.0\text{ MB}$ of Python heap on a 100 MB archive and requiring full file decryption and re-encryption during password updates. Conversely, the improved streaming implementation maintains a bounded Python heap in its file-streaming engine ($\le 0.50\text{–}0.75\text{ MB}$), demonstrating up to a measured $396.5\times$ reduction in Python heap allocation relative to the baseline on a 100 MB archive. It eliminates payload re-encryption during password updates via in-place header rotation ($0.3571\text{ s}$ vs $2.0043\text{ s}$, a $5.61\times$ speedup on the tested 100 MB workload), and achieves a verified streaming encryption throughput of **$110.22\text{ MB/s}$** and decryption throughput of **$162.22\text{ MB/s}$** on 100 MB archives following 128 KB buffer alignment and zero-concatenation framing optimizations. Automated regression testing validates implementation adherence and active adversary rejection across 45 test cases (1 platform-appropriate skip). Finally, we report the remaining architectural limitations of the FastAPI upload gateway and outline defensible bounds for real-world cryptographic deployment.

---

## 1. Introduction

Securing digital files against unauthorized inspection and active tampering is a foundational necessity in modern distributed information systems. Symmetric authenticated ciphers—specifically the Advanced Encryption Standard running in Galois/Counter Mode (AES-256-GCM)—represent the global standard for securing data at rest and in transit. AES-256-GCM provides both confidentiality and cryptographic integrity under standard cryptographic assumptions, utilizing a 128-bit GHASH authenticator tag to detect unauthorized ciphertext modifications.

In early 2026, Rosandi et al. published a design study investigating a user-friendly, browser-based encryption tool utilizing Streamlit and AES-256. While their study demonstrated the functional accessibility of symmetric encryption for desktop end-users, it adopted a traditional, monolithic architecture: deriving a single cryptographic key directly from a passphrase using PBKDF2 and processing the entire file in a single in-memory cipher operation.

While suitable for lightweight educational demonstrations, this monolithic paradigm presents three fundamental engineering and security bottlenecks when scaled to modern operating environments:
1. **Susceptibility of Password Derivation to GPU/ASIC Cracking:** PBKDF2-HMAC-SHA256 is strictly compute-bound and memory-free ($O(1)$ RAM). Modern adversary hardware (GPUs, FPGAs, and ASICs) can evaluate billions of PBKDF2 hashes per second in parallel because the algorithm requires minimal local register storage.
2. **Memory Exhaustion on Large Files:** In-memory cipher calls require holding both the complete plaintext and the complete ciphertext in memory simultaneously ($2\times$ file size), leading to potential memory exhaustion or out-of-memory (OOM) failures on multi-gigabyte files.
3. **Password Rotation Penalty:** Because the file is encrypted directly with the password-derived key, changing a password requires decrypting the entire file, deriving a new key, and re-encrypting the entire payload—incurring severe disk I/O and CPU overhead.

To resolve these challenges, **SecureFileCrypt** was designed and implemented. It preserves the accessibility of password-based authentication while introducing RFC 9106 Argon2id key derivation, envelope encryption (DEK/KEK separation), chunked authenticated streaming, padded metadata confidentiality, and an efficient header rotation mechanism.

---

## 2. Problem Statement and Motivation

Desktop and web-based file encryption utilities frequently prioritize algorithmic correctness over memory scalability, metadata protection, and key management lifecycle requirements. When handling large multimedia files, disk images, or encrypted backups, a cryptosystem must address:
- **Resistance Against Offline Password Guessing:** Passwords chosen by humans frequently possess low entropy. Key derivation must significantly increase the hardware cost and memory bandwidth required for parallelized brute-force attacks.
- **Bounded Memory Footprint:** Processing arbitrary file sizes without exhausting host physical memory or triggering operating system swap thrashing.
- **Tamper Detection and Truncation Resistance:** Detecting unauthorized chunk insertion, deletion, reordering, truncation, or trailing data injection.
- **Metadata Confidentiality:** Preventing passive adversaries from inspecting original filenames, extensions, or file sizes from filesystem containers.
- **Efficient Password Management:** Enabling users to update passphrases without decrypting or rewriting gigabytes of ciphertext.

The baseline architecture evaluated by Rosandi et al. (2026) does not incorporate streaming, envelope key management, or memory-hard derivation, motivating this research and empirical comparative evaluation.

---

## 3. Objectives

The primary research and engineering objectives of this project are:
1. **Reconstruct and Benchmark the Baseline Architecture:** Implement a baseline cryptosystem reconstructed from the design reported by Rosandi et al. (2026), employing PBKDF2-HMAC-SHA256 (reconstructed with 100,000 iterations in accordance with NIST SP 800-132 recommendations) and monolithic AES-256-GCM to establish an empirical performance and memory baseline.
2. **Design an Advanced, Memory-Bounded Cryptosystem:** Implement an improved system incorporating Argon2id (RFC 9106), envelope encryption (DEK/KEK), chunked AEAD streaming with deterministic counter IVs, position-authenticated Additional Authenticated Data (AAD), and PKCS#7 padded metadata.
3. **Provide an Efficient Password Rotation Mechanism:** Decouple payload encryption from passphrase derivation using a random 256-bit Data Encryption Key (DEK), allowing passphrases to be updated by re-wrapping only the 32-byte DEK and updating the container header.
4. **Conduct Rigorous Profiling and Optimization:** Profile microsecond bottlenecks, optimize chunk framing allocations, benchmark filesystem I/O buffer alignments, and evaluate chunk sizes (64 KB vs 128 KB).
5. **Enforce Independent Verification and Audit Integrity:** Verify all empirical claims against raw multi-trial data, separate memory metrics (Python heap vs Process Working Set), qualify small-file speedups, and audit end-to-end API limitations.

---

## 4. Baseline Architecture (Reconstruction of Rosandi et al., 2026)

### 4.1 Specification and Primitives
The baseline implementation reproduces the core cryptographic primitives described in Rosandi et al. (2026):
- **Key Derivation Function (KDF):** PBKDF2-HMAC-SHA256.
  - Salt: 16 bytes (128 bits), randomly sampled via `os.urandom(16)`.
  - Iteration Count: 100,000 iterations (reconstructed based on NIST SP 800-132 recommendations).
  - Derived Key Length: 32 bytes (256 bits).
  - Memory Cost: $O(1)$ RAM (negligible memory footprint).
- **Authenticated Cipher:** AES-256-GCM.
  - Nonce (IV): 12 bytes (96 bits), randomly sampled via `os.urandom(12)`.
  - Authentication Tag: 16 bytes (128 bits), GHASH authenticator appended to ciphertext.
  - Additional Authenticated Data (AAD): None (`None`).
- **File Format:** Linear binary serialization without a magic identifier or format version:
  $$\text{Container} = \text{Salt (16B)} \parallel \text{Nonce (12B)} \parallel \text{Ciphertext} \parallel \text{Tag (16B)}$$

> [!NOTE]
> **Reconstruction Note on Baseline Parameters:**  
> Rosandi et al. (2026) documented the general integration of AES-256 and PBKDF2 in a Streamlit interface, but did not specify the exact iteration count, salt length, or container packing layout. In this codebase, 100,000 iterations, 16-byte random salts, and 12-byte random nonces were adopted as defensible reconstruction parameters compliant with NIST SP 800-132 guidelines.

### 4.2 Limitations of the Baseline Design
While mathematically correct in its use of AES-256-GCM, the baseline design exhibits critical limitations:
1. **Compute-Only Key Derivation:** PBKDF2 requires virtually zero memory to compute. Modern adversary hardware (GPUs and ASICs) can evaluate thousands of candidate passwords concurrently in local cache registers, leaving short or moderately complex user passphrases vulnerable to offline dictionary attacks.
2. **Linear Memory Consumption ($O(N)$):** The baseline reads the complete file into RAM, derives the key, and passes the entire byte array to `aesgcm.encrypt(nonce, plaintext, None)`. For a file of size $N$, the Python runtime buffers the plaintext ($N$), derives the ciphertext ($N + 16\text{ B}$), and constructs the packed container ($N + 44\text{ B}$), consuming $> 2N$ bytes of memory concurrently.
3. **Total Exposure of Container Metadata:** The baseline container format contains no fields for original filename, MIME type, or creation metadata. Operating systems or applications using this format either leak the original filename via the outer filesystem name (e.g., `document.pdf.enc`) or lose the filename entirely upon decryption.
4. **Expensive Password Updates ($O(N)$ Cryptographic Work):** Because the payload is encrypted directly with the key derived from the user's password, updating a password requires decrypting the entire file to plaintext, deriving a new key, and re-encrypting the entire file. On a 100 MB file, this requires $2.0043\text{ s}$ of CPU work and substantial disk I/O.
5. **No Versioning or Magic Bytes:** The container lacks file magic bytes (such as `AGY2`) or format version markers, preventing defensive validation against corrupted or foreign files before launching expensive key derivation routines.

### 4.3 Baseline Limitations and Architectural Improvement Mapping

The following matrix systematically contrasts the baseline cryptosystem (reconstructed from Rosandi et al., 2026) against the proposed SecureFileCrypt architecture across all operational and security dimensions:

**Table 1: Baseline Limitations and Architectural Improvement Mapping**

| Architectural Dimension | Baseline Limitation (Rosandi et al. Reconstruction) | Technical Consequence | SecureFileCrypt Proposed Improvement | Evidence Supporting Improvement | Remaining Limitation / Scope Boundary |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Key Derivation (KDF)** | PBKDF2-HMAC-SHA256 (100k iter, reconstruction choice). | Compute-bound with $O(1)$ RAM; vulnerable to low-cost parallel brute-force on modern GPUs/ASICs. | Argon2id RFC 9106 ($t=2, m=64\text{ MB}, p=4$) with defensive parameter caps. | Forces dedicated 64 MB RAM allocation per lane; verified in `benchmark_kdf`. | Desktop interactive latency floor ($\approx 34\text{–}110\text{ ms}$); weak user passwords remain vulnerable to offline guessing. |
| **Memory Architecture** | Monolithic buffer processing (`aesgcm.encrypt(nonce, plaintext)`). | Memory consumption scales linearly ($> 2N$ bytes); potential OOM failure or swap thrashing on large archives. | Chunked authenticated streaming AEAD (64 KiB default chunk size, 128 KiB stream buffer). | Capped Python heap at $\le 0.52\text{ MiB}$ up to 400 MiB ($1,579.2\times$ heap reduction on 400 MiB). | Web gateway (`server.py`) currently buffers complete uploads in RAM via `await file.read()`. |
| **Password Rotation** | Direct-key encryption: file payload is encrypted directly with password-derived key. | Changing password requires full decryption to plaintext, new key derivation, and full re-encryption ($O(N)$ work). | Dual-key envelope encryption: random 256-bit DEK wrapped by Argon2id KEK; in-place header rewrite ($O(1)$ I/O). | Password update completed in 0.165 s on 400 MiB ($4.75\times$ speedup over baseline). | In-place rewrite is not crash-safe if power fails mid-write; atomic replacement requires $O(N)$ chunk copying (0.849 s). |
| **Tamper & Truncation Defense** | Single monolithic GCM tag at end of container; no positional chunk framing. | Cannot process or authenticate streams progressively; no defense against container truncation prior to full read. | Framed chunk records with deterministic nonce counters and positional AAD binding (`file_id \|\| chunk_idx \|\| is_last`). | Automated test suite confirms rejection of swapped, duplicate, truncated, or trailing chunks (`pytest` 46 passed). | Requires buffering 64 KiB per chunk to verify GHASH tag before releasing chunk plaintext to caller. |
| **Metadata Confidentiality** | No metadata fields in container; relies on filesystem naming. | Original filename, extension, and MIME type either exposed in outer plaintext filename or lost completely. | Structured JSON metadata, PKCS#7 block-padded to 64-byte boundary, encrypted with KEK and independent nonce. | Filename and MIME protected; pad block eliminates exact length leakage (`test_unicode_and_special_filenames`). | Outer file size and container header fields (magic, version, salt, nonce, chunk size) remain visible on disk. |
| **Format Integrity & Versioning** | Raw container layout: `salt (16B) \|\| nonce (12B) \|\| ciphertext \|\| tag (16B)`. | Lacks magic bytes or version markers; fails cryptographically rather than syntactically on invalid files. | Format Version 2 container header with 4-byte magic (`AGY2`), version byte (`0x02`), and defensive parameter caps. | Immediate rejection of invalid versions and parameter bombs ($m \ge 512\text{ MB}$, $t \ge 10$) without memory allocation. | Header fields are plaintext, though fully authenticated via AAD binding to the wrapped DEK. |

---

## 5. Proposed Improved Architecture

The improved SecureFileCrypt architecture addresses each baseline limitation through a layered, defense-in-depth design.

```
+---------------------------------------------------------------------------------------------------+
|                                 SECUREFILECRYPT CONTAINER (FORMAT V2)                              |
+---------------------------------------------------------------------------------------------------+
| FIXED HEADER (111 Bytes):                                                                         |
|   Magic Bytes (4B: 'AGY2') | Version (1B: 0x02) | KDF ID (1B: 0x01 = Argon2id)                    |
|   Time Cost (2B: t=2) | Memory Cost (4B: m=65536 KB) | Parallelism (1B: p=4)                      |
|   Salt (16B) | KEK Nonce (12B) | Wrapped DEK (48B: 32B DEK + 16B GCM Tag)                         |
|   Stream Nonce Prefix (8B) | File ID (8B) | Chunk Size (4B: 64KB) | Meta Len (2B: uint16)         |
+---------------------------------------------------------------------------------------------------+
| VARIABLE ENCRYPTED METADATA (Encrypted with KEK, PKCS#7 Padded to 64B Block Size):                |
|   Metadata Nonce (12B) | Encrypted JSON Metadata (Filename, MIME, Size) | Auth Tag (16B)          |
+---------------------------------------------------------------------------------------------------+
| STREAMING AUTHENTICATED CHUNKS (Encrypted with DEK):                                              |
|   +---------------------------------------------------------------------------------------------+ |
|   | Chunk 0: Length (4B) | IsLast (1B: 0) | Ciphertext (Payload + 16B Tag)                      | |
|   +---------------------------------------------------------------------------------------------+ |
|   | Chunk 1: Length (4B) | IsLast (1B: 0) | Ciphertext (Payload + 16B Tag)                      | |
|   +---------------------------------------------------------------------------------------------+ |
|   | ...                                                                                         | |
|   +---------------------------------------------------------------------------------------------+ |
|   | Chunk N: Length (4B) | IsLast (1B: 1) | Ciphertext (Final Payload + 16B Tag)                | |
|   +---------------------------------------------------------------------------------------------+ |
+---------------------------------------------------------------------------------------------------+
```

### 5.1 Dual-Key Envelope Encryption
SecureFileCrypt decouples data encryption from password derivation using envelope encryption:
- **Data Encryption Key (DEK):** A 256-bit cryptographic key generated using a cryptographically secure pseudorandom number generator (`os.urandom(32)`). The DEK is used exclusively to encrypt and decrypt payload data chunks.
- **Key Encryption Key (KEK):** A 256-bit key derived from the user's passphrase using Argon2id. The KEK is used exclusively to wrap (encrypt) the DEK and encrypt container metadata.
- **Key Wrapping Mechanism:**
  $$\text{Wrapped DEK} = \text{AES-GCM-Encrypt}_{\text{KEK}}(\text{Nonce}_{\text{KEK}}, \text{DEK}, \text{AAD}_{\text{DEK}})$$
  The Additional Authenticated Data ($\text{AAD}_{\text{DEK}}$) cryptographically binds the entire fixed container header:
  $$\text{AAD}_{\text{DEK}} = \text{"AGY2-V2-DEK-WRAP:"} \parallel \text{struct.pack}(>BBHIB16s8s8sI)$$
  binding format version, KDF identifier, time cost, memory cost, parallelism, salt, stream nonce prefix, file ID, and chunk size. This ensures that no header parameter can be tampered with without invalidating DEK unwrapping.

### 5.2 Memory-Hard Key Derivation (Argon2id RFC 9106)
To substantially increase the hardware cost and memory bandwidth required for offline parallel dictionary attacks, SecureFileCrypt selects Argon2id with parameters tuned for interactive desktop usability:
- **Time Cost ($t$):** 2 passes over memory.
- **Memory Cost ($m$):** $64\text{ MB}$ ($65,536\text{ KB}$).
- **Parallelism ($p$):** 4 independent execution lanes/threads.
- **Salt Length:** 16 bytes (128 bits).
- **Defensive Parameter Caps:** To prevent Denial-of-Service (DoS) attacks via malformed header parameters ("parameter bombs"), the implementation enforces defensive validation boundaries:
  $$t \in [1, 10], \quad m \in [8\text{ MB}, 512\text{ MB}], \quad p \in [1, 8], \quad \text{Chunk Size} \in [1\text{ KB}, 64\text{ MB}]$$

> [!NOTE]
> **Argon2id Configuration Rationale:**  
> RFC 9106 Section 7.4 lists several parameter sets depending on system constraints (e.g., $t=1, m=2\text{ GB}, p=4$ for first-option backend password hashing, or $t=3, m=64\text{ MB}$ for memory-constrained devices). In SecureFileCrypt, $t=2, m=64\text{ MB}, p=4$ is the project's selected configuration, chosen to achieve a practical balance between memory hardness and sub-second interactive latency on desktop client hardware.

### 5.3 Chunked Authenticated Streaming AEAD
Rather than buffering entire files in memory, SecureFileCrypt processes files in sequential, bounded chunks (defaulting to 64 KB, $65,536\text{ bytes}$):
1. **Deterministic Nonce Derivation:** For each chunk $i$, a unique 96-bit (12-byte) IV is derived by concatenating an 8-byte random stream prefix with a 4-byte big-endian chunk counter:
   $$\text{Nonce}_i = \text{Stream Nonce Prefix (8B)} \parallel \text{BigEndian}(i, 4\text{B})$$
   This guarantees that no two chunks encrypted under the same DEK share an identical IV. The 32-bit chunk index supports files up to $2^{32} - 1$ chunks (at 64 KB per chunk, this provides a theoretical limit of $256\text{ TB}$).
2. **Positional AAD Binding:** To prevent an active adversary from reordering, duplicating, or splicing chunks across files, each chunk binds its unique file ID, position index, and terminal status into its GCM authentication tag:
   $$\text{AAD}_i = \text{File ID (8B)} \parallel \text{BigEndian}(i, 4\text{B}) \parallel \text{IsLast (1B)}$$
3. **Framing Structure:** Each chunk is prefixed with a 5-byte frame header:
   $$\text{Frame Header} = \text{Length (4B Big-Endian)} \parallel \text{IsLast (1B)}$$
   This structure allows stream parsers to read exact chunk lengths without unbounded buffering.

### 5.4 Encrypted and Padded Metadata
To preserve metadata confidentiality without leaking file characteristics:
- Metadata is encoded as UTF-8 JSON containing original filename, MIME type, and exact file size.
- In Format Version 2 (`FORMAT_VERSION_2`), the metadata payload is padded using PKCS#7 to a **64-byte block boundary** (`METADATA_PADDING_BLOCK_SIZE = 64`) to obscure the exact filename string length from traffic analysis.
- The padded metadata is encrypted using AES-GCM with the KEK and an independent 12-byte nonce, binding the 8-byte file ID via AAD (`"AGY2-V2-META-WRAP:" + file_id`).

### 5.5 Metadata Confidentiality vs Visible Container Attributes
To prevent exaggerated security claims, SecureFileCrypt's metadata exposure model is precisely delineated:
- **Confidential Attributes (Encrypted & Padded):**
  - Original plaintext filename (supports Unicode, spaces, and path traversal strings which are sanitized upon extraction).
  - File MIME content type (e.g., `application/pdf`, `video/mp4`).
  - Exact unpadded plaintext byte length.
  - *Length-Hiding:* Padded to 64-byte boundaries, preventing an observer from determining filename character count from ciphertext length.
- **Visible Container Attributes (In-the-Clear on Disk):**
  - Magic identifier (`b"AGY2"`: 4 bytes) and container version (`0x02`: 1 byte).
  - KDF algorithm identifier (`0x01 = Argon2id`: 1 byte).
  - Argon2id parameters ($t=2, m=65536\text{ KB}, p=4$: 7 bytes total).
  - Salt (16 bytes) and KEK Nonce (12 bytes).
  - Wrapped DEK ciphertext and tag (48 bytes).
  - Stream Nonce Prefix (8 bytes) and File Identifier (8 bytes).
  - Chunk Size (4 bytes) and Encrypted Metadata Length (2 bytes).
  - Outer filesystem container size (reveals file size within 64 KiB chunk granularity).
- **Cryptographic Binding:** All visible fixed header attributes are authenticated as Additional Authenticated Data (AAD) during DEK wrapping. An adversary who alters any visible parameter (such as modifying $m$ or chunk size) causes GCM tag verification to fail immediately upon DEK unwrapping, halting decryption before any chunks are read.

---

## 6. Password Rotation Architecture

Password rotation is a critical lifecycle requirement for production security systems. SecureFileCrypt supports two distinct rotation mechanisms:

### 6.1 In-Place Header Rewrite ($O(1)$ Disk I/O)
When executing `change_password_file(..., atomic=False)`:
1. The container header is read, and the old KEK is derived from `old_password` and the stored salt.
2. The DEK is unwrapped and authenticated via AES-GCM. If the password is wrong, execution aborts immediately without modifying the file.
3. Metadata is decrypted and verified.
4. A fresh 16-byte salt and fresh 12-byte KEK nonce are generated.
5. A new KEK is derived from `new_password` using Argon2id ($t=2, m=64\text{ MB}, p=4$).
6. The *same* 32-byte DEK is re-wrapped under the new KEK with updated AAD.
7. Metadata is re-encrypted under the new KEK.
8. The file pointer seeks to offset 0 (`f.seek(0)`), writes the new 111-byte fixed header plus encrypted metadata, flushes buffers, and executes `os.fsync(f.fileno())`.
- **Complexity:** Constant-size disk I/O (111 bytes fixed header plus padded metadata) and zero payload re-encryption.
- **Failure-Safety Trade-Off:** In-place modification is the fastest rotation mechanism because it avoids rewriting payload chunks. However, if a catastrophic power failure occurs during the physical sector write of the header, the header could become corrupted. This risk is minimized by calling `os.fsync()`, but applications requiring total crash-consistency should utilize the atomic mode.

### 6.2 Atomic File Replacement (Crash-Consistent)
When executing `change_password_file(..., atomic=True)`:
- To eliminate any risk of file corruption if power is interrupted during header modification, the function creates a hidden temporary file (`.{filename}.agy_pw_{rand}.tmp`), writes the new header, stream-copies all existing ciphertext chunks without decryption, flushes and syncs to disk (`os.fsync`), and atomically replaces the original file (`os.replace`).
- **Trade-off:** Provides crash consistency on POSIX and NTFS filesystems at the expense of copying ciphertext chunks ($O(N)$ data transfer, but still $O(1)$ cryptographic DEK re-wrapping).

---

## 7. Implementation & System Optimization Details

During performance profiling (`scratch/profile_bottlenecks.py`), two major architectural bottlenecks were identified in the improved streaming pipeline:
1. **Intermediate Chunk String Concatenation:** In `improved/crypto.py`, the chunk writing loop originally concatenated the 5-byte frame header and the ciphertext buffer:
   ```python
   # Prior implementation (allocates new temporary bytes object per chunk):
   frame_header = pack_header(">IB", len(ciphertext), 1 if is_last else 0)
   write_chunk(frame_header + ciphertext)
   ```
   Over 1,600 chunks on a 100 MB file, allocating and discarding 65,557-byte buffers created significant Python heap churn and garbage collection latency.
2. **Suboptimal I/O Buffer Alignment:** Python's standard `open(..., 'rb')` and `open(..., 'wb')` default to an 8 KB buffer size, causing 8 to 16 OS context switches per 64 KB or 128 KB chunk.

### Implemented Optimizations
- **Optimization 1 (Zero-Concatenation Sequential Writes):** In `encrypt_stream()`, the concatenation was eliminated in favor of sequential stream writes:
  ```python
  # Optimized implementation (zero intermediate memory allocation):
  frame_header = pack_header(">IB", len(ciphertext), 1 if is_last else 0)
  write_chunk(frame_header)
  write_chunk(ciphertext)
  ```
  Byte-for-byte stream identity was verified; SHA-256 output digests matched identically.
- **Optimization 3 (Empirical 128 KB Buffer Tuning):** File stream buffer sizes were benchmarked across 8 KB, 32 KB, 64 KB, 128 KB, 256 KB, and 512 KB (`scratch/test_buffer_sizes.py`). 128 KB demonstrated the lowest write latency ($44.6\text{ ms}$) and highest write throughput ($399.6\text{ MB/s}$ on 18.7 MB), reducing context switches by $61.5\%$. `IO_BUFFER_SIZE = 128 * 1024` was applied to all file stream operations.

### API Architecture Clarification
An audit of `server.py` revealed that the FastAPI endpoint handles file uploads via:
```python
@app.post("/api/encrypt")
async def encrypt_file(file: UploadFile = File(...), password: str = Form(...)):
    content = await file.read()  # In-memory buffering
    in_stream = io.BytesIO(content)
    out_stream = io.BytesIO()
    impr_crypto.encrypt_stream(input_stream=in_stream, output_stream=out_stream, ...)
```
**Architectural Disclosure:** While the cryptographic engine (`improved/crypto.py`) supports bounded streaming via `encrypt_file` and file streams, the HTTP gateway in `server.py` currently buffers complete request bodies into memory via `await file.read()`. End-to-end web streaming is deferred to a future FastAPI refactor utilizing `StreamingResponse` and async chunk iterators (Optimization 6).

---

## 8. Experimental Setup and Methodology

### 8.1 Hardware and Platform Specifications
All benchmarks were executed on an identical host machine to ensure strict comparability:
- **Operating System:** Windows 10 Pro (Build 19045), 64-bit Architecture (AMD64).
- **Runtime Environment:** CPython 3.10.11.
- **Cryptographic Libraries:** `cryptography 42.0.x` (OpenSSL 3.0.x backend), `argon2-cffi 25.1.0`.
- **Filesystem:** NTFS on solid-state drive (SSD).

### 8.2 Standardized Test Datasets
The comparative benchmark suite evaluated six standardized test files spanning representative document and multimedia types:
- **F1 (Text Document):** $0.10\text{ MB}$ ($104,857\text{ bytes}$), ASCII `.txt`.
- **F2 (PDF Document):** $1.25\text{ MB}$ ($1,310,720\text{ bytes}$), Structured binary `.pdf`.
- **F3 (Image):** $5.40\text{ MB}$ ($5,662,310\text{ bytes}$), High-resolution compressed `.jpg`.
- **F4 (Short Video):** $18.70\text{ MB}$ ($19,608,371\text{ bytes}$), MPEG-4 container `.mp4`.
- **F5 (Medium Archive):** $50.00\text{ MB}$ ($52,428,800\text{ bytes}$), High-entropy binary `.bin`.
- **F6 (Large Archive):** $100.00\text{ MB}$ ($104,857,600\text{ bytes}$), High-entropy binary `.bin`.

### 8.3 Timing and Measurement Scopes
- **Number of Trials:** 3 recorded measurement trials per file.
- **Timing Boundaries:** Total file encryption and decryption timings include key derivation, disk file reads, chunk cryptographic framing, temporary file creation, buffer flushing, physical disk synchronization (`os.fsync`), and atomic renaming (`os.replace`).
- **Memory Instrumentation:** Python heap allocations were instrumented using `tracemalloc`. Process Working Set (RSS) was captured using the native Windows API `GetProcessMemoryInfo` (reading `WorkingSetSize`).

---

## 9. Results and Performance Analysis

This section presents the empirical evaluation of SecureFileCrypt, structured into seven core analytical subsections:
1. Baseline Architecture Comparison Overview
2. Key Derivation Function (KDF) Timing and Resource Evaluation
3. 100 MiB Benchmark Results (Cold Disk Streaming and In-Memory Baseline)
4. Extended Large-File Scalability Results (200 MiB, 300 MiB, and 400 MiB)
5. Memory Profiling: Python Heap vs. Sampled Process Working Set
6. Password Rotation Performance Across Distinct Operational Paradigms
7. Cryptographic Output Fidelity and Roundtrip Integrity Verification

---

### 9.1 Baseline Architecture Comparison Overview

The baseline and improved systems reflect two fundamentally divergent architectural paradigms:
- **Baseline (Rosandi et al. Reconstruction):** Designed as an in-memory utility, holding complete plaintext, ciphertext, and container byte arrays concurrently in RAM. It employs PBKDF2-HMAC-SHA256 (100,000 iterations) and direct-key AES-256-GCM.
- **Improved (SecureFileCrypt):** Designed as an authenticated streaming cryptosystem, processing data in sequential 64 KiB frames via dual-key envelope encryption (DEK/KEK) and Argon2id.

Table 2 summarizes the foundational architectural distinctions between the two evaluated cryptosystems.

**Table 2: High-Level Architecture Comparison Matrix**

| Feature / Dimension | Baseline Cryptosystem (Rosandi et al., 2026) | Proposed SecureFileCrypt (Format V2) |
| :--- | :--- | :--- |
| **KDF Primitive** | PBKDF2-HMAC-SHA256 (100k iter, reconstruction choice) | Argon2id RFC 9106 ($t=2, m=64\text{ MB}, p=4$) |
| **Memory Hardness** | $0\text{ MB}$ ($O(1)$ RAM requirement) | $64\text{ MB}$ ($65,536\text{ KB}$) dedicated matrix per lane |
| **Cipher Engine** | Monolithic AES-256-GCM (whole-file RAM buffer) | Chunked AEAD AES-256-GCM (64 KiB frames) |
| **Key Hierarchy** | Single direct key derived from password | Envelope encryption: 256-bit random DEK wrapped by KEK |
| **Password Rotation** | Full re-encryption ($O(N)$ crypto + $O(N)$ data) | In-place header rewrite ($O(1)$ I/O) or atomic replace ($O(N)$ I/O) |
| **Framing & AAD** | None (single trailing GCM tag) | Big-endian counter, File ID, Chunk index, IsLast flag in AAD |
| **Metadata Protection** | None (relies on plaintext filesystem naming) | Encrypted JSON, PKCS#7 padded to 64-byte block boundary |
| **Container Identification** | None (raw salt + nonce + ciphertext + tag) | 4-byte magic (`AGY2`), 1-byte version (`0x02`), defensive caps |

---

### 9.2 Key Derivation Function (KDF) Latency Evaluation

*Source: `benchmark/results/comparative_benchmark.json` and `benchmark/results/large_file_scalability.json`.*

Key derivation functions were evaluated on the reference test host (Windows 10 AMD64, CPython 3.10.11) across multiple multi-trial benchmark sessions. Table 3 records the measured latency and resource profiles.

**Table 3: Key Derivation Function (KDF) Latency and Resource Comparison**

| Primitive | Parameters | Comparative Mean | Comparative Median | Comparative Stdev | Scalability Median | Memory Hardness |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **PBKDF2-HMAC-SHA256** | 100,000 iterations | $0.0187\text{ s}$ ($18.7\text{ ms}$) | $0.0206\text{ s}$ ($20.6\text{ ms}$) | $0.0043\text{ s}$ | $0.0118\text{ s}$ ($11.8\text{ ms}$) | $0\text{ MB}$ ($O(1)$ RAM) |
| **Argon2id (RFC 9106)** | $t=2, m=64\text{ MB}, p=4$ | $0.1096\text{ s}$ ($109.6\text{ ms}$) | $0.0888\text{ s}$ ($88.8\text{ ms}$) | $0.0700\text{ s}$ | $0.0339\text{ s}$ ($33.9\text{ ms}$) | **$64\text{ MB}$** RAM |

#### Analytical Interpretation:
1. **Security-Performance Trade-off:** Argon2id enforces a dedicated 64 MB physical RAM allocation across 4 parallel lanes. In the comparative benchmark, Argon2id required a median of $88.8\text{ ms}$, compared to $20.6\text{ ms}$ for PBKDF2 ($4.31\times$ derivation floor). This computational floor governs small-file performance, where KDF derivation constitutes $>90\%$ of total wall-clock execution time.
2. **KDF Latency Variance Across Sessions:** Across three benchmark runs, Argon2id median latency varied between $0.2688\text{ s}$ (pre-optimization run), $0.0888\text{ s}$ (comparative benchmark), and $0.0339\text{ s}$ (large-file scalability benchmark). PBKDF2 similarly scaled down from $0.0283\text{ s}$ to $0.0206\text{ s}$ to $0.0118\text{ s}$. As documented in the evidence audit, this variation stems from CPU frequency boost scaling, background OS thread contention, and thermal throttling states on the host processor. Because hardware telemetry was not recorded continuously, this variance is treated as an **unresolved environmental condition**, and the 100 MiB and 200–400 MiB benchmark datasets are maintained in strictly separate analytical subsections.

---

### 9.3 100 MiB Benchmark Evaluation (Pre- vs Post-Optimization & In-Memory)

*Source: `benchmark/results/pre_optimization_benchmark.json` and `benchmark/results/comparative_benchmark.json`.*

The comparative benchmark suite evaluated cold disk-to-disk streaming (`encrypt_file` and `decrypt_file`) utilizing 64 KiB default chunk sizes and 128 KiB stream buffering across test datasets F1 through F6.

**Table 4: Disk Streaming Performance Across Standardized Datasets (F1–F6)**

| File ID | Size | Pre-Opt Enc Time | Post-Opt Enc Time | Enc Speedup | Pre-Opt Dec Time | Post-Opt Dec Time | Dec Speedup | Audit Assessment |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **F1** | 0.10 MB | 0.3628 s | 0.0721 s | 5.03× | 0.3871 s | 0.0899 s | 4.31× | **Qualified (KDF Variance)** |
| **F2** | 1.25 MB | 0.3759 s | 0.0620 s | 6.07× | 0.4009 s | 0.0888 s | 4.52× | **Qualified (KDF Variance)** |
| **F3** | 5.40 MB | 0.9046 s | 0.1798 s | 5.03× | 0.8045 s | 0.1913 s | 4.21× | **Qualified (KDF Variance)** |
| **F4** | 18.70 MB | 0.5225 s | 0.2946 s | 1.77× | 0.5863 s | 0.2599 s | 2.26× | **Verified Streaming Gain** |
| **F5** | 50.00 MB | 0.7814 s | 0.4488 s | 1.74× | 0.8151 s | 0.4798 s | 1.70× | **Verified Streaming Gain** |
| **F6** | 100.00 MB | 2.5777 s | **0.9073 s** | **2.84×** | 1.9659 s | **0.6165 s** | **3.19×** | **Verified Streaming Gain** |

**Table 5: 100 MiB Comparative Benchmark Throughput & Heap Scaling (F1–F6)**

| File ID | Size | Pre-Opt Enc Tput | Post-Opt Enc Tput | Pre-Opt Dec Tput | Post-Opt Dec Tput | Stream Python Heap |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **F1** | 0.10 MB | 0.28 MB/s | 1.39 MB/s | 0.26 MB/s | 1.11 MB/s | 0.42 MB |
| **F2** | 1.25 MB | 3.33 MB/s | 20.18 MB/s | 3.12 MB/s | 14.08 MB/s | 0.50 MB |
| **F3** | 5.40 MB | 5.97 MB/s | 30.03 MB/s | 6.71 MB/s | 28.23 MB/s | 0.50 MB |
| **F4** | 18.70 MB | 35.79 MB/s | 63.48 MB/s | 31.90 MB/s | 71.94 MB/s | 0.50 MB |
| **F5** | 50.00 MB | 63.98 MB/s | 111.40 MB/s | 61.34 MB/s | 104.22 MB/s | 0.50 MB |
| **F6** | 100.00 MB | 38.79 MB/s | **110.22 MB/s** | 50.87 MB/s | **162.22 MB/s** | **0.50 MB** |

#### Critical Audit Finding on Small-File Speedups:
On F1 (104 KB, 2 chunks), payload encryption takes $< 0.1\text{ ms}$. During the pre-optimization run, background thread contention resulted in an average Argon2id latency of $0.2688\text{ s}$, whereas in the post-optimization run it completed in $0.1096\text{ s}$. Because KDF derivation represents $>98\%$ of wall-clock time on F1–F3, attributing the $4\times\text{–}6\times$ speedup on small files to chunk streaming optimizations is **an invalid attribution**. True streaming throughput gains are observable on F5 (50 MB) and F6 (100 MB), where encryption throughput improved from **$38.79\text{ MB/s}$ to $110.22\text{ MB/s}$ ($2.84\times$)** and decryption throughput from **$50.87\text{ MB/s}$ to $162.22\text{ MB/s}$ ($3.19\times$)**.

#### In-Memory (RAM-to-RAM) Processing Comparison
To evaluate the pure compute overhead of chunked framing against monolithic processing, both implementations were tested in-memory on pre-allocated byte arrays (`comparative_benchmark.json`). Table 6 presents the in-memory results.

**Table 6: In-Memory (RAM-to-RAM) Processing Comparison (F1–F6)**

| File ID | Size | Baseline Enc Time | Improved Enc Time | Baseline Enc Tput | Improved Enc Tput | Baseline Peak Heap | Improved Peak Heap |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **F1** | 0.10 MB | 0.0319 s | 0.0707 s | 3.14 MB/s | 1.41 MB/s | 0.20 MB | 0.23 MB |
| **F2** | 1.25 MB | 0.0256 s | 0.0612 s | 48.90 MB/s | 20.44 MB/s | 2.50 MB | 0.50 MB |
| **F3** | 5.40 MB | 0.0433 s | 0.1837 s | 124.71 MB/s | 29.41 MB/s | 10.80 MB | 0.50 MB |
| **F4** | 18.70 MB | 0.0756 s | 0.2913 s | 247.35 MB/s | 64.24 MB/s | 37.40 MB | 0.50 MB |
| **F5** | 50.00 MB | 0.1637 s | 0.6330 s | 304.97 MB/s | 79.03 MB/s | 100.00 MB | 0.50 MB |
| **F6** | 100.00 MB | 0.2561 s | 1.1250 s | 389.92 MB/s | 88.89 MB/s | 200.00 MB | **0.50 MB** |

**Interpretation:** The baseline achieves higher in-memory throughput because it invokes a single monolithic OpenSSL C call without chunk framing or counter packing, and uses a fast $18.7\text{ ms}$ PBKDF2 derivation. However, its memory footprint scales linearly at $2\times$ file size ($200.0\text{ MB}$ on F6), whereas the improved system remains bounded at $\le 0.50\text{ MB}$ on the Python heap.

---

### 9.4 Extended Scalability Results (200 MiB, 300 MiB, and 400 MiB)

*Source: `benchmark/results/large_file_scalability.json`.*

To evaluate memory bounding, throughput scaling, and key management beyond 100 MB, an independent scalability benchmark suite was implemented in `benchmark/large_file_scalability.py` and executed on the test host (Windows 10 AMD64, CPython 3.10.11, default 64 KiB chunks, 128 KiB stream buffering).

#### 1. Workload Specifications & Verification
Deterministic, non-sensitive binary test datasets were generated incrementally in 64 KiB blocks:
- **F7 (200 MiB = 209,715,200 bytes):** SHA-256 `24dfb9eb6556110685ff11222e812ab15abcac8cfd985fee2d3438774ea06bcf`
- **F8 (300 MiB = 314,572,800 bytes):** SHA-256 `a8dcda07e8a029c88422dc7583ef36006038533aa570ec20a94b317651843edf`
- **F9 (400 MiB = 419,430,400 bytes):** SHA-256 `45e43128cef78aeeb989326f78fee33c8b5222efb744fc15db9b5529b6907e92`

Pre-flight storage checks confirmed 96.3 GB of available disk space. Available physical RAM was 1.94 GB of 15.7 GB total. Because the baseline requires holding up to $2\times$ file size in Python heap (800 MB on F9), physical memory was verified beforehand to ensure safe execution without swapping, thrashing, or out-of-memory termination.

#### 2. Architectural APIs and Methodological Asymmetry
- **Baseline Monolithic (In-Memory RAM-to-RAM):** `baseline.crypto.encrypt_bytes(plaintext, password)` and `decrypt_bytes(container, password)` operate exclusively on in-memory byte buffers using PBKDF2-HMAC-SHA256 (100k iterations) and AES-256-GCM. File loading from disk is performed prior to timing; **baseline timings exclude disk I/O entirely**.
- **Improved Authenticated Streaming (Disk-to-Disk):** `improved.crypto.encrypt_file(in_path, out_path, password)` and `decrypt_file(in_path, out_path, password)` operate on physical filesystem paths using Argon2id ($t=2, m=64\text{ MB}, p=4$), dual-key envelope encryption (DEK/KEK), 64 KiB chunk authenticated frames, and 128 KiB stream buffering. **Improved streaming timings include full physical disk reads, framing, temporary file creation, buffer flushing, disk synchronization (`os.fsync`), and atomic renaming (`os.replace`)**.
- **Methodological Qualification:** Direct comparison between baseline throughput ($950\text{–}1,155\text{ MiB/s}$) and streaming throughput ($351\text{–}512\text{ MiB/s}$) reflects the fundamental divergence between RAM memory-bandwidth and physical filesystem I/O, rather than an isolated cipher algorithm speed comparison. Furthermore, because these test files were generated immediately prior to benchmarking, they resided in the Windows NTFS standby file cache (warm cache), explaining higher throughput compared to cold disk runs in Section 9.3.

#### 3. Preserved Measured Scalability Results
Table 7 records the exact medians and recalculated throughputs from `benchmark/results/large_file_scalability.json` (3 repetitions per workload; throughput formula: $\text{input\_size\_bytes} / 1,048,576 / \text{elapsed\_seconds}$).

**Table 7: Extended Large-File Scalability Performance (200–400 MiB)**

| File ID | Payload Size | Implementation Architecture | Enc Time (Median) | Enc Throughput (Median) | Dec Time (Median) | Dec Throughput (Median) | Peak Python Heap | Sampled Process RSS | Recovered Output Fidelity |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **F7** | 200 MiB | Baseline (In-Memory Bytes) | **0.190 s** | 1,051.2 MiB/s | **0.223 s** | 897.6 MiB/s | 400.0 MiB | 423.9 MiB | **PASS (SHA-256)** |
| | | Improved (Disk-to-Disk Stream) | 0.569 s | 351.4 MiB/s | 0.570 s | 350.6 MiB/s | **0.52 MiB** | **24.1 MiB** | **PASS (SHA-256)** |
| **F8** | 300 MiB | Baseline (In-Memory Bytes) | **0.260 s** | 1,155.3 MiB/s | **0.292 s** | 1,028.2 MiB/s | 600.0 MiB | 624.2 MiB | **PASS (SHA-256)** |
| | | Improved (Disk-to-Disk Stream) | 0.673 s | 445.6 MiB/s | 0.585 s | 512.9 MiB/s | **0.51 MiB** | **24.1 MiB** | **PASS (SHA-256)** |
| **F9** | 400 MiB | Baseline (In-Memory Bytes) | **0.419 s** | 953.5 MiB/s | **0.447 s** | 894.4 MiB/s | 800.0 MiB | 824.0 MiB | **PASS (SHA-256)** |
| | | Improved (Disk-to-Disk Stream) | 1.014 s | 394.7 MiB/s | 0.919 s | 435.3 MiB/s | **0.51 MiB** | **23.3 MiB** | **PASS (SHA-256)** |

---

### 9.5 Memory Profiling: Python Heap vs. Sampled Process Working Set

To ensure academic measurement integrity, memory metrics were separated into distinct system tiers:
1. **Python Heap (`tracemalloc`):** Measures memory allocated by the Python runtime for objects, byte buffers, and stream chunks. Note that `tracemalloc` instruments only Python heap allocations and is blind to memory allocated directly by native C extensions.
2. **Process Working Set (Sampled RSS via Win32 API):** Measures total physical RAM pages mapped into the process address space at the moment of sampling (`pmc.WorkingSetSize`), capturing external C libraries (OpenSSL `libcrypto` and `argon2-cffi`). Note that the benchmark records an instantaneous sample taken after operation completion rather than a continuous trace of peak working set (`PeakWorkingSetSize`).
3. **Argon2id Native Memory Matrix:** Argon2id allocates a $64\text{ MB}$ memory matrix in C (`hash_secret_raw`) during derivation. This temporary allocation lives in native process memory for $\approx 34\text{–}110\text{ ms}$ and does not register in Python heap tools.

Table 8 compiles the comprehensive memory scaling profile across all tested file sizes (0.10 MB to 400 MiB).

**Table 8: Comprehensive Memory Scaling Comparison Across Workloads**

| Workload ID | Payload Size | Baseline Peak Heap | Stream Peak Heap | Heap Reduction Factor | Baseline Sampled RSS | Stream Sampled RSS |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **F1** | 0.10 MB | 0.20 MB | 0.42 MB | 0.5× | $\approx 22\text{ MB}$ | 22.29 MB |
| **F2** | 1.25 MB | 2.50 MB | 0.50 MB | 5.0× | $\approx 24\text{ MB}$ | 22.37 MB |
| **F3** | 5.40 MB | 10.80 MB | 0.50 MB | 21.4× | $\approx 32\text{ MB}$ | 22.43 MB |
| **F4** | 18.70 MB | 37.40 MB | 0.50 MB | 74.1× | $\approx 58\text{ MB}$ | 22.51 MB |
| **F5** | 50.00 MB | 100.00 MB | 0.50 MB | 198.2× | $\approx 123\text{ MB}$ | 22.62 MB |
| **F6** | 100.00 MB | 200.00 MB | **0.50 MB** | **396.5× less** | $\approx 220\text{ MB}$ | **22.65 MB** |
| **F7** | 200.00 MiB | 400.00 MiB | **0.52 MiB** | **774.2× less** | 423.90 MiB | **24.06 MB** |
| **F8** | 300.00 MiB | 600.00 MiB | **0.51 MiB** | **1,184.3× less** | 624.23 MiB | **24.10 MB** |
| **F9** | 400.00 MiB | 800.00 MiB | **0.51 MiB** | **1,579.2× less** | 824.02 MiB | **23.32 MB** |

#### Memory Scaling Findings:
- **Empirical Heap Bounding:** The baseline cryptosystem exhibits strictly linear heap growth ($O(N)$), consuming **400.0 MiB**, **600.0 MiB**, and **800.0 MiB** of Python heap ($2\times$ payload size) for 200 MiB, 300 MiB, and 400 MiB files respectively. In contrast, SecureFileCrypt's streaming engine observed a bounded Python heap of **$\le 0.52\text{ MiB}$** across all tested workloads—a measured **$1,579.2\times$ heap reduction** at 400 MiB.
- **Process Working Set Stability:** The baseline sampled working set expanded to **824.0 MiB** on 400 MiB, reflecting the physical RAM footprint of holding plaintext and ciphertext buffers simultaneously. The improved streaming process working set was sampled at **$\approx 23.3\text{–}24.1\text{ MB}$**. While this confirms the absence of gross memory accumulation during these test runs, sampled RSS does not track peak working set (`PeakWorkingSetSize`) or constitute a formal mathematical proof against native memory leaks.

---

### 9.6 Password Rotation Performance Across Paradigms

*Source: `benchmark/results/comparative_benchmark.json` and `benchmark/results/large_file_scalability.json`.*

Password rotation workflows were benchmarked across three fundamentally distinct operational paradigms:
1. **Baseline Re-encryption ($O(N)$ In-Memory Crypto):** Full payload decryption and complete re-encryption. Requires $O(N)$ cryptographic computation and $O(N)$ memory.
2. **Improved In-Place Header Rewrite ($O(1)$ Disk I/O):** `change_password_file(..., atomic=False)` decrypts the wrapped DEK using the old KEK, re-wraps it under the new KEK, and overwrites the 111-byte header directly. Requires $O(1)$ disk I/O and $O(1)$ crypto work, leaving all ciphertext chunks untouched. *Failure trade-off:* This operation is not crash-safe; a power failure during the 111-byte overwrite can corrupt the container header.
3. **Improved Atomic Replacement (Crash-Consistent $O(N)$ Data Transfer):** `change_password_file(..., atomic=True)` writes the new header and streams existing ciphertext chunks into a `.tmp` file, calls `os.fsync`, and atomically replaces the file via `os.replace`. Provides crash consistency on supported filesystems (NTFS/POSIX) at the cost of $O(N)$ stream data transfer.

Table 9 presents the measured rotation latencies and in-place speedup factors across all tested file sizes.

**Table 9: Password Rotation Latency Across Operational Paradigms**

| Workload ID | Size | Baseline Re-encrypt ($O(N)$ Crypto) | Improved In-Place Header ($O(1)$ Disk I/O) | In-Place Speedup vs Baseline | Improved Atomic Replace (Crash-Safe $O(N)$) | Plaintext Recovery Verification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **F2** | 1.25 MB | **0.0521 s** | 0.3005 s | 0.17× (Baseline faster) | 0.3036 s | **PASS (SHA-256)** |
| **F4** | 18.70 MB | **0.1174 s** | 0.2872 s | 0.41× (Baseline faster) | 0.3963 s | **PASS (SHA-256)** |
| **F5** | 50.00 MB | **0.3142 s** | 0.4173 s | 0.75× (Baseline faster) | 0.7318 s | **PASS (SHA-256)** |
| **F6** | 100.00 MB | 2.0043 s | **0.3571 s** | **5.61×** | 0.9572 s | **PASS (SHA-256)** |
| **F7** | 200.00 MiB | 0.3970 s | **0.1161 s** | **3.42×** | 0.5099 s | **PASS (SHA-256)** |
| **F8** | 300.00 MiB | 0.4747 s | **0.1230 s** | **3.86×** | 0.7041 s | **PASS (SHA-256)** |
| **F9** | 400.00 MiB | 0.7828 s | **0.1647 s** | **4.75×** | 0.8492 s | **PASS (SHA-256)** |

#### Detailed Paradigm Evaluation:
1. **In-Place Header Overwrite Scalability:** On 400 MiB files (6,400 chunks), in-place rotation completes in **$0.1647\text{ s}$**, compared to **$0.7828\text{ s}$** for baseline re-encryption (**$4.75\times$ speedup**). Only 111 bytes of fixed header plus padded metadata are written to disk; all 6,400 ciphertext chunks remain completely untouched.
2. **Rejection of "Sub-Millisecond" Claims:** While the physical disk seek and write of the 111-byte header requires $< 1\text{ ms}$, the full operation requires deriving the old KEK, deriving the new KEK, and executing an NTFS `os.fsync`. In the scalability run with warm CPU boost, two Argon2id derivations required $\approx 68\text{ ms}$, establishing an operational floor of **$\approx 116\text{–}165\text{ ms}$**. Under cold system conditions (Section 11 in comparative run), this floor is $\approx 300\text{–}360\text{ ms}$.
3. **Crossover Threshold:** On files $< 50\text{ MB}$, baseline re-encryption is faster because two PBKDF2 operations require only $\approx 24\text{–}36\text{ ms}$, whereas two Argon2id operations require $\approx 68\text{–}220\text{ ms}$. In-place rotation becomes decisively advantageous on files $\ge 100\text{ MB}$.
4. **Atomic File Replacement:** Guarantees total crash consistency (via `.tmp`, `fsync`, and atomic `replace`). On 400 MiB, it completes in **$0.8492\text{ s}$**, trading $O(N)$ chunk copy time for zero corruption risk upon unexpected termination.

---

### 9.7 Cryptographic Output Fidelity & Roundtrip Verification

Across all benchmark trials (F1 through F9, comparative suite, and scalability suite), decrypted outputs were checked against the deterministic SHA-256 hash of the original input bitstream.
- **Verification Result:** 100% of decrypted files matched the expected SHA-256 digest byte-for-byte.
- **Roundtrip Fidelity:** Confirms that streaming framing, chunk concatenation elimination, 128 KiB buffer flushing, and key rotation do not introduce bit rot, truncation, or payload alteration.
- **Methodological Qualification:** Plaintext hash equality confirms functional correctness and operational fidelity under normal execution; it does not constitute a formal mathematical proof of cryptographic security against active adversaries, which is addressed in Section 11.

---

## 10. Chunk Size Evaluation: 64 KiB vs 128 KiB

To evaluate whether the default chunk size should be adjusted from 64 KiB to 128 KiB, a controlled multi-trial experiment was conducted across all files with an explicit warm-up pass (`scratch/chunk_64_vs_128_results.json`). Table 10 presents the comparative results.

**Table 10: Multi-Trial Chunk Size Sensitivity Profile (F1–F6)**

| File ID | Size | Chunk Size | Mean Enc (s) | Enc Tput | Mean Dec (s) | Dec Tput | Peak Heap | Process RSS | Enc Speedup |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **F1** | 0.10 MB | 64 KiB | 0.0451 s | 2.22 MB/s | 0.0706 s | 1.42 MB/s | 0.42 MB | 22.29 MB | Baseline |
| | | 128 KiB | 0.0433 s | 2.31 MB/s | 0.0641 s | 1.56 MB/s | 0.48 MB | 22.35 MB | 1.04× |
| **F2** | 1.25 MB | 64 KiB | 0.0476 s | 26.28 MB/s | 0.0597 s | 20.95 MB/s | 0.50 MB | 22.37 MB | Baseline |
| | | 128 KiB | 0.0473 s | 26.45 MB/s | 0.0729 s | 17.15 MB/s | 0.75 MB | 22.27 MB | **0.82× (Dec)** |
| **F3** | 5.40 MB | 64 KiB | 0.0767 s | 70.38 MB/s | 0.0902 s | 59.89 MB/s | 0.50 MB | 22.43 MB | Baseline |
| | | 128 KiB | 0.0559 s | 96.58 MB/s | 0.0808 s | 66.84 MB/s | 0.75 MB | 22.44 MB | 1.37× |
| **F4** | 18.70 MB | 64 KiB | 0.0943 s | 198.26 MB/s | 0.1101 s | 169.78 MB/s | 0.50 MB | 22.51 MB | Baseline |
| | | 128 KiB | 0.0981 s | 190.69 MB/s | 0.1163 s | 160.84 MB/s | 0.75 MB | 22.47 MB | **0.96× (Enc)** |
| **F5** | 50.00 MB | 64 KiB | 0.2010 s | 248.77 MB/s | 0.2359 s | 211.96 MB/s | 0.50 MB | 22.62 MB | Baseline |
| | | 128 KiB | 0.1447 s | **345.51 MB/s** | 0.1647 s | **303.63 MB/s** | 0.75 MB | 22.55 MB | **1.39×** |
| **F6** | 100.00 MB | 64 KiB | 0.4134 s | 241.92 MB/s | 0.3840 s | 260.43 MB/s | 0.50 MB | 22.65 MB | Baseline |
| | | 128 KiB | 0.3309 s | **302.22 MB/s** | 0.2782 s | **359.46 MB/s** | 0.75 MB | 22.54 MB | **1.25× / 1.38×** |

#### Analysis and Design Justification:
- **Workload Dependency:** 128 KiB chunking provides measurable throughput gains on large archives ($\ge 50\text{ MB}$), reaching **$345.51\text{ MB/s}$** on 50 MB files ($+38.9\%$) and **$359.46\text{ MB/s}$** decryption on 100 MB files ($+38.0\%$). However, on small and medium payloads, 128 KiB is either comparable or slightly slower (e.g., F2 decryption is $17.15\text{ MB/s}$ vs $20.95\text{ MB/s}$, a $0.82\times$ factor).
- **Memory Impact:** Peak Python heap increased by only $250\text{ KB}$ (from $0.50\text{ MB}$ to $0.75\text{ MB}$), while Process Working Set (RSS) remained completely unaffected at $\approx 22.5\text{ MB}$.
- **Design Conclusion:** **64 KiB is retained as the defensible general-purpose default**, with 128 KiB recommended as an optional configuration for dedicated bulk storage pipelines.

---

## 11. Security Evaluation and Correctness

The security properties of SecureFileCrypt were evaluated through automated adversarial testing covering functional correctness, structural validation, and active attack simulation.

### 11.1 Test Suite Verification
The complete test suite was executed post-optimization on Windows 10 AMD64:
```powershell
.\.venv_win\Scripts\python.exe -m pytest -v
```
**Results:** **46 passed, 1 skipped, 0 failed in 13.70s**.
- **Skipped Test:** `test_secure_file_permissions` in `improved/tests/test_improved_streaming.py`. This test checks POSIX octal file permissions (`0o600`), which are not supported by the Windows NTFS access control list architecture and are appropriately bypassed.

### 11.2 Evaluated Invariants and Adversarial Test Outcomes
Table 11 maps the verified security invariants against their respective test implementations and evaluated outcomes.

**Table 11: Security and Adversarial Correctness Test Matrix**

| Security Domain | Specific Threat / Invariant Tested | Test Implementation & Result | Evaluated Outcome |
| :--- | :--- | :--- | :--- |
| **Correct Decryption** | Roundtrip fidelity across text, PDF, binary, Unicode, and long filenames | `test_all_256_byte_values_fidelity`, `test_binary_files_roundtrip` | **PASSED:** Plaintext bitstream preserved identically |
| **Wrong Password Rejection** | Authentication failure when incorrect passphrase supplied | `test_wrong_password_rejected` | **PASSED:** Raises `IncorrectPasswordError`, zero plaintext released |
| **Ciphertext Tampering** | Bit-flipping in chunk ciphertext | `test_tampered_chunk_ciphertext_rejected` | **PASSED:** Raises `AuthenticationError` on tampered chunk |
| **Wrapped Key Tampering** | Bit-flipping in KEK nonce, salt, or wrapped DEK | `test_tampered_wrapped_dek_rejected` | **PASSED:** Raises `IncorrectPasswordError` before chunk read |
| **Metadata Modification** | Tampering with encrypted metadata JSON or tag | `test_tampered_metadata_rejected` | **PASSED:** Detected via metadata AAD binding |
| **Chunk Reordering** | Swapping chunk 1 and chunk 2 | `test_swapped_chunks_rejected` | **PASSED:** Detected via positional AAD (`chunk_index`) |
| **Chunk Truncation** | Deleting terminal chunk ($is\_last = 1$) | `test_truncated_stream_rejected` | **PASSED:** Raises `ContainerFormatError` upon premature EOF |
| **Trailing Data Injection** | Appending arbitrary bytes after final chunk | `test_trailing_data_rejected` | **PASSED:** Raises `ContainerFormatError` on extraneous trailing bytes |
| **Malformed Header / DoS** | Header demanding $m=1\text{ TB}$ or $t=10,000$ | `test_parameter_bomb_rejected` | **PASSED:** Rejected defensively before memory allocation |
| **Format Versioning** | Container with unsupported version byte (`0xFF`) | `test_unsupported_version_rejected` | **PASSED:** Raises `ContainerFormatError` immediately |
| **Path Traversal Defense** | Encrypted filename containing `../../etc/shadow` | `test_metadata_path_traversal_sanitized` | **PASSED:** Sanitized to safe basename upon decryption |
| **Zero Plaintext Leakage** | Ensuring no partial plaintext is released upon error | `test_file_streaming_atomic_and_leak_free` | **PASSED:** Aborts stream and unlinks temporary output file |

### 11.3 Scope and Limitations of Test-Based Verification
- **Unit Tests Are Not Formal Proofs:** Passing automated unit tests verifies implementation correctness against modeled attack patterns; it does not constitute a formal mathematical security proof, an exhaustive commercial penetration test, or a hardware side-channel timing audit.
- **Passphrase Entropy Dependency:** Argon2id cannot prevent offline password guessing if the user selects a weak or predictable password. Its memory-hardness drastically increases the monetary and hardware cost per guess by forcing adversaries to allocate dedicated high-bandwidth memory (64 MB in this configuration) per parallel attack thread, neutralizing low-cost register-only parallelization.

---

## 12. Limitations and Threats to Validity

To provide an academically honest assessment, the limitations of SecureFileCrypt are divided into implementation limitations and methodological/experimental limitations.

### 12.1 Implementation and Architectural Limitations

1. **FastAPI Upload Gateway In-Memory Buffering:**
   - In `server.py` line 65, the web endpoint handles file uploads via:
     ```python
     content = await file.read()  # Buffers full upload in server RAM
     in_stream = io.BytesIO(content)
     ```
   - While the core cryptographic engine (`improved/crypto.py`) supports bounded streaming via `encrypt_file` and file streams, the HTTP gateway currently buffers complete request bodies into memory. True end-to-end web streaming requires refactoring `server.py` to use `StreamingResponse` and async chunk iterators (Optimization 6).
2. **Argon2id Computational Floor & Native Memory Cost:**
   - Argon2id enforces a minimum $\approx 34\text{–}110\text{ ms}$ latency floor and allocates a temporary 64 MB matrix in C during derivation. While vital for brute-force resistance, this makes SecureFileCrypt slower than PBKDF2 on files $< 5\text{ MB}$ and imposes a 64 MB RAM floor during the derivation phase.
3. **In-Place Rotation Interruption Risk:**
   - `change_password_file(..., atomic=False)` overwrites the 111-byte header directly on disk. If power fails mid-write during the physical sector update, the container header can become corrupted, rendering the file unrecoverable.
4. **Atomic Replacement Copy Overhead and Filesystem Assumptions:**
   - `change_password_file(..., atomic=True)` guarantees crash consistency by spooling chunks into a `.tmp` file and invoking `os.replace`. However, this requires $O(N)$ data transfer time ($0.849\text{ s}$ on 400 MiB) and relies on atomic rename semantics supported by NTFS and POSIX filesystems.
5. **Platform-Specific Access Control Limitations:**
   - POSIX octal file permissions (`0o600`) are not enforced on Windows NTFS, leaving file confidentiality dependent on Windows user profile directory ACLs.
6. **Absence of Formal Verification or Third-Party Audit:**
   - The cryptographic protocols and container framing have not undergone independent third-party penetration testing or formal mathematical protocol verification (e.g., via ProVerif or Tamarin).
7. **Endpoint and Passphrase Compromise:**
   - SecureFileCrypt protects data at rest on disk. It does not protect against runtime process memory scraping on compromised client endpoints or keylogger-intercepted master passwords.

### 12.2 Methodological and Experimental Limitations

1. **Architectural and I/O Asymmetry in Benchmarks:**
   - Baseline benchmarks (`base_crypto.encrypt_bytes`) measure memory-to-memory throughput on pre-loaded byte buffers, bypassing disk reads and writes. Improved streaming benchmarks (`impr_crypto.encrypt_file`) execute full physical file I/O, temporary file creation, buffer flushing, and `os.fsync`. The resulting throughput numbers reflect memory bandwidth versus filesystem I/O, rather than an isolated cipher algorithm speed comparison.
2. **Filesystem Cache State Discrepancy (Warm vs Cold):**
   - In the 100 MiB comparative benchmark (`run_comparative_benchmarks.py`), tests were executed from cold disk files. In the 200–400 MiB scalability benchmark (`large_file_scalability.py`), test files were generated sequentially prior to execution and resided in the Windows NTFS standby file cache (warm cache), yielding higher streaming throughput ($351\text{–}512\text{ MiB/s}$ vs $110.2\text{ MB/s}$ on F6).
3. **Host Load and CPU Frequency Scaling on KDF Latency:**
   - Argon2id derivation latency varied across sessions ($0.2688\text{ s} \to 0.0888\text{ s} \to 0.0339\text{ s}$) due to dynamic CPU frequency scaling, background thread scheduling, and multi-core thermal states. Hardware telemetry was not recorded continuously.
4. **Python Heap (`tracemalloc`) Blindness to Native C Memory:**
   - `tracemalloc` tracks only Python runtime heap allocations. It is blind to the 64 MB matrix allocated by `argon2-cffi` and memory managed directly by OpenSSL `libcrypto`.
5. **Instantaneous Working Set Sampling vs Continuous Peak Working Set:**
   - Win32 `GetProcessMemoryInfo` captures `pmc.WorkingSetSize` at the instant of function return. It does not track `pmc.PeakWorkingSetSize` during active execution or constitute a formal mathematical proof against native memory leaks.
6. **Trial Sample Count:**
   - 3 trials per file size provide a representative median for scalability trends, but do not support high-confidence statistical significance intervals or tail-latency modeling.

---

## 13. Prioritized Future Work

To transition SecureFileCrypt from an academic prototype to a hardened, enterprise-grade cryptosystem, future development should proceed along the following prioritized directions:

1. **End-to-End Asynchronous Streaming in FastAPI Gateway (Optimization 6):**
   - Refactor `server.py` to stream file uploads and downloads using `StreamingResponse` and async chunk iterators (`file.stream()`) or chunked spooling via `tempfile.SpooledTemporaryFile`. This will eliminate the current in-memory upload buffering and extend bounded memory performance to web clients.
2. **Fair Same-I/O-Path Benchmarking:**
   - Implement benchmark harnesses that compare baseline and improved cryptosystems over identical I/O paths (i.e., disk-to-disk baseline with temporary file flushing vs disk-to-disk streaming, and memory-to-memory baseline vs memory-to-memory streaming) to isolate pure cryptographic framing overhead from disk latency.
3. **Continuous Peak RSS and Native Memory Instrumentation:**
   - Integrate continuous native memory instrumentation tracking `PeakWorkingSetSize` and native C allocations across both OpenSSL and `argon2-cffi`, establishing continuous working-set profiles across long-running pipelines.
4. **Automated Fuzzing and Comprehensive Malformed-File Testing:**
   - Implement continuous structure-aware fuzzing (using tools such as AFL, LibFuzzer, or Hypothesis) targeting chunk framing boundaries, corrupted headers, truncated tags, and malicious parameter combinations.
5. **Independent Third-Party Security Review & Formal Threat Modeling:**
   - Commission an independent third-party cryptographic audit and formal verification of the Format Version 2 container grammar, side-channel timing resistance, and explicit zeroization of plaintext and DEK memory buffers.
6. **Parameter Sensitivity Profiling for KDF and Chunk Granularity:**
   - Conduct comprehensive parameter sensitivity analyses evaluating chunk sizes from 16 KiB to 1 MiB and memory parameters $m=32\text{ MB}$ to $m=256\text{ MB}$ across client device classes (desktop workstations, mobile processors, and embedded systems).

---

## 14. Conclusion

This project designed, implemented, and empirically evaluated **SecureFileCrypt**, an advanced password-based file encryption cryptosystem that systematically addresses the key management, metadata exposure, and memory scaling limitations of conventional monolithic AES-GCM implementations based on Rosandi et al. (2026).

Our empirical findings verify that:
1. **Memory Scalability:** By shifting from monolithic buffer processing to chunked authenticated streaming, SecureFileCrypt achieves an empirically bounded Python heap of **$\approx 0.51\text{–}0.52\text{ MiB}$** across all tested workloads up to 400 MiB. In contrast, the baseline exhibits strictly linear heap growth ($2\times$ payload size), consuming **400.0 MiB**, **600.0 MiB**, and **800.0 MiB** of Python heap on 200 MiB, 300 MiB, and 400 MiB files respectively—demonstrating a measured **$1,579.2\times$ heap reduction** at 400 MiB.
2. **Password Rotation Efficiency:** Dual-key envelope encryption decouples data protection from passphrase derivation. In-place header overwrite completes in **$0.165\text{ s}$ on a 400 MiB file**—a **$4.75\times$ speedup** over full re-encryption—by updating only 111 bytes of fixed header plus padded metadata, with an explicit crash-safety trade-off against atomic replacement ($0.849\text{ s}$).
3. **Benchmark Context & Methodology:** Measured timing comparisons between baseline ($950\text{–}1,155\text{ MiB/s}$) and streaming ($351\text{–}512\text{ MiB/s}$) reflect the fundamental operational divergence between RAM memory-bandwidth and physical filesystem I/O, rather than an isolated cipher algorithm speed comparison.
4. **Security Investment:** The latency advantage of the baseline on small files ($\le 5\text{ MB}$) is an unavoidable consequence of its compute-only PBKDF2 derivation ($18.7\text{ ms}$ with $0\text{ MB}$ RAM). SecureFileCrypt accepts an intentional $\approx 34\text{–}110\text{ ms}$ / 64 MB Argon2id floor to provide robust resistance against modern GPU/ASIC offline password cracking.
5. **System Readiness:** The core Python streaming engine is complete, robust, and verified through automated adversarial testing (46 passed, 1 skipped). Full production deployment requires extending memory-bounded streaming to the FastAPI web gateway and conducting independent third-party security audits.

---

## 15. References

1. **Rosandi, A. A., Supriyono, D. H., Aulia, T. T., & Asri, J. S. (2026).** *Design of File Encryption and Decryption Application Using AES-256 Cryptography Algorithm Based on Streamlit*. International Journal of Multidisciplinary Research and Literature, 5(1), 162–168.
2. **Biryukov, A., Dinu, D., & Khovratovich, D. (2015).** *Argon2: New Generation of Memory-Hard Functions for Password Hashing and Proof-of-Work Problems*. In Advances in Cryptology – EUROCRYPT 2016, Springer.
3. **RFC 9106 (2021).** *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications*. Internet Engineering Task Force (IETF).
4. **Dworkin, M. (2007).** *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*. NIST Special Publication 800-38D, National Institute of Standards and Technology.
5. **Turan, M. S., et al. (2010).** *Recommendation for Password-Based Key Derivation: Part 1: Storage Applications*. NIST Special Publication 800-132, National Institute of Standards and Technology.
6. **Rogaway, P. (2002).** *Authenticated-Encryption with Associated-Data*. In Proceedings of the 9th ACM Conference on Computer and Communications Security (CCS '02), pp. 98–107.
7. **SecureFileCrypt Technical Reports (2026):**
   - *SecureFileCrypt Research & Technical Audit Report* (`report.md`).
   - *Performance Optimization and Profiling Report* (`performance_optimization_report.md`).
   - *Final Independent Validation Report* (`final_validation_report.md`).
   - *Extended Large-File Scalability Summary* (`benchmark/results/large_file_scalability_summary.md`).
   - *Extended Large-File Evidence Audit* (`benchmark/results/large_file_evidence_audit.md`).

---

### Appendix: Visual Benchmark Charts Reference

A complete visual representation of throughput, latency scaling, memory bounds, and password rotation comparisons is generated by `benchmark/plot_results.py` and saved to:
`benchmark/results/benchmark_charts.png`
*(Includes: 1. Encryption & Decryption Throughput across F1–F6; 2. Peak Memory Allocation Scaling; 3. Password Rotation Workflow Latencies; 4. Chunk Size Sensitivity Profile).*
