# AES-256 File Encryption & Decryption: Paper Reproduction & Experimentally Verified Improvement

This repository contains the complete implementation, experimental reproduction, and verified cryptographic improvements based on the research paper:

> **"Design of File Encryption and Decryption Application Using AES-256 Cryptography Algorithm Based on Streamlit"**  
> *Arditya Adjie Rosandi, Dhicky Hariyadi Supriyono, Teguh Tegar Aulia, and Jefry Sunupurwa Asri*  
> Published in: *International Journal of Multidisciplinary Research and Literature (IJOMRAL)*, Vol. 5, No. 1, January 2026, pp. 162–168.

---

## 1. Project Overview & Architecture

The codebase is strictly organized into two distinct, side-by-side systems:

```
ics project/
├── baseline/               # Faithful reproduction of Rosandi et al. (2026)
│   ├── app.py              # Baseline Streamlit web application
│   ├── crypto.py           # PBKDF2-HMAC-SHA256 & monolithic AES-256-GCM
│   ├── file_format.py      # Binary packaging: [salt (16)][nonce (12)][ciphertext (N+16)]
│   ├── requirements.txt    # Baseline dependencies
│   ├── README.md           # Baseline technical documentation
│   └── tests/              # 15 automated functional and security tests
│
├── improved/               # Advanced, experimentally verified system (AGY2 v2)
│   ├── app.py              # Enhanced Streamlit app (Streaming, Envelope, Metadata)
│   ├── crypto.py           # Argon2id KDF, DEK/KEK envelope, chunked streaming AEAD
│   ├── file_format.py      # Versioned 'AGY2' v2 header with full parameter AAD binding
│   ├── requirements.txt    # Improved dependencies
│   ├── README.md           # Improved system documentation
│   └── tests/              # 31 automated functional, security, & streaming tests
│
├── benchmark/              # Automated experimental evaluation suite
│   ├── generate_test_files.py        # Generates F1-F4 paper files + F5/F6 stress vectors
│   ├── run_benchmarks.py             # Baseline microbenchmarks across multiple trials
│   ├── run_comparative_benchmarks.py # Controlled head-to-head comparison
│   ├── plot_results.py               # Generates publication-grade 4-panel visual chart
│   └── results/
│       ├── baseline_benchmark.json    # Baseline reproduction metrics
│       ├── comparative_benchmark.json # Head-to-head empirical results
│       └── benchmark_charts.png       # Comparative visualization chart
│
├── reports/
│   ├── baseline_reproduction_report.md     # Full academic report on paper baseline
│   └── improvement_and_evaluation_report.md # Comparative experimental evaluation
│
├── run_tests.py            # Unified test runner (46 tests, 100% pass rate)
└── README.md               # Main repository documentation
```

---

## 2. Key Architectural Differences

| Feature | Baseline Implementation (Rosandi et al.) | Final Improved Implementation (AGY2 v2) |
| :--- | :--- | :--- |
| **Cipher & Mode** | AES-256-GCM (Monolithic in-memory) | **AES-256-GCM (Chunked Streaming AEAD)** |
| **Key Derivation (KDF)** | PBKDF2-HMAC-SHA256 (100k iter) | **Argon2id (RFC 9106)** ($64\text{ MB}$, $t=2$, $p=4$) |
| **Memory Hardness** | None (0 MB RAM overhead, vulnerable to GPU) | **64 MB Deliberate RAM Hardness** (Starves GPU memory bus) |
| **Memory Scaling** | $O(N)$ (Dual buffers, 200 MB on 100 MB file) | **$O(1)$ Strictly Constant** ($< 0.3\text{ MB}$ RAM on any file size) |
| **Key Management** | Single password-derived key | **Envelope Encryption** (Random DEK + Argon2id KEK) |
| **Password Updates** | Full payload decrypt & re-encrypt ($O(N)$ work) | **Instantaneous DEK Re-wrap** ($O(1)$ time, payload untouched) |
| **Header Authentication** | None | **Cryptographically Bound Header AAD** in AGY2 v2 |
| **Streaming Integrity** | Single GHASH tag at file end | **Per-chunk GHASH + chunk counter & EOF flag in AAD** |
| **Malicious Trailing Data** | Silently ignored (vulnerable) | **Detected & Rejected via `TrailingDataError`** |
| **Metadata Privacy** | None (extension guessed from upload name) | **Encrypted & Block-Padded Header** (hides filename length) |
| **Automated Tests** | 15 tests | **31 tests (46 total across repo, 100% pass rate)** |

---

## 3. Quickstart & Installation

Python 3.10+ is required. Set up and activate a virtual environment:

```bash
# Clone or navigate to the workspace
cd "/mnt/c/Users/hp/OneDrive/Desktop/ics project"

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r baseline/requirements.txt
pip install -r improved/requirements.txt
```

---

## 4. Running the Applications

### Launch Baseline Application
Faithfully reproduces the paper's web interface (Figures 1, 2, 4):
```bash
streamlit run baseline/app.py
```

### Launch Improved Application
Features chunked streaming, dual-mode compatibility, encrypted metadata display, and envelope password changes:
```bash
streamlit run improved/app.py
```

---

## 5. Running Automated Tests

Run the complete 46-test verification suite (15 baseline tests + 31 improved tests):

```bash
python run_tests.py
```
*(or via pytest directly)*:
```bash
pytest baseline/tests/ improved/tests/ -v
```

All 46 tests verify byte-for-byte fidelity, empty file roundtrips, wrong-password rejection, ciphertext tampering detection, chunk swapping detection, version 2 header AAD tampering rejection, trailing data rejection, invalid chunk length rejection, parameter bomb rejection, path-traversal sanitization, atomic password modification, and payload ciphertext invariance.

---

## 6. Reproducing Experiments and Benchmarks

### 1. Run Comparative Benchmarks
Evaluates both implementations side-by-side across sizes from 0.1 MB up to 100 MB with statistical aggregation:

```bash
python benchmark/run_comparative_benchmarks.py --trials 3 --extended
```

### 2. Generate Comparative Visualization Charts
Produces publication-grade visual comparison figures:

```bash
python benchmark/plot_results.py
```
Output saved to: `benchmark/results/benchmark_charts.png`.

---

## 7. Experimental Results Summary

Empirically measured on Linux x86_64:

```
===================================================================================================================
EXPERIMENTAL EVALUATION: BASELINE VS FINAL IMPROVED SYSTEM
===================================================================================================================
File ID Size      Base Enc   Impr Enc   Base Tput     Impr Tput     Base RAM    Stream RAM    RAM Factor
-------------------------------------------------------------------------------------------------------------------
F1      0.1 MB    0.015 s    0.050 s    6.7 MB/s      2.0 MB/s      0.2 MB      0.24 MB       0.8x less 
F2      1.2 MB    0.013 s    0.054 s    95.3 MB/s     23.0 MB/s     2.5 MB      0.26 MB       9.6x less 
F3      5.4 MB    0.017 s    0.060 s    310.9 MB/s    90.2 MB/s     10.8 MB     0.26 MB       41.3x less
F4      18.7 MB   0.030 s    0.075 s    633.7 MB/s    248.5 MB/s    37.4 MB     0.26 MB       143.0x less
F5      50.0 MB   0.778 s    0.140 s    64.3 MB/s     356.7 MB/s    100.0 MB    0.26 MB       382.2x less
F6      100.0 MB  1.249 s    0.437 s    80.0 MB/s     228.7 MB/s    200.0 MB    0.26 MB       764.5x less
===================================================================================================================
```

### Key Experimental Insights:
1. **Strict $O(1)$ Memory Scalability:** While baseline RAM grows linearly to 200 MB on a 100 MB file, improved disk streaming maintains a constant **0.26 MB** heap footprint across all file sizes (up to **764.5× lower RAM** on 100 MB files).
2. **Throughput Scaling on Large Payloads:** On 50 MB files, the improved system achieves **356.7 MB/s** (5.5× faster than baseline 64.3 MB/s). On 100 MB files, it achieves **228.7 MB/s** (2.8× faster than baseline 80.0 MB/s).
3. **KDF Security vs. Latency:** Argon2id introduces ~37 ms of deliberate, memory-hard derivation latency (53.5 ms vs 16.6 ms) while enforcing 64 MB of RAM hardness to defeat parallel GPU cracking.
4. **Envelope Password Agility:** Re-wrapping the DEK without touching the ciphertext payload eliminates multi-megabyte decryption/re-encryption overhead.

---

## 8. Academic Deliverables & Reports

Detailed technical documentation and evaluation analyses are available in `reports/`:
- **[Baseline Reproduction Report](reports/baseline_reproduction_report.md)**: Architecture, parameter reconstruction, stopwatch vs microbenchmark analysis, and verified properties.
- **[Improvement & Evaluation Report](reports/improvement_and_evaluation_report.md)**: Theoretical justification, streaming protocol design, Argon2id security analysis, envelope encryption mathematics, chunk size sensitivity, and experimental results.
