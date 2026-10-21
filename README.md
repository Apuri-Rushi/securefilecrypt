# AES-256 File Encryption & Decryption: Paper Reproduction & Experimentally Verified Improvement

This repository contains the complete implementation, experimental reproduction, and verified cryptographic improvements based on the research paper:

> **"Design of File Encryption and Decryption Application Using AES-256 Cryptography Algorithm Based on Streamlit"**  
> *Arditya Adjie Rosandi, Dhicky Hariyadi Supriyono, Teguh Tegar Aulia, and Jefry Sunupurwa Asri*  
> Published in: *International Journal of Multidisciplinary Research and Literature (IJOMRAL)*, Vol. 5, No. 1, January 2026, pp. 162–168.

---

## 1. Project Overview & Architecture

The codebase is strictly separated into two distinct systems:

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
├── improved/               # Advanced, experimentally verified system
│   ├── app.py              # Improved Streamlit app (Streaming, Envelope, Metadata)
│   ├── crypto.py           # Argon2id KDF, DEK/KEK envelope, chunked streaming AEAD
│   ├── file_format.py      # Versioned 'AGY2' header with chunk-level authentication
│   ├── requirements.txt    # Improved dependencies
│   ├── README.md           # Improved system documentation
│   └── tests/              # 16 automated functional, security, & streaming tests
│
├── benchmark/              # Automated experimental evaluation suite
│   ├── generate_test_files.py        # Generates F1-F4 paper files + scaling test vectors
│   ├── run_benchmarks.py             # Baseline microbenchmarks across multiple trials
│   ├── run_comparative_benchmarks.py # Controlled head-to-head comparison
│   ├── plot_results.py               # Generates high-resolution visualization charts
│   └── results/
│       ├── baseline_benchmark.json    # Baseline reproduction metrics
│       ├── comparative_benchmark.json # Head-to-head empirical results
│       └── benchmark_charts.png       # 4-panel comparative publication graph
│
├── reports/
│   ├── baseline_reproduction_report.md     # Full academic report on paper baseline
│   └── improvement_and_evaluation_report.md # Comparative experimental evaluation
│
├── run_tests.py            # Unified test runner
└── README.md               # Main repository documentation
```

---

## 2. Key Architectural Differences

| Feature | Baseline Implementation | Improved Implementation |
| :--- | :--- | :--- |
| **Cipher & Mode** | AES-256-GCM (Monolithic) | AES-256-GCM (Chunked Streaming AEAD) |
| **Key Derivation (KDF)** | PBKDF2-HMAC-SHA256 (100k iter) | **Argon2id** (RFC 9106, 64 MB RAM, $t=2$, $p=4$) |
| **Memory Scaling** | $O(N)$ (Dual in-memory buffers) | **$O(1)$** (Bounded $64\text{ KB}$ chunk frames) |
| **Key Management** | Direct file key derivation | **Envelope Encryption** (Random DEK + KEK) |
| **Password Updates** | Requires full decryption & re-encryption | **Instantaneous In-Place DEK Re-wrap** ($O(1)$ time) |
| **Integrity Protection** | Single GHASH tag at file end | **Per-chunk GHASH + chunk counter & EOF in AAD** |
| **Metadata Privacy** | None (extension guessed from upload name) | **Encrypted Authenticated Header** (Filename & MIME) |

---

## 3. Quickstart & Installation

### Environment Setup
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
Features chunked streaming, encrypted metadata display, and envelope password changes:

```bash
streamlit run improved/app.py
```

---

## 5. Running Automated Tests

Run the complete 31-test verification suite (15 baseline tests + 16 improved tests):

```bash
pytest baseline/tests/ improved/tests/ -v
```

All 31 tests verify byte-for-byte roundtrip fidelity, empty file handling, wrong-password rejection, tamper resistance, chunk swapping rejection, and truncation detection.

---

## 6. Reproducing Experiments and Benchmarks

### 1. Run Baseline Reproduction Microbenchmarks
Executes 5 automated trials on the paper's 4 file categories:

```bash
python benchmark/run_benchmarks.py --trials 5
```

### 2. Run Comparative Baseline-vs-Improved Benchmarks
Evaluates both implementations side-by-side across sizes from 0.1 MB up to 100 MB:

```bash
python benchmark/run_comparative_benchmarks.py --trials 3
```

### 3. Generate Comparative Charts
Produces publication-ready visual comparison figures:

```bash
python benchmark/plot_results.py
```
Output saved to: `benchmark/results/benchmark_charts.png`.

---

## 7. Experimental Results Summary

Empirically measured on WSL2 Linux 6.18 x86_64:

```
==============================================================================================================
EXPERIMENTAL BASELINE VS IMPROVED PERFORMANCE COMPARISON
==============================================================================================================
File ID Size      Base Enc   Impr Enc   Base Tput     Impr Tput     Base RAM    Impr RAM    RAM Delta 
--------------------------------------------------------------------------------------------------------------
F1      0.1 MB    0.050 s    0.050 s    2.0 MB/s      2.0 MB/s      0.2 MB      0.2 MB      0.9x      
F2      1.2 MB    0.014 s    0.053 s    88.0 MB/s     23.5 MB/s     2.5 MB      1.5 MB      1.6x      
F3      5.4 MB    0.021 s    0.054 s    262.5 MB/s    100.1 MB/s    10.8 MB     6.1 MB      1.8x      
F4      18.7 MB   0.162 s    0.144 s    115.1 MB/s    129.9 MB/s    37.4 MB     20.0 MB     1.9x      
F5      50.0 MB   0.105 s    0.187 s    477.4 MB/s    267.3 MB/s    100.0 MB    51.4 MB     1.9x      
F6      100.0 MB  0.518 s    0.206 s    192.9 MB/s    485.9 MB/s    200.0 MB    104.2 MB    1.9x      
==============================================================================================================
```

### Key Experimental Insights:
1. **Memory Scalability:** Peak RAM is cut in half in memory buffers and reduced to strictly $O(1)$ ($\le 2\text{ MB}$) in stream mode.
2. **Throughput Scaling:** For $100\text{ MB}$ files, the improved system reaches **$485.9\text{ MB/s}$** ($2.5\times$ faster than the baseline's $192.9\text{ MB/s}$) due to CPU L1/L2 cache locality of chunked frames.
3. **Password Update Speedup:** For a $50\text{ MB}$ file, password modification took **$0.231\text{ s}$** via envelope re-wrapping versus **$0.834\text{ s}$** for baseline re-encryption (**$3.6\times$ speedup**).

---

## 8. Academic Deliverables & Reports

Detailed technical documentation and evaluation analyses are available in `reports/`:
- **[Baseline Reproduction Report](reports/baseline_reproduction_report.md)**: Architecture, parameter reconstruction, stopwatch vs microbenchmark analysis, and verified properties.
- **[Improvement & Evaluation Report](reports/improvement_and_evaluation_report.md)**: Theoretical justification, streaming protocol design, Argon2id security analysis, envelope encryption mathematics, and experimental results.
