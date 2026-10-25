"""
Synchronizes reports/SecureFileCrypt_Project_Report.md,
reports/SecureFileCrypt_Research_Report.md, and deliverables/evidence_map.md
with the verified Windows 10 dataset in comparative_benchmark.json and final_submission_report.md.
"""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# 1. Update reports/SecureFileCrypt_Project_Report.md
proj_report_path = PROJECT_ROOT / "reports" / "SecureFileCrypt_Project_Report.md"
content = proj_report_path.read_text(encoding="utf-8")

# Replace Table 7.1 and analysis
old_table_7_1 = """| File ID | File Size (MB) | System Engine | Encryption Mean Time (s) | Encryption Throughput (MB/s) | Decryption Mean Time (s) | Decryption Throughput (MB/s) | Peak Heap RAM (MB) |
| :---: | :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **F1** | 0.10 MB | Baseline (418.pdf)<br>**Improved (AGY2)** | 0.0502 s<br>**0.0497 s** | 1.99 MB/s<br>**2.01 MB/s** | 0.0165 s<br>**0.0495 s** | 6.05 MB/s<br>**2.02 MB/s** | 0.20 MB<br>**0.23 MB** |
| **F2** | 1.25 MB | Baseline (418.pdf)<br>**Improved (AGY2)** | 0.0142 s<br>**0.0533 s** | 88.02 MB/s<br>**23.46 MB/s** | 0.0145 s<br>**0.0562 s** | 86.11 MB/s<br>**22.25 MB/s** | 2.50 MB<br>**1.53 MB** |
| **F3** | 5.40 MB | Baseline (418.pdf)<br>**Improved (AGY2)** | 0.0206 s<br>**0.0540 s** | 262.48 MB/s<br>**100.05 MB/s** | 0.0147 s<br>**0.0525 s** | 367.09 MB/s<br>**102.86 MB/s** | 10.80 MB<br>**6.09 MB** |
| **F4** | 18.70 MB | Baseline (418.pdf)<br>**Improved (AGY2)** | 0.1625 s<br>**0.1440 s** | 115.10 MB/s<br>**129.87 MB/s** | 0.0274 s<br>**0.1272 s** | 682.20 MB/s<br>**146.97 MB/s** | 37.40 MB<br>**20.02 MB** |
| **F5** | 50.00 MB | Baseline (418.pdf)<br>**Improved (AGY2)** | 0.1047 s<br>**0.1870 s** | 477.41 MB/s<br>**267.34 MB/s** | 0.1495 s<br>**0.1584 s** | 334.44 MB/s<br>**315.67 MB/s** | 100.00 MB<br>**51.39 MB** |
| **F6** | 100.00 MB | Baseline (418.pdf)<br>**Improved (AGY2)** | 0.5184 s<br>**0.2058 s** | 192.91 MB/s<br>**485.85 MB/s** | 0.2207 s<br>**0.1802 s** | 453.12 MB/s<br>**554.80 MB/s** | 200.00 MB<br>**104.21 MB** |"""

new_table_7_1 = """| File ID | File Size (MB) | System Engine | Encryption Mean Time (s) | Encryption Throughput (MB/s) | Decryption Mean Time (s) | Decryption Throughput (MB/s) | Peak Heap RAM (MB) |
| :---: | :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **F1** | 0.10 MB | Baseline (In-Memory RAM)<br>**Improved (Disk Streaming)** | 0.0319 s<br>**0.0721 s** | 3.14 MB/s<br>**1.39 MB/s** | 0.0280 s<br>**0.0899 s** | 3.57 MB/s<br>**1.11 MB/s** | 0.20 MB<br>**0.42 MB** |
| **F2** | 1.25 MB | Baseline (In-Memory RAM)<br>**Improved (Disk Streaming)** | 0.0256 s<br>**0.0620 s** | 48.88 MB/s<br>**20.18 MB/s** | 0.0235 s<br>**0.0888 s** | 53.30 MB/s<br>**14.08 MB/s** | 2.50 MB<br>**0.50 MB** |
| **F3** | 5.40 MB | Baseline (In-Memory RAM)<br>**Improved (Disk Streaming)** | 0.0433 s<br>**0.1798 s** | 124.65 MB/s<br>**30.03 MB/s** | 0.0417 s<br>**0.1913 s** | 129.39 MB/s<br>**28.23 MB/s** | 10.80 MB<br>**0.50 MB** |
| **F4** | 18.70 MB | Baseline (In-Memory RAM)<br>**Improved (Disk Streaming)** | 0.0756 s<br>**0.2946 s** | 247.35 MB/s<br>**63.48 MB/s** | 0.0759 s<br>**0.2599 s** | 246.28 MB/s<br>**71.94 MB/s** | 37.40 MB<br>**0.50 MB** |
| **F5** | 50.00 MB | Baseline (In-Memory RAM)<br>**Improved (Disk Streaming)** | 0.1640 s<br>**0.4488 s** | 304.96 MB/s<br>**111.40 MB/s** | 0.1273 s<br>**0.4798 s** | 392.82 MB/s<br>**104.22 MB/s** | 100.00 MB<br>**0.50 MB** |
| **F6** | 100.00 MB | Baseline (In-Memory RAM)<br>**Improved (Disk Streaming)** | 0.2565 s<br>**0.9073 s** | 389.86 MB/s<br>**110.22 MB/s** | 0.2605 s<br>**0.6165 s** | 383.84 MB/s<br>**162.22 MB/s** | 200.00 MB<br>**0.50 MB** |"""

if old_table_7_1 in content:
    content = content.replace(old_table_7_1, new_table_7_1)
    print("Updated Table 7.1 in Project Report")

# Replace KDF Table 7.2
old_kdf = """| **Mean Execution Latency** | **0.0528 s** (52.8 ms) | **0.0469 s** (46.9 ms) | Argon2id is 1.12x faster while memory-hard |
| **Median Execution Latency**| **0.0120 s** (12.0 ms) | **0.0469 s** (46.9 ms) | Argon2id shows low standard deviation (0.001s) |"""

new_kdf = """| **Mean Execution Latency** | **0.0187 s** (18.7 ms) | **0.1096 s** (109.6 ms) | Argon2id enforces 64 MB memory allocation |
| **Median Execution Latency**| **0.0206 s** (20.6 ms) | **0.0888 s** (88.8 ms) | Predictable derivation floor |"""

if old_kdf in content:
    content = content.replace(old_kdf, new_kdf)
    print("Updated KDF Table in Project Report")

# Replace Password Change Table 7.3
old_rot = """| **F2** | 1.25 MB | **0.0274 s** | 0.1060 s | **0.26x** | Baseline is faster (KDF dominates) |
| **F4** | 18.70 MB | **0.0520 s** | 0.3708 s | **0.14x** | Baseline is faster (KDF dominates) |
| **F5** | 50.00 MB | 0.8341 s | **0.2310 s** | **3.61x** | **Envelope rotation is 3.61x faster** |
| **F6 (proj)**| 100.00 MB | ~1.7500 s | **~0.2500 s** | **~7.00x** | **Envelope rotation is ~7x faster** |"""

new_rot = """| **F2** | 1.25 MB | **0.0521 s** | 0.3005 s | **0.17x** | Baseline is faster (2x PBKDF2 < 2x Argon2id) |
| **F4** | 18.70 MB | **0.1174 s** | 0.2872 s | **0.41x** | Baseline is faster on small payload |
| **F5** | 50.00 MB | **0.3142 s** | 0.4173 s | **0.75x** | Approaching crossover threshold |
| **F6** | 100.00 MB | 2.0043 s | **0.3571 s** | **5.61x** | **In-place rotation is 5.61x faster** |
| **F9** | 400.00 MB | 0.7828 s | **0.1647 s** | **4.75x** | **In-place rotation is 4.75x faster** |"""

if old_rot in content:
    content = content.replace(old_rot, new_rot)
    print("Updated Rotation Table in Project Report")

# Update Conclusion Objectives
content = content.replace(
    "- **Objective 2 (Argon2id KDF):** Verified via `comparative_benchmark.json`, demonstrating 46.9 ms derivation latency backed by 64 MB of dedicated RAM.",
    "- **Objective 2 (Argon2id KDF):** Verified via `comparative_benchmark.json`, demonstrating 88.8 ms median derivation latency backed by 64 MB of dedicated RAM."
)
content = content.replace(
    "- **Objective 4 (Streaming AEAD):** Demonstrated a 2.52x throughput increase at 100 MB (485.85 MB/s vs. 192.91 MB/s) and halved memory overhead.",
    "- **Objective 4 (Streaming AEAD):** Demonstrated bounded Python heap allocation (≤0.50 MB across all workloads up to 100 MB; 400x memory reduction) and verified large-file streaming up to 400 MB."
)

proj_report_path.write_text(content, encoding="utf-8")


# 2. Update reports/SecureFileCrypt_Research_Report.md
res_report_path = PROJECT_ROOT / "reports" / "SecureFileCrypt_Research_Report.md"
r_content = res_report_path.read_text(encoding="utf-8")

old_res_table = """| File ID | File Vector & Type | Size (MB) | Baseline Encryption Time (s) | Baseline Throughput (MB/s) | Baseline Peak RAM (MB) | Improved Encryption Time (s) | Improved Throughput (MB/s) | Improved Peak RAM (MB) | Throughput Speedup Factor | Peak RAM Reduction |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **F1** | Text (`.txt`) | 0.10 MB | 0.0502 s | 1.99 MB/s | 0.20 MB | 0.0497 s | 2.01 MB/s | 0.23 MB | **1.01x** | 0.88x |
| **F2** | Document (`.pdf`) | 1.25 MB | 0.0142 s | 88.02 MB/s | 2.50 MB | 0.0533 s | 23.46 MB/s | 1.53 MB | 0.27x | **1.63x** |
| **F3** | Image (`.jpg`) | 5.40 MB | 0.0206 s | 262.48 MB/s | 10.80 MB | 0.0540 s | 100.05 MB/s | 6.09 MB | 0.38x | **1.77x** |
| **F4** | Video (`.mp4`) | 18.70 MB | 0.1625 s | 115.10 MB/s | 37.40 MB | 0.1440 s | 129.87 MB/s | 20.02 MB | **1.13x** | **1.87x** |
| **F5** | Archive (`.bin`) | 50.00 MB | 0.1047 s | 477.41 MB/s | 100.00 MB | 0.1870 s | 267.34 MB/s | 51.39 MB | 0.56x | **1.95x** |
| **F6** | Large Archive (`.bin`) | 100.00 MB | 0.5184 s | 192.91 MB/s | 200.00 MB | **0.2058 s** | **485.85 MB/s** | **104.21 MB** | **2.52x** | **1.92x** |"""

new_res_table = """| File ID | File Vector & Type | Size (MB) | Baseline Encryption Time (s) | Baseline Throughput (MB/s) | Baseline Peak RAM (MB) | Improved Encryption Time (s) | Improved Throughput (MB/s) | Improved Peak RAM (MB) | Methodological Note | Peak RAM Reduction |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **F1** | Text (`.txt`) | 0.10 MB | 0.0319 s | 3.14 MB/s | 0.20 MB | 0.0721 s | 1.39 MB/s | 0.42 MB | Argon2id KDF dominates small file | ~0.5x (header) |
| **F2** | Document (`.pdf`) | 1.25 MB | 0.0256 s | 48.88 MB/s | 2.50 MB | 0.0620 s | 20.18 MB/s | 0.50 MB | Argon2id KDF dominates small file | **5.0x less** |
| **F3** | Image (`.jpg`) | 5.40 MB | 0.0433 s | 124.65 MB/s | 10.80 MB | 0.1798 s | 30.03 MB/s | 0.50 MB | Disk streaming vs RAM bandwidth | **21.6x less** |
| **F4** | Video (`.mp4`) | 18.70 MB | 0.0756 s | 247.35 MB/s | 37.40 MB | 0.2946 s | 63.48 MB/s | 0.50 MB | Disk streaming vs RAM bandwidth | **74.8x less** |
| **F5** | Archive (`.bin`) | 50.00 MB | 0.1640 s | 304.96 MB/s | 100.00 MB | 0.4488 s | 111.40 MB/s | 0.50 MB | Disk streaming vs RAM bandwidth | **200.0x less** |
| **F6** | Large Archive (`.bin`) | 100.00 MB | 0.2565 s | 389.86 MB/s | 200.00 MB | 0.9073 s | 110.22 MB/s | 0.50 MB | Bounded disk streaming (O(1) RAM) | **400.0x less** |"""

if old_res_table in r_content:
    r_content = r_content.replace(old_res_table, new_res_table)
    print("Updated Research Report Comparative Table")

old_res_rot = """| **F2** | 1.25 MB | 0.0274 s | 0.1060 s | 0.26x (KDF dominates) |
| **F4** | 18.70 MB | 0.0520 s | 0.3708 s | 0.14x |
| **F5** | 50.00 MB | 0.8341 s | **0.2310 s** | **3.61x Faster** |
| **F6** | 100.00 MB | ~1.75 s (projected) | **~0.25 s** | **~7x Faster** |"""

new_res_rot = """| **F2** | 1.25 MB | **0.0521 s** | 0.3005 s | 0.17x (Baseline faster) |
| **F4** | 18.70 MB | **0.1174 s** | 0.2872 s | 0.41x (Baseline faster) |
| **F5** | 50.00 MB | **0.3142 s** | 0.4173 s | 0.75x (Approaching crossover) |
| **F6** | 100.00 MB | 2.0043 s | **0.3571 s** | **5.61x Faster (O(1) at scale)** |"""

if old_res_rot in r_content:
    r_content = r_content.replace(old_res_rot, new_res_rot)
    print("Updated Research Report Rotation Table")

old_res_kdf = """| **Mean Derivation Latency** | 0.0528 s (52.8 ms) | 0.0469 s (46.9 ms) | Comparable interactive responsiveness. |"""
new_res_kdf = """| **Mean Derivation Latency** | 0.0187 s (18.7 ms) | 0.1096 s (109.6 ms) | Argon2id enforces 64 MB memory allocation. |"""

if old_res_kdf in r_content:
    r_content = r_content.replace(old_res_kdf, new_res_kdf)
    print("Updated Research Report KDF Table")

r_content = r_content.replace(
    "outperforms the baseline by **2.52x (485.85 MB/s vs. 192.91 MB/s)**",
    "operates with strictly bounded Python heap memory (≤0.50 MB vs 200 MB, a 400x reduction)"
)

res_report_path.write_text(r_content, encoding="utf-8")


# 3. Update deliverables/evidence_map.md
ev_path = PROJECT_ROOT / "deliverables" / "evidence_map.md"
ev_content = ev_path.read_text(encoding="utf-8")

old_ev_table = """| **F1** | 0.10 MB | Encryption Time<br>Throughput<br>Peak Heap RAM | 0.0502 s<br>1.99 MB/s<br>0.20 MB | 0.0497 s<br>2.01 MB/s<br>0.23 MB | 1.01x Enc Time<br>1.01x Throughput<br>0.88x RAM | `comparative_benchmark.json:28–48` |
| **F2** | 1.25 MB | Encryption Time<br>Throughput<br>Peak Heap RAM | 0.0142 s<br>88.02 MB/s<br>2.50 MB | 0.0533 s<br>23.46 MB/s<br>1.53 MB | 0.27x Enc Time<br>0.27x Throughput<br>**1.63x RAM Reduction** | `comparative_benchmark.json:49–69` |
| **F3** | 5.40 MB | Encryption Time<br>Throughput<br>Peak Heap RAM | 0.0206 s<br>262.48 MB/s<br>10.80 MB | 0.0540 s<br>100.05 MB/s<br>6.09 MB | 0.38x Enc Time<br>0.38x Throughput<br>**1.77x RAM Reduction** | `comparative_benchmark.json:70–90` |
| **F4** | 18.70 MB | Encryption Time<br>Throughput<br>Peak Heap RAM | 0.1625 s<br>115.10 MB/s<br>37.40 MB | 0.1440 s<br>129.87 MB/s<br>20.02 MB | **1.13x Speedup**<br>**1.13x Throughput**<br>**1.87x RAM Reduction** | `comparative_benchmark.json:91–111` |
| **F5** | 50.00 MB | Encryption Time<br>Throughput<br>Peak Heap RAM | 0.1047 s<br>477.41 MB/s<br>100.00 MB | 0.1870 s<br>267.34 MB/s<br>51.39 MB | 0.56x Enc Time<br>0.56x Throughput<br>**1.95x RAM Reduction** | `comparative_benchmark.json:112–132` |
| **F6** | 100.00 MB | Encryption Time<br>Throughput<br>Peak Heap RAM | 0.5184 s<br>192.91 MB/s<br>200.00 MB | **0.2058 s**<br>**485.85 MB/s**<br>**104.21 MB** | **2.52x Faster**<br>**2.52x Throughput**<br>**1.92x RAM Reduction** | `comparative_benchmark.json:133–153` |
| **KDF** | N/A | Mean Latency<br>Memory Cost | 52.8 ms (PBKDF2)<br>0 MB ($<1\\text{ KB}$) | 46.9 ms (Argon2id)<br>**64 MB RAM** | Comparable Desktop UI Latency<br>**Massive Memory Hardness** | `comparative_benchmark.json:9–26` |
| **Rotation** | 1.25 MB (F2)<br>18.7 MB (F4)<br>50.0 MB (F5) | Password Update Time | 0.0274 s<br>0.0520 s<br>0.8341 s | 0.1060 s<br>0.3708 s<br>**0.2310 s** | 0.26x (KDF dominates)<br>0.14x<br>**3.61x Faster (O(1) at scale)** | `comparative_benchmark.json:155–177` |"""

new_ev_table = """| **F1** | 0.10 MB | Encryption Time<br>Throughput<br>Peak Heap RAM | 0.0319 s<br>3.14 MB/s<br>0.20 MB | 0.0721 s<br>1.39 MB/s<br>0.42 MB | 0.44x Enc Time<br>0.44x Throughput<br>0.48x RAM | `comparative_benchmark.json:28–71` |
| **F2** | 1.25 MB | Encryption Time<br>Throughput<br>Peak Heap RAM | 0.0256 s<br>48.88 MB/s<br>2.50 MB | 0.0620 s<br>20.18 MB/s<br>0.50 MB | 0.41x Enc Time<br>0.41x Throughput<br>**5.00x RAM Reduction** | `comparative_benchmark.json:72–115` |
| **F3** | 5.40 MB | Encryption Time<br>Throughput<br>Peak Heap RAM | 0.0433 s<br>124.65 MB/s<br>10.80 MB | 0.1798 s<br>30.03 MB/s<br>0.50 MB | 0.24x Enc Time<br>0.24x Throughput<br>**21.60x RAM Reduction** | `comparative_benchmark.json:116–159` |
| **F4** | 18.70 MB | Encryption Time<br>Throughput<br>Peak Heap RAM | 0.0756 s<br>247.35 MB/s<br>37.40 MB | 0.2946 s<br>63.48 MB/s<br>0.50 MB | 0.26x Enc Time<br>0.26x Throughput<br>**74.80x RAM Reduction** | `comparative_benchmark.json:160–203` |
| **F5** | 50.00 MB | Encryption Time<br>Throughput<br>Peak Heap RAM | 0.1640 s<br>304.96 MB/s<br>100.00 MB | 0.4488 s<br>111.40 MB/s<br>0.50 MB | 0.37x Enc Time<br>0.37x Throughput<br>**200.00x RAM Reduction** | `comparative_benchmark.json:204–247` |
| **F6** | 100.00 MB | Encryption Time<br>Throughput<br>Peak Heap RAM | 0.2565 s<br>389.86 MB/s<br>200.00 MB | 0.9073 s<br>110.22 MB/s<br>**0.50 MB** | 0.28x Enc Time (Disk vs RAM)<br>0.28x Throughput<br>**400.00x RAM Reduction** | `comparative_benchmark.json:248–291` |
| **KDF** | N/A | Mean Latency<br>Memory Cost | 18.7 ms (PBKDF2)<br>0 MB ($<1\\text{ KB}$) | 109.6 ms (Argon2id)<br>**64 MB RAM** | Standard Desktop Derivation Latency<br>**Massive Memory Hardness** | `comparative_benchmark.json:9–26` |
| **Rotation** | 1.25 MB (F2)<br>18.7 MB (F4)<br>100.0 MB (F6) | Password Update Time | 0.0521 s<br>0.1174 s<br>2.0043 s | 0.3005 s<br>0.2872 s<br>**0.3571 s** | 0.17x (KDF dominates)<br>0.41x<br>**5.61x Faster (O(1) at scale)** | `comparative_benchmark.json:293–338` |"""

if old_ev_table in ev_content:
    ev_content = ev_content.replace(old_ev_table, new_ev_table)
    print("Updated evidence_map.md Table")

ev_path.write_text(ev_content, encoding="utf-8")
print("Synchronization complete!")
