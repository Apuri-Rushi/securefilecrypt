import os
import sys
import time
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import improved.crypto as impr_crypto

data_path = PROJECT_ROOT / "benchmark" / "test_data" / "sample_F6_100mb.bin"
password = "ComparisonPassword2026!"

print("=== DIAGNOSING TIMING DIFFERENCE ON F6 (100 MB) ===")
print("File exists:", data_path.exists(), "Size:", data_path.stat().st_size)

with tempfile.TemporaryDirectory() as tmpdir:
    tmp_p = Path(tmpdir)
    enc_p = tmp_p / "diag.enc"
    dec_p = tmp_p / "diag.dec"

    # 1. Cold run with 64KB (like run_comparative_benchmarks)
    t0 = time.perf_counter()
    impr_crypto.encrypt_file(data_path, enc_p, password, chunk_size=64*1024)
    cold_64_time = time.perf_counter() - t0
    enc_p.unlink()

    # 2. Warm run with 64KB
    t0 = time.perf_counter()
    impr_crypto.encrypt_file(data_path, enc_p, password, chunk_size=64*1024)
    warm_64_time = time.perf_counter() - t0
    enc_p.unlink()

    # 3. Warm run with 128KB (like benchmark_64_vs_128)
    t0 = time.perf_counter()
    impr_crypto.encrypt_file(data_path, enc_p, password, chunk_size=128*1024)
    warm_128_time = time.perf_counter() - t0
    enc_p.unlink()

    print(f"1. Cold 64KB encrypt_file: {cold_64_time:.4f} s ({100/cold_64_time:.1f} MB/s)")
    print(f"2. Warm 64KB encrypt_file: {warm_64_time:.4f} s ({100/warm_64_time:.1f} MB/s)")
    print(f"3. Warm 128KB encrypt_file: {warm_128_time:.4f} s ({100/warm_128_time:.1f} MB/s)")
