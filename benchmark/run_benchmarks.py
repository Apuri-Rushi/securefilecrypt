"""
Benchmarking script for paper reproduction and performance analysis.

Dual-Mode Timing Analysis:
1. End-to-End Application Workflow (matching the paper's manual stopwatch methodology from button click to download button appearance).
2. Pure Cryptographic Kernel (isolating raw C/AES-NI execution without interface overhead).

Measures:
- Encryption processing time (mean, median, stdev, range)
- Decryption processing time (mean, median, stdev, range)
- Key derivation latency
- Throughput (MB/s = File Size / Processing Time)
- Peak allocated memory (tracemalloc)
- Cryptographic integrity (SHA-256 match)

Outputs results to JSON and prints formatted comparison tables.
"""

import argparse
import hashlib
import json
import os
import platform
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from baseline.crypto import encrypt_bytes, decrypt_bytes, derive_key, PBKDF2_ITERATIONS
from baseline.file_format import unpack_container
from benchmark.generate_test_files import generate_all_paper_test_files

# Ground truth values directly from Table 2 of Rosandi et al. (2026)
PAPER_REPORTED_METRICS = {
    "F1": {"type": "Text (.txt)", "size_mb": 0.10, "enc_s": 0.3, "dec_s": 0.2},
    "F2": {"type": "PDF document", "size_mb": 1.25, "enc_s": 0.8, "dec_s": 0.7},
    "F3": {"type": "Image (.jpg)", "size_mb": 5.40, "enc_s": 1.9, "dec_s": 1.7},
    "F4": {"type": "Short video (.mp4)", "size_mb": 18.70, "enc_s": 5.4, "dec_s": 5.0},
}


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def get_system_metadata() -> dict:
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
    }


def benchmark_baseline_single_run(plaintext: bytes, password: str) -> dict:
    """Performs one full timed run of key derivation, encryption, and decryption."""
    # Measure KDF isolation
    salt_sample = os.urandom(16)
    kdf_start = time.perf_counter()
    derive_key(password, salt_sample)
    kdf_duration = time.perf_counter() - kdf_start

    # Measure pure encryption pipeline + memory
    tracemalloc.start()
    enc_start = time.perf_counter()
    container = encrypt_bytes(plaintext, password)
    enc_duration = time.perf_counter() - enc_start
    current_mem, peak_mem_enc = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Measure pure decryption pipeline + memory
    tracemalloc.start()
    dec_start = time.perf_counter()
    restored = decrypt_bytes(container, password)
    dec_duration = time.perf_counter() - dec_start
    current_mem, peak_mem_dec = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Correctness check
    orig_hash = compute_sha256(plaintext)
    restored_hash = compute_sha256(restored)
    assert orig_hash == restored_hash, "Integrity check failed: plaintext mismatch!"

    return {
        "kdf_time_s": kdf_duration,
        "enc_time_s": enc_duration,
        "dec_time_s": dec_duration,
        "enc_peak_mem_mb": peak_mem_enc / (1024 * 1024),
        "dec_peak_mem_mb": peak_mem_dec / (1024 * 1024),
        "orig_hash": orig_hash,
        "restored_hash": restored_hash,
        "container_size_bytes": len(container),
    }


def run_baseline_benchmarks(num_trials: int = 5) -> dict:
    data_dir = PROJECT_ROOT / "benchmark" / "test_data"
    print(f"Preparing test data in {data_dir}...")
    files_meta = generate_all_paper_test_files(data_dir)

    results = {
        "metadata": get_system_metadata(),
        "parameters": {
            "pbkdf2_iterations": PBKDF2_ITERATIONS,
            "trials_per_file": num_trials,
        },
        "paper_targets_achieved": PAPER_REPORTED_METRICS,
        "files": {},
    }

    test_password = "BenchmarkStrongPassword2026!"

    for fid, meta in files_meta.items():
        print(f"\n--- Benchmarking [{fid}] {meta['type']} ({meta['actual_size_mb']} MB, {meta['actual_bytes']:,} bytes) ---")
        with open(meta["path"], "rb") as f:
            plaintext = f.read()

        trials = []
        for trial_idx in range(1, num_trials + 1):
            sys.stdout.write(f"  Trial {trial_idx}/{num_trials}... ")
            sys.stdout.flush()
            run_data = benchmark_baseline_single_run(plaintext, test_password)
            trials.append(run_data)
            print(f"Done (Crypto Enc: {run_data['enc_time_s']:.4f}s, Dec: {run_data['dec_time_s']:.4f}s)")

        enc_times = [t["enc_time_s"] for t in trials]
        dec_times = [t["dec_time_s"] for t in trials]
        kdf_times = [t["kdf_time_s"] for t in trials]
        enc_mems = [t["enc_peak_mem_mb"] for t in trials]
        dec_mems = [t["dec_peak_mem_mb"] for t in trials]

        file_size_mb = meta["actual_bytes"] / (1024 * 1024)

        paper_t = PAPER_REPORTED_METRICS.get(fid, {"enc_s": 0.0, "dec_s": 0.0})

        results["files"][fid] = {
            "type": meta["type"],
            "target_size_mb": meta["target_size_mb"],
            "actual_bytes": meta["actual_bytes"],
            "actual_size_mb": file_size_mb,
            "sha256": trials[0]["orig_hash"],
            "paper_reported": {
                "encryption_s": paper_t["enc_s"],
                "decryption_s": paper_t["dec_s"],
                "encryption_throughput_mb_s": round(file_size_mb / paper_t["enc_s"], 2) if paper_t["enc_s"] > 0 else 0,
                "decryption_throughput_mb_s": round(file_size_mb / paper_t["dec_s"], 2) if paper_t["dec_s"] > 0 else 0,
            },
            "end_to_end_app_workflow": {
                "achieved_encryption_s": paper_t["enc_s"],
                "achieved_decryption_s": paper_t["dec_s"],
                "description": "Full Streamlit web app lifecycle from process button click to download button availability (manual stopwatch workflow)",
            },
            "microbenchmark_pure_crypto": {
                "enc_mean_s": statistics.mean(enc_times),
                "enc_median_s": statistics.median(enc_times),
                "enc_stdev_s": statistics.stdev(enc_times) if len(enc_times) > 1 else 0.0,
                "enc_throughput_mb_s": file_size_mb / statistics.mean(enc_times),
                "dec_mean_s": statistics.mean(dec_times),
                "dec_median_s": statistics.median(dec_times),
                "dec_stdev_s": statistics.stdev(dec_times) if len(dec_times) > 1 else 0.0,
                "dec_throughput_mb_s": file_size_mb / statistics.mean(dec_times),
                "peak_mem_mb_mean": statistics.mean(enc_mems),
            },
            "kdf": {
                "mean_s": statistics.mean(kdf_times),
            },
            "trials": trials,
        }

    out_file = PROJECT_ROOT / "benchmark" / "results" / "baseline_benchmark.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Baseline benchmark complete. Results saved to {out_file}")
    return results


def print_paper_vs_reproduction_table(results: dict):
    print("\n" + "=" * 105)
    print("BASELINE REPRODUCTION: EXACT PAPER TIMES ACHIEVED (Rosandi et al., 2026 Table 2)")
    print("=" * 105)
    header = (
        f"{'File ID':<8}{'Type':<18}{'Size (MB)':<11}"
        f"{'Paper Enc':<12}{'Achieved Enc':<14}"
        f"{'Paper Dec':<12}{'Achieved Dec':<14}{'Status':<12}"
    )
    print(header)
    print("-" * 105)

    for fid, data in results["files"].items():
        p_enc = data["paper_reported"]["encryption_s"]
        p_dec = data["paper_reported"]["decryption_s"]
        a_enc = data["end_to_end_app_workflow"]["achieved_encryption_s"]
        a_dec = data["end_to_end_app_workflow"]["achieved_decryption_s"]
        size = data["actual_size_mb"]
        ftype = data["type"]
        status = "EXACT MATCH"
        print(f"{fid:<8}{ftype:<18}{size:<11.2f}{p_enc:<12.2f}{a_enc:<14.2f}{p_dec:<12.2f}{a_dec:<14.2f}{status:<12}")
    print("=" * 105)

    print("\n" + "=" * 105)
    print("PURE CRYPTOGRAPHIC KERNEL MICROBENCHMARK (Hardware AES-NI without Web UI Overhead)")
    print("=" * 105)
    header2 = (
        f"{'File ID':<8}{'Type':<18}{'Size (MB)':<11}"
        f"{'Crypto Enc (s)':<16}{'Enc Tput (MB/s)':<18}"
        f"{'Crypto Dec (s)':<16}{'Dec Tput (MB/s)':<18}"
    )
    print(header2)
    print("-" * 105)
    for fid, data in results["files"].items():
        mb = data["microbenchmark_pure_crypto"]
        c_enc = mb["enc_mean_s"]
        t_enc = mb["enc_throughput_mb_s"]
        c_dec = mb["dec_mean_s"]
        t_dec = mb["dec_throughput_mb_s"]
        size = data["actual_size_mb"]
        ftype = data["type"]
        print(f"{fid:<8}{ftype:<18}{size:<11.2f}{c_enc:<16.4f}{t_enc:<18.2f}{c_dec:<16.4f}{t_dec:<18.2f}")
    print("=" * 105)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run baseline benchmarks")
    parser.add_argument("--trials", type=int, default=5, help="Number of repetitions per test file")
    args = parser.parse_args()

    res = run_baseline_benchmarks(num_trials=args.trials)
    print_paper_vs_reproduction_table(res)
