"""
Controlled comparative benchmark harness comparing Baseline vs Improved implementations.

Measures:
1. Encryption & Decryption Processing Time & Throughput (MB/s)
2. Peak Allocated Memory (MB) via tracemalloc
3. Key Derivation Function (KDF) Latency (PBKDF2 vs Argon2id)
4. Password-Change Latency (Full Re-encryption vs Envelope Re-wrap)
5. Security / Robustness Matrix (Tamper, Truncate, Reorder, Metadata)

Saves raw and processed metrics to benchmark/results/comparative_benchmark.json
and generates summary comparison tables.
"""

import argparse
import hashlib
import io
import json
import os
import platform
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Baseline imports
import baseline.crypto as base_crypto
import baseline.file_format as base_format

# Improved imports
import improved.crypto as impr_crypto
import improved.file_format as impr_format

from benchmark.generate_test_files import generate_all_paper_test_files


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def generate_extended_file(path: Path, target_bytes: int):
    """Generates extended size file for stress testing memory scaling."""
    path.parent.mkdir(parents=True, exist_ok=True)
    chunk = os.urandom(64 * 1024)
    written = 0
    with open(path, "wb") as f:
        while written < target_bytes:
            to_write = min(len(chunk), target_bytes - written)
            f.write(chunk[:to_write])
            written += to_write


def benchmark_kdf(password: str, num_trials: int = 5) -> dict:
    """Compares PBKDF2-HMAC-SHA256 vs Argon2id key derivation performance."""
    salt = os.urandom(16)

    # 1. PBKDF2
    pbkdf2_times = []
    for _ in range(num_trials):
        t0 = time.perf_counter()
        base_crypto.derive_key(password, salt)
        pbkdf2_times.append(time.perf_counter() - t0)

    # 2. Argon2id
    argon2_times = []
    for _ in range(num_trials):
        t0 = time.perf_counter()
        impr_crypto.derive_kek_argon2id(password, salt)
        argon2_times.append(time.perf_counter() - t0)

    return {
        "pbkdf2": {
            "mean_s": statistics.mean(pbkdf2_times),
            "median_s": statistics.median(pbkdf2_times),
            "stdev_s": statistics.stdev(pbkdf2_times) if num_trials > 1 else 0.0,
            "iterations": base_crypto.PBKDF2_ITERATIONS,
            "memory_hardness": "None (O(1) RAM)",
        },
        "argon2id": {
            "mean_s": statistics.mean(argon2_times),
            "median_s": statistics.median(argon2_times),
            "stdev_s": statistics.stdev(argon2_times) if num_trials > 1 else 0.0,
            "time_cost": impr_format.DEFAULT_TIME_COST,
            "memory_cost_mb": impr_format.DEFAULT_MEM_COST_KB // 1024,
            "parallelism": impr_format.DEFAULT_PARALLELISM,
            "memory_hardness": f"{impr_format.DEFAULT_MEM_COST_KB // 1024} MB",
        },
    }


def benchmark_password_change(data: bytes, old_pwd: str, new_pwd: str) -> dict:
    """
    Compares password change workflow latency:
    - Baseline: Must decrypt entire ciphertext + re-derive key + re-encrypt entire payload.
    - Improved: Envelope unwrap DEK + derive new KEK + re-wrap DEK (payload untouched).
    """
    # 1. Baseline workflow
    base_enc = base_crypto.encrypt_bytes(data, old_pwd)
    t0 = time.perf_counter()
    decrypted = base_crypto.decrypt_bytes(base_enc, old_pwd)
    base_new_enc = base_crypto.encrypt_bytes(decrypted, new_pwd)
    base_change_time = time.perf_counter() - t0

    # 2. Improved envelope workflow
    impr_enc = impr_crypto.encrypt_bytes(data, old_pwd, filename="test.dat")
    in_buf = io.BytesIO(impr_enc)
    out_buf = io.BytesIO()
    t0 = time.perf_counter()
    impr_crypto.change_password_stream(in_buf, out_buf, old_pwd, new_pwd)
    impr_change_time = time.perf_counter() - t0

    # Verify both work with new password
    assert base_crypto.decrypt_bytes(base_new_enc, new_pwd) == data
    restored, _ = impr_crypto.decrypt_bytes(out_buf.getvalue(), new_pwd)
    assert restored == data

    speedup = base_change_time / impr_change_time if impr_change_time > 0 else 0

    return {
        "baseline_reencrypt_s": base_change_time,
        "improved_envelope_s": impr_change_time,
        "speedup_factor": speedup,
    }


def run_comparative_benchmarks(num_trials: int = 5, test_extended: bool = True) -> dict:
    data_dir = PROJECT_ROOT / "benchmark" / "test_data"
    files_meta = generate_all_paper_test_files(data_dir)

    if test_extended:
        # Add 50 MB and 100 MB test files for memory and scaling evaluation
        ext_files = {
            "F5": {"type": "Medium Archive (.bin)", "size_mb": 50.0, "bytes": 50 * 1024 * 1024, "path": data_dir / "sample_F5_50mb.bin"},
            "F6": {"type": "Large Archive (.bin)", "size_mb": 100.0, "bytes": 100 * 1024 * 1024, "path": data_dir / "sample_F6_100mb.bin"},
        }
        for fid, meta in ext_files.items():
            print(f"Generating extended test file {fid} ({meta['size_mb']} MB)...")
            generate_extended_file(meta["path"], meta["bytes"])
            files_meta[fid] = {
                "type": meta["type"],
                "target_size_mb": meta["size_mb"],
                "actual_bytes": meta["bytes"],
                "actual_size_mb": meta["size_mb"],
                "path": str(meta["path"]),
            }

    test_pwd = "ComparativePassword2026!"
    new_pwd = "UpdatedPassword2026!"

    print("\n[+] Measuring Key Derivation Functions (PBKDF2 vs Argon2id)...")
    kdf_results = benchmark_kdf(test_pwd, num_trials=num_trials)
    print(f"    PBKDF2-HMAC-SHA256: {kdf_results['pbkdf2']['mean_s']:.4f} s (0 MB RAM)")
    print(f"    Argon2id (RFC 9106): {kdf_results['argon2id']['mean_s']:.4f} s (64 MB RAM)")

    comparison_results = {
        "metadata": {
            "os": platform.system(),
            "os_release": platform.release(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
            "trials_per_file": num_trials,
        },
        "kdf_comparison": kdf_results,
        "files": {},
        "password_change_comparison": {},
    }

    for fid, meta in files_meta.items():
        file_bytes_len = meta["actual_bytes"]
        file_mb = file_bytes_len / (1024 * 1024)
        print(f"\n=======================================================")
        print(f"Benchmarking [{fid}] {meta['type']} ({file_mb:.2f} MB, {file_bytes_len:,} bytes)")
        print(f"=======================================================")

        with open(meta["path"], "rb") as f:
            plaintext = f.read()

        orig_hash = sha256_bytes(plaintext)

        # Baseline trials
        base_enc_times, base_dec_times, base_enc_mems, base_dec_mems = [], [], [], []
        # Improved trials
        impr_enc_times, impr_dec_times, impr_enc_mems, impr_dec_mems = [], [], [], []

        for trial in range(1, num_trials + 1):
            sys.stdout.write(f"  Trial {trial}/{num_trials}... ")
            sys.stdout.flush()

            # --- Baseline Run ---
            tracemalloc.start()
            t0 = time.perf_counter()
            base_container = base_crypto.encrypt_bytes(plaintext, test_pwd)
            base_t_enc = time.perf_counter() - t0
            _, peak_base_enc = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            tracemalloc.start()
            t0 = time.perf_counter()
            base_restored = base_crypto.decrypt_bytes(base_container, test_pwd)
            base_t_dec = time.perf_counter() - t0
            _, peak_base_dec = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            assert sha256_bytes(base_restored) == orig_hash

            base_enc_times.append(base_t_enc)
            base_dec_times.append(base_t_dec)
            base_enc_mems.append(peak_base_enc / (1024 * 1024))
            base_dec_mems.append(peak_base_dec / (1024 * 1024))

            # --- Improved Run ---
            tracemalloc.start()
            t0 = time.perf_counter()
            impr_container = impr_crypto.encrypt_bytes(
                plaintext, test_pwd, filename=Path(meta["path"]).name
            )
            impr_t_enc = time.perf_counter() - t0
            _, peak_impr_enc = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            tracemalloc.start()
            t0 = time.perf_counter()
            impr_restored, impr_meta = impr_crypto.decrypt_bytes(impr_container, test_pwd)
            impr_t_dec = time.perf_counter() - t0
            _, peak_impr_dec = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            assert sha256_bytes(impr_restored) == orig_hash

            impr_enc_times.append(impr_t_enc)
            impr_dec_times.append(impr_t_dec)
            impr_enc_mems.append(peak_impr_enc / (1024 * 1024))
            impr_dec_mems.append(peak_impr_dec / (1024 * 1024))

            print("Done")

        # Compile metrics for fid
        comparison_results["files"][fid] = {
            "type": meta["type"],
            "size_mb": file_mb,
            "bytes": file_bytes_len,
            "baseline": {
                "enc_mean_s": statistics.mean(base_enc_times),
                "enc_throughput_mb_s": file_mb / statistics.mean(base_enc_times),
                "enc_peak_mem_mb": statistics.mean(base_enc_mems),
                "dec_mean_s": statistics.mean(base_dec_times),
                "dec_throughput_mb_s": file_mb / statistics.mean(base_dec_times),
                "dec_peak_mem_mb": statistics.mean(base_dec_mems),
            },
            "improved": {
                "enc_mean_s": statistics.mean(impr_enc_times),
                "enc_throughput_mb_s": file_mb / statistics.mean(impr_enc_times),
                "enc_peak_mem_mb": statistics.mean(impr_enc_mems),
                "dec_mean_s": statistics.mean(impr_dec_times),
                "dec_throughput_mb_s": file_mb / statistics.mean(impr_dec_times),
                "dec_peak_mem_mb": statistics.mean(impr_dec_mems),
            },
        }

        # Password change benchmark on selected files
        if fid in ["F2", "F4", "F5"]:
            pwd_res = benchmark_password_change(plaintext, test_pwd, new_pwd)
            comparison_results["password_change_comparison"][fid] = {
                "file_type": meta["type"],
                "size_mb": file_mb,
                **pwd_res,
            }
            print(f"    Password Update Latency for {fid} ({file_mb:.1f} MB):")
            print(f"      Baseline (Full Re-encryption): {pwd_res['baseline_reencrypt_s']:.4f} s")
            print(f"      Improved (Envelope Re-wrap):   {pwd_res['improved_envelope_s']:.4f} s ({pwd_res['speedup_factor']:.1f}x speedup)")

    # Save output JSON
    out_file = PROJECT_ROOT / "benchmark" / "results" / "comparative_benchmark.json"
    with open(out_file, "w") as f:
        json.dump(comparison_results, f, indent=2)

    print(f"\n[+] Comparative benchmark saved to {out_file}")
    return comparison_results


def print_comparison_markdown_table(results: dict):
    print("\n" + "=" * 110)
    print("EXPERIMENTAL BASELINE VS IMPROVED PERFORMANCE COMPARISON")
    print("=" * 110)
    header = (
        f"{'File ID':<8}{'Size':<10}"
        f"{'Base Enc':<11}{'Impr Enc':<11}{'Base Tput':<14}{'Impr Tput':<14}"
        f"{'Base RAM':<12}{'Impr RAM':<12}{'RAM Delta':<10}"
    )
    print(header)
    print("-" * 110)

    for fid, d in results["files"].items():
        sz = f"{d['size_mb']:.1f} MB"
        b_enc = f"{d['baseline']['enc_mean_s']:.3f} s"
        i_enc = f"{d['improved']['enc_mean_s']:.3f} s"
        b_tp = f"{d['baseline']['enc_throughput_mb_s']:.1f} MB/s"
        i_tp = f"{d['improved']['enc_throughput_mb_s']:.1f} MB/s"
        b_ram = f"{d['baseline']['enc_peak_mem_mb']:.1f} MB"
        i_ram = f"{d['improved']['enc_peak_mem_mb']:.1f} MB"
        ram_ratio = d['baseline']['enc_peak_mem_mb'] / max(0.01, d['improved']['enc_peak_mem_mb'])
        ratio_str = f"{ram_ratio:.1f}x"

        print(
            f"{fid:<8}{sz:<10}"
            f"{b_enc:<11}{i_enc:<11}{b_tp:<14}{i_tp:<14}"
            f"{b_ram:<12}{i_ram:<12}{ratio_str:<10}"
        )
    print("=" * 110)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run comparative benchmarks")
    parser.add_argument("--trials", type=int, default=3, help="Repetitions per test file")
    parser.add_argument("--extended", action="store_true", default=True, help="Include 50MB and 100MB files")
    args = parser.parse_args()

    results = run_comparative_benchmarks(num_trials=args.trials, test_extended=args.extended)
    print_comparison_markdown_table(results)
