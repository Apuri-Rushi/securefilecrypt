import json
import statistics
from pathlib import Path

json_path = Path("benchmark/results/large_file_scalability.json")
with open(json_path, "r", encoding="utf-8") as f:
    data = json.load(f)

print("=" * 80)
print("INDEPENDENT RECALCULATION OF LARGE FILE SCALABILITY BENCHMARK METRICS")
print("=" * 80)

# KDF
kdf = data["kdf_comparison"]
pb_trials = kdf["pbkdf2"]["raw_trials"]
ar_trials = kdf["argon2id"]["raw_trials"]

print("\n--- 1. Key Derivation Function ---")
print(f"PBKDF2 raw: {pb_trials}")
print(f"PBKDF2 mean: {statistics.mean(pb_trials):.6f} s | median: {statistics.median(pb_trials):.6f} s | stdev: {statistics.stdev(pb_trials):.6f} s")
print(f"Argon2id raw: {ar_trials}")
print(f"Argon2id mean: {statistics.mean(ar_trials):.6f} s | median: {statistics.median(ar_trials):.6f} s | stdev: {statistics.stdev(ar_trials):.6f} s")
print(f"Argon2id / PBKDF2 median ratio: {statistics.median(ar_trials) / statistics.median(pb_trials):.2f}x")

print("\n--- 2. File Workloads ---")
for fid, f in data["files"].items():
    sz_bytes = f["size_bytes"]
    sz_mib = sz_bytes / (1024 * 1024)
    print(f"\nWorkload {fid}: {f['label']} ({sz_bytes:,} bytes, {sz_mib:.1f} MiB)")
    print(f"SHA-256: {f['sha256']}")
    
    b = f["baseline"]
    s = f["improved_streaming"]
    
    # Baseline Encryption
    b_enc_raw = b["enc_raw_times"]
    b_enc_mean = statistics.mean(b_enc_raw)
    b_enc_median = statistics.median(b_enc_raw)
    b_enc_stdev = statistics.stdev(b_enc_raw)
    b_enc_tputs = [sz_mib / t for t in b_enc_raw]
    b_enc_tput_mean = statistics.mean(b_enc_tputs)
    b_enc_tput_median = statistics.median(b_enc_tputs)
    b_enc_tput_from_median_time = sz_mib / b_enc_median
    
    # Baseline Decryption
    b_dec_raw = b["dec_raw_times"]
    b_dec_mean = statistics.mean(b_dec_raw)
    b_dec_median = statistics.median(b_dec_raw)
    b_dec_stdev = statistics.stdev(b_dec_raw)
    b_dec_tputs = [sz_mib / t for t in b_dec_raw]
    b_dec_tput_mean = statistics.mean(b_dec_tputs)
    b_dec_tput_median = statistics.median(b_dec_tputs)
    b_dec_tput_from_median_time = sz_mib / b_dec_median

    # Stream Encryption
    s_enc_raw = s["enc_raw_times"]
    s_enc_mean = statistics.mean(s_enc_raw)
    s_enc_median = statistics.median(s_enc_raw)
    s_enc_stdev = statistics.stdev(s_enc_raw)
    s_enc_tputs = [sz_mib / t for t in s_enc_raw]
    s_enc_tput_mean = statistics.mean(s_enc_tputs)
    s_enc_tput_median = statistics.median(s_enc_tputs)
    s_enc_tput_from_median_time = sz_mib / s_enc_median

    # Stream Decryption
    s_dec_raw = s["dec_raw_times"]
    s_dec_mean = statistics.mean(s_dec_raw)
    s_dec_median = statistics.median(s_dec_raw)
    s_dec_stdev = statistics.stdev(s_dec_raw)
    s_dec_tputs = [sz_mib / t for t in s_dec_raw]
    s_dec_tput_mean = statistics.mean(s_dec_tputs)
    s_dec_tput_median = statistics.median(s_dec_tputs)
    s_dec_tput_from_median_time = sz_mib / s_dec_median

    print(f"  Baseline Enc Time: mean={b_enc_mean:.4f}s, med={b_enc_median:.4f}s, std={b_enc_stdev:.4f}s")
    print(f"    Tput from raw median: {b_enc_tput_median:.1f} MiB/s | Tput from median time: {b_enc_tput_from_median_time:.1f} MiB/s")
    print(f"  Stream Enc Time:   mean={s_enc_mean:.4f}s, med={s_enc_median:.4f}s, std={s_enc_stdev:.4f}s")
    print(f"    Tput from raw median: {s_enc_tput_median:.1f} MiB/s | Tput from median time: {s_enc_tput_from_median_time:.1f} MiB/s")
    print(f"  Enc Latency Ratio (Stream / Base median): {s_enc_median / b_enc_median:.2f}x")

    print(f"  Baseline Dec Time: mean={b_dec_mean:.4f}s, med={b_dec_median:.4f}s, std={b_dec_stdev:.4f}s")
    print(f"    Tput from raw median: {b_dec_tput_median:.1f} MiB/s | Tput from median time: {b_dec_tput_from_median_time:.1f} MiB/s")
    print(f"  Stream Dec Time:   mean={s_dec_mean:.4f}s, med={s_dec_median:.4f}s, std={s_dec_stdev:.4f}s")
    print(f"    Tput from raw median: {s_dec_tput_median:.1f} MiB/s | Tput from median time: {s_dec_tput_from_median_time:.1f} MiB/s")
    print(f"  Dec Latency Ratio (Stream / Base median): {s_dec_median / b_dec_median:.2f}x")

    # Memory
    b_heap = b["peak_python_heap_mib"]
    s_heap = s["peak_python_heap_mib"]
    heap_ratio = b_heap / s_heap
    b_rss = b["peak_process_rss_mib"]
    s_rss = s["peak_process_rss_mib"]
    print(f"  Memory Heap: Baseline={b_heap:.2f} MiB, Stream={s_heap:.4f} MiB, Reduction={heap_ratio:.1f}x")
    print(f"  Sampled RSS: Baseline={b_rss:.1f} MiB, Stream={s_rss:.1f} MiB")
    print(f"  Integrity Verified: Baseline={b['integrity_verified']}, Stream={s['integrity_verified']}")

print("\n--- 3. Password Rotation Workflows ---")
for fid, r in data["password_rotation"].items():
    b_rot = r["baseline_reencrypt_s"]
    i_rot = r["improved_inplace_header_s"]
    a_rot = r["improved_atomic_file_s"]
    speedup = b_rot / i_rot
    print(f"{fid} ({r['size_mib']} MiB):")
    print(f"  Baseline Re-encrypt:      {b_rot:.4f} s")
    print(f"  Improved In-Place Header: {i_rot:.4f} s (Speedup: {speedup:.2f}x)")
    print(f"  Improved Atomic Replace:  {a_rot:.4f} s (Ratio vs Base: {b_rot / a_rot:.2f}x)")
