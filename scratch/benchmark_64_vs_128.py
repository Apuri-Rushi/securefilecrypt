"""
Controlled comparative benchmark of 64 KB vs 128 KB chunk sizes across files F1-F6.
Measures:
- Encryption and Decryption Latency (mean, median, stdev)
- Encryption and Decryption Throughput (MB/s)
- Peak Python Heap Memory (tracemalloc)
- Process Working Set (RSS via Win32 API)
"""

import ctypes
from ctypes import wintypes
import json
import os
import statistics
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import improved.crypto as impr_crypto
from benchmark.generate_test_files import generate_all_paper_test_files


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


ctypes.windll.kernel32.GetCurrentProcess.restype = ctypes.c_void_p
ctypes.windll.psapi.GetProcessMemoryInfo.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
    wintypes.DWORD,
]


def get_process_rss_mb() -> float:
    pmc = PROCESS_MEMORY_COUNTERS()
    pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
    handle = ctypes.windll.kernel32.GetCurrentProcess()
    if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb):
        return pmc.WorkingSetSize / (1024 * 1024)
    return 0.0


def run_64_vs_128_comparison(trials: int = 3):
    data_dir = PROJECT_ROOT / "benchmark" / "test_data"
    files_meta = generate_all_paper_test_files(data_dir)

    ext_files = {
        "F5": {"type": "Medium Archive (.bin)", "size_mb": 50.0, "bytes": 50 * 1024 * 1024, "path": data_dir / "sample_F5_50mb.bin"},
        "F6": {"type": "Large Archive (.bin)", "size_mb": 100.0, "bytes": 100 * 1024 * 1024, "path": data_dir / "sample_F6_100mb.bin"},
    }
    for fid, meta in ext_files.items():
        if meta["path"].exists():
            files_meta[fid] = {
                "type": meta["type"],
                "target_size_mb": meta["size_mb"],
                "actual_bytes": meta["bytes"],
                "actual_size_mb": meta["size_mb"],
                "path": str(meta["path"]),
            }

    password = "ComparisonPassword2026!"
    results = {}

    print("=" * 110)
    print("CONTROLLED CHUNK SIZE EVALUATION: 64 KB vs 128 KB (STREAMING DISK I/O)")
    print("=" * 110)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_p = Path(tmpdir)

        for fid, meta in files_meta.items():
            f_path = Path(meta["path"])
            size_mb = meta["actual_bytes"] / (1024 * 1024)
            results[fid] = {
                "type": meta["type"],
                "size_mb": size_mb,
                "bytes": meta["actual_bytes"],
            }

            print(f"\nEvaluating [{fid}] {meta['type']} ({size_mb:.2f} MB)...")

            for chunk_kb, chunk_size in [("64KB", 64 * 1024), ("128KB", 128 * 1024)]:
                enc_p = tmp_p / f"{fid}_{chunk_kb}.enc"
                dec_p = tmp_p / f"{fid}_{chunk_kb}.dec"

                # Warmup run
                impr_crypto.encrypt_file(f_path, enc_p, password, chunk_size=chunk_size)
                impr_crypto.decrypt_file(enc_p, dec_p, password)
                if enc_p.exists():
                    enc_p.unlink()
                if dec_p.exists():
                    dec_p.unlink()

                enc_times = []
                dec_times = []
                enc_heaps = []
                enc_rsss = []

                for trial in range(trials):
                    tracemalloc.start()
                    t0 = time.perf_counter()
                    impr_crypto.encrypt_file(f_path, enc_p, password, chunk_size=chunk_size)
                    t_enc = time.perf_counter() - t0
                    _, peak_heap = tracemalloc.get_traced_memory()
                    tracemalloc.stop()
                    rss_enc = get_process_rss_mb()

                    t0 = time.perf_counter()
                    impr_crypto.decrypt_file(enc_p, dec_p, password)
                    t_dec = time.perf_counter() - t0

                    enc_times.append(t_enc)
                    dec_times.append(t_dec)
                    enc_heaps.append(peak_heap / (1024 * 1024))
                    enc_rsss.append(rss_enc)

                    if enc_p.exists():
                        enc_p.unlink()
                    if dec_p.exists():
                        dec_p.unlink()

                mean_enc = statistics.mean(enc_times)
                mean_dec = statistics.mean(dec_times)
                mean_heap = statistics.mean(enc_heaps)
                mean_rss = statistics.mean(enc_rsss)

                results[fid][chunk_kb] = {
                    "enc_mean_s": mean_enc,
                    "enc_median_s": statistics.median(enc_times),
                    "enc_stdev_s": statistics.stdev(enc_times) if trials > 1 else 0.0,
                    "enc_throughput_mb_s": size_mb / mean_enc if mean_enc > 0 else 0,
                    "dec_mean_s": mean_dec,
                    "dec_median_s": statistics.median(dec_times),
                    "dec_stdev_s": statistics.stdev(dec_times) if trials > 1 else 0.0,
                    "dec_throughput_mb_s": size_mb / mean_dec if mean_dec > 0 else 0,
                    "peak_python_heap_mb": mean_heap,
                    "process_rss_mb": mean_rss,
                }

                print(
                    f"  {chunk_kb}: Enc: {mean_enc*1000:6.1f} ms ({size_mb/mean_enc:5.1f} MB/s) | "
                    f"Dec: {mean_dec*1000:6.1f} ms ({size_mb/mean_dec:5.1f} MB/s) | "
                    f"Heap: {mean_heap:4.2f} MB | RSS: {mean_rss:5.1f} MB"
                )

    # Save results to scratch
    out_json = PROJECT_ROOT / "scratch" / "chunk_64_vs_128_results.json"
    with open(out_json, "w") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 110)
    print("SUMMARY COMPARISON TABLE: 64 KB vs 128 KB")
    print("=" * 110)
    header = f"{'File ID':<8}{'Size':<10}{'64K Enc':<12}{'128K Enc':<12}{'64K Tput':<14}{'128K Tput':<14}{'Speedup':<10}{'64K Heap':<12}{'128K Heap':<12}"
    print(header)
    print("-" * 110)
    for fid, d in results.items():
        sz = f"{d['size_mb']:.1f} MB"
        e64 = f"{d['64KB']['enc_mean_s']:.3f} s"
        e128 = f"{d['128KB']['enc_mean_s']:.3f} s"
        t64 = f"{d['64KB']['enc_throughput_mb_s']:.1f} MB/s"
        t128 = f"{d['128KB']['enc_throughput_mb_s']:.1f} MB/s"
        spd = f"{d['128KB']['enc_throughput_mb_s']/max(0.1, d['64KB']['enc_throughput_mb_s']):.2f}x"
        h64 = f"{d['64KB']['peak_python_heap_mb']:.2f} MB"
        h128 = f"{d['128KB']['peak_python_heap_mb']:.2f} MB"
        print(f"{fid:<8}{sz:<10}{e64:<12}{e128:<12}{t64:<14}{t128:<14}{spd:<10}{h64:<12}{h128:<12}")
    print("=" * 110)

    return results


if __name__ == "__main__":
    run_64_vs_128_comparison()
