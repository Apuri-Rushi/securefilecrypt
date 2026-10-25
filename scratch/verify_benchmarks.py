import json
from pathlib import Path

results_file = Path("scratch/chunk_64_vs_128_results.json")
with open(results_file, "r") as f:
    data = json.load(f)

print("=== VERIFICATION OF 64 KB vs 128 KB DATA ===")
for fid, d in data.items():
    sz = d["size_mb"]
    c64 = d["64KB"]
    c128 = d["128KB"]
    enc_spd = c128["enc_throughput_mb_s"] / c64["enc_throughput_mb_s"]
    dec_spd = c128["dec_throughput_mb_s"] / c64["dec_throughput_mb_s"]
    print(f"[{fid}] Size: {sz:.2f} MB ({d['type']})")
    print(f"  64 KB : Enc: {c64['enc_mean_s']:.4f}s (med: {c64['enc_median_s']:.4f}s, std: {c64['enc_stdev_s']:.4f}s) -> {c64['enc_throughput_mb_s']:.2f} MB/s")
    print(f"          Dec: {c64['dec_mean_s']:.4f}s (med: {c64['dec_median_s']:.4f}s, std: {c64['dec_stdev_s']:.4f}s) -> {c64['dec_throughput_mb_s']:.2f} MB/s")
    print(f"          Heap: {c64['peak_python_heap_mb']:.3f} MB | RSS: {c64['process_rss_mb']:.2f} MB")
    print(f"  128 KB: Enc: {c128['enc_mean_s']:.4f}s (med: {c128['enc_median_s']:.4f}s, std: {c128['enc_stdev_s']:.4f}s) -> {c128['enc_throughput_mb_s']:.2f} MB/s")
    print(f"          Dec: {c128['dec_mean_s']:.4f}s (med: {c128['dec_median_s']:.4f}s, std: {c128['dec_stdev_s']:.4f}s) -> {c128['dec_throughput_mb_s']:.2f} MB/s")
    print(f"          Heap: {c128['peak_python_heap_mb']:.3f} MB | RSS: {c128['process_rss_mb']:.2f} MB")
    print(f"  Speedup: Enc: {enc_spd:.2f}x | Dec: {dec_spd:.2f}x")
    print()
