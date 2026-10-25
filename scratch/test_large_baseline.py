import time
import tracemalloc
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import baseline.crypto as base_crypto

for size_mb in [300, 400]:
    print(f"\nTesting {size_mb} MiB...")
    try:
        t0 = time.perf_counter()
        data = b"Y" * (size_mb * 1024 * 1024)
        print(f"Allocated {size_mb} MiB in {time.perf_counter() - t0:.2f} s")

        tracemalloc.start()
        t0 = time.perf_counter()
        enc = base_crypto.encrypt_bytes(data, "TestPass123!")
        enc_time = time.perf_counter() - t0
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        print(f"Baseline {size_mb} MiB Enc: {enc_time:.2f} s ({size_mb/enc_time:.1f} MiB/s), Peak Heap: {peak/(1024*1024):.1f} MiB")

        tracemalloc.start()
        t0 = time.perf_counter()
        dec = base_crypto.decrypt_bytes(enc, "TestPass123!")
        dec_time = time.perf_counter() - t0
        _, peak_dec = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        print(f"Baseline {size_mb} MiB Dec: {dec_time:.2f} s ({size_mb/dec_time:.1f} MiB/s), Peak Heap Dec: {peak_dec/(1024*1024):.1f} MiB")
        assert dec == data
        print(f"Verified {size_mb} MiB!")
        del data, enc, dec
    except MemoryError as e:
        print(f"MemoryError on {size_mb} MiB: {e}")
