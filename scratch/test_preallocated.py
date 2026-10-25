import io
import os
import struct
import sys
import time
import tracemalloc
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from improved import file_format as fmt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Compare encrypt_bytes with BytesIO vs preallocated bytearray
data = os.urandom(18_700_000)
chunk_size = 64 * 1024
key = os.urandom(32)
cipher = AESGCM(key)
prefix = os.urandom(8)
file_id = os.urandom(8)

# Method 1: BytesIO with separate writes
def run_bytesio():
    out = io.BytesIO()
    in_s = io.BytesIO(data)
    curr = in_s.read(chunk_size)
    idx = 0
    w = out.write
    pack = struct.pack
    enc = cipher.encrypt
    while True:
        nxt = in_s.read(chunk_size)
        is_last = (len(nxt) == 0)
        iv = prefix + pack(">I", idx)
        aad = file_id + pack(">IB", idx, 1 if is_last else 0)
        ct = enc(iv, curr, associated_data=aad)
        w(pack(">IB", len(ct), 1 if is_last else 0))
        w(ct)
        if is_last:
            break
        curr = nxt
        idx += 1
    return out.getvalue()

# Method 2: Preallocated bytearray with memoryview
def run_preallocated():
    in_s = io.BytesIO(data)
    num_chunks = max(1, (len(data) + chunk_size - 1) // chunk_size)
    total_est = len(data) + num_chunks * (5 + 16)
    out_arr = bytearray(total_est)
    offset = 0
    curr = in_s.read(chunk_size)
    idx = 0
    pack = struct.pack
    enc = cipher.encrypt
    while True:
        nxt = in_s.read(chunk_size)
        is_last = (len(nxt) == 0)
        iv = prefix + pack(">I", idx)
        aad = file_id + pack(">IB", idx, 1 if is_last else 0)
        ct = enc(iv, curr, associated_data=aad)
        hdr = pack(">IB", len(ct), 1 if is_last else 0)
        out_arr[offset:offset+5] = hdr
        offset += 5
        out_arr[offset:offset+len(ct)] = ct
        offset += len(ct)
        if is_last:
            break
        curr = nxt
        idx += 1
    return bytes(out_arr[:offset])

# Warmup
r1 = run_bytesio()
r2 = run_preallocated()
assert r1 == r2, "Mismatch!"

t0 = time.perf_counter()
tracemalloc.start()
for _ in range(3):
    r1 = run_bytesio()
_, m1 = tracemalloc.get_traced_memory()
tracemalloc.stop()
t1 = (time.perf_counter() - t0) / 3

t0 = time.perf_counter()
tracemalloc.start()
for _ in range(3):
    r2 = run_preallocated()
_, m2 = tracemalloc.get_traced_memory()
tracemalloc.stop()
t2 = (time.perf_counter() - t0) / 3

print(f"BytesIO (two writes):     {t1*1000:.2f} ms | Peak RAM: {m1/(1024*1024):.2f} MB")
print(f"Preallocated bytearray:   {t2*1000:.2f} ms | Peak RAM: {m2/(1024*1024):.2f} MB")
