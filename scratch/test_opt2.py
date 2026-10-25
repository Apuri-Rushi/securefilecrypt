import io
import os
import time
import tracemalloc

# Compare BytesIO append vs preallocated bytearray vs two-writes

data = os.urandom(18_700_000)
chunk_size = 64 * 1024
num_chunks = (len(data) + chunk_size - 1) // chunk_size

# Test A: Original BytesIO with concat write
t0 = time.perf_counter()
tracemalloc.start()
buf_a = io.BytesIO()
write_a = buf_a.write
for i in range(num_chunks):
    chunk = data[i*chunk_size:(i+1)*chunk_size]
    hdr = b"\x00\x00\x00\x10\x00"
    write_a(hdr + chunk)
res_a = buf_a.getvalue()
_, peak_a = tracemalloc.get_traced_memory()
tracemalloc.stop()
t_a = time.perf_counter() - t0

# Test B: BytesIO with two writes (no concat)
t0 = time.perf_counter()
tracemalloc.start()
buf_b = io.BytesIO()
write_b = buf_b.write
for i in range(num_chunks):
    chunk = data[i*chunk_size:(i+1)*chunk_size]
    hdr = b"\x00\x00\x00\x10\x00"
    write_b(hdr)
    write_b(chunk)
res_b = buf_b.getvalue()
_, peak_b = tracemalloc.get_traced_memory()
tracemalloc.stop()
t_b = time.perf_counter() - t0

assert res_a == res_b

print(f"Test A (concat write):   {t_a*1000:.2f} ms | Peak RAM: {peak_a/(1024*1024):.2f} MB")
print(f"Test B (separate write): {t_b*1000:.2f} ms | Peak RAM: {peak_b/(1024*1024):.2f} MB")
