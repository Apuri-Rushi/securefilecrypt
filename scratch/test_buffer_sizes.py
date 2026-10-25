import os
import tempfile
import time
from pathlib import Path

# Benchmark different file buffering sizes for streaming encryption on Windows NTFS

data = os.urandom(18_700_000)
buffer_sizes = [
    ("Default (8 KB)", -1),
    ("32 KB", 32 * 1024),
    ("64 KB", 64 * 1024),
    ("128 KB", 128 * 1024),
    ("256 KB", 256 * 1024),
    ("512 KB", 512 * 1024),
    ("1024 KB", 1024 * 1024),
]

trials = 5

with tempfile.TemporaryDirectory() as tmpdir:
    src = Path(tmpdir) / "source.bin"
    src.write_bytes(data)

    for name, buf_sz in buffer_sizes:
        times = []
        for _ in range(trials):
            dst = Path(tmpdir) / "dest.bin"
            t0 = time.perf_counter()
            with open(src, "rb", buffering=buf_sz) as fin, open(dst, "wb", buffering=buf_sz) as fout:
                while chunk := fin.read(64 * 1024):
                    fout.write(chunk)
                fout.flush()
                os.fsync(fout.fileno())
            times.append(time.perf_counter() - t0)
            if dst.exists():
                dst.unlink()

        avg_t = sum(times) / trials
        mb_s = (len(data) / (1024 * 1024)) / avg_t
        print(f"Buffering: {name:<16} | Mean: {avg_t*1000:6.2f} ms | Throughput: {mb_s:6.1f} MB/s")
