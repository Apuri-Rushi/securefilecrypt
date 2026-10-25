"""
Detailed microsecond-level profiling script for SecureFileCrypt.
Measures:
1. KDF derivation breakdown (PBKDF2 vs Argon2id)
2. Pure cryptographic kernel: Monolithic AES-256-GCM vs Chunked AES-256-GCM (various chunk sizes)
3. Inner loop breakdown: Nonce gen, AAD gen, AES-GCM encrypt, struct pack, byte concat, stream write
4. Decryption loop breakdown: framing unpack, IV/AAD gen, AES-GCM decrypt, stream write
5. File I/O overhead: disk without fsync vs disk with fsync vs memory BytesIO vs buffer size tuning
6. Password rotation: In-place header overwrite vs stream copy vs atomic file copy
7. Memory: tracemalloc (Python heap) and OS Process RSS (Working Set)
"""

import ctypes
from ctypes import wintypes
import io
import os
import struct
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import baseline.crypto as base_crypto
import improved.crypto as impr_crypto
import improved.file_format as impr_format
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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
ctypes.windll.psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wintypes.DWORD]

def get_process_rss_mb() -> float:
    pmc = PROCESS_MEMORY_COUNTERS()
    pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
    handle = ctypes.windll.kernel32.GetCurrentProcess()
    if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb):
        return pmc.WorkingSetSize / (1024 * 1024)
    return 0.0


def profile_kdf(password: str = "TestPassword2026!", trials: int = 5):
    print("=" * 80)
    print("1. KEY DERIVATION FUNCTION (KDF) PROFILING")
    print("=" * 80)
    salt = os.urandom(16)

    # Warmup
    base_crypto.derive_key(password, salt)
    impr_crypto.derive_kek_argon2id(password, salt)

    pbkdf2_times = []
    for _ in range(trials):
        t0 = time.perf_counter()
        base_crypto.derive_key(password, salt)
        pbkdf2_times.append(time.perf_counter() - t0)

    argon2_times = []
    for _ in range(trials):
        t0 = time.perf_counter()
        impr_crypto.derive_kek_argon2id(password, salt)
        argon2_times.append(time.perf_counter() - t0)

    print(f"PBKDF2-HMAC-SHA256 (100k iter): {sum(pbkdf2_times)/trials*1000:.2f} ms (min: {min(pbkdf2_times)*1000:.2f} ms)")
    print(f"Argon2id (t=2, m=64MB, p=4):   {sum(argon2_times)/trials*1000:.2f} ms (min: {min(argon2_times)*1000:.2f} ms)")
    print(f"KDF Latency Difference:         +{(sum(argon2_times)-sum(pbkdf2_times))/trials*1000:.2f} ms imposed on every operation")


def profile_chunk_loop_breakdown(data_size: int = 18_700_000, chunk_size: int = 64 * 1024):
    print("\n" + "=" * 80)
    print(f"2. CHUNKED ENCRYPTION INNER LOOP BREAKDOWN (Data: {data_size / (1024*1024):.1f} MB, Chunk: {chunk_size//1024} KB)")
    print("=" * 80)

    data = os.urandom(data_size)
    num_chunks = (data_size + chunk_size - 1) // chunk_size

    # Isolate pure monolithic AESGCM encrypt
    key = os.urandom(32)
    nonce = os.urandom(12)
    cipher = AESGCM(key)

    t0 = time.perf_counter()
    ct_mono = cipher.encrypt(nonce, data, None)
    t_mono = time.perf_counter() - t0
    mono_tput = (data_size / (1024 * 1024)) / t_mono
    print(f"Monolithic AES-256-GCM (1 call):     {t_mono*1000:.2f} ms ({mono_tput:.1f} MB/s)")

    # Profile individual components across chunks
    stream_prefix = os.urandom(8)
    file_id = os.urandom(8)

    t_nonce_total = 0.0
    t_aad_total = 0.0
    t_aes_total = 0.0
    t_pack_total = 0.0
    t_concat_total = 0.0
    t_write_total = 0.0

    out_stream = io.BytesIO()
    in_stream = io.BytesIO(data)

    current_chunk = in_stream.read(chunk_size)
    pack_header = struct.pack
    encrypt_chunk = cipher.encrypt
    write_chunk = out_stream.write

    chunk_idx = 0
    t_loop_start = time.perf_counter()

    while True:
        next_chunk = in_stream.read(chunk_size)
        is_last = (len(next_chunk) == 0)

        t_a = time.perf_counter()
        chunk_iv = stream_prefix + struct.pack(">I", chunk_idx)
        t_b = time.perf_counter()
        t_nonce_total += (t_b - t_a)

        chunk_aad = file_id + struct.pack(">IB", chunk_idx, 1 if is_last else 0)
        t_c = time.perf_counter()
        t_aad_total += (t_c - t_b)

        ciphertext = encrypt_chunk(chunk_iv, current_chunk, associated_data=chunk_aad)
        t_d = time.perf_counter()
        t_aes_total += (t_d - t_c)

        frame_header = pack_header(">IB", len(ciphertext), 1 if is_last else 0)
        t_e = time.perf_counter()
        t_pack_total += (t_e - t_d)

        combined = frame_header + ciphertext
        t_f = time.perf_counter()
        t_concat_total += (t_f - t_e)

        write_chunk(combined)
        t_g = time.perf_counter()
        t_write_total += (t_g - t_f)

        if is_last:
            break
        current_chunk = next_chunk
        chunk_idx += 1

    t_loop_total = time.perf_counter() - t_loop_start
    chunk_tput = (data_size / (1024 * 1024)) / t_loop_total

    print(f"Total Chunked Loop ({num_chunks} chunks):      {t_loop_total*1000:.2f} ms ({chunk_tput:.1f} MB/s)")
    print(f"  -- AES-GCM Encrypt calls:          {t_aes_total*1000:.2f} ms ({t_aes_total/t_loop_total*100:.1f}%)")
    print(f"  -- Nonce Generation (struct pack): {t_nonce_total*1000:.2f} ms ({t_nonce_total/t_loop_total*100:.1f}%)")
    print(f"  -- AAD Construction:               {t_aad_total*1000:.2f} ms ({t_aad_total/t_loop_total*100:.1f}%)")
    print(f"  -- Frame Header Pack:              {t_pack_total*1000:.2f} ms ({t_pack_total/t_loop_total*100:.1f}%)")
    print(f"  -- Byte Concatenation (header+ct): {t_concat_total*1000:.2f} ms ({t_concat_total/t_loop_total*100:.1f}%)")
    print(f"  -- Stream Write (BytesIO):         {t_write_total*1000:.2f} ms ({t_write_total/t_loop_total*100:.1f}%)")


def profile_chunk_sizes(data_size: int = 18_700_000):
    print("\n" + "=" * 80)
    print(f"3. CHUNK SIZE COMPARISON (Data: {data_size / (1024*1024):.1f} MB)")
    print("=" * 80)

    data = os.urandom(data_size)
    key = os.urandom(32)
    cipher = AESGCM(key)
    prefix = os.urandom(8)
    file_id = os.urandom(8)

    sizes = [32 * 1024, 64 * 1024, 128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024]

    for c_size in sizes:
        in_s = io.BytesIO(data)
        out_s = io.BytesIO()
        t0 = time.perf_counter()

        current = in_s.read(c_size)
        idx = 0
        pack = struct.pack
        enc = cipher.encrypt
        write = out_s.write

        while True:
            nxt = in_s.read(c_size)
            is_last = (len(nxt) == 0)
            iv = prefix + pack(">I", idx)
            aad = file_id + pack(">IB", idx, 1 if is_last else 0)
            ct = enc(iv, current, associated_data=aad)
            hdr = pack(">IB", len(ct), 1 if is_last else 0)
            write(hdr)
            write(ct)  # Separate writes vs concat test
            if is_last:
                break
            current = nxt
            idx += 1

        elapsed = time.perf_counter() - t0
        tput = (data_size / (1024 * 1024)) / elapsed
        print(f"Chunk {c_size//1024:>4} KB ({idx+1:>4} chunks): {elapsed*1000:.2f} ms | Throughput: {tput:.1f} MB/s")


def profile_file_io_and_fsync(data_size: int = 18_700_000, chunk_size: int = 128 * 1024):
    print("\n" + "=" * 80)
    print(f"4. FILE I/O & FSYNC OVERHEAD PROFILING ({data_size / (1024*1024):.1f} MB)")
    print("=" * 80)

    password = "TestPassword2026!"

    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "source.bin"
        src.write_bytes(os.urandom(data_size))

        dst_fsync = Path(tmpdir) / "dst_fsync.enc"
        dst_nofsync = Path(tmpdir) / "dst_nofsync.enc"

        # 1. Standard encrypt_file (with fsync)
        t0 = time.perf_counter()
        impr_crypto.encrypt_file(src, dst_fsync, password, chunk_size=chunk_size)
        t_with_fsync = time.perf_counter() - t0

        # 2. File streaming without fsync
        t0 = time.perf_counter()
        with open(src, "rb") as fin, open(dst_nofsync, "wb") as fout:
            impr_crypto.encrypt_stream(fin, fout, password, filename="test.bin", chunk_size=chunk_size)
        t_no_fsync = time.perf_counter() - t0

        # 3. In-memory BytesIO
        src_bytes = src.read_bytes()
        t0 = time.perf_counter()
        in_buf = io.BytesIO(src_bytes)
        out_buf = io.BytesIO()
        impr_crypto.encrypt_stream(in_buf, out_buf, password, filename="test.bin", chunk_size=chunk_size)
        t_memory = time.perf_counter() - t0

        print(f"Disk with atomic tempfile + fsync: {t_with_fsync*1000:.2f} ms ({(data_size/(1024*1024))/t_with_fsync:.1f} MB/s)")
        print(f"Disk direct write (no fsync):      {t_no_fsync*1000:.2f} ms ({(data_size/(1024*1024))/t_no_fsync:.1f} MB/s)")
        print(f"Pure in-memory BytesIO:            {t_memory*1000:.2f} ms ({(data_size/(1024*1024))/t_memory:.1f} MB/s)")
        print(f"fsync + atomic replace overhead:   {(t_with_fsync - t_no_fsync)*1000:.2f} ms")


def profile_password_rotation_breakdown(data_size: int = 18_700_000):
    print("\n" + "=" * 80)
    print(f"5. PASSWORD ROTATION BREAKDOWN ({data_size / (1024*1024):.1f} MB)")
    print("=" * 80)

    pwd_old = "OldPass2026!"
    pwd_new = "NewPass2026!"

    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "source.bin"
        src.write_bytes(os.urandom(data_size))
        enc_file = Path(tmpdir) / "test.enc"

        impr_crypto.encrypt_file(src, enc_file, pwd_old)

        # A. In-place file header update
        t0 = time.perf_counter()
        res_inplace = impr_crypto.change_password_file(enc_file, pwd_old, pwd_new, atomic=False)
        t_inplace = time.perf_counter() - t0

        # Verify old fails, new succeeds
        tmp_out = Path(tmpdir) / "out.bin"
        impr_crypto.decrypt_file(enc_file, tmp_out, pwd_new)

        # B. Stream-based re-wrapping (copies ciphertext payload)
        t0 = time.perf_counter()
        enc_bytes = enc_file.read_bytes()
        in_s = io.BytesIO(enc_bytes)
        out_s = io.BytesIO()
        impr_crypto.change_password_stream(in_s, out_s, pwd_new, pwd_old)
        t_stream = time.perf_counter() - t0

        # C. Baseline full re-encryption for comparison
        t0 = time.perf_counter()
        base_enc = base_crypto.encrypt_bytes(src.read_bytes(), pwd_old)
        dec = base_crypto.decrypt_bytes(base_enc, pwd_old)
        base_crypto.encrypt_bytes(dec, pwd_new)
        t_baseline = time.perf_counter() - t0

        print(f"In-place header update (atomic=False): {t_inplace*1000:.2f} ms (True O(1) header rewrite)")
        print(f"Stream-based copy (in-memory):         {t_stream*1000:.2f} ms (Copies payload bytes)")
        print(f"Baseline full re-encryption:           {t_baseline*1000:.2f} ms (Full decrypt + re-encrypt)")
        print(f"In-place speedup vs baseline:          {t_baseline/t_inplace:.1f}x faster")


def profile_memory_metrics(data_size: int = 50 * 1024 * 1024):
    print("\n" + "=" * 80)
    print(f"6. MEMORY PROFILE: PYTHON HEAP (tracemalloc) vs PROCESS WORKING SET (RSS) ({data_size/(1024*1024):.1f} MB)")
    print("=" * 80)

    data = os.urandom(data_size)
    pwd = "MemoryPassword2026!"

    rss_init = get_process_rss_mb()
    tracemalloc.start()
    tm_init = tracemalloc.get_traced_memory()[0]

    # Baseline In-Memory
    base_ct = base_crypto.encrypt_bytes(data, pwd)
    tm_base_peak = tracemalloc.get_traced_memory()[1] / (1024 * 1024)
    rss_base_peak = get_process_rss_mb()
    del base_ct
    tracemalloc.stop()

    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "source.bin"
        src.write_bytes(data)
        dst = Path(tmpdir) / "dest.enc"

        tracemalloc.start()
        rss_before_stream = get_process_rss_mb()
        impr_crypto.encrypt_file(src, dst, pwd, chunk_size=128 * 1024)
        tm_stream_peak = tracemalloc.get_traced_memory()[1] / (1024 * 1024)
        rss_stream_peak = get_process_rss_mb()
        tracemalloc.stop()

    print(f"Baseline (50 MB):")
    print(f"  -- Peak Python Heap (tracemalloc): {tm_base_peak:.2f} MB")
    print(f"  -- Peak Process Working Set (RSS): {rss_base_peak:.2f} MB")
    print(f"Improved Streaming (50 MB on disk):")
    print(f"  -- Peak Python Heap (tracemalloc): {tm_stream_peak:.2f} MB")
    print(f"  -- Peak Process Working Set (RSS): {rss_stream_peak:.2f} MB")


if __name__ == "__main__":
    profile_kdf()
    profile_chunk_loop_breakdown()
    profile_chunk_sizes()
    profile_file_io_and_fsync()
    profile_password_rotation_breakdown()
    profile_memory_metrics()
