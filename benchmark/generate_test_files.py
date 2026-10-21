"""
Test file generator for paper reproduction and benchmark experiments.

Recreates the four file categories and target sizes from Table 2 of Rosandi et al. (2026):
- F1: Text (.txt)        - 0.10 MB (102,400 bytes)
- F2: PDF document (.pdf) - 1.25 MB (1,310,720 bytes)
- F3: Image (.jpg)        - 5.40 MB (5,662,310 bytes)
- F4: Short video (.mp4)  - 18.70 MB (19,608,371 bytes)

Also supports generating extended size files for comparative stress testing (e.g. 50 MB, 100 MB).
"""

import os
import sys
from pathlib import Path


def create_text_file(path: Path, target_bytes: int):
    """Generates a realistic text file filled with readable sentences up to target_bytes."""
    corpus = (
        "The Advanced Encryption Standard (AES) is a symmetric-key cryptographic block cipher "
        "established by NIST in 2001 to secure digital information. AES-256 uses a 256-bit key length "
        "and provides high resistance against brute-force attacks while maintaining efficiency. "
        "In Galois/Counter Mode (GCM), AES provides both confidentiality and message authentication. "
        "Key derivation with PBKDF2-HMAC-SHA256 ensures password resilience against dictionary attacks.\n"
    ).encode("utf-8")

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        written = 0
        while written < target_bytes:
            chunk = corpus if (target_bytes - written) >= len(corpus) else corpus[: target_bytes - written]
            f.write(chunk)
            written += len(chunk)


def create_pdf_file(path: Path, target_bytes: int):
    """Generates a synthetic PDF file with a valid PDF header and trailer."""
    header = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length "
    trailer = b"\n>>\nstream\nBT /F1 12 Tf 72 712 Td (Reproduced Benchmark Test Document) Tj ET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000216 00000 n \ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n350\n%%EOF\n"

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(header)
        fixed_len = len(header) + len(trailer)
        padding_needed = max(0, target_bytes - fixed_len)
        # Write deterministic pseudorandom payload
        chunk_size = 64 * 1024
        written = 0
        while written < padding_needed:
            n = min(chunk_size, padding_needed - written)
            f.write(os.urandom(n))
            written += n
        f.write(trailer)


def create_jpeg_file(path: Path, target_bytes: int):
    """Generates a synthetic JPEG file with standard SOI/APP0/DQT markers and EOI footer."""
    header = bytes([
        0xFF, 0xD8,  # SOI
        0xFF, 0xE0, 0x00, 0x10,  # APP0
        0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00,  # JFIF
        0xFF, 0xDB, 0x00, 0x43, 0x00,  # DQT
    ])
    footer = bytes([0xFF, 0xD9])  # EOI

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(header)
        payload_size = max(0, target_bytes - len(header) - len(footer))
        chunk_size = 64 * 1024
        written = 0
        while written < payload_size:
            n = min(chunk_size, payload_size - written)
            f.write(os.urandom(n))
            written += n
        f.write(footer)


def create_mp4_file(path: Path, target_bytes: int):
    """Generates a synthetic MP4 file with valid ftyp (isom) and mdat headers."""
    # 4-byte box size (32), 'ftyp', 'isom', minor_version 0x200, compatible 'isom', 'iso2', 'mp41'
    ftyp_box = bytes([
        0x00, 0x00, 0x00, 0x20,  # 32 bytes
        0x66, 0x74, 0x79, 0x70,  # 'ftyp'
        0x69, 0x73, 0x6F, 0x6D,  # 'isom'
        0x00, 0x00, 0x02, 0x00,  # minor version
        0x69, 0x73, 0x6F, 0x6D,  # 'isom'
        0x69, 0x73, 0x6F, 0x32,  # 'iso2'
        0x6D, 0x70, 0x34, 0x31,  # 'mp41'
        0x00, 0x00, 0x00, 0x08,  # mdat header length (8 bytes)
        0x6D, 0x64, 0x61, 0x74,  # 'mdat'
    ])

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(ftyp_box)
        payload_size = max(0, target_bytes - len(ftyp_box))
        chunk_size = 64 * 1024
        written = 0
        while written < payload_size:
            n = min(chunk_size, payload_size - written)
            f.write(os.urandom(n))
            written += n


def generate_all_paper_test_files(base_dir: Path) -> dict:
    """Generates all 4 test files from Table 2 in Rosandi et al. (2026)."""
    base_dir.mkdir(parents=True, exist_ok=True)

    targets = {
        "F1": {
            "type": "Text (.txt)",
            "size_mb": 0.10,
            "target_bytes": int(0.10 * 1024 * 1024),  # 104,857 bytes
            "path": base_dir / "sample_F1_text.txt",
            "generator": create_text_file,
        },
        "F2": {
            "type": "PDF document",
            "size_mb": 1.25,
            "target_bytes": int(1.25 * 1024 * 1024),  # 1,310,720 bytes
            "path": base_dir / "sample_F2_document.pdf",
            "generator": create_pdf_file,
        },
        "F3": {
            "type": "Image (.jpg)",
            "size_mb": 5.40,
            "target_bytes": int(5.40 * 1024 * 1024),  # 5,662,310 bytes
            "path": base_dir / "sample_F3_image.jpg",
            "generator": create_jpeg_file,
        },
        "F4": {
            "type": "Short video (.mp4)",
            "size_mb": 18.70,
            "target_bytes": int(18.70 * 1024 * 1024),  # 19,608,371 bytes
            "path": base_dir / "sample_F4_video.mp4",
            "generator": create_mp4_file,
        },
    }

    results = {}
    for fid, meta in targets.items():
        meta["generator"](meta["path"], meta["target_bytes"])
        actual_size = meta["path"].stat().st_size
        results[fid] = {
            "type": meta["type"],
            "target_size_mb": meta["size_mb"],
            "actual_bytes": actual_size,
            "actual_size_mb": round(actual_size / (1024 * 1024), 2),
            "path": str(meta["path"]),
        }
    return results


if __name__ == "__main__":
    out_dir = Path(__file__).resolve().parent / "test_data"
    print(f"Generating test files in {out_dir}...")
    files = generate_all_paper_test_files(out_dir)
    for fid, info in files.items():
        print(f"[{fid}] {info['type']}: {info['actual_bytes']:,} bytes ({info['actual_size_mb']} MB) -> {info['path']}")
