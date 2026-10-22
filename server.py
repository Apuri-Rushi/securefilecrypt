"""
FastAPI Backend for SecureFileCrypt React Interface
Exposes baseline (Rosandi et al. 2026) and improved (Argon2id + Streaming AEAD + Envelope) cryptographic engines
with real-time execution telemetry (execution time, peak RAM, throughput).
"""

import sys
import os
import time
import tracemalloc
import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, JSONResponse

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Import baseline and improved crypto modules
from baseline import crypto as base_crypto
from baseline import file_format as base_format
from improved import crypto as impr_crypto
from improved import file_format as impr_format

app = FastAPI(title="SecureFileCrypt API", version="2.0.0")

# Enable CORS for local React development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BENCHMARK_RESULTS_PATH = PROJECT_ROOT / "benchmark" / "results" / "comparative_benchmark.json"

@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "SecureFileCrypt API"}

@app.get("/api/benchmarks")
def get_benchmarks():
    """Returns stored head-to-head empirical benchmark results for visual charts."""
    if not BENCHMARK_RESULTS_PATH.exists():
        raise HTTPException(status_code=404, detail="Benchmark results not found")
    with open(BENCHMARK_RESULTS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data

@app.post("/api/encrypt")
async def encrypt_file(
    file: UploadFile = File(...),
    password: str = Form(...),
    mode: str = Form("improved")  # "baseline" | "improved"
):
    if not password:
        raise HTTPException(status_code=400, detail="Password is required")

    content = await file.read()
    file_size_bytes = len(content)
    file_size_mb = file_size_bytes / (1024 * 1024)

    tracemalloc.start()
    start_time = time.perf_counter()

    try:
        if mode == "baseline":
            # Baseline reproduction: PBKDF2-HMAC-SHA256 + Monolithic AES-256-GCM
            salt, nonce, ciphertext = base_crypto.encrypt_file_data(content, password)
            packaged = base_format.package_container(salt, nonce, ciphertext)
            output_filename = f"{file.filename}.enc"
            kdf_name = "PBKDF2-HMAC-SHA256 (100k iter)"
            kdf_cost = "0 MB RAM (Standard)"
            crypto_architecture = "Monolithic AES-256-GCM (Direct Key)"
        else:
            # Improved system: Argon2id + Envelope DEK/KEK + Chunked AEAD
            import io
            in_stream = io.BytesIO(content)
            out_stream = io.BytesIO()

            metadata = {
                "filename": file.filename or "file.bin",
                "content_type": file.content_type or "application/octet-stream",
                "size": file_size_bytes
            }

            impr_crypto.encrypt_stream(
                in_stream=in_stream,
                out_stream=out_stream,
                password=password,
                metadata=metadata,
                chunk_size=64 * 1024
            )
            packaged = out_stream.getvalue()
            output_filename = f"{file.filename}.enc"
            kdf_name = "Argon2id (RFC 9106)"
            kdf_cost = "64 MB RAM, t=2, p=4"
            crypto_architecture = "Chunked Streaming AEAD + Envelope (DEK/KEK)"

        elapsed_seconds = time.perf_counter() - start_time
        current_ram, peak_ram = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        peak_ram_mb = peak_ram / (1024 * 1024)
        throughput_mbs = file_size_mb / elapsed_seconds if elapsed_seconds > 0 else 0

        # Return encrypted file as attachment with telemetry headers
        headers = {
            "Content-Disposition": f'attachment; filename="{output_filename}"',
            "Access-Control-Expose-Headers": "*",
            "X-Exec-Time-Sec": f"{elapsed_seconds:.4f}",
            "X-Peak-Ram-Mb": f"{peak_ram_mb:.2f}",
            "X-Throughput-Mbs": f"{throughput_mbs:.2f}",
            "X-File-Size-Bytes": str(file_size_bytes),
            "X-Ciphertext-Size-Bytes": str(len(packaged)),
            "X-Mode": mode,
            "X-Kdf": kdf_name,
            "X-Kdf-Cost": kdf_cost,
            "X-Architecture": crypto_architecture
        }

        return Response(content=packaged, media_type="application/octet-stream", headers=headers)

    except Exception as e:
        tracemalloc.stop()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/decrypt")
async def decrypt_file(
    file: UploadFile = File(...),
    password: str = Form(...),
    mode: str = Form("improved")
):
    if not password:
        raise HTTPException(status_code=400, detail="Password is required")

    content = await file.read()
    file_size_bytes = len(content)
    file_size_mb = file_size_bytes / (1024 * 1024)

    tracemalloc.start()
    start_time = time.perf_counter()

    try:
        if mode == "baseline":
            salt, nonce, ciphertext = base_format.parse_container(content)
            plaintext = base_crypto.decrypt_file_data(salt, nonce, ciphertext, password)
            original_filename = file.filename[:-4] if file.filename.endswith(".enc") else f"decrypted_{file.filename}"
            kdf_name = "PBKDF2-HMAC-SHA256 (100k iter)"
        else:
            import io
            in_stream = io.BytesIO(content)
            out_stream = io.BytesIO()

            metadata = impr_crypto.decrypt_stream(
                in_stream=in_stream,
                out_stream=out_stream,
                password=password
            )
            plaintext = out_stream.getvalue()
            original_filename = metadata.get("filename") or (file.filename[:-4] if file.filename.endswith(".enc") else "decrypted_file")
            kdf_name = "Argon2id (RFC 9106)"

        elapsed_seconds = time.perf_counter() - start_time
        current_ram, peak_ram = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        peak_ram_mb = peak_ram / (1024 * 1024)
        throughput_mbs = file_size_mb / elapsed_seconds if elapsed_seconds > 0 else 0

        headers = {
            "Content-Disposition": f'attachment; filename="{original_filename}"',
            "Access-Control-Expose-Headers": "*",
            "X-Exec-Time-Sec": f"{elapsed_seconds:.4f}",
            "X-Peak-Ram-Mb": f"{peak_ram_mb:.2f}",
            "X-Throughput-Mbs": f"{throughput_mbs:.2f}",
            "X-Original-Filename": original_filename,
            "X-Mode": mode,
            "X-Kdf": kdf_name
        }

        return Response(content=plaintext, media_type="application/octet-stream", headers=headers)

    except base_crypto.DecryptionError:
        tracemalloc.stop()
        raise HTTPException(status_code=400, detail="Baseline Authentication Failed: Incorrect password or corrupted payload.")
    except impr_crypto.AuthenticationError:
        tracemalloc.stop()
        raise HTTPException(status_code=400, detail="Improved AEAD Authentication Failed: Invalid password or cryptographic tag mismatch.")
    except Exception as e:
        tracemalloc.stop()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/rewrap-password")
async def rewrap_password(
    file: UploadFile = File(...),
    old_password: str = Form(...),
    new_password: str = Form(...)
):
    """
    Demonstrates O(1) Instantaneous Password Change via Envelope Encryption.
    Modifies only the 32-byte DEK header without decrypting the payload.
    """
    if not old_password or not new_password:
        raise HTTPException(status_code=400, detail="Both old and new passwords are required")

    content = await file.read()
    tracemalloc.start()
    start_time = time.perf_counter()

    try:
        import io
        in_stream = io.BytesIO(content)
        out_stream = io.BytesIO()

        impr_crypto.rewrap_stream_password(
            in_stream=in_stream,
            out_stream=out_stream,
            old_password=old_password,
            new_password=new_password
        )

        rewrapped_bytes = out_stream.getvalue()
        elapsed_seconds = time.perf_counter() - start_time
        current_ram, peak_ram = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        headers = {
            "Content-Disposition": f'attachment; filename="{file.filename}"',
            "Access-Control-Expose-Headers": "*",
            "X-Exec-Time-Sec": f"{elapsed_seconds:.4f}",
            "X-Peak-Ram-Mb": f"{peak_ram / (1024 * 1024):.2f}",
            "X-Operation": "Envelope DEK In-Place Re-wrap (O(1))"
        }

        return Response(content=rewrapped_bytes, media_type="application/octet-stream", headers=headers)

    except impr_crypto.AuthenticationError:
        tracemalloc.stop()
        raise HTTPException(status_code=400, detail="Old password incorrect: Cannot decrypt DEK envelope.")
    except Exception as e:
        tracemalloc.stop()
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)
