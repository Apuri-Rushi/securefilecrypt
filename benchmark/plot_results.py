"""
Generates visual benchmark charts comparing Baseline vs Improved implementations:
1. Throughput vs File Size (MB/s)
2. Peak Memory Consumption vs File Size (MB)
3. Password Change Latency vs File Size (s)
4. Key Derivation Latency & Memory Footprint
"""

import json
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_FILE = PROJECT_ROOT / "benchmark" / "results" / "comparative_benchmark.json"
CHART_FILE = PROJECT_ROOT / "benchmark" / "results" / "benchmark_charts.png"


def generate_charts():
    if not RESULTS_FILE.exists():
        print(f"Error: {RESULTS_FILE} does not exist. Run comparative benchmarks first.")
        return

    with open(RESULTS_FILE, "r") as f:
        data = json.load(f)

    file_ids = list(data["files"].keys())
    sizes = [data["files"][fid]["size_mb"] for fid in file_ids]
    labels = [f"{fid}\n({d['size_mb']:.1f}M)" for fid, d in data["files"].items()]

    base_enc_tp = [data["files"][fid]["baseline"]["enc_throughput_mb_s"] for fid in file_ids]
    impr_enc_tp = [data["files"][fid]["improved"]["enc_throughput_mb_s"] for fid in file_ids]

    base_ram = [data["files"][fid]["baseline"]["enc_peak_mem_mb"] for fid in file_ids]
    impr_ram = [data["files"][fid]["improved"]["enc_peak_mem_mb"] for fid in file_ids]

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle(
        "Cryptographic Performance & Resource Evaluation: Baseline vs Improved System\n"
        "(Rosandi et al. 2026 Reproduction vs Memory-Bounded Envelope AEAD)",
        fontsize=14,
        fontweight="bold",
    )

    # 1. Throughput Comparison
    x = np.arange(len(file_ids))
    width = 0.35
    ax1 = axes[0, 0]
    ax1.bar(x - width / 2, base_enc_tp, width, label="Baseline (AES-GCM / PBKDF2)", color="#3498db")
    ax1.bar(x + width / 2, impr_enc_tp, width, label="Improved (Streaming AEAD / Argon2id)", color="#2ecc71")
    ax1.set_title("Encryption Throughput (Higher is Better)", fontweight="bold")
    ax1.set_ylabel("Throughput (MB/s)")
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels)
    ax1.legend()
    ax1.grid(True, linestyle="--", alpha=0.5)

    # 2. Peak Memory Consumption
    ax2 = axes[0, 1]
    ax2.plot(sizes, base_ram, "o-", color="#e74c3c", linewidth=2.5, label="Baseline (O(N) In-Memory Buffer)")
    ax2.plot(sizes, impr_ram, "s--", color="#27ae60", linewidth=2.5, label="Improved (Chunked Streaming)")
    ax2.set_title("Peak Heap Memory vs File Size (Lower is Better)", fontweight="bold")
    ax2.set_xlabel("Input File Size (MB)")
    ax2.set_ylabel("Peak Allocated Memory (MB)")
    ax2.legend()
    ax2.grid(True, linestyle="--", alpha=0.5)

    # 3. Password Modification Latency
    ax3 = axes[1, 0]
    if "password_change_comparison" in data and data["password_change_comparison"]:
        pwd_fids = list(data["password_change_comparison"].keys())
        pwd_labels = [f"{fid} ({data['password_change_comparison'][fid]['size_mb']:.1f} MB)" for fid in pwd_fids]
        base_pwd_times = [data["password_change_comparison"][fid]["baseline_reencrypt_s"] for fid in pwd_fids]
        impr_pwd_times = [data["password_change_comparison"][fid]["improved_envelope_s"] for fid in pwd_fids]

        x_pwd = np.arange(len(pwd_fids))
        ax3.bar(x_pwd - width / 2, base_pwd_times, width, label="Baseline (Full Re-encryption)", color="#e67e22")
        ax3.bar(x_pwd + width / 2, impr_pwd_times, width, label="Improved (Envelope Re-wrap)", color="#9b59b6")
        ax3.set_title("Password Modification Latency (Lower is Better)", fontweight="bold")
        ax3.set_ylabel("Processing Time (seconds)")
        ax3.set_xticks(x_pwd)
        ax3.set_xticklabels(pwd_labels)
        ax3.legend()
        ax3.grid(True, linestyle="--", alpha=0.5)
    else:
        ax3.text(0.5, 0.5, "No Password Data", ha="center")

    # 4. KDF Latency & Hardness
    ax4 = axes[1, 1]
    kdf_info = data.get("kdf_comparison", {})
    kdf_names = ["PBKDF2-SHA256\n(100k iter, 0 MB RAM)", "Argon2id\n(t=2, m=64 MB, p=4)"]
    kdf_times_ms = [
        kdf_info.get("pbkdf2", {}).get("mean_s", 0.05) * 1000,
        kdf_info.get("argon2id", {}).get("mean_s", 0.05) * 1000,
    ]
    bars = ax4.bar(kdf_names, kdf_times_ms, color=["#1abc9c", "#f39c12"], width=0.45)
    ax4.set_title("KDF Execution Latency & Security Profile", fontweight="bold")
    ax4.set_ylabel("Execution Time (ms)")
    ax4.grid(True, linestyle="--", alpha=0.5)
    for bar in bars:
        height = bar.get_height()
        ax4.annotate(
            f"{height:.1f} ms",
            xy=(bar.get_x() + bar.get_width() / 2, height),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontweight="bold",
        )

    plt.tight_layout()
    CHART_FILE.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(CHART_FILE, dpi=300)
    plt.close()
    print(f"[+] Benchmark charts saved to {CHART_FILE}")


if __name__ == "__main__":
    generate_charts()
