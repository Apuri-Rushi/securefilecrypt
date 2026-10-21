# Paper-Faithful Baseline Implementation

This directory contains the faithful reproduction of the file encryption and decryption application described in:

> **"Design of File Encryption and Decryption Application Using AES-256 Cryptography Algorithm Based on Streamlit"**  
> *Arditya Adjie Rosandi, Dhicky Hariyadi Supriyono, Teguh Tegar Aulia, and Jefry Sunupurwa Asri*  
> International Journal of Multidisciplinary Research and Literature (IJOMRAL), Vol. 5, No. 1, January 2026, pp. 162–168.

---

## 1. Baseline Architecture & Cryptographic Primitives

- **Operating Modes:** `Encrypt` and `Decrypt` via a clean Streamlit interface.
- **Data Encryption:** Advanced Encryption Standard with a 256-bit key in Galois/Counter Mode (**AES-256-GCM**), providing combined confidentiality and integrity authentication.
- **Key Derivation Function (KDF):** **PBKDF2-HMAC-SHA256**.
- **Container Format:** Single-shot binary output with `.enc` extension, adhering to the paper's defined byte order:
  ```
  [salt (16 B)][nonce (12 B)][ciphertext (N B) + tag (16 B)]
  ```

---

## 2. Parameter Specifications & Reconstruction Assumptions

| Parameter | Paper Statement | Baseline Value | Cryptographic / System Rationale |
| :--- | :--- | :---: | :--- |
| **AES Key Size** | 256 bits | 32 bytes (256 bits) | Stated in paper |
| **Cipher Mode** | Galois/Counter Mode (GCM) | AES-256-GCM | Stated in paper |
| **Key Derivation** | PBKDF2-HMAC-SHA256 | PBKDF2-HMAC-SHA256 | Stated in paper |
| **KDF Iterations** | "Sufficient number of iterations" | 100,000 | Reconstruction: NIST SP 800-132 / OWASP standard |
| **Salt Length** | "Random salt" | 16 bytes (128 bits) | Reconstruction: CSPRNG standard |
| **Nonce Length** | "Nonce for AES-GCM" | 12 bytes (96 bits) | Reconstruction: NIST SP 800-38D standard |
| **Authentication Tag** | Integrated AEAD tag | 16 bytes (128 bits) | Reconstruction: Appended by AESGCM library |
| **Filename Handling** | Not specified in container | Streamlit naming logic | Strips `.enc` on decrypt; preserves user convenience |
| **Memory Strategy** | In-memory Streamlit upload | Full byte buffer | Faithful to paper's single-shot architecture |

---

## 3. Directory Layout

- `crypto.py`: Cryptographic functions (`derive_key`, `encrypt_bytes`, `decrypt_bytes`).
- `file_format.py`: Container serialization and deserialization (`pack_container`, `unpack_container`).
- `app.py`: Streamlit web interface matching Figures 1, 2, and 4 of the paper.
- `requirements.txt`: Python dependencies.
- `tests/`: Automated functional and security verification suites.

---

## 4. Running the Baseline Application

To launch the Streamlit web app:

```bash
streamlit run baseline/app.py
```

To run the automated test suite:

```bash
pytest baseline/tests/ -v
```
