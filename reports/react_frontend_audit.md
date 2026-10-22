# React Frontend Audit & Improvement Recommendations

**Project:** SecureFileCrypt  
**Audit Target:** `frontend/` (React 19 + Vite 8 + Recharts + Lucide-React)  
**Backend Target:** `server.py` (FastAPI 0.159.1 / Uvicorn 0.54.0 on `http://127.0.0.1:8000`)  
**Audit Date:** October 2026  
**Auditor Roles:** Senior Frontend Architect, Application Security Auditor, Academic Research Presentation Reviewer  

---

## 1. Executive Summary

A comprehensive source code and runtime audit was conducted on the existing SecureFileCrypt React frontend (`frontend/src/App.jsx`, `frontend/src/index.css`, `frontend/src/App.css`, `frontend/index.html`, and `frontend/vite.config.js`).

### Core Verdict
The React frontend is **fully functional, integrates cleanly with the real FastAPI backend, and successfully executes live cryptographic workflows** (including AES-256 Baseline encryption/decryption, Improved Argon2id+AEAD streaming encryption/decryption, and O(1) Envelope password re-wrapping).

However, before public demonstration or academic project defense, **specific improvements are necessary** to address:
1. Hardcoded API endpoints (`http://127.0.0.1:8000`) that prevent deployment or alternative host configurations.
2. The Mode toggle switch affecting the Envelope tab even though Baseline mode does not support Envelope DEK re-wrapping.
3. Fallback dummy values in telemetry (`"0.05"`, `"1.5"`, `"120.0"`) that could mask missing backend response headers.
4. Missing dynamic fetch for `/api/benchmarks` (relying exclusively on static `BENCHMARK_DATA` in `App.jsx`).
5. Missing `public/shield.svg` referenced in `index.html`.

---

## 2. Existing Frontend Features Verified in Source Code

The following components and behaviors were confirmed by direct static analysis of `frontend/src/App.jsx`:

| Feature / Element | Source Location | Verification Status | Implementation Details |
| :--- | :--- | :---: | :--- |
| **Global Architecture Switcher** | `App.jsx:208–242` | **Verified** | Pill buttons toggle `mode` between `'baseline'` and `'improved'`. Dynamically alters UI badge colors and descriptors. |
| **Tabbed View Navigation** | `App.jsx:246–286` | **Verified** | 3 tabs: `'crypto'` (Cryptographic Lab), `'envelope'` (O(1) Instant Key Rotation), `'benchmarks'` (Research Benchmarks & Metrics). |
| **Cryptographic Lab Workflow** | `App.jsx:289–400` | **Verified** | Supports file selection, passphrase entry, operation toggling (`encrypt` / `decrypt`), and form submission. |
| **Real Backend Integration** | `App.jsx:76–87` | **Verified** | Calls real backend endpoints (`POST /api/encrypt` and `POST /api/decrypt`) using `FormData`. |
| **Real-Time Telemetry Extraction** | `App.jsx:89–104` | **Verified** | Extracts `X-Exec-Time-Sec`, `X-Peak-Ram-Mb`, `X-Throughput-Mbs`, `X-Kdf`, `X-Kdf-Cost`, and `X-Architecture` from response headers. |
| **Automatic File Download** | `App.jsx:106–122` | **Verified** | Parses `Content-Disposition`, extracts server-assigned filename, creates Blob URL, triggers `<a download>`, and revokes object URL. |
| **O(1) Key Rotation Workflow** | `App.jsx:132–191, 465–538` | **Verified** | Sends `.enc` container, old password, and new password to `POST /api/rewrap-password`. Downloads re-wrapped `.enc`. |
| **Comparative Visual Charts** | `App.jsx:541–589` | **Verified** | Renders Recharts responsive bar chart (Throughput MB/s) and line chart (RAM Scaling MB) comparing Baseline vs. Improved across F1–F6. |

---

## 3. Current User Workflows and API Integration

```
                                  [ Browser React UI ]
                                            |
         +----------------------------------+----------------------------------+
         |                                  |                                  |
  [ Cryptographic Lab ]         [ O(1) Key Rotation ]           [ Benchmark Metrics ]
         |                                  |                                  |
    POST /api/encrypt              POST /api/rewrap-password           GET /api/benchmarks
    POST /api/decrypt                       |                             (Available on
         |                                  v                              backend, but
         v                     - Unwraps 32-byte DEK                     currently static
  - Dispatches form-data       - Derives new Argon2id KEK                in App.jsx)
  - Reads telemetry headers    - Re-wraps DEK header
  - Auto-triggers download     - Zero payload re-encryption
```

### Authentication Failure & Tamper Handling
- When bad passwords or tampered files are submitted, the backend returns `HTTP 400` with JSON `{"detail": "..."}`.
- `App.jsx:85-86` catches `!response.ok`, extracts `errorJson.detail`, and renders a clean red error banner.
- Form remains editable; no unhandled crashes occur.

---

## 4. Hardcoded or Mock Data Audit

| Item | Location | Type | Evaluation & Finding |
| :--- | :--- | :---: | :--- |
| `BENCHMARK_DATA` | `App.jsx:22–29` | **Hardcoded Historical** | Holds empirical metrics from WSL2 test runs (F1–F6). **Matches `comparative_benchmark.json` exactly.** However, it is hardcoded as a JavaScript constant rather than fetched dynamically from `GET /api/benchmarks`. |
| Telemetry Fallbacks | `App.jsx:98–103` | **Fallback Values** | `execTime || "0.05"`, `peakRam || "1.5"`, `throughput || "120.0"`. If a header is missing or blocked by CORS, dummy fallback numbers are shown instead of indicating an error. |
| Rewrap Telemetry | `App.jsx:167–172` | **Hardcoded / Partial** | Hardcodes `throughput: "Instantaneous"`, `kdf: "Dual Argon2id KDF Re-wrap"`, `kdfCost: "64 MB RAM"`, and `arch: "Envelope Encryption (DEK/KEK) O(1)"`. Only `execTime` and `peakRam` are parsed from headers. |
| Backend Endpoint URLs | `App.jsx:76, 153` | **Hardcoded Strings** | `http://127.0.0.1:8000/api/...` is hardcoded directly in fetch calls. |

---

## 5. Functional and Integration Findings

### Finding 1: Mode Switcher State Desynchronization with Envelope Rotation
- **File:** `frontend/src/App.jsx:208-242, 465-538`
- **Category:** Functional / UX Inconsistency
- **Evidence:** The global header provides buttons for `Baseline (418.pdf)` and `★ Improved Architecture`. If the user switches the mode to `Baseline` and then clicks the `O(1) Instant Key Rotation` tab, the form still submits to `/api/rewrap-password` (an Improved-only feature). The Baseline paper does not support Envelope DEK encryption.
- **Risk:** User confusion. An evaluator might think Baseline mode supports O(1) password rotation.
- **Recommendation:** When the `envelope` tab is selected, either disable the Baseline mode toggle or display a clear banner stating that Envelope encryption is exclusive to the Improved system.

### Finding 2: Hardcoded API Base URL Prevents Alternative Deployments
- **File:** `frontend/src/App.jsx:76, 153`
- **Category:** Integration / Portability
- **Evidence:**
  ```javascript
  const endpoint = operation === 'encrypt' ? 'http://127.0.0.1:8000/api/encrypt' : 'http://127.0.0.1:8000/api/decrypt';
  ...
  const response = await fetch("http://127.0.0.1:8000/api/rewrap-password", ...);
  ```
- **Risk:** If the backend runs on a different port (e.g. 8080) or another host/domain, the frontend fails to connect.
- **Recommendation:** Use a configurable constant: `const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';`.

### Finding 3: Missing Favicon (`/shield.svg`) Causing 404 in Browser Console
- **File:** `frontend/index.html:5`
- **Category:** Asset Bug
- **Evidence:** `<link rel="icon" type="image/svg+xml" href="/shield.svg" />`.
  However, `frontend/public/` contains `favicon.svg` and `icons.svg`, but **no `shield.svg`**.
- **Impact:** The browser requests `http://localhost:5173/shield.svg` and receives a 404, cluttering the developer console.
- **Recommendation:** Update `index.html` to reference `href="/favicon.svg"`.

### Finding 4: Unused Imports in `App.jsx`
- **File:** `frontend/src/App.jsx:4, 5, 6, 11, 12, 15`
- **Category:** Code Cleanliness (Linter Warnings)
- **Evidence:** `oxlint` reports 6 unused icon imports from `lucide-react`: `Cpu`, `HardDrive`, `Layers`, `FlaskConical`, `Sparkles`, `ArrowRight`.
- **Recommendation:** Clean up unused imports.

---

## 6. Design and Usability Review

### Aesthetics & Academic Presentation
- **Strengths:** 
  - Dark radial gradient (`#172554` to `#0a0e17`) with glassmorphism panels creates a modern, sleek appearance.
  - Clear color differentiation: Rose/Red (`#e11d48`) for the Baseline implementation; Cyan/Blue (`#06b6d4` to `#3b82f6`) for the Improved system.
  - Good typography using Inter and JetBrains Mono from Google Fonts.
  - Real-time telemetry cards clearly display execution time, throughput, peak RAM, and cipher architecture.

### Usability Observations
1. **Password Confirmation in Key Rotation:**
   - In `App.jsx:508–520`, the Key Rotation form provides "Current Old Password" and "New Password", but does not have a "Confirm New Password" field, unlike the Streamlit version (`improved/app.py:195-199`). Adding confirmation prevents accidental typos locking a user out of their file.
2. **File Size Display:**
   - Displays `(file.size / (1024 * 1024)).toFixed(2) MB`. For files under 0.01 MB (like a 200-byte text file), it displays `0.00 MB`. Formatting with `KB` for small files would improve clarity.
3. **Chart Benchmark Context:**
   - The Benchmark tab should explicitly state that the displayed throughput and RAM curves are from the empirical benchmark suite run across standard test files F1–F6, distinguishing them from the live telemetry in the Cryptographic Lab tab.

---

## 7. Security and Integration Audit

| Security Domain | Frontend Practice | Status / Recommendation |
| :--- | :--- | :---: |
| **Plaintext / Password Exposure** | Passwords stored only in React component state during user interaction; never printed or logged to `console.log`. | **Clean** |
| **XSS / HTML Injection** | Error messages and filenames rendered via React JSX text nodes (`{error}`, `{file.name}`); no `dangerouslySetInnerHTML`. | **Clean** |
| **Download Safety** | Blob URLs created via `URL.createObjectURL(blob)` and explicitly destroyed via `URL.revokeObjectURL(url)`. | **Clean** |
| **Duplicate Submission Protection** | Submit button disabled when `loading === true`; button text updates to `"Processing Cryptographic Engine..."`. | **Clean** |

---

## 8. Prioritized Recommendations

### Priority 0 (P0 — Must Fix Before Final Evaluation)
- None. There are zero blocking crashes or security failures in the existing code.

### Priority 1 (P1 — Should Improve Before Demonstration)
1. **P1-1: Configurable API Base URL:** Replace hardcoded `http://127.0.0.1:8000` with `const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'`.
2. **P1-2: Fix Favicon Link:** Update `index.html` to point to `/favicon.svg` to eliminate the 404 error in browser logs.
3. **P1-3: Add New Password Confirmation:** Add "Confirm New Password" input in the Envelope Re-wrapping tab to prevent accidental mistyping.
4. **P1-4: Telemetry Fallback Elimination:** If telemetry headers are missing, display `"N/A"` or indicate unmetered request rather than showing misleading default numbers (`"0.05"` or `"120.0"`).
5. **P1-5: Remove Dead Imports:** Clean up unused `lucide-react` icons to achieve a 100% clean linter report.

### Priority 2 (P2 — Optional Enhancements)
1. **P2-1: Dynamic `/api/benchmarks` Loading:** Fetch live benchmark data from the backend route `/api/benchmarks` on mount, falling back to static constants if the backend is offline.
2. **P2-2: Sub-Megabyte File Size Formatting:** Format file size in KB if size $< 1\text{ MB}$.

---

## 9. Proposed Implementation Plan

If approved, the improvements will be implemented in a single minimal, isolated pass:
1. **Target Files to Modify:**
   - `frontend/src/App.jsx` (API base URL constant, unused import cleanup, telemetry fallback fix, new password confirm field).
   - `frontend/index.html` (Favicon reference fix).
2. **Files to Keep Untouched:**
   - All backend Python code (`server.py`, `baseline/`, `improved/`, `benchmark/`).
   - `frontend/package.json` and dependencies.
   - All benchmark JSON files and test files.

---

## 10. Final Recommendation

> **Is the current React frontend ready for project evaluation, or should we implement specific changes first?**
>
> **The current React frontend is fundamentally working, robust, and capable of demonstrating all core project features.**
> However, implementing the **5 lightweight P1 polish items** (fixing the favicon 404, cleaning up dead imports, abstracting the API URL, adding password confirmation, and removing fallback telemetry defaults) is strongly recommended before formal evaluation. These changes will elevate the project to production-grade quality without touching any backend code or introducing regression risks.
