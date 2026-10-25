"""
Report Generator for SecureFileCrypt Academic Deliverables.
Generates:
1. deliverables/SecureFileCrypt_Project_Report.md (Full GitHub-Flavored Academic Markdown)
2. deliverables/SecureFileCrypt_Project_Report.docx (Formatted Microsoft Word Document)
3. deliverables/SecureFileCrypt_Project_Report.pdf (Academic PDF Document via ReportLab)
"""

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DELIVERABLES_DIR = PROJECT_ROOT / "deliverables"
FIGURES_DIR = DELIVERABLES_DIR / "figures"
DELIVERABLES_DIR.mkdir(parents=True, exist_ok=True)
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

print(f"[+] Output directory: {DELIVERABLES_DIR}")
