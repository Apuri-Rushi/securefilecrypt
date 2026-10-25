"""
Complete Academic Report Generator for SecureFileCrypt.
Outputs:
- deliverables/SecureFileCrypt_Project_Report.md
- deliverables/SecureFileCrypt_Project_Report.docx
- deliverables/SecureFileCrypt_Project_Report.pdf
"""

import os
import sys
import json
from pathlib import Path

# Paths
WORKSPACE_ROOT = Path(r"c:\Users\rushi\Desktop\ICS_project\ics project")
DELIVERABLES_DIR = WORKSPACE_ROOT / "deliverables"
FIGURES_DIR = DELIVERABLES_DIR / "figures"
DELIVERABLES_DIR.mkdir(parents=True, exist_ok=True)
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

MD_PATH = DELIVERABLES_DIR / "SecureFileCrypt_Project_Report.md"
DOCX_PATH = DELIVERABLES_DIR / "SecureFileCrypt_Project_Report.docx"
PDF_PATH = DELIVERABLES_DIR / "SecureFileCrypt_Project_Report.pdf"

print("[+] Script initialized.")
