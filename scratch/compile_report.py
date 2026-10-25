"""
SecureFileCrypt Comprehensive Report Compiler.
Builds:
1. deliverables/SecureFileCrypt_Project_Report.md
2. deliverables/SecureFileCrypt_Project_Report.docx
3. deliverables/SecureFileCrypt_Project_Report.pdf
"""

import sys
import os
from pathlib import Path

WORKSPACE = Path(r"c:\Users\rushi\Desktop\ICS_project\ics project")
DELIV = WORKSPACE / "deliverables"
FIGS = DELIV / "figures"
DELIV.mkdir(parents=True, exist_ok=True)
FIGS.mkdir(parents=True, exist_ok=True)

print("[+] Compiler script initialized.")
