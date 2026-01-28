#!/usr/bin/env python3
"""
Configuration Refactoring Script
Cleans up the repository structure
"""

import os
import shutil
from pathlib import Path

repo_root = Path("F:/work/BugBounty/bugbounty/bugbounty")
os.chdir(repo_root)

print("=" * 60)
print("Repository Cleanup Script")
print("=" * 60)

# Remove old folders
folders_to_remove = [
    "Amazon",
    "Shopify",
    "automation",
    "templates",
    "workflows"
]

for folder in folders_to_remove:
    folder_path = repo_root / folder
    if folder_path.exists():
        print(f"✓ Removing {folder}/")
        shutil.rmtree(folder_path)

# Move docs
docs_path = repo_root / "docs"
docs_path.mkdir(exist_ok=True)

files_to_move = [
    "CONFIG_QUICKSTART.md",
    "CONFIG_TEMPLATES.md",
    "CLAUDE.md",
    "Cursor.md",
    "Gemini.md"
]

for file in files_to_move:
    src = repo_root / file
    if src.exists():
        dst = docs_path / file
        print(f"✓ Moving {file} to docs/")
        shutil.move(str(src), str(dst))

# Remove temporary files
temp_files = [
    "add_verification_phase.py",
    "phase_verification_call.txt",
    "phase_verification_method.txt",
    "verification_import.txt",
    "push_config_changes.bat",
    "push_simple.bat",
    "push_verification.bat",
    "test_anduril_config.py"
]

for file in temp_files:
    file_path = repo_root / file
    if file_path.exists():
        print(f"✓ Removing {file}")
        file_path.unlink()

print("\n" + "=" * 60)
print("✅ Cleanup Complete!")
print("=" * 60)
print("\nRepository structure:")
print("  bugbounty/")
print("    ├── config_scanner.py")
print("    ├── scan_config.yaml")
print("    ├── scanner.py")
print("    ├── tools/")
print("    └── docs/")
