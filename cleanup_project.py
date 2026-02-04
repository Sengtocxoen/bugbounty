#!/usr/bin/env python3
"""
Project Cleanup Script
Removes unnecessary files and directories while keeping essential code.
"""

import os
import shutil
from pathlib import Path

# Get script directory
SCRIPT_DIR = Path(__file__).parent.absolute()

# Directories to remove
DIRS_TO_REMOVE = [
    "legacy",                    # Old legacy scripts
    "docs",                      # Documentation (we have README.md and Agent.md)
    "Phases",                    # Phase docs (covered in Agent.md)
    "KingOfBugBountyTips",      # Empty directory
    ".claude",                   # AI assistant artifacts
]

# Optional: Uncomment if you want to remove books (saves 60+ MB)
# DIRS_TO_REMOVE.append("books")

# Files to remove
FILES_TO_REMOVE = [
    "cleanup_repo.py",           # Old cleanup script (replaced by this one)
    "continuous_config.yaml",    # Old config (we have scan_config.yaml now)
]

def cleanup():
    """Remove unnecessary files and directories"""
    print("🧹 Project Cleanup")
    print("=" * 60)
    
    removed_count = 0
    
    # Remove directories
    print("\n📁 Removing directories...")
    for dir_name in DIRS_TO_REMOVE:
        dir_path = SCRIPT_DIR / dir_name
        if dir_path.exists() and dir_path.is_dir():
            try:
                shutil.rmtree(dir_path)
                print(f"  ✓ Removed: {dir_name}/")
                removed_count += 1
            except Exception as e:
                print(f"  ✗ Failed to remove {dir_name}/: {e}")
        else:
            print(f"  - Skipped: {dir_name}/ (not found)")
    
    # Remove files
    print("\n📄 Removing files...")
    for file_name in FILES_TO_REMOVE:
        file_path = SCRIPT_DIR / file_name
        if file_path.exists() and file_path.is_file():
            try:
                file_path.unlink()
                print(f"  ✓ Removed: {file_name}")
                removed_count += 1
            except Exception as e:
                print(f"  ✗ Failed to remove {file_name}: {e}")
        else:
            print(f"  - Skipped: {file_name} (not found)")
    
    print("\n" + "=" * 60)
    print(f"✅ Cleanup complete! Removed {removed_count} items.")
    print("\n📦 Keeping essential files:")
    print("  - scanner.py, config_scanner.py")
    print("  - scan_config.yaml, scan_config_maximum.yaml")
    print("  - README.md, Agent.md, Feature.md")
    print("  - tools/ (all modules)")
    print("  - requirements.txt")
    print("  - install_enhanced_tools.sh")
    
    # Optional: Show books status
    books_path = SCRIPT_DIR / "books"
    if books_path.exists():
        print("\n📚 Note: 'books/' directory kept (60+ MB of PDFs)")
        print("   To remove: Uncomment 'books' in DIRS_TO_REMOVE")

if __name__ == "__main__":
    print("\n⚠️  This will remove the following:")
    for d in DIRS_TO_REMOVE:
        print(f"   - {d}/")
    for f in FILES_TO_REMOVE:
        print(f"   - {f}")
    
    response = input("\n❓ Proceed with cleanup? (yes/no): ").strip().lower()
    
    if response in ['yes', 'y']:
        cleanup()
    else:
        print("\n❌ Cleanup cancelled.")
