#!/usr/bin/env python3
"""
Quick runner script for Web Hacking 2025 Scanner
================================================

Usage:
  python -m web_hacking_2025.run example.com
  python -m web_hacking_2025.run -f domains.txt
  python -m web_hacking_2025.run example.com --techniques smuggling,cache
"""

import sys
from pathlib import Path

# Ensure parent directory is in path
sys.path.insert(0, str(Path(__file__).parent.parent))

from web_hacking_2025.scanner import main

if __name__ == "__main__":
    main()
