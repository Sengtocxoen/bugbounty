#!/usr/bin/env python3
"""
Standalone Nuclei Runner — toolsforhumanity / Worldcoin
========================================================
Run Nuclei independently from the full deep scan pipeline.

Usage examples:

  # Scan all targets defined in scan_config.yaml
  python run_nuclei.py --program-targets

  # Scan specific targets
  python run_nuclei.py --targets id.worldcoin.org developer.worldcoin.org

  # Scan targets discovered by a previous deep scan
  python run_nuclei.py --scan-file results/toolsforhumanity/<target>/deep_scan_*.json

  # Add a dynamic auth token at runtime (e.g. after Ethereum auth)
  python run_nuclei.py --program-targets -H "x-authorization: TOKEN"

  # Use a different config file
  python run_nuclei.py --config scan_config.yaml --program-targets

  # Override severity / tags
  python run_nuclei.py --program-targets --severity critical high --tags oauth jwt graphql
"""

import sys
from pathlib import Path

# Allow importing from tools/
sys.path.insert(0, str(Path(__file__).parent))

from tools.verification.nuclei_scanner import main

if __name__ == '__main__':
    sys.exit(main())
