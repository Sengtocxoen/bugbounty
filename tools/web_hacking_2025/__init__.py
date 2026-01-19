"""
Web Hacking Techniques 2025 Scanner
====================================
Based on PortSwigger's Top 10 Web Hacking Techniques nominations for 2025.

Modules:
- smuggling: HTTP Request Smuggling variants (CL.TE, TE.CL, H2 downgrade)
- cache_poison: Cache Poisoning & Desynchronization
- parser_xxe: Parser Differential attacks (polyglot, XXE)
- auth_bypass: Authentication & Authorization bypass (SAML, OAuth)
- xss_csrf: Cross-Site attacks (XSS, CSRF, CORS, Clickjacking)
- ssti_inject: Server-Side Template/Code injection (SSTI, SQLi, CMDi)

Usage:
  from web_hacking_2025 import WebHackingScanner
  scanner = WebHackingScanner(output_dir="./results")
  scanner.run(["example.com"])

Or via CLI:
  python -m web_hacking_2025.run example.com
  python -m web_hacking_2025.run -f domains.txt --techniques smuggling,cache
"""

__version__ = "1.0.0"
__author__ = "Bug Bounty Suite"

# Base classes
from .base import (
    TechniqueScanner,
    ScanProgress,
    Finding,
    ScanState,
    ProgressTracker,
    RateLimiter,
    Severity,
    setup_signal_handlers,
    is_shutdown
)

# Technique scanners
from .smuggling import HTTPSmuggling
from .cache_poison import CachePoisoning
from .auth_bypass import AuthBypass
from .xss_csrf import CrossSiteAttacks
from .parser_xxe import ParserXXE
from .ssti_inject import SSTIInjection

# Main scanner
from .scanner import WebHackingScanner, TECHNIQUE_SCANNERS

__all__ = [
    # Base
    "TechniqueScanner",
    "ScanProgress",
    "Finding",
    "ScanState",
    "ProgressTracker",
    "RateLimiter",
    "Severity",
    "setup_signal_handlers",
    "is_shutdown",
    # Scanners
    "HTTPSmuggling",
    "CachePoisoning",
    "AuthBypass",
    "CrossSiteAttacks",
    "ParserXXE",
    "SSTIInjection",
    # Main
    "WebHackingScanner",
    "TECHNIQUE_SCANNERS",
]
