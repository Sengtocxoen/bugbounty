"""
Web Hacking Techniques 2025 Scanner
====================================
Based on PortSwigger's Top 10 Web Hacking Techniques nominations for 2025.

11 Technique Modules:
- smuggling: HTTP Request Smuggling (CL.TE, TE.CL, H2 downgrade, Funky Chunks)
- cache_poison: Cache Poisoning & Desynchronization
- auth_bypass: Authentication & Authorization bypass (SAML, OAuth)
- xss_csrf: Cross-Site attacks (XSS, CSRF, CORS, Clickjacking)
- parser_xxe: Parser Differential attacks (XXE, polyglots)
- ssti_inject: Server-Side Template/Code injection (SSTI, SQLi, CMDi)
- ssrf: Server-Side Request Forgery (cloud metadata, bypass)
- xs_leaks: Cross-Site information leaks (ETag, timing oracles)
- framework_vulns: Framework-specific exploits (ASP.NET, Spring, PHP, Node)
- deserialization: Deserialization attacks (Java, .NET, PHP, Python)
- protocol_attacks: Protocol-specific (WebSocket, GraphQL, HTTP/2, gRPC)

Bug Bounty Compliance:
- Amazon VRP support (user agent, scope, rate limit)
- Shopify Bug Bounty support
- Configurable via --program flag

Usage:
  from web_hacking_2025 import WebHackingScanner
  scanner = WebHackingScanner(output_dir="./results")
  scanner.run(["example.com"])

Or via CLI:
  python -m web_hacking_2025.run example.com
  python -m web_hacking_2025.run -f domains.txt --techniques smuggling,cache,ssrf
  python -m web_hacking_2025.run example.amazon.com --program amazon --h1-user myuser
"""

__version__ = "2.0.0"
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

# Technique scanners (11 modules)
from .smuggling import HTTPSmuggling
from .cache_poison import CachePoisoning
from .auth_bypass import AuthBypass
from .xss_csrf import CrossSiteAttacks
from .parser_xxe import ParserXXE
from .ssti_inject import SSTIInjection
from .ssrf import SSRFDetection
from .xs_leaks import XSLeaks
from .framework_vulns import FrameworkVulns
from .deserialization import Deserialization
from .protocol_attacks import ProtocolAttacks

# Bug bounty configuration
from .bugbounty_config import (
    BugBountyConfig,
    get_program_config,
    detect_program,
    validate_targets,
    ScopeValidator,
    PROGRAMS,
    AMAZON_VRP,
    SHOPIFY_BB,
    GENERIC_BB
)

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
    # Technique Scanners (11)
    "HTTPSmuggling",
    "CachePoisoning",
    "AuthBypass",
    "CrossSiteAttacks",
    "ParserXXE",
    "SSTIInjection",
    "SSRFDetection",
    "XSLeaks",
    "FrameworkVulns",
    "Deserialization",
    "ProtocolAttacks",
    # Bug Bounty Config
    "BugBountyConfig",
    "get_program_config",
    "detect_program",
    "validate_targets",
    "ScopeValidator",
    "PROGRAMS",
    "AMAZON_VRP",
    "SHOPIFY_BB",
    "GENERIC_BB",
    # Main
    "WebHackingScanner",
    "TECHNIQUE_SCANNERS",
]
