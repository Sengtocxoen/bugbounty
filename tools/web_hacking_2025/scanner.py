#!/usr/bin/env python3
"""
Web Hacking Techniques 2025 - Main Scanner Orchestrator
========================================================
Based on PortSwigger's Top 10 Web Hacking Techniques nominations for 2025.

Runs all technique scanners against target domains with:
- Progress tracking and state persistence
- Resumable scans
- Real-time output
- Findings categorized by severity

Usage:
  # Single domain
  python scanner.py example.com

  # Multiple domains from file
  python scanner.py -f domains.txt

  # Resume interrupted scan
  python scanner.py -f domains.txt --resume

  # Run specific techniques only
  python scanner.py example.com --techniques smuggling,cache,xss

  # Custom output directory
  python scanner.py example.com -o ./my_results

  # With rate limiting and custom user agent
  python scanner.py example.com --rate 3 --user-agent "myresearcher"
"""

import sys
import argparse
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from .base import (
    ScanProgress, ProgressTracker, TechniqueScanner, Finding,
    setup_signal_handlers, is_shutdown
)
from .smuggling import HTTPSmuggling
from .cache_poison import CachePoisoning
from .auth_bypass import AuthBypass
from .xss_csrf import CrossSiteAttacks
from .parser_xxe import ParserXXE
from .ssti_inject import SSTIInjection


# Available technique scanners
TECHNIQUE_SCANNERS = {
    "smuggling": {
        "class": HTTPSmuggling,
        "name": "HTTP Request Smuggling",
        "description": "CL.TE, TE.CL, HTTP/2 downgrade attacks"
    },
    "cache": {
        "class": CachePoisoning,
        "name": "Cache Poisoning",
        "description": "Unkeyed headers, cache deception, path normalization"
    },
    "auth": {
        "class": AuthBypass,
        "name": "Auth/Authz Bypass",
        "description": "OAuth, SAML, path traversal, IDOR"
    },
    "xss": {
        "class": CrossSiteAttacks,
        "name": "Cross-Site Attacks",
        "description": "XSS, CSRF, CORS, clickjacking, open redirect"
    },
    "parser": {
        "class": ParserXXE,
        "name": "Parser/XXE",
        "description": "XXE, JSON parser differentials, URL confusion"
    },
    "inject": {
        "class": SSTIInjection,
        "name": "SSTI/Injection",
        "description": "SSTI, SQLi, command injection, PDF exploits"
    },
}


class WebHackingScanner:
    """Main orchestrator for 2025 web hacking techniques scanner"""

    def __init__(self,
                 output_dir: Path,
                 rate_limit: float = 5.0,
                 user_agent: str = "Mozilla/5.0 (compatible; SecurityResearch/1.0)",
                 techniques: List[str] = None,
                 verbose: bool = True,
                 threads: int = 3):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.rate_limit = rate_limit
        self.user_agent = user_agent
        self.verbose = verbose
        self.threads = threads

        # Select techniques to run
        if techniques:
            self.techniques = [t for t in techniques if t in TECHNIQUE_SCANNERS]
        else:
            self.techniques = list(TECHNIQUE_SCANNERS.keys())

        # Initialize progress tracker
        self.progress = None

    def log(self, message: str, level: str = "info"):
        """Log a message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "info": "[*]",
            "success": "[+]",
            "warning": "[!]",
            "error": "[-]"
        }.get(level, "[*]")
        print(f"{timestamp} {prefix} {message}")

    def _init_scanners(self) -> Dict[str, TechniqueScanner]:
        """Initialize technique scanners"""
        scanners = {}
        for tech_id in self.techniques:
            tech_info = TECHNIQUE_SCANNERS[tech_id]
            scanners[tech_id] = tech_info["class"](
                rate_limit=self.rate_limit,
                user_agent=self.user_agent,
                verbose=self.verbose
            )
        return scanners

    def scan_domain(self, domain: str, scanners: Dict[str, TechniqueScanner]) -> List[Finding]:
        """Scan a single domain with all techniques"""
        all_findings = []

        self.log(f"Starting scan on {domain}", "info")
        self.progress.start_domain(domain)

        for tech_id, scanner in scanners.items():
            if is_shutdown():
                break

            tech_name = TECHNIQUE_SCANNERS[tech_id]["name"]
            self.log(f"Running {tech_name} on {domain}")

            try:
                findings = scanner.scan(domain, self.progress)
                all_findings.extend(findings)
                self.progress.complete_technique(domain, tech_id)

                if findings:
                    self.log(f"{tech_name}: Found {len(findings)} issues", "success")

            except Exception as e:
                error_msg = f"Error in {tech_name}: {str(e)}"
                self.log(error_msg, "error")
                self.progress.add_error(domain, error_msg)

            # Save progress after each technique
            self.progress.save()

        if not is_shutdown():
            self.progress.complete_domain(domain)
            self.progress.save()

        return all_findings

    def run(self, domains: List[str], resume: bool = False):
        """Run scanner on all domains"""
        setup_signal_handlers()

        # Initialize or load progress
        if resume:
            self.progress = ScanProgress.load(self.output_dir)
            if self.progress:
                self.log(f"Resuming scan from {self.progress.last_save}", "info")
            else:
                self.log("No previous scan found, starting fresh", "warning")
                self.progress = ScanProgress(output_dir=self.output_dir)
        else:
            self.progress = ScanProgress(output_dir=self.output_dir)

        # Add domains to progress
        for domain in domains:
            self.progress.add_domain(domain, self.techniques)

        # Initialize scanners
        scanners = self._init_scanners()

        # Display scan info
        self._print_banner()
        self.log(f"Scanning {len(domains)} domains")
        self.log(f"Techniques: {', '.join(self.techniques)}")
        self.log(f"Output directory: {self.output_dir}")
        self.log(f"Rate limit: {self.rate_limit} req/s")
        print("-" * 60)

        # Start progress tracker
        tracker = ProgressTracker(self.progress, refresh_interval=5.0)
        tracker.start()

        all_findings = []

        try:
            # Process domains
            for domain in domains:
                if is_shutdown():
                    self.log("Shutdown requested, saving progress...", "warning")
                    break

                # Skip completed domains
                if domain in self.progress.domains:
                    dp = self.progress.domains[domain]
                    if dp.state.value == "completed":
                        self.log(f"Skipping {domain} (already completed)")
                        continue

                findings = self.scan_domain(domain, scanners)
                all_findings.extend(findings)

        finally:
            tracker.stop()
            self.progress.save()

        # Print summary
        self._print_summary(all_findings)

        return all_findings

    def _print_banner(self):
        """Print scanner banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║        Web Hacking Techniques 2025 Scanner                    ║
║        Based on PortSwigger Top 10 Nominations                ║
╚══════════════════════════════════════════════════════════════╝
"""
        print(banner)

    def _print_summary(self, findings: List[Finding]):
        """Print scan summary"""
        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)

        stats = self.progress.get_stats()
        print(f"Domains scanned: {stats['domains_completed']}/{stats['domains_total']}")
        print(f"Total findings: {stats['findings_total']}")
        print()
        print("Findings by severity:")
        for sev, count in stats['findings_by_severity'].items():
            if count > 0:
                print(f"  {sev.upper()}: {count}")

        print()
        print(f"Results saved to: {self.output_dir}")
        print("  - scan_progress.json: Full progress state")
        print("  - domains_status.txt: Domain scan status")
        print("  - findings/: Findings by severity")

        if stats['findings_by_severity'].get('critical', 0) > 0:
            print("\n[!] CRITICAL findings detected! Review immediately.")

        print("=" * 60)


def load_domains_from_file(filepath: str) -> List[str]:
    """Load domains from a file"""
    domains = []
    with open(filepath, 'r') as f:
        for line in f:
            domain = line.strip()
            if domain and not domain.startswith('#'):
                # Remove protocol if present
                domain = domain.replace('https://', '').replace('http://', '')
                domain = domain.split('/')[0]  # Remove path
                domains.append(domain)
    return list(set(domains))  # Deduplicate


def main():
    parser = argparse.ArgumentParser(
        description='Web Hacking Techniques 2025 Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s -f domains.txt --resume
  %(prog)s example.com --techniques smuggling,cache,xss
  %(prog)s example.com -o ./results --rate 3

Available techniques:
  smuggling  - HTTP Request Smuggling (CL.TE, TE.CL, H2)
  cache      - Cache Poisoning (unkeyed headers, deception)
  auth       - Auth/Authz Bypass (OAuth, SAML, path bypass)
  xss        - Cross-Site Attacks (XSS, CSRF, CORS)
  parser     - Parser/XXE (XXE, JSON differential, URL)
  inject     - SSTI/Injection (SSTI, SQLi, CMDi, PDF)
        """
    )

    parser.add_argument('domain', nargs='?', help='Target domain')
    parser.add_argument('-f', '--file', help='File containing domains (one per line)')
    parser.add_argument('-o', '--output', default='./web_hacking_2025_results',
                       help='Output directory (default: ./web_hacking_2025_results)')
    parser.add_argument('--techniques', help='Comma-separated list of techniques to run')
    parser.add_argument('--rate', type=float, default=5.0,
                       help='Rate limit (requests per second, default: 5)')
    parser.add_argument('--user-agent', default='Mozilla/5.0 (compatible; SecurityResearch/1.0)',
                       help='Custom User-Agent string')
    parser.add_argument('--resume', action='store_true',
                       help='Resume previous scan')
    parser.add_argument('--threads', type=int, default=3,
                       help='Number of parallel threads (default: 3)')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Reduce output verbosity')
    parser.add_argument('--list-techniques', action='store_true',
                       help='List available techniques and exit')

    args = parser.parse_args()

    # List techniques
    if args.list_techniques:
        print("\nAvailable techniques:")
        print("-" * 50)
        for tech_id, info in TECHNIQUE_SCANNERS.items():
            print(f"  {tech_id:12} - {info['name']}")
            print(f"               {info['description']}")
        print()
        return

    # Get domains
    domains = []
    if args.domain:
        domains.append(args.domain)
    if args.file:
        domains.extend(load_domains_from_file(args.file))

    if not domains:
        parser.error("No domains specified. Use domain argument or -f file")

    # Parse techniques
    techniques = None
    if args.techniques:
        techniques = [t.strip() for t in args.techniques.split(',')]
        invalid = [t for t in techniques if t not in TECHNIQUE_SCANNERS]
        if invalid:
            parser.error(f"Invalid techniques: {invalid}. Use --list-techniques to see available options.")

    # Run scanner
    scanner = WebHackingScanner(
        output_dir=Path(args.output),
        rate_limit=args.rate,
        user_agent=args.user_agent,
        techniques=techniques,
        verbose=not args.quiet,
        threads=args.threads
    )

    scanner.run(domains, resume=args.resume)


if __name__ == "__main__":
    main()
