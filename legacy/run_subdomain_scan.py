#!/usr/bin/env python3
"""
Subdomain Scan Runner
Quick runner for subdomain scanning with clear output of what gets checked.
"""

import argparse
import sys
import warnings
from datetime import datetime
from pathlib import Path

warnings.filterwarnings('ignore')

# Add tools directory to path
sys.path.insert(0, str(Path(__file__).parent))

from enhanced_subdomain_scanner import (
    EnhancedSubdomainScanner,
    AmazonEnhancedScanner,
    ShopifyEnhancedScanner,
    generate_report,
    save_json_results,
    EXTENDED_WORDLIST,
    COMMON_PORTS,
)
from config import get_amazon_config, get_shopify_config


def print_scan_checklist():
    """Print what the scanner checks"""
    print("""
================================================================================
                      SUBDOMAIN SCANNER - SCAN CHECKLIST
================================================================================

PASSIVE RECONNAISSANCE SOURCES:
  [ ] crt.sh           - Certificate Transparency logs
  [ ] HackerTarget     - Subdomain search API
  [ ] BufferOver.run   - DNS records database
  [ ] AlienVault OTX   - Passive DNS data
  [ ] RapidDNS         - Subdomain enumeration
  [ ] ThreatCrowd      - Threat intelligence API
  [ ] URLScan.io       - Web scan archives
  [ ] CertSpotter      - Certificate monitoring

ACTIVE RECONNAISSANCE:
  [ ] DNS Brute-Force  - {} subdomain prefixes tested
  [ ] Recursive Scan   - Find sub-subdomains of discovered hosts

PER-SUBDOMAIN CHECKS:
  [ ] DNS Resolution   - Get all IP addresses
  [ ] HTTP Check       - Test port 80 connectivity
  [ ] HTTPS Check      - Test port 443 connectivity
  [ ] Title Extract    - Page title from response
  [ ] Server Header    - Web server identification
  [ ] Technology       - Framework/CMS detection
  [ ] SSL Certificate  - Certificate details (issuer, expiry, SAN)
  [ ] Response Hash    - Content fingerprint for comparison
  [ ] Redirect Check   - Follow and record redirects

OPTIONAL PORT SCANNING (--check-ports):
  [ ] FTP (21)         [ ] SSH (22)          [ ] Telnet (23)
  [ ] SMTP (25)        [ ] DNS (53)          [ ] HTTP (80)
  [ ] POP3 (110)       [ ] IMAP (143)        [ ] HTTPS (443)
  [ ] SMB (445)        [ ] IMAPS (993)       [ ] POP3S (995)
  [ ] MySQL (3306)     [ ] RDP (3389)        [ ] PostgreSQL (5432)
  [ ] VNC (5900)       [ ] Redis (6379)      [ ] HTTP-Alt (8080)
  [ ] HTTPS-Alt (8443) [ ] Elasticsearch (9200)  [ ] MongoDB (27017)

TECHNOLOGY DETECTION:
  - Web Servers: nginx, Apache, IIS, Cloudflare
  - Languages: PHP, ASP.NET, Express.js
  - CMS: WordPress, Drupal, Joomla, Shopify
  - Frameworks: React, Vue.js, Angular, Next.js
  - Cloud: AWS, Azure indicators

SCOPE VALIDATION (when --program specified):
  [ ] Amazon VRP rules - Exclude aws/a2z/dev/test/staging patterns
  [ ] Shopify rules    - Core vs non-core asset classification

================================================================================
""".format(len(EXTENDED_WORDLIST)))


def run_scan(domain: str, program: str = None, username: str = "yourh1username",
             dns_bruteforce: bool = True, recursive: bool = True,
             check_ports: bool = False, output: str = None):
    """Run the subdomain scan"""

    # Select scanner based on program
    if program == "amazon":
        config = get_amazon_config(username)
        scanner = AmazonEnhancedScanner(config)
        print(f"[*] Using Amazon VRP configuration")
        print(f"[*] User-Agent: {config.user_agent}")
        print(f"[*] Rate Limit: {config.rate_limit} req/s")
    elif program == "shopify":
        config = get_shopify_config(username)
        scanner = ShopifyEnhancedScanner(config)
        print(f"[*] Using Shopify configuration")
        print(f"[*] Rate Limit: {config.rate_limit} req/s")
    else:
        scanner = EnhancedSubdomainScanner()
        print(f"[*] Using generic scanner configuration")

    # Run the discovery
    if program in ["amazon", "shopify"]:
        result = scanner.run_discovery_with_scope(
            domain,
            dns_bruteforce=dns_bruteforce,
            recursive=recursive,
            check_ports=check_ports,
        )
    else:
        result = scanner.run_discovery(
            domain,
            dns_bruteforce=dns_bruteforce,
            recursive=recursive,
            check_ports=check_ports,
        )

    return result


def print_final_summary(result):
    """Print a clear final summary"""
    print("\n" + "=" * 70)
    print("                         SCAN RESULTS SUMMARY")
    print("=" * 70)

    print(f"""
TARGET DOMAIN: {result.target_domain}
SCAN DURATION: {result.scan_start} to {result.scan_end}

DISCOVERY RESULTS:
  Total Unique Subdomains Found: {result.unique_subdomains}
  Live (Responding) Subdomains:  {result.live_subdomains}
  Dead/Unreachable Subdomains:   {result.unique_subdomains - result.live_subdomains}
""")

    if result.in_scope_count > 0 or result.out_of_scope_count > 0:
        print(f"""SCOPE VALIDATION:
  In-Scope Targets:    {result.in_scope_count}
  Out-of-Scope:        {result.out_of_scope_count}
""")

    print(f"""SOURCES CHECKED:
  Successful: {', '.join(result.sources_successful) or 'None'}
  Failed:     {', '.join(result.sources_failed) or 'None'}
""")

    # List live subdomains
    live_subs = [(s, i) for s, i in result.subdomains.items() if i.is_alive]
    if live_subs:
        print("LIVE SUBDOMAINS:")
        print("-" * 70)

        # Group by status
        for subdomain, info in sorted(live_subs, key=lambda x: x[0]):
            status = info.https_status or info.http_status or "?"
            scope = "[IN-SCOPE]" if info.in_scope else "[OUT-OF-SCOPE]"
            title = f" | {info.title[:40]}" if info.title else ""
            techs = f" | Tech: {', '.join(info.technologies[:2])}" if info.technologies else ""
            print(f"  {subdomain}")
            print(f"    Status: {status} {scope}{title}{techs}")

    # Show ports if any found
    ports_found = [(s, i) for s, i in result.subdomains.items() if i.open_ports]
    if ports_found:
        print("\nOPEN PORTS DETECTED:")
        print("-" * 70)
        for subdomain, info in sorted(ports_found, key=lambda x: x[0]):
            ports_str = ", ".join(f"{p}({s})" for p, s in info.open_ports)
            print(f"  {subdomain}: {ports_str}")

    # Stats
    print("\n" + "-" * 70)
    print("STATISTICS:")

    # Technology breakdown
    all_techs = []
    for info in result.subdomains.values():
        all_techs.extend(info.technologies)
    if all_techs:
        from collections import Counter
        tech_counts = Counter(all_techs)
        print(f"  Technologies Detected: {', '.join(f'{t}({c})' for t, c in tech_counts.most_common(5))}")

    # Server breakdown
    servers = [i.server for i in result.subdomains.values() if i.server]
    if servers:
        from collections import Counter
        server_counts = Counter(servers)
        print(f"  Servers: {', '.join(f'{s}({c})' for s, c in server_counts.most_common(3))}")

    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Subdomain Scanner - Run comprehensive subdomain discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s amazon.com -p amazon -u myh1user
  %(prog)s shopify.com -p shopify --check-ports
  %(prog)s target.com -o results/target_scan
  %(prog)s --list-checks
        """
    )

    parser.add_argument("domain", nargs="?", help="Target domain to scan")
    parser.add_argument("--program", "-p", choices=["amazon", "shopify"],
                        help="Bug bounty program for scope rules")
    parser.add_argument("--username", "-u", default="yourh1username",
                        help="HackerOne username (default: yourh1username)")
    parser.add_argument("--no-bruteforce", action="store_true",
                        help="Skip DNS brute-force")
    parser.add_argument("--no-recursive", action="store_true",
                        help="Skip recursive discovery")
    parser.add_argument("--check-ports", action="store_true",
                        help="Enable port scanning")
    parser.add_argument("--output", "-o",
                        help="Output file prefix (creates .txt and .json)")
    parser.add_argument("--list-checks", action="store_true",
                        help="Show what the scanner checks")

    args = parser.parse_args()

    if args.list_checks:
        print_scan_checklist()
        return 0

    if not args.domain:
        parser.print_help()
        return 1

    print(f"\n[*] Starting Enhanced Subdomain Scan")
    print(f"[*] Target: {args.domain}")
    print(f"[*] Time: {datetime.utcnow().isoformat()}")

    result = run_scan(
        domain=args.domain,
        program=args.program,
        username=args.username,
        dns_bruteforce=not args.no_bruteforce,
        recursive=not args.no_recursive,
        check_ports=args.check_ports,
        output=args.output,
    )

    # Print summary
    print_final_summary(result)

    # Save outputs
    if args.output:
        generate_report(result, f"{args.output}.txt")
        save_json_results(result, f"{args.output}.json")
        print(f"\n[*] Results saved to {args.output}.txt and {args.output}.json")

    return 0


if __name__ == "__main__":
    sys.exit(main())
