#!/usr/bin/env python3
"""
Bug Bounty Scanner - Main Entry Point
Run scans against Amazon VRP or Shopify Bug Bounty targets

Usage:
    python run_scan.py --program amazon --username yourh1name --targets www.amazon.com
    python run_scan.py --program shopify --username yourh1name --targets your-store.myshopify.com
    python run_scan.py --program amazon --username yourh1name --file targets.txt
    python run_scan.py --validate-only --program amazon --targets test.amazon.com

IMPORTANT:
- Set your HackerOne username with --username
- For Amazon: Rate limited to 5 req/sec, uses required User-Agent
- For Shopify: Only test stores YOU created
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime

# Add tools directory to path
sys.path.insert(0, str(Path(__file__).parent))

from config import get_amazon_config, get_shopify_config
from scanner import AmazonScanner, ShopifyScanner
from scope_validator import AmazonScopeValidator, ShopifyScopeValidator


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║                    BUG BOUNTY SCANNER                        ║
║              Amazon VRP & Shopify Bug Bounty                 ║
╠══════════════════════════════════════════════════════════════╣
║  IMPORTANT RULES:                                            ║
║  • Amazon: Max 5 req/sec, use amazonvrpresearcher_username   ║
║  • Shopify: Only test stores YOU created                     ║
║  • Both: Use @wearehackerone.com email for accounts          ║
╚══════════════════════════════════════════════════════════════╝
    """)


def load_targets_from_file(filepath: str) -> list:
    """Load targets from a file (one per line)"""
    targets = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
    except FileNotFoundError:
        print(f"[!] Error: File not found: {filepath}")
        sys.exit(1)
    return targets


def validate_targets(program: str, targets: list, username: str = None):
    """Validate targets against scope without scanning"""
    print(f"\n[*] Validating {len(targets)} targets for {program.upper()}")

    if program == 'amazon':
        config = get_amazon_config(username)
        validator = AmazonScopeValidator(config)
    else:
        config = get_shopify_config(username)
        validator = ShopifyScopeValidator(config)

    in_scope, out_of_scope = validator.filter_targets(targets)

    print(f"\n{'='*60}")
    print(f"VALIDATION RESULTS")
    print(f"{'='*60}")
    print(f"Total targets: {len(targets)}")
    print(f"In scope:      {len(in_scope)}")
    print(f"Out of scope:  {len(out_of_scope)}")

    if in_scope:
        print(f"\n[+] IN SCOPE ({len(in_scope)}):")
        for target in in_scope:
            is_valid, reason = validator.is_in_scope(target)
            print(f"    ✓ {target}")
            print(f"      {reason}")

    if out_of_scope:
        print(f"\n[!] OUT OF SCOPE ({len(out_of_scope)}):")
        for target, reason in out_of_scope:
            print(f"    ✗ {target}")
            print(f"      {reason}")

    return in_scope, out_of_scope


def run_amazon_scan(targets: list, username: str):
    """Run Amazon VRP scan"""
    print("\n" + "="*60)
    print("AMAZON VRP SCAN")
    print("="*60)

    config = get_amazon_config(username)
    scanner = AmazonScanner(config)

    print(f"\n[*] Configuration:")
    print(f"    User-Agent: {config.user_agent}")
    print(f"    Rate Limit: {config.rate_limit} requests/second")
    print(f"    Test Email: {config.test_email}")
    print(f"    Targets: {len(targets)}")

    # Confirm before scanning
    print(f"\n[?] Ready to scan {len(targets)} targets. Continue? (y/n): ", end="")
    try:
        confirm = input().strip().lower()
        if confirm != 'y':
            print("[*] Scan cancelled")
            return
    except:
        print("\n[*] Running in non-interactive mode, proceeding...")

    # Run scans
    results = scanner.scan_multiple(targets)

    # Print summary
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    print(f"Targets scanned: {len(results)}")
    total_findings = sum(len(r.findings) for r in results)
    print(f"Total findings: {total_findings}")

    # Categorize findings
    if total_findings > 0:
        print("\nFindings by severity:")
        severities = {}
        for result in results:
            for finding in result.findings:
                sev = finding.severity
                severities[sev] = severities.get(sev, 0) + 1
        for sev, count in sorted(severities.items()):
            print(f"  {sev}: {count}")

        print("\nFindings by type:")
        types = {}
        for result in results:
            for finding in result.findings:
                t = finding.vuln_type
                types[t] = types.get(t, 0) + 1
        for t, count in sorted(types.items(), key=lambda x: x[1], reverse=True):
            print(f"  {t}: {count}")

    # Save results
    output_path = scanner.save_results(results)

    # Print errors if any
    total_errors = sum(len(r.errors) for r in results)
    if total_errors > 0:
        print(f"\n[!] Total errors: {total_errors}")

    return results


def run_shopify_scan(targets: list, username: str):
    """Run Shopify bug bounty scan"""
    print("\n" + "="*60)
    print("SHOPIFY BUG BOUNTY SCAN")
    print("="*60)

    config = get_shopify_config(username)
    scanner = ShopifyScanner(config)

    print(f"\n[*] Configuration:")
    print(f"    User-Agent: {config.user_agent}")
    print(f"    Rate Limit: {config.rate_limit} requests/second")
    print(f"    Test Email: {config.test_email}")
    print(f"    Targets: {len(targets)}")

    print(f"\n[!] REMINDER: Only test stores YOU created!")
    print(f"    Partner signup: {config.partner_signup_url}")

    # Confirm before scanning
    print(f"\n[?] Ready to scan {len(targets)} targets. Continue? (y/n): ", end="")
    try:
        confirm = input().strip().lower()
        if confirm != 'y':
            print("[*] Scan cancelled")
            return
    except:
        print("\n[*] Running in non-interactive mode, proceeding...")

    # Run scans
    results = scanner.scan_multiple(targets)

    # Print summary
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    print(f"Targets scanned: {len(results)}")
    total_findings = sum(len(r.findings) for r in results)
    print(f"Total findings: {total_findings}")

    if total_findings > 0:
        print("\nFindings by severity:")
        severities = {}
        for result in results:
            for finding in result.findings:
                sev = finding.severity
                severities[sev] = severities.get(sev, 0) + 1
        for sev, count in sorted(severities.items()):
            print(f"  {sev}: {count}")

    # Save results
    output_path = scanner.save_results(results)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Bug Bounty Scanner for Amazon VRP and Shopify",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate targets only (no scanning)
  python run_scan.py --validate-only --program amazon --targets www.amazon.com api.amazon.in

  # Scan Amazon targets
  python run_scan.py --program amazon --username myh1user --targets www.amazon.com

  # Scan Shopify targets from file
  python run_scan.py --program shopify --username myh1user --file shopify_targets.txt

  # Scan with specific targets
  python run_scan.py --program amazon --username myh1user --targets www.amazon.com www.amazon.de

IMPORTANT:
  - For Amazon VRP: Rate limited to 5 req/sec, uses required User-Agent header
  - For Shopify: Only test stores YOU created via partners.shopify.com
  - Both programs: Use @wearehackerone.com email format for test accounts
        """
    )

    parser.add_argument('--program', '-p', choices=['amazon', 'shopify'],
                        required=True, help='Bug bounty program to scan')
    parser.add_argument('--username', '-u', default='yourh1username',
                        help='Your HackerOne username (for User-Agent and email)')
    parser.add_argument('--targets', '-t', nargs='+',
                        help='Target URLs/domains to scan')
    parser.add_argument('--file', '-f',
                        help='File containing targets (one per line)')
    parser.add_argument('--validate-only', '-v', action='store_true',
                        help='Only validate scope, do not scan')
    parser.add_argument('--list-scope', '-l', action='store_true',
                        help='List all in-scope assets for the program')

    args = parser.parse_args()

    print_banner()

    # Get targets
    targets = []
    if args.targets:
        targets.extend(args.targets)
    if args.file:
        targets.extend(load_targets_from_file(args.file))

    # List scope
    if args.list_scope:
        print(f"\n[*] In-scope assets for {args.program.upper()}:")
        if args.program == 'amazon':
            config = get_amazon_config(args.username)
            validator = AmazonScopeValidator(config)
        else:
            config = get_shopify_config(args.username)
            validator = ShopifyScopeValidator(config)

        for entry in validator.get_bounty_eligible()[:30]:
            env = f" ({entry.environment})" if entry.environment else ""
            print(f"  - {entry.identifier} [{entry.asset_type}]{env}")
        print(f"\n  ... and more. See scope CSV for full list.")
        return

    if not targets:
        parser.error("No targets specified. Use --targets or --file")

    # Validate only mode
    if args.validate_only:
        validate_targets(args.program, targets, args.username)
        return

    # Check username
    if args.username == 'yourh1username':
        print("[!] WARNING: Using default username 'yourh1username'")
        print("    Set your actual HackerOne username with --username")
        print()

    # Run scans
    if args.program == 'amazon':
        run_amazon_scan(targets, args.username)
    else:
        run_shopify_scan(targets, args.username)


if __name__ == "__main__":
    main()
