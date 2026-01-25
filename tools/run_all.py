#!/usr/bin/env python3
"""
Unified runner to execute the full pipeline in one command.

This script combines:
  1) Deep scan (recon + discovery + fuzzing)
  2) Web Hacking 2025 technique scanner

Modes:
  - Sequential (default): Find all subdomains first, then scan each
  - Parallel (--parallel): Scan subdomains AS THEY ARE DISCOVERED

It is designed to be a single "run everything" entry point.
"""

import argparse
import sys
from pathlib import Path
from typing import List, Dict
from urllib.parse import urlparse

# Add tools directory to path
sys.path.insert(0, str(Path(__file__).parent))

from deep_scan import DeepScanner, DeepScanConfig
from web_hacking_2025.scanner import WebHackingScanner, load_domains_from_file
from web_hacking_2025.bugbounty_config import get_program_config, ScopeValidator
from parallel_scan import ParallelScanner


def normalize_domain(value: str) -> str:
    """Normalize input to a bare domain (no scheme/path)."""
    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)
        return parsed.netloc
    return value.split("/")[0]


def collect_targets(positional: str, file_path: str, targets: List[str]) -> List[str]:
    """Collect targets from positional, file, and --targets."""
    all_targets = []
    if positional:
        all_targets.append(positional)
    if targets:
        all_targets.extend(targets)
    if file_path:
        all_targets.extend(load_domains_from_file(file_path))
    return [t for t in all_targets if t]


def run_deep_scan(args: argparse.Namespace) -> Dict:
    # Create target-specific output folders
    if len(args.targets_list) == 1:
        safe_target = normalize_domain(args.targets_list[0]).replace("://", "_").replace("/", "_").replace(":", "_")
        deep_output = Path(args.output) / safe_target / "deep_scan"
    else:
        deep_output = Path(args.output) / "deep_scan"
    deep_config = DeepScanConfig(
        targets=args.targets_list,
        program=args.program,
        username=args.username,
        output_dir=deep_output,
        skip_subdomains=args.skip_subdomains,
        skip_ports=args.skip_ports,
        skip_endpoints=args.skip_endpoints,
        skip_tech=args.skip_tech,
        skip_js=args.skip_js,
        skip_fuzz=args.skip_fuzz,
        skip_recursive=args.skip_recursive,
        extended_wordlist=not args.no_extended_wordlist,
        custom_wordlist=Path(args.wordlist) if args.wordlist else None,
        verbose=args.verbose,
    )

    scanner = DeepScanner(deep_config)
    return scanner.run()


def derive_scan_domains(deep_results: Dict, args: argparse.Namespace) -> List[str]:
    if not args.scan_discovered or not deep_results:
        return [normalize_domain(t) for t in args.targets_list]

    discovered = set()
    for result in deep_results.values():
        for sub, info in result.subdomains.items():
            if info.get("is_alive") and (info.get("in_scope") or args.program is None):
                discovered.add(sub)

        if not discovered:
            discovered.add(result.target)

    return sorted(discovered)


def run_web_scanner(domains: List[str], args: argparse.Namespace):
    # Create target-specific output folders for single target
    if len(domains) == 1:
        safe_domain = domains[0].replace("://", "_").replace("/", "_").replace(":", "_")
        web_output = Path(args.output) / safe_domain / "web_hacking_2025"
    else:
        web_output = Path(args.output) / "web_hacking_2025"
    web_output.mkdir(parents=True, exist_ok=True)

    rate_limit = args.rate
    user_agent = args.user_agent

    if args.program:
        program = get_program_config(args.program)
        if rate_limit is None:
            rate_limit = program.rate_limit
        if user_agent is None:
            user_agent = program.get_user_agent(args.username or "researcher")

        if args.validate_scope:
            validator = ScopeValidator(program)
            domains = validator.filter_domains(domains)
            if not domains:
                print("[-] No in-scope domains after validation. Aborting web scanner.")
                return

    techniques = None
    if args.techniques:
        techniques = [t.strip() for t in args.techniques.split(",") if t.strip()]

    scanner = WebHackingScanner(
        output_dir=web_output,
        rate_limit=rate_limit or 5.0,
        user_agent=user_agent or "Mozilla/5.0 (compatible; SecurityResearch/1.0)",
        techniques=techniques,
        verbose=not args.quiet,
        threads=args.threads,
    )

    scanner.run(domains, resume=args.resume)


def run_parallel_scan(args: argparse.Namespace):
    """Run parallel subdomain discovery + vulnerability scanning.

    This mode scans subdomains AS THEY ARE DISCOVERED, rather than
    waiting for all discovery to complete first.
    """
    print("\n" + "=" * 70)
    print("  PARALLEL MODE: Scanning subdomains as they are discovered")
    print("=" * 70 + "\n")

    techniques = None
    if args.techniques:
        techniques = [t.strip() for t in args.techniques.split(",") if t.strip()]

    skip_phases = {
        'skip_subdomains': args.skip_subdomains,
        'skip_recursive': args.skip_recursive,
    }

    scanner = ParallelScanner(
        targets=args.targets_list,
        output_dir=Path(args.output),
        program=args.program,
        username=args.username,
        num_workers=args.workers,
        techniques=techniques,
        skip_phases=skip_phases
    )

    results = scanner.run()
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Unified runner for deep_scan + web_hacking_2025",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run everything on a single target
  python run_all.py example.com -p amazon -u myh1user

  # Run everything from a file
  python run_all.py -f targets.txt -p shopify -u myh1user

  # Use discovered subdomains for technique scanning
  python run_all.py example.com --scan-discovered

  # Skip deep scan, run only technique scanner
  python run_all.py example.com --skip-deep

  # PARALLEL MODE: Scan subdomains as they are discovered (recommended)
  python run_all.py example.com --parallel --workers 5 -p amazon -u myh1user

  # Parallel mode with 10 workers for faster scanning
  python run_all.py -f targets.txt --parallel --workers 10
        """,
    )

    parser.add_argument("target", nargs="?", help="Target domain (e.g., example.com)")
    parser.add_argument("-f", "--file", help="File containing targets (one per line)")
    parser.add_argument("-t", "--targets", nargs="+", help="Additional targets")

    parser.add_argument("-p", "--program", choices=["amazon", "shopify", "generic"], help="Bug bounty program")
    parser.add_argument("-u", "--username", default="yourh1username", help="HackerOne username")
    parser.add_argument("-o", "--output", default="./combined_results", help="Output directory")

    # Deep scan controls
    parser.add_argument("--skip-deep", action="store_true", help="Skip deep scan phase")
    parser.add_argument("--skip-subdomains", action="store_true", help="Skip subdomain discovery")
    parser.add_argument("--skip-ports", action="store_true", help="Skip port scanning")
    parser.add_argument("--skip-endpoints", action="store_true", help="Skip endpoint discovery")
    parser.add_argument("--skip-tech", action="store_true", help="Skip technology detection")
    parser.add_argument("--skip-js", action="store_true", help="Skip JavaScript analysis")
    parser.add_argument("--skip-fuzz", action="store_true", help="Skip parameter fuzzing")
    parser.add_argument("--skip-recursive", action="store_true", help="Skip recursive subdomain discovery")
    parser.add_argument("--wordlist", help="Custom subdomain wordlist file")
    parser.add_argument("--no-extended-wordlist", action="store_true", help="Use minimal wordlist")
    parser.add_argument("--scan-discovered", action="store_true", help="Scan alive discovered subdomains")

    # Web scanner controls
    parser.add_argument("--skip-web", action="store_true", help="Skip web_hacking_2025 scanner")
    parser.add_argument("--techniques", help="Comma-separated list of techniques")
    parser.add_argument("--rate", type=float, default=None, help="Rate limit for technique scanner")
    parser.add_argument("--user-agent", default=None, help="Custom user agent for technique scanner")
    parser.add_argument("--resume", action="store_true", help="Resume previous technique scan")
    parser.add_argument("--threads", type=int, default=3, help="Technique scanner threads")
    parser.add_argument("-q", "--quiet", action="store_true", help="Reduce technique scanner verbosity")
    parser.add_argument("--validate-scope", action="store_true", help="Validate scope before technique scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose deep scan output")

    # Parallel mode options
    parser.add_argument("--parallel", action="store_true",
                        help="Enable parallel mode: scan subdomains as they are discovered")
    parser.add_argument("-w", "--workers", type=int, default=3,
                        help="Number of parallel scanning workers (default: 3, only used with --parallel)")

    args = parser.parse_args()
    args.targets_list = collect_targets(args.target, args.file, args.targets)

    if not args.targets_list:
        parser.error("No targets specified. Use positional target, --targets, or --file.")

    # Check for parallel mode
    if args.parallel:
        # Parallel mode: scan subdomains as they are discovered
        run_parallel_scan(args)
    else:
        # Sequential mode (original behavior)
        # Run deep scan
        deep_results = {}
        if not args.skip_deep:
            deep_results = run_deep_scan(args)

        # Run web techniques scan
        if not args.skip_web:
            domains = derive_scan_domains(deep_results, args)
            run_web_scanner(domains, args)


if __name__ == "__main__":
    main()

