#!/usr/bin/env python3
"""
Bug Bounty Scanner - Unified CLI
Main entry point for all scanning modes
"""

import sys
import argparse
from pathlib import Path

# Add tools to path
sys.path.insert(0, str(Path(__file__).parent / 'tools'))

def print_banner():
    """Print tool banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║         Bug Bounty Automation Suite v2.0                 ║
    ║     Intelligent · Continuous · Comprehensive             ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)


def create_parser():
    """Create argument parser with subcommands"""
    parser = argparse.ArgumentParser(
        description='Bug Bounty Scanner - Unified CLI for all scanning modes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Intelligent scanning (recommended for large subdomain lists)
  python scanner.py intelligent example.com -s subdomains.txt

  # Continuous 24/7 scanning
  python scanner.py continuous -c continuous_config.yaml

  # Deep comprehensive scan
  python scanner.py deep example.com -p amazon

  # Wiz reconnaissance methodology
  python scanner.py recon example.com --thorough

  # Quick subdomain discovery only
  python scanner.py discover example.com

For more help: python scanner.py <mode> --help
        '''
    )
    
    subparsers = parser.add_subparsers(dest='mode', help='Scanning mode')
    
    # === INTELLIGENT MODE ===
    intelligent_parser = subparsers.add_parser(
        'intelligent',
        help='Smart two-phase scanning with duplicate detection (80-85% faster)',
        description='Intelligent scanner: Quick scan all → Detect duplicates → Deep scan only unique targets'
    )
    intelligent_parser.add_argument('target', help='Target domain (e.g., example.com)')
    intelligent_parser.add_argument('-s', '--subdomains', required=True,
                                   help='File with subdomains (one per line)')
    intelligent_parser.add_argument('-o', '--output', default='./results/intelligent',
                                   help='Output directory (default: ./results/intelligent)')
    intelligent_parser.add_argument('-w', '--workers', type=int, default=5,
                                   help='Number of parallel workers for deep scan (default: 5)')
    intelligent_parser.add_argument('-u', '--username', required=False,
                                   help='HackerOne username (for program-specific User-Agent)')
    intelligent_parser.add_argument('--skip-deep', action='store_true',
                                   help='Skip deep scanning (quick scan only)')
    
    # === CONTINUOUS MODE ===
    continuous_parser = subparsers.add_parser(
        'continuous',
        help='24/7 automated scanning with database tracking',
        description='Continuous scanner: Runs forever, tracks changes, sends alerts for new findings'
    )
    continuous_parser.add_argument('-c', '--config', default='continuous_config.yaml',
                                  help='Configuration file (default: continuous_config.yaml)')
    continuous_parser.add_argument('--once', action='store_true',
                                  help='Run once and exit (don\'t loop)')
    
    # === DEEP MODE ===
    deep_parser = subparsers.add_parser(
        'deep',
        help='Comprehensive single-target scan with all tools',
        description='Deep scanner: Full vulnerability scanning, thorough but slower'
    )
    deep_parser.add_argument('target', help='Target domain')
    deep_parser.add_argument('-p', '--program', choices=['amazon', 'shopify', 'generic'],
                            default='generic', help='Bug bounty program preset')
    deep_parser.add_argument('-u', '--username', required=False,
                            help='HackerOne username (e.g., for Amazon: amazonvrpresearcher_yourh1username)')
    deep_parser.add_argument('--parallel', action='store_true',
                            help='Enable parallel scanning (faster)')
    deep_parser.add_argument('--workers', type=int, default=5,
                            help='Number of parallel workers (default: 5)')
    deep_parser.add_argument('--skip-web', action='store_true',
                            help='Skip web vulnerability scanning')
    deep_parser.add_argument('--skip-ports', action='store_true',
                            help='Skip port scanning')
    
    # === RECON MODE ===
    recon_parser = subparsers.add_parser(
        'recon',
        help='Wiz 5-phase reconnaissance methodology',
        description='Reconnaissance: Subdomain discovery, port scanning, tech detection, endpoint discovery'
    )
    recon_parser.add_argument('target', help='Target domain')
    recon_parser.add_argument('--quick', action='store_true',
                             help='Quick mode (faster, less thorough)')
    recon_parser.add_argument('--thorough', action='store_true',
                             help='Thorough mode (slower, more comprehensive)')
    recon_parser.add_argument('-o', '--output', default='./results/recon',
                             help='Output directory (default: ./results/recon)')
    
    # === DISCOVER MODE ===
    discover_parser = subparsers.add_parser(
        'discover',
        help='Fast subdomain and asset discovery only',
        description='Discovery: Quick subdomain enumeration and live host detection (no vulnerability scanning)'
    )
    discover_parser.add_argument('target', help='Target domain')
    discover_parser.add_argument('-o', '--output', default='./results/discovery',
                                help='Output directory (default: ./results/discovery)')
    discover_parser.add_argument('--tools', nargs='+',
                                choices=['subfinder', 'amass', 'assetfinder', 'all'],
                                default=['all'],
                                help='Tools to use (default: all)')
    
    return parser


def run_intelligent_mode(args):
    """Run intelligent scanner"""
    print("\n🧠 Starting Intelligent Scanner...")
    print(f"Target: {args.target}")
    print(f"Subdomains file: {args.subdomains}")
    print(f"Output: {args.output}")
    print(f"Workers: {args.workers}\n")
    
    from scanners.intelligent_scanner import IntelligentScanner
    
    # Load subdomains
    with open(args.subdomains) as f:
        subdomains = [line.strip() for line in f if line.strip()]
        
    print(f"Loaded {len(subdomains)} subdomains\n")
    
    # Create scanner
    scanner = IntelligentScanner(
        output_dir=Path(args.output),
        max_workers=args.workers
    )
    
    # Run scan
    scanner.scan_subdomains(args.target, subdomains)
    
    print("\n✅ Intelligent scan complete!")
    print(f"Results: {args.output}")


def run_continuous_mode(args):
    """Run continuous scanner"""
    print("\n🔄 Starting Continuous Scanner...")
    print(f"Config: {args.config}")
    
    from scanners.continuous_scanner import ContinuousScanner
    
    scanner = ContinuousScanner(Path(args.config))
    
    if args.once:
        print("Running single iteration...\n")
        # Run one iteration
        for target in scanner.targets:
            scanner.scan_target(target)
    else:
        print("Running continuously (Ctrl+C to stop)...\n")
        scanner.run_forever()


def run_deep_mode(args):
    """Run deep scanner"""
    print("\n🔍 Starting Deep Scanner...")
    print(f"Target: {args.target}")
    print(f"Program: {args.program}")
    
    from scanners.deep_scan import DeepScanner, DeepScanConfig
    
    # Create config
    config = DeepScanConfig(
        target=args.target,
        program=args.program,
        program_username=args.username,
        parallel=args.parallel,
        max_workers=args.workers,
        skip_web=args.skip_web,
        skip_ports=args.skip_ports
    )
    
    # Run scan
    scanner = DeepScanner(config)
    scanner.run()
    
    print("\n✅ Deep scan complete!")


def run_recon_mode(args):
    """Run Wiz reconnaissance"""
    print("\n🔎 Starting Wiz Reconnaissance...")
    print(f"Target: {args.target}")
    
    mode = 'thorough' if args.thorough else ('quick' if args.quick else 'normal')
    print(f"Mode: {mode}\n")
    
    from scanners.wiz_recon import WizReconScanner
    
    scanner = WizReconScanner(
        target=args.target,
        output_dir=Path(args.output)
    )
    
    if args.quick:
        scanner.run_quick_mode()
    elif args.thorough:
        scanner.run_thorough_mode()
    else:
        scanner.run()
        
    print("\n✅ Reconnaissance complete!")
    print(f"Results: {args.output}")


def run_discover_mode(args):
    """Run discovery mode"""
    print("\n🌐 Starting Asset Discovery...")
    print(f"Target: {args.target}")
    print(f"Tools: {', '.join(args.tools)}\n")
    
    from discovery.enhanced_subdomain_scanner import EnhancedSubdomainScanner
    
    scanner = EnhancedSubdomainScanner(
        domain=args.target,
        output_dir=Path(args.output)
    )
    
    # Run discovery
    subdomains = scanner.discover_all(tools=args.tools)
    
    print(f"\n✅ Discovered {len(subdomains)} subdomains!")
    print(f"Results: {args.output}")


def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Check mode
    if not args.mode:
        parser.print_help()
        sys.exit(1)
        
    # Route to appropriate mode
    try:
        if args.mode == 'intelligent':
            run_intelligent_mode(args)
        elif args.mode == 'continuous':
            run_continuous_mode(args)
        elif args.mode == 'deep':
            run_deep_mode(args)
        elif args.mode == 'recon':
            run_recon_mode(args)
        elif args.mode == 'discover':
            run_discover_mode(args)
        else:
            print(f"Unknown mode: {args.mode}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
