#!/usr/bin/env python3
"""
Bug Bounty Scanner - Unified Config-Driven CLI
================================================

Single entry point for all scanning modes.
Everything is controlled via scan_config.yaml - no complex CLI args needed.

Usage:
    python scanner.py                          # Uses ./scan_config.yaml
    python scanner.py -c /path/to/config.yaml  # Custom config path
"""

import sys
import signal
import argparse
from pathlib import Path

import yaml

# Add tools to path
sys.path.insert(0, str(Path(__file__).parent / 'tools'))


# Graceful shutdown
SHUTDOWN = False


def _signal_handler(signum, frame):
    global SHUTDOWN
    if SHUTDOWN:
        print("\n[!] Force exit...")
        sys.exit(1)
    print("\n\n[!] Shutdown requested. Finishing current task...")
    print("[!] Press Ctrl+C again to force exit")
    SHUTDOWN = True


signal.signal(signal.SIGINT, _signal_handler)


def safe_print(text):
    """Print text, falling back to ASCII if Unicode fails"""
    try:
        print(text)
    except UnicodeEncodeError:
        ascii_text = text.encode('ascii', 'ignore').decode('ascii')
        print(ascii_text)


def load_config(config_path: Path) -> dict:
    """Load and validate the unified scan configuration."""
    if not config_path.exists():
        safe_print(f"[!] Config file not found: {config_path}")
        safe_print(f"    Create one from template:  cp scan_config.yaml.test scan_config.yaml")
        sys.exit(1)

    with open(config_path) as f:
        config = yaml.safe_load(f) or {}

    return config


def resolve_targets(config: dict) -> list:
    """Resolve target list from config (supports multiple formats)."""
    targets = []
    
    # Format 1: full_recon.yaml style - general.targets as list
    if 'general' in config:
        general = config['general']
        general_targets = general.get('targets', [])
        if isinstance(general_targets, list):
            targets.extend(general_targets)
    
    # Format 2: old scanner.py style - targets.domains as list
    elif 'targets' in config:
        targets_cfg = config['targets']
        
        # Handle if targets is a dict with 'domains' key
        if isinstance(targets_cfg, dict):
            # From domains list
            domains = targets_cfg.get('domains', [])
            if domains:
                targets.extend(domains)
            
            # From targets file
            targets_file = targets_cfg.get('targets_file')
            if targets_file:
                p = Path(targets_file)
                if p.exists():
                    with open(p) as f:
                        targets.extend([line.strip() for line in f if line.strip()])
                else:
                    safe_print(f"[!] Targets file not found: {targets_file}")
        
        # Handle if targets is directly a list
        elif isinstance(targets_cfg, list):
            targets.extend(targets_cfg)
    
    return targets


def resolve_subdomains(config: dict) -> list:
    """Load pre-discovered subdomains if provided."""
    targets_cfg = config.get('targets', {})
    subs_file = targets_cfg.get('subdomains_file')
    if subs_file:
        p = Path(subs_file)
        if p.exists():
            with open(p) as f:
                return [line.strip() for line in f if line.strip()]
    return []


def print_config_summary(config: dict, targets: list):
    """Print a summary of the scan configuration."""
    # Handle both old and new config formats
    if 'general' in config:
        # full_recon.yaml format
        general = config.get('general', {})
        performance = config.get('performance', {})
        mode = config.get('scan_mode', 'fullrecon')
        program = general.get('program')  # Can be string or None
        username = general.get('h1_username', 'N/A')
        rate_limit = performance.get('rate_limit', 10)
        output_dir = general.get('output_dir', 'results')
        workers = performance.get('max_workers', 10)
    else:
        # Old scanner.py format
        mode = config.get('scan_mode', 'deep')
        
        # Handle program as either string or dict
        program_cfg = config.get('program', {})
        if isinstance(program_cfg, str):
            program = program_cfg
            username = config.get('h1_username', 'N/A')
        elif isinstance(program_cfg, dict):
            program = program_cfg.get('name')
            username = program_cfg.get('h1_username', 'N/A')
        else:
            program = None
            username = 'N/A'
        
        rate_limit = config.get('network', {}).get('rate_limit', 10)
        output_dir = config.get('output', {}).get('directory', 'results')
        workers = config.get('workers', {}).get('max_workers', 10)

    print(f"\n{'='*70}")
    print(f"  BUG BOUNTY SCANNER")
    print(f"{'='*70}")
    print(f"  Mode:        {mode}")
    print(f"  Targets:     {len(targets)} ({', '.join(targets[:3])}{'...' if len(targets) > 3 else ''})")
    print(f"  Program:     {program or 'generic'}")
    print(f"  Username:    {username}")
    print(f"  Rate Limit:  {rate_limit} req/s")
    print(f"  Workers:     {workers}")
    print(f"  Output:      {output_dir}")

    # Show enabled phases
    phases = config.get('phases', {})
    enabled = [name for name, cfg in phases.items()
               if isinstance(cfg, dict) and cfg.get('enabled', True)]
    disabled = [name for name, cfg in phases.items()
                if isinstance(cfg, dict) and not cfg.get('enabled', True)]

    if enabled:
        print(f"  Phases ON:   {', '.join(enabled)}")
    if disabled:
        print(f"  Phases OFF:  {', '.join(disabled)}")

    print(f"{'='*70}\n")


def confirm_scan(config: dict) -> bool:
    """Ask for confirmation if safety.confirm_before_run is true."""
    safety = config.get('safety', {})
    if safety.get('confirm_before_run', False):
        try:
            answer = input("Proceed with scan? [y/N]: ").strip().lower()
            return answer == 'y'
        except EOFError:
            return True
    return True


# =============================================================================
# SCAN MODE RUNNERS
# =============================================================================


def run_deep_mode(config: dict, targets: list, config_path: Path = None):
    """Run deep comprehensive scan."""
    from scanners.deep_scan import DeepScanner, DeepScanConfig

    # Detect config format and extract settings
    if 'general' in config:
        # full_recon.yaml format
        general = config.get('general', {})
        performance = config.get('performance', {})
        phases = config.get('phases', {})
        limits = config.get('limits', {})
        
        program = general.get('program')
        username = general.get('h1_username', 'yourh1username')
        custom_headers = general.get('custom_headers', {})
        output_dir = Path(general.get('output_dir', 'results')) / 'deep'
        rate_limit = performance.get('rate_limit', 0)
        request_delay = performance.get('request_delay', 0)
    else:
        # Old scanner.py format
        phases = config.get('phases', {})
        limits = config.get('limits', {})
        network = config.get('network', {})
        output_cfg = config.get('output', {})
        
        # Handle program as string or dict
        program_cfg = config.get('program', {})
        if isinstance(program_cfg, str):
            program = program_cfg
            username = config.get('h1_username', 'yourh1username')
            custom_headers = config.get('custom_headers', {})
        elif isinstance(program_cfg, dict):
            program = program_cfg.get('name')
            username = program_cfg.get('h1_username', 'yourh1username')
            custom_headers = program_cfg.get('custom_headers', {})
        else:
            program = None
            username = 'yourh1username'
            custom_headers = {}
        
        output_dir = Path(output_cfg.get('directory', 'results')) / 'deep'
        rate_limit = network.get('rate_limit', 0)
        request_delay = network.get('request_delay', 0)

    scan_config = DeepScanConfig(
        targets=targets,
        program=program,
        username=username,
        output_dir=output_dir,
        # Phase control from config
        skip_subdomains=not phases.get('subdomain_discovery', {}).get('enabled', True),
        skip_ports=not phases.get('port_scanning', {}).get('enabled', True),
        skip_endpoints=not phases.get('endpoint_discovery', {}).get('enabled', True),
        skip_tech=not phases.get('tech_detection', {}).get('enabled', True),
        skip_js=not phases.get('js_analysis', {}).get('enabled', True),
        skip_fuzz=not phases.get('param_fuzzing', {}).get('enabled', True),
        skip_cloud=not phases.get('cloud_enumeration', {}).get('enabled', True),
        skip_waf=not phases.get('waf_detection', {}).get('enabled', True),
        skip_recursive=not config.get('scope', {}).get('recursive', True),
        skip_verification=not phases.get('verification', {}).get('enabled', True),
        # Verification
        verification_threads=phases.get('verification', {}).get('threads', 10),
        verify_only_high_priority=phases.get('verification', {}).get('verify_only_high_priority', False),
        test_default_credentials=phases.get('verification', {}).get('test_default_credentials', False),
        # Limits
        max_subdomains=limits.get('max_subdomains', 0),
        max_endpoints=limits.get('max_endpoints', 0),
        max_js_files=limits.get('max_js_files', 0),
        max_fuzz_urls=limits.get('max_fuzz_urls', 0),
        # Port scanning
        full_port_scan=phases.get('port_scanning', {}).get('full_scan', True),
        # Wordlist
        extended_wordlist=phases.get('subdomain_discovery', {}).get('use_extended_wordlist', True),
        custom_wordlist=Path(phases.get('subdomain_discovery', {}).get('custom_wordlist')) if phases.get('subdomain_discovery', {}).get('custom_wordlist') else None,
        # Output
        verbose=config.get('output', {}).get('verbose', True) if 'output' in config else True,
        save_json=config.get('output', {}).get('save_json', True) if 'output' in config else True,
        save_txt=config.get('output', {}).get('save_txt', True) if 'output' in config else True,
        # Network overrides
        custom_headers=custom_headers,
        custom_rate_limit=float(rate_limit),
        custom_request_delay=float(request_delay),
        custom_timeout=0,  # No timeouts
        # Pass config file path for Nuclei and advanced features
        config_file=config_path,
    )

    # Store the full config dict on the scan_config so scanners can access it
    scan_config._full_config = config

    scanner = DeepScanner(scan_config)
    scanner.run()

    safe_print("\n[+] Deep scan complete!")


def run_fullrecon_mode(config: dict, targets: list):
    """Run full reconnaissance pipeline."""
    from scanners.full_recon import FullReconScanner, FullReconConfig

    output_dir = Path(config.get('output', {}).get('directory', 'results')) / 'fullrecon'

    # Build the full_recon config dict from our unified config
    recon_cfg = _build_fullrecon_config(config)

    fr_config = FullReconConfig(
        targets=targets,
        config=recon_cfg,
        output_dir=output_dir,
    )

    scanner = FullReconScanner(fr_config)
    scanner.run()

    safe_print("\n[+] Full reconnaissance complete!")


def _build_fullrecon_config(config: dict) -> dict:
    """Translate unified config into full_recon.py config format."""
    phases = config.get('phases', {})
    network = config.get('network', {})
    program_cfg = config.get('program', {})
    advanced = config.get('advanced', {})

    return {
        'general': {
            'program': program_cfg.get('name'),
            'h1_username': program_cfg.get('h1_username'),
            'targets': [],  # Already passed separately
            'custom_headers': program_cfg.get('custom_headers', {}),
            'output_dir': str(Path(config.get('output', {}).get('directory', 'results')) / 'fullrecon'),
            'notifications': config.get('notifications', {}),
            'diff_mode': False,
        },
        'performance': {
            'rate_limit': network.get('rate_limit', 150),
            'request_delay': network.get('request_delay', 0),
            'request_timeout': 0,  # No timeout
            'max_workers': config.get('workers', {}).get('max_workers', 10),
            'threads': config.get('workers', {}).get('tool_threads', {}),
            'adaptive': {
                'enabled': network.get('adaptive_rate_limit', True),
                'backoff_on_429': True,
                'backoff_on_503': True,
                'max_retries': network.get('max_retries', 3),
                'backoff_multiplier': network.get('backoff_multiplier', 2.0),
            },
        },
        'osint': {
            'enabled': phases.get('osint', {}).get('enabled', True),
            'whois': {'enabled': phases.get('osint', {}).get('whois', True)},
            'email_harvesting': {'enabled': phases.get('osint', {}).get('email_harvesting', True)},
            'google_dorking': {'enabled': phases.get('osint', {}).get('google_dorking', True)},
        },
        'subdomains': {
            'enabled': phases.get('subdomain_discovery', {}).get('enabled', True),
        },
        'host_analysis': {
            'enabled': phases.get('port_scanning', {}).get('enabled', True),
        },
        'web_analysis': {
            'enabled': phases.get('endpoint_discovery', {}).get('enabled', True),
        },
        'vulnerability_scan': {
            'enabled': phases.get('vulnerability_scanning', {}).get('enabled', True),
        },
        'verification': {
            'enabled': phases.get('verification', {}).get('enabled', True),
            'threads': phases.get('verification', {}).get('threads', 10),
        },
        'chaining': {
            'enabled': phases.get('vuln_chaining', {}).get('enabled', True),
            'chains': phases.get('vuln_chaining', {}).get('chains', {}),
        },
        'reporting': {
            'enabled': phases.get('reporting', {}).get('enabled', True),
            'formats': {
                'json': config.get('output', {}).get('save_json', True),
                'txt': config.get('output', {}).get('save_txt', True),
                'html': config.get('output', {}).get('save_html', False),
                'csv': config.get('output', {}).get('save_csv', False),
            },
            'scoring': {'hotlist': True},
        },
        'safety': config.get('safety', {}),
    }


def run_intelligent_mode(config: dict, targets: list):
    """Run intelligent two-phase scanner."""
    from scanners.intelligent_scanner import IntelligentScanner

    workers = config.get('workers', {}).get('scan_workers', 5)
    output_dir = Path(config.get('output', {}).get('directory', 'results')) / 'intelligent'

    # Load subdomains (required for intelligent mode)
    subdomains = resolve_subdomains(config)
    if not subdomains:
        # If no subdomains file, use targets as subdomains
        subdomains = targets
        safe_print("[*] No subdomains file provided, using target domains directly")

    target = targets[0] if targets else 'unknown'

    safe_print(f"[*] Loaded {len(subdomains)} subdomains for intelligent scanning")

    scanner = IntelligentScanner(
        output_dir=output_dir,
        max_workers=workers
    )

    scanner.scan_subdomains(target, subdomains)

    safe_print("\n[+] Intelligent scan complete!")


def run_continuous_mode(config: dict, targets: list):
    """Run continuous 24/7 scanner."""
    from scanners.continuous_scanner import ContinuousScanner

    output_dir = Path(config.get('output', {}).get('directory', 'results')) / 'continuous'
    continuous_cfg = config.get('continuous', {})

    # Build continuous scanner config
    cont_config = {
        'scanning': {
            'targets': targets,
            'output_dir': str(output_dir),
            'scan_interval': continuous_cfg.get('scan_interval', 3600),
            'max_cpu': continuous_cfg.get('max_cpu', 80),
            'max_memory': continuous_cfg.get('max_memory', 80),
        },
        'phases': {
            'reconnaissance': config.get('phases', {}).get('subdomain_discovery', {}).get('enabled', True),
            'vulnerability_scanning': config.get('phases', {}).get('vulnerability_scanning', {}).get('enabled', True),
        },
        'tools': {
            'nuclei': config.get('phases', {}).get('vulnerability_scanning', {}).get('nuclei', {}).get('enabled', True),
        },
        'nuclei': {
            'severity': config.get('phases', {}).get('vulnerability_scanning', {}).get('nuclei', {}).get('severity', ['critical', 'high', 'medium']),
            'tags': config.get('phases', {}).get('vulnerability_scanning', {}).get('nuclei', {}).get('tags', []),
        },
        'notifications': config.get('notifications', {}),
    }

    # Write temp config for continuous scanner
    import tempfile
    import json
    temp_cfg = Path(output_dir) / '_continuous_config.yaml'
    temp_cfg.parent.mkdir(parents=True, exist_ok=True)
    with open(temp_cfg, 'w') as f:
        yaml.dump(cont_config, f, default_flow_style=False)

    scanner = ContinuousScanner(temp_cfg)

    safe_print("[*] Running continuously (Ctrl+C to stop)...")
    scanner.run_forever()


def run_recon_mode(config: dict, targets: list):
    """Run Wiz 5-phase reconnaissance."""
    from scanners.wiz_recon import WizReconScanner, save_results

    program = config.get('program', {}).get('name')
    username = config.get('program', {}).get('h1_username', 'yourh1username')
    thoroughness = config.get('phases', {}).get('dns_enumeration', {}).get('thoroughness', 'medium')
    output_dir = Path(config.get('output', {}).get('directory', 'results')) / 'recon'

    scanner = WizReconScanner(
        program=program,
        username=username,
        thoroughness=thoroughness
    )

    for target in targets:
        if SHUTDOWN:
            break
        result = scanner.scan(target)
        save_results(result, output_dir)

    safe_print("\n[+] Reconnaissance complete!")


def run_discover_mode(config: dict, targets: list):
    """Run fast subdomain/asset discovery only."""
    from discovery.enhanced_subdomain_scanner import EnhancedSubdomainScanner

    output_dir = Path(config.get('output', {}).get('directory', 'results')) / 'discovery'

    for target in targets:
        if SHUTDOWN:
            break
        safe_print(f"[*] Discovering assets for: {target}")
        scanner = EnhancedSubdomainScanner(
            domain=target,
            output_dir=output_dir
        )
        subdomains = scanner.discover_all(tools=['all'])
        safe_print(f"[+] Discovered {len(subdomains)} subdomains for {target}")

    safe_print("\n[+] Discovery complete!")


def run_parallel_mode(config: dict, targets: list):
    """Run parallel streaming scanner."""
    from scanners.parallel_scan import ParallelScanner

    program = config.get('program', {}).get('name')
    username = config.get('program', {}).get('h1_username', 'yourh1username')
    workers = config.get('workers', {}).get('scan_workers', 3)
    output_dir = Path(config.get('output', {}).get('directory', 'results')) / 'parallel'

    # Get enabled techniques from config
    techniques = None
    wh2025 = config.get('advanced', {}).get('web_hacking_2025', {})
    if wh2025.get('enabled', True):
        techs = wh2025.get('techniques', {})
        techniques = [name for name, enabled in techs.items() if enabled]

    scanner = ParallelScanner(
        targets=targets,
        output_dir=output_dir,
        program=program,
        username=username,
        num_workers=workers,
        techniques=techniques,
    )

    scanner.run()

    safe_print("\n[+] Parallel scan complete!")


# =============================================================================
# MODE DISPATCH
# =============================================================================

# MODE_RUNNERS: map scan_mode to runner function
MODE_RUNNERS = {
    'deep': run_deep_mode,
    'fullrecon': run_fullrecon_mode,
    'intelligent': run_intelligent_mode,
    'continuous': run_continuous_mode,
    'recon': run_recon_mode,
    'discover': run_discover_mode,
    'parallel': run_parallel_mode,
}


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Bug Bounty Scanner - Config-Driven Security Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python scanner.py                      # Uses ./scan_config.yaml
  python scanner.py -c amazon_config.yaml
  python scanner.py -c /path/to/custom_config.yaml

Config file controls everything:
  - scan_mode: deep, fullrecon, intelligent, or continuous
  - targets: domains to scan
  - phases: what to scan for
  - network: rate limits, headers, etc.

Override config path:
  python scanner.py -c /path/to/my_config.yaml
        '''
    )

    parser.add_argument(
        '-c', '--config',
        default='scan_config.yaml',
        help='Path to scan configuration file (default: scan_config.yaml)'
    )

    args = parser.parse_args()

    # Load configuration
    config_path = Path(args.config)
    config = load_config(config_path)

    # Resolve targets
    targets = resolve_targets(config)
    if not targets:
        safe_print("[!] No targets specified in config file.")
        safe_print("    Edit 'targets.domains' in your scan_config.yaml")
        sys.exit(1)

    # Determine scan mode
    mode = config.get('scan_mode', 'deep')
    if mode not in MODE_RUNNERS:
        safe_print(f"[!] Unknown scan_mode: '{mode}'")
        safe_print(f"    Valid modes: {', '.join(MODE_RUNNERS.keys())}")
        sys.exit(1)

    # Print config summary
    if config.get('safety', {}).get('show_review', True):
        print_config_summary(config, targets)

    # Confirm if needed
    if not confirm_scan(config):
        safe_print("[*] Scan cancelled.")
        sys.exit(0)

    # Run the selected scan mode
    try:
        runner = MODE_RUNNERS[mode]
        # Pass config_path to deep mode for Nuclei and advanced features
        if mode == 'deep':
            runner(config, targets, config_path)
        else:
            runner(config, targets)
    except KeyboardInterrupt:
        safe_print("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        safe_print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
