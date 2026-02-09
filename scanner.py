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


# =============================================================================
# CONFIG HELPERS - Handle both flat (scan_config.yaml) and nested
#                  (full_recon.yaml) config formats
# =============================================================================


def _is_fullrecon_format(config):
    """Check if config uses the full_recon.yaml nested format."""
    return 'general' in config


def _get_program(config):
    """Extract program name from config (handles string, dict, or None)."""
    if _is_fullrecon_format(config):
        return config['general'].get('program')
    program = config.get('program')
    if isinstance(program, dict):
        return program.get('name')
    return program  # string or None


def _get_username(config):
    """Extract h1_username from config (handles multiple locations)."""
    if _is_fullrecon_format(config):
        return config['general'].get('h1_username', 'N/A')
    # Top-level h1_username (scan_config.yaml format)
    if 'h1_username' in config:
        return config['h1_username']
    # Inside program dict (old nested format)
    program = config.get('program')
    if isinstance(program, dict):
        return program.get('h1_username', 'N/A')
    return 'N/A'


def _get_custom_headers(config):
    """Extract custom headers from config."""
    if _is_fullrecon_format(config):
        return config['general'].get('custom_headers', {})
    # Top-level custom_headers (scan_config.yaml format)
    if 'custom_headers' in config:
        return config['custom_headers'] or {}
    # Inside program dict (old nested format)
    program = config.get('program')
    if isinstance(program, dict):
        return program.get('custom_headers', {})
    return {}


def _get_rate_limit(config, default=5):
    """Extract rate limit from config."""
    if _is_fullrecon_format(config):
        return config.get('performance', {}).get('rate_limit', default)
    # Top-level (scan_config.yaml format)
    if 'rate_limit' in config:
        return config['rate_limit']
    # Nested in network (old format)
    return config.get('network', {}).get('rate_limit', default)


def _get_request_delay(config, default=0.2):
    """Extract request delay from config."""
    if _is_fullrecon_format(config):
        return config.get('performance', {}).get('request_delay', default)
    # Top-level (scan_config.yaml format)
    if 'request_delay' in config:
        return config['request_delay']
    return config.get('network', {}).get('request_delay', default)


def _get_request_timeout(config, default=30):
    """Extract request timeout from config."""
    if _is_fullrecon_format(config):
        return config.get('performance', {}).get('request_timeout', default)
    if 'request_timeout' in config:
        return config['request_timeout']
    return config.get('network', {}).get('request_timeout', default)


def _get_output_dir(config, subdir=''):
    """Extract output directory from config."""
    if _is_fullrecon_format(config):
        base = config['general'].get('output_dir', 'results')
    else:
        base = config.get('output', {}).get('directory', 'results')
    path = Path(base)
    if subdir:
        path = path / subdir
    return path


def _get_max_workers(config, default=10):
    """Extract max workers/threads from config."""
    if _is_fullrecon_format(config):
        return config.get('performance', {}).get('max_workers', default)
    # From safety.max_threads (scan_config.yaml format)
    workers = config.get('safety', {}).get('max_threads')
    if workers is not None:
        return workers
    # From verification.threads
    workers = config.get('verification', {}).get('threads')
    if workers is not None:
        return workers
    # From workers section (old nested format)
    return config.get('workers', {}).get('max_workers', default)


def _phase_enabled(phases, phase_name, default=True):
    """Check if a phase is enabled (handles both bool and dict formats).

    scan_config.yaml uses:    phases.subdomain_discovery: true
    full_recon.yaml uses:     phases.subdomain_discovery.enabled: true
    """
    val = phases.get(phase_name, default)
    if isinstance(val, bool):
        return val
    if isinstance(val, dict):
        return val.get('enabled', default)
    return default


def _get_nuclei_config(config):
    """Extract nuclei config from either top-level or nested location."""
    # Top-level nuclei_scan section (scan_config.yaml format)
    if 'nuclei_scan' in config:
        return config['nuclei_scan']
    # Nested inside phases (full_recon.yaml format)
    phases = config.get('phases', {})
    vuln = phases.get('vulnerability_scanning', {})
    if isinstance(vuln, dict):
        return vuln.get('nuclei', {})
    return {}


def _get_verification_config(config):
    """Extract verification settings from config."""
    # Top-level verification section (scan_config.yaml format)
    if 'verification' in config and isinstance(config['verification'], dict):
        return config['verification']
    # From phases (full_recon.yaml format)
    phases = config.get('phases', {})
    verif = phases.get('verification', {})
    if isinstance(verif, dict):
        return verif
    return {}


def _get_port_scan_config(config):
    """Extract port scan settings from config."""
    # Top-level port_scan section (scan_config.yaml format)
    if 'port_scan' in config and isinstance(config['port_scan'], dict):
        return config['port_scan']
    # From phases (full_recon.yaml format)
    phases = config.get('phases', {})
    ps = phases.get('port_scanning', {})
    if isinstance(ps, dict):
        return ps
    return {}


def _get_advanced_features(config):
    """Extract advanced features from config."""
    # scan_config.yaml uses 'advanced_features'
    if 'advanced_features' in config:
        return config['advanced_features']
    # full_recon.yaml or old format uses 'advanced'
    return config.get('advanced', {})


# =============================================================================
# CORE FUNCTIONS
# =============================================================================


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

    # Format 2: targets key
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

        # Handle if targets is directly a list (scan_config.yaml format)
        elif isinstance(targets_cfg, list):
            targets.extend(targets_cfg)

    return targets


def resolve_subdomains(config: dict) -> list:
    """Load pre-discovered subdomains if provided."""
    targets_cfg = config.get('targets', {})
    if isinstance(targets_cfg, dict):
        subs_file = targets_cfg.get('subdomains_file')
        if subs_file:
            p = Path(subs_file)
            if p.exists():
                with open(p) as f:
                    return [line.strip() for line in f if line.strip()]
    return []


def print_config_summary(config: dict, targets: list):
    """Print a summary of the scan configuration."""
    mode = config.get('scan_mode', 'deep')
    program = _get_program(config)
    username = _get_username(config)
    rate_limit = _get_rate_limit(config)
    output_dir = _get_output_dir(config)
    workers = _get_max_workers(config)

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

    # Show enabled phases (handles both bool and dict formats)
    phases = config.get('phases', {})
    enabled = [name for name, val in phases.items() if _phase_enabled(phases, name)]
    disabled = [name for name, val in phases.items() if not _phase_enabled(phases, name)]

    if enabled:
        print(f"  Phases ON:   {', '.join(enabled)}")
    if disabled:
        print(f"  Phases OFF:  {', '.join(disabled)}")

    # Show advanced features status
    adv = _get_advanced_features(config)
    if adv:
        adv_on = [name for name, cfg in adv.items()
                   if isinstance(cfg, dict) and cfg.get('enabled', False)]
        if adv_on:
            print(f"  Advanced:    {', '.join(adv_on)}")

    # Show nuclei status
    nuclei = _get_nuclei_config(config)
    if nuclei.get('enabled', False):
        severity = nuclei.get('severity', [])
        print(f"  Nuclei:      ON ({', '.join(severity)})")

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


def select_scan_mode(config: dict) -> str:
    """Prompt the user to select a scan mode if not specified in config."""
    mode_descriptions = {
        'deep':        'Deep comprehensive scan (all phases, maximum coverage)',
        'fullrecon':   'Full reconnaissance pipeline (8-phase recon)',
        'intelligent': 'Intelligent two-phase scanner (smart prioritization)',
        'continuous':  'Continuous 24/7 scanner (ongoing monitoring)',
        'recon':       'Wiz 5-phase reconnaissance (fast recon)',
        'discover':    'Fast subdomain/asset discovery only',
        'parallel':    'Parallel streaming scanner (speed-optimized)',
    }

    print(f"\n{'='*70}")
    print(f"  SELECT SCAN MODE")
    print(f"{'='*70}")
    for i, (mode, desc) in enumerate(mode_descriptions.items(), 1):
        print(f"  {i}. {mode:14s} - {desc}")
    print(f"{'='*70}")

    while True:
        try:
            choice = input("\nSelect mode [1-7] or name: ").strip().lower()
        except EOFError:
            return 'deep'

        # Accept number
        if choice.isdigit():
            idx = int(choice) - 1
            modes = list(mode_descriptions.keys())
            if 0 <= idx < len(modes):
                return modes[idx]

        # Accept name
        if choice in mode_descriptions:
            return choice

        safe_print(f"[!] Invalid choice: '{choice}'. Try 1-7 or a mode name.")


# =============================================================================
# SCAN MODE RUNNERS
# =============================================================================


def run_deep_mode(config: dict, targets: list, config_path: Path = None):
    """Run deep comprehensive scan."""
    from scanners.deep_scan import DeepScanner, DeepScanConfig

    phases = config.get('phases', {})
    limits = config.get('limits', {})
    verif_cfg = _get_verification_config(config)
    port_cfg = _get_port_scan_config(config)
    adv = _get_advanced_features(config)
    fuzzing_cfg = adv.get('fuzzing', {}) if isinstance(adv, dict) else {}

    scan_config = DeepScanConfig(
        targets=targets,
        program=_get_program(config),
        username=_get_username(config),
        output_dir=_get_output_dir(config, 'deep'),
        # Phase control - uses _phase_enabled to handle bool or dict
        skip_subdomains=not _phase_enabled(phases, 'subdomain_discovery', True),
        skip_ports=not _phase_enabled(phases, 'port_scanning', True),
        skip_endpoints=not _phase_enabled(phases, 'endpoint_discovery', True),
        skip_tech=not _phase_enabled(phases, 'tech_detection', True),
        skip_js=not _phase_enabled(phases, 'js_analysis', True),
        skip_fuzz=not _phase_enabled(phases, 'param_fuzzing', True),
        skip_cloud=not _phase_enabled(phases, 'cloud_enumeration', True),
        skip_waf=not _phase_enabled(phases, 'waf_detection', True),
        skip_recursive=not config.get('scope', {}).get('recursive', True),
        skip_verification=not _phase_enabled(phases, 'verification', True),
        # Verification - from top-level verification section
        verification_threads=verif_cfg.get('threads', 10),
        verify_only_high_priority=verif_cfg.get('verify_only_high_priority', False),
        test_default_credentials=verif_cfg.get('test_default_credentials', False),
        # Limits
        max_subdomains=limits.get('max_subdomains', 0),
        max_endpoints=limits.get('max_endpoints', 0),
        max_js_files=limits.get('max_js_files', 0),
        max_fuzz_urls=limits.get('max_fuzz_urls', 0),
        # Port scanning - from top-level port_scan section
        full_port_scan=port_cfg.get('full_scan', True),
        # Wordlist - from advanced_features.fuzzing or phase config
        extended_wordlist=fuzzing_cfg.get('recursive', True),
        custom_wordlist=Path(fuzzing_cfg['wordlist']) if fuzzing_cfg.get('wordlist') else None,
        # Output
        verbose=config.get('output', {}).get('verbose', True) if 'output' in config else True,
        save_json=config.get('output', {}).get('save_json', True) if 'output' in config else True,
        save_txt=config.get('output', {}).get('save_txt', True) if 'output' in config else True,
        # Network overrides - from top-level rate_limit/request_delay
        custom_headers=_get_custom_headers(config),
        custom_rate_limit=float(_get_rate_limit(config, 0)),
        custom_request_delay=float(_get_request_delay(config, 0)),
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

    output_dir = _get_output_dir(config, 'fullrecon')

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
    nuclei_cfg = _get_nuclei_config(config)
    adv = _get_advanced_features(config)
    vuln_chaining = adv.get('vuln_chaining', {}) if isinstance(adv, dict) else {}

    return {
        'general': {
            'program': _get_program(config),
            'h1_username': _get_username(config),
            'targets': [],  # Already passed separately
            'custom_headers': _get_custom_headers(config),
            'output_dir': str(_get_output_dir(config, 'fullrecon')),
            'notifications': config.get('notifications', {}),
            'diff_mode': False,
        },
        'performance': {
            'rate_limit': _get_rate_limit(config, 150),
            'request_delay': _get_request_delay(config, 0),
            'request_timeout': 0,  # No timeout
            'max_workers': _get_max_workers(config),
            'threads': {},
            'adaptive': {
                'enabled': True,
                'backoff_on_429': True,
                'backoff_on_503': True,
                'max_retries': 3,
                'backoff_multiplier': 2.0,
            },
        },
        'osint': {
            'enabled': _phase_enabled(phases, 'osint', True),
            'whois': {'enabled': True},
            'email_harvesting': {'enabled': True},
            'google_dorking': {'enabled': True},
        },
        'subdomains': {
            'enabled': _phase_enabled(phases, 'subdomain_discovery', True),
        },
        'host_analysis': {
            'enabled': _phase_enabled(phases, 'port_scanning', True),
        },
        'web_analysis': {
            'enabled': _phase_enabled(phases, 'endpoint_discovery', True),
        },
        'vulnerability_scan': {
            'enabled': nuclei_cfg.get('enabled', True) if nuclei_cfg else True,
            'nuclei': nuclei_cfg,
        },
        'verification': {
            'enabled': _phase_enabled(phases, 'verification', True),
            'threads': _get_verification_config(config).get('threads', 10),
        },
        'chaining': {
            'enabled': vuln_chaining.get('enabled', True),
            'chains': {
                'ssrf_idor': vuln_chaining.get('chain_ssrf_idor', True),
                'xss_csrf': vuln_chaining.get('chain_xss_csrf', True),
                'lfi_rce': vuln_chaining.get('chain_lfi_rce', True),
            },
        },
        'reporting': {
            'enabled': True,
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

    workers = _get_max_workers(config, 5)
    output_dir = _get_output_dir(config, 'intelligent')

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

    output_dir = _get_output_dir(config, 'continuous')
    continuous_cfg = config.get('continuous', {})
    phases = config.get('phases', {})
    nuclei_cfg = _get_nuclei_config(config)

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
            'reconnaissance': _phase_enabled(phases, 'subdomain_discovery', True),
            'vulnerability_scanning': nuclei_cfg.get('enabled', True) if nuclei_cfg else True,
        },
        'tools': {
            'nuclei': nuclei_cfg.get('enabled', True) if nuclei_cfg else True,
        },
        'nuclei': {
            'severity': nuclei_cfg.get('severity', ['critical', 'high', 'medium']),
            'tags': nuclei_cfg.get('tags', []),
        },
        'notifications': config.get('notifications', {}),
    }

    # Write temp config for continuous scanner
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

    program = _get_program(config)
    username = _get_username(config)
    output_dir = _get_output_dir(config, 'recon')

    # Thoroughness can be in phases or top-level
    phases = config.get('phases', {})
    dns_phase = phases.get('dns_enumeration', {})
    thoroughness = dns_phase.get('thoroughness', 'medium') if isinstance(dns_phase, dict) else 'medium'

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

    output_dir = _get_output_dir(config, 'discovery')

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

    program = _get_program(config)
    username = _get_username(config)
    workers = _get_max_workers(config, 3)
    output_dir = _get_output_dir(config, 'parallel')

    # Get enabled techniques from advanced_features
    techniques = None
    adv = _get_advanced_features(config)
    wh2025 = adv.get('web_hacking_2025', {}) if isinstance(adv, dict) else {}
    if wh2025.get('enabled', True):
        techs = wh2025.get('techniques', {})
        if techs:
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
  - scan_mode: deep, fullrecon, intelligent, continuous, recon, discover, parallel
  - targets: domains to scan
  - phases: what to scan for
  - rate_limit, request_delay: network settings

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
        safe_print("    Add domains under 'targets:' in your scan_config.yaml")
        sys.exit(1)

    # Determine scan mode - prompt if not set in config
    mode = config.get('scan_mode')
    if not mode:
        mode = select_scan_mode(config)
        config['scan_mode'] = mode

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
