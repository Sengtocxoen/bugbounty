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


def _get_osint_config(config):
    """Extract OSINT settings from config."""
    return config.get('osint', {
        'whois': True,
        'email_harvesting': True,
        'google_dorking': True,
        'github_dorking': True,
        'metadata_extraction': True,
        'cloud_enum': True,
    })


def _get_github_config(config):
    """Extract GitHub/GitLab dorking settings from config."""
    return config.get('github_dorking', {
        'enabled': True,
        'github_token': '',
        'gitlab_token': '',
        'max_results': 50,
    })


def _get_vuln_deep_config(config):
    """Extract deep vulnerability scan settings from config."""
    return config.get('vulnerability_scan', {
        'enabled': True,
        'nuclei': True,
        'xss': True,
        'sqli': True,
        'ssrf': True,
        'cors': True,
        'lfi': True,
        'ssti': True,
        'http_smuggling': False,
    })


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
        'deep':          'Deep comprehensive scan (all phases, maximum coverage)',
        'fullrecon':     'Full reconnaissance pipeline (8-phase recon)',
        'intelligent':   'Intelligent two-phase scanner (smart prioritization)',
        'continuous':    'Continuous 24/7 scanner (ongoing monitoring)',
        'recon':         'Wiz 5-phase reconnaissance (fast recon)',
        'discover':      'Fast subdomain/asset discovery only',
        'parallel':      'Parallel streaming scanner (speed-optimized)',
        # New modes
        'osint':         'OSINT recon (WHOIS, emails, dorks, GitHub, cloud assets)',
        'github':        'GitHub/GitLab dorking for leaked secrets',
        'vuln_deep':     'Deep vulnerability scan (Nuclei + XSS/SQLi/SSRF/CORS/LFI/SSTI)',
        'bug_discovery': 'Lightweight bug discovery pipeline (subdomain+endpoint+JS+fuzz)',
        'all':           'Run deep + vuln_deep + bug_discovery in parallel',
    }

    print(f"\n{'='*70}")
    print(f"  SELECT SCAN MODE")
    print(f"{'='*70}")
    for i, (mode, desc) in enumerate(mode_descriptions.items(), 1):
        print(f"  {i:2d}. {mode:16s} - {desc}")
    print(f"{'='*70}")

    n = len(mode_descriptions)
    while True:
        try:
            choice = input(f"\nSelect mode [1-{n}] or name: ").strip().lower()
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

        safe_print(f"[!] Invalid choice: '{choice}'. Try 1-{n} or a mode name.")


# =============================================================================
# SCAN MODE RUNNERS
# =============================================================================


def run_deep_mode(config: dict, targets: list, config_path: Path = None):
    """Run deep comprehensive scan with auto HTML report generation."""
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
        # Per-phase timeouts from config
        phase_timeouts=config.get('phase_timeouts', {
            'js_analysis': 300,
            'param_fuzzing': 600,
            'endpoint_discovery': 300,
            'nuclei_scan': 600,
            'verification': 300,
        }),
        # Pass config file path for Nuclei and advanced features
        config_file=config_path,
    )

    # Store the full config dict on the scan_config so scanners can access it
    scan_config._full_config = config

    scanner = DeepScanner(scan_config)
    scanner.run()

    # Auto-generate HTML report if enabled
    if config.get('output', {}).get('save_html', False):
        _generate_html_reports(scan_config.output_dir)

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
# HTML REPORT HELPER
# =============================================================================


def _generate_html_reports(output_dir: Path):
    """Auto-generate HTML reports from any JSON scan results found in output_dir."""
    try:
        from reporting.html_report import generate_html_report
        json_files = list(output_dir.rglob('*.json'))
        if not json_files:
            return
        safe_print(f"[*] Generating HTML reports for {len(json_files)} result files...")
        import json
        for jf in json_files:
            try:
                with open(jf) as f:
                    data = json.load(f)
                html_path = jf.with_suffix('.html')
                generate_html_report(data, str(html_path))
                safe_print(f"    [HTML] {html_path.name}")
            except Exception as e:
                safe_print(f"    [!] HTML report error for {jf.name}: {e}")
    except ImportError as e:
        safe_print(f"[!] HTML report module unavailable: {e}")


# =============================================================================
# NEW SCAN MODE RUNNERS
# =============================================================================


def run_osint_mode(config: dict, targets: list):
    """Run comprehensive OSINT reconnaissance (WHOIS, emails, dorks, GitHub, cloud)."""
    from discovery.osint_recon import OSINTRecon
    import json

    output_dir = _get_output_dir(config, 'osint')
    output_dir.mkdir(parents=True, exist_ok=True)
    osint_cfg = _get_osint_config(config)

    recon = OSINTRecon(config={'osint': osint_cfg})

    for target in targets:
        if SHUTDOWN:
            break
        safe_print(f"[*] OSINT recon for: {target}")
        result = recon.run(target, output_dir=output_dir)
        # Save JSON
        out_file = output_dir / f"{target.replace('.', '_')}_osint.json"
        with open(out_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        safe_print(f"[+] OSINT complete: {result.total_findings()} findings → {out_file}")

    # Auto HTML
    if config.get('output', {}).get('save_html', False):
        _generate_html_reports(output_dir)

    safe_print("\n[+] OSINT mode complete!")


def run_github_mode(config: dict, targets: list):
    """Run GitHub/GitLab dorking for leaked secrets and credentials."""
    from discovery.github_dorking import GitHubDorker, GitLabDorker, save_dork_results

    output_dir = _get_output_dir(config, 'github')
    output_dir.mkdir(parents=True, exist_ok=True)
    gh_cfg = _get_github_config(config)

    github_token = gh_cfg.get('github_token') or None
    gitlab_token = gh_cfg.get('gitlab_token') or None
    max_results  = gh_cfg.get('max_results', 50)
    rate_limit   = _get_rate_limit(config, 1)

    gh_dorker = GitHubDorker(github_token=github_token, rate_limit=rate_limit)
    gl_dorker = GitLabDorker(gitlab_token=gitlab_token, rate_limit=rate_limit) if gitlab_token else None

    for target in targets:
        if SHUTDOWN:
            break
        safe_print(f"[*] GitHub dorking: {target}")
        gh_result = gh_dorker.dork_domain(target, max_results=max_results)
        safe_print(f"    GitHub: {len(gh_result.findings)} findings")

        # Save GitHub results
        gh_out = output_dir / f"{target.replace('.', '_')}_github.json"
        save_dork_results(gh_result, str(gh_out))

        if gl_dorker:
            safe_print(f"[*] GitLab dorking: {target}")
            gl_result = gl_dorker.dork_domain(target)
            safe_print(f"    GitLab: {len(gl_result.findings)} findings")
            gl_out = output_dir / f"{target.replace('.', '_')}_gitlab.json"
            save_dork_results(gl_result, str(gl_out))

    if config.get('output', {}).get('save_html', False):
        _generate_html_reports(output_dir)

    safe_print("\n[+] GitHub dorking complete!")


def run_vuln_deep_mode(config: dict, targets: list):
    """Run deep vulnerability scan: Nuclei + XSS + SQLi + SSRF + CORS + LFI + SSTI + more."""
    from analysis.vuln_deep_scan import VulnDeepScanner
    import json

    output_dir = _get_output_dir(config, 'vuln_deep')
    output_dir.mkdir(parents=True, exist_ok=True)
    vuln_cfg = _get_vuln_deep_config(config)

    # Merge with nuclei config if present
    nuclei_cfg = _get_nuclei_config(config)
    if nuclei_cfg:
        vuln_cfg['nuclei_config'] = nuclei_cfg

    scanner = VulnDeepScanner(config={'vulnerability_scan': vuln_cfg})

    for target in targets:
        if SHUTDOWN:
            break
        target_url = target if target.startswith('http') else f'https://{target}'
        safe_print(f"[*] Deep vuln scan: {target_url}")
        result = scanner.run(
            target=target_url,
            live_urls=[target_url],
            output_dir=output_dir
        )
        # Save JSON summary
        out_file = output_dir / f"{target.replace('.', '_')}_vulns.json"
        with open(out_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        sev = result.to_dict().get('summary', {})
        safe_print(
            f"[+] {target}: critical={sev.get('critical',0)} high={sev.get('high',0)} "
            f"medium={sev.get('medium',0)} → {out_file}"
        )

    if config.get('output', {}).get('save_html', False):
        _generate_html_reports(output_dir)

    safe_print("\n[+] Deep vulnerability scan complete!")


def run_bug_discovery_mode(config: dict, targets: list):
    """Run lightweight bug discovery pipeline: subdomain+endpoint+tech+JS+fuzz."""
    from discovery.bug_discovery import run_full_discovery

    output_dir = _get_output_dir(config, 'bug_discovery')
    output_dir.mkdir(parents=True, exist_ok=True)

    phases = config.get('phases', {})
    skip_phases = []
    phase_map = {
        'subdomain_discovery': 'subdomain',
        'tech_detection':      'tech',
        'js_analysis':         'js',
        'param_fuzzing':       'fuzzing',
        'endpoint_discovery':  'endpoints',
    }
    for cfg_key, phase_name in phase_map.items():
        if not _phase_enabled(phases, cfg_key, True):
            skip_phases.append(phase_name)

    program  = _get_program(config)
    username = _get_username(config)

    for target in targets:
        if SHUTDOWN:
            break
        safe_print(f"[*] Bug discovery pipeline: {target}")
        target_dir = output_dir / target.replace('.', '_')
        target_dir.mkdir(parents=True, exist_ok=True)
        run_full_discovery(
            target=target,
            program=program or 'generic',
            username=username or 'researcher',
            output_dir=target_dir,
            skip_phases=skip_phases if skip_phases else None,
        )
        safe_print(f"[+] Bug discovery complete for {target}")

    if config.get('output', {}).get('save_html', False):
        _generate_html_reports(output_dir)

    safe_print("\n[+] Bug discovery mode complete!")


# =============================================================================
# "ALL" MODE - Run multiple scanners in parallel
# =============================================================================


def _run_webhack2025(config: dict, targets: list, output_dir: Path):
    """Run web_hacking_2025 scanner with config-derived settings."""
    from techniques.web_hacking_2025.scanner import WebHackingScanner

    rate_limit = float(_get_rate_limit(config, 5))
    user_agent = _get_custom_headers(config).get(
        'User-Agent', 'Mozilla/5.0 (compatible; SecurityResearch/1.0)'
    )

    adv = _get_advanced_features(config)
    wh2025 = adv.get('web_hacking_2025', {}) if isinstance(adv, dict) else {}
    techniques = None
    techs = wh2025.get('techniques', {})
    if techs:
        techniques = [name for name, enabled in techs.items() if enabled]

    sub_dir = output_dir / 'webhack2025'
    sub_dir.mkdir(parents=True, exist_ok=True)

    scanner = WebHackingScanner(
        output_dir=sub_dir,
        rate_limit=rate_limit,
        user_agent=user_agent,
        techniques=techniques,
        verbose=True,
        threads=3,
    )
    scanner.run(targets, resume=False)
    safe_print("[+] webhack2025 scanner finished")


def _run_vuln_v2(config: dict, targets: list, output_dir: Path):
    """Run vuln_scanner_v2 with config-derived settings."""
    from scanners.vuln_scanner_v2 import ScanConfig, run_scan

    for target in targets:
        # Parse target into host:port
        if ':' in target:
            parts = target.rsplit(':', 1)
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                host = target
                port = 443
        else:
            host = target
            port = 443

        scheme = 'https' if port == 443 else 'http'
        cfg = ScanConfig(host, target_port=port, scheme=scheme)

        # Override results dir
        sub_dir = output_dir / 'vuln_v2'
        sub_dir.mkdir(parents=True, exist_ok=True)
        cfg.results_dir = sub_dir / f"scan_{host}_{port}"
        cfg.results_dir.mkdir(parents=True, exist_ok=True)

        cfg.request_delay = float(_get_request_delay(config, 0.2))
        cfg.timeout = int(_get_request_timeout(config, 20))

        run_scan(cfg)

    safe_print("[+] vuln_v2 scanner finished")


def run_all_mode(config: dict, targets: list, config_path: Path = None):
    """Run multiple scanners in parallel and auto-aggregate results."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    output_dir = _get_output_dir(config)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Determine which scanners to run
    parallel_scanners = config.get('parallel_scanners', ['deep', 'vuln_deep', 'bug_discovery'])

    scanner_funcs = {
        'deep':          lambda: run_deep_mode(config, targets, config_path),
        'webhack2025':   lambda: _run_webhack2025(config, targets, output_dir),
        'vuln_v2':       lambda: _run_vuln_v2(config, targets, output_dir),
        'vuln_deep':     lambda: run_vuln_deep_mode(config, targets),
        'bug_discovery': lambda: run_bug_discovery_mode(config, targets),
        'osint':         lambda: run_osint_mode(config, targets),
        'github':        lambda: run_github_mode(config, targets),
    }

    safe_print(f"[*] Running {len(parallel_scanners)} scanners in parallel: {', '.join(parallel_scanners)}")

    results = {}
    with ThreadPoolExecutor(max_workers=len(parallel_scanners)) as executor:
        futures = {}
        for name in parallel_scanners:
            func = scanner_funcs.get(name)
            if func:
                futures[executor.submit(func)] = name
            else:
                safe_print(f"[!] Unknown scanner: {name}, skipping")

        for future in as_completed(futures):
            name = futures[future]
            try:
                future.result()
                results[name] = "success"
                safe_print(f"[+] {name} completed successfully")
            except Exception as e:
                results[name] = f"error: {e}"
                safe_print(f"[!] {name} failed: {e}")
                import traceback
                traceback.print_exc()

    # Auto-aggregate results
    safe_print("\n[*] Auto-aggregating results from all scanners...")
    try:
        sys.path.insert(0, str(Path(__file__).parent / 'tools'))
        from aggregate_results import aggregate_results
        aggregate_results(output_dir)
    except Exception as e:
        safe_print(f"[!] Aggregation error: {e}")
        import traceback
        traceback.print_exc()

    safe_print("\n[+] All-mode scan complete!")
    for name, status in results.items():
        safe_print(f"    {name}: {status}")


# =============================================================================
# MODE DISPATCH
# =============================================================================

# MODE_RUNNERS: map scan_mode to runner function
MODE_RUNNERS = {
    # Existing modes
    'deep':          run_deep_mode,
    'fullrecon':     run_fullrecon_mode,
    'intelligent':   run_intelligent_mode,
    'continuous':    run_continuous_mode,
    'recon':         run_recon_mode,
    'discover':      run_discover_mode,
    'parallel':      run_parallel_mode,
    'all':           run_all_mode,
    # New modes
    'osint':         run_osint_mode,
    'github':        run_github_mode,
    'vuln_deep':     run_vuln_deep_mode,
    'bug_discovery': run_bug_discovery_mode,
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
        # Pass config_path to modes that need it
        if mode in ('deep', 'all'):
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
