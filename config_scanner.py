#!/usr/bin/env python3
"""
Configuration File Scanner
Loads scan configuration from YAML file and presents a review before running
"""

import yaml
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

def load_config(config_file: str) -> Dict[str, Any]:
    """Load configuration from YAML file"""
    config_path = Path(config_file)
    if not config_path.exists():
        print(f"❌ Configuration file not found: {config_file}")
        sys.exit(1)
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    return config

def print_review(config: Dict[str, Any]):
    """Print a detailed review of the scan configuration"""
    print("\n" + "=" * 80)
    print("                    🔍 SCAN CONFIGURATION REVIEW")
    print("=" * 80)
    
    # Program & User Info
    print(f"\n📋 PROGRAM INFORMATION")
    print(f"   Program: {config.get('program', 'Generic').upper()}")
    print(f"   H1 Username: {config.get('h1_username', 'Not specified')}")
    
    # Targets
    print(f"\n🎯 TARGETS ({len(config.get('targets', []))})")
    for i, target in enumerate(config.get('targets', []), 1):
        print(f"   {i}. {target}")
    
    # Custom Headers
    headers = config.get('custom_headers', {})
    if headers:
        print(f"\n📤 CUSTOM HEADERS ({len(headers)})")
        for key, value in headers.items():
            # Mask sensitive values
            display_value = value if len(str(value)) < 20 else f"{str(value)[:15]}..."
            print(f"   {key}: {display_value}")
    
    # Rate Limiting
    print(f"\n⏱️  RATE LIMITING")
    print(f"   Rate Limit: {config.get('rate_limit', 'Default')} req/sec")
    print(f"   Request Delay: {config.get('request_delay', 'Default')}s")
    print(f"   Request Timeout: {config.get('request_timeout', 30)}s")
    
    # Phases
    phases = config.get('phases', {})
    enabled_phases = [name for name, enabled in phases.items() if enabled]
    disabled_phases = [name for name, enabled in phases.items() if not enabled]
    
    print(f"\n✅ ENABLED PHASES ({len(enabled_phases)}/7)")
    phase_names = {
        'subdomain_discovery': 'Phase 1: Subdomain Discovery',
        'port_scanning': 'Phase 2: Port Scanning',
        'endpoint_discovery': 'Phase 3: Endpoint Discovery',
        'tech_detection': 'Phase 4: Technology Detection',
        'js_analysis': 'Phase 5: JavaScript Analysis',
        'param_fuzzing': 'Phase 6: Parameter Fuzzing',
        'verification': 'Phase 7: Vulnerability Verification'
    }
    
    for phase in enabled_phases:
        print(f"   ✓ {phase_names.get(phase, phase)}")
    
    if disabled_phases:
        print(f"\n⏭️  SKIPPED PHASES ({len(disabled_phases)})")
        for phase in disabled_phases:
            print(f"   ✗ {phase_names.get(phase, phase)}")
    
    # Limits
    limits = config.get('limits', {})
    print(f"\n📊 SCAN LIMITS")
    print(f"   Max Subdomains: {limits.get('max_subdomains', 0) or 'Unlimited'}")
    print(f"   Max Endpoints: {limits.get('max_endpoints', 0) or 'Unlimited'}")
    print(f"   Max JS Files: {limits.get('max_js_files', 0) or 'Unlimited'}")
    print(f"   Max Fuzz URLs: {limits.get('max_fuzz_urls', 0) or 'Unlimited'}")
    
    # Port Scanning
    port_config = config.get('port_scan', {})
    print(f"\n🔌 PORT SCANNING")
    print(f"   Full Port Scan: {'Yes' if port_config.get('full_scan', True) else 'No (web ports only)'}")
    if port_config.get('custom_ports'):
        print(f"   Custom Ports: {', '.join(map(str, port_config['custom_ports']))}")
    
    # Verification
    verify = config.get('verification', {})
    print(f"\n🔍 VERIFICATION SETTINGS")
    print(f"   Threads: {verify.get('threads', 10)}")
    print(f"   High Priority Only: {'Yes' if verify.get('verify_only_high_priority', False) else 'No'}")
    print(f"   Test Default Creds: {'⚠️  YES (DANGER!)' if verify.get('test_default_credentials', False) else 'No (safe)'}")
    
    # Output
    output = config.get('output', {})
    print(f"\n💾 OUTPUT SETTINGS")
    print(f"   Directory: {output.get('directory', 'Default')}")
    print(f"   Save JSON: {'Yes' if output.get('save_json', True) else 'No'}")
    print(f"   Save TXT: {'Yes' if output.get('save_txt', True) else 'No'}")
    print(f"   Save HTML: {'Yes' if output.get('save_html', False) else 'No'}")
    print(f"   Verbose: {'Yes' if output.get('verbose', True) else 'No'}")
    
    # Safety
    safety = config.get('safety', {})
    print(f"\n🛡️  SAFETY SETTINGS")
    print(f"   Confirm Before Run: {'Yes' if safety.get('confirm_before_run', True) else 'No'}")
    print(f"   Max Threads: {safety.get('max_threads', 10)}")
    print(f"   Stop on Critical Error: {'Yes' if safety.get('stop_on_critical_error', False) else 'No'}")
    
    # Scope
    scope = config.get('scope', {})
    if scope.get('enforce_scope'):
        print(f"\n🎯 SCOPE VALIDATION")
        print(f"   Enforce Scope: Yes")
        if scope.get('additional_in_scope'):
            print(f"   Additional In-Scope: {', '.join(scope['additional_in_scope'])}")
        if scope.get('additional_out_scope'):
            print(f"   Additional Out-Scope: {', '.join(scope['additional_out_scope'])}")
    
    # Notes
    if config.get('notes'):
        print(f"\n📝 NOTES")
        for line in config['notes'].strip().split('\n'):
            print(f"   {line}")
    
    print("\n" + "=" * 80)
    print(f"   Scan will start at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80 + "\n")

def confirm_execution() -> bool:
    """Ask user to confirm execution"""
    while True:
        response = input("❓ Proceed with scan? [Y/n/review]: ").strip().lower()
        if response in ['y', 'yes', '']:
            return True
        elif response in ['n', 'no']:
            return False
        elif response in ['r', 'review']:
            return 'review'
        else:
            print("Please enter 'y' (yes), 'n' (no), or 'review'")

def build_command_line_args(config: Dict[str, Any]) -> list:
    """Convert config to command-line arguments for scanner.py"""
    args = []
    
    # Add mode (always deep for config file)
    args.append('deep')
    
    # Add targets
    for target in config.get('targets', []):
        args.extend(['-t', target])
    
    # Add program
    if config.get('program'):
        args.extend(['--program', config['program']])
    
    # Add username
    if config.get('h1_username'):
        args.extend(['--username', config['h1_username']])
    
    # Add phase skips
    phases = config.get('phases', {})
    if not phases.get('subdomain_discovery', True):
        args.append('--skip-subdomains')
    if not phases.get('port_scanning', True):
        args.append('--skip-ports')
    if not phases.get('endpoint_discovery', True):
        args.append('--skip-endpoints')
    if not phases.get('tech_detection', True):
        args.append('--skip-tech')
    if not phases.get('js_analysis', True):
        args.append('--skip-js')
    if not phases.get('param_fuzzing', True):
        args.append('--skip-fuzz')
    if not phases.get('verification', True):
        args.append('--skip-verification')
    
    # Add verbose
    if config.get('output', {}).get('verbose', True):
        args.append('--verbose')
    
    return args

def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python config_scanner.py <config_file.yaml>")
        print("\nExample:")
        print("  python config_scanner.py scan_config.yaml")
        sys.exit(1)
    
    config_file = sys.argv[1]
    
    # Load configuration
    print(f"📖 Loading configuration from: {config_file}")
    config = load_config(config_file)
    
    # Show review
    while True:
        if config.get('safety', {}).get('show_review', True):
            print_review(config)
        
        # Confirm execution
        if config.get('safety', {}).get('confirm_before_run', True):
            result = confirm_execution()
            if result == 'review':
                continue  # Show review again
            elif not result:
                print("\n❌ Scan cancelled by user")
                sys.exit(0)
        
        break
    
    # Build command line args
    args = build_command_line_args(config)
    
    print("\n🚀 Starting scan with configuration:")
    print(f"   Command: python scanner.py {' '.join(args)}\n")
    
    # Import and run the scanner
    sys.path.insert(0, str(Path(__file__).parent / "tools"))
    
    # Import scanner after adding to path
    import scanner
    
    # Set custom headers if specified
    if config.get('custom_headers'):
        # Store custom headers globally for the scanner to use
        import os
        for key, value in config['custom_headers'].items():
            os.environ[f'SCANNER_HEADER_{key}'] = str(value)
    
    # Run scanner with args
    sys.argv = ['scanner.py'] + args
    scanner.main()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user (Ctrl+C)")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
