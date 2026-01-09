#!/usr/bin/env python3
"""
Bug Discovery Tool - Main Orchestrator
Automated bug discovery pipeline that combines:
- Subdomain discovery
- Endpoint discovery
- Technology detection
- JavaScript analysis
- Parameter fuzzing

Run full reconnaissance and vulnerability detection automatically.
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

# Add tools directory to path
sys.path.insert(0, str(Path(__file__).parent))

from config import get_amazon_config, get_shopify_config
from scope_validator import AmazonScopeValidator, ShopifyScopeValidator
from subdomain_discovery import (
    SubdomainDiscovery, AmazonSubdomainDiscovery, ShopifySubdomainDiscovery
)
from endpoint_discovery import (
    EndpointDiscovery, AmazonEndpointDiscovery, ShopifyEndpointDiscovery
)
from tech_detection import (
    TechDetector, AmazonTechDetector, ShopifyTechDetector
)
from js_analyzer import (
    JSAnalyzer, AmazonJSAnalyzer, ShopifyJSAnalyzer
)
from param_fuzzer import (
    ParamFuzzer, AmazonParamFuzzer, ShopifyParamFuzzer
)


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║              BUG DISCOVERY TOOL v1.0                         ║
║         Automated Bug Bounty Reconnaissance                  ║
╠══════════════════════════════════════════════════════════════╣
║  Modules:                                                    ║
║  • Subdomain Discovery (crt.sh, DNS brute-force)            ║
║  • Endpoint Discovery (robots.txt, sitemap, path fuzzing)   ║
║  • Technology Detection (fingerprinting)                     ║
║  • JavaScript Analysis (secrets, endpoints, DOM sinks)       ║
║  • Parameter Fuzzing (XSS, SQLi, SSRF, etc.)                ║
╚══════════════════════════════════════════════════════════════╝
    """)


def run_subdomain_discovery(domain: str, program: str, username: str) -> List[str]:
    """Run subdomain discovery and return in-scope subdomains"""
    print("\n" + "=" * 60)
    print("PHASE 1: SUBDOMAIN DISCOVERY")
    print("=" * 60)

    if program == "amazon":
        discovery = AmazonSubdomainDiscovery(get_amazon_config(username))
        result = discovery.discover_and_validate(domain, check_alive=True)
        return list(result.in_scope) if result.in_scope else list(result.live_subdomains)
    elif program == "shopify":
        discovery = ShopifySubdomainDiscovery(get_shopify_config(username))
        result = discovery.discover_and_validate(domain, check_alive=True)
        return list(result.in_scope) if result.in_scope else list(result.live_subdomains)
    else:
        discovery = SubdomainDiscovery()
        result = discovery.discover(domain, check_alive=True)
        return list(result.live_subdomains)


def run_tech_detection(targets: List[str], program: str, username: str) -> Dict:
    """Run technology detection on targets"""
    print("\n" + "=" * 60)
    print("PHASE 2: TECHNOLOGY DETECTION")
    print("=" * 60)

    tech_results = {}

    if program == "amazon":
        detector = AmazonTechDetector(username)
    elif program == "shopify":
        detector = ShopifyTechDetector(username)
    else:
        detector = TechDetector()

    for target in targets[:10]:  # Limit to first 10
        url = f"https://{target}" if not target.startswith('http') else target
        result = detector.detect(url, deep_scan=True)
        tech_results[target] = {
            "technologies": [
                {"name": t.name, "category": t.category, "version": t.version}
                for t in result.technologies
            ],
            "vuln_notes": [t.vuln_notes for t in result.technologies if t.vuln_notes]
        }

    return tech_results


def run_endpoint_discovery(targets: List[str], program: str, username: str) -> Dict:
    """Run endpoint discovery on targets"""
    print("\n" + "=" * 60)
    print("PHASE 3: ENDPOINT DISCOVERY")
    print("=" * 60)

    endpoint_results = {}

    if program == "amazon":
        discovery = AmazonEndpointDiscovery(username)
    elif program == "shopify":
        discovery = ShopifyEndpointDiscovery(username)
    else:
        discovery = EndpointDiscovery()

    for target in targets[:5]:  # Limit to first 5
        url = f"https://{target}" if not target.startswith('http') else target
        result = discovery.discover(url, bruteforce=True, analyze_js=True)
        endpoint_results[target] = {
            "total_endpoints": len(result.endpoints),
            "interesting": [ep.url for ep in result.endpoints if ep.interesting][:20],
            "api_endpoints": list(result.api_endpoints)[:20],
            "js_files": list(result.js_files)[:10],
        }

    return endpoint_results


def run_js_analysis(targets: List[str], program: str, username: str) -> Dict:
    """Run JavaScript analysis on targets"""
    print("\n" + "=" * 60)
    print("PHASE 4: JAVASCRIPT ANALYSIS")
    print("=" * 60)

    js_results = {}

    if program == "amazon":
        analyzer = AmazonJSAnalyzer(username)
    elif program == "shopify":
        analyzer = ShopifyJSAnalyzer(username)
    else:
        analyzer = JSAnalyzer()

    for target in targets[:5]:  # Limit to first 5
        url = f"https://{target}" if not target.startswith('http') else target
        result = analyzer.analyze_url(url)
        js_results[target] = {
            "secrets_found": len(result.secrets),
            "secrets": [
                {"type": s.type, "file": s.file, "severity": s.severity}
                for s in result.secrets
            ],
            "api_endpoints": [
                {"url": ep.url, "method": ep.method}
                for ep in result.api_endpoints[:20]
            ],
            "dom_sinks": len(result.dom_sinks),
            "exploitable_sinks": len([s for s in result.dom_sinks if s.exploitable]),
            "parameters": list(result.parameters)[:30],
        }

    return js_results


def run_param_fuzzing(urls: List[str], program: str, username: str) -> Dict:
    """Run parameter fuzzing on URLs"""
    print("\n" + "=" * 60)
    print("PHASE 5: PARAMETER FUZZING")
    print("=" * 60)

    fuzz_results = {}

    if program == "amazon":
        fuzzer = AmazonParamFuzzer(username)
    elif program == "shopify":
        fuzzer = ShopifyParamFuzzer(username)
    else:
        fuzzer = ParamFuzzer()

    for url in urls[:10]:  # Limit to first 10 URLs
        if not url.startswith('http'):
            url = f"https://{url}"
        summary = fuzzer.fuzz_url(url, discover_params=True)
        fuzz_results[url] = {
            "parameters_tested": summary.parameters_tested,
            "findings": [
                {
                    "parameter": f.parameter,
                    "vuln_type": f.vuln_type,
                    "severity": f.severity,
                    "payload": f.payload,
                }
                for f in summary.findings
            ]
        }

    return fuzz_results


def generate_report(results: Dict, output_dir: Path):
    """Generate final report"""
    print("\n" + "=" * 60)
    print("GENERATING REPORT")
    print("=" * 60)

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save full JSON report
    report_file = output_dir / f"discovery_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"[*] Full report saved to: {report_file}")

    # Generate summary
    summary_file = output_dir / f"discovery_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(summary_file, 'w') as f:
        f.write("=" * 60 + "\n")
        f.write("BUG DISCOVERY SUMMARY\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"Target: {results.get('target', 'N/A')}\n")
        f.write(f"Program: {results.get('program', 'N/A')}\n")
        f.write(f"Scan Time: {results.get('scan_time', 'N/A')}\n\n")

        # Subdomains
        subdomains = results.get('subdomains', [])
        f.write(f"SUBDOMAINS DISCOVERED: {len(subdomains)}\n")
        for sub in subdomains[:10]:
            f.write(f"  - {sub}\n")
        if len(subdomains) > 10:
            f.write(f"  ... and {len(subdomains) - 10} more\n")
        f.write("\n")

        # Technologies
        tech_results = results.get('technologies', {})
        f.write(f"TECHNOLOGIES DETECTED:\n")
        for target, techs in tech_results.items():
            f.write(f"  {target}:\n")
            for tech in techs.get('technologies', [])[:5]:
                f.write(f"    - {tech['name']} ({tech['category']})\n")
        f.write("\n")

        # Findings
        f.write("POTENTIAL VULNERABILITIES:\n")
        total_findings = 0

        # From JS analysis
        js_results = results.get('js_analysis', {})
        for target, js_data in js_results.items():
            if js_data.get('secrets_found', 0) > 0:
                f.write(f"  [SECRETS] {target}: {js_data['secrets_found']} potential secrets\n")
                total_findings += js_data['secrets_found']
            if js_data.get('exploitable_sinks', 0) > 0:
                f.write(f"  [DOM XSS] {target}: {js_data['exploitable_sinks']} exploitable sinks\n")
                total_findings += js_data['exploitable_sinks']

        # From fuzzing
        fuzz_results = results.get('fuzzing', {})
        for url, fuzz_data in fuzz_results.items():
            for finding in fuzz_data.get('findings', []):
                f.write(f"  [{finding['severity'].upper()}] {finding['vuln_type']}: {finding['parameter']} @ {url}\n")
                total_findings += 1

        f.write(f"\nTOTAL FINDINGS: {total_findings}\n")

    print(f"[*] Summary saved to: {summary_file}")

    return report_file, summary_file


def run_full_discovery(target: str, program: str, username: str,
                       output_dir: Path, skip_phases: List[str] = None):
    """Run full bug discovery pipeline"""
    if skip_phases is None:
        skip_phases = []

    results = {
        "target": target,
        "program": program,
        "username": username,
        "scan_time": datetime.utcnow().isoformat(),
    }

    # Phase 1: Subdomain Discovery
    targets_to_scan = [target]
    if "subdomains" not in skip_phases:
        # Check if target is a domain (not URL)
        if not target.startswith('http') and '/' not in target:
            subdomains = run_subdomain_discovery(target, program, username)
            results['subdomains'] = subdomains
            if subdomains:
                targets_to_scan = subdomains[:10]  # Limit for subsequent phases
        else:
            results['subdomains'] = [target]
    else:
        print("\n[SKIP] Subdomain discovery skipped")
        results['subdomains'] = [target]

    # Phase 2: Technology Detection
    if "tech" not in skip_phases:
        results['technologies'] = run_tech_detection(targets_to_scan, program, username)
    else:
        print("\n[SKIP] Technology detection skipped")

    # Phase 3: Endpoint Discovery
    if "endpoints" not in skip_phases:
        results['endpoints'] = run_endpoint_discovery(targets_to_scan, program, username)

        # Collect interesting URLs for fuzzing
        interesting_urls = []
        for target_data in results['endpoints'].values():
            interesting_urls.extend(target_data.get('interesting', []))
            interesting_urls.extend(target_data.get('api_endpoints', []))
    else:
        print("\n[SKIP] Endpoint discovery skipped")
        interesting_urls = targets_to_scan

    # Phase 4: JavaScript Analysis
    if "js" not in skip_phases:
        results['js_analysis'] = run_js_analysis(targets_to_scan, program, username)
    else:
        print("\n[SKIP] JavaScript analysis skipped")

    # Phase 5: Parameter Fuzzing
    if "fuzz" not in skip_phases:
        # Fuzz interesting URLs
        urls_to_fuzz = list(set(interesting_urls))[:15]
        if urls_to_fuzz:
            results['fuzzing'] = run_param_fuzzing(urls_to_fuzz, program, username)
    else:
        print("\n[SKIP] Parameter fuzzing skipped")

    # Generate report
    report_file, summary_file = generate_report(results, output_dir)

    return results, report_file, summary_file


def main():
    parser = argparse.ArgumentParser(
        description="Bug Discovery Tool - Automated Reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full discovery on a domain
  python bug_discovery.py amazon.com -p amazon -u myh1user

  # Quick scan (skip subdomain discovery)
  python bug_discovery.py www.amazon.com -p amazon -u myh1user --skip subdomains

  # Only run specific phases
  python bug_discovery.py example.com --only tech endpoints

  # Scan a specific URL
  python bug_discovery.py "https://example.com/search?q=test" -p amazon -u myh1user

IMPORTANT:
  - For Amazon VRP: Rate limited to 5 req/sec, uses required User-Agent
  - For Shopify: Only test stores YOU created
  - Always verify targets are in scope before testing
        """
    )

    parser.add_argument("target", help="Target domain or URL")
    parser.add_argument("--program", "-p", choices=["amazon", "shopify"],
                        help="Bug bounty program (for scope validation and rate limits)")
    parser.add_argument("--username", "-u", default="yourh1username",
                        help="Your HackerOne username")
    parser.add_argument("--output", "-o", default="./discovery_results",
                        help="Output directory for results")
    parser.add_argument("--skip", nargs='+',
                        choices=["subdomains", "tech", "endpoints", "js", "fuzz"],
                        help="Skip specific phases")
    parser.add_argument("--only", nargs='+',
                        choices=["subdomains", "tech", "endpoints", "js", "fuzz"],
                        help="Only run specific phases")

    args = parser.parse_args()

    print_banner()

    # Determine which phases to skip
    all_phases = ["subdomains", "tech", "endpoints", "js", "fuzz"]
    skip_phases = args.skip or []

    if args.only:
        skip_phases = [p for p in all_phases if p not in args.only]

    # Validate username
    if args.username == "yourh1username":
        print("[!] WARNING: Using default username 'yourh1username'")
        print("    Set your actual HackerOne username with --username")
        print()

    # Run discovery
    output_dir = Path(args.output)

    print(f"[*] Target: {args.target}")
    print(f"[*] Program: {args.program or 'None (no scope validation)'}")
    print(f"[*] Username: {args.username}")
    print(f"[*] Output: {output_dir}")

    if skip_phases:
        print(f"[*] Skipping: {', '.join(skip_phases)}")

    print()

    try:
        results, report_file, summary_file = run_full_discovery(
            args.target,
            args.program,
            args.username,
            output_dir,
            skip_phases
        )

        # Print final summary
        print("\n" + "=" * 60)
        print("DISCOVERY COMPLETE")
        print("=" * 60)
        print(f"Subdomains found: {len(results.get('subdomains', []))}")

        total_findings = 0
        for js_data in results.get('js_analysis', {}).values():
            total_findings += js_data.get('secrets_found', 0)
            total_findings += js_data.get('exploitable_sinks', 0)
        for fuzz_data in results.get('fuzzing', {}).values():
            total_findings += len(fuzz_data.get('findings', []))

        print(f"Potential vulnerabilities: {total_findings}")
        print(f"\nReports saved to:")
        print(f"  - {report_file}")
        print(f"  - {summary_file}")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
