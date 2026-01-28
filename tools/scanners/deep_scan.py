#!/usr/bin/env python3
"""
Deep Bug Bounty Scanner - All-in-One Comprehensive Scanning Tool
================================================================

A single script to run ALL scanning phases deeply against targets.
No timeout limits - runs until completion or user interruption (Ctrl+C).

Features:
---------
1. Multi-source subdomain discovery (8+ passive sources + DNS brute-force)
2. Port scanning on all discovered hosts
3. Comprehensive endpoint discovery
4. Technology fingerprinting
5. JavaScript analysis (secrets, API endpoints, DOM sinks)
6. Parameter fuzzing for vulnerabilities
7. Recursive subdomain discovery
8. Full scope validation for Amazon VRP and Shopify

Usage:
------
  # Single target
  python deep_scan.py example.com -p amazon -u yourh1username

  # Multiple targets from file
  python deep_scan.py -f targets.txt -p shopify -u yourh1username

  # Custom output directory
  python deep_scan.py example.com -o ./results -p amazon -u myuser

  # Skip specific phases
  python deep_scan.py example.com --skip-ports --skip-fuzz

Author: Bug Bounty Automation Suite
"""

import sys
import json
import signal
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Set, Optional, Any
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import traceback

# Add tools directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Import all scanner modules
from utils.config import get_amazon_config, get_shopify_config, AmazonConfig, ShopifyConfig
from utils.scope_validator import AmazonScopeValidator, ShopifyScopeValidator
from discovery.enhanced_subdomain_scanner import (
    EnhancedSubdomainScanner, AmazonEnhancedScanner, ShopifyEnhancedScanner,
    ScanResult as SubdomainScanResult, SubdomainInfo, EXTENDED_WORDLIST, COMMON_PORTS
)
from discovery.endpoint_discovery import (
    EndpointDiscovery, AmazonEndpointDiscovery, ShopifyEndpointDiscovery,
    EndpointResult, COMMON_PATHS
)
from analysis.tech_detection import TechDetector, AmazonTechDetector, ShopifyTechDetector
from analysis.js_analyzer import JSAnalyzer, AmazonJSAnalyzer, ShopifyJSAnalyzer
from analysis.param_fuzzer import ParamFuzzer, AmazonParamFuzzer, ShopifyParamFuzzer, FUZZ_PAYLOADS


# Global flag for graceful shutdown
SHUTDOWN_FLAG = False


def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    global SHUTDOWN_FLAG
    if SHUTDOWN_FLAG:
        print("\n\n[!] Force exit...")
        sys.exit(1)
    print("\n\n[!] Shutdown requested. Finishing current task...")
    print("[!] Press Ctrl+C again to force exit")
    SHUTDOWN_FLAG = True


signal.signal(signal.SIGINT, signal_handler)


@dataclass
class DeepScanConfig:
    """Configuration for deep scanning"""
    # Target info
    targets: List[str] = field(default_factory=list)
    program: Optional[str] = None  # amazon, shopify, or None
    username: str = "yourh1username"

    # Output
    output_dir: Path = field(default_factory=lambda: Path("./deep_scan_results"))

    # Phase control - all enabled by default for deep scanning
    skip_subdomains: bool = False
    skip_ports: bool = False
    skip_endpoints: bool = False
    skip_tech: bool = False
    skip_js: bool = False
    skip_fuzz: bool = False
    skip_recursive: bool = False
    skip_verification: bool = False  # NEW: Skip vulnerability verification

    # Verification options
    verification_threads: int = 10  # Concurrent verification threads
    verify_only_high_priority: bool = False  # Only verify critical/high severity findings
    test_default_credentials: bool = False  # Test default creds on admin panels (disabled by default)

    # Deep scanning options (no limits by default)
    max_subdomains: int = 0  # 0 = unlimited
    max_endpoints: int = 0   # 0 = unlimited
    max_js_files: int = 0    # 0 = unlimited
    max_fuzz_urls: int = 0   # 0 = unlimited

    # Port scanning
    full_port_scan: bool = True  # Scan all common ports

    # Wordlist options
    extended_wordlist: bool = True  # Use extended subdomain wordlist
    custom_wordlist: Optional[Path] = None

    # Output options
    verbose: bool = True
    save_json: bool = True
    save_txt: bool = True


@dataclass
class DeepScanResult:
    """Complete results from deep scanning"""
    target: str
    program: Optional[str]
    scan_start: str
    scan_end: str = ""

    # Subdomain results
    subdomains_total: int = 0
    subdomains_alive: int = 0
    subdomains_in_scope: int = 0
    subdomains: Dict[str, Dict] = field(default_factory=dict)

    # Endpoint results
    endpoints_total: int = 0
    endpoints_interesting: int = 0
    endpoints: List[Dict] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)

    # Technology results
    technologies: Dict[str, List[Dict]] = field(default_factory=dict)

    # JavaScript analysis
    js_files_analyzed: int = 0
    secrets_found: List[Dict] = field(default_factory=list)
    dom_sinks: List[Dict] = field(default_factory=list)

    # Vulnerability findings
    vulnerabilities: List[Dict] = field(default_factory=list)
    potential_issues: List[Dict] = field(default_factory=list)

    # Port scan results
    open_ports: Dict[str, List[Dict]] = field(default_factory=dict)

    # Verification results
    verified_findings: List[Dict] = field(default_factory=list)
    verification_summary: Dict[str, int] = field(default_factory=dict)

    # Statistics
    total_requests: int = 0
    phases_completed: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class DeepScanner:
    """
    Comprehensive deep scanner that runs ALL scanning phases.
    No limits, no timeouts - runs until complete or interrupted.
    """

    def __init__(self, config: DeepScanConfig):
        self.config = config
        self.results: Dict[str, DeepScanResult] = {}

        # Initialize scanners based on program
        if config.program == "amazon":
            self.program_config = get_amazon_config(config.username)
            self.subdomain_scanner = AmazonEnhancedScanner(self.program_config)
            self.endpoint_discovery = AmazonEndpointDiscovery(config.username)
            self.tech_detector = AmazonTechDetector(config.username)
            self.js_analyzer = AmazonJSAnalyzer(config.username)
            self.param_fuzzer = AmazonParamFuzzer(config.username)
            self.scope_validator = AmazonScopeValidator(self.program_config)
        elif config.program == "shopify":
            self.program_config = get_shopify_config(config.username)
            self.subdomain_scanner = ShopifyEnhancedScanner(self.program_config)
            self.endpoint_discovery = ShopifyEndpointDiscovery(config.username)
            self.tech_detector = ShopifyTechDetector(config.username)
            self.js_analyzer = ShopifyJSAnalyzer(config.username)
            self.param_fuzzer = ShopifyParamFuzzer(config.username)
            self.scope_validator = ShopifyScopeValidator(self.program_config)
        else:
            self.program_config = None
            self.subdomain_scanner = EnhancedSubdomainScanner()
            self.endpoint_discovery = EndpointDiscovery()
            self.tech_detector = TechDetector()
            self.js_analyzer = JSAnalyzer()
            self.param_fuzzer = ParamFuzzer()
            self.scope_validator = None

        # Create output directory
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

    def print_banner(self):
        """Print scanner banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                     DEEP BUG BOUNTY SCANNER v2.0                             ║
║                 All-in-One Comprehensive Scanning Tool                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  PHASES:                                                                      ║
║  [1] Subdomain Discovery     - 8+ passive sources + DNS brute-force          ║
║  [2] Port Scanning           - 22+ common ports on all live hosts            ║
║  [3] Endpoint Discovery      - robots.txt, sitemap, path brute-force         ║
║  [4] Technology Detection    - Fingerprinting & CVE mapping                  ║
║  [5] JavaScript Analysis     - Secrets, API endpoints, DOM XSS sinks         ║
║  [6] Parameter Fuzzing       - XSS, SQLi, SSRF, LFI, RCE, SSTI              ║
║  [7] Recursive Discovery     - Find subdomains of subdomains                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Press Ctrl+C to gracefully stop scanning (current phase will complete)      ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)

    def check_shutdown(self) -> bool:
        """Check if shutdown was requested"""
        return SHUTDOWN_FLAG

    def log(self, message: str, level: str = "INFO"):
        """Log a message with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "INFO": "[*]",
            "SUCCESS": "[+]",
            "WARNING": "[!]",
            "ERROR": "[ERROR]",
            "PHASE": "\n[PHASE]",
            "FINDING": "[!!!]",
        }.get(level, "[*]")
        print(f"{timestamp} {prefix} {message}")

    def phase_header(self, phase_num: int, phase_name: str, target: str):
        """Print phase header"""
        print(f"\n{'='*80}")
        print(f"  PHASE {phase_num}: {phase_name}")
        print(f"  Target: {target}")
        print(f"{'='*80}")

    # ======================== PHASE 1: SUBDOMAIN DISCOVERY ========================

    def phase_subdomain_discovery(self, target: str, result: DeepScanResult) -> List[str]:
        """
        Phase 1: Comprehensive subdomain discovery
        Uses 8+ passive sources + DNS brute-forcing + recursive discovery
        """
        if self.config.skip_subdomains:
            self.log("Subdomain discovery skipped", "WARNING")
            return [target]

        self.phase_header(1, "SUBDOMAIN DISCOVERY", target)

        if self.check_shutdown():
            return [target]

        # Load custom wordlist if provided
        wordlist = EXTENDED_WORDLIST
        if self.config.custom_wordlist and self.config.custom_wordlist.exists():
            with open(self.config.custom_wordlist) as f:
                wordlist = [line.strip() for line in f if line.strip()]
            self.log(f"Loaded custom wordlist: {len(wordlist)} entries")

        # Run subdomain discovery
        try:
            if self.config.program in ["amazon", "shopify"]:
                scan_result = self.subdomain_scanner.run_discovery_with_scope(
                    target,
                    dns_bruteforce=self.config.extended_wordlist,
                    recursive=not self.config.skip_recursive,
                    check_ports=False  # Ports checked in Phase 2
                )
            else:
                scan_result = self.subdomain_scanner.run_discovery(
                    target,
                    dns_bruteforce=self.config.extended_wordlist,
                    recursive=not self.config.skip_recursive,
                    check_ports=False
                )

            # Store results
            result.subdomains_total = scan_result.unique_subdomains
            result.subdomains_alive = scan_result.live_subdomains
            result.subdomains_in_scope = scan_result.in_scope_count

            # Convert to dict for JSON serialization
            for subdomain, info in scan_result.subdomains.items():
                result.subdomains[subdomain] = {
                    "ip_addresses": info.ip_addresses,
                    "is_alive": info.is_alive,
                    "http_status": info.http_status,
                    "https_status": info.https_status,
                    "title": info.title,
                    "server": info.server,
                    "technologies": info.technologies,
                    "in_scope": info.in_scope,
                    "scope_reason": info.scope_reason,
                }

            # Get alive and in-scope subdomains for further scanning
            alive_subdomains = [
                sub for sub, info in scan_result.subdomains.items()
                if info.is_alive and (info.in_scope or self.config.program is None)
            ]

            result.phases_completed.append("subdomain_discovery")
            self.log(f"Subdomain discovery complete: {len(alive_subdomains)} alive targets", "SUCCESS")

            return alive_subdomains if alive_subdomains else [target]

        except Exception as e:
            result.errors.append(f"Subdomain discovery error: {str(e)}")
            self.log(f"Subdomain discovery error: {e}", "ERROR")
            traceback.print_exc()
            return [target]

    # ======================== PHASE 2: PORT SCANNING ========================

    def phase_port_scanning(self, targets: List[str], result: DeepScanResult):
        """
        Phase 2: Port scanning on all alive hosts
        Scans 22+ common ports (web, db, ssh, ftp, etc.)
        """
        if self.config.skip_ports:
            self.log("Port scanning skipped", "WARNING")
            return

        self.phase_header(2, "PORT SCANNING", f"{len(targets)} hosts")

        if self.check_shutdown():
            return

        self.log(f"Scanning {len(COMMON_PORTS)} ports on {len(targets)} hosts...")

        scanned = 0
        for target in targets:
            if self.check_shutdown():
                break

            scanned += 1
            self.log(f"Scanning ports [{scanned}/{len(targets)}]: {target}")

            try:
                open_ports = self.subdomain_scanner.check_ports(target, COMMON_PORTS)
                if open_ports:
                    result.open_ports[target] = [
                        {"port": port, "service": service}
                        for port, service in open_ports
                    ]
                    self.log(f"  Found {len(open_ports)} open ports: {open_ports}", "SUCCESS")
            except Exception as e:
                result.errors.append(f"Port scan error on {target}: {str(e)}")

        result.phases_completed.append("port_scanning")
        self.log(f"Port scanning complete. Found open ports on {len(result.open_ports)} hosts.", "SUCCESS")

    # ======================== PHASE 3: ENDPOINT DISCOVERY ========================

    def phase_endpoint_discovery(self, targets: List[str], result: DeepScanResult) -> List[str]:
        """
        Phase 3: Comprehensive endpoint discovery
        - robots.txt, sitemap.xml parsing
        - Path brute-forcing with 100+ common paths
        - HTML link extraction
        - JavaScript file discovery
        """
        if self.config.skip_endpoints:
            self.log("Endpoint discovery skipped", "WARNING")
            return []

        self.phase_header(3, "ENDPOINT DISCOVERY", f"{len(targets)} targets")

        if self.check_shutdown():
            return []

        all_endpoints = []
        all_js_files = set()
        all_api_endpoints = set()

        for i, target in enumerate(targets):
            if self.check_shutdown():
                break

            url = f"https://{target}" if not target.startswith('http') else target
            self.log(f"Discovering endpoints [{i+1}/{len(targets)}]: {url}")

            try:
                ep_result = self.endpoint_discovery.discover(
                    url,
                    bruteforce=True,
                    analyze_js=True
                )

                # Collect results
                for endpoint in ep_result.endpoints:
                    all_endpoints.append({
                        "url": endpoint.url,
                        "method": endpoint.method,
                        "source": endpoint.source,
                        "status_code": endpoint.status_code,
                        "interesting": endpoint.interesting,
                    })

                all_js_files.update(ep_result.js_files)
                all_api_endpoints.update(ep_result.api_endpoints)

                # Log interesting findings
                interesting = [ep for ep in ep_result.endpoints if ep.interesting]
                if interesting:
                    self.log(f"  Found {len(interesting)} interesting endpoints", "SUCCESS")

            except Exception as e:
                result.errors.append(f"Endpoint discovery error on {target}: {str(e)}")

        # Store results
        result.endpoints = all_endpoints
        result.endpoints_total = len(all_endpoints)
        result.endpoints_interesting = sum(1 for ep in all_endpoints if ep.get("interesting"))
        result.api_endpoints = list(all_api_endpoints)

        result.phases_completed.append("endpoint_discovery")
        self.log(f"Endpoint discovery complete: {result.endpoints_total} endpoints ({result.endpoints_interesting} interesting)", "SUCCESS")

        return list(all_js_files)

    # ======================== PHASE 4: TECHNOLOGY DETECTION ========================

    def phase_tech_detection(self, targets: List[str], result: DeepScanResult):
        """
        Phase 4: Technology fingerprinting
        Detects web servers, frameworks, CMS, libraries, and maps to known CVEs
        """
        if self.config.skip_tech:
            self.log("Technology detection skipped", "WARNING")
            return

        self.phase_header(4, "TECHNOLOGY DETECTION", f"{len(targets)} targets")

        if self.check_shutdown():
            return

        for i, target in enumerate(targets):
            if self.check_shutdown():
                break

            url = f"https://{target}" if not target.startswith('http') else target
            self.log(f"Detecting technologies [{i+1}/{len(targets)}]: {url}")

            try:
                tech_result = self.tech_detector.detect(url, deep_scan=True)

                if tech_result.technologies:
                    result.technologies[target] = [
                        {
                            "name": t.name,
                            "category": t.category,
                            "version": t.version,
                            "vuln_notes": t.vuln_notes,
                        }
                        for t in tech_result.technologies
                    ]
                    self.log(f"  Detected: {', '.join(t.name for t in tech_result.technologies[:5])}", "SUCCESS")

                    # Check for vulnerable technologies
                    for tech in tech_result.technologies:
                        if tech.vuln_notes:
                            result.potential_issues.append({
                                "type": "technology_vulnerability",
                                "target": target,
                                "technology": tech.name,
                                "version": tech.version,
                                "notes": tech.vuln_notes,
                                "severity": "medium",
                            })
                            self.log(f"  [!] Potential vuln: {tech.name} - {tech.vuln_notes}", "FINDING")

            except Exception as e:
                result.errors.append(f"Tech detection error on {target}: {str(e)}")

        result.phases_completed.append("tech_detection")
        self.log(f"Technology detection complete", "SUCCESS")

    # ======================== PHASE 5: JAVASCRIPT ANALYSIS ========================

    def phase_js_analysis(self, targets: List[str], js_files: List[str], result: DeepScanResult):
        """
        Phase 5: Deep JavaScript analysis
        - Extract API endpoints from JS
        - Find secrets and API keys
        - Detect DOM XSS sinks
        - Extract hidden parameters
        """
        if self.config.skip_js:
            self.log("JavaScript analysis skipped", "WARNING")
            return

        self.phase_header(5, "JAVASCRIPT ANALYSIS", f"{len(targets)} targets, {len(js_files)} JS files")

        if self.check_shutdown():
            return

        all_secrets = []
        all_sinks = []
        all_api_endpoints = set()

        # Analyze main targets
        for i, target in enumerate(targets):
            if self.check_shutdown():
                break

            url = f"https://{target}" if not target.startswith('http') else target
            self.log(f"Analyzing JavaScript [{i+1}/{len(targets)}]: {url}")

            try:
                js_result = self.js_analyzer.analyze_url(url)
                result.js_files_analyzed += len(js_result.js_files)

                # Collect secrets
                for secret in js_result.secrets:
                    all_secrets.append({
                        "type": secret.type,
                        "value": secret.value,
                        "context": secret.context,
                        "file": secret.file,
                        "severity": secret.severity,
                        "target": target,
                    })
                    if secret.severity in ["critical", "high"]:
                        self.log(f"  [!!!] SECRET FOUND: {secret.type} in {secret.file}", "FINDING")

                # Collect DOM sinks
                for sink in js_result.dom_sinks:
                    all_sinks.append({
                        "sink_type": sink.sink_type,
                        "code_snippet": sink.code_snippet,
                        "file": sink.file,
                        "exploitable": sink.exploitable,
                        "notes": sink.notes,
                        "target": target,
                    })
                    if sink.exploitable:
                        self.log(f"  [!!!] EXPLOITABLE DOM SINK: {sink.sink_type} in {sink.file}", "FINDING")

                # Collect API endpoints
                for ep in js_result.api_endpoints:
                    all_api_endpoints.add(ep.url)

            except Exception as e:
                result.errors.append(f"JS analysis error on {target}: {str(e)}")

        # Store results
        result.secrets_found = all_secrets
        result.dom_sinks = all_sinks
        result.api_endpoints = list(set(result.api_endpoints) | all_api_endpoints)

        result.phases_completed.append("js_analysis")
        self.log(f"JavaScript analysis complete: {len(all_secrets)} secrets, {len(all_sinks)} DOM sinks", "SUCCESS")

    # ======================== PHASE 6: PARAMETER FUZZING ========================

    def phase_param_fuzzing(self, targets: List[str], result: DeepScanResult):
        """
        Phase 6: Parameter fuzzing for vulnerabilities
        Tests for: XSS, SQLi, SSRF, Path Traversal, Open Redirect,
                   Command Injection, LFI, XXE, SSTI
        """
        if self.config.skip_fuzz:
            self.log("Parameter fuzzing skipped", "WARNING")
            return

        # Collect URLs to fuzz
        urls_to_fuzz = set()

        # Add main targets
        for target in targets:
            url = f"https://{target}" if not target.startswith('http') else target
            urls_to_fuzz.add(url)

        # Add interesting endpoints
        for endpoint in result.endpoints:
            if endpoint.get("interesting"):
                urls_to_fuzz.add(endpoint["url"])

        # Add API endpoints
        urls_to_fuzz.update(result.api_endpoints)

        # Apply limit if set
        if self.config.max_fuzz_urls > 0:
            urls_to_fuzz = list(urls_to_fuzz)[:self.config.max_fuzz_urls]

        self.phase_header(6, "PARAMETER FUZZING", f"{len(urls_to_fuzz)} URLs")

        if self.check_shutdown():
            return

        self.log(f"Testing {len(FUZZ_PAYLOADS)} vulnerability types...")

        for i, url in enumerate(urls_to_fuzz):
            if self.check_shutdown():
                break

            self.log(f"Fuzzing [{i+1}/{len(urls_to_fuzz)}]: {url[:80]}...")

            try:
                fuzz_result = self.param_fuzzer.fuzz_url(url, discover_params=True)
                result.total_requests += fuzz_result.total_requests

                for finding in fuzz_result.findings:
                    vuln_entry = {
                        "url": finding.url,
                        "parameter": finding.parameter,
                        "vuln_type": finding.vuln_type,
                        "payload": finding.payload,
                        "evidence": finding.evidence,
                        "severity": finding.severity,
                        "confidence": finding.confidence,
                        "response_code": finding.response_code,
                    }
                    result.vulnerabilities.append(vuln_entry)
                    self.log(f"  [!!!] {finding.severity.upper()} {finding.vuln_type}: {finding.parameter}", "FINDING")

            except Exception as e:
                result.errors.append(f"Fuzzing error on {url}: {str(e)}")

        result.phases_completed.append("param_fuzzing")
        self.log(f"Parameter fuzzing complete: {len(result.vulnerabilities)} vulnerabilities found", "SUCCESS")

    # ======================== MAIN SCAN ORCHESTRATOR ========================

    def scan_target(self, target: str) -> DeepScanResult:
        """
        Run all scanning phases on a single target
        """
        self.log(f"Starting deep scan of: {target}")

        result = DeepScanResult(
            target=target,
            program=self.config.program,
            scan_start=datetime.utcnow().isoformat(),
        )

        try:
            # Phase 1: Subdomain Discovery
            alive_targets = self.phase_subdomain_discovery(target, result)

            if self.check_shutdown():
                result.scan_end = datetime.utcnow().isoformat()
                return result

            # Phase 2: Port Scanning
            self.phase_port_scanning(alive_targets, result)

            if self.check_shutdown():
                result.scan_end = datetime.utcnow().isoformat()
                return result

            # Phase 3: Endpoint Discovery
            js_files = self.phase_endpoint_discovery(alive_targets, result)

            if self.check_shutdown():
                result.scan_end = datetime.utcnow().isoformat()
                return result

            # Phase 4: Technology Detection
            self.phase_tech_detection(alive_targets, result)

            if self.check_shutdown():
                result.scan_end = datetime.utcnow().isoformat()
                return result

            # Phase 5: JavaScript Analysis
            self.phase_js_analysis(alive_targets, js_files, result)

            if self.check_shutdown():
                result.scan_end = datetime.utcnow().isoformat()
                return result

            # Phase 6: Parameter Fuzzing
            self.phase_param_fuzzing(alive_targets, result)

        except Exception as e:
            result.errors.append(f"Fatal error: {str(e)}")
            self.log(f"Fatal error during scan: {e}", "ERROR")
            traceback.print_exc()

        result.scan_end = datetime.utcnow().isoformat()
        return result

    def run(self) -> Dict[str, DeepScanResult]:
        """
        Run deep scan on all configured targets
        """
        self.print_banner()

        # Print configuration
        print(f"\n{'='*80}")
        print("  SCAN CONFIGURATION")
        print(f"{'='*80}")
        print(f"  Targets:    {len(self.config.targets)}")
        print(f"  Program:    {self.config.program or 'None (generic)'}")
        print(f"  Username:   {self.config.username}")
        print(f"  Output:     {self.config.output_dir}")
        skip_phases = []
        if self.config.skip_subdomains:
            skip_phases.append("subdomains")
        if self.config.skip_ports:
            skip_phases.append("ports")
        if self.config.skip_endpoints:
            skip_phases.append("endpoints")
        if self.config.skip_tech:
            skip_phases.append("tech")
        if self.config.skip_js:
            skip_phases.append("js")
        if self.config.skip_fuzz:
            skip_phases.append("fuzz")
        print(f"  Skip phases: {', '.join(skip_phases) or 'None'}")
        print(f"{'='*80}\n")

        if self.config.program:
            print(f"[*] Rate limit: {self.program_config.rate_limit} req/sec")
            print(f"[*] User-Agent: {self.program_config.user_agent}")

        # Scan each target
        for target in self.config.targets:
            if self.check_shutdown():
                break

            result = self.scan_target(target)
            self.results[target] = result

            # Save results after each target
            self.save_results(target, result)

        # Print final summary
        self.print_summary()

        return self.results

    def save_results(self, target: str, result: DeepScanResult):
        """Save scan results to files"""
        # Clean target for folder name
        safe_target = target.replace("://", "_").replace("/", "_").replace(":", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create target-specific output folder
        target_dir = self.config.output_dir / safe_target
        target_dir.mkdir(parents=True, exist_ok=True)

        # Save JSON
        if self.config.save_json:
            json_file = target_dir / f"deep_scan_{timestamp}.json"
            with open(json_file, 'w') as f:
                # Convert dataclass to dict for JSON serialization
                data = {
                    "target": result.target,
                    "program": result.program,
                    "scan_start": result.scan_start,
                    "scan_end": result.scan_end,
                    "summary": {
                        "subdomains_total": result.subdomains_total,
                        "subdomains_alive": result.subdomains_alive,
                        "subdomains_in_scope": result.subdomains_in_scope,
                        "endpoints_total": result.endpoints_total,
                        "endpoints_interesting": result.endpoints_interesting,
                        "js_files_analyzed": result.js_files_analyzed,
                        "secrets_found": len(result.secrets_found),
                        "dom_sinks": len(result.dom_sinks),
                        "vulnerabilities": len(result.vulnerabilities),
                        "potential_issues": len(result.potential_issues),
                        "total_requests": result.total_requests,
                    },
                    "phases_completed": result.phases_completed,
                    "subdomains": result.subdomains,
                    "open_ports": result.open_ports,
                    "endpoints": result.endpoints,
                    "api_endpoints": result.api_endpoints,
                    "technologies": result.technologies,
                    "secrets_found": result.secrets_found,
                    "dom_sinks": result.dom_sinks,
                    "vulnerabilities": result.vulnerabilities,
                    "potential_issues": result.potential_issues,
                    "errors": result.errors,
                }
                json.dump(data, f, indent=2, default=str)
            self.log(f"JSON saved: {json_file}", "SUCCESS")

        # Save TXT summary
        if self.config.save_txt:
            txt_file = target_dir / f"deep_scan_{timestamp}.txt"
            with open(txt_file, 'w') as f:
                f.write("="*80 + "\n")
                f.write("DEEP BUG BOUNTY SCAN REPORT\n")
                f.write("="*80 + "\n\n")

                f.write(f"Target: {result.target}\n")
                f.write(f"Program: {result.program or 'Generic'}\n")
                f.write(f"Scan Start: {result.scan_start}\n")
                f.write(f"Scan End: {result.scan_end}\n")
                f.write(f"Phases Completed: {', '.join(result.phases_completed)}\n\n")

                f.write("-"*40 + "\n")
                f.write("SUMMARY\n")
                f.write("-"*40 + "\n")
                f.write(f"Subdomains: {result.subdomains_alive}/{result.subdomains_total} alive\n")
                f.write(f"In Scope: {result.subdomains_in_scope}\n")
                f.write(f"Endpoints: {result.endpoints_total} ({result.endpoints_interesting} interesting)\n")
                f.write(f"Secrets Found: {len(result.secrets_found)}\n")
                f.write(f"DOM Sinks: {len(result.dom_sinks)}\n")
                f.write(f"Vulnerabilities: {len(result.vulnerabilities)}\n")
                f.write(f"Potential Issues: {len(result.potential_issues)}\n\n")

                # Vulnerabilities
                if result.vulnerabilities:
                    f.write("-"*40 + "\n")
                    f.write("VULNERABILITIES FOUND\n")
                    f.write("-"*40 + "\n")
                    for vuln in result.vulnerabilities:
                        f.write(f"\n[{vuln['severity'].upper()}] {vuln['vuln_type']}\n")
                        f.write(f"  URL: {vuln['url']}\n")
                        f.write(f"  Parameter: {vuln['parameter']}\n")
                        f.write(f"  Payload: {vuln['payload']}\n")
                        f.write(f"  Confidence: {vuln['confidence']}\n")
                    f.write("\n")

                # Secrets
                if result.secrets_found:
                    f.write("-"*40 + "\n")
                    f.write("SECRETS FOUND\n")
                    f.write("-"*40 + "\n")
                    for secret in result.secrets_found:
                        f.write(f"\n[{secret['severity'].upper()}] {secret['type']}\n")
                        f.write(f"  Value: {secret['value']}\n")
                        f.write(f"  File: {secret['file']}\n")
                        f.write(f"  Target: {secret['target']}\n")
                    f.write("\n")

                # Exploitable DOM Sinks
                exploitable_sinks = [s for s in result.dom_sinks if s.get('exploitable')]
                if exploitable_sinks:
                    f.write("-"*40 + "\n")
                    f.write("EXPLOITABLE DOM SINKS\n")
                    f.write("-"*40 + "\n")
                    for sink in exploitable_sinks:
                        f.write(f"\n{sink['sink_type']} in {sink['file']}\n")
                        f.write(f"  Code: {sink['code_snippet'][:100]}\n")
                    f.write("\n")

                # Open Ports
                if result.open_ports:
                    f.write("-"*40 + "\n")
                    f.write("OPEN PORTS\n")
                    f.write("-"*40 + "\n")
                    for host, ports in result.open_ports.items():
                        ports_str = ", ".join(f"{p['port']}({p['service']})" for p in ports)
                        f.write(f"{host}: {ports_str}\n")
                    f.write("\n")

                # Live Subdomains
                alive_subs = [s for s, info in result.subdomains.items() if info.get('is_alive')]
                if alive_subs:
                    f.write("-"*40 + "\n")
                    f.write(f"LIVE SUBDOMAINS ({len(alive_subs)})\n")
                    f.write("-"*40 + "\n")
                    for sub in sorted(alive_subs):
                        info = result.subdomains[sub]
                        scope = "[IN]" if info.get('in_scope') else "[OUT]"
                        f.write(f"  {scope} {sub}\n")
                    f.write("\n")

                # Errors
                if result.errors:
                    f.write("-"*40 + "\n")
                    f.write("ERRORS\n")
                    f.write("-"*40 + "\n")
                    for error in result.errors:
                        f.write(f"  - {error}\n")

            self.log(f"Report saved: {txt_file}", "SUCCESS")

    def print_summary(self):
        """Print final scan summary"""
        print("\n" + "="*80)
        print("  DEEP SCAN COMPLETE - FINAL SUMMARY")
        print("="*80)

        total_vulns = 0
        total_secrets = 0
        total_sinks = 0
        total_subdomains = 0

        for target, result in self.results.items():
            print(f"\n  Target: {target}")
            print(f"  {'─'*40}")
            print(f"  Subdomains:    {result.subdomains_alive}/{result.subdomains_total} alive")
            print(f"  Endpoints:     {result.endpoints_total} ({result.endpoints_interesting} interesting)")
            print(f"  Vulns Found:   {len(result.vulnerabilities)}")
            print(f"  Secrets:       {len(result.secrets_found)}")
            print(f"  DOM Sinks:     {len([s for s in result.dom_sinks if s.get('exploitable')])}")

            total_vulns += len(result.vulnerabilities)
            total_secrets += len(result.secrets_found)
            total_sinks += len([s for s in result.dom_sinks if s.get('exploitable')])
            total_subdomains += result.subdomains_alive

        print(f"\n{'─'*80}")
        print(f"  TOTALS:")
        print(f"  Total Live Subdomains:       {total_subdomains}")
        print(f"  Total Vulnerabilities:       {total_vulns}")
        print(f"  Total Secrets Found:         {total_secrets}")
        print(f"  Total Exploitable Sinks:     {total_sinks}")
        print(f"\n  Results saved to: {self.config.output_dir}")
        print("="*80 + "\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Deep Bug Bounty Scanner - All-in-One Comprehensive Scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single domain (Amazon VRP)
  python deep_scan.py amazon.com -p amazon -u myh1user

  # Scan multiple targets from file
  python deep_scan.py -f targets.txt -p shopify -u myh1user

  # Generic scan without program restrictions
  python deep_scan.py example.com

  # Skip port scanning and fuzzing
  python deep_scan.py example.com --skip-ports --skip-fuzz

  # Custom output directory
  python deep_scan.py example.com -o /path/to/results

NOTE: This scanner has NO TIMEOUT LIMITS.
      It will run until complete or until you press Ctrl+C.
      Use Ctrl+C once for graceful shutdown, twice for force exit.
        """
    )

    # Target arguments
    parser.add_argument("target", nargs="?", help="Target domain (e.g., example.com)")
    parser.add_argument("-f", "--file", help="File containing list of targets (one per line)")

    # Program configuration
    parser.add_argument("-p", "--program", choices=["amazon", "shopify"],
                        help="Bug bounty program (for scope and rate limits)")
    parser.add_argument("-u", "--username", default="yourh1username",
                        help="Your HackerOne username")

    # Output options
    parser.add_argument("-o", "--output", default="./deep_scan_results",
                        help="Output directory for results")

    # Phase control
    parser.add_argument("--skip-subdomains", action="store_true",
                        help="Skip subdomain discovery")
    parser.add_argument("--skip-ports", action="store_true",
                        help="Skip port scanning")
    parser.add_argument("--skip-endpoints", action="store_true",
                        help="Skip endpoint discovery")
    parser.add_argument("--skip-tech", action="store_true",
                        help="Skip technology detection")
    parser.add_argument("--skip-js", action="store_true",
                        help="Skip JavaScript analysis")
    parser.add_argument("--skip-fuzz", action="store_true",
                        help="Skip parameter fuzzing")
    parser.add_argument("--skip-recursive", action="store_true",
                        help="Skip recursive subdomain discovery")

    # Wordlist options
    parser.add_argument("--wordlist", help="Custom subdomain wordlist file")
    parser.add_argument("--no-extended-wordlist", action="store_true",
                        help="Use minimal wordlist (faster, less thorough)")

    # Verbosity
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")

    args = parser.parse_args()

    # Collect targets
    targets = []
    if args.target:
        targets.append(args.target)
    if args.file:
        try:
            with open(args.file) as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"[ERROR] Target file not found: {args.file}")
            sys.exit(1)

    if not targets:
        parser.print_help()
        print("\n[ERROR] No targets specified. Use a domain argument or -f for file.")
        sys.exit(1)

    # Build configuration
    config = DeepScanConfig(
        targets=targets,
        program=args.program,
        username=args.username,
        output_dir=Path(args.output),
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

    # Validate program requirements
    if args.program and args.username == "yourh1username":
        print("[WARNING] Using default username 'yourh1username'")
        print("          Set your actual HackerOne username with -u/--username")
        print()

    # Run scanner
    scanner = DeepScanner(config)
    results = scanner.run()

    # Exit code based on findings
    total_vulns = sum(len(r.vulnerabilities) for r in results.values())
    sys.exit(0 if total_vulns == 0 else 1)


if __name__ == "__main__":
    main()
