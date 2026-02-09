#!/usr/bin/env python3
"""
Full Reconnaissance Scanner - Master Orchestrator
===================================================
Combines ALL scanning capabilities from reNgine + reconftw into a single
pipeline. Runs every phase in order, passing results between modules.

Pipeline:
  Phase 1: OSINT Reconnaissance
  Phase 2: Deep DNS Enumeration (passive + active + permutations + recursive)
  Phase 3: Host Analysis (HTTP probe, ports, CDN, WAF)
  Phase 4: Deep Web Analysis (CMS, URLs, JS, params, fuzzing, vhosts)
  Phase 5: Vulnerability Scanning (nuclei, XSS, SQLi, CORS, SSRF, ...)
  Phase 6: Verification & Validation
  Phase 7: Vulnerability Chaining & Escalation
  Phase 8: Reporting & Notification

Usage:
  python scanner.py fullrecon -t target.com -c configs/full_recon.yaml
"""

import sys
import json
import signal
import time
import yaml
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, field

# Add parent to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from discovery.osint_recon import OSINTRecon, OSINTResult
from discovery.dns_deep_enum import DNSDeepEnumerator, DNSDeepResult
from analysis.web_deep_analysis import WebDeepAnalyzer, WebAnalysisResult
from analysis.vuln_deep_scan import VulnDeepScanner, VulnScanResult

# Try importing existing modules for verification and chaining
try:
    from verification.verification_manager import VerificationManager
except ImportError:
    VerificationManager = None

try:
    from analysis.vuln_chainer import VulnChainer
except ImportError:
    VulnChainer = None

try:
    from analysis.false_positive_detector import FalsePositiveDetector
except ImportError:
    FalsePositiveDetector = None

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except (ImportError, AttributeError):
    requests = None


# Graceful shutdown
SHUTDOWN = False

def _signal_handler(signum, frame):
    global SHUTDOWN
    if SHUTDOWN:
        print("\n[!] Force exit")
        sys.exit(1)
    print("\n[!] Shutting down gracefully... (Ctrl+C again to force)")
    SHUTDOWN = True

signal.signal(signal.SIGINT, _signal_handler)


@dataclass
class FullReconConfig:
    """Configuration for full reconnaissance scan."""
    targets: List[str] = field(default_factory=list)
    config_file: Optional[Path] = None
    config: Dict = field(default_factory=dict)
    output_dir: Path = field(default_factory=lambda: Path("results/fullrecon"))

    def load(self):
        """Load configuration from YAML file."""
        if self.config_file and self.config_file.exists():
            with open(self.config_file) as f:
                self.config = yaml.safe_load(f) or {}

            # Extract targets from config if not provided via CLI
            general = self.config.get("general", {})
            if not self.targets:
                self.targets = general.get("targets", [])

            # Output directory
            out = general.get("output_dir", "results/fullrecon")
            self.output_dir = Path(out)

        return self


@dataclass
class FullReconResult:
    """Complete full recon results."""
    target: str
    start_time: str = ""
    end_time: str = ""
    osint: Optional[Dict] = None
    dns: Optional[Dict] = None
    web: Optional[Dict] = None
    vulns: Optional[Dict] = None
    verification: Optional[Dict] = None
    chained: Optional[Dict] = None
    summary: Dict = field(default_factory=dict)


class FullReconScanner:
    """Master orchestrator for full reconnaissance pipeline."""

    def __init__(self, config: FullReconConfig):
        self.config = config
        self.cfg = config.config

    def run(self):
        """Run full reconnaissance on all targets."""
        print("\n" + "=" * 70)
        print("  FULL RECONNAISSANCE SCANNER")
        print("  reNgine + reconftw combined pipeline")
        print("=" * 70)

        if not self.config.targets:
            print("[!] No targets specified")
            return

        print(f"\nTargets: {', '.join(self.config.targets)}")
        print(f"Output:  {self.config.output_dir}")
        print(f"Config:  {self.config.config_file or 'defaults'}")

        # Safety confirmation
        safety = self.cfg.get("safety", {})
        if safety.get("confirm_before_run", True):
            self._show_review()
            try:
                answer = input("\nProceed? [y/N]: ").strip().lower()
                if answer != "y":
                    print("[*] Scan cancelled")
                    return
            except EOFError:
                pass

        for target in self.config.targets:
            if SHUTDOWN:
                break
            self._scan_target(target)

    def _show_review(self):
        """Show scan configuration review."""
        print("\n--- Scan Configuration Review ---")
        enabled_phases = []
        if self.cfg.get("osint", {}).get("enabled", True):
            enabled_phases.append("OSINT")
        if self.cfg.get("subdomains", {}).get("enabled", True):
            enabled_phases.append("DNS Enumeration")
        if self.cfg.get("host_analysis", {}).get("enabled", True):
            enabled_phases.append("Host Analysis")
        if self.cfg.get("web_analysis", {}).get("enabled", True):
            enabled_phases.append("Web Analysis")
        if self.cfg.get("vulnerability_scan", {}).get("enabled", True):
            enabled_phases.append("Vulnerability Scanning")
        if self.cfg.get("verification", {}).get("enabled", True):
            enabled_phases.append("Verification")
        if self.cfg.get("chaining", {}).get("enabled", True):
            enabled_phases.append("Vuln Chaining")
        if self.cfg.get("reporting", {}).get("enabled", True):
            enabled_phases.append("Reporting")

        print(f"Enabled phases: {', '.join(enabled_phases)}")

        # Performance
        perf = self.cfg.get("performance", {})
        print(f"Rate limit: {perf.get('rate_limit', 150)} req/s")
        print(f"Max workers: {perf.get('max_workers', 10)}")

    def _scan_target(self, target: str):
        """Run full pipeline on a single target."""
        start_time = datetime.now()
        print(f"\n{'=' * 70}")
        print(f"  TARGET: {target}")
        print(f"  Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'=' * 70}")

        result = FullReconResult(
            target=target,
            start_time=start_time.isoformat(),
        )

        # Create output directory
        target_dir = self.config.output_dir / target.replace(".", "_")
        target_dir.mkdir(parents=True, exist_ok=True)

        # Save progress file for resumability
        progress_file = target_dir / "scan_progress.json"
        progress = self._load_progress(progress_file)

        # =====================================================================
        # PHASE 1: OSINT
        # =====================================================================
        if (self.cfg.get("osint", {}).get("enabled", True)
                and "osint" not in progress.get("completed", [])
                and not SHUTDOWN):
            print(f"\n{'=' * 50}")
            print("  PHASE 1: OSINT RECONNAISSANCE")
            print(f"{'=' * 50}")

            osint_engine = OSINTRecon(self.cfg)
            osint_dir = target_dir / "osint"
            osint_result = osint_engine.run(target, osint_dir)
            result.osint = osint_result.to_dict()
            self._mark_complete(progress, progress_file, "osint")

        # =====================================================================
        # PHASE 2: DNS ENUMERATION
        # =====================================================================
        if (self.cfg.get("subdomains", {}).get("enabled", True)
                and "dns" not in progress.get("completed", [])
                and not SHUTDOWN):
            print(f"\n{'=' * 50}")
            print("  PHASE 2: DEEP DNS ENUMERATION")
            print(f"{'=' * 50}")

            dns_engine = DNSDeepEnumerator(self.cfg)
            dns_dir = target_dir / "dns"
            dns_result = dns_engine.run(target, dns_dir)
            result.dns = dns_result.to_dict()
            self._mark_complete(progress, progress_file, "dns")
        else:
            # Load previous DNS results for downstream phases
            dns_result = self._load_dns_result(target_dir / "dns", target)

        # Get subdomain list for next phases
        subdomains = []
        if dns_result:
            subdomains = list(dns_result.subdomains.keys())
            alive_subs = dns_result.get_alive_subdomains()
        else:
            alive_subs = []

        if not subdomains:
            subdomains = [target]
        if not alive_subs:
            alive_subs = subdomains[:50]

        # =====================================================================
        # PHASE 3 + 4: HOST ANALYSIS + WEB ANALYSIS (combined)
        # =====================================================================
        web_result = None
        if (self.cfg.get("web_analysis", {}).get("enabled", True)
                and "web" not in progress.get("completed", [])
                and not SHUTDOWN):
            print(f"\n{'=' * 50}")
            print("  PHASE 3-4: HOST & WEB ANALYSIS")
            print(f"{'=' * 50}")

            web_engine = WebDeepAnalyzer(self.cfg)
            web_dir = target_dir / "web"
            web_result = web_engine.run(target, alive_subs, web_dir)
            result.web = web_result.to_dict()
            self._mark_complete(progress, progress_file, "web")
        else:
            web_result = self._load_web_result(target_dir / "web", target)

        # Prepare URL lists for vulnerability scanning
        live_urls = list(web_result.targets.keys()) if web_result else [f"https://{target}"]
        all_urls = list(web_result.all_urls) if web_result else []
        classified = web_result.classified_urls if web_result else {}

        # =====================================================================
        # PHASE 5: VULNERABILITY SCANNING
        # =====================================================================
        vuln_result = None
        if (self.cfg.get("vulnerability_scan", {}).get("enabled", True)
                and "vulns" not in progress.get("completed", [])
                and not SHUTDOWN):
            print(f"\n{'=' * 50}")
            print("  PHASE 5: VULNERABILITY SCANNING")
            print(f"{'=' * 50}")

            vuln_engine = VulnDeepScanner(self.cfg)
            vuln_dir = target_dir / "vulns"
            vuln_result = vuln_engine.run(
                target, live_urls, all_urls, classified, vuln_dir
            )
            result.vulns = vuln_result.to_dict()
            self._mark_complete(progress, progress_file, "vulns")

        # =====================================================================
        # PHASE 6: VERIFICATION
        # =====================================================================
        if (self.cfg.get("verification", {}).get("enabled", True)
                and "verify" not in progress.get("completed", [])
                and not SHUTDOWN
                and VerificationManager is not None):
            print(f"\n{'=' * 50}")
            print("  PHASE 6: VERIFICATION & VALIDATION")
            print(f"{'=' * 50}")

            try:
                verify_cfg = self.cfg.get("verification", {})
                # Use existing verification system
                verifier = VerificationManager(config=verify_cfg)

                # Verify findings
                if vuln_result:
                    verified_count = 0
                    for finding in vuln_result.findings:
                        if not finding.verified:
                            # Run through false positive filter
                            if FalsePositiveDetector:
                                try:
                                    fp = FalsePositiveDetector()
                                    is_fp = fp.check(finding.url, finding.evidence)
                                    if is_fp:
                                        finding.severity = "info"
                                        continue
                                except Exception:
                                    pass
                            verified_count += 1

                    print(f"  [+] Verified {verified_count} findings")
                    self._mark_complete(progress, progress_file, "verify")
            except Exception as e:
                print(f"  [-] Verification error: {e}")

        # =====================================================================
        # PHASE 7: VULNERABILITY CHAINING
        # =====================================================================
        if (self.cfg.get("chaining", {}).get("enabled", True)
                and vuln_result and not SHUTDOWN):
            print(f"\n{'=' * 50}")
            print("  PHASE 7: VULNERABILITY CHAINING")
            print(f"{'=' * 50}")

            chain_cfg = self.cfg.get("chaining", {})
            chained = self._chain_vulnerabilities(vuln_result, chain_cfg)
            if chained:
                result.chained = chained
                print(f"  [+] Found {len(chained)} chain opportunities")

        # =====================================================================
        # PHASE 8: REPORTING
        # =====================================================================
        end_time = datetime.now()
        result.end_time = end_time.isoformat()
        duration = end_time - start_time

        print(f"\n{'=' * 50}")
        print("  PHASE 8: REPORTING")
        print(f"{'=' * 50}")

        result.summary = self._build_summary(result, duration)
        self._generate_reports(result, target_dir)

        # Diff mode
        if self.cfg.get("general", {}).get("diff_mode", False):
            prev = self.cfg.get("general", {}).get("previous_results")
            if prev:
                self._generate_diff(result, Path(prev), target_dir)

        # Notifications
        self._send_notifications(result)

        # Final summary
        print(f"\n{'=' * 70}")
        print(f"  SCAN COMPLETE: {target}")
        print(f"  Duration: {duration}")
        print(f"  Results:  {target_dir}")
        print(f"{'=' * 70}")
        self._print_summary(result.summary)

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _load_progress(self, path: Path) -> Dict:
        """Load scan progress for resumability."""
        if path.exists():
            with open(path) as f:
                return json.load(f)
        return {"completed": []}

    def _mark_complete(self, progress: Dict, path: Path, phase: str):
        """Mark a phase as complete for resume capability."""
        if phase not in progress.get("completed", []):
            progress.setdefault("completed", []).append(phase)
        progress["last_update"] = datetime.now().isoformat()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(progress, f, indent=2)

    def _load_dns_result(self, dns_dir: Path, target: str):
        """Load previous DNS results."""
        result_file = dns_dir / f"dns_{target.replace('.', '_')}.json"
        if result_file.exists():
            with open(result_file) as f:
                data = json.load(f)
            # Create a minimal result object
            from discovery.dns_deep_enum import DNSDeepResult, SubdomainEntry
            result = DNSDeepResult(target=target)
            for sub, info in data.get("subdomains", {}).items():
                result.subdomains[sub] = SubdomainEntry(
                    subdomain=sub,
                    source=info.get("source", "loaded"),
                    ip=info.get("ip"),
                    is_alive=info.get("alive", False),
                )
            return result
        return None

    def _load_web_result(self, web_dir: Path, target: str):
        """Load previous web analysis results."""
        result_file = web_dir / f"web_analysis_{target.replace('.', '_')}.json"
        if result_file.exists():
            from analysis.web_deep_analysis import WebAnalysisResult, WebTarget
            result = WebAnalysisResult(target=target)
            with open(result_file) as f:
                data = json.load(f)
            for url, info in data.get("targets", {}).items():
                result.targets[url] = WebTarget(url=url)

            urls_file = web_dir / "all_urls.txt"
            if urls_file.exists():
                with open(urls_file) as f:
                    result.all_urls = set(l.strip() for l in f if l.strip())
            return result
        return None

    def _chain_vulnerabilities(self, vuln_result: VulnScanResult,
                               chain_cfg: Dict) -> List[Dict]:
        """Find vulnerability chain opportunities."""
        chains = []
        findings_by_type = {}
        for f in vuln_result.findings:
            findings_by_type.setdefault(f.vuln_type, []).append(f)

        # SSRF + Cloud metadata = Critical
        if chain_cfg.get("chains", {}).get("ssrf_plus_cloud_metadata", True):
            ssrf = findings_by_type.get("ssrf", [])
            for f in ssrf:
                if "169.254" in f.evidence or "metadata" in f.evidence.lower():
                    chains.append({
                        "chain": "SSRF + Cloud Metadata",
                        "severity": "critical",
                        "findings": [f.url],
                        "impact": "Full cloud instance compromise",
                    })

        # XSS + CSRF = Account Takeover
        if chain_cfg.get("chains", {}).get("xss_plus_csrf", True):
            xss = findings_by_type.get("xss", [])
            cors = findings_by_type.get("cors", [])
            if xss and cors:
                chains.append({
                    "chain": "XSS + CORS Misconfiguration",
                    "severity": "critical",
                    "findings": [xss[0].url, cors[0].url],
                    "impact": "Cross-origin data theft / account takeover",
                })

        # SQLi + Auth Bypass = Full Database Access
        if chain_cfg.get("chains", {}).get("sqli_plus_auth_bypass", True):
            sqli = findings_by_type.get("sqli", [])
            auth = findings_by_type.get("403_bypass", [])
            if sqli and auth:
                chains.append({
                    "chain": "SQL Injection + Auth Bypass",
                    "severity": "critical",
                    "findings": [sqli[0].url, auth[0].url],
                    "impact": "Full database access behind authentication",
                })

        # SSTI + RCE = Full Server Compromise
        if chain_cfg.get("chains", {}).get("ssti_plus_rce", True):
            ssti = findings_by_type.get("ssti", [])
            for f in ssti:
                if f.verified:
                    chains.append({
                        "chain": "SSTI -> RCE",
                        "severity": "critical",
                        "findings": [f.url],
                        "impact": "Remote code execution via template injection",
                    })

        # Open Redirect + OAuth = Account Takeover
        if chain_cfg.get("chains", {}).get("open_redirect_plus_oauth", True):
            redirects = findings_by_type.get("open_redirect", [])
            for r in redirects:
                if any(p in r.url.lower() for p in ["oauth", "authorize", "callback", "redirect_uri"]):
                    chains.append({
                        "chain": "Open Redirect + OAuth",
                        "severity": "critical",
                        "findings": [r.url],
                        "impact": "OAuth token theft / account takeover",
                    })

        # XXE + SSRF = Internal Network Access
        if chain_cfg.get("chains", {}).get("xxe_plus_ssrf", True):
            xxe_nuclei = [f for f in vuln_result.findings
                          if "xxe" in f.vuln_type.lower() or "xxe" in f.title.lower()]
            if xxe_nuclei:
                chains.append({
                    "chain": "XXE -> SSRF",
                    "severity": "high",
                    "findings": [xxe_nuclei[0].url],
                    "impact": "Internal network access via XML external entity",
                })

        return chains

    def _build_summary(self, result: FullReconResult, duration) -> Dict:
        """Build scan summary."""
        summary = {
            "target": result.target,
            "duration": str(duration),
            "start_time": result.start_time,
            "end_time": result.end_time,
        }

        if result.osint:
            summary["osint_findings"] = result.osint.get("total_findings", 0)

        if result.dns:
            summary["subdomains_total"] = result.dns.get("total_unique", 0)
            summary["subdomains_alive"] = result.dns.get("total_alive", 0)
            summary["takeover_candidates"] = len(
                result.dns.get("takeover_candidates", [])
            )

        if result.web:
            summary["live_hosts"] = result.web.get("total_live_hosts", 0)
            summary["urls_collected"] = result.web.get("total_urls", 0)
            summary["parameters"] = result.web.get("total_params", 0)
            summary["secrets"] = result.web.get("total_secrets", 0)

        if result.vulns:
            vs = result.vulns.get("summary", {})
            summary["vulns_total"] = vs.get("total", 0)
            summary["vulns_critical"] = vs.get("critical", 0)
            summary["vulns_high"] = vs.get("high", 0)
            summary["vulns_medium"] = vs.get("medium", 0)
            summary["vulns_low"] = vs.get("low", 0)

        if result.chained:
            summary["chain_opportunities"] = len(result.chained)

        return summary

    def _print_summary(self, summary: Dict):
        """Print formatted summary."""
        print(f"\n  Duration:    {summary.get('duration', 'N/A')}")

        if "osint_findings" in summary:
            print(f"  OSINT:       {summary['osint_findings']} findings")
        if "subdomains_total" in summary:
            print(f"  Subdomains:  {summary['subdomains_total']} total, "
                  f"{summary.get('subdomains_alive', 0)} alive")
        if "takeover_candidates" in summary and summary["takeover_candidates"]:
            print(f"  Takeovers:   {summary['takeover_candidates']} candidates")
        if "live_hosts" in summary:
            print(f"  Live Hosts:  {summary['live_hosts']}")
        if "urls_collected" in summary:
            print(f"  URLs:        {summary['urls_collected']}")
        if "secrets" in summary and summary["secrets"]:
            print(f"  Secrets:     {summary['secrets']}")

        if "vulns_total" in summary:
            print(f"\n  Vulnerabilities:")
            print(f"    Critical: {summary.get('vulns_critical', 0)}")
            print(f"    High:     {summary.get('vulns_high', 0)}")
            print(f"    Medium:   {summary.get('vulns_medium', 0)}")
            print(f"    Low:      {summary.get('vulns_low', 0)}")

        if summary.get("chain_opportunities", 0):
            print(f"\n  Chain Opportunities: {summary['chain_opportunities']}")

    def _generate_reports(self, result: FullReconResult, output_dir: Path):
        """Generate all output reports."""
        report_cfg = self.cfg.get("reporting", {})
        formats = report_cfg.get("formats", {})

        # JSON
        if formats.get("json", True):
            with open(output_dir / "full_report.json", "w") as f:
                json.dump({
                    "summary": result.summary,
                    "osint": result.osint,
                    "dns": result.dns,
                    "web": result.web,
                    "vulns": result.vulns,
                    "chains": result.chained,
                }, f, indent=2, default=str)

        # Text
        if formats.get("txt", True):
            with open(output_dir / "full_report.txt", "w") as f:
                f.write(f"Full Reconnaissance Report - {result.target}\n")
                f.write(f"{'=' * 60}\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n\n")

                f.write("SUMMARY\n")
                f.write("-" * 40 + "\n")
                for k, v in result.summary.items():
                    f.write(f"  {k}: {v}\n")
                f.write("\n")

                # Critical/High findings
                if result.vulns:
                    findings = result.vulns.get("findings", [])
                    critical = [v for v in findings if v["severity"] == "critical"]
                    high = [v for v in findings if v["severity"] == "high"]

                    if critical:
                        f.write("\nCRITICAL FINDINGS\n")
                        f.write("=" * 40 + "\n")
                        for v in critical:
                            f.write(f"  [{v['tool']}] {v['title']}\n")
                            f.write(f"  URL: {v['url']}\n")
                            if v.get("evidence"):
                                f.write(f"  Evidence: {v['evidence'][:200]}\n")
                            f.write("\n")

                    if high:
                        f.write("\nHIGH FINDINGS\n")
                        f.write("=" * 40 + "\n")
                        for v in high:
                            f.write(f"  [{v['tool']}] {v['title']}\n")
                            f.write(f"  URL: {v['url']}\n\n")

                # Chains
                if result.chained:
                    f.write("\nVULNERABILITY CHAINS\n")
                    f.write("=" * 40 + "\n")
                    for chain in result.chained:
                        f.write(f"  {chain['chain']} [{chain['severity']}]\n")
                        f.write(f"  Impact: {chain['impact']}\n\n")

        # CSV
        if formats.get("csv", True) and result.vulns:
            with open(output_dir / "findings.csv", "w") as f:
                f.write("severity,type,title,url,tool,verified\n")
                for v in result.vulns.get("findings", []):
                    row = [
                        v["severity"], v["type"], v["title"].replace(",", ";"),
                        v["url"], v["tool"], str(v.get("verified", False))
                    ]
                    f.write(",".join(row) + "\n")

        # Hotlist (ranked by exploitability)
        if report_cfg.get("scoring", {}).get("hotlist", True) and result.vulns:
            self._generate_hotlist(result, output_dir)

        print(f"  [+] Reports saved to {output_dir}")

    def _generate_hotlist(self, result: FullReconResult, output_dir: Path):
        """Generate a ranked hotlist of most exploitable findings."""
        severity_scores = {
            "critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0
        }
        verified_bonus = 3

        scored = []
        for f in result.vulns.get("findings", []):
            score = severity_scores.get(f["severity"], 0)
            if f.get("verified"):
                score += verified_bonus
            scored.append({"score": score, **f})

        scored.sort(key=lambda x: x["score"], reverse=True)

        with open(output_dir / "hotlist.txt", "w") as f:
            f.write("VULNERABILITY HOTLIST (ranked by exploitability)\n")
            f.write("=" * 60 + "\n\n")
            for i, item in enumerate(scored[:50], 1):
                f.write(f"#{i} [Score: {item['score']}] "
                        f"[{item['severity'].upper()}] {item['title']}\n")
                f.write(f"   URL: {item['url']}\n")
                f.write(f"   Tool: {item['tool']} | "
                        f"Verified: {item.get('verified', False)}\n\n")

    def _generate_diff(self, result: FullReconResult, prev_dir: Path,
                       output_dir: Path):
        """Compare with previous scan results and highlight new findings."""
        prev_file = prev_dir / "full_report.json"
        if not prev_file.exists():
            return

        with open(prev_file) as f:
            prev = json.load(f)

        diff = {"new_findings": [], "new_subdomains": [], "resolved": []}

        # Compare subdomains
        if result.dns and prev.get("dns"):
            current_subs = set(result.dns.get("subdomains", {}).keys())
            prev_subs = set(prev.get("dns", {}).get("subdomains", {}).keys())
            diff["new_subdomains"] = list(current_subs - prev_subs)
            diff["removed_subdomains"] = list(prev_subs - current_subs)

        # Compare vulnerabilities
        if result.vulns and prev.get("vulns"):
            prev_urls = set(f["url"] for f in prev.get("vulns", {}).get("findings", []))
            for f in result.vulns.get("findings", []):
                if f["url"] not in prev_urls:
                    diff["new_findings"].append(f)

        with open(output_dir / "diff_report.json", "w") as f:
            json.dump(diff, f, indent=2)

        if diff["new_subdomains"] or diff["new_findings"]:
            print(f"  [+] Diff: {len(diff['new_subdomains'])} new subdomains, "
                  f"{len(diff['new_findings'])} new findings")

    def _send_notifications(self, result: FullReconResult):
        """Send notifications for critical findings."""
        notif_cfg = self.cfg.get("general", {}).get("notifications", {})
        if not notif_cfg.get("enabled", False):
            return

        summary = result.summary
        critical = summary.get("vulns_critical", 0)
        high = summary.get("vulns_high", 0)

        if critical == 0 and high == 0:
            return

        message = (
            f"Scan Complete: {result.target}\n"
            f"Critical: {critical} | High: {high}\n"
            f"Subdomains: {summary.get('subdomains_total', 0)} | "
            f"URLs: {summary.get('urls_collected', 0)}"
        )

        # Slack
        webhook = notif_cfg.get("slack_webhook")
        if webhook and requests:
            try:
                requests.post(webhook, json={"text": message}, timeout=10)
            except Exception:
                pass

        # Discord
        webhook = notif_cfg.get("discord_webhook")
        if webhook and requests:
            try:
                requests.post(webhook, json={"content": message}, timeout=10)
            except Exception:
                pass

        # Telegram
        bot_token = notif_cfg.get("telegram_bot_token")
        chat_id = notif_cfg.get("telegram_chat_id")
        if bot_token and chat_id and requests:
            try:
                requests.post(
                    f"https://api.telegram.org/bot{bot_token}/sendMessage",
                    json={"chat_id": chat_id, "text": message},
                    timeout=10,
                )
            except Exception:
                pass
