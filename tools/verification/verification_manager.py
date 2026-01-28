"""
Verification Manager
====================

Orchestrates all verification modules and manages the verification process.
"""

from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import traceback

from . import VerificationResult, Severity, ConfidenceLevel
from .redirect_verifier import RedirectVerifier
from .service_verifier import ServiceVerifier
from .git_verifier import GitVerifier
from .graphql_verifier import GraphQLVerifier
from .ssti_verifier import SSTIVerifier
from .admin_verifier import AdminVerifier
from .api_verifier import APIVerifier
from .backup_verifier import BackupVerifier


@dataclass
class VerificationSummary:
    """Summary of verification results"""
    total_findings: int = 0
    verified_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    false_positives: int = 0
    
    def to_dict(self) -> Dict[str, int]:
        return {
            "total_findings": self.total_findings,
            "verified_findings": self.verified_findings,
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "info": self.info_count,
            "false_positives": self.false_positives,
        }


class VerificationManager:
    """
    Manages all verification processes
    Coordinates different verifiers and consolidates results
    """
    
    def __init__(
        self, 
        user_agent: Optional[str] = None,
        timeout: int = 10,
        max_workers: int = 10,
        verbose: bool = True
    ):
        self.user_agent = user_agent
        self.timeout = timeout
        self.max_workers = max_workers
        self.verbose = verbose
        
        # Initialize all verifiers
        self.redirect_verifier = RedirectVerifier(user_agent, timeout)
        self.service_verifier = ServiceVerifier(user_agent, timeout)
        self.git_verifier = GitVerifier(user_agent, timeout)
        self.graphql_verifier = GraphQLVerifier(user_agent, timeout)
        self.ssti_verifier = SSTIVerifier(user_agent, timeout)
        self.admin_verifier = AdminVerifier(user_agent, timeout)
        self.api_verifier = APIVerifier(user_agent, timeout)
        self.backup_verifier = BackupVerifier(user_agent, timeout)
        
        self.all_results: List[VerificationResult] = []
    
    def log(self, message: str, level: str = "INFO"):
        """Log a message if verbose mode is enabled"""
        if self.verbose:
            prefix = {
                "INFO": "[*]",
                "SUCCESS": "[+]",
                "WARNING": "[!]",
                "ERROR": "[ERROR]",
                "FINDING": "[!!!]",
            }.get(level, "[*]")
            print(f"{prefix} {message}")
    
    def verify_scan_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify findings from a completed scan
        
        Args:
            scan_results: Dict with scan results (from DeepScanResult)
        
        Returns:
            Enhanced scan results with verification data
        """
        self.log("Starting vulnerability verification...", "INFO")
        
        verified_results = []
        
        # 1. Verify endpoints (redirects)
        if "endpoints" in scan_results:
            self.log(f"Verifying {len(scan_results['endpoints'])} endpoints...", "INFO")
            endpoint_results = self._verify_endpoints(scan_results["endpoints"])
            verified_results.extend(endpoint_results)
        
        # 2. Verify open ports (services)
        if "open_ports" in scan_results:
            self.log("Verifying open ports...", "INFO")
            port_results = self._verify_ports(scan_results["open_ports"])
            verified_results.extend(port_results)
        
        # 3. Check for .git exposure
        targets = self._extract_targets(scan_results)
        if targets:
            self.log(f"Checking {len(targets)} targets for .git exposure...", "INFO")
            git_results = self._verify_git_exposure(targets)
            verified_results.extend(git_results)
            
            # 4. Check for GraphQL
            self.log("Checking for GraphQL endpoints...", "INFO")
            graphql_results = self._verify_graphql(targets)
            verified_results.extend(graphql_results)
            
            # 5. Check for admin panels
            self.log("Checking for admin panels...", "INFO")
            admin_results = self._verify_admin_panels(targets)
            verified_results.extend(admin_results)
            
            # 6. Check for API endpoints
            self.log("Checking for API endpoints...", "INFO")
            api_results = self._verify_apis(targets)
            verified_results.extend(api_results)
            
            # 7. Check for backup files
            self.log("Checking for backup file exposure...", "INFO")
            backup_results = self._verify_backups(targets)
            verified_results.extend(backup_results)
        
        # 8. Verify potential issues (SSTI, etc.)
        if "potential_issues" in scan_results:
            issue_results = self._verify_potential_issues(scan_results["potential_issues"], targets)
            verified_results.extend(issue_results)
        
        # Consolidate results
        self.all_results = verified_results
        summary = self._generate_summary()
        
        self.log(f"Verification complete: {summary.verified_findings}/{summary.total_findings} findings verified", "SUCCESS")
        self.log(f"  Critical: {summary.critical_count}, High: {summary.high_count}, Medium: {summary.medium_count}", "SUCCESS")
        
        # Add verification data to scan results
        scan_results["verified_findings"] = [r.to_dict() for r in verified_results if r.verified]
        scan_results["verification_summary"] = summary.to_dict()
        
        return scan_results
    
    def _verify_endpoints(self, endpoints: List[Dict]) -> List[VerificationResult]:
        """Verify endpoint accessibility by following redirects"""
        results = []
        
        # Filter interesting endpoints with 301 status
        to_verify = [ep for ep in endpoints if ep.get("status_code") in [301, 302] and ep.get("interesting")]
        
        if not to_verify:
            return results
        
        # Verify in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.redirect_verifier.verify, ep["url"], ep.get("status_code")): ep
                for ep in to_verify[:50]  # Limit to top 50 interesting endpoints
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result.verified and result.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
                        self.log(f"  Found: {result.details[:80]}...", "FINDING")
                
                except Exception as e:
                    self.log(f"  Error verifying endpoint: {e}", "ERROR")
        
        return results
    
    def _verify_ports(self, open_ports: Dict[str, List[Dict]]) -> List[VerificationResult]:
        """Verify open ports/services"""
        results = []
        
        for host, ports in open_ports.items():
            for port_info in ports:
                port = port_info.get("port")
                service = port_info.get("service", "unknown")
                
                try:
                    result = self.service_verifier.verify_port(host, port, service)
                    results.append(result)
                    
                    if result.verified and result.severity in [Severity.CRITICAL, Severity.HIGH]:
                        self.log(f"  CRITICAL: {result.details}", "FINDING")
                
                except Exception as e:
                    self.log(f"  Error verifying {host}:{port}: {e}", "ERROR")
        
        return results
    
    def _verify_git_exposure(self, targets: List[str]) -> List[VerificationResult]:
        """Check for .git repository exposure"""
        results = []
        
        for target in targets[:10]:  # Limit to top 10 targets
            try:
                result = self.git_verifier.verify(target)
                results.append(result)
                
                if result.verified and result.severity in [Severity.CRITICAL, Severity.HIGH]:
                    self.log(f"  CRITICAL: {result.details}", "FINDING")
            
            except Exception as e:
                self.log(f"  Error checking .git on {target}: {e}", "ERROR")
        
        return results
    
    def _verify_graphql(self, targets: List[str]) -> List[VerificationResult]:
        """Verify GraphQL endpoints"""
        results = []
        
        for target in targets[:10]:
            graphql_url = f"https://{target}/graphql" if not target.startswith('http') else f"{target}/graphql"
            
            try:
                result = self.graphql_verifier.verify(graphql_url)
                results.append(result)
                
                if result.verified and result.severity in [Severity.MEDIUM, Severity.HIGH]:
                    self.log(f"  Found: {result.details}", "SUCCESS")
            
            except Exception as e:
                self.log(f"  Error checking GraphQL on {target}: {e}", "ERROR")
        
        return results
    
    def _verify_admin_panels(self, targets: List[str]) -> List[VerificationResult]:
        """Check for admin panel exposure"""
        results = []
        
        for target in targets[:5]:  # Limit to top 5
            try:
                admin_results = self.admin_verifier.verify(f"https://{target}" if not target.startswith('http') else target)
                results.extend(admin_results)
                
                for result in admin_results:
                    if result.verified and result.severity in [Severity.CRITICAL, Severity.HIGH]:
                        self.log(f"  Found: {result.details}", "FINDING")
            
            except Exception as e:
                self.log(f"  Error checking admin panels on {target}: {e}", "ERROR")
        
        return results
    
    def _verify_apis(self, targets: List[str]) -> List[VerificationResult]:
        """Verify API endpoint exposure"""
        results = []
        
        for target in targets[:10]:
            try:
                api_results = self.api_verifier.verify_api(f"https://{target}" if not target.startswith('http') else target)
                results.extend(api_results)
                
                for result in api_results:
                    if result.verified and result.severity in [Severity.MEDIUM, Severity.HIGH]:
                        self.log(f"  Found: {result.details[:80]}...", "SUCCESS")
            
            except Exception as e:
                self.log(f"  Error checking APIs on {target}: {e}", "ERROR")
        
        return results
    
    def _verify_backups(self, targets: List[str]) -> List[VerificationResult]:
        """Check for backup file exposure"""
        results = []
        
        for target in targets[:5]:  # Limit to top 5
            try:
                backup_results = self.backup_verifier.verify(f"https://{target}" if not target.startswith('http') else target)
                results.extend(backup_results)
                
                for result in backup_results:
                    if result.verified and result.severity == Severity.CRITICAL:
                        self.log(f"  CRITICAL: {result.details}", "FINDING")
            
            except Exception as e:
                self.log(f"  Error checking backups on {target}: {e}", "ERROR")
        
        return results
    
    def _verify_potential_issues(self, potential_issues: List[Dict], targets: List[str]) -> List[VerificationResult]:
        """Verify potential issues like SSTI"""
        results = []
        
        for issue in potential_issues:
            if issue.get("technology") == "flask":
                # Test for SSTI
                target_url = f"https://{issue.get('target', targets[0])}" if targets else None
                if target_url:
                    try:
                        result = self.ssti_verifier.verify_url(target_url)
                        results.append(result)
                        
                        if result.verified:
                            self.log(f"  CRITICAL SSTI: {result.details}", "FINDING")
                    except:
                        pass
        
        return results
    
    def _extract_targets(self, scan_results: Dict[str, Any]) -> List[str]:
        """Extract target URLs from scan results"""
        targets = []
        
        # Get alive subdomains
        if "subdomains" in scan_results:
            for subdomain, info in scan_results["subdomains"].items():
                if info.get("is_alive") and info.get("in_scope", True):
                    targets.append(subdomain)
        
        # Get from target field
        if "target" in scan_results:
            targets.append(scan_results["target"])
        
        return list(set(targets))  # Remove duplicates
    
    def _generate_summary(self) -> VerificationSummary:
        """Generate verification summary"""
        summary = VerificationSummary()
        summary.total_findings = len(self.all_results)
        
        for result in self.all_results:
            if result.verified:
                summary.verified_findings += 1
                
                if result.severity == Severity.CRITICAL:
                    summary.critical_count += 1
                elif result.severity == Severity.HIGH:
                    summary.high_count += 1
                elif result.severity == Severity.MEDIUM:
                    summary.medium_count += 1
                elif result.severity == Severity.LOW:
                    summary.low_count += 1
                else:
                    summary.info_count += 1
            
            elif result.finding_type in ["false_positive", "no_git_exposure", "port_closed"]:
                summary.false_positives += 1
        
        return summary
