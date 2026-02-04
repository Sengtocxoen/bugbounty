#!/usr/bin/env python3
"""
Vulnerability Chaining Engine
Automatically chains low-severity findings into high-impact exploits.
Detects and escalates vulnerability chains like: SSRF + IDOR, Hidden Dir + Deep Scan, XSS + CSRF.
"""

import re
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime
from enum import Enum


class VulnType(Enum):
    """Types of vulnerabilities"""
    SSRF = "SSRF"
    IDOR = "IDOR"
    XSS = "XSS"
    CSRF = "CSRF"
    AUTH_BYPASS = "AuthBypass"
    HIDDEN_DIR = "HiddenDirectory"
    INFO_LEAK = "InformationLeakage"
    SQLI = "SQLInjection"
    FILE_UPLOAD = "FileUpload"
    LFI = "LocalFileInclusion"
    RCE = "RemoteCodeExecution"
    XXE = "XXE"


@dataclass
class Vulnerability:
    """A single vulnerability finding"""
    vuln_id: str
    vuln_type: VulnType
    severity: str  # low, medium, high, critical
    description: str
    url: str
    parameter: str = ""
    poc: str = ""
    cvss_score: float = 0.0
    metadata: Dict = field(default_factory=dict)


@dataclass
class VulnChain:
    """A chain of vulnerabilities"""
    chain_id: str
    vulnerabilities: List[Vulnerability]
    chain_type: str  # e.g., "SSRF->IDOR", "Hidden->DeepScan"
    combined_severity: str
    combined_cvss: float
    attack_narrative: str  # Human-readable PoC
    auto_discovered: bool = True


class VulnerabilityChainer:
    """Automatically detect and chain vulnerabilities"""
    
    # Chain rules: (vuln1_type, vuln2_type) -> chain_type
    CHAIN_RULES = {
        (VulnType.SSRF, VulnType.INFO_LEAK): "SSRF_TO_INFO_LEAK",
        (VulnType.SSRF, VulnType.IDOR): "SSRF_TO_IDOR",
        (VulnType.IDOR, VulnType.AUTH_BYPASS): "IDOR_TO_AUTH_BYPASS",
        (VulnType.XSS, VulnType.CSRF): "XSS_TO_CSRF",
        (VulnType.HIDDEN_DIR, VulnType.INFO_LEAK): "HIDDEN_DIR_TO_LEAK",
        (VulnType.LFI, VulnType.RCE): "LFI_TO_RCE",
        (VulnType.FILE_UPLOAD, VulnType.RCE): "UPLOAD_TO_RCE",
        (VulnType.XXE, VulnType.INFO_LEAK): "XXE_TO_INFO_LEAK",
    }
    
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.chains: List[VulnChain] = []
    
    def add_vulnerability(self, vuln: Vulnerability):
        """Add a vulnerability to the pool"""
        self.vulnerabilities.append(vuln)
    
    def _calculate_combined_cvss(self, vulns: List[Vulnerability]) -> float:
        """
        Calculate combined CVSS score for chained vulnerabilities
        Using a simplified model: max(scores) + 0.3 * sum(other scores)
        """
        if not vulns:
            return 0.0
        
        scores = [v.cvss_score for v in vulns if v.cvss_score > 0]
        if not scores:
            # Estimate from severity
            severity_to_cvss = {
                'low': 3.0,
                'medium': 5.5,
                'high': 7.5,
                'critical': 9.5
            }
            scores = [severity_to_cvss.get(v.severity.lower(), 5.0) for v in vulns]
        
        if len(scores) == 1:
            return scores[0]
        
        max_score = max(scores)
        other_scores = [s for s in scores if s != max_score]
        
        combined = max_score + (0.3 * sum(other_scores))
        return min(combined, 10.0)  # Cap at 10.0
    
    def _determine_combined_severity(self, cvss: float) -> str:
        """Determine severity from CVSS score"""
        if cvss >= 9.0:
            return "critical"
        elif cvss >= 7.0:
            return "high"
        elif cvss >= 4.0:
            return "medium"
        else:
            return "low"
    
    def _generate_attack_narrative(self, chain_type: str, vulns: List[Vulnerability]) -> str:
        """Generate human-readable attack narrative"""
        narratives = {
            "SSRF_TO_INFO_LEAK": """
1. SSRF vulnerability allows access to internal services
2. Use SSRF to access {url} which contains {info}
3. Chain allows exfiltration of sensitive data from internal network
PoC: Use SSRF payload to access cloud metadata or internal APIs
""",
            "SSRF_TO_IDOR": """
1. SSRF vulnerability found at {ssrf_url}
2. IDOR vulnerability found at {idor_url}
3. Combine: Use SSRF to access internal API with IDOR to escalate privileges
PoC: SSRF -> internal admin API -> IDOR to access all user accounts
""",
            "IDOR_TO_AUTH_BYPASS": """
1. IDOR allows access to other users' resources
2. Auth bypass allows manipulation of access controls
3. Chain allows complete account takeover
PoC: Enumerate user IDs via IDOR, bypass auth to access admin functions
""",
            "XSS_TO_CSRF": """
1. XSS vulnerability allows script injection
2. CSRF vulnerability allows state-changing actions without token
3. Combine to perform actions on behalf of victim
PoC: Inject XSS that triggers CSRF to change victim's  email/password
""",
            "HIDDEN_DIR_TO_LEAK": """
1. Hidden directory discovered via fuzzing
2. Directory contains sensitive information
3. Information leakage leads to further attacks
PoC: Access {dir} -> Found {files} containing credentials/API keys
""",
            "LFI_TO_RCE": """
1. LFI allows reading arbitrary files
2. Chain with log poisoning or /proc/self/environ
3. Achieve remote code execution
PoC: LFI -> Include log file -> Execute injected PHP code
""",
            "UPLOAD_TO_RCE": """
1. File upload allows uploading arbitrary files
2. Insufficient filtering allows uploading web shells
3. Direct access to uploaded file executes code
PoC: Upload malicious PHP/JSP -> Access upload directory -> Execute shell commands
""",
            "XXE_TO_INFO_LEAK": """
1. XXE allows external entity injection
2. Use XXE to read local files or  make SSRF requests
3. Exfiltrate sensitive data
PoC: XXE -> Read /etc/passwd or cloud metadata
""",
        }
        
        template = narratives.get(chain_type, "Vulnerability chain detected")
        
        # Fill in variables
        for i, vuln in enumerate(vulns):
            template = template.replace(f"{{url}}", vuln.url)
            template = template.replace(f"{{{vuln.vuln_type.value.lower()}_url}}", vuln.url)
            template = template.replace("{info}", vuln.metadata.get('leaked_info', 'sensitive data'))
            template = template.replace("{dir}", vuln.url if vuln.vuln_type == VulnType.HIDDEN_DIR else '')
            template = template.replace("{files}", ', '.join(vuln.metadata.get('files', [])))
        
        return template.strip()
    
    def detect_chains(self) -> List[VulnChain]:
        """Detect vulnerability chains in the current pool"""
        print("\n[*] Analyzing vulnerabilities for chains...")
        
        chains = []
        
        # Check all pairs of vulnerabilities
        for i, vuln1 in enumerate(self.vulnerabilities):
            for vuln2 in self.vulnerabilities[i+1:]:
                # Check if this pair forms a known chain
                chain_type = self.CHAIN_RULES.get((vuln1.vuln_type, vuln2.vuln_type))
                
                if not chain_type:
                    # Try reverse order
                    chain_type = self.CHAIN_RULES.get((vuln2.vuln_type, vuln1.vuln_type))
                    if chain_type:
                        vuln1, vuln2 = vuln2, vuln1
                
                if chain_type:
                    # Create chain
                    vulns = [vuln1, vuln2]
                    combined_cvss = self._calculate_combined_cvss(vulns)
                    combined_severity = self._determine_combined_severity(combined_cvss)
                    
                    chain = VulnChain(
                        chain_id=f"CHAIN_{len(chains)+1}",
                        vulnerabilities=vulns,
                        chain_type=chain_type,
                        combined_severity=combined_severity,
                        combined_cvss=combined_cvss,
                        attack_narrative=self._generate_attack_narrative(chain_type, vulns)
                    )
                    
                    chains.append(chain)
                    print(f"  [CHAIN] {vuln1.vuln_type.value} + {vuln2.vuln_type.value} -> {chain_type}")
                    print(f"          Severity: {combined_severity} (CVSS: {combined_cvss:.1f})")
        
        self.chains = chains
        return chains
    
    def auto_escalate_hidden_directory(self, dir_url: str) -> Dict:
        """
        Auto-escalation: When hidden directory found, trigger deep crawl
        
        Returns: Actions to take
        """
        return {
            'action': 'deep_crawl',
            'target': dir_url,
            'reason': 'Hidden directory found, escalating to deep scan',
            'next_steps': [
                'Run nuclei scan on directory',
                'Crawl for additional endpoints',
                'Check for sensitive files (.git, .env, backups)'
            ]
        }
    
    def auto_escalate_ssrf(self, ssrf_url: str) -> Dict:
        """Auto-escalation: When SSRF found, test cloud metadata endpoints"""
        return {
            'action': 'test_cloud_metadata',
            'targets': [
                'http://169.254.169.254/latest/meta-data/',  # AWS
                'http://metadata.google.internal/computeMetadata/v1/',  # GCP
                'http://169.254.169.254/metadata/instance',  # Azure
            ],
            'reason': 'SSRF detected, testing for cloud credential exposure',
            'next_steps': [
                'Attempt to access cloud metadata',
                'Check for IAM credentials',
                'Test for IDOR on internal APIs'
            ]
        }
    
    def export_chains(self, output_file: str):
        """Export chains to JSON"""
        data = {
            'scan_time': datetime.utcnow().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'total_chains': len(self.chains),
            'chains': [
                {
                    'chain_id': c.chain_id,
                    'chain_type': c.chain_type,
                    'severity': c.combined_severity,
                    'cvss': c.combined_cvss,
                    'vulnerabilities': [
                        {
                            'type': v.vuln_type.value,
                            'severity': v.severity,
                            'url': v.url,
                            'description': v.description
                        }
                        for v in c.vulnerabilities
                    ],
                    'attack_narrative': c.attack_narrative
                }
                for c in self.chains
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\n[*] Chains exported to: {output_file}")


if __name__ == "__main__":
    # Test vulnerability chainer
    chainer = VulnerabilityChainer()
    
    print("Vulnerability Chaining Engine - Test Mode")
    print("="*60)
    
    # Add sample vulnerabilities
    ssrf = Vulnerability(
        vuln_id="VULN_1",
        vuln_type=VulnType.SSRF,
        severity="medium",
        description="SSRF in URL parameter",
        url="https://example.com/fetch?url=",
        parameter="url",
        cvss_score=5.3
    )
    
    idor = Vulnerability(
        vuln_id="VULN_2",
        vuln_type=VulnType.IDOR,
        severity="medium", 
        description="IDOR in user profile endpoint",
        url="https://example.com/api/user/123",
        parameter="user_id",
        cvss_score=4.3
    )
    
    chainer.add_vulnerability(ssrf)
    chainer.add_vulnerability(idor)
    
    # Detect chains
    chains = chainer.detect_chains()
    
    if chains:
        print("\n" + "="*60)
        print("DETECTED VULNERABILITY CHAINS")
        print("="*60)
        
        for chain in chains:
            print(f"\n[CHAIN] {chain.chain_id}: {chain.chain_type}")
            print(f"Severity: {chain.combined_severity.upper()} (CVSS: {chain.combined_cvss:.1f})")
            print(f"\nVulnerabilities:")
            for v in chain.vulnerabilities:
                print(f"  - {v.vuln_type.value}: {v.url}")
            print(f"\nAttack Narrative:")
            print(chain.attack_narrative)
    
    # Test auto-escalation
    print("\n" + "="*60)
    print("AUTO-ESCALATION EXAMPLE")
    print("="*60)
    
    escalation = chainer.auto_escalate_ssrf("https://example.com/fetch?url=")
    print(f"\n[AUTO-ESCALATE] {escalation['reason']}")
    print("Next steps:")
    for step in escalation['next_steps']:
        print(f"  - {step}")
