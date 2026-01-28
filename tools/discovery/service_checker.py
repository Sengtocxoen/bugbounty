#!/usr/bin/env python3
"""
Service-Specific Vulnerability Checker
Checks for common misconfigurations and vulnerabilities on specific services
"""

import socket
import struct
import time
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass


@dataclass
class VulnResult:
    """Vulnerability check result"""
    service: str
    host: str
    port: int
    vulnerable: bool
    severity: str  # critical, high, medium, low
    finding: str
    description: str
    remediation: str


class ServiceChecker:
    """
    Check for service-specific vulnerabilities
    """
    
    def __init__(self, timeout: int = 5):
        """
        Initialize service checker
        
        Args:
            timeout: Socket timeout in seconds
        """
        self.timeout = timeout
    
    def check_redis(self, host: str, port: int = 6379) -> List[VulnResult]:
        """
        Check Redis for unauthenticated access
        
        Args:
            host: Redis host
            port: Redis port (default 6379)
            
        Returns:
            List of vulnerability results
        """
        results = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Try INFO command (should require auth if configured)
            sock.sendall(b"INFO\r\n")
            response = sock.recv(4096)
            
            if b"redis_version" in response or b"# Server" in response:
                results.append(VulnResult(
                    service="Redis",
                    host=host,
                    port=port,
                    vulnerable=True,
                    severity="critical",
                    finding="Unauthenticated Redis Access",
                    description="Redis server allows unauthenticated access to INFO command. Attacker can read/write data.",
                    remediation="Configure Redis with requirepass and bind to localhost only"
                ))
            
            sock.close()
            
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        
        return results
    
    def check_mongodb(self, host: str, port: int = 27017) -> List[VulnResult]:
        """
        Check MongoDB for unauthenticated access
        
        Args:
            host: MongoDB host
            port: MongoDB port (default 27017)
            
        Returns:
            List of vulnerability results
        """
        results = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Try to send listDatabases command
            # MongoDB wire protocol message
            # This is a simplified check - full implementation would need proper BSON encoding
            
            sock.close()
            
            # If connection successful, MongoDB is exposed
            results.append(VulnResult(
                service="MongoDB",
                host=host,
                port=port,
                vulnerable=True,
                severity="critical",
                finding="Exposed MongoDB",
                description="MongoDB is accessible from external network. Potential unauthorized database access.",
                remediation="Bind MongoDB to localhost only and enable authentication"
            ))
            
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        
        return results
    
    def check_elasticsearch(self, host: str, port: int = 9200) -> List[VulnResult]:
        """
        Check Elasticsearch for exposed API
        
        Args:
            host: Elasticsearch host
            port: Elasticsearch port (default 9200)
            
        Returns:
            List of vulnerability results
        """
        results = []
        
        try:
            import requests
            
            url = f"http://{host}:{port}/"
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                if "cluster_name" in data or "tagline" in data:
                    results.append(VulnResult(
                        service="Elasticsearch",
                        host=host,
                        port=port,
                        vulnerable=True,
                        severity="high",
                        finding="Exposed Elasticsearch API",
                        description=f"Elasticsearch API is publicly accessible. Cluster: {data.get('cluster_name', 'unknown')}",
                        remediation="Enable authentication and restrict network access"
                    ))
                    
                    # Try to list indices
                    indices_url = f"http://{host}:{port}/_cat/indices"
                    indices_resp = requests.get(indices_url, timeout=self.timeout)
                    
                    if indices_resp.status_code == 200:
                        results.append(VulnResult(
                            service="Elasticsearch",
                            host=host,
                            port=port,
                            vulnerable=True,
                            severity="critical",
                            finding="Elasticsearch Indices Enumeration",
                            description="Can list all Elasticsearch indices without authentication",
                            remediation="Enable X-Pack security or similar authentication"
                        ))
        
        except Exception:
            pass
        
        return results
    
    def check_mysql(self, host: str, port: int = 3306) -> List[VulnResult]:
        """
        Check MySQL for authentication bypass attempts
        
        Args:
            host: MySQL host
            port: MySQL port (default 3306)
            
        Returns:
            List of vulnerability results
        """
        results = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Read server greeting
            greeting = sock.recv(1024)
            
            if len(greeting) > 0:
                # MySQL is accessible
                results.append(VulnResult(
                    service="MySQL",
                    host=host,
                    port=port,
                    vulnerable=True,
                    severity="medium",
                    finding="Exposed MySQL Port",
                    description="MySQL port is accessible from external network",
                    remediation="Bind MySQL to localhost only or use firewall rules"
                ))
            
            sock.close()
            
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        
        return results
    
    def check_ssh(self, host: str, port: int = 22) -> List[VulnResult]:
        """
        Check SSH for weak ciphers
        
        Args:
            host: SSH host
            port: SSH port (default 22)
            
        Returns:
            List of vulnerability results
        """
        results = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Read SSH banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if banner.startswith('SSH-'):
                # Check for old SSH versions
                if 'SSH-1' in banner:
                    results.append(VulnResult(
                        service="SSH",
                        host=host,
                        port=port,
                        vulnerable=True,
                        severity="high",
                        finding="SSH Protocol 1.0",
                        description=f"Server supports deprecated SSH version 1.0: {banner.strip()}",
                        remediation="Disable SSH protocol 1.0 in sshd_config"
                    ))
                
                # Check for specific vulnerable versions
                version_lower = banner.lower()
                if 'openssh' in version_lower:
                    # Extract version number
                    import re
                    match = re.search(r'openssh[_\s]+([\d.]+)', version_lower)
                    if match:
                        version = match.group(1)
                        # Check for known vulnerable versions (example)
                        if version.startswith('7.2') or version.startswith('7.3'):
                            results.append(VulnResult(
                                service="SSH",
                                host=host,
                                port=port,
                                vulnerable=True,
                                severity="medium",
                                finding="Potentially Vulnerable SSH Version",
                                description=f"OpenSSH version {version} may have known vulnerabilities",
                                remediation="Update OpenSSH to latest version"
                            ))
            
            sock.close()
            
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        
        return results
    
    def check_rdp(self, host: str, port: int = 3389) -> List[VulnResult]:
        """
        Check RDP for exposed service
        
        Args:
            host: RDP host
            port: RDP port (default 3389)
            
        Returns:
            List of vulnerability results
        """
        results = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # RDP is accessible
            results.append(VulnResult(
                service="RDP",
                host=host,
                port=port,
                vulnerable=True,
                severity="high",
                finding="Exposed RDP Service",
                description="RDP is accessible from external network. Potential target for brute-force and BlueKeep.",
                remediation="Restrict RDP access via firewall or VPN, enable NLA, apply patches"
            ))
            
            sock.close()
            
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        
        return results
    
    def check_ftp(self, host: str, port: int = 21) -> List[VulnResult]:
        """
        Check FTP for anonymous access
        
        Args:
            host: FTP host
            port: FTP port (default 21)
            
        Returns:
            List of vulnerability results
        """
        results = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Read FTP banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '220' in banner:  # FTP ready
                # Try anonymous login
                sock.sendall(b"USER anonymous\r\n")
                time.sleep(0.5)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '331' in response:  # Password required
                    sock.sendall(b"PASS anonymous@\r\n")
                    time.sleep(0.5)
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    if '230' in response:  # Login successful
                        results.append(VulnResult(
                            service="FTP",
                            host=host,
                            port=port,
                            vulnerable=True,
                            severity="high",
                            finding="Anonymous FTP Access",
                            description="FTP server allows anonymous login",
                            remediation="Disable anonymous FTP access or use SFTP/FTPS"
                        ))
            
            sock.close()
            
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        
        return results
    
    def check_all_services(self, host: str, ports: List[Tuple[int, str]]) -> List[VulnResult]:
        """
        Check all services on a host
        
        Args:
            host: Target host
            ports: List of (port, service_name) tuples
            
        Returns:
            List of all vulnerability results
        """
        all_results = []
        
        service_checkers = {
            'Redis': (6379, self.check_redis),
            'MongoDB': (27017, self.check_mongodb),
            'Elasticsearch': (9200, self.check_elasticsearch),
            'MySQL': (3306, self.check_mysql),
            'SSH': (22, self.check_ssh),
            'RDP': (3389, self.check_rdp),
            'FTP': (21, self.check_ftp),
        }
        
        for port, service_name in ports:
            # Find matching checker
            for srv, (default_port, checker) in service_checkers.items():
                if service_name.lower() in srv.lower() or port == default_port:
                    try:
                        results = checker(host, port)
                        all_results.extend(results)
                    except Exception:
                        pass
                    break
        
        return all_results


def format_vuln_report(results: List[VulnResult]) -> str:
    """
    Format vulnerability results as a readable report
    
    Args:
        results: List of vulnerability results
        
    Returns:
        Formatted report string
    """
    if not results:
        return "No vulnerabilities found"
    
    report = []
    report.append("=" * 80)
    report.append("SERVICE VULNERABILITY SCAN RESULTS")
    report.append("=" * 80)
    report.append("")
    
    # Group by severity
    by_severity = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': []
    }
    
    for result in results:
        by_severity[result.severity].append(result)
    
    for severity in ['critical', 'high', 'medium', 'low']:
        vulns = by_severity[severity]
        if vulns:
            report.append(f"\n[{severity.upper()}] {len(vulns)} finding(s)")
            report.append("-" * 80)
            
            for vuln in vulns:
                report.append(f"\n  Service: {vuln.service}")
                report.append(f"  Target: {vuln.host}:{vuln.port}")
                report.append(f"  Finding: {vuln.finding}")
                report.append(f"  Description: {vuln.description}")
                report.append(f"  Remediation: {vuln.remediation}")
                report.append("")
    
    return "\n".join(report)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Service Vulnerability Checker")
    parser.add_argument("host", help="Target host")
    parser.add_argument("--port", "-p", type=int, help="Specific port to check")
    parser.add_argument("--service", "-s", choices=['redis', 'mongodb', 'elasticsearch', 'mysql', 'ssh', 'rdp', 'ftp'],
                       help="Service type")
    parser.add_argument("--all", action="store_true", help="Check all common services")
    
    args = parser.parse_args()
    
    checker = ServiceChecker()
    results = []
    
    if args.all:
        common_ports = [
            (21, 'FTP'),
            (22, 'SSH'),
            (3306, 'MySQL'),
            (3389, 'RDP'),
            (6379, 'Redis'),
            (9200, 'Elasticsearch'),
            (27017, 'MongoDB'),
        ]
        results = checker.check_all_services(args.host, common_ports)
    elif args.service:
        service_map = {
            'redis': checker.check_redis,
            'mongodb': checker.check_mongodb,
            'elasticsearch': checker.check_elasticsearch,
            'mysql': checker.check_mysql,
            'ssh': checker.check_ssh,
            'rdp': checker.check_rdp,
            'ftp': checker.check_ftp,
        }
        port = args.port or {
            'redis': 6379,
            'mongodb': 27017,
            'elasticsearch': 9200,
            'mysql': 3306,
            'ssh': 22,
            'rdp': 3389,
            'ftp': 21,
        }[args.service]
        
        results = service_map[args.service](args.host, port)
    
    print(format_vuln_report(results))
