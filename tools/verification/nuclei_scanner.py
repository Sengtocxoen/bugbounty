#!/usr/bin/env python3
"""
Nuclei Scanner Module
Comprehensive Nuclei vulnerability scanner integration for bug bounty workflows
"""

import json
import subprocess
import logging
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import yaml


class NucleiScanner:
    """Nuclei vulnerability scanner with comprehensive configuration support"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, output_dir: Optional[Path] = None):
        """
        Initialize Nuclei scanner
        
        Args:
            config: Nuclei configuration dict (from scan_config.yaml)
            output_dir: Directory for Nuclei results (default: ./nuclei_results)
        """
        self.config = config or self._default_config()
        self.output_dir = Path(output_dir) if output_dir else Path('./nuclei_results')
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger = logging.getLogger('NucleiScanner')
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Verify Nuclei is installed
        if not self._check_nuclei_installed():
            raise RuntimeError("Nuclei is not installed. Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        
        # Update templates if configured
        if self.config.get('update_templates', True):
            self._update_templates()
    
    def _default_config(self) -> Dict[str, Any]:
        """Default Nuclei configuration"""
        return {
            'enabled': True,
            'severity': ['critical', 'high', 'medium'],
            'tags': [],
            'exclude_tags': ['dos'],
            'custom_templates': None,
            'scan_targets': {
                'subdomains': True,
                'endpoints': True,
                'cloud_buckets': False,
                'ports': True
            },
            'rate_limit': 150,  # requests per minute
            'timeout': 300,  # 5 minutes per target
            'update_templates': False,
            'threads': 10
        }
    
    def _check_nuclei_installed(self) -> bool:
        """Check if Nuclei is installed and available"""
        try:
            result = subprocess.run(
                ['nuclei', '-version'],
                capture_output=True,
                timeout=5,
                check=False
            )
            if result.returncode == 0:
                version = result.stdout.decode().strip()
                self.logger.info(f"Nuclei found: {version}")
                return True
            return False
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def _update_templates(self):
        """Update Nuclei templates to latest version"""
        try:
            self.logger.info("Updating Nuclei templates...")
            subprocess.run(
                ['nuclei', '-update-templates', '-silent'],
                check=False
            )
            self.logger.info("Nuclei templates updated successfully")
        except Exception as e:
            self.logger.warning(f"Failed to update templates: {e}")
    
    def load_targets_from_scan_results(self, scan_results_file: Path) -> List[str]:
        """
        Extract targets from deep scan JSON results
        
        Args:
            scan_results_file: Path to deep_scan_*.json file
            
        Returns:
            List of target URLs to scan with Nuclei
        """
        targets = []
        
        try:
            with open(scan_results_file) as f:
                data = json.load(f)
            
            scan_config = self.config.get('scan_targets', {})
            
            # Extract live subdomains
            if scan_config.get('subdomains', True):
                subdomains = data.get('subdomains', {})
                for subdomain, info in subdomains.items():
                    if info.get('is_alive', False):
                        # Prefer HTTPS, fallback to HTTP
                        if info.get('https_status'):
                            targets.append(f"https://{subdomain}")
                        elif info.get('http_status'):
                            targets.append(f"http://{subdomain}")
            
            # Extract endpoints
            if scan_config.get('endpoints', True):
                endpoints = data.get('endpoints', [])
                for endpoint in endpoints:
                    if isinstance(endpoint, dict):
                        url = endpoint.get('url')
                        if url:
                            targets.append(url)
                    elif isinstance(endpoint, str):
                        targets.append(endpoint)
            
            # Extract API endpoints
            if scan_config.get('endpoints', True):
                api_endpoints = data.get('api_endpoints', [])
                for endpoint in api_endpoints:
                    if isinstance(endpoint, dict):
                        url = endpoint.get('url')
                        if url:
                            targets.append(url)
                    elif isinstance(endpoint, str):
                        targets.append(endpoint)
            
            # Extract cloud bucket URLs
            if scan_config.get('cloud_buckets', False):
                buckets = data.get('cloud_buckets', [])
                for bucket in buckets:
                    if isinstance(bucket, dict):
                        url = bucket.get('url')
                        if url:
                            targets.append(url)
            
            # Extract URLs from open ports
            if scan_config.get('ports', True):
                open_ports = data.get('open_ports', {})
                for subdomain, ports in open_ports.items():
                    for port_info in ports:
                        port = port_info.get('port')
                        service = port_info.get('service', '').lower()
                        
                        # Only add HTTP/HTTPS services
                        if service in ['http', 'https', 'http-alt', 'https-alt']:
                            if port in [80, 8080, 8000]:
                                targets.append(f"http://{subdomain}:{port}")
                            elif port in [443, 8443]:
                                targets.append(f"https://{subdomain}:{port}")
            
            # Deduplicate targets
            targets = list(set(targets))
            
            self.logger.info(f"Extracted {len(targets)} targets from scan results")
            return targets
            
        except Exception as e:
            self.logger.error(f"Failed to load targets from {scan_results_file}: {e}")
            return []
    
    def build_nuclei_command(self, targets: List[str], output_file: Path) -> List[str]:
        """
        Build Nuclei command with all configured options
        
        Args:
            targets: List of target URLs
            output_file: Output file for JSON results
            
        Returns:
            Command list for subprocess
        """
        cmd = ['nuclei']
        
        # Severity filters
        severity = self.config.get('severity', ['critical', 'high', 'medium'])
        if severity:
            cmd.extend(['-severity', ','.join(severity)])
        
        # Tags
        tags = self.config.get('tags', [])
        if tags:
            cmd.extend(['-tags', ','.join(tags)])
        
        # Exclude tags
        exclude_tags = self.config.get('exclude_tags', [])
        if exclude_tags:
            cmd.extend(['-exclude-tags', ','.join(exclude_tags)])
        
        # Custom templates
        custom_templates = self.config.get('custom_templates')
        if custom_templates and Path(custom_templates).exists():
            cmd.extend(['-templates', custom_templates])
        
        # Rate limiting (requests per minute -> delay in seconds)
        rate_limit = self.config.get('rate_limit', 150)
        if rate_limit > 0:
            delay = 60.0 / rate_limit  # Convert RPM to delay per request
            cmd.extend(['-rate-limit', str(int(rate_limit))])
        
        # Threads
        threads = self.config.get('threads', 10)
        cmd.extend(['-c', str(threads)])
        
        # Timeout
        timeout = self.config.get('timeout', 300)
        cmd.extend(['-timeout', str(timeout)])
        
        # Output format
        cmd.extend([
            '-json',
            '-o', str(output_file),
            '-silent',
            '-no-color'
        ])
        
        return cmd
    
    def scan_targets(self, targets: List[str], target_name: str = 'scan') -> Dict[str, Any]:
        """
        Run Nuclei scan on target list
        
        Args:
            targets: List of URLs to scan
            target_name: Name for output files
            
        Returns:
            Scan results dictionary
        """
        if not targets:
            self.logger.warning("No targets to scan")
            return {'findings': [], 'summary': {}}
        
        # Create target-specific output directory
        target_dir = self.output_dir / target_name
        target_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_output = target_dir / f'nuclei_scan_{timestamp}.json'
        txt_output = target_dir / f'nuclei_scan_{timestamp}.txt'
        
        # Write targets to temp file
        targets_file = target_dir / f'targets_{timestamp}.txt'
        with open(targets_file, 'w') as f:
            f.write('\n'.join(targets))
        
        self.logger.info(f"Starting Nuclei scan on {len(targets)} targets...")
        self.logger.info(f"Output: {json_output}")
        
        scan_start = datetime.now()
        
        # Build command
        cmd = self.build_nuclei_command(targets, json_output)
        cmd.extend(['-list', str(targets_file)])
        
        try:
            # Run Nuclei
            self.logger.info(f"Running: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            
            scan_end = datetime.now()
            duration = (scan_end - scan_start).total_seconds()
            
            # Parse results
            findings = self._parse_nuclei_output(json_output)
            
            # Create summary
            summary = {
                'scan_start': scan_start.isoformat(),
                'scan_end': scan_end.isoformat(),
                'duration_seconds': duration,
                'targets_scanned': len(targets),
                'vulnerabilities_found': len(findings),
                'by_severity': self._count_by_severity(findings)
            }
            
            # Write text summary
            self._write_text_report(findings, summary, txt_output)
            
            # Write critical findings separately
            critical_findings = [f for f in findings if f.get('severity') == 'critical']
            if critical_findings:
                critical_file = target_dir / f'critical_findings.json'
                with open(critical_file, 'w') as f:
                    json.dump(critical_findings, f, indent=2)
            
            # Write summary
            summary_file = target_dir / 'summary.json'
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2)
            
            self.logger.info(f"Nuclei scan complete! Found {len(findings)} vulnerabilities")
            self.logger.info(f"Critical: {summary['by_severity'].get('critical', 0)}, "
                           f"High: {summary['by_severity'].get('high', 0)}, "
                           f"Medium: {summary['by_severity'].get('medium', 0)}")
            
            return {
                'findings': findings,
                'summary': summary,
                'output_files': {
                    'json': str(json_output),
                    'txt': str(txt_output),
                    'summary': str(summary_file)
                }
            }
            
        except subprocess.TimeoutExpired:
            self.logger.error("Nuclei scan timed out")
            return {'findings': [], 'summary': {'error': 'timeout'}}
        except Exception as e:
            self.logger.error(f"Nuclei scan failed: {e}")
            return {'findings': [], 'summary': {'error': str(e)}}
        finally:
            # Cleanup targets file
            targets_file.unlink(missing_ok=True)
    
    def _parse_nuclei_output(self, output_file: Path) -> List[Dict[str, Any]]:
        """Parse Nuclei JSON output"""
        findings = []
        
        if not output_file.exists():
            return findings
        
        try:
            with open(output_file) as f:
                for line in f:
                    try:
                        result = json.loads(line.strip())
                        
                        # Extract key information
                        finding = {
                            'template_id': result.get('template-id', 'unknown'),
                            'name': result.get('info', {}).get('name', 'Unknown'),
                            'severity': result.get('info', {}).get('severity', 'info'),
                            'matched_at': result.get('matched-at', ''),
                            'type': result.get('type', 'http'),
                            'tags': result.get('info', {}).get('tags', []),
                            'description': result.get('info', {}).get('description', ''),
                            'remediation': result.get('info', {}).get('remediation', ''),
                            'reference': result.get('info', {}).get('reference', []),
                            'classification': result.get('info', {}).get('classification', {}),
                            'extracted_results': result.get('extracted-results', []),
                            'curl_command': result.get('curl-command', ''),
                            'timestamp': result.get('timestamp', datetime.now().isoformat()),
                            'matcher_name': result.get('matcher-name', ''),
                            'raw_result': result  # Keep full result for reference
                        }
                        
                        findings.append(finding)
                        
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            self.logger.error(f"Failed to parse Nuclei output: {e}")
        
        return findings
    
    def _count_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    def _write_text_report(self, findings: List[Dict[str, Any]], summary: Dict[str, Any], output_file: Path):
        """Write human-readable text report"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("NUCLEI VULNERABILITY SCAN REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            # Summary
            f.write(f"Scan Start:  {summary.get('scan_start', 'N/A')}\n")
            f.write(f"Scan End:    {summary.get('scan_end', 'N/A')}\n")
            f.write(f"Duration:    {summary.get('duration_seconds', 0):.2f} seconds\n")
            f.write(f"Targets:     {summary.get('targets_scanned', 0)}\n\n")
            
            # Severity breakdown
            by_severity = summary.get('by_severity', {})
            f.write("Vulnerabilities by Severity:\n")
            f.write(f"  Critical: {by_severity.get('critical', 0)}\n")
            f.write(f"  High:     {by_severity.get('high', 0)}\n")
            f.write(f"  Medium:   {by_severity.get('medium', 0)}\n")
            f.write(f"  Low:      {by_severity.get('low', 0)}\n")
            f.write(f"  Info:     {by_severity.get('info', 0)}\n")
            f.write(f"  TOTAL:    {len(findings)}\n\n")
            
            f.write("=" * 80 + "\n\n")
            
            # Findings
            for i, finding in enumerate(findings, 1):
                severity = finding.get('severity', 'info').upper()
                f.write(f"[{i}] {severity} - {finding.get('name', 'Unknown')}\n")
                f.write("-" * 80 + "\n")
                f.write(f"Template ID:  {finding.get('template_id', 'N/A')}\n")
                f.write(f"Matched At:   {finding.get('matched_at', 'N/A')}\n")
                f.write(f"Type:         {finding.get('type', 'N/A')}\n")
                
                tags = finding.get('tags', [])
                if tags:
                    f.write(f"Tags:         {', '.join(tags)}\n")
                
                desc = finding.get('description', '')
                if desc:
                    f.write(f"\nDescription:\n{desc}\n")
                
                remediation = finding.get('remediation', '')
                if remediation:
                    f.write(f"\nRemediation:\n{remediation}\n")
                
                references = finding.get('reference', [])
                if references:
                    f.write("\nReferences:\n")
                    for ref in references:
                        f.write(f"  - {ref}\n")
                
                classification = finding.get('classification', {})
                if classification:
                    cwe_id = classification.get('cwe-id', [])
                    cvss_score = classification.get('cvss-score')
                    if cwe_id:
                        f.write(f"CWE:          {', '.join(cwe_id)}\n")
                    if cvss_score:
                        f.write(f"CVSS Score:   {cvss_score}\n")
                
                f.write("\n" + "=" * 80 + "\n\n")


def main():
    """CLI entry point for standalone Nuclei scanner"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Nuclei Scanner for Bug Bounty Workflows')
    parser.add_argument('--scan-file', help='Path to deep_scan_*.json file')
    parser.add_argument('--targets', nargs='+', help='Direct target URLs to scan')
    parser.add_argument('--config', help='Path to scan_config.yaml')
    parser.add_argument('--output', default='./nuclei_results', help='Output directory')
    parser.add_argument('--severity', nargs='+', default=['critical', 'high', 'medium'],
                       help='Severity levels to scan')
    parser.add_argument('--tags', nargs='+', help='Tags to include')
    parser.add_argument('--exclude-tags', nargs='+', default=['dos'], help='Tags to exclude')
    
    args = parser.parse_args()
    
    # Load config
    config = None
    if args.config:
        config_path = Path(args.config)
        if config_path.exists():
            with open(config_path) as f:
                full_config = yaml.safe_load(f)
                config = full_config.get('nuclei_scan', {})
    
    # Override with CLI args
    if not config:
        config = {}
    
    if args.severity:
        config['severity'] = args.severity
    if args.tags:
        config['tags'] = args.tags
    if args.exclude_tags:
        config['exclude_tags'] = args.exclude_tags
    
    # Initialize scanner
    scanner = NucleiScanner(config=config, output_dir=Path(args.output))
    
    # Get targets
    targets = []
    if args.scan_file:
        targets = scanner.load_targets_from_scan_results(Path(args.scan_file))
        target_name = Path(args.scan_file).parent.name
    elif args.targets:
        targets = args.targets
        target_name = 'manual_scan'
    else:
        print("Error: Must provide either --scan-file or --targets")
        return 1
    
    if not targets:
        print("No targets found to scan")
        return 1
    
    # Run scan
    results = scanner.scan_targets(targets, target_name)
    
    print(f"\n✓ Scan complete! Results saved to: {args.output}")
    print(f"  Findings: {len(results.get('findings', []))}")
    
    return 0


if __name__ == '__main__':
    exit(main())
