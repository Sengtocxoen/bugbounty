#!/usr/bin/env python3

import subprocess
import sys
import os
import json
from datetime import datetime
import requests
import yaml
from concurrent.futures import ThreadPoolExecutor

class ProgramScanner:
    def __init__(self, config_file, target):
        self.target = target
        self.config = self.load_config(config_file)
        self.results_dir = f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.results_dir, exist_ok=True)

    def load_config(self, config_file):
        """Load program-specific configuration"""
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)

    def check_endpoints(self):
        """Check configured endpoints"""
        print("[+] Checking configured endpoints")
        results = []
        for endpoint in self.config.get('endpoints', []):
            url = f"{self.target.rstrip('/')}{endpoint}"
            try:
                response = requests.get(url, timeout=5)
                results.append({
                    'url': url,
                    'status': response.status_code,
                    'headers': dict(response.headers)
                })
            except Exception as e:
                print(f"[-] Error checking {url}: {str(e)}")
        
        output_file = os.path.join(self.results_dir, "endpoints.json")
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        return output_file

    def check_auth(self):
        """Check authentication mechanisms"""
        print("[+] Checking authentication mechanisms")
        results = []
        for auth_endpoint in self.config.get('auth_endpoints', []):
            url = f"{self.target.rstrip('/')}{auth_endpoint}"
            try:
                response = requests.get(url, timeout=5)
                results.append({
                    'url': url,
                    'status': response.status_code,
                    'content_type': response.headers.get('content-type', ''),
                    'auth_headers': {k: v for k, v in response.headers.items() if 'auth' in k.lower()}
                })
            except Exception as e:
                print(f"[-] Error checking {url}: {str(e)}")
        
        output_file = os.path.join(self.results_dir, "auth_mechanisms.json")
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        return output_file

    def run_nuclei_templates(self):
        """Run configured nuclei templates"""
        print("[+] Running nuclei templates")
        templates = self.config.get('nuclei_templates', [])
        
        output_file = os.path.join(self.results_dir, "nuclei_results.json")
        for template in templates:
            subprocess.run([
                "nuclei",
                "-u", self.target,
                "-t", template,
                "-o", output_file,
                "-json"
            ])
        return output_file

    def run_custom_checks(self):
        """Run program-specific custom checks"""
        print("[+] Running custom checks")
        results = []
        for check in self.config.get('custom_checks', []):
            try:
                # Implement custom check logic here
                results.append({
                    'check_name': check['name'],
                    'status': 'completed',
                    'details': check.get('details', {})
                })
            except Exception as e:
                print(f"[-] Error in custom check {check['name']}: {str(e)}")
        
        output_file = os.path.join(self.results_dir, "custom_checks.json")
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        return output_file

    def generate_report(self):
        """Generate a comprehensive report"""
        report = {
            "target": self.target,
            "scan_time": datetime.now().isoformat(),
            "results_directory": self.results_dir,
            "program_config": self.config.get('program_name', 'Unknown'),
            "checks_performed": [
                "Endpoint Checks",
                "Authentication Checks",
                "Nuclei Templates",
                "Custom Checks"
            ]
        }
        
        report_file = os.path.join(self.results_dir, "report.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=4)
        
        return report_file

def main():
    if len(sys.argv) != 3:
        print("Usage: python program_scanner.py <config_file> <target>")
        sys.exit(1)

    config_file = sys.argv[1]
    target = sys.argv[2]
    scanner = ProgramScanner(config_file, target)
    
    # Run all checks
    endpoints_results = scanner.check_endpoints()
    auth_results = scanner.check_auth()
    nuclei_results = scanner.run_nuclei_templates()
    custom_results = scanner.run_custom_checks()
    
    # Generate report
    report_file = scanner.generate_report()
    print(f"\n[+] Scan completed. Results saved in {scanner.results_dir}")
    print(f"[+] Report generated: {report_file}")

if __name__ == "__main__":
    main() 