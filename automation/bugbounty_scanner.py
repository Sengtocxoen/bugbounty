#!/usr/bin/env python3

import csv
import sys
import os
import json
import yaml
import requests
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin

class BugBountyScanner:
    def __init__(self, csv_file=None, target=None, config_file=None):
        self.csv_file = csv_file
        self.target = target
        self.config_file = config_file
        self.results_base_dir = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.results_base_dir, exist_ok=True)
        
        # Check and install nuclei templates if needed
        self.check_nuclei_templates()
        
        # Default configuration if no config file is provided
        self.config = {
            'endpoints': [
                '/api/v1/', '/api/v2/', '/auth/', '/login', '/register',
                '/reset-password', '/profile', '/settings', '/admin/',
                '/upload/', '/download/', '/export/', '/import/'
            ],
            'auth_endpoints': [
                '/login', '/register', '/reset-password',
                '/oauth/authorize', '/oauth/token'
            ],
            'nuclei_templates': [
                'cves/', 'exposures/', 'misconfiguration/', 'vulnerabilities/'
            ],
            'settings': {
                'max_concurrent_requests': 5,
                'request_timeout': 5,
                'retry_attempts': 3,
                'follow_redirects': True
            }
        }
        
        # Load custom config if provided
        if config_file:
            self.load_config(config_file)
        
        # Load targets from CSV if provided
        self.targets = []
        if csv_file:
            self.targets = self.load_targets_from_csv()
        elif target:
            self.targets = [{'identifier': self.normalize_url(target), 'asset_type': 'url'}]

    def normalize_url(self, url):
        """Add scheme to URL if missing"""
        if not url.startswith(('http://', 'https://')):
            # Try HTTPS first, if it fails, try HTTP
            try:
                response = requests.head(f'https://{url}', timeout=5, allow_redirects=True)
                return f'https://{url}'
            except:
                try:
                    response = requests.head(f'http://{url}', timeout=5, allow_redirects=True)
                    return f'http://{url}'
                except:
                    # If both fail, default to HTTPS
                    return f'https://{url}'
        return url

    def load_config(self, config_file):
        """Load program-specific configuration"""
        try:
            with open(config_file, 'r') as f:
                custom_config = yaml.safe_load(f)
                # Update default config with custom settings
                self.config.update(custom_config)
        except Exception as e:
            print(f"[-] Error loading config file: {str(e)}")
            print("[*] Using default configuration")

    def load_targets_from_csv(self):
        """Load and filter targets from CSV file"""
        targets = []
        try:
            with open(self.csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if self.is_valid_target(row):
                        # Normalize the URL before adding to targets
                        identifier = self.normalize_url(row.get('identifier', ''))
                        targets.append({
                            'identifier': identifier,
                            'asset_type': row.get('asset_type', ''),
                            'instruction': row.get('instruction', ''),
                            'eligible_for_bounty': row.get('eligible_for_bounty', 'false').lower() == 'true',
                            'max_severity': row.get('max_severity', 'medium')
                        })
        except Exception as e:
            print(f"[-] Error reading CSV file: {str(e)}")
            sys.exit(1)
        return targets

    def is_valid_target(self, row):
        """Check if the target is valid for scanning"""
        if row.get('asset_type', '').lower() not in ['url', 'domain']:
            return False
        if row.get('eligible_for_bounty', 'false').lower() != 'true':
            return False
        return True

    def check_endpoints(self, target):
        """Check configured endpoints"""
        print(f"[+] Checking endpoints for {target['identifier']}")
        results = []
        for endpoint in self.config.get('endpoints', []):
            url = urljoin(target['identifier'].rstrip('/'), endpoint)
            try:
                response = requests.get(
                    url,
                    timeout=self.config['settings']['request_timeout'],
                    allow_redirects=self.config['settings']['follow_redirects']
                )
                results.append({
                    'url': url,
                    'status': response.status_code,
                    'headers': dict(response.headers)
                })
            except Exception as e:
                print(f"[-] Error checking {url}: {str(e)}")
        
        return results

    def check_auth(self, target):
        """Check authentication mechanisms"""
        print(f"[+] Checking auth mechanisms for {target['identifier']}")
        results = []
        for auth_endpoint in self.config.get('auth_endpoints', []):
            url = urljoin(target['identifier'].rstrip('/'), auth_endpoint)
            try:
                response = requests.get(
                    url,
                    timeout=self.config['settings']['request_timeout'],
                    allow_redirects=self.config['settings']['follow_redirects']
                )
                results.append({
                    'url': url,
                    'status': response.status_code,
                    'content_type': response.headers.get('content-type', ''),
                    'auth_headers': {k: v for k, v in response.headers.items() if 'auth' in k.lower()}
                })
            except Exception as e:
                print(f"[-] Error checking {url}: {str(e)}")
        
        return results

    def run_nuclei_templates(self, target):
        """Run nuclei templates"""
        print(f"[+] Running nuclei templates for {target['identifier']}")
        results = []
        
        # Define template categories and their paths
        template_categories = {
            'cves': 'nuclei-templates/cves/',
            'exposures': 'nuclei-templates/exposures/',
            'misconfiguration': 'nuclei-templates/misconfiguration/',
            'vulnerabilities': 'nuclei-templates/vulnerabilities/'
        }
        
        for category, template_path in template_categories.items():
            try:
                output_file = os.path.join(self.results_base_dir, f"nuclei_{category}.json")
                subprocess.run([
                    "nuclei",
                    "-u", target['identifier'],
                    "-t", template_path,
                    "-o", output_file,
                    "-j"  # Use -j for JSON output instead of -json
                ], check=True)
                results.append(output_file)
            except Exception as e:
                print(f"[-] Error running nuclei template {category}: {str(e)}")
        
        return results

    def scan_target(self, target):
        """Scan a single target"""
        print(f"\n[+] Scanning target: {target['identifier']}")
        
        # Create target-specific directory
        target_dir = os.path.join(self.results_base_dir, target['identifier'].replace('/', '_').replace(':', '_'))
        os.makedirs(target_dir, exist_ok=True)
        
        # Save target information
        with open(os.path.join(target_dir, 'target_info.json'), 'w') as f:
            json.dump(target, f, indent=4)
        
        try:
            # Run all checks
            endpoints_results = self.check_endpoints(target)
            auth_results = self.check_auth(target)
            nuclei_results = self.run_nuclei_templates(target)
            
            # Save results
            results = {
                'target': target['identifier'],
                'scan_time': datetime.now().isoformat(),
                'endpoints': endpoints_results,
                'auth_mechanisms': auth_results,
                'nuclei_results': nuclei_results
            }
            
            report_file = os.path.join(target_dir, 'report.json')
            with open(report_file, 'w') as f:
                json.dump(results, f, indent=4)
            
            print(f"[+] Scan completed for {target['identifier']}")
            print(f"[+] Results saved in {target_dir}")
            
            return {
                'target': target['identifier'],
                'status': 'completed',
                'report_file': report_file
            }
        except Exception as e:
            print(f"[-] Error scanning {target['identifier']}: {str(e)}")
            return {
                'target': target['identifier'],
                'status': 'failed',
                'error': str(e)
            }

    def run_scans(self):
        """Run scans for all targets"""
        print(f"[+] Found {len(self.targets)} targets to scan")
        
        results = []
        for target in self.targets:
            result = self.scan_target(target)
            results.append(result)
        
        # Generate summary report
        summary = {
            'scan_time': datetime.now().isoformat(),
            'total_targets': len(self.targets),
            'completed_scans': len([r for r in results if r['status'] == 'completed']),
            'failed_scans': len([r for r in results if r['status'] == 'failed']),
            'results': results
        }
        
        summary_file = os.path.join(self.results_base_dir, 'scan_summary.json')
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=4)
        
        print(f"\n[+] All scans completed. Summary saved to {summary_file}")
        return summary_file

    def check_nuclei_templates(self):
        """Check if nuclei templates are installed and install if needed"""
        print("[+] Checking nuclei templates...")
        try:
            # Check if nuclei is installed
            subprocess.run(["nuclei", "-version"], check=True, capture_output=True)
            
            # Check if templates directory exists
            templates_dir = os.path.expanduser("~/nuclei-templates")
            if not os.path.exists(templates_dir):
                print("[+] Installing nuclei templates...")
                subprocess.run([
                    "git", "clone", "https://github.com/projectdiscovery/nuclei-templates.git",
                    templates_dir
                ], check=True)
                print("[+] Nuclei templates installed successfully")
            else:
                print("[+] Nuclei templates found")
        except subprocess.CalledProcessError as e:
            print(f"[-] Error: {str(e)}")
            print("[-] Please make sure nuclei is installed. You can install it with:")
            print("    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Error checking nuclei templates: {str(e)}")
            sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  For single target: python bugbounty_scanner.py -t <target_url>")
        print("  For CSV file: python bugbounty_scanner.py -c <csv_file>")
        print("  Optional: -f <config_file> for custom configuration")
        sys.exit(1)

    target = None
    csv_file = None
    config_file = None

    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '-t':
            target = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '-c':
            csv_file = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '-f':
            config_file = sys.argv[i + 1]
            i += 2
        else:
            i += 1

    scanner = BugBountyScanner(csv_file=csv_file, target=target, config_file=config_file)
    summary_file = scanner.run_scans()
    
    print("\nScan Summary:")
    print(f"Results directory: {scanner.results_base_dir}")
    print(f"Summary file: {summary_file}")

if __name__ == "__main__":
    main() 