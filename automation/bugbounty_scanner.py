#!/usr/bin/env python3

import csv
import sys
import os
import json
import yaml
import requests
import subprocess
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

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
            'settings': {
                'max_concurrent_requests': 5,
                'request_timeout': 5,
                'retry_attempts': 3,
                'follow_redirects': True,
                'max_workers': 10,  # Number of parallel workers
                'waf_bypass': True  # Enable WAF bypass techniques
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

    def check_nuclei_templates(self):
        """Check if nuclei templates are installed and install if needed"""
        print("[+] Checking nuclei templates...")
        try:
            # Check if nuclei is installed
            subprocess.run(["nuclei", "-version"], check=True, capture_output=True)
            
            # Check if templates directory exists in common locations
            possible_template_dirs = [
                os.path.expanduser("~/.local/nuclei-templates"),  # Default Kali location
                os.path.expanduser("~/nuclei-templates"),         # Common location
                "/usr/local/share/nuclei-templates",             # System-wide location
                "/usr/share/nuclei-templates"                    # Alternative system location
            ]
            
            self.templates_dir = None
            for template_dir in possible_template_dirs:
                if os.path.exists(template_dir):
                    self.templates_dir = template_dir
                    print(f"[+] Found nuclei templates in: {template_dir}")
                    break
            
            if not self.templates_dir:
                print("[+] Installing nuclei templates...")
                self.templates_dir = os.path.expanduser("~/.local/nuclei-templates")
                subprocess.run([
                    "nuclei", "-update-templates"
                ], check=True)
                print("[+] Nuclei templates installed successfully")
            
        except subprocess.CalledProcessError as e:
            print(f"[-] Error: {str(e)}")
            print("[-] Please make sure nuclei is installed. You can install it with:")
            print("    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Error checking nuclei templates: {str(e)}")
            sys.exit(1)

    def run_nuclei_templates(self, target):
        """Run nuclei templates"""
        print(f"[+] Running nuclei templates for {target['identifier']}")
        results = []
        
        # Define template categories based on official nuclei-templates repository structure
        template_categories = {
            'http': 'http/',
            'dns': 'dns/',
            'file': 'file/',
            'network': 'network/',
            'ssl': 'ssl/',
            'headless': 'headless/',
            'workflows': 'workflows/',
            'javascript': 'javascript/',
            'dast': 'dast/',
            'cloud': 'cloud/'
        }
        
        # Run all templates at once for better efficiency
        try:
            output_file = os.path.join(self.results_base_dir, f"nuclei_results.json")
            print(f"[+] Running nuclei scan...")
            subprocess.run([
                "nuclei",
                "-u", target['identifier'],
                "-t", self.templates_dir,
                "-o", output_file,
                "-j"  # Use -j for JSON output
            ], check=True)
            results.append(output_file)
        except Exception as e:
            print(f"[-] Error running nuclei scan: {str(e)}")
        
        return results

    def check_waf(self, target):
        """Check for WAF and try to bypass"""
        print(f"[+] Checking WAF for {target['identifier']}")
        waf_results = {
            'detected': False,
            'type': None,
            'bypass_attempted': False,
            'bypass_successful': False
        }
        
        # Common WAF detection headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1'
        }
        
        try:
            # Test for WAF
            response = requests.get(target['identifier'], headers=headers, timeout=5)
            waf_headers = ['x-waf', 'x-cdn', 'cf-ray', 'x-shield', 'x-protection']
            
            for header in waf_headers:
                if header in response.headers:
                    waf_results['detected'] = True
                    waf_results['type'] = header
                    break
            
            # If WAF detected, try bypass techniques
            if waf_results['detected'] and self.config['settings']['waf_bypass']:
                waf_results['bypass_attempted'] = True
                
                # Try different bypass techniques
                bypass_headers = [
                    {'X-Forwarded-For': '127.0.0.1'},
                    {'X-Originating-IP': '127.0.0.1'},
                    {'X-Remote-IP': '127.0.0.1'},
                    {'X-Remote-Addr': '127.0.0.1'}
                ]
                
                for bypass_header in bypass_headers:
                    try:
                        headers.update(bypass_header)
                        bypass_response = requests.get(target['identifier'], headers=headers, timeout=5)
                        if bypass_response.status_code == 200:
                            waf_results['bypass_successful'] = True
                            break
                    except:
                        continue
                
        except Exception as e:
            print(f"[-] Error checking WAF: {str(e)}")
        
        return waf_results

    def run_security_tools(self, target):
        """Run various security tools in parallel"""
        print(f"[+] Running security tools for {target['identifier']}")
        results = {}
        
        # Create target-specific directory
        target_dir = os.path.join(self.results_base_dir, target['identifier'].replace('/', '_').replace(':', '_'))
        os.makedirs(target_dir, exist_ok=True)
        
        # Define tools and their commands
        tools = {
            'nuclei': {
                'command': ['nuclei', '-u', target['identifier'], '-t', self.templates_dir, '-j'],
                'output_file': os.path.join(target_dir, 'nuclei_results.json')
            },
            'sqlmap': {
                'command': ['sqlmap', '-u', target['identifier'], '--batch', '--random-agent', '--output-dir', target_dir],
                'output_file': os.path.join(target_dir, 'sqlmap_results')
            },
            'xsser': {
                'command': ['xsser', '--url', target['identifier'], '--auto'],
                'output_file': os.path.join(target_dir, 'xsser_results.txt')
            }
        }
        
        def run_tool(tool_name, tool_config):
            try:
                print(f"[+] Running {tool_name} for {target['identifier']}")
                subprocess.run(tool_config['command'], check=True)
                return tool_name, tool_config['output_file']
            except Exception as e:
                print(f"[-] Error running {tool_name} for {target['identifier']}: {str(e)}")
                return tool_name, None
        
        # Run tools in parallel
        with ThreadPoolExecutor(max_workers=self.config['settings']['max_workers']) as executor:
            future_to_tool = {
                executor.submit(run_tool, tool_name, tool_config): tool_name
                for tool_name, tool_config in tools.items()
            }
            
            for future in as_completed(future_to_tool):
                tool_name = future_to_tool[future]
                try:
                    tool_name, output_file = future.result()
                    if output_file and os.path.exists(output_file):
                        results[tool_name] = output_file
                except Exception as e:
                    print(f"[-] Error with {tool_name} for {target['identifier']}: {str(e)}")
        
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
            # Check for WAF
            waf_results = self.check_waf(target)
            
            # Run security tools in parallel
            security_results = self.run_security_tools(target)
            
            # Save results
            results = {
                'target': target['identifier'],
                'scan_time': datetime.now().isoformat(),
                'waf_detection': waf_results,
                'security_tools': security_results
            }
            
            report_file = os.path.join(target_dir, 'report.json')
            with open(report_file, 'w') as f:
                json.dump(results, f, indent=4)
            
            print(f"[+] Scan completed for {target['identifier']}")
            print(f"[+] Results saved in {target_dir}")
            
            return {
                'target': target['identifier'],
                'status': 'completed',
                'report_file': report_file,
                'target_dir': target_dir
            }
        except Exception as e:
            print(f"[-] Error scanning {target['identifier']}: {str(e)}")
            return {
                'target': target['identifier'],
                'status': 'failed',
                'error': str(e)
            }

    def generate_comprehensive_summary(self, results):
        """Generate a comprehensive summary of interesting findings"""
        print("[+] Generating comprehensive summary...")
        
        summary = {
            'scan_time': datetime.now().isoformat(),
            'total_targets': len(self.targets),
            'completed_scans': len([r for r in results if r['status'] == 'completed']),
            'failed_scans': len([r for r in results if r['status'] == 'failed']),
            'interesting_findings': {
                'waf_detected': [],
                'non_standard_responses': [],
                'potential_vulnerabilities': [],
                'sensitive_endpoints': [],
                'interesting_headers': [],
                'potential_issues': []
            }
        }
        
        # Interesting response codes to highlight
        interesting_codes = [200, 201, 202, 203, 204, 205, 206, 300, 301, 302, 303, 307, 308, 401, 403, 405, 500, 501, 502, 503]
        
        # Sensitive keywords in URLs/paths
        sensitive_keywords = [
            'admin', 'api', 'auth', 'backup', 'config', 'debug', 'dev', 'git', 'jenkins',
            'login', 'manage', 'php', 'sql', 'test', 'upload', 'wp-', 'wp-content',
            'wp-admin', 'wp-includes', 'wordpress', 'adminer', 'phpmyadmin', 'mysql',
            'database', 'db', 'backup', 'bak', 'old', 'temp', 'tmp', 'log', 'logs',
            'config', 'conf', 'setting', 'settings', 'install', 'setup', 'update',
            'upgrade', 'vendor', 'node_modules', 'bower_components', 'composer',
            'package.json', 'package-lock.json', 'yarn.lock', '.env', '.git',
            '.svn', '.htaccess', 'web.config', 'robots.txt', 'sitemap.xml'
        ]
        
        # Interesting headers to check
        interesting_headers = [
            'server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
            'x-frame-options', 'x-content-type-options', 'x-xss-protection',
            'content-security-policy', 'strict-transport-security', 'x-cache',
            'x-cdn', 'cf-ray', 'x-waf', 'x-shield', 'x-protection'
        ]
        
        for result in results:
            if result['status'] != 'completed':
                continue
                
            target = result['target']
            report_file = result['report_file']
            
            try:
                with open(report_file, 'r') as f:
                    report_data = json.load(f)
                
                # Check WAF detection
                if report_data.get('waf_detection', {}).get('detected'):
                    summary['interesting_findings']['waf_detected'].append({
                        'target': target,
                        'type': report_data['waf_detection']['type'],
                        'bypass_successful': report_data['waf_detection']['bypass_successful']
                    })
                
                # Check security tools results
                security_tools = report_data.get('security_tools', {})
                for tool, output_file in security_tools.items():
                    if os.path.exists(output_file):
                        try:
                            with open(output_file, 'r') as f:
                                tool_results = json.load(f)
                                
                            # Add potential vulnerabilities
                            if tool == 'nuclei':
                                for finding in tool_results:
                                    if finding.get('severity') in ['high', 'critical']:
                                        summary['interesting_findings']['potential_vulnerabilities'].append({
                                            'target': target,
                                            'tool': tool,
                                            'finding': finding
                                        })
                            
                            # Add SQL injection findings
                            elif tool == 'sqlmap':
                                if 'vulnerabilities' in tool_results:
                                    summary['interesting_findings']['potential_vulnerabilities'].append({
                                        'target': target,
                                        'tool': tool,
                                        'finding': tool_results['vulnerabilities']
                                    })
                            
                            # Add XSS findings
                            elif tool == 'xsser':
                                if 'vulnerabilities' in tool_results:
                                    summary['interesting_findings']['potential_vulnerabilities'].append({
                                        'target': target,
                                        'tool': tool,
                                        'finding': tool_results['vulnerabilities']
                                    })
                        except:
                            continue
                
                # Check for non-standard responses
                if 'endpoints' in report_data:
                    for endpoint in report_data['endpoints']:
                        if endpoint.get('status') in interesting_codes:
                            summary['interesting_findings']['non_standard_responses'].append({
                                'target': target,
                                'url': endpoint['url'],
                                'status': endpoint['status'],
                                'headers': endpoint.get('headers', {})
                            })
                
                # Check for sensitive endpoints
                for keyword in sensitive_keywords:
                    if keyword in target.lower():
                        summary['interesting_findings']['sensitive_endpoints'].append({
                            'target': target,
                            'keyword': keyword
                        })
                
                # Check for interesting headers
                if 'headers' in report_data:
                    for header in interesting_headers:
                        if header in report_data['headers']:
                            summary['interesting_findings']['interesting_headers'].append({
                                'target': target,
                                'header': header,
                                'value': report_data['headers'][header]
                            })
                
            except Exception as e:
                print(f"[-] Error processing report for {target}: {str(e)}")
        
        # Generate summary files
        summary_file = os.path.join(self.results_base_dir, 'comprehensive_summary.json')
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=4)
        
        # Generate human-readable summary
        readable_summary = os.path.join(self.results_base_dir, 'comprehensive_summary.txt')
        with open(readable_summary, 'w') as f:
            f.write("=== Bug Bounty Scanner Comprehensive Summary ===\n\n")
            f.write(f"Scan Time: {summary['scan_time']}\n")
            f.write(f"Total Targets: {summary['total_targets']}\n")
            f.write(f"Completed Scans: {summary['completed_scans']}\n")
            f.write(f"Failed Scans: {summary['failed_scans']}\n\n")
            
            # WAF Detection
            f.write("=== WAF Detection ===\n")
            for waf in summary['interesting_findings']['waf_detected']:
                f.write(f"Target: {waf['target']}\n")
                f.write(f"WAF Type: {waf['type']}\n")
                f.write(f"Bypass Successful: {waf['bypass_successful']}\n\n")
            
            # Potential Vulnerabilities
            f.write("=== Potential Vulnerabilities ===\n")
            for vuln in summary['interesting_findings']['potential_vulnerabilities']:
                f.write(f"Target: {vuln['target']}\n")
                f.write(f"Tool: {vuln['tool']}\n")
                f.write(f"Finding: {json.dumps(vuln['finding'], indent=2)}\n\n")
            
            # Non-Standard Responses
            f.write("=== Non-Standard Responses ===\n")
            for response in summary['interesting_findings']['non_standard_responses']:
                f.write(f"Target: {response['target']}\n")
                f.write(f"URL: {response['url']}\n")
                f.write(f"Status: {response['status']}\n")
                f.write(f"Headers: {json.dumps(response['headers'], indent=2)}\n\n")
            
            # Sensitive Endpoints
            f.write("=== Sensitive Endpoints ===\n")
            for endpoint in summary['interesting_findings']['sensitive_endpoints']:
                f.write(f"Target: {endpoint['target']}\n")
                f.write(f"Keyword: {endpoint['keyword']}\n\n")
            
            # Interesting Headers
            f.write("=== Interesting Headers ===\n")
            for header in summary['interesting_findings']['interesting_headers']:
                f.write(f"Target: {header['target']}\n")
                f.write(f"Header: {header['header']}\n")
                f.write(f"Value: {header['value']}\n\n")
        
        print(f"[+] Comprehensive summary generated:")
        print(f"    - JSON summary: {summary_file}")
        print(f"    - Human-readable summary: {readable_summary}")
        
        return summary_file, readable_summary

    def run_scans(self):
        """Run scans for all targets in parallel"""
        print(f"[+] Found {len(self.targets)} targets to scan")
        
        results = []
        with ThreadPoolExecutor(max_workers=self.config['settings']['max_workers']) as executor:
            future_to_target = {
                executor.submit(self.scan_target, target): target
                for target in self.targets
            }
            
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    results.append(result)
                    print(f"[+] Completed scanning {target['identifier']}")
                except Exception as e:
                    print(f"[-] Error scanning {target['identifier']}: {str(e)}")
                    results.append({
                        'target': target['identifier'],
                        'status': 'failed',
                        'error': str(e)
                    })
        
        # Generate comprehensive summary
        summary_file, readable_summary = self.generate_comprehensive_summary(results)
        
        # Print final summary
        print("\n=== Scan Summary ===")
        print(f"Results directory: {self.results_base_dir}")
        print(f"Total targets scanned: {len(self.targets)}")
        print(f"Successfully scanned: {len([r for r in results if r['status'] == 'completed'])}")
        print(f"Failed scans: {len([r for r in results if r['status'] == 'failed'])}")
        print(f"\nDetailed results:")
        for result in results:
            if result['status'] == 'completed':
                print(f"✓ {result['target']} - Results in {result['target_dir']}")
            else:
                print(f"✗ {result['target']} - Failed: {result.get('error', 'Unknown error')}")
        
        print(f"\nComprehensive summaries:")
        print(f"- JSON summary: {summary_file}")
        print(f"- Human-readable summary: {readable_summary}")
        
        return summary_file

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