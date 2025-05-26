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
from pathlib import Path

def check_venv():
    """Check if running in virtual environment"""
    if not os.environ.get('VIRTUAL_ENV'):
        print("[-] Warning: Not running in a virtual environment!")
        print("[-] It is recommended to run this script in a virtual environment.")
        print("[-] You can create and activate a virtual environment with:")
        print("    python -m venv venv")
        print("    source venv/bin/activate  # On Unix/macOS")
        print("    venv\\Scripts\\activate    # On Windows")
        response = input("Do you want to continue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)

class BugBountyScanner:
    def __init__(self, csv_file=None, target=None, config_file=None):
        self.csv_file = csv_file
        self.target = target
        self.config_file = config_file
        self.results_base_dir = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.results_base_dir, exist_ok=True)
        
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
                'max_workers': 10
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

    def get_tool_path(self, tool_name):
        """Get the path to a tool"""
        tools_dir = Path(__file__).parent.parent / 'tools'
        if tool_name == 'XSStrike':
            return tools_dir / 'XSStrike' / 'xsstrike.py'
        return None

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

    def discover_parameters(self, target):
        """Discover parameters using multiple tools"""
        print(f"[+] Discovering parameters for {target['identifier']}")
        parameters = set()
        
        # Try Arjun first
        try:
            print("[+] Running Arjun...")
            arjun_output = os.path.join(self.results_base_dir, f"arjun_results_{target['identifier'].replace('/', '_')}.json")
            subprocess.run([
                'arjun',
                '-u', target['identifier'],
                '-o', arjun_output,
                '--passive',
                '-t', '10',
                '-T', '10',
                '--rate-limit', '10',
                '--stable'
            ], check=True)
            
            if os.path.exists(arjun_output):
                with open(arjun_output, 'r') as f:
                    arjun_results = json.load(f)
                    if isinstance(arjun_results, list):
                        for result in arjun_results:
                            if 'params' in result:
                                parameters.update(result['params'])
        except Exception as e:
            print(f"[-] Error running Arjun: {str(e)}")
        
        # Try ParamSpider as backup
        if not parameters:
            try:
                print("[+] Running ParamSpider...")
                paramspider_output = os.path.join(self.results_base_dir, f"paramspider_results_{target['identifier'].replace('/', '_')}.txt")
                domain = urlparse(target['identifier']).netloc
                subprocess.run([
                    'paramspider',
                    '--domain', domain,
                    '--exclude', 'js,jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico',
                    '--output', paramspider_output
                ], check=True)
                
                if os.path.exists(paramspider_output):
                    with open(paramspider_output, 'r') as f:
                        for line in f:
                            if '?' in line:
                                params = line.split('?')[1].split('&')
                                parameters.update([p.split('=')[0] for p in params])
            except Exception as e:
                print(f"[-] Error running ParamSpider: {str(e)}")
        
        return list(parameters)

    def run_security_tools(self, target):
        """Run various security tools in parallel"""
        print(f"[+] Running security tools for {target['identifier']}")
        results = {}
        
        # Create target-specific directory
        target_dir = os.path.join(self.results_base_dir, target['identifier'].replace('/', '_').replace(':', '_'))
        os.makedirs(target_dir, exist_ok=True)
        
        # Discover parameters first
        parameters = self.discover_parameters(target)
        if not parameters:
            print(f"[-] No parameters found for {target['identifier']}, skipping SQLMap")
        else:
            print(f"[+] Found parameters: {', '.join(parameters)}")
        
        # Check for XSStrike
        xsstrike_path = self.get_tool_path('XSStrike')
        if xsstrike_path and xsstrike_path.exists():
            print(f"[+] Found XSStrike at {xsstrike_path}")
            try:
                # Run XSStrike scan with correct parameters
                xsstrike_output = os.path.join(target_dir, 'xsstrike_results.json')
                subprocess.run([
                    'python3', str(xsstrike_path),
                    '-u', target['identifier'],
                    '--crawl',
                    '--blind',
                    '--skip-dom',
                    '--json',
                    '--timeout', '10',
                    '--threads', '10',
                    '--delay', '1',
                    '--console-log-level', 'VULN',
                    '--file-log-level', 'VULN',
                    '--log-file', xsstrike_output
                ], check=True)
                results['xsstrike'] = xsstrike_output
            except Exception as e:
                print(f"[-] Error running XSStrike: {str(e)}")
        else:
            print(f"[-] XSStrike not found at {xsstrike_path}")
        
        # Define other tools and their commands
        tools = {
            'nuclei': {
                'command': [
                    'nuclei',
                    '-u', target['identifier'],
                    '-severity', 'critical,high,medium',
                    '-c', '50',
                    '-bulk-size', '25',
                    '-rate-limit', '150',
                    '-timeout', '5',
                    '-o', os.path.join(target_dir, 'nuclei_results.json')
                ],
                'output_file': os.path.join(target_dir, 'nuclei_results.json')
            }
        }
        
        # Add SQLMap only if parameters were found
        if parameters:
            tools['sqlmap'] = {
                'command': [
                    'sqlmap',
                    '-u', target['identifier'],
                    '--batch',
                    '--random-agent',
                    '--output-dir', target_dir,
                    '--forms',
                    '--crawl=2',
                    '--level=3',
                    '--risk=2',
                    '--threads=10',
                    '--param-del="&"',
                    '--skip-urlencode',
                    '--eval="from urllib.parse import unquote; print(unquote(\'%s\'))"',
                    '--smart',
                    '--technique=BEUSTQ',
                    '--time-sec=5',
                    '--retries=2'
                ],
                'output_file': os.path.join(target_dir, 'sqlmap_results')
            }
        
        # Add Gospider with correct parameters
        tools.update({
            'gospider': {
                'command': [
                    'gospider',
                    '-s', target['identifier'],
                    '-o', os.path.join(target_dir, 'gospider_results.txt'),
                    '-c', '10',
                    '-d', '3',
                    '--sitemap',
                    '--robots',
                    '--other-source',
                    '--include-subs',
                    '-t', '10',
                    '-m', '10',
                    '-k', '1',
                    '-v'
                ],
                'output_file': os.path.join(target_dir, 'gospider_results.txt')
            }
        })
        
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
            # Run security tools in parallel
            security_results = self.run_security_tools(target)
            
            # Save results
            results = {
                'target': target['identifier'],
                'scan_time': datetime.now().isoformat(),
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

    def generate_tool_report(self, results):
        """Generate a report of tool findings"""
        print("[+] Generating tool report...")
        
        report = {
            'scan_time': datetime.now().isoformat(),
            'total_targets': len(self.targets),
            'completed_scans': len([r for r in results if r['status'] == 'completed']),
            'failed_scans': len([r for r in results if r['status'] == 'failed']),
            'findings': {
                'nuclei': [],
                'sqlmap': [],
                'xsstrike': [],
                'gospider': []
            }
        }
        
        for result in results:
            if result['status'] != 'completed':
                continue
                
            target = result['target']
            report_file = result['report_file']
            
            try:
                with open(report_file, 'r') as f:
                    report_data = json.load(f)
                
                # Process tool results
                security_tools = report_data.get('security_tools', {})
                for tool, output_file in security_tools.items():
                    if os.path.exists(output_file):
                        try:
                            with open(output_file, 'r') as f:
                                tool_results = json.load(f)
                                
                            # Process Nuclei results
                            if tool == 'nuclei':
                                for finding in tool_results:
                                    if finding.get('severity') in ['high', 'critical', 'medium']:
                                        report['findings']['nuclei'].append({
                                            'target': target,
                                            'severity': finding.get('severity'),
                                            'name': finding.get('info', {}).get('name'),
                                            'description': finding.get('info', {}).get('description'),
                                            'url': finding.get('matched-at')
                                        })
                            
                            # Process SQLMap results
                            elif tool == 'sqlmap':
                                if isinstance(tool_results, dict) and 'vulnerabilities' in tool_results:
                                    report['findings']['sqlmap'].append({
                                        'target': target,
                                        'vulnerabilities': tool_results['vulnerabilities']
                                    })
                            
                            # Process XSStrike results
                            elif tool == 'xsstrike':
                                if isinstance(tool_results, dict) and 'vulnerabilities' in tool_results:
                                    report['findings']['xsstrike'].append({
                                        'target': target,
                                        'vulnerabilities': tool_results['vulnerabilities']
                                    })
                            
                            # Process Gospider results
                            elif tool == 'gospider':
                                if isinstance(tool_results, list):
                                    report['findings']['gospider'].append({
                                        'target': target,
                                        'urls': tool_results
                                    })
                        except Exception as e:
                            print(f"[-] Error processing {tool} results for {target}: {str(e)}")
                            continue
                
            except Exception as e:
                print(f"[-] Error processing report for {target}: {str(e)}")
        
        # Generate report files
        report_file = os.path.join(self.results_base_dir, 'tool_report.json')
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=4)
        
        # Generate human-readable report
        readable_report = os.path.join(self.results_base_dir, 'tool_report.txt')
        with open(readable_report, 'w') as f:
            f.write("=== Bug Bounty Scanner Tool Report ===\n\n")
            f.write(f"Scan Time: {report['scan_time']}\n")
            f.write(f"Total Targets: {report['total_targets']}\n")
            f.write(f"Completed Scans: {report['completed_scans']}\n")
            f.write(f"Failed Scans: {report['failed_scans']}\n\n")
            
            # Nuclei Findings
            f.write("=== Nuclei Findings ===\n")
            for finding in report['findings']['nuclei']:
                f.write(f"Target: {finding['target']}\n")
                f.write(f"Severity: {finding['severity']}\n")
                f.write(f"Name: {finding['name']}\n")
                f.write(f"Description: {finding['description']}\n")
                f.write(f"URL: {finding['url']}\n\n")
            
            # SQLMap Findings
            f.write("=== SQLMap Findings ===\n")
            for finding in report['findings']['sqlmap']:
                f.write(f"Target: {finding['target']}\n")
                f.write(f"Vulnerabilities: {json.dumps(finding['vulnerabilities'], indent=2)}\n\n")
            
            # XSStrike Findings
            f.write("=== XSStrike Findings ===\n")
            for finding in report['findings']['xsstrike']:
                f.write(f"Target: {finding['target']}\n")
                f.write(f"Vulnerabilities: {json.dumps(finding['vulnerabilities'], indent=2)}\n\n")
            
            # Gospider Findings
            f.write("=== Gospider Findings ===\n")
            for finding in report['findings']['gospider']:
                f.write(f"Target: {finding['target']}\n")
                f.write(f"Discovered URLs: {len(finding['urls'])}\n")
                f.write("Sample URLs:\n")
                for url in finding['urls'][:10]:  # Show first 10 URLs
                    f.write(f"- {url}\n")
                f.write("\n")
        
        print(f"[+] Tool report generated:")
        print(f"    - JSON report: {report_file}")
        print(f"    - Human-readable report: {readable_report}")
        
        return report_file, readable_report

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
        
        # Generate tool report
        report_file, readable_report = self.generate_tool_report(results)
        
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
        
        print(f"\nTool reports:")
        print(f"- JSON report: {report_file}")
        print(f"- Human-readable report: {readable_report}")
        
        return self.results_base_dir

def main():
    # Check if running in virtual environment
    check_venv()
    
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
    results_dir = scanner.run_scans()
    
    print("\nScan Summary:")
    print(f"Results directory: {results_dir}")

if __name__ == "__main__":
    main() 