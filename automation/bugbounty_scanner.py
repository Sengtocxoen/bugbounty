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
from jinja2 import Environment, FileSystemLoader
from typing import Dict
import argparse
import shutil
import time

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
    def __init__(self, output_dir, config_file=None):
        self.output_dir = output_dir
        self.config_file = config_file
        self.results_base_dir = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.results_base_dir, exist_ok=True)
        
        # Default configuration if no config file is provided
        self.config = {
            'scan_categories': {
                'recon': {
                    'enabled': True,
                    'tools': ['sublist3r', 'knock', 'massdns', 'asnlookup', 'bbot', 'httprobe', 'waybackurls', 'aquatone'],
                    'settings': {
                        'max_concurrent_requests': 5,
                        'request_timeout': 5
                    }
                },
                'web_scan': {
                    'enabled': True,
                    'tools': ['dirsearch', 'katana'],
                    'settings': {
                        'max_depth': 3,
                        'concurrency': 10
                    }
                },
                'vuln_scan': {
                    'enabled': True,
                    'tools': ['sqlmap', 'xsscrapy'],
                    'settings': {
                        'max_severity': 'high',
                        'scan_timeout': 300
                    }
                }
            },
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
                'max_workers': 10,
                'shodan_api_key': '',
                'censys_api_id': '',
                'censys_api_secret': ''
            }
        }
        
        # Load custom config if provided
        if config_file:
            self.load_config(config_file)
        
        # Load targets from CSV if provided
        self.targets = []
        if self.config_file:
            self.targets = self.load_targets_from_csv()
        elif self.config['scan_categories']['recon']['enabled']:
            self.targets = [{'identifier': self.normalize_url(target), 'asset_type': 'url'} for target in self.config['scan_categories']['recon']['tools']]

        # Add new workflow configurations
        self.workflows = {
            'api_testing': {
                'enabled': False,
                'tools': ['katana', 'sqlmap', 'xsscrapy'],
                'settings': {
                    'focus_endpoints': ['/api/', '/v1/', '/v2/', '/graphql'],
                    'auth_required': True,
                    'rate_limit_detection': True
                }
            },
            'auth_testing': {
                'enabled': False,
                'tools': ['katana', 'sqlmap', 'xsscrapy'],
                'settings': {
                    'focus_endpoints': ['/login', '/register', '/reset-password', '/oauth'],
                    'test_2fa': True,
                    'session_analysis': True
                }
            },
            'business_logic': {
                'enabled': False,
                'tools': ['katana', 'sqlmap'],
                'settings': {
                    'workflow_testing': True,
                    'state_analysis': True,
                    'race_condition_testing': True
                }
            }
        }

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
            with open(self.config_file, 'r', encoding='utf-8') as f:
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

    def run_recon_tools(self, target: str) -> Dict[str, any]:
        """Run reconnaissance tools"""
        results = {}
        recon_dir = Path(self.output_dir) / 'recon'
        recon_dir.mkdir(parents=True, exist_ok=True)
        
        # Run BBOT
        try:
            print("[+] Running BBOT scanner...")
            bbot_output = recon_dir / 'bbot_results'
            # List available presets first
            subprocess.run(['bbot', '-lm'], check=True)
            # Run with individual modules instead of presets
            subprocess.run([
                'bbot',
                '-t', target,
                '-m', 'subdomain,cloud,email',
                '-o', str(bbot_output),
                '--json',
                '--allow-deadly',
                '--force'
            ], check=True)
            if (bbot_output / 'bbot.json').exists():
                results['bbot'] = json.loads((bbot_output / 'bbot.json').read_text())
        except subprocess.CalledProcessError as e:
            print(f"[-] Error running BBOT: {str(e)}")
        
        # Run Sublist3r
        try:
            print("[+] Running Sublist3r...")
            sublist3r_output = recon_dir / 'sublist3r.txt'
            # Update Sublist3r to handle CSRF token error
            sublist3r_script = Path(__file__).parent.parent / 'tools' / 'Sublist3r' / 'sublist3r.py'
            if sublist3r_script.exists():
                content = sublist3r_script.read_text()
                # Add error handling for CSRF token
                content = content.replace(
                    'token = csrf_regex.findall(resp)[0]',
                    'tokens = csrf_regex.findall(resp)\ntoken = tokens[0] if tokens else ""'
                )
                sublist3r_script.write_text(content)
            
            subprocess.run([
                'python3',
                str(sublist3r_script),
                '-d', urlparse(target).netloc,
                '-o', str(sublist3r_output)
            ], check=True)
            if sublist3r_output.exists():
                results['sublist3r'] = sublist3r_output.read_text()
        except subprocess.CalledProcessError as e:
            print(f"[-] Error running Sublist3r: {str(e)}")
        
        # Run Knock
        try:
            print("[+] Running Knock...")
            knock_output = recon_dir / 'knock_results.json'
            subprocess.run([
                'python3',
                str(Path(__file__).parent.parent / 'tools' / 'knock' / 'knockpy.py'),
                '-d', urlparse(target).netloc,
                '--json',
                '--save', str(knock_output)
            ], check=True)
            if knock_output.exists():
                results['knock'] = json.loads(knock_output.read_text())
        except subprocess.CalledProcessError as e:
            print(f"[-] Error running Knock: {str(e)}")
        
        # Run Httprobe
        try:
            print("[+] Running Httprobe...")
            httprobe_output = recon_dir / 'httprobe.txt'
            if results.get('sublist3r'):
                subprocess.run([
                    'httprobe',
                    '-c', str(self.config['scan_categories']['recon']['settings']['max_concurrent_requests']),
                    '-t', str(self.config['scan_categories']['recon']['settings']['request_timeout'])
                ], input=results['sublist3r'].encode(), 
                   stdout=httprobe_output.open('w'), check=True)
                if httprobe_output.exists():
                    results['httprobe'] = httprobe_output.read_text()
        except subprocess.CalledProcessError as e:
            print(f"[-] Error running Httprobe: {str(e)}")
        
        return results

    def run_web_scan_tools(self, target: str) -> Dict[str, any]:
        """Run web scanning tools"""
        results = {}
        web_scan_dir = Path(self.output_dir) / 'web_scan'
        web_scan_dir.mkdir(parents=True, exist_ok=True)
        
        # Run Dirsearch
        try:
            print("[+] Running Dirsearch...")
            dirsearch_output = web_scan_dir / 'dirsearch.txt'
            subprocess.run([
                'python3',
                str(Path(__file__).parent.parent / 'tools' / 'dirsearch' / 'dirsearch.py'),
                '-u', target,
                '-e', 'php,asp,aspx,jsp,html,js',
                '-x', '403,404',
                '-o', str(dirsearch_output)
            ], check=True)
            if dirsearch_output.exists():
                results['dirsearch'] = dirsearch_output.read_text()
        except subprocess.CalledProcessError as e:
            print(f"[-] Error running Dirsearch: {str(e)}")
        
        # Run Katana
        try:
            print("[+] Running Katana...")
            katana_output = web_scan_dir / 'katana.txt'
            # Check if katana is installed
            if not shutil.which('katana'):
                print("[-] Katana not found in PATH. Installing...")
                subprocess.run([
                    'go', 'install', 'github.com/projectdiscovery/katana/cmd/katana@latest'
                ], check=True)
            
            subprocess.run([
                'katana',
                '-u', target,
                '-d', str(self.config['scan_categories']['web_scan']['settings']['max_depth']),
                '-o', str(katana_output)
            ], check=True)
            if katana_output.exists():
                results['katana'] = katana_output.read_text()
        except subprocess.CalledProcessError as e:
            print(f"[-] Error running Katana: {str(e)}")
        
        return results

    def run_vuln_scan_tools(self, target: str) -> Dict[str, any]:
        """Run vulnerability scanning tools"""
        results = {}
        vuln_scan_dir = Path(self.output_dir) / 'vuln_scan'
        vuln_scan_dir.mkdir(parents=True, exist_ok=True)
        
        # Run SQLMap
        try:
            print("[+] Running SQLMap...")
            sqlmap_output = vuln_scan_dir / 'sqlmap'
            subprocess.run([
                'python3',
                str(Path(__file__).parent.parent / 'tools' / 'sqlmap-dev' / 'sqlmap.py'),
                '-u', target,
                '--batch',
                '--random-agent',
                '--level', '2',
                '--risk', '2',
                '--output-dir', str(sqlmap_output)
            ], check=True)
            if (sqlmap_output / 'log').exists():
                results['sqlmap'] = (sqlmap_output / 'log').read_text()
        except subprocess.CalledProcessError as e:
            print(f"[-] Error running SQLMap: {str(e)}")
        
        # Run XSSCrapy
        try:
            print("[+] Running XSSCrapy...")
            xsscrapy_output = vuln_scan_dir / 'xsscrapy.txt'
            
            # First, try to fix Python 3 compatibility
            xsscrapy_dir = Path(__file__).parent.parent / 'tools' / 'xsscrapy'
            spider_file = xsscrapy_dir / 'xsscrapy' / 'spiders' / 'xss_spider.py'
            
            if spider_file.exists():
                # Read the file content
                content = spider_file.read_text()
                # Replace Python 2 imports with Python 3
                content = content.replace('from urlparse import', 'from urllib.parse import')
                # Write back the modified content
                spider_file.write_text(content)
            
            # Run XSSCrapy with Python 3
            subprocess.run([
                'python3',
                str(xsscrapy_dir / 'xsscrapy.py'),
                '-u', target,
                '-o', str(xsscrapy_output),
                '--threads', '10',
                '--timeout', '10'
            ], check=True)
            
            if xsscrapy_output.exists():
                results['xsscrapy'] = xsscrapy_output.read_text()
        except subprocess.CalledProcessError as e:
            print(f"[-] Error running XSSCrapy: {str(e)}")
            print("[*] Trying alternative XSSCrapy execution...")
            try:
                # Try running with Python 2 if available
                subprocess.run([
                    'python2',
                    str(xsscrapy_dir / 'xsscrapy.py'),
                    '-u', target,
                    '-o', str(xsscrapy_output),
                    '--threads', '10',
                    '--timeout', '10'
                ], check=True)
                if xsscrapy_output.exists():
                    results['xsscrapy'] = xsscrapy_output.read_text()
            except subprocess.CalledProcessError as e:
                print(f"[-] Error running XSSCrapy with Python 2: {str(e)}")
                print("[*] You may need to install Python 2 or update XSSCrapy to Python 3")
        
        return results

    def run_security_tools(self, target: str) -> Dict[str, any]:
        """Run security tools based on enabled categories"""
        results = {}
        
        # Create main output directory
        self.output_dir = Path(self.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Run tools based on enabled categories
        if self.config['scan_categories']['recon']['enabled']:
            results['recon'] = self.run_recon_tools(target)
        
        if self.config['scan_categories']['web_scan']['enabled']:
            results['web_scan'] = self.run_web_scan_tools(target)
        
        if self.config['scan_categories']['vuln_scan']['enabled']:
            results['vuln_scan'] = self.run_vuln_scan_tools(target)
        
        # Save all results to a single JSON file
        results_file = self.output_dir / 'scan_results.json'
        with results_file.open('w') as f:
            json.dump(results, f, indent=2)
        
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
            security_results = self.run_security_tools(target['identifier'])
            
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

    def generate_html_report(self, target, results):
        """Generate HTML report using template"""
        # Set up Jinja2 environment
        template_dir = Path(__file__).parent.parent / 'templates'
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template('report_template.html')
        
        # Process tool results
        processed_results = {}
        
        # Process Sublist3r results
        if 'sublist3r' in results:
            try:
                with open(results['sublist3r'], 'r') as f:
                    processed_results['sublist3r_findings'] = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"[-] Error processing Sublist3r results: {str(e)}")
        
        # Process Dirsearch results
        if 'dirsearch' in results:
            try:
                with open(results['dirsearch'], 'r') as f:
                    processed_results['dirsearch_findings'] = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"[-] Error processing Dirsearch results: {str(e)}")
        
        # Process Knock results
        if 'knock' in results:
            try:
                with open(results['knock'], 'r') as f:
                    processed_results['knock_findings'] = json.load(f)
            except Exception as e:
                print(f"[-] Error processing Knock results: {str(e)}")
        
        # Process MassDNS results
        if 'massdns' in results:
            try:
                with open(results['massdns'], 'r') as f:
                    processed_results['massdns_findings'] = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"[-] Error processing MassDNS results: {str(e)}")
        
        # Process ASNLookup results
        if 'asnlookup' in results:
            try:
                with open(results['asnlookup'], 'r') as f:
                    processed_results['asnlookup_findings'] = json.load(f)
            except Exception as e:
                print(f"[-] Error processing ASNLookup results: {str(e)}")
        
        # Process Httprobe results
        if 'httprobe' in results:
            try:
                with open(results['httprobe'], 'r') as f:
                    processed_results['httprobe_findings'] = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"[-] Error processing Httprobe results: {str(e)}")
        
        # Process Waybackurls results
        if 'waybackurls' in results:
            try:
                with open(results['waybackurls'], 'r') as f:
                    processed_results['waybackurls_findings'] = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"[-] Error processing Waybackurls results: {str(e)}")
        
        # Process Aquatone results
        if 'aquatone' in results:
            processed_results['aquatone_findings'] = results['aquatone']
        
        # Process SQLMap results
        if 'sqlmap' in results:
            try:
                with open(os.path.join(results['sqlmap'], 'log'), 'r') as f:
                    vulnerabilities = []
                    for line in f:
                        if line.strip():
                            try:
                                vulnerabilities.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                    processed_results['sqlmap_findings'] = [{
                        'target': target['identifier'],
                        'vulnerabilities': vulnerabilities
                    }]
            except Exception as e:
                print(f"[-] Error processing SQLMap results: {str(e)}")
        
        # Process Nuclei results
        if 'nuclei' in results:
            try:
                with open(results['nuclei'], 'r') as f:
                    processed_results['nuclei_findings'] = json.load(f)
            except Exception as e:
                print(f"[-] Error processing Nuclei results: {str(e)}")
        
        # Prepare data for template
        template_data = {
            'target': target['identifier'],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            **processed_results
        }
        
        # Generate report
        report_path = os.path.join(self.results_base_dir, f"report_{target['identifier'].replace('/', '_').replace(':', '_')}.html")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(template.render(**template_data))
        
        print(f"[+] Generated HTML report: {report_path}")
        return report_path

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
                'gospider': [],
                'shodan': [],
                'censys': [],
                'vulners': []
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
                            
                            # Process Shodan results
                            elif tool == 'shodan':
                                if isinstance(tool_results, dict):
                                    report['findings']['shodan'].append({
                                        'target': target,
                                        'results': tool_results
                                    })
                            
                            # Process Censys results
                            elif tool == 'censys':
                                if isinstance(tool_results, dict):
                                    report['findings']['censys'].append({
                                        'target': target,
                                        'results': tool_results
                                    })
                            
                            # Process Vulners results
                            elif tool == 'vulners':
                                if isinstance(tool_results, dict):
                                    report['findings']['vulners'].append({
                                        'target': target,
                                        'results': tool_results
                                    })
                        except Exception as e:
                            print(f"[-] Error processing {tool} results for {target}: {str(e)}")
                            continue
                
                # Generate HTML report for this target
                html_report = self.generate_html_report({'identifier': target}, report['findings'])
                print(f"[+] Generated HTML report: {html_report}")
                
            except Exception as e:
                print(f"[-] Error processing report for {target}: {str(e)}")
        
        # Generate JSON report
        report_file = os.path.join(self.results_base_dir, 'tool_report.json')
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=4)
        
        return report_file

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
        report_file = self.generate_tool_report(results)
        
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
        
        return self.results_base_dir

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Bug Bounty Scanner')
    parser.add_argument('-t', '--target', help='Target URL or domain')
    parser.add_argument('-f', '--file', help='File containing list of targets')
    parser.add_argument('-o', '--output', help='Output directory for results', default='scan_results')
    parser.add_argument('-c', '--config', help='Path to configuration file')
    
    args = parser.parse_args()
    
    if not args.target and not args.file:
        parser.print_help()
        sys.exit(1)
    
    scanner = BugBountyScanner(args.output, args.config)
    
    if args.target:
        results = scanner.run_security_tools(args.target)
        print(f"[+] Scan completed. Results saved to {args.output}")
    elif args.file:
        with open(args.file) as f:
            targets = [line.strip() for line in f if line.strip()]
        
        for target in targets:
            print(f"[+] Scanning {target}...")
            results = scanner.run_security_tools(target)
            print(f"[+] Scan completed for {target}")
        
        print(f"[+] All scans completed. Results saved to {args.output}")

if __name__ == "__main__":
    main() 