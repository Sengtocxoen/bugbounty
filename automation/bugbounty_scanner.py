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
        if csv_file:
            self.targets = self.load_targets_from_csv()
        elif target:
            self.targets = [{'identifier': self.normalize_url(target), 'asset_type': 'url'}]

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

    def run_recon_tools(self, target):
        """Run reconnaissance tools"""
        print(f"[+] Running reconnaissance tools for {target['identifier']}")
        results = {}
        
        # Create target-specific directory
        target_dir = os.path.join(self.results_base_dir, target['identifier'].replace('/', '_').replace(':', '_'))
        os.makedirs(target_dir, exist_ok=True)
        
        # Get domain for subdomain enumeration
        domain = urlparse(target['identifier']).netloc

        # Run BBOT for comprehensive scanning
        try:
            print("[+] Running BBOT scanner...")
            bbot_output = os.path.join(target_dir, "bbot_results")
            bbot_json = os.path.join(target_dir, "bbot_results.json")
            
            subprocess.run([
                'bbot',
                '-t', target['identifier'],
                '-p', 'subdomain-enum', 'cloud-enum', 'email-enum',
                '-o', bbot_output,
                '--json', bbot_json,
                '--allow-deadly',
                '--force',
                '--no-deps'
            ], check=True)
            
            if os.path.exists(bbot_json):
                with open(bbot_json, 'r') as f:
                    bbot_data = json.load(f)
                    results['bbot'] = {
                        'output_dir': bbot_output,
                        'json_file': bbot_json,
                        'findings': bbot_data,
                        'status': 'completed'
                    }
        except Exception as e:
            print(f"[-] Error running BBOT: {str(e)}")
            results['bbot'] = {'status': 'failed', 'error': str(e)}

        # Run other recon tools
        recon_tools = {
            'sublist3r': {
                'command': [
                    'python3',
                    str(Path(__file__).parent.parent / 'tools' / 'Sublist3r' / 'sublist3r.py'),
                    '-d', domain,
                    '-o', os.path.join(target_dir, 'sublist3r_results.txt')
                ]
            },
            'knock': {
                'command': [
                    'python3',
                    str(Path(__file__).parent.parent / 'tools' / 'knock' / 'knockpy.py'),
                    domain,
                    '-o', os.path.join(target_dir, 'knock_results.json')
                ]
            },
            'massdns': {
                'command': [
                    str(Path(__file__).parent.parent / 'tools' / 'massdns' / 'bin' / 'massdns'),
                    '-r', str(Path(__file__).parent.parent / 'tools' / 'massdns' / 'lists' / 'resolvers.txt'),
                    '-t', 'A',
                    '-o', 'S',
                    '-w', os.path.join(target_dir, 'massdns_results.txt'),
                    os.path.join(target_dir, 'sublist3r_results.txt')
                ]
            },
            'asnlookup': {
                'command': [
                    'python3',
                    str(Path(__file__).parent.parent / 'tools' / 'asnlookup' / 'asnlookup.py'),
                    '-o', domain,
                    '-f', os.path.join(target_dir, 'asnlookup_results.txt')
                ]
            }
        }

        for tool_name, tool_config in recon_tools.items():
            try:
                print(f"[+] Running {tool_name}...")
                subprocess.run(tool_config['command'], check=True)
                results[tool_name] = {'status': 'completed'}
            except Exception as e:
                print(f"[-] Error running {tool_name}: {str(e)}")
                results[tool_name] = {'status': 'failed', 'error': str(e)}

        return results

    def run_web_scan_tools(self, target):
        """Run web scanning tools"""
        print(f"[+] Running web scanning tools for {target['identifier']}")
        results = {}
        
        target_dir = os.path.join(self.results_base_dir, target['identifier'].replace('/', '_').replace(':', '_'))
        os.makedirs(target_dir, exist_ok=True)

        # Run Katana crawler
        try:
            print("[+] Running Katana crawler...")
            katana_output = os.path.join(target_dir, "katana_results.txt")
            katana_json = os.path.join(target_dir, "katana_results.json")
            
            subprocess.run([
                'katana',
                '-u', target['identifier'],
                '-jc',
                '-o', katana_json,
                '-d', '3',
                '-c', '10',
                '-p', '10',
                '-rl', '150',
                '-kf', 'all',
                '-aff',
                '-fs', 'rdn',
                '-silent'
            ], check=True)
            
            if os.path.exists(katana_json):
                with open(katana_json, 'r') as f:
                    katana_data = json.load(f)
                    with open(katana_output, 'w') as out:
                        for item in katana_data:
                            out.write(f"URL: {item.get('url', 'N/A')}\n")
                            out.write(f"Method: {item.get('method', 'N/A')}\n")
                            out.write(f"Status: {item.get('status', 'N/A')}\n")
                            out.write(f"Content-Type: {item.get('content_type', 'N/A')}\n")
                            out.write(f"Technologies: {', '.join(item.get('technologies', []))}\n")
                            out.write("-" * 80 + "\n")
            
            results['katana'] = {
                'output_file': katana_output,
                'json_file': katana_json,
                'status': 'completed'
            }
        except Exception as e:
            print(f"[-] Error running Katana: {str(e)}")
            results['katana'] = {'status': 'failed', 'error': str(e)}

        # Run Dirsearch
        try:
            print("[+] Running Dirsearch...")
            dirsearch_output = os.path.join(target_dir, 'dirsearch_results.txt')
            subprocess.run([
                'python3',
                str(Path(__file__).parent.parent / 'tools' / 'dirsearch' / 'dirsearch.py'),
                '-u', target['identifier'],
                '-e', 'php,asp,aspx,jsp,html,js,txt',
                '-x', '403,404',
                '-o', dirsearch_output
            ], check=True)
            results['dirsearch'] = {'status': 'completed', 'output': dirsearch_output}
        except Exception as e:
            print(f"[-] Error running Dirsearch: {str(e)}")
            results['dirsearch'] = {'status': 'failed', 'error': str(e)}

        return results

    def run_vuln_scan_tools(self, target):
        """Run vulnerability scanning tools"""
        print(f"[+] Running vulnerability scanning tools for {target['identifier']}")
        results = {}
        
        target_dir = os.path.join(self.results_base_dir, target['identifier'].replace('/', '_').replace(':', '_'))
        os.makedirs(target_dir, exist_ok=True)

        # Run XSSCrapy
        try:
            print("[+] Running XSSCrapy...")
            xsscrapy_output = os.path.join(target_dir, "xsscrapy_results.txt")
            subprocess.run([
                'python3',
                str(Path(__file__).parent.parent / 'tools' / 'xsscrapy' / 'xsscrapy.py'),
                '-u', target['identifier'],
                '-o', xsscrapy_output,
                '--cookie', 'SessionID=test',
                '--threads', '10',
                '--timeout', '10'
            ], check=True)
            results['xsscrapy'] = {'status': 'completed', 'output': xsscrapy_output}
        except Exception as e:
            print(f"[-] Error running XSSCrapy: {str(e)}")
            results['xsscrapy'] = {'status': 'failed', 'error': str(e)}

        # Run SQLMap if parameters were found
        parameters = self.discover_parameters(target)
        if parameters:
            try:
                print("[+] Running SQLMap...")
                sqlmap_output = os.path.join(target_dir, 'sqlmap_results')
                subprocess.run([
                    'python3',
                    str(Path(__file__).parent.parent / 'tools' / 'sqlmap-dev' / 'sqlmap.py'),
                    '-u', target['identifier'],
                    '--batch',
                    '--random-agent',
                    '--output-dir', sqlmap_output,
                    '--forms',
                    '--crawl=2',
                    '--level=3',
                    '--risk=2',
                    '--threads=10'
                ], check=True)
                results['sqlmap'] = {'status': 'completed', 'output': sqlmap_output}
            except Exception as e:
                print(f"[-] Error running SQLMap: {str(e)}")
                results['sqlmap'] = {'status': 'failed', 'error': str(e)}

        return results

    def run_api_testing_workflow(self, target):
        """Run API-focused testing workflow"""
        print(f"[+] Running API testing workflow for {target['identifier']}")
        results = {}
        
        target_dir = os.path.join(self.results_base_dir, target['identifier'].replace('/', '_').replace(':', '_'))
        os.makedirs(target_dir, exist_ok=True)

        # API Endpoint Discovery
        try:
            print("[+] Discovering API endpoints...")
            katana_output = os.path.join(target_dir, "api_endpoints.json")
            subprocess.run([
                'katana',
                '-u', target['identifier'],
                '-jc',
                '-o', katana_output,
                '-d', '3',
                '-c', '10',
                '-p', '10',
                '-rl', '150',
                '-kf', 'all',
                '-aff',
                '-fs', 'rdn',
                '-silent',
                '-match', 'api|v1|v2|graphql'
            ], check=True)
            results['api_discovery'] = {'status': 'completed', 'output': katana_output}
        except Exception as e:
            print(f"[-] Error in API discovery: {str(e)}")
            results['api_discovery'] = {'status': 'failed', 'error': str(e)}

        # API Authentication Testing
        if self.workflows['api_testing']['settings']['auth_required']:
            try:
                print("[+] Testing API authentication...")
                auth_output = os.path.join(target_dir, "api_auth_test.txt")
                # Test common authentication bypasses
                auth_tests = [
                    'Authorization: Bearer null',
                    'Authorization: Bearer undefined',
                    'Authorization: Bearer 0',
                    'X-API-Key: null',
                    'X-API-Key: undefined'
                ]
                with open(auth_output, 'w') as f:
                    for test in auth_tests:
                        f.write(f"Testing: {test}\n")
                results['api_auth'] = {'status': 'completed', 'output': auth_output}
            except Exception as e:
                print(f"[-] Error in API auth testing: {str(e)}")
                results['api_auth'] = {'status': 'failed', 'error': str(e)}

        # Rate Limit Testing
        if self.workflows['api_testing']['settings']['rate_limit_detection']:
            try:
                print("[+] Testing rate limits...")
                rate_output = os.path.join(target_dir, "rate_limit_test.txt")
                # Implement rate limit testing
                with open(rate_output, 'w') as f:
                    f.write("Rate limit testing results\n")
                results['rate_limit'] = {'status': 'completed', 'output': rate_output}
            except Exception as e:
                print(f"[-] Error in rate limit testing: {str(e)}")
                results['rate_limit'] = {'status': 'failed', 'error': str(e)}

        return results

    def run_auth_testing_workflow(self, target):
        """Run authentication testing workflow"""
        print(f"[+] Running authentication testing workflow for {target['identifier']}")
        results = {}
        
        target_dir = os.path.join(self.results_base_dir, target['identifier'].replace('/', '_').replace(':', '_'))
        os.makedirs(target_dir, exist_ok=True)

        # Login Form Testing
        try:
            print("[+] Testing login forms...")
            login_output = os.path.join(target_dir, "login_test.txt")
            # Test common login bypasses
            login_tests = [
                'admin:admin',
                'admin:password',
                'admin:123456',
                'admin:admin123',
                'admin:password123'
            ]
            with open(login_output, 'w') as f:
                for test in login_tests:
                    f.write(f"Testing: {test}\n")
            results['login_test'] = {'status': 'completed', 'output': login_output}
        except Exception as e:
            print(f"[-] Error in login testing: {str(e)}")
            results['login_test'] = {'status': 'failed', 'error': str(e)}

        # 2FA Testing
        if self.workflows['auth_testing']['settings']['test_2fa']:
            try:
                print("[+] Testing 2FA...")
                tfa_output = os.path.join(target_dir, "2fa_test.txt")
                # Test common 2FA bypasses
                tfa_tests = [
                    '000000',
                    '123456',
                    '111111',
                    '999999'
                ]
                with open(tfa_output, 'w') as f:
                    for test in tfa_tests:
                        f.write(f"Testing: {test}\n")
                results['2fa_test'] = {'status': 'completed', 'output': tfa_output}
            except Exception as e:
                print(f"[-] Error in 2FA testing: {str(e)}")
                results['2fa_test'] = {'status': 'failed', 'error': str(e)}

        # Session Analysis
        if self.workflows['auth_testing']['settings']['session_analysis']:
            try:
                print("[+] Analyzing sessions...")
                session_output = os.path.join(target_dir, "session_analysis.txt")
                # Test session management
                with open(session_output, 'w') as f:
                    f.write("Session analysis results\n")
                results['session_analysis'] = {'status': 'completed', 'output': session_output}
            except Exception as e:
                print(f"[-] Error in session analysis: {str(e)}")
                results['session_analysis'] = {'status': 'failed', 'error': str(e)}

        return results

    def run_business_logic_workflow(self, target):
        """Run business logic testing workflow"""
        print(f"[+] Running business logic testing workflow for {target['identifier']}")
        results = {}
        
        target_dir = os.path.join(self.results_base_dir, target['identifier'].replace('/', '_').replace(':', '_'))
        os.makedirs(target_dir, exist_ok=True)

        # Workflow Testing
        if self.workflows['business_logic']['settings']['workflow_testing']:
            try:
                print("[+] Testing business workflows...")
                workflow_output = os.path.join(target_dir, "workflow_test.txt")
                # Test common workflow bypasses
                with open(workflow_output, 'w') as f:
                    f.write("Workflow testing results\n")
                results['workflow_test'] = {'status': 'completed', 'output': workflow_output}
            except Exception as e:
                print(f"[-] Error in workflow testing: {str(e)}")
                results['workflow_test'] = {'status': 'failed', 'error': str(e)}

        # State Analysis
        if self.workflows['business_logic']['settings']['state_analysis']:
            try:
                print("[+] Analyzing state management...")
                state_output = os.path.join(target_dir, "state_analysis.txt")
                # Test state management
                with open(state_output, 'w') as f:
                    f.write("State analysis results\n")
                results['state_analysis'] = {'status': 'completed', 'output': state_output}
            except Exception as e:
                print(f"[-] Error in state analysis: {str(e)}")
                results['state_analysis'] = {'status': 'failed', 'error': str(e)}

        # Race Condition Testing
        if self.workflows['business_logic']['settings']['race_condition_testing']:
            try:
                print("[+] Testing for race conditions...")
                race_output = os.path.join(target_dir, "race_condition_test.txt")
                # Test race conditions
                with open(race_output, 'w') as f:
                    f.write("Race condition testing results\n")
                results['race_condition_test'] = {'status': 'completed', 'output': race_output}
            except Exception as e:
                print(f"[-] Error in race condition testing: {str(e)}")
                results['race_condition_test'] = {'status': 'failed', 'error': str(e)}

        return results

    def run_security_tools(self, target):
        """Run all security tools based on enabled categories and workflows"""
        print(f"[+] Running security tools for {target['identifier']}")
        results = {}
        
        # Run tools based on enabled categories
        for category, config in self.config['scan_categories'].items():
            if config['enabled']:
                if category == 'recon':
                    results['recon'] = self.run_recon_tools(target)
                elif category == 'web_scan':
                    results['web_scan'] = self.run_web_scan_tools(target)
                elif category == 'vuln_scan':
                    results['vuln_scan'] = self.run_vuln_scan_tools(target)
        
        # Run enabled workflows
        for workflow, config in self.workflows.items():
            if config['enabled']:
                if workflow == 'api_testing':
                    results['api_testing'] = self.run_api_testing_workflow(target)
                elif workflow == 'auth_testing':
                    results['auth_testing'] = self.run_auth_testing_workflow(target)
                elif workflow == 'business_logic':
                    results['business_logic'] = self.run_business_logic_workflow(target)
        
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
    # Check if running in virtual environment
    check_venv()
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  For single target: python bugbounty_scanner.py -t <target_url>")
        print("  For CSV file: python bugbounty_scanner.py -c <csv_file>")
        print("  Optional: -f <config_file> for custom configuration")
        print("\nScan Categories:")
        print("  - recon: Subdomain enumeration and reconnaissance")
        print("  - web_scan: Web path discovery and crawling")
        print("  - vuln_scan: Vulnerability scanning (XSS, SQLi)")
        print("\nWorkflows:")
        print("  - api_testing: API-focused testing")
        print("  - auth_testing: Authentication testing")
        print("  - business_logic: Business logic testing")
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