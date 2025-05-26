#!/usr/bin/env python3

import csv
import sys
import os
import json
import yaml
import requests
import subprocess
import venv
import shutil
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Import tool manager
sys.path.append(str(Path(__file__).parent.parent))
from tools.tool_manager import ToolManager

class VenvManager:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.venv_dir = self.base_dir / 'venv'
        self.requirements_file = self.base_dir / 'requirements.txt'
        self.tools_dir = self.base_dir / 'tools'
        self.tools_dir.mkdir(exist_ok=True)
        self.activate_script = self.venv_dir / 'bin' / 'activate' if os.name != 'nt' else self.venv_dir / 'Scripts' / 'activate.bat'

    def setup_venv(self):
        """Set up virtual environment if needed"""
        if not self.venv_dir.exists():
            print("[+] Virtual environment not found. Creating one...")
            try:
                venv.create(self.venv_dir, with_pip=True)
                print(f"[+] Virtual environment created at {self.venv_dir}")
                self.install_requirements()
                self.install_tools()
            except Exception as e:
                print(f"[-] Error creating virtual environment: {str(e)}")
                return False
        return True

    def install_requirements(self):
        """Install requirements in the virtual environment"""
        print("[+] Installing requirements...")
        try:
            # Create requirements.txt if it doesn't exist
            if not self.requirements_file.exists():
                with open(self.requirements_file, 'w') as f:
                    f.write("""requests>=2.31.0
pyyaml>=6.0.1
beautifulsoup4>=4.12.2
colorama>=0.4.6
tqdm>=4.66.1
pipx>=1.2.0
""")

            # Install requirements using the virtual environment's pip
            pip_path = self.venv_dir / 'bin' / 'pip' if os.name != 'nt' else self.venv_dir / 'Scripts' / 'pip.exe'
            subprocess.run([str(pip_path), 'install', '-r', str(self.requirements_file)], check=True)
            print("[+] Requirements installed successfully")
            return True
        except Exception as e:
            print(f"[-] Error installing requirements: {str(e)}")
            return False

    def install_tools(self):
        """Install required tools"""
        print("[+] Installing required tools...")
        
        # Install XSStrike
        xsstrike_dir = self.tools_dir / 'XSStrike'
        if not xsstrike_dir.exists():
            print("[+] Installing XSStrike...")
            try:
                subprocess.run(['git', 'clone', 'https://github.com/s0md3v/XSStrike', str(xsstrike_dir)], check=True)
                pip_path = self.venv_dir / 'bin' / 'pip' if os.name != 'nt' else self.venv_dir / 'Scripts' / 'pip.exe'
                subprocess.run([str(pip_path), 'install', '-r', str(xsstrike_dir / 'requirements.txt'), '--break-system-packages'], check=True)
            except Exception as e:
                print(f"[-] Error installing XSStrike: {str(e)}")

        # Install Arjun using pipx
        print("[+] Installing Arjun...")
        try:
            subprocess.run(['pipx', 'install', 'arjun'], check=True)
        except Exception as e:
            print(f"[-] Error installing Arjun: {str(e)}")

        # Install ParamSpider
        paramspider_dir = self.tools_dir / 'paramspider'
        if not paramspider_dir.exists():
            print("[+] Installing ParamSpider...")
            try:
                subprocess.run(['git', 'clone', 'https://github.com/devanshbatham/paramspider', str(paramspider_dir)], check=True)
                pip_path = self.venv_dir / 'bin' / 'pip' if os.name != 'nt' else self.venv_dir / 'Scripts' / 'pip.exe'
                subprocess.run([str(pip_path), 'install', '.'], cwd=str(paramspider_dir), check=True)
            except Exception as e:
                print(f"[-] Error installing ParamSpider: {str(e)}")

        # Install waybackurls
        print("[+] Installing waybackurls...")
        try:
            subprocess.run(['go', 'install', 'github.com/tomnomnom/waybackurls@latest'], check=True)
        except Exception as e:
            print(f"[-] Error installing waybackurls: {str(e)}")

        # Install gospider
        print("[+] Installing gospider...")
        try:
            os.environ['GO111MODULE'] = 'on'
            subprocess.run(['go', 'install', 'github.com/jaeles-project/gospider@latest'], check=True)
        except Exception as e:
            print(f"[-] Error installing gospider: {str(e)}")

    def get_python_path(self):
        """Get the path to the Python executable in the virtual environment"""
        if os.name == 'nt':  # Windows
            return self.venv_dir / 'Scripts' / 'python.exe'
        return self.venv_dir / 'bin' / 'python'

    def get_tool_path(self, tool_name):
        """Get the path to a tool"""
        if tool_name == 'XSStrike':
            return self.tools_dir / 'XSStrike' / 'xsstrike.py'
        elif tool_name == 'ParamSpider':
            return self.tools_dir / 'paramspider' / 'paramspider.py'
        return None

    def run_in_venv(self, script_path, *args):
        """Run a script in the virtual environment"""
        python_path = self.get_python_path()
        try:
            subprocess.run([str(python_path), str(script_path)] + list(args), check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"[-] Error running script in virtual environment: {str(e)}")
            return False

class BugBountyScanner:
    def __init__(self, csv_file=None, target=None, config_file=None):
        self.csv_file = csv_file
        self.target = target
        self.config_file = config_file
        self.results_base_dir = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.results_base_dir, exist_ok=True)
        
        # Initialize tool manager with GitHub URLs
        self.tool_manager = ToolManager()
        self.tool_urls = {
            'XSStrike': 'https://github.com/s0md3v/XSStrike',
            'Arjun': 'https://github.com/s0md3v/Arjun',
            'ParamSpider': 'https://github.com/devanshbatham/ParamSpider',
            'Waybackurls': 'https://github.com/tomnomnom/waybackurls',
            'Gospider': 'https://github.com/jaeles-project/gospider'
        }
        
        # Install required tools if not present
        self.install_required_tools()
        
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
                'max_workers': 10,
                'waf_bypass': True
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

    def install_required_tools(self):
        """Install required tools if not present"""
        print("[+] Checking and installing required tools...")
        for tool_name, repo_url in self.tool_urls.items():
            if not self.tool_manager.get_tool_path(tool_name):
                print(f"[+] Installing {tool_name}...")
                install_cmd = None
                if tool_name == 'XSStrike':
                    install_cmd = "pip install -r requirements.txt"
                elif tool_name == 'Arjun':
                    install_cmd = "pip install -r requirements.txt"
                elif tool_name == 'ParamSpider':
                    install_cmd = "pip install -r requirements.txt"
                self.tool_manager.install_tool(tool_name, repo_url, install_cmd)

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
                '-oJ', arjun_output,
                '--passive'
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
        paramspider_path = self.venv_manager.get_tool_path('ParamSpider')
        if paramspider_path and not parameters:
            try:
                print("[+] Running ParamSpider...")
                paramspider_output = os.path.join(self.results_base_dir, f"paramspider_results_{target['identifier'].replace('/', '_')}.txt")
                subprocess.run([
                    'python', str(paramspider_path),
                    '--domain', urlparse(target['identifier']).netloc,
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
        xsstrike_path = self.venv_manager.get_tool_path('XSStrike')
        if xsstrike_path:
            print(f"[+] Found XSStrike at {xsstrike_path}")
            try:
                # Run XSStrike scan
                xsstrike_output = os.path.join(target_dir, 'xsstrike_results.json')
                subprocess.run([
                    'python', str(xsstrike_path),
                    '--url', target['identifier'],
                    '--params',
                    '--crawl',
                    '--blind',
                    '--skip-dom',
                    '--skip-poc',
                    '--output', xsstrike_output
                ], check=True)
                results['xsstrike'] = xsstrike_output
            except Exception as e:
                print(f"[-] Error running XSStrike: {str(e)}")
        
        # Define other tools and their commands
        tools = {
            'nuclei': {
                'command': ['nuclei', '-u', target['identifier'], '-t', self.templates_dir, '-j'],
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
                    '--eval="from urllib.parse import unquote; print(unquote(\'%s\'))"'
                ],
                'output_file': os.path.join(target_dir, 'sqlmap_results')
            }
        
        # Add other tools
        tools.update({
            'gospider': {
                'command': [
                    'gospider',
                    '-s', target['identifier'],
                    '-o', os.path.join(target_dir, 'gospider_results.txt'),
                    '-c', '10',
                    '-d', '3',
                    '--js',
                    '--sitemap',
                    '--robots',
                    '--other-source',
                    '--include-subs',
                    '--json'
                ],
                'output_file': os.path.join(target_dir, 'gospider_results.txt')
            },
            'waybackurls': {
                'command': [
                    'waybackurls',
                    target['identifier'].replace('https://', '').replace('http://', ''),
                    '>', os.path.join(target_dir, 'waybackurls_results.txt')
                ],
                'output_file': os.path.join(target_dir, 'waybackurls_results.txt')
            }
        })
        
        def run_tool(tool_name, tool_config):
            try:
                print(f"[+] Running {tool_name} for {target['identifier']}")
                # Handle special case for waybackurls which uses shell redirection
                if tool_name == 'waybackurls':
                    subprocess.run(' '.join(tool_config['command']), shell=True, check=True)
                else:
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
                            elif tool == 'xsstrike':
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
    # Initialize virtual environment manager
    venv_manager = VenvManager()
    
    # Set up virtual environment if needed
    if not venv_manager.setup_venv():
        print("[-] Failed to set up virtual environment")
        sys.exit(1)

    # Get the path to the current script
    current_script = Path(__file__)
    
    # Run the script in the virtual environment
    if not venv_manager.run_in_venv(current_script, *sys.argv[1:]):
        sys.exit(1)

if __name__ == "__main__":
    # Check if we're running in the virtual environment
    if not os.environ.get('VIRTUAL_ENV'):
        # We're not in the virtual environment, so set it up and run the script again
        main()
    else:
        # We're in the virtual environment, so run the actual scanner code
        # [Rest of your existing BugBountyScanner class and code here]
        # ... (keep all the existing scanner code)
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