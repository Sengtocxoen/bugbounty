#!/usr/bin/env python3

import os
import sys
import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Union

class ToolsManager:
    def __init__(self, tools_dir: Union[str, Path] = None):
        """Initialize the tools manager"""
        self.tools_dir = Path(tools_dir) if tools_dir else Path(__file__).parent
        
        # Tools categorized by their primary focus
        self.tools = {
            # Reconnaissance Tools
            'recon': {
                'sublist3r': {
                    'repo': 'https://github.com/aboul3la/Sublist3r.git',
                    'path': self.tools_dir / 'Sublist3r',
                    'requirements': 'requirements.txt',
                    'main_script': 'sublist3r.py',
                    'description': 'Subdomain enumeration tool using multiple sources'
                },
                'knock': {
                    'repo': 'https://github.com/guelfoweb/knock.git',
                    'path': self.tools_dir / 'knock',
                    'requirements': 'requirements.txt',
                    'main_script': 'knockpy.py',
                    'description': 'Subdomain enumeration tool with multiple sources'
                },
                'massdns': {
                    'repo': 'https://github.com/blechschmidt/massdns.git',
                    'path': self.tools_dir / 'massdns',
                    'requirements': None,
                    'main_script': 'bin/massdns',
                    'description': 'High-performance DNS stub resolver'
                },
                'asnlookup': {
                    'repo': 'https://github.com/yassineaboukir/asnlookup.git',
                    'path': self.tools_dir / 'asnlookup',
                    'requirements': 'requirements.txt',
                    'main_script': 'asnlookup.py',
                    'description': 'ASN lookup tool for finding IP ranges'
                },
                'bbot': {
                    'repo': 'https://github.com/blacklanternsecurity/bbot.git',
                    'path': self.tools_dir / 'bbot',
                    'requirements': 'requirements.txt',
                    'main_script': 'bbot',
                    'description': 'Recursive internet scanner with advanced OSINT capabilities'
                }
            },
            
            # Web Scanning Tools
            'web_scan': {
                'dirsearch': {
                    'repo': 'https://github.com/maurosoria/dirsearch.git',
                    'path': self.tools_dir / 'dirsearch',
                    'requirements': 'requirements.txt',
                    'main_script': 'dirsearch.py',
                    'description': 'Fast web path scanner with multiple wordlists'
                },
                'katana': {
                    'repo': 'https://github.com/projectdiscovery/katana.git',
                    'path': self.tools_dir / 'katana',
                    'requirements': None,
                    'main_script': 'katana',
                    'description': 'Next-generation crawling and spidering framework'
                }
            },
            
            # Vulnerability Scanning Tools
            'vuln_scan': {
                'sqlmap': {
                    'repo': 'https://github.com/sqlmapproject/sqlmap.git',
                    'path': self.tools_dir / 'sqlmap-dev',
                    'requirements': None,
                    'main_script': 'sqlmap.py',
                    'description': 'Advanced SQL injection testing tool'
                },
                'xsscrapy': {
                    'repo': 'https://github.com/DanMcInerney/xsscrapy.git',
                    'path': self.tools_dir / 'xsscrapy',
                    'requirements': 'requirements.txt',
                    'main_script': 'xsscrapy.py',
                    'description': 'Fast, thorough XSS/SQLi spider with comprehensive testing'
                }
            },
            
            # Wordlists and Resources
            'resources': {
                'seclists': {
                    'repo': 'https://github.com/danielmiessler/SecLists.git',
                    'path': self.tools_dir / 'SecLists',
                    'requirements': None,
                    'main_script': None,
                    'description': 'Collection of multiple types of lists for security testing'
                }
            }
        }
        
        # Go tools categorized by their primary focus
        self.go_tools = {
            'recon': {
                'httprobe': {
                    'package': 'github.com/tomnomnom/httprobe',
                    'description': 'HTTP probe tool for finding live hosts'
                },
                'waybackurls': {
                    'package': 'github.com/tomnomnom/waybackurls',
                    'description': 'Wayback machine URL finder'
                },
                'aquatone': {
                    'package': 'github.com/michenriksen/aquatone',
                    'description': 'Visual recon tool for web applications'
                }
            }
        }

    def install_system_dependencies(self) -> bool:
        """Install system dependencies"""
        try:
            if sys.platform == 'linux':
                subprocess.run(['sudo', 'apt-get', 'update'], check=True)
                subprocess.run(['sudo', 'apt-get', 'install', '-y',
                              'python3-pip', 'python3-dev', 'git', 'wget', 'curl',
                              'nmap', 'chromium-browser'], check=True)
            elif sys.platform == 'darwin':
                subprocess.run(['brew', 'update'], check=True)
                subprocess.run(['brew', 'install', 'python3', 'git', 'wget', 'curl',
                              'nmap', 'chromium'], check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"[-] Error installing system dependencies: {str(e)}")
            return False

    def install_python_tool(self, tool_name: str) -> bool:
        """Install a Python tool"""
        if tool_name not in self.tools:
            print(f"[-] Unknown tool: {tool_name}")
            return False

        tool = self.tools[tool_name]
        try:
            # Clone repository
            if not tool['path'].exists():
                print(f"[+] Installing {tool_name}...")
                subprocess.run(['git', 'clone', tool['repo'], str(tool['path'])], check=True)
            
            # Install requirements if any
            if tool['requirements']:
                req_file = tool['path'] / tool['requirements']
                if req_file.exists():
                    subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', str(req_file)], check=True)
            
            # Special handling for massdns
            if tool_name == 'massdns':
                subprocess.run(['make'], cwd=tool['path'], check=True)
            
            # Special handling for seclists
            if tool_name == 'seclists':
                dns_file = tool['path'] / 'Discovery' / 'DNS' / 'dns-Jhaddix.txt'
                if dns_file.exists():
                    with open(dns_file, 'r') as f:
                        lines = f.readlines()
                    with open(dns_file, 'w') as f:
                        f.writelines(lines[:-14])
            
            return True
        except subprocess.CalledProcessError as e:
            print(f"[-] Error installing {tool_name}: {str(e)}")
            return False

    def install_go_tool(self, tool_name: str) -> bool:
        """Install a Go tool"""
        if tool_name not in self.go_tools:
            print(f"[-] Unknown Go tool: {tool_name}")
            return False

        try:
            print(f"[+] Installing {tool_name}...")
            subprocess.run(['go', 'get', '-u', self.go_tools[tool_name]['package']], check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"[-] Error installing {tool_name}: {str(e)}")
            return False

    def install_all(self) -> bool:
        """Install all tools"""
        # Install system dependencies
        if not self.install_system_dependencies():
            return False

        # Install Python tools
        for category, tools in self.tools.items():
            for tool_name in tools:
                if not self.install_python_tool(tool_name):
                    return False

        # Install Go tools
        for category, tools in self.go_tools.items():
            for tool_name in tools:
                if not self.install_go_tool(tool_name):
                    return False

        print("[+] All tools have been installed successfully!")
        return True

    def get_tool_path(self, tool_name: str) -> Optional[Path]:
        """Get the path to a tool's main script"""
        if tool_name in self.tools:
            tool = self.tools[tool_name]
            if tool['main_script']:
                return tool['path'] / tool['main_script']
        return None

    def run_tool(self, tool_name: str, args: List[str]) -> Optional[str]:
        """Run a tool with the given arguments"""
        if tool_name in self.tools:
            tool_path = self.get_tool_path(tool_name)
            if tool_path and tool_path.exists():
                try:
                    result = subprocess.run([sys.executable, str(tool_path)] + args,
                                         capture_output=True, text=True, check=True)
                    return result.stdout
                except subprocess.CalledProcessError as e:
                    print(f"[-] Error running {tool_name}: {str(e)}")
                    return None
        elif tool_name in self.go_tools:
            try:
                result = subprocess.run([tool_name] + args,
                                     capture_output=True, text=True, check=True)
                return result.stdout
            except subprocess.CalledProcessError as e:
                print(f"[-] Error running {tool_name}: {str(e)}")
                return None
        return None

    def get_tools_by_category(self, category: str) -> Dict[str, Dict]:
        """Get all tools in a specific category"""
        if category in self.tools:
            return self.tools[category]
        elif category in self.go_tools:
            return self.go_tools[category]
        return {}

    def list_tools_by_category(self) -> Dict[str, Dict[str, str]]:
        """List all tools organized by category"""
        categories = {}
        
        # Python tools
        for category, tools in self.tools.items():
            categories[category] = {
                name: tool['description']
                for name, tool in tools.items()
            }
        
        # Go tools
        for category, tools in self.go_tools.items():
            if category not in categories:
                categories[category] = {}
            for name, tool in tools.items():
                categories[category][name] = tool['description']
        
        return categories

    def install_category(self, category: str) -> bool:
        """Install all tools in a specific category"""
        success = True
        
        # Install Python tools in category
        if category in self.tools:
            for tool_name in self.tools[category]:
                if not self.install_python_tool(tool_name):
                    success = False
        
        # Install Go tools in category
        if category in self.go_tools:
            for tool_name in self.go_tools[category]:
                if not self.install_go_tool(tool_name):
                    success = False
        
        return success

    def run_category_scan(self, category: str, target: str, args: List[str] = None) -> Dict[str, Any]:
        """Run all tools in a specific category against a target"""
        results = {}
        
        # Run Python tools in category
        if category in self.tools:
            for tool_name in self.tools[category]:
                tool_args = [target] + (args or [])
                result = self.run_tool(tool_name, tool_args)
                if result:
                    results[tool_name] = result
        
        # Run Go tools in category
        if category in self.go_tools:
            for tool_name in self.go_tools[category]:
                tool_args = [target] + (args or [])
                result = self.run_tool(tool_name, tool_args)
                if result:
                    results[tool_name] = result
        
        return results

def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Bug Bounty Tools Manager')
    parser.add_argument('--install', action='store_true', help='Install all tools')
    parser.add_argument('--install-category', help='Install tools in a specific category')
    parser.add_argument('--list', action='store_true', help='List all available tools')
    parser.add_argument('--list-categories', action='store_true', help='List tools by category')
    parser.add_argument('--category', help='Run all tools in a specific category')
    parser.add_argument('--tool', help='Run a specific tool')
    parser.add_argument('--args', nargs='*', help='Arguments for the tool')
    parser.add_argument('--target', help='Target to scan')
    
    args = parser.parse_args()
    
    manager = ToolsManager()
    
    if args.install:
        manager.install_all()
    elif args.install_category:
        manager.install_category(args.install_category)
    elif args.list:
        tools = manager.list_tools()
        print("\nAvailable Tools:")
        for name, desc in tools.items():
            print(f"\n{name}:")
            print(f"  {desc}")
    elif args.list_categories:
        categories = manager.list_tools_by_category()
        print("\nTools by Category:")
        for category, tools in categories.items():
            print(f"\n{category.upper()}:")
            for name, desc in tools.items():
                print(f"  {name}: {desc}")
    elif args.category and args.target:
        results = manager.run_category_scan(args.category, args.target, args.args)
        print(f"\nResults from {args.category} scan:")
        for tool, result in results.items():
            print(f"\n{tool}:")
            print(result)
    elif args.tool:
        if args.args:
            result = manager.run_tool(args.tool, args.args)
            if result:
                print(result)
        else:
            print(f"[-] Please provide arguments for {args.tool}")
    else:
        parser.print_help()

if __name__ == '__main__':
    main() 