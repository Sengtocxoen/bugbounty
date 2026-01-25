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
                    'install_cmd': 'pip install -r requirements.txt',
                    'main_script': 'sublist3r.py',
                    'description': 'Subdomain enumeration tool using multiple sources'
                },
                'knock': {
                    'repo': 'https://github.com/guelfoweb/knock.git',
                    'path': self.tools_dir / 'knock',
                    'requirements': 'requirements.txt',
                    'install_cmd': 'pip install .',
                    'main_script': 'knockpy.py',
                    'description': 'Subdomain enumeration tool with multiple sources'
                },
                'asnlookup': {
                    'repo': 'https://github.com/yassineaboukir/asnlookup.git',
                    'path': self.tools_dir / 'asnlookup',
                    'requirements': 'requirements.txt',
                    'install_cmd': 'pip install -r requirements.txt',
                    'main_script': 'asnlookup.py',
                    'description': 'ASN lookup tool for finding IP ranges'
                },
                'bbot': {
                    'repo': 'https://github.com/blacklanternsecurity/bbot.git',
                    'path': self.tools_dir / 'bbot',
                    'requirements': 'requirements.txt',
                    'install_cmd': 'pipx install bbot',
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
                    'install_cmd': 'pip install -r requirements.txt',
                    'main_script': 'dirsearch.py',
                    'description': 'Fast web path scanner with multiple wordlists'
                },
                'katana': {
                    'repo': 'https://github.com/projectdiscovery/katana.git',
                    'path': self.tools_dir / 'katana',
                    'requirements': None,
                    'install_cmd': 'go install github.com/projectdiscovery/katana/cmd/katana@latest',
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
                    'install_cmd': None,
                    'main_script': 'sqlmap.py',
                    'description': 'Advanced SQL injection testing tool'
                },
                'xsscrapy': {
                    'repo': 'https://github.com/DanMcInerney/xsscrapy.git',
                    'path': self.tools_dir / 'xsscrapy',
                    'requirements': 'requirements.txt',
                    'install_cmd': 'pip install -r requirements.txt',
                    'main_script': 'xsscrapy.py',
                    'description': 'Fast, thorough XSS/SQLi spider with comprehensive testing'
                }
            }
        }
        
        # Go tools categorized by their primary focus
        self.go_tools = {
            'recon': {
                'httprobe': {
                    'package': 'github.com/tomnomnom/httprobe',
                    'install_cmd': 'go install github.com/tomnomnom/httprobe@latest',
                    'description': 'HTTP probe tool for finding live hosts'
                },
                'waybackurls': {
                    'package': 'github.com/tomnomnom/waybackurls',
                    'install_cmd': 'go install github.com/tomnomnom/waybackurls@latest',
                    'description': 'Wayback machine URL finder'
                }
            }
        }

    def install_system_dependencies(self):
        """Install system dependencies"""
        print("[+] Installing system dependencies...")
        
        # Define dependencies based on OS
        if os.path.exists('/etc/debian_version'):  # Debian/Ubuntu/Kali
            dependencies = [
                'python3-pip',
                'python3-dev',
                'git',
                'wget',
                'curl',
                'nmap',
                'chromium'
            ]
            try:
                # Update package list first
                subprocess.run(['sudo', 'apt', 'update'], check=True)
                # Install dependencies
                subprocess.run(['sudo', 'apt', 'install', '-y'] + dependencies, check=True)
                return True
            except subprocess.CalledProcessError as e:
                print(f"[-] Error installing system dependencies: {str(e)}")
                return False
        else:
            print("[-] Unsupported operating system")
            return False

    def install_python_tool(self, tool_name: str, tool_info: dict) -> bool:
        """Install a Python tool"""
        try:
            print(f"[+] Installing {tool_name}...")
            
            # Clone repository if it doesn't exist
            if not tool_info['path'].exists():
                subprocess.run(['git', 'clone', tool_info['repo'], str(tool_info['path'])], check=True)
            
            # Change to tool directory
            os.chdir(tool_info['path'])
            
            # Install using the specified command
            if tool_info['install_cmd']:
                # Split command to check if sudo is needed
                cmd_parts = tool_info['install_cmd'].split()
                if cmd_parts[0] == 'sudo':
                    # Remove sudo from command parts
                    cmd_parts = cmd_parts[1:]
                    # Run with sudo
                    subprocess.run(['sudo'] + cmd_parts, check=True)
                else:
                    # Run without sudo
                    subprocess.run(cmd_parts, check=True)
            
            print(f"[+] {tool_name} installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[-] Error installing {tool_name}: {str(e)}")
            return False
        finally:
            # Return to original directory
            os.chdir(self.tools_dir)

    def install_go_tool(self, tool_name: str, tool_info: dict) -> bool:
        """Install a Go tool"""
        try:
            print(f"[+] Installing {tool_name}...")
            
            # Use the specified install command
            if tool_info['install_cmd']:
                # Handle environment variables
                if 'CGO_ENABLED=1' in tool_info['install_cmd']:
                    # Split the command and set environment variable
                    cmd_parts = tool_info['install_cmd'].split()
                    env = os.environ.copy()
                    env['CGO_ENABLED'] = '1'
                    # Remove the environment variable from command
                    cmd = [part for part in cmd_parts if part != 'CGO_ENABLED=1']
                    subprocess.run(cmd, env=env, check=True)
                else:
                    subprocess.run(tool_info['install_cmd'].split(), check=True)
            else:
                # Fallback to default go install
                subprocess.run(['go', 'install', tool_info['package'] + '@latest'], check=True)
            
            print(f"[+] {tool_name} installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[-] Error installing {tool_name}: {str(e)}")
            return False

    def install(self):
        """Install all tools"""
        print("[+] Installing tools...")
        
        # Create tools directory if it doesn't exist
        os.makedirs(self.tools_dir, exist_ok=True)
        
        # Install system dependencies
        if not self.install_system_dependencies():
            print("[-] Failed to install system dependencies")
            return False
        
        # Install Python tools
        for category, tools in self.tools.items():
            for tool_name, tool_info in tools.items():
                self.install_python_tool(tool_name, tool_info)
        
        # Install Go tools
        for category, tools in self.go_tools.items():
            for tool_name, tool_info in tools.items():
                self.install_go_tool(tool_name, tool_info)
        
        print("[+] Tool installation completed")
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
                if not self.install_python_tool(tool_name, self.tools[category][tool_name]):
                    success = False
        
        # Install Go tools in category
        if category in self.go_tools:
            for tool_name in self.go_tools[category]:
                if not self.install_go_tool(tool_name, self.go_tools[category][tool_name]):
                    success = False
        
        return success

    def run_category_scan(self, category: str, target: str, args: List[str] = None) -> Dict[str, any]:
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
        print("[*] Note: Some commands may require sudo privileges. You will be prompted when needed.")
        manager.install()
    elif args.install_category:
        print("[*] Note: Some commands may require sudo privileges. You will be prompted when needed.")
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