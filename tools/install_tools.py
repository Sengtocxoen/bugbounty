#!/usr/bin/env python3

import os
import sys
import subprocess
from pathlib import Path

class ToolInstaller:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.tools_dir = self.base_dir / 'tools'
        self.tools_dir.mkdir(exist_ok=True)
        
        # Tool configurations
        self.tools = {
            'XSStrike': {
                'repo': 'https://github.com/s0md3v/XSStrike',
                'install_cmd': 'pip install -r requirements.txt'
            },
            'Arjun': {
                'repo': 'https://github.com/s0md3v/Arjun',
                'install_cmd': 'pipx install arjun'
            },
            'ParamSpider': {
                'repo': 'https://github.com/devanshbatham/paramspider',
                'install_cmd': 'cd paramspider && pip install .'
            },
            'Waybackurls': {
                'install_cmd': 'go install github.com/tomnomnom/waybackurls@latest'
            },
            'Gospider': {
                'install_cmd': 'go install github.com/jaeles-project/gospider@latest'
            }
        }

    def install_tool(self, tool_name):
        """Install a specific tool"""
        if tool_name not in self.tools:
            print(f"[-] Unknown tool: {tool_name}")
            return False

        print(f"[+] Installing {tool_name}...")
        tool_config = self.tools[tool_name]

        try:
            # For tools that need to be cloned from git
            if 'repo' in tool_config:
                tool_dir = self.tools_dir / tool_name
                if not tool_dir.exists():
                    subprocess.run(['git', 'clone', tool_config['repo'], str(tool_dir)], check=True)
                
                # Run installation command in the tool's directory
                if 'install_cmd' in tool_config:
                    subprocess.run(tool_config['install_cmd'], shell=True, cwd=str(tool_dir), check=True)
            
            # For tools that can be installed directly
            elif 'install_cmd' in tool_config:
                subprocess.run(tool_config['install_cmd'], shell=True, check=True)

            print(f"[+] Successfully installed {tool_name}")
            return True

        except Exception as e:
            print(f"[-] Error installing {tool_name}: {str(e)}")
            return False

    def install_all_tools(self):
        """Install all tools"""
        print("[+] Installing all tools...")
        for tool_name in self.tools:
            self.install_tool(tool_name)

def main():
    installer = ToolInstaller()
    
    if len(sys.argv) > 1:
        # Install specific tool
        tool_name = sys.argv[1]
        installer.install_tool(tool_name)
    else:
        # Install all tools
        installer.install_all_tools()

if __name__ == "__main__":
    main() 