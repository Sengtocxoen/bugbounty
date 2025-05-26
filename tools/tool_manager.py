#!/usr/bin/env python3

import os
import sys
import json
import subprocess
from pathlib import Path

class ToolManager:
    def __init__(self):
        self.tools_dir = Path(__file__).parent
        self.tools_config = self.tools_dir / 'tools_config.json'
        self.tools = self._load_tools_config()

    def _load_tools_config(self):
        """Load tools configuration"""
        if self.tools_config.exists():
            with open(self.tools_config, 'r') as f:
                return json.load(f)
        return {}

    def _save_tools_config(self):
        """Save tools configuration"""
        with open(self.tools_config, 'w') as f:
            json.dump(self.tools, f, indent=4)

    def install_tool(self, tool_name, repo_url, install_cmd=None):
        """Install a tool from its repository"""
        tool_dir = self.tools_dir / tool_name
        
        if tool_dir.exists():
            print(f"[!] Tool {tool_name} already exists in {tool_dir}")
            return False

        print(f"[+] Installing {tool_name}...")
        try:
            # Clone the repository
            subprocess.run(['git', 'clone', repo_url, str(tool_dir)], check=True)
            
            # Run installation command if provided
            if install_cmd:
                subprocess.run(install_cmd, cwd=tool_dir, shell=True, check=True)
            
            # Add tool to configuration
            self.tools[tool_name] = {
                'path': str(tool_dir),
                'repo': repo_url,
                'installed': True
            }
            self._save_tools_config()
            
            print(f"[+] Successfully installed {tool_name}")
            return True
            
        except Exception as e:
            print(f"[-] Error installing {tool_name}: {str(e)}")
            if tool_dir.exists():
                subprocess.run(['rm', '-rf', str(tool_dir)])
            return False

    def uninstall_tool(self, tool_name):
        """Uninstall a tool"""
        if tool_name not in self.tools:
            print(f"[!] Tool {tool_name} not found")
            return False

        tool_dir = Path(self.tools[tool_name]['path'])
        if tool_dir.exists():
            try:
                subprocess.run(['rm', '-rf', str(tool_dir)], check=True)
                del self.tools[tool_name]
                self._save_tools_config()
                print(f"[+] Successfully uninstalled {tool_name}")
                return True
            except Exception as e:
                print(f"[-] Error uninstalling {tool_name}: {str(e)}")
                return False
        return False

    def update_tool(self, tool_name):
        """Update a tool to its latest version"""
        if tool_name not in self.tools:
            print(f"[!] Tool {tool_name} not found")
            return False

        tool_dir = Path(self.tools[tool_name]['path'])
        if tool_dir.exists():
            try:
                subprocess.run(['git', 'pull'], cwd=tool_dir, check=True)
                print(f"[+] Successfully updated {tool_name}")
                return True
            except Exception as e:
                print(f"[-] Error updating {tool_name}: {str(e)}")
                return False
        return False

    def list_tools(self):
        """List all installed tools"""
        if not self.tools:
            print("[!] No tools installed")
            return

        print("\n=== Installed Tools ===")
        for tool_name, tool_info in self.tools.items():
            status = "✓" if tool_info['installed'] else "✗"
            print(f"{status} {tool_name}")
            print(f"    Path: {tool_info['path']}")
            print(f"    Repo: {tool_info['repo']}\n")

    def get_tool_path(self, tool_name):
        """Get the installation path of a tool"""
        if tool_name in self.tools and self.tools[tool_name]['installed']:
            return self.tools[tool_name]['path']
        return None

def main():
    manager = ToolManager()
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  install <tool_name> <repo_url> [install_cmd]")
        print("  uninstall <tool_name>")
        print("  update <tool_name>")
        print("  list")
        sys.exit(1)

    command = sys.argv[1]
    
    if command == "install" and len(sys.argv) >= 4:
        tool_name = sys.argv[2]
        repo_url = sys.argv[3]
        install_cmd = sys.argv[4] if len(sys.argv) > 4 else None
        manager.install_tool(tool_name, repo_url, install_cmd)
    
    elif command == "uninstall" and len(sys.argv) >= 3:
        tool_name = sys.argv[2]
        manager.uninstall_tool(tool_name)
    
    elif command == "update" and len(sys.argv) >= 3:
        tool_name = sys.argv[2]
        manager.update_tool(tool_name)
    
    elif command == "list":
        manager.list_tools()
    
    else:
        print("Invalid command or arguments")
        sys.exit(1)

if __name__ == "__main__":
    main() 