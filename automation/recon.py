#!/usr/bin/env python3

import subprocess
import sys
import os
import json
from datetime import datetime

class ReconAutomation:
    def __init__(self, target):
        self.target = target
        self.results_dir = f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.results_dir, exist_ok=True)

    def run_subfinder(self):
        """Run subfinder to discover subdomains"""
        print(f"[+] Running subfinder on {self.target}")
        output_file = os.path.join(self.results_dir, "subdomains.txt")
        subprocess.run(["subfinder", "-d", self.target, "-o", output_file])
        return output_file

    def run_nuclei(self):
        """Run nuclei for vulnerability scanning"""
        print("[+] Running nuclei scan")
        output_file = os.path.join(self.results_dir, "nuclei_results.json")
        subprocess.run(["nuclei", "-u", self.target, "-o", output_file, "-json"])
        return output_file

    def run_httpx(self, subdomains_file):
        """Run httpx to check for live hosts"""
        print("[+] Running httpx to check live hosts")
        output_file = os.path.join(self.results_dir, "live_hosts.txt")
        subprocess.run(["httpx", "-l", subdomains_file, "-o", output_file])
        return output_file

    def generate_report(self):
        """Generate a summary report"""
        report = {
            "target": self.target,
            "scan_time": datetime.now().isoformat(),
            "results_directory": self.results_dir,
            "tools_run": ["subfinder", "nuclei", "httpx"]
        }
        
        report_file = os.path.join(self.results_dir, "report.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=4)
        
        return report_file

def main():
    if len(sys.argv) != 2:
        print("Usage: python recon.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    recon = ReconAutomation(target)
    
    # Run reconnaissance tools
    subdomains_file = recon.run_subfinder()
    live_hosts_file = recon.run_httpx(subdomains_file)
    nuclei_results = recon.run_nuclei()
    
    # Generate report
    report_file = recon.generate_report()
    print(f"\n[+] Reconnaissance completed. Results saved in {recon.results_dir}")
    print(f"[+] Report generated: {report_file}")

if __name__ == "__main__":
    main() 