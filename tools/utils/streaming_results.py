#!/usr/bin/env python3
"""
Streaming Results Writer
Write results to files in real-time as they're discovered, not waiting for all scans to complete
"""

import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from threading import Lock
from dataclasses import dataclass, asdict
import csv


@dataclass
class Finding:
    """Individual vulnerability finding"""
    timestamp: str
    target: str
    subdomain: Optional[str]
    url: str
    vulnerability_type: str
    severity: str
    tool: str
    evidence: str
    status: str = 'new'  # new, verified, skipped_deep_scan
    
    
class StreamingResultsWriter:
    """
    Write results progressively to files as they're found
    
    Features:
    - Write immediately, don't wait for all scans
    - Separate files per target
    - JSON and CSV formats
    - Thread-safe writing
    - Progress tracking
    """
    
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Thread locks for safe concurrent writing
        self.locks = {}
        self.main_lock = Lock()
        
        # Track progress per target
        self.target_progress = {}
        
        # Keep file handles open for streaming
        self.file_handles = {}
        
        # Initialize summary file
        self.summary_file = self.output_dir / 'scan_summary.json'
        self.init_summary()
        
    def init_summary(self):
        """Initialize summary file"""
        summary = {
            'scan_started': datetime.now().isoformat(),
            'targets': {},
            'total_findings': 0,
            'by_severity': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        with open(self.summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
            
    def get_target_lock(self, target: str) -> Lock:
        """Get or create lock for target"""
        with self.main_lock:
            if target not in self.locks:
                self.locks[target] = Lock()
            return self.locks[target]
            
    def write_finding(self, finding: Finding):
        """
        Write finding immediately to target-specific file
        
        This is called AS SOON AS a finding is discovered, not waiting for scan completion
        """
        target = finding.target
        lock = self.get_target_lock(target)
        
        with lock:
            # Create target directory
            target_dir = self.output_dir / self._sanitize_filename(target)
            target_dir.mkdir(parents=True, exist_ok=True)
            
            # Write to JSON file (append mode)
            json_file = target_dir / 'findings.jsonl'  # JSON Lines format
            with open(json_file, 'a') as f:
                f.write(json.dumps(asdict(finding)) + '\n')
                f.flush()  # Force write to disk immediately
                
            # Write to CSV file
            csv_file = target_dir / 'findings.csv'
            file_exists = csv_file.exists()
            with open(csv_file, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=asdict(finding).keys())
                if not file_exists:
                    writer.writeheader()
                writer.writerow(asdict(finding))
                f.flush()
                
            # Update summary
            self.update_summary(finding)
            
            # Print to console for real-time feedback
            self.print_finding(finding)
            
    def write_subdomain(self, target: str, subdomain: str, is_alive: bool, 
                       http_status: Optional[int] = None, was_skipped: bool = False):
        """Write subdomain discovery result immediately"""
        lock = self.get_target_lock(target)
        
        with lock:
            target_dir = self.output_dir / self._sanitize_filename(target)
            target_dir.mkdir(parents=True, exist_ok=True)
            
            # Write to subdomains file
            subdomains_file = target_dir / 'subdomains.txt'
            with open(subdomains_file, 'a') as f:
                status = "ALIVE" if is_alive else "DEAD"
                skip_marker = " [SKIPPED_DEEP]" if was_skipped else ""
                line = f"{subdomain} | {status}"
                if http_status:
                    line += f" | HTTP {http_status}"
                line += skip_marker + "\n"
                f.write(line)
                f.flush()
                
            # Also write to JSON for machine parsing
            subdomains_json = target_dir / 'subdomains.jsonl'
            with open(subdomains_json, 'a') as f:
                data = {
                    'timestamp': datetime.now().isoformat(),
                    'subdomain': subdomain,
                    'is_alive': is_alive,
                    'http_status': http_status,
                    'was_skipped_deep_scan': was_skipped
                }
                f.write(json.dumps(data) + '\n')
                f.flush()
                
    def write_endpoint(self, target: str, endpoint: str, method: str = 'GET',
                      status_code: Optional[int] = None, was_skipped: bool = False):
        """Write discovered endpoint immediately"""
        lock = self.get_target_lock(target)
        
        with lock:
            target_dir = self.output_dir / self._sanitize_filename(target)
            target_dir.mkdir(parents=True, exist_ok=True)
            
            endpoints_file = target_dir / 'endpoints.txt'
            skip_marker = " [SKIPPED_DEEP]" if was_skipped else ""
            with open(endpoints_file, 'a') as f:
                line = f"{method} {endpoint}"
                if status_code:
                    line += f" | HTTP {status_code}"
                line += skip_marker + "\n"
                f.write(line)
                f.flush()
                
    def update_progress(self, target: str, phase: str, completed: int, total: int):
        """
        Update progress for a target
        
        This allows you to see: "Target example.com: 50/1000 subdomains scanned"
        """
        lock = self.get_target_lock(target)
        
        with lock:
            if target not in self.target_progress:
                self.target_progress[target] = {}
                
            self.target_progress[target][phase] = {
                'completed': completed,
                'total': total,
                'percentage': (completed / total * 100) if total > 0 else 0,
                'last_update': datetime.now().isoformat()
            }
            
            # Write progress file
            target_dir = self.output_dir / self._sanitize_filename(target)
            target_dir.mkdir(parents=True, exist_ok=True)
            
            progress_file = target_dir / 'progress.json'
            with open(progress_file, 'w') as f:
                json.dump(self.target_progress[target], f, indent=2)
                f.flush()
                
            # Print progress
            self.print_progress(target, phase, completed, total)
            
    def update_summary(self, finding: Finding):
        """Update overall summary statistics"""
        with self.main_lock:
            try:
                with open(self.summary_file, 'r') as f:
                    summary = json.load(f)
            except:
                self.init_summary()
                with open(self.summary_file, 'r') as f:
                    summary = json.load(f)
                    
            # Update counts
            summary['total_findings'] += 1
            
            severity = finding.severity.lower()
            if severity in summary['by_severity']:
                summary['by_severity'][severity] += 1
                
            # Update target stats
            target = finding.target
            if target not in summary['targets']:
                summary['targets'][target] = {
                    'findings': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0,
                    'last_finding': None
                }
                
            summary['targets'][target]['findings'] += 1
            if severity in summary['targets'][target]:
                summary['targets'][target][severity] += 1
            summary['targets'][target]['last_finding'] = finding.timestamp
            
            summary['last_updated'] = datetime.now().isoformat()
            
            # Write updated summary
            with open(self.summary_file, 'w') as f:
                json.dump(summary, f, indent=2)
                f.flush()
                
    def write_skipped_endpoints(self, target: str, skipped: Dict[str, str]):
        """
        Write list of endpoints that were skipped for deep scanning
        
        These can be reviewed/scanned later if needed
        """
        lock = self.get_target_lock(target)
        
        with lock:
            target_dir = self.output_dir / self._sanitize_filename(target)
            target_dir.mkdir(parents=True, exist_ok=True)
            
            skipped_file = target_dir / 'skipped_deep_scan.json'
            with open(skipped_file, 'w') as f:
                data = {
                    'timestamp': datetime.now().isoformat(),
                    'total_skipped': len(skipped),
                    'endpoints': skipped
                }
                json.dump(data, f, indent=2)
                f.flush()
                
            # Also create a simple text file
            skipped_txt = target_dir / 'skipped_deep_scan.txt'
            with open(skipped_txt, 'w') as f:
                f.write(f"# Endpoints skipped for deep scanning\n")
                f.write(f"# Total: {len(skipped)}\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
                
                for endpoint, reason in skipped.items():
                    f.write(f"{endpoint}\n  Reason: {reason}\n\n")
                    
    def print_finding(self, finding: Finding):
        """Print finding to console with color"""
        severity_colors = {
            'critical': '\033[91m',  # Red
            'high': '\033[93m',      # Yellow
            'medium': '\033[94m',    # Blue
            'low': '\033[92m',       # Green
            'info': '\033[90m'       # Gray
        }
        reset = '\033[0m'
        
        color = severity_colors.get(finding.severity.lower(), '')
        status_marker = "⚠️ " if finding.status == 'skipped_deep_scan' else "✓ "
        
        print(f"{color}[{finding.severity.upper()}]{reset} {status_marker}{finding.target}")
        print(f"  └─ {finding.vulnerability_type}")
        print(f"     URL: {finding.url}")
        if finding.status == 'skipped_deep_scan':
            print(f"     Note: Marked for later deep scan")
        print()
        
    def print_progress(self, target: str, phase: str, completed: int, total: int):
        """Print progress to console"""
        percentage = (completed / total * 100) if total > 0 else 0
        bar_length = 40
        filled = int(bar_length * completed / total) if total > 0 else 0
        bar = '█' * filled + '░' * (bar_length - filled)
        
        print(f"\r[{target}] {phase}: [{bar}] {completed}/{total} ({percentage:.1f}%)", end='', flush=True)
        
        if completed >= total:
            print()  # New line when complete
            
    def get_live_summary(self) -> Dict:
        """Get current summary (read from file)"""
        try:
            with open(self.summary_file, 'r') as f:
                return json.load(f)
        except:
            return {}
            
    def _sanitize_filename(self, name: str) -> str:
        """Sanitize filename"""
        return name.replace('/', '_').replace(':', '_').replace('.', '_')
        
    def finalize_target(self, target: str):
        """Mark target as complete and generate final report"""
        lock = self.get_target_lock(target)
        
        with lock:
            target_dir = self.output_dir / self._sanitize_filename(target)
            
            # Create completion marker
            complete_file = target_dir / 'SCAN_COMPLETE.txt'
            with open(complete_file, 'w') as f:
                f.write(f"Scan completed: {datetime.now().isoformat()}\n")
                
            print(f"\n✅ Completed scan for {target}")
            print(f"   Results: {target_dir}")
            

class RealTimeMonitor:
    """
    Monitor for live viewing of scan progress
    
    Usage:
        monitor = RealTimeMonitor(output_dir)
        monitor.watch()  # Continuously display current progress
    """
    
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.summary_file = self.output_dir / 'scan_summary.json'
        
    def watch(self, interval: int = 2):
        """Watch and display progress in real-time"""
        import os
        
        try:
            while True:
                # Clear screen
                os.system('clear' if os.name == 'posix' else 'cls')
                
                # Display summary
                self.display_summary()
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\nMonitoring stopped.")
            
    def display_summary(self):
        """Display current summary"""
        try:
            with open(self.summary_file, 'r') as f:
                summary = json.load(f)
        except:
            print("No data available yet...")
            return
            
        print("=" * 60)
        print("BUG BOUNTY SCAN - LIVE RESULTS")
        print("=" * 60)
        print(f"\nStarted: {summary.get('scan_started', 'Unknown')}")
        print(f"Last Update: {summary.get('last_updated', 'Unknown')}")
        
        print(f"\n📊 OVERALL STATISTICS")
        print(f"   Total Findings: {summary.get('total_findings', 0)}")
        
        by_severity = summary.get('by_severity', {})
        print(f"\n   By Severity:")
        print(f"      🔴 Critical: {by_severity.get('critical', 0)}")
        print(f"      🟠 High:     {by_severity.get('high', 0)}")
        print(f"      🟡 Medium:   {by_severity.get('medium', 0)}")
        print(f"      🟢 Low:      {by_severity.get('low', 0)}")
        print(f"      ℹ️  Info:     {by_severity.get('info', 0)}")
        
        # Target-specific stats
        targets = summary.get('targets', {})
        if targets:
            print(f"\n🎯 PER-TARGET RESULTS")
            for target, stats in targets.items():
                print(f"\n   {target}")
                print(f"      Findings: {stats.get('findings', 0)}")
                print(f"      Critical: {stats.get('critical', 0)} | High: {stats.get('high', 0)} | Medium: {stats.get('medium', 0)}")
                
                # Check for progress file
                target_dir = self.output_dir / target.replace('/', '_').replace(':', '_').replace('.', '_')
                progress_file = target_dir / 'progress.json'
                if progress_file.exists():
                    with open(progress_file, 'r') as f:
                        progress = json.load(f)
                        for phase, data in progress.items():
                            print(f"      {phase}: {data['completed']}/{data['total']} ({data['percentage']:.1f}%)")
                            
        print("\n" + "=" * 60)


if __name__ == '__main__':
    # Example usage
    writer = StreamingResultsWriter(Path('./results/streaming'))
    
    # Simulate finding results in real-time
    finding1 = Finding(
        timestamp=datetime.now().isoformat(),
        target='example.com',
        subdomain='admin.example.com',
        url='https://admin.example.com/login',
        vulnerability_type='XSS',
        severity='high',
        tool='dalfox',
        evidence='Reflected XSS in search parameter'
    )
    
    # Write immediately - don't wait!
    writer.write_finding(finding1)
    
    # Update progress
    writer.update_progress('example.com', 'subdomain_scan', 50, 1000)
    
    print("\nResults written to:", writer.output_dir)
