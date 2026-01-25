#!/usr/bin/env python3
"""
Continuous Bug Bounty Scanner
Runs 24/7 without timeout, intelligently discovering and testing targets
"""

import os
import sys
import time
import json
import logging
import sqlite3
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set
import subprocess
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
import psutil

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from deep_scan import DeepScanner, DeepScanConfig
from web_hacking_2025.scanner import WebHackingScanner
from wiz_recon import WizReconScanner


class FindingsDatabase:
    """SQLite database for tracking findings and preventing duplicates"""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.create_tables()
        
    def create_tables(self):
        """Create database schema"""
        cursor = self.conn.cursor()
        
        # Findings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                vulnerability_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                url TEXT,
                parameter TEXT,
                payload TEXT,
                evidence TEXT,
                tool TEXT,
                hash TEXT UNIQUE NOT NULL,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reported BOOLEAN DEFAULT 0,
                status TEXT DEFAULT 'new',
                notes TEXT
            )
        ''')
        
        # Subdomains table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                is_alive BOOLEAN,
                http_status INTEGER,
                technologies TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(domain, subdomain)
            )
        ''')
        
        # Scan history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                findings_count INTEGER DEFAULT 0,
                status TEXT
            )
        ''')
        
        self.conn.commit()
        
    def add_finding(self, finding: Dict) -> str:
        """Add finding with automatic deduplication"""
        finding_hash = self.hash_finding(finding)
        cursor = self.conn.cursor()
        
        # Check if exists
        cursor.execute('SELECT id FROM findings WHERE hash = ?', (finding_hash,))
        existing = cursor.fetchone()
        
        if existing:
            # Update last_seen
            cursor.execute(
                'UPDATE findings SET last_seen = CURRENT_TIMESTAMP WHERE hash = ?',
                (finding_hash,)
            )
            self.conn.commit()
            return 'duplicate'
        else:
            # Insert new finding
            cursor.execute('''
                INSERT INTO findings (
                    target, vulnerability_type, severity, url, 
                    parameter, payload, evidence, tool, hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                finding.get('target'),
                finding.get('vulnerability_type'),
                finding.get('severity'),
                finding.get('url'),
                finding.get('parameter'),
                finding.get('payload'),
                finding.get('evidence'),
                finding.get('tool'),
                finding_hash
            ))
            self.conn.commit()
            return 'new'
            
    def hash_finding(self, finding: Dict) -> str:
        """Create unique hash for finding"""
        key = f"{finding.get('target')}|{finding.get('vulnerability_type')}|{finding.get('url')}|{finding.get('parameter')}"
        return hashlib.sha256(key.encode()).hexdigest()
        
    def get_new_findings(self, since_hours: int = 24) -> List[Dict]:
        """Get new findings from last N hours"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM findings 
            WHERE first_seen >= datetime('now', ?) 
            AND status = 'new'
            ORDER BY severity DESC, first_seen DESC
        ''', (f'-{since_hours} hours',))
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
        
    def add_subdomain(self, domain: str, subdomain: str, is_alive: bool, 
                     http_status: int = None, technologies: List[str] = None):
        """Track discovered subdomain"""
        cursor = self.conn.cursor()
        tech_str = ','.join(technologies) if technologies else None
        
        cursor.execute('''
            INSERT OR REPLACE INTO subdomains 
            (domain, subdomain, is_alive, http_status, technologies, last_seen)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (domain, subdomain, is_alive, http_status, tech_str))
        self.conn.commit()
        
    def get_previous_subdomains(self, domain: str) -> Set[str]:
        """Get previously discovered subdomains"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT subdomain FROM subdomains WHERE domain = ?', (domain,))
        return {row[0] for row in cursor.fetchall()}


class ResourceManager:
    """Manage system resources to prevent overload"""
    
    def __init__(self, max_cpu: int = 80, max_memory: int = 80):
        self.max_cpu = max_cpu
        self.max_memory = max_memory
        
    def should_throttle(self) -> bool:
        """Check if we should slow down"""
        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory().percent
        
        if cpu > self.max_cpu or memory > self.max_memory:
            logging.warning(f"High resource usage: CPU={cpu}%, Memory={memory}%")
            return True
        return False
        
    def get_optimal_workers(self) -> int:
        """Calculate optimal number of workers"""
        cpu_count = psutil.cpu_count()
        available_memory_gb = psutil.virtual_memory().available / (1024**3)
        
        # Conservative: 1 worker per 2 cores, max based on available memory
        workers = min(
            cpu_count // 2,
            int(available_memory_gb // 1)  # 1 worker per GB
        )
        
        return max(1, min(workers, 10))  # Between 1 and 10 workers


class NotificationSystem:
    """Send alerts for high-priority findings"""
    
    def __init__(self, config: Dict):
        self.slack_webhook = config.get('slack_webhook')
        self.discord_webhook = config.get('discord_webhook')
        self.enabled = self.slack_webhook or self.discord_webhook
        
    def send_alert(self, finding: Dict):
        """Send alert for critical/high severity findings"""
        if not self.enabled:
            return
            
        severity = finding.get('severity', '').lower()
        if severity not in ['critical', 'high']:
            return
            
        message = self.format_message(finding)
        
        if self.slack_webhook:
            self._send_slack(message)
            
        if self.discord_webhook:
            self._send_discord(message)
            
    def format_message(self, finding: Dict) -> str:
        """Format finding as message"""
        emoji = '🔴' if finding['severity'] == 'critical' else '🟠'
        
        return f"""
{emoji} **New {finding['severity'].upper()} Severity Finding**

**Type:** {finding['vulnerability_type']}
**Target:** {finding['target']}
**URL:** {finding.get('url', 'N/A')}
**Parameter:** {finding.get('parameter', 'N/A')}
**Tool:** {finding.get('tool', 'Unknown')}

**Evidence:**
```
{finding.get('evidence', '')[:300]}
```

**Discovered:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
    def _send_slack(self, message: str):
        """Send to Slack"""
        try:
            import requests
            requests.post(self.slack_webhook, json={'text': message}, timeout=10)
        except Exception as e:
            logging.error(f"Failed to send Slack alert: {e}")
            
    def _send_discord(self, message: str):
        """Send to Discord"""
        try:
            import requests
            requests.post(self.discord_webhook, json={'content': message}, timeout=10)
        except Exception as e:
            logging.error(f"Failed to send Discord alert: {e}")


class ContinuousScanner:
    """Main continuous scanning orchestrator"""
    
    def __init__(self, config_path: Path):
        self.config = self.load_config(config_path)
        self.output_dir = Path(self.config['scanning']['output_dir'])
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.db = FindingsDatabase(self.output_dir / 'findings.db')
        self.resource_manager = ResourceManager(
            max_cpu=self.config['scanning'].get('max_cpu', 80),
            max_memory=self.config['scanning'].get('max_memory', 80)
        )
        self.notifications = NotificationSystem(self.config.get('notifications', {}))
        
        # Setup logging
        self.setup_logging()
        
        # Load targets
        self.targets = self.load_targets()
        
    def load_config(self, config_path: Path) -> Dict:
        """Load configuration from YAML"""
        with open(config_path) as f:
            return yaml.safe_load(f)
            
    def load_targets(self) -> List[str]:
        """Load targets from configuration"""
        targets_file = self.config['scanning'].get('targets_file')
        if targets_file and Path(targets_file).exists():
            with open(targets_file) as f:
                return [line.strip() for line in f if line.strip()]
        
        return self.config['scanning'].get('targets', [])
        
    def setup_logging(self):
        """Configure logging"""
        log_file = self.output_dir / 'continuous_scanner.log'
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
    def run_forever(self):
        """Main continuous scanning loop"""
        logging.info("Starting continuous bug bounty scanner...")
        logging.info(f"Targets: {len(self.targets)}")
        logging.info(f"Scan interval: {self.config['scanning']['scan_interval']} seconds")
        
        iteration = 0
        
        while True:
            try:
                iteration += 1
                logging.info(f"\n{'='*60}")
                logging.info(f"Starting scan iteration #{iteration}")
                logging.info(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                logging.info(f"{'='*60}\n")
                
                # Check resource usage
                if self.resource_manager.should_throttle():
                    logging.warning("High resource usage detected. Pausing for 5 minutes...")
                    time.sleep(300)
                    continue
                
                # Scan all targets
                for target in self.targets:
                    self.scan_target(target)
                    
                # Report summary
                self.report_iteration_summary(iteration)
                
                # Wait before next iteration
                scan_interval = self.config['scanning']['scan_interval']
                logging.info(f"\nWaiting {scan_interval} seconds before next scan...")
                time.sleep(scan_interval)
                
            except KeyboardInterrupt:
                logging.info("\n\nReceived interrupt signal. Shutting down gracefully...")
                break
            except Exception as e:
                logging.error(f"Error in scan iteration: {e}", exc_info=True)
                logging.info("Waiting 5 minutes before retry...")
                time.sleep(300)
                
    def scan_target(self, target: str):
        """Scan a single target"""
        logging.info(f"\n[+] Scanning target: {target}")
        
        scan_id = self.db.conn.execute('''
            INSERT INTO scan_history (target, scan_type, start_time, status)
            VALUES (?, ?, ?, ?)
        ''', (target, 'full', datetime.now(), 'running')).lastrowid
        self.db.conn.commit()
        
        findings_count = 0
        
        try:
            # 1. Reconnaissance
            if self.config['phases']['reconnaissance']:
                new_subdomains = self.run_reconnaissance(target)
                logging.info(f"  [+] Found {len(new_subdomains)} new subdomains")
                
            # 2. Vulnerability Scanning
            if self.config['phases']['vulnerability_scanning']:
                findings = self.run_vulnerability_scan(target)
                findings_count += len(findings)
                
                # Process findings
                for finding in findings:
                    status = self.db.add_finding(finding)
                    if status == 'new':
                        logging.info(f"  [!] NEW {finding['severity']} - {finding['vulnerability_type']}")
                        self.notifications.send_alert(finding)
                        
            # 3. Update scan history
            self.db.conn.execute('''
                UPDATE scan_history 
                SET end_time = ?, findings_count = ?, status = ?
                WHERE id = ?
            ''', (datetime.now(), findings_count, 'completed', scan_id))
            self.db.conn.commit()
            
            logging.info(f"  [✓] Scan completed. New findings: {findings_count}")
            
        except Exception as e:
            logging.error(f"  [✗] Error scanning {target}: {e}", exc_info=True)
            self.db.conn.execute('''
                UPDATE scan_history SET end_time = ?, status = ?
                WHERE id = ?
            ''', (datetime.now(), 'failed', scan_id))
            self.db.conn.commit()
            
    def run_reconnaissance(self, target: str) -> Set[str]:
        """Run reconnaissance phase"""
        logging.info("  [*] Running reconnaissance...")
        
        # Get previous subdomains
        previous_subs = self.db.get_previous_subdomains(target)
        
        # Run subdomain discovery
        current_subs = set()
        
        tools = ['subfinder', 'assetfinder']
        for tool in tools:
            try:
                result = subprocess.run(
                    [tool, '-d', target, '-silent'],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                subs = {line.strip() for line in result.stdout.splitlines() if line.strip()}
                current_subs.update(subs)
            except Exception as e:
                logging.warning(f"    [!] {tool} failed: {e}")
                
        # Find new subdomains
        new_subs = current_subs - previous_subs
        
        # Update database
        for sub in current_subs:
            self.db.add_subdomain(target, sub, is_alive=True)
            
        return new_subs
        
    def run_vulnerability_scan(self, target: str) -> List[Dict]:
        """Run vulnerability scanning phase"""
        logging.info("  [*] Running vulnerability scanning...")
        
        findings = []
        
        # Run Nuclei
        if 'nuclei' in self.config['tools']:
            nuclei_findings = self.run_nuclei(target)
            findings.extend(nuclei_findings)
            
        # Run custom checks
        # Add more scanners here
        
        return findings
        
    def run_nuclei(self, target: str) -> List[Dict]:
        """Run Nuclei vulnerability scanner"""
        output_file = self.output_dir / f'nuclei_{target.replace(".", "_")}.json'
        
        cmd = [
            'nuclei',
            '-u', f'https://{target}',
            '-severity', ','.join(self.config['nuclei']['severity']),
            '-json',
            '-o', str(output_file),
            '-silent'
        ]
        
        if self.config['nuclei'].get('tags'):
            cmd.extend(['-tags', ','.join(self.config['nuclei']['tags'])])
            
        try:
            subprocess.run(cmd, timeout=600, check=False)
            
            # Parse results
            findings = []
            if output_file.exists():
                with open(output_file) as f:
                    for line in f:
                        try:
                            result = json.loads(line)
                            findings.append({
                                'target': target,
                                'vulnerability_type': result.get('info', {}).get('name'),
                                'severity': result.get('info', {}).get('severity'),
                                'url': result.get('matched-at'),
                                'evidence': json.dumps(result.get('extracted-results', [])),
                                'tool': 'nuclei'
                            })
                        except json.JSONDecodeError:
                            continue
                            
            return findings
            
        except Exception as e:
            logging.error(f"    [!] Nuclei failed: {e}")
            return []
            
    def report_iteration_summary(self, iteration: int):
        """Report summary of scan iteration"""
        logging.info(f"\n{'='*60}")
        logging.info(f"Iteration #{iteration} Summary")
        logging.info(f"{'='*60}")
        
        # Get stats from last 24 hours
        new_findings = self.db.get_new_findings(since_hours=24)
        
        by_severity = {}
        for finding in new_findings:
            severity = finding['severity']
            by_severity[severity] = by_severity.get(severity, 0) + 1
            
        logging.info(f"New findings (last 24h): {len(new_findings)}")
        for severity, count in sorted(by_severity.items()):
            logging.info(f"  {severity}: {count}")
            
        logging.info(f"{'='*60}\n")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Continuous Bug Bounty Scanner')
    parser.add_argument('-c', '--config', default='continuous_config.yaml',
                       help='Configuration file path')
    args = parser.parse_args()
    
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: Configuration file not found: {config_path}")
        print("Please create a configuration file. See continuous_config.yaml.example")
        sys.exit(1)
        
    scanner = ContinuousScanner(config_path)
    scanner.run_forever()


if __name__ == '__main__':
    main()
