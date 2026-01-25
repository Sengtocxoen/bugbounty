#!/usr/bin/env python3
"""
Intelligent Smart Scanner
Combines response detection, streaming output, and smart queueing for optimal scanning

Strategy:
1. Quick scan all targets first (1 request each)
2. Detect duplicates and skip deep scan
3. Write results in real-time (don't wait for everything)
4. Queue unique endpoints for deep scan
5. Come back and deep scan later
"""

import time
import requests
from pathlib import Path
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import logging

from smart_response_detector import (
    SmartResponseDetector,
    AdaptiveRateLimiter,
    SmartScanQueue
)
from streaming_results import StreamingResultsWriter, Finding


class IntelligentScanner:
    """
    Intelligent scanner with:
    - Response similarity detection
    - Streaming real-time output
    - Two-phase scanning (quick then deep)
    - Adaptive rate limiting
    """
    
    def __init__(self, output_dir: Path, max_workers: int = 5):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.response_detector = SmartResponseDetector(similarity_threshold=0.95)
        self.rate_limiter = AdaptiveRateLimiter(base_rate=5)
        self.scan_queue = SmartScanQueue()
        self.results_writer = StreamingResultsWriter(output_dir)
        
        # Scanning settings
        self.max_workers = max_workers
        self.timeout = 10
        self.user_agent = 'Mozilla/5.0 (compatible; SecurityResearch/1.0)'
        
        # Setup logging
        self.setup_logging()
        
    def setup_logging(self):
        """Configure logging"""
        log_file = self.output_dir / 'intelligent_scanner.log'
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def scan_subdomains(self, target: str, subdomains: List[str]):
        """
        Scan subdomains intelligently
        
        Phase 1: Quick scan (1 request per subdomain)
        Phase 2: Deep scan (only unique responses)
        """
        
        self.logger.info(f"Starting intelligent scan for {target}")
        self.logger.info(f"Total subdomains: {len(subdomains)}")
        
        # Add to queue
        urls = [f"https://{sub}" for sub in subdomains]
        self.scan_queue.add_targets(urls)
        
        # Phase 1: Quick scan
        self.logger.info("\n🚀 Phase 1: Quick Scan (detecting duplicates)")
        self.quick_scan_phase(target)
        
        # Phase 2: Deep scan (only unique responses)
        deep_scan_count = len(self.scan_queue.deep_scan_queue)
        if deep_scan_count > 0:
            self.logger.info(f"\n🔍 Phase 2: Deep Scan ({deep_scan_count} unique targets)")
            self.deep_scan_phase(target)
        else:
            self.logger.info("\n✅ No unique targets found for deep scan (all were duplicates)")
            
        # Write skipped endpoints summary
        skipped = self.response_detector.get_skipped_summary()
        self.results_writer.write_skipped_endpoints(
            target, 
            self.response_detector.skipped_endpoints
        )
        
        # Finalize
        self.results_writer.finalize_target(target)
        
        # Print summary
        self.print_summary(target, skipped)
        
    def quick_scan_phase(self, target: str):
        """
        Phase 1: Quick scan - 1 request per subdomain
        
        Goal: Identify duplicates quickly, mark unique ones for deep scan
        """
        
        total = len(self.scan_queue.quick_scan_queue)
        completed = 0
        duplicates = 0
        
        while True:
            url = self.scan_queue.get_next_quick_scan()
            if not url:
                break
                
            try:
                # Rate limiting
                time.sleep(self.rate_limiter.get_delay())
                
                # Make request
                response = requests.get(
                    url,
                    headers={'User-Agent': self.user_agent},
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False
                )
                
                # Check if we should skip deep scan
                should_skip, reason = self.response_detector.should_skip_deep_scan(response, url)
                
                # Write subdomain result immediately
                subdomain = url.replace('https://', '').replace('http://', '')
                self.results_writer.write_subdomain(
                    target=target,
                    subdomain=subdomain,
                    is_alive=True,
                    http_status=response.status_code,
                    was_skipped=should_skip
                )
                
                if should_skip:
                    # Mark as completed (skip deep scan)
                    self.scan_queue.mark_completed(url)
                    duplicates += 1
                    self.rate_limiter.record_request(is_duplicate=True)
                    self.logger.debug(f"[SKIP] {url}: {reason}")
                else:
                    # Queue for deep scan
                    self.scan_queue.mark_for_deep_scan(url)
                    self.rate_limiter.record_request(is_duplicate=False)
                    self.logger.info(f"[UNIQUE] {url}: Queued for deep scan")
                    
            except requests.exceptions.RequestException as e:
                self.logger.debug(f"[ERROR] {url}: {e}")
                # Write as dead subdomain
                subdomain = url.replace('https://', '').replace('http://', '')
                self.results_writer.write_subdomain(
                    target=target,
                    subdomain=subdomain,
                    is_alive=False
                )
                self.scan_queue.mark_completed(url)
                
            except Exception as e:
                self.logger.error(f"[ERROR] {url}: {e}")
                self.scan_queue.mark_completed(url)
                
            # Update progress in real-time
            completed += 1
            self.results_writer.update_progress(
                target=target,
                phase='quick_scan',
                completed=completed,
                total=total
            )
            
        self.logger.info(f"\n✅ Quick scan complete")
        self.logger.info(f"   Scanned: {completed}/{total}")
        self.logger.info(f"   Duplicates skipped: {duplicates}")
        self.logger.info(f"   Unique (for deep scan): {len(self.scan_queue.deep_scan_queue)}")
        
    def deep_scan_phase(self, target: str):
        """
        Phase 2: Deep scan - only unique responses
        
        Run comprehensive vulnerability scans on targets that weren't duplicates
        """
        
        total = len(self.scan_queue.deep_scan_queue)
        completed = 0
        
        # Use thread pool for parallel deep scanning
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            
            while True:
                url = self.scan_queue.get_next_deep_scan()
                if not url:
                    break
                    
                # Submit deep scan task
                future = executor.submit(self.deep_scan_single, target, url)
                futures[future] = url
                
            # Process results as they complete
            for future in as_completed(futures):
                url = futures[future]
                try:
                    findings = future.result()
                    
                    # Write findings immediately (streaming)
                    for finding in findings:
                        self.results_writer.write_finding(finding)
                        
                    self.scan_queue.mark_completed(url)
                    
                except Exception as e:
                    self.logger.error(f"[ERROR] Deep scan failed for {url}: {e}")
                    
                # Update progress
                completed += 1
                self.results_writer.update_progress(
                    target=target,
                    phase='deep_scan',
                    completed=completed,
                    total=total
                )
                
    def deep_scan_single(self, target: str, url: str) -> List[Finding]:
        """
        Deep scan a single URL
        
        This is where you'd run:
        - Content discovery (ffuf)
        - Vulnerability scanning (nuclei)
        - Parameter fuzzing (arjun)
        - XSS testing (dalfox)
        etc.
        """
        
        findings = []
        subdomain = url.replace('https://', '').replace('http://', '')
        
        self.logger.info(f"[DEEP] Starting deep scan: {url}")
        
        # Example: Run Nuclei
        nuclei_findings = self.run_nuclei(target, url)
        findings.extend(nuclei_findings)
        
        # Example: Content discovery
        # endpoints = self.discover_content(url)
        # findings.extend(self.scan_endpoints(endpoints))
        
        # Add more tools here...
        
        return findings
        
    def run_nuclei(self, target: str, url: str) -> List[Finding]:
        """Run Nuclei vulnerability scanner"""
        import subprocess
        import json
        import tempfile
        
        findings = []
        
        try:
            # Create temp file for output
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
                output_file = f.name
                
            # Run Nuclei
            cmd = [
                'nuclei',
                '-u', url,
                '-severity', 'critical,high,medium',
                '-json',
                '-o', output_file,
                '-silent'
            ]
            
            subprocess.run(cmd, timeout=300, check=False, capture_output=True)
            
            # Parse results
            if Path(output_file).exists():
                with open(output_file) as f:
                    for line in f:
                        try:
                            result = json.loads(line)
                            
                            finding = Finding(
                                timestamp=datetime.now().isoformat(),
                                target=target,
                                subdomain=url.replace('https://', '').replace('http://', ''),
                                url=result.get('matched-at', url),
                                vulnerability_type=result.get('info', {}).get('name', 'Unknown'),
                                severity=result.get('info', {}).get('severity', 'info'),
                                tool='nuclei',
                                evidence=json.dumps(result.get('extracted-results', [])),
                                status='verified'
                            )
                            findings.append(finding)
                            
                        except json.JSONDecodeError:
                            continue
                            
            # Cleanup
            Path(output_file).unlink(missing_ok=True)
            
        except Exception as e:
            self.logger.error(f"Nuclei scan failed for {url}: {e}")
            
        return findings
        
    def print_summary(self, target: str, skipped_summary: Dict):
        """Print final summary"""
        print("\n" + "=" * 60)
        print(f"SCAN COMPLETE: {target}")
        print("=" * 60)
        
        status = self.scan_queue.get_status()
        print(f"\n📊 Scan Statistics:")
        print(f"   Total processed: {status['total_processed']}")
        print(f"   Completed: {status['completed']}")
        print(f"   Duplicates skipped: {skipped_summary['total_skipped']}")
        print(f"   Duplicate groups: {skipped_summary['duplicate_groups']}")
        
        summary = self.results_writer.get_live_summary()
        if target in summary.get('targets', {}):
            target_stats = summary['targets'][target]
            print(f"\n🎯 Findings for {target}:")
            print(f"   Total: {target_stats.get('findings', 0)}")
            print(f"   Critical: {target_stats.get('critical', 0)}")
            print(f"   High: {target_stats.get('high', 0)}")
            print(f"   Medium: {target_stats.get('medium', 0)}")
            print(f"   Low: {target_stats.get('low', 0)}")
            
        print(f"\n📁 Results saved to:")
        target_dir = self.output_dir / target.replace('.', '_')
        print(f"   {target_dir}/")
        print(f"   ├── findings.jsonl (all findings)")
        print(f"   ├── findings.csv (spreadsheet format)")
        print(f"   ├── subdomains.txt (discovered subdomains)")
        print(f"   ├── skipped_deep_scan.json (endpoints to review)")
        print(f"   └── progress.json (scan progress)")
        
        print("\n" + "=" * 60)


def main():
    """Example usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Intelligent Bug Bounty Scanner')
    parser.add_argument('target', help='Target domain')
    parser.add_argument('-s', '--subdomains-file', required=True,
                       help='File with subdomains (one per line)')
    parser.add_argument('-o', '--output', default='./results/intelligent',
                       help='Output directory')
    parser.add_argument('-w', '--workers', type=int, default=5,
                       help='Number of parallel workers for deep scan')
    
    args = parser.parse_args()
    
    # Load subdomains
    with open(args.subdomains_file) as f:
        subdomains = [line.strip() for line in f if line.strip()]
        
    print(f"\n🎯 Intelligent Scanner")
    print(f"Target: {args.target}")
    print(f"Subdomains: {len(subdomains)}")
    print(f"Output: {args.output}\n")
    
    # Create scanner
    scanner = IntelligentScanner(
        output_dir=Path(args.output),
        max_workers=args.workers
    )
    
    # Run scan
    scanner.scan_subdomains(args.target, subdomains)
    
    print("\n✅ Scan complete! Check output directory for results.")
    print(f"\nTo view live progress, run:")
    print(f"  python streaming_results.py monitor {args.output}")


if __name__ == '__main__':
    main()
