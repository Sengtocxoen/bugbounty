#!/usr/bin/env python3
"""
Parallel Bug Bounty Scanner - Stream Processing Pipeline
=========================================================

Scans subdomains AS THEY ARE DISCOVERED, rather than waiting for
all discovery to complete first.

Architecture:
- Producer thread: Subdomain discovery (continuously finds new subdomains)
- Consumer threads: Vulnerability scanning (nuclei, web_hacking_2025, etc.)
- Queue: Thread-safe queue connecting producers to consumers

This enables:
- sub1.target.com found -> immediately starts scanning
- sub2.target.com found -> starts scanning in parallel
- Discovery continues while scans are running

Usage:
    python parallel_scan.py example.com -p amazon -u myh1user --workers 5
    python parallel_scan.py -f targets.txt --parallel --workers 10
"""

import sys
import json
import signal
import argparse
import threading
import queue
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Set, Optional, Callable
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, Future
from urllib.parse import urlparse

# Add tools directory to path
sys.path.insert(0, str(Path(__file__).parent))

from .deep_scan import DeepScanner, DeepScanConfig, DeepScanResult, SHUTDOWN_FLAG
from techniques.web_hacking_2025.scanner import WebHackingScanner
from techniques.web_hacking_2025.bugbounty_config import get_program_config, ScopeValidator


# Global shutdown flag
SHUTDOWN_REQUESTED = False


def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    global SHUTDOWN_REQUESTED
    if SHUTDOWN_REQUESTED:
        print("\n\n[!] Force exit...")
        sys.exit(1)
    print("\n\n[!] Shutdown requested. Finishing current tasks...")
    print("[!] Press Ctrl+C again to force exit")
    SHUTDOWN_REQUESTED = True


signal.signal(signal.SIGINT, signal_handler)


@dataclass
class SubdomainTask:
    """A subdomain to be scanned"""
    subdomain: str
    target: str  # Original target domain
    discovered_at: float = field(default_factory=time.time)
    metadata: Dict = field(default_factory=dict)


@dataclass
class ScanResult:
    """Result from scanning a subdomain"""
    subdomain: str
    target: str
    success: bool
    findings_count: int = 0
    duration: float = 0.0
    error: Optional[str] = None
    output_dir: Optional[Path] = None


class SubdomainQueue:
    """Thread-safe queue for discovered subdomains"""

    def __init__(self, maxsize: int = 0):
        self._queue = queue.Queue(maxsize=maxsize)
        self._seen = set()
        self._lock = threading.Lock()
        self._discovery_complete = threading.Event()
        self._stats = {
            'discovered': 0,
            'queued': 0,
            'processed': 0,
            'duplicates': 0,
        }

    def put(self, task: SubdomainTask) -> bool:
        """Add a subdomain to the queue. Returns False if duplicate."""
        with self._lock:
            if task.subdomain in self._seen:
                self._stats['duplicates'] += 1
                return False
            self._seen.add(task.subdomain)
            self._stats['discovered'] += 1

        self._queue.put(task)
        with self._lock:
            self._stats['queued'] += 1
        return True

    def get(self, timeout: float = 1.0) -> Optional[SubdomainTask]:
        """Get next subdomain from queue. Returns None if queue is empty and discovery complete."""
        try:
            task = self._queue.get(timeout=timeout)
            with self._lock:
                self._stats['processed'] += 1
            return task
        except queue.Empty:
            if self._discovery_complete.is_set() and self._queue.empty():
                return None
            return None  # Timeout, but discovery still running

    def mark_discovery_complete(self):
        """Signal that no more subdomains will be added"""
        self._discovery_complete.set()

    def is_discovery_complete(self) -> bool:
        """Check if discovery has finished"""
        return self._discovery_complete.is_set()

    def is_empty(self) -> bool:
        """Check if queue is empty"""
        return self._queue.empty()

    def get_stats(self) -> Dict:
        """Get queue statistics"""
        with self._lock:
            return dict(self._stats)


class StreamingSubdomainDiscovery:
    """
    Subdomain discovery that streams results to a queue as they're found.
    """

    def __init__(self, config: DeepScanConfig, task_queue: SubdomainQueue):
        self.config = config
        self.queue = task_queue
        self.scanner = DeepScanner(config)
        self._discovered_count = 0

    def _subdomain_callback(self, subdomain: str, target: str, info: Dict):
        """Called when a subdomain is discovered"""
        global SHUTDOWN_REQUESTED
        if SHUTDOWN_REQUESTED:
            return

        # Only queue alive and in-scope subdomains
        if info.get('is_alive') and (info.get('in_scope', True) or self.config.program is None):
            task = SubdomainTask(
                subdomain=subdomain,
                target=target,
                metadata=info
            )
            if self.queue.put(task):
                self._discovered_count += 1
                print(f"[QUEUE] Added: {subdomain} (queue size: ~{self.queue._queue.qsize()})")

    def discover(self, target: str) -> int:
        """
        Run subdomain discovery, streaming results to queue.
        Returns total number of subdomains queued.
        """
        print(f"\n[DISCOVERY] Starting subdomain enumeration for: {target}")
        print(f"[DISCOVERY] Subdomains will be queued for scanning as they're found\n")

        try:
            # Run the subdomain discovery phase
            result = DeepScanResult(
                target=target,
                program=self.config.program,
                scan_start=datetime.utcnow().isoformat(),
            )

            # Get alive subdomains from discovery
            alive_targets = self.scanner.phase_subdomain_discovery(target, result)

            # Queue each discovered subdomain
            for subdomain in alive_targets:
                if SHUTDOWN_REQUESTED:
                    break
                info = result.subdomains.get(subdomain, {})
                self._subdomain_callback(subdomain, target, {'is_alive': True, 'in_scope': True, **info})

            print(f"\n[DISCOVERY] Complete: {self._discovered_count} subdomains queued for scanning")

        except Exception as e:
            print(f"[DISCOVERY ERROR] {e}")

        return self._discovered_count


class ParallelVulnScanner:
    """
    Vulnerability scanner that processes subdomains from a queue in parallel.
    """

    def __init__(self,
                 task_queue: SubdomainQueue,
                 output_dir: Path,
                 config: DeepScanConfig,
                 num_workers: int = 3,
                 techniques: Optional[List[str]] = None):
        self.queue = task_queue
        self.output_dir = output_dir
        self.config = config
        self.num_workers = num_workers
        self.techniques = techniques
        self.results: List[ScanResult] = []
        self._lock = threading.Lock()
        self._active_workers = 0

        # Get program config for rate limiting
        self.rate_limit = 5.0
        self.user_agent = "Mozilla/5.0 (compatible; SecurityResearch/1.0)"
        if config.program:
            program_config = get_program_config(config.program)
            self.rate_limit = program_config.rate_limit
            self.user_agent = program_config.get_user_agent(config.username)

    def _scan_subdomain(self, task: SubdomainTask) -> ScanResult:
        """Scan a single subdomain"""
        start_time = time.time()
        subdomain = task.subdomain

        # Create subdomain-specific output directory
        safe_name = subdomain.replace("://", "_").replace("/", "_").replace(":", "_").replace(".", "_")
        sub_output = self.output_dir / task.target.replace(".", "_") / safe_name
        sub_output.mkdir(parents=True, exist_ok=True)

        print(f"[SCAN START] {subdomain}")

        try:
            # Create scanner for this subdomain
            scanner = WebHackingScanner(
                output_dir=sub_output,
                rate_limit=self.rate_limit,
                user_agent=self.user_agent,
                techniques=self.techniques,
                verbose=False,  # Reduce noise in parallel mode
                threads=1,  # Single thread per subdomain to avoid overwhelming
            )

            # Run the scan
            scanner.run([subdomain], resume=False)

            # Count findings from output files
            findings_count = 0
            for severity in ['critical', 'high', 'medium', 'low']:
                findings_file = sub_output / subdomain / 'findings' / f'{severity}_findings.json'
                if findings_file.exists():
                    try:
                        with open(findings_file) as f:
                            data = json.load(f)
                            findings_count += len(data.get('findings', []))
                    except:
                        pass

            duration = time.time() - start_time
            print(f"[SCAN DONE] {subdomain} - {findings_count} findings in {duration:.1f}s")

            return ScanResult(
                subdomain=subdomain,
                target=task.target,
                success=True,
                findings_count=findings_count,
                duration=duration,
                output_dir=sub_output
            )

        except Exception as e:
            duration = time.time() - start_time
            print(f"[SCAN ERROR] {subdomain}: {e}")
            return ScanResult(
                subdomain=subdomain,
                target=task.target,
                success=False,
                duration=duration,
                error=str(e)
            )

    def _worker(self, worker_id: int):
        """Worker thread that processes subdomains from queue"""
        global SHUTDOWN_REQUESTED

        with self._lock:
            self._active_workers += 1

        print(f"[WORKER {worker_id}] Started")

        while not SHUTDOWN_REQUESTED:
            task = self.queue.get(timeout=2.0)

            if task is None:
                # Check if we should exit
                if self.queue.is_discovery_complete() and self.queue.is_empty():
                    break
                continue

            result = self._scan_subdomain(task)

            with self._lock:
                self.results.append(result)

        with self._lock:
            self._active_workers -= 1

        print(f"[WORKER {worker_id}] Stopped")

    def run(self) -> List[ScanResult]:
        """Start worker threads and process queue"""
        print(f"\n[SCANNER] Starting {self.num_workers} parallel scanner workers")

        threads = []
        for i in range(self.num_workers):
            t = threading.Thread(target=self._worker, args=(i,), daemon=True)
            t.start()
            threads.append(t)

        # Wait for all workers to complete
        for t in threads:
            t.join()

        return self.results


class ParallelScanner:
    """
    Main orchestrator for parallel subdomain discovery + vulnerability scanning.
    """

    def __init__(self,
                 targets: List[str],
                 output_dir: Path,
                 program: Optional[str] = None,
                 username: str = "yourh1username",
                 num_workers: int = 3,
                 techniques: Optional[List[str]] = None,
                 skip_phases: Optional[Dict[str, bool]] = None):

        self.targets = targets
        self.output_dir = output_dir
        self.program = program
        self.username = username
        self.num_workers = num_workers
        self.techniques = techniques
        self.skip_phases = skip_phases or {}

        # Create shared queue
        self.queue = SubdomainQueue()

        # Build config for subdomain discovery
        self.config = DeepScanConfig(
            targets=targets,
            program=program,
            username=username,
            output_dir=output_dir / "discovery",
            skip_ports=True,  # Skip in discovery, do in vuln scan
            skip_endpoints=True,
            skip_tech=True,
            skip_js=True,
            skip_fuzz=True,
            skip_subdomains=self.skip_phases.get('skip_subdomains', False),
            skip_recursive=self.skip_phases.get('skip_recursive', False),
        )

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> Dict:
        """
        Run parallel discovery + scanning.

        Returns dict with:
        - discovery_stats: Subdomain discovery statistics
        - scan_results: List of scan results per subdomain
        - summary: Overall summary
        """
        global SHUTDOWN_REQUESTED

        print("\n" + "=" * 80)
        print("  PARALLEL BUG BOUNTY SCANNER")
        print("  Streaming subdomain discovery + concurrent vulnerability scanning")
        print("=" * 80)
        print(f"\n  Targets:     {len(self.targets)}")
        print(f"  Program:     {self.program or 'Generic'}")
        print(f"  Workers:     {self.num_workers}")
        print(f"  Output:      {self.output_dir}")
        print(f"\n  Press Ctrl+C to gracefully stop")
        print("=" * 80 + "\n")

        # Start vulnerability scanner workers (consumers)
        vuln_scanner = ParallelVulnScanner(
            task_queue=self.queue,
            output_dir=self.output_dir / "scans",
            config=self.config,
            num_workers=self.num_workers,
            techniques=self.techniques
        )

        # Start scanner workers in background
        scanner_thread = threading.Thread(target=vuln_scanner.run, daemon=True)
        scanner_thread.start()

        # Run subdomain discovery (producer) for each target
        discovery = StreamingSubdomainDiscovery(self.config, self.queue)

        total_discovered = 0
        for target in self.targets:
            if SHUTDOWN_REQUESTED:
                break
            count = discovery.discover(target)
            total_discovered += count

        # Signal that discovery is complete
        self.queue.mark_discovery_complete()
        print(f"\n[DISCOVERY] All targets processed. Waiting for scans to complete...")

        # Wait for scanner workers to finish
        scanner_thread.join()

        # Collect results
        queue_stats = self.queue.get_stats()
        scan_results = vuln_scanner.results

        # Generate summary
        summary = self._generate_summary(queue_stats, scan_results)

        # Save summary
        self._save_summary(summary)

        return {
            'discovery_stats': queue_stats,
            'scan_results': scan_results,
            'summary': summary
        }

    def _generate_summary(self, queue_stats: Dict, scan_results: List[ScanResult]) -> Dict:
        """Generate scan summary"""
        successful = [r for r in scan_results if r.success]
        failed = [r for r in scan_results if not r.success]

        total_findings = sum(r.findings_count for r in successful)
        total_duration = sum(r.duration for r in scan_results)

        # Group by severity
        findings_by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for result in successful:
            if result.output_dir:
                for severity in findings_by_severity:
                    findings_file = result.output_dir / result.subdomain / 'findings' / f'{severity}_findings.json'
                    if findings_file.exists():
                        try:
                            with open(findings_file) as f:
                                data = json.load(f)
                                findings_by_severity[severity] += len(data.get('findings', []))
                        except:
                            pass

        return {
            'targets': self.targets,
            'program': self.program,
            'timestamp': datetime.utcnow().isoformat(),
            'discovery': {
                'total_discovered': queue_stats['discovered'],
                'duplicates_filtered': queue_stats['duplicates'],
                'subdomains_scanned': queue_stats['processed'],
            },
            'scanning': {
                'successful_scans': len(successful),
                'failed_scans': len(failed),
                'total_duration_seconds': total_duration,
            },
            'findings': {
                'total': total_findings,
                'by_severity': findings_by_severity,
            },
            'subdomains_scanned': [r.subdomain for r in scan_results],
            'errors': [{'subdomain': r.subdomain, 'error': r.error} for r in failed],
        }

    def _save_summary(self, summary: Dict):
        """Save summary to file"""
        summary_file = self.output_dir / 'parallel_scan_summary.json'
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        print(f"\n[SUMMARY] Saved to: {summary_file}")

        # Print summary
        print("\n" + "=" * 80)
        print("  PARALLEL SCAN COMPLETE")
        print("=" * 80)
        print(f"\n  Subdomains Discovered:  {summary['discovery']['total_discovered']}")
        print(f"  Subdomains Scanned:     {summary['discovery']['subdomains_scanned']}")
        print(f"  Successful Scans:       {summary['scanning']['successful_scans']}")
        print(f"  Failed Scans:           {summary['scanning']['failed_scans']}")
        print(f"\n  Total Findings:         {summary['findings']['total']}")
        print(f"    Critical:             {summary['findings']['by_severity']['critical']}")
        print(f"    High:                 {summary['findings']['by_severity']['high']}")
        print(f"    Medium:               {summary['findings']['by_severity']['medium']}")
        print(f"    Low:                  {summary['findings']['by_severity']['low']}")
        print(f"\n  Total Duration:         {summary['scanning']['total_duration_seconds']:.1f}s")
        print(f"  Results saved to:       {self.output_dir}")
        print("=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Parallel Bug Bounty Scanner - Stream processing pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan with 5 parallel workers
  python parallel_scan.py example.com -p amazon -u myh1user --workers 5

  # Scan multiple targets from file
  python parallel_scan.py -f targets.txt --workers 10

  # Run specific techniques only
  python parallel_scan.py example.com --techniques ssrf,injection,auth_bypass

  # Skip subdomain discovery (scan provided domains directly)
  python parallel_scan.py sub1.example.com sub2.example.com --skip-discovery
        """
    )

    parser.add_argument("targets", nargs="*", help="Target domains")
    parser.add_argument("-f", "--file", help="File containing targets (one per line)")
    parser.add_argument("-p", "--program", choices=["amazon", "shopify"],
                        help="Bug bounty program (for scope/rate limits)")
    parser.add_argument("-u", "--username", default="yourh1username",
                        help="HackerOne username")
    parser.add_argument("-o", "--output", default="./parallel_results",
                        help="Output directory")
    parser.add_argument("-w", "--workers", type=int, default=3,
                        help="Number of parallel scanning workers (default: 3)")
    parser.add_argument("--techniques", help="Comma-separated list of techniques to run")
    parser.add_argument("--skip-discovery", action="store_true",
                        help="Skip subdomain discovery, scan provided targets directly")
    parser.add_argument("--skip-recursive", action="store_true",
                        help="Skip recursive subdomain discovery")

    args = parser.parse_args()

    # Collect targets
    targets = list(args.targets) if args.targets else []
    if args.file:
        try:
            with open(args.file) as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"[ERROR] File not found: {args.file}")
            sys.exit(1)

    if not targets:
        parser.print_help()
        print("\n[ERROR] No targets specified")
        sys.exit(1)

    # Parse techniques
    techniques = None
    if args.techniques:
        techniques = [t.strip() for t in args.techniques.split(",") if t.strip()]

    # Skip phases
    skip_phases = {
        'skip_subdomains': args.skip_discovery,
        'skip_recursive': args.skip_recursive,
    }

    # Run parallel scanner
    scanner = ParallelScanner(
        targets=targets,
        output_dir=Path(args.output),
        program=args.program,
        username=args.username,
        num_workers=args.workers,
        techniques=techniques,
        skip_phases=skip_phases
    )

    results = scanner.run()

    # Exit code based on findings
    total_findings = results['summary']['findings']['total']
    sys.exit(0 if total_findings == 0 else 1)


if __name__ == "__main__":
    main()
