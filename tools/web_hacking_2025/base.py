#!/usr/bin/env python3
"""
Base classes for 2025 Web Hacking Techniques Scanner
Provides progress tracking, state persistence, and finding management.
"""

import json
import time
import signal
import threading
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any, Callable
from enum import Enum
from abc import ABC, abstractmethod
import sys

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    sys.exit(1)


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanState(Enum):
    """Scan state for resumable operations"""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Finding:
    """Represents a security finding"""
    domain: str
    technique: str
    category: str
    severity: str
    title: str
    description: str
    evidence: str
    reproduction_steps: List[str]
    request: Optional[str] = None
    response: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_report(self) -> str:
        """Generate a formatted report string"""
        lines = [
            f"=" * 80,
            f"FINDING: {self.title}",
            f"=" * 80,
            f"Domain: {self.domain}",
            f"Technique: {self.technique}",
            f"Category: {self.category}",
            f"Severity: {self.severity.upper()}",
            f"Timestamp: {self.timestamp}",
            f"-" * 80,
            f"Description:",
            f"  {self.description}",
            f"-" * 80,
            f"Evidence:",
            f"  {self.evidence}",
            f"-" * 80,
            f"Reproduction Steps:",
        ]
        for i, step in enumerate(self.reproduction_steps, 1):
            lines.append(f"  {i}. {step}")

        if self.request:
            lines.extend([f"-" * 80, f"Request:", self.request])
        if self.response:
            lines.extend([f"-" * 80, f"Response (truncated):", self.response[:2000]])

        lines.append("=" * 80)
        return "\n".join(lines)


@dataclass
class DomainProgress:
    """Progress tracking for a single domain"""
    domain: str
    state: ScanState = ScanState.NOT_STARTED
    techniques_completed: List[str] = field(default_factory=list)
    techniques_pending: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    last_update: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "domain": self.domain,
            "state": self.state.value,
            "techniques_completed": self.techniques_completed,
            "techniques_pending": self.techniques_pending,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "last_update": self.last_update,
        }


@dataclass
class ScanProgress:
    """Overall scan progress with persistence"""
    output_dir: Path
    domains_total: int = 0
    domains_completed: int = 0
    domains_in_progress: int = 0
    domains: Dict[str, DomainProgress] = field(default_factory=dict)
    findings_total: int = 0
    start_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_save: Optional[str] = None

    def __post_init__(self):
        self.output_dir = Path(self.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def add_domain(self, domain: str, techniques: List[str]):
        """Add a domain to track"""
        with self._lock:
            if domain not in self.domains:
                self.domains[domain] = DomainProgress(
                    domain=domain,
                    techniques_pending=techniques.copy()
                )
                self.domains_total += 1

    def start_domain(self, domain: str):
        """Mark domain scan as started"""
        with self._lock:
            if domain in self.domains:
                self.domains[domain].state = ScanState.IN_PROGRESS
                self.domains[domain].start_time = datetime.utcnow().isoformat()
                self.domains_in_progress += 1

    def complete_technique(self, domain: str, technique: str):
        """Mark a technique as completed for a domain"""
        with self._lock:
            if domain in self.domains:
                dp = self.domains[domain]
                if technique in dp.techniques_pending:
                    dp.techniques_pending.remove(technique)
                if technique not in dp.techniques_completed:
                    dp.techniques_completed.append(technique)
                dp.last_update = datetime.utcnow().isoformat()

    def add_finding(self, domain: str, finding: Finding):
        """Add a finding for a domain"""
        with self._lock:
            if domain in self.domains:
                self.domains[domain].findings.append(finding)
                self.findings_total += 1
                # Auto-save on findings
                self._save_finding(finding)

    def add_error(self, domain: str, error: str):
        """Add an error for a domain"""
        with self._lock:
            if domain in self.domains:
                self.domains[domain].errors.append(error)

    def complete_domain(self, domain: str):
        """Mark domain scan as completed"""
        with self._lock:
            if domain in self.domains:
                self.domains[domain].state = ScanState.COMPLETED
                self.domains[domain].end_time = datetime.utcnow().isoformat()
                self.domains_completed += 1
                self.domains_in_progress = max(0, self.domains_in_progress - 1)

    def _save_finding(self, finding: Finding):
        """Save individual finding immediately"""
        findings_dir = self.output_dir / "findings"
        findings_dir.mkdir(exist_ok=True)

        # Save to severity-based files
        severity_file = findings_dir / f"{finding.severity}_findings.json"
        findings_list = []
        if severity_file.exists():
            try:
                findings_list = json.loads(severity_file.read_text())
            except:
                pass
        findings_list.append(finding.to_dict())
        severity_file.write_text(json.dumps(findings_list, indent=2))

        # Also append to all_findings.txt for quick viewing
        all_file = findings_dir / "all_findings.txt"
        with open(all_file, "a") as f:
            f.write(finding.to_report() + "\n\n")

    def save(self):
        """Save complete progress state"""
        with self._lock:
            self.last_save = datetime.utcnow().isoformat()

            # Save main progress file
            progress_file = self.output_dir / "scan_progress.json"
            progress_data = {
                "domains_total": self.domains_total,
                "domains_completed": self.domains_completed,
                "domains_in_progress": self.domains_in_progress,
                "findings_total": self.findings_total,
                "start_time": self.start_time,
                "last_save": self.last_save,
                "domains": {k: v.to_dict() for k, v in self.domains.items()}
            }
            progress_file.write_text(json.dumps(progress_data, indent=2))

            # Save domain list
            domains_file = self.output_dir / "domains_status.txt"
            with open(domains_file, "w") as f:
                f.write(f"# Scan Progress - {self.last_save}\n")
                f.write(f"# Total: {self.domains_total}, Completed: {self.domains_completed}\n\n")
                for domain, dp in self.domains.items():
                    f.write(f"[{dp.state.value}] {domain} - {len(dp.findings)} findings\n")

    @classmethod
    def load(cls, output_dir: Path) -> Optional['ScanProgress']:
        """Load progress from file for resumption"""
        progress_file = output_dir / "scan_progress.json"
        if not progress_file.exists():
            return None

        try:
            data = json.loads(progress_file.read_text())
            progress = cls(output_dir=output_dir)
            progress.domains_total = data.get("domains_total", 0)
            progress.domains_completed = data.get("domains_completed", 0)
            progress.domains_in_progress = 0  # Reset, will restart in-progress
            progress.findings_total = data.get("findings_total", 0)
            progress.start_time = data.get("start_time", progress.start_time)

            for domain, dp_data in data.get("domains", {}).items():
                findings = [
                    Finding(**f) for f in dp_data.get("findings", [])
                ]
                dp = DomainProgress(
                    domain=domain,
                    state=ScanState(dp_data.get("state", "not_started")),
                    techniques_completed=dp_data.get("techniques_completed", []),
                    techniques_pending=dp_data.get("techniques_pending", []),
                    findings=findings,
                    errors=dp_data.get("errors", []),
                    start_time=dp_data.get("start_time"),
                    end_time=dp_data.get("end_time"),
                    last_update=dp_data.get("last_update"),
                )
                # Reset in-progress domains to pending techniques
                if dp.state == ScanState.IN_PROGRESS:
                    dp.state = ScanState.NOT_STARTED
                progress.domains[domain] = dp

            return progress
        except Exception as e:
            print(f"[!] Error loading progress: {e}")
            return None

    def get_stats(self) -> Dict:
        """Get current statistics"""
        with self._lock:
            by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for dp in self.domains.values():
                for f in dp.findings:
                    sev = f.severity.lower()
                    if sev in by_severity:
                        by_severity[sev] += 1

            return {
                "domains_total": self.domains_total,
                "domains_completed": self.domains_completed,
                "domains_in_progress": self.domains_in_progress,
                "findings_total": self.findings_total,
                "findings_by_severity": by_severity,
            }


class ProgressTracker:
    """Real-time progress display"""

    def __init__(self, progress: ScanProgress, refresh_interval: float = 2.0):
        self.progress = progress
        self.refresh_interval = refresh_interval
        self._stop = False
        self._thread = None

    def start(self):
        """Start progress display thread"""
        self._stop = False
        self._thread = threading.Thread(target=self._display_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop progress display"""
        self._stop = True
        if self._thread:
            self._thread.join(timeout=1)

    def _display_loop(self):
        """Display progress periodically"""
        while not self._stop:
            stats = self.progress.get_stats()
            self._print_status(stats)
            time.sleep(self.refresh_interval)

    def _print_status(self, stats: Dict):
        """Print current status"""
        print(f"\r[Progress] Domains: {stats['domains_completed']}/{stats['domains_total']} | "
              f"Findings: {stats['findings_total']} "
              f"(C:{stats['findings_by_severity']['critical']} "
              f"H:{stats['findings_by_severity']['high']} "
              f"M:{stats['findings_by_severity']['medium']} "
              f"L:{stats['findings_by_severity']['low']})",
              end="", flush=True)


class RateLimiter:
    """Thread-safe rate limiter"""

    def __init__(self, rate_per_second: float = 5.0):
        self.rate = rate_per_second
        self.min_interval = 1.0 / rate_per_second
        self.last_request = 0.0
        self._lock = threading.Lock()

    def wait(self):
        """Wait if necessary to maintain rate limit"""
        with self._lock:
            now = time.time()
            elapsed = now - self.last_request
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_request = time.time()


class TechniqueScanner(ABC):
    """Base class for technique-specific scanners"""

    TECHNIQUE_NAME = "base"
    TECHNIQUE_CATEGORY = "generic"

    def __init__(self,
                 rate_limit: float = 5.0,
                 user_agent: str = "Mozilla/5.0 (compatible; SecurityResearch/1.0)",
                 timeout: int = 30,
                 verbose: bool = True):
        self.rate_limiter = RateLimiter(rate_limit)
        self.user_agent = user_agent
        self.timeout = timeout
        self.verbose = verbose
        self.session = self._create_session()
        self._shutdown = False

    def _create_session(self) -> requests.Session:
        """Create a session with retry logic"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
        })
        return session

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a rate-limited request"""
        if self._shutdown:
            return None

        self.rate_limiter.wait()
        try:
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('verify', True)
            kwargs.setdefault('allow_redirects', False)
            return self.session.request(method, url, **kwargs)
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"  [!] Request error for {url}: {type(e).__name__}")
            return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("POST", url, **kwargs)

    def log(self, message: str, level: str = "info"):
        """Log a message if verbose"""
        if self.verbose:
            prefix = {"info": "[*]", "success": "[+]", "warning": "[!]", "error": "[-]"}.get(level, "[*]")
            print(f"  {prefix} {message}")

    def shutdown(self):
        """Signal scanner to stop"""
        self._shutdown = True

    @abstractmethod
    def scan(self, domain: str, progress: ScanProgress) -> List[Finding]:
        """
        Scan a domain for this technique's vulnerabilities.
        Must be implemented by subclasses.

        Args:
            domain: Target domain (e.g., "example.com")
            progress: Progress tracker for updates

        Returns:
            List of findings
        """
        pass

    def create_finding(self,
                       domain: str,
                       severity: str,
                       title: str,
                       description: str,
                       evidence: str,
                       reproduction_steps: List[str],
                       request: str = None,
                       response: str = None,
                       **metadata) -> Finding:
        """Helper to create a finding"""
        return Finding(
            domain=domain,
            technique=self.TECHNIQUE_NAME,
            category=self.TECHNIQUE_CATEGORY,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            reproduction_steps=reproduction_steps,
            request=request,
            response=response,
            metadata=metadata
        )


# Global shutdown flag for graceful termination
SHUTDOWN_FLAG = False

def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown"""
    global SHUTDOWN_FLAG

    def handler(signum, frame):
        global SHUTDOWN_FLAG
        if SHUTDOWN_FLAG:
            print("\n[!] Force exit...")
            sys.exit(1)
        print("\n[!] Shutdown requested. Saving progress...")
        SHUTDOWN_FLAG = True

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

def is_shutdown() -> bool:
    """Check if shutdown was requested"""
    return SHUTDOWN_FLAG
