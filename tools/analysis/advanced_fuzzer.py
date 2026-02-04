#!/usr/bin/env python3
"""
Advanced Fuzzing Engine
Implements "Wfuzz Logic" with recursive direction fuzzing, smart filtering, and header fuzzing.
Features: recursive fuzzing, soft 404 detection, session management, deduplication.
"""

import requests
import time
import hashlib
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse
import pickle
import os


@dataclass
class FuzzResult:
    """Result from a fuzzing attempt"""
    url: str
    status_code: int
    content_length: int
    word_count: int
    line_count: int
    response_time: float
    headers: Dict[str, str] = field(default_factory=dict)
    is_soft_404: bool = False
    is_interesting: bool = False


@dataclass
class FuzzSession:
    """Fuzzing session state for resume capability"""
    target_url: str
    wordlist_file: str
    tested_paths: Set[str] = field(default_factory=set)
    found_directories: List[str] = field(default_factory=list)
    baseline_404: Optional[FuzzResult] = None
    session_file: str = "fuzz_session.pkl"


class AdvancedFuzzer:
    """Advanced fuzzing with recursive discovery and smart filtering"""
    
    def __init__(self, rate_limit: float = 10.0, timeout: int = 5, 
                 user_agent: str = "BugBountyResearcher", max_threads: int = 10):
        """
        Initialize advanced fuzzer
        
        Args:
            rate_limit: Requests per second
            timeout: Request timeout in seconds
            user_agent: User agent string
            max_threads: Max concurrent threads
        """
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.user_agent = user_agent
        self.max_threads = max_threads
        
        self.session = requests.Session()
        self.session.headers['User-Agent'] = user_agent
        
        # Adaptive rate limiting
        self.min_interval = 1.0 / rate_limit
        self.last_request = 0.0
        self.consecutive_blocks = 0
        self.lock = threading.Lock()
        
        # Session state
        self.fuzz_session: Optional[FuzzSession] = None
        
        # Results storage
        self.results: List[FuzzResult] = []
        self.dedup_cache: Dict[str, str] = {}  # URL -> response hash
    
    def _rate_limit_wait(self):
        """Adaptive rate limiting"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_request
            
            # Adaptive delay based on blocks
            if self.consecutive_blocks > 0:
                delay = self.min_interval * (2 ** min(self.consecutive_blocks, 5))
                delay = min(delay, 30.0)  # Cap at 30 seconds
            else:
                delay = self.min_interval
            
            if elapsed < delay:
                time.sleep(delay - elapsed)
            
            self.last_request = time.time()
    
    def _calculate_baseline_404(self, base_url: str) -> FuzzResult:
        """Calculate baseline 404 response characteristics"""
        # Request a known non-existent path
        test_path = f"/nonexistent{hashlib.md5(str(time.time()).encode()).hexdigest()}"
        test_url = urljoin(base_url, test_path)
        
        self._rate_limit_wait()
        
        try:
            start = time.time()
            response = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
            elapsed = time.time() - start
            
            content = response.text
            
            baseline = FuzzResult(
                url=test_url,
                status_code=response.status_code,
                content_length=len(content),
                word_count=len(content.split()),
                line_count=content.count('\n'),
                response_time=elapsed,
                is_soft_404=True
            )
            
            print(f"[*] Baseline 404: {baseline.status_code} | {baseline.line_count} lines | {baseline.word_count} words")
            return baseline
            
        except Exception as e:
            print(f"[!] Baseline error: {e}")
            return None
    
    def _is_soft_404(self, result: FuzzResult, baseline: Optional[FuzzResult]) -> bool:
        """
        Detect soft 404s using smart filtering
        
        A soft 404 is a page that returns 200 OK but is actually a 404 page.
        We detect it by comparing line count, word count, and content length.
        """
        if not baseline:
            return False
        
        # If status is explicitly 404, it's a real 404
        if result.status_code == 404:
            return True
        
        # Check if line count and word count are very similar to baseline
        line_diff = abs(result.line_count - baseline.line_count)
        word_diff = abs(result.word_count - baseline.word_count)
        
        # Threshold: within 10% variance is likely soft 404
        line_threshold = max(5, int(baseline.line_count * 0.1))
        word_threshold = max(10, int(baseline.word_count * 0.1))
        
        if line_diff <= line_threshold and word_diff <= word_threshold:
            return True
        
        return False
    
    def _is_interesting(self, result: FuzzResult) -> bool:
        """Determine if a result is interesting"""
        # Interesting status codes
        interesting_codes = [200, 301, 302, 401, 403, 500]
        
        if result.status_code in interesting_codes and not result.is_soft_404:
            return True
        
        return False
    
    def _fuzz_headers(self, url: str) -> List[FuzzResult]:
        """Systematically fuzz headers for bypasses"""
        print(f"\n[*] Header Fuzzing: {url}")
        
        header_payloads = {
            'X-Forwarded-For': ['127.0.0.1', '10.0.0.1', '192.168.1.1', 'localhost'],
            'X-Real-IP': ['127.0.0.1', '10.0.0.1'],
            'Client-IP': ['127.0.0.1'],
            'X-Originating-IP': ['127.0.0.1'],
            'Host': ['localhost', 'internal.example.com', 'admin.example.com'],
            'X-Custom-IP-Authorization': ['127.0.0.1'],
        }
        
        results = []
        
        for header_name, values in header_payloads.items():
            for value in values:
                self._rate_limit_wait()
                
                try:
                    headers = {header_name: value}
                    start = time.time()
                    response = self.session.get(url, headers=headers, timeout=self.timeout, allow_redirects=False)
                    elapsed = time.time() - start
                    
                    content = response.text
                    
                    result = FuzzResult(
                        url=f"{url} (Header: {header_name}={value})",
                        status_code=response.status_code,
                        content_length=len(content),
                        word_count=len(content.split()),
                        line_count=content.count('\n'),
                        response_time=elapsed,
                        headers={header_name: value}
                    )
                    
                    # Check if different from normal response
                    if response.status_code in [200, 301, 302] and response.status_code != 403:
                        result.is_interesting = True
                        print(f"  [BYPASS] {header_name}: {value} -> {response.status_code}")
                        results.append(result)
                        
                except Exception:
                    pass
        
        return results
    
    def fuzz_directory(self, base_url: str, wordlist: List[str], 
                      recursive: bool = True, max_depth: int = 3, 
                      current_depth: int = 0) -> List[FuzzResult]:
        """
        Fuzz a directory with recursive capability
        
        Args:
            base_url: Base URL to fuzz
            wordlist: List of paths to try
            recursive: Enable recursive fuzzing
            max_depth: Maximum recursion depth
            current_depth: Current recursion depth (internal)
        """
        if current_depth >= max_depth:
            print(f"[*] Max depth {max_depth} reached")
            return []
        
        print(f"\n[*] Fuzzing: {base_url} (Depth: {current_depth})")
        print(f"    Wordlist size: {len(wordlist)}")
        
        # Calculate baseline if first run
        if not self.fuzz_session or not self.fuzz_session.baseline_404:
            baseline = self._calculate_baseline_404(base_url)
            if self.fuzz_session:
                self.fuzz_session.baseline_404 = baseline
        else:
            baseline = self.fuzz_session.baseline_404
        
        found_dirs = []
        results = []
        
        for path in wordlist:
            # Skip if already tested (deduplication)
            if self.fuzz_session and path in self.fuzz_session.tested_paths:
                continue
            
            # Build URL
            test_url = urljoin(base_url, path.lstrip('/'))
            
            # Rate limiting
            self._rate_limit_wait()
            
            try:
                start = time.time()
                response = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                elapsed = time.time() - start
                
                # Handle rate limiting
                if response.status_code in [429, 503]:
                    self.consecutive_blocks += 1
                    print(f"  [!] Rate limited, backing off...")
                    time.sleep(5)
                    continue
                else:
                    self.consecutive_blocks = max(0, self.consecutive_blocks - 1)
                
                content = response.text
                
                result = FuzzResult(
                    url=test_url,
                    status_code=response.status_code,
                    content_length=len(content),
                    word_count=len(content.split()),
                    line_count=content.count('\n'),
                    response_time=elapsed
                )
                
                # Check for soft 404
                result.is_soft_404 = self._is_soft_404(result, baseline)
                result.is_interesting = self._is_interesting(result)
                
                # Store result if interesting
                if result.is_interesting:
                    results.append(result)
                    print(f"  [FOUND] {result.status_code} | {path} | {result.line_count} lines")
                    
                    # If it's a directory (301, 302, or 200 with path ending in /)
                    if response.status_code in [301, 302] or (response.status_code == 200 and path.endswith('/')):
                        found_dirs.append(test_url)
                
                # Mark as tested
                if self.fuzz_session:
                    self.fuzz_session.tested_paths.add(path)
                
            except requests.Timeout:
                pass
            except Exception as e:
                pass
        
        # Recursive fuzzing on found directories
        if recursive and found_dirs:
            print(f"\n[*] Found {len(found_dirs)} directories for recursive fuzzing")
            
            for dir_url in found_dirs[:5]:  # Limit to first 5 to avoid explosion
                print(f"\n[RECURSE] Entering: {dir_url}")
                sub_results = self.fuzz_directory(
                    dir_url, 
                    wordlist, 
                    recursive=True, 
                    max_depth=max_depth,
                    current_depth=current_depth + 1
                )
                results.extend(sub_results)
        
        return results
    
    def save_session(self, session_file: str):
        """Save fuzzing session for resume"""
        if self.fuzz_session:
            with open(session_ file, 'wb') as f:
                pickle.dump(self.fuzz_session, f)
            print(f"[*] Session saved to: {session_file}")
    
    def load_session(self, session_file: str) -> bool:
        """Load fuzzing session"""
        if os.path.exists(session_file):
            try:
                with open(session_file, 'rb') as f:
                    self.fuzz_session = pickle.load(f)
                print(f"[*] Session loaded from: {session_file}")
                return True
            except:
                print(f"[!] Failed to load session")
                return False
        return False


def load_wordlist(wordlist_file: str) -> List[str]:
    """Load wordlist from file"""
    try:
        with open(wordlist_file, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist_file}")
        return []


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced Directory Fuzzer")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist file")
    parser.add_argument("--recursive", "-r", action="store_true", help="Recursive fuzzing")
    parser.add_argument("--depth", type=int, default=3, help="Max recursion depth")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent threads")
    parser.add_argument("--rate-limit", type=float, default=10.0, help="Requests per second")
    parser.add_argument("--header-fuzz", action="store_true", help="Enable header fuzzing")
    parser.add_argument("--resume", help="Resume from session file")
    
    args = parser.parse_args()
    
    fuzzer = AdvancedFuzzer(rate_limit=args.rate_limit, max_threads=args.threads)
    
    # Load or create session
    if args.resume and fuzzer.load_session(args.resume):
        wordlist = load_wordlist(args.wordlist)
    else:
        wordlist = load_wordlist(args.wordlist)
        fuzzer.fuzz_session = FuzzSession(
            target_url=args.url,
            wordlist_file=args.wordlist
        )
    
    if not wordlist:
        print("[!] No wordlist loaded")
        exit(1)
    
    # Run fuzzing
    results = fuzzer.fuzz_directory(
        args.url, 
        wordlist, 
        recursive=args.recursive,
        max_depth=args.depth
    )
    
    # Header fuzzing on found paths
    if args.header_fuzz:
        for result in results[:10]:  # Test first 10 found paths
            header_results = fuzzer._fuzz_headers(result.url)
            results.extend(header_results)
    
    # Print summary
    print("\n" + "="*60)
    print("FUZZING SUMMARY")
    print("="*60)
    print(f"Total interesting results: {len(results)}")
    
    for result in results:
        if result.is_interesting:
            print(f"  [{result.status_code}] {result.url} ({result.line_count} lines)")
    
    # Save session
    if fuzzer.fuzz_session:
        fuzzer.save_session("fuzz_session.pkl")
