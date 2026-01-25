#!/usr/bin/env python3
"""
Smart Response Detector
Identifies similar/duplicate responses to avoid wasting time scanning identical pages
"""

import hashlib
import re
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from collections import defaultdict
import requests


@dataclass
class ResponseSignature:
    """Signature of an HTTP response for comparison"""
    status_code: int
    content_hash: str
    content_length: int
    title: Optional[str]
    headers_hash: str
    is_redirect: bool
    redirect_location: Optional[str]
    
    
class SmartResponseDetector:
    """
    Detect duplicate/similar responses to skip redundant scanning
    
    Strategy:
    1. Take 1 sample request first
    2. Compare with known response patterns
    3. If similar (>95%), mark as duplicate and skip deep scan
    4. Track which endpoints were skipped for later review
    """
    
    def __init__(self, similarity_threshold: float = 0.95):
        self.similarity_threshold = similarity_threshold
        
        # Store seen response signatures
        self.response_signatures: Dict[str, ResponseSignature] = {}
        
        # Track duplicate groups
        self.duplicate_groups: Dict[str, List[str]] = defaultdict(list)
        
        # Track skipped endpoints for later deep scan
        self.skipped_endpoints: Dict[str, str] = {}  # url -> reason
        
        # Common patterns to detect
        self.error_patterns = {
            '404': re.compile(r'(not found|404|page.+not.+exist)', re.I),
            '403': re.compile(r'(forbidden|access denied|403)', re.I),
            'error': re.compile(r'(error|exception|failed)', re.I),
            'redirect': re.compile(r'(redirect|moved)', re.I),
        }
        
    def get_response_signature(self, response: requests.Response, url: str) -> ResponseSignature:
        """Create a signature for response comparison"""
        
        # Hash the content
        content_hash = hashlib.md5(response.content).hexdigest()
        
        # Extract title if HTML
        title = None
        if 'text/html' in response.headers.get('Content-Type', ''):
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.I)
            if title_match:
                title = title_match.group(1).strip()
                
        # Hash significant headers (ignore date, cookies, etc.)
        significant_headers = ['content-type', 'server', 'x-powered-by']
        header_str = '|'.join(
            f"{k}:{v}" for k, v in response.headers.items() 
            if k.lower() in significant_headers
        )
        headers_hash = hashlib.md5(header_str.encode()).hexdigest()
        
        # Check if redirect
        is_redirect = response.status_code in [301, 302, 303, 307, 308]
        redirect_location = response.headers.get('Location') if is_redirect else None
        
        return ResponseSignature(
            status_code=response.status_code,
            content_hash=content_hash,
            content_length=len(response.content),
            title=title,
            headers_hash=headers_hash,
            is_redirect=is_redirect,
            redirect_location=redirect_location
        )
        
    def is_duplicate_response(self, response: requests.Response, url: str) -> tuple[bool, Optional[str]]:
        """
        Check if this response is similar to a known response
        
        Returns:
            (is_duplicate, similar_url)
        """
        
        signature = self.get_response_signature(response, url)
        
        # Quick check: exact content hash match
        for known_url, known_sig in self.response_signatures.items():
            if signature.content_hash == known_sig.content_hash:
                # Exact duplicate
                self.duplicate_groups[known_url].append(url)
                return True, known_url
                
        # Check for similar responses
        for known_url, known_sig in self.response_signatures.items():
            if self._is_similar(signature, known_sig, response, url):
                self.duplicate_groups[known_url].append(url)
                return True, known_url
                
        # Not a duplicate - store this signature
        self.response_signatures[url] = signature
        return False, None
        
    def _is_similar(self, sig1: ResponseSignature, sig2: ResponseSignature, 
                    response: requests.Response, url: str) -> bool:
        """Check if two response signatures are similar"""
        
        # Different status codes = not similar (usually)
        if sig1.status_code != sig2.status_code:
            return False
            
        # Check redirect similarity
        if sig1.is_redirect and sig2.is_redirect:
            # If both redirect to same location, they're similar
            if sig1.redirect_location == sig2.redirect_location:
                return True
                
        # Check content length similarity (within 5%)
        if abs(sig1.content_length - sig2.content_length) > (sig1.content_length * 0.05):
            return False
            
        # Check title similarity
        if sig1.title and sig2.title:
            title_similarity = SequenceMatcher(None, sig1.title, sig2.title).ratio()
            if title_similarity < 0.9:
                return False
                
        # Headers must be similar
        if sig1.headers_hash != sig2.headers_hash:
            return False
            
        return True
        
    def should_skip_deep_scan(self, response: requests.Response, url: str) -> tuple[bool, str]:
        """
        Determine if we should skip deep scanning this endpoint
        
        Returns:
            (should_skip, reason)
        """
        
        # Check for common error pages
        for error_type, pattern in self.error_patterns.items():
            if pattern.search(response.text):
                reason = f"Common {error_type} page detected"
                self.skipped_endpoints[url] = reason
                return True, reason
                
        # Check for duplicate response
        is_dup, similar_url = self.is_duplicate_response(response, url)
        if is_dup:
            reason = f"Duplicate of {similar_url}"
            self.skipped_endpoints[url] = reason
            return True, reason
            
        # Check for empty or very small responses
        if len(response.content) < 100:
            reason = "Response too small (likely empty page)"
            self.skipped_endpoints[url] = reason
            return True, reason
            
        return False, ""
        
    def get_skipped_summary(self) -> Dict:
        """Get summary of skipped endpoints"""
        return {
            'total_skipped': len(self.skipped_endpoints),
            'duplicate_groups': len(self.duplicate_groups),
            'skipped_by_group': {
                group: len(urls) for group, urls in self.duplicate_groups.items()
            },
            'skipped_endpoints': self.skipped_endpoints
        }
        
    def get_endpoints_for_deep_scan(self) -> List[str]:
        """Get list of endpoints that were skipped and need deep scan later"""
        return list(self.skipped_endpoints.keys())


class AdaptiveRateLimiter:
    """
    Adaptive rate limiting based on response patterns
    
    If we detect many duplicates, we can scan faster.
    If we detect unique responses, we slow down to be thorough.
    """
    
    def __init__(self, base_rate: int = 5):
        self.base_rate = base_rate  # requests per second
        self.current_rate = base_rate
        self.min_rate = 1
        self.max_rate = 20
        
        self.recent_duplicates = []
        self.window_size = 20  # Track last 20 requests
        
    def record_request(self, is_duplicate: bool):
        """Record whether the last request was a duplicate"""
        self.recent_duplicates.append(is_duplicate)
        
        # Keep only recent history
        if len(self.recent_duplicates) > self.window_size:
            self.recent_duplicates.pop(0)
            
        # Adjust rate based on duplicate ratio
        self._adjust_rate()
        
    def _adjust_rate(self):
        """Adjust scanning rate based on duplicate ratio"""
        if len(self.recent_duplicates) < 10:
            return  # Not enough data
            
        duplicate_ratio = sum(self.recent_duplicates) / len(self.recent_duplicates)
        
        if duplicate_ratio > 0.7:
            # Lots of duplicates, we can go faster
            self.current_rate = min(self.max_rate, self.current_rate * 1.2)
        elif duplicate_ratio < 0.3:
            # Mostly unique responses, be more careful
            self.current_rate = max(self.min_rate, self.current_rate * 0.8)
            
    def get_delay(self) -> float:
        """Get current delay between requests in seconds"""
        return 1.0 / self.current_rate


class SmartScanQueue:
    """
    Priority queue for smart scanning
    
    Strategy:
    1. Quick scan all endpoints (1 request each)
    2. Mark duplicates
    3. Queue unique endpoints for deep scan
    4. Process deep scan queue later
    """
    
    def __init__(self):
        self.quick_scan_queue: List[str] = []
        self.deep_scan_queue: List[str] = []
        self.completed: Set[str] = set()
        self.in_progress: Set[str] = set()
        
    def add_targets(self, urls: List[str]):
        """Add targets to quick scan queue"""
        self.quick_scan_queue.extend(urls)
        
    def get_next_quick_scan(self) -> Optional[str]:
        """Get next URL for quick scan"""
        if self.quick_scan_queue:
            url = self.quick_scan_queue.pop(0)
            self.in_progress.add(url)
            return url
        return None
        
    def mark_for_deep_scan(self, url: str):
        """Mark URL for deep scanning later"""
        if url not in self.deep_scan_queue:
            self.deep_scan_queue.append(url)
        if url in self.in_progress:
            self.in_progress.remove(url)
            
    def mark_completed(self, url: str):
        """Mark URL as fully scanned"""
        self.completed.add(url)
        if url in self.in_progress:
            self.in_progress.remove(url)
            
    def get_next_deep_scan(self) -> Optional[str]:
        """Get next URL for deep scan"""
        if self.deep_scan_queue:
            url = self.deep_scan_queue.pop(0)
            self.in_progress.add(url)
            return url
        return None
        
    def get_status(self) -> Dict:
        """Get current queue status"""
        return {
            'quick_scan_remaining': len(self.quick_scan_queue),
            'deep_scan_pending': len(self.deep_scan_queue),
            'completed': len(self.completed),
            'in_progress': len(self.in_progress),
            'total_processed': len(self.completed) + len(self.deep_scan_queue)
        }


if __name__ == '__main__':
    # Example usage
    detector = SmartResponseDetector()
    
    # Simulate scanning
    import requests
    
    urls = [
        'https://example.com/page1',
        'https://example.com/page2',
        'https://example.com/page3',
    ]
    
    for url in urls:
        try:
            response = requests.get(url, timeout=5)
            should_skip, reason = detector.should_skip_deep_scan(response, url)
            
            if should_skip:
                print(f"[SKIP] {url}: {reason}")
            else:
                print(f"[SCAN] {url}: Unique response, performing deep scan")
                
        except Exception as e:
            print(f"[ERROR] {url}: {e}")
            
    # Print summary
    summary = detector.get_skipped_summary()
    print(f"\nSummary: Skipped {summary['total_skipped']} endpoints")
    print(f"Found {summary['duplicate_groups']} duplicate groups")
