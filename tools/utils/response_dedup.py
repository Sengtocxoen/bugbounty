#!/usr/bin/env python3
"""
Response Deduplication Module
Prevents scanning duplicate response templates by calculating response fingerprints.
Saves time by only deep-scanning one instance per template (e.g., /product/1 vs /product/99).
"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict


@dataclass
class ResponseFingerprint:
    """Fingerprint of an HTTP response"""
    url: str
    status_code: int
    content_hash: str  # Hash of normalized content
    structure_hash: str  # Hash of HTML structure only
    headers_hash: str  # Hash of important headers
    word_count: int
    line_count: int
    similarity_group: str = ""  # Assigned group ID for similar responses


@dataclass
class TemplateGroup:
    """Group of similar response templates"""
    group_id: str
    representative_url: str  # The first/best URL to scan
    similar_urls: List[str] = field(default_factory=list)
    fingerprint: Optional[ResponseFingerprint] = None
    count: int = 0


class ResponseDeduplicator:
    """Deduplicate similar HTTP responses to avoid redundant scanning"""
    
    def __init__(self, similarity_threshold: float = 0.85):
        """
        Initialize deduplicator
        
        Args:
            similarity_threshold: 0.0-1.0, how similar responses must be to group (default: 0.85)
        """
        self.similarity_threshold = similarity_threshold
        self.fingerprints: Dict[str, ResponseFingerprint] = {}
        self.groups: Dict[str, TemplateGroup] = {}
        self.url_to_group: Dict[str, str] = {}
        
    def _normalize_content(self, content: str) -> str:
        """Normalize content by removing dynamic elements"""
        # Remove common dynamic elements
        content = re.sub(r'\b\d{4}-\d{2}-\d{2}\b', 'DATE', content)  # Dates
        content = re.sub(r'\b\d{2}:\d{2}:\d{2}\b', 'TIME', content)  # Times
        content = re.sub(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', 'UUID', content, flags=re.IGNORECASE)  # UUIDs
        content = re.sub(r'\b[A-Za-z0-9]{20,}\b', 'TOKEN', content)  # Long tokens
        content = re.sub(r'\b\d{6,}\b', 'NUMBER', content)  # Large numbers (IDs)
        
        # Remove whitespace variations
        content = re.sub(r'\s+', ' ', content)
        
        return content.strip()
    
    def _extract_html_structure(self, html: str) -> str:
        """Extract HTML structure (tags only, no content)"""
        # Remove content between tags, keep structure
        structure = re.sub(r'>([^<]+)<', '><', html)
        
        # Remove attributes that might vary
        structure = re.sub(r'<(\w+)[^>]*>', r'<\1>', structure)
        
        # Normalize whitespace
        structure = re.sub(r'\s+', '', structure)
        
        return structure
    
    def _hash_string(self, s: str) -> str:
        """Create SHA256 hash of string"""
        return hashlib.sha256(s.encode('utf-8')).hexdigest()[:16]
    
    def _calculate_fingerprint(self, url: str, status_code: int, content: str, 
                              headers: Dict[str, str]) -> ResponseFingerprint:
        """Calculate fingerprint for a response"""
        # Normalize content
        normalized = self._normalize_content(content)
        content_hash = self._hash_string(normalized)
        
        # Extract structure
        structure = self._extract_html_structure(content)
        structure_hash = self._hash_string(structure)
        
        # Hash important headers (content-type, server)
        important_headers = {
            k.lower(): v for k, v in headers.items() 
            if k.lower() in ['content-type', 'server', 'x-powered-by']
        }
        headers_str = '|'.join(f"{k}:{v}" for k, v in sorted(important_headers.items()))
        headers_hash = self._hash_string(headers_str)
        
        # Calculate metrics
        word_count = len(normalized.split())
        line_count = content.count('\n')
        
        return ResponseFingerprint(
            url=url,
            status_code=status_code,
            content_hash=content_hash,
            structure_hash=structure_hash,
            headers_hash=headers_hash,
            word_count=word_count,
            line_count=line_count
        )
    
    def _calculate_similarity(self, fp1: ResponseFingerprint, fp2: ResponseFingerprint) -> float:
        """Calculate similarity score between two fingerprints (0.0-1.0)"""
        # Different status codes = not similar
        if fp1.status_code != fp2.status_code:
            return 0.0
        
        # Different headers = not similar
        if fp1.headers_hash != fp2.headers_hash:
            return 0.0
        
        # Structure match is most important
        structure_match = 1.0 if fp1.structure_hash == fp2.structure_hash else 0.0
        
        # Word/line count similarity
        if fp1.word_count > 0 and fp2.word_count > 0:
            word_diff = abs(fp1.word_count - fp2.word_count)
            word_sim = 1.0 - (word_diff / max(fp1.word_count, fp2.word_count))
        else:
            word_sim = 0.0
            
        if fp1.line_count > 0 and fp2.line_count > 0:
            line_diff = abs(fp1.line_count - fp2.line_count)
            line_sim = 1.0 - (line_diff / max(fp1.line_count, fp2.line_count))
        else:
            line_sim = 0.0
        
        # Content hash match
        content_match = 1.0 if fp1.content_hash == fp2.content_hash else 0.0
        
        # Weighted similarity
        similarity = (
            structure_match * 0.5 +  # Structure is most important
            content_match * 0.3 +     # Content similarity
            word_sim * 0.1 +          # Word count similarity
            line_sim * 0.1            # Line count similarity
        )
        
        return similarity
    
    def add_response(self, url: str, status_code: int, content: str, 
                    headers: Dict[str, str]) -> Tuple[bool, Optional[str]]:
        """
        Add a response and check if it's a duplicate
        
        Returns:
            (is_duplicate, representative_url)
            - is_duplicate: True if this is similar to an existing response
            - representative_url: If duplicate, the URL of the representative to scan instead
        """
        # Calculate fingerprint
        fp = self._calculate_fingerprint(url, status_code, content, headers)
        self.fingerprints[url] = fp
        
        # Check against existing groups
        best_match_group = None
        best_similarity = 0.0
        
        for group_id, group in self.groups.items():
            if group.fingerprint:
                similarity = self._calculate_similarity(fp, group.fingerprint)
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_match_group = group_id
        
        # If found similar group
        if best_match_group and best_similarity >= self.similarity_threshold:
            group = self.groups[best_match_group]
            group.similar_urls.append(url)
            group.count += 1
            self.url_to_group[url] = best_match_group
            fp.similarity_group = best_match_group
            return (True, group.representative_url)
        
        # Create new group
        group_id = self._hash_string(url)
        new_group = TemplateGroup(
            group_id=group_id,
            representative_url=url,
            fingerprint=fp,
            count=1
        )
        self.groups[group_id] = new_group
        self.url_to_group[url] = group_id
        fp.similarity_group = group_id
        
        return (False, None)
    
    def should_scan(self, url: str) -> bool:
        """
        Check if a URL should be scanned (i.e., it's representative or unique)
        
        Returns:
            True if should scan, False if it's a duplicate
        """
        if url not in self.url_to_group:
            return True  # Unknown URL, scan it
        
        group_id = self.url_to_group[url]
        group = self.groups[group_id]
        
        # Only scan the representative URL
        return url == group.representative_url
    
    def get_stats(self) -> Dict:
        """Get deduplication statistics"""
        total_urls = len(self.fingerprints)
        unique_groups = len(self.groups)
        duplicates = total_urls - unique_groups
        
        if total_urls > 0:
            dedup_ratio = duplicates / total_urls
        else:
            dedup_ratio = 0.0
        
        largest_groups = sorted(
            self.groups.values(), 
            key=lambda g: g.count, 
            reverse=True
        )[:5]
        
        return {
            'total_urls': total_urls,
            'unique_groups': unique_groups,
            'duplicates': duplicates,
            'deduplication_ratio': dedup_ratio,
            'time_savings_estimate': f"{int(dedup_ratio * 100)}%",
            'largest_groups': [
                {
                    'representative': g.representative_url,
                    'count': g.count,
                    'similar_urls': g.similar_urls[:3]  # Show first 3
                }
                for g in largest_groups
            ]
        }
    
    def print_stats(self):
        """Print deduplication statistics"""
        stats = self.get_stats()
        
        print("\n" + "="*60)
        print("RESPONSE DEDUPLICATION STATISTICS")
        print("="*60)
        print(f"Total URLs processed: {stats['total_urls']}")
        print(f"Unique response templates: {stats['unique_groups']}")
        print(f"Duplicate responses: {stats['duplicates']}")
        print(f"Estimated time savings: {stats['time_savings_estimate']}")
        
        if stats['largest_groups']:
            print("\nLargest template groups:")
            for i, group in enumerate(stats['largest_groups'], 1):
                print(f"\n  {i}. {group['representative']} ({group['count']} similar)")
                if group['similar_urls']:
                    for url in group['similar_urls']:
                        print(f"     - {url}")
                    if group['count'] > 3:
                        print(f"     ... and {group['count'] - 3} more")


if __name__ == "__main__":
    # Test deduplicator
    dedup = ResponseDeduplicator(similarity_threshold=0.85)
    
    # Simulate product pages with similar structure
    test_responses = [
        ("/product/1", 200, "<html><body><h1>Product</h1><p>ID: 1</p><p>Price: $10</p></body></html>", {"content-type": "text/html"}),
        ("/product/2", 200, "<html><body><h1>Product</h1><p>ID: 2</p><p>Price: $20</p></body></html>", {"content-type": "text/html"}),
        ("/product/99", 200, "<html><body><h1>Product</h1><p>ID: 99</p><p>Price: $99</p></body></html>", {"content-type": "text/html"}),
        ("/about", 200, "<html><body><h1>About Us</h1><p>Company info</p></body></html>", {"content-type": "text/html"}),
        ("/contact", 200, "<html><body><h1>Contact</h1><form>...</form></body></html>", {"content-type": "text/html"}),
    ]
    
    print("\nTesting Response Deduplication:")
    print("-" * 60)
    
    for url, status, content, headers in test_responses:
        is_dup, rep_url = dedup.add_response(url, status, content, headers)
        if is_dup:
            print(f"[SKIP] {url} - Similar to {rep_url}")
        else:
            print(f"[SCAN] {url} - New template")
    
    dedup.print_stats()
