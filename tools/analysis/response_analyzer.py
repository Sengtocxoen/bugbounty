#!/usr/bin/env python3
"""
Response Analyzer
Analyzes HTTP responses to detect patterns, cluster similar responses, and filter noise
"""

import hashlib
import re
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import difflib


@dataclass
class ResponseSignature:
    """Signature of an HTTP response for comparison"""
    status_code: int
    content_hash: str
    content_length: int
    title: Optional[str] = None
    headers_hash: str = ""
    technologies: List[str] = field(default_factory=list)
    
    def similarity(self, other: 'ResponseSignature') -> float:
        """
        Calculate similarity score with another response
        Returns 0.0 to 1.0 (1.0 = identical)
        """
        score = 0.0
        
        # Status code match (30%)
        if self.status_code == other.status_code:
            score += 0.3
        
        # Content hash exact match (40%)
        if self.content_hash == other.content_hash:
            score += 0.4
        
        # Content length similarity (15%)
        if self.content_length > 0 and other.content_length > 0:
            length_ratio = min(self.content_length, other.content_length) / max(self.content_length, other.content_length)
            score += 0.15 * length_ratio
        
        # Title match (10%)
        if self.title and other.title:
            if self.title == other.title:
                score += 0.1
        
        # Technology overlap (5%)
        if self.technologies and other.technologies:
            common =set(self.technologies) & set(other.technologies)
            if common:
                score += 0.05
        
        return score


@dataclass
class ResponseCluster:
    """A cluster of similar responses"""
    signature: ResponseSignature
    urls: List[str] = field(default_factory=list)
    count: int = 0
    is_error_page: bool = False
    is_auth_redirect: bool = False
    is_soft_404: bool = False
    
    def add_url(self, url: str):
        """Add a URL to this cluster"""
        if url not in self.urls:
            self.urls.append(url)
            self.count += 1


class ResponseAnalyzer:
    """
    Analyzes HTTP responses to identify patterns and filter noise
    """
    
    def __init__(self, similarity_threshold: float = 0.8):
        """
        Initialize response analyzer
        
        Args:
            similarity_threshold: Threshold for clustering similar responses (0.0-1.0)
        """
        self.similarity_threshold = similarity_threshold
        self.clusters: List[ResponseCluster] = []
        self.error_patterns = self._load_error_patterns()
        self.boring_patterns = self._load_boring_patterns()
    
    def _load_error_patterns(self) -> List[str]:
        """Load patterns that indicate error pages"""
        return [
            r'(?i)page\s+(?:not\s+)?found',
            r'(?i)404\s+(?:error|not\s+found)',
            r'(?i)error\s+404',
            r'(?i)the\s+(?:page|resource)\s+you\s+(?:requested|are\s+looking\s+for)',
            r'(?i)sorry,?\s+(?:we\s+)?(?:could(?:n\'?t)?|can\'?t)\s+find',
            r'(?i)this\s+(?:page|url)\s+(?:does(?:n\'?t)?|doesn\'?t)\s+exist',
            r'(?i)access\s+denied',
            r'(?i)forbidden',
            r'(?i)unauthorized',
            r'(?i)internal\s+server\s+error',
            r'(?i)service\s+unavailable',
            r'(?i)bad\s+(?:gateway|request)',
        ]
    
    def _load_boring_patterns(self) -> List[str]:
        """Load patterns for boring/generic pages"""
        return [
            r'(?i)coming\s+soon',
            r'(?i)under\s+construction',
            r'(?i)maintenance\s+mode',
            r'(?i)this\s+(?:site|domain)\s+(?:is\s+)?(?:for\s+sale|parked)',
            r'(?i)default\s+(?:page|website)',
            r'(?i)it\s+works!?',  # Apache default
            r'(?i)welcome\s+to\s+nginx',
        ]
    
    def normalize_content(self, content: str) -> str:
        """
        Normalize content by removing dynamic elements
        
        Args:
            content: Raw HTML/text content
            
        Returns:
            Normalized content
        """
        # Remove common dynamic elements
        normalized = content
        
        # Remove CSRF tokens, nonces, timestamps
        normalized = re.sub(r'(?:csrf|nonce|token|_token|authenticity_token)["\']?\s*[:=]\s*["\']?[\w\-]+', '', normalized, flags=re.IGNORECASE)
        
        # Remove timestamps (Unix timestamps, ISO dates)
        normalized = re.sub(r'\b\d{10,13}\b', '', normalized)
        normalized = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', '', normalized)
        
        # Remove session IDs
        normalized = re.sub(r'(?:session|sid|sess_?id)["\']?\s*[:=]\s*["\']?[\w\-]{16,}', '', normalized, flags=re.IGNORECASE)
        
        # Remove script/style content (usually dynamic)
        normalized = re.sub(r'<script[^>]*>.*?</script>', '', normalized, flags=re.DOTALL | re.IGNORECASE)
        normalized = re.sub(r'<style[^>]*>.*?</style>', '', normalized, flags=re.DOTALL | re.IGNORECASE)
        
        # Normalize whitespace
        normalized = re.sub(r'\s+', ' ', normalized)
        
        return normalized.strip()
    
    def compute_content_hash(self, content: str) -> str:
        """
        Compute hash of normalized content
        
        Args:
            content: Raw content
            
        Returns:
            MD5 hash of normalized content
        """
        normalized = self.normalize_content(content)
        return hashlib.md5(normalized.encode('utf-8', errors='ignore')).hexdigest()
    
    def extract_title(self, html: str) -> Optional[str]:
        """
        Extract page title from HTML
        
        Args:
            html: HTML content
            
        Returns:
            Page title or None
        """
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else None
    
    def is_error_page(self, content: str, status_code: int) -> bool:
        """
        Check if response is an error page
        
        Args:
            content: Response content
            status_code: HTTP status code
            
        Returns:
            True if error page
        """
        # Check status code
        if status_code in [400, 401, 403, 404, 500, 502, 503]:
            return True
        
        # Check content patterns
        content_lower = content.lower()
        for pattern in self.error_patterns:
            if re.search(pattern, content_lower):
                return True
        
        return False
    
    def is_boring_page(self, content: str, title: Optional[str] = None) -> bool:
        """
        Check if response is a boring/generic page
        
        Args:
            content: Response content
            title: Page title
            
        Returns:
            True if boring page
        """
        content_lower = content.lower()
        
        for pattern in self.boring_patterns:
            if re.search(pattern, content_lower):
                return True
        
        if title:
            title_lower = title.lower()
            for pattern in self.boring_patterns:
                if re.search(pattern, title_lower):
                    return True
        
        return False
    
    def create_signature(self, content: str, status_code: int, headers: Dict = None) -> ResponseSignature:
        """
        Create a signature from a response
        
        Args:
            content: Response content
            status_code: HTTP status code
            headers: Response headers dict
            
        Returns:
            ResponseSignature object
        """
        content_hash = self.compute_content_hash(content)
        title = self.extract_title(content)
        
        # Simple header hash (just content-type for now)
        headers_hash = ""
        if headers:
            ct = headers.get('content-type', headers.get('Content-Type', ''))
            if ct:
                headers_hash = hashlib.md5(ct.encode()).hexdigest()[:8]
        
        # Detect technologies from headers and content
        technologies = []
        if headers:
            server = headers.get('server', headers.get('Server', ''))
            if 'nginx' in server.lower():
                technologies.append('nginx')
            elif 'apache' in server.lower():
                technologies.append('apache')
            elif 'iis' in server.lower():
                technologies.append('iis')
            
            if 'x-powered-by' in headers or 'X-Powered-By' in headers:
                powered = headers.get('x-powered-by', headers.get('X-Powered-By', ''))
                if 'php' in powered.lower():
                    technologies.append('php')
                elif 'asp.net' in powered.lower():
                    technologies.append('asp.net')
        
        return ResponseSignature(
            status_code=status_code,
            content_hash=content_hash,
            content_length=len(content),
            title=title,
            headers_hash=headers_hash,
            technologies=technologies
        )
    
    def find_similar_cluster(self, signature: ResponseSignature) -> Optional[ResponseCluster]:
        """
        Find a cluster similar to the given signature
        
        Args:
            signature: Response signature to match
            
        Returns:
            Matching ResponseCluster or None
        """
        for cluster in self.clusters:
            similarity = cluster.signature.similarity(signature)
            if similarity >= self.similarity_threshold:
                return cluster
        return None
    
    def add_response(self, url: str, content: str, status_code: int, headers: Dict = None) -> Tuple[ResponseCluster, bool]:
        """
        Add a response to the analyzer
        
        Args:
            url: URL of the response
            content: Response content
            status_code: HTTP status code
            headers: Response headers
            
        Returns:
            Tuple of (ResponseCluster, is_new_cluster)
        """
        signature = self.create_signature(content, status_code, headers)
        
        # Check if it matches an existing cluster
        cluster = self.find_similar_cluster(signature)
        
        if cluster:
            cluster.add_url(url)
            return cluster, False
        else:
            # Create new cluster
            new_cluster = ResponseCluster(
                signature=signature,
                urls=[url],
                count=1,
                is_error_page=self.is_error_page(content, status_code),
                is_soft_404=(status_code == 200 and self.is_error_page(content, status_code)),
                is_boring=self.is_boring_page(content, signature.title)
            )
            self.clusters.append(new_cluster)
            return new_cluster, True
    
    def get_unique_responses(self) -> List[ResponseCluster]:
        """
        Get list of unique response clusters
        
        Returns:
            List of ResponseCluster objects
        """
        return self.clusters
    
    def get_interesting_clusters(self) -> List[ResponseCluster]:
        """
        Get clusters that are potentially interesting (not errors or boring pages)
        
        Returns:
            List of interesting ResponseCluster objects
        """
        return [
            c for c in self.clusters
            if not c.is_error_page and not c.is_soft_404 and not c.is_boring
        ]
    
    def get_statistics(self) -> Dict:
        """
        Get analysis statistics
        
        Returns:
            Statistics dictionary
        """
        total_urls = sum(c.count for c in self.clusters)
        unique_responses = len(self.clusters)
        error_clusters = sum(1 for c in self.clusters if c.is_error_page)
        soft_404_clusters = sum(1 for c in self.clusters if c.is_soft_404)
        boring_clusters = sum(1 for c in self.clusters if c.is_boring)
        interesting_clusters = len(self.get_interesting_clusters())
        
        return {
            'total_urls_analyzed': total_urls,
            'unique_response_patterns': unique_responses,
            'error_page_clusters': error_clusters,
            'soft_404_clusters': soft_404_clusters,
            'boring_page_clusters': boring_clusters,
            'interesting_clusters': interesting_clusters,
            'duplicate_ratio': 1 - (unique_responses / total_urls) if total_urls > 0 else 0,
        }


if __name__ == "__main__":
    # Example usage
    analyzer = ResponseAnalyzer(similarity_threshold=0.8)
    
    # Simulate some responses
    sample_404 = "<html><head><title>404 Not Found</title></head><body><h1>Page not found</h1></body></html>"
    sample_200 = "<html><head><title>Home Page</title></head><body><h1>Welcome</h1><p>Content here</p></body></html>"
    
    # Add responses
    analyzer.add_response("http://example.com/page1", sample_404, 404)
    analyzer.add_response("http://example.com/page2", sample_404, 404)  # Duplicate
    analyzer.add_response("http://example.com/page3", sample_404, 404)  # Duplicate
    analyzer.add_response("http://example.com/home", sample_200, 200)
    
    # Get stats
    stats = analyzer.get_statistics()
    print("Response Analysis Statistics:")
    print(f"  Total URLs: {stats['total_urls_analyzed']}")
    print(f"  Unique patterns: {stats['unique_response_patterns']}")
    print(f"  Error pages: {stats['error_page_clusters']}")
    print(f"  Interesting: {stats['interesting_clusters']}")
    print(f"  Duplicate ratio: {stats['duplicate_ratio']:.1%}")
    
    print("\nClusters:")
    for i, cluster in enumerate(analyzer.get_unique_responses()):
        print(f"\n  Cluster {i+1}:")
        print(f"    Status: {cluster.signature.status_code}")
        print(f"    URLs: {cluster.count}")
        print(f"    Error page: {cluster.is_error_page}")
        print(f"    Sample: {cluster.urls[0]}")
