#!/usr/bin/env python3
"""
Enhanced HTTP Client with Redirect Following, Retry Logic, and Response Analysis
"""

import requests
import time
import hashlib
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
import dns.resolver
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class RedirectChain:
    """Stores information about redirect chain"""
    original_url: str
    final_url: str
    redirects: List[Dict] = field(default_factory=list)
    status_codes: List[int] = field(default_factory=list)
    redirect_count: int = 0
    
    def add_redirect(self, url: str, status_code: int):
        self.redirects.append({"url": url, "status_code": status_code})
        self.status_codes.append(status_code)
        self.redirect_count += 1


@dataclass
class EnhancedResponse:
    """Enhanced response with additional metadata"""
    url: str
    status_code: int
    headers: Dict
    content: bytes
    text: str
    content_length: int
    content_hash: str
    redirect_chain: Optional[RedirectChain] = None
    is_meaningful: bool = True
    similarity_score: float = 0.0


class EnhancedHTTPClient:
    """
    Enhanced HTTP client with:
    - Redirect following with chain tracking
    - Exponential backoff retry logic
    - Multiple DNS server support
    - Response content analysis
    - Similarity detection
    """
    
    # DNS servers to try in order
    DNS_SERVERS = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222']
    
    def __init__(self, user_agent: str = None, rate_limit: float = 1.0, timeout: int = 10):
        """
        Initialize enhanced HTTP client
        
        Args:
            user_agent: Custom User-Agent string
            rate_limit: Requests per second limit
            timeout: Request timeout in seconds
        """
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.last_request_time = 0
        
        # Create session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Response cache for similarity detection
        self.response_cache: Dict[str, EnhancedResponse] = {}
    
    def _apply_rate_limit(self):
        """Apply rate limiting between requests"""
        if self.rate_limit > 0:
            elapsed = time.time() - self.last_request_time
            min_interval = 1.0 / self.rate_limit
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
        self.last_request_time = time.time()
    
    def resolve_with_multiple_servers(self, domain: str) -> List[str]:
        """
        Try to resolve domain using multiple DNS servers
        
        Args:
            domain: Domain to resolve
            
        Returns:
            List of IP addresses
        """
        for dns_server in self.DNS_SERVERS:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = 2
                resolver.lifetime = 2
                
                answers = resolver.resolve(domain, 'A')
                return [str(rdata) for rdata in answers]
            except Exception:
                continue
        
        return []
    
    def calculate_content_hash(self, content: bytes) -> str:
        """Calculate SHA256 hash of content"""
        return hashlib.sha256(content).hexdigest()
    
    def calculate_similarity(self, content1: bytes, content2: bytes) -> float:
        """
        Calculate similarity between two responses
        
        Returns:
            Similarity score between 0.0 and 1.0
        """
        if content1 == content2:
            return 1.0
        
        # Simple similarity based on length difference
        len1, len2 = len(content1), len(content2)
        if len1 == 0 and len2 == 0:
            return 1.0
        
        max_len = max(len1, len2)
        min_len = min(len1, len2)
        
        # Calculate length-based similarity
        length_similarity = min_len / max_len if max_len > 0 else 0
        
        # If very similar length, compare hashes
        if length_similarity > 0.95:
            hash1 = self.calculate_content_hash(content1)
            hash2 = self.calculate_content_hash(content2)
            return 1.0 if hash1 == hash2 else 0.9
        
        return length_similarity
    
    def is_content_meaningful(self, response: requests.Response) -> bool:
        """
        Determine if response content is meaningful (not error page or empty)
        
        Args:
            response: HTTP response object
            
        Returns:
            True if content appears meaningful
        """
        # Check status code
        if response.status_code >= 400:
            return False
        
        # Check content length
        content_length = len(response.content)
        if content_length < 100:  # Too small to be meaningful
            return False
        
        # Check for common error indicators
        text_lower = response.text.lower()
        error_indicators = [
            'page not found',
            '404 not found',
            'error 404',
            'not found',
            'access denied',
            'forbidden',
            'unauthorized',
            'this page does not exist',
            'file not found',
        ]
        
        for indicator in error_indicators:
            if indicator in text_lower:
                return False
        
        # Check content type
        content_type = response.headers.get('Content-Type', '').lower()
        if 'text/html' in content_type or 'application/json' in content_type:
            return True
        
        return content_length > 500  # Likely meaningful if substantial content
    
    def get_with_redirects(self, url: str, max_redirects: int = 3, 
                          method: str = 'GET', **kwargs) -> Tuple[Optional[EnhancedResponse], Optional[RedirectChain]]:
        """
        Perform HTTP request with redirect chain tracking
        
        Args:
            url: URL to request
            max_redirects: Maximum number of redirects to follow
            method: HTTP method (GET, POST, etc.)
            **kwargs: Additional arguments for requests
            
        Returns:
            Tuple of (EnhancedResponse, RedirectChain)
        """
        self._apply_rate_limit()
        
        redirect_chain = RedirectChain(original_url=url, final_url=url)
        current_url = url
        
        headers = kwargs.get('headers', {})
        headers['User-Agent'] = self.user_agent
        kwargs['headers'] = headers
        kwargs['timeout'] = self.timeout
        
        for i in range(max_redirects + 1):
            try:
                # Make request without following redirects
                kwargs['allow_redirects'] = False
                response = self.session.request(method, current_url, **kwargs)
                
                # Check if this is a redirect
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location')
                    if not location:
                        break
                    
                    # Handle relative URLs
                    next_url = urljoin(current_url, location)
                    redirect_chain.add_redirect(current_url, response.status_code)
                    current_url = next_url
                    
                    # Check if we've hit max redirects
                    if i >= max_redirects:
                        break
                else:
                    # Not a redirect, this is our final response
                    redirect_chain.final_url = current_url
                    
                    content_hash = self.calculate_content_hash(response.content)
                    is_meaningful = self.is_content_meaningful(response)
                    
                    enhanced_response = EnhancedResponse(
                        url=current_url,
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        content=response.content,
                        text=response.text,
                        content_length=len(response.content),
                        content_hash=content_hash,
                        redirect_chain=redirect_chain,
                        is_meaningful=is_meaningful
                    )
                    
                    return enhanced_response, redirect_chain
                    
            except requests.RequestException as e:
                # Request failed
                return None, redirect_chain
        
        # Max redirects reached
        return None, redirect_chain
    
    def request_with_retry(self, url: str, max_retries: int = 3, 
                          method: str = 'GET', **kwargs) -> Optional[EnhancedResponse]:
        """
        Perform HTTP request with exponential backoff retry
        
        Args:
            url: URL to request
            max_retries: Maximum number of retry attempts
            method: HTTP method
            **kwargs: Additional arguments for requests
            
        Returns:
            EnhancedResponse or None
        """
        for attempt in range(max_retries):
            try:
                response, redirect_chain = self.get_with_redirects(url, method=method, **kwargs)
                if response:
                    return response
            except Exception as e:
                if attempt < max_retries - 1:
                    # Exponential backoff: 1s, 2s, 4s
                    wait_time = 2 ** attempt
                    time.sleep(wait_time)
                    continue
                return None
        
        return None
    
    def get(self, url: str, **kwargs) -> Optional[EnhancedResponse]:
        """Convenience method for GET requests"""
        return self.request_with_retry(url, method='GET', **kwargs)
    
    def post(self, url: str, **kwargs) -> Optional[EnhancedResponse]:
        """Convenience method for POST requests"""
        return self.request_with_retry(url, method='POST', **kwargs)
    
    def head(self, url: str, **kwargs) -> Optional[EnhancedResponse]:
        """Convenience method for HEAD requests"""
        return self.request_with_retry(url, method='HEAD', **kwargs)
    
    def find_similar_responses(self, response: EnhancedResponse, threshold: float = 0.9) -> List[str]:
        """
        Find cached responses similar to the given response
        
        Args:
            response: Response to compare
            threshold: Similarity threshold (0.0 to 1.0)
            
        Returns:
            List of URLs with similar responses
        """
        similar_urls = []
        
        for cached_url, cached_response in self.response_cache.items():
            similarity = self.calculate_similarity(response.content, cached_response.content)
            if similarity >= threshold:
                similar_urls.append(cached_url)
        
        return similar_urls
    
    def cache_response(self, response: EnhancedResponse):
        """Cache response for similarity detection"""
        self.response_cache[response.url] = response
    
    def is_duplicate_response(self, response: EnhancedResponse, threshold: float = 0.95) -> bool:
        """
        Check if response is duplicate of a cached response
        
        Args:
            response: Response to check
            threshold: Similarity threshold
            
        Returns:
            True if duplicate found
        """
        similar = self.find_similar_responses(response, threshold)
        return len(similar) > 0
