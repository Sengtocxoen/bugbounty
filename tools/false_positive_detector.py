#!/usr/bin/env python3
"""
False Positive Detection Module
Detects and filters false positives in vulnerability scanning:
- Redirect chain analysis (auth/middleware page detection)
- Baseline response comparison
- Soft 404 detection
- Content-type validation
- Response fingerprinting
"""

import re
import hashlib
import time
import threading
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Tuple, Callable
from urllib.parse import urlparse, urljoin
from difflib import SequenceMatcher
from collections import defaultdict

try:
    import requests
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    exit(1)


@dataclass
class ResponseFingerprint:
    """Fingerprint of an HTTP response for comparison"""
    url: str
    status_code: int
    content_length: int
    content_hash: str
    content_type: str
    title: Optional[str] = None
    redirect_url: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    is_error_page: bool = False
    is_auth_page: bool = False
    is_soft_404: bool = False
    body_sample: str = ""  # First 500 chars for comparison


@dataclass
class FalsePositiveResult:
    """Result of false positive analysis"""
    is_false_positive: bool
    confidence: str  # high, medium, low
    reason: str
    details: Dict = field(default_factory=dict)


# Patterns that indicate auth/login pages
AUTH_PAGE_PATTERNS = [
    # URL patterns
    r'/login', r'/signin', r'/sign-in', r'/auth', r'/authenticate',
    r'/sso', r'/saml', r'/oauth', r'/cas', r'/adfs',
    r'/account/login', r'/user/login', r'/session', r'/security',

    # Content patterns (case insensitive)
    r'<title>.*(?:login|sign\s*in|authenticate|access\s*denied).*</title>',
    r'<form[^>]*(?:login|signin|auth)',
    r'name=["\'](?:username|email|password|credential)["\']',
    r'id=["\'](?:login|signin|auth)[-_]?(?:form|button|submit)',
    r'(?:enter|input)\s+(?:your\s+)?(?:username|email|password)',
    r'(?:forgot|reset)\s+(?:your\s+)?password',
    r'(?:don\'?t\s+have\s+an?\s+)?account\s*\?',
    r'please\s+(?:log\s*in|sign\s*in|authenticate)',
    r'session\s+(?:expired|timeout|invalid)',
    r'access\s+denied',
    r'unauthorized',
    r'authentication\s+required',
]

# Patterns that indicate error/soft 404 pages
ERROR_PAGE_PATTERNS = [
    r'<title>.*(?:404|not\s*found|error|oops|page\s*not).*</title>',
    r'(?:page|resource|file)\s+(?:not\s+found|doesn\'?t\s+exist)',
    r'(?:404|not\s*found)\s*(?:error)?',
    r'(?:the|this)\s+page\s+(?:you\s+(?:are\s+)?look|doesn\'?t|could\s+not)',
    r'(?:sorry|oops),?\s+(?:we\s+)?(?:couldn\'?t|can\'?t)\s+find',
    r'(?:invalid|unknown)\s+(?:page|url|path|resource)',
    r'(?:no\s+)?(?:results?|matches?)\s+found',
]

# Common redirect destinations that indicate false positives
REDIRECT_SINKS = [
    '/login', '/signin', '/auth', '/sso', '/unauthorized',
    '/error', '/404', '/access-denied', '/forbidden',
    '/home', '/index', '/welcome', '/landing',
]


class FalsePositiveDetector:
    """
    Detects false positives by analyzing responses and comparing against baselines.

    Key features:
    - Tracks redirect patterns to identify auth/middleware pages
    - Maintains baseline responses for comparison
    - Detects soft 404s that return 200 status codes
    - Validates that response content matches expected vulnerability indicators
    """

    def __init__(self, session: requests.Session = None, rate_limit: float = 5.0):
        self.session = session or requests.Session()
        self.rate_limit = rate_limit
        self.min_interval = 1.0 / rate_limit
        self.last_request = 0.0
        self.lock = threading.Lock()

        # Cache for baselines and fingerprints
        self.baseline_cache: Dict[str, ResponseFingerprint] = {}
        self.redirect_destinations: Dict[str, int] = defaultdict(int)
        self.auth_page_fingerprints: Set[str] = set()
        self.error_page_fingerprints: Set[str] = set()

        # Statistics
        self.stats = {
            'requests_made': 0,
            'false_positives_detected': 0,
            'auth_redirects': 0,
            'soft_404s': 0,
        }

    def _rate_limit_wait(self):
        """Wait to respect rate limit"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_request
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_request = time.time()
            self.stats['requests_made'] += 1

    def _make_request(self, url: str, method: str = "GET",
                      follow_redirects: bool = False, **kwargs) -> Optional[requests.Response]:
        """Make a rate-limited request"""
        self._rate_limit_wait()
        try:
            kwargs.setdefault('timeout', 10)
            kwargs.setdefault('allow_redirects', follow_redirects)
            response = self.session.request(method, url, **kwargs)
            return response
        except Exception:
            return None

    def _extract_title(self, html: str) -> Optional[str]:
        """Extract page title from HTML"""
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else None

    def _compute_content_hash(self, content: str) -> str:
        """Compute a normalized hash of content (ignoring dynamic elements)"""
        # Remove common dynamic elements
        normalized = content
        # Remove CSRF tokens, nonces, timestamps
        normalized = re.sub(r'(?:csrf|nonce|token|timestamp)["\']?\s*[:=]\s*["\']?[\w\-]+["\']?', '', normalized, flags=re.IGNORECASE)
        # Remove session IDs
        normalized = re.sub(r'(?:session|sid|jsessionid)["\']?\s*[:=]\s*["\']?[\w\-]+["\']?', '', normalized, flags=re.IGNORECASE)
        # Remove numbers that might be timestamps
        normalized = re.sub(r'\d{10,13}', '', normalized)
        # Remove UUIDs
        normalized = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '', normalized, flags=re.IGNORECASE)

        return hashlib.md5(normalized.encode()).hexdigest()

    def _is_auth_page(self, url: str, content: str) -> bool:
        """Check if response is an auth/login page"""
        url_lower = url.lower()
        content_lower = content.lower()

        # Check URL patterns
        for pattern in AUTH_PAGE_PATTERNS[:10]:  # URL patterns
            if re.search(pattern, url_lower):
                return True

        # Check content patterns
        for pattern in AUTH_PAGE_PATTERNS[10:]:  # Content patterns
            if re.search(pattern, content_lower):
                return True

        return False

    def _is_error_page(self, content: str) -> bool:
        """Check if response is an error page"""
        content_lower = content.lower()

        for pattern in ERROR_PAGE_PATTERNS:
            if re.search(pattern, content_lower):
                return True

        return False

    def _follow_redirect_chain(self, url: str, max_redirects: int = 10) -> Tuple[List[str], Optional[requests.Response]]:
        """Follow redirect chain and return all URLs visited"""
        chain = [url]
        current_url = url
        final_response = None

        for _ in range(max_redirects):
            response = self._make_request(current_url, follow_redirects=False)
            if not response:
                break

            final_response = response

            if response.status_code not in [301, 302, 303, 307, 308]:
                break

            location = response.headers.get('Location', '')
            if not location:
                break

            # Resolve relative URLs
            next_url = urljoin(current_url, location)
            chain.append(next_url)
            current_url = next_url

        return chain, final_response

    def fingerprint_response(self, url: str, response: requests.Response = None,
                             follow_redirects: bool = True) -> ResponseFingerprint:
        """Create a fingerprint of an HTTP response"""
        if response is None:
            if follow_redirects:
                chain, response = self._follow_redirect_chain(url)
            else:
                response = self._make_request(url, follow_redirects=False)
                chain = [url]
        else:
            chain = [url]

        if not response:
            return ResponseFingerprint(
                url=url,
                status_code=0,
                content_length=0,
                content_hash="",
                content_type="",
                is_error_page=True
            )

        content = response.text or ""
        content_type = response.headers.get('Content-Type', '')

        # Get redirect URL if applicable
        redirect_url = None
        if response.status_code in [301, 302, 303, 307, 308]:
            redirect_url = response.headers.get('Location', '')
        elif len(chain) > 1:
            redirect_url = chain[-1]

        # Track redirect destination frequency
        if redirect_url:
            parsed = urlparse(redirect_url)
            self.redirect_destinations[parsed.path] += 1

        fingerprint = ResponseFingerprint(
            url=url,
            status_code=response.status_code,
            content_length=len(content),
            content_hash=self._compute_content_hash(content),
            content_type=content_type,
            title=self._extract_title(content),
            redirect_url=redirect_url,
            redirect_chain=chain,
            is_error_page=self._is_error_page(content),
            is_auth_page=self._is_auth_page(url if not redirect_url else redirect_url, content),
            body_sample=content[:500]
        )

        # Cache auth page fingerprints
        if fingerprint.is_auth_page:
            self.auth_page_fingerprints.add(fingerprint.content_hash)

        # Cache error page fingerprints
        if fingerprint.is_error_page:
            self.error_page_fingerprints.add(fingerprint.content_hash)

        return fingerprint

    def get_baseline(self, base_url: str, force_refresh: bool = False) -> ResponseFingerprint:
        """Get or create a baseline fingerprint for a URL"""
        parsed = urlparse(base_url)
        baseline_key = f"{parsed.scheme}://{parsed.netloc}"

        if baseline_key in self.baseline_cache and not force_refresh:
            return self.baseline_cache[baseline_key]

        # Create baseline from root URL
        baseline = self.fingerprint_response(baseline_key)

        # Also get a 404 baseline
        random_path = f"{baseline_key}/nonexistent_path_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        not_found_baseline = self.fingerprint_response(random_path)
        not_found_baseline.is_soft_404 = not_found_baseline.status_code == 200

        # Store baselines
        self.baseline_cache[baseline_key] = baseline
        self.baseline_cache[f"{baseline_key}:404"] = not_found_baseline

        return baseline

    def compare_responses(self, fp1: ResponseFingerprint, fp2: ResponseFingerprint) -> float:
        """Compare two response fingerprints, return similarity score (0-1)"""
        if fp1.content_hash == fp2.content_hash:
            return 1.0

        # Compare multiple aspects
        scores = []

        # Status code match
        scores.append(1.0 if fp1.status_code == fp2.status_code else 0.0)

        # Content length similarity
        max_len = max(fp1.content_length, fp2.content_length, 1)
        len_diff = abs(fp1.content_length - fp2.content_length) / max_len
        scores.append(max(0, 1 - len_diff))

        # Title match
        if fp1.title and fp2.title:
            scores.append(1.0 if fp1.title.lower() == fp2.title.lower() else 0.0)

        # Content type match
        ct1 = fp1.content_type.split(';')[0].strip() if fp1.content_type else ''
        ct2 = fp2.content_type.split(';')[0].strip() if fp2.content_type else ''
        scores.append(1.0 if ct1 == ct2 else 0.0)

        # Body sample similarity
        if fp1.body_sample and fp2.body_sample:
            similarity = SequenceMatcher(None, fp1.body_sample, fp2.body_sample).ratio()
            scores.append(similarity)

        return sum(scores) / len(scores) if scores else 0.0

    def is_redirect_to_auth(self, fingerprint: ResponseFingerprint) -> bool:
        """Check if response redirects to an auth/login page"""
        if not fingerprint.redirect_url:
            return fingerprint.is_auth_page

        # Check redirect URL for auth patterns
        redirect_path = urlparse(fingerprint.redirect_url).path.lower()
        for sink in REDIRECT_SINKS[:5]:  # Auth-related sinks
            if sink in redirect_path:
                return True

        # Check if redirect destination is a known auth page
        if fingerprint.content_hash in self.auth_page_fingerprints:
            return True

        return fingerprint.is_auth_page

    def is_soft_404(self, fingerprint: ResponseFingerprint, base_url: str = None) -> bool:
        """Check if response is a soft 404"""
        if fingerprint.status_code != 200:
            return False

        # Check against cached error page fingerprints
        if fingerprint.content_hash in self.error_page_fingerprints:
            return True

        # Check error page patterns
        if fingerprint.is_error_page:
            return True

        # Compare to 404 baseline if available
        if base_url:
            parsed = urlparse(base_url)
            baseline_key = f"{parsed.scheme}://{parsed.netloc}:404"
            if baseline_key in self.baseline_cache:
                not_found = self.baseline_cache[baseline_key]
                similarity = self.compare_responses(fingerprint, not_found)
                if similarity > 0.85:
                    return True

        return False

    def is_common_redirect_destination(self, path: str, threshold: int = 3) -> bool:
        """Check if a path is a common redirect destination (likely middleware)"""
        return self.redirect_destinations.get(path, 0) >= threshold

    def analyze_for_false_positive(self, url: str, response: requests.Response,
                                   vuln_type: str, payload: str = "",
                                   evidence_func: Callable = None) -> FalsePositiveResult:
        """
        Comprehensive false positive analysis for a vulnerability finding.

        Args:
            url: The tested URL
            response: The HTTP response
            vuln_type: Type of vulnerability being tested
            payload: The payload used in testing
            evidence_func: Function to verify evidence is valid

        Returns:
            FalsePositiveResult with determination and reasoning
        """
        fingerprint = self.fingerprint_response(url, response, follow_redirects=False)

        # Get baseline for comparison
        baseline = self.get_baseline(url)

        # Check 1: Is this an auth page redirect?
        if self.is_redirect_to_auth(fingerprint):
            self.stats['auth_redirects'] += 1
            self.stats['false_positives_detected'] += 1
            return FalsePositiveResult(
                is_false_positive=True,
                confidence="high",
                reason="Response redirects to authentication page",
                details={
                    'redirect_url': fingerprint.redirect_url,
                    'redirect_chain': fingerprint.redirect_chain,
                    'is_auth_page': True
                }
            )

        # Check 2: Is this a soft 404?
        if self.is_soft_404(fingerprint, url):
            self.stats['soft_404s'] += 1
            self.stats['false_positives_detected'] += 1
            return FalsePositiveResult(
                is_false_positive=True,
                confidence="high",
                reason="Response is a soft 404 error page",
                details={
                    'title': fingerprint.title,
                    'is_error_page': True
                }
            )

        # Check 3: Does response match a common redirect destination?
        if fingerprint.redirect_url:
            redirect_path = urlparse(fingerprint.redirect_url).path
            if self.is_common_redirect_destination(redirect_path):
                self.stats['false_positives_detected'] += 1
                return FalsePositiveResult(
                    is_false_positive=True,
                    confidence="medium",
                    reason=f"Redirects to common destination: {redirect_path}",
                    details={
                        'redirect_path': redirect_path,
                        'occurrence_count': self.redirect_destinations[redirect_path]
                    }
                )

        # Check 4: Does response match baseline too closely? (no actual processing)
        similarity = self.compare_responses(fingerprint, baseline)
        if similarity > 0.95 and vuln_type not in ['cors', 'security_headers']:
            return FalsePositiveResult(
                is_false_positive=True,
                confidence="medium",
                reason="Response identical to baseline (payload not processed)",
                details={
                    'similarity': similarity,
                    'baseline_hash': baseline.content_hash,
                    'response_hash': fingerprint.content_hash
                }
            )

        # Check 5: Content type validation
        content_type = fingerprint.content_type.lower()
        html_required_vulns = ['xss', 'ssti', 'open_redirect']
        if vuln_type in html_required_vulns:
            if 'text/html' not in content_type and 'application/xhtml' not in content_type:
                return FalsePositiveResult(
                    is_false_positive=True,
                    confidence="medium",
                    reason=f"Response is not HTML ({content_type}), cannot contain {vuln_type}",
                    details={'content_type': content_type}
                )

        # Check 6: Custom evidence validation
        if evidence_func:
            evidence_valid = evidence_func(response, payload)
            if not evidence_valid:
                return FalsePositiveResult(
                    is_false_positive=True,
                    confidence="high",
                    reason="Evidence validation failed",
                    details={'evidence_func': evidence_func.__name__}
                )

        # Passed all checks - likely genuine
        return FalsePositiveResult(
            is_false_positive=False,
            confidence="high",
            reason="Passed all false positive checks",
            details={
                'fingerprint': {
                    'status_code': fingerprint.status_code,
                    'content_length': fingerprint.content_length,
                    'title': fingerprint.title,
                    'is_auth_page': fingerprint.is_auth_page,
                    'is_error_page': fingerprint.is_error_page
                }
            }
        )

    def validate_sqli_evidence(self, response: requests.Response, payload: str) -> bool:
        """Validate SQL injection evidence is genuine, not just keyword match"""
        content = response.text.lower()

        # False positive patterns - tech names in non-error contexts
        fp_patterns = [
            r'powered\s+by\s+(?:mysql|postgresql|oracle)',
            r'database:\s+(?:mysql|postgresql)',
            r'<!--.*(?:mysql|postgresql|oracle).*-->',
            r'copyright.*(?:mysql|oracle)',
        ]

        for pattern in fp_patterns:
            if re.search(pattern, content):
                # Check if there's also a real error
                error_patterns = [
                    r'sql\s+syntax.*error',
                    r'unclosed\s+quotation',
                    r'unterminated\s+string',
                    r'unexpected\s+end\s+of\s+(?:sql\s+)?command',
                    r'(?:mysql|pg|ora)\d{4,5}',  # Error codes
                ]
                if not any(re.search(ep, content) for ep in error_patterns):
                    return False

        return True

    def validate_xss_evidence(self, response: requests.Response, payload: str) -> bool:
        """Validate XSS reflection is in executable context, not escaped/commented"""
        content = response.text

        if payload not in content:
            return False

        # Check if payload is in HTML comment
        comment_pattern = r'<!--[^>]*' + re.escape(payload) + r'[^>]*-->'
        if re.search(comment_pattern, content):
            return False

        # Check if payload is in script string (might be escaped)
        # Look for payload in quotes after escaping characters
        escaped_patterns = [
            r'["\'].*\\x3c.*' + re.escape(payload.replace('<', '')),
            r'&lt;' + re.escape(payload.replace('<', '')),
            r'%3c' + re.escape(payload.replace('<', '')).lower(),
        ]
        for pattern in escaped_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return False

        # Check if in proper HTML context (not attribute value that's quoted)
        # This is a simplified check - real XSS validation needs DOM parsing
        return True

    def validate_ssti_evidence(self, response: requests.Response, payload: str) -> bool:
        """Validate SSTI evidence - check if '49' is from template evaluation"""
        content = response.text

        if '49' not in content:
            return False

        # Check if '49' appears in likely false positive contexts
        fp_patterns = [
            r'error\s*[:\-]?\s*49',
            r'page\s*49',
            r'item\s*49',
            r'id["\']?\s*[:=]\s*["\']?49',
            r'\.49\.',  # File extension or version
            r'\d49\d',  # Part of larger number
            r'49%',  # Percentage
            r'\$49',  # Price
        ]

        # Find all '49' occurrences
        for match in re.finditer(r'(?<!\d)49(?!\d)', content):
            start = max(0, match.start() - 50)
            end = min(len(content), match.end() + 50)
            context = content[start:end].lower()

            # Check if this '49' is in a false positive context
            is_fp = False
            for pattern in fp_patterns:
                if re.search(pattern, context):
                    is_fp = True
                    break

            if not is_fp:
                # Found a '49' that's not in FP context - could be real
                return True

        return False

    def get_stats(self) -> Dict:
        """Get detection statistics"""
        return dict(self.stats)

    def reset_stats(self):
        """Reset detection statistics"""
        self.stats = {
            'requests_made': 0,
            'false_positives_detected': 0,
            'auth_redirects': 0,
            'soft_404s': 0,
        }


class RedirectTracker:
    """
    Tracks redirect patterns across multiple requests to identify
    middleware/auth page redirects that cause false positives.
    """

    def __init__(self):
        self.redirect_map: Dict[str, List[str]] = defaultdict(list)
        self.destination_counts: Dict[str, int] = defaultdict(int)
        self.common_destinations: Set[str] = set()
        self.threshold = 5  # Number of times a destination must appear to be "common"

    def record_redirect(self, source_url: str, destination_url: str):
        """Record a redirect from source to destination"""
        self.redirect_map[source_url].append(destination_url)

        # Track destination frequency
        parsed = urlparse(destination_url)
        dest_path = parsed.path
        self.destination_counts[dest_path] += 1

        # Update common destinations
        if self.destination_counts[dest_path] >= self.threshold:
            self.common_destinations.add(dest_path)

    def is_suspicious_redirect(self, destination_url: str) -> bool:
        """Check if destination is suspiciously common (likely auth/middleware)"""
        parsed = urlparse(destination_url)
        return parsed.path in self.common_destinations

    def get_redirect_summary(self) -> Dict:
        """Get summary of redirect patterns"""
        return {
            'total_redirects': sum(len(v) for v in self.redirect_map.values()),
            'unique_sources': len(self.redirect_map),
            'common_destinations': list(self.common_destinations),
            'destination_counts': dict(sorted(
                self.destination_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10])
        }


# Evidence validators for different vulnerability types
EVIDENCE_VALIDATORS = {
    'sqli': lambda fp, resp, payload: fp.validate_sqli_evidence(resp, payload),
    'xss': lambda fp, resp, payload: fp.validate_xss_evidence(resp, payload),
    'ssti': lambda fp, resp, payload: fp.validate_ssti_evidence(resp, payload),
}


def create_detector(session: requests.Session = None, rate_limit: float = 5.0) -> FalsePositiveDetector:
    """Factory function to create a configured false positive detector"""
    return FalsePositiveDetector(session=session, rate_limit=rate_limit)


if __name__ == "__main__":
    # Demo/test mode
    print("False Positive Detector Module")
    print("=" * 50)
    print("\nThis module provides:")
    print("  - Redirect chain analysis")
    print("  - Auth/login page detection")
    print("  - Soft 404 detection")
    print("  - Baseline response comparison")
    print("  - Evidence validation for SQLi, XSS, SSTI")
    print("\nUsage:")
    print("  from false_positive_detector import FalsePositiveDetector")
    print("  detector = FalsePositiveDetector()")
    print("  result = detector.analyze_for_false_positive(url, response, 'xss')")
    print("  if result.is_false_positive:")
    print("      print(f'False positive: {result.reason}')")
