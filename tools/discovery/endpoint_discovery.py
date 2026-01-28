#!/usr/bin/env python3
"""
Endpoint Discovery Module
Discovers endpoints on web applications using:
- robots.txt parsing
- sitemap.xml parsing
- Common path brute-forcing
- JavaScript file analysis
- HTML link extraction

Includes false positive detection for:
- Soft 404 pages (200 status but actually error)
- Auth/middleware redirects
- Generic error pages

Respects rate limits for bug bounty compliance.
"""

import re
import json
import time
import hashlib
import threading
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher
import xml.etree.ElementTree as ET

try:
    import requests
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    exit(1)

from utils.config import get_amazon_config, get_shopify_config
from analysis.false_positive_detector import FalsePositiveDetector, RedirectTracker


@dataclass
class Endpoint:
    """Represents a discovered endpoint"""
    url: str
    method: str = "GET"
    source: str = ""  # robots.txt, sitemap, js, html, bruteforce
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    parameters: List[str] = field(default_factory=list)
    interesting: bool = False
    notes: str = ""
    # False positive detection fields
    verified: bool = True  # Passed FP checks
    is_soft_404: bool = False
    is_auth_redirect: bool = False
    redirect_destination: Optional[str] = None


@dataclass
class EndpointResult:
    """Results from endpoint discovery"""
    target: str
    endpoints: List[Endpoint] = field(default_factory=list)
    js_files: Set[str] = field(default_factory=set)
    api_endpoints: Set[str] = field(default_factory=set)
    forms: List[Dict] = field(default_factory=list)
    discovery_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())


# Common paths to check for interesting endpoints
COMMON_PATHS = [
    # API endpoints
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/graphql", "/graphql/console", "/graphiql",
    "/rest", "/json", "/xml",

    # Admin & authentication
    "/admin", "/administrator", "/login", "/logout",
    "/signin", "/signup", "/register", "/auth",
    "/oauth", "/oauth2", "/sso", "/saml",
    "/password", "/forgot-password", "/reset-password",
    "/account", "/profile", "/settings", "/preferences",

    # Common files
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.well-known/security.txt", "/.well-known/openid-configuration",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/swagger.json", "/swagger.yaml", "/openapi.json",
    "/api-docs", "/docs", "/documentation",

    # Development/debug
    "/debug", "/trace", "/test", "/phpinfo.php",
    "/info", "/status", "/health", "/healthcheck",
    "/metrics", "/actuator", "/actuator/health",
    "/console", "/terminal", "/shell",

    # Sensitive files
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.env", "/.env.local", "/.env.production",
    "/config.json", "/config.yaml", "/config.xml",
    "/package.json", "/composer.json",
    "/web.config", "/wp-config.php.bak",
    "/.htaccess", "/.htpasswd",
    "/server-status", "/server-info",

    # Backup files
    "/backup", "/backups", "/backup.sql", "/backup.zip",
    "/db.sql", "/database.sql", "/dump.sql",

    # Error pages (information disclosure)
    "/error", "/errors", "/404", "/500",

    # Search & data
    "/search", "/query", "/find", "/lookup",
    "/export", "/import", "/download", "/upload",

    # User data
    "/users", "/user", "/members", "/customers",
    "/orders", "/invoices", "/payments",

    # Internal tools
    "/jenkins", "/gitlab", "/jira", "/confluence",
    "/kibana", "/grafana", "/prometheus",
    "/phpmyadmin", "/adminer", "/mysql",
    "/redis", "/memcached", "/elasticsearch",
]

# Patterns that indicate interesting endpoints
INTERESTING_PATTERNS = [
    r'/api/', r'/v\d+/', r'/graphql',
    r'/admin', r'/internal', r'/debug',
    r'/auth', r'/oauth', r'/login',
    r'/upload', r'/download', r'/export',
    r'/user', r'/account', r'/profile',
    r'/config', r'/settings', r'/preferences',
    r'\.(json|xml|yaml|yml)$',
    r'/swagger', r'/openapi', r'/docs',
    r'/backup', r'/dump', r'/db',
    r'/token', r'/key', r'/secret',
]


class EndpointDiscovery:
    """Discover endpoints on web applications with FP detection"""

    def __init__(self, rate_limit: float = 5.0, user_agent: str = "BugBountyResearcher",
                 enable_fp_detection: bool = True):
        self.rate_limit = rate_limit
        self.min_interval = 1.0 / rate_limit
        self.last_request = 0.0
        self.lock = threading.Lock()
        self.user_agent = user_agent
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })

        # False positive detection
        self.enable_fp_detection = enable_fp_detection
        self.redirect_tracker = RedirectTracker() if enable_fp_detection else None

        # Baseline responses for soft 404 detection
        self.baseline_404: Dict[str, Dict] = {}  # domain -> {hash, length, title}
        self.baseline_home: Dict[str, Dict] = {}  # domain -> {hash, length, title}

        # Statistics
        self.stats = {
            'endpoints_found': 0,
            'soft_404s_filtered': 0,
            'auth_redirects_filtered': 0,
            'verified_endpoints': 0,
        }

    def _rate_limit_wait(self):
        """Wait to respect rate limit"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_request
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_request = time.time()

    def _request(self, url: str, method: str = "GET", follow_redirects: bool = True,
                 **kwargs) -> Optional[requests.Response]:
        """Make a rate-limited request"""
        self._rate_limit_wait()
        try:
            kwargs.setdefault('timeout', 10)
            kwargs.setdefault('allow_redirects', follow_redirects)
            kwargs.setdefault('verify', True)
            response = self.session.request(method, url, **kwargs)

            # Track redirects for FP detection
            if self.redirect_tracker and response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if location:
                    self.redirect_tracker.record_redirect(url, urljoin(url, location))

            return response
        except Exception:
            return None

    def _extract_title(self, html: str) -> Optional[str]:
        """Extract page title from HTML"""
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else None

    def _compute_content_hash(self, content: str) -> str:
        """Compute normalized hash ignoring dynamic content"""
        # Remove dynamic elements
        normalized = re.sub(r'(?:csrf|nonce|token|timestamp|session)["\']?\s*[:=]\s*["\']?[\w\-]+', '',
                           content, flags=re.IGNORECASE)
        normalized = re.sub(r'\d{10,13}', '', normalized)  # Timestamps
        return hashlib.md5(normalized.encode()).hexdigest()

    def _establish_baselines(self, base_url: str):
        """Establish baseline responses for soft 404 detection"""
        parsed = urlparse(base_url)
        domain = f"{parsed.scheme}://{parsed.netloc}"

        if domain in self.baseline_404:
            return  # Already established

        # Get 404 baseline with a random non-existent path
        random_path = f"/nonexistent_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        response_404 = self._request(f"{domain}{random_path}", follow_redirects=False)

        if response_404:
            content = response_404.text or ""
            self.baseline_404[domain] = {
                'hash': self._compute_content_hash(content),
                'length': len(content),
                'title': self._extract_title(content),
                'status': response_404.status_code,
            }
        else:
            self.baseline_404[domain] = {'hash': '', 'length': 0, 'title': None, 'status': 0}

        # Get homepage baseline
        response_home = self._request(domain, follow_redirects=False)

        if response_home:
            content = response_home.text or ""
            self.baseline_home[domain] = {
                'hash': self._compute_content_hash(content),
                'length': len(content),
                'title': self._extract_title(content),
                'status': response_home.status_code,
            }
        else:
            self.baseline_home[domain] = {'hash': '', 'length': 0, 'title': None, 'status': 0}

    def _is_soft_404(self, url: str, response: requests.Response) -> bool:
        """Check if response is a soft 404 (200 status but actually error)"""
        if response.status_code != 200:
            return False

        parsed = urlparse(url)
        domain = f"{parsed.scheme}://{parsed.netloc}"

        baseline = self.baseline_404.get(domain)
        if not baseline:
            return False

        content = response.text or ""
        content_hash = self._compute_content_hash(content)
        title = self._extract_title(content)

        # Check if matches 404 baseline exactly
        if content_hash == baseline['hash']:
            return True

        # Check title for error indicators
        if title:
            title_lower = title.lower()
            error_titles = ['404', 'not found', 'page not found', 'error',
                          'oops', 'sorry', 'missing', 'unavailable']
            if any(err in title_lower for err in error_titles):
                return True

        # Check content length similarity to 404 baseline
        if baseline['length'] > 0:
            length_ratio = abs(len(content) - baseline['length']) / max(baseline['length'], 1)
            if length_ratio < 0.1:  # Very similar length
                # Do detailed comparison
                baseline_404_resp = self.baseline_404.get(f"{domain}:content")
                if baseline_404_resp:
                    similarity = SequenceMatcher(None, content[:1000], baseline_404_resp[:1000]).ratio()
                    if similarity > 0.9:
                        return True

        # Check for error page patterns in content
        error_patterns = [
            r'page\s+(?:not\s+found|doesn\'?t\s+exist)',
            r'(?:404|not\s+found)\s+(?:error)?',
            r'(?:the|this)\s+(?:page|resource)\s+(?:you|was)',
            r'(?:sorry|oops),?\s+(?:we\s+)?(?:couldn\'?t|can\'?t)\s+find',
            r'(?:no\s+)?(?:results?|matches?)\s+found',
        ]

        content_lower = content.lower()
        if any(re.search(pattern, content_lower) for pattern in error_patterns):
            return True

        return False

    def _is_auth_redirect(self, response: requests.Response) -> Tuple[bool, Optional[str]]:
        """Check if response is a redirect to auth page"""
        if response.status_code not in [301, 302, 303, 307, 308]:
            return False, None

        location = response.headers.get('Location', '').lower()
        if not location:
            return False, None

        auth_indicators = [
            '/login', '/signin', '/sign-in', '/auth', '/authenticate',
            '/sso', '/saml', '/oauth', '/cas', '/session', '/security',
            '/account/login', '/user/login', '/access-denied', '/unauthorized',
            '/forbidden', 'returnurl=', 'redirect=', 'next=',
        ]

        if any(ind in location for ind in auth_indicators):
            return True, location

        # Check if redirect destination is a known common redirect
        if self.redirect_tracker:
            parsed = urlparse(location)
            if self.redirect_tracker.is_suspicious_redirect(location):
                return True, location

        return False, None

    def _verify_endpoint(self, url: str, response: requests.Response) -> Tuple[bool, str]:
        """Verify endpoint is real, not a soft 404 or auth redirect"""
        # Check for auth redirect
        is_auth, redirect_dest = self._is_auth_redirect(response)
        if is_auth:
            self.stats['auth_redirects_filtered'] += 1
            return False, f"Auth redirect to {redirect_dest}"

        # Check for soft 404
        if self._is_soft_404(url, response):
            self.stats['soft_404s_filtered'] += 1
            return False, "Soft 404 detected"

        self.stats['verified_endpoints'] += 1
        return True, "Verified"

    def _is_interesting(self, url: str) -> bool:
        """Check if URL matches interesting patterns"""
        for pattern in INTERESTING_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    def parse_robots_txt(self, base_url: str) -> List[Endpoint]:
        """Parse robots.txt for endpoints"""
        endpoints = []
        robots_url = urljoin(base_url, "/robots.txt")
        print(f"    [robots.txt] Checking {robots_url}")

        response = self._request(robots_url)
        if response and response.status_code == 200:
            for line in response.text.split('\n'):
                line = line.strip()
                if line.lower().startswith(('disallow:', 'allow:', 'sitemap:')):
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        path = parts[1].strip()
                        if path and not path.startswith('#'):
                            # Handle sitemap URLs
                            if line.lower().startswith('sitemap:'):
                                url = path
                            else:
                                # Handle wildcards
                                path = path.replace('*', '')
                                if path:
                                    url = urljoin(base_url, path)
                                else:
                                    continue

                            endpoint = Endpoint(
                                url=url,
                                source="robots.txt",
                                interesting=self._is_interesting(url)
                            )
                            endpoints.append(endpoint)

            print(f"    [robots.txt] Found {len(endpoints)} paths")
        return endpoints

    def parse_sitemap(self, base_url: str, sitemap_url: str = None) -> List[Endpoint]:
        """Parse sitemap.xml for endpoints"""
        endpoints = []
        if not sitemap_url:
            sitemap_url = urljoin(base_url, "/sitemap.xml")

        print(f"    [sitemap] Checking {sitemap_url}")

        response = self._request(sitemap_url)
        if response and response.status_code == 200:
            try:
                # Parse XML
                root = ET.fromstring(response.content)
                # Handle different sitemap formats
                ns = {'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'}

                # Check for sitemap index
                for sitemap in root.findall('.//sm:sitemap/sm:loc', ns) or root.findall('.//sitemap/loc'):
                    loc = sitemap.text if hasattr(sitemap, 'text') else sitemap
                    if loc:
                        # Recursively parse nested sitemaps (limit depth)
                        pass  # Skip to avoid too many requests

                # Parse URLs
                for url_elem in root.findall('.//sm:url/sm:loc', ns) or root.findall('.//url/loc'):
                    url = url_elem.text if hasattr(url_elem, 'text') else str(url_elem)
                    if url:
                        endpoint = Endpoint(
                            url=url,
                            source="sitemap.xml",
                            interesting=self._is_interesting(url)
                        )
                        endpoints.append(endpoint)

                print(f"    [sitemap] Found {len(endpoints)} URLs")
            except ET.ParseError:
                print("    [sitemap] Failed to parse XML")

        return endpoints

    def bruteforce_paths(self, base_url: str, paths: List[str] = None,
                         max_workers: int = 5) -> List[Endpoint]:
        """Brute-force common paths with soft 404 and redirect detection"""
        if paths is None:
            paths = COMMON_PATHS

        endpoints = []
        print(f"    [bruteforce] Checking {len(paths)} common paths...")

        # Establish baselines for FP detection
        if self.enable_fp_detection:
            print(f"    [bruteforce] Establishing baselines for FP detection...")
            self._establish_baselines(base_url)

        found = 0
        filtered = 0

        for path in paths:
            url = urljoin(base_url, path)

            # Use GET instead of HEAD for better FP detection (need response body)
            response = self._request(url, method="GET", follow_redirects=False)

            if not response:
                continue

            self.stats['endpoints_found'] += 1

            # Skip obvious errors
            if response.status_code in [404, 500, 502, 503]:
                continue

            # 403 might be interesting (access denied but exists)
            is_403 = response.status_code == 403

            # Apply FP detection for 200/redirect responses
            if self.enable_fp_detection and not is_403:
                is_verified, verification_msg = self._verify_endpoint(url, response)

                if not is_verified:
                    filtered += 1
                    continue

            content_type = response.headers.get('Content-Type', '')

            # Check if this is a redirect
            is_redirect = response.status_code in [301, 302, 303, 307, 308]
            redirect_dest = response.headers.get('Location', '') if is_redirect else None

            endpoint = Endpoint(
                url=url,
                source="bruteforce",
                status_code=response.status_code,
                content_type=content_type,
                interesting=self._is_interesting(url),
                verified=True,
                is_soft_404=False,
                is_auth_redirect=False,
                redirect_destination=redirect_dest,
            )
            endpoints.append(endpoint)
            found += 1

            if response.status_code == 200:
                print(f"      [+] {path} -> {response.status_code}")
            elif is_403:
                print(f"      [?] {path} -> 403 (exists but forbidden)")

        print(f"    [bruteforce] Found {found} accessible paths")
        if self.enable_fp_detection:
            print(f"    [bruteforce] Filtered {filtered} false positives (soft 404s, auth redirects)")

        return endpoints

    def extract_from_html(self, base_url: str) -> Tuple[List[Endpoint], Set[str]]:
        """Extract links and JS files from HTML"""
        endpoints = []
        js_files = set()

        print(f"    [html] Extracting links from {base_url}")

        response = self._request(base_url)
        if not response or response.status_code != 200:
            return endpoints, js_files

        html = response.text

        # Extract links
        link_patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'data-url=["\']([^"\']+)["\']',
        ]

        found_urls = set()
        for pattern in link_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if match.startswith(('http://', 'https://', '/')):
                    url = urljoin(base_url, match)
                    found_urls.add(url)
                elif not match.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    url = urljoin(base_url, match)
                    found_urls.add(url)

        # Separate JS files and endpoints
        parsed_base = urlparse(base_url)
        for url in found_urls:
            parsed = urlparse(url)

            # Only include same-domain URLs
            if parsed.netloc and parsed.netloc != parsed_base.netloc:
                continue

            if url.endswith('.js'):
                js_files.add(url)
            else:
                endpoint = Endpoint(
                    url=url,
                    source="html",
                    interesting=self._is_interesting(url)
                )
                endpoints.append(endpoint)

        # Extract forms
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']?(\w+)["\']?'
        forms = re.findall(form_pattern, html, re.IGNORECASE)

        print(f"    [html] Found {len(endpoints)} links, {len(js_files)} JS files, {len(forms)} forms")
        return endpoints, js_files

    def extract_from_js(self, js_url: str) -> List[Endpoint]:
        """Extract API endpoints from JavaScript files"""
        endpoints = []

        response = self._request(js_url)
        if not response or response.status_code != 200:
            return endpoints

        js_content = response.text

        # Patterns for API endpoints in JS
        api_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.\w+\(["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
            r'\.put\(["\']([^"\']+)["\']',
            r'\.delete\(["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
            r'endpoint:\s*["\']([^"\']+)["\']',
            r'apiUrl:\s*["\']([^"\']+)["\']',
        ]

        found_paths = set()
        for pattern in api_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if match.startswith('/') or match.startswith('http'):
                    found_paths.add(match)

        for path in found_paths:
            endpoint = Endpoint(
                url=path,
                source=f"js:{js_url.split('/')[-1]}",
                interesting=True  # API endpoints are always interesting
            )
            endpoints.append(endpoint)

        return endpoints

    def discover(self, target: str, bruteforce: bool = True,
                 analyze_js: bool = True) -> EndpointResult:
        """
        Full endpoint discovery pipeline
        """
        # Normalize target URL
        if not target.startswith('http'):
            target = f"https://{target}"

        print(f"\n[*] Endpoint Discovery: {target}")
        print("=" * 50)

        result = EndpointResult(target=target)
        all_endpoints = []

        # 1. Check robots.txt
        all_endpoints.extend(self.parse_robots_txt(target))

        # 2. Check sitemap
        all_endpoints.extend(self.parse_sitemap(target))

        # 3. Extract from HTML
        html_endpoints, js_files = self.extract_from_html(target)
        all_endpoints.extend(html_endpoints)
        result.js_files = js_files

        # 4. Brute-force common paths
        if bruteforce:
            all_endpoints.extend(self.bruteforce_paths(target))

        # 5. Analyze JavaScript files
        if analyze_js and js_files:
            print(f"    [js] Analyzing {len(js_files)} JavaScript files...")
            for js_url in list(js_files)[:10]:  # Limit to first 10
                js_endpoints = self.extract_from_js(js_url)
                all_endpoints.extend(js_endpoints)
                result.api_endpoints.update(ep.url for ep in js_endpoints)

        # Deduplicate endpoints
        seen_urls = set()
        for ep in all_endpoints:
            if ep.url not in seen_urls:
                seen_urls.add(ep.url)
                result.endpoints.append(ep)

        # Sort by interestingness
        result.endpoints.sort(key=lambda x: (not x.interesting, x.url))

        print(f"\n    [TOTAL] {len(result.endpoints)} unique endpoints")
        print(f"    [INTERESTING] {sum(1 for ep in result.endpoints if ep.interesting)}")

        if self.enable_fp_detection:
            print(f"\n    [FP-DETECTION STATS]")
            print(f"      Endpoints analyzed: {self.stats['endpoints_found']}")
            print(f"      Soft 404s filtered: {self.stats['soft_404s_filtered']}")
            print(f"      Auth redirects filtered: {self.stats['auth_redirects_filtered']}")
            print(f"      Verified endpoints: {self.stats['verified_endpoints']}")

            if self.redirect_tracker:
                redirect_summary = self.redirect_tracker.get_redirect_summary()
                if redirect_summary.get('common_destinations'):
                    print(f"\n    [COMMON REDIRECT DESTINATIONS] (likely auth/middleware)")
                    for dest in redirect_summary['common_destinations'][:5]:
                        print(f"      - {dest}")

        return result

    def get_stats(self) -> Dict:
        """Get discovery statistics"""
        stats = dict(self.stats)
        if self.redirect_tracker:
            stats['redirects'] = self.redirect_tracker.get_redirect_summary()
        return stats


class AmazonEndpointDiscovery(EndpointDiscovery):
    """Amazon VRP-compliant endpoint discovery with FP detection"""

    def __init__(self, username: str = "yourh1username", enable_fp_detection: bool = True):
        config = get_amazon_config(username)
        super().__init__(
            rate_limit=config.rate_limit,
            user_agent=config.user_agent,
            enable_fp_detection=enable_fp_detection
        )


class ShopifyEndpointDiscovery(EndpointDiscovery):
    """Shopify-compliant endpoint discovery with FP detection"""

    def __init__(self, username: str = "yourh1username", enable_fp_detection: bool = True):
        config = get_shopify_config(username)
        super().__init__(
            rate_limit=config.rate_limit,
            user_agent=config.user_agent,
            enable_fp_detection=enable_fp_detection
        )


def save_endpoints(result: EndpointResult, output_file: str, discovery_stats: Dict = None):
    """Save endpoint results to JSON file with FP detection stats"""
    data = {
        "target": result.target,
        "discovery_time": result.discovery_time,
        "total_endpoints": len(result.endpoints),
        "interesting_count": sum(1 for ep in result.endpoints if ep.interesting),
        "verified_count": sum(1 for ep in result.endpoints if ep.verified),
        "js_files": sorted(list(result.js_files)),
        "api_endpoints": sorted(list(result.api_endpoints)),
        "endpoints": [
            {
                "url": ep.url,
                "method": ep.method,
                "source": ep.source,
                "status_code": ep.status_code,
                "content_type": ep.content_type,
                "interesting": ep.interesting,
                "verified": ep.verified,
                "is_soft_404": ep.is_soft_404,
                "is_auth_redirect": ep.is_auth_redirect,
                "redirect_destination": ep.redirect_destination,
                "parameters": ep.parameters,
                "notes": ep.notes,
            }
            for ep in result.endpoints
        ]
    }

    # Add FP detection stats
    if discovery_stats:
        data["false_positive_detection"] = {
            "enabled": True,
            "endpoints_analyzed": discovery_stats.get('endpoints_found', 0),
            "soft_404s_filtered": discovery_stats.get('soft_404s_filtered', 0),
            "auth_redirects_filtered": discovery_stats.get('auth_redirects_filtered', 0),
            "verified_endpoints": discovery_stats.get('verified_endpoints', 0),
        }

        if 'redirects' in discovery_stats:
            data["redirect_analysis"] = discovery_stats['redirects']

    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"\n[*] Results saved to: {output_file}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Endpoint Discovery Tool with False Positive Detection")
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--program", "-p", choices=["amazon", "shopify"],
                        help="Bug bounty program for rate limiting")
    parser.add_argument("--username", "-u", default="yourh1username",
                        help="HackerOne username")
    parser.add_argument("--no-bruteforce", action="store_true",
                        help="Skip path brute-forcing")
    parser.add_argument("--no-js", action="store_true",
                        help="Skip JavaScript analysis")
    parser.add_argument("--no-fp-detection", action="store_true",
                        help="Disable false positive detection (not recommended)")
    parser.add_argument("--output", "-o", help="Output JSON file")

    args = parser.parse_args()

    enable_fp = not args.no_fp_detection

    # Create discovery instance
    if args.program == "amazon":
        discovery = AmazonEndpointDiscovery(args.username, enable_fp_detection=enable_fp)
    elif args.program == "shopify":
        discovery = ShopifyEndpointDiscovery(args.username, enable_fp_detection=enable_fp)
    else:
        discovery = EndpointDiscovery(enable_fp_detection=enable_fp)

    if enable_fp:
        print("[*] False Positive Detection: ENABLED")
        print("    - Soft 404 detection")
        print("    - Auth redirect detection")
        print("    - Redirect pattern analysis")
    else:
        print("[!] False Positive Detection: DISABLED")

    # Run discovery
    result = discovery.discover(
        args.target,
        bruteforce=not args.no_bruteforce,
        analyze_js=not args.no_js
    )

    # Print summary
    print("\n" + "=" * 50)
    print("ENDPOINT DISCOVERY SUMMARY")
    print("=" * 50)
    print(f"Target: {result.target}")
    print(f"Total endpoints: {len(result.endpoints)}")
    print(f"Verified endpoints: {sum(1 for ep in result.endpoints if ep.verified)}")
    print(f"Interesting: {sum(1 for ep in result.endpoints if ep.interesting)}")
    print(f"JS files found: {len(result.js_files)}")
    print(f"API endpoints: {len(result.api_endpoints)}")

    # Print interesting endpoints (verified only)
    interesting = [ep for ep in result.endpoints if ep.interesting and ep.verified]
    if interesting:
        print("\nVerified Interesting Endpoints:")
        for ep in interesting[:20]:
            status = f"[{ep.status_code}]" if ep.status_code else ""
            print(f"  {status} {ep.url} ({ep.source})")
        if len(interesting) > 20:
            print(f"  ... and {len(interesting) - 20} more")

    # Save results
    if args.output:
        save_endpoints(result, args.output, discovery.get_stats())
