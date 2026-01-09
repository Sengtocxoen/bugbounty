#!/usr/bin/env python3
"""
Endpoint Discovery Module
Discovers endpoints on web applications using:
- robots.txt parsing
- sitemap.xml parsing
- Common path brute-forcing
- JavaScript file analysis
- HTML link extraction

Respects rate limits for bug bounty compliance.
"""

import re
import json
import time
import threading
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET

try:
    import requests
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    exit(1)

from config import get_amazon_config, get_shopify_config


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
    """Discover endpoints on web applications"""

    def __init__(self, rate_limit: float = 5.0, user_agent: str = "BugBountyResearcher"):
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

    def _rate_limit_wait(self):
        """Wait to respect rate limit"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_request
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_request = time.time()

    def _request(self, url: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
        """Make a rate-limited request"""
        self._rate_limit_wait()
        try:
            kwargs.setdefault('timeout', 10)
            kwargs.setdefault('allow_redirects', True)
            kwargs.setdefault('verify', True)
            response = self.session.request(method, url, **kwargs)
            return response
        except Exception:
            return None

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
        """Brute-force common paths"""
        if paths is None:
            paths = COMMON_PATHS

        endpoints = []
        print(f"    [bruteforce] Checking {len(paths)} common paths...")

        found = 0
        for path in paths:
            url = urljoin(base_url, path)
            response = self._request(url, method="HEAD")

            if response and response.status_code not in [404, 403, 500, 502, 503]:
                content_type = response.headers.get('Content-Type', '')
                endpoint = Endpoint(
                    url=url,
                    source="bruteforce",
                    status_code=response.status_code,
                    content_type=content_type,
                    interesting=self._is_interesting(url)
                )
                endpoints.append(endpoint)
                found += 1

                if response.status_code == 200:
                    print(f"      [+] {path} -> {response.status_code}")

        print(f"    [bruteforce] Found {found} accessible paths")
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

        return result


class AmazonEndpointDiscovery(EndpointDiscovery):
    """Amazon VRP-compliant endpoint discovery"""

    def __init__(self, username: str = "yourh1username"):
        config = get_amazon_config(username)
        super().__init__(
            rate_limit=config.rate_limit,
            user_agent=config.user_agent
        )


class ShopifyEndpointDiscovery(EndpointDiscovery):
    """Shopify-compliant endpoint discovery"""

    def __init__(self, username: str = "yourh1username"):
        config = get_shopify_config(username)
        super().__init__(
            rate_limit=config.rate_limit,
            user_agent=config.user_agent
        )


def save_endpoints(result: EndpointResult, output_file: str):
    """Save endpoint results to JSON file"""
    data = {
        "target": result.target,
        "discovery_time": result.discovery_time,
        "total_endpoints": len(result.endpoints),
        "interesting_count": sum(1 for ep in result.endpoints if ep.interesting),
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
                "parameters": ep.parameters,
                "notes": ep.notes,
            }
            for ep in result.endpoints
        ]
    }

    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"\n[*] Results saved to: {output_file}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Endpoint Discovery Tool")
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--program", "-p", choices=["amazon", "shopify"],
                        help="Bug bounty program for rate limiting")
    parser.add_argument("--username", "-u", default="yourh1username",
                        help="HackerOne username")
    parser.add_argument("--no-bruteforce", action="store_true",
                        help="Skip path brute-forcing")
    parser.add_argument("--no-js", action="store_true",
                        help="Skip JavaScript analysis")
    parser.add_argument("--output", "-o", help="Output JSON file")

    args = parser.parse_args()

    # Create discovery instance
    if args.program == "amazon":
        discovery = AmazonEndpointDiscovery(args.username)
    elif args.program == "shopify":
        discovery = ShopifyEndpointDiscovery(args.username)
    else:
        discovery = EndpointDiscovery()

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
    print(f"Interesting: {sum(1 for ep in result.endpoints if ep.interesting)}")
    print(f"JS files found: {len(result.js_files)}")
    print(f"API endpoints: {len(result.api_endpoints)}")

    # Print interesting endpoints
    interesting = [ep for ep in result.endpoints if ep.interesting]
    if interesting:
        print("\nInteresting endpoints:")
        for ep in interesting[:20]:
            status = f"[{ep.status_code}]" if ep.status_code else ""
            print(f"  {status} {ep.url} ({ep.source})")
        if len(interesting) > 20:
            print(f"  ... and {len(interesting) - 20} more")

    # Save results
    if args.output:
        save_endpoints(result, args.output)
