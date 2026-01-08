#!/usr/bin/env python3
"""
Bug Bounty Scanner
Compliant scanner for Amazon VRP and Shopify Bug Bounty programs
Includes rate limiting, proper headers, and scope validation
"""

import time
import json
import socket
import ssl
import re
import hashlib
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urlparse, urljoin, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    exit(1)

from config import (
    AmazonConfig, ShopifyConfig,
    get_amazon_config, get_shopify_config,
    SECURITY_HEADERS, TEST_PAYLOADS, VULN_PRIORITIES
)
from scope_validator import AmazonScopeValidator, ShopifyScopeValidator


@dataclass
class Finding:
    """Represents a security finding"""
    target: str
    vuln_type: str
    severity: str
    description: str
    evidence: str
    reproduction_steps: List[str]
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    request: Optional[str] = None
    response: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ScanResult:
    """Results from a scan"""
    target: str
    scan_type: str
    start_time: str
    end_time: str
    findings: List[Finding]
    errors: List[str]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict:
        result = asdict(self)
        result['findings'] = [f.to_dict() for f in self.findings]
        return result


class RateLimiter:
    """Thread-safe rate limiter"""

    def __init__(self, rate_per_second: float):
        self.rate = rate_per_second
        self.min_interval = 1.0 / rate_per_second
        self.last_request = 0.0
        self.lock = threading.Lock()

    def wait(self):
        """Wait if necessary to maintain rate limit"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_request
            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                time.sleep(sleep_time)
            self.last_request = time.time()


class BaseScanner:
    """Base scanner class with common functionality"""

    def __init__(self, rate_limit: float, user_agent: str, timeout: int = 30):
        self.rate_limiter = RateLimiter(rate_limit)
        self.user_agent = user_agent
        self.timeout = timeout
        self.session = self._create_session()
        self.findings: List[Finding] = []
        self.errors: List[str] = []

    def _create_session(self) -> requests.Session:
        """Create a session with retry logic"""
        session = requests.Session()

        # Retry strategy for transient failures
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set default headers
        session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

        return session

    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make a rate-limited request"""
        self.rate_limiter.wait()

        try:
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('verify', True)
            kwargs.setdefault('allow_redirects', False)

            response = self.session.request(method, url, **kwargs)
            return response

        except requests.exceptions.Timeout:
            self.errors.append(f"Timeout: {url}")
        except requests.exceptions.SSLError as e:
            self.errors.append(f"SSL Error for {url}: {str(e)}")
        except requests.exceptions.ConnectionError as e:
            self.errors.append(f"Connection Error for {url}: {str(e)}")
        except Exception as e:
            self.errors.append(f"Error for {url}: {str(e)}")

        return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self._request('GET', url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self._request('POST', url, **kwargs)

    def add_finding(self, finding: Finding):
        """Add a finding to the results"""
        self.findings.append(finding)
        print(f"  [!] FINDING: {finding.vuln_type} - {finding.severity}")

    def check_security_headers(self, url: str) -> List[Finding]:
        """Check for missing security headers"""
        findings = []
        response = self.get(url)

        if not response:
            return findings

        missing_headers = []
        for header in SECURITY_HEADERS:
            if header.lower() not in [h.lower() for h in response.headers.keys()]:
                missing_headers.append(header)

        if missing_headers:
            finding = Finding(
                target=url,
                vuln_type="Missing Security Headers",
                severity="info",  # Usually low/informational
                description=f"Missing headers: {', '.join(missing_headers)}",
                evidence=f"Response headers: {dict(response.headers)}",
                reproduction_steps=[
                    f"1. Send GET request to {url}",
                    "2. Observe missing security headers in response"
                ]
            )
            findings.append(finding)

        return findings

    def check_ssl_tls(self, hostname: str, port: int = 443) -> List[Finding]:
        """Check SSL/TLS configuration"""
        findings = []

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Check for weak TLS versions
                    if version in ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2']:
                        finding = Finding(
                            target=hostname,
                            vuln_type="Weak TLS Version",
                            severity="medium",
                            description=f"Server supports weak TLS version: {version}",
                            evidence=f"TLS Version: {version}, Cipher: {cipher}",
                            reproduction_steps=[
                                f"1. Connect to {hostname}:{port}",
                                f"2. Observe TLS version: {version}"
                            ]
                        )
                        findings.append(finding)

        except ssl.SSLError as e:
            self.errors.append(f"SSL error for {hostname}: {str(e)}")
        except socket.error as e:
            self.errors.append(f"Socket error for {hostname}: {str(e)}")

        return findings

    def check_open_redirect(self, url: str) -> List[Finding]:
        """Check for open redirect vulnerabilities"""
        findings = []
        parsed = urlparse(url)

        # Common redirect parameters
        redirect_params = ['url', 'redirect', 'next', 'return', 'returnUrl',
                          'goto', 'dest', 'destination', 'redir', 'redirect_uri',
                          'return_url', 'continue', 'target']

        for param in redirect_params:
            for payload in TEST_PAYLOADS['open_redirect']:
                test_url = f"{url}?{param}={payload}"
                response = self.get(test_url)

                if response and response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if 'evil.com' in location or location.startswith('//'):
                        finding = Finding(
                            target=url,
                            vuln_type="Open Redirect",
                            severity="low",
                            description=f"Open redirect via {param} parameter",
                            evidence=f"Redirect to: {location}",
                            reproduction_steps=[
                                f"1. Visit: {test_url}",
                                f"2. Observe redirect to: {location}"
                            ],
                            request=f"GET {test_url}",
                            response=f"HTTP {response.status_code} Location: {location}"
                        )
                        findings.append(finding)
                        break  # Found vuln for this param, move on

        return findings

    def check_cors(self, url: str) -> List[Finding]:
        """Check for CORS misconfigurations"""
        findings = []

        # Test with arbitrary origin
        headers = {'Origin': 'https://evil.com'}
        response = self.get(url, headers=headers)

        if response:
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')

            if acao == '*':
                finding = Finding(
                    target=url,
                    vuln_type="CORS Wildcard",
                    severity="medium",
                    description="CORS allows any origin (wildcard)",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    reproduction_steps=[
                        f"1. Send request with Origin: https://evil.com",
                        f"2. Observe Access-Control-Allow-Origin: *"
                    ]
                )
                findings.append(finding)

            elif 'evil.com' in acao:
                severity = "high" if acac.lower() == 'true' else "medium"
                finding = Finding(
                    target=url,
                    vuln_type="CORS Origin Reflection",
                    severity=severity,
                    description=f"CORS reflects arbitrary origin{' with credentials' if acac else ''}",
                    evidence=f"Access-Control-Allow-Origin: {acao}, Allow-Credentials: {acac}",
                    reproduction_steps=[
                        f"1. Send request with Origin: https://evil.com",
                        f"2. Observe origin is reflected in ACAO header"
                    ]
                )
                findings.append(finding)

        return findings

    def check_xss_reflection(self, url: str, params: List[str] = None) -> List[Finding]:
        """Check for reflected XSS (non-invasive)"""
        findings = []

        # Use a canary value that's unlikely to appear naturally
        canary = f"xss_test_{hashlib.md5(url.encode()).hexdigest()[:8]}"

        # If no params specified, try common ones
        if not params:
            params = ['q', 'search', 'query', 'term', 'keyword', 'name',
                     'id', 'page', 'view', 'action', 'redirect', 'url']

        for param in params:
            test_url = f"{url}?{param}={canary}"
            response = self.get(test_url)

            if response and canary in response.text:
                # Found reflection, test with actual XSS payload
                test_payload = f"<{canary}>"
                test_url2 = f"{url}?{param}={test_payload}"
                response2 = self.get(test_url2)

                if response2 and test_payload in response2.text:
                    finding = Finding(
                        target=url,
                        vuln_type="Potential XSS",
                        severity="medium",
                        description=f"HTML tag reflection in {param} parameter",
                        evidence=f"Input '<{canary}>' reflected in response",
                        reproduction_steps=[
                            f"1. Visit: {test_url2}",
                            f"2. Observe input reflected in page source"
                        ]
                    )
                    findings.append(finding)

        return findings

    def check_information_disclosure(self, url: str) -> List[Finding]:
        """Check for information disclosure"""
        findings = []

        # Common sensitive paths
        sensitive_paths = [
            '/.git/config',
            '/.env',
            '/config.php.bak',
            '/web.config',
            '/crossdomain.xml',
            '/clientaccesspolicy.xml',
            '/phpinfo.php',
            '/server-status',
            '/debug',
            '/.DS_Store',
            '/robots.txt',
            '/sitemap.xml',
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path in sensitive_paths:
            test_url = urljoin(base_url, path)
            response = self.get(test_url)

            if response and response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')

                # Check for actual sensitive content
                sensitive_patterns = [
                    (r'\[core\]', '.git/config exposed'),
                    (r'DB_PASSWORD|API_KEY|SECRET', 'Environment variables exposed'),
                    (r'phpinfo\(\)', 'PHP info exposed'),
                    (r'<Directory', 'Server status exposed'),
                ]

                for pattern, desc in sensitive_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        finding = Finding(
                            target=test_url,
                            vuln_type="Information Disclosure",
                            severity="medium",
                            description=desc,
                            evidence=f"Found at: {test_url}",
                            reproduction_steps=[
                                f"1. Visit: {test_url}",
                                f"2. Observe sensitive information"
                            ]
                        )
                        findings.append(finding)
                        break

        return findings


class AmazonScanner(BaseScanner):
    """
    Scanner for Amazon VRP
    IMPORTANT: Follows all Amazon VRP rules:
    - Rate limit: 5 requests/second
    - User-Agent: amazonvrpresearcher_<username>
    - Validates scope before scanning
    """

    def __init__(self, config: Optional[AmazonConfig] = None):
        self.config = config or get_amazon_config()
        super().__init__(
            rate_limit=self.config.rate_limit,
            user_agent=self.config.user_agent,
            timeout=self.config.request_timeout
        )
        self.validator = AmazonScopeValidator(self.config)

        # Create output directory
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        print(f"[*] Amazon VRP Scanner initialized")
        print(f"    User-Agent: {self.user_agent}")
        print(f"    Rate Limit: {self.config.rate_limit} req/sec")
        print(f"    Test Email: {self.config.test_email}")

    def validate_target(self, target: str) -> Tuple[bool, str]:
        """Validate target is in scope"""
        return self.validator.is_in_scope(target)

    def scan_target(self, target: str) -> Optional[ScanResult]:
        """Scan a single target with all checks"""
        # Validate scope first
        is_valid, reason = self.validate_target(target)
        if not is_valid:
            print(f"[!] SKIPPING {target}: {reason}")
            return None

        print(f"\n[+] Scanning: {target}")
        print(f"    Scope: {reason}")

        start_time = datetime.utcnow().isoformat()
        self.findings = []
        self.errors = []

        # Ensure https
        if not target.startswith('http'):
            target = f"https://{target}"

        # Run checks
        print("    Checking security headers...")
        self.findings.extend(self.check_security_headers(target))

        print("    Checking CORS...")
        self.findings.extend(self.check_cors(target))

        print("    Checking open redirects...")
        self.findings.extend(self.check_open_redirect(target))

        print("    Checking for information disclosure...")
        self.findings.extend(self.check_information_disclosure(target))

        print("    Checking XSS reflection...")
        self.findings.extend(self.check_xss_reflection(target))

        # SSL/TLS check
        parsed = urlparse(target)
        if parsed.scheme == 'https':
            print("    Checking SSL/TLS...")
            self.findings.extend(self.check_ssl_tls(parsed.netloc))

        end_time = datetime.utcnow().isoformat()

        result = ScanResult(
            target=target,
            scan_type="amazon_vrp",
            start_time=start_time,
            end_time=end_time,
            findings=self.findings,
            errors=self.errors,
            metadata={
                "user_agent": self.user_agent,
                "rate_limit": self.config.rate_limit,
                "scope_validation": reason,
            }
        )

        return result

    def scan_multiple(self, targets: List[str]) -> List[ScanResult]:
        """Scan multiple targets (sequentially due to rate limit)"""
        results = []

        # Filter to in-scope targets first
        in_scope, out_of_scope = self.validator.filter_targets(targets)

        print(f"\n[*] Target Analysis:")
        print(f"    In Scope: {len(in_scope)}")
        print(f"    Out of Scope: {len(out_of_scope)}")

        if out_of_scope:
            print("\n[!] Out of scope targets (skipped):")
            for target, reason in out_of_scope[:5]:  # Show first 5
                print(f"    - {target}: {reason}")
            if len(out_of_scope) > 5:
                print(f"    ... and {len(out_of_scope) - 5} more")

        for target in in_scope:
            result = self.scan_target(target)
            if result:
                results.append(result)

        return results

    def save_results(self, results: List[ScanResult], filename: str = None) -> Path:
        """Save scan results to JSON file"""
        if not filename:
            filename = f"amazon_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        output_path = self.config.output_dir / filename

        data = {
            "program": "Amazon VRP",
            "scanner_config": {
                "user_agent": self.user_agent,
                "rate_limit": self.config.rate_limit,
                "test_email": self.config.test_email,
            },
            "scan_date": datetime.utcnow().isoformat(),
            "total_targets": len(results),
            "total_findings": sum(len(r.findings) for r in results),
            "results": [r.to_dict() for r in results]
        }

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"\n[*] Results saved to: {output_path}")
        return output_path


class ShopifyScanner(BaseScanner):
    """
    Scanner for Shopify Bug Bounty
    IMPORTANT: Follows all Shopify rules:
    - Only test stores you created
    - Uses proper email format
    - Respects API rate limits
    """

    def __init__(self, config: Optional[ShopifyConfig] = None):
        self.config = config or get_shopify_config()
        super().__init__(
            rate_limit=self.config.rate_limit,
            user_agent=self.config.user_agent,
            timeout=self.config.request_timeout
        )
        self.validator = ShopifyScopeValidator(self.config)

        # Create output directory
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        print(f"[*] Shopify Scanner initialized")
        print(f"    User-Agent: {self.user_agent}")
        print(f"    Rate Limit: {self.config.rate_limit} req/sec")
        print(f"    Test Email: {self.config.test_email}")
        print(f"    Partner Signup: {self.config.partner_signup_url}")

    def validate_target(self, target: str) -> Tuple[bool, str]:
        """Validate target is in scope"""
        return self.validator.is_in_scope(target)

    def check_graphql_introspection(self, url: str) -> List[Finding]:
        """Check if GraphQL introspection is enabled"""
        findings = []

        # Common GraphQL endpoints
        graphql_paths = ['/graphql', '/api/graphql', '/graphql.json', '/admin/api/graphql.json']

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path in graphql_paths:
            test_url = urljoin(base_url, path)

            # Introspection query
            query = {"query": "{ __schema { types { name } } }"}

            response = self.post(
                test_url,
                json=query,
                headers={'Content-Type': 'application/json'}
            )

            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if 'data' in data and '__schema' in data.get('data', {}):
                        finding = Finding(
                            target=test_url,
                            vuln_type="GraphQL Introspection Enabled",
                            severity="low",
                            description="GraphQL introspection is enabled, allowing schema discovery",
                            evidence=f"Found {len(data['data']['__schema'].get('types', []))} types",
                            reproduction_steps=[
                                f"1. Send introspection query to {test_url}",
                                "2. Observe full schema returned"
                            ]
                        )
                        findings.append(finding)
                except:
                    pass

        return findings

    def check_api_versioning(self, url: str) -> List[Finding]:
        """Check for exposed old API versions"""
        findings = []

        # Shopify API versions to check
        old_versions = ['2019-04', '2019-07', '2019-10', '2020-01', '2020-04']

        parsed = urlparse(url)
        if 'myshopify.com' in parsed.netloc:
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for version in old_versions:
                test_url = f"{base_url}/admin/api/{version}/shop.json"
                response = self.get(test_url)

                if response and response.status_code != 404:
                    finding = Finding(
                        target=test_url,
                        vuln_type="Old API Version Accessible",
                        severity="info",
                        description=f"Old API version {version} is accessible",
                        evidence=f"HTTP {response.status_code}",
                        reproduction_steps=[
                            f"1. Access {test_url}",
                            f"2. Observe response: {response.status_code}"
                        ]
                    )
                    findings.append(finding)

        return findings

    def scan_target(self, target: str) -> Optional[ScanResult]:
        """Scan a single Shopify target"""
        # Validate scope first
        is_valid, reason = self.validate_target(target)
        if not is_valid:
            print(f"[!] SKIPPING {target}: {reason}")
            return None

        print(f"\n[+] Scanning: {target}")
        print(f"    Scope: {reason}")

        start_time = datetime.utcnow().isoformat()
        self.findings = []
        self.errors = []

        # Ensure https
        if not target.startswith('http'):
            target = f"https://{target}"

        # Run checks
        print("    Checking security headers...")
        self.findings.extend(self.check_security_headers(target))

        print("    Checking CORS...")
        self.findings.extend(self.check_cors(target))

        print("    Checking GraphQL introspection...")
        self.findings.extend(self.check_graphql_introspection(target))

        print("    Checking API versioning...")
        self.findings.extend(self.check_api_versioning(target))

        print("    Checking open redirects...")
        self.findings.extend(self.check_open_redirect(target))

        print("    Checking for information disclosure...")
        self.findings.extend(self.check_information_disclosure(target))

        # SSL/TLS check
        parsed = urlparse(target)
        if parsed.scheme == 'https':
            print("    Checking SSL/TLS...")
            self.findings.extend(self.check_ssl_tls(parsed.netloc))

        end_time = datetime.utcnow().isoformat()

        result = ScanResult(
            target=target,
            scan_type="shopify",
            start_time=start_time,
            end_time=end_time,
            findings=self.findings,
            errors=self.errors,
            metadata={
                "user_agent": self.user_agent,
                "rate_limit": self.config.rate_limit,
                "scope_validation": reason,
            }
        )

        return result

    def scan_multiple(self, targets: List[str]) -> List[ScanResult]:
        """Scan multiple Shopify targets"""
        results = []

        # Filter to in-scope targets first
        in_scope, out_of_scope = self.validator.filter_targets(targets)

        print(f"\n[*] Target Analysis:")
        print(f"    In Scope: {len(in_scope)}")
        print(f"    Out of Scope: {len(out_of_scope)}")

        if out_of_scope:
            print("\n[!] Out of scope targets (skipped):")
            for target, reason in out_of_scope[:5]:
                print(f"    - {target}: {reason}")
            if len(out_of_scope) > 5:
                print(f"    ... and {len(out_of_scope) - 5} more")

        for target in in_scope:
            result = self.scan_target(target)
            if result:
                results.append(result)

        return results

    def save_results(self, results: List[ScanResult], filename: str = None) -> Path:
        """Save scan results to JSON file"""
        if not filename:
            filename = f"shopify_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        output_path = self.config.output_dir / filename

        data = {
            "program": "Shopify Bug Bounty",
            "scanner_config": {
                "user_agent": self.user_agent,
                "rate_limit": self.config.rate_limit,
                "test_email": self.config.test_email,
            },
            "scan_date": datetime.utcnow().isoformat(),
            "total_targets": len(results),
            "total_findings": sum(len(r.findings) for r in results),
            "results": [r.to_dict() for r in results]
        }

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"\n[*] Results saved to: {output_path}")
        return output_path


if __name__ == "__main__":
    print("=" * 60)
    print("BUG BOUNTY SCANNER")
    print("Amazon VRP & Shopify Bug Bounty")
    print("=" * 60)

    # Demo mode - test scope validation
    print("\n[DEMO] Testing scope validation only (no live scans)")

    # Amazon scope test
    print("\n--- Amazon VRP Scope Test ---")
    amazon = AmazonScanner()
    test_targets = [
        "www.amazon.com",
        "aws.amazon.com",  # Out of scope
        "test.amazon.de",  # Out of scope (test env)
    ]
    for target in test_targets:
        is_valid, reason = amazon.validate_target(target)
        status = "IN SCOPE" if is_valid else "OUT OF SCOPE"
        print(f"  {target}: {status}")

    # Shopify scope test
    print("\n--- Shopify Scope Test ---")
    shopify = ShopifyScanner()
    test_targets = [
        "admin.shopify.com",
        "community.shopify.com",  # Out of scope
        "partners.shopify.com",
    ]
    for target in test_targets:
        is_valid, reason = shopify.validate_target(target)
        status = "IN SCOPE" if is_valid else "OUT OF SCOPE"
        print(f"  {target}: {status}")

    print("\n[*] Use run_scan.py to perform actual scans")
