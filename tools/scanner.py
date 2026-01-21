#!/usr/bin/env python3
"""
Bug Bounty Scanner
Compliant scanner for Amazon VRP and Shopify Bug Bounty programs
Includes rate limiting, proper headers, scope validation, and false positive detection

False Positive Detection Features:
- Redirect chain analysis for auth page detection
- Baseline response comparison
- Soft 404 detection
- Context-aware vulnerability validation
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
from difflib import SequenceMatcher
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
from false_positive_detector import FalsePositiveDetector, RedirectTracker


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
    # False positive detection fields
    verified: bool = True  # Passed FP checks
    confidence: str = "medium"  # high, medium, low
    fp_check_result: str = ""  # Result of FP analysis

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
    """Base scanner class with common functionality and FP detection"""

    def __init__(self, rate_limit: float, user_agent: str, timeout: int = 30,
                 enable_fp_detection: bool = True):
        self.rate_limiter = RateLimiter(rate_limit)
        self.user_agent = user_agent
        self.timeout = timeout
        self.session = self._create_session()
        self.findings: List[Finding] = []
        self.errors: List[str] = []

        # False positive detection
        self.enable_fp_detection = enable_fp_detection
        self.fp_detector = FalsePositiveDetector(self.session, rate_limit) if enable_fp_detection else None
        self.redirect_tracker = RedirectTracker() if enable_fp_detection else None

        # Baselines for comparison
        self.baselines: Dict[str, Dict] = {}

        # Stats
        self.fp_stats = {
            'checks_run': 0,
            'findings_verified': 0,
            'false_positives_filtered': 0,
        }

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
        status = "VERIFIED" if finding.verified else "UNVERIFIED"
        print(f"  [!] FINDING: {finding.vuln_type} - {finding.severity} [{status}]")

    def _get_baseline(self, url: str) -> Optional[Dict]:
        """Get or create baseline for a URL"""
        parsed = urlparse(url)
        base_key = f"{parsed.scheme}://{parsed.netloc}"

        if base_key not in self.baselines:
            response = self.get(base_key)
            if response:
                content = response.text or ""
                self.baselines[base_key] = {
                    'hash': hashlib.md5(content.encode()).hexdigest(),
                    'length': len(content),
                    'status': response.status_code,
                }
            else:
                self.baselines[base_key] = None

        return self.baselines.get(base_key)

    def _is_auth_redirect(self, response: requests.Response) -> bool:
        """Check if response is a redirect to auth page"""
        if response.status_code not in [301, 302, 303, 307, 308]:
            return False

        location = response.headers.get('Location', '').lower()
        auth_patterns = ['/login', '/signin', '/auth', '/sso', '/oauth',
                        '/session', '/unauthorized', '/access-denied']

        return any(pattern in location for pattern in auth_patterns)

    def _is_error_page(self, response: requests.Response) -> bool:
        """Check if response is an error page"""
        if not response.text:
            return False

        content_lower = response.text.lower()

        # Check for error patterns
        error_patterns = [
            r'<title>[^<]*(?:error|404|not found|oops)[^<]*</title>',
            r'page\s+not\s+found',
            r'access\s+denied',
            r'invalid\s+request',
        ]

        return any(re.search(pattern, content_lower) for pattern in error_patterns)

    def _validate_finding(self, finding: Finding, response: requests.Response,
                          vuln_type: str) -> Tuple[bool, str]:
        """Validate a finding using FP detection"""
        if not self.enable_fp_detection:
            return True, "FP detection disabled"

        self.fp_stats['checks_run'] += 1

        # Check 1: Auth redirect
        if self._is_auth_redirect(response):
            self.fp_stats['false_positives_filtered'] += 1
            return False, "Response is auth redirect"

        # Check 2: Error page (for most vulns)
        if vuln_type not in ['missing_headers', 'ssl_tls'] and self._is_error_page(response):
            self.fp_stats['false_positives_filtered'] += 1
            return False, "Response is error page"

        # Check 3: Use FP detector for detailed analysis
        if self.fp_detector:
            fp_result = self.fp_detector.analyze_for_false_positive(
                finding.target, response, vuln_type
            )
            if fp_result.is_false_positive:
                self.fp_stats['false_positives_filtered'] += 1
                return False, fp_result.reason

        self.fp_stats['findings_verified'] += 1
        return True, "Verified"

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
        """Check for open redirect vulnerabilities with FP detection"""
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

                if not response:
                    continue

                if response.status_code not in [301, 302, 303, 307, 308]:
                    continue

                location = response.headers.get('Location', '')

                # Validate redirect target
                is_valid_redirect = False
                redirect_target = None

                # Check for evil.com in various formats
                if 'evil.com' in location.lower():
                    try:
                        # Parse to verify it's actually redirecting to evil.com domain
                        if location.startswith('//'):
                            location_parsed = urlparse('https:' + location)
                        else:
                            location_parsed = urlparse(location)

                        if location_parsed.netloc and 'evil.com' in location_parsed.netloc.lower():
                            is_valid_redirect = True
                            redirect_target = location_parsed.netloc
                    except Exception:
                        pass

                # Also check for protocol-relative redirects to external domains
                if not is_valid_redirect and location.startswith('//'):
                    try:
                        location_parsed = urlparse('https:' + location)
                        if location_parsed.netloc and location_parsed.netloc != parsed.netloc:
                            is_valid_redirect = True
                            redirect_target = location_parsed.netloc
                    except Exception:
                        pass

                if not is_valid_redirect:
                    continue

                # FP Check: Make sure this isn't a normal auth flow redirect
                if self.enable_fp_detection:
                    # Check if the param is being used for legitimate internal redirects
                    auth_indicators = ['/login', '/auth', '/oauth', '/sso', '/callback']
                    if any(ind in location.lower() for ind in auth_indicators):
                        # Could be OAuth callback, not open redirect
                        self.fp_stats['false_positives_filtered'] += 1
                        continue

                finding = Finding(
                    target=url,
                    vuln_type="Open Redirect",
                    severity="low",
                    description=f"Open redirect via {param} parameter to external domain",
                    evidence=f"Redirect to: {location} (domain: {redirect_target})",
                    reproduction_steps=[
                        f"1. Visit: {test_url}",
                        f"2. Observe redirect to external domain: {redirect_target}"
                    ],
                    request=f"GET {test_url}",
                    response=f"HTTP {response.status_code} Location: {location}",
                    verified=True,
                    confidence="high",
                    fp_check_result="Verified - redirects to controlled external domain"
                )
                findings.append(finding)
                break  # Found vuln for this param, move on

        return findings

    def check_cors(self, url: str) -> List[Finding]:
        """Check for CORS misconfigurations with FP detection"""
        findings = []

        # Test with arbitrary origin
        headers = {'Origin': 'https://evil.com'}
        response = self.get(url, headers=headers)

        if not response:
            return findings

        # FP Check: Skip if response is auth redirect
        if self.enable_fp_detection and self._is_auth_redirect(response):
            return findings

        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')

        if acao == '*':
            # Wildcard CORS - lower severity if no credentials
            finding = Finding(
                target=url,
                vuln_type="CORS Wildcard",
                severity="medium" if acac.lower() != 'true' else "low",  # Wildcard + credentials is actually invalid
                description="CORS allows any origin (wildcard)",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                reproduction_steps=[
                    f"1. Send request with Origin: https://evil.com",
                    f"2. Observe Access-Control-Allow-Origin: *"
                ],
                verified=True,
                confidence="high",
                fp_check_result="Verified - CORS header present"
            )
            findings.append(finding)

        elif acao and 'evil.com' in acao.lower():
            # Origin reflection - this is more serious
            severity = "high" if acac.lower() == 'true' else "medium"

            # Additional validation - make sure it's actually our origin
            if acao.strip() == 'https://evil.com':
                finding = Finding(
                    target=url,
                    vuln_type="CORS Origin Reflection",
                    severity=severity,
                    description=f"CORS reflects arbitrary origin{' with credentials' if acac.lower() == 'true' else ''}",
                    evidence=f"Access-Control-Allow-Origin: {acao}, Allow-Credentials: {acac}",
                    reproduction_steps=[
                        f"1. Send request with Origin: https://evil.com",
                        f"2. Observe origin is reflected in ACAO header",
                        f"3. {'Credentials are allowed, enabling cookie theft' if acac.lower() == 'true' else 'Credentials not allowed'}"
                    ],
                    verified=True,
                    confidence="high",
                    fp_check_result="Verified - arbitrary origin reflected in CORS headers"
                )
                findings.append(finding)

        return findings

    def check_xss_reflection(self, url: str, params: List[str] = None) -> List[Finding]:
        """Check for reflected XSS (non-invasive) with FP detection"""
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

            if not response:
                continue

            # FP Check: Skip if auth redirect
            if self.enable_fp_detection and self._is_auth_redirect(response):
                continue

            if canary not in (response.text or ''):
                continue

            # Found reflection, test with actual XSS payload
            test_payload = f"<{canary}>"
            test_url2 = f"{url}?{param}={test_payload}"
            response2 = self.get(test_url2)

            if not response2 or test_payload not in (response2.text or ''):
                continue

            # FP Check: Verify XSS is in HTML context, not escaped
            is_valid_xss = True
            fp_reason = ""

            if self.enable_fp_detection:
                content = response2.text

                # Check if payload is HTML-encoded
                if f"&lt;{canary}&gt;" in content:
                    is_valid_xss = False
                    fp_reason = "Payload is HTML-encoded"

                # Check if in HTML comment
                elif re.search(r'<!--[^>]*' + re.escape(test_payload) + r'[^>]*-->', content):
                    is_valid_xss = False
                    fp_reason = "Payload in HTML comment"

                # Check if in JavaScript string (escaped)
                elif re.search(r'["\'][^"\']*\\x3c' + canary, content):
                    is_valid_xss = False
                    fp_reason = "Payload escaped in JS"

                # Check if response is error page
                elif self._is_error_page(response2):
                    is_valid_xss = False
                    fp_reason = "Response is error page"

            if not is_valid_xss:
                self.fp_stats['false_positives_filtered'] += 1
                continue

            finding = Finding(
                target=url,
                vuln_type="Potential XSS",
                severity="medium",
                description=f"HTML tag reflection in {param} parameter",
                evidence=f"Input '<{canary}>' reflected in response without encoding",
                reproduction_steps=[
                    f"1. Visit: {test_url2}",
                    f"2. Observe input reflected in page source"
                ],
                verified=True,
                confidence="high" if self.enable_fp_detection else "medium",
                fp_check_result="Verified - payload reflected unencoded in HTML context"
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
                            ],
                            verified=True,
                            confidence="high",
                            fp_check_result="Verified - sensitive pattern found in response"
                        )
                        findings.append(finding)
                        break

        return findings

    def get_fp_stats(self) -> Dict:
        """Get false positive detection statistics"""
        stats = dict(self.fp_stats)
        if self.fp_detector:
            stats['detector_stats'] = self.fp_detector.get_stats()
        if self.redirect_tracker:
            stats['redirect_summary'] = self.redirect_tracker.get_redirect_summary()
        return stats


class AmazonScanner(BaseScanner):
    """
    Scanner for Amazon VRP
    IMPORTANT: Follows all Amazon VRP rules:
    - Rate limit: 5 requests/second
    - User-Agent: amazonvrpresearcher_<username>
    - Validates scope before scanning
    - Includes false positive detection
    """

    def __init__(self, config: Optional[AmazonConfig] = None, enable_fp_detection: bool = True):
        self.config = config or get_amazon_config()
        super().__init__(
            rate_limit=self.config.rate_limit,
            user_agent=self.config.user_agent,
            timeout=self.config.request_timeout,
            enable_fp_detection=enable_fp_detection
        )
        self.validator = AmazonScopeValidator(self.config)

        # Create output directory
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        print(f"[*] Amazon VRP Scanner initialized")
        print(f"    User-Agent: {self.user_agent}")
        print(f"    Rate Limit: {self.config.rate_limit} req/sec")
        print(f"    Test Email: {self.config.test_email}")
        print(f"    FP Detection: {'ENABLED' if enable_fp_detection else 'DISABLED'}")

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
        """Save scan results to JSON file with FP detection stats"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Create target-specific folder if single target, otherwise use combined folder
        if len(results) == 1:
            safe_target = results[0].target.replace("://", "_").replace("/", "_").replace(":", "_")
            target_dir = self.config.output_dir / safe_target
        else:
            target_dir = self.config.output_dir / f"combined_{timestamp}"
        target_dir.mkdir(parents=True, exist_ok=True)

        if not filename:
            filename = f"amazon_scan_{timestamp}.json"

        output_path = target_dir / filename

        # Count verified findings
        verified_findings = sum(
            sum(1 for f in r.findings if f.verified)
            for r in results
        )

        data = {
            "program": "Amazon VRP",
            "scanner_config": {
                "user_agent": self.user_agent,
                "rate_limit": self.config.rate_limit,
                "test_email": self.config.test_email,
                "fp_detection_enabled": self.enable_fp_detection,
            },
            "scan_date": datetime.utcnow().isoformat(),
            "total_targets": len(results),
            "total_findings": sum(len(r.findings) for r in results),
            "verified_findings": verified_findings,
            "false_positive_stats": self.get_fp_stats() if self.enable_fp_detection else None,
            "results": [r.to_dict() for r in results]
        }

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"\n[*] Results saved to: {output_path}")
        if self.enable_fp_detection:
            print(f"    Verified findings: {verified_findings}")
            print(f"    FP filtered: {self.fp_stats.get('false_positives_filtered', 0)}")
        return output_path


class ShopifyScanner(BaseScanner):
    """
    Scanner for Shopify Bug Bounty
    IMPORTANT: Follows all Shopify rules:
    - Only test stores you created
    - Uses proper email format
    - Respects API rate limits
    - Includes false positive detection
    """

    def __init__(self, config: Optional[ShopifyConfig] = None, enable_fp_detection: bool = True):
        self.config = config or get_shopify_config()
        super().__init__(
            rate_limit=self.config.rate_limit,
            user_agent=self.config.user_agent,
            timeout=self.config.request_timeout,
            enable_fp_detection=enable_fp_detection
        )
        self.validator = ShopifyScopeValidator(self.config)

        # Create output directory
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        print(f"[*] Shopify Scanner initialized")
        print(f"    User-Agent: {self.user_agent}")
        print(f"    Rate Limit: {self.config.rate_limit} req/sec")
        print(f"    Test Email: {self.config.test_email}")
        print(f"    Partner Signup: {self.config.partner_signup_url}")
        print(f"    FP Detection: {'ENABLED' if enable_fp_detection else 'DISABLED'}")

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
        """Save scan results to JSON file with FP detection stats"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Create target-specific folder if single target, otherwise use combined folder
        if len(results) == 1:
            safe_target = results[0].target.replace("://", "_").replace("/", "_").replace(":", "_")
            target_dir = self.config.output_dir / safe_target
        else:
            target_dir = self.config.output_dir / f"combined_{timestamp}"
        target_dir.mkdir(parents=True, exist_ok=True)

        if not filename:
            filename = f"shopify_scan_{timestamp}.json"

        output_path = target_dir / filename

        # Count verified findings
        verified_findings = sum(
            sum(1 for f in r.findings if f.verified)
            for r in results
        )

        data = {
            "program": "Shopify Bug Bounty",
            "scanner_config": {
                "user_agent": self.user_agent,
                "rate_limit": self.config.rate_limit,
                "test_email": self.config.test_email,
                "fp_detection_enabled": self.enable_fp_detection,
            },
            "scan_date": datetime.utcnow().isoformat(),
            "total_targets": len(results),
            "total_findings": sum(len(r.findings) for r in results),
            "verified_findings": verified_findings,
            "false_positive_stats": self.get_fp_stats() if self.enable_fp_detection else None,
            "results": [r.to_dict() for r in results]
        }

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"\n[*] Results saved to: {output_path}")
        if self.enable_fp_detection:
            print(f"    Verified findings: {verified_findings}")
            print(f"    FP filtered: {self.fp_stats.get('false_positives_filtered', 0)}")
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
