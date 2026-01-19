#!/usr/bin/env python3
"""
Cache Poisoning & Desynchronization Detection Module
=====================================================
Based on 2025 techniques including:
- Unkeyed header poisoning
- Stale-while-revalidate exploitation
- Response batching race conditions
- Cache key normalization issues
- HTTP/2 cache poisoning via pseudo-headers

References:
- Web Cache Deception attacks
- Cache poisoning via unkeyed headers
- Next.js response cache batcher racing
"""

import time
import random
import string
import hashlib
import re
from typing import List, Optional, Dict, Tuple
from urllib.parse import urlparse, urljoin, quote
from dataclasses import dataclass

from .base import TechniqueScanner, Finding, ScanProgress, is_shutdown


@dataclass
class CacheTestResult:
    """Result of a cache test"""
    cached: bool
    cache_headers: Dict[str, str]
    response_time_first: float
    response_time_cached: float
    cache_key_indicators: List[str]


class CachePoisoning(TechniqueScanner):
    """Cache Poisoning vulnerability scanner"""

    TECHNIQUE_NAME = "cache_poisoning"
    TECHNIQUE_CATEGORY = "cache_attacks"

    # Unkeyed headers to test
    UNKEYED_HEADERS = [
        ("X-Forwarded-Host", "{canary}.evil.com"),
        ("X-Forwarded-Scheme", "nothttps"),
        ("X-Forwarded-Proto", "nothttps"),
        ("X-Original-URL", "/{canary}"),
        ("X-Rewrite-URL", "/{canary}"),
        ("X-Host", "{canary}.evil.com"),
        ("X-Forwarded-Server", "{canary}.evil.com"),
        ("X-HTTP-Host-Override", "{canary}.evil.com"),
        ("Forwarded", "host={canary}.evil.com"),
        ("X-Original-Host", "{canary}.evil.com"),
        ("True-Client-IP", "127.0.0.1"),
        ("X-Real-IP", "127.0.0.1"),
        ("X-Client-IP", "127.0.0.1"),
        ("Client-IP", "127.0.0.1"),
        ("X-Originating-IP", "127.0.0.1"),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("X-WAF-Bypass", "1"),
        ("X-Debug", "1"),
        ("X-Forwarded-Port", "1337"),
    ]

    # Path normalization tests for cache deception
    PATH_NORMALIZATION = [
        ("Path traversal", "..%2f"),
        ("Double encoding", "%252f"),
        ("Backslash", "..\\"),
        ("Null byte", "%00"),
        ("Tab encoding", "%09"),
        ("Semicolon path", ";"),
        ("Unicode slash", "%c0%af"),
    ]

    # Static extensions for cache deception
    STATIC_EXTENSIONS = [
        ".css", ".js", ".jpg", ".png", ".gif", ".ico", ".svg",
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".json"
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cache_buster = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

    def _generate_canary(self) -> str:
        """Generate a unique canary value for detection"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))

    def _check_caching(self, domain: str, path: str = "/") -> Optional[CacheTestResult]:
        """Check if a URL is being cached"""
        url = f"https://{domain}{path}"

        # Add cache buster to avoid poisoning real cache
        buster = f"?cb={self._generate_canary()}"
        test_url = url + buster

        # First request
        start1 = time.time()
        resp1 = self.get(test_url)
        time1 = time.time() - start1

        if resp1 is None:
            return None

        # Second request
        time.sleep(0.5)
        start2 = time.time()
        resp2 = self.get(test_url)
        time2 = time.time() - start2

        if resp2 is None:
            return None

        # Analyze cache headers
        cache_headers = {}
        cache_indicators = []

        for header in ['Cache-Control', 'X-Cache', 'X-Cache-Status', 'CF-Cache-Status',
                       'Age', 'X-Varnish', 'Via', 'X-Proxy-Cache', 'X-CDN-Cache-Status',
                       'X-Fastly-Request-ID', 'X-Akamai-Staging']:
            if header in resp1.headers:
                cache_headers[header] = resp1.headers[header]

        # Detect caching indicators
        if 'X-Cache' in resp1.headers:
            cache_indicators.append(f"X-Cache: {resp1.headers['X-Cache']}")
        if 'CF-Cache-Status' in resp1.headers:
            cache_indicators.append(f"Cloudflare: {resp1.headers['CF-Cache-Status']}")
        if 'Age' in resp1.headers:
            cache_indicators.append(f"Age: {resp1.headers['Age']}")
        if 'X-Varnish' in resp1.headers:
            cache_indicators.append("Varnish detected")

        # Determine if cached (HIT on second request or significant time difference)
        cached = False
        if 'X-Cache' in resp2.headers and 'HIT' in resp2.headers['X-Cache'].upper():
            cached = True
        elif 'CF-Cache-Status' in resp2.headers and resp2.headers['CF-Cache-Status'] in ['HIT', 'DYNAMIC']:
            cached = True
        elif time1 > 0 and time2 < time1 * 0.5:  # Second request much faster
            cached = True

        return CacheTestResult(
            cached=cached,
            cache_headers=cache_headers,
            response_time_first=time1,
            response_time_cached=time2,
            cache_key_indicators=cache_indicators
        )

    def _test_unkeyed_header_poisoning(self, domain: str, path: str = "/") -> List[Dict]:
        """Test for unkeyed header cache poisoning"""
        findings = []
        canary = self._generate_canary()
        cache_buster = f"?unkh={canary}"
        url = f"https://{domain}{path}{cache_buster}"

        for header_name, header_value in self.UNKEYED_HEADERS:
            if is_shutdown():
                break

            test_value = header_value.replace("{canary}", canary)
            headers = {header_name: test_value}

            # Send poisoning request
            resp1 = self.get(url, headers=headers)
            if resp1 is None:
                continue

            # Check if header value reflected in response
            if canary in resp1.text:
                # Try without the header to see if it's cached
                time.sleep(0.5)
                resp2 = self.get(url)

                if resp2 and canary in resp2.text:
                    findings.append({
                        "header": header_name,
                        "value": test_value,
                        "url": url,
                        "cached": True,
                        "evidence": f"Unkeyed header '{header_name}' value cached and reflected"
                    })
                else:
                    findings.append({
                        "header": header_name,
                        "value": test_value,
                        "url": url,
                        "cached": False,
                        "evidence": f"Header '{header_name}' reflected but not cached (still potential for exploitation)"
                    })

        return findings

    def _test_cache_deception(self, domain: str) -> List[Dict]:
        """Test for web cache deception vulnerabilities"""
        findings = []
        canary = self._generate_canary()

        # Test URLs that might contain sensitive data
        sensitive_paths = [
            "/account",
            "/profile",
            "/settings",
            "/api/user",
            "/api/me",
            "/dashboard",
            "/my-account",
        ]

        for base_path in sensitive_paths:
            if is_shutdown():
                break

            for ext in self.STATIC_EXTENSIONS[:3]:  # Test with first few extensions
                # Create path with static extension
                deception_path = f"{base_path}/anything{canary}{ext}"
                url = f"https://{domain}{deception_path}"

                resp = self.get(url, allow_redirects=True)
                if resp is None:
                    continue

                # Check if we got non-404 response with sensitive-looking content
                if resp.status_code == 200:
                    content_lower = resp.text.lower()
                    sensitive_indicators = ['email', 'password', 'token', 'api_key', 'session',
                                            'username', 'account', 'balance', 'credit']

                    for indicator in sensitive_indicators:
                        if indicator in content_lower:
                            # Check if response is being cached
                            cache_headers = {k: v for k, v in resp.headers.items()
                                             if 'cache' in k.lower() or k.lower() in ['age', 'x-varnish']}

                            if cache_headers or resp.headers.get('Cache-Control', '').find('no-') == -1:
                                findings.append({
                                    "path": deception_path,
                                    "status": resp.status_code,
                                    "indicator": indicator,
                                    "cache_headers": cache_headers,
                                    "evidence": f"Sensitive path {base_path} accessible with static extension, may cache user data"
                                })
                                break

        return findings

    def _test_path_normalization(self, domain: str) -> List[Dict]:
        """Test for cache key normalization issues"""
        findings = []

        # Test with a specific endpoint that returns different content
        test_paths = ["/", "/robots.txt", "/favicon.ico"]

        for base_path in test_paths:
            if is_shutdown():
                break

            # Get baseline response
            baseline_url = f"https://{domain}{base_path}"
            baseline = self.get(baseline_url)
            if baseline is None:
                continue

            baseline_hash = hashlib.md5(baseline.content).hexdigest()

            for norm_name, norm_char in self.PATH_NORMALIZATION:
                # Test if normalization bypasses caching
                test_path = f"/{norm_char}{base_path.lstrip('/')}"
                test_url = f"https://{domain}{test_path}"

                test_resp = self.get(test_url)
                if test_resp is None:
                    continue

                test_hash = hashlib.md5(test_resp.content).hexdigest()

                # Same content but different path = normalization issue
                if test_hash == baseline_hash and test_path != base_path:
                    findings.append({
                        "technique": norm_name,
                        "original_path": base_path,
                        "normalized_path": test_path,
                        "evidence": f"Path '{test_path}' normalizes to '{base_path}' - potential cache key issue"
                    })

        return findings

    def _test_stale_while_revalidate(self, domain: str) -> Optional[Dict]:
        """Test for stale-while-revalidate exploitation"""
        url = f"https://{domain}/"
        resp = self.get(url)

        if resp is None:
            return None

        cache_control = resp.headers.get('Cache-Control', '')

        # Check for stale-while-revalidate
        swr_match = re.search(r'stale-while-revalidate[=\s]*(\d+)?', cache_control)
        stale_if_error = 'stale-if-error' in cache_control

        if swr_match or stale_if_error:
            return {
                "cache_control": cache_control,
                "swr_present": bool(swr_match),
                "stale_if_error": stale_if_error,
                "evidence": f"Cache-Control includes stale directives: {cache_control}"
            }

        return None

    def _test_vary_header_bypass(self, domain: str) -> List[Dict]:
        """Test for Vary header bypass opportunities"""
        findings = []
        url = f"https://{domain}/"

        resp = self.get(url)
        if resp is None:
            return findings

        vary_header = resp.headers.get('Vary', '')

        if vary_header:
            # Check if Vary includes exploitable headers
            exploitable = []

            if 'User-Agent' in vary_header:
                exploitable.append("User-Agent (can be controlled)")
            if 'Accept-Language' in vary_header:
                exploitable.append("Accept-Language (can be controlled)")
            if 'Accept-Encoding' in vary_header:
                exploitable.append("Accept-Encoding (can be controlled)")
            if 'X-' in vary_header:
                # Custom X- headers in Vary
                exploitable.append(f"Custom headers in Vary: {vary_header}")

            if exploitable:
                findings.append({
                    "vary_header": vary_header,
                    "exploitable_headers": exploitable,
                    "evidence": f"Vary header includes controllable headers: {vary_header}"
                })

        return findings

    def scan(self, domain: str, progress: ScanProgress) -> List[Finding]:
        """Scan domain for cache poisoning vulnerabilities"""
        findings = []
        self.log(f"Testing cache poisoning on {domain}")

        # Check basic caching behavior
        self.log("Checking caching behavior")
        cache_result = self._check_caching(domain)

        if cache_result:
            if cache_result.cached or cache_result.cache_headers:
                self.log(f"Caching detected: {cache_result.cache_key_indicators}", "info")

                finding = self.create_finding(
                    domain=domain,
                    severity="info",
                    title="Caching Infrastructure Detected",
                    description=f"Target uses caching. Cache indicators: {', '.join(cache_result.cache_key_indicators)}",
                    evidence=f"Cache headers: {cache_result.cache_headers}",
                    reproduction_steps=[
                        "Send two identical requests",
                        f"First request time: {cache_result.response_time_first:.2f}s",
                        f"Second request time: {cache_result.response_time_cached:.2f}s",
                        "Cache headers observed in response"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test unkeyed header poisoning
        if not is_shutdown():
            self.log("Testing unkeyed header poisoning")
            header_findings = self._test_unkeyed_header_poisoning(domain)

            for hf in header_findings:
                severity = "high" if hf.get("cached") else "medium"
                finding = self.create_finding(
                    domain=domain,
                    severity=severity,
                    title=f"Unkeyed Header Poisoning: {hf['header']}",
                    description=f"Header '{hf['header']}' value is reflected and {'cached' if hf.get('cached') else 'potentially cacheable'}",
                    evidence=hf["evidence"],
                    reproduction_steps=[
                        f"Send request with header: {hf['header']}: {hf['value']}",
                        "Observe that header value is reflected in response",
                        "Second request without header may still contain poisoned content" if hf.get("cached") else "Test with different cache busters to confirm caching"
                    ],
                    header=hf["header"],
                    test_url=hf["url"]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test cache deception
        if not is_shutdown():
            self.log("Testing web cache deception")
            deception_findings = self._test_cache_deception(domain)

            for df in deception_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="high",
                    title=f"Potential Web Cache Deception",
                    description=f"Sensitive endpoint accessible with static extension, may cache user data",
                    evidence=df["evidence"],
                    reproduction_steps=[
                        f"Access sensitive path with static extension: {df['path']}",
                        f"Response contained sensitive indicator: {df['indicator']}",
                        "If cached, attacker can retrieve cached user data"
                    ],
                    sensitive_indicator=df["indicator"]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test path normalization
        if not is_shutdown():
            self.log("Testing path normalization issues")
            norm_findings = self._test_path_normalization(domain)

            for nf in norm_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="medium",
                    title=f"Cache Key Path Normalization: {nf['technique']}",
                    description="Different URL paths normalize to same content, potential cache poisoning vector",
                    evidence=nf["evidence"],
                    reproduction_steps=[
                        f"Access original path: {nf['original_path']}",
                        f"Access normalized path: {nf['normalized_path']}",
                        "Both return identical content, indicating path normalization"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test stale-while-revalidate
        if not is_shutdown():
            self.log("Checking for stale-while-revalidate")
            swr_result = self._test_stale_while_revalidate(domain)

            if swr_result:
                finding = self.create_finding(
                    domain=domain,
                    severity="low",
                    title="Stale-While-Revalidate Cache Policy",
                    description="Cache uses stale-while-revalidate which may allow serving poisoned content during revalidation window",
                    evidence=swr_result["evidence"],
                    reproduction_steps=[
                        "Observe Cache-Control header with stale-while-revalidate",
                        "Poisoned content may persist during revalidation window",
                        "Test for cache poisoning with longer TTL payloads"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test Vary header bypass
        if not is_shutdown():
            self.log("Checking Vary header configuration")
            vary_findings = self._test_vary_header_bypass(domain)

            for vf in vary_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="low",
                    title="Vary Header with Controllable Values",
                    description="Vary header includes headers that attackers can control, potential for cache-based attacks",
                    evidence=vf["evidence"],
                    reproduction_steps=[
                        f"Vary header: {vf['vary_header']}",
                        f"Exploitable headers: {', '.join(vf['exploitable_headers'])}",
                        "Test cache segmentation by varying these headers"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        self.log(f"Completed: {len(findings)} cache issues found", "success" if findings else "info")
        return findings
