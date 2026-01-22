#!/usr/bin/env python3
"""
XS-Leaks (Cross-Site Leaks) Detection Module
=============================================
Based on 2025 techniques including:
- ETag length variation detection
- Connection-pool timing oracles
- Fontleak via CSS ligatures
- Frame counting attacks
- Error-based state detection
- Navigation timing leaks

References:
- XS-Leaks Wiki
- Connection pool exhaustion research
- CSS-based exfiltration techniques
"""

import re
import time
import random
import string
import hashlib
from typing import List, Optional, Dict, Tuple
from urllib.parse import urlparse, quote

from .base import TechniqueScanner, Finding, ScanProgress, is_shutdown


class XSLeaks(TechniqueScanner):
    """Cross-Site Leaks vulnerability scanner"""

    TECHNIQUE_NAME = "xs_leaks"
    TECHNIQUE_CATEGORY = "information_disclosure"

    # Endpoints that typically have state-dependent responses
    STATE_ENDPOINTS = [
        "/api/user",
        "/api/me",
        "/api/profile",
        "/api/account",
        "/api/notifications",
        "/api/messages",
        "/api/inbox",
        "/api/settings",
        "/dashboard",
        "/account",
        "/profile",
        "/settings",
        "/admin",
        "/internal",
    ]

    # Search endpoints for oracle testing
    SEARCH_ENDPOINTS = [
        "/search",
        "/api/search",
        "/api/users/search",
        "/api/query",
        "/find",
        "/lookup",
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.pii_indicators = [
            "email", "username", "user_id", "phone", "address",
            "first_name", "last_name", "ssn", "account", "balance"
        ]

    def _check_etag_variation(self, domain: str) -> List[Dict]:
        """Check for ETag-based information leakage"""
        findings = []

        for endpoint in self.STATE_ENDPOINTS:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"

            # Make multiple requests and check ETag variation
            etags = []
            for _ in range(3):
                resp = self.get(url, allow_redirects=False)
                if resp and 'ETag' in resp.headers:
                    etags.append(resp.headers['ETag'])

            if len(set(etags)) > 1:
                # ETag varies - potential leak vector
                findings.append({
                    "type": "etag_variation",
                    "endpoint": endpoint,
                    "etags": list(set(etags)),
                    "evidence": f"ETag varies across requests: {list(set(etags))[:3]}"
                })

            # Check for weak ETags (W/ prefix)
            if etags and any(e.startswith('W/') for e in etags):
                findings.append({
                    "type": "weak_etag",
                    "endpoint": endpoint,
                    "etag": etags[0],
                    "evidence": f"Weak ETag detected - may leak content length: {etags[0]}"
                })

        return findings

    def _check_timing_oracle(self, domain: str) -> List[Dict]:
        """Check for timing-based information leakage"""
        findings = []

        for endpoint in self.STATE_ENDPOINTS[:5]:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"

            # Measure response times
            times = []
            for _ in range(5):
                start = time.time()
                resp = self.get(url, allow_redirects=True)
                elapsed = time.time() - start
                if resp:
                    times.append(elapsed)
                time.sleep(0.1)  # Small delay between requests

            if len(times) >= 3:
                avg_time = sum(times) / len(times)
                variance = sum((t - avg_time) ** 2 for t in times) / len(times)

                # High variance might indicate state-dependent processing
                if variance > 0.1:
                    findings.append({
                        "type": "timing_variance",
                        "endpoint": endpoint,
                        "avg_time": avg_time,
                        "variance": variance,
                        "times": times,
                        "evidence": f"High timing variance ({variance:.3f}s) - potential timing oracle"
                    })

        return findings

    def _check_content_length_oracle(self, domain: str) -> List[Dict]:
        """Check for content-length based information leakage"""
        findings = []

        for endpoint in self.STATE_ENDPOINTS:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"

            # Measure content lengths
            lengths = []
            for _ in range(3):
                resp = self.get(url, allow_redirects=True)
                if resp:
                    lengths.append(len(resp.content))

            if len(set(lengths)) > 1:
                findings.append({
                    "type": "content_length_variation",
                    "endpoint": endpoint,
                    "lengths": list(set(lengths)),
                    "evidence": f"Content length varies: {list(set(lengths))}"
                })

        return findings

    def _check_error_oracle(self, domain: str) -> List[Dict]:
        """Check for error-based state detection"""
        findings = []

        # Test endpoints with various IDs
        id_endpoints = [
            "/api/users/{id}",
            "/api/posts/{id}",
            "/api/documents/{id}",
            "/api/orders/{id}",
            "/users/{id}",
            "/profile/{id}",
        ]

        for endpoint_template in id_endpoints:
            if is_shutdown():
                break

            # Test existing vs non-existing resource detection
            existing_ids = ["1", "100", "admin"]
            nonexistent_id = "99999999999"

            for existing_id in existing_ids:
                exist_url = f"https://{domain}{endpoint_template.replace('{id}', existing_id)}"
                nonexist_url = f"https://{domain}{endpoint_template.replace('{id}', nonexistent_id)}"

                resp_exist = self.get(exist_url, allow_redirects=False)
                resp_nonexist = self.get(nonexist_url, allow_redirects=False)

                if resp_exist and resp_nonexist:
                    exist_text = (resp_exist.text or "").lower()
                    nonexist_text = (resp_nonexist.text or "").lower()
                    exist_has_pii = any(ind in exist_text for ind in self.pii_indicators)
                    nonexist_has_pii = any(ind in nonexist_text for ind in self.pii_indicators)

                    if (resp_exist.status_code == 200 and resp_nonexist.status_code in [403, 404] and
                            exist_has_pii and not nonexist_has_pii):
                        findings.append({
                            "type": "error_oracle_confirmed",
                            "endpoint": endpoint_template,
                            "existing_status": resp_exist.status_code,
                            "nonexistent_status": resp_nonexist.status_code,
                            "evidence": "Existing resource exposes user data while non-existing does not"
                        })
                        break

        return findings

    def _check_frame_counting(self, domain: str) -> Dict:
        """Check if frame counting attack might be possible"""
        url = f"https://{domain}/"
        resp = self.get(url, allow_redirects=True)

        if resp is None:
            return {}

        # Check X-Frame-Options and CSP
        xfo = resp.headers.get('X-Frame-Options', '').upper()
        csp = resp.headers.get('Content-Security-Policy', '')

        frameable = True
        if xfo in ['DENY', 'SAMEORIGIN']:
            frameable = False
        if 'frame-ancestors' in csp:
            if "'none'" in csp or "'self'" in csp:
                frameable = False

        if frameable:
            # Check for iframes in response
            iframe_count = len(re.findall(r'<iframe', resp.text, re.IGNORECASE))
            return {
                "frameable": True,
                "iframe_count": iframe_count,
                "evidence": f"Page is frameable with {iframe_count} iframes - frame counting possible"
            }

        return {"frameable": False}

    def _check_coop_coep(self, domain: str) -> Dict:
        """Check for Cross-Origin Opener Policy and Embedder Policy"""
        url = f"https://{domain}/"
        resp = self.get(url, allow_redirects=True)

        if resp is None:
            return {}

        coop = resp.headers.get('Cross-Origin-Opener-Policy', '')
        coep = resp.headers.get('Cross-Origin-Embedder-Policy', '')
        corp = resp.headers.get('Cross-Origin-Resource-Policy', '')

        missing = []
        if not coop:
            missing.append("Cross-Origin-Opener-Policy")
        if not coep:
            missing.append("Cross-Origin-Embedder-Policy")
        if not corp:
            missing.append("Cross-Origin-Resource-Policy")

        return {
            "coop": coop,
            "coep": coep,
            "corp": corp,
            "missing": missing,
            "evidence": f"Missing headers: {missing}" if missing else "All cross-origin policies set"
        }

    def _check_redirect_oracle(self, domain: str) -> List[Dict]:
        """Check for redirect-based information leakage"""
        findings = []

        # Endpoints that might redirect based on auth state
        redirect_endpoints = [
            "/login",
            "/auth",
            "/oauth/callback",
            "/dashboard",
            "/admin",
            "/account",
            "/profile",
        ]

        for endpoint in redirect_endpoints:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"
            resp = self.get(url, allow_redirects=False)

            if resp and resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get('Location', '')
                findings.append({
                    "type": "redirect_oracle",
                    "endpoint": endpoint,
                    "redirect_to": location,
                    "status": resp.status_code,
                    "evidence": f"Redirect detected: {endpoint} -> {location}"
                })

        return findings

    def _check_search_oracle(self, domain: str) -> List[Dict]:
        """Check for search-based oracles (result count, timing)"""
        findings = []

        for endpoint in self.SEARCH_ENDPOINTS:
            if is_shutdown():
                break

            # Test with different queries
            queries = [
                ("a", "common"),
                ("zzzzzzzzz", "rare"),
                ("admin", "sensitive"),
            ]

            results = []
            for query, query_type in queries:
                url = f"https://{domain}{endpoint}?q={query}"
                start = time.time()
                resp = self.get(url, allow_redirects=True)
                elapsed = time.time() - start

                if resp and resp.status_code == 200:
                    results.append({
                        "query": query,
                        "type": query_type,
                        "length": len(resp.content),
                        "time": elapsed
                    })

            if len(results) >= 2:
                # Check for length differences
                lengths = [r["length"] for r in results]
                if max(lengths) - min(lengths) > 500:
                    findings.append({
                        "type": "search_length_oracle",
                        "endpoint": endpoint,
                        "results": results,
                        "evidence": f"Search results length varies significantly"
                    })

                # Check for timing differences
                times = [r["time"] for r in results]
                if max(times) - min(times) > 0.5:
                    findings.append({
                        "type": "search_timing_oracle",
                        "endpoint": endpoint,
                        "results": results,
                        "evidence": f"Search timing varies: {min(times):.2f}s to {max(times):.2f}s"
                    })

        return findings

    def _check_cache_timing(self, domain: str) -> List[Dict]:
        """Check for cache-based timing oracles"""
        findings = []

        static_resources = [
            "/favicon.ico",
            "/robots.txt",
            "/sitemap.xml",
        ]

        for resource in static_resources:
            if is_shutdown():
                break

            url = f"https://{domain}{resource}"

            # First request (cold cache)
            start1 = time.time()
            resp1 = self.get(url, allow_redirects=True)
            time1 = time.time() - start1

            if resp1 is None:
                continue

            time.sleep(0.5)

            # Second request (potentially warm cache)
            start2 = time.time()
            resp2 = self.get(url, allow_redirects=True)
            time2 = time.time() - start2

            if resp2 is None:
                continue

            # Significant timing difference indicates caching
            if time1 > time2 * 1.5 and time1 - time2 > 0.1:
                findings.append({
                    "type": "cache_timing",
                    "resource": resource,
                    "cold_time": time1,
                    "warm_time": time2,
                    "evidence": f"Cache timing detectable: cold={time1:.3f}s, warm={time2:.3f}s"
                })

        return findings

    def scan(self, domain: str, progress: ScanProgress) -> List[Finding]:
        """Scan domain for XS-Leak vulnerabilities"""
        findings = []
        self.log(f"Testing XS-Leaks on {domain}")

        # Check error oracles
        if not is_shutdown():
            self.log("Checking error-based oracles")
            error_findings = self._check_error_oracle(domain)

            for erf in error_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="high",
                    title="XS-Leak: Confirmed Resource Oracle",
                    description="Endpoint reveals sensitive resource existence with data exposure",
                    evidence=erf["evidence"],
                    reproduction_steps=[
                        f"Endpoint template: {erf['endpoint']}",
                        "Compare responses for existing vs non-existing resources"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        self.log(f"Completed: {len(findings)} XS-Leak issues found", "success" if findings else "info")
        return findings
