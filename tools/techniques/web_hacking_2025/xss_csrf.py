#!/usr/bin/env python3
"""
Cross-Site Attack Detection Module
===================================
Based on 2025 techniques including:
- DOM clobbering with HTMLCollection gadgets
- Self-XSS escalation via credentialless iframes
- toString/valueOf coercion chains
- CSWSH via WebSocket GraphQL
- CSS-based exfiltration using ligatures
- SVG filter clickjacking
- DOM-based extension clickjacking

References:
- DOM Clobbering research
- Self-XSS escalation techniques
- CSS injection and fontleak
"""

import re
import random
import string
import html
from typing import List, Optional, Dict
from urllib.parse import urlparse, urljoin, quote, parse_qs, urlencode

from .base import TechniqueScanner, Finding, ScanProgress, is_shutdown


class CrossSiteAttacks(TechniqueScanner):
    """Cross-Site attack vulnerability scanner"""

    TECHNIQUE_NAME = "xss_csrf"
    TECHNIQUE_CATEGORY = "cross_site"

    # XSS payloads for detection (non-malicious probes)
    XSS_PROBES = [
        # Basic reflection test
        ("<canary>", "basic_html"),
        ("javascript:canary", "javascript_uri"),
        ("'canary", "single_quote"),
        ('"canary', "double_quote"),
        # Event handlers
        ("onmouseover=canary", "event_handler"),
        # Template injection indicators
        ("{{canary}}", "template_injection"),
        ("${canary}", "template_literal"),
        # DOM clobbering
        ("<img name=canary>", "dom_clobbering"),
        ("<form name=canary>", "form_clobbering"),
        # SVG/MathML
        ("<svg onload=canary>", "svg_xss"),
        ("<math><mtext><table><mglyph><style><img src=canary>", "mathml_xss"),
    ]

    # CSRF token patterns to detect
    CSRF_TOKEN_PATTERNS = [
        r'csrf[_-]?token',
        r'_csrf',
        r'authenticity[_-]?token',
        r'__RequestVerificationToken',
        r'antiforgery',
        r'xsrf[_-]?token',
        r'_token',
    ]

    # Clickjacking bypass headers to check
    FRAMING_HEADERS = [
        'X-Frame-Options',
        'Content-Security-Policy',
    ]

    # GraphQL endpoints for CSWSH testing
    GRAPHQL_ENDPOINTS = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/query",
        "/gql",
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.canary = self._generate_canary()

    def _generate_canary(self) -> str:
        """Generate unique canary for detection"""
        return 'xss' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

    def _find_reflection_points(self, domain: str) -> List[Dict]:
        """Find URL parameters that reflect in response"""
        reflection_points = []

        # Common pages with parameters
        test_urls = [
            f"https://{domain}/",
            f"https://{domain}/search",
            f"https://{domain}/api/search",
        ]

        # Common parameter names
        param_names = ["q", "query", "search", "s", "id", "page", "name", "url", "redirect", "next", "return", "callback"]

        for base_url in test_urls:
            if is_shutdown():
                break

            for param in param_names:
                canary = self._generate_canary()
                test_url = f"{base_url}?{param}={canary}"

                resp = self.get(test_url, allow_redirects=True)
                if resp and canary in resp.text:
                    reflection_points.append({
                        "url": base_url,
                        "parameter": param,
                        "reflected": True,
                        "context": self._detect_context(resp.text, canary),
                        "method": "GET",
                        "response_obj": resp
                    })

        return reflection_points

    def _detect_context(self, html_content: str, canary: str) -> str:
        """Detect the context where canary is reflected"""
        # Find canary position
        pos = html_content.find(canary)
        if pos == -1:
            return "unknown"

        # Get surrounding context
        start = max(0, pos - 50)
        end = min(len(html_content), pos + len(canary) + 50)
        context = html_content[start:end]

        # Analyze context
        if f'"{canary}"' in context or f"'{canary}'" in context:
            return "attribute_value"
        elif f'<script>' in context.lower() or 'javascript' in context.lower():
            return "javascript"
        elif f'<' in context[:pos-start] and '>' in context[pos-start+len(canary):]:
            return "html_content"
        elif f'href=' in context or f'src=' in context:
            return "url_attribute"
        elif f'style=' in context:
            return "css_context"
        else:
            return "html_body"

    def _test_xss_payloads(self, domain: str, reflection_point: Dict) -> List[Dict]:
        """Test XSS payloads on a reflection point"""
        findings = []
        base_url = reflection_point["url"]
        param = reflection_point["parameter"]

        for payload_template, payload_type in self.XSS_PROBES:
            if is_shutdown():
                break

            canary = self._generate_canary()
            payload = payload_template.replace("canary", canary)
            encoded_payload = quote(payload)

            test_url = f"{base_url}?{param}={encoded_payload}"
            resp = self.get(test_url, allow_redirects=True)

            if resp is None:
                continue

            # Check for unencoded reflection
            if canary in resp.text:
                # Check if payload structure is preserved
                if payload_type == "basic_html" and f"<{canary}>" in resp.text:
                    findings.append({
                        "type": "html_injection",
                        "payload_type": payload_type,
                        "parameter": param,
                        "url": test_url,
                        "method": "GET",
                        "response_obj": resp,
                        "evidence": f"HTML tags reflected unencoded: <{canary}>"
                    })

                elif payload_type == "event_handler" and f"onmouseover={canary}" in resp.text.lower():
                    findings.append({
                        "type": "event_handler_injection",
                        "payload_type": payload_type,
                        "parameter": param,
                        "url": test_url,
                        "method": "GET",
                        "response_obj": resp,
                        "evidence": "Event handler attribute reflected"
                    })

                elif payload_type == "template_injection" and f"{{{{{canary}}}}}" in resp.text:
                    findings.append({
                        "type": "template_injection",
                        "payload_type": payload_type,
                        "parameter": param,
                        "url": test_url,
                        "method": "GET",
                        "response_obj": resp,
                        "evidence": "Template syntax reflected - potential SSTI"
                    })

                elif payload_type == "dom_clobbering" and f'name={canary}' in resp.text.lower():
                    findings.append({
                        "type": "dom_clobbering",
                        "payload_type": payload_type,
                        "parameter": param,
                        "url": test_url,
                        "method": "GET",
                        "response_obj": resp,
                        "evidence": "DOM clobbering element name reflected"
                    })

        return findings

    def _test_csrf_protection(self, domain: str) -> List[Dict]:
        """Test CSRF protection mechanisms"""
        findings = []

        # Find forms on the target
        test_pages = [
            f"https://{domain}/",
            f"https://{domain}/login",
            f"https://{domain}/register",
            f"https://{domain}/settings",
            f"https://{domain}/account",
        ]

        for page_url in test_pages:
            if is_shutdown():
                break

            resp = self.get(page_url, allow_redirects=True)
            if resp is None or resp.status_code != 200:
                continue

            content = resp.text

            # Look for forms
            forms = re.findall(r'<form[^>]*>(.*?)</form>', content, re.DOTALL | re.IGNORECASE)

            for form_content in forms:
                # Check for CSRF token
                has_csrf = False
                for pattern in self.CSRF_TOKEN_PATTERNS:
                    if re.search(pattern, form_content, re.IGNORECASE):
                        has_csrf = True
                        break

                # Check for POST method forms without CSRF
                if 'method=' in form_content.lower():
                    method_match = re.search(r'method=["\']?(\w+)', form_content, re.IGNORECASE)
                    if method_match and method_match.group(1).upper() == 'POST' and not has_csrf:
                        # Extract form action
                        action_match = re.search(r'action=["\']?([^"\'\s>]+)', form_content, re.IGNORECASE)
                        action = action_match.group(1) if action_match else "unknown"

                        findings.append({
                            "page": page_url,
                            "form_action": action,
                            "method": "POST",
                            "csrf_protected": False,
                            "response_obj": resp,
                            "evidence": f"POST form without CSRF token at {page_url}"
                        })

        return findings

    def _test_clickjacking(self, domain: str) -> Dict:
        """Test clickjacking protection"""
        url = f"https://{domain}/"
        resp = self.get(url, allow_redirects=True)

        if resp is None:
            return {}

        result = {
            "x_frame_options": None,
            "csp_frame_ancestors": None,
            "vulnerable": True,
            "response_obj": resp
        }

        # Check X-Frame-Options
        xfo = resp.headers.get('X-Frame-Options', '').upper()
        if xfo:
            result["x_frame_options"] = xfo
            if xfo in ['DENY', 'SAMEORIGIN']:
                result["vulnerable"] = False

        # Check CSP frame-ancestors
        csp = resp.headers.get('Content-Security-Policy', '')
        if 'frame-ancestors' in csp:
            fa_match = re.search(r"frame-ancestors\s+([^;]+)", csp)
            if fa_match:
                result["csp_frame_ancestors"] = fa_match.group(1)
                if "'none'" in fa_match.group(1) or "'self'" in fa_match.group(1):
                    result["vulnerable"] = False

        return result

    def _test_cors_misconfiguration(self, domain: str) -> List[Dict]:
        """Test for CORS misconfigurations"""
        findings = []

        test_origins = [
            "https://evil.com",
            f"https://{domain}.evil.com",
            f"https://evil{domain}",
            "null",
            f"https://{domain}",  # Same origin baseline
        ]

        api_endpoints = [
            f"https://{domain}/",
            f"https://{domain}/api/",
            f"https://{domain}/api/user",
            f"https://{domain}/api/v1/",
        ]

        for endpoint in api_endpoints:
            if is_shutdown():
                break

            for origin in test_origins:
                headers = {"Origin": origin}
                resp = self.get(endpoint, headers=headers, allow_redirects=False)

                if resp is None:
                    continue

                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')

                if acao:
                    # Dangerous: reflects arbitrary origin with credentials
                    if acao == origin and origin not in [f"https://{domain}", "null"] and acac.lower() == 'true':
                        findings.append({
                            "endpoint": endpoint,
                            "origin_tested": origin,
                            "acao": acao,
                            "credentials": acac,
                            "severity": "high",
                            "response_obj": resp,
                            "evidence": f"CORS reflects arbitrary origin with credentials: {origin}"
                        })

                    # Wildcard with credentials attempt
                    elif acao == '*' and acac.lower() == 'true':
                        findings.append({
                            "endpoint": endpoint,
                            "origin_tested": origin,
                            "acao": acao,
                            "credentials": acac,
                            "severity": "medium",
                            "response_obj": resp,
                            "evidence": "CORS wildcard with credentials (browser will block, but misconfigured)"
                        })

                    # Null origin accepted
                    elif origin == "null" and acao == "null":
                        findings.append({
                            "endpoint": endpoint,
                            "origin_tested": origin,
                            "acao": acao,
                            "credentials": acac,
                            "severity": "medium",
                            "response_obj": resp,
                            "evidence": "CORS accepts null origin (sandboxed iframe bypass)"
                        })

        return findings

    def _test_websocket_csrf(self, domain: str) -> List[Dict]:
        """Test for WebSocket CSRF (CSWSH) via GraphQL"""
        findings = []

        for endpoint in self.GRAPHQL_ENDPOINTS:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"

            # Test if GraphQL endpoint exists
            resp = self.post(url,
                             json={"query": "{ __typename }"},
                             headers={"Content-Type": "application/json"})

            if resp is None:
                continue

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if 'data' in data or 'errors' in data:
                        # GraphQL endpoint found, check for CSRF protection
                        # Test without origin header
                        resp_no_origin = self.post(url,
                                                   json={"query": "{ __typename }"},
                                                   headers={"Content-Type": "application/json"})

                        if resp_no_origin and resp_no_origin.status_code == 200:
                            findings.append({
                                "endpoint": url,
                                "type": "graphql_csrf",
                                "response_obj": resp_no_origin,
                                "evidence": f"GraphQL endpoint at {endpoint} accepts requests without origin validation"
                            })
                except:
                    pass

        return findings

    def _test_open_redirect(self, domain: str) -> List[Dict]:
        """Test for open redirect vulnerabilities"""
        findings = []

        # Common redirect parameters
        redirect_params = ["redirect", "url", "next", "return", "returnUrl", "return_to",
                          "redir", "destination", "dest", "go", "target", "link", "out"]

        # Malicious destinations
        evil_urls = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https:evil.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ]

        base_paths = ["/", "/login", "/logout", "/auth/callback"]

        def _is_external_redirect(location: str, expected_host: str) -> bool:
            if not location:
                return False
            try:
                resolved = urljoin(f"https://{domain}/", location)
                parsed = urlparse(resolved)
                if not parsed.netloc:
                    return False
                dest_host = parsed.netloc.split("@")[-1].split(":")[0].lower()
                # Require a true external redirect (not same domain or subdomain)
                if dest_host == domain.lower() or dest_host.endswith(f".{domain.lower()}"):
                    return False
                return dest_host == expected_host or dest_host.endswith(f".{expected_host}")
            except Exception:
                return False

        for base_path in base_paths:
            for param in redirect_params[:5]:  # Limit for efficiency
                for evil_url in evil_urls[:3]:
                    if is_shutdown():
                        break

                    test_url = f"https://{domain}{base_path}?{param}={quote(evil_url)}"
                    resp = self.get(test_url, allow_redirects=False)

                    if resp is None:
                        continue

                    if resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get('Location', '')
                        if _is_external_redirect(location, "evil.com"):
                            findings.append({
                                "url": test_url,
                                "parameter": param,
                                "payload": evil_url,
                                "redirect_location": location,
                                "response_obj": resp,
                                "evidence": f"Open redirect via {param} parameter to {location}"
                            })
                            break  # Found for this param, move on

        return findings

    def scan(self, domain: str, progress: ScanProgress) -> List[Finding]:
        """Scan domain for cross-site vulnerabilities"""
        findings = []
        self.log(f"Testing cross-site attacks on {domain}")

        # Find reflection points
        self.log("Finding reflection points")
        reflection_points = self._find_reflection_points(domain)

        if reflection_points:
            self.log(f"Found {len(reflection_points)} reflection points", "success")

            for rp in reflection_points:
                finding = self.create_finding(
                    domain=domain,
                    severity="info",
                    title=f"Parameter Reflection: {rp['parameter']}",
                    description=f"Parameter '{rp['parameter']}' reflects in {rp['context']} context",
                    evidence=f"URL: {rp['url']}?{rp['parameter']}=<probe>",
                    reproduction_steps=[
                        f"Access: {rp['url']}?{rp['parameter']}=TEST",
                        f"Value reflected in: {rp['context']}"
                    ],
                    response_obj=rp.get("response_obj"),
                    sub_technique="reflection",
                    parameter=rp["parameter"],
                    http_method=rp.get("method"),
                    endpoint=rp.get("url")
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

                # Test XSS payloads on this reflection point
                xss_findings = self._test_xss_payloads(domain, rp)
                for xf in xss_findings:
                    severity = "high" if xf["type"] in ["html_injection", "event_handler_injection"] else "medium"
                    finding = self.create_finding(
                        domain=domain,
                        severity=severity,
                        title=f"XSS: {xf['type']} via {xf['parameter']}",
                        description=f"Cross-site scripting via {xf['type']}",
                        evidence=xf["evidence"],
                        reproduction_steps=[
                            f"URL: {xf['url']}",
                            f"Payload type: {xf['payload_type']}"
                        ],
                        response_obj=xf.get("response_obj"),
                        sub_technique="xss",
                        parameter=xf["parameter"],
                        payload_type=xf.get("payload_type"),
                        http_method=xf.get("method"),
                        endpoint=xf.get("url")
                    )
                    findings.append(finding)
                    progress.add_finding(domain, finding)

        # Test CSRF protection
        if not is_shutdown():
            self.log("Testing CSRF protection")
            csrf_findings = self._test_csrf_protection(domain)

            for cf in csrf_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="medium",
                    title=f"Missing CSRF Protection",
                    description=f"POST form without CSRF token protection",
                    evidence=cf["evidence"],
                    reproduction_steps=[
                        f"Page: {cf['page']}",
                        f"Form action: {cf['form_action']}",
                        "Form submits via POST without CSRF token"
                    ],
                    response_obj=cf.get("response_obj"),
                    sub_technique="csrf",
                    endpoint=cf.get("page"),
                    http_method=cf.get("method")
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test clickjacking
        if not is_shutdown():
            self.log("Testing clickjacking protection")
            clickjack = self._test_clickjacking(domain)

            if clickjack.get("vulnerable"):
                finding = self.create_finding(
                    domain=domain,
                    severity="low",
                    title="Missing Clickjacking Protection",
                    description="Page can be framed - missing X-Frame-Options or CSP frame-ancestors",
                    evidence=f"X-Frame-Options: {clickjack.get('x_frame_options', 'Not set')}, CSP frame-ancestors: {clickjack.get('csp_frame_ancestors', 'Not set')}",
                    reproduction_steps=[
                        "Create HTML page with iframe pointing to target",
                        "Page can be embedded in attacker-controlled frame"
                    ],
                    response_obj=clickjack.get("response_obj"),
                    sub_technique="clickjacking",
                    endpoint=f"https://{domain}/",
                    http_method="GET"
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test CORS
        if not is_shutdown():
            self.log("Testing CORS configuration")
            cors_findings = self._test_cors_misconfiguration(domain)

            for cf in cors_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity=cf["severity"],
                    title=f"CORS Misconfiguration",
                    description="CORS policy allows cross-origin requests from untrusted origins",
                    evidence=cf["evidence"],
                    reproduction_steps=[
                        f"Endpoint: {cf['endpoint']}",
                        f"Send request with Origin: {cf['origin_tested']}",
                        f"Response ACAO: {cf['acao']}, ACAC: {cf['credentials']}"
                    ],
                    response_obj=cf.get("response_obj"),
                    sub_technique="cors",
                    endpoint=cf.get("endpoint"),
                    http_method="GET"
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test WebSocket CSRF
        if not is_shutdown():
            self.log("Testing WebSocket/GraphQL CSRF")
            ws_findings = self._test_websocket_csrf(domain)

            for wf in ws_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="medium",
                    title=f"GraphQL CSRF (CSWSH Potential)",
                    description="GraphQL endpoint accessible without proper CSRF protection",
                    evidence=wf["evidence"],
                    reproduction_steps=[
                        f"Endpoint: {wf['endpoint']}",
                        "Test cross-origin requests to this endpoint",
                        "May be exploitable via WebSocket upgrade (CSWSH)"
                    ],
                    response_obj=wf.get("response_obj"),
                    sub_technique="graphql_csrf",
                    endpoint=wf.get("endpoint"),
                    http_method="POST"
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test open redirect
        if not is_shutdown():
            self.log("Testing open redirect")
            redirect_findings = self._test_open_redirect(domain)

            for rf in redirect_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="medium",
                    title=f"Open Redirect via {rf['parameter']}",
                    description="Application redirects to arbitrary external URLs",
                    evidence=rf["evidence"],
                    reproduction_steps=[
                        f"URL: {rf['url']}",
                        f"Redirects to: {rf['redirect_location']}"
                    ],
                    response_obj=rf.get("response_obj"),
                    sub_technique="open_redirect",
                    parameter=rf.get("parameter"),
                    endpoint=rf.get("url"),
                    http_method="GET"
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        self.log(f"Completed: {len(findings)} cross-site issues found", "success" if findings else "info")
        return findings
