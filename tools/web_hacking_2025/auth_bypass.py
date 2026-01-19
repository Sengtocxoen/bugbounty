#!/usr/bin/env python3
"""
Authentication & Authorization Bypass Detection Module
======================================================
Based on 2025 techniques including:
- SAML signature bypass (void canonicalization)
- OAuth redirect URI manipulation
- WebAuthn passkey vulnerabilities
- Path traversal auth bypass
- IPv6 userinfo parsing issues
- Authorization code injection

References:
- Void Canonicalization SAML attacks
- OAuth implicit flow weaknesses
- WebAuthn non-discoverable credential issues
"""

import re
import base64
import hashlib
import urllib.parse
from typing import List, Optional, Dict
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

from .base import TechniqueScanner, Finding, ScanProgress, is_shutdown


class AuthBypass(TechniqueScanner):
    """Authentication and Authorization bypass scanner"""

    TECHNIQUE_NAME = "auth_bypass"
    TECHNIQUE_CATEGORY = "authentication"

    # Common OAuth endpoints to discover
    OAUTH_ENDPOINTS = [
        "/oauth/authorize",
        "/oauth/token",
        "/oauth2/authorize",
        "/oauth2/token",
        "/oauth2/auth",
        "/auth/oauth",
        "/login/oauth",
        "/api/oauth/authorize",
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
        "/connect/authorize",
        "/connect/token",
    ]

    # SAML endpoints
    SAML_ENDPOINTS = [
        "/saml/login",
        "/saml/sso",
        "/saml/acs",
        "/saml/metadata",
        "/auth/saml",
        "/sso/saml",
        "/api/saml",
        "/simplesaml/",
        "/adfs/ls/",
        "/FederationMetadata/2007-06/FederationMetadata.xml",
    ]

    # Path bypass patterns
    PATH_BYPASS_PATTERNS = [
        # Case manipulation
        ("/admin", "/Admin"),
        ("/admin", "/ADMIN"),
        # Path traversal
        ("/admin", "/./admin"),
        ("/admin", "//admin"),
        ("/admin", "/admin/"),
        ("/admin", "/admin/."),
        ("/admin", "/admin/..;/admin"),
        ("/admin", "/%2e/admin"),
        ("/admin", "/admin%00"),
        ("/admin", "/admin%20"),
        ("/admin", "/admin%09"),
        # HTTP method / verb tampering headers
        ("/admin", "/admin"),
    ]

    # HTTP headers for bypass
    BYPASS_HEADERS = [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Host": "localhost"},
        {"X-Forwarded-Host": "localhost"},
        {"True-Client-IP": "127.0.0.1"},
    ]

    # OAuth redirect URI bypasses
    REDIRECT_BYPASSES = [
        # Open redirect via subdomain
        "evil.{domain}",
        "{domain}.evil.com",
        "{domain}@evil.com",
        # Path confusion
        "{domain}/callback/../../../evil.com/",
        "{domain}%2F%2Fevil.com",
        # Fragment/query confusion
        "{domain}#@evil.com",
        "{domain}?@evil.com",
        "{domain}%00@evil.com",
        # IPv6 userinfo
        "evil.com%23@{domain}",
        # Backslash normalization
        "{domain}\\@evil.com",
    ]

    def __init__(self, protected_paths: List[str] = None, **kwargs):
        super().__init__(**kwargs)
        self.protected_paths = protected_paths or [
            "/admin", "/api/admin", "/management",
            "/internal", "/debug", "/console",
            "/actuator", "/metrics", "/health"
        ]

    def _discover_oauth_endpoints(self, domain: str) -> Dict:
        """Discover OAuth endpoints and configuration"""
        oauth_info = {
            "endpoints": [],
            "openid_config": None,
            "authorization_endpoint": None,
            "token_endpoint": None
        }

        # Check well-known OpenID configuration
        openid_url = f"https://{domain}/.well-known/openid-configuration"
        resp = self.get(openid_url)

        if resp and resp.status_code == 200:
            try:
                config = resp.json()
                oauth_info["openid_config"] = config
                oauth_info["authorization_endpoint"] = config.get("authorization_endpoint")
                oauth_info["token_endpoint"] = config.get("token_endpoint")
            except:
                pass

        # Probe common endpoints
        for endpoint in self.OAUTH_ENDPOINTS:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"
            resp = self.get(url, allow_redirects=False)

            if resp and resp.status_code in [200, 302, 400, 401]:
                oauth_info["endpoints"].append({
                    "path": endpoint,
                    "status": resp.status_code,
                    "url": url
                })

        return oauth_info

    def _discover_saml_endpoints(self, domain: str) -> List[Dict]:
        """Discover SAML endpoints"""
        saml_endpoints = []

        for endpoint in self.SAML_ENDPOINTS:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"
            resp = self.get(url, allow_redirects=False)

            if resp and resp.status_code in [200, 302, 400, 405]:
                saml_endpoints.append({
                    "path": endpoint,
                    "status": resp.status_code,
                    "url": url,
                    "has_saml_content": bool(resp.text and 'saml' in resp.text.lower())
                })

        return saml_endpoints

    def _test_oauth_redirect_bypass(self, domain: str, auth_endpoint: str) -> List[Dict]:
        """Test for OAuth redirect_uri bypass vulnerabilities"""
        findings = []

        if not auth_endpoint:
            return findings

        # Parse the authorization endpoint
        parsed = urlparse(auth_endpoint)
        base_domain = parsed.netloc

        # Test various redirect_uri bypasses
        for bypass_pattern in self.REDIRECT_BYPASSES:
            if is_shutdown():
                break

            test_redirect = f"https://{bypass_pattern.format(domain=base_domain)}/callback"

            params = {
                "client_id": "test_client",
                "redirect_uri": test_redirect,
                "response_type": "code",
                "scope": "openid",
                "state": "test_state"
            }

            test_url = f"{auth_endpoint}?{urlencode(params)}"
            resp = self.get(test_url, allow_redirects=False)

            if resp is None:
                continue

            # Check if redirect was accepted (302 to our URI) or reflected
            if resp.status_code == 302:
                location = resp.headers.get('Location', '')
                if 'evil.com' in location or test_redirect in location:
                    findings.append({
                        "bypass_type": "redirect_uri_bypass",
                        "pattern": bypass_pattern,
                        "test_uri": test_redirect,
                        "response_location": location,
                        "evidence": f"Redirect URI bypass accepted: {test_redirect}"
                    })

            # Check for reflection without validation
            elif resp.status_code == 200 and test_redirect in resp.text:
                findings.append({
                    "bypass_type": "redirect_uri_reflection",
                    "pattern": bypass_pattern,
                    "test_uri": test_redirect,
                    "evidence": f"Redirect URI reflected without proper validation"
                })

        return findings

    def _test_path_bypass(self, domain: str) -> List[Dict]:
        """Test for path-based authorization bypass"""
        findings = []

        for protected_path in self.protected_paths:
            if is_shutdown():
                break

            # Get baseline response for protected path
            baseline_url = f"https://{domain}{protected_path}"
            baseline = self.get(baseline_url, allow_redirects=False)

            if baseline is None:
                continue

            baseline_status = baseline.status_code

            # Skip if already accessible (not protected)
            if baseline_status == 200:
                continue

            # Test path manipulations
            for original, bypass in self.PATH_BYPASS_PATTERNS:
                bypass_path = bypass.replace("/admin", protected_path)
                bypass_url = f"https://{domain}{bypass_path}"

                resp = self.get(bypass_url, allow_redirects=False)
                if resp and resp.status_code == 200 and resp.status_code != baseline_status:
                    findings.append({
                        "bypass_type": "path_manipulation",
                        "original_path": protected_path,
                        "bypass_path": bypass_path,
                        "original_status": baseline_status,
                        "bypass_status": resp.status_code,
                        "evidence": f"Path bypass successful: {bypass_path} returned 200 while {protected_path} returned {baseline_status}"
                    })

            # Test header-based bypasses
            for headers in self.BYPASS_HEADERS:
                # Modify header values for current path
                test_headers = {}
                for k, v in headers.items():
                    test_headers[k] = v.replace("/admin", protected_path) if "/admin" in v else v

                resp = self.get(baseline_url, headers=test_headers, allow_redirects=False)
                if resp and resp.status_code == 200 and resp.status_code != baseline_status:
                    findings.append({
                        "bypass_type": "header_bypass",
                        "path": protected_path,
                        "headers": test_headers,
                        "original_status": baseline_status,
                        "bypass_status": resp.status_code,
                        "evidence": f"Header bypass with {list(test_headers.keys())[0]}: returned 200"
                    })

            # Test HTTP method override
            method_override_headers = [
                {"X-HTTP-Method-Override": "GET"},
                {"X-Method-Override": "GET"},
                {"X-HTTP-Method": "GET"},
            ]

            for override_header in method_override_headers:
                resp = self.post(baseline_url, headers=override_header, allow_redirects=False)
                if resp and resp.status_code == 200 and baseline_status != 200:
                    findings.append({
                        "bypass_type": "method_override",
                        "path": protected_path,
                        "header": list(override_header.keys())[0],
                        "evidence": f"HTTP method override bypass successful"
                    })

        return findings

    def _test_idor_patterns(self, domain: str) -> List[Dict]:
        """Test for basic IDOR patterns"""
        findings = []

        # Common IDOR endpoints
        idor_patterns = [
            "/api/users/{id}",
            "/api/user/{id}",
            "/api/account/{id}",
            "/api/profile/{id}",
            "/api/orders/{id}",
            "/api/documents/{id}",
            "/users/{id}",
            "/user/{id}/profile",
            "/download/{id}",
            "/file/{id}",
        ]

        for pattern in idor_patterns[:5]:  # Limit to first 5 for efficiency
            if is_shutdown():
                break

            # Test with ID 1 (common admin/first user)
            test_path = pattern.replace("{id}", "1")
            url = f"https://{domain}{test_path}"

            resp = self.get(url, allow_redirects=False)
            if resp and resp.status_code == 200:
                # Check if response contains user data indicators
                content = resp.text.lower()
                indicators = ['email', 'username', 'phone', 'address', 'name']

                for indicator in indicators:
                    if indicator in content:
                        findings.append({
                            "endpoint": test_path,
                            "id_tested": "1",
                            "status": resp.status_code,
                            "indicator": indicator,
                            "evidence": f"IDOR endpoint found: {test_path} - contains '{indicator}'"
                        })
                        break

        return findings

    def _test_jwt_vulnerabilities(self, domain: str) -> List[Dict]:
        """Check for JWT-related vulnerabilities in authentication"""
        findings = []

        # Check common auth endpoints for JWT usage
        auth_endpoints = ["/api/login", "/auth/login", "/login", "/api/auth"]

        for endpoint in auth_endpoints:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"
            resp = self.get(url, allow_redirects=False)

            if resp is None:
                continue

            # Check response headers for JWT indicators
            for header_name, header_value in resp.headers.items():
                if 'eyJ' in str(header_value):  # JWT header starts with base64 of {"
                    findings.append({
                        "endpoint": endpoint,
                        "header": header_name,
                        "evidence": f"JWT token found in {header_name} header"
                    })

            # Check for JWT in cookies
            cookies = resp.headers.get('Set-Cookie', '')
            if 'eyJ' in cookies:
                findings.append({
                    "endpoint": endpoint,
                    "location": "Set-Cookie",
                    "evidence": "JWT token set in cookie"
                })

        return findings

    def _test_registration_bypass(self, domain: str) -> List[Dict]:
        """Test for registration/signup bypass vulnerabilities"""
        findings = []

        # Check for admin registration endpoints
        admin_register_endpoints = [
            "/admin/register",
            "/api/admin/register",
            "/register?role=admin",
            "/signup?type=admin",
            "/api/users/register",
        ]

        for endpoint in admin_register_endpoints:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"
            resp = self.get(url, allow_redirects=False)

            if resp and resp.status_code in [200, 405]:  # 405 = POST only but exists
                # Check if registration form or API exists
                if resp.status_code == 200 or 'register' in resp.text.lower():
                    findings.append({
                        "endpoint": endpoint,
                        "status": resp.status_code,
                        "evidence": f"Potential admin registration endpoint: {endpoint}"
                    })

        return findings

    def scan(self, domain: str, progress: ScanProgress) -> List[Finding]:
        """Scan domain for authentication/authorization bypass vulnerabilities"""
        findings = []
        self.log(f"Testing auth bypass on {domain}")

        # Discover OAuth endpoints
        self.log("Discovering OAuth endpoints")
        oauth_info = self._discover_oauth_endpoints(domain)

        if oauth_info["endpoints"]:
            self.log(f"Found {len(oauth_info['endpoints'])} OAuth endpoints", "success")

            finding = self.create_finding(
                domain=domain,
                severity="info",
                title="OAuth Endpoints Discovered",
                description=f"Found {len(oauth_info['endpoints'])} OAuth-related endpoints",
                evidence=f"Endpoints: {[e['path'] for e in oauth_info['endpoints']]}",
                reproduction_steps=[
                    "OAuth endpoints discovered:",
                    *[f"- {e['path']} (status: {e['status']})" for e in oauth_info['endpoints'][:5]]
                ]
            )
            findings.append(finding)
            progress.add_finding(domain, finding)

            # Test OAuth redirect bypass
            if oauth_info.get("authorization_endpoint"):
                self.log("Testing OAuth redirect_uri bypass")
                redirect_findings = self._test_oauth_redirect_bypass(domain, oauth_info["authorization_endpoint"])

                for rf in redirect_findings:
                    finding = self.create_finding(
                        domain=domain,
                        severity="high",
                        title=f"OAuth Redirect URI Bypass: {rf['bypass_type']}",
                        description=f"OAuth redirect_uri validation can be bypassed using: {rf['pattern']}",
                        evidence=rf["evidence"],
                        reproduction_steps=[
                            f"Use redirect_uri: {rf['test_uri']}",
                            "OAuth authorization endpoint accepts the malicious redirect"
                        ]
                    )
                    findings.append(finding)
                    progress.add_finding(domain, finding)

        # Discover SAML endpoints
        if not is_shutdown():
            self.log("Discovering SAML endpoints")
            saml_endpoints = self._discover_saml_endpoints(domain)

            if saml_endpoints:
                finding = self.create_finding(
                    domain=domain,
                    severity="info",
                    title="SAML Endpoints Discovered",
                    description="SAML authentication endpoints found - test for signature bypass vulnerabilities",
                    evidence=f"SAML endpoints: {[e['path'] for e in saml_endpoints]}",
                    reproduction_steps=[
                        "SAML endpoints to investigate:",
                        *[f"- {e['path']} (status: {e['status']})" for e in saml_endpoints[:5]],
                        "Test for void canonicalization and signature bypass"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test path-based authorization bypass
        if not is_shutdown():
            self.log("Testing path-based auth bypass")
            path_findings = self._test_path_bypass(domain)

            for pf in path_findings:
                severity = "critical" if pf["bypass_type"] in ["path_manipulation", "header_bypass"] else "high"
                finding = self.create_finding(
                    domain=domain,
                    severity=severity,
                    title=f"Authorization Bypass: {pf['bypass_type']}",
                    description=f"Protected path can be accessed via {pf['bypass_type']}",
                    evidence=pf["evidence"],
                    reproduction_steps=[
                        f"Original protected path: {pf.get('path') or pf.get('original_path')}",
                        f"Bypass technique: {pf['bypass_type']}",
                        f"Details: {pf}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test IDOR patterns
        if not is_shutdown():
            self.log("Testing IDOR patterns")
            idor_findings = self._test_idor_patterns(domain)

            for idr in idor_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="medium",
                    title=f"Potential IDOR: {idr['endpoint']}",
                    description=f"Endpoint may be vulnerable to IDOR - returns user data with predictable ID",
                    evidence=idr["evidence"],
                    reproduction_steps=[
                        f"Access endpoint: {idr['endpoint']}",
                        f"Change ID parameter to access other users' data",
                        f"Data indicator found: {idr['indicator']}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test JWT vulnerabilities
        if not is_shutdown():
            self.log("Checking for JWT usage")
            jwt_findings = self._test_jwt_vulnerabilities(domain)

            for jf in jwt_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="info",
                    title=f"JWT Token Usage Detected",
                    description=f"JWT authentication in use - test for algorithm confusion and weak keys",
                    evidence=jf["evidence"],
                    reproduction_steps=[
                        f"JWT found at: {jf['endpoint']}",
                        "Test for: alg:none bypass, RS256->HS256 confusion, weak secrets"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test registration bypass
        if not is_shutdown():
            self.log("Testing registration bypass")
            reg_findings = self._test_registration_bypass(domain)

            for rf in reg_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="medium",
                    title=f"Potential Admin Registration: {rf['endpoint']}",
                    description="Admin or privileged registration endpoint may be accessible",
                    evidence=rf["evidence"],
                    reproduction_steps=[
                        f"Access: {rf['endpoint']}",
                        "Attempt to register with elevated privileges"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        self.log(f"Completed: {len(findings)} auth issues found", "success" if findings else "info")
        return findings
