#!/usr/bin/env python3
"""
Framework-Specific Vulnerabilities Detection Module
====================================================
Based on 2025 techniques including:
- ASP.NET path traversal + view engine bypass
- Java deserialization indicators
- ORM injection (Prisma, Beego, etc.)
- Spring Boot actuator exposure
- Express.js prototype pollution
- Rails mass assignment
- PHP type juggling

References:
- ASP.NET Razor exploits
- Java gadget chains
- Modern ORM vulnerabilities
"""

import re
import json
import base64
import random
import string
from typing import List, Optional, Dict
from urllib.parse import urlparse, quote, urlencode

from .base import TechniqueScanner, Finding, ScanProgress, is_shutdown


class FrameworkVulns(TechniqueScanner):
    """Framework-specific vulnerability scanner"""

    TECHNIQUE_NAME = "framework_vulns"
    TECHNIQUE_CATEGORY = "framework_specific"

    # ASP.NET specific endpoints
    ASPNET_ENDPOINTS = [
        # Debug and error pages
        "/elmah.axd",
        "/trace.axd",
        "/Trace.axd",
        "/_framework/blazor.webassembly.js",
        # Web.config exposure
        "/web.config",
        "/Web.config",
        # ViewState endpoints
        "/__doPostBack",
        # MVC routing
        "/error",
        "/error/notfound",
    ]

    # Java/Spring endpoints
    JAVA_ENDPOINTS = [
        # Spring Boot Actuator
        "/actuator",
        "/actuator/health",
        "/actuator/info",
        "/actuator/env",
        "/actuator/configprops",
        "/actuator/mappings",
        "/actuator/beans",
        "/actuator/heapdump",
        "/actuator/threaddump",
        "/actuator/loggers",
        "/actuator/metrics",
        "/actuator/jolokia",
        "/actuator/gateway/routes",
        # Legacy actuator paths
        "/health",
        "/info",
        "/env",
        "/mappings",
        "/beans",
        "/dump",
        "/trace",
        "/logfile",
        # Swagger/OpenAPI
        "/swagger-ui.html",
        "/swagger-ui/",
        "/v2/api-docs",
        "/v3/api-docs",
        "/api-docs",
        # Druid
        "/druid/index.html",
        "/druid/sql.html",
    ]

    # PHP specific
    PHP_ENDPOINTS = [
        "/phpinfo.php",
        "/info.php",
        "/test.php",
        "/php_info.php",
        "/i.php",
        "/.env",
        "/config.php",
        "/wp-config.php",
        "/configuration.php",
        "/.git/config",
        "/.svn/entries",
        "/composer.json",
        "/vendor/autoload.php",
    ]

    # Node.js/Express specific
    NODE_ENDPOINTS = [
        "/package.json",
        "/node_modules/",
        "/.npmrc",
        "/npm-debug.log",
        "/yarn.lock",
        "/graphql",
        "/playground",
    ]

    # Ruby/Rails specific
    RAILS_ENDPOINTS = [
        "/rails/info/routes",
        "/rails/info/properties",
        "/rails/mailers",
        "/sidekiq",
        "/resque",
        "/Gemfile",
        "/Gemfile.lock",
        "/config/database.yml",
        "/config/secrets.yml",
    ]

    # Django/Python specific
    PYTHON_ENDPOINTS = [
        "/admin/",
        "/__debug__/",
        "/static/admin/",
        "/requirements.txt",
        "/settings.py",
        "/manage.py",
        "/.python-version",
        "/Pipfile",
        "/pyproject.toml",
    ]

    # ORM injection payloads
    ORM_PAYLOADS = [
        # Prisma type coercion
        {"where": {"id": {"equals": None}}},
        {"where": {"OR": [{"id": 1}, {"id": 2}]}},
        # Sequelize operator injection
        {"id": {"$ne": None}},
        {"id": {"$gt": 0}},
        # MongoDB-style
        {"$where": "1==1"},
        {"$gt": ""},
        # Beego filter expressions
        {"filter": "__proto__[admin]=true"},
    ]

    # Deserialization indicators
    DESER_INDICATORS = [
        # Java serialized object magic bytes (base64)
        "rO0AB",  # Base64 of Java serialized
        "H4sIAAAA",  # Base64 of gzipped data
        # .NET ViewState
        "__VIEWSTATE",
        "__EVENTVALIDATION",
        # PHP serialized
        "a:0:{}",
        'O:8:"stdClass"',
        # Python pickle
        "gASV",
        # Ruby Marshal
        "BAh",
    ]

    # Technology detection patterns
    TECH_PATTERNS = {
        "aspnet": [
            (r'ASP\.NET', 'header_or_body'),
            (r'__VIEWSTATE', 'body'),
            (r'\.aspx', 'url'),
            (r'X-AspNet-Version', 'header'),
            (r'X-Powered-By.*ASP', 'header'),
        ],
        "java": [
            (r'JSESSIONID', 'cookie'),
            (r'java\.lang', 'body'),
            (r'Servlet', 'header_or_body'),
            (r'Spring', 'header_or_body'),
            (r'X-Powered-By.*Servlet', 'header'),
        ],
        "php": [
            (r'PHPSESSID', 'cookie'),
            (r'X-Powered-By.*PHP', 'header'),
            (r'\.php', 'url'),
        ],
        "nodejs": [
            (r'Express', 'header'),
            (r'X-Powered-By.*Express', 'header'),
            (r'connect\.sid', 'cookie'),
        ],
        "rails": [
            (r'_session_id', 'cookie'),
            (r'X-Request-Id', 'header'),
            (r'X-Runtime', 'header'),
            (r'\.rb', 'body'),
        ],
        "django": [
            (r'csrfmiddlewaretoken', 'body'),
            (r'sessionid', 'cookie'),
            (r'django', 'body'),
        ],
    }

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _detect_technology(self, domain: str) -> Dict:
        """Detect the technology stack used by the target"""
        url = f"https://{domain}/"
        resp = self.get(url, allow_redirects=True)

        if resp is None:
            return {"detected": [], "indicators": []}

        detected = []
        indicators = []

        headers_str = str(resp.headers).lower()
        cookies_str = str(resp.cookies).lower()
        body = resp.text.lower()
        url_str = str(resp.url).lower()

        for tech, patterns in self.TECH_PATTERNS.items():
            for pattern, location in patterns:
                if location == 'header' and re.search(pattern, headers_str, re.IGNORECASE):
                    detected.append(tech)
                    indicators.append(f"{tech}: {pattern} in headers")
                    break
                elif location == 'cookie' and re.search(pattern, cookies_str, re.IGNORECASE):
                    detected.append(tech)
                    indicators.append(f"{tech}: {pattern} in cookies")
                    break
                elif location == 'body' and re.search(pattern, body, re.IGNORECASE):
                    detected.append(tech)
                    indicators.append(f"{tech}: {pattern} in body")
                    break
                elif location == 'url' and re.search(pattern, url_str, re.IGNORECASE):
                    detected.append(tech)
                    indicators.append(f"{tech}: {pattern} in URL")
                    break
                elif location == 'header_or_body':
                    if re.search(pattern, headers_str + body, re.IGNORECASE):
                        detected.append(tech)
                        indicators.append(f"{tech}: {pattern}")
                        break

        # Additional header checks
        server = resp.headers.get('Server', '').lower()
        powered_by = resp.headers.get('X-Powered-By', '').lower()

        if 'apache' in server:
            indicators.append("Server: Apache")
        if 'nginx' in server:
            indicators.append("Server: Nginx")
        if 'iis' in server:
            detected.append('aspnet')
            indicators.append("Server: IIS")
        if 'tomcat' in server or 'jetty' in server:
            detected.append('java')
            indicators.append(f"Server: {server}")

        return {
            "detected": list(set(detected)),
            "indicators": indicators,
            "server": server,
            "powered_by": powered_by
        }

    def _contains_secrets(self, text: str) -> bool:
        if not text:
            return False
        lower = text.lower()
        secret_markers = [
            "password", "secret", "token", "apikey", "api_key", "access_key",
            "client_secret", "private_key", "connectionstring", "db_password"
        ]
        if any(marker in lower for marker in secret_markers):
            return True
        if "begin rsa private key" in lower or "begin private key" in lower:
            return True
        return False

    def _scan_aspnet(self, domain: str) -> List[Dict]:
        """Scan for ASP.NET specific vulnerabilities"""
        findings = []

        # Test path traversal with .aspx
        traversal_payloads = [
            "/..%252f..%252f..%252fweb.config",
            "/....//....//web.config",
            "/.%2e/.%2e/web.config",
        ]

        for payload in traversal_payloads:
            if is_shutdown():
                break

            url = f"https://{domain}{payload}"
            resp = self.get(url, allow_redirects=False)

            if resp and resp.status_code == 200:
                if 'configuration' in resp.text.lower() or 'connectionstring' in resp.text.lower():
                    findings.append({
                        "type": "path_traversal",
                        "payload": payload,
                        "evidence": f"Path traversal to web.config successful"
                    })

        return findings

    def _scan_java_spring(self, domain: str) -> List[Dict]:
        """Scan for Java/Spring specific vulnerabilities"""
        findings = []

        for endpoint in self.JAVA_ENDPOINTS:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"
            resp = self.get(url, allow_redirects=False)

            if resp is None:
                continue

            if resp.status_code == 200:
                sensitive_actuators = ['env', 'configprops', 'heapdump', 'threaddump', 'logfile', 'jolokia']
                is_sensitive = any(s in endpoint for s in sensitive_actuators)
                content_type = resp.headers.get("Content-Type", "").lower()
                is_html = "text/html" in content_type or "<html" in (resp.text or "").lower()[:500]
                looks_binary = any(x in content_type for x in ["octet-stream", "zip", "gzip"])

                if is_sensitive:
                    if self._contains_secrets(resp.text) or looks_binary or (len(resp.content) > 5000 and not is_html):
                        findings.append({
                            "type": "actuator_sensitive_exposure",
                            "endpoint": endpoint,
                            "evidence": f"Sensitive Spring endpoint exposed: {endpoint}"
                        })

        return findings

    def _scan_php(self, domain: str) -> List[Dict]:
        """Scan for PHP specific vulnerabilities"""
        findings = []

        for endpoint in self.PHP_ENDPOINTS:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"
            resp = self.get(url, allow_redirects=False)

            if resp and resp.status_code == 200:
                # Check for phpinfo exposure
                if 'phpinfo' in endpoint and 'PHP Version' in resp.text:
                    version_match = re.search(r'PHP Version.*?(\d+\.\d+\.\d+)', resp.text)
                    if version_match:
                        findings.append({
                            "type": "phpinfo_exposure",
                            "version": version_match.group(1),
                            "evidence": f"PHPInfo exposed - Version: {version_match.group(1)}"
                        })
                        continue

                sensitive = endpoint in ['/.env', '/wp-config.php', '/configuration.php', '/.git/config', '/config.php']
                if sensitive and self._contains_secrets(resp.text):
                    findings.append({
                        "type": "php_sensitive_exposure",
                        "endpoint": endpoint,
                        "evidence": f"Sensitive PHP config exposed: {endpoint}"
                    })

        return findings

    def _scan_nodejs(self, domain: str) -> List[Dict]:
        """Scan for Node.js specific vulnerabilities"""
        findings = []

        for endpoint in self.NODE_ENDPOINTS:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"
            resp = self.get(url, allow_redirects=False)

            if resp and resp.status_code == 200:
                if endpoint in ["/.npmrc", "/npm-debug.log"] and self._contains_secrets(resp.text):
                    findings.append({
                        "type": "node_sensitive_exposure",
                        "endpoint": endpoint,
                        "evidence": f"Sensitive Node.js config exposed: {endpoint}"
                    })

        # Test prototype pollution via query params (requires propagation evidence)
        pp_token = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        pp_payloads = [
            f"__proto__[polluted_pp_test]={pp_token}",
            f"constructor[prototype][polluted_pp_test]={pp_token}",
            f"__proto__.polluted_pp_test={pp_token}",
        ]
        verify_paths = ["/api/user/profile", "/api/config", "/"]
        baseline_texts = {}

        for path in verify_paths:
            resp = self.get(f"https://{domain}{path}", allow_redirects=True)
            baseline_texts[path] = resp.text if resp else ""

        for payload in pp_payloads:
            if is_shutdown():
                break

            url = f"https://{domain}/?{payload}"
            resp = self.get(url, allow_redirects=True)

            if resp and resp.status_code in [200, 201, 204]:
                # Verify pollution propagates to a separate request
                propagated = False
                for path in verify_paths:
                    verify_resp = self.get(f"https://{domain}{path}", allow_redirects=True)
                    if verify_resp and pp_token in verify_resp.text and pp_token not in baseline_texts.get(path, ""):
                        propagated = True
                        break

                if propagated:
                    findings.append({
                        "type": "prototype_pollution",
                        "payload": payload,
                        "evidence": f"Prototype pollution confirmed: polluted_pp_test propagated via {payload}"
                    })

        return findings

    def _scan_rails(self, domain: str) -> List[Dict]:
        """Scan for Rails specific vulnerabilities"""
        findings = []

        for endpoint in self.RAILS_ENDPOINTS:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"
            resp = self.get(url, allow_redirects=False)

            if resp and resp.status_code == 200:
                if endpoint in ["/config/database.yml", "/config/secrets.yml"] and self._contains_secrets(resp.text):
                    findings.append({
                        "type": "rails_sensitive_exposure",
                        "endpoint": endpoint,
                        "evidence": f"Sensitive Rails config exposed: {endpoint}"
                    })

        return findings

    def _scan_orm_injection(self, domain: str) -> List[Dict]:
        """Scan for ORM injection vulnerabilities"""
        # Disabled: ORM errors are not confirmation of injection.
        return []

    def scan(self, domain: str, progress: ScanProgress) -> List[Finding]:
        """Scan domain for framework-specific vulnerabilities"""
        findings = []
        self.log(f"Testing framework vulnerabilities on {domain}")

        # Detect technology
        self.log("Detecting technology stack")
        tech_info = self._detect_technology(domain)

        if tech_info["detected"]:
            self.log(f"Detected: {', '.join(tech_info['detected'])}", "success")

            finding = self.create_finding(
                domain=domain,
                severity="info",
                title=f"Technology Detected: {', '.join(tech_info['detected'])}",
                description=f"Identified technology stack",
                evidence=f"Indicators: {tech_info['indicators'][:5]}",
                reproduction_steps=[
                    f"Server: {tech_info['server']}",
                    f"X-Powered-By: {tech_info['powered_by']}",
                    f"Technologies: {tech_info['detected']}"
                ]
            )
            findings.append(finding)
            progress.add_finding(domain, finding)

        # Scan based on detected technology
        detected = tech_info["detected"]

        if 'aspnet' in detected or not detected:
            self.log("Scanning for ASP.NET vulnerabilities")
            aspnet_findings = self._scan_aspnet(domain)

            for af in aspnet_findings:
                severity = "critical" if af["type"] in ["path_traversal", "viewstate_unencrypted"] else "medium"
                finding = self.create_finding(
                    domain=domain,
                    severity=severity,
                    title=f"ASP.NET: {af['type'].replace('_', ' ').title()}",
                    description=f"ASP.NET vulnerability detected",
                    evidence=af["evidence"],
                    reproduction_steps=[
                        f"Type: {af['type']}",
                        f"Details: {af}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        if 'java' in detected or not detected:
            self.log("Scanning for Java/Spring vulnerabilities")
            java_findings = self._scan_java_spring(domain)

            for jf in java_findings:
                severity = "critical" if jf.get("sensitive") or jf["type"] == "credential_exposure" else "high"
                finding = self.create_finding(
                    domain=domain,
                    severity=severity,
                    title=f"Java/Spring: {jf['type'].replace('_', ' ').title()}",
                    description=f"Java/Spring vulnerability or exposure",
                    evidence=jf["evidence"],
                    reproduction_steps=[
                        f"Endpoint: {jf.get('endpoint', 'N/A')}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        if 'php' in detected or not detected:
            self.log("Scanning for PHP vulnerabilities")
            php_findings = self._scan_php(domain)

            for pf in php_findings:
                severity = "high" if pf.get("sensitive") or pf["type"] == "type_juggling" else "medium"
                finding = self.create_finding(
                    domain=domain,
                    severity=severity,
                    title=f"PHP: {pf['type'].replace('_', ' ').title()}",
                    description=f"PHP vulnerability or exposure",
                    evidence=pf["evidence"],
                    reproduction_steps=[
                        f"Details: {pf}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        if 'nodejs' in detected or not detected:
            self.log("Scanning for Node.js vulnerabilities")
            node_findings = self._scan_nodejs(domain)

            for nf in node_findings:
                severity = "high" if nf["type"] == "prototype_pollution_indicator" else "medium"
                finding = self.create_finding(
                    domain=domain,
                    severity=severity,
                    title=f"Node.js: {nf['type'].replace('_', ' ').title()}",
                    description=f"Node.js vulnerability or exposure",
                    evidence=nf["evidence"],
                    reproduction_steps=[
                        f"Details: {nf}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        if 'rails' in detected:
            self.log("Scanning for Rails vulnerabilities")
            rails_findings = self._scan_rails(domain)

            for rf in rails_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="medium",
                    title=f"Rails: {rf['type'].replace('_', ' ').title()}",
                    description=f"Rails vulnerability or exposure",
                    evidence=rf["evidence"],
                    reproduction_steps=[
                        f"Details: {rf}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Always scan for ORM injection
        if not is_shutdown():
            self.log("Scanning for ORM injection")
            orm_findings = self._scan_orm_injection(domain)

            for of in orm_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="high",
                    title=f"ORM: {of['type'].replace('_', ' ').title()}",
                    description=f"ORM injection vulnerability",
                    evidence=of["evidence"],
                    reproduction_steps=[
                        f"Endpoint: {of['endpoint']}",
                        f"Payload: {of['payload']}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        self.log(f"Completed: {len(findings)} framework issues found", "success" if findings else "info")
        return findings
