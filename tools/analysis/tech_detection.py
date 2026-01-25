#!/usr/bin/env python3
"""
Technology Detection Module
Detects technologies, frameworks, and platforms on web applications.
Helps identify potential vulnerabilities based on known tech stack.

Detection methods:
- HTTP headers analysis
- HTML meta tags
- JavaScript libraries
- Cookie patterns
- Response patterns
"""

import re
import json
import time
import threading
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime

try:
    import requests
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    exit(1)

from config import get_amazon_config, get_shopify_config


@dataclass
class Technology:
    """Represents a detected technology"""
    name: str
    category: str  # framework, cms, server, cdn, analytics, etc.
    version: Optional[str] = None
    confidence: str = "medium"  # low, medium, high
    evidence: str = ""
    cves: List[str] = field(default_factory=list)
    vuln_notes: str = ""


@dataclass
class TechResult:
    """Results from technology detection"""
    target: str
    technologies: List[Technology] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    detection_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())


# Technology fingerprints database
TECH_FINGERPRINTS = {
    # Web Servers
    "nginx": {
        "category": "server",
        "headers": {"server": r"nginx/?(\d+\.[\d.]+)?"},
        "vuln_notes": "Check for misconfigurations, off-by-slash vulnerabilities",
    },
    "apache": {
        "category": "server",
        "headers": {"server": r"Apache/?(\d+\.[\d.]+)?"},
        "vuln_notes": "Check for mod_status, .htaccess bypass, path traversal",
    },
    "iis": {
        "category": "server",
        "headers": {"server": r"Microsoft-IIS/?(\d+\.[\d.]+)?"},
        "vuln_notes": "Check for short filename disclosure, tilde enumeration",
    },
    "cloudflare": {
        "category": "cdn",
        "headers": {"server": r"cloudflare", "cf-ray": r".+"},
        "cookies": ["__cfduid", "__cf_bm"],
        "vuln_notes": "WAF bypass techniques may be relevant",
    },
    "aws_elb": {
        "category": "cdn",
        "headers": {"server": r"awselb"},
        "cookies": ["AWSELB", "AWSELBCORS"],
        "vuln_notes": "AWS infrastructure - check for S3 bucket misconfigs",
    },
    "akamai": {
        "category": "cdn",
        "headers": {"x-akamai-transformed": r".+", "server": r"AkamaiGHost"},
        "vuln_notes": "Enterprise CDN - WAF bypass may be relevant",
    },

    # Frameworks
    "react": {
        "category": "framework",
        "html": [r'data-reactroot', r'__NEXT_DATA__', r'_reactRootContainer'],
        "js": [r'react\.production\.min\.js', r'react-dom'],
        "vuln_notes": "Check for XSS via dangerouslySetInnerHTML, prototype pollution",
    },
    "vue": {
        "category": "framework",
        "html": [r'data-v-[a-f0-9]+', r'__vue__'],
        "js": [r'vue\.min\.js', r'vue\.runtime'],
        "vuln_notes": "Check for XSS via v-html directive",
    },
    "angular": {
        "category": "framework",
        "html": [r'ng-app', r'ng-controller', r'ng-model', r'\[\(ngModel\)\]'],
        "js": [r'angular\.min\.js', r'@angular/core'],
        "vuln_notes": "Check for template injection, XSS via ng-bind-html",
    },
    "jquery": {
        "category": "library",
        "html": [r'jquery-\d'],
        "js": [r'jquery[\.-](\d+\.[\d.]+)'],
        "vuln_notes": "Old versions vulnerable to XSS (< 3.5.0)",
    },
    "bootstrap": {
        "category": "library",
        "html": [r'bootstrap\.min\.css', r'class="[^"]*btn btn-'],
        "js": [r'bootstrap[\.-](\d+\.[\d.]+)'],
        "vuln_notes": "Check for XSS in tooltips/popovers in old versions",
    },

    # CMS
    "wordpress": {
        "category": "cms",
        "html": [r'/wp-content/', r'/wp-includes/', r'wp-json'],
        "headers": {"x-powered-by": r"WordPress"},
        "vuln_notes": "Check xmlrpc.php, wp-login.php bruteforce, plugin vulns",
    },
    "drupal": {
        "category": "cms",
        "html": [r'Drupal\.settings', r'/sites/default/files'],
        "headers": {"x-drupal-cache": r".+", "x-generator": r"Drupal"},
        "vuln_notes": "Check for Drupalgeddon, user enumeration, module vulns",
    },
    "joomla": {
        "category": "cms",
        "html": [r'/media/jui/', r'/components/com_'],
        "headers": {"x-content-encoded-by": r"Joomla"},
        "vuln_notes": "Check for SQL injection, extension vulnerabilities",
    },
    "shopify": {
        "category": "platform",
        "html": [r'cdn\.shopify\.com', r'Shopify\.theme'],
        "headers": {"x-shopify-stage": r".+"},
        "cookies": ["_shopify_s", "_shopify_y"],
        "vuln_notes": "Focus on app-specific vulns, Liquid template injection",
    },

    # Backend languages/frameworks
    "php": {
        "category": "language",
        "headers": {"x-powered-by": r"PHP/?(\d+\.[\d.]+)?"},
        "vuln_notes": "Check for file inclusion, type juggling, deserialization",
    },
    "aspnet": {
        "category": "framework",
        "headers": {"x-aspnet-version": r"(\d+\.[\d.]+)", "x-powered-by": r"ASP\.NET"},
        "cookies": ["ASP.NET_SessionId", ".AspNetCore."],
        "vuln_notes": "Check for viewstate deserialization, padding oracle",
    },
    "java": {
        "category": "language",
        "headers": {"x-powered-by": r"Servlet|JSP|JSF"},
        "cookies": ["JSESSIONID"],
        "vuln_notes": "Check for deserialization (Log4Shell, Spring4Shell), OGNL injection",
    },
    "python": {
        "category": "language",
        "headers": {"server": r"gunicorn|uvicorn|Werkzeug|waitress"},
        "vuln_notes": "Check for SSTI (Jinja2), pickle deserialization, path traversal",
    },
    "ruby": {
        "category": "language",
        "headers": {"x-powered-by": r"Phusion Passenger", "server": r"thin|unicorn|puma"},
        "cookies": ["_session_id"],
        "vuln_notes": "Check for ERB SSTI, YAML deserialization, mass assignment",
    },
    "express": {
        "category": "framework",
        "headers": {"x-powered-by": r"Express"},
        "vuln_notes": "Check for prototype pollution, NoSQL injection, path traversal",
    },
    "django": {
        "category": "framework",
        "cookies": ["csrftoken", "sessionid"],
        "html": [r'csrfmiddlewaretoken'],
        "vuln_notes": "Check for SSTI, SQL injection, debug mode enabled",
    },
    "flask": {
        "category": "framework",
        "headers": {"server": r"Werkzeug"},
        "cookies": ["session"],
        "vuln_notes": "Check for SSTI (Jinja2), debug mode, secret key issues",
    },
    "rails": {
        "category": "framework",
        "headers": {"x-powered-by": r"Phusion Passenger"},
        "cookies": ["_rails_session", "_session_id"],
        "vuln_notes": "Check for mass assignment, YAML deserialization, CSRF",
    },
    "laravel": {
        "category": "framework",
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "html": [r'laravel-token'],
        "vuln_notes": "Check for debug mode, unserialize vulns, .env exposure",
    },
    "spring": {
        "category": "framework",
        "headers": {"x-application-context": r".+"},
        "vuln_notes": "Check for Spring4Shell, actuator exposure, SpEL injection",
    },

    # Analytics & Tracking
    "google_analytics": {
        "category": "analytics",
        "html": [r'google-analytics\.com/analytics\.js', r'gtag\(', r'UA-\d+-\d+'],
        "vuln_notes": "N/A - informational",
    },
    "google_tag_manager": {
        "category": "analytics",
        "html": [r'googletagmanager\.com/gtm\.js', r'GTM-[A-Z0-9]+'],
        "vuln_notes": "Check for GTM container hijacking",
    },

    # Security
    "recaptcha": {
        "category": "security",
        "html": [r'google\.com/recaptcha', r'g-recaptcha'],
        "vuln_notes": "Check for bypass, rate limiting without captcha elsewhere",
    },
    "hcaptcha": {
        "category": "security",
        "html": [r'hcaptcha\.com', r'h-captcha'],
        "vuln_notes": "Check for bypass techniques",
    },

    # GraphQL
    "graphql": {
        "category": "api",
        "html": [r'/graphql', r'GraphQL'],
        "headers": {"content-type": r"application/graphql"},
        "vuln_notes": "Check for introspection, batching attacks, IDOR, injection",
    },

    # API Gateways
    "kong": {
        "category": "gateway",
        "headers": {"via": r"kong", "x-kong-proxy-latency": r".+"},
        "vuln_notes": "Check for admin API exposure, plugin misconfigurations",
    },
    "aws_api_gateway": {
        "category": "gateway",
        "headers": {"x-amzn-requestid": r".+", "x-amz-apigw-id": r".+"},
        "vuln_notes": "Check for authorization bypass, lambda injection",
    },
}


class TechDetector:
    """Detect technologies on web applications"""

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

    def _rate_limit_wait(self):
        """Wait to respect rate limit"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_request
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_request = time.time()

    def _request(self, url: str) -> Optional[requests.Response]:
        """Make a rate-limited request"""
        self._rate_limit_wait()
        try:
            response = self.session.get(url, timeout=15, allow_redirects=True)
            return response
        except Exception:
            return None

    def detect_from_headers(self, headers: Dict[str, str]) -> List[Technology]:
        """Detect technologies from HTTP headers"""
        technologies = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for tech_name, fingerprint in TECH_FINGERPRINTS.items():
            if "headers" not in fingerprint:
                continue

            for header, pattern in fingerprint["headers"].items():
                if header.lower() in headers_lower:
                    value = headers_lower[header.lower()]
                    match = re.search(pattern, value, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.groups() else None
                        tech = Technology(
                            name=tech_name,
                            category=fingerprint["category"],
                            version=version,
                            confidence="high",
                            evidence=f"Header: {header}={value}",
                            vuln_notes=fingerprint.get("vuln_notes", ""),
                        )
                        technologies.append(tech)
                        break

        return technologies

    def detect_from_cookies(self, cookies: Dict[str, str]) -> List[Technology]:
        """Detect technologies from cookies"""
        technologies = []
        cookie_names = set(cookies.keys())

        for tech_name, fingerprint in TECH_FINGERPRINTS.items():
            if "cookies" not in fingerprint:
                continue

            for cookie_pattern in fingerprint["cookies"]:
                for cookie_name in cookie_names:
                    if cookie_pattern.lower() in cookie_name.lower():
                        tech = Technology(
                            name=tech_name,
                            category=fingerprint["category"],
                            confidence="high",
                            evidence=f"Cookie: {cookie_name}",
                            vuln_notes=fingerprint.get("vuln_notes", ""),
                        )
                        technologies.append(tech)
                        break

        return technologies

    def detect_from_html(self, html: str) -> List[Technology]:
        """Detect technologies from HTML content"""
        technologies = []

        for tech_name, fingerprint in TECH_FINGERPRINTS.items():
            if "html" not in fingerprint:
                continue

            for pattern in fingerprint["html"]:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else None
                    tech = Technology(
                        name=tech_name,
                        category=fingerprint["category"],
                        version=version,
                        confidence="medium",
                        evidence=f"HTML pattern: {pattern[:50]}",
                        vuln_notes=fingerprint.get("vuln_notes", ""),
                    )
                    technologies.append(tech)
                    break

        return technologies

    def detect_from_js(self, html: str) -> List[Technology]:
        """Detect technologies from JavaScript references"""
        technologies = []

        for tech_name, fingerprint in TECH_FINGERPRINTS.items():
            if "js" not in fingerprint:
                continue

            for pattern in fingerprint["js"]:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else None
                    tech = Technology(
                        name=tech_name,
                        category=fingerprint["category"],
                        version=version,
                        confidence="medium",
                        evidence=f"JS pattern: {pattern[:50]}",
                        vuln_notes=fingerprint.get("vuln_notes", ""),
                    )
                    technologies.append(tech)
                    break

        return technologies

    def detect_special(self, url: str, response: requests.Response) -> List[Technology]:
        """Special detection methods for specific technologies"""
        technologies = []

        # Check for GraphQL endpoint
        graphql_paths = ['/graphql', '/api/graphql', '/graphql.json']
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path in graphql_paths:
            self._rate_limit_wait()
            try:
                gql_url = f"{base_url}{path}"
                gql_response = self.session.post(
                    gql_url,
                    json={"query": "{ __typename }"},
                    timeout=5,
                    headers={"Content-Type": "application/json"}
                )
                if gql_response.status_code == 200:
                    try:
                        data = gql_response.json()
                        if 'data' in data or 'errors' in data:
                            tech = Technology(
                                name="graphql",
                                category="api",
                                confidence="high",
                                evidence=f"GraphQL endpoint: {path}",
                                vuln_notes="Check introspection, batching, IDOR, injection",
                            )
                            technologies.append(tech)
                            break
                    except:
                        pass
            except:
                pass

        # Check for common admin paths
        admin_paths = ['/admin', '/wp-admin', '/administrator', '/admin.php']
        for path in admin_paths:
            self._rate_limit_wait()
            try:
                admin_url = f"{base_url}{path}"
                admin_response = self.session.head(admin_url, timeout=5, allow_redirects=False)
                if admin_response.status_code in [200, 301, 302, 401, 403]:
                    tech = Technology(
                        name="admin_panel",
                        category="admin",
                        confidence="medium",
                        evidence=f"Admin path: {path} -> {admin_response.status_code}",
                        vuln_notes="Check for bruteforce, default credentials, bypass",
                    )
                    technologies.append(tech)
                    break
            except:
                pass

        return technologies

    def detect(self, target: str, deep_scan: bool = True) -> TechResult:
        """
        Full technology detection
        """
        # Normalize target URL
        if not target.startswith('http'):
            target = f"https://{target}"

        print(f"\n[*] Technology Detection: {target}")
        print("=" * 50)

        result = TechResult(target=target)

        # Make initial request
        print("    [HTTP] Fetching target...")
        response = self._request(target)

        if not response:
            print("    [ERROR] Failed to fetch target")
            return result

        result.headers = dict(response.headers)
        result.cookies = list(response.cookies.keys())

        # Detect from headers
        print("    [HEADERS] Analyzing HTTP headers...")
        techs = self.detect_from_headers(result.headers)
        result.technologies.extend(techs)
        if techs:
            print(f"      Found: {', '.join(t.name for t in techs)}")

        # Detect from cookies
        print("    [COOKIES] Analyzing cookies...")
        techs = self.detect_from_cookies(dict(response.cookies))
        result.technologies.extend(techs)
        if techs:
            print(f"      Found: {', '.join(t.name for t in techs)}")

        # Detect from HTML
        print("    [HTML] Analyzing page content...")
        techs = self.detect_from_html(response.text)
        result.technologies.extend(techs)
        if techs:
            print(f"      Found: {', '.join(t.name for t in techs)}")

        # Detect from JS references
        print("    [JS] Checking JavaScript references...")
        techs = self.detect_from_js(response.text)
        result.technologies.extend(techs)
        if techs:
            print(f"      Found: {', '.join(t.name for t in techs)}")

        # Special detection methods
        if deep_scan:
            print("    [DEEP] Running special detection...")
            techs = self.detect_special(target, response)
            result.technologies.extend(techs)
            if techs:
                print(f"      Found: {', '.join(t.name for t in techs)}")

        # Deduplicate
        seen = set()
        unique_techs = []
        for tech in result.technologies:
            key = (tech.name, tech.category)
            if key not in seen:
                seen.add(key)
                unique_techs.append(tech)
        result.technologies = unique_techs

        print(f"\n    [TOTAL] {len(result.technologies)} technologies detected")

        return result


class AmazonTechDetector(TechDetector):
    """Amazon VRP-compliant technology detection"""

    def __init__(self, username: str = "yourh1username"):
        config = get_amazon_config(username)
        super().__init__(
            rate_limit=config.rate_limit,
            user_agent=config.user_agent
        )


class ShopifyTechDetector(TechDetector):
    """Shopify-compliant technology detection"""

    def __init__(self, username: str = "yourh1username"):
        config = get_shopify_config(username)
        super().__init__(
            rate_limit=config.rate_limit,
            user_agent=config.user_agent
        )


def save_tech_results(result: TechResult, output_file: str):
    """Save technology detection results to JSON file"""
    data = {
        "target": result.target,
        "detection_time": result.detection_time,
        "total_technologies": len(result.technologies),
        "headers": result.headers,
        "cookies": result.cookies,
        "technologies": [
            {
                "name": t.name,
                "category": t.category,
                "version": t.version,
                "confidence": t.confidence,
                "evidence": t.evidence,
                "vuln_notes": t.vuln_notes,
            }
            for t in result.technologies
        ]
    }

    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"\n[*] Results saved to: {output_file}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Technology Detection Tool")
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--program", "-p", choices=["amazon", "shopify"],
                        help="Bug bounty program for rate limiting")
    parser.add_argument("--username", "-u", default="yourh1username",
                        help="HackerOne username")
    parser.add_argument("--no-deep", action="store_true",
                        help="Skip deep scan (special detection)")
    parser.add_argument("--output", "-o", help="Output JSON file")

    args = parser.parse_args()

    # Create detector
    if args.program == "amazon":
        detector = AmazonTechDetector(args.username)
    elif args.program == "shopify":
        detector = ShopifyTechDetector(args.username)
    else:
        detector = TechDetector()

    # Run detection
    result = detector.detect(args.target, deep_scan=not args.no_deep)

    # Print summary
    print("\n" + "=" * 50)
    print("TECHNOLOGY DETECTION SUMMARY")
    print("=" * 50)
    print(f"Target: {result.target}")
    print(f"Technologies found: {len(result.technologies)}")

    if result.technologies:
        # Group by category
        categories = {}
        for tech in result.technologies:
            if tech.category not in categories:
                categories[tech.category] = []
            categories[tech.category].append(tech)

        print("\nDetected technologies:")
        for category, techs in sorted(categories.items()):
            print(f"\n  [{category.upper()}]")
            for tech in techs:
                version = f" v{tech.version}" if tech.version else ""
                print(f"    - {tech.name}{version} ({tech.confidence})")
                if tech.vuln_notes:
                    print(f"      -> {tech.vuln_notes}")

    # Save results
    if args.output:
        save_tech_results(result, args.output)
