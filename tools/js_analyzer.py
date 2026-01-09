#!/usr/bin/env python3
"""
JavaScript Analyzer Module
Analyzes JavaScript files to extract:
- API endpoints and routes
- Secrets and API keys (for responsible disclosure)
- DOM sinks for XSS
- Interesting functions and patterns
- Hidden parameters

Helps identify potential vulnerabilities in client-side code.
"""

import re
import json
import time
import threading
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Tuple
from urllib.parse import urlparse, urljoin
from datetime import datetime

try:
    import requests
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    exit(1)

from config import get_amazon_config, get_shopify_config


@dataclass
class SecretFinding:
    """Represents a potential secret/key found in JS"""
    type: str  # api_key, aws_key, jwt, etc.
    value: str  # The actual value (partially redacted)
    context: str  # Surrounding code
    file: str
    line: int = 0
    severity: str = "high"


@dataclass
class ApiEndpoint:
    """API endpoint extracted from JS"""
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    source_file: str = ""
    context: str = ""


@dataclass
class DomSink:
    """Potential DOM XSS sink"""
    sink_type: str  # innerHTML, document.write, eval, etc.
    code_snippet: str
    file: str
    exploitable: bool = False
    notes: str = ""


@dataclass
class JSAnalysisResult:
    """Results from JavaScript analysis"""
    target: str
    js_files: List[str] = field(default_factory=list)
    api_endpoints: List[ApiEndpoint] = field(default_factory=list)
    secrets: List[SecretFinding] = field(default_factory=list)
    dom_sinks: List[DomSink] = field(default_factory=list)
    parameters: Set[str] = field(default_factory=set)
    interesting_strings: List[str] = field(default_factory=list)
    analysis_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())


# Patterns for secrets and API keys
SECRET_PATTERNS = {
    "aws_access_key": {
        "pattern": r'(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        "severity": "critical",
        "description": "AWS Access Key ID",
    },
    "aws_secret_key": {
        "pattern": r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
        "severity": "critical",
        "description": "Potential AWS Secret Key",
    },
    "google_api_key": {
        "pattern": r'AIza[0-9A-Za-z_-]{35}',
        "severity": "high",
        "description": "Google API Key",
    },
    "github_token": {
        "pattern": r'gh[pousr]_[A-Za-z0-9_]{36,}',
        "severity": "critical",
        "description": "GitHub Token",
    },
    "slack_token": {
        "pattern": r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
        "severity": "high",
        "description": "Slack Token",
    },
    "stripe_key": {
        "pattern": r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}',
        "severity": "critical",
        "description": "Stripe API Key",
    },
    "jwt_token": {
        "pattern": r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
        "severity": "medium",
        "description": "JWT Token",
    },
    "private_key": {
        "pattern": r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        "severity": "critical",
        "description": "Private Key",
    },
    "basic_auth": {
        "pattern": r'(?:Authorization|authorization)["\s:]+Basic\s+[A-Za-z0-9+/=]+',
        "severity": "high",
        "description": "Basic Auth Credentials",
    },
    "bearer_token": {
        "pattern": r'(?:Authorization|authorization)["\s:]+Bearer\s+[A-Za-z0-9_.-]+',
        "severity": "high",
        "description": "Bearer Token",
    },
    "password_field": {
        "pattern": r'["\'](?:password|passwd|pwd|secret|api_?key|apikey|access_?token|auth_?token)["\'\s]*[:=]\s*["\'][^"\']{8,}["\']',
        "severity": "medium",
        "description": "Hardcoded Password/Secret",
    },
    "mongodb_uri": {
        "pattern": r'mongodb(?:\+srv)?://[^\s"\']+',
        "severity": "critical",
        "description": "MongoDB Connection String",
    },
    "postgres_uri": {
        "pattern": r'postgres(?:ql)?://[^\s"\']+',
        "severity": "critical",
        "description": "PostgreSQL Connection String",
    },
    "internal_ip": {
        "pattern": r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
        "severity": "low",
        "description": "Internal IP Address",
    },
}

# DOM XSS sinks
DOM_SINKS = {
    "innerHTML": {
        "pattern": r'\.innerHTML\s*[+]?=',
        "description": "innerHTML assignment",
        "severity": "high",
    },
    "outerHTML": {
        "pattern": r'\.outerHTML\s*[+]?=',
        "description": "outerHTML assignment",
        "severity": "high",
    },
    "document.write": {
        "pattern": r'document\.write(?:ln)?\s*\(',
        "description": "document.write()",
        "severity": "high",
    },
    "eval": {
        "pattern": r'(?<!\.)\beval\s*\(',
        "description": "eval()",
        "severity": "critical",
    },
    "Function": {
        "pattern": r'(?:new\s+)?Function\s*\(',
        "description": "Function constructor",
        "severity": "high",
    },
    "setTimeout_string": {
        "pattern": r'setTimeout\s*\(\s*["\']',
        "description": "setTimeout with string",
        "severity": "medium",
    },
    "setInterval_string": {
        "pattern": r'setInterval\s*\(\s*["\']',
        "description": "setInterval with string",
        "severity": "medium",
    },
    "location_assign": {
        "pattern": r'(?:location|window\.location)(?:\.href)?\s*=',
        "description": "location assignment (open redirect)",
        "severity": "medium",
    },
    "jquery_html": {
        "pattern": r'\$\([^)]+\)\.html\s*\(',
        "description": "jQuery .html()",
        "severity": "high",
    },
    "jquery_append": {
        "pattern": r'\$\([^)]+\)\.(?:append|prepend|after|before)\s*\(',
        "description": "jQuery DOM manipulation",
        "severity": "medium",
    },
    "dangerouslySetInnerHTML": {
        "pattern": r'dangerouslySetInnerHTML',
        "description": "React dangerouslySetInnerHTML",
        "severity": "high",
    },
    "v-html": {
        "pattern": r'v-html\s*=',
        "description": "Vue v-html directive",
        "severity": "high",
    },
    "ng-bind-html": {
        "pattern": r'ng-bind-html(?:-unsafe)?',
        "description": "Angular ng-bind-html",
        "severity": "high",
    },
}

# API endpoint patterns
API_PATTERNS = [
    # Fetch API
    (r'fetch\s*\(\s*["\']([^"\']+)["\']', "fetch"),
    (r'fetch\s*\(\s*`([^`]+)`', "fetch_template"),

    # Axios
    (r'axios\.(?:get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']', "axios"),
    (r'axios\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', "axios_config"),

    # jQuery AJAX
    (r'\$\.(?:ajax|get|post)\s*\(\s*["\']([^"\']+)["\']', "jquery"),
    (r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', "jquery_config"),

    # XMLHttpRequest
    (r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH)["\'],\s*["\']([^"\']+)["\']', "xhr"),

    # URL strings
    (r'["\']\/api\/[^"\']+["\']', "api_string"),
    (r'["\']\/v\d+\/[^"\']+["\']', "versioned_api"),

    # URL construction
    (r'(?:baseUrl|apiUrl|endpoint|API_URL|BASE_URL)\s*[+:=]\s*["\']([^"\']+)["\']', "url_config"),
]

# Parameter patterns
PARAM_PATTERNS = [
    r'[?&](\w+)=',  # URL parameters
    r'params\s*:\s*\{([^}]+)\}',  # Object params
    r'\.(?:get|post|put|delete)\s*\([^)]*,\s*\{([^}]+)\}',  # Request body
    r'FormData\(\).*?\.append\s*\(\s*["\'](\w+)["\']',  # FormData
    r'(?:name|id)\s*=\s*["\'](\w+)["\']',  # Form field names
]


class JSAnalyzer:
    """Analyze JavaScript files for security issues"""

    def __init__(self, rate_limit: float = 5.0, user_agent: str = "BugBountyResearcher"):
        self.rate_limit = rate_limit
        self.min_interval = 1.0 / rate_limit
        self.last_request = 0.0
        self.lock = threading.Lock()
        self.user_agent = user_agent
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': user_agent})

    def _rate_limit_wait(self):
        """Wait to respect rate limit"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_request
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_request = time.time()

    def _fetch_js(self, url: str) -> Optional[str]:
        """Fetch JavaScript file content"""
        self._rate_limit_wait()
        try:
            response = self.session.get(url, timeout=15)
            if response.status_code == 200:
                return response.text
        except:
            pass
        return None

    def _redact_secret(self, value: str, keep_chars: int = 4) -> str:
        """Redact a secret value, keeping first/last chars"""
        if len(value) <= keep_chars * 2:
            return '*' * len(value)
        return value[:keep_chars] + '*' * (len(value) - keep_chars * 2) + value[-keep_chars:]

    def find_secrets(self, js_content: str, source_file: str) -> List[SecretFinding]:
        """Find potential secrets in JavaScript code"""
        findings = []

        for secret_type, config in SECRET_PATTERNS.items():
            matches = re.finditer(config["pattern"], js_content, re.IGNORECASE)
            for match in matches:
                value = match.group(0)

                # Skip common false positives
                if secret_type == "aws_secret_key":
                    # Skip if looks like a hash or common string
                    if re.match(r'^[a-f0-9]{40}$', value):
                        continue

                # Get context (surrounding code)
                start = max(0, match.start() - 50)
                end = min(len(js_content), match.end() + 50)
                context = js_content[start:end].replace('\n', ' ')

                finding = SecretFinding(
                    type=secret_type,
                    value=self._redact_secret(value),
                    context=context[:100] + "..." if len(context) > 100 else context,
                    file=source_file,
                    severity=config["severity"],
                )
                findings.append(finding)

        return findings

    def find_api_endpoints(self, js_content: str, base_url: str, source_file: str) -> List[ApiEndpoint]:
        """Extract API endpoints from JavaScript"""
        endpoints = []
        seen = set()

        for pattern, pattern_type in API_PATTERNS:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                url = match.group(1) if match.groups() else match.group(0)
                url = url.strip('"\'')

                # Skip empty, fragments, or data URIs
                if not url or url.startswith('#') or url.startswith('data:'):
                    continue

                # Resolve relative URLs
                if url.startswith('/'):
                    parsed = urlparse(base_url)
                    url = f"{parsed.scheme}://{parsed.netloc}{url}"
                elif not url.startswith('http'):
                    url = urljoin(base_url, url)

                # Skip duplicates
                if url in seen:
                    continue
                seen.add(url)

                # Determine HTTP method from context
                method = "GET"
                context_start = max(0, match.start() - 100)
                context = js_content[context_start:match.end()]
                if re.search(r'\.post\(|POST|method:\s*["\']POST', context, re.IGNORECASE):
                    method = "POST"
                elif re.search(r'\.put\(|PUT|method:\s*["\']PUT', context, re.IGNORECASE):
                    method = "PUT"
                elif re.search(r'\.delete\(|DELETE|method:\s*["\']DELETE', context, re.IGNORECASE):
                    method = "DELETE"

                # Extract parameters
                params = re.findall(r'[?&](\w+)=', url)

                endpoint = ApiEndpoint(
                    url=url.split('?')[0],  # Remove query string
                    method=method,
                    parameters=params,
                    source_file=source_file,
                    context=pattern_type,
                )
                endpoints.append(endpoint)

        return endpoints

    def find_dom_sinks(self, js_content: str, source_file: str) -> List[DomSink]:
        """Find potential DOM XSS sinks"""
        sinks = []

        for sink_name, config in DOM_SINKS.items():
            matches = re.finditer(config["pattern"], js_content, re.IGNORECASE)
            for match in matches:
                # Get surrounding code for context
                start = max(0, match.start() - 30)
                end = min(len(js_content), match.end() + 50)
                code_snippet = js_content[start:end].replace('\n', ' ')

                # Check if input might be user-controlled
                exploitable = False
                if re.search(r'location\.|\.hash|\.search|document\.URL|\.referrer|window\.name', code_snippet):
                    exploitable = True

                sink = DomSink(
                    sink_type=sink_name,
                    code_snippet=code_snippet[:100],
                    file=source_file,
                    exploitable=exploitable,
                    notes=config["description"],
                )
                sinks.append(sink)

        return sinks

    def find_parameters(self, js_content: str) -> Set[str]:
        """Extract potential parameters from JavaScript"""
        params = set()

        for pattern in PARAM_PATTERNS:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = ' '.join(match)
                # Extract individual parameter names
                param_names = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]{2,30})\b', match)
                params.update(param_names)

        # Filter out common false positives
        exclude = {'function', 'return', 'const', 'let', 'var', 'true', 'false',
                   'null', 'undefined', 'this', 'window', 'document', 'console',
                   'error', 'Error', 'Array', 'Object', 'String', 'Number', 'Boolean'}
        params = params - exclude

        return params

    def analyze_url(self, url: str) -> JSAnalysisResult:
        """Analyze all JavaScript files from a URL"""
        if not url.startswith('http'):
            url = f"https://{url}"

        print(f"\n[*] JavaScript Analysis: {url}")
        print("=" * 50)

        result = JSAnalysisResult(target=url)

        # Fetch the main page first
        print("    [FETCH] Getting main page...")
        self._rate_limit_wait()
        try:
            response = self.session.get(url, timeout=15)
        except:
            print("    [ERROR] Failed to fetch target")
            return result

        # Extract JavaScript file URLs
        js_pattern = r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']'
        js_urls = set()

        for match in re.finditer(js_pattern, response.text, re.IGNORECASE):
            js_url = match.group(1)
            if js_url.startswith('//'):
                js_url = 'https:' + js_url
            elif js_url.startswith('/'):
                parsed = urlparse(url)
                js_url = f"{parsed.scheme}://{parsed.netloc}{js_url}"
            elif not js_url.startswith('http'):
                js_url = urljoin(url, js_url)
            js_urls.add(js_url)

        # Also analyze inline scripts
        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', response.text, re.DOTALL | re.IGNORECASE)

        result.js_files = list(js_urls)
        print(f"    [FOUND] {len(js_urls)} external JS files, {len(inline_scripts)} inline scripts")

        # Analyze inline scripts
        print("    [ANALYZE] Checking inline scripts...")
        for i, script in enumerate(inline_scripts):
            if len(script.strip()) > 50:  # Skip tiny scripts
                result.secrets.extend(self.find_secrets(script, f"inline_script_{i}"))
                result.api_endpoints.extend(self.find_api_endpoints(script, url, f"inline_script_{i}"))
                result.dom_sinks.extend(self.find_dom_sinks(script, f"inline_script_{i}"))
                result.parameters.update(self.find_parameters(script))

        # Analyze external JS files (limit to avoid too many requests)
        print(f"    [ANALYZE] Checking external JS files...")
        for js_url in list(js_urls)[:15]:  # Limit to 15 files
            js_file = js_url.split('/')[-1].split('?')[0]
            print(f"      Analyzing: {js_file}")

            content = self._fetch_js(js_url)
            if content:
                result.secrets.extend(self.find_secrets(content, js_file))
                result.api_endpoints.extend(self.find_api_endpoints(content, url, js_file))
                result.dom_sinks.extend(self.find_dom_sinks(content, js_file))
                result.parameters.update(self.find_parameters(content))

        # Deduplicate endpoints by URL
        seen_urls = set()
        unique_endpoints = []
        for ep in result.api_endpoints:
            if ep.url not in seen_urls:
                seen_urls.add(ep.url)
                unique_endpoints.append(ep)
        result.api_endpoints = unique_endpoints

        print(f"\n    [RESULTS]")
        print(f"      Secrets found: {len(result.secrets)}")
        print(f"      API endpoints: {len(result.api_endpoints)}")
        print(f"      DOM sinks: {len(result.dom_sinks)}")
        print(f"      Parameters: {len(result.parameters)}")

        return result


class AmazonJSAnalyzer(JSAnalyzer):
    """Amazon VRP-compliant JS analyzer"""

    def __init__(self, username: str = "yourh1username"):
        config = get_amazon_config(username)
        super().__init__(
            rate_limit=config.rate_limit,
            user_agent=config.user_agent
        )


class ShopifyJSAnalyzer(JSAnalyzer):
    """Shopify-compliant JS analyzer"""

    def __init__(self, username: str = "yourh1username"):
        config = get_shopify_config(username)
        super().__init__(
            rate_limit=config.rate_limit,
            user_agent=config.user_agent
        )


def save_js_results(result: JSAnalysisResult, output_file: str):
    """Save JS analysis results to JSON"""
    data = {
        "target": result.target,
        "analysis_time": result.analysis_time,
        "js_files_analyzed": len(result.js_files),
        "js_files": result.js_files,
        "secrets": [
            {
                "type": s.type,
                "value": s.value,
                "context": s.context,
                "file": s.file,
                "severity": s.severity,
            }
            for s in result.secrets
        ],
        "api_endpoints": [
            {
                "url": ep.url,
                "method": ep.method,
                "parameters": ep.parameters,
                "source_file": ep.source_file,
            }
            for ep in result.api_endpoints
        ],
        "dom_sinks": [
            {
                "sink_type": s.sink_type,
                "code_snippet": s.code_snippet,
                "file": s.file,
                "exploitable": s.exploitable,
                "notes": s.notes,
            }
            for s in result.dom_sinks
        ],
        "parameters": sorted(list(result.parameters)),
    }

    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"\n[*] Results saved to: {output_file}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="JavaScript Analyzer")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--program", "-p", choices=["amazon", "shopify"],
                        help="Bug bounty program")
    parser.add_argument("--username", "-u", default="yourh1username",
                        help="HackerOne username")
    parser.add_argument("--output", "-o", help="Output JSON file")

    args = parser.parse_args()

    # Create analyzer
    if args.program == "amazon":
        analyzer = AmazonJSAnalyzer(args.username)
    elif args.program == "shopify":
        analyzer = ShopifyJSAnalyzer(args.username)
    else:
        analyzer = JSAnalyzer()

    # Run analysis
    result = analyzer.analyze_url(args.target)

    # Print summary
    print("\n" + "=" * 50)
    print("JAVASCRIPT ANALYSIS SUMMARY")
    print("=" * 50)

    if result.secrets:
        print("\n[!] SECRETS FOUND:")
        for secret in result.secrets:
            print(f"  [{secret.severity.upper()}] {secret.type}")
            print(f"    Value: {secret.value}")
            print(f"    File: {secret.file}")

    if result.api_endpoints:
        print(f"\nAPI ENDPOINTS ({len(result.api_endpoints)}):")
        for ep in result.api_endpoints[:15]:
            print(f"  [{ep.method}] {ep.url}")
            if ep.parameters:
                print(f"       Params: {', '.join(ep.parameters)}")

    if result.dom_sinks:
        exploitable = [s for s in result.dom_sinks if s.exploitable]
        print(f"\nDOM SINKS ({len(result.dom_sinks)} total, {len(exploitable)} potentially exploitable):")
        for sink in exploitable[:10]:
            print(f"  [!] {sink.sink_type} in {sink.file}")
            print(f"      {sink.code_snippet[:60]}...")

    if result.parameters:
        print(f"\nPARAMETERS ({len(result.parameters)}):")
        print(f"  {', '.join(list(result.parameters)[:30])}")
        if len(result.parameters) > 30:
            print(f"  ... and {len(result.parameters) - 30} more")

    if args.output:
        save_js_results(result, args.output)
