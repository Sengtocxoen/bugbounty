#!/usr/bin/env python3
"""
Subdomain Discovery Module
Discovers subdomains using multiple techniques:
- Certificate Transparency logs (crt.sh)
- DNS brute-forcing with common wordlist
- Recursive discovery

Respects rate limits for bug bounty compliance.
"""

import json
import time
import socket
import threading
from dataclasses import dataclass, field
from typing import List, Set, Optional, Tuple
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import requests
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    exit(1)

from utils.config import AmazonConfig, ShopifyConfig, get_amazon_config, get_shopify_config
from utils.scope_validator import AmazonScopeValidator, ShopifyScopeValidator


@dataclass
class SubdomainResult:
    """Result of subdomain discovery"""
    domain: str
    subdomains: Set[str] = field(default_factory=set)
    live_subdomains: Set[str] = field(default_factory=set)
    in_scope: Set[str] = field(default_factory=set)
    out_of_scope: Set[str] = field(default_factory=set)
    discovery_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())


# Common subdomain wordlist for brute-forcing
COMMON_SUBDOMAINS = [
    "www", "api", "app", "admin", "dev", "staging", "test", "beta", "alpha",
    "m", "mobile", "mail", "smtp", "pop", "imap", "webmail", "email",
    "ftp", "sftp", "ssh", "vpn", "remote", "gateway", "proxy",
    "cdn", "static", "assets", "img", "images", "media", "files", "download",
    "login", "auth", "sso", "oauth", "accounts", "account", "user", "users",
    "portal", "dashboard", "panel", "console", "manage", "management",
    "blog", "news", "support", "help", "docs", "documentation", "wiki",
    "shop", "store", "cart", "checkout", "pay", "payment", "payments",
    "search", "data", "db", "database", "sql", "mysql", "postgres", "mongo",
    "cache", "redis", "memcached", "elastic", "elasticsearch", "kibana",
    "jenkins", "ci", "cd", "build", "deploy", "git", "gitlab", "github",
    "status", "health", "monitor", "metrics", "logs", "logging", "trace",
    "internal", "intranet", "corp", "corporate", "office", "hr",
    "partner", "partners", "vendor", "vendors", "supplier", "suppliers",
    "demo", "sandbox", "preview", "uat", "qa", "prod", "production",
    "service", "services", "microservice", "ms", "svc",
    "v1", "v2", "v3", "api-v1", "api-v2", "api-v3",
    "graphql", "rest", "ws", "websocket", "socket", "wss",
    "secure", "ssl", "https", "origin", "edge", "node",
    "backup", "bak", "old", "new", "temp", "tmp", "archive",
    "analytics", "tracking", "ads", "advertising", "marketing",
    "crm", "erp", "bi", "reporting", "reports",
    "aws", "s3", "ec2", "lambda", "azure", "gcp", "cloud",
    "cdn1", "cdn2", "cdn3", "web1", "web2", "web3", "app1", "app2",
]


class SubdomainDiscovery:
    """Subdomain discovery using multiple techniques"""

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

    def discover_crtsh(self, domain: str) -> Set[str]:
        """
        Discover subdomains using Certificate Transparency logs (crt.sh)
        This is passive reconnaissance - no direct interaction with target
        """
        subdomains = set()
        print(f"    [crt.sh] Querying certificate transparency logs...")

        try:
            self._rate_limit_wait()
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = self.session.get(url, timeout=30)

            if response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        # Handle wildcard and multi-line entries
                        for subdomain in name.split('\n'):
                            subdomain = subdomain.strip().lower()
                            # Remove wildcards
                            if subdomain.startswith('*.'):
                                subdomain = subdomain[2:]
                            if subdomain.endswith(domain) and subdomain:
                                subdomains.add(subdomain)
                    print(f"    [crt.sh] Found {len(subdomains)} unique entries")
                except json.JSONDecodeError:
                    print("    [crt.sh] Failed to parse response")
            else:
                print(f"    [crt.sh] HTTP {response.status_code}")

        except requests.exceptions.Timeout:
            print("    [crt.sh] Request timed out")
        except Exception as e:
            print(f"    [crt.sh] Error: {str(e)}")

        return subdomains

    def discover_dns_bruteforce(self, domain: str, wordlist: List[str] = None,
                                 max_workers: int = 10) -> Set[str]:
        """
        Brute-force subdomain discovery via DNS resolution
        NOTE: This is active reconnaissance - be mindful of rate limits
        """
        if wordlist is None:
            wordlist = COMMON_SUBDOMAINS

        subdomains = set()
        print(f"    [DNS] Brute-forcing {len(wordlist)} subdomains...")

        def check_subdomain(sub: str) -> Optional[str]:
            """Check if a subdomain resolves"""
            full_domain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                return full_domain
            except socket.gaierror:
                return None

        # Use thread pool but respect rate limits
        found_count = 0
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomains.add(result)
                    found_count += 1

        print(f"    [DNS] Found {found_count} resolving subdomains")
        return subdomains

    def check_alive(self, subdomains: Set[str], timeout: int = 5) -> Set[str]:
        """
        Check which subdomains are alive (responding to HTTP/HTTPS)
        """
        alive = set()
        print(f"    [ALIVE] Checking {len(subdomains)} subdomains for HTTP response...")

        def check_http(subdomain: str) -> Optional[str]:
            """Check if subdomain responds to HTTP/HTTPS"""
            for scheme in ['https', 'http']:
                try:
                    self._rate_limit_wait()
                    url = f"{scheme}://{subdomain}"
                    response = self.session.head(url, timeout=timeout, allow_redirects=True)
                    if response.status_code < 500:
                        return subdomain
                except:
                    continue
            return None

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(check_http, sub): sub for sub in subdomains}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    alive.add(result)

        print(f"    [ALIVE] {len(alive)} subdomains responding")
        return alive

    def discover(self, domain: str, check_alive: bool = True,
                 dns_bruteforce: bool = True) -> SubdomainResult:
        """
        Full subdomain discovery pipeline
        """
        print(f"\n[*] Subdomain Discovery: {domain}")
        print("=" * 50)

        result = SubdomainResult(domain=domain)

        # Certificate Transparency (passive)
        ct_subs = self.discover_crtsh(domain)
        result.subdomains.update(ct_subs)

        # DNS Brute-force (active)
        if dns_bruteforce:
            dns_subs = self.discover_dns_bruteforce(domain)
            result.subdomains.update(dns_subs)

        print(f"\n    [TOTAL] {len(result.subdomains)} unique subdomains found")

        # Check which are alive
        if check_alive and result.subdomains:
            result.live_subdomains = self.check_alive(result.subdomains)

        return result


class AmazonSubdomainDiscovery(SubdomainDiscovery):
    """Amazon VRP-compliant subdomain discovery"""

    def __init__(self, config: Optional[AmazonConfig] = None):
        self.config = config or get_amazon_config()
        super().__init__(
            rate_limit=self.config.rate_limit,
            user_agent=self.config.user_agent
        )
        self.validator = AmazonScopeValidator(self.config)

    def discover_and_validate(self, domain: str, **kwargs) -> SubdomainResult:
        """Discover subdomains and validate against scope"""
        result = self.discover(domain, **kwargs)

        print("\n    [SCOPE] Validating against Amazon VRP scope...")

        for subdomain in result.live_subdomains or result.subdomains:
            is_valid, reason = self.validator.is_in_scope(subdomain)
            if is_valid:
                result.in_scope.add(subdomain)
            else:
                result.out_of_scope.add(subdomain)

        print(f"    [SCOPE] In-scope: {len(result.in_scope)}")
        print(f"    [SCOPE] Out-of-scope: {len(result.out_of_scope)}")

        return result


class ShopifySubdomainDiscovery(SubdomainDiscovery):
    """Shopify-compliant subdomain discovery"""

    def __init__(self, config: Optional[ShopifyConfig] = None):
        self.config = config or get_shopify_config()
        super().__init__(
            rate_limit=self.config.rate_limit,
            user_agent=self.config.user_agent
        )
        self.validator = ShopifyScopeValidator(self.config)

    def discover_and_validate(self, domain: str, **kwargs) -> SubdomainResult:
        """Discover subdomains and validate against scope"""
        result = self.discover(domain, **kwargs)

        print("\n    [SCOPE] Validating against Shopify scope...")

        for subdomain in result.live_subdomains or result.subdomains:
            is_valid, reason = self.validator.is_in_scope(subdomain)
            if is_valid:
                result.in_scope.add(subdomain)
            else:
                result.out_of_scope.add(subdomain)

        print(f"    [SCOPE] In-scope: {len(result.in_scope)}")
        print(f"    [SCOPE] Out-of-scope: {len(result.out_of_scope)}")

        return result


def save_subdomains(result: SubdomainResult, output_file: str):
    """Save subdomain results to file"""
    data = {
        "domain": result.domain,
        "discovery_time": result.discovery_time,
        "total_found": len(result.subdomains),
        "live_count": len(result.live_subdomains),
        "in_scope_count": len(result.in_scope),
        "out_of_scope_count": len(result.out_of_scope),
        "all_subdomains": sorted(list(result.subdomains)),
        "live_subdomains": sorted(list(result.live_subdomains)),
        "in_scope": sorted(list(result.in_scope)),
        "out_of_scope": sorted(list(result.out_of_scope)),
    }

    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"\n[*] Results saved to: {output_file}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Subdomain Discovery Tool")
    parser.add_argument("domain", help="Target domain (e.g., amazon.com)")
    parser.add_argument("--program", "-p", choices=["amazon", "shopify"],
                        help="Bug bounty program for scope validation")
    parser.add_argument("--username", "-u", default="yourh1username",
                        help="HackerOne username")
    parser.add_argument("--no-bruteforce", action="store_true",
                        help="Skip DNS brute-force (passive only)")
    parser.add_argument("--no-alive-check", action="store_true",
                        help="Skip HTTP alive check")
    parser.add_argument("--output", "-o", help="Output JSON file")

    args = parser.parse_args()

    # Run discovery
    if args.program == "amazon":
        config = get_amazon_config(args.username)
        discovery = AmazonSubdomainDiscovery(config)
        result = discovery.discover_and_validate(
            args.domain,
            dns_bruteforce=not args.no_bruteforce,
            check_alive=not args.no_alive_check
        )
    elif args.program == "shopify":
        config = get_shopify_config(args.username)
        discovery = ShopifySubdomainDiscovery(config)
        result = discovery.discover_and_validate(
            args.domain,
            dns_bruteforce=not args.no_bruteforce,
            check_alive=not args.no_alive_check
        )
    else:
        discovery = SubdomainDiscovery()
        result = discovery.discover(
            args.domain,
            dns_bruteforce=not args.no_bruteforce,
            check_alive=not args.no_alive_check
        )

    # Print summary
    print("\n" + "=" * 50)
    print("SUBDOMAIN DISCOVERY SUMMARY")
    print("=" * 50)
    print(f"Domain: {result.domain}")
    print(f"Total found: {len(result.subdomains)}")
    print(f"Live: {len(result.live_subdomains)}")
    if args.program:
        print(f"In-scope: {len(result.in_scope)}")
        print(f"Out-of-scope: {len(result.out_of_scope)}")

    # Save if output specified
    if args.output:
        save_subdomains(result, args.output)
    else:
        # Print in-scope subdomains
        if result.in_scope:
            print("\nIn-scope subdomains:")
            for sub in sorted(result.in_scope)[:20]:
                print(f"  - {sub}")
            if len(result.in_scope) > 20:
                print(f"  ... and {len(result.in_scope) - 20} more")
