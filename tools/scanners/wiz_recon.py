#!/usr/bin/env python3
"""
Wiz Bug Bounty Reconnaissance Module
====================================

Implements the 5-phase reconnaissance methodology from Wiz's Bug Bounty Masterclass:

Phase 1: Passive Subdomain Discovery
    - Subfinder (CT logs, search engines, DNS datasets)
    - Multiple passive APIs (crt.sh, HackerTarget, etc.)

Phase 2: DNS Resolution
    - Filter non-resolving domains with puredns
    - Wildcard detection

Phase 3: Active DNS Discovery
    - DNS bruteforcing with wordlists
    - DNS permutation with alterx

Phase 4: Root Domain Discovery
    - Reverse WHOIS lookup
    - Crunchbase acquisition search
    - GitHub domain mining
    - AI-suggested domains (placeholder)

Phase 5: Public Exposure Probing
    - httpx metadata extraction (title, status, IP, CNAME, tech)
    - Port scanning for non-HTTP services

Reference: https://www.wiz.io/bug-bounty-masterclass/reconnaissance/overview

Usage:
    python wiz_recon.py example.com -p amazon -u myh1user
    python wiz_recon.py example.com --quick  # Fast mode
    python wiz_recon.py example.com --very-thorough  # Deep mode
"""

import sys
import json
import time
import re
import socket
import threading
import argparse
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Set, Dict, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    sys.exit(1)

# Add tools directory to path
sys.path.insert(0, str(Path(__file__).parent))

from external_tools import (
    SubfinderWrapper, PurednsWrapper, AlterxWrapper, HttpxWrapper, NmapWrapper,
    ToolChecker, ToolResult, HttpxResult
)
from utils.config import get_amazon_config, get_shopify_config, AmazonConfig, ShopifyConfig
from utils.scope_validator import AmazonScopeValidator, ShopifyScopeValidator


# Extended wordlist for DNS bruteforcing (Wiz recommended)
DNS_WORDLIST_QUICK = [
    "www", "api", "app", "admin", "dev", "staging", "test", "beta", "m", "mobile",
    "mail", "smtp", "webmail", "ftp", "vpn", "remote", "cdn", "static", "assets",
    "login", "auth", "sso", "portal", "dashboard", "panel", "blog", "docs", "wiki",
    "shop", "store", "pay", "support", "help", "status", "monitor", "git", "gitlab"
]

DNS_WORDLIST_MEDIUM = DNS_WORDLIST_QUICK + [
    "api-v1", "api-v2", "api-v3", "v1", "v2", "v3", "graphql", "rest", "ws",
    "internal", "intranet", "corp", "office", "private", "secure", "ssl",
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic", "cache",
    "jenkins", "ci", "cd", "build", "deploy", "docker", "k8s", "kubernetes",
    "aws", "s3", "azure", "gcp", "cloud", "lambda", "storage", "bucket",
    "analytics", "tracking", "metrics", "logs", "trace", "prometheus", "grafana",
    "crm", "erp", "hr", "finance", "billing", "invoice", "order", "cart",
    "partner", "vendor", "affiliate", "demo", "sandbox", "uat", "qa", "prod",
    "web1", "web2", "app1", "app2", "api1", "api2", "node1", "node2", "server1",
    "origin", "edge", "proxy", "gateway", "lb", "loadbalancer", "firewall"
]

DNS_WORDLIST_THOROUGH = DNS_WORDLIST_MEDIUM + [
    # Extended prefixes
    "www1", "www2", "www3", "m1", "m2", "api-dev", "api-staging", "api-prod",
    "dev1", "dev2", "dev3", "test1", "test2", "stage1", "stage2",
    "alpha", "canary", "nightly", "rc", "release", "preprod", "pre-prod",
    # Infrastructure
    "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2", "mx", "mx1", "mx2",
    "pop", "pop3", "imap", "smtp1", "smtp2", "relay", "outbound",
    "sftp", "ftps", "ssh", "bastion", "jump", "rdp", "terminal",
    # Services
    "svc", "service", "microservice", "ms", "micro", "worker", "job", "cron",
    "queue", "mq", "rabbitmq", "kafka", "celery", "task", "scheduler",
    "search", "solr", "lucene", "algolia", "typesense",
    # Business
    "checkout", "payment", "payments", "subscribe", "subscription", "membership",
    "account", "accounts", "user", "users", "member", "members", "customer",
    "report", "reports", "bi", "data", "warehouse", "bigdata", "lake",
    # Monitoring
    "health", "healthcheck", "ping", "check", "uptime", "newrelic", "datadog",
    "sentry", "bugsnag", "rollbar", "splunk", "elk", "kibana", "logstash",
    "jaeger", "zipkin", "apm", "observability",
    # Security
    "sec", "security", "waf", "ids", "ips", "siem", "vault", "secrets",
    "cert", "certs", "certificates", "pki", "ocsp", "crl",
    # Geographic
    "us", "eu", "asia", "apac", "emea", "us-east", "us-west", "eu-west",
    "east", "west", "north", "south", "global", "region", "regional",
    # Legacy
    "old", "new", "legacy", "archive", "backup", "bak", "bkp", "temp", "tmp",
    # Numbered variants
    "cdn1", "cdn2", "cdn3", "static1", "static2", "img1", "img2",
    "media1", "media2", "video1", "video2", "file1", "file2",
    "proxy1", "proxy2", "gateway1", "gateway2", "lb1", "lb2",
]


@dataclass
class RootDomainInfo:
    """Information about a root domain discovered"""
    domain: str
    source: str  # whois, crunchbase, github, manual
    company_name: Optional[str] = None
    acquisition_date: Optional[str] = None
    confidence: str = "medium"  # low, medium, high
    notes: Optional[str] = None


@dataclass
class SubdomainData:
    """Comprehensive data about a subdomain"""
    subdomain: str
    is_alive: bool = False
    status_code: Optional[int] = None
    title: Optional[str] = None
    ip_address: Optional[str] = None
    cname: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    server: Optional[str] = None
    content_length: Optional[int] = None
    redirect_url: Optional[str] = None
    open_ports: Dict[int, str] = field(default_factory=dict)
    source: str = "passive"  # passive, bruteforce, permutation
    in_scope: bool = True
    scope_reason: str = ""


@dataclass
class WizReconResult:
    """Complete reconnaissance result following Wiz methodology"""
    target_domain: str
    program: Optional[str]
    scan_start: str
    scan_end: str = ""

    # Phase 1: Passive Discovery
    passive_subdomains: int = 0
    passive_sources_used: List[str] = field(default_factory=list)

    # Phase 2: DNS Resolution
    resolved_subdomains: int = 0
    wildcard_detected: bool = False

    # Phase 3: Active Discovery
    bruteforce_found: int = 0
    permutation_found: int = 0

    # Phase 4: Root Domain Discovery
    root_domains: List[RootDomainInfo] = field(default_factory=list)

    # Phase 5: Public Exposure
    live_assets: int = 0
    http_services: int = 0
    non_http_services: int = 0

    # Aggregated data
    all_subdomains: Dict[str, SubdomainData] = field(default_factory=dict)
    in_scope_count: int = 0
    out_of_scope_count: int = 0

    # Statistics
    total_requests: int = 0
    duration_seconds: float = 0
    phases_completed: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class RootDomainDiscovery:
    """
    Phase 4: Root Domain Discovery

    Discovers additional root domains owned by the target organization through:
    - Reverse WHOIS lookup
    - Crunchbase acquisition search
    - GitHub domain mining
    """

    def __init__(self, rate_limit: float = 2.0):
        self.rate_limit = rate_limit
        self.min_interval = 1.0 / rate_limit
        self.last_request = 0.0
        self.lock = threading.Lock()

        self.session = requests.Session()
        retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; BugBountyResearcher/1.0)'
        })

    def _rate_limit_wait(self):
        with self.lock:
            now = time.time()
            elapsed = now - self.last_request
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_request = time.time()

    def _safe_request(self, url: str, **kwargs) -> Optional[requests.Response]:
        self._rate_limit_wait()
        try:
            kwargs.setdefault('timeout', 15)
            kwargs.setdefault('verify', False)
            return self.session.get(url, **kwargs)
        except Exception:
            return None

    def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """
        Get WHOIS information for a domain

        Returns:
            Dict with registrant info (org, email, etc.)
        """
        whois_info = {
            "registrant_org": None,
            "registrant_email": None,
            "registrar": None,
            "created_date": None,
            "nameservers": []
        }

        # Try whois via API (fallback method - many APIs require auth)
        try:
            # Using a simple whois service
            response = self._safe_request(f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&outputFormat=JSON")
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    record = data.get("WhoisRecord", {})
                    registrant = record.get("registrant", {})
                    whois_info["registrant_org"] = registrant.get("organization")
                    whois_info["registrant_email"] = registrant.get("email")
                    whois_info["registrar"] = record.get("registrarName")
                except:
                    pass
        except:
            pass

        return whois_info

    def reverse_whois_search(self, org_name: str = None, email: str = None) -> List[RootDomainInfo]:
        """
        Search for domains with same registrant

        This would typically require paid API access (whoxy.com, domaintools, etc.)
        Returns placeholder for now - implement with actual API key
        """
        domains = []

        # NOTE: Reverse WHOIS typically requires paid API
        # Popular services: whoxy.com, domaintools.com, whoisxmlapi.com

        print(f"    [REVERSE-WHOIS] Searching for domains registered to: {org_name or email}")
        print(f"    [REVERSE-WHOIS] NOTE: Full reverse WHOIS requires API key (whoxy.com recommended)")

        return domains

    def search_crunchbase(self, company_name: str) -> List[RootDomainInfo]:
        """
        Search Crunchbase for company acquisitions

        Note: Full Crunchbase API requires authentication
        This provides guidance for manual research
        """
        domains = []

        print(f"    [CRUNCHBASE] Searching acquisitions for: {company_name}")
        print(f"    [CRUNCHBASE] Manual check: https://www.crunchbase.com/organization/{company_name.lower().replace(' ', '-')}")

        # Try to scrape basic info (limited without API)
        search_url = f"https://www.crunchbase.com/organization/{company_name.lower().replace(' ', '-')}"
        response = self._safe_request(search_url)

        if response and response.status_code == 200:
            # Look for acquisition mentions
            if "acquired" in response.text.lower():
                print(f"    [CRUNCHBASE] Found acquisition mentions - manual review recommended")

        return domains

    def search_github(self, domain: str, org_name: str = None) -> List[RootDomainInfo]:
        """
        Search GitHub for domain references in code/configs

        Searches for:
        - Internal domain references
        - Config files with domain lists
        - Documentation mentioning other domains
        """
        domains = []

        search_terms = [
            f'"{domain}" extension:json',
            f'"{domain}" extension:yml',
            f'"{domain}" extension:yaml',
            f'"{domain}" extension:conf',
        ]

        if org_name:
            search_terms.extend([
                f'org:{org_name.replace(" ", "")} domain',
                f'"{org_name}" site:github.com'
            ])

        print(f"    [GITHUB] Searching code for domain references...")

        for term in search_terms[:2]:  # Limit to avoid rate limiting
            try:
                # GitHub code search API (requires auth for higher limits)
                search_url = f"https://api.github.com/search/code?q={term}"
                response = self._safe_request(search_url)

                if response and response.status_code == 200:
                    data = response.json()
                    if data.get("total_count", 0) > 0:
                        print(f"    [GITHUB] Found {data['total_count']} results for: {term[:50]}...")
                        # Would need to parse results for domain extraction
                elif response and response.status_code == 403:
                    print(f"    [GITHUB] Rate limited - authenticate for better results")
                    break
            except Exception as e:
                pass

            time.sleep(2)  # Respect GitHub rate limits

        return domains

    def discover_root_domains(self, primary_domain: str, company_name: str = None) -> List[RootDomainInfo]:
        """
        Run all root domain discovery methods

        Args:
            primary_domain: The main target domain
            company_name: Company name for acquisition search

        Returns:
            List of discovered root domains
        """
        print(f"\n[PHASE 4] ROOT DOMAIN DISCOVERY")
        print("-" * 50)

        all_domains = []

        # 1. WHOIS lookup
        print(f"  [1/3] WHOIS Lookup for {primary_domain}")
        whois_info = self.whois_lookup(primary_domain)

        if whois_info.get("registrant_org"):
            org = whois_info["registrant_org"]
            print(f"    Registrant Organization: {org}")

            # Reverse WHOIS
            print(f"  [2/3] Reverse WHOIS Search")
            reverse_domains = self.reverse_whois_search(org_name=org)
            all_domains.extend(reverse_domains)

        # 2. Crunchbase acquisitions
        print(f"  [3/3] Crunchbase Acquisition Search")
        if company_name:
            crunchbase_domains = self.search_crunchbase(company_name)
            all_domains.extend(crunchbase_domains)
        else:
            # Extract company name from domain
            base_name = primary_domain.split('.')[0]
            crunchbase_domains = self.search_crunchbase(base_name)
            all_domains.extend(crunchbase_domains)

        # 3. GitHub search
        github_domains = self.search_github(primary_domain, company_name)
        all_domains.extend(github_domains)

        # Deduplicate
        seen = set()
        unique_domains = []
        for d in all_domains:
            if d.domain not in seen:
                seen.add(d.domain)
                unique_domains.append(d)

        print(f"\n    [SUMMARY] Discovered {len(unique_domains)} additional root domains")
        return unique_domains


class WizReconScanner:
    """
    Main reconnaissance scanner implementing Wiz 5-phase methodology

    Phases:
    1. Passive Subdomain Discovery
    2. DNS Resolution
    3. Active DNS Discovery (brute-force + permutation)
    4. Root Domain Discovery
    5. Public Exposure Probing
    """

    def __init__(self, program: str = None, username: str = "yourh1username",
                 thoroughness: str = "medium"):
        """
        Initialize scanner

        Args:
            program: Bug bounty program (amazon, shopify, None)
            username: HackerOne username
            thoroughness: quick, medium, or thorough
        """
        self.program = program
        self.username = username
        self.thoroughness = thoroughness

        # Configure based on program
        if program == "amazon":
            self.config = get_amazon_config(username)
            self.scope_validator = AmazonScopeValidator(self.config)
            self.rate_limit = self.config.rate_limit
        elif program == "shopify":
            self.config = get_shopify_config(username)
            self.scope_validator = ShopifyScopeValidator(self.config)
            self.rate_limit = self.config.rate_limit
        else:
            self.config = None
            self.scope_validator = None
            self.rate_limit = 10.0

        # Select wordlist based on thoroughness
        self.wordlist = {
            "quick": DNS_WORDLIST_QUICK,
            "medium": DNS_WORDLIST_MEDIUM,
            "thorough": DNS_WORDLIST_THOROUGH,
        }.get(thoroughness, DNS_WORDLIST_MEDIUM)

        # Initialize tool wrappers
        self.subfinder = SubfinderWrapper()
        self.puredns = PurednsWrapper()
        self.alterx = AlterxWrapper()
        self.httpx = HttpxWrapper(rate_limit=int(self.rate_limit * 30))  # 30x for parallel probing
        self.nmap = NmapWrapper()
        self.root_discovery = RootDomainDiscovery()

        # HTTP session for fallback requests
        self.session = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        if self.config:
            self.session.headers.update({'User-Agent': self.config.user_agent})

    def print_banner(self):
        """Print scanner banner"""
        print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║              WIZ BUG BOUNTY RECONNAISSANCE SCANNER                           ║
║          Based on: wiz.io/bug-bounty-masterclass/reconnaissance              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  PHASES:                                                                      ║
║  [1] Passive Discovery   - subfinder + 8 passive APIs                        ║
║  [2] DNS Resolution      - puredns filtering, wildcard detection             ║
║  [3] Active Discovery    - DNS brute-force + alterx permutations             ║
║  [4] Root Domains        - Reverse WHOIS, Crunchbase, GitHub                 ║
║  [5] Exposure Probing    - httpx metadata + port scanning                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """)

    def log(self, message: str, level: str = "INFO"):
        """Log with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix = {
            "INFO": "[*]",
            "SUCCESS": "[+]",
            "WARNING": "[!]",
            "ERROR": "[ERROR]",
            "PHASE": "\n[PHASE]",
        }.get(level, "[*]")
        print(f"{timestamp} {prefix} {message}")

    # ======================== PHASE 1: PASSIVE DISCOVERY ========================

    def phase1_passive_discovery(self, domain: str, result: WizReconResult) -> Set[str]:
        """
        Phase 1: Passive Subdomain Discovery

        Uses subfinder + multiple passive APIs to discover subdomains
        without directly contacting the target.
        """
        print(f"\n{'='*60}")
        print(f"  PHASE 1: PASSIVE SUBDOMAIN DISCOVERY")
        print(f"  Target: {domain}")
        print(f"{'='*60}")

        all_subdomains = set()
        sources_used = []

        # 1. Subfinder (queries ~60 sources)
        print("\n  [1/9] Running subfinder...")
        sf_result = self.subfinder.run(domain, all_sources=True)
        if sf_result.success:
            all_subdomains.update(sf_result.output)
            sources_used.append(f"subfinder ({len(sf_result.output)})")
            print(f"    Found: {len(sf_result.output)} subdomains")
        elif not sf_result.tool_available:
            print(f"    subfinder not installed - using API fallbacks")

        # 2. crt.sh (Certificate Transparency)
        print("  [2/9] Querying crt.sh (CT logs)...")
        ct_subs = self._query_crtsh(domain)
        all_subdomains.update(ct_subs)
        if ct_subs:
            sources_used.append(f"crt.sh ({len(ct_subs)})")
        print(f"    Found: {len(ct_subs)} subdomains")

        # 3. HackerTarget
        print("  [3/9] Querying HackerTarget...")
        ht_subs = self._query_hackertarget(domain)
        all_subdomains.update(ht_subs)
        if ht_subs:
            sources_used.append(f"hackertarget ({len(ht_subs)})")
        print(f"    Found: {len(ht_subs)} subdomains")

        # 4. AlienVault OTX
        print("  [4/9] Querying AlienVault OTX...")
        otx_subs = self._query_alienvault(domain)
        all_subdomains.update(otx_subs)
        if otx_subs:
            sources_used.append(f"alienvault ({len(otx_subs)})")
        print(f"    Found: {len(otx_subs)} subdomains")

        # 5. URLScan.io
        print("  [5/9] Querying URLScan.io...")
        us_subs = self._query_urlscan(domain)
        all_subdomains.update(us_subs)
        if us_subs:
            sources_used.append(f"urlscan ({len(us_subs)})")
        print(f"    Found: {len(us_subs)} subdomains")

        # 6. RapidDNS
        print("  [6/9] Querying RapidDNS...")
        rd_subs = self._query_rapiddns(domain)
        all_subdomains.update(rd_subs)
        if rd_subs:
            sources_used.append(f"rapiddns ({len(rd_subs)})")
        print(f"    Found: {len(rd_subs)} subdomains")

        # 7. CertSpotter
        print("  [7/9] Querying CertSpotter...")
        cs_subs = self._query_certspotter(domain)
        all_subdomains.update(cs_subs)
        if cs_subs:
            sources_used.append(f"certspotter ({len(cs_subs)})")
        print(f"    Found: {len(cs_subs)} subdomains")

        # 8. ThreatCrowd
        print("  [8/9] Querying ThreatCrowd...")
        tc_subs = self._query_threatcrowd(domain)
        all_subdomains.update(tc_subs)
        if tc_subs:
            sources_used.append(f"threatcrowd ({len(tc_subs)})")
        print(f"    Found: {len(tc_subs)} subdomains")

        # 9. BufferOver
        print("  [9/9] Querying BufferOver...")
        bo_subs = self._query_bufferover(domain)
        all_subdomains.update(bo_subs)
        if bo_subs:
            sources_used.append(f"bufferover ({len(bo_subs)})")
        print(f"    Found: {len(bo_subs)} subdomains")

        # Update result
        result.passive_subdomains = len(all_subdomains)
        result.passive_sources_used = sources_used
        result.phases_completed.append("passive_discovery")

        print(f"\n  [PHASE 1 COMPLETE] Total unique subdomains: {len(all_subdomains)}")
        return all_subdomains

    def _query_crtsh(self, domain: str) -> Set[str]:
        """Query crt.sh for CT log entries"""
        subdomains = set()
        try:
            response = self.session.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=30
            )
            if response.status_code == 200:
                for entry in response.json():
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.startswith('*.'):
                            sub = sub[2:]
                        if sub.endswith(domain) and sub:
                            subdomains.add(sub)
        except:
            pass
        return subdomains

    def _query_hackertarget(self, domain: str) -> Set[str]:
        """Query HackerTarget API"""
        subdomains = set()
        try:
            response = self.session.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}",
                timeout=15
            )
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if ',' in line:
                        sub = line.split(',')[0].strip().lower()
                        if sub.endswith(domain):
                            subdomains.add(sub)
        except:
            pass
        return subdomains

    def _query_alienvault(self, domain: str) -> Set[str]:
        """Query AlienVault OTX"""
        subdomains = set()
        try:
            response = self.session.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                timeout=15
            )
            if response.status_code == 200:
                for record in response.json().get('passive_dns', []):
                    hostname = record.get('hostname', '').strip().lower()
                    if hostname.endswith(domain):
                        subdomains.add(hostname)
        except:
            pass
        return subdomains

    def _query_urlscan(self, domain: str) -> Set[str]:
        """Query URLScan.io"""
        subdomains = set()
        try:
            response = self.session.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}",
                timeout=15
            )
            if response.status_code == 200:
                for result in response.json().get('results', []):
                    url = result.get('page', {}).get('domain', '').strip().lower()
                    if url.endswith(domain):
                        subdomains.add(url)
        except:
            pass
        return subdomains

    def _query_rapiddns(self, domain: str) -> Set[str]:
        """Query RapidDNS"""
        subdomains = set()
        try:
            response = self.session.get(
                f"https://rapiddns.io/subdomain/{domain}?full=1",
                timeout=15
            )
            if response.status_code == 200:
                pattern = r'<td>([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')</td>'
                for match in re.findall(pattern, response.text, re.IGNORECASE):
                    subdomains.add(match.lower())
        except:
            pass
        return subdomains

    def _query_certspotter(self, domain: str) -> Set[str]:
        """Query CertSpotter"""
        subdomains = set()
        try:
            response = self.session.get(
                f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
                timeout=15
            )
            if response.status_code == 200:
                for cert in response.json():
                    for name in cert.get('dns_names', []):
                        name = name.strip().lower()
                        if name.startswith('*.'):
                            name = name[2:]
                        if name.endswith(domain):
                            subdomains.add(name)
        except:
            pass
        return subdomains

    def _query_threatcrowd(self, domain: str) -> Set[str]:
        """Query ThreatCrowd"""
        subdomains = set()
        try:
            response = self.session.get(
                f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
                timeout=15
            )
            if response.status_code == 200:
                for sub in response.json().get('subdomains', []) or []:
                    sub = sub.strip().lower()
                    if sub.endswith(domain):
                        subdomains.add(sub)
        except:
            pass
        return subdomains

    def _query_bufferover(self, domain: str) -> Set[str]:
        """Query BufferOver.run"""
        subdomains = set()
        try:
            response = self.session.get(
                f"https://dns.bufferover.run/dns?q=.{domain}",
                timeout=15
            )
            if response.status_code == 200:
                data = response.json()
                for record in (data.get('FDNS_A', []) or []) + (data.get('RDNS', []) or []):
                    if ',' in str(record):
                        sub = record.split(',')[-1].strip().lower()
                        if sub.endswith(domain):
                            subdomains.add(sub)
        except:
            pass
        return subdomains

    # ======================== PHASE 2: DNS RESOLUTION ========================

    def phase2_dns_resolution(self, subdomains: Set[str], result: WizReconResult) -> Set[str]:
        """
        Phase 2: DNS Resolution

        Filter non-resolving domains using puredns.
        Typically converts ~1600 passive subdomains to ~1200 active ones.
        """
        print(f"\n{'='*60}")
        print(f"  PHASE 2: DNS RESOLUTION")
        print(f"  Input: {len(subdomains)} subdomains")
        print(f"{'='*60}")

        if not subdomains:
            result.phases_completed.append("dns_resolution")
            return set()

        # Use puredns for filtering
        print(f"\n  Resolving {len(subdomains)} subdomains...")
        dns_result = self.puredns.resolve(list(subdomains))

        if dns_result.success:
            resolved = set(dns_result.output)
            print(f"  Resolved: {len(resolved)} subdomains ({len(resolved)*100//len(subdomains)}%)")

            if not dns_result.tool_available:
                print("  (Using Python fallback - puredns not installed)")
        else:
            # Fallback to basic resolution
            print("  puredns failed, using basic resolution...")
            resolved = self._basic_resolve(subdomains)

        # Wildcard detection
        wildcard = self._detect_wildcard(list(subdomains)[0].split('.')[-2] + '.' + list(subdomains)[0].split('.')[-1] if subdomains else "")
        if wildcard:
            print(f"\n  [!] WILDCARD DNS DETECTED - filtering required")
            result.wildcard_detected = True
            # Filter obvious wildcard responses
            resolved = self._filter_wildcards(resolved)

        result.resolved_subdomains = len(resolved)
        result.phases_completed.append("dns_resolution")

        print(f"\n  [PHASE 2 COMPLETE] Resolved: {len(resolved)} subdomains")
        return resolved

    def _basic_resolve(self, subdomains: Set[str]) -> Set[str]:
        """Basic DNS resolution fallback"""
        resolved = set()

        def check(sub):
            try:
                socket.gethostbyname(sub)
                return sub
            except:
                return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check, s): s for s in subdomains}
            for future in as_completed(futures):
                if future.result():
                    resolved.add(future.result())

        return resolved

    def _detect_wildcard(self, domain: str) -> bool:
        """Detect wildcard DNS"""
        if not domain:
            return False
        random_sub = f"randomnonexistent12345.{domain}"
        try:
            socket.gethostbyname(random_sub)
            return True
        except:
            return False

    def _filter_wildcards(self, subdomains: Set[str]) -> Set[str]:
        """Filter obvious wildcard responses (basic implementation)"""
        # In production, would compare response content/IP patterns
        return subdomains

    # ======================== PHASE 3: ACTIVE DISCOVERY ========================

    def phase3_active_discovery(self, domain: str, known_subdomains: Set[str],
                                 result: WizReconResult) -> Set[str]:
        """
        Phase 3: Active DNS Discovery

        1. DNS Bruteforcing with wordlist
        2. DNS Permutation with alterx
        """
        print(f"\n{'='*60}")
        print(f"  PHASE 3: ACTIVE DNS DISCOVERY")
        print(f"  Mode: {self.thoroughness}")
        print(f"{'='*60}")

        new_subdomains = set()

        # 3a. DNS Bruteforce
        print(f"\n  [3a] DNS Bruteforce ({len(self.wordlist)} words)...")

        bf_result = self.puredns.bruteforce(domain, self._create_temp_wordlist())
        if bf_result.success:
            bf_found = set(bf_result.output) - known_subdomains
            new_subdomains.update(bf_found)
            result.bruteforce_found = len(bf_found)
            print(f"    Found: {len(bf_found)} new subdomains")
        else:
            # Fallback to basic bruteforce
            print("    puredns not available, using basic bruteforce...")
            bf_found = self._basic_bruteforce(domain, self.wordlist, known_subdomains)
            new_subdomains.update(bf_found)
            result.bruteforce_found = len(bf_found)
            print(f"    Found: {len(bf_found)} new subdomains")

        # 3b. DNS Permutation with alterx
        print(f"\n  [3b] DNS Permutation (alterx)...")

        # Only permute a subset for efficiency
        to_permute = list(known_subdomains | new_subdomains)[:100]

        perm_result = self.alterx.generate(to_permute, limit=5000)
        if perm_result.output:
            # Resolve permutations
            print(f"    Generated {len(perm_result.output)} permutations, resolving...")
            resolved_perms = self.puredns.resolve(perm_result.output)

            if resolved_perms.success:
                perm_found = set(resolved_perms.output) - known_subdomains - new_subdomains
                new_subdomains.update(perm_found)
                result.permutation_found = len(perm_found)
                print(f"    Found: {len(perm_found)} new subdomains from permutation")
            else:
                # Basic resolve fallback
                perm_found = self._basic_resolve(set(perm_result.output)) - known_subdomains - new_subdomains
                new_subdomains.update(perm_found)
                result.permutation_found = len(perm_found)
                print(f"    Found: {len(perm_found)} new subdomains from permutation")

        result.phases_completed.append("active_discovery")

        print(f"\n  [PHASE 3 COMPLETE] New subdomains: {len(new_subdomains)}")
        return new_subdomains

    def _create_temp_wordlist(self) -> str:
        """Create temporary wordlist file"""
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(self.wordlist))
            return f.name

    def _basic_bruteforce(self, domain: str, wordlist: List[str],
                          known: Set[str]) -> Set[str]:
        """Basic DNS bruteforce fallback"""
        found = set()

        def check(word):
            sub = f"{word}.{domain}"
            try:
                socket.gethostbyname(sub)
                return sub
            except:
                return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check, w): w for w in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result and result not in known:
                    found.add(result)

        return found

    # ======================== PHASE 4: ROOT DOMAIN DISCOVERY ========================

    def phase4_root_discovery(self, domain: str, result: WizReconResult) -> List[RootDomainInfo]:
        """
        Phase 4: Root Domain Discovery

        Discover additional root domains through:
        - Reverse WHOIS
        - Crunchbase acquisitions
        - GitHub mining
        """
        root_domains = self.root_discovery.discover_root_domains(domain)
        result.root_domains = root_domains
        result.phases_completed.append("root_discovery")
        return root_domains

    # ======================== PHASE 5: PUBLIC EXPOSURE PROBING ========================

    def phase5_exposure_probing(self, subdomains: Set[str], result: WizReconResult):
        """
        Phase 5: Public Exposure Probing

        1. HTTP probing with httpx (status, title, tech, IP, CNAME)
        2. Port scanning for non-HTTP services
        """
        print(f"\n{'='*60}")
        print(f"  PHASE 5: PUBLIC EXPOSURE PROBING")
        print(f"  Targets: {len(subdomains)} subdomains")
        print(f"{'='*60}")

        if not subdomains:
            result.phases_completed.append("exposure_probing")
            return

        # 5a. HTTP Probing
        print(f"\n  [5a] HTTP Probing with httpx...")

        tool_result, httpx_results = self.httpx.probe(list(subdomains))

        live_count = 0
        for hr in httpx_results:
            subdomain = urlparse(hr.url).netloc
            if subdomain not in result.all_subdomains:
                result.all_subdomains[subdomain] = SubdomainData(subdomain=subdomain)

            sd = result.all_subdomains[subdomain]
            sd.is_alive = True
            sd.status_code = hr.status_code
            sd.title = hr.title
            sd.ip_address = hr.ip
            sd.cname = hr.cname
            sd.technologies = hr.technologies
            sd.server = hr.server
            sd.content_length = hr.content_length
            sd.redirect_url = hr.redirect_url
            live_count += 1

        print(f"    Live HTTP services: {live_count}")

        # Interesting status codes (Wiz methodology)
        status_breakdown = {}
        for hr in httpx_results:
            code = hr.status_code
            status_breakdown[code] = status_breakdown.get(code, 0) + 1

        print(f"\n    Status Code Breakdown:")
        for code, count in sorted(status_breakdown.items()):
            action = {
                200: "Test immediately",
                301: "Follow redirect",
                302: "Follow redirect",
                403: "Probe alternate paths (/admin, /api)",
                404: "Fuzz additional routes",
                500: "Investigate further",
            }.get(code, "Review")
            print(f"      {code}: {count} - {action}")

        # 5b. Port Scanning
        print(f"\n  [5b] Port Scanning (non-HTTP services)...")

        # Only scan live hosts
        live_hosts = [s for s, d in result.all_subdomains.items() if d.is_alive]
        non_http_services = 0

        # Scan common non-HTTP ports
        non_http_ports = [21, 22, 23, 25, 53, 110, 143, 445, 993, 995,
                         3306, 3389, 5432, 5900, 6379, 9200, 27017]

        for host in live_hosts[:20]:  # Limit for speed
            open_ports = self.nmap.scan_ports(host, non_http_ports, service_detection=False)
            if open_ports:
                result.all_subdomains[host].open_ports = {
                    p: info["service"] for p, info in open_ports.items()
                }
                non_http_services += len(open_ports)
                print(f"    {host}: {list(open_ports.keys())}")

        # Update result
        result.live_assets = live_count
        result.http_services = live_count
        result.non_http_services = non_http_services
        result.phases_completed.append("exposure_probing")

        print(f"\n  [PHASE 5 COMPLETE] Live: {live_count}, Non-HTTP services: {non_http_services}")

    # ======================== SCOPE VALIDATION ========================

    def validate_scope(self, result: WizReconResult):
        """Validate all subdomains against program scope"""
        if not self.scope_validator:
            return

        print(f"\n  Validating against {self.program} scope...")

        for subdomain, data in result.all_subdomains.items():
            is_valid, reason = self.scope_validator.is_in_scope(subdomain)
            data.in_scope = is_valid
            data.scope_reason = reason
            if is_valid:
                result.in_scope_count += 1
            else:
                result.out_of_scope_count += 1

        print(f"  In-scope: {result.in_scope_count}")
        print(f"  Out-of-scope: {result.out_of_scope_count}")

    # ======================== MAIN SCAN ========================

    def scan(self, domain: str, skip_phases: List[str] = None) -> WizReconResult:
        """
        Run complete Wiz 5-phase reconnaissance

        Args:
            domain: Target domain
            skip_phases: List of phases to skip (e.g., ["root_discovery"])

        Returns:
            WizReconResult with all findings
        """
        skip_phases = skip_phases or []
        start_time = time.time()

        self.print_banner()

        # Print configuration
        print(f"\n{'='*60}")
        print(f"  CONFIGURATION")
        print(f"{'='*60}")
        print(f"  Target:        {domain}")
        print(f"  Program:       {self.program or 'Generic'}")
        print(f"  Thoroughness:  {self.thoroughness}")
        print(f"  Wordlist:      {len(self.wordlist)} entries")
        if self.config:
            print(f"  Rate Limit:    {self.rate_limit} req/sec")
            print(f"  User-Agent:    {self.config.user_agent[:50]}...")

        # Check tools
        ToolChecker.print_status()

        # Initialize result
        result = WizReconResult(
            target_domain=domain,
            program=self.program,
            scan_start=datetime.utcnow().isoformat()
        )

        # Phase 1: Passive Discovery
        if "passive" not in skip_phases:
            passive_subs = self.phase1_passive_discovery(domain, result)
        else:
            passive_subs = set()
            print("\n  [SKIPPED] Phase 1: Passive Discovery")

        # Phase 2: DNS Resolution
        if "resolution" not in skip_phases:
            resolved_subs = self.phase2_dns_resolution(passive_subs, result)
        else:
            resolved_subs = passive_subs
            print("\n  [SKIPPED] Phase 2: DNS Resolution")

        # Initialize subdomain data
        for sub in resolved_subs:
            result.all_subdomains[sub] = SubdomainData(subdomain=sub, source="passive")

        # Phase 3: Active Discovery
        if "active" not in skip_phases:
            new_subs = self.phase3_active_discovery(domain, resolved_subs, result)
            for sub in new_subs:
                source = "bruteforce" if sub not in resolved_subs else "permutation"
                result.all_subdomains[sub] = SubdomainData(subdomain=sub, source=source)
            resolved_subs.update(new_subs)
        else:
            print("\n  [SKIPPED] Phase 3: Active Discovery")

        # Phase 4: Root Domain Discovery
        if "root" not in skip_phases:
            self.phase4_root_discovery(domain, result)
        else:
            print("\n  [SKIPPED] Phase 4: Root Domain Discovery")

        # Phase 5: Exposure Probing
        if "probing" not in skip_phases:
            self.phase5_exposure_probing(resolved_subs, result)
        else:
            print("\n  [SKIPPED] Phase 5: Exposure Probing")

        # Scope Validation
        self.validate_scope(result)

        # Finalize
        result.scan_end = datetime.utcnow().isoformat()
        result.duration_seconds = time.time() - start_time

        # Print summary
        self._print_summary(result)

        return result

    def _print_summary(self, result: WizReconResult):
        """Print scan summary"""
        print(f"\n{'='*60}")
        print(f"  WIZ RECON COMPLETE - SUMMARY")
        print(f"{'='*60}")
        print(f"  Target:              {result.target_domain}")
        print(f"  Duration:            {result.duration_seconds:.1f} seconds")
        print(f"  Phases Completed:    {', '.join(result.phases_completed)}")
        print(f"\n  SUBDOMAIN COUNTS:")
        print(f"    Passive Found:     {result.passive_subdomains}")
        print(f"    After Resolution:  {result.resolved_subdomains}")
        print(f"    Bruteforce Found:  {result.bruteforce_found}")
        print(f"    Permutation Found: {result.permutation_found}")
        print(f"    Total Unique:      {len(result.all_subdomains)}")
        print(f"\n  EXPOSURE:")
        print(f"    Live Assets:       {result.live_assets}")
        print(f"    HTTP Services:     {result.http_services}")
        print(f"    Non-HTTP Services: {result.non_http_services}")
        if self.program:
            print(f"\n  SCOPE:")
            print(f"    In-Scope:          {result.in_scope_count}")
            print(f"    Out-of-Scope:      {result.out_of_scope_count}")
        print(f"{'='*60}\n")


def save_results(result: WizReconResult, output_dir: Path):
    """Save results to files"""
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_safe = result.target_domain.replace('.', '_')

    # JSON output
    json_file = output_dir / f"wiz_recon_{target_safe}_{timestamp}.json"
    with open(json_file, 'w') as f:
        data = {
            "target": result.target_domain,
            "program": result.program,
            "scan_start": result.scan_start,
            "scan_end": result.scan_end,
            "duration_seconds": result.duration_seconds,
            "summary": {
                "passive_subdomains": result.passive_subdomains,
                "resolved_subdomains": result.resolved_subdomains,
                "bruteforce_found": result.bruteforce_found,
                "permutation_found": result.permutation_found,
                "live_assets": result.live_assets,
                "in_scope": result.in_scope_count,
                "out_of_scope": result.out_of_scope_count,
            },
            "passive_sources": result.passive_sources_used,
            "wildcard_detected": result.wildcard_detected,
            "phases_completed": result.phases_completed,
            "subdomains": {
                sub: asdict(data) for sub, data in result.all_subdomains.items()
            },
            "root_domains": [asdict(rd) for rd in result.root_domains],
            "errors": result.errors,
        }
        json.dump(data, f, indent=2, default=str)
    print(f"[+] JSON saved: {json_file}")

    # Subdomains list (simple text)
    subs_file = output_dir / f"subdomains_{target_safe}_{timestamp}.txt"
    with open(subs_file, 'w') as f:
        for sub in sorted(result.all_subdomains.keys()):
            f.write(f"{sub}\n")
    print(f"[+] Subdomains list: {subs_file}")

    # Live targets (for further testing)
    live_file = output_dir / f"live_{target_safe}_{timestamp}.txt"
    with open(live_file, 'w') as f:
        for sub, data in result.all_subdomains.items():
            if data.is_alive:
                f.write(f"{sub}\n")
    print(f"[+] Live targets: {live_file}")

    # In-scope targets
    if result.in_scope_count > 0:
        scope_file = output_dir / f"in_scope_{target_safe}_{timestamp}.txt"
        with open(scope_file, 'w') as f:
            for sub, data in result.all_subdomains.items():
                if data.in_scope and data.is_alive:
                    f.write(f"{sub}\n")
        print(f"[+] In-scope targets: {scope_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Wiz Bug Bounty Reconnaissance Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick scan
  python wiz_recon.py example.com --quick

  # Standard scan with Amazon VRP settings
  python wiz_recon.py amazon.com -p amazon -u myh1user

  # Thorough scan with output
  python wiz_recon.py example.com --very-thorough -o ./results

  # Skip specific phases
  python wiz_recon.py example.com --skip-root --skip-ports

Reference: https://www.wiz.io/bug-bounty-masterclass/reconnaissance/overview
        """
    )

    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("-p", "--program", choices=["amazon", "shopify"],
                        help="Bug bounty program for scope validation")
    parser.add_argument("-u", "--username", default="yourh1username",
                        help="HackerOne username")
    parser.add_argument("-o", "--output", help="Output directory")

    # Thoroughness
    thoroughness = parser.add_mutually_exclusive_group()
    thoroughness.add_argument("--quick", action="store_true",
                              help="Quick scan (small wordlist)")
    thoroughness.add_argument("--very-thorough", action="store_true",
                              help="Very thorough scan (large wordlist)")

    # Skip phases
    parser.add_argument("--skip-passive", action="store_true",
                        help="Skip passive discovery")
    parser.add_argument("--skip-active", action="store_true",
                        help="Skip active discovery (bruteforce/permutation)")
    parser.add_argument("--skip-root", action="store_true",
                        help="Skip root domain discovery")
    parser.add_argument("--skip-ports", action="store_true",
                        help="Skip port scanning")

    args = parser.parse_args()

    # Determine thoroughness
    if args.quick:
        thoroughness = "quick"
    elif args.very_thorough:
        thoroughness = "thorough"
    else:
        thoroughness = "medium"

    # Build skip list
    skip_phases = []
    if args.skip_passive:
        skip_phases.append("passive")
    if args.skip_active:
        skip_phases.append("active")
    if args.skip_root:
        skip_phases.append("root")
    if args.skip_ports:
        skip_phases.append("probing")

    # Run scanner
    scanner = WizReconScanner(
        program=args.program,
        username=args.username,
        thoroughness=thoroughness
    )

    result = scanner.scan(args.domain, skip_phases=skip_phases)

    # Save results
    if args.output:
        save_results(result, Path(args.output))
    else:
        save_results(result, Path(f"./wiz_recon_{args.domain.replace('.', '_')}"))


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings('ignore')
    main()
