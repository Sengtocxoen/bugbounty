#!/usr/bin/env python3
"""
Enhanced Subdomain Scanner
Multi-source subdomain discovery with comprehensive scanning capabilities.

Sources:
- Certificate Transparency (crt.sh)
- DNS Dumpster
- BufferOver.run
- HackerTarget
- AlienVault OTX
- RapidDNS
- URLScan.io
- ThreatCrowd
- DNS brute-force with extended wordlist

Features:
- Multiple passive recon sources
- Active DNS brute-forcing
- HTTP/HTTPS response checking
- Port scanning (common ports)
- Technology fingerprinting
- Recursive subdomain discovery
- Detailed scan reporting
"""

import json
import time
import socket
import ssl
import re
import threading
import hashlib
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Tuple, Any
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("ERROR: requests library required. Install with: pip install requests")
    exit(1)

from config import AmazonConfig, ShopifyConfig, get_amazon_config, get_shopify_config
from scope_validator import AmazonScopeValidator, ShopifyScopeValidator


# Extended subdomain wordlist for comprehensive brute-forcing
EXTENDED_WORDLIST = [
    # Common prefixes
    "www", "www1", "www2", "www3", "m", "mobile", "wap",
    # API endpoints
    "api", "api1", "api2", "api3", "api-v1", "api-v2", "api-v3", "apis",
    "rest", "restapi", "graphql", "gql", "ws", "websocket", "wss",
    # Applications
    "app", "app1", "app2", "apps", "application", "webapp", "web",
    "portal", "dashboard", "admin", "administrator", "panel", "console",
    "manage", "management", "manager", "cms", "backend", "backoffice",
    # Authentication
    "auth", "auth0", "login", "signin", "signup", "register", "sso",
    "oauth", "oauth2", "oidc", "saml", "cas", "accounts", "account",
    "identity", "id", "idp", "users", "user", "member", "members",
    # Development
    "dev", "devel", "develop", "development", "devops", "dev1", "dev2",
    "stage", "staging", "stg", "uat", "qa", "test", "testing", "sandbox",
    "demo", "preview", "beta", "alpha", "canary", "nightly", "rc",
    "int", "integration", "preprod", "pre-prod", "gamma",
    # Infrastructure
    "mail", "email", "smtp", "pop", "pop3", "imap", "mx", "mx1", "mx2",
    "webmail", "outlook", "exchange",
    "ftp", "sftp", "ftps", "files", "file", "upload", "uploads", "download",
    "vpn", "vpn1", "vpn2", "remote", "rdp", "ssh", "bastion", "jump",
    "dns", "dns1", "dns2", "ns", "ns1", "ns2", "ns3",
    # Content Delivery
    "cdn", "cdn1", "cdn2", "cdn3", "static", "assets", "asset",
    "img", "image", "images", "media", "video", "videos", "audio",
    "content", "storage", "store", "s3", "blob", "bucket",
    # Database
    "db", "db1", "db2", "database", "sql", "mysql", "postgres", "postgresql",
    "mongo", "mongodb", "redis", "cache", "memcache", "memcached",
    "elastic", "elasticsearch", "es", "kibana", "logstash",
    # Monitoring
    "monitor", "monitoring", "status", "health", "healthcheck",
    "metrics", "prometheus", "grafana", "datadog", "newrelic",
    "logs", "log", "logging", "syslog", "splunk", "elk",
    "trace", "tracing", "jaeger", "zipkin", "apm",
    # CI/CD
    "jenkins", "ci", "cd", "build", "builds", "deploy", "deployment",
    "git", "gitlab", "github", "bitbucket", "svn", "repo", "repos",
    "artifactory", "nexus", "docker", "registry", "container", "k8s",
    "kubernetes", "rancher", "openshift", "argo", "argocd",
    # Cloud
    "aws", "azure", "gcp", "cloud", "cloudfront", "edge",
    "lambda", "functions", "serverless", "faas",
    # Security
    "secure", "security", "sec", "ssl", "tls", "https",
    "firewall", "fw", "waf", "proxy", "reverse-proxy", "lb", "loadbalancer",
    "vault", "secrets", "cert", "certs", "certificates", "pki",
    # Business
    "shop", "store", "cart", "checkout", "pay", "payment", "payments",
    "billing", "invoice", "invoices", "order", "orders", "commerce",
    "crm", "erp", "sales", "marketing", "hr", "finance",
    "support", "help", "helpdesk", "ticket", "tickets", "service", "services",
    "docs", "documentation", "doc", "wiki", "kb", "knowledge",
    "blog", "news", "press", "community", "forum", "forums",
    "partner", "partners", "vendor", "vendors", "affiliate", "affiliates",
    # Internal
    "internal", "intranet", "corp", "corporate", "office", "hq",
    "private", "local", "localhost", "home", "lan",
    # Legacy/Backup
    "old", "new", "legacy", "archive", "backup", "bak", "bkp",
    "temp", "tmp", "test1", "test2", "dev-old",
    # Analytics
    "analytics", "tracking", "stats", "statistics", "report", "reports",
    "bi", "business-intelligence", "data", "bigdata", "warehouse",
    # Messaging
    "chat", "im", "message", "messaging", "slack", "teams", "zoom",
    "sms", "push", "notification", "notifications", "alert", "alerts",
    # Geographic
    "us", "eu", "asia", "apac", "emea", "us-east", "us-west", "eu-west",
    "east", "west", "north", "south", "global", "region", "regional",
    # Services
    "svc", "service", "microservice", "ms", "micro",
    "gateway", "gw", "router", "ingress", "egress",
    # Numbered variants
    "web1", "web2", "web3", "app1", "app2", "app3",
    "server", "server1", "server2", "srv", "srv1", "srv2",
    "node", "node1", "node2", "host", "host1", "host2",
    # Search
    "search", "solr", "lucene", "algolia", "typesense",
    # Queue/Workers
    "queue", "mq", "rabbitmq", "kafka", "celery", "worker", "workers",
    "job", "jobs", "scheduler", "cron", "task", "tasks",
    # Miscellaneous
    "origin", "primary", "secondary", "master", "slave", "replica",
    "prod", "production", "live", "release", "stable",
    "proxy1", "proxy2", "gateway1", "gateway2",
]

# Common ports to check
COMMON_PORTS = [
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (5900, "VNC"),
    (6379, "Redis"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
    (8888, "HTTP-Alt2"),
    (9200, "Elasticsearch"),
    (27017, "MongoDB"),
]


@dataclass
class SubdomainInfo:
    """Detailed information about a subdomain"""
    subdomain: str
    ip_addresses: List[str] = field(default_factory=list)
    is_alive: bool = False
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    open_ports: List[Tuple[int, str]] = field(default_factory=list)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    content_length: Optional[int] = None
    redirect_url: Optional[str] = None
    response_hash: Optional[str] = None
    source: str = "unknown"
    in_scope: bool = True
    scope_reason: str = ""
    scan_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class ScanResult:
    """Complete scan result"""
    target_domain: str
    scan_start: str
    scan_end: str = ""
    total_sources_checked: int = 0
    sources_successful: List[str] = field(default_factory=list)
    sources_failed: List[str] = field(default_factory=list)
    total_subdomains_found: int = 0
    unique_subdomains: int = 0
    live_subdomains: int = 0
    in_scope_count: int = 0
    out_of_scope_count: int = 0
    subdomains: Dict[str, SubdomainInfo] = field(default_factory=dict)
    scan_phases: List[Dict[str, Any]] = field(default_factory=list)


class EnhancedSubdomainScanner:
    """Enhanced subdomain discovery and scanning"""

    def __init__(self, rate_limit: float = 5.0, user_agent: str = "BugBountyResearcher",
                 timeout: int = 10, max_workers: int = 20):
        self.rate_limit = rate_limit
        self.min_interval = 1.0 / rate_limit
        self.last_request = 0.0
        self.lock = threading.Lock()
        self.user_agent = user_agent
        self.timeout = timeout
        self.max_workers = max_workers

        # Create session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({
            'User-Agent': user_agent,
            'Accept': 'text/html,application/json,*/*',
        })

    def _rate_limit_wait(self):
        """Wait to respect rate limit"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_request
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_request = time.time()

    def _safe_request(self, url: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
        """Make a safe HTTP request with rate limiting"""
        self._rate_limit_wait()
        try:
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('verify', False)
            if method.upper() == "GET":
                return self.session.get(url, **kwargs)
            elif method.upper() == "HEAD":
                return self.session.head(url, **kwargs)
        except Exception:
            pass
        return None

    # ==================== PASSIVE RECON SOURCES ====================

    def discover_crtsh(self, domain: str) -> Set[str]:
        """Certificate Transparency logs via crt.sh"""
        subdomains = set()
        print(f"    [crt.sh] Querying certificate transparency logs...")

        try:
            response = self._safe_request(f"https://crt.sh/?q=%.{domain}&output=json", timeout=30)
            if response and response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.startswith('*.'):
                            sub = sub[2:]
                        if sub.endswith(domain) and sub:
                            subdomains.add(sub)
                print(f"    [crt.sh] Found {len(subdomains)} entries")
        except Exception as e:
            print(f"    [crt.sh] Error: {str(e)[:50]}")

        return subdomains

    def discover_hackertarget(self, domain: str) -> Set[str]:
        """HackerTarget subdomain finder"""
        subdomains = set()
        print(f"    [HackerTarget] Querying API...")

        try:
            response = self._safe_request(f"https://api.hackertarget.com/hostsearch/?q={domain}")
            if response and response.status_code == 200:
                for line in response.text.split('\n'):
                    if ',' in line:
                        sub = line.split(',')[0].strip().lower()
                        if sub.endswith(domain):
                            subdomains.add(sub)
                print(f"    [HackerTarget] Found {len(subdomains)} entries")
        except Exception as e:
            print(f"    [HackerTarget] Error: {str(e)[:50]}")

        return subdomains

    def discover_bufferover(self, domain: str) -> Set[str]:
        """BufferOver.run DNS records"""
        subdomains = set()
        print(f"    [BufferOver] Querying DNS records...")

        try:
            response = self._safe_request(f"https://dns.bufferover.run/dns?q=.{domain}")
            if response and response.status_code == 200:
                data = response.json()
                for record in data.get('FDNS_A', []) or []:
                    if ',' in str(record):
                        sub = record.split(',')[-1].strip().lower()
                        if sub.endswith(domain):
                            subdomains.add(sub)
                for record in data.get('RDNS', []) or []:
                    if ',' in str(record):
                        sub = record.split(',')[-1].strip().lower()
                        if sub.endswith(domain):
                            subdomains.add(sub)
                print(f"    [BufferOver] Found {len(subdomains)} entries")
        except Exception as e:
            print(f"    [BufferOver] Error: {str(e)[:50]}")

        return subdomains

    def discover_alienvault(self, domain: str) -> Set[str]:
        """AlienVault OTX passive DNS"""
        subdomains = set()
        print(f"    [AlienVault] Querying OTX...")

        try:
            response = self._safe_request(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            )
            if response and response.status_code == 200:
                data = response.json()
                for record in data.get('passive_dns', []):
                    hostname = record.get('hostname', '').strip().lower()
                    if hostname.endswith(domain):
                        subdomains.add(hostname)
                print(f"    [AlienVault] Found {len(subdomains)} entries")
        except Exception as e:
            print(f"    [AlienVault] Error: {str(e)[:50]}")

        return subdomains

    def discover_rapiddns(self, domain: str) -> Set[str]:
        """RapidDNS subdomain search"""
        subdomains = set()
        print(f"    [RapidDNS] Querying...")

        try:
            response = self._safe_request(f"https://rapiddns.io/subdomain/{domain}?full=1")
            if response and response.status_code == 200:
                pattern = r'<td>([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')</td>'
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    subdomains.add(match.lower())
                print(f"    [RapidDNS] Found {len(subdomains)} entries")
        except Exception as e:
            print(f"    [RapidDNS] Error: {str(e)[:50]}")

        return subdomains

    def discover_threatcrowd(self, domain: str) -> Set[str]:
        """ThreatCrowd API"""
        subdomains = set()
        print(f"    [ThreatCrowd] Querying API...")

        try:
            response = self._safe_request(
                f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
            )
            if response and response.status_code == 200:
                data = response.json()
                for sub in data.get('subdomains', []) or []:
                    sub = sub.strip().lower()
                    if sub.endswith(domain):
                        subdomains.add(sub)
                print(f"    [ThreatCrowd] Found {len(subdomains)} entries")
        except Exception as e:
            print(f"    [ThreatCrowd] Error: {str(e)[:50]}")

        return subdomains

    def discover_urlscan(self, domain: str) -> Set[str]:
        """URLScan.io search"""
        subdomains = set()
        print(f"    [URLScan] Querying...")

        try:
            response = self._safe_request(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
            )
            if response and response.status_code == 200:
                data = response.json()
                for result in data.get('results', []):
                    page = result.get('page', {})
                    url = page.get('domain', '').strip().lower()
                    if url.endswith(domain):
                        subdomains.add(url)
                print(f"    [URLScan] Found {len(subdomains)} entries")
        except Exception as e:
            print(f"    [URLScan] Error: {str(e)[:50]}")

        return subdomains

    def discover_crtsh_org(self, domain: str) -> Set[str]:
        """Additional cert search via certspotter"""
        subdomains = set()
        print(f"    [CertSpotter] Querying...")

        try:
            response = self._safe_request(
                f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            )
            if response and response.status_code == 200:
                data = response.json()
                for cert in data:
                    for name in cert.get('dns_names', []):
                        name = name.strip().lower()
                        if name.startswith('*.'):
                            name = name[2:]
                        if name.endswith(domain):
                            subdomains.add(name)
                print(f"    [CertSpotter] Found {len(subdomains)} entries")
        except Exception as e:
            print(f"    [CertSpotter] Error: {str(e)[:50]}")

        return subdomains

    # ==================== ACTIVE RECON ====================

    def discover_dns_bruteforce(self, domain: str, wordlist: List[str] = None,
                                 max_workers: int = None) -> Set[str]:
        """DNS brute-force with extended wordlist"""
        if wordlist is None:
            wordlist = EXTENDED_WORDLIST
        if max_workers is None:
            max_workers = self.max_workers

        subdomains = set()
        print(f"    [DNS-BF] Brute-forcing {len(wordlist)} subdomain prefixes...")

        def check_subdomain(sub: str) -> Optional[str]:
            full_domain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                return full_domain
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomains.add(result)

        print(f"    [DNS-BF] Found {len(subdomains)} resolving subdomains")
        return subdomains

    def discover_recursive(self, domain: str, known_subdomains: Set[str],
                           depth: int = 1) -> Set[str]:
        """Recursive subdomain discovery - find subdomains of subdomains"""
        if depth <= 0:
            return set()

        new_subdomains = set()
        prefixes = ["www", "api", "app", "admin", "dev", "staging", "mail", "m"]

        print(f"    [RECURSIVE] Checking subdomains of {len(known_subdomains)} hosts...")

        for subdomain in known_subdomains:
            for prefix in prefixes:
                candidate = f"{prefix}.{subdomain}"
                try:
                    socket.gethostbyname(candidate)
                    if candidate not in known_subdomains:
                        new_subdomains.add(candidate)
                except socket.gaierror:
                    pass

        print(f"    [RECURSIVE] Found {len(new_subdomains)} additional subdomains")
        return new_subdomains

    # ==================== SCANNING ====================

    def get_ip_addresses(self, subdomain: str) -> List[str]:
        """Resolve all IP addresses for a subdomain"""
        ips = []
        try:
            results = socket.getaddrinfo(subdomain, None)
            for result in results:
                ip = result[4][0]
                if ip not in ips:
                    ips.append(ip)
        except socket.gaierror:
            pass
        return ips

    def check_http_response(self, subdomain: str) -> Dict[str, Any]:
        """Check HTTP/HTTPS response and extract information"""
        result = {
            'is_alive': False,
            'http_status': None,
            'https_status': None,
            'title': None,
            'server': None,
            'content_length': None,
            'redirect_url': None,
            'response_hash': None,
            'technologies': [],
        }

        for scheme in ['https', 'http']:
            try:
                url = f"{scheme}://{subdomain}"
                response = self._safe_request(url, allow_redirects=True)
                if response:
                    result['is_alive'] = True
                    if scheme == 'https':
                        result['https_status'] = response.status_code
                    else:
                        result['http_status'] = response.status_code

                    # Extract info from first successful response
                    if not result['title']:
                        # Extract title
                        title_match = re.search(r'<title[^>]*>([^<]+)</title>',
                                               response.text, re.IGNORECASE)
                        if title_match:
                            result['title'] = title_match.group(1).strip()[:100]

                        # Server header
                        result['server'] = response.headers.get('Server')
                        result['content_length'] = len(response.content)
                        result['response_hash'] = hashlib.md5(response.content).hexdigest()[:16]

                        # Check for redirect
                        if response.history:
                            result['redirect_url'] = response.url

                        # Technology detection
                        result['technologies'] = self._detect_technologies(response)

            except Exception:
                pass

        return result

    def _detect_technologies(self, response: requests.Response) -> List[str]:
        """Detect technologies from HTTP response"""
        techs = []
        headers = response.headers
        content = response.text.lower()

        # Server technologies
        server = headers.get('Server', '').lower()
        if 'nginx' in server:
            techs.append('nginx')
        if 'apache' in server:
            techs.append('Apache')
        if 'cloudflare' in server or 'cf-ray' in headers:
            techs.append('Cloudflare')
        if 'iis' in server:
            techs.append('IIS')

        # Powered-by header
        powered = headers.get('X-Powered-By', '').lower()
        if 'php' in powered:
            techs.append('PHP')
        if 'asp.net' in powered:
            techs.append('ASP.NET')
        if 'express' in powered:
            techs.append('Express.js')

        # Content detection
        if 'wp-content' in content or 'wordpress' in content:
            techs.append('WordPress')
        if 'drupal' in content:
            techs.append('Drupal')
        if 'joomla' in content:
            techs.append('Joomla')
        if 'shopify' in content:
            techs.append('Shopify')
        if 'react' in content or 'reactdom' in content:
            techs.append('React')
        if 'vue' in content or 'vuejs' in content:
            techs.append('Vue.js')
        if 'angular' in content:
            techs.append('Angular')
        if 'next' in content and 'data-n' in content:
            techs.append('Next.js')

        # AWS/Cloud indicators
        if 'x-amz' in str(headers).lower():
            techs.append('AWS')
        if 'x-azure' in str(headers).lower():
            techs.append('Azure')

        return list(set(techs))

    def check_ports(self, subdomain: str, ports: List[Tuple[int, str]] = None) -> List[Tuple[int, str]]:
        """Check for open ports"""
        if ports is None:
            ports = COMMON_PORTS

        open_ports = []
        ip = None

        try:
            ip = socket.gethostbyname(subdomain)
        except socket.gaierror:
            return open_ports

        def check_port(port_info: Tuple[int, str]) -> Optional[Tuple[int, str]]:
            port, service = port_info
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return (port, service)
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_port, p): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

        return sorted(open_ports, key=lambda x: x[0])

    def get_ssl_info(self, subdomain: str) -> Dict[str, Any]:
        """Get SSL certificate information"""
        ssl_info = {}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((subdomain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=subdomain) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                    ssl_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    ssl_info['expires'] = cert.get('notAfter')
                    ssl_info['san'] = cert.get('subjectAltName', [])
        except Exception:
            pass
        return ssl_info

    def scan_subdomain(self, subdomain: str, check_ports: bool = False) -> SubdomainInfo:
        """Perform detailed scan of a subdomain"""
        info = SubdomainInfo(subdomain=subdomain)

        # Get IP addresses
        info.ip_addresses = self.get_ip_addresses(subdomain)

        # Check HTTP response
        http_info = self.check_http_response(subdomain)
        info.is_alive = http_info['is_alive']
        info.http_status = http_info['http_status']
        info.https_status = http_info['https_status']
        info.title = http_info['title']
        info.server = http_info['server']
        info.technologies = http_info['technologies']
        info.content_length = http_info['content_length']
        info.redirect_url = http_info['redirect_url']
        info.response_hash = http_info['response_hash']

        # Get SSL info if alive
        if info.is_alive:
            info.ssl_info = self.get_ssl_info(subdomain)

        # Port scan if requested
        if check_ports and info.ip_addresses:
            info.open_ports = self.check_ports(subdomain)

        return info

    # ==================== MAIN DISCOVERY ====================

    def run_discovery(self, domain: str, dns_bruteforce: bool = True,
                      recursive: bool = True, check_ports: bool = False) -> ScanResult:
        """Run complete subdomain discovery"""
        result = ScanResult(
            target_domain=domain,
            scan_start=datetime.utcnow().isoformat()
        )

        print(f"\n{'='*60}")
        print(f"ENHANCED SUBDOMAIN SCANNER")
        print(f"Target: {domain}")
        print(f"{'='*60}")

        all_subdomains = set()
        sources = [
            ("crt.sh", self.discover_crtsh),
            ("HackerTarget", self.discover_hackertarget),
            ("BufferOver", self.discover_bufferover),
            ("AlienVault", self.discover_alienvault),
            ("RapidDNS", self.discover_rapiddns),
            ("ThreatCrowd", self.discover_threatcrowd),
            ("URLScan", self.discover_urlscan),
            ("CertSpotter", self.discover_crtsh_org),
        ]

        # Phase 1: Passive reconnaissance
        print(f"\n[PHASE 1] Passive Reconnaissance")
        print("-" * 40)
        result.total_sources_checked = len(sources)

        for source_name, source_func in sources:
            try:
                found = source_func(domain)
                if found:
                    all_subdomains.update(found)
                    result.sources_successful.append(source_name)
                else:
                    result.sources_failed.append(source_name)
            except Exception:
                result.sources_failed.append(source_name)

        result.scan_phases.append({
            "phase": "Passive Recon",
            "subdomains_found": len(all_subdomains),
            "sources_success": len(result.sources_successful),
            "sources_failed": len(result.sources_failed),
        })

        print(f"\n    [SUMMARY] Passive recon: {len(all_subdomains)} unique subdomains")

        # Phase 2: DNS brute-force
        if dns_bruteforce:
            print(f"\n[PHASE 2] Active DNS Brute-Force")
            print("-" * 40)
            bf_found = self.discover_dns_bruteforce(domain)
            new_from_bf = bf_found - all_subdomains
            all_subdomains.update(bf_found)
            result.scan_phases.append({
                "phase": "DNS Brute-Force",
                "new_subdomains": len(new_from_bf),
                "total_from_bf": len(bf_found),
            })
            print(f"    [SUMMARY] DNS brute-force: {len(new_from_bf)} new subdomains")

        # Phase 3: Recursive discovery
        if recursive:
            print(f"\n[PHASE 3] Recursive Subdomain Discovery")
            print("-" * 40)
            recursive_found = self.discover_recursive(domain, all_subdomains, depth=1)
            all_subdomains.update(recursive_found)
            result.scan_phases.append({
                "phase": "Recursive Discovery",
                "new_subdomains": len(recursive_found),
            })

        result.unique_subdomains = len(all_subdomains)

        # Phase 4: Detailed scanning
        print(f"\n[PHASE 4] Scanning {len(all_subdomains)} Subdomains")
        print("-" * 40)

        live_count = 0
        scanned = 0

        for subdomain in sorted(all_subdomains):
            scanned += 1
            if scanned % 10 == 0 or scanned == len(all_subdomains):
                print(f"    [SCAN] Progress: {scanned}/{len(all_subdomains)}", end='\r')

            info = self.scan_subdomain(subdomain, check_ports=check_ports)
            result.subdomains[subdomain] = info
            if info.is_alive:
                live_count += 1

        print(f"\n    [SCAN] Complete: {live_count} live subdomains")

        result.live_subdomains = live_count
        result.total_subdomains_found = len(all_subdomains)
        result.scan_end = datetime.utcnow().isoformat()

        result.scan_phases.append({
            "phase": "Detailed Scan",
            "scanned": len(all_subdomains),
            "alive": live_count,
        })

        return result


class AmazonEnhancedScanner(EnhancedSubdomainScanner):
    """Amazon VRP-compliant enhanced scanner"""

    def __init__(self, config: Optional[AmazonConfig] = None):
        self.config = config or get_amazon_config()
        super().__init__(
            rate_limit=self.config.rate_limit,
            user_agent=self.config.user_agent,
        )
        self.validator = AmazonScopeValidator(self.config)

    def run_discovery_with_scope(self, domain: str, **kwargs) -> ScanResult:
        """Run discovery with Amazon VRP scope validation"""
        result = self.run_discovery(domain, **kwargs)

        print(f"\n[PHASE 5] Validating Against Amazon VRP Scope")
        print("-" * 40)

        for subdomain, info in result.subdomains.items():
            is_valid, reason = self.validator.is_in_scope(subdomain)
            info.in_scope = is_valid
            info.scope_reason = reason
            if is_valid:
                result.in_scope_count += 1
            else:
                result.out_of_scope_count += 1

        print(f"    In-scope: {result.in_scope_count}")
        print(f"    Out-of-scope: {result.out_of_scope_count}")

        return result


class ShopifyEnhancedScanner(EnhancedSubdomainScanner):
    """Shopify-compliant enhanced scanner"""

    def __init__(self, config: Optional[ShopifyConfig] = None):
        self.config = config or get_shopify_config()
        super().__init__(
            rate_limit=self.config.rate_limit,
            user_agent=self.config.user_agent,
        )
        self.validator = ShopifyScopeValidator(self.config)

    def run_discovery_with_scope(self, domain: str, **kwargs) -> ScanResult:
        """Run discovery with Shopify scope validation"""
        result = self.run_discovery(domain, **kwargs)

        print(f"\n[PHASE 5] Validating Against Shopify Scope")
        print("-" * 40)

        for subdomain, info in result.subdomains.items():
            is_valid, reason = self.validator.is_in_scope(subdomain)
            info.in_scope = is_valid
            info.scope_reason = reason
            if is_valid:
                result.in_scope_count += 1
            else:
                result.out_of_scope_count += 1

        print(f"    In-scope: {result.in_scope_count}")
        print(f"    Out-of-scope: {result.out_of_scope_count}")

        return result


def generate_report(result: ScanResult, output_file: str = None) -> str:
    """Generate detailed scan report"""
    lines = []
    lines.append("=" * 70)
    lines.append("SUBDOMAIN SCAN REPORT")
    lines.append("=" * 70)
    lines.append(f"Target Domain: {result.target_domain}")
    lines.append(f"Scan Start: {result.scan_start}")
    lines.append(f"Scan End: {result.scan_end}")
    lines.append("")

    lines.append("SCAN SUMMARY")
    lines.append("-" * 40)
    lines.append(f"Total Sources Checked: {result.total_sources_checked}")
    lines.append(f"Sources Successful: {', '.join(result.sources_successful)}")
    lines.append(f"Sources Failed: {', '.join(result.sources_failed) or 'None'}")
    lines.append(f"Total Unique Subdomains: {result.unique_subdomains}")
    lines.append(f"Live Subdomains: {result.live_subdomains}")
    if result.in_scope_count > 0 or result.out_of_scope_count > 0:
        lines.append(f"In-Scope: {result.in_scope_count}")
        lines.append(f"Out-of-Scope: {result.out_of_scope_count}")
    lines.append("")

    lines.append("SCAN PHASES")
    lines.append("-" * 40)
    for phase in result.scan_phases:
        phase_name = phase.pop('phase', 'Unknown')
        details = ', '.join(f"{k}: {v}" for k, v in phase.items())
        lines.append(f"  {phase_name}: {details}")
    lines.append("")

    # Live subdomains table
    live_subs = [(s, i) for s, i in result.subdomains.items() if i.is_alive]
    if live_subs:
        lines.append("LIVE SUBDOMAINS")
        lines.append("-" * 40)
        lines.append(f"{'Subdomain':<45} {'Status':<10} {'Title':<30} {'Tech'}")
        lines.append("-" * 100)

        for subdomain, info in sorted(live_subs, key=lambda x: x[0]):
            status = info.https_status or info.http_status or "-"
            title = (info.title or "-")[:28]
            techs = ", ".join(info.technologies[:3]) if info.technologies else "-"
            scope_marker = "[IN]" if info.in_scope else "[OUT]"
            lines.append(f"{subdomain:<45} {status:<10} {title:<30} {techs}")
        lines.append("")

    # Port scan results
    ports_found = [(s, i) for s, i in result.subdomains.items() if i.open_ports]
    if ports_found:
        lines.append("OPEN PORTS")
        lines.append("-" * 40)
        for subdomain, info in sorted(ports_found, key=lambda x: x[0]):
            ports_str = ", ".join(f"{p}({s})" for p, s in info.open_ports)
            lines.append(f"  {subdomain}: {ports_str}")
        lines.append("")

    # Scope classification
    if result.in_scope_count > 0:
        lines.append("IN-SCOPE SUBDOMAINS")
        lines.append("-" * 40)
        in_scope = [s for s, i in result.subdomains.items() if i.in_scope and i.is_alive]
        for subdomain in sorted(in_scope):
            lines.append(f"  {subdomain}")
        lines.append("")

    report_text = "\n".join(lines)

    if output_file:
        with open(output_file, 'w') as f:
            f.write(report_text)
        print(f"\n[*] Report saved to: {output_file}")

    return report_text


def save_json_results(result: ScanResult, output_file: str):
    """Save detailed results as JSON"""
    data = {
        "target_domain": result.target_domain,
        "scan_start": result.scan_start,
        "scan_end": result.scan_end,
        "summary": {
            "total_sources": result.total_sources_checked,
            "sources_successful": result.sources_successful,
            "sources_failed": result.sources_failed,
            "unique_subdomains": result.unique_subdomains,
            "live_subdomains": result.live_subdomains,
            "in_scope": result.in_scope_count,
            "out_of_scope": result.out_of_scope_count,
        },
        "phases": result.scan_phases,
        "subdomains": {},
    }

    for subdomain, info in result.subdomains.items():
        data["subdomains"][subdomain] = {
            "ip_addresses": info.ip_addresses,
            "is_alive": info.is_alive,
            "http_status": info.http_status,
            "https_status": info.https_status,
            "title": info.title,
            "server": info.server,
            "technologies": info.technologies,
            "open_ports": info.open_ports,
            "ssl_info": info.ssl_info,
            "content_length": info.content_length,
            "redirect_url": info.redirect_url,
            "response_hash": info.response_hash,
            "in_scope": info.in_scope,
            "scope_reason": info.scope_reason,
        }

    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2, default=str)

    print(f"[*] JSON results saved to: {output_file}")


if __name__ == "__main__":
    import argparse
    import warnings
    warnings.filterwarnings('ignore')

    parser = argparse.ArgumentParser(
        description="Enhanced Subdomain Scanner - Multi-source discovery with detailed scanning"
    )
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--program", "-p", choices=["amazon", "shopify"],
                        help="Bug bounty program for scope validation")
    parser.add_argument("--username", "-u", default="yourh1username",
                        help="HackerOne username")
    parser.add_argument("--no-bruteforce", action="store_true",
                        help="Skip DNS brute-force (passive only)")
    parser.add_argument("--no-recursive", action="store_true",
                        help="Skip recursive subdomain discovery")
    parser.add_argument("--check-ports", action="store_true",
                        help="Perform port scanning on live hosts")
    parser.add_argument("--output", "-o", help="Output file prefix (creates .txt and .json)")
    parser.add_argument("--json-only", action="store_true",
                        help="Only save JSON output")
    parser.add_argument("--list-sources", action="store_true",
                        help="List available discovery sources")

    args = parser.parse_args()

    if args.list_sources:
        print("Available subdomain discovery sources:")
        print("  1. crt.sh (Certificate Transparency)")
        print("  2. HackerTarget API")
        print("  3. BufferOver.run DNS")
        print("  4. AlienVault OTX")
        print("  5. RapidDNS")
        print("  6. ThreatCrowd API")
        print("  7. URLScan.io")
        print("  8. CertSpotter")
        print("  9. DNS Brute-Force (extended wordlist)")
        print(" 10. Recursive Discovery")
        exit(0)

    # Run scan
    if args.program == "amazon":
        config = get_amazon_config(args.username)
        scanner = AmazonEnhancedScanner(config)
        result = scanner.run_discovery_with_scope(
            args.domain,
            dns_bruteforce=not args.no_bruteforce,
            recursive=not args.no_recursive,
            check_ports=args.check_ports,
        )
    elif args.program == "shopify":
        config = get_shopify_config(args.username)
        scanner = ShopifyEnhancedScanner(config)
        result = scanner.run_discovery_with_scope(
            args.domain,
            dns_bruteforce=not args.no_bruteforce,
            recursive=not args.no_recursive,
            check_ports=args.check_ports,
        )
    else:
        scanner = EnhancedSubdomainScanner()
        result = scanner.run_discovery(
            args.domain,
            dns_bruteforce=not args.no_bruteforce,
            recursive=not args.no_recursive,
            check_ports=args.check_ports,
        )

    # Generate output
    if args.output:
        if not args.json_only:
            generate_report(result, f"{args.output}.txt")
        save_json_results(result, f"{args.output}.json")
    else:
        # Print report to stdout
        print(generate_report(result))

    print("\n" + "=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
