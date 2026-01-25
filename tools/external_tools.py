#!/usr/bin/env python3
"""
External Tool Wrappers for Bug Bounty Reconnaissance

Provides Python wrappers for popular external recon tools:
- subfinder: Passive subdomain discovery
- puredns: DNS resolution and filtering
- alterx: DNS permutation generation
- httpx: HTTP probing with metadata extraction
- nmap: Port scanning

Each wrapper handles:
- Tool availability detection
- Proper argument formatting
- Output parsing
- Error handling
- Fallback to Python implementations when tools unavailable
"""

import subprocess
import shutil
import json
import tempfile
import re
from pathlib import Path
from typing import List, Set, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket


@dataclass
class ToolResult:
    """Result from external tool execution"""
    success: bool
    output: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    raw_output: str = ""
    tool_available: bool = True


@dataclass
class HttpxResult:
    """Parsed result from httpx probe"""
    url: str
    status_code: Optional[int] = None
    title: Optional[str] = None
    ip: Optional[str] = None
    cname: Optional[str] = None
    content_length: Optional[int] = None
    technologies: List[str] = field(default_factory=list)
    server: Optional[str] = None
    redirect_url: Optional[str] = None
    response_time: Optional[float] = None
    tls_version: Optional[str] = None
    cdn: Optional[str] = None


class ToolChecker:
    """Check availability of external tools"""

    _cache: Dict[str, bool] = {}

    @classmethod
    def is_available(cls, tool_name: str) -> bool:
        """Check if a tool is available in PATH"""
        if tool_name not in cls._cache:
            cls._cache[tool_name] = shutil.which(tool_name) is not None
        return cls._cache[tool_name]

    @classmethod
    def get_available_tools(cls) -> Dict[str, bool]:
        """Get availability status of all recon tools"""
        tools = ["subfinder", "puredns", "alterx", "httpx", "nmap", "amass", "massdns"]
        return {tool: cls.is_available(tool) for tool in tools}

    @classmethod
    def print_status(cls):
        """Print tool availability status"""
        print("\n[*] External Tool Status:")
        print("-" * 40)
        for tool, available in cls.get_available_tools().items():
            status = "[INSTALLED]" if available else "[NOT FOUND]"
            print(f"  {tool:<15} {status}")
        print()


class SubfinderWrapper:
    """
    Wrapper for subfinder - passive subdomain enumeration tool

    Subfinder queries multiple passive sources:
    - Certificate Transparency logs
    - Search engines
    - DNS datasets
    - Security APIs

    Usage:
        wrapper = SubfinderWrapper()
        result = wrapper.run("example.com")
    """

    def __init__(self, timeout: int = 300):
        self.timeout = timeout
        self.available = ToolChecker.is_available("subfinder")

    def run(self, domain: str, sources: List[str] = None,
            verbose: bool = False, all_sources: bool = True) -> ToolResult:
        """
        Run subfinder on a domain

        Args:
            domain: Target domain
            sources: Specific sources to use (default: all)
            verbose: Enable verbose output
            all_sources: Use all available sources

        Returns:
            ToolResult with discovered subdomains
        """
        if not self.available:
            return ToolResult(
                success=False,
                tool_available=False,
                errors=["subfinder not installed. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"]
            )

        cmd = ["subfinder", "-d", domain, "-silent"]

        if all_sources:
            cmd.append("-all")

        if sources:
            cmd.extend(["-sources", ",".join(sources)])

        if verbose:
            cmd.remove("-silent")
            cmd.append("-v")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            subdomains = [
                line.strip().lower()
                for line in result.stdout.split('\n')
                if line.strip() and line.strip().endswith(domain)
            ]

            return ToolResult(
                success=result.returncode == 0,
                output=list(set(subdomains)),
                raw_output=result.stdout,
                errors=[result.stderr] if result.stderr else []
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                errors=[f"subfinder timed out after {self.timeout}s"]
            )
        except Exception as e:
            return ToolResult(
                success=False,
                errors=[str(e)]
            )


class PurednsWrapper:
    """
    Wrapper for puredns - fast DNS resolution and bruteforce tool

    Puredns features:
    - Mass DNS resolution
    - Wildcard detection
    - DNS bruteforcing with wordlists

    Usage:
        wrapper = PurednsWrapper()
        result = wrapper.resolve(subdomains)
        result = wrapper.bruteforce("example.com", wordlist_path)
    """

    def __init__(self, resolvers_file: str = None, timeout: int = 600):
        self.timeout = timeout
        self.available = ToolChecker.is_available("puredns")
        self.resolvers_file = resolvers_file

    def resolve(self, subdomains: List[str]) -> ToolResult:
        """
        Resolve a list of subdomains, filtering non-resolving ones

        Args:
            subdomains: List of subdomains to resolve

        Returns:
            ToolResult with resolving subdomains
        """
        if not self.available:
            # Fallback to Python DNS resolution
            return self._fallback_resolve(subdomains)

        # Write subdomains to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(subdomains))
            input_file = f.name

        try:
            cmd = ["puredns", "resolve", input_file, "--quiet"]

            if self.resolvers_file:
                cmd.extend(["-r", self.resolvers_file])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            resolved = [
                line.strip().lower()
                for line in result.stdout.split('\n')
                if line.strip()
            ]

            return ToolResult(
                success=result.returncode == 0,
                output=resolved,
                raw_output=result.stdout,
                errors=[result.stderr] if result.stderr else []
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                errors=[f"puredns timed out after {self.timeout}s"]
            )
        except Exception as e:
            return ToolResult(
                success=False,
                errors=[str(e)]
            )
        finally:
            Path(input_file).unlink(missing_ok=True)

    def bruteforce(self, domain: str, wordlist: str) -> ToolResult:
        """
        Bruteforce subdomains using wordlist

        Args:
            domain: Target domain
            wordlist: Path to wordlist file

        Returns:
            ToolResult with discovered subdomains
        """
        if not self.available:
            return ToolResult(
                success=False,
                tool_available=False,
                errors=["puredns not installed. Install: go install github.com/d3mondev/puredns/v2@latest"]
            )

        if not Path(wordlist).exists():
            return ToolResult(
                success=False,
                errors=[f"Wordlist not found: {wordlist}"]
            )

        cmd = ["puredns", "bruteforce", wordlist, domain, "--quiet"]

        if self.resolvers_file:
            cmd.extend(["-r", self.resolvers_file])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            subdomains = [
                line.strip().lower()
                for line in result.stdout.split('\n')
                if line.strip()
            ]

            return ToolResult(
                success=result.returncode == 0,
                output=subdomains,
                raw_output=result.stdout,
                errors=[result.stderr] if result.stderr else []
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                errors=[f"puredns bruteforce timed out after {self.timeout}s"]
            )
        except Exception as e:
            return ToolResult(
                success=False,
                errors=[str(e)]
            )

    def _fallback_resolve(self, subdomains: List[str]) -> ToolResult:
        """Fallback Python-based DNS resolution"""
        resolved = []

        def check_dns(subdomain: str) -> Optional[str]:
            try:
                socket.gethostbyname(subdomain)
                return subdomain
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_dns, sub): sub for sub in subdomains}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    resolved.append(result)

        return ToolResult(
            success=True,
            output=resolved,
            tool_available=False,
            errors=["Using Python fallback (puredns not available)"]
        )


class AlterxWrapper:
    """
    Wrapper for alterx - subdomain permutation generator

    Alterx generates intelligent variations of known subdomains:
    - Prefix/suffix additions
    - Number increments
    - Word replacements
    - Pattern-based mutations

    Usage:
        wrapper = AlterxWrapper()
        result = wrapper.generate(known_subdomains)
    """

    def __init__(self, timeout: int = 120):
        self.timeout = timeout
        self.available = ToolChecker.is_available("alterx")

    def generate(self, subdomains: List[str], patterns: List[str] = None,
                 enrich: bool = True, limit: int = 0) -> ToolResult:
        """
        Generate permutations of known subdomains

        Args:
            subdomains: Known subdomains to permute
            patterns: Custom patterns to use
            enrich: Enable enrichment mode
            limit: Limit number of results (0 = unlimited)

        Returns:
            ToolResult with permuted subdomains
        """
        if not self.available:
            # Fallback to Python-based permutation
            return self._fallback_permute(subdomains)

        # Write subdomains to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(subdomains))
            input_file = f.name

        try:
            cmd = ["alterx", "-l", input_file, "-silent"]

            if enrich:
                cmd.append("-enrich")

            if limit > 0:
                cmd.extend(["-limit", str(limit)])

            if patterns:
                for pattern in patterns:
                    cmd.extend(["-p", pattern])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            permutations = [
                line.strip().lower()
                for line in result.stdout.split('\n')
                if line.strip()
            ]

            return ToolResult(
                success=result.returncode == 0,
                output=list(set(permutations)),
                raw_output=result.stdout,
                errors=[result.stderr] if result.stderr else []
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                errors=[f"alterx timed out after {self.timeout}s"]
            )
        except Exception as e:
            return ToolResult(
                success=False,
                errors=[str(e)]
            )
        finally:
            Path(input_file).unlink(missing_ok=True)

    def _fallback_permute(self, subdomains: List[str]) -> ToolResult:
        """Fallback Python-based permutation generation"""
        permutations = set()

        # Common prefixes and suffixes for permutation
        prefixes = ["dev", "staging", "test", "api", "admin", "internal", "prod",
                    "stage", "uat", "qa", "beta", "alpha", "new", "old", "v2", "v3"]
        suffixes = ["dev", "staging", "test", "api", "admin", "internal", "prod",
                    "stage", "uat", "qa", "beta", "1", "2", "3", "01", "02"]

        for subdomain in subdomains:
            parts = subdomain.split('.')
            if len(parts) < 2:
                continue

            base = parts[0]
            rest = '.'.join(parts[1:])

            # Add prefixes
            for prefix in prefixes:
                permutations.add(f"{prefix}-{base}.{rest}")
                permutations.add(f"{prefix}.{base}.{rest}")

            # Add suffixes
            for suffix in suffixes:
                permutations.add(f"{base}-{suffix}.{rest}")
                permutations.add(f"{base}{suffix}.{rest}")

            # Number increments if base ends with number
            match = re.match(r'^(.+?)(\d+)$', base)
            if match:
                prefix, num = match.groups()
                for i in range(1, 6):
                    permutations.add(f"{prefix}{int(num) + i}.{rest}")
                    permutations.add(f"{prefix}{int(num) - i}.{rest}")

        return ToolResult(
            success=True,
            output=list(permutations),
            tool_available=False,
            errors=["Using Python fallback (alterx not available)"]
        )


class HttpxWrapper:
    """
    Wrapper for httpx - fast HTTP toolkit

    Httpx provides:
    - HTTP probing with various outputs
    - Title extraction
    - Status codes
    - Technology detection
    - IP/CNAME resolution
    - Response time measurement

    Usage:
        wrapper = HttpxWrapper()
        results = wrapper.probe(subdomains)
    """

    def __init__(self, timeout: int = 30, threads: int = 50, rate_limit: int = 150):
        self.timeout = timeout
        self.threads = threads
        self.rate_limit = rate_limit
        self.available = ToolChecker.is_available("httpx")

    def probe(self, targets: List[str], follow_redirects: bool = True,
              tech_detect: bool = True) -> Tuple[ToolResult, List[HttpxResult]]:
        """
        Probe targets for HTTP services

        Args:
            targets: List of domains/URLs to probe
            follow_redirects: Follow HTTP redirects
            tech_detect: Enable technology detection

        Returns:
            Tuple of (ToolResult, List[HttpxResult])
        """
        if not self.available:
            return self._fallback_probe(targets)

        # Write targets to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(targets))
            input_file = f.name

        try:
            cmd = [
                "httpx",
                "-l", input_file,
                "-silent",
                "-json",
                "-status-code",
                "-title",
                "-ip",
                "-cname",
                "-content-length",
                "-response-time",
                "-threads", str(self.threads),
                "-rate-limit", str(self.rate_limit),
                "-timeout", str(self.timeout),
            ]

            if follow_redirects:
                cmd.extend(["-follow-redirects", "-location"])

            if tech_detect:
                cmd.append("-tech-detect")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout * len(targets) // self.threads + 60
            )

            parsed_results = []
            alive_urls = []

            for line in result.stdout.split('\n'):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    httpx_result = HttpxResult(
                        url=data.get("url", ""),
                        status_code=data.get("status_code"),
                        title=data.get("title"),
                        ip=data.get("host") or data.get("a", [None])[0] if data.get("a") else None,
                        cname=data.get("cname", [None])[0] if data.get("cname") else None,
                        content_length=data.get("content_length"),
                        technologies=data.get("tech", []),
                        server=data.get("webserver"),
                        redirect_url=data.get("final_url") if data.get("final_url") != data.get("url") else None,
                        response_time=data.get("response_time"),
                        tls_version=data.get("tls", {}).get("version") if data.get("tls") else None,
                        cdn=data.get("cdn"),
                    )
                    parsed_results.append(httpx_result)
                    alive_urls.append(httpx_result.url)
                except json.JSONDecodeError:
                    continue

            return (
                ToolResult(
                    success=True,
                    output=alive_urls,
                    raw_output=result.stdout
                ),
                parsed_results
            )

        except subprocess.TimeoutExpired:
            return (
                ToolResult(success=False, errors=["httpx timed out"]),
                []
            )
        except Exception as e:
            return (
                ToolResult(success=False, errors=[str(e)]),
                []
            )
        finally:
            Path(input_file).unlink(missing_ok=True)

    def _fallback_probe(self, targets: List[str]) -> Tuple[ToolResult, List[HttpxResult]]:
        """Fallback Python-based HTTP probing"""
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        results = []
        alive_urls = []

        def probe_target(target: str) -> Optional[HttpxResult]:
            url = target if target.startswith('http') else f"https://{target}"
            try:
                response = session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False
                )

                # Extract title
                title = None
                title_match = re.search(r'<title[^>]*>([^<]+)</title>',
                                       response.text, re.IGNORECASE)
                if title_match:
                    title = title_match.group(1).strip()[:100]

                return HttpxResult(
                    url=url,
                    status_code=response.status_code,
                    title=title,
                    content_length=len(response.content),
                    server=response.headers.get('Server'),
                    redirect_url=response.url if response.url != url else None,
                )
            except:
                # Try HTTP if HTTPS failed
                if url.startswith('https://'):
                    try:
                        url = url.replace('https://', 'http://')
                        response = session.get(url, timeout=self.timeout, verify=False)
                        return HttpxResult(
                            url=url,
                            status_code=response.status_code,
                            content_length=len(response.content),
                        )
                    except:
                        pass
                return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(probe_target, t): t for t in targets}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    alive_urls.append(result.url)

        return (
            ToolResult(
                success=True,
                output=alive_urls,
                tool_available=False,
                errors=["Using Python fallback (httpx not available)"]
            ),
            results
        )


class NmapWrapper:
    """
    Wrapper for nmap - network scanner

    Usage:
        wrapper = NmapWrapper()
        result = wrapper.scan_ports(target, ports=[80, 443, 8080])
    """

    def __init__(self, timeout: int = 300):
        self.timeout = timeout
        self.available = ToolChecker.is_available("nmap")

    def scan_ports(self, target: str, ports: List[int] = None,
                   service_detection: bool = True) -> Dict[int, Dict[str, Any]]:
        """
        Scan ports on a target

        Args:
            target: Target IP or hostname
            ports: List of ports to scan (default: common ports)
            service_detection: Enable service/version detection

        Returns:
            Dict mapping port number to port info
        """
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                     3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]

        if not self.available:
            return self._fallback_scan(target, ports)

        port_str = ",".join(str(p) for p in ports)

        cmd = ["nmap", "-p", port_str, "--open", "-oG", "-", target]

        if service_detection:
            cmd.insert(1, "-sV")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            # Parse greppable output
            open_ports = {}
            for line in result.stdout.split('\n'):
                if 'Ports:' in line:
                    # Extract port info: 80/open/tcp//http//
                    port_matches = re.findall(
                        r'(\d+)/open/(\w+)//([^/]*)//',
                        line
                    )
                    for port, proto, service in port_matches:
                        open_ports[int(port)] = {
                            "protocol": proto,
                            "service": service or "unknown",
                            "state": "open"
                        }

            return open_ports

        except subprocess.TimeoutExpired:
            return {}
        except Exception:
            return self._fallback_scan(target, ports)

    def _fallback_scan(self, target: str, ports: List[int]) -> Dict[int, Dict[str, Any]]:
        """Fallback Python-based port scanning"""
        open_ports = {}

        # Common port-to-service mapping
        service_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
            993: "imaps", 995: "pop3s", 3306: "mysql", 3389: "rdp",
            5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
            8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb"
        }

        def check_port(port: int) -> Optional[Tuple[int, Dict]]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                sock.close()
                if result == 0:
                    return (port, {
                        "protocol": "tcp",
                        "service": service_map.get(port, "unknown"),
                        "state": "open"
                    })
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_port, p): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports[result[0]] = result[1]

        return open_ports


def install_instructions():
    """Print installation instructions for all tools"""
    print("""
External Tool Installation Instructions
=======================================

1. SUBFINDER (Passive subdomain discovery)
   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

2. PUREDNS (DNS resolution & bruteforce)
   go install github.com/d3mondev/puredns/v2@latest

   Also need massdns:
   git clone https://github.com/blechschmidt/massdns.git
   cd massdns && make && sudo make install

3. ALTERX (Subdomain permutation)
   go install github.com/projectdiscovery/alterx/cmd/alterx@latest

4. HTTPX (HTTP probing)
   go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

5. NMAP (Port scanning)
   sudo apt install nmap  # Debian/Ubuntu
   brew install nmap      # macOS

Make sure $GOPATH/bin is in your PATH:
   export PATH=$PATH:$(go env GOPATH)/bin
""")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--install":
        install_instructions()
    else:
        print("[*] External Tool Wrappers for Bug Bounty Reconnaissance")
        ToolChecker.print_status()
        print("\nRun with --install for installation instructions")
