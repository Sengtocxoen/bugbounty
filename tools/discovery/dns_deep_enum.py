#!/usr/bin/env python3
"""
Deep DNS Enumeration Module
============================
Comprehensive subdomain discovery combining every technique from reconftw + reNgine.

Phases:
  1. Passive enumeration (subfinder, amass, assetfinder, crt.sh, CT logs)
  2. Active DNS brute force (puredns, massdns)
  3. Permutation / mutation (gotator, ripgen)
  4. DNS resolution (dnsx - A, AAAA, CNAME, MX, NS, TXT, NOERROR)
  5. Web scraping for subdomains (katana, gospider, hakrawler)
  6. Certificate transparency (tlsx)
  7. Analytics relationship discovery
  8. Recursive enumeration
  9. Subdomain takeover detection
  10. DNS zone transfer testing
  11. Reverse IP / CIDR discovery
"""

import subprocess
import shutil
import json
import re
import tempfile
import socket
from pathlib import Path
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

try:
    import requests
except ImportError:
    requests = None


@dataclass
class SubdomainEntry:
    """A discovered subdomain with metadata."""
    subdomain: str
    source: str
    ip: Optional[str] = None
    cname: Optional[str] = None
    cdn: Optional[str] = None
    is_alive: bool = False
    http_status: Optional[int] = None
    title: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    takeover_vulnerable: bool = False
    takeover_service: Optional[str] = None


@dataclass
class DNSDeepResult:
    """Complete DNS enumeration result."""
    target: str
    subdomains: Dict[str, SubdomainEntry] = field(default_factory=dict)
    zone_transfer_vulnerable: bool = False
    zone_transfer_data: List[str] = field(default_factory=list)
    analytics_related: List[str] = field(default_factory=list)
    reverse_ip_domains: List[str] = field(default_factory=list)
    asn_info: Dict = field(default_factory=dict)
    total_unique: int = 0

    def get_alive_subdomains(self) -> List[str]:
        return [s for s, e in self.subdomains.items() if e.is_alive]

    def get_takeover_candidates(self) -> List[str]:
        return [s for s, e in self.subdomains.items() if e.takeover_vulnerable]

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "total_unique": len(self.subdomains),
            "total_alive": len(self.get_alive_subdomains()),
            "takeover_candidates": self.get_takeover_candidates(),
            "zone_transfer_vulnerable": self.zone_transfer_vulnerable,
            "analytics_related": self.analytics_related,
            "reverse_ip_domains": self.reverse_ip_domains,
            "asn_info": self.asn_info,
            "subdomains": {
                k: {
                    "ip": v.ip, "cname": v.cname, "cdn": v.cdn,
                    "alive": v.is_alive, "status": v.http_status,
                    "title": v.title, "source": v.source,
                    "technologies": v.technologies,
                    "takeover": v.takeover_vulnerable,
                }
                for k, v in self.subdomains.items()
            }
        }


def _available(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: List[str], timeout: int = None) -> Optional[str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else r.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _lines(output: Optional[str]) -> List[str]:
    if not output:
        return []
    return [l.strip() for l in output.splitlines() if l.strip()]


class DNSDeepEnumerator:
    """Deep DNS enumeration engine."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.sub_cfg = self.config.get("subdomains", {})
        self.wordlists = self.config.get("wordlists", {})
        self.tool_paths = self.config.get("tool_paths", {})

    def _tool(self, name: str) -> str:
        return self.tool_paths.get(name, name)

    def run(self, target: str, output_dir: Path = None) -> DNSDeepResult:
        """Run all DNS enumeration phases."""
        result = DNSDeepResult(target=target)
        print(f"\n[DNS] Deep DNS enumeration for {target}")

        # Phase 1: Passive
        if self.sub_cfg.get("passive", {}).get("enabled", True):
            print("  [*] Phase 1: Passive subdomain enumeration...")
            self._passive_enum(target, result)
            print(f"      Found: {len(result.subdomains)} subdomains")

        # Phase 2: Certificate Transparency
        if self.sub_cfg.get("certificates", {}).get("enabled", True):
            print("  [*] Phase 2: Certificate transparency...")
            self._cert_transparency(target, result)
            print(f"      Total: {len(result.subdomains)} subdomains")

        # Phase 3: Brute force
        if self.sub_cfg.get("bruteforce", {}).get("enabled", True):
            print("  [*] Phase 3: DNS brute force...")
            self._bruteforce(target, result)
            print(f"      Total: {len(result.subdomains)} subdomains")

        # Phase 4: Permutations
        if self.sub_cfg.get("permutations", {}).get("enabled", True):
            print("  [*] Phase 4: Subdomain permutations...")
            self._permutations(target, result)
            print(f"      Total: {len(result.subdomains)} subdomains")

        # Phase 5: Web scraping
        if self.sub_cfg.get("scraping", {}).get("enabled", True):
            print("  [*] Phase 5: Web scraping for subdomains...")
            self._web_scraping(target, result)
            print(f"      Total: {len(result.subdomains)} subdomains")

        # Phase 6: Analytics relationships
        if self.sub_cfg.get("analytics", {}).get("enabled", True):
            print("  [*] Phase 6: Analytics relationships...")
            self._analytics(target, result)

        # Phase 7: DNS resolution
        if self.sub_cfg.get("resolution", {}).get("enabled", True):
            print("  [*] Phase 7: DNS resolution...")
            self._resolve_all(target, result)

        # Phase 8: Recursive enumeration
        if self.sub_cfg.get("recursive", {}).get("enabled", True):
            print("  [*] Phase 8: Recursive enumeration...")
            self._recursive_enum(target, result)
            print(f"      Total: {len(result.subdomains)} subdomains")

        # Phase 9: Zone transfer
        if self.sub_cfg.get("zone_transfer", {}).get("enabled", True):
            print("  [*] Phase 9: Zone transfer testing...")
            self._zone_transfer(target, result)

        # Phase 10: Subdomain takeover
        if self.sub_cfg.get("takeover", {}).get("enabled", True):
            print("  [*] Phase 10: Subdomain takeover detection...")
            self._takeover_detection(target, result)

        # Phase 11: Reverse IP
        if self.sub_cfg.get("reverse_ip", {}).get("enabled", True):
            print("  [*] Phase 11: Reverse IP / CIDR discovery...")
            self._reverse_ip(target, result)

        result.total_unique = len(result.subdomains)

        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            # Save full results
            with open(output_dir / f"dns_{target.replace('.', '_')}.json", "w") as f:
                json.dump(result.to_dict(), f, indent=2)
            # Save subdomain list
            with open(output_dir / f"subdomains_{target.replace('.', '_')}.txt", "w") as f:
                for sub in sorted(result.subdomains.keys()):
                    f.write(f"{sub}\n")
            # Save alive subdomains
            alive = result.get_alive_subdomains()
            with open(output_dir / f"alive_{target.replace('.', '_')}.txt", "w") as f:
                for sub in sorted(alive):
                    f.write(f"{sub}\n")

        print(f"[DNS] Complete: {len(result.subdomains)} unique, "
              f"{len(result.get_alive_subdomains())} alive, "
              f"{len(result.get_takeover_candidates())} takeover candidates")
        return result

    def _add_sub(self, result: DNSDeepResult, subdomain: str, source: str):
        """Add a subdomain to results if valid."""
        subdomain = subdomain.strip().lower().rstrip(".")
        if not subdomain or not subdomain.endswith(result.target):
            return
        if subdomain not in result.subdomains:
            result.subdomains[subdomain] = SubdomainEntry(
                subdomain=subdomain, source=source
            )

    # -------------------------------------------------------------------------
    # Passive Enumeration
    # -------------------------------------------------------------------------
    def _passive_enum(self, target: str, result: DNSDeepResult):
        passive_cfg = self.sub_cfg.get("passive", {})

        tools_to_run = []

        if passive_cfg.get("subfinder", True) and _available("subfinder"):
            tools_to_run.append(("subfinder", [
                self._tool("subfinder"), "-d", target, "-all", "-silent"
            ]))

        if passive_cfg.get("amass", True) and _available("amass"):
            tools_to_run.append(("amass", [
                self._tool("amass"), "enum", "-passive", "-d", target
            ]))

        if passive_cfg.get("assetfinder", True) and _available("assetfinder"):
            tools_to_run.append(("assetfinder", [
                self._tool("assetfinder"), "--subs-only", target
            ]))

        if passive_cfg.get("github_subdomains", True) and _available("github-subdomains"):
            gh_token = self.config.get("api_keys", {}).get("github_token")
            if gh_token:
                tools_to_run.append(("github-subdomains", [
                    "github-subdomains", "-d", target, "-t", gh_token
                ]))

        # Run all passive tools in parallel
        with ThreadPoolExecutor(max_workers=len(tools_to_run) or 1) as pool:
            futures = {}
            for name, cmd in tools_to_run:
                futures[pool.submit(_run, cmd, 300)] = name

            for future in as_completed(futures):
                name = futures[future]
                try:
                    output = future.result()
                    for line in _lines(output):
                        # Clean output
                        sub = line.strip()
                        if " " in sub:
                            sub = sub.split()[-1]
                        self._add_sub(result, sub, name)
                except Exception:
                    pass

    # -------------------------------------------------------------------------
    # Certificate Transparency
    # -------------------------------------------------------------------------
    def _cert_transparency(self, target: str, result: DNSDeepResult):
        cert_cfg = self.sub_cfg.get("certificates", {})

        # crt.sh query
        if cert_cfg.get("ct_logs", True) and requests:
            try:
                resp = requests.get(
                    f"https://crt.sh/?q=%.{target}&output=json",
                    timeout=30
                )
                if resp.status_code == 200:
                    certs = resp.json()
                    for cert in certs:
                        name = cert.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lstrip("*.")
                            self._add_sub(result, sub, "crt.sh")
            except Exception:
                pass

        # tlsx for TLS certificate inspection
        if cert_cfg.get("tlsx", True) and _available("tlsx"):
            # Write current subdomains to file
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tmp:
                for sub in list(result.subdomains.keys())[:500]:
                    tmp.write(f"{sub}\n")
                tmp_path = tmp.name

            output = _run([
                self._tool("tlsx"), "-l", tmp_path,
                "-san", "-cn", "-silent", "-resp-only"
            ], timeout=300)
            for line in _lines(output):
                self._add_sub(result, line, "tlsx")

    # -------------------------------------------------------------------------
    # DNS Brute Force
    # -------------------------------------------------------------------------
    def _bruteforce(self, target: str, result: DNSDeepResult):
        bf_cfg = self.sub_cfg.get("bruteforce", {})
        tool = bf_cfg.get("tool", "puredns")

        wordlist = bf_cfg.get("wordlist",
                              "/opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt")
        if bf_cfg.get("use_deep_wordlist", True):
            deep_wl = bf_cfg.get("deep_wordlist",
                                 "/opt/wordlists/best-dns-wordlist.txt")
            if Path(deep_wl).exists():
                wordlist = deep_wl

        resolvers = self.wordlists.get("resolvers", "/opt/wordlists/resolvers.txt")

        if tool == "puredns" and _available("puredns"):
            cmd = [
                self._tool("puredns"), "bruteforce", wordlist, target,
                "--resolvers", resolvers, "-q"
            ]
            output = _run(cmd, timeout=1800)
            for line in _lines(output):
                self._add_sub(result, line, "puredns_bf")

        elif _available("massdns"):
            # Generate candidates
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tmp:
                if Path(wordlist).exists():
                    with open(wordlist) as wl:
                        for word in wl:
                            word = word.strip()
                            if word:
                                tmp.write(f"{word}.{target}\n")
                tmp_path = tmp.name

            output = _run([
                "massdns", "-r", resolvers, "-t", "A",
                "-o", "S", tmp_path
            ], timeout=1800)
            for line in _lines(output):
                parts = line.split()
                if parts:
                    sub = parts[0].rstrip(".")
                    self._add_sub(result, sub, "massdns_bf")

    # -------------------------------------------------------------------------
    # Permutations
    # -------------------------------------------------------------------------
    def _permutations(self, target: str, result: DNSDeepResult):
        perm_cfg = self.sub_cfg.get("permutations", {})

        # Write current subdomains to file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as tmp:
            for sub in list(result.subdomains.keys()):
                tmp.write(f"{sub}\n")
            tmp_path = tmp.name

        permuted = set()

        # gotator
        if perm_cfg.get("gotator", True) and _available("gotator"):
            output = _run([
                self._tool("gotator"), "-sub", tmp_path,
                "-perm", str(perm_cfg.get("max_permutations", 10000)),
                "-depth", "1", "-numbers", "3", "-mindup", "-adv",
            ], timeout=600)
            for line in _lines(output):
                permuted.add(line.strip())

        # Resolve permutations with puredns
        if permuted and _available("puredns"):
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tmp2:
                for p in permuted:
                    tmp2.write(f"{p}\n")
                perm_path = tmp2.name

            resolvers = self.wordlists.get("resolvers", "/opt/wordlists/resolvers.txt")
            output = _run([
                self._tool("puredns"), "resolve", perm_path,
                "--resolvers", resolvers, "-q"
            ], timeout=900)
            for line in _lines(output):
                self._add_sub(result, line, "permutation")
        else:
            # Add unresolved permutations
            for p in list(permuted)[:5000]:
                self._add_sub(result, p, "permutation_unresolved")

    # -------------------------------------------------------------------------
    # Web Scraping
    # -------------------------------------------------------------------------
    def _web_scraping(self, target: str, result: DNSDeepResult):
        scrape_cfg = self.sub_cfg.get("scraping", {})

        # katana
        if scrape_cfg.get("katana", True) and _available("katana"):
            output = _run([
                self._tool("katana"), "-u", f"https://{target}",
                "-d", "3", "-silent", "-jc", "-kf", "all",
            ], timeout=300)
            if output:
                for line in _lines(output):
                    # Extract subdomains from URLs
                    subs = re.findall(
                        r'(?:https?://)?([a-zA-Z0-9._-]+\.' + re.escape(target) + r')',
                        line
                    )
                    for sub in subs:
                        self._add_sub(result, sub, "katana")

        # gospider
        if scrape_cfg.get("gospider", True) and _available("gospider"):
            output = _run([
                self._tool("gospider"), "-s", f"https://{target}",
                "-d", "3", "-c", "10", "--subs",
            ], timeout=300)
            if output:
                for line in _lines(output):
                    subs = re.findall(
                        r'(?:https?://)?([a-zA-Z0-9._-]+\.' + re.escape(target) + r')',
                        line
                    )
                    for sub in subs:
                        self._add_sub(result, sub, "gospider")

    # -------------------------------------------------------------------------
    # Analytics Relationships
    # -------------------------------------------------------------------------
    def _analytics(self, target: str, result: DNSDeepResult):
        """Find related domains via shared analytics/tracking IDs."""
        if not requests:
            return

        # Check for builtwith data (passive)
        try:
            resp = requests.get(
                f"https://api.builtwith.com/free1/api.json?KEY=free&LOOKUP={target}",
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                # Extract analytics IDs
                for group in data.get("groups", []):
                    for cat in group.get("categories", []):
                        for live in cat.get("live", []):
                            if "analytics" in cat.get("name", "").lower():
                                result.analytics_related.append(live.get("Domain", ""))
        except Exception:
            pass

        # AnalyticsRelationships tool (if available as a Go binary)
        # This is a passive technique

    # -------------------------------------------------------------------------
    # DNS Resolution
    # -------------------------------------------------------------------------
    def _resolve_all(self, target: str, result: DNSDeepResult):
        """Resolve all discovered subdomains with dnsx."""
        if not _available("dnsx"):
            return

        # Write subdomains to file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as tmp:
            for sub in result.subdomains:
                tmp.write(f"{sub}\n")
            tmp_path = tmp.name

        # Resolve with full record types
        output = _run([
            self._tool("dnsx"), "-l", tmp_path,
            "-a", "-cname", "-resp", "-silent", "-json",
        ], timeout=600)

        for line in _lines(output):
            try:
                data = json.loads(line)
                host = data.get("host", "").strip()
                if host in result.subdomains:
                    entry = result.subdomains[host]
                    if data.get("a"):
                        entry.ip = data["a"][0] if isinstance(data["a"], list) else data["a"]
                    if data.get("cname"):
                        entry.cname = data["cname"][0] if isinstance(data["cname"], list) else data["cname"]
                    entry.is_alive = True
            except json.JSONDecodeError:
                # Plain text output
                sub = line.split()[0] if line.split() else ""
                if sub in result.subdomains:
                    result.subdomains[sub].is_alive = True

        # NOERROR check
        res_cfg = self.sub_cfg.get("resolution", {})
        if res_cfg.get("check_noerror", True):
            output = _run([
                self._tool("dnsx"), "-l", tmp_path,
                "-rcode", "noerror,servfail", "-silent",
            ], timeout=300)
            for line in _lines(output):
                parts = line.split()
                if parts:
                    sub = parts[0]
                    self._add_sub(result, sub, "dnsx_noerror")

    # -------------------------------------------------------------------------
    # Recursive Enumeration
    # -------------------------------------------------------------------------
    def _recursive_enum(self, target: str, result: DNSDeepResult):
        """Recursively discover subdomains on found subdomains."""
        rec_cfg = self.sub_cfg.get("recursive", {})
        max_depth = rec_cfg.get("max_depth", 3)

        # Find unique subdomain patterns (e.g., if we found dev.api.target.com,
        # also try to enumerate api.target.com)
        current_subs = set(result.subdomains.keys())
        depth_targets = set()

        for sub in current_subs:
            parts = sub.replace(f".{target}", "").split(".")
            if len(parts) >= 2:
                # e.g., "dev.api" -> also enumerate "api.target.com"
                for i in range(1, min(len(parts), max_depth)):
                    parent = ".".join(parts[i:]) + f".{target}"
                    if parent != target and parent not in depth_targets:
                        depth_targets.add(parent)

        # Use dsieve to find interesting patterns
        if _available("dsieve") and current_subs:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tmp:
                for s in current_subs:
                    tmp.write(f"{s}\n")
                tmp_path = tmp.name

            output = _run([
                self._tool("dsieve"), "-if", tmp_path, "-f", "3"
            ], timeout=60)
            for line in _lines(output):
                depth_targets.add(line.strip())

        if not depth_targets:
            return

        # Run subfinder on discovered patterns
        if rec_cfg.get("recursive_passive", True) and _available("subfinder"):
            for dt in list(depth_targets)[:50]:
                output = _run([
                    self._tool("subfinder"), "-d", dt, "-silent"
                ], timeout=60)
                for line in _lines(output):
                    self._add_sub(result, line, "recursive_passive")

    # -------------------------------------------------------------------------
    # Zone Transfer
    # -------------------------------------------------------------------------
    def _zone_transfer(self, target: str, result: DNSDeepResult):
        """Test for DNS zone transfer (AXFR) misconfiguration."""
        # Get nameservers
        ns_output = _run(["dig", "+short", "NS", target], timeout=15)
        if not ns_output:
            return

        nameservers = [ns.strip().rstrip(".")
                       for ns in ns_output.splitlines() if ns.strip()]

        for ns in nameservers:
            output = _run(
                ["dig", "AXFR", target, f"@{ns}"], timeout=30
            )
            if output and "Transfer failed" not in output and "XFR size" in output:
                result.zone_transfer_vulnerable = True
                result.zone_transfer_data.append(output)

                # Extract subdomains from zone transfer
                for line in output.splitlines():
                    parts = line.split()
                    if parts and parts[0].endswith(f".{target}."):
                        sub = parts[0].rstrip(".")
                        self._add_sub(result, sub, "zone_transfer")

                result.findings = getattr(result, "findings", [])
                print(f"      [!] ZONE TRANSFER POSSIBLE on {ns}!")

    # -------------------------------------------------------------------------
    # Subdomain Takeover
    # -------------------------------------------------------------------------
    def _takeover_detection(self, target: str, result: DNSDeepResult):
        """Detect subdomain takeover vulnerabilities."""
        takeover_cfg = self.sub_cfg.get("takeover", {})

        # Write subdomains to file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as tmp:
            for sub in result.subdomains:
                tmp.write(f"{sub}\n")
            tmp_path = tmp.name

        # nuclei takeover templates
        if takeover_cfg.get("nuclei_takeover", True) and _available("nuclei"):
            output = _run([
                self._tool("nuclei"), "-l", tmp_path,
                "-t", "http/takeovers/",
                "-silent", "-nc",
            ], timeout=600)
            for line in _lines(output):
                # Parse nuclei output
                parts = line.split()
                if parts:
                    for part in parts:
                        if part.endswith(target) or target in part:
                            sub = re.sub(r'https?://', '', part).split('/')[0].split(':')[0]
                            if sub in result.subdomains:
                                result.subdomains[sub].takeover_vulnerable = True
                                result.subdomains[sub].takeover_service = line
                            break

        # dnstake
        if takeover_cfg.get("dnstake", True) and _available("dnstake"):
            output = _run([
                "dnstake", "-f", tmp_path, "-silent"
            ], timeout=300)
            for line in _lines(output):
                if "VULNERABLE" in line.upper():
                    # Extract subdomain
                    for sub in result.subdomains:
                        if sub in line:
                            result.subdomains[sub].takeover_vulnerable = True
                            break

        # subjack
        if takeover_cfg.get("subjack", True) and _available("subjack"):
            output = _run([
                "subjack", "-w", tmp_path, "-t", "50", "-ssl",
                "-a", "-o", "-"
            ], timeout=300)
            for line in _lines(output):
                if "VULNERABLE" in line.upper() or "[TAKEOVER]" in line.upper():
                    for sub in result.subdomains:
                        if sub in line:
                            result.subdomains[sub].takeover_vulnerable = True
                            break

    # -------------------------------------------------------------------------
    # Reverse IP / CIDR
    # -------------------------------------------------------------------------
    def _reverse_ip(self, target: str, result: DNSDeepResult):
        """Discover domains from reverse IP and CIDR ranges."""
        rev_cfg = self.sub_cfg.get("reverse_ip", {})

        # Collect unique IPs
        ips = set()
        for entry in result.subdomains.values():
            if entry.ip:
                ips.add(entry.ip)

        if not ips:
            return

        # hakip2host
        if rev_cfg.get("hakip2host", True) and _available("hakip2host"):
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tmp:
                for ip in ips:
                    tmp.write(f"{ip}\n")
                tmp_path = tmp.name

            output = _run([
                self._tool("hakip2host"), "-f", tmp_path
            ], timeout=300)
            for line in _lines(output):
                # hakip2host outputs "IP domain"
                parts = line.split()
                if len(parts) >= 2:
                    domain = parts[-1].strip()
                    if target in domain:
                        self._add_sub(result, domain, "reverse_ip")
                    else:
                        result.reverse_ip_domains.append(domain)

        # ASN lookup for CIDR discovery
        if rev_cfg.get("asn_lookup", True) and requests:
            # Get ASN for main domain IP
            try:
                main_ip = socket.gethostbyname(target)
                resp = requests.get(
                    f"https://api.hackertarget.com/aslookup/?q={main_ip}",
                    timeout=15
                )
                if resp.status_code == 200:
                    result.asn_info = {"ip": main_ip, "data": resp.text.strip()}
            except Exception:
                pass
