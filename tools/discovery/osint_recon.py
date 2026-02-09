#!/usr/bin/env python3
"""
OSINT Reconnaissance Module
============================
Comprehensive open-source intelligence gathering inspired by reconftw + reNgine.

Phases:
  1. WHOIS lookup
  2. Email harvesting
  3. Google dorking
  4. GitHub/GitLab dorking (credential leaks)
  5. Repository scanning (trufflehog/gitleaks)
  6. Document metadata extraction
  7. API leak detection (Postman/Swagger)
  8. Email security (SPF/DMARC/DKIM)
  9. Cloud storage enumeration
  10. Third-party misconfiguration mapping
"""

import subprocess
import shutil
import json
import re
import tempfile
import socket
from pathlib import Path
from typing import List, Dict, Optional, Set, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

try:
    import requests
except ImportError:
    requests = None

try:
    import dns.resolver
except ImportError:
    dns = None


@dataclass
class OSINTFinding:
    """Single OSINT finding"""
    category: str        # whois, email, dork, leak, metadata, etc.
    source: str          # Tool or source that found it
    finding_type: str    # credential, url, email, document, etc.
    value: str           # The actual finding
    severity: str = "info"  # info, low, medium, high, critical
    details: Dict = field(default_factory=dict)
    verified: bool = False


@dataclass
class OSINTResult:
    """Complete OSINT result for a target"""
    target: str
    whois_data: Dict = field(default_factory=dict)
    emails: List[str] = field(default_factory=list)
    dork_results: List[Dict] = field(default_factory=list)
    leaked_credentials: List[Dict] = field(default_factory=list)
    repo_secrets: List[Dict] = field(default_factory=list)
    metadata: List[Dict] = field(default_factory=list)
    api_leaks: List[Dict] = field(default_factory=list)
    email_security: Dict = field(default_factory=dict)
    cloud_assets: List[Dict] = field(default_factory=list)
    misconfigs: List[Dict] = field(default_factory=list)
    findings: List[OSINTFinding] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "total_findings": self.total_findings,
            "whois": self.whois_data,
            "emails": self.emails,
            "dork_results": self.dork_results,
            "leaked_credentials": self.leaked_credentials,
            "repo_secrets": self.repo_secrets,
            "metadata": self.metadata,
            "api_leaks": self.api_leaks,
            "email_security": self.email_security,
            "cloud_assets": self.cloud_assets,
            "misconfigs": self.misconfigs,
            "findings": [
                {
                    "category": f.category,
                    "source": f.source,
                    "type": f.finding_type,
                    "value": f.value,
                    "severity": f.severity,
                    "details": f.details,
                    "verified": f.verified,
                }
                for f in self.findings
            ],
        }


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run_cmd(cmd: List[str], timeout: int = None) -> Optional[str]:
    """Run a command and return stdout, or None on failure. No timeout - runs until complete."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return None


class OSINTRecon:
    """Full OSINT reconnaissance engine."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.osint_cfg = self.config.get("osint", {})
        self.api_keys = self.config.get("api_keys", {})

    def run(self, target: str, output_dir: Path = None) -> OSINTResult:
        """Run all enabled OSINT modules against a target domain."""
        result = OSINTResult(target=target)
        print(f"\n[OSINT] Starting OSINT reconnaissance on {target}")

        phases = []
        if self.osint_cfg.get("whois", {}).get("enabled", True):
            phases.append(("WHOIS", self._whois))
        if self.osint_cfg.get("emails", {}).get("enabled", True):
            phases.append(("Email Harvesting", self._harvest_emails))
        if self.osint_cfg.get("google_dorks", {}).get("enabled", True):
            phases.append(("Google Dorking", self._google_dorks))
        if self.osint_cfg.get("github_dorking", {}).get("enabled", True):
            phases.append(("GitHub Dorking", self._github_dorking))
        if self.osint_cfg.get("repo_scanning", {}).get("enabled", True):
            phases.append(("Repository Scanning", self._repo_scanning))
        if self.osint_cfg.get("metadata", {}).get("enabled", True):
            phases.append(("Metadata Extraction", self._metadata_extraction))
        if self.osint_cfg.get("api_leaks", {}).get("enabled", True):
            phases.append(("API Leak Detection", self._api_leak_detection))
        if self.osint_cfg.get("email_security", {}).get("enabled", True):
            phases.append(("Email Security", self._email_security))
        if self.osint_cfg.get("cloud_enum", {}).get("enabled", True):
            phases.append(("Cloud Enumeration", self._cloud_enum))
        if self.osint_cfg.get("misconfig_mapper", {}).get("enabled", True):
            phases.append(("Misconfiguration Mapping", self._misconfig_mapping))

        for name, func in phases:
            print(f"  [*] {name}...")
            try:
                func(target, result)
                count = len(result.findings)
                print(f"      Total findings so far: {count}")
            except Exception as e:
                print(f"      [-] Error in {name}: {e}")

        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            out_file = output_dir / f"osint_{target.replace('.', '_')}.json"
            with open(out_file, "w") as f:
                json.dump(result.to_dict(), f, indent=2, default=str)
            print(f"  [+] OSINT results saved to {out_file}")

        print(f"[OSINT] Complete: {result.total_findings} findings for {target}")
        return result

    # -------------------------------------------------------------------------
    # WHOIS
    # -------------------------------------------------------------------------
    def _whois(self, target: str, result: OSINTResult):
        """WHOIS lookup for domain registration info."""
        output = _run_cmd(["whois", target], timeout=30)
        if not output:
            return

        whois_data = {}
        for line in output.splitlines():
            line = line.strip()
            if ":" in line and not line.startswith("%") and not line.startswith("#"):
                key, _, val = line.partition(":")
                key = key.strip().lower().replace(" ", "_")
                val = val.strip()
                if key and val:
                    whois_data[key] = val

        result.whois_data = whois_data

        # Extract interesting fields
        for key in ["registrant_email", "admin_email", "tech_email"]:
            if key in whois_data:
                email = whois_data[key]
                if "@" in email and email not in result.emails:
                    result.emails.append(email)
                    result.findings.append(OSINTFinding(
                        category="whois", source="whois",
                        finding_type="email", value=email,
                        details={"field": key}
                    ))

        # Check for registrar info
        registrar = whois_data.get("registrar", "")
        if registrar:
            result.findings.append(OSINTFinding(
                category="whois", source="whois",
                finding_type="registrar", value=registrar,
            ))

    # -------------------------------------------------------------------------
    # Email Harvesting
    # -------------------------------------------------------------------------
    def _harvest_emails(self, target: str, result: OSINTResult):
        """Harvest emails using multiple tools."""
        emails = set(result.emails)

        # theHarvester
        if _tool_available("theHarvester"):
            output = _run_cmd([
                "theHarvester", "-d", target, "-b", "all", "-l", "200"
            ], timeout=120)
            if output:
                for line in output.splitlines():
                    line = line.strip()
                    if "@" in line and target in line:
                        # Basic email regex
                        found = re.findall(
                            r'[\w.+-]+@[\w-]+\.[\w.-]+', line
                        )
                        emails.update(found)

        # emailfinder
        if _tool_available("emailfinder"):
            output = _run_cmd(["emailfinder", "-d", target], timeout=120)
            if output:
                found = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', output)
                emails.update(found)

        # DNS MX + TXT records for email info
        if dns:
            try:
                mx_records = dns.resolver.resolve(target, "MX")
                for mx in mx_records:
                    result.findings.append(OSINTFinding(
                        category="email", source="dns_mx",
                        finding_type="mx_record",
                        value=str(mx.exchange),
                        details={"priority": mx.preference}
                    ))
            except Exception:
                pass

        for email in emails:
            if email not in result.emails:
                result.emails.append(email)
                result.findings.append(OSINTFinding(
                    category="email", source="harvester",
                    finding_type="email", value=email
                ))

    # -------------------------------------------------------------------------
    # Google Dorking
    # -------------------------------------------------------------------------
    def _google_dorks(self, target: str, result: OSINTResult):
        """Generate and collect Google dork queries."""
        dork_cfg = self.osint_cfg.get("google_dorks", {})

        dork_categories = {}
        if dork_cfg.get("sensitive_files", True):
            dork_categories["sensitive_files"] = [
                f'site:{target} ext:sql',
                f'site:{target} ext:bak',
                f'site:{target} ext:log',
                f'site:{target} ext:env',
                f'site:{target} ext:cfg',
                f'site:{target} ext:conf',
                f'site:{target} ext:ini',
                f'site:{target} ext:yml',
                f'site:{target} ext:xml',
                f'site:{target} ext:json',
                f'site:{target} filetype:sql "password"',
                f'site:{target} filetype:log "error"',
                f'site:{target} ext:pem OR ext:key OR ext:p12',
            ]
        if dork_cfg.get("login_pages", True):
            dork_categories["login_pages"] = [
                f'site:{target} inurl:login',
                f'site:{target} inurl:admin',
                f'site:{target} inurl:dashboard',
                f'site:{target} inurl:signin',
                f'site:{target} inurl:register',
                f'site:{target} intitle:"admin panel"',
                f'site:{target} intitle:"login" inurl:admin',
            ]
        if dork_cfg.get("exposed_documents", True):
            dork_categories["exposed_documents"] = [
                f'site:{target} ext:pdf',
                f'site:{target} ext:doc OR ext:docx',
                f'site:{target} ext:xls OR ext:xlsx',
                f'site:{target} ext:csv',
                f'site:{target} ext:ppt OR ext:pptx',
            ]
        if dork_cfg.get("error_pages", True):
            dork_categories["error_pages"] = [
                f'site:{target} "error" "warning"',
                f'site:{target} "stack trace"',
                f'site:{target} "sql syntax"',
                f'site:{target} "fatal error"',
                f'site:{target} inurl:debug',
                f'site:{target} "index of /"',
                f'site:{target} intitle:"index of"',
            ]
        if dork_cfg.get("api_endpoints", True):
            dork_categories["api_endpoints"] = [
                f'site:{target} inurl:api',
                f'site:{target} inurl:graphql',
                f'site:{target} inurl:swagger',
                f'site:{target} inurl:openapi',
                f'site:{target} inurl:v1 OR inurl:v2 OR inurl:v3',
                f'site:{target} ext:wsdl',
                f'site:{target} inurl:rest',
            ]

        # Use dorks_hunter if available
        if _tool_available("dorks_hunter"):
            output = _run_cmd(
                ["dorks_hunter", "-d", target], timeout=120
            )
            if output:
                for line in output.splitlines():
                    line = line.strip()
                    if line:
                        result.dork_results.append({
                            "source": "dorks_hunter",
                            "dork": line
                        })

        # Store generated dorks as findings
        for category, dorks in dork_categories.items():
            for dork in dorks:
                result.dork_results.append({
                    "category": category,
                    "dork": dork,
                    "url": f"https://www.google.com/search?q={dork.replace(' ', '+')}"
                })
                result.findings.append(OSINTFinding(
                    category="dork", source="generated",
                    finding_type=category, value=dork
                ))

    # -------------------------------------------------------------------------
    # GitHub / GitLab Dorking
    # -------------------------------------------------------------------------
    def _github_dorking(self, target: str, result: OSINTResult):
        """Search GitHub for leaked credentials and sensitive data."""
        gh_cfg = self.osint_cfg.get("github_dorking", {})
        gh_token = gh_cfg.get("github_token") or self.api_keys.get("github_token")

        # GitHub dork queries
        github_dorks = []
        if gh_cfg.get("search_passwords", True):
            github_dorks.extend([
                f'"{target}" password',
                f'"{target}" secret',
                f'"{target}" passwd',
            ])
        if gh_cfg.get("search_api_keys", True):
            github_dorks.extend([
                f'"{target}" api_key',
                f'"{target}" apikey',
                f'"{target}" api_secret',
                f'"{target}" access_key',
            ])
        if gh_cfg.get("search_tokens", True):
            github_dorks.extend([
                f'"{target}" token',
                f'"{target}" bearer',
                f'"{target}" authorization',
                f'"{target}" jwt',
            ])
        if gh_cfg.get("search_internal_urls", True):
            github_dorks.extend([
                f'"{target}" internal',
                f'"{target}" staging',
                f'"{target}" dev.',
                f'"{target}" vpn',
            ])
        if gh_cfg.get("search_env_files", True):
            github_dorks.extend([
                f'"{target}" filename:.env',
                f'"{target}" filename:.npmrc',
                f'"{target}" filename:docker-compose',
                f'"{target}" filename:credentials',
                f'"{target}" filename:config.json',
            ])

        # Use github-subdomains tool if available
        if _tool_available("github-subdomains") and gh_token:
            output = _run_cmd([
                "github-subdomains", "-d", target, "-t", gh_token
            ], timeout=120)
            if output:
                for line in output.splitlines():
                    line = line.strip()
                    if line:
                        result.findings.append(OSINTFinding(
                            category="github", source="github-subdomains",
                            finding_type="subdomain", value=line
                        ))

        # API-based search if token available
        if gh_token and requests:
            headers = {
                "Authorization": f"token {gh_token}",
                "Accept": "application/vnd.github.v3+json",
            }
            max_results = gh_cfg.get("max_results", 100)

            for dork in github_dorks[:20]:  # Limit to avoid rate limits
                try:
                    resp = requests.get(
                        "https://api.github.com/search/code",
                        params={"q": dork, "per_page": min(max_results, 30)},
                        headers=headers,
                        timeout=15,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        for item in data.get("items", []):
                            leak = {
                                "dork": dork,
                                "repo": item.get("repository", {}).get("full_name", ""),
                                "file": item.get("path", ""),
                                "url": item.get("html_url", ""),
                            }
                            result.leaked_credentials.append(leak)
                            result.findings.append(OSINTFinding(
                                category="github", source="github_api",
                                finding_type="code_match", value=leak["url"],
                                severity="medium",
                                details=leak
                            ))
                    time.sleep(2)  # Rate limit respect
                except Exception:
                    continue
        else:
            # Just store the dork URLs for manual checking
            for dork in github_dorks:
                encoded = dork.replace('"', "%22").replace(" ", "+")
                result.findings.append(OSINTFinding(
                    category="github", source="generated",
                    finding_type="dork",
                    value=f"https://github.com/search?q={encoded}&type=code"
                ))

    # -------------------------------------------------------------------------
    # Repository Scanning
    # -------------------------------------------------------------------------
    def _repo_scanning(self, target: str, result: OSINTResult):
        """Scan repositories for secrets using trufflehog/gitleaks."""
        repo_cfg = self.osint_cfg.get("repo_scanning", {})

        # Trufflehog - scan GitHub org
        if repo_cfg.get("trufflehog", True) and _tool_available("trufflehog"):
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as tmp:
                tmp_path = tmp.name

            output = _run_cmd([
                "trufflehog", "github",
                "--org", target.split(".")[0],
                "--json", "--only-verified",
            ], timeout=600)

            if output:
                for line in output.splitlines():
                    try:
                        secret = json.loads(line)
                        result.repo_secrets.append(secret)
                        result.findings.append(OSINTFinding(
                            category="repo_secret", source="trufflehog",
                            finding_type=secret.get("DetectorName", "unknown"),
                            value=secret.get("Raw", ""),
                            severity="high",
                            verified=secret.get("Verified", False),
                            details={
                                "repo": secret.get("SourceMetadata", {}).get(
                                    "Data", {}
                                ).get("Github", {}).get("repository", ""),
                                "file": secret.get("SourceMetadata", {}).get(
                                    "Data", {}
                                ).get("Github", {}).get("file", ""),
                            }
                        ))
                    except json.JSONDecodeError:
                        continue

        # Gitleaks
        if repo_cfg.get("gitleaks", True) and _tool_available("gitleaks"):
            output = _run_cmd([
                "gitleaks", "detect", "--source", ".",
                "--report-format", "json", "--no-git",
            ], timeout=300)
            if output:
                try:
                    secrets = json.loads(output)
                    for secret in (secrets if isinstance(secrets, list) else []):
                        result.repo_secrets.append(secret)
                        result.findings.append(OSINTFinding(
                            category="repo_secret", source="gitleaks",
                            finding_type=secret.get("RuleID", "unknown"),
                            value=secret.get("Match", ""),
                            severity="high",
                            details={
                                "file": secret.get("File", ""),
                                "line": secret.get("StartLine", 0),
                            }
                        ))
                except json.JSONDecodeError:
                    pass

    # -------------------------------------------------------------------------
    # Document Metadata Extraction
    # -------------------------------------------------------------------------
    def _metadata_extraction(self, target: str, result: OSINTResult):
        """Extract metadata from publicly available documents."""
        meta_cfg = self.osint_cfg.get("metadata", {})

        if _tool_available("metagoofil"):
            file_types = ",".join(meta_cfg.get("file_types", ["pdf", "doc", "xls"]))
            max_files = str(meta_cfg.get("max_files", 100))

            with tempfile.TemporaryDirectory() as tmpdir:
                output = _run_cmd([
                    "metagoofil", "-d", target,
                    "-t", file_types,
                    "-l", max_files,
                    "-o", tmpdir,
                ], timeout=300)

                if output:
                    # Parse metagoofil output for usernames, emails, software
                    for line in output.splitlines():
                        if "User:" in line or "Author:" in line:
                            val = line.split(":", 1)[-1].strip()
                            if val:
                                result.metadata.append({"type": "user", "value": val})
                                result.findings.append(OSINTFinding(
                                    category="metadata", source="metagoofil",
                                    finding_type="username", value=val,
                                    severity="low"
                                ))
                        elif "Software:" in line or "Creator:" in line:
                            val = line.split(":", 1)[-1].strip()
                            if val:
                                result.metadata.append({"type": "software", "value": val})

    # -------------------------------------------------------------------------
    # API Leak Detection
    # -------------------------------------------------------------------------
    def _api_leak_detection(self, target: str, result: OSINTResult):
        """Search for exposed API documentation and Postman workspaces."""
        api_cfg = self.osint_cfg.get("api_leaks", {})

        # Search for Swagger/OpenAPI endpoints
        if api_cfg.get("search_swagger", True) and requests:
            swagger_paths = [
                "/swagger.json", "/swagger/v1/swagger.json",
                "/api-docs", "/api/swagger.json",
                "/openapi.json", "/openapi.yaml",
                "/v2/api-docs", "/v3/api-docs",
                "/swagger-ui.html", "/swagger-ui/",
                "/api/v1/swagger.json", "/api/v2/swagger.json",
                "/docs", "/redoc",
            ]
            for path in swagger_paths:
                for scheme in ["https", "http"]:
                    url = f"{scheme}://{target}{path}"
                    try:
                        resp = requests.get(url, timeout=10, verify=False,
                                            allow_redirects=True)
                        if resp.status_code == 200:
                            ct = resp.headers.get("content-type", "")
                            if "json" in ct or "yaml" in ct or "swagger" in resp.text[:500].lower():
                                result.api_leaks.append({
                                    "type": "swagger",
                                    "url": url,
                                    "status": resp.status_code,
                                })
                                result.findings.append(OSINTFinding(
                                    category="api_leak", source="swagger_scan",
                                    finding_type="api_documentation",
                                    value=url, severity="medium",
                                    details={"content_type": ct}
                                ))
                    except Exception:
                        continue

        # Porch-pirate (Postman workspace scanner)
        if api_cfg.get("search_postman", True) and _tool_available("porch-pirate"):
            output = _run_cmd(
                ["porch-pirate", "-s", target], timeout=120
            )
            if output:
                for line in output.splitlines():
                    line = line.strip()
                    if line and "http" in line:
                        result.api_leaks.append({
                            "type": "postman",
                            "value": line,
                        })
                        result.findings.append(OSINTFinding(
                            category="api_leak", source="porch-pirate",
                            finding_type="postman_workspace",
                            value=line, severity="medium"
                        ))

    # -------------------------------------------------------------------------
    # Email Security (SPF/DMARC/DKIM)
    # -------------------------------------------------------------------------
    def _email_security(self, target: str, result: OSINTResult):
        """Check email security configurations."""
        sec_cfg = self.osint_cfg.get("email_security", {})
        email_sec = {}

        if dns is None:
            # Fallback to dig
            if sec_cfg.get("check_spf", True):
                output = _run_cmd(["dig", "+short", "TXT", target], timeout=15)
                if output:
                    for line in output.splitlines():
                        if "v=spf1" in line:
                            email_sec["spf"] = line.strip('"')
                            break
            if sec_cfg.get("check_dmarc", True):
                output = _run_cmd(
                    ["dig", "+short", "TXT", f"_dmarc.{target}"], timeout=15
                )
                if output:
                    for line in output.splitlines():
                        if "v=DMARC1" in line:
                            email_sec["dmarc"] = line.strip('"')
                            break
        else:
            # SPF
            if sec_cfg.get("check_spf", True):
                try:
                    answers = dns.resolver.resolve(target, "TXT")
                    for rdata in answers:
                        txt = rdata.to_text().strip('"')
                        if "v=spf1" in txt:
                            email_sec["spf"] = txt
                            break
                except Exception:
                    email_sec["spf"] = "NOT FOUND"

            # DMARC
            if sec_cfg.get("check_dmarc", True):
                try:
                    answers = dns.resolver.resolve(f"_dmarc.{target}", "TXT")
                    for rdata in answers:
                        txt = rdata.to_text().strip('"')
                        if "v=DMARC1" in txt:
                            email_sec["dmarc"] = txt
                            break
                except Exception:
                    email_sec["dmarc"] = "NOT FOUND"

            # DKIM (common selectors)
            if sec_cfg.get("check_dkim", True):
                dkim_selectors = [
                    "default", "google", "selector1", "selector2",
                    "k1", "mail", "smtp", "dkim",
                ]
                for sel in dkim_selectors:
                    try:
                        answers = dns.resolver.resolve(
                            f"{sel}._domainkey.{target}", "TXT"
                        )
                        for rdata in answers:
                            txt = rdata.to_text().strip('"')
                            if "v=DKIM1" in txt or "p=" in txt:
                                email_sec[f"dkim_{sel}"] = txt
                                break
                    except Exception:
                        continue

        # Analyze security posture
        if email_sec.get("spf") == "NOT FOUND":
            result.findings.append(OSINTFinding(
                category="email_security", source="dns",
                finding_type="missing_spf",
                value=f"{target} has no SPF record",
                severity="medium"
            ))
        if email_sec.get("dmarc") == "NOT FOUND":
            result.findings.append(OSINTFinding(
                category="email_security", source="dns",
                finding_type="missing_dmarc",
                value=f"{target} has no DMARC record",
                severity="medium"
            ))
        elif email_sec.get("dmarc") and "p=none" in email_sec.get("dmarc", ""):
            result.findings.append(OSINTFinding(
                category="email_security", source="dns",
                finding_type="weak_dmarc",
                value=f"{target} DMARC policy is 'none' (not enforcing)",
                severity="low"
            ))

        # Spoofcheck
        if sec_cfg.get("check_spoofability", True) and _tool_available("spoofcheck"):
            output = _run_cmd(["spoofcheck", target], timeout=30)
            if output and "SPOOFABLE" in output.upper():
                result.findings.append(OSINTFinding(
                    category="email_security", source="spoofcheck",
                    finding_type="spoofable_domain",
                    value=f"{target} is potentially spoofable",
                    severity="medium",
                    details={"output": output}
                ))

        result.email_security = email_sec

    # -------------------------------------------------------------------------
    # Cloud Enumeration
    # -------------------------------------------------------------------------
    def _cloud_enum(self, target: str, result: OSINTResult):
        """Enumerate cloud storage and services."""
        cloud_cfg = self.osint_cfg.get("cloud_enum", {})
        base_name = target.split(".")[0]
        keywords = [base_name, target.replace(".", "-"), target.replace(".", "")]

        # cloud_enum tool
        if _tool_available("cloud_enum"):
            for keyword in keywords[:2]:
                output = _run_cmd([
                    "python3", shutil.which("cloud_enum") or "cloud_enum",
                    "-k", keyword,
                ], timeout=300)
                if output:
                    for line in output.splitlines():
                        line = line.strip()
                        if line and ("s3" in line.lower() or "blob" in line.lower()
                                     or "storage" in line.lower()):
                            result.cloud_assets.append({
                                "type": "cloud_storage",
                                "value": line
                            })
                            result.findings.append(OSINTFinding(
                                category="cloud", source="cloud_enum",
                                finding_type="cloud_storage",
                                value=line, severity="medium"
                            ))

        # S3Scanner
        if cloud_cfg.get("check_s3", True) and _tool_available("s3scanner"):
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tmp:
                for kw in keywords:
                    tmp.write(f"{kw}\n")
                    tmp.write(f"{kw}-dev\n")
                    tmp.write(f"{kw}-staging\n")
                    tmp.write(f"{kw}-backup\n")
                    tmp.write(f"{kw}-assets\n")
                    tmp.write(f"{kw}-uploads\n")
                    tmp.write(f"{kw}-data\n")
                    tmp.write(f"{kw}-logs\n")
                    tmp.write(f"{kw}-private\n")
                    tmp.write(f"{kw}-public\n")
                tmp_path = tmp.name

            output = _run_cmd(
                ["s3scanner", "--bucket-file", tmp_path], timeout=300
            )
            if output:
                for line in output.splitlines():
                    if "exists" in line.lower() or "open" in line.lower():
                        result.cloud_assets.append({
                            "type": "s3_bucket",
                            "value": line.strip()
                        })
                        severity = "high" if "open" in line.lower() else "medium"
                        result.findings.append(OSINTFinding(
                            category="cloud", source="s3scanner",
                            finding_type="s3_bucket",
                            value=line.strip(), severity=severity
                        ))

    # -------------------------------------------------------------------------
    # Third-party Misconfiguration Mapping
    # -------------------------------------------------------------------------
    def _misconfig_mapping(self, target: str, result: OSINTResult):
        """Check for third-party service misconfigurations."""
        if _tool_available("misconfig-mapper"):
            output = _run_cmd(
                ["misconfig-mapper", "-target", target], timeout=120
            )
            if output:
                for line in output.splitlines():
                    line = line.strip()
                    if line and "FOUND" in line.upper():
                        result.misconfigs.append({"value": line})
                        result.findings.append(OSINTFinding(
                            category="misconfig", source="misconfig-mapper",
                            finding_type="service_misconfig",
                            value=line, severity="medium"
                        ))

        # Manual checks for common misconfigs
        if requests:
            misconfig_checks = [
                (f"https://{target}/.well-known/security.txt", "security_txt"),
                (f"https://{target}/robots.txt", "robots_txt"),
                (f"https://{target}/sitemap.xml", "sitemap"),
                (f"https://{target}/crossdomain.xml", "crossdomain"),
                (f"https://{target}/clientaccesspolicy.xml", "clientaccess"),
                (f"https://{target}/.well-known/openid-configuration", "openid"),
                (f"https://{target}/.well-known/jwks.json", "jwks"),
            ]
            for url, check_type in misconfig_checks:
                try:
                    resp = requests.get(url, timeout=10, verify=False)
                    if resp.status_code == 200 and len(resp.text) > 10:
                        result.findings.append(OSINTFinding(
                            category="misconfig", source="http_check",
                            finding_type=check_type, value=url,
                            details={"status": resp.status_code,
                                     "length": len(resp.text)}
                        ))
                except Exception:
                    continue
