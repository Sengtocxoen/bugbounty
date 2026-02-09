#!/usr/bin/env python3
"""
Deep Vulnerability Scanning Module
====================================
Comprehensive vulnerability testing combining reNgine + reconftw capabilities.

Phases:
  1. Nuclei CVE/misconfiguration scanning
  2. XSS testing (dalfox, blind XSS)
  3. SQL injection (sqlmap, ghauri)
  4. CORS misconfiguration (corsy)
  5. SSL/TLS audit (testssl.sh)
  6. Open redirect (oralyzer)
  7. SSRF testing (interactsh + ffuf)
  8. CRLF injection (crlfuzz)
  9. LFI testing
  10. SSTI testing
  11. Command injection (commix)
  12. Prototype pollution (ppmap)
  13. HTTP request smuggling
  14. Web cache poisoning
  15. 403 bypass (nomore403)
  16. Broken link hijacking
"""

import subprocess
import shutil
import json
import re
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except (ImportError, AttributeError):
    requests = None


@dataclass
class VulnFinding:
    """A single vulnerability finding."""
    vuln_type: str           # xss, sqli, cors, ssrf, etc.
    severity: str            # info, low, medium, high, critical
    url: str
    tool: str
    title: str
    details: Dict = field(default_factory=dict)
    evidence: str = ""
    verified: bool = False
    cvss: Optional[float] = None


@dataclass
class VulnScanResult:
    """Complete vulnerability scan results."""
    target: str
    findings: List[VulnFinding] = field(default_factory=list)

    @property
    def critical(self) -> List[VulnFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high(self) -> List[VulnFinding]:
        return [f for f in self.findings if f.severity == "high"]

    @property
    def medium(self) -> List[VulnFinding]:
        return [f for f in self.findings if f.severity == "medium"]

    @property
    def low(self) -> List[VulnFinding]:
        return [f for f in self.findings if f.severity == "low"]

    @property
    def info(self) -> List[VulnFinding]:
        return [f for f in self.findings if f.severity == "info"]

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "summary": {
                "total": len(self.findings),
                "critical": len(self.critical),
                "high": len(self.high),
                "medium": len(self.medium),
                "low": len(self.low),
                "info": len(self.info),
            },
            "findings": [
                {
                    "type": f.vuln_type, "severity": f.severity,
                    "url": f.url, "tool": f.tool, "title": f.title,
                    "details": f.details, "evidence": f.evidence,
                    "verified": f.verified,
                }
                for f in self.findings
            ],
        }


def _available(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: List[str], timeout: int = None, stdin_data: str = None) -> Optional[str]:
    """Run a command and return stdout. No timeout - runs until complete."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            input=stdin_data
        )
        return r.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _lines(output: Optional[str]) -> List[str]:
    if not output:
        return []
    return [l.strip() for l in output.splitlines() if l.strip()]


class VulnDeepScanner:
    """Deep vulnerability scanning engine."""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.vuln_cfg = self.config.get("vulnerability_scan", {})
        self.wordlists = self.config.get("wordlists", {})
        self.tool_paths = self.config.get("tool_paths", {})
        self.perf = self.config.get("performance", {})

    def _tool(self, name: str) -> str:
        return self.tool_paths.get(name, name)

    def run(self, target: str, live_urls: List[str],
            all_urls: List[str] = None,
            classified_urls: Dict[str, List[str]] = None,
            output_dir: Path = None) -> VulnScanResult:
        """Run all vulnerability scanning phases."""
        result = VulnScanResult(target=target)
        all_urls = all_urls or []
        classified_urls = classified_urls or {}

        print(f"\n[VULN] Deep vulnerability scanning for {target}")
        print(f"       Live URLs: {len(live_urls)}, Collected URLs: {len(all_urls)}")

        # Phase 1: Nuclei
        if self.vuln_cfg.get("nuclei", {}).get("enabled", True):
            print("  [*] Phase 1: Nuclei scanning...")
            self._nuclei_scan(live_urls, all_urls, result)
            print(f"      Findings: {len(result.findings)}")

        # Phase 2: XSS
        if self.vuln_cfg.get("xss", {}).get("enabled", True):
            print("  [*] Phase 2: XSS testing...")
            xss_urls = classified_urls.get("xss", all_urls[:500])
            self._xss_scan(xss_urls, result)

        # Phase 3: SQL Injection
        if self.vuln_cfg.get("sqli", {}).get("enabled", True):
            print("  [*] Phase 3: SQL injection testing...")
            sqli_urls = classified_urls.get("sqli", all_urls[:300])
            self._sqli_scan(sqli_urls, result)

        # Phase 4: CORS
        if self.vuln_cfg.get("cors", {}).get("enabled", True):
            print("  [*] Phase 4: CORS misconfiguration...")
            self._cors_scan(live_urls, result)

        # Phase 5: SSL/TLS
        if self.vuln_cfg.get("ssl_tls", {}).get("enabled", True):
            print("  [*] Phase 5: SSL/TLS audit...")
            self._ssl_scan(live_urls, result)

        # Phase 6: Open Redirect
        if self.vuln_cfg.get("open_redirect", {}).get("enabled", True):
            print("  [*] Phase 6: Open redirect testing...")
            redirect_urls = classified_urls.get("redirect", all_urls[:300])
            self._redirect_scan(redirect_urls, result)

        # Phase 7: SSRF
        if self.vuln_cfg.get("ssrf", {}).get("enabled", True):
            print("  [*] Phase 7: SSRF testing...")
            ssrf_urls = classified_urls.get("ssrf", all_urls[:200])
            self._ssrf_scan(ssrf_urls, result)

        # Phase 8: CRLF
        if self.vuln_cfg.get("crlf", {}).get("enabled", True):
            print("  [*] Phase 8: CRLF injection testing...")
            self._crlf_scan(live_urls, result)

        # Phase 9: LFI
        if self.vuln_cfg.get("lfi", {}).get("enabled", True):
            print("  [*] Phase 9: LFI testing...")
            lfi_urls = classified_urls.get("lfi", all_urls[:200])
            self._lfi_scan(lfi_urls, live_urls, result)

        # Phase 10: SSTI
        if self.vuln_cfg.get("ssti", {}).get("enabled", True):
            print("  [*] Phase 10: SSTI testing...")
            ssti_urls = classified_urls.get("ssti", all_urls[:200])
            self._ssti_scan(ssti_urls, live_urls, result)

        # Phase 11: Command Injection
        if self.vuln_cfg.get("command_injection", {}).get("enabled", True):
            print("  [*] Phase 11: Command injection testing...")
            rce_urls = classified_urls.get("rce", all_urls[:100])
            self._command_injection(rce_urls, result)

        # Phase 12: Prototype Pollution
        if self.vuln_cfg.get("prototype_pollution", {}).get("enabled", True):
            print("  [*] Phase 12: Prototype pollution testing...")
            self._prototype_pollution(live_urls, result)

        # Phase 13: HTTP Smuggling
        if self.vuln_cfg.get("smuggling", {}).get("enabled", True):
            print("  [*] Phase 13: HTTP request smuggling...")
            self._http_smuggling(live_urls, result)

        # Phase 14: Cache Attacks
        if self.vuln_cfg.get("cache_attacks", {}).get("enabled", True):
            print("  [*] Phase 14: Web cache poisoning...")
            self._cache_attacks(live_urls, result)

        # Phase 15: 403 Bypass
        if self.vuln_cfg.get("four_xx_bypass", {}).get("enabled", True):
            print("  [*] Phase 15: 403 bypass testing...")
            self._four_xx_bypass(live_urls, result)

        # Phase 16: Broken Links
        if self.vuln_cfg.get("broken_links", {}).get("enabled", True):
            print("  [*] Phase 16: Broken link hijacking...")
            self._broken_links(all_urls, result)

        if output_dir:
            self._save_results(result, output_dir)

        print(f"\n[VULN] Complete: {len(result.findings)} findings")
        print(f"       Critical: {len(result.critical)} | High: {len(result.high)} | "
              f"Medium: {len(result.medium)} | Low: {len(result.low)}")
        return result

    # -------------------------------------------------------------------------
    # Nuclei Scanning
    # -------------------------------------------------------------------------
    def _nuclei_scan(self, live_urls: List[str], all_urls: List[str],
                     result: VulnScanResult):
        if not _available("nuclei"):
            return

        nuc_cfg = self.vuln_cfg.get("nuclei", {})

        # Update templates
        if nuc_cfg.get("update_templates", True):
            _run([self._tool("nuclei"), "-update-templates"], timeout=120)

        # Write targets
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as tmp:
            # Combine live URLs and discovered endpoints
            targets = set(live_urls)
            if nuc_cfg.get("scan_endpoints", True):
                targets.update(all_urls[:5000])
            for t in targets:
                tmp.write(f"{t}\n")
            tmp_path = tmp.name

        severity = ",".join(nuc_cfg.get("severity", ["critical", "high", "medium"]))
        exclude_tags = ",".join(nuc_cfg.get("exclude_tags", ["dos"]))
        rate = nuc_cfg.get("rate_limit", 150)
        concurrency = nuc_cfg.get("concurrency", 50)

        cmd = [
            self._tool("nuclei"), "-l", tmp_path,
            "-severity", severity,
            "-etags", exclude_tags,
            "-rl", str(rate),
            "-c", str(concurrency),
            "-json", "-silent", "-nc",
            "-timeout", str(nuc_cfg.get("timeout", 30)),
            "-retries", str(nuc_cfg.get("retries", 2)),
        ]

        # Custom templates
        custom = nuc_cfg.get("custom_templates")
        if custom and Path(custom).exists():
            cmd.extend(["-t", custom])

        output = _run(cmd, timeout=3600)  # 1 hour max for nuclei
        for line in _lines(output):
            try:
                data = json.loads(line)
                finding = VulnFinding(
                    vuln_type="nuclei_" + data.get("info", {}).get("classification", {}).get("cve-id", ["misc"])[0] if data.get("info", {}).get("classification", {}).get("cve-id") else "nuclei",
                    severity=data.get("info", {}).get("severity", "info"),
                    url=data.get("matched-at", data.get("host", "")),
                    tool="nuclei",
                    title=data.get("info", {}).get("name", "Unknown"),
                    details={
                        "template": data.get("template-id", ""),
                        "tags": data.get("info", {}).get("tags", []),
                        "reference": data.get("info", {}).get("reference", []),
                        "description": data.get("info", {}).get("description", ""),
                    },
                    evidence=data.get("extracted-results", ""),
                    verified=True,
                )
                result.findings.append(finding)
            except (json.JSONDecodeError, TypeError, KeyError):
                continue

    # -------------------------------------------------------------------------
    # XSS Testing
    # -------------------------------------------------------------------------
    def _xss_scan(self, urls: List[str], result: VulnScanResult):
        xss_cfg = self.vuln_cfg.get("xss", {})

        if not urls:
            return

        # Dalfox
        if _available("dalfox"):
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tmp:
                for url in urls[:500]:
                    if "?" in url:
                        tmp.write(f"{url}\n")
                tmp_path = tmp.name

            cmd = [
                self._tool("dalfox"), "file", tmp_path,
                "-silence", "-json",
                "-w", str(self.perf.get("threads", {}).get("dalfox", 30)),
            ]

            # Blind XSS
            if xss_cfg.get("blind_xss", True):
                callback = xss_cfg.get("blind_xss_callback")
                if callback:
                    cmd.extend(["--blind", callback])

            output = _run(cmd, timeout=1800)
            for line in _lines(output):
                try:
                    data = json.loads(line)
                    if data.get("type") == "found" or data.get("poc"):
                        result.findings.append(VulnFinding(
                            vuln_type="xss",
                            severity="high",
                            url=data.get("data", data.get("url", "")),
                            tool="dalfox",
                            title=f"XSS - {data.get('cwe', 'Reflected')}",
                            evidence=data.get("poc", data.get("payload", "")),
                            verified=True,
                            details={
                                "param": data.get("param", ""),
                                "payload": data.get("payload", ""),
                                "method": data.get("method", "GET"),
                            }
                        ))
                except json.JSONDecodeError:
                    # Plain text output
                    if "[POC]" in line or "[V]" in line:
                        result.findings.append(VulnFinding(
                            vuln_type="xss", severity="high",
                            url=line, tool="dalfox",
                            title="XSS Found", evidence=line, verified=True,
                        ))

    # -------------------------------------------------------------------------
    # SQL Injection
    # -------------------------------------------------------------------------
    def _sqli_scan(self, urls: List[str], result: VulnScanResult):
        sqli_cfg = self.vuln_cfg.get("sqli", {})
        parameterized = [u for u in urls if "?" in u][:100]

        if not parameterized:
            return

        # Ghauri (modern, fast)
        if sqli_cfg.get("ghauri", True) and _available("ghauri"):
            for url in parameterized[:30]:
                output = _run([
                    self._tool("ghauri"), "-u", url, "--batch", "--level", "3",
                ], timeout=120)
                if output and ("injectable" in output.lower() or "vulnerable" in output.lower()):
                    result.findings.append(VulnFinding(
                        vuln_type="sqli", severity="critical",
                        url=url, tool="ghauri",
                        title="SQL Injection",
                        evidence=output[:500], verified=True,
                    ))

        # SQLMap
        if sqli_cfg.get("sqlmap", True) and _available("sqlmap"):
            level = sqli_cfg.get("sqlmap_level", 3)
            risk = sqli_cfg.get("sqlmap_risk", 2)
            threads = sqli_cfg.get("sqlmap_threads", 5)

            for url in parameterized[:20]:
                output = _run([
                    self._tool("sqlmap"), "-u", url,
                    "--batch", "--level", str(level),
                    "--risk", str(risk),
                    "--threads", str(threads),
                    "--smart", "--tamper", "between,randomcase",
                ], timeout=300)
                if output and "is vulnerable" in output.lower():
                    # Extract injection details
                    result.findings.append(VulnFinding(
                        vuln_type="sqli", severity="critical",
                        url=url, tool="sqlmap",
                        title="SQL Injection (sqlmap confirmed)",
                        evidence=output[:500], verified=True,
                    ))

    # -------------------------------------------------------------------------
    # CORS Misconfiguration
    # -------------------------------------------------------------------------
    def _cors_scan(self, urls: List[str], result: VulnScanResult):
        # Corsy
        if _available("corsy") or Path(f"{Path.home()}/Tools/Corsy/corsy.py").exists():
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tmp:
                for url in urls:
                    tmp.write(f"{url}\n")
                tmp_path = tmp.name

            corsy_cmd = "corsy" if _available("corsy") else f"python3 {Path.home()}/Tools/Corsy/corsy.py"
            output = _run(
                corsy_cmd.split() + ["-i", tmp_path], timeout=300
            )
            if output:
                for line in _lines(output):
                    if "misconfigured" in line.lower() or "vulnerable" in line.lower():
                        result.findings.append(VulnFinding(
                            vuln_type="cors", severity="medium",
                            url=line, tool="corsy",
                            title="CORS Misconfiguration",
                            evidence=line, verified=True,
                        ))

        # Manual CORS check
        if requests:
            for url in urls[:50]:
                try:
                    # Test null origin
                    resp = requests.get(
                        url, timeout=10, verify=False,
                        headers={"Origin": "null"}
                    )
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    if acao == "null":
                        result.findings.append(VulnFinding(
                            vuln_type="cors", severity="high",
                            url=url, tool="manual",
                            title="CORS - Null Origin Reflected",
                            evidence=f"ACAO: {acao}", verified=True,
                        ))
                    # Test arbitrary origin
                    resp = requests.get(
                        url, timeout=10, verify=False,
                        headers={"Origin": "https://evil.com"}
                    )
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                    if "evil.com" in acao and acac.lower() == "true":
                        result.findings.append(VulnFinding(
                            vuln_type="cors", severity="high",
                            url=url, tool="manual",
                            title="CORS - Arbitrary Origin with Credentials",
                            evidence=f"ACAO: {acao}, ACAC: {acac}",
                            verified=True,
                        ))
                except Exception:
                    continue

    # -------------------------------------------------------------------------
    # SSL/TLS Audit
    # -------------------------------------------------------------------------
    def _ssl_scan(self, urls: List[str], result: VulnScanResult):
        testssl_path = shutil.which("testssl.sh") or f"{Path.home()}/Tools/testssl.sh/testssl.sh"

        if not Path(testssl_path).exists():
            return

        for url in urls[:10]:
            host = re.sub(r'https?://', '', url).split('/')[0]
            if ":" not in host:
                host += ":443"

            output = _run([
                testssl_path, "--json", "--quiet", host
            ], timeout=300)
            if output:
                try:
                    findings = json.loads(output)
                    for f in (findings if isinstance(findings, list) else []):
                        sev = f.get("severity", "INFO").lower()
                        if sev in ["critical", "high", "medium"]:
                            result.findings.append(VulnFinding(
                                vuln_type="ssl_tls",
                                severity=sev,
                                url=url, tool="testssl",
                                title=f.get("id", "SSL Issue"),
                                evidence=f.get("finding", ""),
                                details={"ip": f.get("ip", "")},
                            ))
                except json.JSONDecodeError:
                    # Parse text output
                    for line in output.splitlines():
                        if "VULNERABLE" in line or "NOT ok" in line:
                            result.findings.append(VulnFinding(
                                vuln_type="ssl_tls", severity="medium",
                                url=url, tool="testssl",
                                title="SSL/TLS Issue",
                                evidence=line.strip(),
                            ))

    # -------------------------------------------------------------------------
    # Open Redirect
    # -------------------------------------------------------------------------
    def _redirect_scan(self, urls: List[str], result: VulnScanResult):
        redirect_urls = [u for u in urls if "?" in u and any(
            p in u.lower() for p in ["redirect", "url", "next", "return", "goto", "dest", "redir"]
        )][:200]

        if not redirect_urls:
            return

        # Oralyzer
        oralyzer_path = (shutil.which("oralyzer") or
                         f"{Path.home()}/Tools/Oralyzer/oralyzer.py")
        if Path(oralyzer_path).exists():
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tmp:
                for url in redirect_urls:
                    tmp.write(f"{url}\n")
                tmp_path = tmp.name

            output = _run(
                ["python3", oralyzer_path, "-l", tmp_path], timeout=600
            )
            if output:
                for line in _lines(output):
                    if "VULNERABLE" in line.upper() or "FOUND" in line.upper():
                        result.findings.append(VulnFinding(
                            vuln_type="open_redirect", severity="medium",
                            url=line, tool="oralyzer",
                            title="Open Redirect", evidence=line, verified=True,
                        ))

    # -------------------------------------------------------------------------
    # SSRF
    # -------------------------------------------------------------------------
    def _ssrf_scan(self, urls: List[str], result: VulnScanResult):
        ssrf_cfg = self.vuln_cfg.get("ssrf", {})
        ssrf_params = [u for u in urls if "?" in u and any(
            p in u.lower() for p in ["url", "uri", "path", "src", "dest",
                                      "redirect", "file", "page", "feed",
                                      "host", "site", "img", "load"]
        )][:200]

        if not ssrf_params:
            return

        # interactsh for OOB detection
        callback_url = ssrf_cfg.get("callback_url")
        if ssrf_cfg.get("interactsh", True) and _available("interactsh-client") and not callback_url:
            # Start interactsh in background - for now use placeholder
            pass

        # SSRF with ffuf
        if _available("ffuf") and callback_url:
            ssrf_payloads = [
                callback_url,
                f"http://169.254.169.254/latest/meta-data/",
                f"http://metadata.google.internal/computeMetadata/v1/",
                f"http://169.254.169.254/metadata/instance",
                "http://127.0.0.1:80",
                "http://127.0.0.1:443",
                "http://[::1]:80",
                "http://0177.0.0.1",
                "http://0x7f.0x0.0x0.0x1",
            ]
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tmp:
                for p in ssrf_payloads:
                    tmp.write(f"{p}\n")
                payloads_path = tmp.name

            for url in ssrf_params[:20]:
                if "FUZZ" not in url:
                    # Replace parameter value with FUZZ
                    parts = url.split("?", 1)
                    if len(parts) == 2:
                        params = parts[1].split("&")
                        for i, param in enumerate(params):
                            if "=" in param:
                                key = param.split("=")[0]
                                fuzz_url = f"{parts[0]}?{'&'.join(params[:i])}&{key}=FUZZ&{'&'.join(params[i+1:])}"
                                fuzz_url = fuzz_url.replace("?&", "?").rstrip("&")
                                output = _run([
                                    self._tool("ffuf"), "-u", fuzz_url,
                                    "-w", payloads_path,
                                    "-mc", "200,301,302,307",
                                    "-s",
                                ], timeout=60)
                                if output:
                                    for line in _lines(output):
                                        result.findings.append(VulnFinding(
                                            vuln_type="ssrf", severity="high",
                                            url=url, tool="ffuf",
                                            title="Potential SSRF",
                                            evidence=line,
                                        ))
                                break

    # -------------------------------------------------------------------------
    # CRLF Injection
    # -------------------------------------------------------------------------
    def _crlf_scan(self, urls: List[str], result: VulnScanResult):
        if not _available("crlfuzz"):
            return

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as tmp:
            for url in urls:
                tmp.write(f"{url}\n")
            tmp_path = tmp.name

        output = _run([
            self._tool("crlfuzz"), "-l", tmp_path, "-s", "-o", "-",
        ], timeout=600)
        for line in _lines(output):
            if line.startswith("http"):
                result.findings.append(VulnFinding(
                    vuln_type="crlf", severity="medium",
                    url=line, tool="crlfuzz",
                    title="CRLF Injection", verified=True,
                ))

    # -------------------------------------------------------------------------
    # LFI Testing
    # -------------------------------------------------------------------------
    def _lfi_scan(self, urls: List[str], live_urls: List[str],
                  result: VulnScanResult):
        lfi_cfg = self.vuln_cfg.get("lfi", {})
        wordlist = lfi_cfg.get(
            "wordlist",
            self.wordlists.get("lfi",
                               "/opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt")
        )

        if not _available("ffuf") or not Path(wordlist).exists():
            return

        # Find URLs with file-like parameters
        lfi_targets = [u for u in urls if "?" in u and any(
            p in u.lower() for p in ["file", "path", "page", "include",
                                      "dir", "doc", "folder", "root",
                                      "template", "php_path"]
        )][:100]

        for url in lfi_targets[:20]:
            parts = url.split("?", 1)
            if len(parts) != 2:
                continue
            params = parts[1].split("&")
            for param in params:
                if "=" in param:
                    key = param.split("=")[0]
                    if any(p in key.lower() for p in ["file", "path", "page", "include", "dir"]):
                        fuzz_url = f"{parts[0]}?{key}=FUZZ"
                        output = _run([
                            self._tool("ffuf"), "-u", fuzz_url,
                            "-w", wordlist,
                            "-mc", "200",
                            "-fs", "0",
                            "-s",
                        ], timeout=120)
                        if output:
                            for line in _lines(output):
                                result.findings.append(VulnFinding(
                                    vuln_type="lfi", severity="high",
                                    url=url, tool="ffuf",
                                    title="Local File Inclusion",
                                    evidence=line, verified=True,
                                    details={"param": key}
                                ))
                        break

    # -------------------------------------------------------------------------
    # SSTI Testing
    # -------------------------------------------------------------------------
    def _ssti_scan(self, urls: List[str], live_urls: List[str],
                   result: VulnScanResult):
        # Nuclei SSTI templates
        if _available("nuclei"):
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as tmp:
                ssti_urls = [u for u in urls if "?" in u][:500]
                for url in ssti_urls:
                    tmp.write(f"{url}\n")
                tmp_path = tmp.name

            output = _run([
                self._tool("nuclei"), "-l", tmp_path,
                "-tags", "ssti",
                "-silent", "-json", "-nc",
            ], timeout=600)
            for line in _lines(output):
                try:
                    data = json.loads(line)
                    result.findings.append(VulnFinding(
                        vuln_type="ssti",
                        severity=data.get("info", {}).get("severity", "high"),
                        url=data.get("matched-at", ""),
                        tool="nuclei",
                        title=data.get("info", {}).get("name", "SSTI"),
                        verified=True,
                    ))
                except json.JSONDecodeError:
                    continue

        # Manual SSTI probes
        if requests:
            ssti_probes = [
                ("{{7*7}}", "49"),
                ("${7*7}", "49"),
                ("<%= 7*7 %>", "49"),
                ("#{7*7}", "49"),
                ("{{config}}", "SECRET_KEY"),
            ]
            param_urls = [u for u in urls if "?" in u][:50]
            for url in param_urls:
                parts = url.split("?", 1)
                if len(parts) != 2:
                    continue
                for probe, expected in ssti_probes:
                    try:
                        test_url = f"{parts[0]}?{parts[1].split('=')[0]}={probe}"
                        resp = requests.get(test_url, timeout=10, verify=False)
                        if expected in resp.text:
                            result.findings.append(VulnFinding(
                                vuln_type="ssti", severity="critical",
                                url=url, tool="manual",
                                title="Server-Side Template Injection",
                                evidence=f"Probe: {probe}, Found: {expected}",
                                verified=True,
                            ))
                            break
                    except Exception:
                        continue

    # -------------------------------------------------------------------------
    # Command Injection
    # -------------------------------------------------------------------------
    def _command_injection(self, urls: List[str], result: VulnScanResult):
        commix_path = (shutil.which("commix") or
                       f"{Path.home()}/Tools/commix/commix.py")

        if not Path(commix_path).exists() and not _available("commix"):
            return

        rce_urls = [u for u in urls if "?" in u][:30]
        for url in rce_urls:
            cmd = ["python3", commix_path] if not _available("commix") else ["commix"]
            output = _run(
                cmd + ["-u", url, "--batch", "--level", "2"],
                timeout=120
            )
            if output and ("injectable" in output.lower() or "vulnerable" in output.lower()):
                result.findings.append(VulnFinding(
                    vuln_type="command_injection", severity="critical",
                    url=url, tool="commix",
                    title="OS Command Injection",
                    evidence=output[:500], verified=True,
                ))

    # -------------------------------------------------------------------------
    # Prototype Pollution
    # -------------------------------------------------------------------------
    def _prototype_pollution(self, urls: List[str], result: VulnScanResult):
        ppmap_path = f"{Path.home()}/Tools/ppmap"
        if not Path(ppmap_path).exists():
            return

        for url in urls[:20]:
            output = _run([
                "bash", f"{ppmap_path}/ppmap.sh", url
            ], timeout=60)
            if output and "VULNERABLE" in output.upper():
                result.findings.append(VulnFinding(
                    vuln_type="prototype_pollution", severity="high",
                    url=url, tool="ppmap",
                    title="Prototype Pollution",
                    evidence=output[:500], verified=True,
                ))

    # -------------------------------------------------------------------------
    # HTTP Request Smuggling
    # -------------------------------------------------------------------------
    def _http_smuggling(self, urls: List[str], result: VulnScanResult):
        smuggler_path = (shutil.which("smuggler") or
                         f"{Path.home()}/Tools/smuggler/smuggler.py")

        if Path(smuggler_path).exists() or _available("smuggler"):
            for url in urls[:10]:
                cmd = ["python3", smuggler_path] if not _available("smuggler") else ["smuggler"]
                output = _run(cmd + ["-u", url], timeout=120)
                if output and ("VULNERABLE" in output.upper() or "DESYNC" in output.upper()):
                    result.findings.append(VulnFinding(
                        vuln_type="http_smuggling", severity="high",
                        url=url, tool="smuggler",
                        title="HTTP Request Smuggling",
                        evidence=output[:500], verified=True,
                    ))

    # -------------------------------------------------------------------------
    # Web Cache Poisoning
    # -------------------------------------------------------------------------
    def _cache_attacks(self, urls: List[str], result: VulnScanResult):
        cache_cfg = self.vuln_cfg.get("cache_attacks", {})

        # Manual unkeyed header test
        if requests:
            unkeyed_headers = [
                "X-Forwarded-Host", "X-Forwarded-Scheme",
                "X-Original-URL", "X-Rewrite-URL",
                "X-Forwarded-For", "X-Host",
                "X-Forwarded-Server", "X-HTTP-Dest-Forwarded",
            ]
            for url in urls[:20]:
                for header in unkeyed_headers:
                    try:
                        resp1 = requests.get(url, timeout=10, verify=False)
                        resp2 = requests.get(
                            url, timeout=10, verify=False,
                            headers={header: "evil.com"}
                        )
                        if "evil.com" in resp2.text and "evil.com" not in resp1.text:
                            result.findings.append(VulnFinding(
                                vuln_type="cache_poisoning", severity="high",
                                url=url, tool="manual",
                                title=f"Web Cache Poisoning - {header}",
                                evidence=f"Header {header}: evil.com reflected in response",
                                verified=True,
                                details={"header": header}
                            ))
                            break
                    except Exception:
                        continue

    # -------------------------------------------------------------------------
    # 403 Bypass
    # -------------------------------------------------------------------------
    def _four_xx_bypass(self, urls: List[str], result: VulnScanResult):
        if not _available("nomore403"):
            # Manual bypass attempts
            if not requests:
                return

            bypass_headers = [
                {"X-Original-URL": "/admin"},
                {"X-Rewrite-URL": "/admin"},
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Custom-IP-Authorization": "127.0.0.1"},
                {"X-Real-IP": "127.0.0.1"},
            ]
            bypass_paths = [
                "/admin", "/admin/", "/Admin", "//admin",
                "/admin.html", "/admin%20/", "/admin%09/",
                "/.;/admin", "/;/admin", "/admin..;/",
            ]

            # Find 403 URLs
            for url in urls[:30]:
                try:
                    resp = requests.get(url, timeout=10, verify=False)
                    if resp.status_code == 403:
                        # Try header bypasses
                        for headers in bypass_headers:
                            try:
                                resp2 = requests.get(
                                    url, timeout=10, verify=False,
                                    headers=headers
                                )
                                if resp2.status_code == 200:
                                    result.findings.append(VulnFinding(
                                        vuln_type="403_bypass", severity="medium",
                                        url=url, tool="manual",
                                        title="403 Bypass via Header",
                                        evidence=f"Headers: {headers} -> 200",
                                        verified=True,
                                    ))
                                    break
                            except Exception:
                                continue
                except Exception:
                    continue
            return

        # nomore403
        for url in urls[:30]:
            output = _run([
                self._tool("nomore403"), "-u", url
            ], timeout=60)
            if output:
                for line in _lines(output):
                    if "200" in line or "bypass" in line.lower():
                        result.findings.append(VulnFinding(
                            vuln_type="403_bypass", severity="medium",
                            url=url, tool="nomore403",
                            title="403 Bypass", evidence=line, verified=True,
                        ))

    # -------------------------------------------------------------------------
    # Broken Link Hijacking
    # -------------------------------------------------------------------------
    def _broken_links(self, urls: List[str], result: VulnScanResult):
        """Find broken links that could be hijacked."""
        if not requests:
            return

        # Check external links for hijackable domains
        external_links = set()
        for url in urls[:1000]:
            # Skip same-domain URLs
            if result.target not in url:
                external_links.add(url)

        for url in list(external_links)[:100]:
            try:
                resp = requests.head(url, timeout=10, verify=False,
                                     allow_redirects=True)
                if resp.status_code in [404, 410]:
                    # Check if domain is available for registration
                    host = re.sub(r'https?://', '', url).split('/')[0]
                    result.findings.append(VulnFinding(
                        vuln_type="broken_link", severity="low",
                        url=url, tool="manual",
                        title=f"Broken External Link ({host})",
                        details={"status": resp.status_code},
                    ))
            except requests.exceptions.ConnectionError:
                # Domain might be unregistered
                host = re.sub(r'https?://', '', url).split('/')[0]
                result.findings.append(VulnFinding(
                    vuln_type="broken_link_hijack", severity="medium",
                    url=url, tool="manual",
                    title=f"Potentially Hijackable Broken Link ({host})",
                    details={"reason": "connection_failed"},
                ))
            except Exception:
                continue

    # -------------------------------------------------------------------------
    # Save Results
    # -------------------------------------------------------------------------
    def _save_results(self, result: VulnScanResult, output_dir: Path):
        output_dir.mkdir(parents=True, exist_ok=True)

        data = result.to_dict()

        # Full results
        with open(output_dir / f"vulns_{result.target.replace('.', '_')}.json", "w") as f:
            json.dump(data, f, indent=2)

        # Severity-separated files
        for severity in ["critical", "high", "medium", "low", "info"]:
            findings = [f for f in data["findings"] if f["severity"] == severity]
            if findings:
                with open(output_dir / f"vulns_{severity}.json", "w") as f:
                    json.dump(findings, f, indent=2)

        # Human-readable report
        with open(output_dir / "vuln_report.txt", "w") as f:
            f.write(f"Vulnerability Scan Report - {result.target}\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Total Findings: {len(result.findings)}\n")
            f.write(f"  Critical: {len(result.critical)}\n")
            f.write(f"  High:     {len(result.high)}\n")
            f.write(f"  Medium:   {len(result.medium)}\n")
            f.write(f"  Low:      {len(result.low)}\n")
            f.write(f"  Info:     {len(result.info)}\n\n")

            for severity in ["critical", "high", "medium", "low"]:
                findings = [f for f in result.findings if f.severity == severity]
                if findings:
                    f.write(f"\n{'=' * 40}\n")
                    f.write(f" {severity.upper()} FINDINGS\n")
                    f.write(f"{'=' * 40}\n\n")
                    for finding in findings:
                        f.write(f"  [{finding.tool}] {finding.title}\n")
                        f.write(f"  URL: {finding.url}\n")
                        if finding.evidence:
                            f.write(f"  Evidence: {finding.evidence[:200]}\n")
                        f.write(f"  Verified: {finding.verified}\n\n")
