#!/usr/bin/env python3
"""
Burp Suite Professional - Headless Wrapper
==========================================
Controls Burp Pro via the burp-rest-api (REST/JSON API).
Supports auto-launch, scope management, spider, active scan,
report download, and result parsing into unified Finding format.

Requirements:
    - burp-rest-api JAR (https://github.com/vmware/burp-rest-api)
    - Burp Suite Professional JAR + valid license
    - Java 17+

Usage (standalone):
    python burp_wrapper.py --target https://example.com --output results/

As library:
    from scanners.burp_wrapper import BurpProAPI, BurpReportParser
    api = BurpProAPI("http://localhost:8090")
    api.set_scope("https://example.com")
    api.start_spider("https://example.com")
    api.start_scan("https://example.com")
    api.poll_status()
    report = api.get_report("XML")
"""

import json
import time
import logging
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("[!] 'requests' module not found. Install: pip install requests")
    raise

logger = logging.getLogger('BurpWrapper')


# =============================================================================
# BURP PRO REST API CLIENT
# =============================================================================

class BurpProAPI:
    """
    REST API client for burp-rest-api.
    Controls Burp Suite Professional in headless mode.
    """

    def __init__(self, api_url: str = "http://localhost:8090",
                 api_key: str = "", timeout: int = 30):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        if api_key:
            self.session.headers['X-Api-Key'] = api_key

    # -------------------------------------------------------------------------
    # Health & Version
    # -------------------------------------------------------------------------

    def is_alive(self) -> bool:
        """Check if Burp REST API is reachable."""
        try:
            resp = self.session.get(
                f"{self.api_url}/burp/versions",
                timeout=self.timeout
            )
            return resp.status_code == 200
        except requests.ConnectionError:
            return False
        except Exception as e:
            logger.warning(f"Burp health check failed: {e}")
            return False

    def get_version(self) -> Dict[str, Any]:
        """Get Burp Suite version info."""
        resp = self.session.get(
            f"{self.api_url}/burp/versions",
            timeout=self.timeout
        )
        resp.raise_for_status()
        return resp.json()

    # -------------------------------------------------------------------------
    # Scope
    # -------------------------------------------------------------------------

    def set_scope(self, url: str) -> bool:
        """Add a URL to the Burp target scope."""
        try:
            resp = self.session.put(
                f"{self.api_url}/burp/target/scope",
                params={"url": url},
                timeout=self.timeout
            )
            if resp.status_code == 200:
                logger.info(f"[Burp] Scope set: {url}")
                return True
            else:
                logger.warning(f"[Burp] Scope failed ({resp.status_code}): {url}")
                return False
        except Exception as e:
            logger.error(f"[Burp] Scope error: {e}")
            return False

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL is in the Burp target scope."""
        try:
            resp = self.session.get(
                f"{self.api_url}/burp/target/scope",
                params={"url": url},
                timeout=self.timeout
            )
            return resp.status_code == 200 and resp.json().get('inScope', False)
        except Exception:
            return False

    def exclude_from_scope(self, url: str) -> bool:
        """Remove a URL from the Burp target scope."""
        try:
            resp = self.session.delete(
                f"{self.api_url}/burp/target/scope",
                params={"url": url},
                timeout=self.timeout
            )
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"[Burp] Scope exclusion error: {e}")
            return False

    # -------------------------------------------------------------------------
    # Spider (Crawl)
    # -------------------------------------------------------------------------

    def start_spider(self, base_url: str) -> bool:
        """Start the Burp spider on the given base URL."""
        try:
            resp = self.session.post(
                f"{self.api_url}/burp/spider",
                params={"baseUrl": base_url},
                timeout=self.timeout
            )
            if resp.status_code == 200:
                logger.info(f"[Burp] Spider started: {base_url}")
                return True
            else:
                logger.warning(f"[Burp] Spider start failed ({resp.status_code})")
                return False
        except Exception as e:
            logger.error(f"[Burp] Spider error: {e}")
            return False

    def get_spider_status(self) -> int:
        """Get spider progress (0-100)."""
        try:
            resp = self.session.get(
                f"{self.api_url}/burp/spider/status",
                timeout=self.timeout
            )
            if resp.status_code == 200:
                return resp.json().get('spiderPercentage', 0)
            return -1
        except Exception:
            return -1

    def wait_for_spider(self, poll_interval: int = 5,
                        timeout: int = 600) -> bool:
        """Wait for spider to complete."""
        start = time.time()
        while time.time() - start < timeout:
            pct = self.get_spider_status()
            if pct < 0:
                logger.error("[Burp] Spider status check failed")
                return False
            if pct >= 100:
                logger.info("[Burp] Spider complete")
                return True
            logger.info(f"[Burp] Spider progress: {pct}%")
            time.sleep(poll_interval)

        logger.warning(f"[Burp] Spider timed out after {timeout}s")
        return False

    # -------------------------------------------------------------------------
    # Active Scanner
    # -------------------------------------------------------------------------

    def start_scan(self, base_url: str) -> bool:
        """Start an active scan on the given base URL."""
        try:
            resp = self.session.post(
                f"{self.api_url}/burp/scanner",
                params={"baseUrl": base_url},
                timeout=self.timeout
            )
            if resp.status_code == 200:
                logger.info(f"[Burp] Active scan started: {base_url}")
                return True
            else:
                logger.warning(f"[Burp] Scan start failed ({resp.status_code})")
                return False
        except Exception as e:
            logger.error(f"[Burp] Scan error: {e}")
            return False

    def get_scan_status(self) -> int:
        """Get active scan progress (0-100)."""
        try:
            resp = self.session.get(
                f"{self.api_url}/burp/scanner/status",
                timeout=self.timeout
            )
            if resp.status_code == 200:
                return resp.json().get('scanPercentage', 0)
            return -1
        except Exception:
            return -1

    def wait_for_scan(self, poll_interval: int = 10,
                      timeout: int = 3600) -> bool:
        """Wait for active scan to complete."""
        start = time.time()
        while time.time() - start < timeout:
            pct = self.get_scan_status()
            if pct < 0:
                logger.error("[Burp] Scan status check failed")
                return False
            if pct >= 100:
                logger.info("[Burp] Active scan complete")
                return True
            elapsed = int(time.time() - start)
            logger.info(f"[Burp] Scan progress: {pct}% ({elapsed}s elapsed)")
            time.sleep(poll_interval)

        logger.warning(f"[Burp] Active scan timed out after {timeout}s")
        return False

    # -------------------------------------------------------------------------
    # Scan Issues
    # -------------------------------------------------------------------------

    def get_issues(self, url_prefix: str = "") -> List[Dict]:
        """Get scanner issues (findings) from Burp."""
        try:
            params = {}
            if url_prefix:
                params["urlPrefix"] = url_prefix
            resp = self.session.get(
                f"{self.api_url}/burp/scanner/issues",
                params=params,
                timeout=self.timeout
            )
            if resp.status_code == 200:
                return resp.json().get('issues', [])
            return []
        except Exception as e:
            logger.error(f"[Burp] Get issues error: {e}")
            return []

    # -------------------------------------------------------------------------
    # Report
    # -------------------------------------------------------------------------

    def get_report(self, report_type: str = "XML",
                   url_prefix: str = "") -> Optional[str]:
        """
        Download scan report.

        Args:
            report_type: "XML" or "HTML"
            url_prefix: Optional URL prefix filter

        Returns:
            Report content as string, or None on error.
        """
        try:
            params = {"reportType": report_type.upper()}
            if url_prefix:
                params["urlPrefix"] = url_prefix
            resp = self.session.get(
                f"{self.api_url}/burp/report",
                params=params,
                timeout=120  # Reports can take a while
            )
            if resp.status_code == 200:
                logger.info(f"[Burp] Report downloaded ({report_type})")
                return resp.text
            else:
                logger.warning(f"[Burp] Report download failed ({resp.status_code})")
                return None
        except Exception as e:
            logger.error(f"[Burp] Report error: {e}")
            return None

    # -------------------------------------------------------------------------
    # Proxy / Sitemap
    # -------------------------------------------------------------------------

    def get_sitemap(self, url_prefix: str = "") -> List[Dict]:
        """Get the Burp site map entries."""
        try:
            params = {}
            if url_prefix:
                params["urlPrefix"] = url_prefix
            resp = self.session.get(
                f"{self.api_url}/burp/target/sitemap",
                params=params,
                timeout=self.timeout
            )
            if resp.status_code == 200:
                return resp.json().get('messages', [])
            return []
        except Exception:
            return []

    # -------------------------------------------------------------------------
    # Control
    # -------------------------------------------------------------------------

    def stop(self) -> bool:
        """Stop Burp Suite."""
        try:
            resp = self.session.get(
                f"{self.api_url}/burp/stop",
                timeout=self.timeout
            )
            return resp.status_code == 200
        except Exception:
            return False

    # -------------------------------------------------------------------------
    # Full Scan Orchestration
    # -------------------------------------------------------------------------

    def run_full_scan(self, target_url: str,
                      scan_type: str = "active",
                      spider_timeout: int = 600,
                      scan_timeout: int = 3600,
                      exclude_urls: List[str] = None) -> Dict[str, Any]:
        """
        Orchestrate a complete Burp scan: scope → spider → scan → issues.

        Args:
            target_url: Target URL to scan
            scan_type: "spider_only", "passive", or "active"
            spider_timeout: Max spider time (seconds)
            scan_timeout: Max scan time (seconds)
            exclude_urls: URLs to exclude from scope

        Returns:
            Dict with keys: success, issues, sitemap_count, timings
        """
        result = {
            'success': False,
            'issues': [],
            'sitemap_count': 0,
            'timings': {},
            'errors': [],
        }

        # Step 1: Check API
        if not self.is_alive():
            result['errors'].append("Burp REST API is not reachable")
            return result

        # Step 2: Set scope
        if not self.set_scope(target_url):
            result['errors'].append(f"Failed to set scope: {target_url}")
            return result

        # Optional: exclude URLs
        if exclude_urls:
            for url in exclude_urls:
                self.exclude_from_scope(url)

        # Step 3: Spider
        t0 = time.time()
        if not self.start_spider(target_url):
            result['errors'].append("Failed to start spider")
            return result

        spider_ok = self.wait_for_spider(timeout=spider_timeout)
        result['timings']['spider'] = round(time.time() - t0, 1)

        if not spider_ok:
            result['errors'].append("Spider timed out or failed")
            # Continue anyway — we may have partial results

        # Step 4: Active scan (if requested)
        if scan_type in ("active", "passive"):
            t1 = time.time()
            if not self.start_scan(target_url):
                result['errors'].append("Failed to start active scan")
                return result

            scan_ok = self.wait_for_scan(timeout=scan_timeout)
            result['timings']['scan'] = round(time.time() - t1, 1)

            if not scan_ok:
                result['errors'].append("Active scan timed out or failed")

        # Step 5: Collect results
        result['issues'] = self.get_issues(target_url)
        result['sitemap_count'] = len(self.get_sitemap(target_url))
        result['success'] = True

        return result


# =============================================================================
# BURP REPORT PARSER
# =============================================================================

class BurpReportParser:
    """
    Parse Burp Suite XML reports into the unified Finding format
    used by external_scanners.py.
    """

    # Burp severity mapping → unified severity
    SEVERITY_MAP = {
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'information': 'info',
        'info': 'info',
    }

    # Burp confidence mapping
    CONFIDENCE_MAP = {
        'certain': 'high',
        'firm': 'medium',
        'tentative': 'low',
    }

    @staticmethod
    def parse_xml(xml_content: str) -> List[Dict[str, Any]]:
        """
        Parse Burp XML report into list of finding dicts.

        Args:
            xml_content: Raw XML string from Burp report

        Returns:
            List of finding dicts compatible with scanner Finding format
        """
        findings = []
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            logger.error(f"[BurpParser] XML parse error: {e}")
            return findings

        for issue in root.findall('.//issue'):
            finding = BurpReportParser._parse_issue(issue)
            if finding:
                findings.append(finding)

        logger.info(f"[BurpParser] Parsed {len(findings)} issues from Burp report")
        return findings

    @staticmethod
    def _parse_issue(issue_elem) -> Optional[Dict[str, Any]]:
        """Parse a single <issue> element into a finding dict."""
        try:
            # Extract text safely with fallback
            def text(tag, default=''):
                el = issue_elem.find(tag)
                return el.text.strip() if el is not None and el.text else default

            # Core fields
            url = text('url')
            name = text('name', 'Unknown Burp Issue')
            severity = text('severity', 'info').lower()
            confidence = text('confidence', 'tentative').lower()
            issue_type = text('type', '0')

            # Detail fields
            issue_background = text('issueBackground')
            issue_detail = text('issueDetail')
            remediation_background = text('remediationBackground')
            remediation_detail = text('remediationDetail')

            # Request/Response from first item
            request_str = ''
            response_str = ''
            items = issue_elem.findall('.//requestresponse')
            if items:
                req_el = items[0].find('request')
                resp_el = items[0].find('response')
                if req_el is not None and req_el.text:
                    request_str = req_el.text[:2000]  # Truncate large requests
                if resp_el is not None and resp_el.text:
                    response_str = resp_el.text[:2000]  # Truncate large responses

            # Build description
            description_parts = []
            if issue_detail:
                description_parts.append(issue_detail)
            if issue_background:
                description_parts.append(f"Background: {issue_background}")
            description = ' | '.join(description_parts) if description_parts else name

            # Build remediation
            remediation_parts = []
            if remediation_detail:
                remediation_parts.append(remediation_detail)
            if remediation_background:
                remediation_parts.append(remediation_background)
            remediation = ' | '.join(remediation_parts)

            # Parse host from URL
            parsed = urlparse(url)
            host = parsed.netloc or url

            return {
                'target': host,
                'url': url,
                'vuln_type': name,
                'severity': BurpReportParser.SEVERITY_MAP.get(severity, 'info'),
                'confidence': BurpReportParser.CONFIDENCE_MAP.get(confidence, 'low'),
                'description': description,
                'remediation': remediation,
                'evidence': request_str[:500] if request_str else '',
                'request': request_str,
                'response': response_str,
                'burp_type_id': issue_type,
                'source': 'burp_suite_pro',
                'timestamp': datetime.utcnow().isoformat(),
                'reproduction_steps': [
                    f"1. Open Burp Suite and navigate to: {url}",
                    f"2. Issue type: {name}",
                    f"3. Confidence: {confidence}",
                ],
            }
        except Exception as e:
            logger.error(f"[BurpParser] Issue parse error: {e}")
            return None

    @staticmethod
    def parse_issues_json(issues: List[Dict]) -> List[Dict[str, Any]]:
        """
        Parse issues from the REST API /burp/scanner/issues endpoint
        into the unified Finding format.

        Args:
            issues: List of issue dicts from the REST API

        Returns:
            List of finding dicts
        """
        findings = []
        for issue in issues:
            try:
                url = issue.get('url', '')
                name = issue.get('issueName', issue.get('name', 'Unknown'))
                severity = issue.get('severity', 'info').lower()
                confidence = issue.get('confidence', 'tentative').lower()

                parsed = urlparse(url)
                host = parsed.netloc or url

                finding = {
                    'target': host,
                    'url': url,
                    'vuln_type': name,
                    'severity': BurpReportParser.SEVERITY_MAP.get(severity, 'info'),
                    'confidence': BurpReportParser.CONFIDENCE_MAP.get(confidence, 'low'),
                    'description': issue.get('issueDetail', name),
                    'remediation': issue.get('remediationDetail', ''),
                    'evidence': '',
                    'source': 'burp_suite_pro',
                    'timestamp': datetime.utcnow().isoformat(),
                    'burp_type_id': str(issue.get('typeIndex', 0)),
                    'reproduction_steps': [
                        f"1. Navigate to: {url}",
                        f"2. Issue: {name}",
                        f"3. Severity: {severity} / Confidence: {confidence}",
                    ],
                }
                findings.append(finding)
            except Exception as e:
                logger.error(f"[BurpParser] JSON issue parse error: {e}")
                continue

        return findings


# =============================================================================
# BURP LAUNCHER
# =============================================================================

def launch_burp(jar_path: str, api_jar_path: str = "",
                port: int = 8090, headless: bool = True,
                config_file: str = "",
                java_path: str = "java") -> Optional[subprocess.Popen]:
    """
    Launch Burp Suite Professional in headless mode via burp-rest-api.

    Args:
        jar_path: Path to burpsuite_pro.jar
        api_jar_path: Path to burp-rest-api.jar (if empty, uses jar_path directly)
        port: REST API port (default 8090)
        headless: Run without GUI
        config_file: Optional Burp config file path
        java_path: Path to java executable

    Returns:
        subprocess.Popen instance, or None on failure
    """
    jar_path = Path(jar_path)
    if not jar_path.exists():
        logger.error(f"[Burp] JAR not found: {jar_path}")
        return None

    # Build command
    cmd = [java_path]

    if headless:
        cmd.extend(['-Djava.awt.headless=true'])

    cmd.extend(['-Xmx2G'])  # 2GB heap

    if api_jar_path:
        # Using burp-rest-api wrapper
        api_jar = Path(api_jar_path)
        if not api_jar.exists():
            logger.error(f"[Burp] API JAR not found: {api_jar}")
            return None
        cmd.extend([
            '-jar', str(api_jar),
            f'--burp.jar={jar_path}',
            f'--server.port={port}',
        ])
    else:
        # Direct Burp Pro headless (limited functionality)
        cmd.extend(['-jar', str(jar_path)])

    if config_file:
        cmd.extend([f'--config-file={config_file}'])

    logger.info(f"[Burp] Launching: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for API to become available
        api = BurpProAPI(f"http://localhost:{port}")
        for i in range(60):  # Wait up to 60 seconds
            time.sleep(1)
            if api.is_alive():
                logger.info(f"[Burp] API ready on port {port}")
                return proc

            # Check if process crashed
            if proc.poll() is not None:
                stderr = proc.stderr.read().decode('utf-8', errors='replace')
                logger.error(f"[Burp] Process exited with code {proc.returncode}: {stderr[:500]}")
                return None

        logger.error("[Burp] API did not become available within 60 seconds")
        proc.terminate()
        return None

    except FileNotFoundError:
        logger.error(f"[Burp] Java not found at: {java_path}")
        return None
    except Exception as e:
        logger.error(f"[Burp] Launch error: {e}")
        return None


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Burp Suite Pro Headless Scanner')
    parser.add_argument('--target', required=True, help='Target URL to scan')
    parser.add_argument('--api-url', default='http://localhost:8090',
                        help='Burp REST API URL (default: http://localhost:8090)')
    parser.add_argument('--api-key', default='', help='API key')
    parser.add_argument('--scan-type', default='active',
                        choices=['spider_only', 'passive', 'active'],
                        help='Scan type (default: active)')
    parser.add_argument('--output', default='results',
                        help='Output directory for reports')
    parser.add_argument('--report-format', default='XML',
                        choices=['XML', 'HTML'], help='Report format')
    parser.add_argument('--spider-timeout', type=int, default=600,
                        help='Spider timeout in seconds')
    parser.add_argument('--scan-timeout', type=int, default=3600,
                        help='Scan timeout in seconds')

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s [%(name)s] %(message)s')

    api = BurpProAPI(api_url=args.api_url, api_key=args.api_key)

    # Check connectivity
    if not api.is_alive():
        print(f"[!] Cannot reach Burp REST API at {args.api_url}")
        print(f"    Start it with: java -jar burp-rest-api.jar --burp.jar=burpsuite_pro.jar")
        exit(1)

    print(f"[+] Connected to Burp Pro at {args.api_url}")
    version = api.get_version()
    print(f"    Version: {version}")

    # Run scan
    print(f"[*] Starting {args.scan_type} scan on {args.target}")
    result = api.run_full_scan(
        target_url=args.target,
        scan_type=args.scan_type,
        spider_timeout=args.spider_timeout,
        scan_timeout=args.scan_timeout,
    )

    if result['errors']:
        for err in result['errors']:
            print(f"[!] {err}")

    # Parse findings
    findings = BurpReportParser.parse_issues_json(result['issues'])
    print(f"[+] Found {len(findings)} issues")

    for f in findings:
        sev = f['severity'].upper()
        print(f"    [{sev}] {f['vuln_type']} → {f['url']}")

    # Save report
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save JSON findings
    json_path = output_dir / 'burp_findings.json'
    with open(json_path, 'w') as fh:
        json.dump(findings, fh, indent=2, default=str)
    print(f"[+] JSON findings saved: {json_path}")

    # Download full report
    report = api.get_report(report_type=args.report_format, url_prefix=args.target)
    if report:
        ext = 'xml' if args.report_format == 'XML' else 'html'
        report_path = output_dir / f'burp_report.{ext}'
        with open(report_path, 'w', encoding='utf-8') as fh:
            fh.write(report)
        print(f"[+] Full report saved: {report_path}")

    # Summary
    print(f"\n{'='*50}")
    print(f"  Burp Scan Summary")
    print(f"{'='*50}")
    print(f"  Target:     {args.target}")
    print(f"  Issues:     {len(findings)}")
    print(f"  Sitemap:    {result['sitemap_count']} entries")
    print(f"  Timings:    {result['timings']}")
    if result['errors']:
        print(f"  Errors:     {len(result['errors'])}")
    print(f"{'='*50}")
