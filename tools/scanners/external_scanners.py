#!/usr/bin/env python3
"""
External Scanners Module
========================
Wrapper for nikto, wapiti, and nuclei (fixed invocation).
Each tool runs as a subprocess with configurable timeouts.
Results are parsed into a unified format.
"""

import json
import subprocess
import logging
import re
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime


logger = logging.getLogger('ExternalScanners')


class ExternalScanners:
    """Orchestrates nikto, wapiti, and nuclei scans with unified output."""

    def __init__(self, output_dir: Path, config: Optional[Dict[str, Any]] = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.config = config or {}

    # ------------------------------------------------------------------
    # nikto
    # ------------------------------------------------------------------
    def run_nikto(self, target: str, output_dir: Path,
                  timeout: int = 0) -> List[Dict]:
        """Run nikto against a single target and return findings."""
        findings: List[Dict] = []
        output_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r'[^a-zA-Z0-9._-]', '_', target)
        json_file = output_dir / f"nikto_{safe}.json"

        url = target if target.startswith('http') else f"https://{target}"

        cmd = [
            'nikto', '-h', url,
            '-Format', 'json',
            '-output', str(json_file),
            '-Tuning', '1234567890abc',
        ]

        logger.info(f"[nikto] Running: {' '.join(cmd)}")
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                check=False,
            )
            logger.info(f"[nikto] exit code {proc.returncode}")
        except FileNotFoundError:
            logger.error("[nikto] binary not found — skipping")
            return findings

        # Parse JSON output
        if json_file.exists():
            try:
                with open(json_file) as f:
                    data = json.load(f)

                # nikto JSON can be a dict with key "vulnerabilities" or a list
                vulns = []
                if isinstance(data, dict):
                    vulns = data.get('vulnerabilities', [])
                    # Sometimes nikto wraps in {"host": ..., "ip": ..., "vulnerabilities": [...]}
                    if not vulns and 'host' in data:
                        vulns = data.get('vulnerabilities', [])
                elif isinstance(data, list):
                    vulns = data

                for v in vulns:
                    sev = self._nikto_severity(v)
                    findings.append({
                        'tool': 'nikto',
                        'severity': sev,
                        'title': v.get('msg', v.get('id', 'Unknown')),
                        'url': v.get('url', url),
                        'description': v.get('msg', ''),
                        'evidence': f"OSVDB-{v.get('OSVDB', 'N/A')} | Method: {v.get('method', '')}",
                        'category': 'Web Server',
                    })
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"[nikto] JSON parse error: {e}")

        # Fallback: parse text output from stdout
        if not findings and 'proc' in dir():
            findings.extend(self._parse_nikto_text(proc.stdout, url))

        logger.info(f"[nikto] {len(findings)} findings for {target}")
        return findings

    @staticmethod
    def _nikto_severity(vuln: dict) -> str:
        msg = (vuln.get('msg', '') + ' ' + str(vuln.get('id', ''))).lower()
        if any(kw in msg for kw in ['xss', 'injection', 'rce', 'exec', 'remote code']):
            return 'high'
        if any(kw in msg for kw in ['directory listing', 'interesting', 'default', 'backup']):
            return 'medium'
        return 'low'

    @staticmethod
    def _parse_nikto_text(text: str, base_url: str) -> List[Dict]:
        """Parse nikto plain-text stdout as fallback."""
        findings = []
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith('+'):
                continue
            if 'Target' in line and ('Host:' in line or 'Port:' in line):
                continue
            m = re.match(r'\+\s+(\w+)\s+(.+?):\s+(.+)', line)
            if m:
                sev = 'low'
                desc = m.group(3)
                if any(kw in desc.lower() for kw in ['xss', 'injection', 'rce']):
                    sev = 'high'
                elif any(kw in desc.lower() for kw in ['interesting', 'directory', 'listing']):
                    sev = 'medium'
                findings.append({
                    'tool': 'nikto',
                    'severity': sev,
                    'title': f"Nikto: {desc[:80]}",
                    'url': base_url + m.group(2),
                    'description': desc,
                    'evidence': f"{m.group(1)} {m.group(2)}",
                    'category': 'Web Server',
                })
        return findings

    # ------------------------------------------------------------------
    # wapiti
    # ------------------------------------------------------------------
    def run_wapiti(self, target: str, output_dir: Path,
                   timeout: int = 0) -> List[Dict]:
        """Run wapiti against a single target and return findings."""
        findings: List[Dict] = []
        output_dir.mkdir(parents=True, exist_ok=True)

        url = target if target.startswith('http') else f"https://{target}"

        # wapiti writes JSON into <output_dir>
        cmd = [
            'wapiti', '-u', url,
            '-f', 'json',
            '-o', str(output_dir),
            '--flush-attacks', '--flush-session',
            '-m', 'all',
            '--scope', 'url',
        ]

        logger.info(f"[wapiti] Running: {' '.join(cmd)}")
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                check=False,
            )
            logger.info(f"[wapiti] exit code {proc.returncode}")
        except FileNotFoundError:
            logger.error("[wapiti] binary not found — skipping")
            return findings

        # Wapiti writes JSON report(s) in output_dir or a subdirectory
        findings.extend(self._parse_wapiti_dir(output_dir, url))
        logger.info(f"[wapiti] {len(findings)} findings for {target}")
        return findings

    @staticmethod
    def _parse_wapiti_dir(output_dir: Path, base_url: str) -> List[Dict]:
        """Find and parse wapiti JSON report files in the output directory."""
        findings: List[Dict] = []

        # Wapiti may write to output_dir directly or into .wapiti/scans/...
        json_files = list(output_dir.rglob('*.json'))
        for jf in json_files:
            try:
                with open(jf) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            # Wapiti JSON structure: {"vulnerabilities": {"Vuln Type": [...]}, ...}
            # or {"classifications": ..., "vulnerabilities": ...}
            vuln_dict = data.get('vulnerabilities', {})
            if not isinstance(vuln_dict, dict):
                continue

            for vuln_type, vuln_list in vuln_dict.items():
                if not isinstance(vuln_list, list):
                    continue
                for v in vuln_list:
                    sev = v.get('level', 'low')
                    # wapiti levels: 1=low, 2=medium, 3=high, 4=critical
                    if isinstance(sev, int):
                        sev = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}.get(sev, 'low')

                    findings.append({
                        'tool': 'wapiti',
                        'severity': str(sev).lower(),
                        'title': f"{vuln_type}: {v.get('info', '')[:80]}",
                        'url': v.get('path', v.get('url', base_url)),
                        'description': v.get('info', ''),
                        'evidence': f"Method: {v.get('method', '')} | Param: {v.get('parameter', '')} | Payload: {str(v.get('payload', ''))[:120]}",
                        'category': vuln_type,
                    })

            # Also parse "anomalies" section if present
            anomaly_dict = data.get('anomalies', {})
            if isinstance(anomaly_dict, dict):
                for anomaly_type, anomaly_list in anomaly_dict.items():
                    if not isinstance(anomaly_list, list):
                        continue
                    for a in anomaly_list:
                        findings.append({
                            'tool': 'wapiti',
                            'severity': 'low',
                            'title': f"{anomaly_type}: {a.get('info', '')[:80]}",
                            'url': a.get('path', a.get('url', base_url)),
                            'description': a.get('info', ''),
                            'evidence': f"Method: {a.get('method', '')} | Param: {a.get('parameter', '')}",
                            'category': anomaly_type,
                        })

        return findings

    # ------------------------------------------------------------------
    # nuclei (fixed invocation — no -tags filter)
    # ------------------------------------------------------------------
    def run_nuclei(self, targets: List[str], output_dir: Path,
                   timeout: int = 0,
                   technologies: Optional[Dict] = None) -> List[Dict]:
        """Run nuclei with ALL templates (no -tags filter) against targets."""
        findings: List[Dict] = []
        if not targets:
            return findings

        output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_out = output_dir / f'nuclei_{ts}.json'
        targets_file = output_dir / f'nuclei_targets_{ts}.txt'

        with open(targets_file, 'w') as f:
            f.write('\n'.join(targets))

        # Build command — NO -tags flag so nuclei uses ALL templates
        cmd = ['nuclei']

        # Severity filter
        severity = self.config.get('nuclei_severity',
                                   self.config.get('severity', ['critical', 'high', 'medium']))
        if severity:
            cmd.extend(['-severity', ','.join(severity)])

        # Exclude tags (dos, fuzzing, intrusive)
        exclude_tags = self.config.get('nuclei_exclude_tags',
                                       self.config.get('exclude_tags', ['dos', 'fuzzing', 'intrusive']))
        if exclude_tags:
            cmd.extend(['-exclude-tags', ','.join(exclude_tags)])

        # Custom headers (-H "Name: Value") — read from config custom_headers
        custom_headers = self.config.get('custom_headers', {})
        for name, value in custom_headers.items():
            if value:
                cmd.extend(['-H', f'{name}: {value}'])

        # Nuclei native config file (-config path) — for advanced auth/headers
        nuclei_config_file = self.config.get('nuclei_config_file')
        if nuclei_config_file and Path(nuclei_config_file).exists():
            cmd.extend(['-config', nuclei_config_file])

        # Per-request timeout (seconds per individual HTTP request)
        cmd.extend(['-timeout', '10'])

        # Concurrency
        threads = self.config.get('threads', 3)
        cmd.extend(['-c', str(threads)])

        # Rate limit
        rate_limit = self.config.get('rate_limit', 100)
        if rate_limit:
            cmd.extend(['-rate-limit', str(rate_limit)])

        # Output
        cmd.extend([
            '-json', '-o', str(json_out),
            '-silent', '-no-color',
            '-list', str(targets_file),
        ])

        logger.info(f"[nuclei] Running: {' '.join(cmd)}")
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                check=False,
            )
            logger.info(f"[nuclei] exit code {proc.returncode}")
        except FileNotFoundError:
            logger.error("[nuclei] binary not found — skipping")
            return findings
        finally:
            targets_file.unlink(missing_ok=True)

        # Parse JSONL output
        if json_out.exists():
            try:
                with open(json_out) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            r = json.loads(line)
                            info = r.get('info', {})
                            classification = info.get('classification', {})
                            findings.append({
                                'tool': 'nuclei',
                                'severity': info.get('severity', 'info'),
                                'title': info.get('name', r.get('template-id', 'Unknown')),
                                'url': r.get('matched-at', ''),
                                'description': info.get('description', ''),
                                'evidence': f"Template: {r.get('template-id', '')} | Tags: {', '.join(info.get('tags', []))}",
                                'category': ', '.join(info.get('tags', [])),
                                'template_id': r.get('template-id', ''),
                                'remediation': info.get('remediation', ''),
                                'reference': info.get('reference', []),
                                'cwe': ', '.join(classification.get('cwe-id', [])) if classification.get('cwe-id') else '',
                                'cvss': classification.get('cvss-score', ''),
                            })
                        except json.JSONDecodeError:
                            continue
            except OSError as e:
                logger.error(f"[nuclei] failed to read output: {e}")

        logger.info(f"[nuclei] {len(findings)} findings")
        return findings

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------
    def scan_all(self, targets: List[str], output_dir: Path,
                 config: Optional[Dict] = None,
                 nuclei_targets: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run all enabled external scanners against the targets.

        Args:
            targets: Root URLs for nikto/wapiti (they crawl from root).
            output_dir: Output directory for results.
            config: Scanner config dict.
            nuclei_targets: Expanded URL list for nuclei (root URLs + discovered
                            endpoints + API endpoints). If None, uses targets.

        Returns dict with keys: nikto, wapiti, nuclei, all_findings, summary.
        """
        cfg = config or self.config
        results: Dict[str, Any] = {
            'nikto': [], 'wapiti': [], 'nuclei': [],
            'all_findings': [], 'summary': {},
        }

        scan_start = datetime.now()

        # --- nikto (per root target — it crawls from there) ---
        if cfg.get('nikto', True):
            nikto_dir = output_dir / 'nikto'
            for t in targets:
                url = t if t.startswith('http') else f"https://{t}"
                r = self.run_nikto(url, nikto_dir)
                results['nikto'].extend(r)
                results['all_findings'].extend(r)

        # --- wapiti (per root target — it crawls from there) ---
        if cfg.get('wapiti', True):
            for t in targets:
                url = t if t.startswith('http') else f"https://{t}"
                safe = re.sub(r'[^a-zA-Z0-9._-]', '_', url)
                wapiti_dir = output_dir / 'wapiti' / safe
                r = self.run_wapiti(url, wapiti_dir)
                results['wapiti'].extend(r)
                results['all_findings'].extend(r)

        # --- nuclei (all discovered URLs — it tests templates per URL) ---
        if cfg.get('nuclei', True):
            nuclei_dir = output_dir / 'nuclei'
            urls_for_nuclei = nuclei_targets if nuclei_targets else targets
            nuclei_urls = []
            for t in urls_for_nuclei:
                nuclei_urls.append(t if t.startswith('http') else f"https://{t}")
            r = self.run_nuclei(nuclei_urls, nuclei_dir)
            results['nuclei'].extend(r)
            results['all_findings'].extend(r)

        scan_end = datetime.now()
        duration = (scan_end - scan_start).total_seconds()

        # Severity counts
        by_severity: Dict[str, int] = {}
        for f in results['all_findings']:
            s = f.get('severity', 'info').lower()
            by_severity[s] = by_severity.get(s, 0) + 1

        results['summary'] = {
            'scan_start': scan_start.isoformat(),
            'scan_end': scan_end.isoformat(),
            'duration_seconds': duration,
            'root_targets_scanned': len(targets),
            'nuclei_targets_scanned': len(nuclei_targets if nuclei_targets else targets),
            'targets_scanned': len(targets),
            'total_findings': len(results['all_findings']),
            'by_severity': by_severity,
            'by_tool': {
                'nikto': len(results['nikto']),
                'wapiti': len(results['wapiti']),
                'nuclei': len(results['nuclei']),
            },
        }

        # Save combined JSON
        combined_file = output_dir / 'external_scanners_combined.json'
        try:
            with open(combined_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        except OSError as e:
            logger.error(f"Failed to save combined results: {e}")

        logger.info(
            f"[external_scanners] Done: {len(results['all_findings'])} total findings "
            f"in {duration:.1f}s (nikto={len(results['nikto'])}, "
            f"wapiti={len(results['wapiti'])}, nuclei={len(results['nuclei'])})"
        )

        return results
