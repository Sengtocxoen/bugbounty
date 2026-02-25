#!/usr/bin/env python3
"""
Results Aggregator - Combines findings from all scanning tools
==============================================================
Reads results from: vuln_scanner_v2, nuclei, nikto, sqlmap, ffuf
Produces a unified bug bounty report with severity ratings.
"""

import json
import os
import re
import glob
from datetime import datetime
from pathlib import Path
from collections import defaultdict


def parse_vuln_scanner_results(results_base):
    """Parse results from vuln_scanner_v2.py"""
    findings = []
    # Find the most recent comprehensive scan directory
    scan_dirs = sorted(glob.glob(str(results_base / "comprehensive_scan_*")))
    if not scan_dirs:
        return findings

    latest = Path(scan_dirs[-1])
    report_file = latest / "FINAL_REPORT.json"
    if not report_file.exists():
        return findings

    with open(report_file) as f:
        data = json.load(f)

    for finding in data.get("findings", []):
        # Scanner uses "type" and "detail" fields
        vuln_type = finding.get("type", finding.get("title", "Unknown"))
        detail = finding.get("detail", finding.get("description", ""))
        findings.append({
            "tool": "vuln_scanner_v2",
            "severity": finding.get("severity", "info").upper(),
            "title": f"{vuln_type}: {detail}" if detail else vuln_type,
            "url": finding.get("url", ""),
            "description": f"CWE: {finding.get('cwe', 'N/A')} | Method: {finding.get('method', '')} | Param: {finding.get('parameter', '')}",
            "evidence": finding.get("evidence", ""),
            "category": vuln_type,
        })
    return findings


def parse_nuclei_results(results_base):
    """Parse nuclei JSONL results"""
    findings = []
    nuclei_file = results_base / "nuclei_v2" / "nuclei_results.jsonl"
    if not nuclei_file.exists():
        return findings

    with open(nuclei_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                findings.append({
                    "tool": "nuclei",
                    "severity": info.get("severity", "info").upper(),
                    "title": info.get("name", data.get("template-id", "Unknown")),
                    "url": data.get("matched-at", data.get("url", "")),
                    "description": info.get("description", ""),
                    "evidence": f"Template: {data.get('template-id', '')}",
                    "category": ", ".join(info.get("tags", [])) if isinstance(info.get("tags"), list) else str(info.get("tags", "")),
                })
            except json.JSONDecodeError:
                continue
    return findings


def parse_nikto_results(results_base):
    """Parse nikto text results"""
    findings = []
    nikto_file = results_base / "nikto_v2" / "nikto_results.txt"
    if not nikto_file.exists():
        return findings

    with open(nikto_file) as f:
        for line in f:
            line = line.strip()
            if not line.startswith("+"):
                continue
            # Skip backup/cert file noise (false positives from Juice Shop returning 200 for everything)
            if "backup/cert file found" in line:
                continue
            if "Target" in line and ("Host:" in line or "Port:" in line):
                continue

            # Extract the finding
            # Format: + METHOD /path: Description
            match = re.match(r'\+\s+(\w+)\s+(.+?):\s+(.+)', line)
            if match:
                method = match.group(1)
                path = match.group(2)
                desc = match.group(3)

                severity = "LOW"
                if any(kw in desc.lower() for kw in ["xss", "injection", "rce", "exec"]):
                    severity = "HIGH"
                elif any(kw in desc.lower() for kw in ["interesting", "directory", "listing", "robots"]):
                    severity = "MEDIUM"
                elif any(kw in desc.lower() for kw in ["header", "cookie", "x-content"]):
                    severity = "LOW"

                findings.append({
                    "tool": "nikto",
                    "severity": severity,
                    "title": f"Nikto: {desc[:80]}",
                    "url": path,
                    "description": desc,
                    "evidence": f"{method} {path}",
                    "category": "Web Server",
                })
    return findings


def parse_wapiti_results(results_base):
    """Parse wapiti JSON results"""
    findings = []
    wapiti_base = results_base / "wapiti"
    if not wapiti_base.exists():
        # Also check under external_scanners subdirectories
        for ext_dir in results_base.rglob("external_scanners"):
            wb = ext_dir / "wapiti"
            if wb.exists():
                wapiti_base = wb
                break
    if not wapiti_base.exists():
        return findings

    for json_file in wapiti_base.rglob("*.json"):
        try:
            with open(json_file) as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            continue

        vuln_dict = data.get("vulnerabilities", {})
        if not isinstance(vuln_dict, dict):
            continue

        for vuln_type, vuln_list in vuln_dict.items():
            if not isinstance(vuln_list, list):
                continue
            for v in vuln_list:
                sev = v.get("level", "low")
                if isinstance(sev, int):
                    sev = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}.get(sev, "LOW")
                else:
                    sev = str(sev).upper()

                findings.append({
                    "tool": "wapiti",
                    "severity": sev,
                    "title": f"{vuln_type}: {v.get('info', '')[:80]}",
                    "url": v.get("path", v.get("url", "")),
                    "description": v.get("info", ""),
                    "evidence": f"Method: {v.get('method', '')} | Param: {v.get('parameter', '')}",
                    "category": vuln_type,
                })

    return findings


def parse_sqlmap_results(results_base):
    """Parse sqlmap log results from all subdirectories"""
    findings = []
    sqlmap_base = results_base / "sqlmap_v2"
    if not sqlmap_base.exists():
        return findings

    seen_params = set()

    # Recursively find all 'log' files in sqlmap output dirs (target IP dirs)
    for log_file in sqlmap_base.rglob("log"):
        with open(log_file) as f:
            content = f.read()

        if "sqlmap identified the following injection" not in content:
            continue

        # Extract parameter and type
        param_match = re.search(r"Parameter:\s+(.+?)(?:\s*\()", content)
        type_match = re.search(r"Type:\s+(.+)", content)
        payload_match = re.search(r"Payload:\s+(.+)", content)
        dbms_match = re.search(r"back-end DBMS:\s+(.+)", content)

        param_name = param_match.group(1).strip() if param_match else "Unknown"
        if param_name in seen_params:
            continue
        seen_params.add(param_name)

        findings.append({
            "tool": "sqlmap",
            "severity": "CRITICAL",
            "title": f"SQL Injection (sqlmap confirmed) - {param_name}",
            "url": str(log_file.parent.name),
            "description": f"SQLMap confirmed SQL injection. DBMS: {dbms_match.group(1) if dbms_match else 'Unknown'}. "
                          f"Type: {type_match.group(1) if type_match else 'Unknown'}",
            "evidence": f"Payload: {payload_match.group(1)[:200] if payload_match else 'N/A'}",
            "category": "SQL Injection",
        })

    # Also check stdout logs for vulnerability confirmation
    for log_file in sqlmap_base.rglob("*.log"):
        with open(log_file) as f:
            content = f.read()

        if "is vulnerable" in content and "sqlmap identified the following injection" in content:
            param_match = re.search(r"Parameter:\s+(.+?)(?:\s*\()", content)
            param_name = param_match.group(1).strip() if param_match else "Unknown"
            if param_name in seen_params:
                continue
            seen_params.add(param_name)

            type_match = re.search(r"Type:\s+(.+)", content)
            payload_match = re.search(r"Payload:\s+(.+)", content)

            findings.append({
                "tool": "sqlmap",
                "severity": "CRITICAL",
                "title": f"SQL Injection (sqlmap confirmed) - {param_name}",
                "url": log_file.stem,
                "description": f"Type: {type_match.group(1) if type_match else 'Unknown'}",
                "evidence": f"Payload: {payload_match.group(1)[:200] if payload_match else 'N/A'}",
                "category": "SQL Injection",
            })

    return findings


def parse_ffuf_results(results_base):
    """Parse ffuf JSON results"""
    findings = []
    ffuf_base = results_base / "ffuf_v2"
    if not ffuf_base.exists():
        return findings

    for json_file in ffuf_base.glob("*.json"):
        try:
            with open(json_file) as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            continue

        results = data.get("results", [])
        # Find noise by grouping similar response lengths (within 50 bytes)
        from collections import Counter
        all_lengths = [r.get("length", 0) for r in results]
        # Round to nearest 100 to cluster similar error pages
        rounded = Counter([l // 100 * 100 for l in all_lengths])
        noise_ranges = {bucket for bucket, c in rounded.most_common(5) if c > len(results) * 0.15}
        noise_lengths = set()
        for l in set(all_lengths):
            if l // 100 * 100 in noise_ranges:
                noise_lengths.add(l)

        for result in results:
            status = result.get("status", 0)
            url = result.get("url", "")
            length = result.get("length", 0)
            word = result.get("input", {}).get("FUZZ", "")

            # Skip responses with the most common length (SPA/error page noise)
            if length in noise_lengths:
                continue
            # Skip very small responses
            if length < 100:
                continue
            # Skip 404s
            if status == 404:
                continue

            severity = "INFO"
            if any(kw in word.lower() for kw in ["admin", "backup", "config", "debug", "env", "secret", ".env", "passwd"]):
                severity = "MEDIUM"
            elif any(kw in word.lower() for kw in ["api", "ftp", "upload", "swagger", "graphql"]):
                severity = "LOW"

            findings.append({
                "tool": "ffuf",
                "severity": severity,
                "title": f"Directory/Endpoint Found: /{word}",
                "url": url,
                "description": f"HTTP {status}, {length} bytes",
                "evidence": f"Status: {status}, Length: {length}",
                "category": "Content Discovery",
            })
    return findings


def parse_webhack2025_results(results_base):
    """Parse web_hacking_2025 scanner results"""
    findings = []
    wh_base = results_base / "webhack2025_parallel"
    if not wh_base.exists():
        return findings

    # Find all findings JSON files
    for severity in ["critical", "high", "medium", "low", "info"]:
        for json_file in wh_base.rglob(f"{severity}_findings.json"):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                finding_list = data.get("findings", []) if isinstance(data, dict) else data
                for finding in finding_list:
                    findings.append({
                        "tool": "web_hacking_2025",
                        "severity": finding.get("severity", severity).upper(),
                        "title": finding.get("title", "Unknown"),
                        "url": finding.get("evidence", ""),
                        "description": finding.get("description", ""),
                        "evidence": finding.get("evidence", ""),
                        "category": finding.get("technique", finding.get("category", "")),
                    })
            except (json.JSONDecodeError, FileNotFoundError):
                continue

    return findings


def parse_vuln_v2_parallel(results_base):
    """Parse vuln_scanner_v2 parallel results (from vuln_v2_parallel dir)"""
    findings = []
    v2_dir = results_base / "vuln_v2_parallel"
    if not v2_dir.exists():
        return findings

    report_file = v2_dir / "FINAL_REPORT.json"
    if not report_file.exists():
        return findings

    with open(report_file) as f:
        data = json.load(f)

    for finding in data.get("findings", []):
        vuln_type = finding.get("type", "Unknown")
        detail = finding.get("detail", "")
        findings.append({
            "tool": "vuln_scanner_v2",
            "severity": finding.get("severity", "info").upper(),
            "title": f"{vuln_type}: {detail}" if detail else vuln_type,
            "url": finding.get("url", ""),
            "description": f"CWE: {finding.get('cwe', 'N/A')} | Method: {finding.get('method', '')} | Param: {finding.get('parameter', '')}",
            "evidence": finding.get("evidence", ""),
            "category": vuln_type,
        })
    return findings


def deduplicate_findings(findings):
    """Remove duplicate findings based on URL + category + title similarity.
    When two findings collide on the same key, keep the higher-severity one."""
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    seen = {}  # key -> index in unique list
    unique = []
    for f in findings:
        url_norm = f["url"].rstrip("/").lower() if f["url"] else ""
        category_norm = re.sub(r'[^a-z0-9]', '', (f.get("category") or "").lower())
        title_norm = re.sub(r'[^a-z0-9]', '', f["title"].lower())[:100]
        key = f"{url_norm}|{category_norm}|{title_norm}"
        if key not in seen:
            seen[key] = len(unique)
            unique.append(f)
        else:
            # Keep higher severity
            existing_idx = seen[key]
            existing_sev = severity_rank.get(unique[existing_idx]["severity"], 5)
            new_sev = severity_rank.get(f["severity"], 5)
            if new_sev < existing_sev:
                unique[existing_idx] = f
    return unique


def generate_report(findings, output_dir):
    """Generate unified bug bounty report"""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 5))

    # Count by severity
    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1

    # Count by tool
    tool_counts = defaultdict(int)
    for f in findings:
        tool_counts[f["tool"]] += 1

    # Text report
    lines = []
    lines.append("=" * 80)
    lines.append("UNIFIED BUG BOUNTY VULNERABILITY REPORT")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"Total Unique Findings: {len(findings)}")
    lines.append("")
    lines.append("SEVERITY BREAKDOWN:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts[sev] > 0:
            lines.append(f"  {sev}: {counts[sev]}")
    lines.append("")
    lines.append("FINDINGS BY TOOL:")
    for tool, count in sorted(tool_counts.items()):
        lines.append(f"  {tool}: {count}")
    lines.append("")
    lines.append("-" * 80)

    current_severity = None
    for i, f in enumerate(findings, 1):
        if f["severity"] != current_severity:
            current_severity = f["severity"]
            lines.append("")
            lines.append(f"{'=' * 40}")
            lines.append(f"  {current_severity} SEVERITY FINDINGS")
            lines.append(f"{'=' * 40}")

        lines.append("")
        lines.append(f"[{i}] [{f['severity']}] {f['title']}")
        lines.append(f"    Tool: {f['tool']}")
        lines.append(f"    URL: {f['url']}")
        if f["category"]:
            lines.append(f"    Category: {f['category']}")
        if f["description"]:
            lines.append(f"    Description: {f['description'][:200]}")
        if f["evidence"]:
            lines.append(f"    Evidence: {f['evidence'][:200]}")

    lines.append("")
    lines.append("=" * 80)
    lines.append("END OF REPORT")
    lines.append("=" * 80)

    report_text = "\n".join(lines)

    # Save text report
    text_path = output_dir / "UNIFIED_REPORT.txt"
    with open(text_path, "w") as f:
        f.write(report_text)

    # Save JSON report
    json_path = output_dir / "UNIFIED_REPORT.json"
    with open(json_path, "w") as f:
        json.dump({
            "generated": datetime.now().isoformat(),
            "total_findings": len(findings),
            "severity_counts": dict(counts),
            "tool_counts": dict(tool_counts),
            "findings": findings,
        }, f, indent=2)

    return report_text, text_path, json_path


def _auto_detect_results_dir():
    """Try to detect results directory from scan_config.yaml"""
    config_path = Path("scan_config.yaml")
    if not config_path.exists():
        config_path = Path(__file__).parent.parent / "scan_config.yaml"
    if config_path.exists():
        try:
            import yaml
            with open(config_path) as f:
                data = yaml.safe_load(f)
            output_dir = data.get('output', {}).get('directory', '')
            if output_dir:
                p = Path(output_dir)
                if p.exists():
                    return p
        except Exception:
            pass
    return None


def aggregate_results(results_base: Path, output_dir: Path = None):
    """Aggregate results from a given results directory. Returns (unique_findings, output_dir)."""
    if output_dir is None:
        output_dir = results_base / "unified_report"
    output_dir.mkdir(parents=True, exist_ok=True)

    print("[*] Aggregating results from all scanning tools...")

    all_findings = []

    parsers = [
        ("vuln_scanner_v2 results (comprehensive)", parse_vuln_scanner_results),
        ("vuln_scanner_v2 results (parallel run)", parse_vuln_v2_parallel),
        ("web_hacking_2025 results", parse_webhack2025_results),
        ("nuclei results", parse_nuclei_results),
        ("nikto results", parse_nikto_results),
        ("wapiti results", parse_wapiti_results),
        ("sqlmap results", parse_sqlmap_results),
        ("ffuf results", parse_ffuf_results),
    ]

    for name, parser in parsers:
        print(f"[+] Parsing {name}...")
        findings = parser(results_base)
        print(f"    Found {len(findings)} findings")
        all_findings.extend(findings)

    print(f"\n[*] Total findings before dedup: {len(all_findings)}")
    unique_findings = deduplicate_findings(all_findings)
    print(f"[*] Unique findings after dedup: {len(unique_findings)}")

    report_text, text_path, json_path = generate_report(unique_findings, output_dir)
    print(f"\n[+] Text report saved to: {text_path}")
    print(f"[+] JSON report saved to: {json_path}")

    return unique_findings, output_dir


def main():
    import argparse as _argparse
    parser = _argparse.ArgumentParser(
        description="Aggregate vulnerability scan results into a unified report"
    )
    parser.add_argument(
        "results_dir", nargs="?", default=None,
        help="Results directory (auto-detects from scan_config.yaml if omitted)"
    )
    parser.add_argument(
        "-o", "--output", default=None,
        help="Output directory for the unified report"
    )
    args = parser.parse_args()

    # Determine results directory
    if args.results_dir:
        results_base = Path(args.results_dir)
    else:
        results_base = _auto_detect_results_dir()
        if results_base is None:
            print("[!] No results directory specified and could not auto-detect from scan_config.yaml")
            print("    Usage: python aggregate_results.py /path/to/results [-o /path/to/output]")
            return

    if not results_base.exists():
        print(f"[!] Results directory not found: {results_base}")
        return

    output_dir = Path(args.output) if args.output else None

    unique_findings, out = aggregate_results(results_base, output_dir)
    print(f"\n[+] Aggregation complete: {len(unique_findings)} unique findings in {out}")


if __name__ == "__main__":
    main()
