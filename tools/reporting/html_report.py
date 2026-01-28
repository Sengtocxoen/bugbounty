#!/usr/bin/env python3
"""
HTML Report Generator
Generates professional HTML reports for bug bounty findings
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from html import escape


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Scan Report - {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        
        .header .target {{
            font-size: 1.3em;
            opacity: 0.95;
            font-weight: 300;
        }}
        
        .header .scan-time {{
            margin-top: 10px;
            opacity: 0.8;
            font-size: 0.9em;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        
        .summary-card {{
            background: white;
            padding: 25px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }}
        
        .summary-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.15);
        }}
        
        .summary-card .number {{
            font-size: 2.5em;
            font-weight: 700;
            color: #667eea;
            margin-bottom: 5px;
        }}
        
        .summary-card .label {{
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .summary-card.critical .number {{ color: #dc3545; }}
        .summary-card.high .number {{ color: #fd7e14; }}
        .summary-card.medium .number {{ color: #ffc107; }}
        .summary-card.low .number {{ color: #28a745; }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section-title {{
            font-size: 1.8em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
            color: #2d3748;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .severity-critical {{
            background: #dc3545;
            color: white;
        }}
        
        .severity-high {{
            background: #fd7e14;
            color: white;
        }}
        
        .severity-medium {{
            background: #ffc107;
            color: #333;
        }}
        
        .severity-low {{
            background: #28a745;
            color: white;
        }}
        
        .severity-info {{
            background: #17a2b8;
            color: white;
        }}
        
        .finding-card {{
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 6px;
            transition: all 0.2s;
        }}
        
        .finding-card:hover {{
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            background: #fff;
        }}
        
        .finding-card.critical {{
            border-left-color: #dc3545;
        }}
        
        .finding-card.high {{
            border-left-color: #fd7e14;
        }}
        
        .finding-card.medium {{
            border-left-color: #ffc107;
        }}
        
        .finding-card.low {{
            border-left-color: #28a745;
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .finding-title {{
            font-size: 1.2em;
            font-weight: 600;
            color: #2d3748;
        }}
        
        .finding-details {{
            margin-top: 10px;
        }}
        
        .detail-row {{
            margin-bottom: 10px;
            line-height: 1.6;
        }}
        
        .detail-label {{
            font-weight: 600;
            color: #4a5568;
            margin-right: 8px;
        }}
        
        .code-block {{
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin-top: 10px;
        }}
        
        .subdomain-list {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 10px;
            margin-top: 15px;
        }}
        
        .subdomain-item {{
            background: white;
            padding: 12px;
            border-radius: 6px;
            border: 1px solid #e2e8f0;
            font-size: 0.9em;
        }}
        
        .subdomain-item.alive {{
            border-left: 3px solid #28a745;
        }}
        
        .subdomain-item.dead {{
            opacity: 0.6;
        }}
        
        .endpoint-method {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.75em;
            font-weight: 700;
            margin-right: 8px;
        }}
        
        .method-GET {{ background: #28a745; color: white; }}
        .method-POST {{ background: #007bff; color: white; }}
        .method-PUT {{ background: #fd7e14; color: white; }}
        .method-DELETE {{ background: #dc3545; color: white; }}
        
        .footer {{
            background: #2d3748;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }}
        
        .collapsible {{
            cursor: pointer;
            user-select: none;
        }}
        
        .collapsible:hover {{
            opacity: 0.8;
        }}
        
        .collapse-content {{
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }}
        
        .collapse-content.active {{
            max-height: 5000px;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            .container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Bug Bounty Scan Report</h1>
            <div class="target">{target}</div>
            <div class="scan-time">Scan Date: {scan_time}</div>
            {program_badge}
        </div>
        
        <div class="summary">
            {summary_cards}
        </div>
        
        <div class="content">
            {content_sections}
        </div>
        
        <div class="footer">
            Generated by Enhanced Bug Bounty Scanner | {generated_time}
        </div>
    </div>
    
    <script>
        // Collapsible sections
        document.querySelectorAll('.collapsible').forEach(item => {{
            item.addEventListener('click', function() {{
                this.classList.toggle('active');
                const content = this.nextElementSibling;
                content.classList.toggle('active');
            }});
        }});
    </script>
</body>
</html>
"""


def generate_summary_card(number: int, label: str, severity: str = "") -> str:
    """Generate a summary card HTML"""
    severity_class = f"class=\"summary-card {severity}\"" if severity else "class=\"summary-card\""
    return f"""
    <div {severity_class}>
        <div class="number">{number}</div>
        <div class="label">{label}</div>
    </div>
    """


def generate_finding_card(finding: Dict, finding_type: str) -> str:
    """Generate a finding card HTML"""
    severity = finding.get('severity', 'info')
    title = finding.get('title', finding.get('finding', finding.get('type', 'Unknown')))
    
    details_html = []
    
    # Add common details
    if 'url' in finding:
        details_html.append(f'<div class="detail-row"><span class="detail-label">URL:</span><code>{escape(finding["url"])}</code></div>')
    
    if 'host' in finding and 'port' in finding:
        details_html.append(f'<div class="detail-row"><span class="detail-label">Target:</span>{finding["host"]}:{finding["port"]}</div>')
    
    if 'description' in finding:
        details_html.append(f'<div class="detail-row"><span class="detail-label">Description:</span>{escape(finding["description"])}</div>')
    
    if 'payload' in finding:
        details_html.append(f'<div class="detail-row"><span class="detail-label">Payload:</span><div class="code-block">{escape(finding["payload"])}</div></div>')
    
    if 'evidence' in finding:
        details_html.append(f'<div class="detail-row"><span class="detail-label">Evidence:</span><div class="code-block">{escape(str(finding["evidence"])[:500])}</div></div>')
    
    if 'remediation' in finding:
        details_html.append(f'<div class="detail-row"><span class="detail-label">Remediation:</span>{escape(finding["remediation"])}</div>')
    
    if 'value' in finding and finding_type == 'secret':
        details_html.append(f'<div class="detail-row"><span class="detail-label">Value:</span><code>{escape(finding["value"])}</code></div>')
        if 'file' in finding:
            details_html.append(f'<div class="detail-row"><span class="detail-label">File:</span><code>{escape(finding["file"])}</code></div>')
    
    details = '\n'.join(details_html)
    
    return f"""
    <div class="finding-card {severity}">
        <div class="finding-header">
            <span class="finding-title">{escape(title)}</span>
            <span class="severity-badge severity-{severity}">{severity.upper()}</span>
        </div>
        <div class="finding-details">
            {details}
        </div>
    </div>
    """


def generate_subdomain_section(subdomains: Dict) -> str:
    """Generate subdomains section HTML"""
    if not subdomains:
        return ""
    
    alive_count = sum(1 for info in subdomains.values() if isinstance(info, dict) and info.get('is_alive'))
    
    items_html = []
    for subdomain, info in subdomains.items():
        if not isinstance(info, dict):
            continue
        
        is_alive = info.get('is_alive', False)
        alive_class = "alive" if is_alive else "dead"
        status = "✅ Alive" if is_alive else "❌ Dead"
        http_status = info.get('http_status') or info.get('https_status') or 'N/A'
        
        items_html.append(f"""
        <div class="subdomain-item {alive_class}">
            <div style="font-weight: 600; margin-bottom: 5px;">{escape(subdomain)}</div>
            <div style="font-size: 0.85em; color: #6c757d;">
                {status} | Status: {http_status}
            </div>
        </div>
        """)
    
    return f"""
    <div class="section">
        <h2 class="section-title collapsible">📡 Subdomains ({alive_count}/{len(subdomains)} alive)</h2>
        <div class="collapse-content">
            <div class="subdomain-list">
                {''.join(items_html)}
            </div>
        </div>
    </div>
    """


def generate_endpoints_section(endpoints: List[Dict]) -> str:
    """Generate endpoints section HTML"""
    if not endpoints:
        return ""
    
    interesting_count = sum(1 for ep in endpoints if ep.get('interesting'))
    
    items_html = []
    for ep in endpoints[:100]:  # Limit to 100
        method = ep.get('method', 'GET')
        url = ep.get('url', '')
        status = ep.get('status_code', 'N/A')
        interesting = '⭐ Interesting' if ep.get('interesting') else ''
        
        items_html.append(f"""
        <div class="finding-card">
            <div style="margin-bottom: 8px;">
                <span class="endpoint-method method-{method}">{method}</span>
                <code>{escape(url)}</code>
            </div>
            <div style="font-size: 0.85em; color: #6c757d;">
                Status: {status} {interesting}
            </div>
        </div>
        """)
    
    return f"""
    <div class="section">
        <h2 class="section-title collapsible">🔗 Endpoints ({interesting_count} interesting)</h2>
        <div class="collapse-content">
            {''.join(items_html)}
        </div>
    </div>
    """


def generate_html_report(scan_data: Dict, output_file: str):
    """
    Generate an HTML report from scan data
    
    Args:
        scan_data: Scan results dictionary (from deep_scan JSON)
        output_file: Path to save HTML report
    """
    target = scan_data.get('target', 'Unknown')
    scan_time = scan_data.get('scan_start', scan_data.get('scan_end', 'Unknown'))
    program = scan_data.get('program', '')
    summary = scan_data.get('summary', {})
    
    # Format scan time
    try:
        if 'T' in scan_time:
            dt = datetime.fromisoformat(scan_time.replace('Z', '+00:00'))
            scan_time = dt.strftime('%B %d, %Y at %H:%M UTC')
    except:
        pass
    
    # Program badge
    program_badge = ''
    if program:
        program_badge = f'<div style="margin-top: 10px; font-size: 0.9em;">Program: <strong>{program.upper()}</strong></div>'
    
    # Summary cards
    summary_cards = []
    summary_cards.append(generate_summary_card(
        summary.get('subdomains_alive', 0),
        'Alive Subdomains',
        'info'
    ))
    summary_cards.append(generate_summary_card(
        summary.get('endpoints_interesting', 0),
        'Interesting Endpoints',
        'info'
    ))
    summary_cards.append(generate_summary_card(
        summary.get('secrets_found', 0),
        'Secrets Found',
        'critical' if summary.get('secrets_found', 0) > 0 else ''
    ))
    summary_cards.append(generate_summary_card(
        summary.get('vulnerabilities', 0),
        'Vulnerabilities',
        'high' if summary.get('vulnerabilities', 0) > 0 else ''
    ))
    summary_cards.append(generate_summary_card(
        len(scan_data.get('open_ports', {})),
        'Hosts with Open Ports',
        ''
    ))
    
    # Content sections
    content_sections = []
    
    # Vulnerabilities section
    vulnerabilities = scan_data.get('vulnerabilities', [])
    if vulnerabilities:
        vuln_html = []
        for vuln in vulnerabilities:
            vuln_html.append(generate_finding_card(vuln, 'vulnerability'))
        
        content_sections.append(f"""
        <div class="section">
            <h2 class="section-title">🚨 Vulnerabilities ({len(vulnerabilities)})</h2>
            {''.join(vuln_html)}
        </div>
        """)
    
    # Secrets section
    secrets = scan_data.get('secrets', [])
    if secrets:
        secret_html = []
        for secret in secrets:
            secret_html.append(generate_finding_card(secret, 'secret'))
        
        content_sections.append(f"""
        <div class="section">
            <h2 class="section-title">🔑 Secrets Found ({len(secrets)})</h2>
            {''.join(secret_html)}
        </div>
        """)
    
    # Service vulnerabilities
    service_vulns = []
    for host, ports in scan_data.get('open_ports', {}).items():
        for port in ports:
            if 'vulnerabilities' in port:
                for vuln in port['vulnerabilities']:
                    vuln['host'] = host
                    vuln['port'] = port['port']
                    service_vulns.append(vuln)
    
    if service_vulns:
        service_html = []
        for vuln in service_vulns:
            service_html.append(generate_finding_card(vuln, 'service'))
        
        content_sections.append(f"""
        <div class="section">
            <h2 class="section-title">⚙️ Service Vulnerabilities ({len(service_vulns)})</h2>
            {''.join(service_html)}
        </div>
        """)
    
    # Subdomains
    content_sections.append(generate_subdomain_section(scan_data.get('subdomains', {})))
    
    # Endpoints
    content_sections.append(generate_endpoints_section(scan_data.get('endpoints', [])))
    
    # Generate final HTML
    html = HTML_TEMPLATE.format(
        target=escape(target),
        scan_time=escape(scan_time),
        program_badge=program_badge,
        summary_cards=''.join(summary_cards),
        content_sections=''.join(content_sections),
        generated_time=datetime.now().strftime('%B %d, %Y at %H:%M')
    )
    
    # Write to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"\n✅ HTML report generated: {output_file}")
    return output_file


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python html_report.py <scan_json_file> [output_html]")
        sys.exit(1)
    
    json_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else json_file.replace('.json', '.html')
    
    # Load scan data
    with open(json_file, 'r') as f:
        scan_data = json.load(f)
    
    # Generate report
    generate_html_report(scan_data, output_file)
    print(f"\n📊 Open the report: file://{Path(output_file).absolute()}")
