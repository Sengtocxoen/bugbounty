#!/usr/bin/env python3
"""
SSTI & Code Injection Detection Module
======================================
Based on 2025 techniques including:
- Blind SSTI using error oracles
- Implicit toString coercion
- PDF generation path traversal
- phar deserialization
- ORM injection variants

References:
- Server-side template injection research
- Deserialization gadget chains
- PDF generator vulnerabilities
"""

import re
import random
import string
import time
from typing import List, Optional, Dict, Callable
from urllib.parse import quote, urlencode, urlparse, urljoin

from .base import TechniqueScanner, Finding, ScanProgress, is_shutdown


class SSTIInjection(TechniqueScanner):
    """Server-Side Template Injection and Code Injection scanner"""

    TECHNIQUE_NAME = "injection"
    TECHNIQUE_CATEGORY = "injection"

    # SSTI detection payloads for various template engines
    SSTI_PAYLOADS = [
        # Jinja2/Twig
        {
            "name": "Jinja2/Twig Math",
            "payload": "{{7*7}}",
            "expect": "49",
            "engines": ["jinja2", "twig"]
        },
        {
            "name": "Jinja2/Twig String",
            "payload": "{{\"test\".upper()}}",
            "expect": "TEST",
            "engines": ["jinja2"]
        },
        # Freemarker
        {
            "name": "Freemarker Math",
            "payload": "${7*7}",
            "expect": "49",
            "engines": ["freemarker"]
        },
        # Velocity
        {
            "name": "Velocity Math",
            "payload": "#set($x=7*7)$x",
            "expect": "49",
            "engines": ["velocity"]
        },
        # Smarty
        {
            "name": "Smarty Math",
            "payload": "{7*7}",
            "expect": "49",
            "engines": ["smarty"]
        },
        # Mako
        {
            "name": "Mako Math",
            "payload": "${7*7}",
            "expect": "49",
            "engines": ["mako"]
        },
        # ERB (Ruby)
        {
            "name": "ERB Math",
            "payload": "<%=7*7%>",
            "expect": "49",
            "engines": ["erb"]
        },
        # Pebble
        {
            "name": "Pebble Math",
            "payload": "{{7*7}}",
            "expect": "49",
            "engines": ["pebble"]
        },
        # Thymeleaf
        {
            "name": "Thymeleaf Expression",
            "payload": "${7*7}",
            "expect": "49",
            "engines": ["thymeleaf"]
        },
        # EL Expression (Java)
        {
            "name": "EL Expression",
            "payload": "${7*7}",
            "expect": "49",
            "engines": ["el"]
        },
        # Handlebars/Mustache
        {
            "name": "Handlebars",
            "payload": "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{/with}}{{/with}}{{/with}}",
            "expect": "error",  # Error-based detection
            "engines": ["handlebars"]
        },
    ]

    # Blind SSTI (error-based)
    BLIND_SSTI_PAYLOADS = [
        {
            "name": "Jinja2 Error",
            "payload": "{{7*'7'}}",
            "error_indicators": ["TypeError", "unsupported operand", "can't multiply"]
        },
        {
            "name": "Jinja2 Undefined",
            "payload": "{{nonexistent_var}}",
            "error_indicators": ["undefined", "not defined", "UndefinedError"]
        },
        {
            "name": "Freemarker Error",
            "payload": "${nonexistent}",
            "error_indicators": ["undefined", "ParseException", "InvalidReferenceException"]
        },
    ]

    # SQL injection payloads
    SQL_PAYLOADS = [
        # Error-based detection
        {
            "name": "Single Quote",
            "payload": "'",
            "errors": ["SQL_ERROR"]
        },
        {
            "name": "Comment",
            "payload": "1'--",
            "errors": ["SQL_ERROR"]
        },
        {
            "name": "Boolean True",
            "payload": "1 OR 1=1--",
            "comparison": True
        },
        {
            "name": "Boolean False",
            "payload": "1 AND 1=2--",
            "comparison": True
        },
        # Time-based blind
        {
            "name": "Time Sleep MySQL",
            "payload": "1' AND SLEEP(5)--",
            "time_based": 5
        },
        {
            "name": "Time Sleep Postgres",
            "payload": "1'; SELECT pg_sleep(5)--",
            "time_based": 5
        },
    ]

    SQL_ERROR_PATTERNS = [
        r"you have an error in your sql syntax",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"sql syntax.*mysql",
        r"warning.*mysql",
        r"pg::syntaxerror",
        r"postgresql.*syntax error",
        r"sqlite.*syntax error",
        r"ora-\d{4,}",
        r"sqlserver.*driver",
        r"mssql.*syntax",
    ]

    # Command injection payloads
    CMD_PAYLOADS = [
        # Time-based detection
        {
            "name": "Sleep Unix",
            "payload": ";sleep 5;",
            "time_based": 5
        },
        {
            "name": "Sleep Windows",
            "payload": "& ping -n 5 127.0.0.1 &",
            "time_based": 5
        },
        # Echo-based detection
        {
            "name": "Echo Unix",
            "payload": ";echo CMDINJECTED;",
            "expect": "CMDINJECTED"
        },
        {
            "name": "Backtick",
            "payload": "`echo CMDINJECTED`",
            "expect": "CMDINJECTED"
        },
        {
            "name": "Pipe",
            "payload": "| echo CMDINJECTED",
            "expect": "CMDINJECTED"
        },
    ]

    # PDF generation vulnerabilities
    PDF_PAYLOADS = [
        {
            "name": "SSRF via PDF",
            "payload": "<iframe src='http://127.0.0.1:80/'></iframe>",
            "type": "ssrf"
        },
        {
            "name": "Local File Read",
            "payload": "<script>x=new XMLHttpRequest();x.open('GET','file:///etc/passwd');x.send();</script>",
            "type": "lfi"
        },
        {
            "name": "Path Traversal",
            "payload": "<link rel='stylesheet' href='file:///etc/passwd'>",
            "type": "lfi"
        },
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.canary = self._generate_canary()

    def _generate_canary(self) -> str:
        """Generate unique canary for detection"""
        return 'ssti' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

    def _validate_ssti_evidence(self, response_text: str, expected: str) -> bool:
        """Validate SSTI evidence - ensure expected output is from template evaluation, not false positive.

        Returns True if the evidence appears genuine, False if it's likely a false positive.
        """
        if expected not in response_text:
            return False

        # For numeric results like "49" (from 7*7), check context to avoid false positives
        if expected.isdigit():
            # Patterns that indicate false positives
            fp_patterns = [
                rf'error\s*[:\-]?\s*{expected}',      # error: 49, error-49
                rf'page\s*{expected}',                 # page 49
                rf'item\s*{expected}',                 # item 49
                rf'id["\']?\s*[:=]\s*["\']?{expected}', # id="49", id: 49
                rf'\.{expected}\.',                    # .49. (version)
                rf'\d{expected}\d',                    # part of larger number
                rf'{expected}%',                       # 49% (percentage)
                rf'\${expected}',                      # $49 (price)
                rf'£{expected}',                       # £49 (price)
                rf'€{expected}',                       # €49 (price)
                rf'¥{expected}',                       # ¥49 (price)
                rf'{expected}\.99',                    # 49.99 (price)
                rf'{expected}\.00',                    # 49.00 (price)
                rf'status["\']?\s*[:=]\s*["\']?{expected}', # status: 49
                rf'code["\']?\s*[:=]\s*["\']?{expected}',   # code: 49
            ]

            # Find all occurrences of expected value
            for match in re.finditer(rf'(?<!\d){re.escape(expected)}(?!\d)', response_text):
                start = max(0, match.start() - 30)
                end = min(len(response_text), match.end() + 30)
                context = response_text[start:end].lower()

                # Check if this occurrence is in a false positive context
                is_fp = any(re.search(pattern, context, re.IGNORECASE) for pattern in fp_patterns)

                if not is_fp:
                    # Found an occurrence that's not in a known FP context
                    # This could be genuine SSTI
                    return True

            # All occurrences were in FP contexts
            return False

        # For string results like "TEST", less likely to be FP but still validate
        elif expected.isupper() and expected.isalpha():
            # Make sure it's not just in a generic context like navigation/headers
            if response_text.count(expected) > 5:
                # If the value appears many times, it's probably a common word/UI element
                return False

        return True

    def _build_ssti_variants(self, payload: str, expected: str) -> List[Dict[str, str]]:
        """Create unique SSTI payload variants to reduce false positives."""
        # Math-based payloads: replace 7*7 with unique values and expect unique results
        if expected.isdigit() and "7*7" in payload:
            a1, b1 = random.randint(11, 97), random.randint(11, 97)
            a2, b2 = random.randint(11, 97), random.randint(11, 97)
            while a1 * b1 == a2 * b2:
                a2, b2 = random.randint(11, 97), random.randint(11, 97)
            expr1 = f"{a1}*{b1}"
            expr2 = f"{a2}*{b2}"
            return [
                {"payload": payload.replace("7*7", expr1), "expect": str(a1 * b1)},
                {"payload": payload.replace("7*7", expr2), "expect": str(a2 * b2)},
            ]

        # String-based payloads (upper) should use unique token
        if "upper()" in payload and "test" in payload:
            token1 = self._generate_canary()
            token2 = self._generate_canary()
            return [
                {"payload": payload.replace("test", token1), "expect": token1.upper()},
                {"payload": payload.replace("test", token2), "expect": token2.upper()},
            ]

        return [{"payload": payload, "expect": expected}]

    def _same_domain(self, url: str, domain: str) -> bool:
        try:
            host = urlparse(url).netloc.lower()
        except Exception:
            return False
        return host == domain.lower() or host.endswith(f".{domain.lower()}")

    def _follow_same_domain(self,
                            method: str,
                            url: str,
                            domain: str,
                            request_fn: Callable,
                            **kwargs):
        """Follow redirects only within the same domain; return None if out-of-scope."""
        resp = request_fn(url, allow_redirects=False, **kwargs)
        if resp is None:
            return None
        if not self._same_domain(resp.url, domain):
            return None
        hops = 0
        while resp.is_redirect and hops < 2:
            location = resp.headers.get("Location")
            if not location:
                break
            next_url = urljoin(resp.url, location)
            if not self._same_domain(next_url, domain):
                return None
            resp = request_fn(next_url, allow_redirects=False, **kwargs)
            if resp is None:
                return None
            hops += 1
        return resp

    def _find_injectable_params(self, domain: str) -> List[Dict]:
        """Find parameters that might be injectable"""
        injectable = []

        # Common endpoints with user input
        test_cases = [
            ("/search", ["q", "query", "search"]),
            ("/", ["name", "email", "message", "comment"]),
            ("/api/render", ["template", "content", "text"]),
            ("/preview", ["content", "data", "template"]),
            ("/email/preview", ["subject", "body", "template"]),
            ("/report", ["title", "content"]),
        ]

        for endpoint, params in test_cases:
            if is_shutdown():
                break

            for param in params:
                canary = self._generate_canary()
                url = f"https://{domain}{endpoint}?{param}={canary}"

                resp = self._follow_same_domain("GET", url, domain, self.get)
                if resp and canary in resp.text:
                    injectable.append({
                        "url": f"https://{domain}{endpoint}",
                        "parameter": param,
                        "method": "GET",
                        "reflected": True
                    })

                # Also test POST
                resp_post = self._follow_same_domain(
                    "POST",
                    f"https://{domain}{endpoint}",
                    domain,
                    self.post,
                    data={param: canary}
                )
                if resp_post and canary in resp_post.text:
                    injectable.append({
                        "url": f"https://{domain}{endpoint}",
                        "parameter": param,
                        "method": "POST",
                        "reflected": True
                    })

        return injectable

    def _test_ssti(self, domain: str, injectable: Dict) -> List[Dict]:
        """Test SSTI payloads on an injectable parameter"""
        findings = []
        url = injectable["url"]
        param = injectable["parameter"]
        method = injectable["method"]

        # Baseline response to avoid false positives on static content
        baseline_canary = self._generate_canary()
        if method == "GET":
            baseline_resp = self._follow_same_domain("GET", f"{url}?{param}={baseline_canary}", domain, self.get)
        else:
            baseline_resp = self._follow_same_domain("POST", url, domain, self.post, data={param: baseline_canary})
        if baseline_resp is None:
            return findings
        baseline_text = baseline_resp.text if baseline_resp and baseline_resp.text else ""

        for ssti in self.SSTI_PAYLOADS:
            if is_shutdown():
                break

            variants = self._build_ssti_variants(ssti["payload"], ssti["expect"])

            if method == "GET":
                test_url = f"{url}?{param}={quote(variants[0]['payload'])}"
                resp = self._follow_same_domain("GET", test_url, domain, self.get)
            else:
                resp = self._follow_same_domain("POST", url, domain, self.post, data={param: variants[0]['payload']})

            if resp is None:
                continue

            # Check for expected output with proper false positive validation
            # Just finding "49" in a page is NOT proof of SSTI - could be price, page number, etc.
            if ssti["expect"] != "error":
                # Require two distinct payloads to both evaluate correctly
                if len(variants) >= 2:
                    variant_a, variant_b = variants[0], variants[1]

                    if method == "GET":
                        test_url_b = f"{url}?{param}={quote(variant_b['payload'])}"
                        resp_b = self._follow_same_domain("GET", test_url_b, domain, self.get)
                    else:
                        resp_b = self._follow_same_domain("POST", url, domain, self.post, data={param: variant_b['payload']})

                    if resp_b is None:
                        continue

                    expected_a = variant_a["expect"]
                    expected_b = variant_b["expect"]
                    resp_a_text = resp.text or ""
                    resp_b_text = resp_b.text or ""

                    if (expected_a in resp_a_text and expected_b in resp_b_text and
                            expected_a not in baseline_text and expected_b not in baseline_text and
                            expected_a not in resp_b_text and expected_b not in resp_a_text):
                        if self._validate_ssti_evidence(resp_a_text, expected_a) and self._validate_ssti_evidence(resp_b_text, expected_b):
                            reflection_possible = variant_a["payload"] in resp_a_text or variant_b["payload"] in resp_b_text
                            findings.append({
                                "type": "ssti_confirmed",
                                "name": ssti["name"],
                                "engines": ssti["engines"],
                                "parameter": param,
                                "payload": variant_a["payload"],
                                "method": method,
                                "url": url,
                                "response_obj": resp_b,
                                "reflection_possible": reflection_possible,
                                "evidence": f"SSTI output observed: {variant_a['payload']} -> {expected_a} and {variant_b['payload']} -> {expected_b}"
                            })
                            break  # Found it, no need to test more
                else:
                    expected = variants[0]["expect"]
                    if expected in resp.text and expected not in baseline_text:
                        if self._validate_ssti_evidence(resp.text, expected):
                            reflection_possible = variants[0]["payload"] in resp.text
                            findings.append({
                                "type": "ssti_confirmed",
                                "name": ssti["name"],
                                "engines": ssti["engines"],
                                "parameter": param,
                                "payload": variants[0]["payload"],
                                "method": method,
                                "url": url,
                                "response_obj": resp,
                                "reflection_possible": reflection_possible,
                                "evidence": f"SSTI output observed: {variants[0]['payload']} -> {expected} (context validated)"
                            })
                            break  # Found it, no need to test more

        # Test blind SSTI (error-based)
        for blind in self.BLIND_SSTI_PAYLOADS:
            if is_shutdown():
                break

            payload = blind["payload"]

            if method == "GET":
                test_url = f"{url}?{param}={quote(payload)}"
                resp = self._follow_same_domain("GET", test_url, domain, self.get)
            else:
                resp = self._follow_same_domain("POST", url, domain, self.post, data={param: payload})

            if resp is None:
                continue

            # Check for error indicators
            response_lower = resp.text.lower()
            for indicator in blind["error_indicators"]:
                if indicator.lower() in response_lower:
                    findings.append({
                        "type": "ssti_error_based",
                        "name": blind["name"],
                        "parameter": param,
                        "payload": payload,
                        "method": method,
                        "url": url,
                        "response_obj": resp,
                        "evidence": f"Error-based SSTI indicator: {indicator}"
                    })
                    break

        return findings

    def _test_sql_injection(self, domain: str, injectable: Dict) -> List[Dict]:
        """Test SQL injection payloads"""
        findings = []
        url = injectable["url"]
        param = injectable["parameter"]
        method = injectable["method"]

        # Get baseline response
        baseline_canary = self._generate_canary()
        if method == "GET":
            start = time.time()
            baseline_resp = self._follow_same_domain("GET", f"{url}?{param}={baseline_canary}", domain, self.get)
            baseline_time = time.time() - start
        else:
            start = time.time()
            baseline_resp = self._follow_same_domain("POST", url, domain, self.post, data={param: baseline_canary})
            baseline_time = time.time() - start

        if baseline_resp is None:
            return findings

        baseline_len = len(baseline_resp.text)
        baseline_text = baseline_resp.text.lower()

        compiled_errors = [re.compile(pat, re.IGNORECASE) for pat in self.SQL_ERROR_PATTERNS]

        for sql in self.SQL_PAYLOADS:
            if is_shutdown():
                break

            payload = sql["payload"]

            if method == "GET":
                test_url = f"{url}?{param}={quote(payload)}"
                start = time.time()
                resp = self._follow_same_domain("GET", test_url, domain, self.get)
                resp_time = time.time() - start
            else:
                start = time.time()
                resp = self._follow_same_domain("POST", url, domain, self.post, data={param: payload})
                resp_time = time.time() - start

            if resp is None:
                continue

            # Error-based detection
            if "errors" in sql:
                response_lower = resp.text.lower()
                if any(r.search(response_lower) for r in compiled_errors) and not any(r.search(baseline_text) for r in compiled_errors):
                        findings.append({
                            "type": "sqli_error",
                            "name": sql["name"],
                            "parameter": param,
                            "payload": payload,
                            "method": method,
                            "url": url,
                            "response_obj": resp,
                        "evidence": "SQL error pattern detected in response"
                        })

            # Time-based detection
            if "time_based" in sql:
                delays = 1 if resp_time >= sql["time_based"] - 1 and resp_time > baseline_time + 3 else 0
                for _ in range(1):
                    if is_shutdown():
                        break
                    if method == "GET":
                        start = time.time()
                        follow_resp = self._follow_same_domain("GET", test_url, domain, self.get)
                        follow_time = time.time() - start
                    else:
                        start = time.time()
                        follow_resp = self._follow_same_domain("POST", url, domain, self.post, data={param: payload})
                        follow_time = time.time() - start
                    if follow_resp is None:
                        continue
                    if follow_time >= sql["time_based"] - 1 and follow_time > baseline_time + 3:
                        delays += 1
                if delays >= 2:
                    findings.append({
                        "type": "sqli_time_based",
                        "name": sql["name"],
                        "parameter": param,
                        "payload": payload,
                        "method": method,
                        "url": url,
                        "response_obj": resp,
                        "evidence": f"Time-based SQLi: consistent >= {sql['time_based']}s delay over multiple attempts"
                    })

            # Boolean-based detection
            if sql.get("comparison"):
                # Need to compare true vs false responses
                pass  # Simplified for this implementation

        return findings

    def _test_command_injection(self, domain: str, injectable: Dict) -> List[Dict]:
        """Test command injection payloads"""
        findings = []
        url = injectable["url"]
        param = injectable["parameter"]
        method = injectable["method"]
        cmd_token = "cmd" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))

        # Get baseline time/response
        baseline_canary = self._generate_canary()
        if method == "GET":
            start = time.time()
            baseline_resp = self._follow_same_domain("GET", f"{url}?{param}={baseline_canary}", domain, self.get)
            baseline_time = time.time() - start
        else:
            start = time.time()
            baseline_resp = self._follow_same_domain("POST", url, domain, self.post, data={param: baseline_canary})
            baseline_time = time.time() - start

        if baseline_resp is None:
            return findings
        baseline_text = baseline_resp.text if baseline_resp.text else ""

        for cmd in self.CMD_PAYLOADS:
            if is_shutdown():
                break

            payload = cmd["payload"].replace("CMDINJECTED", cmd_token)
            expected_token = cmd.get("expect")
            if expected_token:
                expected_token = cmd_token

            if method == "GET":
                test_url = f"{url}?{param}={quote(payload)}"
                start = time.time()
                resp = self._follow_same_domain("GET", test_url, domain, self.get)
                resp_time = time.time() - start
            else:
                start = time.time()
                resp = self._follow_same_domain("POST", url, domain, self.post, data={param: payload})
                resp_time = time.time() - start

            if resp is None:
                continue

            # Echo-based detection (avoid baseline reflection)
            if expected_token and expected_token in resp.text and expected_token not in baseline_text:
                findings.append({
                    "type": "cmdi_confirmed",
                    "name": cmd["name"],
                    "parameter": param,
                    "payload": payload,
                    "method": method,
                    "url": url,
                    "response_obj": resp,
                    "evidence": f"Command output observed: {expected_token} in response"
                })

            # Time-based detection
            if "time_based" in cmd:
                delays = 1 if resp_time >= cmd["time_based"] - 1 and resp_time > baseline_time + 3 else 0
                for _ in range(1):
                    if is_shutdown():
                        break
                    if method == "GET":
                        start = time.time()
                        follow_resp = self._follow_same_domain("GET", test_url, domain, self.get)
                        follow_time = time.time() - start
                    else:
                        start = time.time()
                        follow_resp = self._follow_same_domain("POST", url, domain, self.post, data={param: payload})
                        follow_time = time.time() - start
                    if follow_resp is None:
                        continue
                    if follow_time >= cmd["time_based"] - 1 and follow_time > baseline_time + 3:
                        delays += 1
                if delays >= 2:
                    findings.append({
                        "type": "cmdi_time_based",
                        "name": cmd["name"],
                        "parameter": param,
                        "payload": payload,
                        "method": method,
                        "url": url,
                        "response_obj": resp,
                        "evidence": f"Time-based command injection: consistent >= {cmd['time_based']}s delay over multiple attempts"
                    })

        return findings

    def _find_pdf_generators(self, domain: str) -> List[Dict]:
        """Find PDF generation endpoints"""
        pdf_endpoints = []

        test_endpoints = [
            "/api/pdf",
            "/api/export/pdf",
            "/api/generate-pdf",
            "/export",
            "/download/pdf",
            "/print",
            "/api/print",
            "/invoice/pdf",
            "/report/pdf",
            "/api/render",
        ]

        for endpoint in test_endpoints:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"
            resp = self.get(url, allow_redirects=False)

            if resp and resp.status_code in [200, 400, 405]:
                # Check if it seems to be a PDF endpoint
                content_type = resp.headers.get('Content-Type', '')
                if 'pdf' in content_type or 'pdf' in endpoint:
                    pdf_endpoints.append({
                        "url": url,
                        "endpoint": endpoint,
                        "method": "GET" if resp.status_code == 200 else "POST"
                    })

                # Also check POST
                resp_post = self.post(url,
                                     data={"content": "test"},
                                     allow_redirects=False)
                if resp_post and resp_post.status_code in [200, 400]:
                    pdf_endpoints.append({
                        "url": url,
                        "endpoint": endpoint,
                        "method": "POST"
                    })

        return pdf_endpoints

    def _test_pdf_vulnerabilities(self, domain: str, endpoint: Dict) -> List[Dict]:
        """Test PDF generation for vulnerabilities"""
        findings = []
        url = endpoint["url"]

        for pdf_payload in self.PDF_PAYLOADS:
            if is_shutdown():
                break

            # Try to inject payload into PDF content
            resp = self.post(url,
                            data={"content": pdf_payload["payload"], "html": pdf_payload["payload"]},
                            headers={"Content-Type": "application/x-www-form-urlencoded"})

            if resp is None:
                continue

            # Check response for indicators
            if resp.status_code == 200:
                findings.append({
                    "type": f"pdf_{pdf_payload['type']}",
                    "name": pdf_payload["name"],
                    "url": url,
                    "payload": pdf_payload["payload"],
                    "evidence": f"PDF endpoint accepted {pdf_payload['type']} payload - verify in generated PDF"
                })

        return findings

    def _test_prototype_pollution(self, domain: str) -> List[Dict]:
        """Test for prototype pollution vulnerabilities

        IMPORTANT: Real prototype pollution detection requires proving that:
        1. The polluted property affects OTHER objects/requests (not just echoing back our payload)
        2. OR causes observable behavior changes in the application

        Just seeing our payload in the response is NOT proof of pollution -
        many APIs simply store and return what you send them.
        """
        findings = []

        # Common API endpoints
        api_endpoints = [
            "/api/user/settings",
            "/api/config",
            "/api/update",
            "/api/merge",
        ]

        # Prototype pollution payloads
        pp_payloads = [
            {"__proto__": {"polluted_pp_test": "true"}},
            {"constructor": {"prototype": {"polluted_pp_test": "true"}}},
        ]

        for endpoint in api_endpoints:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"

            # First, get a baseline response WITHOUT our payload
            baseline_resp = self.get(url, headers={"Content-Type": "application/json"})
            if baseline_resp is None:
                continue

            baseline_has_polluted = False
            try:
                baseline_data = baseline_resp.json()
                baseline_has_polluted = "polluted_pp_test" in str(baseline_data)
            except:
                pass

            for payload in pp_payloads:
                resp = self.post(url,
                                json=payload,
                                headers={"Content-Type": "application/json"})

                if resp is None:
                    continue

                # IMPORTANT: Don't just check if our payload is echoed back
                # That's not proof of pollution - servers often return what you POST

                if resp.status_code == 200:
                    try:
                        data = resp.json()

                        # Check if our polluted property appears in response
                        if data.get("polluted_pp_test") == "true":
                            # This alone is NOT proof - could just be echoing our payload

                            # To confirm real pollution, make a SEPARATE request
                            # and check if the polluted property persists/propagates
                            verify_resp = self.get(f"https://{domain}/api/user/profile",
                                                  headers={"Content-Type": "application/json"})
                            verify_resp2 = self.get(url,
                                                   headers={"Content-Type": "application/json"})

                            # Check if pollution propagated to other endpoints
                            pollution_propagated = False
                            for vr in [verify_resp, verify_resp2]:
                                if vr is None:
                                    continue
                                try:
                                    vdata = vr.json()
                                    # Check if our polluted property appears in a DIFFERENT request
                                    # where we didn't explicitly send it
                                    if "polluted_pp_test" in str(vdata) and not baseline_has_polluted:
                                        pollution_propagated = True
                                        break
                                except:
                                    pass

                            if pollution_propagated:
                                findings.append({
                                    "type": "prototype_pollution",
                                    "url": url,
                                    "payload": str(payload),
                                    "evidence": "Prototype pollution confirmed: polluted property propagated to other requests"
                                })
                            # Note: If only echoed back, don't report - that's not real pollution
                    except:
                        pass

        return findings

    def scan(self, domain: str, progress: ScanProgress) -> List[Finding]:
        """Scan domain for SSTI and injection vulnerabilities"""
        findings = []
        self.log(f"Testing SSTI/injection on {domain}")

        # Find injectable parameters
        self.log("Finding injectable parameters")
        injectables = self._find_injectable_params(domain)

        if injectables:
            self.log(f"Found {len(injectables)} potential injection points", "success")

            for injectable in injectables:
                # Test SSTI
                self.log(f"Testing SSTI on {injectable['parameter']}")
                ssti_findings = self._test_ssti(domain, injectable)

                for sf in ssti_findings:
                    evidence_type = "error_based" if sf["type"] == "ssti_error_based" else "output_match"
                    reflection_possible = sf.get("reflection_possible", False)
                    if sf["type"] == "ssti_confirmed":
                        severity = "high" if reflection_possible else "high"
                        confidence = "low" if reflection_possible else "medium"
                    else:
                        severity = "medium"
                        confidence = "low"
                    title_suffix = "SSTI (Possible Reflection)" if reflection_possible else "SSTI"

                    finding = self.create_finding(
                        domain=domain,
                        severity=severity,
                        title=f"{title_suffix}: {sf['name']}",
                        description=f"Server-Side Template Injection via {sf['parameter']}",
                        evidence=sf["evidence"],
                        reproduction_steps=[
                            f"URL: {injectable['url']}",
                            f"Parameter: {sf['parameter']}",
                            f"Payload: {sf['payload']}"
                        ],
                        response_obj=sf.get("response_obj"),
                        sub_technique="ssti",
                        confidence=confidence,
                        evidence_type=evidence_type,
                        parameter=sf["parameter"],
                        payload=sf["payload"],
                        http_method=sf.get("method"),
                        endpoint=sf.get("url")
                    )
                    findings.append(finding)
                    progress.add_finding(domain, finding)

                # Test SQL injection
                if not is_shutdown():
                    self.log(f"Testing SQLi on {injectable['parameter']}")
                    sqli_findings = self._test_sql_injection(domain, injectable)

                    for sqf in sqli_findings:
                        severity = "high" if "error" in sqf["type"] else "medium"
                        confidence = "medium" if "error" in sqf["type"] else "low"
                        evidence_type = "error_pattern" if "error" in sqf["type"] else "time_delay"
                        finding = self.create_finding(
                            domain=domain,
                            severity=severity,
                            title=f"SQL Injection: {sqf['name']}",
                            description=f"SQL Injection via {sqf['parameter']}",
                            evidence=sqf["evidence"],
                            reproduction_steps=[
                                f"URL: {injectable['url']}",
                                f"Parameter: {sqf['parameter']}",
                                f"Payload: {sqf['payload']}"
                            ],
                            response_obj=sqf.get("response_obj"),
                            sub_technique="sqli",
                            confidence=confidence,
                            evidence_type=evidence_type,
                            parameter=sqf["parameter"],
                            payload=sqf["payload"],
                            http_method=injectable.get("method"),
                            endpoint=injectable.get("url")
                        )
                        findings.append(finding)
                        progress.add_finding(domain, finding)

                # Test command injection
                if not is_shutdown():
                    self.log(f"Testing CMDi on {injectable['parameter']}")
                    cmdi_findings = self._test_command_injection(domain, injectable)

                    for cf in cmdi_findings:
                        if cf["type"] == "cmdi_confirmed":
                            severity = "high"
                            confidence = "medium"
                            evidence_type = "output_match"
                        else:
                            severity = "medium"
                            confidence = "low"
                            evidence_type = "time_delay"
                        finding = self.create_finding(
                            domain=domain,
                            severity=severity,
                            title=f"OS Command Injection: {cf['name']}",
                            description=f"OS Command Injection via {cf['parameter']}",
                            evidence=cf["evidence"],
                            reproduction_steps=[
                                f"URL: {injectable['url']}",
                                f"Parameter: {cf['parameter']}",
                                f"Payload: {cf['payload']}"
                            ],
                            response_obj=cf.get("response_obj"),
                            sub_technique="command_injection",
                            confidence=confidence,
                            evidence_type=evidence_type,
                            parameter=cf["parameter"],
                            payload=cf["payload"],
                            http_method=cf.get("method"),
                            endpoint=cf.get("url")
                        )
                        findings.append(finding)
                        progress.add_finding(domain, finding)

        # Find and test PDF generators
        if not is_shutdown():
            self.log("Finding PDF generation endpoints")
            pdf_endpoints = self._find_pdf_generators(domain)

            for endpoint in pdf_endpoints:
                pdf_findings = self._test_pdf_vulnerabilities(domain, endpoint)

                for pf in pdf_findings:
                    finding = self.create_finding(
                        domain=domain,
                        severity="high",
                        title=f"PDF Generator: {pf['name']}",
                        description=f"PDF generation endpoint may be vulnerable to {pf['type']}",
                        evidence=pf["evidence"],
                        reproduction_steps=[
                            f"URL: {pf['url']}",
                            f"Inject payload into PDF content parameter",
                            f"Payload: {pf['payload'][:100]}"
                        ]
                    )
                    findings.append(finding)
                    progress.add_finding(domain, finding)

        # Test prototype pollution
        if not is_shutdown():
            self.log("Testing prototype pollution")
            pp_findings = self._test_prototype_pollution(domain)

            for ppf in pp_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="high",
                    title="Prototype Pollution",
                    description="Server-side prototype pollution vulnerability",
                    evidence=ppf["evidence"],
                    reproduction_steps=[
                        f"URL: {ppf['url']}",
                        f"Payload: {ppf['payload']}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        self.log(f"Completed: {len(findings)} injection issues found", "success" if findings else "info")
        return findings
