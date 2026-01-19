#!/usr/bin/env python3
"""
Protocol-Specific Attacks Detection Module
==========================================
Based on 2025 techniques including:
- WebSocket vulnerabilities (CSWSH, state fuzzing)
- HTTP/2 specific attacks
- gRPC security issues
- GraphQL introspection and injection
- QUIC/HTTP3 considerations

References:
- WebSocket security research
- HTTP/2 timing attacks
- GraphQL security best practices
"""

import re
import json
import socket
import ssl
import time
import base64
import hashlib
from typing import List, Optional, Dict, Tuple
from urllib.parse import urlparse, quote

from .base import TechniqueScanner, Finding, ScanProgress, is_shutdown


class ProtocolAttacks(TechniqueScanner):
    """Protocol-specific vulnerability scanner"""

    TECHNIQUE_NAME = "protocol_attacks"
    TECHNIQUE_CATEGORY = "protocol"

    # WebSocket endpoints to probe
    WEBSOCKET_ENDPOINTS = [
        "/ws",
        "/websocket",
        "/socket",
        "/socket.io/",
        "/sockjs/",
        "/cable",
        "/live",
        "/realtime",
        "/stream",
        "/events",
        "/notifications",
        "/chat",
    ]

    # GraphQL endpoints
    GRAPHQL_ENDPOINTS = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/query",
        "/gql",
        "/graphiql",
        "/playground",
        "/altair",
    ]

    # gRPC endpoints
    GRPC_ENDPOINTS = [
        "/grpc",
        "/api/grpc",
        "/rpc",
    ]

    # GraphQL introspection query
    INTROSPECTION_QUERY = '''
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          fields {
            name
            args { name type { name } }
          }
        }
      }
    }
    '''

    # GraphQL injection payloads
    GRAPHQL_INJECTIONS = [
        # Batching attack
        [{"query": "{ __typename }"}, {"query": "{ __typename }"}],
        # Field suggestions (error-based enumeration)
        {"query": "{ user { __typename } }"},
        {"query": "{ admin { __typename } }"},
        # Alias-based DoS
        {"query": "{ a1:__typename a2:__typename a3:__typename a4:__typename a5:__typename }"},
        # Directive abuse
        {"query": "{ __typename @include(if: true) }"},
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _check_websocket_support(self, domain: str) -> List[Dict]:
        """Check for WebSocket endpoints"""
        findings = []

        for endpoint in self.WEBSOCKET_ENDPOINTS:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"

            # Try WebSocket upgrade
            headers = {
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": base64.b64encode(b"test1234567890ab").decode(),
                "Sec-WebSocket-Version": "13",
            }

            resp = self.get(url, headers=headers, allow_redirects=False)

            if resp is None:
                continue

            # Check for WebSocket upgrade response
            if resp.status_code == 101:
                findings.append({
                    "type": "websocket_endpoint",
                    "endpoint": endpoint,
                    "status": 101,
                    "evidence": f"WebSocket endpoint found: {endpoint}"
                })
            elif resp.status_code in [200, 400] and 'websocket' in resp.text.lower():
                findings.append({
                    "type": "websocket_possible",
                    "endpoint": endpoint,
                    "status": resp.status_code,
                    "evidence": f"Possible WebSocket endpoint: {endpoint}"
                })

            # Check for Socket.IO
            if 'socket.io' in endpoint.lower():
                socketio_url = f"https://{domain}{endpoint}?EIO=4&transport=polling"
                resp_sio = self.get(socketio_url)

                if resp_sio and resp_sio.status_code == 200:
                    findings.append({
                        "type": "socketio_endpoint",
                        "endpoint": endpoint,
                        "evidence": f"Socket.IO endpoint found"
                    })

        return findings

    def _test_websocket_csrf(self, domain: str, endpoint: str) -> List[Dict]:
        """Test WebSocket endpoint for CSWSH (Cross-Site WebSocket Hijacking)"""
        findings = []

        url = f"https://{domain}{endpoint}"

        # Test without Origin header
        headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": base64.b64encode(b"test1234567890ab").decode(),
            "Sec-WebSocket-Version": "13",
        }

        resp = self.get(url, headers=headers, allow_redirects=False)

        if resp and resp.status_code == 101:
            findings.append({
                "type": "cswsh_no_origin",
                "endpoint": endpoint,
                "evidence": "WebSocket accepts connection without Origin header"
            })

        # Test with evil Origin
        headers["Origin"] = "https://evil.com"
        resp = self.get(url, headers=headers, allow_redirects=False)

        if resp and resp.status_code == 101:
            findings.append({
                "type": "cswsh_any_origin",
                "endpoint": endpoint,
                "evidence": "WebSocket accepts connection from any Origin"
            })

        return findings

    def _check_graphql(self, domain: str) -> List[Dict]:
        """Check for GraphQL endpoints and vulnerabilities"""
        findings = []

        for endpoint in self.GRAPHQL_ENDPOINTS:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"

            # Test introspection
            resp = self.post(url,
                            json={"query": self.INTROSPECTION_QUERY},
                            headers={"Content-Type": "application/json"})

            if resp is None:
                continue

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if 'data' in data and '__schema' in str(data):
                        # Introspection enabled
                        schema = data.get('data', {}).get('__schema', {})
                        types = schema.get('types', [])

                        findings.append({
                            "type": "graphql_introspection",
                            "endpoint": endpoint,
                            "types_count": len(types),
                            "evidence": f"GraphQL introspection enabled - {len(types)} types exposed"
                        })

                        # Look for sensitive types
                        sensitive_types = ['User', 'Admin', 'Account', 'Password', 'Token', 'Secret', 'Key']
                        found_sensitive = [t['name'] for t in types if any(s.lower() in t.get('name', '').lower() for s in sensitive_types)]

                        if found_sensitive:
                            findings.append({
                                "type": "graphql_sensitive_types",
                                "endpoint": endpoint,
                                "types": found_sensitive[:10],
                                "evidence": f"Sensitive types exposed: {found_sensitive[:5]}"
                            })

                except:
                    pass

            # Test for batching attack
            batch_payload = [{"query": "{ __typename }"}, {"query": "{ __typename }"}]
            resp_batch = self.post(url,
                                   json=batch_payload,
                                   headers={"Content-Type": "application/json"})

            if resp_batch and resp_batch.status_code == 200:
                try:
                    data = resp_batch.json()
                    if isinstance(data, list) and len(data) == 2:
                        findings.append({
                            "type": "graphql_batching",
                            "endpoint": endpoint,
                            "evidence": "GraphQL batching enabled - potential for DoS or bypass"
                        })
                except:
                    pass

            # Test field suggestion (error-based enumeration)
            typo_query = {"query": "{ userr { id } }"}  # Intentional typo
            resp_typo = self.post(url,
                                  json=typo_query,
                                  headers={"Content-Type": "application/json"})

            if resp_typo and resp_typo.status_code == 200:
                try:
                    data = resp_typo.json()
                    errors = data.get('errors', [])
                    for error in errors:
                        msg = str(error.get('message', '')).lower()
                        if 'did you mean' in msg or 'suggestion' in msg:
                            findings.append({
                                "type": "graphql_field_suggestion",
                                "endpoint": endpoint,
                                "evidence": "GraphQL field suggestions enabled - schema enumeration possible"
                            })
                            break
                except:
                    pass

        return findings

    def _test_graphql_injection(self, domain: str, endpoint: str) -> List[Dict]:
        """Test GraphQL endpoint for injection vulnerabilities"""
        findings = []
        url = f"https://{domain}{endpoint}"

        # SQL injection via GraphQL variables
        sqli_payloads = [
            {"query": "query($id: String!) { user(id: $id) { name } }", "variables": {"id": "1' OR '1'='1"}},
            {"query": "mutation { login(username: \"admin'--\", password: \"x\") { token } }"},
        ]

        for payload in sqli_payloads:
            if is_shutdown():
                break

            resp = self.post(url,
                            json=payload,
                            headers={"Content-Type": "application/json"})

            if resp is None:
                continue

            response_lower = resp.text.lower()

            # Check for SQL errors
            sql_errors = ['sql', 'syntax', 'mysql', 'postgres', 'sqlite', 'oracle']
            if any(err in response_lower for err in sql_errors):
                findings.append({
                    "type": "graphql_sqli",
                    "endpoint": endpoint,
                    "payload": str(payload),
                    "evidence": "SQL error in GraphQL response - potential SQLi"
                })

        # NoSQL injection
        nosql_payloads = [
            {"query": '{ users(filter: "{\\"$gt\\": \\"\\"}" ) { id } }'},
            {"query": "{ users(where: { id_not: null }) { id } }"},
        ]

        for payload in nosql_payloads:
            if is_shutdown():
                break

            resp = self.post(url,
                            json=payload,
                            headers={"Content-Type": "application/json"})

            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if 'data' in data and data['data']:
                        findings.append({
                            "type": "graphql_nosql_indicator",
                            "endpoint": endpoint,
                            "evidence": "NoSQL-style query may be processed"
                        })
                except:
                    pass

        return findings

    def _check_http2(self, domain: str) -> Dict:
        """Check HTTP/2 support and potential issues"""
        result = {
            "http2_supported": False,
            "alpn_protocols": [],
            "issues": []
        }

        try:
            context = ssl.create_default_context()
            context.set_alpn_protocols(['h2', 'http/1.1'])

            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    alpn = ssock.selected_alpn_protocol()
                    result["alpn_protocols"] = [alpn] if alpn else []

                    if alpn == 'h2':
                        result["http2_supported"] = True

        except Exception as e:
            result["error"] = str(e)

        # If HTTP/2 supported, check for potential issues
        if result["http2_supported"]:
            # Check if server properly handles HTTP/2
            url = f"https://{domain}/"
            resp = self.get(url, allow_redirects=True)

            if resp:
                # Check for HSTS (important for HTTP/2)
                if 'Strict-Transport-Security' not in resp.headers:
                    result["issues"].append("Missing HSTS with HTTP/2")

        return result

    def _check_grpc(self, domain: str) -> List[Dict]:
        """Check for gRPC endpoints"""
        findings = []

        for endpoint in self.GRPC_ENDPOINTS:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"

            # gRPC uses application/grpc content type
            headers = {
                "Content-Type": "application/grpc",
                "grpc-accept-encoding": "identity,deflate,gzip"
            }

            resp = self.post(url, data=b'', headers=headers)

            if resp and resp.status_code in [200, 415, 501]:
                content_type = resp.headers.get('Content-Type', '')
                if 'grpc' in content_type or resp.status_code == 415:
                    findings.append({
                        "type": "grpc_endpoint",
                        "endpoint": endpoint,
                        "evidence": f"gRPC endpoint detected"
                    })

        # Check for gRPC-web
        grpc_web_test = f"https://{domain}/api"
        headers = {"Content-Type": "application/grpc-web+proto"}
        resp = self.post(grpc_web_test, data=b'', headers=headers)

        if resp and 'grpc' in resp.headers.get('Content-Type', ''):
            findings.append({
                "type": "grpc_web",
                "endpoint": "/api",
                "evidence": "gRPC-web detected"
            })

        return findings

    def _check_server_sent_events(self, domain: str) -> List[Dict]:
        """Check for Server-Sent Events endpoints"""
        findings = []

        sse_endpoints = [
            "/events",
            "/sse",
            "/stream",
            "/api/events",
            "/api/stream",
            "/notifications/stream",
        ]

        for endpoint in sse_endpoints:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"

            headers = {"Accept": "text/event-stream"}
            resp = self.get(url, headers=headers, allow_redirects=False, timeout=5)

            if resp:
                content_type = resp.headers.get('Content-Type', '')
                if 'text/event-stream' in content_type:
                    findings.append({
                        "type": "sse_endpoint",
                        "endpoint": endpoint,
                        "evidence": f"SSE endpoint found: {endpoint}"
                    })

        return findings

    def _check_cors_websocket(self, domain: str) -> List[Dict]:
        """Check CORS configuration for API/WebSocket endpoints"""
        findings = []

        # Test various origins
        test_origins = [
            f"https://{domain}",  # Same origin
            "https://evil.com",
            f"https://{domain}.evil.com",
            "null",
        ]

        api_endpoints = ["/api/", "/api/user", "/graphql"]

        for endpoint in api_endpoints:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"

            for origin in test_origins:
                headers = {
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                }

                # Preflight request
                resp = self.session.options(url, headers=headers, timeout=self.timeout)

                if resp is None:
                    continue

                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')

                if origin == "https://evil.com" and acao == origin:
                    findings.append({
                        "type": "cors_reflection",
                        "endpoint": endpoint,
                        "origin": origin,
                        "credentials": acac.lower() == 'true',
                        "evidence": f"CORS reflects arbitrary origin: {origin}"
                    })

                if origin == "null" and acao == "null":
                    findings.append({
                        "type": "cors_null_origin",
                        "endpoint": endpoint,
                        "evidence": "CORS accepts null origin"
                    })

        return findings

    def scan(self, domain: str, progress: ScanProgress) -> List[Finding]:
        """Scan domain for protocol-specific vulnerabilities"""
        findings = []
        self.log(f"Testing protocol attacks on {domain}")

        # Check WebSocket
        self.log("Checking WebSocket endpoints")
        ws_findings = self._check_websocket_support(domain)

        for wf in ws_findings:
            finding = self.create_finding(
                domain=domain,
                severity="info",
                title=f"WebSocket: {wf['type'].replace('_', ' ').title()}",
                description=f"WebSocket endpoint detected",
                evidence=wf["evidence"],
                reproduction_steps=[
                    f"Endpoint: {wf['endpoint']}"
                ]
            )
            findings.append(finding)
            progress.add_finding(domain, finding)

            # Test for CSWSH
            if wf["type"] == "websocket_endpoint":
                cswsh_findings = self._test_websocket_csrf(domain, wf["endpoint"])

                for cf in cswsh_findings:
                    finding = self.create_finding(
                        domain=domain,
                        severity="high",
                        title=f"CSWSH: {cf['type'].replace('_', ' ').title()}",
                        description="Cross-Site WebSocket Hijacking possible",
                        evidence=cf["evidence"],
                        reproduction_steps=[
                            f"Endpoint: {cf['endpoint']}",
                            "WebSocket accepts cross-origin connections"
                        ]
                    )
                    findings.append(finding)
                    progress.add_finding(domain, finding)

        # Check GraphQL
        if not is_shutdown():
            self.log("Checking GraphQL endpoints")
            gql_findings = self._check_graphql(domain)

            for gf in gql_findings:
                severity_map = {
                    "graphql_introspection": "medium",
                    "graphql_sensitive_types": "high",
                    "graphql_batching": "low",
                    "graphql_field_suggestion": "low",
                }
                severity = severity_map.get(gf["type"], "info")

                finding = self.create_finding(
                    domain=domain,
                    severity=severity,
                    title=f"GraphQL: {gf['type'].replace('_', ' ').title()}",
                    description=gf["evidence"],
                    evidence=gf["evidence"],
                    reproduction_steps=[
                        f"Endpoint: {gf['endpoint']}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

                # Test injection on GraphQL endpoints
                if gf["type"] == "graphql_introspection":
                    inj_findings = self._test_graphql_injection(domain, gf["endpoint"])

                    for inf in inj_findings:
                        finding = self.create_finding(
                            domain=domain,
                            severity="high",
                            title=f"GraphQL Injection: {inf['type']}",
                            description="Injection vulnerability in GraphQL",
                            evidence=inf["evidence"],
                            reproduction_steps=[
                                f"Endpoint: {inf['endpoint']}",
                                f"Payload: {inf.get('payload', 'N/A')}"
                            ]
                        )
                        findings.append(finding)
                        progress.add_finding(domain, finding)

        # Check HTTP/2
        if not is_shutdown():
            self.log("Checking HTTP/2 support")
            h2_result = self._check_http2(domain)

            if h2_result["http2_supported"]:
                finding = self.create_finding(
                    domain=domain,
                    severity="info",
                    title="HTTP/2 Supported",
                    description=f"Target supports HTTP/2",
                    evidence=f"ALPN: {h2_result['alpn_protocols']}",
                    reproduction_steps=[
                        "HTTP/2 negotiated via ALPN"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

                for issue in h2_result["issues"]:
                    finding = self.create_finding(
                        domain=domain,
                        severity="low",
                        title=f"HTTP/2 Issue: {issue}",
                        description=issue,
                        evidence=issue,
                        reproduction_steps=["Check security headers for HTTP/2"]
                    )
                    findings.append(finding)
                    progress.add_finding(domain, finding)

        # Check gRPC
        if not is_shutdown():
            self.log("Checking gRPC endpoints")
            grpc_findings = self._check_grpc(domain)

            for grf in grpc_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="info",
                    title=f"gRPC: {grf['type'].replace('_', ' ').title()}",
                    description="gRPC endpoint detected",
                    evidence=grf["evidence"],
                    reproduction_steps=[
                        f"Endpoint: {grf['endpoint']}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Check SSE
        if not is_shutdown():
            self.log("Checking Server-Sent Events")
            sse_findings = self._check_server_sent_events(domain)

            for sf in sse_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="info",
                    title="SSE Endpoint Detected",
                    description="Server-Sent Events endpoint",
                    evidence=sf["evidence"],
                    reproduction_steps=[
                        f"Endpoint: {sf['endpoint']}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Check CORS for WebSocket/API
        if not is_shutdown():
            self.log("Checking CORS configuration")
            cors_findings = self._check_cors_websocket(domain)

            for corf in cors_findings:
                severity = "high" if corf.get("credentials") else "medium"
                finding = self.create_finding(
                    domain=domain,
                    severity=severity,
                    title=f"CORS: {corf['type'].replace('_', ' ').title()}",
                    description="CORS misconfiguration on API endpoint",
                    evidence=corf["evidence"],
                    reproduction_steps=[
                        f"Endpoint: {corf['endpoint']}",
                        f"Origin tested: {corf.get('origin', 'N/A')}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        self.log(f"Completed: {len(findings)} protocol issues found", "success" if findings else "info")
        return findings
