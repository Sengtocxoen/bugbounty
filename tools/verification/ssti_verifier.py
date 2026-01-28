"""
SSTI (Server-Side Template Injection) Verifier
===============================================

Tests for template injection vulnerabilities in various template engines.
"""

import requests
from urllib.parse import quote, urlencode
from typing import Dict, List, Optional
from . import BaseVerifier, VerificationResult, Severity, ConfidenceLevel


class SSTIVerifier(BaseVerifier):
    """Verifies Server-Side Template Injection vulnerabilities"""
    
    # Template engine test payloads
    PAYLOADS = [
        # Flask/Jinja2
        {
            "engine": "Jinja2/Flask",
            "payload": "{{7*7}}",
            "expected": "49",
            "severity": Severity.CRITICAL,
        },
        {
            "engine": "Jinja2/Flask",
            "payload": "{{config}}",
            "expected": ["SECRET_KEY", "DEBUG", "config"],
            "severity": Severity.CRITICAL,
        },
        # Twig
        {
            "engine": "Twig",
            "payload": "{{7*'7'}}",
            "expected": "7777777",
            "severity": Severity.CRITICAL,
        },
        # Freemarker
        {
            "engine": "Freemarker",
            "payload": "${7*7}",
            "expected": "49",
            "severity": Severity.CRITICAL,
        },
        # Smarty
        {
            "engine": "Smarty",
            "payload": "{7*7}",
            "expected": "49",
            "severity": Severity.CRITICAL,
        },
        # Velocity
        {
            "engine": "Velocity",
            "payload": "#set($x=7*7)$x",
            "expected": "49",
            "severity": Severity.CRITICAL,
        },
        # ERB (Ruby)
        {
            "engine": "ERB",
            "payload": "<%= 7*7 %>",
            "expected": "49",
            "severity": Severity.CRITICAL,
        },
    ]
    
    def verify_url(self, url: str, parameter: Optional[str] = None) -> VerificationResult:
        """
        Test URL for SSTI vulnerabilities
        
        Args:
            url: URL to test
            parameter: Optional specific parameter to test
        
        Returns:
            VerificationResult with SSTI findings
        """
        if not url.startswith('http'):
            url = f"https://{url}"
        
        try:
            # If parameter specified, inject there
            if parameter:
                return self._test_parameter(url, parameter)
            
            # Otherwise, test common injection points
            results = []
            
            # Test query parameters
            if '?' in url:
                base_url = url.split('?')[0]
                query_string = url.split('?')[1]
                params = dict(p.split('=') for p in query_string.split('&') if '=' in p)
                
                for param_name in params.keys():
                    result = self._test_parameter(url, param_name)
                    if result.verified:
                        return result
            
            # Test path injection
            path_result = self._test_path_injection(url)
            if path_result.verified:
                return path_result
            
            # No SSTI found
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.HIGH,
                severity=Severity.INFO,
                finding_type="no_ssti",
                target=url,
                details="No SSTI vulnerability detected",
                proof={}
            )
        
        except Exception as e:
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.UNVERIFIED,
                severity=Severity.INFO,
                finding_type="verification_error",
                target=url,
                details=f"Error: {str(e)}",
                proof={}
            )
    
    def _test_parameter(self, url: str, parameter: str) -> VerificationResult:
        """Test a specific parameter for SSTI"""
        
        for payload_data in self.PAYLOADS:
            payload = payload_data["payload"]
            expected = payload_data["expected"]
            engine = payload_data["engine"]
            
            try:
                # Build test URL
                if '?' in url:
                    base_url, query_string = url.split('?', 1)
                    params = dict(p.split('=', 1) for p in query_string.split('&') if '=' in p)
                    params[parameter] = payload
                    test_url = f"{base_url}?{urlencode(params)}"
                else:
                    test_url = f"{url}?{parameter}={quote(payload)}"
                
                # Send request
                response = requests.get(
                    test_url,
                    headers=self.get_headers(),
                    timeout=self.timeout,
                    verify=False
                )
                
                # Check if payload was reflected and evaluated
                if isinstance(expected, list):
                    # Multiple possible indicators
                    if any(exp in response.text for exp in expected):
                        return VerificationResult(
                            verified=True,
                            confidence=ConfidenceLevel.CONFIRMED,
                            severity=payload_data["severity"],
                            finding_type="ssti_vulnerability",
                            target=url,
                            details=f"SSTI vulnerability confirmed! {engine} template engine detected. Payload executed: {payload}",
                            proof={
                                "engine": engine,
                                "parameter": parameter,
                                "payload": payload,
                                "response_snippet": response.text[:500],
                                "test_url": test_url,
                            },
                            remediation="Never pass user input directly to template rendering. Use safe template rendering with auto-escaping.",
                            cvss_score=9.8
                        )
                else:
                    # Exact match
                    if expected in response.text and payload not in response.text:
                        # Payload was evaluated (expected result appears but not the payload itself)
                        return VerificationResult(
                            verified=True,
                            confidence=ConfidenceLevel.CONFIRMED,
                            severity=payload_data["severity"],
                            finding_type="ssti_vulnerability",
                            target=url,
                            details=f"SSTI vulnerability confirmed! {engine} template engine. Payload '{payload}' evaluated to '{expected}'",
                            proof={
                                "engine": engine,
                                "parameter": parameter,
                                "payload": payload,
                                "expected_result": expected,
                                "found_in_response": True,
                                "response_snippet": response.text[:500],
                            },
                            remediation="Never pass user input to template rendering. Disable template evaluation for user input.",
                            cvss_score=9.8
                        )
            
            except:
                continue
        
        return VerificationResult(
            verified=False,
            confidence=ConfidenceLevel.HIGH,
            severity=Severity.INFO,
            finding_type="no_ssti",
            target=url,
            details=f"No SSTI found in parameter '{parameter}'",
            proof={}
        )
    
    def _test_path_injection(self, url: str) -> VerificationResult:
        """Test for SSTI in URL path"""
        
        for payload_data in self.PAYLOADS:
            payload = payload_data["payload"]
            expected = payload_data["expected"]
            engine = payload_data["engine"]
            
            try:
                # Inject payload in path
                test_url = f"{url.rstrip('/')}/{quote(payload)}"
                
                response = requests.get(
                    test_url,
                    headers=self.get_headers(),
                    timeout=self.timeout,
                    verify=False
                )
                
                if isinstance(expected, str) and expected in response.text and payload not in response.text:
                    return VerificationResult(
                        verified=True,
                        confidence=ConfidenceLevel.CONFIRMED,
                        severity=payload_data["severity"],
                        finding_type="ssti_path_injection",
                        target=url,
                        details=f"SSTI in URL path! {engine} engine. Payload evaluated.",
                        proof={
                            "engine": engine,
                            "injection_point": "URL path",
                            "payload": payload,
                            "expected_result": expected,
                            "test_url": test_url,
                        },
                        cvss_score=9.8
                    )
            
            except:
                continue
        
        return VerificationResult(
            verified=False,
            confidence=ConfidenceLevel.MEDIUM,
            severity=Severity.INFO,
            finding_type="no_ssti",
            target=url,
            details="No SSTI found in URL path",
            proof={}
        )
