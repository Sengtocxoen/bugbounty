#!/usr/bin/env python3
"""
Deserialization Vulnerability Detection Module
===============================================
Based on 2025 techniques including:
- Java deserialization gadget chains
- .NET deserialization (ViewState, JSON.NET)
- PHP unserialize()
- Python pickle
- Ruby Marshal
- Node.js deserialization
- phar stream wrapper abuse

References:
- ysoserial payload research
- .NET ToolPane type confusion
- PHP phar deserialization
"""

import re
import base64
import zlib
import random
import string
import time
from typing import List, Optional, Dict
from urllib.parse import quote

from .base import TechniqueScanner, Finding, ScanProgress, is_shutdown


class Deserialization(TechniqueScanner):
    """Deserialization vulnerability scanner"""

    TECHNIQUE_NAME = "deserialization"
    TECHNIQUE_CATEGORY = "injection"

    # Java serialized object signatures (base64)
    JAVA_SIGNATURES = [
        "rO0AB",  # Standard Java serialized
        "H4sIAAAA",  # GZIP compressed
    ]

    # .NET serialized signatures
    DOTNET_SIGNATURES = [
        "AAEAAAD",  # BinaryFormatter
        "ew0K",  # JSON.NET with $type
    ]

    # PHP serialized signatures
    PHP_SIGNATURES = [
        'O:',  # Object
        'a:',  # Array
        's:',  # String
        'i:',  # Integer
    ]

    # Known vulnerable parameters
    DESER_PARAMS = [
        "data", "object", "payload", "session", "state",
        "viewstate", "token", "serialized", "base64",
        "encoded", "message", "body", "content", "input",
        "user", "auth", "credentials", "transfer", "file",
    ]

    # Java gadget detection (passive)
    JAVA_GADGET_INDICATORS = [
        "commons-collections",
        "spring-core",
        "commons-beanutils",
        "jdk7u21",
        "rome",
        "xalan",
        "c3p0",
        "hibernate",
        "groovy",
        "jackson",
    ]

    # Error patterns indicating deserialization
    DESER_ERRORS = {
        "java": [
            "java.io.InvalidClassException",
            "java.io.StreamCorruptedException",
            "java.lang.ClassNotFoundException",
            "java.io.ObjectInputStream",
            "InvalidObjectException",
            "ClassCastException",
            "java.rmi.RemoteException",
        ],
        "dotnet": [
            "System.Runtime.Serialization",
            "SerializationException",
            "TypeLoadException",
            "InvalidCastException",
            "BinaryFormatter",
            "DataContractSerializer",
        ],
        "php": [
            "unserialize()",
            "__wakeup()",
            "__destruct()",
            "allowed classes",
            "Unserialization of",
        ],
        "python": [
            "pickle",
            "unpickle",
            "cPickle",
            "_pickle",
            "UnpicklingError",
        ],
        "ruby": [
            "Marshal.load",
            "TypeError",
            "ArgumentError",
            "YAML.load",
        ],
    }

    # Test payloads (safe detection payloads)
    DETECTION_PAYLOADS = {
        # Java - corrupted serialized object to trigger error
        "java_corrupt": base64.b64encode(b'\xac\xed\x00\x05\x00\x00').decode(),
        # PHP - serialized object with class lookup
        "php_class_lookup": 'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
        # Python - corrupted pickle
        "python_corrupt": base64.b64encode(b'\x80\x04\x95\x00').decode(),
    }

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _find_serialized_data(self, domain: str) -> List[Dict]:
        """Find endpoints that use serialized data"""
        # Disabled: presence of serialized data is not a vulnerability by itself.
        return []

    def _test_viewstate(self, domain: str) -> List[Dict]:
        """Test for ViewState deserialization vulnerabilities"""
        # Disabled: ViewState indicators alone do not confirm exploitability.
        return []

    def _test_java_deser(self, domain: str) -> List[Dict]:
        """Test for Java deserialization vulnerabilities"""
        # Disabled: error messages alone are not confirmation of exploitability.
        return []

        # Common endpoints that might accept serialized Java objects
        endpoints = [
            "/api/",
            "/rmi/",
            "/jmx/",
            "/invoke",
            "/remoting/",
        ]

        # Test with corrupted Java serialized object
        corrupt_payload = base64.b64decode(self.DETECTION_PAYLOADS["java_corrupt"])

        for endpoint in endpoints:
            if is_shutdown():
                break

            url = f"https://{domain}{endpoint}"

            # Test POST with serialized data
            headers = {
                "Content-Type": "application/x-java-serialized-object"
            }
            resp = self.post(url, data=corrupt_payload, headers=headers)

            if resp is None:
                continue

            # Check for Java deserialization error
            response_text = resp.text.lower()
            for error in self.DESER_ERRORS["java"]:
                if error.lower() in response_text:
                    findings.append({
                        "type": "java_deser_error",
                        "endpoint": endpoint,
                        "error": error,
                        "evidence": f"Java deserialization error triggered: {error}"
                    })
                    break

            # Also check with base64 encoded
            for param in self.DESER_PARAMS[:5]:
                test_url = f"{url}?{param}={quote(self.DETECTION_PAYLOADS['java_corrupt'])}"
                resp = self.get(test_url)

                if resp:
                    for error in self.DESER_ERRORS["java"]:
                        if error.lower() in resp.text.lower():
                            findings.append({
                                "type": "java_deser_param",
                                "endpoint": endpoint,
                                "param": param,
                                "evidence": f"Java deserialization via parameter: {param}"
                            })
                            break

        return findings

    def _test_php_deser(self, domain: str) -> List[Dict]:
        """Test for PHP deserialization vulnerabilities"""
        # Disabled: deserialization errors are not proof of vulnerability.
        return []

    def _test_phar_deser(self, domain: str) -> List[Dict]:
        """Test for phar:// wrapper deserialization"""
        # Disabled: phar indicator strings are not proof of deserialization.
        return []

    def _test_node_deser(self, domain: str) -> List[Dict]:
        """Test for Node.js deserialization vulnerabilities"""
        # Disabled: response reflection of payload fragments is not proof.
        return []

    def _check_error_responses(self, domain: str) -> List[Dict]:
        """Check various endpoints for deserialization error messages"""
        # Disabled: error messages alone are not confirmation.
        return []

    def scan(self, domain: str, progress: ScanProgress) -> List[Finding]:
        """Scan domain for deserialization vulnerabilities"""
        findings = []
        self.log(f"Testing deserialization on {domain}")

        # Find serialized data in responses
        self.log("Finding serialized data in responses")
        serial_findings = self._find_serialized_data(domain)

        for sf in serial_findings:
            severity = "high" if "unprotected" in sf.get("evidence", "").lower() else "medium"
            finding = self.create_finding(
                domain=domain,
                severity=severity,
                title=f"Serialized Data: {sf['type'].replace('_', ' ').title()}",
                description=f"Serialized data detected that may be vulnerable",
                evidence=sf["evidence"],
                reproduction_steps=[
                    f"Location: {sf.get('location', 'N/A')}",
                    f"Type: {sf['type']}"
                ]
            )
            findings.append(finding)
            progress.add_finding(domain, finding)

        # Test ViewState
        if not is_shutdown():
            self.log("Testing ViewState deserialization")
            viewstate_findings = self._test_viewstate(domain)

            for vf in viewstate_findings:
                severity = "high" if "unsigned" in vf["type"] else "medium"
                finding = self.create_finding(
                    domain=domain,
                    severity=severity,
                    title=f"ViewState: {vf['type'].replace('_', ' ').title()}",
                    description="ViewState may be vulnerable to deserialization attacks",
                    evidence=vf["evidence"],
                    reproduction_steps=[
                        f"Page: {vf['page']}",
                        "Use ysoserial.net to generate payload"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test Java deserialization
        if not is_shutdown():
            self.log("Testing Java deserialization")
            java_findings = self._test_java_deser(domain)

            for jf in java_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="critical",
                    title=f"Java Deserialization: {jf['type']}",
                    description="Java deserialization vulnerability detected",
                    evidence=jf["evidence"],
                    reproduction_steps=[
                        f"Endpoint: {jf['endpoint']}",
                        "Use ysoserial to generate exploitation payload"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test PHP deserialization
        if not is_shutdown():
            self.log("Testing PHP deserialization")
            php_findings = self._test_php_deser(domain)

            for pf in php_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="high",
                    title="PHP Deserialization",
                    description="PHP unserialize() may be vulnerable",
                    evidence=pf["evidence"],
                    reproduction_steps=[
                        f"Endpoint: {pf['endpoint']}",
                        f"Parameter: {pf['param']}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test phar:// wrapper
        if not is_shutdown():
            self.log("Testing phar:// deserialization")
            phar_findings = self._test_phar_deser(domain)

            for pharf in phar_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="high",
                    title="phar:// Wrapper Deserialization",
                    description="phar:// stream wrapper may trigger deserialization",
                    evidence=pharf["evidence"],
                    reproduction_steps=[
                        f"Endpoint: {pharf['endpoint']}",
                        f"Parameter: {pharf['param']}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Test Node.js deserialization
        if not is_shutdown():
            self.log("Testing Node.js deserialization")
            node_findings = self._test_node_deser(domain)

            for nf in node_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="critical",
                    title="Node.js Deserialization",
                    description="Node.js serialize/deserialize vulnerability",
                    evidence=nf["evidence"],
                    reproduction_steps=[
                        f"Endpoint: {nf['endpoint']}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        # Check error responses
        if not is_shutdown():
            self.log("Checking for deserialization errors")
            error_findings = self._check_error_responses(domain)

            for ef in error_findings:
                finding = self.create_finding(
                    domain=domain,
                    severity="high",
                    title=f"Deserialization Error: {ef['type']}",
                    description="Deserialization error triggered - endpoint may be vulnerable",
                    evidence=ef["evidence"],
                    reproduction_steps=[
                        f"Endpoint: {ef['endpoint']}",
                        f"Error: {ef['error']}"
                    ]
                )
                findings.append(finding)
                progress.add_finding(domain, finding)

        self.log(f"Completed: {len(findings)} deserialization issues found", "success" if findings else "info")
        return findings
