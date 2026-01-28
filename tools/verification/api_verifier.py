"""
API Endpoint Verifier
======================

Verifies API endpoint accessibility and documentation exposure.
"""

import requests
import json
from typing import Optional, List, Dict
from . import BaseVerifier, VerificationResult, Severity, ConfidenceLevel


class APIVerifier(BaseVerifier):
    """Verifies API endpoint exposure"""
    
    API_PATHS = [
        "/api",
        "/api/v1",
        "/api/v2",
        "/api/v3",
        "/v1",
        "/v2",
        "/rest",
        "/restapi",
    ]
    
    DOC_PATHS = [
        "/swagger.json",
        "/swagger.yaml",
        "/openapi.json",
        "/openapi.yaml",
        "/api-docs",
        "/api/docs",
        "/api/swagger",
        "/docs",
        "/api.json",
    ]
    
    def verify_api(self, base_url: str) -> List[VerificationResult]:
        """Verify API endpoints"""
        if not base_url.startswith('http'):
            base_url = f"https://{base_url}"
        
        base_url = base_url.rstrip('/')
        results = []
        
        # Check API paths
        for path in self.API_PATHS:
            url = f"{base_url}{path}"
            result = self._check_api_endpoint(url)
            if result.verified:
                results.append(result)
        
        # Check documentation
        doc_results = self.verify_documentation(base_url)
        results.extend([r for r in doc_results if r.verified])
        
        return results if results else [VerificationResult(
            verified=False,
            confidence=ConfidenceLevel.HIGH,
            severity=Severity.INFO,
            finding_type="no_api",
            target=base_url,
            details="No accessible API endpoints found",
            proof={}
        )]
    
    def _check_api_endpoint(self, url: str) -> VerificationResult:
        """Check a specific API endpoint"""
        try:
            # Try different HTTP methods
            methods_tried = []
            
            for method in ['GET', 'POST', 'OPTIONS']:
                try:
                    if method == 'GET':
                        response = requests.get(url, headers=self.get_headers(), timeout=self.timeout, verify=False)
                    elif method == 'OPTIONS':
                        response = requests.options(url, headers=self.get_headers(), timeout=self.timeout, verify=False)
                    else:
                        response = requests.post(url, headers=self.get_headers(), timeout=self.timeout, verify=False)
                    
                    methods_tried.append({
                        "method": method,
                        "status": response.status_code,
                        "content_type": response.headers.get("Content-Type"),
                    })
                    
                    # Check if it's a valid API response
                    if response.status_code in [200, 401, 403]:
                        content_type = response.headers.get("Content-Type", "")
                        
                        # Try to parse as JSON
                        is_json = False
                        endpoints = []
                        
                        if "json" in content_type.lower():
                            try:
                                data = response.json()
                                is_json = True
                                
                                # Try to extract endpoint information
                                if isinstance(data, dict):
                                    endpoints = list(data.keys())[:10]
                            except:
                                pass
                        
                        # Determine severity
                        if response.status_code == 200:
                            if is_json:
                                severity = Severity.MEDIUM
                                finding_type = "api_endpoint_accessible"
                                details = f"API endpoint accessible at {url}. Returns JSON data."
                            else:
                                severity = Severity.LOW
                                finding_type = "api_endpoint_found"
                                details = f"API endpoint found at {url}."
                        else:
                            severity = Severity.LOW
                            finding_type = "api_requires_auth"
                            details = f"API endpoint exists at {url} but requires authentication."
                        
                        return VerificationResult(
                            verified=True,
                            confidence=ConfidenceLevel.CONFIRMED,
                            severity=severity,
                            finding_type=finding_type,
                            target=url,
                            details=details,
                            proof={
                                "url": url,
                                "status_code": response.status_code,
                                "content_type": content_type,
                                "is_json": is_json,
                                "endpoints": endpoints,
                                "methods_allowed": [m["method"] for m in methods_tried if m["status"] < 405],
                                "cors_headers": response.headers.get("Access-Control-Allow-Origin"),
                            },
                            remediation="Ensure API requires proper authentication and authorization"
                        )
                
                except requests.exceptions.RequestException:
                    continue
            
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.CONFIRMED,
                severity=Severity.INFO,
                finding_type="api_not_found",
                target=url,
                details="API endpoint not accessible",
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
    
    def verify_documentation(self, base_url: str) -> List[VerificationResult]:
        """Check for exposed API documentation"""
        if not base_url.startswith('http'):
            base_url = f"https://{base_url}"
        
        base_url = base_url.rstrip('/')
        results = []
        
        for path in self.DOC_PATHS:
            url = f"{base_url}{path}"
            
            try:
                response = requests.get(
                    url,
                    headers=self.get_headers(),
                    timeout=self.timeout,
                    verify=False
                )
                
                if response.status_code == 200 and len(response.content) > 0:
                    content_type = response.headers.get("Content-Type", "")
                    
                    # Check if it's OpenAPI/Swagger documentation
                    is_swagger = False
                    endpoints_count = 0
                    
                    if "json" in content_type.lower() or path.endswith('.json'):
                        try:
                            data = response.json()
                            
                            # Check for OpenAPI/Swagger structure
                            if any(key in data for key in ["swagger", "openapi", "paths"]):
                                is_swagger = True
                                
                                if "paths" in data:
                                    endpoints_count = len(data["paths"])
                        except:
                            pass
                    
                    elif "yaml" in content_type.lower() or path.endswith('.yaml'):
                        is_swagger = "swagger" in response.text.lower() or "openapi" in response.text.lower()
                    
                    if is_swagger or len(response.content) > 100:
                        results.append(VerificationResult(
                            verified=True,
                            confidence=ConfidenceLevel.CONFIRMED,
                            severity=Severity.MEDIUM,
                            finding_type="api_documentation_exposed",
                            target=url,
                            details=f"API documentation exposed! {'Swagger/OpenAPI' if is_swagger else 'Documentation'} found at {path}",
                            proof={
                                "url": url,
                                "is_swagger": is_swagger,
                                "endpoints_count": endpoints_count,
                                "content_length": len(response.content),
                                "content_type": content_type,
                            },
                            remediation="Remove API documentation from production or require authentication",
                            cvss_score=5.3
                        ))
            
            except:
                continue
        
        return results
