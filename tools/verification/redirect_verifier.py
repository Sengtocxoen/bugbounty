"""
HTTP Redirect Verifier
======================

Follows HTTP redirects to verify if endpoints actually exist.
Helps filter out false positives from path brute-forcing.
"""

import requests
from urllib.parse import urljoin, urlparse
from typing import Optional, List, Tuple
from . import BaseVerifier, VerificationResult, Severity, ConfidenceLevel


class RedirectVerifier(BaseVerifier):
    """Verifies endpoints by following redirects"""
    
    def __init__(self, user_agent: Optional[str] = None, timeout: int = 10, max_redirects: int = 10):
        super().__init__(user_agent, timeout)
        self.max_redirects = max_redirects
    
    def verify(self, url: str, initial_status: Optional[int] = None) -> VerificationResult:
        """
        Follow redirects and verify if endpoint is accessible
        
        Args:
            url: URL to verify
            initial_status: Known initial status code (e.g., 301)
        
        Returns:
            VerificationResult with details about final destination
        """
        redirect_chain = []
        current_url = url
        
        try:
            for hop in range(self.max_redirects):
                response = requests.get(
                    current_url,
                    headers=self.get_headers(),
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False
                )
                
                redirect_chain.append({
                    "url": current_url,
                    "status": response.status_code,
                    "location": response.headers.get("Location"),
                })
                
                # Check if we've reached final destination
                if response.status_code not in [301, 302, 303, 307, 308]:
                    # Final response
                    return self._analyze_final_response(url, response, redirect_chain)
                
                # Follow redirect
                location = response.headers.get("Location")
                if not location:
                    break
                
                # Handle relative vs absolute redirects
                current_url = urljoin(current_url, location)
                
                # Detect redirect loops
                if current_url in [r["url"] for r in redirect_chain[:-1]]:
                    return VerificationResult(
                        verified=False,
                        confidence=ConfidenceLevel.CONFIRMED,
                        severity=Severity.INFO,
                        finding_type="redirect_loop",
                        target=url,
                        details=f"Redirect loop detected at {current_url}",
                        proof={"redirect_chain": redirect_chain}
                    )
            
            # Max redirects reached
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.MEDIUM,
                severity=Severity.LOW,
                finding_type="excessive_redirects",
                target=url,
                details=f"Too many redirects (>{self.max_redirects})",
                proof={"redirect_chain": redirect_chain}
            )
        
        except requests.exceptions.Timeout:
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.UNVERIFIED,
                severity=Severity.INFO,
                finding_type="timeout",
                target=url,
                details="Request timed out",
                proof={}
            )
        
        except Exception as e:
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.UNVERIFIED,
                severity=Severity.INFO,
                finding_type="connection_error",
                target=url,
                details=f"Error: {str(e)}",
                proof={}
            )
    
    def _analyze_final_response(
        self, 
        original_url: str, 
        response: requests.Response, 
        redirect_chain: List[Dict]
    ) -> VerificationResult:
        """Analyze the final response after following redirects"""
        
        status = response.status_code
        final_url = response.url or redirect_chain[-1]["url"]
        
        # 200 OK - Endpoint exists and is accessible
        if status == 200:
            content_length = len(response.content)
            content_type = response.headers.get("Content-Type", "")
            
            return VerificationResult(
                verified=True,
                confidence=ConfidenceLevel.CONFIRMED,
                severity=Severity.MEDIUM if len(redirect_chain) > 1 else Severity.LOW,
                finding_type="accessible_endpoint",
                target=original_url,
                details=f"Endpoint accessible after {len(redirect_chain)} redirect(s). Final URL: {final_url}",
                proof={
                    "final_url": final_url,
                    "status_code": status,
                    "content_length": content_length,
                    "content_type": content_type,
                    "redirect_chain": redirect_chain,
                    "redirects": len(redirect_chain) - 1,
                }
            )
        
        # 401/403 - Exists but requires authentication/forbidden
        elif status in [401, 403]:
            return VerificationResult(
                verified=True,
                confidence=ConfidenceLevel.CONFIRMED,
                severity=Severity.MEDIUM,
                finding_type="protected_endpoint",
                target=original_url,
                details=f"Endpoint exists but is {('forbidden' if status == 403 else 'requires authentication')}. Final URL: {final_url}",
                proof={
                    "final_url": final_url,
                    "status_code": status,
                    "redirect_chain": redirect_chain,
                },
                remediation="Check if authentication can be bypassed or default credentials exist"
            )
        
        # 404/410 - Not found (false positive)
        elif status in [404, 410]:
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.CONFIRMED,
                severity=Severity.INFO,
                finding_type="false_positive",
                target=original_url,
                details=f"Endpoint does not exist (HTTP {status}). Likely false positive from brute-force.",
                proof={
                    "final_url": final_url,
                    "status_code": status,
                    "redirect_chain": redirect_chain,
                }
            )
        
        # 500+ - Server error (endpoint exists but erroring)
        elif status >= 500:
            return VerificationResult(
                verified=True,
                confidence=ConfidenceLevel.HIGH,
                severity=Severity.LOW,
                finding_type="erroring_endpoint",
                target=original_url,
                details=f"Endpoint exists but returning server error ({status})",
                proof={
                    "final_url": final_url,
                    "status_code": status,
                    "redirect_chain": redirect_chain,
                }
            )
        
        # Other status codes
        else:
            return VerificationResult(
                verified=True,
                confidence=ConfidenceLevel.MEDIUM,
                severity=Severity.LOW,
                finding_type="unknown_status",
                target=original_url,
                details=f"Endpoint returned status {status}",
                proof={
                    "final_url": final_url,
                    "status_code": status,
                    "redirect_chain": redirect_chain,
                }
            )
    
    def verify_batch(self, endpoints: List[Dict]) -> List[VerificationResult]:
        """
        Verify multiple endpoints in batch
        
        Args:
            endpoints: List of endpoint dicts with 'url' and optional 'status_code'
        
        Returns:
            List of VerificationResults
        """
        results = []
        for ep in endpoints:
            url = ep.get("url")
            status = ep.get("status_code")
            if url:
                result = self.verify(url, status)
                results.append(result)
        return results
