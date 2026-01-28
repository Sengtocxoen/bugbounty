"""
Git Repository Verifier
========================

Verifies exposed .git repositories and tests if source code can be extracted.
"""

import requests
from typing import List, Dict, Optional
from . import BaseVerifier, VerificationResult, Severity, ConfidenceLevel


class GitVerifier(BaseVerifier):
    """Verifies .git repository exposure"""
    
    GIT_FILES = [
        ".git/config",
        ".git/HEAD",
        ".git/index",
        ".git/logs/HEAD",
        ".git/description",
    ]
    
    SENSITIVE_FILES = [
        ".env",
        ".env.local",
        ".env.production",
        "config.json",
        "config.yaml",
        "secrets.yaml",
        "application.properties",
    ]
    
    def verify(self, base_url: str) -> VerificationResult:
        """
        Test if .git repository is exposed
        
        Args:
            base_url: Base URL to test (e.g., https://example.com)
        
        Returns:
            VerificationResult with details about .git exposure
        """
        if not base_url.startswith('http'):
            base_url = f"https://{base_url}"
        
        base_url = base_url.rstrip('/')
        accessible_files = []
        
        try:
            # Test common .git files
            for git_file in self.GIT_FILES:
                url = f"{base_url}/{git_file}"
                try:
                    response = requests.get(
                        url,
                        headers=self.get_headers(),
                        timeout=self.timeout,
                        allow_redirects=True,
                        verify=False
                    )
                    
                    # Check if file is accessible
                    if response.status_code == 200:
                        content_length = len(response.content)
                        
                        # Validate it's actually a git file
                        if git_file == ".git/config" and b"[core]" in response.content:
                            accessible_files.append({
                                "file": git_file,
                                "size": content_length,
                                "preview": response.text[:200],
                            })
                        elif git_file == ".git/HEAD" and b"ref:" in response.content:
                            accessible_files.append({
                                "file": git_file,
                                "size": content_length,
                                "content": response.text.strip(),
                            })
                        elif content_length > 0:
                            accessible_files.append({
                                "file": git_file,
                                "size": content_length,
                            })
                
                except requests.exceptions.RequestException:
                    continue
            
            # If .git files are accessible, this is a critical finding
            if accessible_files:
                # Try to detect if full repository is downloadable
                extractable = self._check_extractability(base_url)
                
                severity = Severity.CRITICAL if extractable else Severity.HIGH
                details = f"Exposed .git repository! {len(accessible_files)} git files are accessible."
                if extractable:
                    details += " Full repository appears extractable using git-dumper or similar tools."
                
                return VerificationResult(
                    verified=True,
                    confidence=ConfidenceLevel.CONFIRMED,
                    severity=severity,
                    finding_type="git_repository_exposure",
                    target=base_url,
                    details=details,
                    proof={
                        "accessible_files": accessible_files,
                        "extractable": extractable,
                        "git_url": f"{base_url}/.git/",
                    },
                    remediation="Remove .git directory from web root or block access via .htaccess/nginx config",
                    cvss_score=9.1 if extractable else 8.2
                )
            
            else:
                return VerificationResult(
                    verified=False,
                    confidence=ConfidenceLevel.CONFIRMED,
                    severity=Severity.INFO,
                    finding_type="no_git_exposure",
                    target=base_url,
                    details=".git directory not accessible (false positive)",
                    proof={}
                )
        
        except Exception as e:
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.UNVERIFIED,
                severity=Severity.INFO,
                finding_type="verification_error",
                target=base_url,
                details=f"Error during verification: {str(e)}",
                proof={}
            )
    
    def _check_extractability(self, base_url: str) -> bool:
        """Check if the full repository can be extracted"""
        try:
            # Try to access .git/objects directory
            objects_url = f"{base_url}/.git/objects/"
            response = requests.get(
                objects_url,
                headers=self.get_headers(),
                timeout=self.timeout,
                verify=False
            )
            
            # If we can list objects or get a 403 (exists but denied), it's likely extractable
            if response.status_code in [200, 403]:
                return True
            
            return False
        
        except:
            return False
    
    def check_sensitive_files(self, base_url: str) -> List[Dict]:
        """Check for other sensitive files that might be exposed"""
        if not base_url.startswith('http'):
            base_url = f"https://{base_url}"
        
        base_url = base_url.rstrip('/')
        found_files = []
        
        for filename in self.SENSITIVE_FILES:
            try:
                url = f"{base_url}/{filename}"
                response = requests.get(
                    url,
                    headers=self.get_headers(),
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False
                )
                
                if response.status_code == 200 and len(response.content) > 0:
                    found_files.append({
                        "file": filename,
                        "size": len(response.content),
                        "url": url,
                    })
            
            except:
                continue
        
        return found_files
