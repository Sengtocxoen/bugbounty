"""
Admin Panel Verifier
====================

Verifies admin panel accessibility and authentication requirements.
"""

import requests
from bs4 import BeautifulSoup
from typing import Optional, List, Dict
from . import BaseVerifier, VerificationResult, Severity, ConfidenceLevel


class AdminVerifier(BaseVerifier):
    """Verifies admin panel exposure and accessibility"""
    
    ADMIN_PATHS = [
        "/admin",
        "/administrator",
        "/adminer",
        "/admin.php",
        "/admin/login",
        "/admin/index.php",
        "/wp-admin",
        "/phpmyadmin",
        "/cpanel",
        "/panel",
        "/dashboard",
        "/manage",
        "/admin-console",
        "/backend",
    ]
    
    LOGIN_INDICATORS = [
        "login",
        "password",
        "username",
        "sign in",
        "log in",
        "authentication",
        "csrf",
        "token",
    ]
    
    def verify(self, base_url: str, check_default_creds: bool = False) -> List[VerificationResult]:
        """
        Verify admin panel accessibility
        
        Args:
            base_url: Base URL to check
            check_default_creds: Whether to test default credentials (disabled by default)
        
        Returns:
            List of VerificationResults for found admin panels
        """
        if not base_url.startswith('http'):
            base_url = f"https://{base_url}"
        
        base_url = base_url.rstrip('/')
        results = []
        
        for path in self.ADMIN_PATHS:
            url = f"{base_url}{path}"
            result = self._check_admin_path(url, check_default_creds)
            if result.verified:
                results.append(result)
        
        return results if results else [VerificationResult(
            verified=False,
            confidence=ConfidenceLevel.HIGH,
            severity=Severity.INFO,
            finding_type="no_admin_panel",
            target=base_url,
            details="No accessible admin panels found",
            proof={}
        )]
    
    def _check_admin_path(self, url: str, check_default_creds: bool) -> VerificationResult:
        """Check a specific admin path"""
        try:
            response = requests.get(
                url,
                headers=self.get_headers(),
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )
            
            # 200 - Admin panel is accessible
            if response.status_code == 200:
                content_lower = response.text.lower()
                
                # Check if it's a login page
                is_login_page = sum(1 for indicator in self.LOGIN_INDICATORS if indicator in content_lower) >= 2
                
                # Parse page for details
                details = self._parse_admin_page(response.text)
                
                if is_login_page:
                    severity = Severity.MEDIUM
                    finding_type = "admin_login_page"
                    description = f"Admin login page found at {url}"
                    cvss = 4.3
                else:
                    # Accessible without login - CRITICAL
                    severity = Severity.HIGH
                    finding_type = "admin_panel_accessible"
                    description = f"Admin panel accessible without authentication at {url}!"
                    cvss = 7.5
                
                # Test default credentials if enabled
                creds_tested = False
                creds_successful = False
                if check_default_creds and is_login_page:
                    creds_successful = self._test_default_credentials(url, response.text)
                    creds_tested = True
                    if creds_successful:
                        severity = Severity.CRITICAL
                        finding_type = "admin_default_credentials"
                        description = f"Admin panel login with DEFAULT CREDENTIALS at {url}!"
                        cvss = 9.8
                
                return VerificationResult(
                    verified=True,
                    confidence=ConfidenceLevel.CONFIRMED,
                    severity=severity,
                    finding_type=finding_type,
                    target=url,
                    details=description,
                    proof={
                        "url": url,
                        "status_code": response.status_code,
                        "is_login_page": is_login_page,
                        "page_title": details.get("title"),
                        "form_action": details.get("form_action"),
                        "default_creds_tested": creds_tested,
                        "default_creds_successful": creds_successful,
                        "content_length": len(response.content),
                    },
                    remediation="Protect admin panel with strong authentication, IP whitelisting, or VPN access",
                    cvss_score=cvss
                )
            
            # 401/403 - Exists but protected
            elif response.status_code in [401, 403]:
                return VerificationResult(
                    verified=True,
                    confidence=ConfidenceLevel.CONFIRMED,
                    severity=Severity.LOW,
                    finding_type="admin_panel_protected",
                    target=url,
                    details=f"Admin panel exists at {url} but is {'forbidden' if response.status_code == 403 else 'requires authentication'}",
                    proof={
                        "url": url,
                        "status_code": response.status_code,
                        "www_authenticate": response.headers.get("WWW-Authenticate"),
                    }
                )
            
            # 404 - Not found
            elif response.status_code == 404:
                return VerificationResult(
                    verified=False,
                    confidence=ConfidenceLevel.CONFIRMED,
                    severity=Severity.INFO,
                    finding_type="admin_not_found",
                    target=url,
                    details=f"Admin path not found (404)",
                    proof={}
                )
            
            else:
                return VerificationResult(
                    verified=False,
                    confidence=ConfidenceLevel.MEDIUM,
                    severity=Severity.INFO,
                    finding_type="admin_unknown_status",
                    target=url,
                    details=f"Unusual status code: {response.status_code}",
                    proof={"status_code": response.status_code}
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
    
    def _parse_admin_page(self, html: str) -> Dict:
        """Parse admin page for details"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            title = soup.find('title')
            title_text = title.string if title else None
            
            # Find login form
            form = soup.find('form')
            form_action = form.get('action') if form else None
            
            return {
                "title": title_text,
                "form_action": form_action,
            }
        except:
            return {}
    
    def _test_default_credentials(self, url: str, html: str) -> bool:
        """
        Test common default credentials
        WARNING: Only use this on assets you own or have permission to test
        """
        DEFAULT_CREDS = [
            ("admin", "admin"),
            ("admin", "password"),
            ("administrator", "administrator"),
            ("root", "root"),
            ("admin", ""),
        ]
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            form = soup.find('form')
            if not form:
                return False
            
            action = form.get('action', '')
            method = form.get('method', 'post').lower()
            
            # Build form URL
            if action.startswith('http'):
                form_url = action
            elif action.startswith('/'):
                base = '/'.join(url.split('/')[:3])
                form_url = f"{base}{action}"
            else:
                form_url = f"{url.rsplit('/', 1)[0]}/{action}" if action else url
            
            # Find input fields
            inputs = form.find_all('input')
            username_field = None
            password_field = None
            
            for inp in inputs:
                input_type = inp.get('type', '').lower()
                input_name = inp.get('name', '').lower()
                
                if input_type == 'password' or 'pass' in input_name:
                    password_field = inp.get('name')
                elif input_type == 'text' or 'user' in input_name or 'login' in input_name:
                    username_field = inp.get('name')
            
            if not (username_field and password_field):
                return False
            
            # Test default credentials
            for username, password in DEFAULT_CREDS:
                data = {
                    username_field: username,
                    password_field: password,
                }
                
                # Add other form fields
                for inp in inputs:
                    if inp.get('name') not in [username_field, password_field]:
                        data[inp.get('name')] = inp.get('value', '')
                
                try:
                    if method == 'post':
                        response = requests.post(
                            form_url,
                            data=data,
                            headers=self.get_headers(),
                            timeout=self.timeout,
                            allow_redirects=False,
                            verify=False
                        )
                    else:
                        response = requests.get(
                            form_url,
                            params=data,
                            headers=self.get_headers(),
                            timeout=self.timeout,
                            allow_redirects=False,
                            verify=False
                        )
                    
                    # Check for successful login indicators
                    if response.status_code in [200, 301, 302]:
                        content_lower = response.text.lower()
                        success_indicators = ["dashboard", "welcome", "logout", "admin panel"]
                        failure_indicators = ["invalid", "incorrect", "failed", "error"]
                        
                        has_success = any(ind in content_lower for ind in success_indicators)
                        has_failure = any(ind in content_lower for ind in failure_indicators)
                        
                        if has_success and not has_failure:
                            return True
                
                except:
                    continue
        
        except:
            pass
        
        return False
