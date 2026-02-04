#!/usr/bin/env python3
"""
Secret Validation Module
Validates extracted secrets (AWS keys, Firebase URLs, API keys) to reduce false positives.
Only reports secrets that are actually valid and potentially exploitable.
"""

import re
import requests
import time
from dataclasses import dataclass
from typing import Optional, Dict, List
from enum import Enum


class ValidationStatus(Enum):
    """Status of secret validation"""
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass
class ValidationResult:
    """Result of secret validation"""
    secret_type: str
    value: str  # Redacted or partial
    status: ValidationStatus
    details: str = ""
    confidence: str = "medium"  # low, medium, high
    validated_at: str = ""


class SecretValidator:
    """Validate extracted secrets to confirm they're active"""
    
    def __init__(self, timeout: int = 5, rate_limit: float = 2.0):
        """
        Initialize validator
        
        Args:
            timeout: Request timeout in seconds
            rate_limit: Requests per second for validation
        """
        self.timeout = timeout
        self.min_interval = 1.0 / rate_limit
        self.last_request = 0.0
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'BugBountySecurityResearch/1.0'
    
    def _rate_limit_wait(self):
        """Wait to respect rate limit"""
        now = time.time()
        elapsed = now - self.last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_request = time.time()
    
    def _redact_secret(self, value: str, keep_chars: int = 4) -> str:
        """Redact secret value"""
        if len(value) <= keep_chars * 2:
            return '*' * len(value)
        return value[:keep_chars] + '*' * (len(value) - keep_chars * 2) + value[-keep_chars:]
    
    def validate_aws_key(self, access_key: str, secret_key: Optional[str] = None) -> ValidationResult:
        """
        Validate AWS access key
        
        Note: Without secret key, we can only check format.
        With secret key, we attempt AWS STS GetCallerIdentity (safe, read-only).
        """
        result = ValidationResult(
            secret_type="aws_access_key",
            value=self._redact_secret(access_key),
            status=ValidationStatus.UNKNOWN
        )
        
        # Check format first
        if not re.match(r'^(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}$', access_key):
            result.status = ValidationStatus.INVALID
            result.details = "Invalid AWS access key format"
            result.confidence = "high"
            return result
        
        # If we don't have secret key, can't validate further
        if not secret_key:
            result.status = ValidationStatus.UNKNOWN
            result.details = "Valid format, but secret key needed for full validation"
            result.confidence = "low"
            return result
        
        # Attempt AWS STS GetCallerIdentity (safest way to check)
        # This is a read-only operation that doesn't modify anything
        self._rate_limit_wait()
        
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            
            # Create temporary session with the keys
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
            sts = session.client('sts')
            
            # GetCallerIdentity - safe, read-only
            response = sts.get_caller_identity()
            
            result.status = ValidationStatus.VALID
            result.details = f"Active AWS credentials! Account: {response.get('Account', 'Unknown')}"
            result.confidence = "high"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if 'InvalidClientTokenId' in error_code:
                result.status = ValidationStatus.INVALID
                result.details = "Invalid AWS credentials"
                result.confidence = "high"
            else:
                result.status = ValidationStatus.ERROR
                result.details = f"AWS error: {error_code}"
                result.confidence = "medium"
                
        except NoCredentialsError:
            result.status = ValidationStatus.INVALID
            result.details = "Invalid AWS credentials"
            result.confidence = "high"
            
        except ImportError:
            result.status = ValidationStatus.UNKNOWN
            result.details = "boto3 not installed, cannot validate AWS keys"
            result.confidence = "low"
            
        except Exception as e:
            result.status = ValidationStatus.ERROR
            result.details = f"Validation error: {str(e)[:100]}"
            result.confidence = "low"
        
        return result
    
    def validate_firebase_url(self, firebase_url: str) -> ValidationResult:
        """Validate Firebase URL by attempting to access it"""
        result = ValidationResult(
            secret_type="firebase_url",
            value=firebase_url,
            status=ValidationStatus.UNKNOWN
        )
        
        # Check format
        if not re.match(r'^https://[a-zA-Z0-9-]+\.firebaseio\.com/?', firebase_url):
            result.status = ValidationStatus.INVALID
            result.details = "Invalid Firebase URL format"
            result.confidence = "high"
            return result
        
        # Try to access .json endpoint (Firebase REST API)
        self._rate_limit_wait()
        
        try:
            test_url = firebase_url.rstrip('/') + '/.json'
            response = self.session.get(test_url, timeout=self.timeout)
            
            if response.status_code == 200:
                # Check if readable
                content = response.text
                if content and content != 'null':
                    result.status = ValidationStatus.VALID
                    result.details = "Firebase database is PUBLICLY READABLE! Critical finding."
                    result.confidence = "high"
                else:
                    result.status = ValidationStatus.VALID
                    result.details = "Firebase URL exists (empty or null response)"
                    result.confidence = "medium"
            elif response.status_code == 401 or response.status_code == 403:
                result.status = ValidationStatus.VALID
                result.details = "Firebase URL exists but requires authentication"
                result.confidence = "medium"
            elif response.status_code == 404:
                result.status = ValidationStatus.INVALID
                result.details = "Firebase database does not exist"
                result.confidence = "high"
            else:
                result.status = ValidationStatus.UNKNOWN
                result.details = f"Unexpected status code: {response.status_code}"
                result.confidence = "low"
                
        except requests.Timeout:
            result.status = ValidationStatus.UNKNOWN
            result.details = "Request timeout"
            result.confidence = "low"
            
        except Exception as e:
            result.status = ValidationStatus.ERROR
            result.details = f"Validation error: {str(e)[:100]}"
            result.confidence = "low"
        
        return result
    
    def validate_google_api_key(self, api_key: str) -> ValidationResult:
        """Validate Google API key"""
        result = ValidationResult(
            secret_type="google_api_key",
            value=self._redact_secret(api_key),
            status=ValidationStatus.UNKNOWN
        )
        
        # Check format
        if not re.match(r'^AIza[0-9A-Za-z_-]{35}$', api_key):
            result.status = ValidationStatus.INVALID
            result.details = "Invalid Google API key format"
            result.confidence = "high"
            return result
        
        # Try Google Maps Geocoding API (free tier, minimal)
        self._rate_limit_wait()
        
        try:
            test_url = f"https://maps.googleapis.com/maps/api/geocode/json?address=test&key={api_key}"
            response = self.session.get(test_url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                status = data.get('status', '')
                
                if status == 'REQUEST_DENIED':
                    result.status = ValidationStatus.INVALID
                    result.details = "API key invalid or restricted"
                    result.confidence = "high"
                elif status in ['OK', 'ZERO_RESULTS']:
                    result.status = ValidationStatus.VALID
                    result.details = "Active Google API key!"
                    result.confidence = "high"
                else:
                    result.status = ValidationStatus.UNKNOWN
                    result.details = f"API response: {status}"
                    result.confidence = "medium"
            else:
                result.status = ValidationStatus.UNKNOWN
                result.details = f"HTTP {response.status_code}"
                result.confidence = "low"
                
        except Exception as e:
            result.status = ValidationStatus.ERROR
            result.details = f"Validation error: {str(e)[:100]}"
            result.confidence = "low"
        
        return result
    
    def validate_github_token(self, token: str) -> ValidationResult:
        """Validate GitHub token"""
        result = ValidationResult(
            secret_type="github_token",
            value=self._redact_secret(token),
            status=ValidationStatus.UNKNOWN
        )
        
        # Check format
        if not re.match(r'^gh[pousr]_[A-Za-z0-9_]{36,}$', token):
            result.status = ValidationStatus.INVALID
            result.details = "Invalid GitHub token format"
            result.confidence = "high"
            return result
        
        # Try GitHub API
        self._rate_limit_wait()
        
        try:
            headers = {'Authorization': f'token {token}'}
            response = self.session.get('https://api.github.com/user', 
                                       headers=headers, 
                                       timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                username = data.get('login', 'unknown')
                result.status = ValidationStatus.VALID
                result.details = f"Active GitHub token for user: {username}"
                result.confidence = "high"
            elif response.status_code == 401:
                result.status = ValidationStatus.INVALID
                result.details = "Invalid GitHub token"
                result.confidence = "high"
            else:
                result.status = ValidationStatus.UNKNOWN
                result.details = f"HTTP {response.status_code}"
                result.confidence = "low"
                
        except Exception as e:
            result.status = ValidationStatus.ERROR
            result.details = f"Validation error: {str(e)[:100]}"
            result.confidence = "low"
        
        return result
    
    def validate_slack_token(self, token: str) -> ValidationResult:
        """Validate Slack token"""
        result = ValidationResult(
            secret_type="slack_token",
            value=self._redact_secret(token),
            status=ValidationStatus.UNKNOWN
        )
        
        # Check format
        if not re.match(r'^xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*$', token):
            result.status = ValidationStatus.INVALID
            result.details = "Invalid Slack token format"
            result.confidence = "high"
            return result
        
        # Try Slack API
        self._rate_limit_wait()
        
        try:
            headers = {'Authorization': f'Bearer {token}'}
            response = self.session.get('https://slack.com/api/auth.test', 
                                       headers=headers, 
                                       timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    team = data.get('team', 'unknown')
                    result.status = ValidationStatus.VALID
                    result.details = f"Active Slack token for team: {team}"
                    result.confidence = "high"
                else:
                    error = data.get('error', 'unknown')
                    if 'invalid_auth' in error:
                        result.status = ValidationStatus.INVALID
                        result.details = "Invalid Slack token"
                        result.confidence = "high"
                    else:
                        result.status = ValidationStatus.UNKNOWN
                        result.details = f"Slack error: {error}"
                        result.confidence = "medium"
            else:
                result.status = ValidationStatus.UNKNOWN
                result.details = f"HTTP {response.status_code}"
                result.confidence = "low"
                
        except Exception as e:
            result.status = ValidationStatus.ERROR
            result.details = f"Validation error: {str(e)[:100]}"
            result.confidence = "low"
        
        return result
    
    def validate_secret(self, secret_type: str, value: str, 
                       extra_data: Optional[Dict] = None) -> ValidationResult:
        """
        Validate a secret based on its type
        
        Args:
            secret_type: Type of secret (aws_access_key, firebase_url, etc.)
            value: The secret value
            extra_data: Additional data (e.g., secret_key for AWS)
        """
        extra_data = extra_data or {}
        
        validators = {
            'aws_access_key': lambda: self.validate_aws_key(value, extra_data.get('secret_key')),
            'firebase_url': lambda: self.validate_firebase_url(value),
            'google_api_key': lambda: self.validate_google_api_key(value),
            'github_token': lambda: self.validate_github_token(value),
            'slack_token': lambda: self.validate_slack_token(value),
        }
        
        validator = validators.get(secret_type)
        if validator:
            return validator()
        
        # Unknown type, return unknown status
        return ValidationResult(
            secret_type=secret_type,
            value=self._redact_secret(value),
            status=ValidationStatus.UNKNOWN,
            details="No validator available for this secret type",
            confidence="low"
        )


if __name__ == "__main__":
    # Test validator
    validator = SecretValidator()
    
    print("\nTesting Secret Validator:")
    print("="*60)
    
    # Test invalid Firebase URL
    result = validator.validate_firebase_url("https://test-invalid-xyz123.firebaseio.com")
    print(f"\n[{result.status.value.upper()}] Firebase URL: {result.value}")
    print(f"  Details: {result.details}")
    print(f"  Confidence: {result.confidence}")
    
    # Test invalid Google API key format
    result = validator.validate_google_api_key("invalid_key_format")
    print(f"\n[{result.status.value.upper()}] Google API Key: {result.value}")
    print(f"  Details: {result.details}")
    print(f"  Confidence: {result.confidence}")
    
    print("\n" + "="*60)
    print("Note: Real secret validation requires actual keys.")
    print("Use responsibly and only on authorized targets!")
